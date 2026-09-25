"""Signed agent credential format (demo-only, JWT-like but deliberately minimal).

Token layout::

    atg1.<base64url(canonical JSON claims)>.<base64url(Ed25519 signature)>

The signature covers the ASCII bytes ``atg1.<payload>``. Claims:

    cid  credential ID          sub  user ID          mid  merchant ID
    aid  agent ID               iat  issued-at (epoch s)
    exp  expiry (epoch s)       scope  list of granted scopes
    iss  issuer                 kid  signing key ID

This module is pure: it signs and verifies. Revocation, expiry and claim matching are
decided by the gateway, which has access to the credential registry and the clock.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from app.crypto import KeyManager
from app.timeutils import from_epoch, to_epoch

TOKEN_PREFIX = "atg1"
ISSUER = "agent-trust-gateway-demo"
VALID_SCOPES = ("browse", "search", "purchase")


@dataclass(frozen=True)
class CredentialClaims:
    cid: str
    sub: str
    mid: str
    aid: str
    iat: int
    exp: int
    scope: tuple[str, ...]
    iss: str = ISSUER
    kid: str = ""

    @property
    def issued_at(self) -> datetime:
        return from_epoch(self.iat)

    @property
    def expires_at(self) -> datetime:
        return from_epoch(self.exp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cid": self.cid,
            "sub": self.sub,
            "mid": self.mid,
            "aid": self.aid,
            "iat": self.iat,
            "exp": self.exp,
            "scope": list(self.scope),
            "iss": self.iss,
            "kid": self.kid,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CredentialClaims:
        scope = data["scope"]
        if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
            raise ValueError("scope must be a list of strings")
        return cls(
            cid=str(data["cid"]),
            sub=str(data["sub"]),
            mid=str(data["mid"]),
            aid=str(data["aid"]),
            iat=int(data["iat"]),
            exp=int(data["exp"]),
            scope=tuple(scope),
            iss=str(data.get("iss", "")),
            kid=str(data.get("kid", "")),
        )


class TokenStatus(str, Enum):
    VALID = "valid"
    MALFORMED = "malformed"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass(frozen=True)
class TokenVerification:
    status: TokenStatus
    claims: CredentialClaims | None = None
    unverified_claims: CredentialClaims | None = None  # parsed but NOT trusted


def new_credential_id() -> str:
    return f"cred_{secrets.token_hex(8)}"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _canonical(claims: CredentialClaims) -> bytes:
    return json.dumps(claims.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def encode_token(claims: CredentialClaims, keys: KeyManager) -> str:
    payload = _b64e(_canonical(claims))
    signing_input = f"{TOKEN_PREFIX}.{payload}".encode("ascii")
    return f"{TOKEN_PREFIX}.{payload}.{_b64e(keys.sign(signing_input))}"


def issue_credential(
    keys: KeyManager,
    *,
    user_id: str,
    merchant_id: str,
    agent_id: str,
    scopes: list[str] | tuple[str, ...],
    ttl: timedelta,
    now: datetime,
    credential_id: str | None = None,
) -> tuple[CredentialClaims, str]:
    unknown = set(scopes) - set(VALID_SCOPES)
    if unknown:
        raise ValueError(f"Unknown scopes: {sorted(unknown)}")
    if ttl.total_seconds() <= 0:
        raise ValueError("ttl must be positive")
    claims = CredentialClaims(
        cid=credential_id or new_credential_id(),
        sub=user_id,
        mid=merchant_id,
        aid=agent_id,
        iat=to_epoch(now),
        exp=to_epoch(now + ttl),
        scope=tuple(sorted(set(scopes))),
        kid=keys.kid,
    )
    return claims, encode_token(claims, keys)


def _parse(token: str) -> tuple[bytes, bytes, CredentialClaims] | None:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None
    try:
        claims = CredentialClaims.from_dict(json.loads(_b64d(parts[1])))
        signature = _b64d(parts[2])
    except (ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError):
        return None
    return f"{parts[0]}.{parts[1]}".encode("ascii"), signature, claims


def verify_token(token: str, keys: KeyManager) -> TokenVerification:
    parsed = _parse(token)
    if parsed is None:
        return TokenVerification(TokenStatus.MALFORMED)
    signing_input, signature, claims = parsed
    if claims.iss != ISSUER or not keys.verify(signature, signing_input):
        return TokenVerification(TokenStatus.INVALID_SIGNATURE, unverified_claims=claims)
    return TokenVerification(TokenStatus.VALID, claims=claims)


def tamper_claims(token: str, **changes: Any) -> str:
    """Rewrite claims while keeping the original signature. Used by demo scenarios/tests
    to simulate an agent editing its own credential (e.g. to escalate scope)."""
    prefix, payload, signature = token.split(".")
    data = json.loads(_b64d(payload))
    data.update(changes)
    new_payload = _b64e(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return f"{prefix}.{new_payload}.{signature}"
