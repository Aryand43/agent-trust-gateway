from __future__ import annotations

from datetime import timedelta

import pytest

from app.credentials import TokenStatus, issue_credential, tamper_claims, verify_token
from app.crypto import KeyManager
from app.timeutils import to_epoch, utcnow


def _issue(keys: KeyManager, **kw):  # type: ignore[no-untyped-def]
    now = kw.pop("now", utcnow())
    return issue_credential(
        keys, user_id="usr_a", merchant_id="mer_a", agent_id="agt_a",
        scopes=kw.pop("scopes", ["search", "browse"]), ttl=timedelta(minutes=15), now=now, **kw,
    )


def test_issued_credential_contains_required_claims(keys: KeyManager) -> None:
    now = utcnow()
    claims, token = _issue(keys, now=now)
    assert claims.cid.startswith("cred_")
    assert (claims.sub, claims.mid, claims.aid) == ("usr_a", "mer_a", "agt_a")
    assert claims.iat == to_epoch(now)
    assert claims.exp == to_epoch(now) + 900
    assert claims.scope == ("browse", "search")  # sorted, de-duplicated
    assert claims.kid == keys.kid
    assert token.startswith("atg1.") and token.count(".") == 2


def test_valid_signature_verifies(keys: KeyManager) -> None:
    claims, token = _issue(keys)
    result = verify_token(token, keys)
    assert result.status is TokenStatus.VALID
    assert result.claims == claims


def test_tampered_claims_fail_signature(keys: KeyManager) -> None:
    _, token = _issue(keys)
    forged = tamper_claims(token, scope=["browse", "purchase", "search"])
    result = verify_token(forged, keys)
    assert result.status is TokenStatus.INVALID_SIGNATURE
    assert result.claims is None


def test_token_signed_by_other_key_is_rejected(keys: KeyManager) -> None:
    _, token = _issue(KeyManager.generate())
    assert verify_token(token, keys).status is TokenStatus.INVALID_SIGNATURE


@pytest.mark.parametrize("bad", ["", "garbage", "atg1.abc", "jwt.a.b", "atg1.!!!.???", "atg1.e30.AAAA"])
def test_malformed_tokens(keys: KeyManager, bad: str) -> None:
    assert verify_token(bad, keys).status is TokenStatus.MALFORMED


def test_unknown_scope_rejected(keys: KeyManager) -> None:
    with pytest.raises(ValueError):
        _issue(keys, scopes=["admin"])


def test_key_persisted_with_restricted_permissions(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "k.pem"
    first = KeyManager.load_or_create(path)
    second = KeyManager.load_or_create(path)
    assert first.kid == second.kid
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert "PRIVATE" not in repr(first)
