"""Deterministic, explainable risk engine.

``assess(signals)`` is a pure function: same signals in, same score out. It has no I/O,
so it can be unit-tested exhaustively and later swapped for a learned model that consumes
the same ``RiskSignals`` and returns the same ``RiskAssessment``.

Scoring: start at ``BASE_SCORE`` (neutral, "unknown traffic"), add or subtract the points
in ``WEIGHTS`` for every signal that fires, then clamp to 0..100.

    0-39  -> allow      40-69 -> review      70-100 -> block
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class CredentialState(str, Enum):
    NOT_PROVIDED = "not_provided"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MALFORMED = "malformed"
    INVALID_SIGNATURE = "invalid_signature"
    UNKNOWN = "unknown"  # validly signed but absent from the registry


BASE_SCORE = 25
REVIEW_THRESHOLD = 40
BLOCK_THRESHOLD = 70

# Tiers are (inclusive minimum, factor code), highest first; only the top tier fires.
# Velocity counts prior requests in the last 60 s from the same credential (or IP if none).
VELOCITY_TIERS: tuple[tuple[int, str], ...] = (
    (41, "velocity_extreme"),
    (21, "velocity_high"),
    (11, "velocity_elevated"),
)
FAILURE_TIERS: tuple[tuple[int, str], ...] = ((6, "repeated_failures_high"), (3, "repeated_failures"))
MULTI_ACCOUNT_TIERS: tuple[tuple[int, str], ...] = (
    (6, "many_accounts_from_ip_high"),
    (3, "many_accounts_from_ip"),
)

# code -> (points, human-readable explanation)
WEIGHTS: dict[str, tuple[int, str]] = {
    # Trust-reducing (negative) signals
    "verified_credential": (-20, "Valid signature, active credential, claims match, scope granted"),
    "transparent_agent": (-5, "Agent openly declared itself and presented a verified credential"),
    # Credential integrity
    "malformed_credential": (50, "Credential could not be parsed"),
    "invalid_signature": (50, "Credential signature is invalid or was tampered with"),
    "unknown_credential": (40, "Credential ID is not in the issuer registry"),
    "credential_revoked": (55, "Credential has been revoked"),
    "credential_expired": (45, "Credential has expired"),
    # Identity and authorisation
    "unknown_agent": (30, "Agent ID is not registered"),
    "agent_mismatch": (35, "Request agent ID does not match the credential"),
    "merchant_mismatch": (45, "Credential was issued for a different merchant"),
    "user_mismatch": (45, "Credential was issued for a different user account"),
    "scope_not_granted": (40, "Requested action is outside the credential's scope"),
    # Self-declaration consistency
    "undeclared_agent_with_credential": (10, "Presented an agent credential without declaring agent status"),
    "declared_agent_without_credential": (25, "Declared itself an agent but presented no credential"),
    "automation_user_agent": (30, "Automation/scripting user-agent with no credential or declaration"),
    # Behaviour
    "velocity_elevated": (25, "More than 10 requests in the last minute"),
    "velocity_high": (40, "More than 20 requests in the last minute"),
    "velocity_extreme": (55, "More than 40 requests in the last minute"),
    "repeated_failures": (15, "3+ recent requests were reviewed or blocked"),
    "repeated_failures_high": (25, "6+ recent requests were reviewed or blocked"),
    "ip_change": (15, "Credential is being used from a new IP address"),
    "user_agent_change": (10, "Credential is being used with a new user-agent"),
    "many_accounts_from_ip": (25, "Same IP touched 3+ different user accounts in 10 minutes"),
    "many_accounts_from_ip_high": (40, "Same IP touched 6+ different user accounts in 10 minutes"),
}


@dataclass(frozen=True)
class RiskSignals:
    """Everything the engine needs, already extracted from the request and history."""

    credential_state: CredentialState = CredentialState.NOT_PROVIDED
    agent_known: bool = True
    agent_match: bool = True
    merchant_match: bool = True
    user_match: bool = True
    scope_granted: bool = True
    declared_agent: bool = False
    automation_user_agent: bool = False
    requests_last_minute: int = 0
    recent_failures: int = 0
    ip_changed: bool = False
    user_agent_changed: bool = False
    distinct_accounts_from_ip: int = 0

    @property
    def credential_present(self) -> bool:
        return self.credential_state is not CredentialState.NOT_PROVIDED

    @property
    def claims_consistent(self) -> bool:
        return self.agent_known and self.agent_match and self.merchant_match and self.user_match


@dataclass(frozen=True)
class RiskFactor:
    code: str
    points: int
    description: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    decision: Decision
    factors: tuple[RiskFactor, ...] = field(default_factory=tuple)
    base_score: int = BASE_SCORE


def decision_for(score: int) -> Decision:
    if score >= BLOCK_THRESHOLD:
        return Decision.BLOCK
    if score >= REVIEW_THRESHOLD:
        return Decision.REVIEW
    return Decision.ALLOW


def _tier(value: int, tiers: tuple[tuple[int, str], ...]) -> str | None:
    for minimum, code in tiers:
        if value >= minimum:
            return code
    return None


def _fired_codes(s: RiskSignals) -> list[str]:
    codes: list[str] = []
    state = s.credential_state

    # --- Credential integrity -------------------------------------------------------
    state_codes = {
        CredentialState.MALFORMED: "malformed_credential",
        CredentialState.INVALID_SIGNATURE: "invalid_signature",
        CredentialState.UNKNOWN: "unknown_credential",
        CredentialState.REVOKED: "credential_revoked",
        CredentialState.EXPIRED: "credential_expired",
    }
    if state in state_codes:
        codes.append(state_codes[state])

    # --- Identity / authorisation (only meaningful when claims were readable) --------
    if not s.agent_known:
        codes.append("unknown_agent")
    if s.credential_present:
        if not s.agent_match:
            codes.append("agent_mismatch")
        if not s.merchant_match:
            codes.append("merchant_mismatch")
        if not s.user_match:
            codes.append("user_mismatch")
        if not s.scope_granted:
            codes.append("scope_not_granted")

    fully_verified = state is CredentialState.ACTIVE and s.claims_consistent and s.scope_granted
    if fully_verified:
        codes.append("verified_credential")
        if s.declared_agent:
            codes.append("transparent_agent")

    # --- Self-declaration consistency ----------------------------------------------
    if s.credential_present and not s.declared_agent:
        codes.append("undeclared_agent_with_credential")
    if not s.credential_present and s.declared_agent:
        codes.append("declared_agent_without_credential")
    if not s.credential_present and not s.declared_agent and s.automation_user_agent:
        codes.append("automation_user_agent")

    # --- Behaviour -----------------------------------------------------------------
    for value, tiers in (
        (s.requests_last_minute, VELOCITY_TIERS),
        (s.recent_failures, FAILURE_TIERS),
        (s.distinct_accounts_from_ip, MULTI_ACCOUNT_TIERS),
    ):
        code = _tier(value, tiers)
        if code:
            codes.append(code)
    if s.ip_changed:
        codes.append("ip_change")
    if s.user_agent_changed:
        codes.append("user_agent_change")
    return codes


def assess(signals: RiskSignals) -> RiskAssessment:
    factors = tuple(
        RiskFactor(code, WEIGHTS[code][0], WEIGHTS[code][1]) for code in _fired_codes(signals)
    )
    raw = BASE_SCORE + sum(f.points for f in factors)
    score = max(0, min(100, raw))
    return RiskAssessment(score=score, decision=decision_for(score), factors=factors)
