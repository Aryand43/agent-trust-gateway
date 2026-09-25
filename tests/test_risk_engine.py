"""The engine is pure, so these tests pin the scoring contract precisely."""

from __future__ import annotations

import pytest

from app.risk.engine import (
    BASE_SCORE,
    WEIGHTS,
    CredentialState,
    Decision,
    RiskSignals,
    assess,
    decision_for,
)

VERIFIED = RiskSignals(credential_state=CredentialState.ACTIVE, declared_agent=True)


def codes(signals: RiskSignals) -> list[str]:
    return [f.code for f in assess(signals).factors]


@pytest.mark.parametrize(
    ("score", "decision"),
    [(0, Decision.ALLOW), (39, Decision.ALLOW), (40, Decision.REVIEW), (69, Decision.REVIEW),
     (70, Decision.BLOCK), (100, Decision.BLOCK)],
)
def test_threshold_boundaries(score: int, decision: Decision) -> None:
    assert decision_for(score) is decision


def test_assessment_is_deterministic() -> None:
    s = RiskSignals(credential_state=CredentialState.EXPIRED, requests_last_minute=25, ip_changed=True)
    assert len({assess(s) for _ in range(20)}) == 1


def test_human_traffic_is_neutral_and_allowed() -> None:
    r = assess(RiskSignals())
    assert r.score == BASE_SCORE and r.decision is Decision.ALLOW and r.factors == ()


def test_verified_transparent_agent_scores_lowest() -> None:
    r = assess(VERIFIED)
    assert codes(VERIFIED) == ["verified_credential", "transparent_agent"]
    assert r.score == 0 and r.decision is Decision.ALLOW


@pytest.mark.parametrize(
    ("state", "code"),
    [(CredentialState.EXPIRED, "credential_expired"), (CredentialState.REVOKED, "credential_revoked"),
     (CredentialState.INVALID_SIGNATURE, "invalid_signature"), (CredentialState.MALFORMED, "malformed_credential")],
)
def test_bad_credentials_always_block(state: CredentialState, code: str) -> None:
    r = assess(RiskSignals(credential_state=state, declared_agent=True))
    assert code in codes(RiskSignals(credential_state=state))
    assert "verified_credential" not in [f.code for f in r.factors]
    assert r.decision is Decision.BLOCK


@pytest.mark.parametrize("field", ["merchant_match", "user_match"])
def test_merchant_or_user_mismatch_blocks(field: str) -> None:
    r = assess(RiskSignals(credential_state=CredentialState.ACTIVE, declared_agent=True, **{field: False}))
    assert r.decision is Decision.BLOCK
    assert "verified_credential" not in [f.code for f in r.factors]


def test_scope_mismatch_requires_review() -> None:
    r = assess(RiskSignals(credential_state=CredentialState.ACTIVE, declared_agent=True, scope_granted=False))
    assert [f.code for f in r.factors] == ["scope_not_granted"]
    assert r.score == BASE_SCORE + WEIGHTS["scope_not_granted"][0]
    assert r.decision is Decision.REVIEW


def test_velocity_escalates_monotonically() -> None:
    base = dict(automation_user_agent=False)
    scores = [assess(RiskSignals(requests_last_minute=n, **base)).score for n in (0, 10, 11, 21, 41)]
    assert scores == sorted(scores)
    assert scores[0] == scores[1]  # 10 is still within normal
    assert len(set(scores[1:])) == 4  # each tier adds more risk
    assert "velocity_extreme" in codes(RiskSignals(requests_last_minute=41))
    assert codes(RiskSignals(requests_last_minute=41)).count("velocity_extreme") == 1  # single tier fires


def test_velocity_pushes_even_verified_agent_to_review() -> None:
    r = assess(RiskSignals(credential_state=CredentialState.ACTIVE, declared_agent=True, requests_last_minute=25))
    assert r.decision is Decision.REVIEW


def test_declaration_consistency_signals() -> None:
    assert "declared_agent_without_credential" in codes(RiskSignals(declared_agent=True))
    assert "automation_user_agent" in codes(RiskSignals(automation_user_agent=True))
    assert "undeclared_agent_with_credential" in codes(RiskSignals(credential_state=CredentialState.ACTIVE))


def test_score_is_clamped() -> None:
    worst = RiskSignals(
        credential_state=CredentialState.REVOKED, agent_known=False, merchant_match=False, user_match=False,
        agent_match=False, scope_granted=False, requests_last_minute=100, recent_failures=10,
        ip_changed=True, user_agent_changed=True, distinct_accounts_from_ip=20,
    )
    assert assess(worst).score == 100
    assert assess(VERIFIED).score >= 0


def test_every_factor_is_documented() -> None:
    for code, (points, text) in WEIGHTS.items():
        assert isinstance(points, int) and text, code
