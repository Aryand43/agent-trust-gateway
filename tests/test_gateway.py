"""Gateway service tests against a real SQLite database."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.credentials import tamper_claims
from app.crypto import KeyManager
from app.schemas import EvaluationRequest
from app.services import gateway, registry
from app.timeutils import utcnow
from tests.conftest import AGENT, MERCHANT, USER

AGENT_UA = "TestAgent/1.0"


def req(token: str | None, **kw: object) -> EvaluationRequest:
    data: dict[str, object] = dict(credential=token, merchant_id=MERCHANT, user_id=USER, agent_id=AGENT,
                                   action="search", ip_address="203.0.113.5", user_agent=AGENT_UA,
                                   declared_agent=True)
    data.update(kw)
    return EvaluationRequest.model_validate(data)


def codes(result) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.code for f in result.risk_factors]


def test_valid_credential_is_allowed(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    cid, token = issue()
    r = gateway.evaluate(session, keys, req(token))
    assert r.decision == "allow"
    assert r.identity_status == "verified_agent"
    assert r.authorisation_status == "authorised"
    assert r.credential_status == "active"
    assert r.credential_id == cid
    assert r.classification == "authorised_agent"


def test_expired_credential_blocked(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue(ttl_seconds=60, issued_ago=600)
    r = gateway.evaluate(session, keys, req(token))
    assert r.credential_status == "expired"
    assert "credential_expired" in codes(r)
    assert r.decision == "block"


def test_expiry_enforced_at_evaluation_time(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue(ttl_seconds=60)
    later = utcnow() + timedelta(seconds=61)
    assert gateway.evaluate(session, keys, req(token), now=later).decision == "block"


def test_revoked_credential_blocked(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    cid, token = issue()
    assert gateway.evaluate(session, keys, req(token)).decision == "allow"
    registry.revoke_credential(session, cid, "test")
    r = gateway.evaluate(session, keys, req(token))
    assert r.credential_status == "revoked"
    assert r.authorisation_status == "credential_invalid"
    assert r.decision == "block"


def test_invalid_signature_blocked_and_claims_untrusted(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    r = gateway.evaluate(session, keys, req(tamper_claims(token, scope=["purchase"]), action="purchase"))
    assert r.credential_status == "invalid_signature"
    assert r.credential_id is None
    assert r.decision == "block"


def test_merchant_mismatch_blocked(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    r = gateway.evaluate(session, keys, req(token, merchant_id="mer_other"))
    assert "merchant_mismatch" in codes(r)
    assert r.authorisation_status == "mismatch"
    assert r.decision == "block"


def test_user_mismatch_blocked(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    r = gateway.evaluate(session, keys, req(token, user_id="usr_someone_else"))
    assert "user_mismatch" in codes(r)
    assert r.decision == "block"


def test_agent_mismatch_and_unknown_agent(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    r = gateway.evaluate(session, keys, req(token, agent_id="agt_impostor"))
    assert {"agent_mismatch", "unknown_agent"} <= set(codes(r))
    assert r.decision == "block"


def test_scope_mismatch_reviewed(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    r = gateway.evaluate(session, keys, req(token, action="purchase"))
    assert r.authorisation_status == "scope_not_granted"
    assert codes(r) == ["scope_not_granted"]
    assert r.decision == "review"


def test_velocity_escalates_risk(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    now = utcnow()
    results = [gateway.evaluate(session, keys, req(token), now=now + timedelta(milliseconds=i)) for i in range(30)]
    scores = [r.risk_score for r in results]
    assert results[0].decision == "allow"
    assert scores == sorted(scores)  # never de-escalates within the burst
    assert "velocity_elevated" in codes(results[11])
    assert "velocity_high" in codes(results[21])
    assert results[-1].decision == "review"


def test_velocity_window_expires(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    now = utcnow()
    for i in range(15):
        gateway.evaluate(session, keys, req(token), now=now + timedelta(milliseconds=i))
    later = gateway.evaluate(session, keys, req(token), now=now + timedelta(seconds=90))
    assert not any(c.startswith("velocity") for c in codes(later))


def test_ip_change_detected(session: Session, keys: KeyManager, issue) -> None:  # type: ignore[no-untyped-def]
    _, token = issue()
    gateway.evaluate(session, keys, req(token))
    r = gateway.evaluate(session, keys, req(token, ip_address="198.51.100.200", user_agent="curl/8.0"))
    assert {"ip_change", "user_agent_change"} <= set(codes(r))


def test_scraper_across_accounts_blocked(session: Session, keys: KeyManager) -> None:
    results = [
        gateway.evaluate(session, keys, req(None, agent_id=None, declared_agent=False, user_agent="python-requests/2.31",
                                             user_id=f"usr_victim_{i}", ip_address="198.51.100.9"))
        for i in range(8)
    ]
    assert results[0].decision == "review"
    assert results[-1].decision == "block"
    assert "many_accounts_from_ip_high" in codes(results[-1])


def test_human_browser_allowed(session: Session, keys: KeyManager) -> None:
    r = gateway.evaluate(session, keys, req(None, agent_id=None, declared_agent=False,
                                             user_agent="Mozilla/5.0 (Macintosh) Safari/605.1.15"))
    assert (r.decision, r.identity_status, r.classification) == ("allow", "presumed_human", "human")


def test_declared_agent_without_credential_reviewed(session: Session, keys: KeyManager) -> None:
    r = gateway.evaluate(session, keys, req(None))
    assert r.identity_status == "unverified_agent"
    assert r.decision == "review"
