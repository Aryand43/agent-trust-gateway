"""The gateway: verify the credential, gather signals, score, persist an event."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.credentials import CredentialClaims, TokenStatus, verify_token
from app.crypto import KeyManager
from app.errors import NotFoundError
from app.logging_config import get_logger
from app.models import Agent, Credential, Event, Merchant
from app.risk import behaviour
from app.risk.engine import CredentialState, Decision, RiskSignals, assess
from app.schemas import EvaluationRequest, EvaluationResponse, RiskFactorOut
from app.timeutils import utcnow

log = get_logger("gateway")


@dataclass(frozen=True)
class CredentialCheck:
    state: CredentialState
    claims: CredentialClaims | None  # only set when the signature verified


def check_credential(session: Session, keys: KeyManager, token: str | None, now: datetime) -> CredentialCheck:
    if not token:
        return CredentialCheck(CredentialState.NOT_PROVIDED, None)
    result = verify_token(token, keys)
    if result.status is TokenStatus.MALFORMED:
        return CredentialCheck(CredentialState.MALFORMED, None)
    if result.status is TokenStatus.INVALID_SIGNATURE:
        # Unverified claims are never trusted, not even the credential ID.
        return CredentialCheck(CredentialState.INVALID_SIGNATURE, None)

    claims = result.claims
    assert claims is not None
    row = session.get(Credential, claims.cid)
    if row is None:
        state = CredentialState.UNKNOWN
    else:
        state = CredentialState(row.status_at(now))
    # The signed expiry is authoritative even if the registry disagrees.
    if state is CredentialState.ACTIVE and now >= claims.expires_at:
        state = CredentialState.EXPIRED
    return CredentialCheck(state, claims)


def _identity_status(check: CredentialCheck, agent_known: bool, signals: RiskSignals) -> str:
    if check.state is CredentialState.NOT_PROVIDED:
        if signals.declared_agent or signals.automation_user_agent:
            return "unverified_agent"
        return "presumed_human"
    if check.state is not CredentialState.ACTIVE:
        return "invalid_credential"
    return "verified_agent" if agent_known else "unregistered_agent"


def _authorisation_status(check: CredentialCheck, signals: RiskSignals) -> str:
    if check.state is CredentialState.NOT_PROVIDED:
        return "not_applicable"
    if check.state is not CredentialState.ACTIVE:
        return "credential_invalid"
    if not (signals.merchant_match and signals.user_match and signals.agent_match):
        return "mismatch"
    if not signals.agent_known:
        return "unregistered_agent"
    if not signals.scope_granted:
        return "scope_not_granted"
    return "authorised"


def _classification(decision: Decision, identity: str) -> str:
    if decision is Decision.ALLOW and identity == "verified_agent":
        return "authorised_agent"
    if decision is Decision.ALLOW and identity == "presumed_human":
        return "human"
    if decision is Decision.ALLOW:
        return "unverified"
    return "suspicious"


def evaluate(
    session: Session,
    keys: KeyManager,
    req: EvaluationRequest,
    *,
    now: datetime | None = None,
    scenario: str | None = None,
) -> EvaluationResponse:
    now = now or utcnow()
    if session.get(Merchant, req.merchant_id) is None:
        raise NotFoundError("Merchant", req.merchant_id)

    ip = str(req.ip_address)
    check = check_credential(session, keys, req.credential, now)
    claims = check.claims

    agent_id = req.agent_id or (claims.aid if claims else None)
    user_id = req.user_id or (claims.sub if claims else None)
    agent_known = agent_id is None or session.get(Agent, agent_id) is not None
    credential_id = claims.cid if claims else None

    history = behaviour.collect(
        session, now=now, credential_id=credential_id, ip_address=ip,
        user_agent=req.user_agent, user_id=user_id,
    )
    signals = RiskSignals(
        credential_state=check.state,
        agent_known=agent_known,
        agent_match=claims is None or req.agent_id is None or req.agent_id == claims.aid,
        merchant_match=claims is None or req.merchant_id == claims.mid,
        user_match=claims is None or req.user_id is None or req.user_id == claims.sub,
        scope_granted=claims is None or req.action in claims.scope,
        declared_agent=req.declared_agent,
        automation_user_agent=behaviour.is_automation_user_agent(req.user_agent),
        requests_last_minute=history.requests_last_minute,
        recent_failures=history.recent_failures,
        ip_changed=history.ip_changed,
        user_agent_changed=history.user_agent_changed,
        distinct_accounts_from_ip=history.distinct_accounts_from_ip,
    )
    assessment = assess(signals)

    identity = _identity_status(check, agent_known, signals)
    authorisation = _authorisation_status(check, signals)
    classification = _classification(assessment.decision, identity)
    factors = [RiskFactorOut(code=f.code, points=f.points, description=f.description) for f in assessment.factors]

    event = Event(
        id=f"evt_{secrets.token_hex(8)}",
        created_at=now,
        merchant_id=req.merchant_id,
        user_id=user_id,
        agent_id=agent_id,
        credential_id=credential_id,
        action=req.action,
        ip_address=ip,
        user_agent=req.user_agent,
        declared_agent=req.declared_agent,
        decision=assessment.decision.value,
        risk_score=assessment.score,
        classification=classification,
        identity_status=identity,
        authorisation_status=authorisation,
        credential_status=check.state.value,
        risk_factors=[f.model_dump() for f in factors],
        request_metadata=req.metadata,
        scenario=scenario,
    )
    session.add(event)
    session.commit()

    log.info(
        "request_evaluated",
        extra={"ctx": {
            "event_id": event.id, "decision": event.decision, "score": event.risk_score,
            "credential_id": credential_id, "credential_status": event.credential_status,
            "merchant_id": req.merchant_id, "action": req.action,
            "factors": [f.code for f in factors], "scenario": scenario,
        }},
    )
    return EvaluationResponse(
        event_id=event.id,
        decision=event.decision,  # type: ignore[arg-type]
        risk_score=event.risk_score,
        base_score=assessment.base_score,
        classification=classification,
        identity_status=identity,
        authorisation_status=authorisation,
        credential_status=event.credential_status,
        credential_id=credential_id,
        risk_factors=factors,
        evaluated_at=now,
    )
