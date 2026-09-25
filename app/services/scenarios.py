"""One-click demo scenarios. Each builds realistic requests and runs them through the gateway.

Different scenarios use different source IPs (documentation ranges, RFC 5737) so that
behavioural signals from one scenario don't bleed into another.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.credentials import tamper_claims
from app.crypto import KeyManager
from app.errors import AppError
from app.schemas import EvaluationRequest, ScenarioInfo, ScenarioResult
from app.services import gateway, registry
from app.timeutils import utcnow

DEMO_USER_ID = "usr_alex_tan"
DEMO_MERCHANT_ID = "mer_demoshop"
DEMO_AGENT_ID = "agt_shopping_assistant"
DEMO_AUTHORISATION_ID = "auth_alex_shopping_assistant"

AGENT_UA = "ShoppingAssistant/1.0 (+https://agents.example/shopping-assistant)"
BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
SCRAPER_UA = "python-requests/2.31.0"

SCENARIOS: dict[str, ScenarioInfo] = {
    s.key: s
    for s in [
        ScenarioInfo(key="legitimate", title="Legitimate authorised agent", expected="allow",
                     description="Shopping Assistant presents a fresh, valid credential and searches within its granted scope."),
        ScenarioInfo(key="human", title="Human shopper", expected="allow",
                     description="A person browsing in Safari: no agent credential, no automation signals."),
        ScenarioInfo(key="expired", title="Expired credential", expected="block",
                     description="The agent replays a credential whose 15-minute lifetime ended long ago."),
        ScenarioInfo(key="revoked", title="Revoked credential", expected="block",
                     description="Alex revokes the agent's credential; the agent keeps using it."),
        ScenarioInfo(key="invalid_signature", title="Invalid signature", expected="block",
                     description="The agent edits its own credential to add 'purchase' scope, breaking the Ed25519 signature."),
        ScenarioInfo(key="high_velocity", title="High-velocity suspicious agent", expected="block",
                     description="An undeclared scraper fires 25 rapid requests across many customer accounts."),
        ScenarioInfo(key="unauthorised_scope", title="Unauthorised scope", expected="review",
                     description="A valid browse/search credential attempts a purchase: step-up approval required."),
        ScenarioInfo(key="account_mismatch", title="Credential replay on another account", expected="block",
                     description="Alex's valid credential is used to act on a different customer's account."),
    ]
}


def _fresh_token(session: Session, keys: KeyManager, ttl: timedelta, now: datetime) -> str:
    auth = registry.get_authorisation(session, DEMO_AUTHORISATION_ID)
    return registry.issue_for_authorisation(session, keys, auth, ttl=ttl, now=now).token


def _agent_request(token: str | None, ip: str, action: str = "search", **overrides: object) -> EvaluationRequest:
    base: dict[str, object] = dict(
        credential=token, merchant_id=DEMO_MERCHANT_ID, user_id=DEMO_USER_ID, agent_id=DEMO_AGENT_ID,
        action=action, ip_address=ip, user_agent=AGENT_UA, declared_agent=True,
        metadata={"path": f"/api/{action}", "query": "running shoes"},
    )
    base.update(overrides)
    return EvaluationRequest.model_validate(base)


Builder = Callable[[Session, KeyManager, datetime, timedelta, int], list[EvaluationRequest]]


def _legitimate(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    return [_agent_request(_fresh_token(s, k, ttl, now), "203.0.113.10")]


def _human(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    return [EvaluationRequest(
        merchant_id=DEMO_MERCHANT_ID, user_id=DEMO_USER_ID, action="browse",
        ip_address="192.0.2.25", user_agent=BROWSER_UA, declared_agent=False,  # type: ignore[arg-type]
        metadata={"path": "/products/trail-runner-2"},
    )]


def _expired(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    token = _fresh_token(s, k, ttl, now - ttl - timedelta(minutes=30))
    return [_agent_request(token, "203.0.113.21")]


def _revoked(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    auth = registry.get_authorisation(s, DEMO_AUTHORISATION_ID)
    issued = registry.issue_for_authorisation(s, k, auth, ttl=ttl, now=now - timedelta(seconds=30))
    registry.revoke_credential(s, issued.credential.id, "User revoked agent access", now=now - timedelta(seconds=5))
    return [_agent_request(issued.token, "203.0.113.22")]


def _invalid_signature(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    token = tamper_claims(_fresh_token(s, k, ttl, now), scope=["browse", "purchase", "search"])
    return [_agent_request(token, "203.0.113.23", action="purchase")]


def _high_velocity(s: Session, k: KeyManager, now: datetime, ttl: timedelta, count: int) -> list[EvaluationRequest]:
    return [
        EvaluationRequest(
            merchant_id=DEMO_MERCHANT_ID, user_id=f"usr_customer_{i % 9 + 1:02d}",
            action="search" if i % 2 else "browse", ip_address="198.51.100.66",  # type: ignore[arg-type]
            user_agent=SCRAPER_UA, declared_agent=False, metadata={"path": f"/api/accounts/{i % 9 + 1}/orders"},
        )
        for i in range(count)
    ]


def _unauthorised_scope(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    token = _fresh_token(s, k, ttl, now)
    return [_agent_request(token, "203.0.113.24", action="purchase",
                           metadata={"path": "/api/checkout", "sku": "TR2-42", "amount": 129.0})]


def _account_mismatch(s: Session, k: KeyManager, now: datetime, ttl: timedelta, _: int) -> list[EvaluationRequest]:
    token = _fresh_token(s, k, ttl, now)
    return [_agent_request(token, "203.0.113.25", user_id="usr_jordan_lee")]


BUILDERS: dict[str, Builder] = {
    "legitimate": _legitimate,
    "human": _human,
    "expired": _expired,
    "revoked": _revoked,
    "invalid_signature": _invalid_signature,
    "high_velocity": _high_velocity,
    "unauthorised_scope": _unauthorised_scope,
    "account_mismatch": _account_mismatch,
}


def run_scenario(
    session: Session,
    keys: KeyManager,
    key: str,
    *,
    ttl_seconds: int,
    now: datetime | None = None,
    burst: int = 25,
) -> ScenarioResult:
    if key not in SCENARIOS:
        raise AppError(404, "unknown_scenario", f"Unknown scenario '{key}'", {"available": list(SCENARIOS)})
    now = now or utcnow()
    requests = BUILDERS[key](session, keys, now, timedelta(seconds=ttl_seconds), burst)
    results = [
        gateway.evaluate(session, keys, req, now=now + timedelta(milliseconds=i * 40), scenario=key)
        for i, req in enumerate(requests)
    ]
    return ScenarioResult(
        scenario=SCENARIOS[key],
        requests_sent=len(results),
        final=results[-1],
        decisions=[r.decision for r in results],
    )
