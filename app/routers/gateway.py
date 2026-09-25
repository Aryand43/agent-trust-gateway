"""Gateway evaluation, a sample protected merchant API, and demo scenarios."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import Settings
from app.crypto import KeyManager
from app.deps import get_keys, get_session, get_settings
from app.schemas import EvaluationRequest, EvaluationResponse, ScenarioInfo, ScenarioResult
from app.services import gateway, scenarios

router = APIRouter(prefix="/api", tags=["gateway"])

_STATUS_FOR_DECISION = {"allow": 200, "review": 428, "block": 403}


@router.post("/gateway/evaluate", response_model=EvaluationResponse)
def evaluate(
    body: EvaluationRequest,
    session: Session = Depends(get_session),
    keys: KeyManager = Depends(get_keys),
) -> EvaluationResponse:
    """Score a request. Always returns 200 with a decision; enforcement is the caller's job."""
    return gateway.evaluate(session, keys, body)


@router.post("/merchant/{merchant_id}/{action}")
def protected_merchant_action(
    merchant_id: str,
    action: Literal["browse", "search", "purchase"],
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_declared_agent: bool = Header(default=False),
    x_forwarded_for: str | None = Header(default=None),
    user_agent: str = Header(default=""),
    session: Session = Depends(get_session),
    keys: KeyManager = Depends(get_keys),
) -> JSONResponse:
    """A sample merchant endpoint enforcing the gateway decision.

    Send ``Authorization: AgentCredential <token>``. Responds 200 (allow),
    428 (review: step-up needed) or 403 (block).
    """
    token = None
    if authorization and authorization.lower().startswith("agentcredential "):
        token = authorization.split(" ", 1)[1]
    ip = (x_forwarded_for or "").split(",")[0].strip() or (request.client.host if request.client else "127.0.0.1")
    if ip == "testclient":
        ip = "127.0.0.1"
    result = gateway.evaluate(session, keys, EvaluationRequest(
        credential=token, merchant_id=merchant_id, user_id=x_user_id, agent_id=x_agent_id,
        action=action, ip_address=ip, user_agent=user_agent[:512],  # type: ignore[arg-type]
        declared_agent=x_declared_agent, metadata={"path": request.url.path},
    ))
    body: dict[str, Any] = {"decision": result.decision, "gateway": result.model_dump(mode="json")}
    if result.decision == "allow":
        body["data"] = {"action": action, "items": [{"sku": "TR2-42", "name": "Trail Runner 2", "price": 129.0}]}
    elif result.decision == "review":
        body["challenge"] = "step_up_authorisation_required"
    return JSONResponse(status_code=_STATUS_FOR_DECISION[result.decision], content=body)


@router.get("/demo/scenarios", response_model=list[ScenarioInfo])
def list_scenarios() -> list[ScenarioInfo]:
    return list(scenarios.SCENARIOS.values())


@router.post("/demo/scenarios/{key}", response_model=ScenarioResult)
def run_scenario(
    key: str,
    session: Session = Depends(get_session),
    keys: KeyManager = Depends(get_keys),
    settings: Settings = Depends(get_settings),
) -> ScenarioResult:
    return scenarios.run_scenario(session, keys, key, ttl_seconds=settings.credential_ttl_seconds)
