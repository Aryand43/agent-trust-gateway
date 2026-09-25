"""Pydantic request/response schemas."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from app.risk.engine import BASE_SCORE

Scope = Literal["browse", "search", "purchase"]
DecisionLiteral = Literal["allow", "review", "block"]
IdPattern = r"^[A-Za-z0-9_\-]{1,64}$"


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- Registry -----------------------------------------------------------------------


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str | None = Field(default=None, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    id: str | None = Field(default=None, pattern=IdPattern)


class UserOut(ORMModel):
    id: str
    name: str
    email: str | None
    created_at: datetime


class MerchantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    id: str | None = Field(default=None, pattern=IdPattern)


class MerchantOut(ORMModel):
    id: str
    name: str
    created_at: datetime


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    operator: str = Field(default="", max_length=120)
    id: str | None = Field(default=None, pattern=IdPattern)


class AgentOut(ORMModel):
    id: str
    name: str
    operator: str
    created_at: datetime


# ---- Authorisations & credentials ---------------------------------------------------


class AuthorisationCreate(BaseModel):
    user_id: str = Field(pattern=IdPattern)
    merchant_id: str = Field(pattern=IdPattern)
    agent_id: str = Field(pattern=IdPattern)
    scopes: list[Scope] = Field(min_length=1, max_length=3)
    ttl_seconds: int | None = Field(default=None, ge=30, le=86_400)

    @field_validator("scopes")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        return sorted(set(v))


class CredentialOut(ORMModel):
    id: str
    authorisation_id: str
    user_id: str
    merchant_id: str
    agent_id: str
    scopes: list[str]
    key_id: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    status: str = "active"


class IssuedCredential(BaseModel):
    """Returned once at issuance. The token itself is never stored server-side."""

    credential: CredentialOut
    token: str
    claims: dict[str, Any]


class AuthorisationOut(ORMModel):
    id: str
    user_id: str
    merchant_id: str
    agent_id: str
    scopes: list[str]
    created_at: datetime


class AuthorisationCreated(BaseModel):
    authorisation: AuthorisationOut
    issued: IssuedCredential


class RevokeRequest(BaseModel):
    reason: str = Field(default="Revoked from dashboard", max_length=200)


# ---- Gateway ------------------------------------------------------------------------


class EvaluationRequest(BaseModel):
    credential: str | None = Field(default=None, max_length=4096)
    merchant_id: str = Field(pattern=IdPattern)
    user_id: str | None = Field(default=None, pattern=IdPattern)
    agent_id: str | None = Field(default=None, pattern=IdPattern)
    action: Scope
    ip_address: IPvAnyAddress
    user_agent: str = Field(default="", max_length=512)
    declared_agent: bool = False
    metadata: dict[str, Any] | None = None

    @field_validator("credential")
    @classmethod
    def _blank_to_none(cls, v: str | None) -> str | None:
        return v.strip() or None if v is not None else None

    @field_validator("metadata")
    @classmethod
    def _limit_metadata(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and len(json.dumps(v, default=str)) > 4096:
            raise ValueError("metadata must serialise to at most 4096 bytes")
        return v


class RiskFactorOut(BaseModel):
    code: str
    points: int
    description: str


class EvaluationResponse(BaseModel):
    event_id: str
    decision: DecisionLiteral
    risk_score: int = Field(ge=0, le=100)
    base_score: int
    classification: str
    identity_status: str
    authorisation_status: str
    credential_status: str
    credential_id: str | None
    risk_factors: list[RiskFactorOut]
    evaluated_at: datetime


class EventOut(ORMModel):
    id: str
    created_at: datetime
    merchant_id: str
    user_id: str | None
    agent_id: str | None
    credential_id: str | None
    action: str
    ip_address: str
    user_agent: str
    declared_agent: bool
    decision: DecisionLiteral
    risk_score: int
    base_score: int = BASE_SCORE
    classification: str
    identity_status: str
    authorisation_status: str
    credential_status: str
    risk_factors: list[RiskFactorOut]
    request_metadata: dict[str, Any] | None
    scenario: str | None


class DashboardSummary(BaseModel):
    total_requests: int
    allowed: int
    review: int
    blocked: int
    active_credentials: int
    revoked_credentials: int
    expired_credentials: int
    by_classification: dict[str, int]
    users: int
    merchants: int
    agents: int


class ScenarioInfo(BaseModel):
    key: str
    title: str
    description: str
    expected: DecisionLiteral


class ScenarioResult(BaseModel):
    scenario: ScenarioInfo
    requests_sent: int
    final: EvaluationResponse
    decisions: list[DecisionLiteral]
