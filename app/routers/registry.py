"""Users, merchants, agents, authorisations and credentials."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.crypto import KeyManager
from app.deps import get_keys, get_session, get_settings
from app.models import Agent, Authorisation, Merchant, User
from app.schemas import (
    AgentCreate,
    AgentOut,
    AuthorisationCreate,
    AuthorisationCreated,
    AuthorisationOut,
    CredentialOut,
    IssuedCredential,
    MerchantCreate,
    MerchantOut,
    RevokeRequest,
    UserCreate,
    UserOut,
)
from app.services import registry

router = APIRouter(prefix="/api", tags=["registry"])


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, session: Session = Depends(get_session)) -> User:
    return registry.create_user(session, body)


@router.get("/users", response_model=list[UserOut])
def list_users(session: Session = Depends(get_session)) -> list[User]:
    return list(session.scalars(select(User).order_by(User.created_at)))


@router.post("/merchants", response_model=MerchantOut, status_code=status.HTTP_201_CREATED)
def create_merchant(body: MerchantCreate, session: Session = Depends(get_session)) -> Merchant:
    return registry.create_merchant(session, body)


@router.get("/merchants", response_model=list[MerchantOut])
def list_merchants(session: Session = Depends(get_session)) -> list[Merchant]:
    return list(session.scalars(select(Merchant).order_by(Merchant.created_at)))


@router.post("/agents", response_model=AgentOut, status_code=status.HTTP_201_CREATED)
def create_agent(body: AgentCreate, session: Session = Depends(get_session)) -> Agent:
    return registry.create_agent(session, body)


@router.get("/agents", response_model=list[AgentOut])
def list_agents(session: Session = Depends(get_session)) -> list[Agent]:
    return list(session.scalars(select(Agent).order_by(Agent.created_at)))


@router.post("/authorisations", response_model=AuthorisationCreated, status_code=status.HTTP_201_CREATED)
def create_authorisation(
    body: AuthorisationCreate,
    session: Session = Depends(get_session),
    keys: KeyManager = Depends(get_keys),
    settings: Settings = Depends(get_settings),
) -> AuthorisationCreated:
    auth, issued = registry.create_authorisation(
        session, keys, body, default_ttl_seconds=settings.credential_ttl_seconds
    )
    return AuthorisationCreated(authorisation=AuthorisationOut.model_validate(auth), issued=issued)


@router.get("/authorisations", response_model=list[AuthorisationOut])
def list_authorisations(session: Session = Depends(get_session)) -> list[Authorisation]:
    return list(session.scalars(select(Authorisation).order_by(Authorisation.created_at.desc())))


@router.post(
    "/authorisations/{authorisation_id}/credentials",
    response_model=IssuedCredential,
    status_code=status.HTTP_201_CREATED,
)
def issue_credential(
    authorisation_id: str,
    session: Session = Depends(get_session),
    keys: KeyManager = Depends(get_keys),
    settings: Settings = Depends(get_settings),
) -> IssuedCredential:
    """Mint a fresh short-lived credential from an existing authorisation."""
    auth = registry.get_authorisation(session, authorisation_id)
    return registry.issue_for_authorisation(
        session, keys, auth, ttl=timedelta(seconds=settings.credential_ttl_seconds)
    )


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials(
    status_filter: Literal["active", "expired", "revoked"] | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
) -> list[CredentialOut]:
    return registry.list_credentials(session, status_filter, limit)


@router.post("/credentials/{credential_id}/revoke", response_model=CredentialOut)
def revoke_credential(
    credential_id: str,
    body: RevokeRequest | None = None,
    session: Session = Depends(get_session),
) -> CredentialOut:
    row = registry.revoke_credential(session, credential_id, (body or RevokeRequest()).reason)
    return registry.credential_out(row)


@router.get("/keys/public")
def public_key(keys: KeyManager = Depends(get_keys)) -> dict[str, str]:
    """Verifier key so a merchant could validate credentials independently."""
    return {"kid": keys.kid, "alg": "Ed25519", "public_key_pem": keys.public_key_pem()}
