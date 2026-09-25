"""Users, merchants, agents, authorisations and credential lifecycle."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.credentials import issue_credential
from app.crypto import KeyManager
from app.errors import AppError, ConflictError, NotFoundError
from app.logging_config import get_logger
from app.models import Agent, Authorisation, Credential, Merchant, User
from app.schemas import (
    AgentCreate,
    AuthorisationCreate,
    CredentialOut,
    IssuedCredential,
    MerchantCreate,
    UserCreate,
)
from app.timeutils import utcnow

log = get_logger("registry")


def _new_id(prefix: str, name: str | None = None) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")[:24]
    suffix = secrets.token_hex(3)
    return f"{prefix}_{slug}_{suffix}" if slug else f"{prefix}_{suffix}"


def _require(session: Session, model: type, obj_id: str, label: str):  # type: ignore[no-untyped-def]
    obj = session.get(model, obj_id)
    if obj is None:
        raise NotFoundError(label, obj_id)
    return obj


def create_user(session: Session, data: UserCreate) -> User:
    user_id = data.id or _new_id("usr", data.name)
    if session.get(User, user_id):
        raise ConflictError(f"User '{user_id}' already exists")
    user = User(id=user_id, name=data.name, email=data.email)
    session.add(user)
    session.commit()
    log.info("user_created", extra={"ctx": {"user_id": user.id}})
    return user


def create_merchant(session: Session, data: MerchantCreate) -> Merchant:
    merchant_id = data.id or _new_id("mer", data.name)
    if session.get(Merchant, merchant_id):
        raise ConflictError(f"Merchant '{merchant_id}' already exists")
    merchant = Merchant(id=merchant_id, name=data.name)
    session.add(merchant)
    session.commit()
    log.info("merchant_created", extra={"ctx": {"merchant_id": merchant.id}})
    return merchant


def create_agent(session: Session, data: AgentCreate) -> Agent:
    agent_id = data.id or _new_id("agt", data.name)
    if session.get(Agent, agent_id):
        raise ConflictError(f"Agent '{agent_id}' already exists")
    agent = Agent(id=agent_id, name=data.name, operator=data.operator)
    session.add(agent)
    session.commit()
    log.info("agent_created", extra={"ctx": {"agent_id": agent.id}})
    return agent


def credential_out(row: Credential, now: datetime | None = None) -> CredentialOut:
    out = CredentialOut.model_validate(row)
    out.status = row.status_at(now or utcnow())
    return out


def issue_for_authorisation(
    session: Session,
    keys: KeyManager,
    authorisation: Authorisation,
    *,
    ttl: timedelta,
    now: datetime | None = None,
) -> IssuedCredential:
    now = now or utcnow()
    claims, token = issue_credential(
        keys,
        user_id=authorisation.user_id,
        merchant_id=authorisation.merchant_id,
        agent_id=authorisation.agent_id,
        scopes=authorisation.scopes,
        ttl=ttl,
        now=now,
    )
    row = Credential(
        id=claims.cid,
        authorisation_id=authorisation.id,
        user_id=claims.sub,
        merchant_id=claims.mid,
        agent_id=claims.aid,
        scopes=list(claims.scope),
        key_id=claims.kid,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )
    session.add(row)
    session.commit()
    log.info(
        "credential_issued",
        extra={"ctx": {"credential_id": row.id, "authorisation_id": authorisation.id,
                       "scopes": row.scopes, "expires_at": row.expires_at.isoformat()}},
    )
    return IssuedCredential(credential=credential_out(row, now), token=token, claims=claims.to_dict())


def create_authorisation(
    session: Session,
    keys: KeyManager,
    data: AuthorisationCreate,
    *,
    default_ttl_seconds: int,
    now: datetime | None = None,
) -> tuple[Authorisation, IssuedCredential]:
    _require(session, User, data.user_id, "User")
    _require(session, Merchant, data.merchant_id, "Merchant")
    _require(session, Agent, data.agent_id, "Agent")
    now = now or utcnow()
    authorisation = Authorisation(
        id=_new_id("auth"),
        user_id=data.user_id,
        merchant_id=data.merchant_id,
        agent_id=data.agent_id,
        scopes=list(data.scopes),
        created_at=now,
    )
    session.add(authorisation)
    session.commit()
    ttl = timedelta(seconds=data.ttl_seconds or default_ttl_seconds)
    issued = issue_for_authorisation(session, keys, authorisation, ttl=ttl, now=now)
    return authorisation, issued


def get_authorisation(session: Session, authorisation_id: str) -> Authorisation:
    return _require(session, Authorisation, authorisation_id, "Authorisation")


def revoke_credential(
    session: Session, credential_id: str, reason: str, now: datetime | None = None
) -> Credential:
    row: Credential = _require(session, Credential, credential_id, "Credential")
    if row.revoked_at is not None:
        raise AppError(409, "already_revoked", f"Credential '{credential_id}' is already revoked")
    row.revoked_at = now or utcnow()
    row.revoked_reason = reason
    session.commit()
    log.info("credential_revoked", extra={"ctx": {"credential_id": row.id, "reason": reason}})
    return row


def list_credentials(session: Session, status: str | None = None, limit: int = 100) -> list[CredentialOut]:
    now = utcnow()
    rows = session.scalars(select(Credential).order_by(Credential.issued_at.desc()).limit(500)).all()
    out = [credential_out(r, now) for r in rows]
    if status:
        out = [c for c in out if c.status == status]
    return out[:limit]
