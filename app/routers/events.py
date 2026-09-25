"""Event log and dashboard summary."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.deps import get_session
from app.errors import NotFoundError
from app.models import Agent, Credential, Event, Merchant, User
from app.schemas import DashboardSummary, EventOut
from app.timeutils import utcnow

router = APIRouter(prefix="/api", tags=["events"])


@router.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    decision: Literal["allow", "review", "block"] | None = None,
    merchant_id: str | None = None,
    session: Session = Depends(get_session),
) -> list[Event]:
    stmt = select(Event).order_by(Event.created_at.desc()).limit(limit)
    if decision:
        stmt = stmt.where(Event.decision == decision)
    if merchant_id:
        stmt = stmt.where(Event.merchant_id == merchant_id)
    return list(session.scalars(stmt))


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: str, session: Session = Depends(get_session)) -> Event:
    event = session.get(Event, event_id)
    if event is None:
        raise NotFoundError("Event", event_id)
    return event


@router.get("/dashboard/summary", response_model=DashboardSummary)
def summary(session: Session = Depends(get_session)) -> DashboardSummary:
    decisions = dict(session.execute(select(Event.decision, func.count()).group_by(Event.decision)).all())
    classes = dict(session.execute(select(Event.classification, func.count()).group_by(Event.classification)).all())
    now = utcnow()
    creds = session.scalars(select(Credential)).all()
    cred_status = [c.status_at(now) for c in creds]

    def count(model: type) -> int:
        return session.scalar(select(func.count()).select_from(model)) or 0

    return DashboardSummary(
        total_requests=sum(decisions.values()),
        allowed=decisions.get("allow", 0),
        review=decisions.get("review", 0),
        blocked=decisions.get("block", 0),
        active_credentials=cred_status.count("active"),
        revoked_credentials=cred_status.count("revoked"),
        expired_credentials=cred_status.count("expired"),
        by_classification=classes,
        users=count(User),
        merchants=count(Merchant),
        agents=count(Agent),
    )
