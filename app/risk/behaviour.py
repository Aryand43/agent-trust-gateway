"""Behavioural signal extraction from recent event history.

Kept separate from the pure engine so the scoring logic has no database dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Event

VELOCITY_WINDOW = timedelta(seconds=60)
FAILURE_WINDOW = timedelta(minutes=5)
ACCOUNT_WINDOW = timedelta(minutes=10)
FINGERPRINT_WINDOW = timedelta(minutes=30)

_AUTOMATION_UA = re.compile(
    r"(python-requests|python-urllib|aiohttp|httpx|curl/|wget|go-http-client|okhttp|java/|"
    r"libwww|scrapy|headlesschrome|phantomjs|selenium|puppeteer|playwright|bot\b|crawler|spider)",
    re.IGNORECASE,
)


def is_automation_user_agent(user_agent: str) -> bool:
    return not user_agent.strip() or bool(_AUTOMATION_UA.search(user_agent))


@dataclass(frozen=True)
class BehaviourSignals:
    requests_last_minute: int
    recent_failures: int
    ip_changed: bool
    user_agent_changed: bool
    distinct_accounts_from_ip: int


def collect(
    session: Session,
    *,
    now: datetime,
    credential_id: str | None,
    ip_address: str,
    user_agent: str,
    user_id: str | None,
) -> BehaviourSignals:
    # Actor key: the credential when present, otherwise the source IP.
    actor = Event.credential_id == credential_id if credential_id else Event.ip_address == ip_address

    velocity = session.scalar(
        select(func.count()).where(actor, Event.created_at > now - VELOCITY_WINDOW, Event.created_at <= now)
    ) or 0

    failure_scope = or_(Event.ip_address == ip_address, actor)
    failures = session.scalar(
        select(func.count()).where(
            failure_scope,
            Event.decision != "allow",
            Event.created_at > now - FAILURE_WINDOW,
            Event.created_at <= now,
        )
    ) or 0

    accounts = set(
        session.scalars(
            select(Event.user_id).distinct().where(
                Event.ip_address == ip_address,
                Event.user_id.is_not(None),
                Event.created_at > now - ACCOUNT_WINDOW,
                Event.created_at <= now,
            )
        )
    )
    if user_id:
        accounts.add(user_id)

    ip_changed = ua_changed = False
    if credential_id:
        prior = session.execute(
            select(Event.ip_address, Event.user_agent).where(
                Event.credential_id == credential_id,
                Event.created_at > now - FINGERPRINT_WINDOW,
                Event.created_at <= now,
            )
        ).all()
        if prior:
            ip_changed = ip_address not in {row.ip_address for row in prior}
            ua_changed = user_agent not in {row.user_agent for row in prior}

    return BehaviourSignals(
        requests_last_minute=velocity,
        recent_failures=failures,
        ip_changed=ip_changed,
        user_agent_changed=ua_changed,
        distinct_accounts_from_ip=len(accounts),
    )
