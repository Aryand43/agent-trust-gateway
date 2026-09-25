"""First-start demo data: DemoShop, Alex Tan, Shopping Assistant, one authorisation, sample events."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.crypto import KeyManager
from app.logging_config import get_logger
from app.models import Agent, Authorisation, Merchant, User
from app.services.scenarios import (
    DEMO_AGENT_ID,
    DEMO_AUTHORISATION_ID,
    DEMO_MERCHANT_ID,
    DEMO_USER_ID,
    run_scenario,
)
from app.timeutils import utcnow

log = get_logger("seed")

# (scenario, minutes ago) — spread over past hours so they don't trip live velocity windows.
_SEED_EVENTS: list[tuple[str, int]] = [
    ("human", 300),
    ("legitimate", 280),
    ("legitimate", 250),
    ("unauthorised_scope", 220),
    ("expired", 190),
    ("human", 160),
    ("invalid_signature", 140),
    ("revoked", 120),
    ("high_velocity", 90),
    ("legitimate", 45),
]


def seed_if_empty(session: Session, keys: KeyManager, ttl_seconds: int) -> bool:
    if session.get(Merchant, DEMO_MERCHANT_ID) is not None:
        return False

    now = utcnow()
    created = now - timedelta(hours=6)
    session.add_all([
        Merchant(id=DEMO_MERCHANT_ID, name="DemoShop", created_at=created),
        User(id=DEMO_USER_ID, name="Alex Tan", email="alex.tan@example.com", created_at=created),
        Agent(id=DEMO_AGENT_ID, name="Shopping Assistant", operator="Example Agents Inc.", created_at=created),
    ])
    session.flush()
    session.add(Authorisation(
        id=DEMO_AUTHORISATION_ID, user_id=DEMO_USER_ID, merchant_id=DEMO_MERCHANT_ID,
        agent_id=DEMO_AGENT_ID, scopes=["browse", "search"], created_at=created,
    ))
    session.commit()

    for scenario, minutes_ago in _SEED_EVENTS:
        run_scenario(session, keys, scenario, ttl_seconds=ttl_seconds,
                     now=now - timedelta(minutes=minutes_ago), burst=6)
    log.info("demo_data_seeded", extra={"ctx": {"merchant_id": DEMO_MERCHANT_ID}})
    return True
