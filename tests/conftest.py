from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import Settings
from app.crypto import KeyManager
from app.db import create_db_engine, create_session_factory, init_db
from app.main import create_app
from app.models import Agent, Authorisation, Merchant, User
from app.services import registry
from app.timeutils import utcnow

USER, MERCHANT, AGENT, AUTH = "usr_test", "mer_test", "agt_test", "auth_test"


@pytest.fixture(scope="session")
def keys() -> KeyManager:
    return KeyManager.generate()


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'test.db'}")
    init_db(engine)
    factory = create_session_factory(engine)
    with factory() as s:
        s.add_all([
            User(id=USER, name="Test User"),
            Merchant(id=MERCHANT, name="Test Shop"),
            Merchant(id="mer_other", name="Other Shop"),
            Agent(id=AGENT, name="Test Agent"),
        ])
        s.flush()
        s.add(Authorisation(id=AUTH, user_id=USER, merchant_id=MERCHANT, agent_id=AGENT,
                            scopes=["browse", "search"]))
        s.commit()
        yield s
    engine.dispose()


@pytest.fixture
def issue(session: Session, keys: KeyManager):
    """Issue a credential from the test authorisation; returns (credential_id, token)."""

    def _issue(ttl_seconds: int = 900, issued_ago: int = 0) -> tuple[str, str]:
        auth = session.get(Authorisation, AUTH)
        issued = registry.issue_for_authorisation(
            session, keys, auth, ttl=timedelta(seconds=ttl_seconds),
            now=utcnow() - timedelta(seconds=issued_ago),
        )
        return issued.credential.id, issued.token

    return _issue


def make_settings(tmp_path: Path, seed: bool) -> Settings:
    return Settings(data_dir=tmp_path, seed_demo_data=seed, log_level="WARNING")


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(make_settings(tmp_path, seed=False))) as c:
        yield c


@pytest.fixture
def seeded_client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(make_settings(tmp_path, seed=True))) as c:
        yield c
