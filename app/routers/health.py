from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.crypto import KeyManager
from app.deps import get_keys, get_session

router = APIRouter(tags=["health"])


@router.get("/health")
def health(session: Session = Depends(get_session), keys: KeyManager = Depends(get_keys)) -> dict[str, object]:
    session.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__, "database": "ok", "signing_key_id": keys.kid, "demo_only": True}
