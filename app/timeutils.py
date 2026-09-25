"""UTC time helpers. All timestamps in the system are timezone-aware UTC."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """SQLite drops tzinfo; treat naive datetimes as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_epoch(value: datetime) -> int:
    return int(ensure_utc(value).timestamp())


def from_epoch(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)
