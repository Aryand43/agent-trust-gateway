"""Runtime configuration, read from environment variables with local-friendly defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("ATG_DATA_DIR", "data")))
    database_url: str = ""
    key_path: Path | None = None
    credential_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("ATG_CREDENTIAL_TTL_SECONDS", "900"))
    )
    seed_demo_data: bool = field(default_factory=lambda: _env_bool("ATG_SEED_DEMO_DATA", True))
    log_level: str = field(default_factory=lambda: os.getenv("ATG_LOG_LEVEL", "INFO"))
    cors_origins: list[str] = field(
        default_factory=lambda: _env_list(
            "ATG_CORS_ORIGINS",
            ["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000"],
        )
    )

    def __post_init__(self) -> None:
        # Derive paths from data_dir unless explicitly provided.
        if not self.database_url:
            default_db = f"sqlite:///{self.data_dir / 'agent_trust.db'}"
            object.__setattr__(self, "database_url", os.getenv("ATG_DATABASE_URL", default_db))
        if self.key_path is None:
            default_key = self.data_dir / "demo_ed25519_private.pem"
            object.__setattr__(self, "key_path", Path(os.getenv("ATG_KEY_PATH", str(default_key))))
