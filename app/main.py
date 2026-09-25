"""Application factory. Run with ``uvicorn app.main:app --reload``."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings
from app.crypto import KeyManager
from app.db import create_db_engine, create_session_factory, init_db
from app.errors import register_error_handlers
from app.logging_config import configure_logging, get_logger
from app.routers import events, gateway, health, registry
from app.services.seed import seed_if_empty

STATIC_DIR = Path(__file__).parent / "static"
log = get_logger("app")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_db_engine(settings.database_url)
        init_db(engine)
        assert settings.key_path is not None
        app.state.settings = settings
        app.state.keys = KeyManager.load_or_create(settings.key_path)
        app.state.session_factory = create_session_factory(engine)
        if settings.seed_demo_data:
            with app.state.session_factory() as session:
                seed_if_empty(session, app.state.keys, settings.credential_ttl_seconds)
        log.info("startup_complete", extra={"ctx": {"version": __version__, "kid": app.state.keys.kid}})
        yield
        engine.dispose()

    app = FastAPI(
        title="Agent Trust Gateway (demo)",
        version=__version__,
        description=(
            "Risk-scoring and authorisation **prototype** for distinguishing humans, "
            "user-authorised AI agents and suspicious automation. Not production bot detection."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
    register_error_handlers(app)

    @app.middleware("http")
    async def access_log(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = uuid.uuid4().hex[:12]
        start = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        if request.url.path.startswith(("/api", "/health")):
            log.info("http_request", extra={"ctx": {
                "request_id": request_id, "method": request.method, "path": request.url.path,
                "status": response.status_code, "duration_ms": round((time.perf_counter() - start) * 1000, 1),
            }})
        return response

    for router in (health.router, registry.router, gateway.router, events.router):
        app.include_router(router)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
