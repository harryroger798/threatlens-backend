import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from app.api.v1 import admin, alerts, auth, dashboard, events, feeds, incidents, indicators, intel, reports_export
from app.core.config import settings
from app.db import init_db
from app.services import enrichment  # ensure module import surfaces errors early
from app.services.bus import bus
from app.services.scoring import SEVERITY_BANDS  # noqa: F401
from app.ws import router as ws_router
from app.feeds.runner import start_scheduler, scheduler as _scheduler_ref


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from app.seed import run_seed

    run_seed()
    _cleanup_e2e()
    loop = asyncio.get_running_loop()
    bus.bind_loop(loop)
    start_scheduler()
    yield
    if _scheduler_ref is not None:
        _scheduler_ref.stop()


app = FastAPI(
    title="ThreatLens API",
    version=settings.APP_VERSION,
    description="Cyber Threat Intelligence Dashboard — REST + WebSocket API (OpenAPI 3, auto-generated).",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:4173", "http://127.0.0.1:4173",
        "http://localhost:8788", "http://127.0.0.1:8788",
        "https://threatlens-5f1.pages.dev",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-ThreatLens-API"] = settings.APP_VERSION
    return response


@app.exception_handler(HTTPException)
async def uniform_error_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if not isinstance(detail, dict):
        detail = {"error_code": "error", "message": str(detail)}
    return JSONResponse(
        status_code=exc.status_code,
        content={"error_code": detail.get("error_code", "error"), "message": detail.get("message", ""), "correlation_id": request.headers.get("x-correlation-id", "n/a")},
        headers=getattr(exc, "headers", None),
    )


@app.get("/health", tags=["system"])
@app.get("/api/v1/health", tags=["system"])
def health():
    from datetime import datetime, timezone

    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION, "time": datetime.now(timezone.utc).isoformat()}


app.include_router(auth.router, prefix="/api/v1")
app.include_router(indicators.router, prefix="/api/v1")
app.include_router(intel.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
app.include_router(feeds.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(reports_export.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(ws_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)


def _cleanup_e2e():
    """One-time cleanup of test artifacts pushed during E2E verification sweeps."""
    from app.db import SessionLocal
    from app.models import Feed, User, Incident, Indicator, Hunt
    from sqlalchemy import delete, or_, select
    db = SessionLocal()
    try:
        # feeds
        for feed in db.execute(select(Feed).where(or_(Feed.name.like('%E2E%'), Feed.name.like('%e2e%')))).scalars().all():
            db.delete(feed)
        # users
        for user in db.execute(select(User).where(or_(User.email.like('e2e-%'), User.name.like('%E2E%')))).scalars().all():
            db.delete(user)
        # incidents
        for inc in db.execute(select(Incident).where(or_(Incident.title.like('E2E%'), Incident.title.like('Escalation: %'), Incident.title.like('Retest incident%')))).scalars().all():
            db.delete(inc)
        # indicators
        for ind in db.execute(select(Indicator).where(or_(Indicator.value.like('e2e-%'), Indicator.value.like('live-alert-%'), Indicator.value.like('live-broadcast%')))).scalars().all():
            db.delete(ind)
        # hunts
        for hunt in db.execute(select(Hunt).where(Hunt.name.like('%sweep test%'))).scalars().all():
            db.delete(hunt)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
