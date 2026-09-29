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
    """One-time cleanup of test artifacts pushed during E2E verification sweeps.
    Uses raw SQL in FK dependency order to avoid constraint violations."""
    import sqlalchemy as sa
    from app.db import engine
    try:
        with engine.connect() as conn:
            # find e2e indicator ids first
            ind_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%'"
            )).fetchall()]
            inc_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%'"
            )).fetchall()]
            user_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%'"
            )).fetchall()]
            feed_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM feeds WHERE name LIKE '%E2E%' OR name LIKE '%e2e%'"
            )).fetchall()]
            hunt_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM hunts WHERE name LIKE '%sweep test%'"
            )).fetchall()]

            if not any([ind_ids, inc_ids, user_ids, feed_ids, hunt_ids]):
                return

            # clean children first (FK order)
            for iid in ind_ids:
                for tbl in ['indicator_tags', 'indicator_techniques', 'indicator_sources',
                            'enrichments', 'analyst_notes', 'indicator_relationships']:
                    conn.execute(sa.text(f'DELETE FROM {tbl} WHERE indicator_id = :iid'), {'iid': iid})
                conn.execute(sa.text('DELETE FROM indicator_relationships WHERE target_id = :iid'), {'iid': iid})
            for iid in inc_ids:
                conn.execute(sa.text('DELETE FROM incident_timeline WHERE incident_id = :iid'), {'iid': iid})
            for iid in ind_ids:
                conn.execute(sa.text('UPDATE alerts SET indicator_id = NULL WHERE indicator_id = :iid'), {'iid': iid})
                conn.execute(sa.text('DELETE FROM alerts WHERE indicator_id = :iid'), {'iid': iid})
            for uid in user_ids:
                conn.execute(sa.text('DELETE FROM refresh_tokens WHERE user_id = :uid'), {'uid': uid})
            for fid in feed_ids:
                conn.execute(sa.text('DELETE FROM indicator_sources WHERE feed_id = :fid'), {'fid': fid})

            # now delete parents
            for iid in inc_ids:
                conn.execute(sa.text('DELETE FROM incidents WHERE id = :iid'), {'iid': iid})
            for iid in ind_ids:
                conn.execute(sa.text('DELETE FROM indicators WHERE id = :iid'), {'iid': iid})
            for uid in user_ids:
                conn.execute(sa.text('DELETE FROM users WHERE id = :uid'), {'uid': uid})
            for fid in feed_ids:
                conn.execute(sa.text('DELETE FROM feeds WHERE id = :fid'), {'fid': fid})
            for hid in hunt_ids:
                conn.execute(sa.text('DELETE FROM hunts WHERE id = :hid'), {'hid': hid})

            conn.commit()
    except Exception:
        pass  # cleanup is best-effort, never blocks startup
