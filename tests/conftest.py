"""Shared test setup: one isolated temp DB per run, initialised + seeded once."""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.gettempdir()}/threatlens_pytest_{os.getpid()}.db"

from fastapi.testclient import TestClient  # noqa: E402
from app.db import init_db  # noqa: E402
from app.seed import run_seed  # noqa: E402
from app.main import app  # noqa: E402

init_db()
run_seed()

from app.feeds.runner import FeedScheduler, scheduler as _sched_mod  # noqa: E402

if _sched_mod is None:
    _sched = FeedScheduler(poll_granularity_seconds=3600)
    _sched.start()
    import app.feeds.runner as _runner

    _runner.scheduler = _sched

client = TestClient(app)
