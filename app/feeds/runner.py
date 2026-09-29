"""Feed scheduler: background worker that polls each enabled feed on its own
schedule (independent so one slow source never blocks others), normalises and
deduplicates records, then runs the post-ingest pipeline. Runs in its own
thread with a dedicated DB session; idempotent and replay-safe."""
import threading
import time
import traceback
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.audit import record as audit_record
from app.db import SessionLocal
from app.feeds.adapters import run_adapter
from app.models import Feed
from app.services.bus import publish
from app.services.ingest import full_pipeline, ingest_batch


class FeedScheduler(threading.Thread):
    def __init__(self, poll_granularity_seconds: int = 30):
        super().__init__(daemon=True, name="feed-scheduler")
        self.granularity = poll_granularity_seconds
        self._stop = threading.Event()
        self.last_results: list[dict] = []

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                traceback.print_exc()
            self._stop.wait(self.granularity)

    def tick(self) -> list[dict]:
        db = SessionLocal()
        results: list[dict] = []
        try:
            feeds = db.execute(select(Feed).where(Feed.enabled.is_(True))).scalars().all()
            now = datetime.now(timezone.utc)
            for feed in feeds:
                due = (
                    feed.last_polled_at is None
                    or (now - _aware(feed.last_polled_at)).total_seconds() >= feed.poll_interval_seconds
                )
                if not due:
                    continue
                results.append(self.poll_feed(db, feed))
                db.commit()
        finally:
            db.close()
        self.last_results = results
        return results

    def poll_feed(self, db, feed: Feed) -> dict:
        records, error = run_adapter(feed.slug, feed)
        stats = {"created": 0, "merged": 0, "skipped": 0}
        if records:
            stats = ingest_batch(db, records, feed=feed)
            feed.items_ingested += stats["created"] + stats["merged"]
            feed.last_status = "ok"
            feed.last_error = error
        else:
            feed.last_status = "error"
            feed.last_error = error
        feed.last_polled_at = datetime.now(timezone.utc)
        audit_record(
            db,
            actor_id=None, actor_email="system@feed-scheduler",
            action="feed.poll", entity_type="feed", entity_id=feed.id,
            details={"slug": feed.slug, "records": len(records), **stats, "error": error},
        )
        publish("system.health", {"feed": feed.slug, "status": feed.last_status, "at": feed.last_polled_at.isoformat()})
        db.commit()
        return {"feed": feed.slug, "records": len(records), **stats, "error": error}


def _aware(dt) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


scheduler: FeedScheduler | None = None


def start_scheduler() -> FeedScheduler:
    global scheduler
    if scheduler is None or not scheduler.is_alive():
        scheduler = FeedScheduler()
        scheduler.start()
    return scheduler
