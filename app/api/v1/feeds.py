"""Feeds management (FR-05): add/disable/re-poll from the UI without code changes."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.feeds.adapters import ADAPTERS
from app.feeds import runner as feed_runner
from app.models import Feed

router = APIRouter(prefix="/feeds", tags=["feeds"])


def _serialize(f: Feed) -> dict:
    return {
        "id": f.id, "name": f.name, "slug": f.slug, "provider": f.provider,
        "transport": f.transport, "url": f.url, "default_tlp": f.default_tlp,
        "source_confidence": f.source_confidence, "poll_interval_seconds": f.poll_interval_seconds,
        "enabled": f.enabled, "secret_ref": f.secret_ref,
        "last_polled_at": f.last_polled_at.isoformat() if f.last_polled_at else None,
        "last_status": f.last_status, "last_error": f.last_error,
        "items_ingested": f.items_ingested,
    }


@router.get("")
def list_feeds(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_CONFIGURE_FEEDS))):
    rows = db.execute(select(Feed).order_by(Feed.name)).scalars().all()
    return {"total": len(rows), "items": [_serialize(f) for f in rows], "known_adapters": sorted(ADAPTERS.keys())}


class FeedCreateIn(BaseModel):
    name: str
    provider: str
    transport: str = "http_json"
    url: str | None = None
    adapter_slug: str
    default_tlp: str = "green"
    source_confidence: int = 50
    poll_interval_seconds: int = 900
    enabled: bool = True
    secret_ref: str | None = None


@router.post("", status_code=201)
def create_feed(body: FeedCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_CONFIGURE_FEEDS))):
    if body.adapter_slug not in ADAPTERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "unknown_adapter", "message": f"Adapter must be one of {sorted(ADAPTERS)}"})
    slug = body.adapter_slug if body.adapter_slug != "reference" else f"custom-{body.name.lower().replace(' ', '-')}"
    existing = db.execute(select(Feed).where(Feed.slug == slug)).scalars().first()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"error_code": "conflict", "message": "A feed with this slug already exists"})
    feed = Feed(
        name=body.name, slug=slug, provider=body.provider, transport=body.transport,
        url=body.url, default_tlp=body.default_tlp, source_confidence=body.source_confidence,
        poll_interval_seconds=body.poll_interval_seconds, enabled=body.enabled,
        secret_ref=body.secret_ref, last_status=None,
    )
    db.add(feed)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="feed.created",
                 entity_type="feed", entity_id=feed.id, details={"slug": feed.slug, "adapter": body.adapter_slug})
    db.commit()
    return _serialize(feed)


@router.post("/{feed_id}/toggle")
def toggle_feed(feed_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_CONFIGURE_FEEDS))):
    feed = db.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Feed not found"})
    feed.enabled = not feed.enabled
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="feed.toggled",
                 entity_type="feed", entity_id=feed.id, details={"slug": feed.slug, "enabled": feed.enabled})
    db.commit()
    return _serialize(feed)


@router.post("/{feed_id}/poll")
def poll_feed_now(feed_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_CONFIGURE_FEEDS))):
    feed = db.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Feed not found"})
    if feed_runner.scheduler is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail={"error_code": "scheduler_down", "message": "Feed scheduler not running"})
    result = feed_runner.scheduler.poll_feed(db, feed)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="feed.manual_poll",
                 entity_type="feed", entity_id=feed.id, details={"slug": feed.slug, "result": {k: v for k, v in result.items() if k != "records"}})
    db.commit()
    return _serialize(feed) | {"poll_result": result}


class FeedUpdateIn(BaseModel):
    poll_interval_seconds: int | None = None
    source_confidence: int | None = None
    default_tlp: str | None = None
    enabled: bool | None = None


@router.patch("/{feed_id}")
def update_feed(feed_id: str, body: FeedUpdateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_CONFIGURE_FEEDS))):
    feed = db.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Feed not found"})
    changes = {}
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        setattr(feed, field, value)
        changes[field] = value
    if changes:
        audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="feed.updated",
                     entity_type="feed", entity_id=feed.id, details={"slug": feed.slug, "changes": changes})
        db.commit()
    return _serialize(feed)

