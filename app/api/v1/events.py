"""Inbound integration hook (FR-29): SIEM/EDR/ticketing push events in."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.core.config import settings
from app.models import Indicator, IOC_TYPES, SecurityEvent, User
from app.services.bus import publish
from app.services.correlation import correlate_indicator
from app.services.ingest import full_pipeline

router = APIRouter(prefix="/events", tags=["events"])


class EventIn(BaseModel):
    event_type: str = "http_request"
    indicator_value: str
    indicator_type: str | None = None
    observed_at: datetime | None = None
    asset: str | None = None
    source_system: str | None = None
    country: str | None = None
    raw: dict | None = None


@router.post("", status_code=202)
def ingest_event(events: list[EventIn] | EventIn, db: Session = Depends(get_db),
                 ctx=Depends(rbac_permission(perms.P_INGEST_EVENTS)),
                 x_api_key: str | None = Header(None)):
    if isinstance(events, EventIn):
        events = [events]
    accepted = 0
    rejected = 0
    for ev in events[:500]:
        from app.services.normalise import normalise

        parsed = normalise(ev.indicator_value, ev.indicator_type)
        if parsed is None:
            rejected += 1
            continue
        observed = ev.observed_at or datetime.now(timezone.utc)
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        db.add(
            SecurityEvent(
                observed_at=observed,
                event_type=ev.event_type[:64],
                indicator_value=parsed[0],
                indicator_type=parsed[1],
                asset=(ev.asset or "")[:255] or None,
                source_system=(ev.source_system or "")[:128] or None,
                country=(ev.country or "")[:2] or None,
                raw=ev.raw,
            )
        )
        accepted += 1
        # Backfill the indicator side of the correlation when absent
        ind = db.execute(select(Indicator).where(Indicator.value == parsed[0], Indicator.type == parsed[1])).scalars().first()
        if ind is None:
            from app.services.ingest import ingest_indicator

            ind = ingest_indicator(db, value=parsed[0], hint_type=parsed[1], source_name="internal-event-backfill",
                                   source_confidence=45, tlp="amber", seen_at=observed)
            if ind:
                full_pipeline(db, ind)
        else:
            correlate_indicator(db, ind)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="events.ingested",
                 entity_type="security_event", details={"accepted": accepted, "rejected": rejected})
    publish("system.health", {"events_accepted": accepted})
    db.commit()
    return {"accepted": accepted, "rejected": rejected}

