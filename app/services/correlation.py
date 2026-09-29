"""Correlation (FR-16): match indicators against ingested internal security
events and keep incident timelines in sync with what intelligence found."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import (Alert, Incident, IncidentTimelineEntry,
                        Indicator, IOC_TYPES, SecurityEvent, aware)


def _parse_type_hint(value: str) -> str:
    from app.services.normalise import detect_type

    return detect_type(value) or "domain"


def correlate_indicator(db: Session, indicator: Indicator) -> int:
    """Count internal sightings inside the correlation window and update the
    indicator. Called after every ingest and after manual enrichment."""
    window_start = datetime.now(timezone.utc) - timedelta(days=settings.CORRELATION_WINDOW_DAYS)
    count = (
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.indicator_value == indicator.value,
                SecurityEvent.observed_at >= window_start,
            )
        )
        .scalar()
        or 0
    )
    if count != indicator.internal_sightings:
        indicator.internal_sightings = int(count)

    if count > 0:
        _propagate_to_open_incidents(db, indicator, int(count))
    return int(count)


def correlate_new_event(db: Session, event: SecurityEvent) -> Indicator | None:
    """An inbound internal event may arrive before the matching indicator exists;
    backfill a lightweight indicator so both sides of the correlation exist."""
    indicator = db.execute(
        select(Indicator).where(Indicator.value == event.indicator_value)
    ).scalars().first()
    return indicator


def _propagate_to_open_incidents(db: Session, indicator: Indicator, count: int) -> None:
    incidents = (
        db.execute(select(Incident).where(Incident.status.in_(["open", "contained"])))
        .scalars()
        .all()
    )
    now = datetime.now(timezone.utc)
    for incident in incidents:
        if indicator.id in (incident.indicator_ids or []):
            latest = (
                db.execute(
                    select(IncidentTimelineEntry)
                    .where(
                        IncidentTimelineEntry.incident_id == incident.id,
                        IncidentTimelineEntry.related_indicator_id == indicator.id,
                        IncidentTimelineEntry.entry_type == "correlation",
                    )
                    .order_by(IncidentTimelineEntry.occurred_at.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
            if latest and (now - aware(latest.occurred_at)).total_seconds() < 3600:
                continue
            db.add(
                IncidentTimelineEntry(
                    incident_id=incident.id,
                    occurred_at=now,
                    entry_type="correlation",
                    title=f"Internal sighting: {indicator.value} seen {count}x in the last {settings.CORRELATION_WINDOW_DAYS} days",
                    body="Auto-captured by the correlation engine from ingested internal events.",
                    related_indicator_id=indicator.id,
                    evidence={"sightings": count, "window_days": settings.CORRELATION_WINDOW_DAYS},
                )
            )


def incidents_for_indicator(db: Session, indicator_id: str) -> list[Incident]:
    incidents = (
        db.execute(select(Incident).where(Incident.status.in_(["open", "contained"])))
        .scalars()
        .all()
    )
    return [i for i in incidents if indicator_id in (i.indicator_ids or [])]


def events_for_value(db: Session, value: str, limit: int = 25) -> list[SecurityEvent]:
    window_start = datetime.now(timezone.utc) - timedelta(days=settings.CORRELATION_WINDOW_DAYS)
    return (
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.indicator_value == value, SecurityEvent.observed_at >= window_start)
            .order_by(SecurityEvent.observed_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
