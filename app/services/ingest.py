"""Ingestion service: normalise → dedupe (canonical merge with provenance) →
score → enrich-hook → correlate → alert. Idempotent and replay-safe (NFR-07):
re-ingesting an identical record refreshes provenance instead of duplicating."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import (Alert, AlertRule, Enrichment, Feed, Indicator,
                        IndicatorSource, Incident, IOC_TYPES, IOC_STATUSES,
                        SecurityEvent, aware)
from app.services import scoring
from app.services import normalise as norm
from app.services.alerting import evaluate_rules_for_indicator
from app.services.correlation import correlate_indicator


def upsert_source_provenance(
    db: Session,
    indicator: Indicator,
    *,
    feed: Feed | None,
    source_name: str,
    source_confidence: int,
    seen_at: datetime | None = None,
    reference: str | None = None,
) -> None:
    if feed is not None:
        existing = (
            db.execute(
                select(IndicatorSource).where(
                    IndicatorSource.indicator_id == indicator.id,
                    IndicatorSource.feed_id == feed.id,
                )
            )
            .scalars()
            .first()
        )
    else:
        existing = (
            db.execute(
                select(IndicatorSource).where(
                    IndicatorSource.indicator_id == indicator.id,
                    IndicatorSource.source_name == source_name,
                )
            )
            .scalars()
            .first()
        )
    seen_at = aware(seen_at or datetime.now(timezone.utc))
    if existing:
        existing.last_seen = max(aware(existing.last_seen), seen_at)
        existing.source_confidence = max(existing.source_confidence, source_confidence)
        if reference and not existing.reference:
            existing.reference = reference
        return
    db.add(
        IndicatorSource(
            indicator_id=indicator.id,
            feed_id=feed.id if feed else None,
            source_name=source_name,
            source_confidence=source_confidence,
            first_seen=seen_at,
            last_seen=seen_at,
            reference=reference,
        )
    )


def ingest_indicator(
    db: Session,
    *,
    value: str,
    hint_type: str | None = None,
    feed: Feed | None = None,
    source_name: str | None = None,
    source_confidence: int = 50,
    seen_at: datetime | None = None,
    description: str | None = None,
    malware_family: str | None = None,
    tlp: str = "green",
    reference: str | None = None,
    kill_chain_phase: str | None = None,
    tag_names: list[str] | None = None,
) -> Indicator | None:
    parsed = norm.normalise(value, hint_type)
    if parsed is None:
        return None
    canonical_value, ioc_type = parsed
    seen_at = seen_at or datetime.now(timezone.utc)
    source_name = source_name or (feed.name if feed else "manual")

    indicator = (
        db.execute(
            select(Indicator).where(Indicator.value == canonical_value, Indicator.type == ioc_type)
        )
        .scalars()
        .first()
    )

    if indicator is None:
        indicator = Indicator(
            value=canonical_value,
            type=ioc_type,
            tlp=tlp or (feed.default_tlp if feed else "amber"),
            description=description,
            malware_family=malware_family,
            kill_chain_phase=kill_chain_phase,
            first_seen=seen_at,
            last_seen=seen_at,
            status="active",
        )
        db.add(indicator)
        db.flush()
    else:
        indicator.last_seen = max(aware(indicator.last_seen), aware(seen_at))
        if description and not indicator.description:
            indicator.description = description
        if malware_family and not indicator.malware_family:
            indicator.malware_family = malware_family
        # Re-activate on fresh external evidence unless explicitly whitelisted
        if indicator.status in ("expired", "under_review") and not indicator.ttl_days:
            indicator.status = "active"

    upsert_source_provenance(
        db, indicator,
        feed=feed, source_name=source_name, source_confidence=source_confidence,
        seen_at=seen_at, reference=reference,
    )
    if tag_names:
        _attach_tags(db, indicator, tag_names)

    _apply_ttl(indicator)
    db.flush()  # persist new/updated provenance before scoring reads the collection
    _rescore(db, indicator)
    db.flush()
    return indicator


def _attach_tags(db: Session, indicator: Indicator, names: list[str]) -> None:
    from app.models import IndicatorTag, Tag

    for name in names:
        name = name.strip().lower()
        if not name:
            continue
        tag = db.execute(select(Tag).where(Tag.name == name)).scalars().first()
        if not tag:
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
        link = db.execute(
            select(IndicatorTag).where(
                IndicatorTag.indicator_id == indicator.id, IndicatorTag.tag_id == tag.id
            )
        ).scalars().first()
        if not link:
            db.add(IndicatorTag(indicator_id=indicator.id, tag_id=tag.id))


def _apply_ttl(indicator: Indicator) -> None:
    """FR-08: configurable TTL ages stale indicators out of active status."""
    ttl_days = indicator.ttl_days or 30
    indicator.expires_at = aware(indicator.last_seen) + timedelta(days=ttl_days)
    now = datetime.now(timezone.utc)
    if indicator.expires_at < now and indicator.status == "active":
        indicator.status = "expired"


def _rescore(db: Session, indicator: Indicator) -> None:
    # Sources may have been added via pk FK this session; refresh the collection
    # so confidence/scoring always derives from the full provenance list.
    db.expire(indicator, ["sources"])
    confidences = [s.source_confidence for s in indicator.sources]
    feed_reputation = None
    if indicator.sources:
        feed_reputation = max((s.source_confidence for s in indicator.sources), default=None)
    indicator.confidence = scoring.aggregate_confidence(confidences)
    indicator.severity_score = scoring.compute_score(
        source_reputation=scoring.source_reputation(confidences, feed_reputation),
        confidence=indicator.confidence,
        last_seen=indicator.last_seen,
        internal_sightings=indicator.internal_sightings,
        ioc_type=indicator.type,
    )


def refresh_score(db: Session, indicator: Indicator) -> None:
    _rescore(db, indicator)


def reindex_search(db: Session, indicator: Indicator) -> None:
    """Search index projection hook. With the SQLite/Postgres path the search API
    queries the canonical store directly (same access pattern); the method is the
    seam where an Elasticsearch/OpenSearch projector would be registered."""
    return None


def full_pipeline(db: Session, indicator: Indicator) -> dict:
    """Post-ingest pipeline: correlation → alerting → projection."""
    from app.services.bus import publish

    result = {"correlated_events": 0, "alerts_raised": []}
    result["correlated_events"] = correlate_indicator(db, indicator)
    db.flush()

    created = evaluate_rules_for_indicator(db, indicator)
    db.flush()
    result["alerts_raised"] = [a.id for a in created]

    severity = scoring.severity_for_score(indicator.severity_score)
    if indicator.severity_score >= 70:  # high_severity channel threshold (PRD §10.3)
        publish("indicators.high_severity", {
            "id": indicator.id, "value": indicator.value, "type": indicator.type,
            "severity": severity, "severity_score": indicator.severity_score,
        })
    for alert in created:
        publish("alerts.stream", {
            "id": alert.id, "title": alert.title, "severity": alert.severity,
            "state": alert.state, "indicator_id": alert.indicator_id,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        })
    return result


def ingest_batch(
    db: Session,
    records: list[dict],
    *,
    feed: Feed | None,
) -> dict:
    """Feed-shaped batch ingest with per-record normalisation and dedupe stats."""
    created = 0
    merged = 0
    skipped = 0
    for rec in records:
        raw_value = rec.get("value") or rec.get("ioc") or rec.get("url") or rec.get("ip")
        if not raw_value:
            skipped += 1
            continue
        existing = None
        parsed = norm.normalise(str(raw_value), rec.get("type"))
        if parsed:
            existing = db.execute(
                select(Indicator).where(Indicator.value == parsed[0], Indicator.type == parsed[1])
            ).scalars().first()
        ind = ingest_indicator(
            db,
            value=str(raw_value),
            hint_type=rec.get("type"),
            feed=feed,
            source_confidence=rec.get("confidence", feed.source_confidence if feed else 50),
            seen_at=rec.get("seen_at"),
            description=rec.get("description"),
            malware_family=rec.get("malware_family"),
            tlp=rec.get("tlp", feed.default_tlp if feed else "amber"),
            reference=rec.get("reference"),
            tag_names=rec.get("tags"),
        )
        if ind is None:
            skipped += 1
        elif existing is not None:
            merged += 1
        else:
            created += 1
    db.flush()
    return {"created": created, "merged": merged, "skipped": skipped}
