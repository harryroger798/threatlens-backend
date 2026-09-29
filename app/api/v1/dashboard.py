"""Aggregations for the four dashboards (PRD Â§12) â€” computed from the canonical
store; heavy analytics would move to the Elasticsearch projection at scale."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.models import (Alert, Feed, Incident, Indicator,
                        IndicatorSource, IOC_TYPES, SecurityEvent, User)
from app.services.scoring import severity_for_score

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _window(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


@router.get("/executive")
def executive_dashboard(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    now = datetime.now(timezone.utc)

    def count(stmt) -> int:
        return db.execute(stmt).scalar() or 0

    active_total = count(select(func.count(Indicator.id)).where(Indicator.status == "active"))
    critical = count(select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score >= 85))
    high = count(select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score >= 70, Indicator.severity_score < 85))
    new_alerts_24h = count(select(func.count(Alert.id)).where(Alert.created_at >= _window(1)))
    open_alerts = count(select(func.count(Alert.id)).where(Alert.state.in_(["new", "acknowledged", "in_progress"])))
    resolved_30d = count(select(func.count(Alert.id)).where(Alert.resolved_at >= _window(30), Alert.resolved_at.is_not(None)))
    open_incidents = count(select(func.count(Incident.id)).where(Incident.status == "open"))
    with_sightings = count(select(func.count(Indicator.id)).where(Indicator.internal_sightings > 0, Indicator.status == "active"))

    # 30-day trend: daily indicator volume + alert throughput
    days = []
    for i in range(29, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        alerts = db.execute(select(func.count(Alert.id)).where(Alert.created_at >= day_start, Alert.created_at < day_end)).scalar() or 0
        seen = db.execute(select(func.count(Indicator.id)).where(Indicator.last_seen >= day_start, Indicator.last_seen < day_end)).scalar() or 0
        days.append({"date": day_start.date().isoformat(), "alerts": int(alerts), "indicators_seen": int(seen)})

    categories = db.execute(select(Indicator.type, func.count(Indicator.id)).where(Indicator.status == "active").group_by(Indicator.type)).all()
    top_families = db.execute(
        select(Indicator.malware_family, func.count(Indicator.id))
        .where(Indicator.status == "active", Indicator.malware_family.is_not(None))
        .group_by(Indicator.malware_family).order_by(func.count(Indicator.id).desc()).limit(6)
    ).all()

    severity_dist = {"critical": critical, "high": high}
    medium = count(select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score >= 45, Indicator.severity_score < 70))
    low = count(select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score < 45))
    severity_dist["medium"] = medium
    severity_dist["low"] = low

    # headline risk score: volume-weighted mean of active severity
    mean_score = db.execute(select(func.avg(Indicator.severity_score)).where(Indicator.status == "active")).scalar()
    risk_score = int(round(mean_score)) if mean_score is not None else 0

    return {
        "risk_score": risk_score,
        "risk_trend": [d for d in days[-14:]],
        "active_indicators": active_total,
        "critical_count": critical,
        "high_count": high,
        "indicators_with_internal_sightings": with_sightings,
        "alerts_new_24h": new_alerts_24h,
        "alerts_open": open_alerts,
        "alerts_resolved_30d": resolved_30d,
        "open_incidents": open_incidents,
        "severity_distribution": severity_dist,
        "categories": [{"type": t, "count": int(c)} for t, c in categories],
        "top_malware_families": [{"family": f, "count": int(c)} for f, c in top_families],
        "throughput": days,
    }


@router.get("/analyst")
def analyst_dashboard(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    now = datetime.now(timezone.utc)
    new_count = db.execute(select(func.count(Alert.id)).where(Alert.state == "new")).scalar() or 0
    unassigned = db.execute(select(func.count(Alert.id)).where(Alert.state.in_(["new", "acknowledged"]), Alert.assignee_id.is_(None))).scalar() or 0
    mine = db.execute(select(func.count(Alert.id)).where(Alert.assignee_id == ctx.id, Alert.state.in_(["new", "acknowledged", "in_progress"]))).scalar() or 0
    in_progress = db.execute(select(func.count(Alert.id)).where(Alert.state == "in_progress")).scalar() or 0

    queue = db.execute(
        select(Alert).where(Alert.state.in_(["new", "acknowledged", "in_progress"])).order_by(Alert.severity_score.desc(), Alert.created_at.asc()).limit(50)
    ).scalars().all()

    alerts_out = []
    for a in queue:
        ind = db.get(Indicator, a.indicator_id)
        alerts_out.append({
            "id": a.id, "title": a.title, "severity": a.severity, "severity_score": a.severity_score,
            "state": a.state, "created_at": a.created_at.isoformat(),
            "assignee_id": a.assignee_id, "incident_id": a.incident_id,
            "indicator": {"id": ind.id, "value": ind.value, "type": ind.type, "tlp": ind.tlp,
                          "internal_sightings": ind.internal_sightings, "confidence": ind.confidence} if ind else None,
        })

    hourly = []
    for i in range(12, -1, -1):
        start = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
        c = db.execute(select(func.count(Alert.id)).where(Alert.created_at >= start, Alert.created_at < end)).scalar() or 0
        hourly.append({"hour": start.isoformat(), "alerts": int(c)})

    by_severity = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        by_severity[sev] = db.execute(select(func.count(Alert.id)).where(Alert.severity == sev, Alert.state.in_(["new", "acknowledged", "in_progress"]))).scalar() or 0

    return {
        "counters": {"new": int(new_count), "unassigned": int(unassigned), "mine": int(mine), "in_progress": int(in_progress)},
        "queue": alerts_out,
        "alerts_per_hour": hourly,
        "open_by_severity": by_severity,
    }


@router.get("/threat")
def threat_dashboard(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    """Aggregates for hunting: sources, kill-chain phases, geographic density."""
    sources = db.execute(
        select(IndicatorSource.source_name, func.count(func.distinct(IndicatorSource.indicator_id)))
        .group_by(IndicatorSource.source_name).order_by(func.count(func.distinct(IndicatorSource.indicator_id)).desc()).limit(10)
    ).all()

    # country density from enrichment geo + security events
    from app.models import Enrichment

    geo_rows = db.execute(select(Enrichment.data).where(Enrichment.kind == "geo")).scalars().all()
    country_counts: dict[str, int] = {}
    for data in geo_rows:
        c = (data or {}).get("country")
        if c:
            country_counts[c] = country_counts.get(c, 0) + 1
    event_countries = db.execute(select(SecurityEvent.country, func.count(SecurityEvent.id)).group_by(SecurityEvent.country)).all()
    for c, n in event_countries:
        if c:
            country_counts[c] = country_counts.get(c, 0) + int(n)

    volume_days = []
    now = datetime.now(timezone.utc)
    for i in range(13, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        counts = db.execute(
            select(Indicator.type, func.count(Indicator.id))
            .where(Indicator.first_seen >= day_start, Indicator.first_seen < day_end)
            .group_by(Indicator.type)
        ).all()
        volume_days.append({"date": day_start.date().isoformat(), **{t: int(n) for t, n in counts}})

    from app.models import IndicatorRelationship
    rel_count = db.execute(select(func.count(IndicatorRelationship.id))).scalar() or 0

    severity_dist = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        bands = [85, 70, 45, 25, 0]
        names = ["critical", "high", "medium", "low", "info"]
        idx = names.index(sev)
        lo, hi = bands[idx], (100 if idx == 0 else bands[idx - 1] - 1)
        severity_dist[sev] = int(db.execute(
            select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score >= lo, Indicator.severity_score <= hi)
        ).scalar() or 0)

    return {
        "top_sources": [{"source": s, "indicators": int(n)} for s, n in sources],
        "country_density": [{"country": c, "count": n} for c, n in sorted(country_counts.items(), key=lambda kv: -kv[1])][:40],
        "volume_by_day": volume_days,
        "severity_distribution": severity_dist,
        "relationship_count": int(rel_count),
    }


@router.get("/health")
def platform_health(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    feeds = db.execute(select(Feed)).scalars().all()
    feed_status = [
        {"slug": f.slug, "name": f.name, "enabled": f.enabled, "last_status": f.last_status,
         "last_polled_at": f.last_polled_at.isoformat() if f.last_polled_at else None,
         "last_error": f.last_error, "items_ingested": f.items_ingested}
        for f in feeds
    ]
    stale = sum(1 for f in feeds if f.enabled and (f.last_status or "") == "error")
    return {"feeds": feed_status, "feeds_in_error": stale, "feeds_total": len(feeds)}

