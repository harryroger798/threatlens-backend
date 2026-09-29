"""Alert rule engine (FR-17) and lifecycle transitions (FR-18)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (ALERT_STATES, Alert, AlertRule, Feed, Indicator,
                        IndicatorTag, Incident, IncidentTimelineEntry, Tag)
from app.services import scoring
from app.services.bus import publish


def _rule_matches(rule: AlertRule, indicator: Indicator, feed_slugs: set[str]) -> bool:
    if not rule.enabled:
        return False
    if indicator.severity_score < rule.min_score:
        return False
    if rule.ioc_types and indicator.type not in rule.ioc_types:
        return False
    if rule.require_internal_sighting and indicator.internal_sightings < 1:
        return False
    if rule.feed_slugs and not feed_slugs:
        return False
    if rule.tags:
        ind_tags = {t.tag.name for t in indicator.tags}
        if not ind_tags.intersection(rule.tags):
            return False
    return True


def evaluate_rules_for_indicator(db: Session, indicator: Indicator) -> list[Alert]:
    """Raise an alert for every matching enabled rule, unless the same
    indicator+rule pair raised one within the last 12 hours."""
    rules = db.execute(select(AlertRule)).scalars().all()
    feeds = db.execute(select(Feed)).scalars().all()
    feed_by_id = {f.id: f.slug for f in feeds}
    feed_slugs = {feed_by_id.get(s.feed_id) for s in indicator.sources if s.feed_id in feed_by_id}

    raised: list[Alert] = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=12)
    for rule in rules:
        if not _rule_matches(rule, indicator, feed_slugs):
            continue
        recent = (
            db.execute(
                select(Alert).where(
                    Alert.indicator_id == indicator.id,
                    Alert.rule_id == rule.id,
                    Alert.created_at >= cutoff,
                )
            )
            .scalars()
            .first()
        )
        if recent:
            continue
        severity = scoring.severity_for_score(indicator.severity_score)
        alert = Alert(
            title=_title(indicator, rule),
            severity=severity,
            severity_score=indicator.severity_score,
            indicator_id=indicator.id,
            rule_id=rule.id,
            state="new",
        )
        db.add(alert)
        db.flush()
        raised.append(alert)
    return raised


def _title(indicator: Indicator, rule: AlertRule) -> str:
    fam = f" [{indicator.malware_family}]" if indicator.malware_family else ""
    return f"{indicator.type.upper()} {indicator.value}{fam} hit rule '{rule.name}' (score {indicator.severity_score})"


VALID_TRANSITIONS = {
    "new": {"acknowledged", "resolved", "closed"},
    "acknowledged": {"in_progress", "resolved", "closed"},
    "in_progress": {"resolved", "closed"},
    "resolved": {"closed"},
    "closed": set(),
}


def transition_alert(db: Session, alert: Alert, new_state: str, actor_email: str | None = None,
                     assignee_id: str | None = None) -> Alert:
    if new_state not in ALERT_STATES:
        raise ValueError(f"unknown state {new_state}")
    if new_state != alert.state and new_state not in VALID_TRANSITIONS.get(alert.state, set()):
        raise ValueError(f"invalid transition {alert.state} -> {new_state}")
    now = datetime.now(timezone.utc)
    alert.state = new_state
    if assignee_id:
        alert.assignee_id = assignee_id
    if new_state == "acknowledged":
        alert.acknowledged_at = now
    if new_state == "resolved":
        alert.resolved_at = now
    if new_state in ("resolved", "closed") and alert.incident_id is None:
        _auto_timeline(db, alert, actor_email, new_state)
    publish("alerts.stream", {
        "id": alert.id, "title": alert.title, "severity": alert.severity,
        "state": alert.state, "indicator_id": alert.indicator_id,
        "assignee_id": alert.assignee_id,
    })
    return alert


def _auto_timeline(db: Session, alert: Alert, actor_email: str | None, state: str) -> None:
    if not alert.incident_id:
        return
    db.add(
        IncidentTimelineEntry(
            incident_id=alert.incident_id,
            entry_type="analyst_action",
            actor_email=actor_email,
            title=f"Alert '{alert.title}' → {state}",
            body=None,
            related_indicator_id=alert.indicator_id,
            evidence={"alert_id": alert.id, "state": state},
        )
    )


def escalate_to_incident(db: Session, alert: Alert, incident: Incident) -> None:
    alert.incident_id = incident.id
    ids = incident.alert_ids or []
    if alert.id not in ids:
        ids.append(alert.id)
        incident.alert_ids = ids
    ind_ids = incident.indicator_ids or []
    if alert.indicator_id not in ind_ids:
        ind_ids.append(alert.indicator_id)
        incident.indicator_ids = ind_ids
    indicator = db.get(Indicator, alert.indicator_id)
    db.add(
        IncidentTimelineEntry(
            incident_id=incident.id,
            entry_type="analyst_action",
            title=f"Alert escalated into incident: {alert.title}",
            body=f"Indicator {indicator.value if indicator else alert.indicator_id} linked to the incident.",
            related_indicator_id=alert.indicator_id,
            evidence={"alert_id": alert.id},
        )
    )
