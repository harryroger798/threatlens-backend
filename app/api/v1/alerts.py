from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_, select, func
from sqlalchemy.orm import Session, joinedload

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.models import (ALERT_STATES, Alert, AlertRule, Incident,
                        Indicator, IOC_TYPES, User)
from app.services.alerting import escalate_to_incident, transition_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _serialize(a: Alert) -> dict:
    ind = a.indicator
    return {
        "id": a.id,
        "title": a.title,
        "severity": a.severity,
        "severity_score": a.severity_score,
        "state": a.state,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        "incident_id": a.incident_id,
        "rule_id": a.rule_id,
        "assignee": {"id": a.assignee_id} if a.assignee_id else None,
        "indicator": {
            "id": ind.id, "value": ind.value, "type": ind.type, "tlp": ind.tlp,
            "confidence": ind.confidence, "internal_sightings": ind.internal_sightings,
        } if ind else None,
    }


@router.get("")
def list_alerts(
    db: Session = Depends(get_db),
    ctx=Depends(rbac_permission(perms.P_MANAGE_ALERTS)),
    state: str | None = None,
    severity: str | None = None,
    mine: bool = False,
    unassigned: bool = False,
    q: str | None = None,
    sort: str = "-created_at",
    page: int = 1,
    page_size: int = 25,
):
    stmt = select(Alert).options(joinedload(Alert.indicator))
    if state:
        stmt = stmt.where(Alert.state == state)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if mine:
        stmt = stmt.where(Alert.assignee_id == ctx.id)
    if unassigned:
        stmt = stmt.where(Alert.assignee_id.is_(None))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.join(Indicator, Alert.indicator_id == Indicator.id).where(
            or_(func.lower(Alert.title).like(like), func.lower(Indicator.value).like(like))
        )
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()

    order = {
        "-created_at": Alert.created_at.desc(),
        "created_at": Alert.created_at.asc(),
        "-severity_score": Alert.severity_score.desc(),
        "severity_score": Alert.severity_score.asc(),
    }
    stmt = stmt.order_by(order.get(sort, Alert.created_at.desc()))
    page_size = min(max(page_size, 1), 200)
    page = max(page, 1)
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).unique().scalars().all()
    return {"total": total, "page": page, "page_size": page_size, "items": [_serialize(a) for a in rows]}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_ALERTS))):
    rules = db.execute(select(AlertRule)).scalars().all()
    return [
        {
            "id": r.id, "name": r.name, "enabled": r.enabled, "min_score": r.min_score,
            "ioc_types": r.ioc_types, "feed_slugs": r.feed_slugs, "tags": r.tags,
            "require_internal_sighting": r.require_internal_sighting,
            "route_to_role": r.route_to_role, "route_to_user_id": r.route_to_user_id,
        }
        for r in rules
    ]


class RuleIn(BaseModel):
    name: str
    enabled: bool = True
    min_score: int = 70
    ioc_types: list[str] | None = None
    feed_slugs: list[str] | None = None
    tags: list[str] | None = None
    require_internal_sighting: bool = False
    route_to_role: str | None = None
    route_to_user_id: str | None = None


def _validate_rule(body: RuleIn) -> None:
    if body.ioc_types is not None and any(t not in IOC_TYPES for t in body.ioc_types):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_type", "message": "Unknown IOC type in rule"})


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_ALERTS))):
    _validate_rule(body)
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="alert_rule.created",
                 entity_type="alert_rule", entity_id=rule.id, details={"name": rule.name, "min_score": rule.min_score})
    db.commit()
    return {"ok": True, "id": rule.id}


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_ALERTS))):
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Rule not found"})
    _validate_rule(body)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="alert_rule.updated",
                 entity_type="alert_rule", entity_id=rule.id, details={"name": rule.name})
    db.commit()
    return {"ok": True}


class AlertPatchIn(BaseModel):
    state: str | None = None
    assignee_id: str | None = None
    escalate_to_incident_id: str | None = None
    new_incident_title: str | None = None


@router.patch("/{alert_id}")
def patch_alert(alert_id: str, body: AlertPatchIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_ALERTS))):
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalars().first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Alert not found"})

    before_state = alert.state
    detail_out: dict = {"alert_id": alert.id}

    if body.assignee_id:
        assignee = db.get(User, body.assignee_id)
        if assignee is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Assignee not found"})
        alert.assignee_id = assignee.id

    if body.escalate_to_incident_id:
        incident = db.get(Incident, body.escalate_to_incident_id)
        if incident is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
        escalate_to_incident(db, alert, incident)
        if alert.state == "new":
            transition_alert(db, alert, "acknowledged")
    elif body.new_incident_title:
        incident = Incident(
            title=body.new_incident_title,
            description=f"Auto-created from alert escalation by {ctx.email}",
            severity=alert.severity,
            status="open",
            lead_id=ctx.id,
            alert_ids=[alert.id],
            indicator_ids=[alert.indicator_id],
            containment_checklist=[
                {\'text\': \'Isolate affected hosts\', \'done\': False},
                {\'text\': \'Block indicators at perimeter\', \'done\': False},
                {\'text\': \'Rotate exposed credentials\', \'done\': False},
                {\'text\': \'Preserve forensic evidence\', \'done\': False},
            ],
        )
        db.add(incident)
        db.flush()
        escalate_to_incident(db, alert, incident)
        if alert.state == "new":
            transition_alert(db, alert, "acknowledged")
        detail_out["incident_id"] = incident.id

    if body.state:
        try:
            transition_alert(db, alert, body.state, actor_email=ctx.email)
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"error_code": "invalid_transition", "message": str(exc)})

    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="alert.updated",
                 entity_type="alert", entity_id=alert.id,
                 details={"from_state": before_state, "to_state": alert.state,
                          "assignee": body.assignee_id, "escalated": bool(body.escalate_to_incident_id or body.new_incident_title)})
    db.commit()
    detail_out.update(_serialize(alert))
    return detail_out

