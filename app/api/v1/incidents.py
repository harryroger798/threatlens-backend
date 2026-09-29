from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.models import (Alert, Incident, IncidentTimelineEntry, Indicator,
                        SEVERITIES, User)
from app.services.bus import publish

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _serialize(i: Incident, db: Session) -> dict:
    lead = db.get(User, i.lead_id) if i.lead_id else None
    indicator_count = len(i.indicator_ids or [])
    timeline_count = db.execute(
        select(func.count(IncidentTimelineEntry.id)).where(IncidentTimelineEntry.incident_id == i.id)
    ).scalar() or 0
    return {
        "id": i.id, "title": i.title, "description": i.description,
        "severity": i.severity, "status": i.status,
        "lead": {"id": lead.id, "name": lead.name, "email": lead.email} if lead else None,
        "indicator_ids": i.indicator_ids or [],
        "alert_ids": i.alert_ids or [],
        "containment_checklist": i.containment_checklist or [],
        "timeline_count": timeline_count,
        "indicator_count": indicator_count,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


@router.get("")
def list_incidents(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS)), status_filter: str | None = None):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    rows = db.execute(stmt).scalars().all()
    return {"total": len(rows), "items": [_serialize(i, db) for i in rows]}


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    data = _serialize(inc, db)
    indicators = db.execute(select(Indicator).where(Indicator.id.in_(inc.indicator_ids or []))).scalars().all()
    data["indicators"] = [
        {"id": i.id, "value": i.value, "type": i.type, "severity_score": i.severity_score,
         "tlp": i.tlp, "malware_family": i.malware_family, "internal_sightings": i.internal_sightings}
        for i in sorted(indicators, key=lambda x: -x.severity_score)
    ]
    return data


@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_DASHBOARDS))):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    entries = (
        db.execute(select(IncidentTimelineEntry).where(IncidentTimelineEntry.incident_id == incident_id).order_by(IncidentTimelineEntry.occurred_at.asc()))
        .scalars()
        .all()
    )
    rel = {i.id: i.value for i in db.execute(select(Indicator).where(Indicator.id.in_([e.related_indicator_id for e in entries if e.related_indicator_id]))).scalars().all()}
    return {
        "incident_id": incident_id,
        "entries": [
            {
                "id": e.id, "occurred_at": e.occurred_at.isoformat(), "entry_type": e.entry_type,
                "actor": e.actor_email, "title": e.title, "body": e.body,
                "related_indicator": {"id": e.related_indicator_id, "value": rel.get(e.related_indicator_id)} if e.related_indicator_id else None,
                "evidence": e.evidence,
            }
            for e in entries
        ],
    }


class IncidentCreateIn(BaseModel):
    title: str
    description: str | None = None
    severity: str = "high"
    indicator_ids: list[str] | None = None
    alert_ids: list[str] | None = None


@router.post("", status_code=201)
def create_incident(body: IncidentCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_INCIDENTS))):
    if body.severity not in SEVERITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_severity", "message": "Unknown severity"})
    incident = Incident(
        title=body.title, description=body.description, severity=body.severity,
        status="open", lead_id=ctx.id,
        indicator_ids=body.indicator_ids or [], alert_ids=body.alert_ids or [],
        containment_checklist=[
            {"text": "Isolate affected hosts", "done": False},
            {"text": "Block indicators at perimeter", "done": False},
            {"text": "Rotate exposed credentials", "done": False},
            {"text": "Preserve forensic evidence", "done": False},
        ],
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentTimelineEntry(
            incident_id=incident.id, entry_type="note", actor_email=ctx.email,
            title="Incident opened", body=body.description or body.title,
        )
    )
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="incident.created",
                 entity_type="incident", entity_id=incident.id, details={"title": incident.title, "severity": incident.severity})
    db.commit()
    return _serialize(incident, db)


class IncidentPatchIn(BaseModel):
    status: str | None = None
    title: str | None = None
    description: str | None = None
    lead_id: str | None = None


INCIDENT_STATUSES = ("open", "contained", "resolved", "closed")


@router.patch("/{incident_id}")
def patch_incident(incident_id: str, body: IncidentPatchIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_INCIDENTS))):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    changes = {}
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        if field == "status" and value not in INCIDENT_STATUSES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_status", "message": "Unknown incident status"})
        setattr(inc, field, value)
        changes[field] = value
    if changes:
        db.add(
            IncidentTimelineEntry(
                incident_id=inc.id, entry_type="analyst_action", actor_email=ctx.email,
                title=f"Incident updated: {', '.join(f'{k}â†’{v}' for k, v in changes.items())}",
            )
        )
        audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="incident.updated",
                     entity_type="incident", entity_id=inc.id, details={"changes": changes})
        publish("incidents." + inc.id, {"type": "updated", "status": inc.status})
        db.commit()
    return _serialize(inc, db)


class TimelineAddIn(BaseModel):
    entry_type: str = "note"
    title: str
    body: str | None = None
    related_indicator_id: str | None = None


@router.post("/{incident_id}/timeline", status_code=201)
def add_timeline_entry(incident_id: str, body: TimelineAddIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_INCIDENTS))):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    entry = IncidentTimelineEntry(
        incident_id=incident_id, entry_type=body.entry_type, actor_email=ctx.email,
        title=body.title, body=body.body, related_indicator_id=body.related_indicator_id,
        occurred_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="incident.timeline_added",
                 entity_type="incident", entity_id=incident_id, details={"entry": body.title})
    publish("incidents." + incident_id, {"type": "timeline", "entry_id": entry.id, "title": entry.title})
    db.commit()
    return {"ok": True, "id": entry.id}


class ChecklistToggleIn(BaseModel):
    index: int
    done: bool


@router.post("/{incident_id}/checklist")
def toggle_checklist(incident_id: str, body: ChecklistToggleIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_INCIDENTS))):
    import copy

    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    # deep copy: JSON columns need new objects or the ORM won't detect the change
    items = copy.deepcopy(list(inc.containment_checklist or []))
    if body.index < 0 or body.index >= len(items):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "bad_index", "message": "Checklist index out of range"})
    items[body.index]["done"] = body.done
    inc.containment_checklist = items
    db.add(
        IncidentTimelineEntry(
            incident_id=incident_id, entry_type="containment", actor_email=ctx.email,
            title=f"Containment step {'completed' if body.done else 'reopened'}: {items[body.index]['text']}",
        )
    )
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="incident.checklist_toggled",
                 entity_type="incident", entity_id=incident_id, details={"index": body.index, "done": body.done})
    db.commit()
    return _serialize(inc, db)


class LinkIndicatorIn(BaseModel):
    indicator_id: str


@router.post("/{incident_id}/indicators", status_code=201)
def link_indicator(incident_id: str, body: LinkIndicatorIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_INCIDENTS))):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Incident not found"})
    ind = db.get(Indicator, body.indicator_id)
    if ind is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Indicator not found"})
    ids = list(inc.indicator_ids or [])
    if ind.id in ids:
        return {"ok": True, "already_linked": True}
    ids.append(ind.id)
    inc.indicator_ids = ids
    db.add(
        IncidentTimelineEntry(
            incident_id=incident_id, entry_type="analyst_action", actor_email=ctx.email,
            title=f"Indicator linked: {ind.value}", related_indicator_id=ind.id,
        )
    )
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="incident.indicator_linked",
                 entity_type="incident", entity_id=incident_id, details={"indicator": ind.value})
    db.commit()
    return {"ok": True}

