from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import or_, select, func
from sqlalchemy.orm import Session, joinedload

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.core.config import settings
from app.models import (Alert, Indicator, IndicatorSource, IndicatorTag,
                        AnalystNote, Tag, AttackTechnique, IndicatorTechnique)
from app.services import normalise as norm
from app.services.enrichment import full_enrichment
from app.services.ingest import full_pipeline, refresh_score
from app.services.scoring import severity_for_score

router = APIRouter(prefix="/indicators", tags=["indicators"])


def _serialize(ind: Indicator, db: Session) -> dict:
    return {
        "id": ind.id,
        "value": ind.value,
        "type": ind.type,
        "severity_score": ind.severity_score,
        "severity": severity_for_score(ind.severity_score),
        "confidence": ind.confidence,
        "tlp": ind.tlp,
        "status": ind.status,
        "description": ind.description,
        "malware_family": ind.malware_family,
        "kill_chain_phase": ind.kill_chain_phase,
        "internal_sightings": ind.internal_sightings,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        "expires_at": ind.expires_at.isoformat() if ind.expires_at else None,
        "sources": [
            {"name": s.source_name, "confidence": s.source_confidence,
             "first_seen": s.first_seen.isoformat(), "last_seen": s.last_seen.isoformat(),
             "reference": s.reference}
            for s in ind.sources
        ],
        "tags": [t.tag.name for t in ind.tags],
        "techniques": [
            {"technique_id": t.technique.technique_id, "name": t.technique.name, "tactic": t.technique.tactic}
            for t in ind.techniques
        ],
    }


def _get_indicator_or_404(db: Session, indicator_id: str) -> Indicator:
    ind = db.get(Indicator, indicator_id)
    if ind is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error_code": "not_found", "message": "Indicator not found"})
    return ind


@router.get("")
def list_indicators(
    db: Session = Depends(get_db),
    ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL)),
    q: str | None = Query(None, description="substring match on value/description/family"),
    type: str | None = None,
    severity: str | None = None,
    status: str | None = "active",
    tlp: str | None = None,
    tag: str | None = None,
    source: str | None = None,
    min_score: int | None = None,
    sort: str = "-severity_score",
    page: int = 1,
    page_size: int = 25,
):
    stmt = select(Indicator).options(joinedload(Indicator.sources), joinedload(Indicator.tags, IndicatorTag.tag))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Indicator.value).like(like), func.lower(func.coalesce(Indicator.description, "")).like(like), func.lower(func.coalesce(Indicator.malware_family, "")).like(like)))
    if type:
        stmt = stmt.where(Indicator.type == type)
    if status:
        stmt = stmt.where(Indicator.status == status)
    if tlp:
        stmt = stmt.where(Indicator.tlp == tlp)
    if severity:
        from app.services.scoring import SEVERITY_BANDS

        bands = [85, 70, 45, 25, 0]
        names = ["critical", "high", "medium", "low", "info"]
        idx = names.index(severity)
        lo = bands[idx]
        hi = 100 if idx == 0 else bands[idx - 1] - 1
        stmt = stmt.where(Indicator.severity_score >= lo, Indicator.severity_score <= hi)
    if min_score is not None:
        stmt = stmt.where(Indicator.severity_score >= min_score)
    if tag:
        stmt = stmt.join(IndicatorTag, IndicatorTag.indicator_id == Indicator.id).join(Tag, Tag.id == IndicatorTag.tag_id).where(Tag.name == tag.lower())
    if source:
        stmt = stmt.join(IndicatorSource, IndicatorSource.indicator_id == Indicator.id).where(IndicatorSource.source_name.ilike(f"%{source}%"))

    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()

    order_map = {
        "-severity_score": Indicator.severity_score.desc(),
        "severity_score": Indicator.severity_score.asc(),
        "-last_seen": Indicator.last_seen.desc(),
        "last_seen": Indicator.last_seen.asc(),
        "value": Indicator.value.asc(),
    }
    stmt = stmt.order_by(order_map.get(sort, Indicator.severity_score.desc()))
    page_size = min(max(page_size, 1), 200)
    page = max(page, 1)
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).unique().scalars().all()

    return {"total": total, "page": page, "page_size": page_size, "items": [_serialize(i, db) for i in rows]}


@router.get("/{indicator_id}")
def get_indicator(indicator_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    ind = _get_indicator_or_404(db, indicator_id)
    data = _serialize(ind, db)
    notes = db.execute(select(AnalystNote).where(AnalystNote.indicator_id == ind.id).order_by(AnalystNote.created_at.desc())).scalars().all()
    data["notes"] = [{"author": n.author_email, "body": n.body, "created_at": n.created_at.isoformat()} for n in notes]
    return data


@router.post("/{indicator_id}/enrich")
def enrich_indicator(indicator_id: str, request: Request, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_ENRICH_TAG))):
    ind = _get_indicator_or_404(db, indicator_id)
    result = full_enrichment(db, ind)
    correlation_count = 0
    from app.services.correlation import correlate_indicator

    correlation_count = correlate_indicator(db, ind)
    refresh_score(db, ind)
    db.flush()
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="indicator.enriched",
                 entity_type="indicator", entity_id=ind.id,
                 details={"value": ind.value, "enrichers": sorted(result.keys())},
                 ip=request.client.host if request.client else None)
    db.commit()
    data = _serialize(ind, db)
    data["enrichment"] = result
    data["correlated_events"] = correlation_count
    return data


class TagIn(BaseModel):
    tags: list[str]


@router.post("/{indicator_id}/tags")
def add_tags(indicator_id: str, body: TagIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_ENRICH_TAG))):
    ind = _get_indicator_or_404(db, indicator_id)
    from app.services.ingest import _attach_tags

    _attach_tags(db, ind, body.tags)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="indicator.tagged",
                 entity_type="indicator", entity_id=ind.id, details={"tags": body.tags})
    db.commit()
    return _serialize(ind, db)


class NoteIn(BaseModel):
    body: str


@router.post("/{indicator_id}/notes")
def add_note(indicator_id: str, body: NoteIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_ENRICH_TAG))):
    ind = _get_indicator_or_404(db, indicator_id)
    note = AnalystNote(indicator_id=ind.id, author_id=ctx.id, author_email=ctx.email, body=body.body)
    db.add(note)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="indicator.noted",
                 entity_type="indicator", entity_id=ind.id, details={"length": len(body.body)})
    db.commit()
    return {"ok": True}


class IndicatorCreateIn(BaseModel):
    value: str
    type: str | None = None
    tlp: str = "amber"
    description: str | None = None
    malware_family: str | None = None
    tags: list[str] | None = None
    confidence: int = 70


@router.post("", status_code=201)
def create_indicator(body: IndicatorCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_ENRICH_TAG))):
    parsed = norm.normalise(body.value, body.type)
    if parsed is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_ioc", "message": "Value is not a recognisable IOC"})
    from app.services.ingest import ingest_indicator

    ind = ingest_indicator(
        db, value=body.value, hint_type=body.type, source_name=f"manual:{ctx.email}",
        source_confidence=body.confidence, tlp=body.tlp,
        description=body.description, malware_family=body.malware_family, tag_names=body.tags,
    )
    if ind is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_ioc", "message": "Value is not a recognisable IOC"})
    full_pipeline(db, ind)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="indicator.created",
                 entity_type="indicator", entity_id=ind.id, details={"value": ind.value, "type": ind.type})
    db.commit()
    return _serialize(ind, db)


class IndicatorUpdateIn(BaseModel):
    status: str | None = None
    tlp: str | None = None
    description: str | None = None
    malware_family: str | None = None
    kill_chain_phase: str | None = None
    ttl_days: int | None = None


@router.patch("/{indicator_id}")
def update_indicator(indicator_id: str, body: IndicatorUpdateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_ENRICH_TAG))):
    ind = _get_indicator_or_404(db, indicator_id)
    changes = {}
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        if field == "status" and value not in ("active", "expired", "whitelisted", "under_review"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_status", "message": "Unknown status"})
        if field == "tlp" and value not in ("clear", "green", "amber", "red"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_tlp", "message": "Unknown TLP"})
        setattr(ind, field, value)
        changes[field] = value
    if changes:
        refresh_score(db, ind)
        audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="indicator.updated",
                     entity_type="indicator", entity_id=ind.id, details={"changes": changes})
        db.commit()
    return _serialize(ind, db)


@router.get("/{indicator_id}/relationships")
def indicator_relationships(indicator_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    ind = _get_indicator_or_404(db, indicator_id)
    from app.models import IndicatorRelationship

    rows = db.execute(
        select(IndicatorRelationship).where(
            or_(IndicatorRelationship.source_id == ind.id, IndicatorRelationship.target_id == ind.id)
        )
    ).scalars().all()
    ids = {r.source_id for r in rows} | {r.target_id for r in rows}
    related = {i.id: i for i in db.execute(select(Indicator).where(Indicator.id.in_(ids))).scalars().all()} if ids else {}
    return [
        {
            "source_id": r.source_id, "target_id": r.target_id, "relation": r.relation,
            "source": {"id": r.source_id, "value": related[r.source_id].value, "type": related[r.source_id].type, "severity_score": related[r.source_id].severity_score} if r.source_id in related else {"id": r.source_id, "value": "?", "type": "domain", "severity_score": 0},
            "target": {"id": r.target_id, "value": related[r.target_id].value, "type": related[r.target_id].type, "severity_score": related[r.target_id].severity_score} if r.target_id in related else {"id": r.target_id, "value": "?", "type": "domain", "severity_score": 0},
        }
        for r in rows
    ]


@router.get("/{indicator_id}/correlation")
def indicator_correlation(indicator_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    ind = _get_indicator_or_404(db, indicator_id)
    from app.services.correlation import events_for_value

    events = events_for_value(db, ind.value)
    return {
        "sightings": ind.internal_sightings,
        "events": [
            {
                "observed_at": e.observed_at.isoformat(),
                "event_type": e.event_type,
                "asset": e.asset,
                "source_system": e.source_system,
                "country": e.country,
            }
            for e in events
        ],
    }

