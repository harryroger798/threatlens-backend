"""One-look analysis endpoints (PRD Â§10.2): IP reputation, hash verdicts,
domain analysis, and faceted full-text search."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.models import (Alert, AttackTechnique, Feed, IOC_TYPES,
                        Indicator, IndicatorSource, IndicatorTag,
                        IndicatorTechnique, SecurityEvent, Tag)
from app.services.enrichment import (enrich_cve_kev, enrich_domain_analysis,
                                     enrich_geo, enrich_reputation_ip,
                                     enrich_verdicts)
from app.services.scoring import severity_for_score

router = APIRouter(tags=["intel"])


def _find_by_value(db: Session, value: str) -> Indicator | None:
    return (
        db.execute(
            select(Indicator)
            .options(joinedload(Indicator.sources), joinedload(Indicator.tags, IndicatorTag.tag))
            .where(Indicator.value == value.strip().lower() if ":" not in value and "://" not in value else Indicator.value == value.strip())
        )
        .scalars()
        .first()
    )


@router.get("/reputation/ip/{ip}")
def ip_reputation(ip: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    ind = db.execute(select(Indicator).where(Indicator.type == "ip", Indicator.value == ip)).scalars().first()
    if ind is None:
        from app.services.ingest import ingest_indicator

        ind = ingest_indicator(db, value=ip, source_name="on-demand lookup", source_confidence=40, tlp="clear")
        if ind is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_ioc", "message": "Not a valid IP address"})
        db.commit()
    rep = enrich_reputation_ip(db, ind)
    geo = enrich_geo(db, ind)
    db.commit()
    return {"indicator": {"id": ind.id, "value": ind.value, "severity_score": ind.severity_score,
                          "severity": severity_for_score(ind.severity_score), "internal_sightings": ind.internal_sightings},
            "reputation": rep, "geo": geo}


@router.get("/hash/{digest}")
def hash_lookup(digest: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    d = digest.strip().lower()
    if len(d) not in (32, 40, 64):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_hash", "message": "Expected MD5/SHA-1/SHA-256 hex digest"})
    ind = db.execute(select(Indicator).where(Indicator.type.in_(["hash_md5", "hash_sha1", "hash_sha256"]), Indicator.value == d)).scalars().first()
    if ind is None:
        from app.services.ingest import ingest_indicator

        ind = ingest_indicator(db, value=d, source_name="on-demand lookup", source_confidence=40, tlp="clear")
        db.commit()
    verdicts = enrich_verdicts(db, ind)
    db.commit()
    return {"indicator": {"id": ind.id, "value": ind.value, "type": ind.type,
                          "severity_score": ind.severity_score, "severity": severity_for_score(ind.severity_score)},
            "verdicts": verdicts}


@router.get("/domains/{domain}/analysis")
def domain_analysis(domain: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    from app.services.normalise import normalise

    parsed = normalise(domain, "domain")
    if parsed is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_domain", "message": "Not a valid domain"})
    ind = db.execute(select(Indicator).where(Indicator.type == "domain", Indicator.value == parsed[0])).scalars().first()
    if ind is None:
        from app.services.ingest import ingest_indicator

        ind = ingest_indicator(db, value=parsed[0], hint_type="domain", source_name="on-demand lookup", source_confidence=40, tlp="clear")
        db.commit()
    analysis = enrich_domain_analysis(db, ind)
    geo = enrich_geo(db, ind)
    db.commit()
    return {"indicator": {"id": ind.id, "value": ind.value, "severity_score": ind.severity_score,
                          "severity": severity_for_score(ind.severity_score), "internal_sightings": ind.internal_sightings},
            "analysis": analysis, "geo": geo}


@router.get("/search")
def search(
    db: Session = Depends(get_db),
    ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL)),
    q: str | None = None,
    types: str | None = None,
    tags: str | None = None,
    sources: str | None = None,
    techniques: str | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    tlp: str | None = None,
    status: str | None = "active",
    limit: int = 50,
):
    """Full-text + faceted search across indicators. Sub-second over the
    canonical store; the same contract sits in front of Elasticsearch at scale."""
    # ES seam: when ES_URL is configured, route to Elasticsearch; otherwise
    # query the canonical store directly (same API contract, same result shape).
    from app.core.config import settings as _settings
    if _settings.ES_URL:
        return _es_search_route(db, q=q, types=types, tags=tags, sources=sources,
                                techniques=techniques, min_score=min_score,
                                max_score=max_score, tlp=tlp, status=status, limit=limit)

    stmt = select(Indicator).options(joinedload(Indicator.sources), joinedload(Indicator.tags, IndicatorTag.tag))
    facets_applied = {}
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Indicator.value).like(like),
                              func.lower(func.coalesce(Indicator.description, "")).like(like),
                              func.lower(func.coalesce(Indicator.malware_family, "")).like(like)))
    if types:
        type_list = [t.strip() for t in types.split(",") if t.strip() in IOC_TYPES]
        if type_list:
            stmt = stmt.where(Indicator.type.in_(type_list))
        facets_applied["types"] = type_list
    if tags:
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
        if tag_list:
            stmt = stmt.join(IndicatorTag, IndicatorTag.indicator_id == Indicator.id).join(Tag, Tag.id == IndicatorTag.tag_id).where(Tag.name.in_(tag_list))
        facets_applied["tags"] = tag_list
    if sources:
        src_list = [s.strip() for s in sources.split(",") if s.strip()]
        if src_list:
            stmt = stmt.join(IndicatorSource, IndicatorSource.indicator_id == Indicator.id).where(IndicatorSource.source_name.in_(src_list))
        facets_applied["sources"] = src_list
    if techniques:
        tech_list = [t.strip().upper() for t in techniques.split(",") if t.strip()]
        if tech_list:
            stmt = stmt.join(IndicatorTechnique, IndicatorTechnique.indicator_id == Indicator.id).where(IndicatorTechnique.technique_id.in_(tech_list))
        facets_applied["techniques"] = tech_list
    if min_score is not None:
        stmt = stmt.where(Indicator.severity_score >= min_score)
    if max_score is not None:
        stmt = stmt.where(Indicator.severity_score <= max_score)
    if tlp:
        stmt = stmt.where(Indicator.tlp == tlp)
    if status:
        stmt = stmt.where(Indicator.status == status)

    limit = min(max(limit, 1), 200)
    rows = db.execute(stmt.order_by(Indicator.severity_score.desc()).limit(limit)).unique().scalars().all()

    type_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    tag_counts: dict[str, int] = {}
    for r in rows:
        type_counts[r.type] = type_counts.get(r.type, 0) + 1
        for s in r.sources:
            source_counts[s.source_name] = source_counts.get(s.source_name, 0) + 1
        for t in r.tags:
            tag_counts[t.tag.name] = tag_counts.get(t.tag.name, 0) + 1

    return {
        "query": q,
        "facets_applied": facets_applied,
        "count": len(rows),
        "results": [
            {
                "id": r.id, "value": r.value, "type": r.type,
                "severity_score": r.severity_score, "severity": severity_for_score(r.severity_score),
                "confidence": r.confidence, "tlp": r.tlp, "status": r.status,
                "malware_family": r.malware_family,
                "description": (r.description or "")[:180],
                "internal_sightings": r.internal_sightings,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "sources": [s.source_name for s in r.sources],
                "tags": [t.tag.name for t in r.tags],
            }
            for r in rows
        ],
        "facet_counts": {"types": type_counts, "sources": source_counts, "tags": tag_counts},
    }


@router.get("/attack/matrix")
def attack_matrix(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL))):
    """ATT&CK technique overlay: coverage + gaps across mapped indicators."""
    from app.models import IndicatorTechnique

    rows = db.execute(
        select(IndicatorTechnique.technique_id, func.count(IndicatorTechnique.id))
        .group_by(IndicatorTechnique.technique_id)
    ).all()
    counts = {tid: n for tid, n in rows}
    techniques = db.execute(select(AttackTechnique)).scalars().all()
    return [
        {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic,
         "indicator_count": counts.get(t.technique_id, 0)}
        for t in techniques
    ]



def _es_search_route(db, **params):
    """Route a search to Elasticsearch when configured. Falls back to the
    canonical store on ES errors. Same response shape as the direct path."""
    from app.services.es_search import build_es_query, ES_INDEX_NAME
    import httpx
    from app.core.config import settings as cfg
    from fastapi import HTTPException, status as http_status

    es_query = build_es_query(
        q=params.get('q'), types=params.get('types'),
        tags=params.get('tags'), sources=params.get('sources'),
        techniques=params.get('techniques'),
        min_score=params.get('min_score'), max_score=params.get('max_score'),
        tlp=params.get('tlp'), status=params.get('status'),
        limit=params.get('limit', 50),
    )
    try:
        resp = httpx.post(
            f"{cfg.ES_URL.rstrip('/')}/{ES_INDEX_NAME}/_search",
            json=es_query, timeout=5,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        # ES unreachable: fall through to canonical store
        return _canonical_search(db, **params)

    hits = payload.get('hits', {}).get('hits', [])
    total = payload.get('hits', {}).get('total', {}).get('value', len(hits))
    results = []
    for hit in hits:
        src = hit.get('_source', {})
        results.append({
            'id': src.get('id'), 'value': src.get('value'), 'type': src.get('type'),
            'severity_score': src.get('severity_score', 0),
            'severity': scoring.severity_for_score(src.get('severity_score', 0)),
            'confidence': src.get('confidence', 0), 'tlp': src.get('tlp', 'amber'),
            'status': src.get('status', 'active'), 'malware_family': src.get('malware_family'),
            'description': (src.get('description') or '')[:180],
            'internal_sightings': src.get('internal_sightings', 0),
            'last_seen': src.get('last_seen'), 'sources': src.get('sources', []),
            'tags': src.get('tags', []),
        })
    return {'query': params.get('q'), 'count': len(results), 'results': results,
            'facet_counts': _facet_counts(db)}
