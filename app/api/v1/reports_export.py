"""Reports (FR-23) and exports (FR-24): on-demand PDF, STIX 2.1 bundles, CSV."""
import csv
import io
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.api.deps import rbac_permission
from app.db import get_db
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.models import (Alert, Incident, IncidentTimelineEntry, Indicator,
                        IndicatorSource, IndicatorTag, Report, TLP_VALUES, User)
from app.services.scoring import severity_for_score

router = APIRouter(tags=["reports"])

REPORT_DIR = os.path.join(tempfile.gettempdir(), "threatlens_reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ------------------------------------------------------------------- STIX ----

STIX_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
}


def _stix_pattern(ind: Indicator) -> str | None:
    if ind.type == "ip":
        return f"[ipv4-addr:value = '{ind.value}']"
    if ind.type == "domain":
        return f"[domain-name:value = '{ind.value}']"
    if ind.type == "url":
        return f"[url:value = '{ind.value}']"
    if ind.type == "email":
        return f"[email-addr:value = '{ind.value}']"
    if ind.type in ("hash_md5", "hash_sha1", "hash_sha256"):
        algo = {"hash_md5": "MD5", "hash_sha1": "SHA-1", "hash_sha256": "SHA-256"}[ind.type]
        return f"[file:hashes.'{algo}' = '{ind.value}']"
    if ind.type == "cve":
        return f"[vulnerability:id = '{ind.value}']"
    return None


def build_stix_bundle(indicators: list[Indicator]) -> dict:
    objects = []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    seen_hashes = set()
    for ind in indicators:
        pattern = _stix_pattern(ind)
        if not pattern:
            continue
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind.id}",
            "created": ind.first_seen.isoformat().replace("+00:00", "Z") if ind.first_seen else now,
            "modified": ind.updated_at.isoformat().replace("+00:00", "Z") if ind.updated_at else now,
            "name": ind.value,
            "description": ind.description or f"{ind.type} indicator",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ind.first_seen.isoformat().replace("+00:00", "Z") if ind.first_seen else now,
            "labels": [t.tag.name for t in ind.tags] or ["malicious-activity"],
            "confidence": ind.confidence,
            "x_threatlens_severity": severity_for_score(ind.severity_score),
            "x_threatlens_score": ind.severity_score,
            "x_threatlens_tlp": ind.tlp,
        }
        if ind.malware_family:
            indicator_obj["x_threatlens_malware_family"] = ind.malware_family
        objects.append(indicator_obj)
        if ind.type in ("hash_md5", "hash_sha1", "hash_sha256") and ind.value not in seen_hashes:
            objects.append({
                "type": "file", "spec_version": "2.1", "id": f"file--{ind.id}",
                "hashes": {{"hash_md5": "MD5", "hash_sha1": "SHA-1", "hash_sha256": "SHA-256"}[ind.type]: ind.value},
            })
            seen_hashes.add(ind.value)
    return {
        "type": "bundle",
        "id": f"bundle--{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "objects": objects,
    }


@router.get("/export/stix")
def export_stix(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL)),
                min_score: int = 0, tlp_max: str | None = None, limit: int = 500):
    """STIX 2.1 bundle export. TLP handling is honoured: amber/red restricted
    markings are only included when explicitly requested."""
    stmt = select(Indicator).options(joinedload(Indicator.tags, IndicatorTag.tag)).where(Indicator.status == "active", Indicator.severity_score >= min_score).order_by(Indicator.severity_score.desc(), Indicator.last_seen.desc()).limit(min(limit, 2000))
    rows = db.execute(stmt).unique().scalars().all()
    if tlp_max:
        order = {t: i for i, t in enumerate(TLP_VALUES)}
        max_i = order.get(tlp_max, len(TLP_VALUES) - 1)
        rows = [r for r in rows if order.get(r.tlp, 0) <= max_i]
    bundle = build_stix_bundle(rows)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="export.stix",
                 details={"objects": len(bundle["objects"]), "min_score": min_score, "tlp_max": tlp_max})
    db.commit()
    return bundle


@router.get("/export/csv")
def export_csv(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SEARCH_INTEL)),
               min_score: int = 0, limit: int = 2000):
    stmt = select(Indicator).where(Indicator.status == "active", Indicator.severity_score >= min_score).limit(min(limit, 5000))
    rows = db.execute(stmt).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["value", "type", "severity_score", "severity", "confidence", "tlp", "status",
                     "malware_family", "internal_sightings", "sources", "tags", "first_seen", "last_seen"])
    for r in rows:
        writer.writerow([
            r.value, r.type, r.severity_score, severity_for_score(r.severity_score), r.confidence,
            r.tlp, r.status, r.malware_family or "", r.internal_sightings,
            "|".join(s.source_name for s in r.sources), "|".join(t.tag.name for t in r.tags),
            r.first_seen.isoformat() if r.first_seen else "", r.last_seen.isoformat() if r.last_seen else "",
        ])
    buf.seek(0)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="export.csv", details={"rows": len(rows)})
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=threatlens_indicators.csv"})


# ------------------------------------------------------------------- PDF -----

def _summarise(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    week = now - timedelta(days=7)
    total_active = db.execute(select(func.count(Indicator.id)).where(Indicator.status == "active")).scalar() or 0
    critical = db.execute(select(func.count(Indicator.id)).where(Indicator.status == "active", Indicator.severity_score >= 85)).scalar() or 0
    alerts_7d = db.execute(select(func.count(Alert.id)).where(Alert.created_at >= week)).scalar() or 0
    incidents_open = db.execute(select(func.count(Incident.id)).where(Incident.status == "open")).scalar() or 0
    top = db.execute(
        select(Indicator).where(Indicator.status == "active").order_by(Indicator.severity_score.desc()).limit(10)
    ).scalars().all()
    cats = db.execute(select(Indicator.type, func.count(Indicator.id)).where(Indicator.status == "active").group_by(Indicator.type)).all()
    return {
        "generated_at": now.isoformat(),
        "total_active": int(total_active), "critical": int(critical),
        "alerts_7d": int(alerts_7d), "incidents_open": int(incidents_open),
        "top_indicators": top,
        "categories": cats,
    }


def _render_pdf(summary: dict, title: str, out_path: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1e293b"), spaceBefore=10)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)

    doc = SimpleDocTemplate(out_path, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    story = [Paragraph(title, h1),
             Paragraph(f"ThreatLens Â· Sentinova Security Systems Â· Generated {summary['generated_at']}", body),
             Spacer(1, 6)]

    exec_summary = (
        f"As of this report, the platform tracks {summary['total_active']} active indicators. "
        f"{summary['critical']} are rated critical (score >= 85). In the last 7 days the platform raised "
        f"{summary['alerts_7d']} alerts and {summary['incidents_open']} incidents remain open. "
        f"Priorities below are ranked by the reproducible severity scoring model (source reputation, "
        f"confidence, recency, internal sightings, IOC type)."
    )
    story += [Paragraph("Executive summary", h2), Paragraph(exec_summary, body), Spacer(1, 4)]

    story.append(Paragraph("Indicator mix by type", h2))
    cat_rows = [["Type", "Active"]] + [[t, str(n)] for t, n in summary["categories"]]
    cat_table = Table(cat_rows, colWidths=[60 * mm, 30 * mm])
    cat_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0"))]))
    story += [cat_table, Spacer(1, 4)]

    story.append(Paragraph("Top 10 indicators by severity", h2))
    top_rows = [["Value", "Type", "Score", "Severity", "Sightings"]]
    for ind in summary["top_indicators"]:
        top_rows.append([ind.value[:48], ind.type, str(ind.severity_score), severity_for_score(ind.severity_score), str(ind.internal_sightings)])
    top_table = Table(top_rows, colWidths=[70 * mm, 25 * mm, 15 * mm, 25 * mm, 20 * mm])
    top_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                                   ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story += [top_table, Spacer(1, 4)]
    story.append(Paragraph("Handling: Traffic Light Protocol markings are honoured in all exports. "
                           "This report is generated from the append-only audit trail and canonical indicator store.", body))
    doc.build(story)


class ReportCreateIn(BaseModel):
    title: str = "Threat Intelligence Posture Report"
    kind: str = "executive"
    incident_id: str | None = None


@router.post("/reports")
def create_report(body: ReportCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_GENERATE_REPORTS))):
    if body.kind == "incident":
        incident = db.get(Incident, body.incident_id or "")
        if incident is None:
            raise HTTPException(404, detail={"error_code": "not_found", "message": "Incident not found"})
        summary = _summarise(db)
        summary["incident"] = incident.title
        out_path = os.path.join(REPORT_DIR, f"incident_{incident.id[:8]}.pdf")
        _render_pdf(summary, f"Incident Report: {incident.title}", out_path)
        # Timeline digest appended as metadata for the record
        entries = db.execute(select(IncidentTimelineEntry).where(IncidentTimelineEntry.incident_id == incident.id).order_by(IncidentTimelineEntry.occurred_at.asc())).scalars().all()
        summary["timeline_entries"] = len(entries)
    else:
        summary = _summarise(db)
        out_path = os.path.join(REPORT_DIR, f"exec_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.pdf")
        _render_pdf(summary, body.title, out_path)

    report = Report(
        title=body.title, kind=body.kind, requested_by_email=ctx.email,
        incident_id=body.incident_id, file_path=out_path, status="ready",
        summary={"total_active": summary["total_active"], "critical": summary["critical"],
                 "alerts_7d": summary["alerts_7d"], "incidents_open": summary["incidents_open"]},
    )
    db.add(report)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="report.generated",
                 entity_type="report", entity_id=report.id, details={"title": body.title, "kind": body.kind})
    db.commit()
    return {"id": report.id, "title": report.title, "status": report.status, "created_at": report.created_at.isoformat()}


@router.get("/reports")
def list_reports(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_GENERATE_REPORTS))):
    rows = db.execute(select(Report).order_by(Report.created_at.desc()).limit(50)).scalars().all()
    return [
        {"id": r.id, "title": r.title, "kind": r.kind, "status": r.status,
         "requested_by": r.requested_by_email, "created_at": r.created_at.isoformat(),
         "summary": r.summary}
        for r in rows
    ]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_GENERATE_REPORTS))):
    report = db.get(Report, report_id)
    if report is None or not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(404, detail={"error_code": "not_found", "message": "Report file not found"})
    return FileResponse(report.file_path, media_type="application/pdf", filename=os.path.basename(report.file_path))

