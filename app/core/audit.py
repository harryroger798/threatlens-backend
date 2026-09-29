"""Append-only audit log. Every authentication and state-changing action is
recorded with actor, timestamp, correlation id and before/after evidence."""
import json
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import AuditLog


def _coerce(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _coerce(v) for k, v in value.items()}
    return str(value)


def record(
    db: Session,
    *,
    actor_id: str | None,
    actor_email: str | None,
    action: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict | None = None,
    ip: str | None = None,
    correlation_id: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        id=None,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=json.dumps(_coerce(details or {}), default=str),
        ip=ip,
        correlation_id=correlation_id or secrets.token_hex(8),
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    return entry
