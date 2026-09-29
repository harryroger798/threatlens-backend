"""Admin: users & roles (P_MANAGE_USERS), audit log viewer, saved hunts."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.api.deps import rbac_permission
from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.core.security import hash_password
from app.db import get_db
from app.models import (AuditLog, Hunt, ROLES, User)
from app.services.bus import bus

router = APIRouter(tags=["admin"])


# ------------------------------------------------------------- saved hunts ---

class HuntCreateIn(BaseModel):
    name: str
    query: str | None = None
    facets: dict = {}
    notes: str | None = None


@router.get("/hunts")
def list_hunts(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SAVED_HUNTS))):
    rows = db.execute(select(Hunt).order_by(Hunt.created_at.desc()).limit(50)).scalars().all()
    return [
        {"id": h.id, "name": h.name, "query": h.query, "facets": h.facets,
         "notes": h.notes, "created_by": h.created_by_email, "created_at": h.created_at.isoformat()}
        for h in rows
    ]


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SAVED_HUNTS))):
    hunt = Hunt(name=body.name, query=body.query, facets=body.facets, notes=body.notes,
                created_by_id=ctx.id, created_by_email=ctx.email)
    db.add(hunt)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="hunt.saved",
                 entity_type="hunt", entity_id=hunt.id, details={"name": body.name, "facets": body.facets})
    db.commit()
    return {"ok": True, "id": hunt.id}


@router.delete("/hunts/{hunt_id}")
def delete_hunt(hunt_id: str, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_SAVED_HUNTS))):
    hunt = db.get(Hunt, hunt_id)
    if hunt is None:
        raise HTTPException(404, detail={"error_code": "not_found", "message": "Hunt not found"})
    db.delete(hunt)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="hunt.deleted", entity_type="hunt", entity_id=hunt_id)
    db.commit()
    return {"ok": True}


# -------------------------------------------------------------------- users ---

@router.get("/users")
def list_users(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_USERS))):
    rows = db.execute(select(User).order_by(User.name)).scalars().all()
    return [
        {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "status": u.status,
         "mfa_enabled": u.mfa_enabled, "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None}
        for u in rows
    ]


class UserCreateIn(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str


@router.post("/users", status_code=201)
def create_user(body: UserCreateIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_USERS))):
    if body.role not in ROLES:
        raise HTTPException(422, detail={"error_code": "invalid_role", "message": f"Role must be one of {ROLES}"})
    if len(body.password) < 10:
        raise HTTPException(422, detail={"error_code": "weak_password", "message": "Password must be at least 10 characters"})
    exists = db.execute(select(User).where(User.email == body.email.lower())).scalars().first()
    if exists:
        raise HTTPException(409, detail={"error_code": "conflict", "message": "User already exists"})
    user = User(email=body.email.lower(), name=body.name, role=body.role,
                password_hash=hash_password(body.password), status="active")
    db.add(user)
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="user.created",
                 entity_type="user", entity_id=user.id, details={"email": user.email, "role": user.role})
    db.commit()
    return {"ok": True, "id": user.id}


class UserPatchIn(BaseModel):
    role: str | None = None
    status: str | None = None


@router.patch("/users/{user_id}")
def patch_user(user_id: str, body: UserPatchIn, db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_MANAGE_USERS))):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail={"error_code": "not_found", "message": "User not found"})
    changes = {}
    if body.role:
        if body.role not in ROLES:
            raise HTTPException(422, detail={"error_code": "invalid_role", "message": f"Role must be one of {ROLES}"})
        user.role = body.role
        changes["role"] = body.role
    if body.status:
        if body.status not in ("active", "disabled", "locked"):
            raise HTTPException(422, detail={"error_code": "invalid_status", "message": "Unknown status"})
        user.status = body.status
        changes["status"] = body.status
    audit_record(db, actor_id=ctx.id, actor_email=ctx.email, action="user.updated",
                 entity_type="user", entity_id=user.id, details={"changes": changes})
    db.commit()
    return {"ok": True, "changes": changes}


# ------------------------------------------------------------------- audit ----

@router.get("/audit")
def view_audit(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_AUDIT)),
               action: str | None = None, actor: str | None = None, page: int = 1, page_size: int = 50):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_email.ilike(f"%{actor}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    page_size = min(max(page_size, 1), 200)
    page = max(page, 1)
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {
        "total": int(total), "page": page, "page_size": page_size,
        "items": [
            {
                "id": a.id, "created_at": a.created_at.isoformat(), "actor": a.actor_email or a.actor_id,
                "action": a.action, "entity_type": a.entity_type, "entity_id": a.entity_id,
                "details": a.details, "ip": a.ip, "correlation_id": a.correlation_id,
            }
            for a in rows
        ],
    }


@router.get("/health/system")
def system_health(db: Session = Depends(get_db), ctx=Depends(rbac_permission(perms.P_VIEW_AUDIT))):
    from app.core.config import settings as cfg

    ok = db.execute(select(func.count(User.id))).scalar() is not None
    return {
        "status": "ok" if ok else "degraded",
        "app": cfg.APP_NAME,
        "version": cfg.APP_VERSION,
        "bus": bus.stats(),
        "database": "connected",
    }
