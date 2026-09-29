import secrets
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core import permissions as perms
from app.core.audit import record as audit_record
from app.core.ratelimit import rate_limit
from app.core.security import decode_token
from app.db import get_db
from app.models import User

bearer = HTTPBearer(auto_error=False)


class AuthContext:
    def __init__(self, user: User):
        self.user = user
        self.role = user.role
        self.id = user.id
        self.email = user.email


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "unauthenticated", "message": "Missing bearer token"})
    try:
        payload = decode_token(credentials.credentials, "access")
    except ValueError as exc:
        code = str(exc)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": code, "message": "Token expired or invalid"},
        )
    user = db.get(User, payload["sub"])
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "user_inactive", "message": "Account disabled or unknown"})
    rate_limit(request, user.id)
    return AuthContext(user)


def rbac_permission(permission: str):
    """Server-side RBAC enforced on every request (PRD §13.2); denials audited."""

    def _dep(request: Request, ctx: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)) -> AuthContext:
        if not perms.has_permission(ctx.role, permission):
            audit_record(
                db,
                actor_id=ctx.id, actor_email=ctx.email,
                action="authz.denied",
                entity_type="permission", entity_id=permission,
                details={"role": ctx.role, "path": request.url.path},
                ip=request.client.host if request.client else None,
            )
            db.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"error_code": "forbidden", "message": f"Role '{ctx.role}' lacks '{permission}'"})
        return ctx

    return _dep


def new_correlation_id() -> str:
    return secrets.token_hex(8)
