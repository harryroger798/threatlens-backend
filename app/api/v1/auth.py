from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.audit import record as audit_record
from app.core.config import settings
from app.core.security import (hash_password, issue_access_token,
                               issue_refresh_token, verify_password,
                               verify_totp)
from app.db import get_db
from app.models import RefreshToken, User, aware

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "threatlens_refresh"


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


def _user_dict(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "mfa_enabled": u.mfa_enabled}


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.email == body.email.lower())).scalars().first()
    ip = _client_ip(request)
    corr = None

    if user is None:
        # Constant-shape failure: audit without revealing account existence
        audit_record(db, actor_id=None, actor_email=body.email, action="auth.login_failed",
                     details={"reason": "unknown_user"}, ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "invalid_credentials", "message": "Invalid email or password"})

    if user.status == "locked" or (user.locked_until and aware(user.locked_until) > datetime.now(timezone.utc)):
        audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.login_blocked",
                     details={"reason": "locked"}, ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, detail={"error_code": "account_locked", "message": "Account locked; try again later"})

    if user.status == "disabled":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"error_code": "account_disabled", "message": "Account disabled"})

    if not verify_password(body.password, user.password_hash):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= settings.MAX_FAILED_LOGINS:
            user.status = "locked"
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
        audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.login_failed",
                     details={"reason": "bad_password", "failed_logins": user.failed_logins}, ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "invalid_credentials", "message": "Invalid email or password"})

    if user.mfa_enabled:
        if not body.totp_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "mfa_required", "message": "TOTP code required"})
        if not verify_totp(user.mfa_secret or "", body.totp_code):
            audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.login_failed",
                         details={"reason": "bad_totp"}, ip=ip)
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "invalid_credentials", "message": "Invalid TOTP code"})

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)

    token, _ = issue_refresh_token(user.id, user.role)
    rt = RefreshToken(user_id=user.id, jti=_jti(token), expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_DAYS))
    db.add(rt)

    access, ttl = issue_access_token(user.id, user.role)
    audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.login",
                 details={"role": user.role}, ip=ip)
    db.commit()
    return LoginOut(access_token=access, expires_in=ttl, user=_user_dict(user))


def _jti(token: str) -> str:
    from app.core.security import decode_token

    payload = decode_token(token, "refresh")
    return payload["jti"]


@router.post("/refresh")
def refresh(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "unauthenticated", "message": "No refresh cookie"})
    from app.core.security import decode_token

    try:
        payload = decode_token(token, "refresh")
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "token_invalid", "message": "Refresh token invalid or expired"})

    rt = db.execute(select(RefreshToken).where(RefreshToken.jti == payload["jti"])).scalars().first()
    if rt is None or rt.revoked or aware(rt.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "token_revoked", "message": "Refresh token revoked"})

    user = db.get(User, payload["sub"])
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "user_inactive", "message": "Account inactive"})

    rt.revoked = True  # rotation: one-time use
    access, ttl = issue_access_token(user.id, user.role)
    new_refresh, _ = issue_refresh_token(user.id, user.role)
    new_rt = RefreshToken(user_id=user.id, jti=_jti(new_refresh), expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_DAYS))
    db.add(new_rt)
    audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.token_refreshed", details={})
    db.commit()
    return {"access_token": access, "token_type": "bearer", "expires_in": ttl}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if token:
        from app.core.security import decode_token

        try:
            payload = decode_token(token, "refresh")
            rt = db.execute(select(RefreshToken).where(RefreshToken.jti == payload["jti"])).scalars().first()
            if rt:
                rt.revoked = True
        except ValueError:
            pass
    audit_record(db, actor_id=None, actor_email=None, action="auth.logout", details={})
    db.commit()
    return {"ok": True}


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(body: ChangePasswordIn, ctx=Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, ctx.id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail={"error_code": "invalid_credentials", "message": "Current password incorrect"})
    if len(body.new_password) < 10:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "weak_password", "message": "Password must be at least 10 characters"})
    user.password_hash = hash_password(body.new_password)
    audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.password_changed", entity_type="user", entity_id=user.id)
    db.commit()
    return {"ok": True}


class MfaStartOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/mfa/start", response_model=MfaStartOut)
def mfa_start(ctx=Depends(get_current_user), db: Session = Depends(get_db)):
    from app.core.security import new_totp_secret, totp_setup_uri

    user = db.get(User, ctx.id)
    secret = new_totp_secret()
    user.mfa_secret = secret  # not yet confirmed/enabled
    db.commit()
    return MfaStartOut(secret=secret, otpauth_uri=totp_setup_uri(secret, user.email))


class MfaVerifyIn(BaseModel):
    code: str


@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyIn, ctx=Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, ctx.id)
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"error_code": "mfa_not_started", "message": "Start MFA enrolment first"})
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error_code": "invalid_totp", "message": "Invalid TOTP code"})
    user.mfa_enabled = True
    audit_record(db, actor_id=user.id, actor_email=user.email, action="auth.mfa_enabled", entity_type="user", entity_id=user.id)
    db.commit()
    return {"ok": True, "mfa_enabled": True}
