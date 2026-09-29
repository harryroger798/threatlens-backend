import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pyotp

from app.core.config import settings

_ALGO = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def _issue(sub: str, role: str, kind: str, minutes: int) -> tuple[str, str, int]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=minutes)
    jti = secrets.token_hex(12)
    payload = {"sub": sub, "role": role, "typ": kind, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "jti": jti}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_ALGO), jti, minutes * 60


def issue_access_token(user_id: str, role: str) -> tuple[str, int]:
    token, _, ttl = _issue(user_id, role, "access", settings.ACCESS_TOKEN_MINUTES)
    return token, ttl


def issue_refresh_token(user_id: str, role: str) -> tuple[str, int]:
    token, _, ttl = _issue(user_id, role, "refresh", settings.REFRESH_TOKEN_DAYS * 24 * 60)
    return token, ttl


def decode_token(token: str, expected_type: str = "access") -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[_ALGO])
    except jwt.ExpiredSignatureError:
        raise ValueError("token_expired")
    except jwt.InvalidTokenError:
        raise ValueError("token_invalid")
    if payload.get("typ") != expected_type:
        raise ValueError("token_invalid")
    return payload


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_setup_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="ThreatLens")


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
