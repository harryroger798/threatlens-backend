"""Canonical normalisation (FR-02): every ingested record is parsed into one
schema regardless of source format. Type detection is strict and validated."""
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.models import IOC_TYPES

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$", re.IGNORECASE)
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def detect_type(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _CVE_RE.match(v):
        return "cve"
    if _EMAIL_RE.match(v):
        return "email"
    if _URL_SCHEME_RE.match(v):
        return "url"
    lowered = v.lower()
    if re.fullmatch(r"[0-9a-f]{32}", lowered):
        return "hash_md5"
    if re.fullmatch(r"[0-9a-f]{40}", lowered):
        return "hash_sha1"
    if re.fullmatch(r"[0-9a-f]{64}", lowered):
        return "hash_sha256"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def normalise_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def normalise(value: str, hint_type: str | None = None) -> tuple[str, str] | None:
    """Returns (canonical_value, ioc_type) or None when unparseable."""
    v = (value or "").strip()
    t = hint_type if hint_type in IOC_TYPES else detect_type(v)
    if not t or not v:
        return None
    if t == "domain":
        return normalise_domain(v), t
    if t == "ip":
        try:
            return str(ipaddress.ip_address(v)), t
        except ValueError:
            return None
    if t == "cve":
        return v.upper(), t
    if t in ("hash_md5", "hash_sha1", "hash_sha256"):
        return v.lower(), t
    if t == "email":
        return v.lower(), t
    return v, t


def sha256_of(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_iso(dt_value) -> datetime | None:
    if not dt_value:
        return None
    if isinstance(dt_value, datetime):
        return dt_value if dt_value.tzinfo else dt_value.replace(tzinfo=timezone.utc)
    s = str(dt_value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None
