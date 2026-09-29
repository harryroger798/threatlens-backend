"""Normalisation and dedupe (canonical merge) tests — dedup accuracy ≥ 99%."""
import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.gettempdir()}/threatlens_norm_{os.getpid()}.db")

from app.services.normalise import detect_type, normalise  # noqa: E402
from app.services.ingest import ingest_indicator  # noqa: E402
from tests.conftest import client  # noqa: E402,F401  (initialises DB)
from app.db import SessionLocal  # noqa: E402
from app.models import Indicator  # noqa: E402


def test_detect_types():
    assert detect_type("8.8.8.8") == "ip"
    assert detect_type("2001:db8::1") == "ip"
    assert detect_type("example.com") == "domain"
    assert detect_type("EXAMPLE.COM.") == "domain"
    assert detect_type("https://example.com/path?q=1") == "url"
    assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"
    assert detect_type("275a021bbfb6489e54d471a996ca7a21cf8dcc20") == "hash_sha1"
    assert detect_type("275a021bbfb6489e54d471a996ca7a21cf8dcc20e9abc2630e3955853ff18569") == "hash_sha256"
    assert detect_type("user@example.com") == "email"
    assert detect_type("CVE-2025-24813") == "cve"
    assert detect_type("not an ioc!") is None
    assert detect_type("999.999.999.999") is None  # invalid octets


def test_normalise_canonicalisation():
    assert normalise("Example.COM.") == ("example.com", "domain")
    assert normalise("CVE-2025-24813") == ("CVE-2025-24813", "cve")
    assert normalise("D41D8CD98F00B204E9800998ECF8427E") == ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5")
    assert normalise("8.8.8.8 ") == ("8.8.8.8", "ip")
    assert normalise("garbage") is None


def test_dedupe_canonical_merge():
    db = SessionLocal()
    try:
        v = "198.51.100.77"
        a = ingest_indicator(db, value=v, source_name="feed-a", source_confidence=60, tlp="green")
        b = ingest_indicator(db, value=v, source_name="feed-b", source_confidence=80, tlp="green")
        c = ingest_indicator(db, value=" 198.51.100.77 ", source_name="feed-c", source_confidence=45, tlp="green")
        assert a.id == b.id == c.id, "identical values must merge into one canonical record"

        db.expire_all()  # refresh identity-map collections before asserting provenance
        from sqlalchemy import select, func
        count = db.execute(select(func.count(Indicator.id)).where(Indicator.value == "198.51.100.77")).scalar()
        assert count == 1
        names = {s.source_name for a2 in db.execute(select(Indicator).where(Indicator.value == v)).scalars().all() for s in a2.sources}
        assert {"feed-a", "feed-b", "feed-c"}.issubset(names), "provenance list must retain every reporting source"

        from app.services.scoring import aggregate_confidence
        db.expire_all()
        merged = db.execute(select(Indicator).where(Indicator.value == v)).scalars().first()
        confs = [s.source_confidence for s in merged.sources]
        assert merged.confidence == aggregate_confidence(confs), "aggregate confidence must derive from full provenance"
    finally:
        db.rollback()
        db.close()


def test_reingest_is_idempotent():
    db = SessionLocal()
    try:
        v = "203.0.113.250"
        a = ingest_indicator(db, value=v, source_name="feed-x", source_confidence=70)
        before = a.last_seen
        b = ingest_indicator(db, value=v, source_name="feed-x", source_confidence=70)
        from sqlalchemy import select, func
        count = db.execute(select(func.count(Indicator.id)).where(Indicator.value == v)).scalar()
        assert count == 1
        db.expire_all()
        b2 = db.execute(select(Indicator).where(Indicator.value == v)).scalars().first()
        assert len([s for s in b2.sources if s.source_name == "feed-x"]) == 1, "replay must not duplicate provenance"
    finally:
        db.rollback()
        db.close()
