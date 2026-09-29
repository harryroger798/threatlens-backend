import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index,
                        Integer, SmallInteger, String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def uid() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime:
    """SQLite returns naive datetimes; treat stored values as UTC."""
    if dt is None:
        return now_utc()
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


TLP_VALUES = ("clear", "green", "amber", "red")
IOC_TYPES = ("ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve")
IOC_STATUSES = ("active", "expired", "whitelisted", "under_review")
ALERT_STATES = ("new", "acknowledged", "in_progress", "resolved", "closed")
SEVERITIES = ("critical", "high", "medium", "low", "info")
ROLES = ("administrator", "security_engineer", "incident_responder", "threat_hunter", "soc_analyst", "executive")
USER_STATUSES = ("active", "disabled", "locked")


def _uuid_pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=uid)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(Enum(*ROLES, name="user_role"))
    status: Mapped[str] = mapped_column(Enum(*USER_STATUSES, name="user_status"), default="active")
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    """Rotating refresh tokens: each issued token is revoked on use."""
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = _uuid_pk()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    jti: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")


class Indicator(Base, TimestampMixin):
    """Canonical IOC record (PRD §9.2)."""
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_indicator_value_type"),
        Index("ix_indicators_active_severity", "status", "severity_score"),
    )

    id: Mapped[str] = _uuid_pk()
    value: Mapped[str] = mapped_column(String(2048), index=True)
    type: Mapped[str] = mapped_column(Enum(*IOC_TYPES, name="ioc_type"))
    severity_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    confidence: Mapped[int] = mapped_column(SmallInteger, default=0)
    tlp: Mapped[str] = mapped_column(Enum(*TLP_VALUES, name="tlp"), default="amber")
    status: Mapped[str] = mapped_column(Enum(*IOC_STATUSES, name="ioc_status"), default="active")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    malware_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kill_chain_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    diamond_model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    internal_sightings: Mapped[int] = mapped_column(Integer, default=0)
    ttl_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sources: Mapped[list["IndicatorSource"]] = relationship(back_populates="indicator", cascade="all, delete-orphan")
    enrichments: Mapped[list["Enrichment"]] = relationship(back_populates="indicator", cascade="all, delete-orphan")
    tags: Mapped[list["IndicatorTag"]] = relationship(back_populates="indicator", cascade="all, delete-orphan")
    techniques: Mapped[list["IndicatorTechnique"]] = relationship(back_populates="indicator", cascade="all, delete-orphan")
    notes: Mapped[list["AnalystNote"]] = relationship(back_populates="indicator", cascade="all, delete-orphan")


class IndicatorSource(Base):
    """Per-feed provenance: which source reported the indicator, when, at what confidence."""
    __tablename__ = "indicator_sources"

    id: Mapped[str] = _uuid_pk()
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    feed_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("feeds.id"), nullable=True)
    source_name: Mapped[str] = mapped_column(String(128))
    source_confidence: Mapped[int] = mapped_column(SmallInteger, default=50)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    indicator: Mapped["Indicator"] = relationship(back_populates="sources")


class Enrichment(Base):
    """Cached enrichment results (reputation, geo/ASN, detection verdicts)."""
    __tablename__ = "enrichments"

    id: Mapped[str] = _uuid_pk()
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64))  # reputation | geo | verdicts | scan_context
    provider: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    indicator: Mapped["Indicator"] = relationship(back_populates="enrichments")


class IndicatorRelationship(Base):
    """Typed edges between indicators: resolves-to, communicates-with, drops."""
    __tablename__ = "indicator_relationships"

    id: Mapped[str] = _uuid_pk()
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    relation: Mapped[str] = mapped_column(String(64))

    source: Mapped["Indicator"] = relationship(foreign_keys=[source_id])
    target: Mapped["Indicator"] = relationship(foreign_keys=[target_id])


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[str] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    indicators: Mapped[list["IndicatorTag"]] = relationship(back_populates="tag")


class IndicatorTag(Base):
    __tablename__ = "indicator_tags"
    __table_args__ = (UniqueConstraint("indicator_id", "tag_id", name="uq_indicator_tag"),)

    id: Mapped[str] = _uuid_pk()
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    tag_id: Mapped[str] = mapped_column(String(36), ForeignKey("tags.id"), index=True)

    indicator: Mapped["Indicator"] = relationship(back_populates="tags")
    tag: Mapped["Tag"] = relationship(back_populates="indicators")


class AttackTechnique(Base):
    """MITRE ATT&CK technique reference."""
    __tablename__ = "attack_techniques"

    id: Mapped[str] = _uuid_pk()
    technique_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # T1566 etc.
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class IndicatorTechnique(Base):
    __tablename__ = "indicator_techniques"
    __table_args__ = (UniqueConstraint("indicator_id", "technique_id", name="uq_indicator_technique"),)

    id: Mapped[str] = _uuid_pk()
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(32), ForeignKey("attack_techniques.technique_id"), index=True)

    indicator: Mapped["Indicator"] = relationship(back_populates="techniques")
    technique: Mapped["AttackTechnique"] = relationship()


class AnalystNote(Base):
    """Free-text analyst notes attached to an indicator."""
    __tablename__ = "analyst_notes"

    id: Mapped[str] = _uuid_pk()
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    author_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    author_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    indicator: Mapped["Indicator"] = relationship(back_populates="notes")


class Feed(Base):
    """Configured sources: transport, schedule, credentials reference, enabled state."""
    __tablename__ = "feeds"

    id: Mapped[str] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64))
    transport: Mapped[str] = mapped_column(String(32), default="http_json")  # http_json | http_csv | api | internal_sim
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    default_tlp: Mapped[str] = mapped_column(Enum(*TLP_VALUES, name="tlp"), default="green")
    source_confidence: Mapped[int] = mapped_column(SmallInteger, default=50)  # source reputation weight input
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=900)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)  # secrets-manager reference, never a secret
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # ok | error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    items_ingested: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class SecurityEvent(Base, TimestampMixin):
    """Ingested internal events used for correlation."""
    __tablename__ = "security_events"

    id: Mapped[str] = _uuid_pk()
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    event_type: Mapped[str] = mapped_column(String(64))  # dns_query | http_request | firewall_deny | edr_detection | auth_fail
    indicator_value: Mapped[str] = mapped_column(String(2048), index=True)
    indicator_type: Mapped[str] = mapped_column(Enum(*IOC_TYPES, name="ioc_type"))
    asset: Mapped[str | None] = mapped_column(String(255), nullable=True)  # internal host/user
    source_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[str] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_score: Mapped[int] = mapped_column(SmallInteger, default=70)
    ioc_types: Mapped[list | None] = mapped_column(JSON, nullable=True)  # None = all
    feed_slugs: Mapped[list | None] = mapped_column(JSON, nullable=True)  # None = all
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    require_internal_sighting: Mapped[bool] = mapped_column(Boolean, default=False)
    route_to_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    route_to_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = _uuid_pk()
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"), index=True)
    severity_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    indicator_id: Mapped[str] = mapped_column(String(36), ForeignKey("indicators.id"), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("alert_rules.id"), nullable=True)
    state: Mapped[str] = mapped_column(Enum(*ALERT_STATES, name="alert_state"), default="new", index=True)
    assignee_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    indicator: Mapped["Indicator"] = relationship()
    rule: Mapped["AlertRule"] = relationship()


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[str] = _uuid_pk()
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(Enum(*SEVERITIES, name="severity"), default="high")
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | contained | resolved | closed
    lead_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    indicator_ids: Mapped[list] = mapped_column(JSON, default=list)
    containment_checklist: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class IncidentTimelineEntry(Base):
    """Ordered, append-only events belonging to an incident (PRD §6.4 FR-19)."""
    __tablename__ = "incident_timeline"

    id: Mapped[str] = _uuid_pk()
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    entry_type: Mapped[str] = mapped_column(String(64))  # detection | correlation | analyst_action | containment | note | report
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    related_indicator_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("indicators.id"), nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Hunt(Base):
    """Saved hunt: persisted query + facets so successful hunts become reusable."""
    __tablename__ = "hunts"

    id: Mapped[str] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(255))
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    facets: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = _uuid_pk()
    title: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32), default="executive")  # executive | incident | threat
    requested_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ready")
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AuditLog(Base):
    """Append-only; no UPDATE/DELETE is ever issued against it (tamper-evidence)."""
    __tablename__ = "audit_log"

    id: Mapped[str] = _uuid_pk()
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
