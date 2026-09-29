"""Severity scoring engine (FR-13).

A transparent, reproducible 0–100 score computed from five weighted inputs:

    score = W_SOURCE   * source_reputation    (0-100, strongest reporting source's reputation)
          + W_CONFIDENCE* aggregate_confidence (0-100, provenance-weighted confidence)
          + W_RECENCY   * recency              (0-100, exponential decay: 100 * e^(-hours/72))
          + W_SIGHTINGS * internal_sightings   (0-100, 20 pts per internal sighting, capped)
          + W_TYPE      * type_weight          (0-100, static weight per IOC type)

Severity bands (consistent colour language across every view):
    >= 85 critical | >= 70 high | >= 45 medium | >= 25 low | else info

The model is deterministic: identical inputs always yield identical outputs,
which is asserted by table-driven unit tests.
"""
import math
from datetime import datetime, timezone

from app.core.config import settings

TYPE_WEIGHTS = {
    "url": 100,
    "hash_sha256": 90,
    "cve": 88,
    "domain": 80,
    "hash_md5": 76,
    "ip": 72,
    "hash_sha1": 70,
    "email": 40,
}

SEVERITY_BANDS = ((85, "critical"), (70, "high"), (45, "medium"), (25, "low"), (0, "info"))


def severity_for_score(score: int) -> str:
    for threshold, severity in SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return "info"


def recency_component(last_seen: datetime) -> int:
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    hours = max(0.0, (datetime.now(timezone.utc) - last_seen).total_seconds() / 3600)
    return int(100 * math.exp(-hours / 72))


def sightings_component(sightings: int) -> int:
    return min(100, 20 * max(0, sightings))


def compute_score(
    *,
    source_reputation: int,
    confidence: int,
    last_seen: datetime,
    internal_sightings: int,
    ioc_type: str,
) -> int:
    s = settings
    total = (
        s.SCORE_W_SOURCE * _clamp(source_reputation)
        + s.SCORE_W_CONFIDENCE * _clamp(confidence)
        + s.SCORE_W_RECENCY * recency_component(last_seen)
        + s.SCORE_W_SIGHTINGS * sightings_component(internal_sightings)
        + s.SCORE_W_TYPE * TYPE_WEIGHTS.get(ioc_type, 50)
    )
    return int(round(_clamp(total)))


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, float(x)))


def aggregate_confidence(source_confidences: list[int]) -> int:
    """Provenance-weighted confidence (FR-03/FR-13).

    Base: max source confidence. Independent corroboration boosts confidence:
    +8 per additional distinct reporting source (capped at 100).
    """
    if not source_confidences:
        return 0
    base = max(source_confidences)
    n = len(source_confidences)
    return min(100, int(base + 8 * (n - 1)))


def source_reputation(source_confidences: list[int], feed_reputation: int | None = None) -> int:
    if feed_reputation is not None:
        return _clamp(feed_reputation)
    return max(source_confidences) if source_confidences else 50
