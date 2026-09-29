"""Table-driven tests for the scoring engine: deterministic, exact outputs."""
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.services.scoring import (aggregate_confidence, compute_score,
                                  recency_component, severity_for_score,
                                  sightings_component, source_reputation)

NOW = datetime.now(timezone.utc)


def test_severity_bands_exact():
    assert severity_for_score(100) == "critical"
    assert severity_for_score(85) == "critical"
    assert severity_for_score(84) == "high"
    assert severity_for_score(70) == "high"
    assert severity_for_score(69) == "medium"
    assert severity_for_score(45) == "medium"
    assert severity_for_score(44) == "low"
    assert severity_for_score(25) == "low"
    assert severity_for_score(24) == "info"
    assert severity_for_score(0) == "info"


def test_recency_decay_known_points():
    import math

    now = datetime.now(timezone.utc)
    # Fresh: near-100
    assert recency_component(now - timedelta(seconds=1)) >= 98
    # Exact-decay points within ±1 of the continuous formula
    for hours in (72, 216, 432):
        t = now - timedelta(hours=hours)
        expected = int(100 * math.exp(-hours / 72))
        assert abs(recency_component(t) - expected) <= 1, f"{hours}h"
    # Monotonic decay
    t1 = now - timedelta(hours=10)
    t2 = now - timedelta(hours=300)
    assert recency_component(t1) > recency_component(t2)


def test_sightings_component():
    assert sightings_component(0) == 0
    assert sightings_component(2) == 40
    assert sightings_component(5) == 100
    assert sightings_component(50) == 100  # capped
    assert sightings_component(-1) == 0


def test_confidence_corroboration():
    assert aggregate_confidence([]) == 0
    assert aggregate_confidence([70]) == 70
    assert aggregate_confidence([70, 70, 70]) == 86  # +8 per extra source
    assert aggregate_confidence([40, 90]) == 98  # max base + boost
    assert aggregate_confidence([95, 95, 95, 95]) == 100  # capped


def test_source_reputation():
    assert source_reputation([], 65) == 65
    assert source_reputation([50, 80]) == 80
    assert source_reputation([]) == 50


def test_compute_score_table():
    cases = [
        # (source_rep, confidence, hours_since_seen, sightings, type, expected)
        (100, 100, 0, 5, "url", 100),
        (0, 0, 10_000, 0, "email", 4),
        (95, 90, 1, 2, "hash_sha256", None),
        (30, 25, 200, 0, "ip", None),
    ]
    for src, conf, hours, sightings, typ, expected in cases:
        score = compute_score(
            source_reputation=src, confidence=conf,
            last_seen=NOW - timedelta(hours=hours),
            internal_sightings=sightings, ioc_type=typ,
        )
        assert 0 <= score <= 100
        if expected is not None:
            assert score == expected, f"{src},{conf},{hours},{sightings},{typ} → {score} != {expected}"


def test_score_is_deterministic():
    args = dict(source_reputation=80, confidence=75, last_seen=NOW - timedelta(hours=5),
                internal_sightings=2, ioc_type="domain")
    assert compute_score(**args) == compute_score(**args)


def test_score_ordering_reflects_risk_inputs():
    fresh_bad = compute_score(source_reputation=95, confidence=90, last_seen=NOW - timedelta(hours=1),
                              internal_sightings=4, ioc_type="ip")
    stale_quiet = compute_score(source_reputation=20, confidence=15, last_seen=NOW - timedelta(hours=400),
                                internal_sightings=0, ioc_type="email")
    assert fresh_bad > stale_quiet


def test_weights_sum_to_one():
    s = settings
    assert abs(s.SCORE_W_SOURCE + s.SCORE_W_CONFIDENCE + s.SCORE_W_RECENCY + s.SCORE_W_SIGHTINGS + s.SCORE_W_TYPE - 1.0) < 1e-9
