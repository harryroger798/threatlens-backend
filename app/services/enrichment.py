"""Enrichment service (FR-10..FR-14): IP reputation, malicious-domain analysis,
malware-hash verdicts, geo/ASN. Results are cached (DB-backed with TTL) and
cold lookups are bounded so interactive latency stays in budget.

Real providers are used when reachable; deterministic reference enrichers keep
the demo fully functional offline (values are derived from a stable hash of the
indicator so they never contradict themselves between calls)."""
import hashlib
import os
import json
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Enrichment, Indicator, aware
from app.services.scoring import severity_for_score

CACHE_TTL_MINUTES = 60


def _get_env_key(name: str) -> str:
    """Read an API key from the environment. Empty string = not configured."""
    return os.environ.get(name, "")


def _try_abuseipdb(ip: str) -> dict | None:
    """Real AbuseIPDB API call for IP reputation (free: 1000/day)."""
    key = _get_env_key("ABUSEIPDB_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if resp.status_code == 200:
            j = resp.json().get("data", {})
            return {
                "abuse_confidence_score": j.get("abuseConfidenceScore", 0),
                "total_reports": j.get("totalReports", 0),
                "distinct_reporters": j.get("numDistinctUsers", 0),
                "verdict": "malicious" if j.get("abuseConfidenceScore", 0) >= 50 else ("suspicious" if j.get("abuseConfidenceScore", 0) >= 25 else "clean"),
                "isp": j.get("isp", ""),
                "usage_type": j.get("usageType", ""),
                "country_code": j.get("countryCode", ""),
                "is_whitelisted": j.get("isWhitelisted", False),
                "last_reported": j.get("lastReportedAt", ""),
            }
    except Exception:
        pass
    return None


def _try_virustotal_hash(sha256: str) -> dict | None:
    """Real VirusTotal API call for hash verdicts (free: 4/min, 500/day)."""
    key = _get_env_key("VIRUSTOTAL_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0) + stats.get("timeout", 0)
            families = []
            pop = attrs.get("popular_threat_classification", {})
            if pop.get("suggested_threat_label"):
                families.append(pop["suggested_threat_label"].split("/")[0].split(".")[0])
            for _, v in results.items():
                if v.get("result") and v["result"] not in ("clean", "unrated", "timeout"):
                    fam = v["result"].split("/")[0].split(".")[0]
                    if fam and fam not in families:
                        families.append(fam)
            return {
                "engine_total": total or 70,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "ratio": round(malicious / max(1, total), 2),
                "families": families[:3],
            }
    except Exception:
        pass
    return None


def _try_virustotal_domain(domain: str) -> dict | None:
    """Real VirusTotal API call for domain analysis."""
    key = _get_env_key("VIRUSTOTAL_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            cats = attrs.get("categories", {})
            return {
                "newly_registered": attrs.get("creation_date", 0) > (datetime.now(timezone.utc).timestamp() - 86400 * 90),
                "known_phishing": any("phish" in str(c).lower() for c in cats.values()),
                "dga_like": False,
                "registrar_age_days": max(1, int((datetime.now(timezone.utc).timestamp() - attrs.get("creation_date", 0)) / 86400)) if attrs.get("creation_date") else 0,
                "resolves": True,
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "categories": list(cats.values())[:3],
            }
    except Exception:
        pass
    return None


def _try_ipapi_geo(ip: str) -> dict | None:
    """Real geolocation via ip-api.com (free, no key, 45 req/min)."""
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,as,asName,org,lat,lon"},
            timeout=8,
        )
        if resp.status_code == 200:
            j = resp.json()
            if j.get("status") == "success":
                return {
                    "country": j.get("countryCode", ""),
                    "asn": j.get("as", "").split(" ")[0] if j.get("as") else "",
                    "asn_owner": j.get("asName", "") or j.get("org", ""),
                    "latitude": j.get("lat", 0),
                    "longitude": j.get("lon", 0),
                }
    except Exception:
        pass
    return None

COUNTRY_POOL = ["RU", "CN", "US", "BR", "IN", "NL", "DE", "UA", "VN", "IR", "RO", "GB", "FR", "TR", "ID", "KR"]
ASN_POOL = [
    ("AS14061", "DigitalOcean, LLC"), ("AS9009", "M247 Europe SRL"),
    ("AS16509", "Amazon.com, Inc."), ("AS45102", "Alibaba Cloud"),
    ("AS49981", "WorldStream B.V."), ("AS208323", "Comfortel Ltd."),
]
FAMILIES = ["Emotet", "Qakbot", "Dridex", "AsyncRAT", "Cobalt Strike", "IcedID", "AgentTesla"]
VERDICT_POOL = [(58, 2), (44, 0), (67, 4), (39, 1), (72, 6), (31, 0)]


def _stable_bucket(value: str, mod: int) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest(), 16) % mod


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_cached(db: Session, indicator: Indicator, kind: str, provider: str) -> Enrichment | None:
    row = (
        db.execute(
            select(Enrichment).where(
                Enrichment.indicator_id == indicator.id,
                Enrichment.kind == kind,
                Enrichment.provider == provider,
            )
        )
        .scalars()
        .first()
    )
    if row and row.expires_at and aware(row.expires_at) > _now():
        return row
    return None


def _store(db: Session, indicator: Indicator, kind: str, provider: str, data: dict) -> Enrichment:
    row = (
        db.execute(
            select(Enrichment).where(
                Enrichment.indicator_id == indicator.id,
                Enrichment.kind == kind,
                Enrichment.provider == provider,
            )
        )
        .scalars()
        .first()
    )
    expires = _now() + timedelta(minutes=CACHE_TTL_MINUTES)
    if row:
        row.data = data
        row.fetched_at = _now()
        row.expires_at = expires
    else:
        row = Enrichment(indicator_id=indicator.id, kind=kind, provider=provider, data=data, expires_at=expires)
        db.add(row)
        db.flush()
    return row


def _try_http_json(url: str, timeout: float = 4.0):
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def enrich_reputation_ip(db: Session, indicator: Indicator) -> dict:
    cached = _get_cached(db, indicator, "reputation", "ip_reputation")
    if cached:
        return cached.data
    # real AbuseIPDB API when key is configured
    real = _try_abuseipdb(indicator.value) if indicator.type == "ip" else None
    if real:
        abuse_conf = real["abuse_confidence_score"]
        reports = real["total_reports"]
        data = {**real, "verdict": real["verdict"], "last_reported": real.get("last_reported", "")}
        _store(db, indicator, "reputation", "ip_reputation", data)
        return data
    bucket = _stable_bucket(indicator.value, 100)
    abuse_conf = max(10, min(100, bucket + 15))
    reports = 3 + _stable_bucket(indicator.value, 300)
    data = {
        "abuse_confidence_score": abuse_conf,
        "total_reports": reports,
        "distinct_reporters": max(1, reports // 4),
        "verdict": "malicious" if abuse_conf >= 50 else ("suspicious" if abuse_conf >= 25 else "benign"),
        "last_reported": (indicator.last_seen.isoformat() if indicator.last_seen else None),
    }
    _store(db, indicator, "reputation", "ip_reputation", data)
    return data


def enrich_geo(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("ip", "domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "geo", "geo_asn")
    if cached:
        return cached.data
    host = indicator.value
    if indicator.type in ("domain", "url"):
        host = indicator.value.split("://", 1)[-1].split("/", 1)[0]
    # real ip-api.com geolocation for IP indicators (free, no key)
    if indicator.type == "ip":
        real = _try_ipapi_geo(indicator.value)
        if real:
            data = real
            _store(db, indicator, "geo", "geo_asn", data)
            return data
    country = COUNTRY_POOL[_stable_bucket(host, len(COUNTRY_POOL))]
    asn_id, asn_name = ASN_POOL[_stable_bucket(host + "|asn", len(ASN_POOL))]
    data = {
        "country": country,
        "asn": asn_id,
        "asn_owner": asn_name,
        "latitude": round(-60 + _stable_bucket(host + "|lat", 150), 4),
        "longitude": round(-120 + _stable_bucket(host + "|lon", 240), 4),
    }
    _store(db, indicator, "geo", "geo_asn", data)
    return data


def enrich_verdicts(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("hash_md5", "hash_sha1", "hash_sha256", "domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "verdicts", "detection_engines")
    if cached:
        return cached.data
    # real VirusTotal API for hash indicators
    if indicator.type in ("hash_sha256", "hash_sha1", "hash_md5"):
        real = _try_virustotal_hash(indicator.value)
        if real:
            data = real
            _store(db, indicator, "verdicts", "detection_engines", data)
            return data
    malicious = VERDICT_POOL[_stable_bucket(indicator.value, len(VERDICT_POOL))][0]
    suspicious = _stable_bucket(indicator.value + "|s", 5)
    total = 72
    data = {
        "engine_total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": total - malicious - suspicious,
        "ratio": round(malicious / total, 2),
        "families": [FAMILIES[_stable_bucket(indicator.value, len(FAMILIES))]] if malicious > 20 else [],
    }
    _store(db, indicator, "verdicts", "detection_engines", data)
    return data


def enrich_domain_analysis(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("domain", "url", "ip"):
        return {}
    cached = _get_cached(db, indicator, "scan_context", "domain_analysis")
    if cached:
        return cached.data
    bucket = _stable_bucket(indicator.value, 100)
    # real VirusTotal domain analysis when key is configured
    if indicator.type in ("domain", "url"):
        host = indicator.value.split("://", 1)[-1].split("/", 1)[0] if indicator.type == "url" else indicator.value
        real = _try_virustotal_domain(host)
        if real:
            data = real
            _store(db, indicator, "scan_context", "domain_analysis", data)
            return data
    newly_registered = bucket % 7 == 0
    phishing = indicator.malware_family in ("PhishKit",) or bucket % 9 == 0
    data = {
        "newly_registered": newly_registered,
        "known_phishing": phishing,
        "dga_like": bucket % 11 == 0,
        "registrar_age_days": 3 + _stable_bucket(indicator.value + "|age", 3000),
        "resolves": True,
    }
    _store(db, indicator, "scan_context", "domain_analysis", data)
    return data


def enrich_cve_kev(db: Session, indicator: Indicator) -> dict:
    """CVE indicators are checked against the CISA KEV catalog (real, no key)."""
    if indicator.type != "cve":
        return {}
    cached = _get_cached(db, indicator, "reputation", "cisa_kev")
    if cached:
        return cached.data
    data: dict = {"kev_listed": False, "known_exploited": False}
    payload = _try_http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if payload and isinstance(payload.get("vulnerabilities"), list):
        match = next((v for v in payload["vulnerabilities"] if v.get("cveID", "").upper() == indicator.value.upper()), None)
        if match:
            data = {
                "kev_listed": True,
                "known_exploited": True,
                "kev_date_added": match.get("dateAdded"),
                "kev_description": (match.get("shortDescription") or "")[:400],
            }
    else:
        bucket = _stable_bucket(indicator.value, 10)
        data = {"kev_listed": bucket >= 6, "known_exploited": bucket >= 6}
    _store(db, indicator, "reputation", "cisa_kev", data)
    return data


def full_enrichment(db: Session, indicator: Indicator) -> dict:
    """Run every applicable enricher and return a merged result payload."""
    result: dict = {}
    if indicator.type == "ip":
        result["reputation"] = enrich_reputation_ip(db, indicator)
    if indicator.type == "cve":
        result["kev"] = enrich_cve_kev(db, indicator)
    geo = enrich_geo(db, indicator)
    if geo:
        result["geo"] = geo
    verdicts = enrich_verdicts(db, indicator)
    if verdicts:
        result["verdicts"] = verdicts
    domain = enrich_domain_analysis(db, indicator)
    if domain:
        result["domain_analysis"] = domain
    result["scoring"] = {
        "severity_score": indicator.severity_score,
        "severity": severity_for_score(indicator.severity_score),
        "confidence": indicator.confidence,
        "internal_sightings": indicator.internal_sightings,
    }
    return result
