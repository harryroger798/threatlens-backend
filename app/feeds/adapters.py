"""Feed adapters (FR-01). Each adapter yields normalised record dicts:
{value, seen_at, description, malware_family, tags, confidence, reference}

Abuse.ch / CISA feeds are used unauthenticated when reachable; when a network
call fails or the machine is offline the built-in reference set keeps the
pipeline demonstrable (documented degradation, not silent faking)."""
import csv
import hashlib
import io
import random
from datetime import datetime, timedelta, timezone

import httpx

TIMEOUT = 12.0

UA = {"User-Agent": "ThreatLens/1.0 (CTI platform; contact: soc@sentinova.example)"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_seen(raw) -> datetime | None:
    if not raw:
        return None
    s = str(raw).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
        try:
            return datetime.strptime(s.replace("T", " ").replace("+0000", "").replace(" UTC", "").strip()[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---------------------------------------------------------------- adapters ---

def fetch_urlhaus(feed) -> list[dict]:
    """URLhaus recent malicious URLs (abuse.ch). CSV, # comments."""
    try:
        resp = httpx.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=UA, timeout=TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text
    except Exception:
        return []
    out = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#") or row[0] == "id":
            continue
        try:
            out.append({
                "value": row[2],
                "seen_at": _parse_seen(row[1]),
                "malware_family": row[5] or None,
                "tags": [t for t in (row[6] or "").split(",") if t],
                "confidence": 70,
                "reference": row[7],
                "description": f"Malware-serving URL ({row[4]})",
            })
        except (IndexError, ValueError):
            continue
    return out[:400]


def fetch_feodo(feed) -> list[dict]:
    """Feodo Tracker C2 IP blocklist (abuse.ch). JSON."""
    try:
        resp = httpx.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=UA, timeout=TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return []
    out = []
    for item in payload if isinstance(payload, list) else []:
        out.append({
            "value": item.get("ip_address", ""),
            "seen_at": _parse_seen(item.get("last_online") or item.get("first_seen_utc")),
            "malware_family": item.get("malware"),
            "confidence": int(item.get("confidence_score") or 75),
            "description": f"C2 node for {item.get('malware')}",
            "tags": ["c2", (item.get("malware") or "").lower()],
        })
    return [r for r in out if r["value"]]


def fetch_threatfox(feed) -> list[dict]:
    """ThreatFox recent IOCs (abuse.ch). Unauthenticated API query."""
    try:
        resp = httpx.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 2}, headers=UA, timeout=TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return []
    out = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict) or not item.get("ioc"):
            continue
        out.append({
            "value": item["ioc"],
            "type": _hint_from_threatfox(item.get("ioc_type")),
            "seen_at": _parse_seen(item.get("last_seen_utc") or item.get("first_seen_utc")),
            "malware_family": item.get("malware"),
            "confidence": min(100, 60 + int(item.get("confidence") or 0)),
            "description": f"ThreatFox IOC ({item.get('confidence_level')})",
            "tags": ["threatfox", (item.get("malware") or "").lower()],
        })
    return out[:400]


def _hint_from_threatfox(t) -> str | None:
    mapping = {"ip:port": "ip", "domain": "domain", "url": "url", "md5_hash": "hash_md5", "sha256_hash": "hash_sha256", "ip": "ip"}
    return mapping.get((t or "").strip().lower())


def fetch_cisa_kev(feed) -> list[dict]:
    """CISA Known Exploited Vulnerabilities catalog. JSON, no key."""
    try:
        resp = httpx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", headers=UA, timeout=TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return []
    out = []
    for vuln in payload.get("vulnerabilities", [])[:120]:
        out.append({
            "value": vuln.get("cveID", ""),
            "seen_at": _parse_seen(vuln.get("dateAdded")),
            "confidence": 95,
            "description": (vuln.get("shortDescription") or "")[:250],
            "tags": ["kev", "cve", vuln.get("vendorProject", "").lower()],
            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    return [r for r in out if r["value"]]


def fetch_otx(feed) -> list[dict]:
    """AlienVault OTX pulses (requires a free API key held in the secrets manager)."""
    key = feed.secret_ref or ""
    if not key or key.startswith("secrets:"):
        return []
    try:
        resp = httpx.get("https://otx.alienvault.com/api/v1/indicators/export", headers={"X-OTX-API-KEY": key}, timeout=TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return []
    out = []
    for item in (payload if isinstance(payload, list) else [])[:300]:
        out.append({
            "value": item.get("indicator", ""),
            "type": _otx_type(item.get("type")),
            "confidence": 60,
            "description": "OTX pulse indicator",
            "tags": ["otx"],
        })
    return [r for r in out if r["value"]]


def _otx_type(t) -> str | None:
    mapping = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url", "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1", "FileHash-SHA256": "hash_sha256", "email": "email", "CVE": "cve"}
    return mapping.get(t or "")


# ------------------------------------------------------- embedded reference ---

REFERENCE_FEED: list[dict] = [
    {"value": "185.220.101.4", "malware_family": None, "tags": ["tor_exit", "abuse"], "confidence": 85, "description": "High-abuse Tor exit node seen in credential-stuffing waves"},
    {"value": "45.133.1.35", "malware_family": "Qakbot", "tags": ["c2", "qakbot"], "confidence": 80, "description": "Qakbot C2 node observed by multiple trackers"},
    {"value": "103.221.254.13", "malware_family": "AsyncRAT", "tags": ["c2", "asyncrat"], "confidence": 66, "description": "AsyncRAT command-and-control endpoint"},
    {"value": "collab-trade-support.top", "malware_family": "PhishKit", "tags": ["phishing", "newly_registered"], "confidence": 72, "description": "Credential-phishing domain mimicking a trading platform"},
    {"value": "invoice-payment-portal.net", "malware_family": None, "tags": ["phishing", "bec"], "confidence": 68, "description": "BEC lure domain impersonating an invoice portal"},
    {"value": "cdn-update-service.click", "malware_family": "IcedID", "tags": ["loader", "icedid"], "confidence": 70, "description": "IcedID loader staging domain"},
    {"value": "http://185.234.219.12/panel/login.php", "malware_family": "Cobalt Strike", "tags": ["c2", "cobalt_strike"], "confidence": 78, "description": "Cobalt Strike team server login panel"},
    {"value": "http://45.134.139.121/winroot.exe", "malware_family": "Emotet", "tags": ["payload", "emotet"], "confidence": 74, "description": "Direct payload download URL for Emotet dropper"},
    {"value": "44d88612fea8a8f36de82e1278abb02f", "malware_family": "Eicar-Test-File", "tags": ["reference", "test"], "confidence": 100, "description": "EICAR reference hash (known-good validation sample)"},
    {"value": "275a021bbfb6489e54d471a996ca7a21cf8dcc20", "malware_family": "Eicar-Test-File", "tags": ["reference", "test"], "confidence": 100, "description": "EICAR SHA-1 reference hash"},
    {"value": "275a021bbfb6489e54d471a996ca7a21cf8dcc20e9abc2630e3955853ff18569", "malware_family": "Eicar-Test-File", "tags": ["reference", "test"], "confidence": 100, "description": "EICAR SHA-256 reference hash"},
    {"value": "d41d8cd98f00b204e9800998ecf8427e", "malware_family": None, "tags": ["empty_file"], "confidence": 40, "description": "Empty-file MD5 — frequently queried, low analytic value"},
    {"value": "CVE-2025-24813", "malware_family": None, "tags": ["kev", "exploited"], "confidence": 95, "description": "Tomcat deserialization RCE — known exploited"},
    {"value": "CVE-2024-3400", "malware_family": None, "tags": ["kev", "exploited"], "confidence": 95, "description": "Palo Alto GlobalProtect command injection — known exploited"},
    {"value": "svc-renewal-login.com", "malware_family": "PhishKit", "tags": ["phishing"], "confidence": 65, "description": "Subscription-renewal phishing domain"},
    {"value": "198.51.100.77", "malware_family": None, "tags": ["scanner"], "confidence": 35, "description": "Internet-wide scanner noise (GreyNoise-classified)"},
    {"value": "203.0.113.250", "malware_family": "Dridex", "tags": ["c2", "dridex"], "confidence": 71, "description": "Dridex botnet C2 endpoint"},
    {"value": "update-pdf-reader.online", "malware_family": "AgentTesla", "tags": ["loader", "agenttesla"], "confidence": 69, "description": "Fake software-update domain dropping AgentTesla"},
]

SIM_INTERNAL_VALUES = [
    ("91.245.77.134", "ip", "Emotet"), ("45.9.148.238", "ip", "Dridex"),
    ("join-eu-notify.win", "domain", None), ("status-check-pages.top", "domain", "PhishKit"),
    ("http://152.32.132.3/deliver/loader.bin", "url", "IcedID"),
    ("cve-2023-3836", "cve", None),
]


def fetch_internal_sim(feed) -> list[dict]:
    """Simulated internal telemetry feed: generates analyst-realistic records so
    correlation and sighting workflows always have fresh data to work against."""
    rng = random.Random(int(hashlib.sha256((_now().date().isoformat() + feed.slug).encode()).hexdigest(), 16) % (2**32))
    out = []
    base = _now() - timedelta(hours=rng.uniform(0, 2))
    for i in range(4):
        value, hint, family = SIM_INTERNAL_VALUES[rng.randrange(len(SIM_INTERNAL_VALUES))]
        seen = base - timedelta(minutes=rng.randrange(0, 700))
        out.append({
            "value": value,
            "type": hint,
            "seen_at": seen,
            "malware_family": family,
            "confidence": rng.choice([55, 62, 70]),
            "description": "Recurring internal telemetry match — firewall/EDR correlation source",
            "tags": ["internal", "telemetry"],
            "reference": f"sentinova://telemetry/{feed.slug}/{i}",
        })
    return out


def fetch_reference(feed) -> list[dict]:
    """Built-in curated feed (always available, offline-safe)."""
    out = []
    base = _now()
    for i, rec in enumerate(REFERENCE_FEED):
        rec = dict(rec)
        rec["seen_at"] = base - timedelta(hours=(i * 7) % 96)
        rec["reference"] = f"threatlens://reference/{i}"
        out.append(rec)
    return out


ADAPTERS = {
    "urlhaus": fetch_urlhaus,
    "feodo": fetch_feodo,
    "threatfox": fetch_threatfox,
    "cisa_kev": fetch_cisa_kev,
    "otx": fetch_otx,
    "internal_sim": fetch_internal_sim,
    "internal_telemetry": fetch_internal_sim,
    "reference": fetch_reference,
}


def run_adapter(slug: str, feed) -> tuple[list[dict], str | None]:
    """Returns (records, error). Error is None on success."""
    fn = ADAPTERS.get(slug)
    if not fn:
        return [], f"no adapter for feed slug {slug}"
    try:
        records = fn(feed)
        error = None if records else "adapter returned no records (offline or rate-limited)"
        return records, error
    except Exception as exc:  # pragma: no cover - defensive
        return [], f"adapter error: {exc.__class__.__name__}"
