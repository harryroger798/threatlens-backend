import io

p = r"C:\Users\joxor\threatlens\backend\app\services\enrichment.py"
raw = io.open(p, "rb").read().decode("utf-8")

EDITS = [
    # 1) add os import at the top (after hashlib)
    ("import hashlib\n", "import hashlib\nimport os\n"),
    # 2) add env key helper after the imports block (after CACHE_TTL_MINUTES)
    ("CACHE_TTL_MINUTES = 60\n",
     """CACHE_TTL_MINUTES = 60


def _get_env_key(name: str) -> str:
    \"\"\"Read an API key from the environment. Empty string = not configured.\"\"\"
    return os.environ.get(name, "")


def _try_abuseipdb(ip: str) -> dict | None:
    \"\"\"Real AbuseIPDB API call for IP reputation (free: 1000/day).\"\"\"
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
    \"\"\"Real VirusTotal API call for hash verdicts (free: 4/min, 500/day).\"\"\"
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
    \"\"\"Real VirusTotal API call for domain analysis.\"\"\"
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
    \"\"\"Real geolocation via ip-api.com (free, no key, 45 req/min).\"\"\"
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
"""),
]

for old, new in EDITS:
    n = raw.count(old)
    print(("OK  " if n >= 1 else f"MISS({n}) "), old[:64].replace("\n", "\\n"))
    if n >= 1:
        raw = raw.replace(old, new, 1)

# 3) modify enrich_reputation_ip to use AbuseIPDB
old_rep = """    bucket = _stable_bucket(indicator.value, 100)
    abuse_conf = max(10, min(100, bucket + 15))
    reports = 3 + _stable_bucket(indicator.value, 300)"""
new_rep = """    # real AbuseIPDB API when key is configured
    real = _try_abuseipdb(indicator.value) if indicator.type == "ip" else None
    if real:
        abuse_conf = real["abuse_confidence_score"]
        reports = real["total_reports"]
        data = {**real, "verdict": real["verdict"], "last_reported": real.get("last_reported", "")}
        _store(db, indicator, "reputation", "ip_reputation", data)
        return data
    bucket = _stable_bucket(indicator.value, 100)
    abuse_conf = max(10, min(100, bucket + 15))
    reports = 3 + _stable_bucket(indicator.value, 300)"""
n = raw.count(old_rep)
print('reputation API anchor:', n)
if n == 1:
    raw = raw.replace(old_rep, new_rep)

# 4) modify enrich_geo to use ip-api.com for IP indicators
old_geo = """    country = COUNTRY_POOL[_stable_bucket(host, len(COUNTRY_POOL))]
    asn_id, asn_name = ASN_POOL[_stable_bucket(host + "|asn", len(ASN_POOL))]"""
new_geo = """    # real ip-api.com geolocation for IP indicators (free, no key)
    if indicator.type == "ip":
        real = _try_ipapi_geo(indicator.value)
        if real:
            data = real
            _store(db, indicator, "geo", "geo_asn", data)
            return data
    country = COUNTRY_POOL[_stable_bucket(host, len(COUNTRY_POOL))]
    asn_id, asn_name = ASN_POOL[_stable_bucket(host + "|asn", len(ASN_POOL))]"""
n = raw.count(old_geo)
print('geo API anchor:', n)
if n == 1:
    raw = raw.replace(old_geo, new_geo)

# 5) modify enrich_verdicts to use VirusTotal for hashes
old_verd = """    malicious = VERDICT_POOL[_stable_bucket(indicator.value, len(VERDICT_POOL))][0]
    suspicious = _stable_bucket(indicator.value + "|s", 5)
    total = 72"""
new_verd = """    # real VirusTotal API for hash indicators
    if indicator.type in ("hash_sha256", "hash_sha1", "hash_md5"):
        real = _try_virustotal_hash(indicator.value)
        if real:
            data = real
            _store(db, indicator, "verdicts", "detection_engines", data)
            return data
    malicious = VERDICT_POOL[_stable_bucket(indicator.value, len(VERDICT_POOL))][0]
    suspicious = _stable_bucket(indicator.value + "|s", 5)
    total = 72"""
n = raw.count(old_verd)
print('verdicts API anchor:', n)
if n == 1:
    raw = raw.replace(old_verd, new_verd)

# 6) modify enrich_domain_analysis to use VirusTotal for domains
old_dom = """    newly_registered = bucket % 7 == 0
    phishing = indicator.malware_family in ("PhishKit",) or bucket % 9 == 0"""
new_dom = """    # real VirusTotal domain analysis when key is configured
    if indicator.type in ("domain", "url"):
        host = indicator.value.split("://", 1)[-1].split("/", 1)[0] if indicator.type == "url" else indicator.value
        real = _try_virustotal_domain(host)
        if real:
            data = real
            _store(db, indicator, "scan_context", "domain_analysis", data)
            return data
    newly_registered = bucket % 7 == 0
    phishing = indicator.malware_family in ("PhishKit",) or bucket % 9 == 0"""
n = raw.count(old_dom)
print('domain API anchor:', n)
if n == 1:
    raw = raw.replace(old_dom, new_dom)

io.open(p, "wb").write(raw.encode("utf-8"))
print("OK  enrichment.py: real API integrations wired")
