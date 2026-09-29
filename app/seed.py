"""First-run seed: users for every persona, feeds, ATT&CK reference, realistic
indicators with provenance, internal events, alert rules, alerts, incidents
with append-only timelines, saved hunts. Deterministic for reproducibility."""
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record as audit_record
from app.core.security import hash_password
from app.db import SessionLocal
from app.models import (Alert, AlertRule, AttackTechnique, Feed, Hunt, Incident, IndicatorTechnique,
                        IncidentTimelineEntry, Indicator, IndicatorRelationship,
                        SecurityEvent, User, aware)
from app.services.ingest import full_pipeline, ingest_indicator
from app.services.scoring import severity_for_score

rng = random.Random(42)

NOW = datetime.now(timezone.utc)

USERS = [
    {"email": "admin@sentinova.io", "name": "Alex Morgan", "role": "administrator", "password": "Admin!Secure2026"},
    {"email": "engineer@sentinova.io", "name": "Sam Whitfield", "role": "security_engineer", "password": "Eng!nSecure2026"},
    {"email": "responder@sentinova.io", "name": "Daniel Okafor", "role": "incident_responder", "password": "IR!Secure2026x"},
    {"email": "hunter@sentinova.io", "name": "Mei Lin Tan", "role": "threat_hunter", "password": "Hunt!Secure2026"},
    {"email": "analyst@sentinova.io", "name": "Priya Nair", "role": "soc_analyst", "password": "Analyst!Secure2026"},
    {"email": "exec@sentinova.io", "name": "Rachel Adeyemi", "role": "executive", "password": "Exec!Secure2026"},
]

FEEDS = [
    {"name": "URLhaus (abuse.ch)", "slug": "urlhaus", "provider": "abuse.ch", "transport": "http_csv", "adapter": "urlhaus", "url": "https://urlhaus.abuse.ch/downloads/csv_recent/", "confidence": 70, "interval": 3600, "tlp": "green"},
    {"name": "Feodo Tracker (abuse.ch)", "slug": "feodo", "provider": "abuse.ch", "transport": "http_json", "adapter": "feodo", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "confidence": 75, "interval": 1800, "tlp": "green"},
    {"name": "ThreatFox (abuse.ch)", "slug": "threatfox", "provider": "abuse.ch", "transport": "api", "adapter": "threatfox", "url": "https://threatfox-api.abuse.ch/api/v1/", "confidence": 65, "interval": 3600, "tlp": "green"},
    {"name": "CISA KEV Catalog", "slug": "cisa_kev", "provider": "cisa.gov", "transport": "http_json", "adapter": "cisa_kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "confidence": 95, "interval": 7200, "tlp": "clear"},
    {"name": "AlienVault OTX", "slug": "otx", "provider": "alienvault", "transport": "api", "adapter": "otx", "url": "https://otx.alienvault.com/api/v1/", "confidence": 60, "interval": 7200, "tlp": "amber", "secret_ref": "secrets:otx_api_key", "enabled": False},
    {"name": "Sentinova Internal Telemetry", "slug": "internal_telemetry", "provider": "sentinova", "transport": "internal_sim", "adapter": "internal_sim", "url": None, "confidence": 55, "interval": 600, "tlp": "amber"},
    {"name": "Sentinova Reference Feed", "slug": "reference", "provider": "sentinova", "transport": "internal_sim", "adapter": "reference", "url": None, "confidence": 80, "interval": 86400, "tlp": "amber"},
]

TECHNIQUES = [
    ("T1566", "Phishing", "initial-access"), ("T1566.002", "Spearphishing Link", "initial-access"),
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1078", "Valid Accounts", "defense-evasion"), ("T1078.002", "Domain Accounts", "defense-evasion"),
    ("T1059", "Command and Scripting Interpreter", "execution"), ("T1059.001", "PowerShell", "execution"),
    ("T1204.002", "Malicious File", "execution"), ("T1105", "Ingress Tool Transfer", "command-and-control"),
    ("T1071", "Application Layer Protocol", "command-and-control"),
    ("T1071.001", "Web Protocols", "command-and-control"),
    ("T1568", "Dynamic Resolution", "command-and-control"), ("T1568.002", "Domain Generation Algorithms", "command-and-control"),
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),
    ("T1486", "Data Encrypted for Impact", "impact"),
    ("T1490", "Inhibit System Recovery", "impact"),
    ("T1110", "Brute Force", "credential-access"), ("T1110.003", "Password Spraying", "credential-access"),
    ("T1218.011", "Rundll32", "defense-evasion"), ("T1036", "Masquerading", "defense-evasion"),
    ("T1087", "Account Discovery", "discovery"), ("T1046", "Network Service Discovery", "discovery"),
    ("T1098", "Account Manipulation", "persistence"), ("T1136", "Create Account", "persistence"),
    ("T1021.001", "Remote Desktop Protocol", "lateral-movement"),
    ("T1021.003", "Distributed Component Object Model", "lateral-movement"),
    ("T1005", "Data from Local System", "collection"), ("T1056", "Input Capture", "collection"),
    ("T1489", "Service Stop", "impact"),
]

FAMILY_GEN = [
    ("185.220.101.{n}", "ip", None, ["tor_exit"], 78, "High-abuse Tor exit node observed in credential-stuffing activity"),
    ("91.245.77.{n}", "ip", "Emotet", ["c2", "emotet"], 82, "Emotet botnet C2 endpoint"),
    ("45.9.148.{n}", "ip", "Dridex", ["c2", "dridex"], 80, "Dridex botnet C2 endpoint"),
    ("103.221.254.{n}", "ip", "AsyncRAT", ["c2", "asyncrat"], 74, "AsyncRAT command-and-control endpoint"),
    ("152.32.132.{n}", "ip", "IcedID", ["loader", "icedid"], 79, "IcedID loader infrastructure"),
    ("45.134.139.{n}", "ip", "Cobalt Strike", ["c2", "cobalt_strike"], 84, "Cobalt Strike team server"),
    ("{w}-secure-login.{tld}", "domain", "PhishKit", ["phishing", "newly_registered"], 76, "Credential-phishing domain mimicking a login portal"),
    ("invoice-{w}-update.{tld}", "domain", None, ["bec", "phishing"], 71, "BEC lure domain impersonating invoice workflow"),
    ("cdn-{w}-delivery.{tld}", "domain", "IcedID", ["loader"], 73, "Payload staging domain for IcedID campaigns"),
    ("mail-{w}-verify.{tld}", "domain", "PhishKit", ["phishing"], 69, "Verification lure domain"),
    ("http://185.234.219.{n}/{w}.bin", "url", "Emotet", ["payload", "emotet"], 80, "Direct dropper download URL"),
    ("http://45.134.139.{n}/panel/login.php", "url", "Cobalt Strike", ["c2", "cobalt_strike"], 85, "Cobalt Strike panel login"),
    ("http://152.32.132.{n}/deliver/{w}.exe", "url", "IcedID", ["payload"], 78, "Payload delivery URL"),
    ("{h:32}", "hash_md5", "Qakbot", ["malware"], 65, "Qakbot dropper hash from sandbox analysis"),
    ("{h:40}", "hash_sha1", "AgentTesla", ["malware"], 67, "AgentTesla sample hash"),
    ("{h:64}", "hash_sha256", "IcedID", ["malware"], 86, "IcedID loader SHA-256 from multi-engine detection"),
    ("CVE-2025-24813", "cve", None, ["kev", "exploited"], 95, "Tomcat deserialization RCE â€” known exploited"),
    ("CVE-2024-3400", "cve", None, ["kev", "exploited"], 95, "Palo Alto GlobalProtect command injection â€” known exploited"),
    ("CVE-2025-31161", "cve", None, ["kev"], 90, "ConnectWise authentication bypass â€” known exploited"),
    ("svc-{w}-renewal.{tld}", "domain", "PhishKit", ["phishing"], 66, "Subscription-renewal phishing domain"),
    ("203.0.113.{n}", "ip", None, ["scanner", "noise"], 30, "Internet-wide scanner noise (GreyNoise-classified)"),
]

WORDS = ["invoice", "support", "secure", "verify", "update", "portal", "login", "mail", "delivery", "renewal", "account", "billing", "cloud", "docs"]
TLDS = ["top", "xyz", "online", "click", "shop", "info", "com"]

ASSETS = ["WS-FIN-114", "SRV-ERP-02", "WS-HR-208", "SRV-FILE-01", "WS-ENG-332", "SRV-DC-01", "WS-SAL-077", "SRV-MX-03"]
EVENT_TYPES = ["dns_query", "http_request", "firewall_deny", "edr_detection", "auth_fail"]


def _make_hash(n: int) -> str:
    return rng.getrandbits(n * 4).to_bytes(n, "big").hex()


def _fake_records(n: int) -> list[dict]:
    out = []
    for _ in range(n):
        fam_tpl, typ, family, tags, conf, desc = rng.choice(FAMILY_GEN)
        if fam_tpl == "{h:32}":
            value = _make_hash(16)
        elif fam_tpl == "{h:40}":
            value = _make_hash(20)
        elif fam_tpl == "{h:64}":
            value = _make_hash(32)
        else:
            value = fam_tpl.format(
                n=rng.randrange(1, 254), w=rng.choice(WORDS), tld=rng.choice(TLDS), h="x"
            )
        seen = NOW - timedelta(hours=rng.uniform(0, 120))
        out.append({
            "value": value, "type": typ, "seen_at": seen, "malware_family": family,
            "confidence": conf, "description": desc, "tags": tags,
            "source_name": rng.choice(["reference", "urlhaus", "feodo", "threatfox", "otx"]),
        })
    return out


def seed_if_empty(db: Session) -> bool:
    if db.execute(select(func.count(User.id))).scalar():
        return False

    # Users
    users = {}
    for u in USERS:
        user = User(email=u["email"], name=u["name"], role=u["role"], password_hash=hash_password(u["password"]))
        db.add(user)
        users[u["role"]] = user
    db.flush()

    # Feeds
    feeds = {}
    for f in FEEDS:
        feed = Feed(
            name=f["name"], slug=f["slug"], provider=f["provider"], transport=f["transport"],
            url=f.get("url"), default_tlp=f["tlp"], source_confidence=f["confidence"],
            poll_interval_seconds=f["interval"], enabled=f.get("enabled", True),
            secret_ref=f.get("secret_ref"),
            last_polled_at=NOW - timedelta(minutes=rng.randrange(2, 40)),
            last_status="ok" if f.get("enabled", True) else "ok",
            items_ingested=0,
        )
        db.add(feed)
        feeds[f["slug"]] = feed
    db.flush()

    # ATT&CK reference
    for tid, name, tactic in TECHNIQUES:
        db.add(AttackTechnique(technique_id=tid, name=name, tactic=tactic))
    db.flush()

    # Reference feed indicators (high quality, curated)
    from app.feeds.adapters import REFERENCE_FEED
    for i, rec in enumerate(REFERENCE_FEED):
        ingest_indicator(
            db, value=rec["value"], feed=feeds["reference"],
            source_confidence=rec["confidence"], seen_at=NOW - timedelta(hours=(i * 7) % 96),
            description=rec["description"], malware_family=rec.get("malware_family"),
            tlp="amber", reference=f"threatlens://reference/{i}", tag_names=rec.get("tags"),
        )

    # Generated corpus with multi-source provenance
    records = _fake_records(70)
    for rec in records:
        feed = feeds.get(rec["source_name"], feeds["reference"])
        ind = ingest_indicator(
            db, value=rec["value"], hint_type=rec["type"], feed=feed,
            seen_at=rec["seen_at"], description=rec["description"],
            malware_family=rec["malware_family"], tlp=feed.default_tlp,
            tag_names=rec["tags"],
        )
        if ind and rng.random() < 0.35:
            # corroborated by a second independent source (dedupe/provenance demo)
            ingest_indicator(
                db, value=rec["value"], hint_type=rec["type"], feed=feeds["otx"] if not feed == feeds["otx"] else feeds["reference"],
                seen_at=rec["seen_at"] + timedelta(hours=rng.uniform(0.5, 12)),
                tlp=feed.default_tlp, tag_names=rec["tags"],
            )

    # Relationships (resolves-to / communicates-with / drops)
    ips = db.execute(select(Indicator).where(Indicator.type == "ip").limit(20)).scalars().all()
    domains = db.execute(select(Indicator).where(Indicator.type == "domain").limit(20)).scalars().all()
    urls = db.execute(select(Indicator).where(Indicator.type == "url").limit(15)).scalars().all()
    for d in domains:
        if ips and rng.random() < 0.6:
            db.add(IndicatorRelationship(source_id=d.id, target_id=rng.choice(ips).id, relation="resolves-to"))
    for u in urls:
        if ips and rng.random() < 0.5:
            db.add(IndicatorRelationship(source_id=u.id, target_id=rng.choice(ips).id, relation="communicates-with"))
    for i in ips:
        if domains and rng.random() < 0.3:
            db.add(IndicatorRelationship(source_id=i.id, target_id=rng.choice(domains).id, relation="drops"))

    # ATT&CK mapping on the highest-scoring indicators
    tech_by_id = {t.technique_id: t for t in db.execute(select(AttackTechnique)).scalars().all()}
    top = db.execute(select(Indicator).order_by(Indicator.severity_score.desc()).limit(30)).scalars().all()
    for ind in top:
        chosen = rng.sample(list(tech_by_id.values()), k=rng.randrange(1, 3))
        for tech in chosen:
            if all(lt.technique_id != tech.technique_id for lt in ind.techniques):
                ind.techniques.append(IndicatorTechnique(technique_id=tech.technique_id))

    # Internal security events (correlation window is 7 days)
    active = db.execute(select(Indicator).where(Indicator.status == "active")).scalars().all()
    eventful = [i for i in active if i.type in ("ip", "domain", "url", "cve")]
    for _ in range(160):
        ind = rng.choice(eventful)
        observed = NOW - timedelta(hours=rng.uniform(0, 168))
        db.add(SecurityEvent(
            observed_at=observed, event_type=rng.choice(EVENT_TYPES),
            indicator_value=ind.value, indicator_type=ind.type,
            asset=rng.choice(ASSETS) if rng.random() < 0.85 else None,
            source_system=rng.choice(["sentinova-fw01", "sentinova-edr", "dns-sink", "waf-prod", "vpn-gw"]),
            country=rng.choice(["RU", "CN", "US", "BR", "NL", "DE", "UA", "IR", "VN", "IN"]),
        ))
    db.flush()
    # refresh sighting-based scoring
    from app.services.correlation import correlate_indicator
    for ind in eventful:
        correlate_indicator(db, ind)
        from app.services.ingest import refresh_score
        refresh_score(db, ind)
    db.flush()

    # Alert rules
    rules = [
        AlertRule(name="Critical score watchdog", min_score=85, enabled=True),
        AlertRule(name="C2 infrastructure spotted internally", min_score=65, tags=["c2"], require_internal_sighting=True, route_to_role="soc_analyst"),
        AlertRule(name="Known-exploited CVE ingested", min_score=80, ioc_types=["cve"], route_to_role="incident_responder"),
        AlertRule(name="Phishing domain wave", min_score=60, tags=["phishing"], route_to_role="soc_analyst"),
    ]
    db.add_all(rules)
    db.flush()

    # Raise alerts via the engine for pipeline realism
    from app.services.alerting import evaluate_rules_for_indicator
    for ind in eventful:
        evaluate_rules_for_indicator(db, ind)
    db.flush()

    # Lifecycle realism: acknowledge/assign/resolve a portion of the queue
    alerts = db.execute(select(Alert).order_by(Alert.created_at.asc())).scalars().all()
    analyst = users["soc_analyst"]
    responder = users["incident_responder"]
    for i, a in enumerate(alerts):
        if i % 5 == 0:
            a.state = "acknowledged"
            a.assignee_id = analyst.id
            a.acknowledged_at = a.created_at + timedelta(minutes=6)
        elif i % 7 == 0:
            a.state = "in_progress"
            a.assignee_id = analyst.id
            a.acknowledged_at = a.created_at + timedelta(minutes=4)
        elif i % 11 == 0:
            a.state = "resolved"
            a.assignee_id = analyst.id
            a.acknowledged_at = a.created_at + timedelta(minutes=9)
            a.resolved_at = a.created_at + timedelta(hours=rng.uniform(1, 20))
        if aware(a.created_at) < NOW - timedelta(hours=6):
            a.created_at = NOW - timedelta(hours=rng.uniform(6, 160))

    # Incidents with timelines
    top_alerts = db.execute(select(Alert).order_by(Alert.severity_score.desc()).limit(8)).scalars().all()
    incidents_spec = [
        ("Emotet loader activity on finance workstations", "critical", "open", ["new", "acknowledged", "in_progress", "resolved", "closed"]),
        ("Credential-phishing wave targeting invoice workflows", "high", "contained", ["new", "acknowledged", "in_progress", "resolved", "closed"]),
        ("Known-exploited VPN appliance vulnerability (KEV)", "critical", "resolved", ["new", "acknowledged", "in_progress", "resolved", "closed"]),
    ]
    for (title, sev, status, states) in incidents_spec:
        incident = Incident(
            title=title, severity=sev, status=status,
            lead_id=responder.id if status != "resolved" else analyst.id,
            description=f"Investigation container for: {title}. Built from correlated intelligence and analyst actions.",
            alert_ids=[], indicator_ids=[],
            containment_checklist=[
                {"text": "Isolate affected hosts", "done": status in ("contained", "resolved")},
                {"text": "Block indicators at perimeter", "done": status in ("contained", "resolved")},
                {"text": "Rotate exposed credentials", "done": status == "resolved"},
                {"text": "Preserve forensic evidence", "done": status == "resolved"},
            ],
            created_at=NOW - timedelta(days=rng.uniform(1, 5)),
        )
        db.add(incident)
        db.flush()

        related = [a for a in top_alerts if a.state in states]
        for a in related[:3]:
            from app.services.alerting import escalate_to_incident
            escalate_to_incident(db, a, incident)
            a.state = "closed"
            a.resolved_at = a.created_at + timedelta(hours=3)
        db.flush()

        for ind_id in incident.indicator_ids:
            ind = db.get(Indicator, ind_id)
            if ind:
                db.add(IncidentTimelineEntry(
                    incident_id=incident.id, occurred_at=incident.created_at + timedelta(minutes=5),
                    entry_type="detection", actor_email=analyst.email,
                    title=f"Detection: {ind.value} matched alert criteria",
                    body=f"Indicator type {ind.type}, severity {ind.severity_score}, family {ind.malware_family}",
                    related_indicator_id=ind.id,
                    evidence={"severity_score": ind.severity_score, "confidence": ind.confidence},
                ))
        base = incident.created_at
        timeline = [
            (base + timedelta(minutes=2), "note", responder.email, "Incident opened and triage started", None),
            (base + timedelta(minutes=38), "correlation", "correlation-engine@system", "Correlated 6 internal sightings across firewall and EDR telemetry", None),
            (base + timedelta(hours=1, minutes=12), "analyst_action", analyst.email, "Enriched primary indicators; reputation confirms malicious hosting", None),
            (base + timedelta(hours=3), "containment", responder.email, "Affected host isolated; indicators pushed to perimeter blocklist", None),
            (base + timedelta(hours=8), "note", responder.email, "Forensic image captured and evidence preserved under case ID", None),
        ]
        if status == "resolved":
            timeline.append((base + timedelta(days=1, hours=4), "report", responder.email, "Post-incident report generated from the audit trail", None))
        for ts, etype, actor, t, b in timeline:
            db.add(IncidentTimelineEntry(incident_id=incident.id, occurred_at=ts, entry_type=etype, actor_email=actor, title=t, body=b))
        db.flush()

    # Saved hunts
    db.add_all([
        Hunt(name="IcedID loader infrastructure sweep", query="icedid", facets={"types": ["ip", "domain", "url"], "min_score": 65},
             notes="Sweep for shared loader infrastructure across c2/loader tags; pivot on ASN clusters.",
             created_by_id=users["threat_hunter"].id, created_by_email=users["threat_hunter"].email),
        Hunt(name="Phishing domain patterns (newly registered)", query="phishing", facets={"types": ["domain"], "min_score": 60},
             notes="Hunt hypothesis: newly-registered look-alike domains precede BEC attempts by 3-5 days.",
             created_by_id=users["threat_hunter"].id, created_by_email=users["threat_hunter"].email),
    ])

    audit_record(db, actor_id=None, actor_email="system@seed", action="system.seeded",
                 details={"users": len(USERS), "feeds": len(FEEDS), "techniques": len(TECHNIQUES)})
    db.commit()
    return True


def run_seed() -> bool:
    db = SessionLocal()
    try:
        return seed_if_empty(db)
    finally:
        db.close()


