"""API-level tests: RBAC enforcement, audit coverage, lifecycle transitions."""
import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.gettempdir()}/threatlens_test_{os.getpid()}.db")

from tests.conftest import client  # noqa: E402


def login(email: str, password: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


ROLE_ACCOUNTS = {
    "admin": ("admin@sentinova.io", "Admin!Secure2026", "administrator"),
    "engineer": ("engineer@sentinova.io", "Eng!nSecure2026", "security_engineer"),
    "responder": ("responder@sentinova.io", "IR!Secure2026x", "incident_responder"),
    "hunter": ("hunter@sentinova.io", "Hunt!Secure2026", "threat_hunter"),
    "analyst": ("analyst@sentinova.io", "Analyst!Secure2026", "soc_analyst"),
    "exec": ("exec@sentinova.io", "Exec!Secure2026", "executive"),
}


def test_health_public():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_rejects_bad_credentials():
    r = client.post("/api/v1/auth/login", json={"email": "admin@sentinova.io", "password": "wrong"})
    assert r.status_code == 401
    assert r.json()["error_code"] == "invalid_credentials"


def test_all_roles_can_login():
    for email, pwd, role in ROLE_ACCOUNTS.values():
        r = client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
        assert r.status_code == 200, f"{email}: {r.text}"
        assert r.json()["user"]["role"] == role


def test_missing_token_is_401():
    r = client.get("/api/v1/indicators")
    assert r.status_code == 401


def test_rbac_matrix():
    tokens = {key: login(email, pwd) for key, (email, pwd, _role) in ROLE_ACCOUNTS.items()}

    # Executives can read dashboards but cannot search intelligence (— in matrix)
    r = client.get("/api/v1/dashboard/executive", headers=auth_header(tokens["exec"]))
    assert r.status_code == 200
    r = client.get("/api/v1/indicators", headers=auth_header(tokens["exec"]))
    assert r.status_code == 403

    # Executives cannot manage alerts
    r = client.get("/api/v1/alerts", headers=auth_header(tokens["exec"]))
    assert r.status_code == 403

    # Analysts cannot configure feeds
    r = client.get("/api/v1/feeds", headers=auth_header(tokens["analyst"]))
    assert r.status_code == 403

    # Engineers configure feeds but cannot manage users
    r = client.get("/api/v1/feeds", headers=auth_header(tokens["engineer"]))
    assert r.status_code == 200
    r = client.get("/api/v1/users", headers=auth_header(tokens["engineer"]))
    assert r.status_code == 403

    # Only admin sees the full audit log and user list
    r = client.get("/api/v1/audit", headers=auth_header(tokens["admin"]))
    assert r.status_code == 200
    r = client.get("/api/v1/users", headers=auth_header(tokens["admin"]))
    assert r.status_code == 200


def test_indicator_flow_and_audit():
    token = login(*ROLE_ACCOUNTS["analyst"][:2])
    r = client.post("/api/v1/indicators", headers=auth_header(token),
                    json={"value": "192.0.2.55", "description": "test", "tags": ["c2"]})
    assert r.status_code == 201, r.text
    ind = r.json()
    assert ind["severity_score"] >= 0

    # enrich
    r = client.post(f"/api/v1/indicators/{ind['id']}/enrich", headers=auth_header(token))
    assert r.status_code == 200
    body = r.json()
    assert "enrichment" in body and "geo" in body["enrichment"]

    # search finds it
    r = client.get("/api/v1/search", headers=auth_header(token), params={"q": "192.0.2.55"})
    assert r.status_code == 200
    assert r.json()["count"] >= 1

    # audit trail recorded both actions
    admin_token = login(*ROLE_ACCOUNTS["admin"][:2])
    r = client.get("/api/v1/audit", headers=auth_header(admin_token), params={"action": "indicator.enriched"})
    assert r.status_code == 200 and r.json()["total"] >= 1


def test_invalid_ioc_rejected():
    token = login(*ROLE_ACCOUNTS["analyst"][:2])
    r = client.post("/api/v1/indicators", headers=auth_header(token), json={"value": "!!!not-an-ioc!!!"})
    assert r.status_code == 422


def test_alert_lifecycle_transitions():
    token = login(*ROLE_ACCOUNTS["analyst"][:2])
    r = client.get("/api/v1/alerts", headers=auth_header(token), params={"state": "new", "page_size": 1})
    assert r.status_code == 200 and r.json()["total"] > 0
    alert_id = r.json()["items"][0]["id"]

    r = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth_header(token), json={"state": "in_progress"})
    assert r.status_code == 409, "new → in_progress must be rejected"

    r = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth_header(token), json={"state": "acknowledged"})
    assert r.status_code == 200 and r.json()["state"] == "acknowledged"

    r = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth_header(token), json={"state": "in_progress"})
    assert r.status_code == 200

    r = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth_header(token), json={"state": "resolved"})
    assert r.status_code == 200


def test_alert_escalation_creates_incident():
    token = login(*ROLE_ACCOUNTS["analyst"][:2])
    r = client.get("/api/v1/alerts", headers=auth_header(token), params={"state": "new", "page_size": 1})
    alert = r.json()["items"][0]
    r = client.patch(f"/api/v1/alerts/{alert['id']}", headers=auth_header(token),
                     json={"new_incident_title": "Escalated incident from test"})
    assert r.status_code == 200
    incident_id = r.json().get("incident_id")
    assert incident_id

    r = client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=auth_header(token))
    assert r.status_code == 200
    assert any("escalat" in e["title"].lower() for e in r.json()["entries"])


def test_incident_timeline_append_order():
    token = login(*ROLE_ACCOUNTS["responder"][:2])
    r = client.get("/api/v1/incidents", headers=auth_header(token))
    inc = r.json()["items"][0]
    r = client.post(f"/api/v1/incidents/{inc['id']}/timeline", headers=auth_header(token),
                    json={"entry_type": "note", "title": "Analyst note from test", "body": "manual entry"})
    assert r.status_code == 201
    r = client.get(f"/api/v1/incidents/{inc['id']}/timeline", headers=auth_header(token))
    entries = r.json()["entries"]
    assert entries == sorted(entries, key=lambda e: e["occurred_at"]), "timeline must be ordered"


def test_exports():
    token = login(*ROLE_ACCOUNTS["hunter"][:2])
    r = client.get("/api/v1/export/stix", headers=auth_header(token), params={"min_score": 50, "tlp_max": "amber"})
    assert r.status_code == 200
    bundle = r.json()
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) > 0
    for obj in bundle["objects"]:
        assert obj["type"] in ("indicator", "file")
        if obj["type"] == "indicator":
            assert obj["pattern"].startswith("[")

    r = client.get("/api/v1/export/csv", headers=auth_header(token))
    assert r.status_code == 200
    assert b"value,type" in r.content

    r = client.post("/api/v1/reports", headers=auth_header(token), json={"title": "Test report"})
    assert r.status_code == 200, r.text
    report_id = r.json()["id"]
    r = client.get(f"/api/v1/reports/{report_id}/download", headers=auth_header(token))
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_stix_tlp_restriction():
    token = login(*ROLE_ACCOUNTS["hunter"][:2])
    r = client.get("/api/v1/export/stix", headers=auth_header(token), params={"tlp_max": "green"})
    bundle = r.json()
    for obj in bundle["objects"]:
        if obj["type"] == "indicator":
            assert obj["x_threatlens_tlp"] in ("clear", "green")


def test_events_ingest_webhook():
    token = login(*ROLE_ACCOUNTS["admin"][:2])
    payload = {"event_type": "firewall_deny", "indicator_value": "198.51.100.200", "asset": "WS-TEST-1"}
    r = client.post("/api/v1/events", headers=auth_header(token), json=[payload, payload])
    assert r.status_code == 202
    assert r.json()["accepted"] == 2

    # exec may not push events
    exec_token = login(*ROLE_ACCOUNTS["exec"][:2])
    r = client.post("/api/v1/events", headers=auth_header(exec_token), json=payload)
    assert r.status_code == 403


def test_feeds_admin_flow():
    token = login(*ROLE_ACCOUNTS["engineer"][:2])
    r = client.get("/api/v1/feeds", headers=auth_header(token))
    assert r.status_code == 200
    feeds = r.json()["items"]
    assert len(feeds) >= 6, "PRD requires ≥6 configured sources"
    enabled = [f for f in feeds if f["enabled"]]
    assert len(enabled) >= 5

    target = next(f for f in feeds if f["slug"] == "reference")
    r = client.post(f"/api/v1/feeds/{target['id']}/poll", headers=auth_header(token))
    assert r.status_code == 200
    assert r.json()["poll_result"]["records"] > 0


def test_login_lockout():
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "hunter@sentinova.io", "password": "bad-bad-bad"})
    r = client.post("/api/v1/auth/login", json={"email": "hunter@sentinova.io", "password": "bad-bad-bad"})
    assert r.status_code == 423, "5 consecutive failures must lock the account"
