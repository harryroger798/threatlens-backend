# ThreatLens — Cyber Threat Intelligence Dashboard

A production CTI platform for aggregating, correlating, scoring and operationalising
threat intelligence across a SOC. Built with FastAPI, SQLAlchemy and a vanilla JS
operations console, deployed on Render + Cloudflare Pages.

**Live:** https://threatlens-5f1.pages.dev/threatlens
**API:** https://threatlens-backend-tqbc.onrender.com (Swagger at `/docs`)

## What it does

ThreatLens ingests indicators of compromise (IOCs) from public threat feeds, enriches
them against reputation services, correlates them against internal security events,
assigns a confidence-weighted severity score, and surfaces the results through four
role-specific dashboards: Executive, SOC Analyst, Incident Response and Threat Hunting.

Standards: STIX 2.1 export, MITRE ATT&CK technique mapping, Traffic Light Protocol,
Cyber Kill Chain / Diamond Model fields, CISA KEV catalog integration.

## Architecture

```
External feeds (abuse.ch, CISA KEV, TAXII 2.1)
        │  per-feed scheduler (independent intervals)
        ▼
Normalise → Deduplicate → Score (0–100) → Correlate → Alert rules
        │                                        │
        ▼                                        ▼
  Canonical store (SQLite/Postgres)       Event bus (asyncio/Redis)
        │                                        │
        └──────► FastAPI REST (/api/v1) ◄────────┘
                        │         │
                   WebSocket   Swagger UI
                        │
              Vanilla JS console (Tailwind v4)
              Executive │ Analyst │ IR │ Hunting
```

### Scoring model

Every indicator gets a 0–100 score from five weighted inputs:

```
score = 0.30 × source_reputation
      + 0.25 × aggregate_confidence
      + 0.20 × recency (exp decay, 72h half-life)
      + 0.15 × internal_sightings (20 pts each, capped)
      + 0.10 × ioc_type_weight
```

Severity bands: ≥85 critical · ≥70 high · ≥45 medium · ≥25 low · else info.

### Feed pipeline

Each feed polls on an independent schedule (600–86,400 s). Records are normalised
to a canonical schema (IP, domain, URL, MD5, SHA-1, SHA-256, email, CVE), deduplicated
to a single canonical record with per-source provenance, TTL-aged, scored, correlated
against internal events, and evaluated against configurable alert rules.

Adapters: URLhaus CSV, Feodo Tracker JSON, ThreatFox API, CISA KEV JSON, OTX REST,
TAXII 2.1 collections, internal telemetry simulator, curated reference set.

### Enrichment

IP reputation via AbuseIPDB API v2, geolocation/ASN via ip-api.com, hash verdicts via
VirusTotal API v3, domain analysis via VirusTotal, CVE lookups via CISA KEV.
Results cached (60 min TTL) with deterministic fallback when keys are not configured.

## Project structure

```
backend/
  app/
    api/v1/          # REST routers (46 endpoints across 10 routers)
      auth.py         # JWT login, refresh rotation, MFA, password change
      indicators.py   # IOC CRUD, enrich, tags, notes, correlation, relationships
      intel.py        # IP reputation, hash lookup, domain analysis, search, ATT&CK
      alerts.py       # Alert queue, rules engine, lifecycle transitions
      incidents.py    # Incident workspace, timeline, checklist
      feeds.py        # Feed CRUD, toggle, re-poll
      events.py       # Inbound SIEM/EDR webhook
      dashboard.py    # Executive/analyst/threat aggregations
      admin.py        # Users, audit log, saved hunts, system health
      reports_export.py  # PDF generation, STIX 2.1 bundles, CSV export
    core/
      config.py       # Settings (env vars, scoring weights, rate limits)
      security.py     # JWT, bcrypt, TOTP MFA
      permissions.py  # RBAC matrix (6 roles × 11 permissions)
      audit.py        # Append-only audit trail
      ratelimit.py    # Per-principal sliding-window limiter
    services/
      scoring.py      # 0–100 scoring engine
      normalise.py    # IOC type detection + canonicalisation
      ingest.py       # Canonical merge, provenance, TTL, scoring pipeline
      enrichment.py   # AbuseIPDB, VirusTotal, ip-api.com, CISA KEV integrations
      correlation.py  # Indicator ↔ internal event matching
      alerting.py     # Alert rule evaluation + lifecycle transitions
      bus.py          # In-process pub/sub (Redis-swappable)
    feeds/
      adapters.py     # Feed adapters (URLhaus, Feodo, ThreatFox, CISA KEV, OTX, TAXII 2.1)
      taxii21.py      # TAXII 2.1 client with STIX pattern parser
      runner.py       # Background feed scheduler thread
    ws.py             # WebSocket gateway (4 channels)
  services/           # ES search/projector seam
  tests/              # 28 unit tests
  requirements.txt
  Dockerfile
  render.yaml
```

## Running locally

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/uvicorn app.main:app --port 8000
# Swagger UI at http://localhost:8000/docs
```

First run creates the SQLite schema, seeds demo data (personas, feeds, ATT&CK
techniques, indicators, events, incidents) and starts the feed scheduler.

## Tests

```bash
.venv/Scripts/pytest tests -q
# 28 tests: scoring, dedup, normalise, RBAC, lifecycle, exports, lockout
```

## Deployment

- **Backend**: Render (Docker, 1c-2g, persistent disk for SQLite)
- **Frontend**: Cloudflare Pages (vanilla JS console + Pages Function proxy)
- **Repo**: github.com/harryroger798/threatlens-backend

## Key decisions

- SQLite over Postgres for the baseline (zero-dependency, persistent disk on Render;
  DATABASE_URL swaps to Postgres for production scale)
- In-process scheduler over Celery (single-engineer build; per-feed independence via
  threading; Redis-swappable pub/sub for multi-instance)
- Canonical store search over Elasticsearch (ES seam implemented: document shape,
  mapping, DSL builder, projector — drop in ES_URL to activate)
- Vanilla JS console over React (smaller bundle, no build step, same Tailwind
  design system; TanStack-equivalent caching via custom fetch layer)
