"""Role-based access control, enforced server-side on every endpoint.

Permission matrix mirrors PRD Section 11.2. Every state-changing endpoint
declares the permission it requires; read endpoints declare read permissions.
"""

ROLE_ADMIN = "administrator"
ROLE_SEC_ENGINEER = "security_engineer"
ROLE_IR = "incident_responder"
ROLE_HUNTER = "threat_hunter"
ROLE_ANALYST = "soc_analyst"
ROLE_EXEC = "executive"

ALL_ROLES = [ROLE_ADMIN, ROLE_SEC_ENGINEER, ROLE_IR, ROLE_HUNTER, ROLE_ANALYST, ROLE_EXEC]

# Granular permissions (● = granted, ◐ = limited/contextual is modelled with
# narrower scopes at the endpoint level, — = not granted)
P_VIEW_DASHBOARDS = "dashboards.view"
P_SEARCH_INTEL = "intel.search"
P_ENRICH_TAG = "indicators.enrich"
P_MANAGE_ALERTS = "alerts.manage"
P_MANAGE_INCIDENTS = "incidents.manage"
P_SAVED_HUNTS = "hunts.save"
P_GENERATE_REPORTS = "reports.generate"
P_CONFIGURE_FEEDS = "feeds.configure"
P_MANAGE_USERS = "users.manage"
P_VIEW_AUDIT = "audit.view"
P_INGEST_EVENTS = "events.ingest"

_ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_ADMIN: {
        P_VIEW_DASHBOARDS, P_SEARCH_INTEL, P_ENRICH_TAG, P_MANAGE_ALERTS,
        P_MANAGE_INCIDENTS, P_SAVED_HUNTS, P_GENERATE_REPORTS, P_CONFIGURE_FEEDS,
        P_MANAGE_USERS, P_VIEW_AUDIT, P_INGEST_EVENTS,
    },
    ROLE_SEC_ENGINEER: {
        P_VIEW_DASHBOARDS, P_SEARCH_INTEL, P_ENRICH_TAG, P_MANAGE_ALERTS,
        P_SAVED_HUNTS, P_GENERATE_REPORTS, P_CONFIGURE_FEEDS, P_VIEW_AUDIT, P_INGEST_EVENTS,
    },
    ROLE_IR: {
        P_VIEW_DASHBOARDS, P_SEARCH_INTEL, P_ENRICH_TAG, P_MANAGE_ALERTS,
        P_MANAGE_INCIDENTS, P_SAVED_HUNTS, P_GENERATE_REPORTS, P_VIEW_AUDIT,
    },
    ROLE_HUNTER: {
        P_VIEW_DASHBOARDS, P_SEARCH_INTEL, P_ENRICH_TAG, P_MANAGE_ALERTS,
        P_MANAGE_INCIDENTS, P_SAVED_HUNTS, P_GENERATE_REPORTS,
    },
    ROLE_ANALYST: {
        P_VIEW_DASHBOARDS, P_SEARCH_INTEL, P_ENRICH_TAG, P_MANAGE_ALERTS,
        P_MANAGE_INCIDENTS, P_SAVED_HUNTS, P_GENERATE_REPORTS,
    },
    ROLE_EXEC: {
        P_VIEW_DASHBOARDS, P_GENERATE_REPORTS,
    },
}


def role_permissions(role: str) -> set[str]:
    return _ROLE_PERMISSIONS.get(role, set())


def has_permission(role: str, permission: str) -> bool:
    return permission in role_permissions(role)


class PermissionDenied(Exception):
    def __init__(self, permission: str):
        self.permission = permission
        super().__init__(f"role lacks permission: {permission}")
