import io

p = r"C:\Users\joxor\threatlens\backend\app\main.py"
raw = io.open(p, "rb").read().decode("utf-8")

# replace the entire _cleanup_e2e function with a simpler, FK-ignore version
i_start = raw.index("def _cleanup_e2e():")
# find the end: the next top-level def or the end of file
i_end = raw.index("\ndef ", i_start + 10)
if i_end == -1:
    i_end = len(raw)

NEW_CLEANUP = """def _cleanup_e2e():
    \"\"\"One-time cleanup of test artifacts from E2E verification sweeps.
    Uses PRAGMA foreign_keys=OFF (SQLite) for a clean sweep."""
    import sqlalchemy as sa
    from app.db import engine
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys = OFF"))
            has_e2e = conn.execute(sa.text(
                "SELECT COUNT(*) FROM feeds WHERE name LIKE '%E2E%'"
            )).scalar()
            if not has_e2e:
                conn.execute(sa.text("PRAGMA foreign_keys = ON"))
                return
            # indicators + all children
            conn.execute(sa.text(
                "DELETE FROM indicator_tags WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM indicator_techniques WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM indicator_sources WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM enrichments WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM analyst_notes WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM indicator_relationships WHERE source_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%') "
                "OR target_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM alerts WHERE indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM incident_timeline WHERE related_indicator_id IN "
                "(SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%'"
            ))
            # incidents + children
            conn.execute(sa.text(
                "DELETE FROM incident_timeline WHERE incident_id IN "
                "(SELECT id FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%'"
            ))
            # feeds
            conn.execute(sa.text(
                "DELETE FROM feeds WHERE name LIKE '%E2E%' OR name LIKE '%e2e%'"
            ))
            # users + tokens
            conn.execute(sa.text(
                "DELETE FROM refresh_tokens WHERE user_id IN "
                "(SELECT id FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%')"
            ))
            conn.execute(sa.text(
                "DELETE FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%'"
            ))
            # hunts
            conn.execute(sa.text(
                "DELETE FROM hunts WHERE name LIKE '%sweep test%'"
            ))
            conn.execute(sa.text("PRAGMA foreign_keys = ON"))
            conn.commit()
    except Exception:
        pass  # cleanup is best-effort, never blocks startup"""

new_raw = raw[:i_start] + NEW_CLEANUP + raw[i_end:]
io.open(p, "wb").write(new_raw.encode("utf-8"))
print("OK  _cleanup_e2e rewritten with PRAGMA foreign_keys=OFF")
