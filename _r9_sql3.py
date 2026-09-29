import io

p = r"C:\Users\joxor\threatlens\backend\app\main.py"
lines = io.open(p, "rb").read().decode("utf-8").split("\n")

# find the start of _cleanup_e2e (line 105, index 104)
start_idx = None
for i, ln in enumerate(lines):
    if ln.strip().startswith("def _cleanup_e2e"):
        start_idx = i
        break

# find the end: next line starting with "def " or end of file
end_idx = len(lines)
for i in range(start_idx + 1, len(lines)):
    if lines[i].startswith("def ") or lines[i].startswith("class "):
        end_idx = i
        break

NEW_FN = '''def _cleanup_e2e():
    """One-time cleanup of test artifacts from E2E sweeps. PRAGMA FK off."""
    import sqlalchemy as sa
    from app.db import engine
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys = OFF"))
            has_e2e = conn.execute(sa.text("SELECT COUNT(*) FROM feeds WHERE name LIKE '%E2E%'")).scalar()
            if not has_e2e:
                conn.execute(sa.text("PRAGMA foreign_keys = ON"))
                return
            conn.execute(sa.text("DELETE FROM indicator_tags WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM indicator_techniques WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM indicator_sources WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM enrichments WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM analyst_notes WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM indicator_relationships WHERE source_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%') OR target_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM alerts WHERE indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM incident_timeline WHERE related_indicator_id IN (SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%')"))
            conn.execute(sa.text("DELETE FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%'"))
            conn.execute(sa.text("DELETE FROM incident_timeline WHERE incident_id IN (SELECT id FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%')"))
            conn.execute(sa.text("DELETE FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%'"))
            conn.execute(sa.text("DELETE FROM feeds WHERE name LIKE '%E2E%' OR name LIKE '%e2e%'"))
            conn.execute(sa.text("DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%')"))
            conn.execute(sa.text("DELETE FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%'"))
            conn.execute(sa.text("DELETE FROM hunts WHERE name LIKE '%sweep test%'"))
            conn.execute(sa.text("PRAGMA foreign_keys = ON"))
            conn.commit()
    except Exception:
        pass'''

lines[start_idx:end_idx] = [NEW_FN]
content = '\n'.join(lines)
io.open(p, "wb").write(content.encode("utf-8"))
print("OK  _cleanup_e2e rewritten with PRAGMA foreign_keys=OFF, lines", start_idx + 1, "to", end_idx)
