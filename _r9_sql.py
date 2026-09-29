import io

p = r"C:\Users\joxor\threatlens\backend\app\main.py"
raw = io.open(p, "rb").read().decode("utf-8")

# replace the ORM-based cleanup with raw SQL in correct FK order
old_cleanup = """def _cleanup_e2e():
    \"\"\"One-time cleanup of test artifacts pushed during E2E verification sweeps.\"\"\"
    from app.db import SessionLocal
    from app.models import Feed, User, Incident, Indicator, Hunt
    from sqlalchemy import delete, or_, select
    db = SessionLocal()
    try:
        # feeds
        for feed in db.execute(select(Feed).where(or_(Feed.name.like('%E2E%'), Feed.name.like('%e2e%')))).scalars().all():
            db.delete(feed)
        # users
        for user in db.execute(select(User).where(or_(User.email.like('e2e-%'), User.name.like('%E2E%')))).scalars().all():
            db.delete(user)
        # incidents
        for inc in db.execute(select(Incident).where(or_(Incident.title.like('E2E%'), Incident.title.like('Escalation: %'), Incident.title.like('Retest incident%')))).scalars().all():
            db.delete(inc)
        # indicators
        for ind in db.execute(select(Indicator).where(or_(Indicator.value.like('e2e-%'), Indicator.value.like('live-alert-%'), Indicator.value.like('live-broadcast%')))).scalars().all():
            db.delete(ind)
        # hunts
        for hunt in db.execute(select(Hunt).where(Hunt.name.like('%sweep test%'))).scalars().all():
            db.delete(hunt)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()"""

new_cleanup = """def _cleanup_e2e():
    \"\"\"One-time cleanup of test artifacts pushed during E2E verification sweeps.
    Uses raw SQL in FK dependency order to avoid constraint violations.\"\"\"
    import sqlalchemy as sa
    from app.db import engine
    try:
        with engine.connect() as conn:
            # find e2e indicator ids first
            ind_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM indicators WHERE value LIKE 'e2e-%' OR value LIKE 'live-alert-%' OR value LIKE 'live-broadcast%'"
            )).fetchall()]
            inc_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM incidents WHERE title LIKE 'E2E%' OR title LIKE 'Escalation: %' OR title LIKE 'Retest incident%'"
            )).fetchall()]
            user_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM users WHERE email LIKE 'e2e-%' OR name LIKE '%E2E%'"
            )).fetchall()]
            feed_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM feeds WHERE name LIKE '%E2E%' OR name LIKE '%e2e%'"
            )).fetchall()]
            hunt_ids = [row[0] for row in conn.execute(sa.text(
                "SELECT id FROM hunts WHERE name LIKE '%sweep test%'"
            )).fetchall()]

            if not any([ind_ids, inc_ids, user_ids, feed_ids, hunt_ids]):
                return

            # clean children first (FK order)
            for iid in ind_ids:
                for tbl in ['indicator_tags', 'indicator_techniques', 'indicator_sources',
                            'enrichments', 'analyst_notes', 'indicator_relationships']:
                    conn.execute(sa.text(f'DELETE FROM {tbl} WHERE indicator_id = :iid'), {'iid': iid})
                conn.execute(sa.text('DELETE FROM indicator_relationships WHERE target_id = :iid'), {'iid': iid})
            for iid in inc_ids:
                conn.execute(sa.text('DELETE FROM incident_timeline WHERE incident_id = :iid'), {'iid': iid})
            for iid in ind_ids:
                conn.execute(sa.text('UPDATE alerts SET indicator_id = NULL WHERE indicator_id = :iid'), {'iid': iid})
                conn.execute(sa.text('DELETE FROM alerts WHERE indicator_id = :iid'), {'iid': iid})
            for uid in user_ids:
                conn.execute(sa.text('DELETE FROM refresh_tokens WHERE user_id = :uid'), {'uid': uid})
            for fid in feed_ids:
                conn.execute(sa.text('DELETE FROM indicator_sources WHERE feed_id = :fid'), {'fid': fid})

            # now delete parents
            for iid in inc_ids:
                conn.execute(sa.text('DELETE FROM incidents WHERE id = :iid'), {'iid': iid})
            for iid in ind_ids:
                conn.execute(sa.text('DELETE FROM indicators WHERE id = :iid'), {'iid': iid})
            for uid in user_ids:
                conn.execute(sa.text('DELETE FROM users WHERE id = :uid'), {'uid': uid})
            for fid in feed_ids:
                conn.execute(sa.text('DELETE FROM feeds WHERE id = :fid'), {'fid': fid})
            for hid in hunt_ids:
                conn.execute(sa.text('DELETE FROM hunts WHERE id = :hid'), {'hid': hid})

            conn.commit()
    except Exception:
        pass  # cleanup is best-effort, never blocks startup"""

n = raw.count(old_cleanup)
print('cleanup anchor:', n)
if n == 1:
    raw = raw.replace(old_cleanup, new_cleanup)
    io.open(p, "wb").write(raw.encode("utf-8"))
    print("OK  main.py: cleanup rewritten with raw SQL")
