import io

BASE = r"C:\Users\joxor\threatlens\backend"

# 1) auth.py: set the refresh cookie on login
p = BASE + r"\app\api\v1\auth.py"
raw = io.open(p, "rb").read().decode("utf-8")

old_sig = "def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):"
new_sig = "def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):"
n = raw.count(old_sig)
print('login sig anchor:', n)
if n == 1:
    raw = raw.replace(old_sig, new_sig)

# add Response import
old_imp = "from fastapi import APIRouter, HTTPException, Request, status"
new_imp = "from fastapi import APIRouter, HTTPException, Request, Response, status"
n = raw.count(old_imp)
print('Response import anchor:', n)
if n == 1:
    raw = raw.replace(old_imp, new_imp)

# set the refresh cookie before returning LoginOut
old_ret = "    return LoginOut(access_token=access, expires_in=ttl, user=_user_dict(user))"
new_ret = """    response.set_cookie(
        key="threatlens_refresh",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_DAYS * 24 * 3600,
    )
    return LoginOut(access_token=access, expires_in=ttl, user=_user_dict(user))"""
n = raw.count(old_ret)
print('cookie set anchor:', n)
if n == 1:
    raw = raw.replace(old_ret, new_ret)

# refresh endpoint: also set a new cookie after rotation
old_refresh_ret = '    return {"access_token": access, "token_type": "bearer", "expires_in": ttl}'
new_refresh_ret = """    response.set_cookie(
        key="threatlens_refresh",
        value=new_refresh,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_DAYS * 24 * 3600,
    )
    return {"access_token": access, "token_type": "bearer", "expires_in": ttl}"""
n = raw.count(old_refresh_ret)
print('refresh cookie anchor:', n)
if n == 1:
    raw = raw.replace(old_refresh_ret, new_refresh_ret)

# refresh endpoint also needs Response param
old_refresh_sig = "def refresh(request: Request, db: Session = Depends(get_db)):"
new_refresh_sig = "def refresh(request: Request, response: Response, db: Session = Depends(get_db)):"
n = raw.count(old_refresh_sig)
print('refresh sig anchor:', n)
if n == 1:
    raw = raw.replace(old_refresh_sig, new_refresh_sig)

io.open(p, "wb").write(raw.encode("utf-8"))

# 2) cleanup: add e2e artifact removal to the startup lifespan
p2 = BASE + r"\app\main.py"
raw2 = io.open(p2, "rb").read().decode("utf-8")

old_lifespan = "    run_seed()"
new_lifespan = """    run_seed()
    _cleanup_e2e()"""
n = raw2.count(old_lifespan)
print('lifespan cleanup anchor:', n)
if n == 1:
    raw2 = raw2.replace(old_lifespan, new_lifespan)

cleanup_fn = '''

def _cleanup_e2e():
    """One-time cleanup of test artifacts pushed during E2E verification sweeps."""
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
        db.close()
'''
if '_cleanup_e2e' not in raw2 or raw2.count('def _cleanup_e2e') <= 1:
    raw2 = raw2.rstrip() + "\n" + cleanup_fn
    io.open(p2, "wb").write(raw2.encode("utf-8"))
    print("OK  main.py: cleanup appended")
