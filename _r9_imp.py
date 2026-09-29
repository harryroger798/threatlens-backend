import io

p = r"C:\Users\joxor\threatlens\backend\app\api\v1\auth.py"
raw = io.open(p, "rb").read().decode("utf-8")

old = "from fastapi import APIRouter, Depends, HTTPException, Request, status"
new = "from fastapi import APIRouter, Depends, HTTPException, Request, Response, status"
n = raw.count(old)
print('anchor:', n)
if n == 1:
    raw = raw.replace(old, new)
    io.open(p, "wb").write(raw.encode("utf-8"))
