from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import time
import os
from contextlib import asynccontextmanager
import secrets

DB = "/data/tokens.db"
ADMIN_KEY = os.getenv("ADMIN_KEY", "olly6969")

PLAN_DURATIONS = {
    # days
    "1d": 1 * 86400,
    "3d": 3 * 86400,

    # weeks
    "1w": 7 * 86400,
    "2w": 14 * 86400,
    "3w": 21 * 86400,
    "6w": 42 * 86400,

    # months (30d each, standard practice)
    "1m": 30 * 86400,
    "2m": 60 * 86400,
    "3m": 90 * 86400,
    "6m": 180 * 86400,
    "9m": 270 * 86400,

    # years
    "1y": 365 * 86400,
    "2y": 730 * 86400,

    # lifetime
    "infinite": None
}

from fastapi import Header, Depends

def require_admin(x_admin_key: str | None = Header(None)):
    if x_admin_key != os.environ.get("ADMIN_KEY"):
        raise HTTPException(status_code=401, detail="Unauthorized")

def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at REAL,
            revoked INTEGER DEFAULT 0
        )
    """)
    con.commit()
    con.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🔥 Initializing database")
    init_db()
    yield
    print("🛑 Shutting down")

app = FastAPI(lifespan=lifespan)

class VerifyRequest(BaseModel):
    token: str
    hwid: str

class GenerateRequest(BaseModel):
    plan: str

@app.post("/verify")
def verify(data: VerifyRequest):
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute(
        "SELECT expires_at, hwid, revoked FROM tokens WHERE token = ?",
        (data.token,)
    )
    row = cur.fetchone()
    con.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid token")

    expires_at, bound_hwid, revoked = row

    if revoked:
        raise HTTPException(status_code=403, detail="Token revoked")

    if expires_at and time.time() > expires_at:
        raise HTTPException(status_code=403, detail="Token expired")

    if bound_hwid is None:
        con = sqlite3.connect(DB)
        cur = con.cursor()
        cur.execute(
            "UPDATE tokens SET hwid = ? WHERE token = ?",
            (data.hwid, data.token)
        )
        con.commit()
        con.close()
    elif bound_hwid != data.hwid:
        raise HTTPException(status_code=403, detail="HWID mismatch")

    return {"status": "ok"}

@app.post("/generate")
def generate(data: GenerateRequest):
    plan = data.plan.lower()

    if plan not in PLAN_DURATIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan. Valid plans: {', '.join(PLAN_DURATIONS.keys())}"
        )

    token = f"OLLY-{secrets.token_hex(12).upper()}"

    duration = PLAN_DURATIONS[plan]
    expires_at = None if duration is None else time.time() + duration

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO tokens (token, expires_at, revoked) VALUES (?, ?, 0)",
        (token, expires_at)
    )
    con.commit()
    con.close()

    return {
        "token": token,
        "plan": plan,
        "expires_at": expires_at
    }

@app.post("/admin/verify")
def admin_verify(
    data: dict,
    _: None = Depends(require_admin)
):
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute(
        "SELECT expires_at, hwid, revoked FROM tokens WHERE token = ?",
        (data["token"],)
    )
    row = cur.fetchone()
    con.close()

    if not row:
        raise HTTPException(status_code=404, detail="Token not found")

    expires_at, hwid, revoked = row

    seconds_remaining = None
    if expires_at:
        seconds_remaining = max(0, int(expires_at - time.time()))

    return {
        "token": data["token"],
        "hwid": hwid,
        "revoked": bool(revoked),
        "expires_at": expires_at,
        "seconds_remaining": seconds_remaining
    }

@app.post("/admin/unbind")
def admin_unbind(
    data: dict,
    _: None = Depends(require_admin)
):
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute(
        "UPDATE tokens SET hwid = NULL WHERE token = ?",
        (data["token"],)
    )
    con.commit()
    con.close()

    return {"status": "ok"}

@app.post("/admin/revoke")
def admin_revoke(
    data: dict,
    _: None = Depends(require_admin)
):
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute(
        "UPDATE tokens SET revoked = 1 WHERE token = ?",
        (data["token"],)
    )
    con.commit()
    con.close()

    return {"status": "revoked"}
