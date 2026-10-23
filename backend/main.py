import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security import hash_password, decode_token
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.db.models import UserModel, HoneytokenModel
from app.api import api_router
from app.api.honeytoken import HoneytokenHit, record_hit
from app.services.live import live_feed
from app.services.pipeline import refresh_honeytokens
from app.services.risk_decay import run_decay_job
from app.services.graph_correlation import run_graph_correlation
import app.api.settings as settings_api

log = logging.getLogger("soc")


def seed_defaults():
    """Admin user + the decoys we plant. Safe to run on every start."""
    db = SessionLocal()
    try:
        if not db.query(UserModel).filter(UserModel.username == settings.ADMIN_USERNAME).first():
            db.add(UserModel(username=settings.ADMIN_USERNAME, password_hash=hash_password(settings.ADMIN_PASSWORD), role="admin"))
        known = {h.decoy_value for h in db.query(HoneytokenModel).all()}
        for d in settings.honeytoken_list:
            if d in known:
                continue
            kind = "fake endpoint" if d.startswith("/") else ("fake DB credential" if "secret" in d.lower() or "svc" in d else "fake API key")
            db.add(HoneytokenModel(type=kind, decoy_value=d, resource_path=d if d.startswith("/") else None))
        db.commit()
        refresh_honeytokens(db)
    finally:
        db.close()


async def _loop(seconds: int, fn):
    """Very small scheduler: run a blocking job every N seconds in a worker thread."""
    while True:
        await asyncio.sleep(seconds)
        try:
            await asyncio.to_thread(fn)
        except Exception as e:  # a failing job must not kill the app
            log.warning("background job failed: %s", e)


def _decay_job():
    db = SessionLocal()
    try:
        run_decay_job(db)
    finally:
        db.close()


def _graph_job():
    db = SessionLocal()
    try:
        settings_api._last_graph = run_graph_correlation(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_defaults()
    tasks = [asyncio.create_task(_loop(settings.DECAY_JOB_INTERVAL_SECONDS, _decay_job)),
             asyncio.create_task(_loop(settings.GRAPH_JOB_INTERVAL_SECONDS, _graph_job))]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=("Mini SOC: upload logs, detect threats across five signal types, correlate them into incidents "
                 "(time window + NetworkX), score risk with decay, explain in plain language, respond manually or automatically."),
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.websocket("/api/ws/alerts")
async def alerts_ws(ws: WebSocket, token: str = ""):
    """Live feed: the dashboard connects here and gets every new alert as it is created."""
    if not decode_token(token):
        await ws.close(code=4401)
        return
    await live_feed.connect(ws)
    try:
        while True:
            await ws.receive_text()      # we only push, but must keep reading to notice disconnects
    except WebSocketDisconnect:
        live_feed.disconnect(ws)


@app.get("/admin/backup-keys")
def decoy_backup_keys(request: Request):
    """
    HONEYTOKEN decoy route. It looks like a juicy admin page but no real user has a reason to
    open it, so every visit is reported to the honeytoken webhook logic.
    """
    from app.db.session import SessionLocal as _S
    db = _S()
    try:
        if not db.query(HoneytokenModel).filter(HoneytokenModel.decoy_value == "/admin/backup-keys").first():
            raise HTTPException(status_code=404, detail="Not Found")
        record_hit(db, HoneytokenHit(token="/admin/backup-keys", resource="/admin/backup-keys",
                                     source_ip=request.client.host if request.client else None,
                                     user_agent=request.headers.get("user-agent")))
    finally:
        db.close()
    return {"keys": ["AKIAFAKEFAKEFAKE0001", "AKIAFAKEFAKEFAKE0002"], "note": "decoy"}


@app.get("/")
def root():
    return {"service": settings.PROJECT_NAME, "version": settings.VERSION, "status": "online",
            "docs_url": "/docs", "api_prefix": "/api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
