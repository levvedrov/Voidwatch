import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import router
from admin import admin_router
from classifier import classifier
from database import AlertRecord, ProcessRecord, SessionLocal, init_db
import settings as _cfg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_PRUNE_INTERVAL = 3600

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

_CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
_cors_origins = [o.strip() for o in _CORS_ORIGINS.split(",")] if _CORS_ORIGINS != "*" else ["*"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _run_prune() -> tuple[int, int]:
    cfg  = _cfg.load()
    now  = _utcnow()
    db   = SessionLocal()
    try:
        deleted_p = db.query(ProcessRecord).filter(
            ProcessRecord.timestamp < now - timedelta(days=cfg["process_retain_days"])
        ).delete(synchronize_session=False)
        deleted_a = db.query(AlertRecord).filter(
            AlertRecord.timestamp < now - timedelta(days=cfg["alert_retain_days"])
        ).delete(synchronize_session=False)
        db.commit()
        return deleted_p, deleted_a
    finally:
        db.close()


def _pruner():
    log = logging.getLogger(__name__)
    while True:
        time.sleep(_PRUNE_INTERVAL)
        try:
            dp, da = _run_prune()
            if dp or da:
                log.info("DB pruned: %d process rows, %d alert rows", dp, da)
        except Exception as exc:
            log.error("DB pruner error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Voidwatch backend starting")
    init_db()
    log.info("Database initialised")
    classifier.load()
    if classifier.model is not None:
        log.info("ML model loaded")
    else:
        log.warning("ML model not loaded — scoring is rules-only")
    if _cors_origins == ["*"]:
        log.warning(
            "CORS is open to all origins. Set CORS_ORIGINS env var before exposing to a network "
            "(e.g. CORS_ORIGINS=http://localhost:8000,app://.)."
        )
    threading.Thread(target=_pruner, daemon=True, name="db-pruner").start()
    log.info("Listening on http://%s:%d", HOST, PORT)
    yield
    log.info("Backend shutting down")


app = FastAPI(title="Voidwatch Backend", version="0.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(admin_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False, log_level="warning")
