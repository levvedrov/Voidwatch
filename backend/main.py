import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import FastAPI

from api import router
from classifier import classifier
from database import AlertRecord, ProcessRecord, SessionLocal, init_db
import settings as _cfg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_PRUNE_INTERVAL = 3600  # seconds between prune passes


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
    if classifier.rf is not None:
        log.info("Model loaded")
    threading.Thread(target=_pruner, daemon=True, name="db-pruner").start()
    log.info("Listening on http://127.0.0.1:8000")
    yield
    log.info("Backend shutting down")


app = FastAPI(title="Voidwatch Backend", version="0.2.0", lifespan=lifespan)
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
