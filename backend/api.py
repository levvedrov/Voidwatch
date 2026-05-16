import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from database import AgentRecord, AlertRecord, ProcessRecord, get_db
from models import (AgentOut, AlertOut, ProcessOut, RegisterPayload,
                    RetentionPayload, TelemetryPayload)
from scoring import score_batch
from classifier import classifier
import settings as _cfg

def _safe_proba(proc) -> float:
    try:
        return classifier.predict_proba(proc)
    except Exception:
        return 0.0

router = APIRouter()

_API_KEY      = os.environ.get("VOIDWATCH_API_KEY", "")
_DEDUP_WINDOW = timedelta(minutes=10)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.get("/health")
def health():
    return {"status": "ok"}


def _check_auth(x_api_key: str = Header(default="")) -> None:
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _proc_to_out(r: ProcessRecord) -> ProcessOut:
    return ProcessOut(
        id=r.id, agent_id=r.agent_id, timestamp=r.timestamp,
        name=r.name, parent_name=r.parent_name, command_line=r.command_line,
        path=r.path, pid=r.pid, parent_pid=r.parent_pid,
        cpu_usage=r.cpu_usage, mem_usage=r.mem_usage,
        is_signed=r.is_signed, sha256=r.sha256,
        connection_count=r.connection_count,
        destination_ips=json.loads(r.destination_ips or "[]"),
        destination_ports=json.loads(r.destination_ports or "[]"),
        protocols=json.loads(r.protocols or "[]"),
        ml_score=r.ml_score or 0.0,
    )


def _alert_to_out(r: AlertRecord) -> AlertOut:
    return AlertOut(
        id=r.id, agent_id=r.agent_id, timestamp=r.timestamp,
        pid=r.pid, process_name=r.process_name, parent_name=r.parent_name or "",
        risk_score=r.risk_score, risk_level=r.risk_level,
        confidence=r.confidence, confidence_label=r.confidence_label or "LOW",
        category=r.category or "Suspicious Behavior",
        reasons=json.loads(r.reasons or "[]"),
        mitre=json.loads(r.mitre or "[]"),
        ml_score=r.ml_score or 0.0,
        timeline=json.loads(r.timeline or "[]"),
    )


def _upsert_agent(db: Session, agent_id: str, metadata: dict | None) -> None:
    existing = db.query(AgentRecord).filter(AgentRecord.agent_id == agent_id).first()
    if existing:
        existing.last_seen = _utcnow()
        if metadata:
            existing.hostname = metadata.get("hostname", existing.hostname)
            existing.os       = metadata.get("os",       existing.os)
            existing.ip       = metadata.get("ip",       existing.ip)
            existing.username = metadata.get("username", existing.username)
    else:
        meta = metadata or {}
        db.add(AgentRecord(
            agent_id=agent_id,
            hostname=meta.get("hostname", "unknown"),
            os=meta.get("os", "unknown"),
            ip=meta.get("ip", "unknown"),
            username=meta.get("username", "unknown"),
        ))


# ---------------------------------------------------------------------------
# Telemetry endpoints
# ---------------------------------------------------------------------------

@router.post("/register", status_code=200, dependencies=[Depends(_check_auth)])
def register_agent(payload: RegisterPayload, db: Session = Depends(get_db)):
    _upsert_agent(db, payload.agent_id, payload.metadata.model_dump())
    db.commit()
    return {"status": "ok"}


@router.post("/telemetry", status_code=201, dependencies=[Depends(_check_auth)])
def receive_telemetry(payload: TelemetryPayload, db: Session = Depends(get_db)):
    ts   = payload.timestamp or _utcnow()
    meta = payload.metadata.model_dump() if payload.metadata else None

    _upsert_agent(db, payload.agent_id, meta)
    db.commit()  # persist last_seen immediately so dashboard reads current time

    for proc in payload.processes:
        db.add(ProcessRecord(
            agent_id=payload.agent_id, timestamp=ts,
            name=proc.name, parent_name=proc.parent_name,
            command_line=proc.command_line, path=proc.path,
            pid=proc.pid, parent_pid=proc.parent_pid,
            cpu_usage=proc.cpu_usage, mem_usage=proc.mem_usage,
            is_signed=proc.is_signed, sha256=proc.sha256,
            connection_count=proc.connection_count,
            destination_ips=json.dumps(proc.destination_ips),
            destination_ports=json.dumps(proc.destination_ports),
            protocols=json.dumps(proc.protocols),
            ml_score=_safe_proba(proc),
        ))

    alerts = score_batch(payload.agent_id, payload.processes)
    cutoff  = ts - _DEDUP_WINDOW
    added   = 0
    for a in alerts:
        duplicate = db.query(AlertRecord).filter(
            AlertRecord.agent_id     == a["agent_id"],
            AlertRecord.process_name == a["process_name"],
            AlertRecord.risk_level   == a["risk_level"],
            AlertRecord.timestamp    >= cutoff,
        ).first()
        if duplicate:
            continue
        db.add(AlertRecord(
            agent_id=a["agent_id"], timestamp=ts,
            pid=a["pid"], process_name=a["process_name"], parent_name=a["parent_name"],
            risk_score=a["risk_score"], risk_level=a["risk_level"],
            confidence=a["confidence"], confidence_label=a["confidence_label"],
            category=a["category"],
            reasons=json.dumps(a["reasons"]),
            mitre=json.dumps(a["mitre"]),
            ml_score=a["ml_score"],
            timeline=json.dumps(a["timeline"]),
        ))
        added += 1

    db.commit()
    return {"received": len(payload.processes), "alerts_generated": added}


# ---------------------------------------------------------------------------
# Query endpoints
# ---------------------------------------------------------------------------

@router.get("/processes", response_model=list[ProcessOut], dependencies=[Depends(_check_auth)])
def get_processes(
    agent_id: Optional[str] = Query(None),
    limit: int   = Query(200, ge=1, le=1000),
    offset: int  = Query(0, ge=0),
    db: Session  = Depends(get_db),
):
    q = db.query(ProcessRecord)
    if agent_id:
        q = q.filter(ProcessRecord.agent_id == agent_id)
    rows = q.order_by(ProcessRecord.timestamp.desc()).offset(offset).limit(limit).all()
    return [_proc_to_out(r) for r in rows]


@router.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(_check_auth)])
def get_alerts(
    agent_id:  Optional[str] = Query(None),
    min_score: int            = Query(0, ge=0, le=150),
    risk_level: Optional[str] = Query(None),
    category:  Optional[str] = Query(None),
    limit: int  = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(AlertRecord)
    if agent_id:
        q = q.filter(AlertRecord.agent_id == agent_id)
    if min_score > 0:
        q = q.filter(AlertRecord.risk_score >= min_score)
    if risk_level:
        q = q.filter(AlertRecord.risk_level == risk_level.upper())
    if category:
        q = q.filter(AlertRecord.category == category)
    rows = q.order_by(AlertRecord.timestamp.desc()).offset(offset).limit(limit).all()
    return [_alert_to_out(r) for r in rows]


@router.get("/agents", response_model=list[AgentOut], dependencies=[Depends(_check_auth)])
def get_agents(db: Session = Depends(get_db)):
    return [
        AgentOut(
            agent_id=r.agent_id, hostname=r.hostname, os=r.os,
            ip=r.ip, username=r.username,
            first_seen=r.first_seen, last_seen=r.last_seen,
        )
        for r in db.query(AgentRecord).order_by(AgentRecord.last_seen.desc()).all()
    ]


@router.get("/timeline", dependencies=[Depends(_check_auth)])
def get_timeline(
    agent_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(AlertRecord)
    if agent_id:
        q = q.filter(AlertRecord.agent_id == agent_id)
    rows = q.order_by(AlertRecord.timestamp.desc()).limit(limit).all()
    events = []
    for r in rows:
        for entry in json.loads(r.timeline or "[]"):
            events.append({
                "agent_id":   r.agent_id,
                "alert_id":   r.id,
                "process":    r.process_name,
                "risk_level": r.risk_level,
                **entry,
            })
    return events


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------

@router.get("/settings")
def get_settings():
    return _cfg.load()


@router.put("/settings", dependencies=[Depends(_check_auth)])
def update_settings(payload: RetentionPayload):
    updates = payload.model_dump(exclude_none=True)
    return _cfg.save(updates)


@router.get("/settings/stats", dependencies=[Depends(_check_auth)])
def get_stats(db: Session = Depends(get_db)):
    from database import DATABASE_URL, _is_sqlite
    db_size_mb = 0.0
    if _is_sqlite:
        db_path = Path(__file__).parent / "voidwatch.db"
        if db_path.exists():
            db_size_mb = round(db_path.stat().st_size / (1024 * 1024), 2)
    return {
        "db_size_mb":      db_size_mb,
        "db_type":         "sqlite" if _is_sqlite else "postgresql",
        "process_records": db.query(ProcessRecord).count(),
        "alert_records":   db.query(AlertRecord).count(),
    }


@router.post("/settings/prune", dependencies=[Depends(_check_auth)])
def prune_now(db: Session = Depends(get_db)):
    cfg = _cfg.load()
    now = _utcnow()
    deleted_p = db.query(ProcessRecord).filter(
        ProcessRecord.timestamp < now - timedelta(days=cfg["process_retain_days"])
    ).delete(synchronize_session=False)
    deleted_a = db.query(AlertRecord).filter(
        AlertRecord.timestamp < now - timedelta(days=cfg["alert_retain_days"])
    ).delete(synchronize_session=False)
    db.commit()
    return {"deleted_processes": deleted_p, "deleted_alerts": deleted_a}
