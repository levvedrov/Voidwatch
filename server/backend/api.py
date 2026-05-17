import csv
import io
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import (AgentRecord, AlertFeedback, AlertRecord, Allowlist,
                      EnrollmentToken, ProcessRecord, RevokedAgent, get_db)
from models import (AgentModePayload, AgentOut, AlertOut, AllowlistEntry,
                    AllowlistOut, CreateTokenPayload, EnrollRequest,
                    EnrollResponse, FeedbackOut, FeedbackPayload, ProcessOut,
                    RegisterPayload, RetentionPayload, TelemetryPayload,
                    TokenOut)
from scoring import score_batch
from classifier import classifier
import settings as _cfg
import license as _lic


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


@router.post("/license/activate")
def license_activate(payload: dict):
    raw = (payload.get("key") or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="No key provided")
    try:
        lic = _lic.activate(raw)
        return lic.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.delete("/license", dependencies=[Depends(_check_auth)])
def license_deactivate():
    from license import _LICENSE_FILE, _free
    import license as _license_mod
    if _LICENSE_FILE.exists():
        _LICENSE_FILE.unlink()
    _license_mod.license = _free()
    return {"tier": "free"}


def _check_auth(
    x_api_key: str = Header(default=""),
    x_agent_id: str = Header(default=""),
    x_agent_secret: str = Header(default=""),
    db: Session = Depends(get_db),
) -> None:
    # Admin API key — full access
    if _API_KEY and x_api_key == _API_KEY:
        return
    # Per-agent secret auth
    if x_agent_id and x_agent_secret:
        agent = db.query(AgentRecord).filter(AgentRecord.agent_id == x_agent_id).first()
        if agent and agent.agent_secret and agent.agent_secret == x_agent_secret:
            revoked = db.query(RevokedAgent).filter(RevokedAgent.agent_id == x_agent_id).first()
            if revoked:
                raise HTTPException(status_code=403, detail="Agent revoked")
            return
    if _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing credentials")


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


def _upsert_agent(db: Session, agent_id: str, metadata: dict | None) -> AgentRecord:
    existing = db.query(AgentRecord).filter(AgentRecord.agent_id == agent_id).first()
    if existing:
        existing.last_seen = _utcnow()
        if metadata:
            existing.hostname = metadata.get("hostname", existing.hostname)
            existing.os       = metadata.get("os",       existing.os)
            existing.ip       = metadata.get("ip",       existing.ip)
            existing.username = metadata.get("username", existing.username)
        return existing
    else:
        meta = metadata or {}
        rec = AgentRecord(
            agent_id=agent_id,
            hostname=meta.get("hostname", "unknown"),
            os=meta.get("os", "unknown"),
            ip=meta.get("ip", "unknown"),
            username=meta.get("username", "unknown"),
            mode="detect",
        )
        db.add(rec)
        return rec


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

    # Skip scoring in collect_only mode
    agent_rec = db.query(AgentRecord).filter(AgentRecord.agent_id == payload.agent_id).first()
    if agent_rec and agent_rec.mode == "collect_only":
        db.commit()
        return {"received": len(payload.processes), "alerts_generated": 0, "mode": "collect_only"}

    alerts = score_batch(payload.agent_id, payload.processes, db=db,
                         ml_enabled=_lic.license.can("ml"))
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
    agents = db.query(AgentRecord).order_by(AgentRecord.last_seen.desc()).all()
    result = []
    for r in agents:
        event_count    = db.query(ProcessRecord).filter(ProcessRecord.agent_id == r.agent_id).count()
        alert_count    = db.query(AlertRecord).filter(AlertRecord.agent_id == r.agent_id).count()
        feedback_count = db.query(AlertFeedback).filter(AlertFeedback.agent_id == r.agent_id).count()
        result.append(AgentOut(
            agent_id=r.agent_id, hostname=r.hostname, os=r.os,
            ip=r.ip, username=r.username,
            first_seen=r.first_seen, last_seen=r.last_seen,
            mode=r.mode or "detect",
            event_count=event_count,
            alert_count=alert_count,
            feedback_count=feedback_count,
        ))
    return result


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
    return {**_cfg.load(), "license": _lic.license.to_dict()}


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


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

@router.post("/agents/enroll", response_model=EnrollResponse)
def enroll_agent(payload: EnrollRequest, db: Session = Depends(get_db)):
    tok = db.query(EnrollmentToken).filter(
        EnrollmentToken.token == payload.token,
        EnrollmentToken.used == False,
    ).first()
    if not tok:
        raise HTTPException(status_code=403, detail="Invalid or expired enrollment token")
    if tok.expires_at and tok.expires_at < _utcnow():
        raise HTTPException(status_code=403, detail="Enrollment token expired")

    agent_id     = f"{payload.hostname or 'agent'}-{uuid.uuid4().hex[:8]}"
    agent_secret = secrets.token_hex(32)

    db.add(AgentRecord(
        agent_id=agent_id,
        hostname=payload.hostname or "unknown",
        os=payload.os or "unknown",
        ip=payload.ip or "unknown",
        username=payload.username or "unknown",
        mode="collect_only",
        agent_secret=agent_secret,
    ))
    tok.used    = True
    tok.used_by = agent_id
    db.commit()
    return EnrollResponse(agent_id=agent_id, agent_secret=agent_secret, mode="collect_only")


@router.post("/agents/tokens", response_model=TokenOut, dependencies=[Depends(_check_auth)])
def create_token(payload: CreateTokenPayload, db: Session = Depends(get_db)):
    tok = EnrollmentToken(
        token=secrets.token_hex(24),
        label=payload.label,
        expires_at=(_utcnow() + timedelta(hours=payload.expires_hours)) if payload.expires_hours else None,
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)
    return TokenOut(
        id=tok.id, token=tok.token, label=tok.label,
        created_at=tok.created_at, expires_at=tok.expires_at,
        used=tok.used, used_by=tok.used_by,
    )


@router.get("/agents/tokens", response_model=list[TokenOut], dependencies=[Depends(_check_auth)])
def list_tokens(db: Session = Depends(get_db)):
    return [
        TokenOut(id=t.id, token=t.token, label=t.label,
                 created_at=t.created_at, expires_at=t.expires_at,
                 used=t.used, used_by=t.used_by)
        for t in db.query(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()).all()
    ]


@router.put("/agents/{agent_id}/mode", dependencies=[Depends(_check_auth)])
def set_agent_mode(agent_id: str, payload: AgentModePayload, db: Session = Depends(get_db)):
    if payload.mode not in ("collect_only", "detect", "debug"):
        raise HTTPException(status_code=400, detail="mode must be collect_only, detect, or debug")
    agent = db.query(AgentRecord).filter(AgentRecord.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.mode = payload.mode
    db.commit()
    return {"agent_id": agent_id, "mode": payload.mode}


@router.post("/agents/{agent_id}/revoke", dependencies=[Depends(_check_auth)])
def revoke_agent(agent_id: str, reason: str = "", db: Session = Depends(get_db)):
    existing = db.query(RevokedAgent).filter(RevokedAgent.agent_id == agent_id).first()
    if not existing:
        db.add(RevokedAgent(agent_id=agent_id, reason=reason))
        db.commit()
    return {"agent_id": agent_id, "revoked": True}


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

@router.post("/alerts/{alert_id}/feedback", dependencies=[Depends(_check_auth)])
def submit_feedback(alert_id: int, payload: FeedbackPayload, db: Session = Depends(get_db)):
    _lic.license.require("feedback")
    valid = {"true_positive", "false_positive", "ignore", "suspicious_ok"}
    if payload.feedback_type not in valid:
        raise HTTPException(status_code=400, detail=f"feedback_type must be one of {valid}")
    alert = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    existing = db.query(AlertFeedback).filter(AlertFeedback.alert_id == alert_id).first()
    if existing:
        existing.feedback_type = payload.feedback_type
        existing.reason        = payload.reason
    else:
        db.add(AlertFeedback(
            alert_id=alert_id, agent_id=alert.agent_id,
            process_name=alert.process_name,
            feedback_type=payload.feedback_type, reason=payload.reason,
        ))
    db.commit()
    return {"alert_id": alert_id, "feedback_type": payload.feedback_type}


@router.get("/feedback", response_model=list[FeedbackOut], dependencies=[Depends(_check_auth)])
def get_feedback(limit: int = Query(100, le=500), db: Session = Depends(get_db)):
    rows = db.query(AlertFeedback).order_by(AlertFeedback.timestamp.desc()).limit(limit).all()
    return [FeedbackOut(id=r.id, alert_id=r.alert_id, agent_id=r.agent_id,
                        process_name=r.process_name, feedback_type=r.feedback_type,
                        reason=r.reason, timestamp=r.timestamp) for r in rows]


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

@router.get("/allowlist", response_model=list[AllowlistOut], dependencies=[Depends(_check_auth)])
def get_allowlist(db: Session = Depends(get_db)):
    return [AllowlistOut(id=r.id, kind=r.kind, value=r.value,
                         note=r.note, created_at=r.created_at)
            for r in db.query(Allowlist).order_by(Allowlist.created_at.desc()).all()]


@router.post("/allowlist", response_model=AllowlistOut, dependencies=[Depends(_check_auth)])
def add_allowlist(entry: AllowlistEntry, db: Session = Depends(get_db)):
    _lic.license.require("allowlist")
    valid = {"process", "publisher", "path", "hash", "parent_child"}
    if entry.kind not in valid:
        raise HTTPException(status_code=400, detail=f"kind must be one of {valid}")
    rec = Allowlist(kind=entry.kind, value=entry.value, note=entry.note)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return AllowlistOut(id=rec.id, kind=rec.kind, value=rec.value,
                        note=rec.note, created_at=rec.created_at)


@router.delete("/allowlist/{entry_id}", dependencies=[Depends(_check_auth)])
def remove_allowlist(entry_id: int, db: Session = Depends(get_db)):
    rec = db.query(Allowlist).filter(Allowlist.id == entry_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(rec)
    db.commit()
    return {"deleted": entry_id}


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

@router.get("/reports/alerts.csv", dependencies=[Depends(_check_auth)])
def export_alerts_csv(
    agent_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    _lic.license.require("export")
    q = db.query(AlertRecord)
    if agent_id:
        q = q.filter(AlertRecord.agent_id == agent_id)
    rows = q.order_by(AlertRecord.timestamp.desc()).limit(5000).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id","agent_id","timestamp","process_name","parent_name",
                     "risk_score","risk_level","category","ml_score","reasons","mitre"])
    for r in rows:
        writer.writerow([r.id, r.agent_id, r.timestamp, r.process_name, r.parent_name,
                         r.risk_score, r.risk_level, r.category, r.ml_score,
                         r.reasons, r.mitre])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=voidwatch_alerts.csv"},
    )


@router.get("/reports/telemetry.csv", dependencies=[Depends(_check_auth)])
def export_telemetry_csv(
    agent_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    _lic.license.require("export")
    q = db.query(ProcessRecord)
    if agent_id:
        q = q.filter(ProcessRecord.agent_id == agent_id)
    rows = q.order_by(ProcessRecord.timestamp.desc()).limit(10000).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id","agent_id","timestamp","name","parent_name","pid",
                     "path","is_signed","connection_count","ml_score"])
    for r in rows:
        writer.writerow([r.id, r.agent_id, r.timestamp, r.name, r.parent_name,
                         r.pid, r.path, r.is_signed, r.connection_count, r.ml_score])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=voidwatch_telemetry.csv"},
    )
