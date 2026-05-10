import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import AgentRecord, AlertRecord, ProcessRecord, get_db
from models import AgentOut, AlertOut, ProcessOut, TelemetryPayload
from scoring import score_batch

router = APIRouter()


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
        existing.last_seen = datetime.utcnow()
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
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/telemetry", status_code=201)
def receive_telemetry(payload: TelemetryPayload, db: Session = Depends(get_db)):
    ts   = payload.timestamp or datetime.utcnow()
    meta = payload.metadata.model_dump() if payload.metadata else None

    _upsert_agent(db, payload.agent_id, meta)

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
        ))

    alerts = score_batch(payload.agent_id, payload.processes)
    for a in alerts:
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

    db.commit()
    return {"received": len(payload.processes), "alerts_generated": len(alerts)}


@router.get("/processes", response_model=list[ProcessOut])
def get_processes(
    agent_id: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(ProcessRecord)
    if agent_id:
        q = q.filter(ProcessRecord.agent_id == agent_id)
    return [_proc_to_out(r) for r in q.order_by(ProcessRecord.timestamp.desc()).limit(limit)]


@router.get("/alerts", response_model=list[AlertOut])
def get_alerts(
    agent_id: Optional[str] = Query(None),
    min_score: int = Query(0, ge=0, le=150),
    risk_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
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
    return [_alert_to_out(r) for r in q.order_by(AlertRecord.timestamp.desc())]


@router.get("/agents", response_model=list[AgentOut])
def get_agents(db: Session = Depends(get_db)):
    return [
        AgentOut(
            agent_id=r.agent_id, hostname=r.hostname, os=r.os,
            ip=r.ip, username=r.username,
            first_seen=r.first_seen, last_seen=r.last_seen,
        )
        for r in db.query(AgentRecord).order_by(AgentRecord.last_seen.desc()).all()
    ]


@router.get("/timeline")
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
                "agent_id":     r.agent_id,
                "alert_id":     r.id,
                "process":      r.process_name,
                "risk_level":   r.risk_level,
                **entry,
            })
    return events
