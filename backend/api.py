import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import AlertRecord, ProcessRecord, get_db
from models import AlertOut, ProcessOut, TelemetryPayload
from scoring import score_batch

router = APIRouter()


def _proc_to_out(r: ProcessRecord) -> ProcessOut:
    return ProcessOut(
        id=r.id,
        agent_id=r.agent_id,
        timestamp=r.timestamp,
        name=r.name,
        parent_name=r.parent_name,
        command_line=r.command_line,
        path=r.path,
        pid=r.pid,
        parent_pid=r.parent_pid,
        cpu_usage=r.cpu_usage,
        mem_usage=r.mem_usage,
        is_signed=r.is_signed,
        sha256=r.sha256,
        connection_count=r.connection_count,
        destination_ips=json.loads(r.destination_ips or "[]"),
        destination_ports=json.loads(r.destination_ports or "[]"),
        protocols=json.loads(r.protocols or "[]"),
    )


def _alert_to_out(r: AlertRecord) -> AlertOut:
    return AlertOut(
        id=r.id,
        agent_id=r.agent_id,
        pid=r.pid,
        process_name=r.process_name,
        reason=r.reason,
        score=r.score,
        timestamp=r.timestamp,
    )


@router.post("/telemetry", status_code=201)
def receive_telemetry(payload: TelemetryPayload, db: Session = Depends(get_db)):
    ts = payload.timestamp or datetime.utcnow()

    for proc in payload.processes:
        db.add(ProcessRecord(
            agent_id=payload.agent_id,
            timestamp=ts,
            name=proc.name,
            parent_name=proc.parent_name,
            command_line=proc.command_line,
            path=proc.path,
            pid=proc.pid,
            parent_pid=proc.parent_pid,
            cpu_usage=proc.cpu_usage,
            mem_usage=proc.mem_usage,
            is_signed=proc.is_signed,
            sha256=proc.sha256,
            connection_count=proc.connection_count,
            destination_ips=json.dumps(proc.destination_ips),
            destination_ports=json.dumps(proc.destination_ports),
            protocols=json.dumps(proc.protocols),
        ))

    alerts = score_batch(payload.agent_id, payload.processes)
    for alert in alerts:
        db.add(AlertRecord(**alert, timestamp=ts))

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
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
):
    q = db.query(AlertRecord)
    if agent_id:
        q = q.filter(AlertRecord.agent_id == agent_id)
    if min_score > 0:
        q = q.filter(AlertRecord.score >= min_score)
    return [_alert_to_out(r) for r in q.order_by(AlertRecord.timestamp.desc())]
