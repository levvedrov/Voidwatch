"""
Voidwatch — License Admin Panel
Served at /admin  (protected by VOIDWATCH_API_KEY)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from database import (AgentRecord, AlertFeedback, AlertRecord, Allowlist, IssuedLicense,
                      ProcessLabel, ProcessRecord, get_db)
import license as _lic

log = logging.getLogger(__name__)

_API_KEY         = os.environ.get("VOIDWATCH_API_KEY", "")
_PRIVATE_KEY_PATH = Path(__file__).parent.parent / "license_private.pem"

admin_router = APIRouter(prefix="/admin")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _check_admin(
    x_api_key: str = Header(default=""),
    key: str = Query(default=""),
) -> None:
    provided = x_api_key or key
    if _API_KEY and provided != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@admin_router.get("/licenses", dependencies=[Depends(_check_admin)])
def list_licenses(db: Session = Depends(get_db)):
    rows = db.query(IssuedLicense).order_by(IssuedLicense.issued_at.desc()).all()
    active_raw = _lic.license.raw
    now = datetime.now(timezone.utc)
    result = []
    for r in rows:
        exp = r.expires
        expired = bool(exp and datetime.fromisoformat(exp.isoformat()).replace(tzinfo=timezone.utc) < now)
        result.append({
            "id":        r.id,
            "customer":  r.customer,
            "tier":      r.tier,
            "features":  json.loads(r.features) if r.features else [],
            "issued_at": r.issued_at.isoformat() if r.issued_at else None,
            "expires":   r.expires.isoformat() if r.expires else None,
            "note":      r.note or "",
            "token":     r.jwt_token,
            "is_active": r.jwt_token == active_raw,
            "expired":   expired,
        })
    return result


@admin_router.post("/licenses", dependencies=[Depends(_check_admin)])
def issue_license(payload: dict, db: Session = Depends(get_db)):
    tier     = (payload.get("tier") or "pro").lower()
    customer = (payload.get("customer") or "").strip()
    expires  = (payload.get("expires") or "").strip()
    note     = (payload.get("note") or "").strip()

    if not customer:
        raise HTTPException(status_code=400, detail="Customer name is required")
    if tier not in {"free", "pro", "enterprise", "beta"}:
        raise HTTPException(status_code=400, detail="tier must be free, pro, enterprise, or beta")
    if not _PRIVATE_KEY_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Private key not found at {_PRIVATE_KEY_PATH}. "
                   "Generate with: openssl genrsa -out server/license_private.pem 2048",
        )

    features = {
        "free":       [],
        "pro":        ["ml", "export", "feedback", "allowlist"],
        "enterprise": ["ml", "export", "feedback", "allowlist"],
        "beta":       ["ml", "export", "feedback", "allowlist"],
    }[tier]

    jwt_payload: dict = {"tier": tier, "customer": customer, "features": features}
    expires_dt = None
    if expires and expires.lower() != "none":
        try:
            expires_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expiry date — use YYYY-MM-DD")
        jwt_payload["expires"] = expires

    try:
        import jwt
        token = jwt.encode(jwt_payload, _PRIVATE_KEY_PATH.read_text(), algorithm="RS256")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {e}")

    record = IssuedLicense(
        customer  = customer,
        tier      = tier,
        features  = json.dumps(features),
        issued_at = datetime.now(timezone.utc).replace(tzinfo=None),
        expires   = expires_dt.replace(tzinfo=None) if expires_dt else None,
        note      = note,
        jwt_token = token,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    log.info("[admin] Issued %s license for %r (id=%d)", tier.upper(), customer, record.id)
    return {"id": record.id, "token": token, "tier": tier, "customer": customer}


@admin_router.delete("/licenses/{license_id}", dependencies=[Depends(_check_admin)])
def delete_license(license_id: int, db: Session = Depends(get_db)):
    rec = db.query(IssuedLicense).filter(IssuedLicense.id == license_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="License not found")
    db.delete(rec)
    db.commit()
    return {"deleted": license_id}


@admin_router.get("/stats", dependencies=[Depends(_check_admin)])
def stats(db: Session = Depends(get_db)):
    now           = datetime.utcnow()
    threshold     = now - timedelta(seconds=60)
    day_ago       = now - timedelta(hours=24)

    online_agents = db.query(AgentRecord).filter(AgentRecord.last_seen >= threshold).count()
    total_agents  = db.query(AgentRecord).count()
    # Distinct process names — matches client-side deduplication
    total_procs  = db.query(func.count(distinct(ProcessRecord.name))).scalar() or 0

    alerts = db.query(func.count(distinct(ProcessRecord.name))).filter(
                 ProcessRecord.ml_score >= 0.80
             ).scalar() or 0

    alerts_today = db.query(func.count(distinct(ProcessRecord.name))).filter(
                       ProcessRecord.ml_score  >= 0.80,
                       ProcessRecord.timestamp >= day_ago,
                   ).scalar() or 0

    issued  = db.query(IssuedLicense).all()
    by_tier = {"free": 0, "pro": 0, "enterprise": 0, "beta": 0}
    for r in issued:
        by_tier[r.tier] = by_tier.get(r.tier, 0) + 1

    lbl_counts = dict(
        db.query(ProcessLabel.label, func.count(ProcessLabel.id))
          .group_by(ProcessLabel.label).all()
    )
    avg_ml_raw   = db.query(func.avg(ProcessRecord.ml_score)).scalar()
    avg_ml_score = round((avg_ml_raw or 0) * 100, 1)

    all_agents     = db.query(AgentRecord.first_seen, AgentRecord.last_seen).all()
    uptime_seconds = sum(
        max(0, (a.last_seen - a.first_seen).total_seconds())
        for a in all_agents if a.first_seen and a.last_seen
    )
    uptime_hours = round(uptime_seconds / 3600, 1)

    total_feedback  = db.query(AlertFeedback).count()
    allowlist_count = db.query(Allowlist).count()

    return {
        "online_agents":     online_agents,
        "total_agents":      total_agents,
        "alerts":            alerts,
        "alerts_today":      alerts_today,
        "processes":         total_procs,
        "avg_ml_score":      avg_ml_score,
        "uptime_hours":      uptime_hours,
        "issued_total":      len(issued),
        "by_tier":           by_tier,
        "labeled_malicious": lbl_counts.get("malicious", 0),
        "labeled_benign":    lbl_counts.get("benign", 0),
        "total_feedback":    total_feedback,
        "allowlist_count":   allowlist_count,
    }


# ---------------------------------------------------------------------------
# Process labeling
# ---------------------------------------------------------------------------

@admin_router.get("/processes", dependencies=[Depends(_check_admin)])
def list_processes(
    filter: str = Query("unverified"),
    page:   int = Query(1, ge=1),
    limit:  int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    all_labels = {pl.process_id: pl for pl in db.query(ProcessLabel).all()}
    exported   = {pid for pid, pl in all_labels.items() if pl.exported}

    # Deduplicate: keep only the latest record (max id) per process name
    latest_id_subq = (
        db.query(func.max(ProcessRecord.id))
          .filter(ProcessRecord.ml_score >= 0.80)
          .group_by(ProcessRecord.name)
    )
    q = db.query(ProcessRecord).filter(ProcessRecord.id.in_(latest_id_subq))

    if exported:
        q = q.filter(ProcessRecord.id.notin_(exported))

    if filter == "unverified":
        not_unverified = {pid for pid, pl in all_labels.items()
                          if pl.label != "unverified" and not pl.exported}
        if not_unverified:
            q = q.filter(ProcessRecord.id.notin_(not_unverified))
    elif filter in ("malicious", "benign"):
        target = {pid for pid, pl in all_labels.items()
                  if pl.label == filter and not pl.exported}
        q = q.filter(ProcessRecord.id.in_(target)) if target else q.filter(False)

    total = q.count()
    rows  = q.order_by(ProcessRecord.timestamp.desc()) \
             .offset((page - 1) * limit).limit(limit).all()

    items = []
    for p in rows:
        pl = all_labels.get(p.id)
        items.append({
            "id":           p.id,
            "name":         p.name or "",
            "parent_name":  p.parent_name or "",
            "agent_id":     (p.agent_id or "")[:12],
            "timestamp":    p.timestamp.isoformat() if p.timestamp else None,
            "ml_score":     round((p.ml_score or 0) * 100),
            "command_line": p.command_line or "",
            "label":        pl.label if pl else "unverified",
        })
    return {"total": total, "page": page, "limit": limit, "items": items}


@admin_router.post("/processes/{process_id}/label", dependencies=[Depends(_check_admin)])
def label_process(process_id: int, payload: dict, db: Session = Depends(get_db)):
    label = (payload.get("label") or "unverified").lower()
    if label not in {"unverified", "malicious", "benign"}:
        raise HTTPException(400, "label must be unverified, malicious, or benign")
    pl = db.query(ProcessLabel).filter(ProcessLabel.process_id == process_id).first()
    if pl:
        pl.label     = label
        pl.labeled_at = datetime.utcnow()
    else:
        db.add(ProcessLabel(process_id=process_id, label=label))
    db.commit()
    return {"ok": True}


@admin_router.get("/dataset/{label}", dependencies=[Depends(_check_admin)])
def download_dataset(label: str, db: Session = Depends(get_db)):
    if label not in {"malicious", "benign"}:
        raise HTTPException(400, "label must be malicious or benign")

    pending_ids = [
        pl.process_id for pl in
        db.query(ProcessLabel).filter(
            ProcessLabel.label    == label,
            ProcessLabel.exported == False,
        ).all()
    ]
    if not pending_ids:
        raise HTTPException(404, f"No pending {label} processes to export")

    procs = db.query(ProcessRecord).filter(ProcessRecord.id.in_(pending_ids)).all()

    lines = []
    for p in procs:
        ts = p.timestamp.strftime("%Y-%m-%d %H:%M:%S.000") if p.timestamp else ""
        lines.append(json.dumps({
            "EventID":         1,
            "UtcTime":         ts,
            "ProcessId":       p.pid       or 0,
            "ParentProcessId": p.parent_pid or 0,
            "Image":           p.path      or p.name or "",
            "ParentImage":     p.parent_name or "",
            "CommandLine":     p.command_line or "",
            "Hashes":          f"SHA256={p.sha256}" if p.sha256 else "",
        }))

    # Mark exported atomically with the response
    db.query(ProcessLabel).filter(
        ProcessLabel.process_id.in_(pending_ids)
    ).update({"exported": True}, synchronize_session=False)
    db.commit()

    fname = f"voidwatch_{label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content="\n".join(lines),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ---------------------------------------------------------------------------
# Panel HTML
# ---------------------------------------------------------------------------

@admin_router.get("", response_class=HTMLResponse)
def admin_panel():
    return HTMLResponse(content=_HTML)


_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Voidwatch — Admin</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
  :root {
    --bg:        #0d0f14;
    --card:      #13161e;
    --card2:     #181c26;
    --border:    #1e2435;
    --border-hi: #2a3050;
    --text:      #e2e8f0;
    --text-sec:  #94a3b8;
    --text-muted:#4a5568;
    --accent:    #4f8ef7;
    --danger:    #ef4444;
    --warn:      #f59e0b;
    --ok:        #22c55e;
    --font-mono: 'Consolas','Courier New',monospace;
    --radius:    8px;
  }
  body { background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif;
         font-size:14px; min-height:100vh; line-height:1.5 }

  ::-webkit-scrollbar { width:6px; height:6px }
  ::-webkit-scrollbar-track { background:transparent }
  ::-webkit-scrollbar-thumb { background:var(--border-hi); border-radius:3px }
  ::-webkit-scrollbar-thumb:hover { background:#3a4060 }

  /* ── Login ── */
  #login { display:flex; align-items:center; justify-content:center; min-height:100vh }
  .login-box { background:var(--card); border:1px solid var(--border-hi); border-radius:12px;
               padding:44px 40px; width:360px; text-align:center;
               box-shadow:0 8px 32px rgba(0,0,0,.6),0 0 0 1px rgba(79,142,247,.06) }
  .login-box h1 { font-size:20px; font-weight:800; letter-spacing:.18em; margin-bottom:6px }
  .login-box p  { color:var(--text-muted); margin-bottom:28px; font-size:11px;
                  text-transform:uppercase; letter-spacing:.1em }
  .login-box input { width:100%; padding:10px 14px; background:var(--bg);
                     border:1px solid var(--border-hi); border-radius:7px;
                     color:var(--text); font-size:14px; margin-bottom:12px; outline:none;
                     transition:border-color .15s,box-shadow .15s }
  .login-box input:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(79,142,247,.12) }

  /* ── Shell ── */
  #panel { display:none; min-height:100vh; flex-direction:column }

  /* topbar */
  .topbar {
    position:sticky; top:0; z-index:100;
    background:rgba(8,10,14,.96);
    backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
    border-bottom:1px solid var(--border);
    display:flex; align-items:stretch;
    padding:0 24px; gap:0; height:48px;
  }
  .topbar-brand {
    font-size:12px; font-weight:800; letter-spacing:.16em;
    color:var(--text-muted); display:flex; align-items:center;
    padding-right:24px; border-right:1px solid var(--border);
    margin-right:4px; white-space:nowrap;
  }
  .topbar-brand span { color:var(--accent) }
  .tab-btn {
    padding:0 18px; height:48px; font-size:13px; font-weight:600;
    color:var(--text-muted); background:none; border:none;
    border-bottom:2px solid transparent; cursor:pointer;
    transition:color .15s; white-space:nowrap;
  }
  .tab-btn:hover { color:var(--text-sec) }
  .tab-btn.active { color:var(--text); border-bottom-color:var(--accent) }
  .topbar-right { margin-left:auto; display:flex; align-items:center; gap:14px }
  .live-dot { display:inline-block; width:6px; height:6px; border-radius:50%;
              background:var(--ok); vertical-align:middle; margin-right:5px;
              animation:pulse 2s ease-in-out infinite }
  @keyframes pulse {
    0%,100%{ opacity:1; box-shadow:0 0 0 0 rgba(34,197,94,.5) }
    50%     { opacity:.6; box-shadow:0 0 0 4px rgba(34,197,94,0) }
  }
  .live-label { font-size:11px; color:var(--text-muted) }

  /* page content */
  .page { display:none; max-width:1140px; margin:0 auto; padding:32px 24px }
  .page.active { display:block }
  .page-title { font-size:17px; font-weight:700; margin-bottom:24px; color:var(--text);
                display:flex; align-items:baseline; gap:0 }

  /* cards */
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(148px,1fr));
           gap:12px; margin-bottom:28px }
  .card { background:var(--card); border:1px solid var(--border); border-radius:var(--radius);
          padding:18px 20px; transition:border-color .2s,box-shadow .2s }
  .card:hover { border-color:var(--border-hi); box-shadow:0 2px 12px rgba(0,0,0,.4) }
  .card-label { font-size:10px; color:var(--text-muted); text-transform:uppercase;
                letter-spacing:.1em; margin-bottom:8px; font-weight:600 }
  .card-value { font-size:26px; font-weight:700; line-height:1 }
  .card-sub   { font-size:11px; color:var(--text-muted); margin-top:5px }

  /* badges */
  .badge { display:inline-block; padding:2px 9px; border-radius:20px;
           font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em }
  .badge-free       { background:rgba(74,85,104,.2);  color:var(--text-muted); border:1px solid var(--border) }
  .badge-pro        { background:rgba(26,58,107,.4);  color:#60a5fa;  border:1px solid rgba(96,165,250,.2) }
  .badge-enterprise { background:rgba(45,26,94,.4);   color:#a78bfa;  border:1px solid rgba(167,139,250,.2) }
  .badge-beta       { background:rgba(20,49,31,.5);   color:#22c55e;  border:1px solid rgba(34,197,94,.25) }
  .badge-expired    { background:rgba(59,18,18,.5);   color:var(--danger); border:1px solid rgba(239,68,68,.2) }
  .badge-active     { background:rgba(20,49,31,.5);   color:var(--ok);     border:1px solid rgba(34,197,94,.25) }

  /* panel box */
  .panel-box { background:var(--card); border:1px solid var(--border); border-radius:var(--radius);
               padding:20px 24px; margin-bottom:24px; overflow:hidden }
  .panel-box h2 { font-size:11px; font-weight:700; margin:-20px -24px 20px;
                  padding:13px 24px; color:var(--text-muted); text-transform:uppercase;
                  letter-spacing:.1em; border-bottom:1px solid var(--border);
                  background:rgba(0,0,0,.2) }

  /* form */
  .form-row { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:12px }
  label  { display:block; font-size:10px; color:var(--text-muted); margin-bottom:5px;
           text-transform:uppercase; letter-spacing:.08em; font-weight:600 }
  input, select, textarea {
    width:100%; padding:9px 12px; background:var(--bg);
    border:1px solid var(--border-hi); border-radius:6px;
    color:var(--text); font-size:13px; outline:none; font-family:inherit;
    transition:border-color .15s,box-shadow .15s }
  input:focus, select:focus, textarea:focus {
    border-color:var(--accent); box-shadow:0 0 0 3px rgba(79,142,247,.1) }

  /* buttons */
  .btn { padding:9px 20px; border:none; border-radius:6px; cursor:pointer;
         font-size:13px; font-weight:600; transition:opacity .15s,box-shadow .15s }
  .btn:hover { opacity:.88 }
  .btn:active { opacity:.72 }
  .btn:disabled { opacity:.38; cursor:not-allowed }
  .btn-primary { background:var(--accent); color:#fff; box-shadow:0 2px 8px rgba(79,142,247,.3) }
  .btn-primary:hover { box-shadow:0 4px 16px rgba(79,142,247,.4) }
  .btn-danger  { background:var(--danger); color:#fff; padding:5px 12px; font-size:12px }
  .btn-copy    { background:var(--card2); color:var(--text-sec); border:1px solid var(--border-hi);
                 padding:4px 10px; font-size:11px; border-radius:4px }
  .btn-ghost   { background:var(--card); color:var(--text-sec); border:1px solid var(--border-hi);
                 font-size:12px; padding:6px 14px }

  /* table */
  table { width:100%; border-collapse:collapse }
  th { text-align:left; font-size:10px; color:var(--text-muted); text-transform:uppercase;
       letter-spacing:.09em; padding:0 12px 11px; font-weight:700 }
  td { padding:11px 12px; border-top:1px solid var(--border); font-size:13px; vertical-align:middle }
  tr:hover td { background:var(--card2) }
  .mono { font-family:var(--font-mono); font-size:11px; color:var(--text-muted);
          max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }

  /* filter bar */
  .filter-bar { display:flex; gap:6px; margin-bottom:14px; align-items:center; flex-wrap:wrap }
  .filter-btn { padding:5px 16px; border-radius:20px; font-size:12px; font-weight:600;
                background:transparent; color:var(--text-muted);
                border:1px solid var(--border-hi); cursor:pointer; transition:all .15s }
  .filter-btn:hover { color:var(--text); border-color:var(--text-muted) }
  .filter-btn.active { background:var(--accent); color:#fff; border-color:var(--accent);
                       box-shadow:0 2px 8px rgba(79,142,247,.25) }

  /* label chips */
  .lbl-chip { display:inline-block; padding:2px 9px; border-radius:4px;
              font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.06em }
  .lbl-unverified { background:rgba(74,85,104,.2);  color:var(--text-muted) }
  .lbl-malicious  { background:rgba(59,18,18,.5);   color:#ef4444 }
  .lbl-benign     { background:rgba(20,49,31,.5);   color:#22c55e }

  /* action buttons */
  .act-btn { padding:4px 10px; border-radius:5px; font-size:11px; font-weight:600;
             cursor:pointer; border:1px solid; transition:opacity .15s }
  .act-btn:hover { opacity:.8 }
  .act-mal  { background:rgba(59,18,18,.5); color:#ef4444; border-color:rgba(239,68,68,.3) }
  .act-ben  { background:rgba(20,49,31,.5); color:#22c55e; border-color:rgba(34,197,94,.3) }
  .act-undo { background:var(--card2); color:var(--text-muted); border-color:var(--border-hi) }

  /* labeled stripes */
  .stripe { border-radius:var(--radius); margin-bottom:12px; overflow:hidden; border:1px solid }
  .stripe-benign   { border-color:rgba(34,197,94,.18); background:rgba(34,197,94,.02) }
  .stripe-malicious{ border-color:rgba(239,68,68,.18); background:rgba(239,68,68,.02) }
  .stripe-hdr {
    display:flex; align-items:center; gap:10px;
    padding:10px 16px; cursor:pointer; user-select:none; transition:background .12s;
  }
  .stripe-hdr:hover { background:rgba(255,255,255,.03) }
  .stripe-arrow { font-size:10px; opacity:.5; transition:transform .2s }
  .stripe-arrow.open { transform:rotate(90deg) }
  .stripe-title { font-size:13px; font-weight:600; flex:1 }
  .stripe-benign    .stripe-title { color:#22c55e }
  .stripe-malicious .stripe-title { color:#ef4444 }
  .stripe-body { display:none; border-top:1px solid rgba(255,255,255,.05) }
  .stripe-body table { margin:0 }
  .stripe-body td { padding:8px 12px; font-size:12px }
  .stripe-body tr:first-child td { border-top:none }

  /* misc */
  .err   { color:var(--danger); font-size:12px; margin-top:8px }
  .ok    { color:var(--ok);     font-size:12px; margin-top:8px }
  .empty { text-align:center; padding:48px 20px; color:var(--text-muted); font-size:13px }
  hr { border:none; border-top:1px solid var(--border); margin:20px 0 }

  /* ── Dashboard layout ── */
  .metrics-row { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:20px }
  .metric { background:var(--card); border:1px solid var(--border); border-radius:var(--radius);
            padding:18px 18px 14px; transition:border-color .2s,box-shadow .2s }
  .metric:hover { border-color:var(--border-hi); box-shadow:0 2px 12px rgba(0,0,0,.4) }
  .metric-label { font-size:10px; color:var(--text-muted); text-transform:uppercase;
                  letter-spacing:.1em; font-weight:600; margin-bottom:10px }
  .metric-value { font-size:28px; font-weight:700; line-height:1; margin-bottom:5px }
  .metric-sub   { font-size:11px; color:var(--text-muted) }
  .dash-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px }
  .dash-grid .panel-box { margin-bottom:0 }
  .stat-list { display:flex; flex-direction:column }
  .stat-row  { display:flex; align-items:center; justify-content:space-between;
               padding:10px 0; border-bottom:1px solid var(--border) }
  .stat-row:last-child { border-bottom:none }
  .stat-label { font-size:13px; color:var(--text-sec) }
  .stat-val   { font-size:20px; font-weight:700 }
</style>
</head>
<body>

<!-- LOGIN -->
<div id="login">
  <div class="login-box">
    <h1>VOIDWATCH</h1>
    <p>Admin Panel</p>
    <input id="key-input" type="password" placeholder="Admin API key" />
    <button class="btn btn-primary" style="width:100%;margin-top:4px" onclick="doLogin()">Sign In</button>
    <div id="login-err" class="err" style="display:none;margin-top:10px"></div>
  </div>
</div>

<!-- PANEL -->
<div id="panel">

  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-brand">VOID<span>WATCH</span></div>
    <button class="tab-btn active" data-tab="dashboard"  onclick="switchTab('dashboard')">Dashboard</button>
    <button class="tab-btn"        data-tab="licenses"   onclick="switchTab('licenses')">Issue License</button>
    <button class="tab-btn"        data-tab="labeling"   onclick="switchTab('labeling')">Process Labeling</button>
    <div class="topbar-right">
      <span class="live-label"><span class="live-dot"></span><span id="last-updated">—</span></span>
      <button class="btn btn-ghost" onclick="doLogout()">Sign Out</button>
    </div>
  </div>

  <!-- ── Dashboard tab ── -->
  <div id="tab-dashboard" class="page active">
    <div class="page-title">Dashboard</div>

    <!-- Primary metrics — always one horizontal row -->
    <div class="metrics-row">
      <div class="metric">
        <div class="metric-label">Online Agents</div>
        <div class="metric-value" id="s-agents">—</div>
        <div class="metric-sub">Last 60 s</div>
      </div>
      <div class="metric">
        <div class="metric-label">Total Agents</div>
        <div class="metric-value" id="s-total-agents">—</div>
        <div class="metric-sub">All time</div>
      </div>
      <div class="metric">
        <div class="metric-label">Alerts</div>
        <div class="metric-value" style="color:var(--danger)" id="s-alerts">—</div>
        <div class="metric-sub">All time · ML ≥ 80%</div>
      </div>
      <div class="metric">
        <div class="metric-label">Alerts Today</div>
        <div class="metric-value" style="color:var(--warn)" id="s-alerts-today">—</div>
        <div class="metric-sub">Last 24 h</div>
      </div>
      <div class="metric">
        <div class="metric-label">Total Processes</div>
        <div class="metric-value" id="s-procs">—</div>
        <div class="metric-sub">All time</div>
      </div>
      <div class="metric">
        <div class="metric-label">Avg ML Score</div>
        <div class="metric-value" id="s-avg-ml">—</div>
        <div class="metric-sub">All processes</div>
      </div>
    </div>

    <!-- Secondary section — two side-by-side panels -->
    <div class="dash-grid">
      <div class="panel-box">
        <h2>Licenses</h2>
        <div class="stat-list">
          <div class="stat-row">
            <span class="stat-label"><span class="badge badge-free">Free</span></span>
            <span class="stat-val" id="s-free">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label"><span class="badge badge-pro">Pro</span></span>
            <span class="stat-val" style="color:#60a5fa" id="s-pro">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label"><span class="badge badge-enterprise">Enterprise</span></span>
            <span class="stat-val" style="color:#a78bfa" id="s-ent">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label"><span class="badge badge-beta">Beta</span></span>
            <span class="stat-val" style="color:#22c55e" id="s-beta">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Total Issued</span>
            <span class="stat-val" id="s-issued-total">—</span>
          </div>
        </div>
      </div>

      <div class="panel-box">
        <h2>Dataset &amp; Activity</h2>
        <div class="stat-list">
          <div class="stat-row">
            <span class="stat-label">Labeled Malicious</span>
            <span class="stat-val" style="color:var(--danger)" id="s-lbl-mal">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Labeled Benign</span>
            <span class="stat-val" style="color:var(--ok)" id="s-lbl-ben">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Alert Feedback</span>
            <span class="stat-val" id="s-feedback">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Allowlist Entries</span>
            <span class="stat-val" id="s-allowlist">—</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Total Agent Uptime</span>
            <span class="stat-val" id="s-uptime">—</span>
          </div>
        </div>
      </div>
    </div>

  </div>

  <!-- ── Issue License tab ── -->
  <div id="tab-licenses" class="page">
    <div class="page-title">Issue License</div>
    <div class="panel-box">
      <h2>New License Key</h2>
      <div class="form-row">
        <div>
          <label>Customer Name</label>
          <input id="f-customer" type="text" placeholder="Acme Corp" />
        </div>
        <div>
          <label>Tier</label>
          <select id="f-tier">
            <option value="free">Free</option>
            <option value="pro" selected>Pro</option>
            <option value="enterprise">Enterprise</option>
            <option value="beta">Beta</option>
          </select>
        </div>
        <div>
          <label>Expires (YYYY-MM-DD or blank)</label>
          <input id="f-expires" type="text" placeholder="2027-12-31" />
        </div>
      </div>
      <div class="form-row">
        <div>
          <label>Note (optional)</label>
          <input id="f-note" type="text" placeholder="Internal note" />
        </div>
        <div style="display:flex;align-items:flex-end;gap:10px">
          <button class="btn btn-primary" onclick="issueKey()">Generate License Key</button>
          <span id="f-msg" style="font-size:12px"></span>
        </div>
      </div>
      <div id="new-key-box" style="display:none;margin-top:16px">
        <hr>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span style="font-size:12px;font-weight:700;color:var(--ok)">✓ License key generated</span>
          <button class="btn btn-copy" onclick="copyNewKey()">Copy Key</button>
        </div>
        <div id="new-key-text" class="mono"
             style="background:var(--bg);padding:12px;border-radius:6px;border:1px solid var(--border-hi);
                    font-size:11px;word-break:break-all;white-space:normal;overflow:visible"></div>
      </div>
    </div>

    <div class="panel-box">
      <h2>Issued Licenses</h2>
      <table style="table-layout:fixed">
        <colgroup>
          <col style="width:4%">
          <col style="width:15%">
          <col style="width:9%">
          <col style="width:10%">
          <col style="width:10%">
          <col style="width:9%">
          <col style="width:22%">
          <col style="width:13%">
          <col style="width:8%">
        </colgroup>
        <thead><tr>
          <th>#</th><th>Customer</th><th>Tier</th>
          <th>Issued</th><th>Expires</th><th>Status</th>
          <th>Key</th><th>Note</th><th></th>
        </tr></thead>
        <tbody id="lic-tbody">
          <tr><td colspan="9" class="empty">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Process Labeling tab ── -->
  <div id="tab-labeling" class="page">
    <div class="page-title">Process Labeling
      <span style="font-size:12px;font-weight:400;color:var(--text-muted);margin-left:10px">Alerts from clients (ML ≥ 80%) · label to build training dataset</span>
    </div>

    <!-- Benign stripe -->
    <div class="stripe stripe-benign">
      <div class="stripe-hdr" onclick="toggleStripe('benign')">
        <span class="stripe-arrow" id="arrow-benign">▶</span>
        <span class="stripe-title">Benign: <span id="stripe-count-benign">—</span> selected</span>
        <button class="btn" id="btn-dl-benign"
          style="background:#14311f;color:#22c55e;border:1px solid #22c55e44;font-size:12px;padding:5px 14px"
          onclick="downloadDataset('benign');event.stopPropagation()">↓ Download</button>
      </div>
      <div class="stripe-body" id="stripe-body-benign">
        <table>
          <thead><tr>
            <th>Process</th><th>Parent</th><th>Agent</th><th>ML%</th><th>Time</th><th></th>
          </tr></thead>
          <tbody id="stripe-rows-benign"><tr><td colspan="6" class="empty">—</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- Malicious stripe -->
    <div class="stripe stripe-malicious" style="margin-bottom:20px">
      <div class="stripe-hdr" onclick="toggleStripe('malicious')">
        <span class="stripe-arrow" id="arrow-malicious">▶</span>
        <span class="stripe-title">Malicious: <span id="stripe-count-malicious">—</span> selected</span>
        <button class="btn" id="btn-dl-mal"
          style="background:#3b1212;color:#ef4444;border:1px solid #ef444444;font-size:12px;padding:5px 14px"
          onclick="downloadDataset('malicious');event.stopPropagation()">↓ Download</button>
      </div>
      <div class="stripe-body" id="stripe-body-malicious">
        <table>
          <thead><tr>
            <th>Process</th><th>Parent</th><th>Agent</th><th>ML%</th><th>Time</th><th></th>
          </tr></thead>
          <tbody id="stripe-rows-malicious"><tr><td colspan="6" class="empty">—</td></tr></tbody>
        </table>
      </div>
    </div>

    <div class="panel-box">
      <div class="filter-bar">
        <button class="filter-btn active" data-f="unverified" onclick="setFilter('unverified')">Unverified</button>
        <button class="filter-btn" data-f="malicious"  onclick="setFilter('malicious')">Malicious</button>
        <button class="filter-btn" data-f="benign"     onclick="setFilter('benign')">Benign</button>
        <button class="filter-btn" data-f="all"        onclick="setFilter('all')">All</button>
        <span id="proc-count" style="margin-left:auto;font-size:12px;color:var(--text-muted)"></span>
      </div>

      <table style="table-layout:fixed">
        <colgroup>
          <col style="width:22%">
          <col style="width:16%">
          <col style="width:17%">
          <col style="width:8%">
          <col style="width:13%">
          <col style="width:10%">
          <col style="width:14%">
        </colgroup>
        <thead><tr>
          <th>Process</th><th>Parent</th><th>Agent</th>
          <th>ML%</th><th>Time</th><th>Label</th>
          <th style="text-align:right">Actions</th>
        </tr></thead>
        <tbody id="proc-tbody">
          <tr><td colspan="7" class="empty">Loading…</td></tr>
        </tbody>
      </table>
      <div id="proc-pagination" style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:13px"></div>
    </div>
  </div>

</div><!-- /panel -->

<script>
let _key = ''

// ── Auth ──────────────────────────────────────────────────────────────
async function doLogin() {
  const k = document.getElementById('key-input').value.trim()
  try {
    const r = await fetch('/admin/stats', { headers: { 'X-API-Key': k } })
    if (!r.ok) { showLoginErr('Invalid key'); return }
    _key = k
    sessionStorage.setItem('vw_admin_key', k)
    showPanel()
  } catch { showLoginErr('Could not reach server') }
}
function doLogout() {
  sessionStorage.removeItem('vw_admin_key'); _key = ''
  document.getElementById('login').style.display = 'flex'
  document.getElementById('panel').style.display = 'none'
}
function showLoginErr(msg) {
  const el = document.getElementById('login-err')
  el.textContent = msg; el.style.display = 'block'
}
document.getElementById('key-input').addEventListener('keydown', e => { if (e.key==='Enter') doLogin() })

// ── Tab navigation ────────────────────────────────────────────────────
let _activeTab = 'dashboard'
function switchTab(name) {
  _activeTab = name
  document.querySelectorAll('.tab-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === name))
  document.querySelectorAll('.page').forEach(p =>
    p.classList.toggle('active', p.id === 'tab-' + name))
  if (name === 'labeling') { loadProcesses(_procFilter, _procPage); loadStripes() }
}

// ── Init ──────────────────────────────────────────────────────────────
let _lastRefresh = null
let _refreshTimers = []

async function showPanel() {
  document.getElementById('login').style.display = 'none'
  document.getElementById('panel').style.display = 'flex'
  await Promise.all([loadStats(), loadLicenses()])
  startLiveRefresh()
}

function startLiveRefresh() {
  _refreshTimers.forEach(clearInterval)
  _refreshTimers = [
    setInterval(loadStats,    10_000),
    setInterval(loadLicenses, 30_000),
    setInterval(() => { if (_activeTab === 'labeling') { loadProcesses(); loadStripes() } }, 30_000),
    setInterval(tickUpdated,   1_000),
  ]
}

function tickUpdated() {
  const el = document.getElementById('last-updated')
  if (!el || !_lastRefresh) return
  const s = Math.round((Date.now() - _lastRefresh) / 1000)
  el.textContent = s < 5 ? 'just now' : `updated ${s}s ago`
}

function api(path, opts={}) {
  return fetch(path, { ...opts, headers: {
    'X-API-Key': _key, 'Content-Type': 'application/json', ...(opts.headers||{})
  }})
}

// ── Stats ─────────────────────────────────────────────────────────────
function fmtUptime(hours) {
  if (hours < 1)   return Math.round(hours * 60) + ' min'
  if (hours < 48)  return hours.toFixed(1) + ' h'
  if (hours < 8760) return (hours / 24).toFixed(1) + ' d'
  return (hours / 8760).toFixed(1) + ' yr'
}

async function loadStats() {
  try {
    const r = await api('/admin/stats')
    if (!r.ok) return
    const d = await r.json()
    document.getElementById('s-agents').textContent        = d.online_agents
    document.getElementById('s-total-agents').textContent  = d.total_agents ?? '—'
    document.getElementById('s-alerts').textContent        = (d.alerts || 0).toLocaleString()
    document.getElementById('s-alerts-today').textContent  = (d.alerts_today || 0).toLocaleString()
    document.getElementById('s-procs').textContent         = (d.processes || 0).toLocaleString()
    document.getElementById('s-avg-ml').textContent        = (d.avg_ml_score ?? 0) + '%'
    document.getElementById('s-free').textContent          = d.by_tier.free || 0
    document.getElementById('s-pro').textContent           = d.by_tier.pro  || 0
    document.getElementById('s-ent').textContent           = d.by_tier.enterprise || 0
    document.getElementById('s-beta').textContent          = d.by_tier.beta || 0
    document.getElementById('s-issued-total').textContent  = d.issued_total || 0
    document.getElementById('s-lbl-mal').textContent       = d.labeled_malicious || 0
    document.getElementById('s-lbl-ben').textContent       = d.labeled_benign || 0
    document.getElementById('s-feedback').textContent      = d.total_feedback ?? 0
    document.getElementById('s-allowlist').textContent     = d.allowlist_count ?? 0
    document.getElementById('s-uptime').textContent        = fmtUptime(d.uptime_hours || 0)
    _lastRefresh = Date.now(); tickUpdated()
  } catch {}
}

// ── Licenses ──────────────────────────────────────────────────────────
async function loadLicenses() {
  try {
    const r = await api('/admin/licenses')
    if (!r.ok) return
    const rows = await r.json()
    const tb = document.getElementById('lic-tbody')
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="9" class="empty">No licenses issued yet</td></tr>'; return }
    tb.innerHTML = rows.map(l => {
      const status  = l.expired   ? '<span class="badge badge-expired">Expired</span>'
                    : l.is_active ? '<span class="badge badge-active">Active</span>'
                    :               '<span style="color:var(--text-muted);font-size:12px">—</span>'
      const expires = l.expires ? l.expires.slice(0,10) : '<span style="color:var(--text-muted)">Never</span>'
      const short   = l.token.slice(0,28) + '…'
      return `<tr>
        <td style="color:var(--text-muted)">${l.id}</td>
        <td style="font-weight:600">${esc(l.customer)}</td>
        <td>${tierBadge(l.tier)}</td>
        <td style="color:var(--text-sec)">${l.issued_at ? l.issued_at.slice(0,10) : '—'}</td>
        <td>${expires}</td><td>${status}</td>
        <td><span class="mono" title="${esc(l.token)}">${short}</span>
            <button class="btn btn-copy" onclick="copyTok(${l.id})">Copy</button></td>
        <td style="color:var(--text-muted);font-size:12px">${esc(l.note)}</td>
        <td><button class="btn btn-danger" onclick="delLic(${l.id})">Delete</button></td>
      </tr>`
    }).join('')
    window._tokens = {}
    rows.forEach(l => { window._tokens[l.id] = l.token })
  } catch {}
}

function copyTok(id) {
  navigator.clipboard.writeText(window._tokens[id]||'').then(()=>alert('Copied'))
}
async function delLic(id) {
  if (!confirm('Delete this record? (Issued JWT still works if distributed.)')) return
  await api(`/admin/licenses/${id}`, { method:'DELETE' })
  loadLicenses(); loadStats()
}

// ── Issue ─────────────────────────────────────────────────────────────
async function issueKey() {
  const customer = document.getElementById('f-customer').value.trim()
  const tier     = document.getElementById('f-tier').value
  const expires  = document.getElementById('f-expires').value.trim()
  const note     = document.getElementById('f-note').value.trim()
  const msg      = document.getElementById('f-msg')
  if (!customer) { msg.style.color='var(--danger)'; msg.textContent='Customer name required'; return }
  msg.textContent = 'Generating…'; msg.style.color = 'var(--text-muted)'
  try {
    const r = await api('/admin/licenses', {
      method:'POST', body: JSON.stringify({customer,tier,expires:expires||null,note})
    })
    const d = await r.json()
    if (!r.ok) { msg.style.color='var(--danger)'; msg.textContent=d.detail||'Error'; return }
    msg.style.color='var(--ok)'; msg.textContent='✓ Issued'
    document.getElementById('new-key-box').style.display = 'block'
    document.getElementById('new-key-text').textContent  = d.token
    window._newToken = d.token
    document.getElementById('f-customer').value = ''
    document.getElementById('f-expires').value  = ''
    document.getElementById('f-note').value     = ''
    loadLicenses(); loadStats()
    setTimeout(() => { msg.textContent = '' }, 3000)
  } catch { msg.style.color='var(--danger)'; msg.textContent='Request failed' }
}
function copyNewKey() {
  navigator.clipboard.writeText(window._newToken||'').then(()=>alert('Key copied'))
}

// ── Process Labeling ──────────────────────────────────────────────────
let _procFilter = sessionStorage.getItem('vw_proc_filter') || 'unverified'
let _procPage   = parseInt(sessionStorage.getItem('vw_proc_page') || '1', 10)
const _PROC_LIMIT = 50

async function loadProcesses(filter, page) {
  filter = filter || _procFilter
  page   = page   || _procPage
  _procFilter = filter; _procPage = page
  sessionStorage.setItem('vw_proc_filter', filter)
  sessionStorage.setItem('vw_proc_page', String(page))
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.f === filter))
  const tb = document.getElementById('proc-tbody')
  tb.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>'
  try {
    const r = await api(`/admin/processes?filter=${filter}&page=${page}&limit=${_PROC_LIMIT}`)
    const d = await r.json()
    document.getElementById('proc-count').textContent = `${d.total.toLocaleString()} processes`
    if (!d.items.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty">No processes</td></tr>'; return
    }
    tb.innerHTML = d.items.map(p => {
      const mlColor = p.ml_score >= 80 ? '#ef4444' : '#f59e0b'
      const chip    = `<span class="lbl-chip lbl-${p.label}">${p.label}</span>`
      const actions = p.label === 'unverified'
        ? `<button class="act-btn act-mal" onclick="setLabel(${p.id},'malicious')">Malicious</button>
           <button class="act-btn act-ben" onclick="setLabel(${p.id},'benign')">Benign</button>`
        : `<button class="act-btn act-undo" onclick="setLabel(${p.id},'unverified')">Undo</button>`
      const ts  = p.timestamp ? p.timestamp.slice(0,16).replace('T',' ') : '—'
      const cmd = p.command_line
        ? `<span title="${esc(p.command_line)}" style="cursor:help;color:var(--text-muted);font-size:11px"> ···</span>` : ''
      return `<tr>
        <td style="font-weight:600">${esc(p.name)}${cmd}</td>
        <td style="color:var(--text-muted)">${esc(p.parent_name)}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${esc(p.agent_id)}</td>
        <td style="font-family:var(--font-mono);font-weight:700;color:${mlColor}">${p.ml_score}%</td>
        <td style="color:var(--text-sec);font-size:12px">${ts}</td>
        <td>${chip}</td>
        <td style="text-align:right;white-space:nowrap">${actions}</td>
      </tr>`
    }).join('')
    // Pagination
    const pages = Math.ceil(d.total / _PROC_LIMIT)
    const pg = document.getElementById('proc-pagination')
    if (pages <= 1) { pg.innerHTML = ''; return }
    pg.innerHTML = `
      <button class="btn btn-ghost" onclick="loadProcesses('${filter}',${page-1})"
        ${page<=1?'disabled':''}>← Prev</button>
      <span style="color:var(--text-muted)">Page ${page} / ${pages}</span>
      <button class="btn btn-ghost" onclick="loadProcesses('${filter}',${page+1})"
        ${page>=pages?'disabled':''}>Next →</button>`
  } catch(e) {
    tb.innerHTML = `<tr><td colspan="7" class="empty">${esc(e.message)}</td></tr>`
  }
}

function setFilter(f) { loadProcesses(f, 1) }

async function setLabel(id, label) {
  await api(`/admin/processes/${id}/label`, { method:'POST', body:JSON.stringify({label}) })
  loadProcesses(_procFilter, _procPage)
  loadStripes()
  loadStats()
}

// ── Label stripes ─────────────────────────────────────────────────────
const _stripeOpen = { benign: false, malicious: false }

function toggleStripe(label) {
  _stripeOpen[label] = !_stripeOpen[label]
  const body  = document.getElementById(`stripe-body-${label}`)
  const arrow = document.getElementById(`arrow-${label}`)
  body.style.display  = _stripeOpen[label] ? 'block' : 'none'
  arrow.classList.toggle('open', _stripeOpen[label])
  if (_stripeOpen[label]) _renderStripe(label)
}

async function loadStripes() {
  for (const label of ['benign', 'malicious']) {
    try {
      const r = await api(`/admin/processes?filter=${label}&page=1&limit=200`)
      const d = await r.json()
      document.getElementById(`stripe-count-${label}`).textContent = d.total
      if (_stripeOpen[label]) _renderStripeRows(label, d.items)
    } catch {}
  }
}

async function _renderStripe(label) {
  try {
    const r = await api(`/admin/processes?filter=${label}&page=1&limit=200`)
    const d = await r.json()
    document.getElementById(`stripe-count-${label}`).textContent = d.total
    _renderStripeRows(label, d.items)
  } catch {}
}

function _renderStripeRows(label, items) {
  const tb = document.getElementById(`stripe-rows-${label}`)
  if (!items.length) {
    tb.innerHTML = '<tr><td colspan="6" class="empty">None</td></tr>'; return
  }
  const mlColor = label === 'malicious' ? '#ef4444' : '#22c55e'
  tb.innerHTML = items.map(p => {
    const ts = p.timestamp ? p.timestamp.slice(0,16).replace('T',' ') : '—'
    const cmd = p.command_line
      ? `<span title="${esc(p.command_line)}" style="cursor:help;color:var(--text-muted)"> ···</span>` : ''
    return `<tr>
      <td style="font-weight:600">${esc(p.name)}${cmd}</td>
      <td style="color:var(--text-muted)">${esc(p.parent_name)}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${esc(p.agent_id)}</td>
      <td style="font-family:var(--font-mono);font-weight:700;color:${mlColor}">${p.ml_score}%</td>
      <td style="color:var(--text-sec);font-size:11px">${ts}</td>
      <td><button class="act-btn act-undo" onclick="setLabel(${p.id},'unverified')">Undo</button></td>
    </tr>`
  }).join('')
}

async function downloadDataset(label) {
  const btn = document.getElementById(label==='benign' ? 'btn-dl-benign' : 'btn-dl-mal')
  const orig = btn.textContent; btn.textContent = 'Preparing…'; btn.disabled = true
  try {
    const r = await api(`/admin/dataset/${label}`)
    if (!r.ok) { const d=await r.json(); alert(d.detail||'No data to export'); return }
    const blob = await r.blob()
    const cd   = r.headers.get('Content-Disposition') || ''
    const name = (cd.match(/filename="([^"]+)"/) || [])[1] || `voidwatch_${label}.json`
    const url  = URL.createObjectURL(blob)
    const a    = Object.assign(document.createElement('a'), {href:url, download:name})
    a.click(); URL.revokeObjectURL(url)
    loadProcesses(_procFilter, _procPage); loadStripes(); loadStats()
  } catch(e) { alert('Download failed: ' + e.message)
  } finally { btn.textContent = orig; btn.disabled = false }
}

// ── Helpers ───────────────────────────────────────────────────────────
function tierBadge(tier) {
  const cls = {free:'badge-free',pro:'badge-pro',enterprise:'badge-enterprise',beta:'badge-beta'}[tier]||'badge-free'
  return `<span class="badge ${cls}">${tier}</span>`
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

// ── Boot ─────────────────────────────────────────────────────────────
const saved = sessionStorage.getItem('vw_admin_key')
if (saved) { _key = saved; showPanel() }
</script>
</body>
</html>
"""
