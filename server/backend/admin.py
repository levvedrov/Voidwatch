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
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import (AgentRecord, AlertRecord, IssuedLicense,
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
    threshold     = datetime.utcnow() - timedelta(seconds=60)
    online_agents = db.query(AgentRecord).filter(AgentRecord.last_seen >= threshold).count()
    total_alerts  = db.query(AlertRecord).count()
    total_procs   = db.query(ProcessRecord).count()
    issued        = db.query(IssuedLicense).all()
    by_tier       = {"free": 0, "pro": 0, "enterprise": 0, "beta": 0}
    for r in issued:
        by_tier[r.tier] = by_tier.get(r.tier, 0) + 1
    high_risk  = (
        db.query(func.count())
          .select_from(
              db.query(func.max(ProcessRecord.id))
                .filter(ProcessRecord.ml_score >= 0.80)
                .group_by(ProcessRecord.name)
                .subquery()
          ).scalar() or 0
    )
    lbl_counts = dict(
        db.query(ProcessLabel.label, func.count(ProcessLabel.id))
          .group_by(ProcessLabel.label).all()
    )
    return {
        "online_agents":     online_agents,
        "high_risk":         high_risk,
        "processes":         total_procs,
        "issued_total":      len(issued),
        "by_tier":           by_tier,
        "labeled_malicious": lbl_counts.get("malicious", 0),
        "labeled_benign":    lbl_counts.get("benign", 0),
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
  }
  body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif;
         font-size:14px; min-height:100vh }

  /* ── Login ── */
  #login { display:flex; align-items:center; justify-content:center; min-height:100vh }
  .login-box { background:var(--card); border:1px solid var(--border-hi); border-radius:10px;
               padding:40px; width:360px; text-align:center }
  .login-box h1 { font-size:22px; font-weight:700; letter-spacing:.08em; margin-bottom:6px }
  .login-box p  { color:var(--text-sec); margin-bottom:24px; font-size:13px }
  .login-box input { width:100%; padding:10px 14px; background:var(--bg);
                     border:1px solid var(--border-hi); border-radius:6px;
                     color:var(--text); font-size:14px; margin-bottom:12px; outline:none }
  .login-box input:focus { border-color:var(--accent) }

  /* ── Shell ── */
  #panel { display:none; min-height:100vh; flex-direction:column }

  /* topbar */
  .topbar {
    position:sticky; top:0; z-index:100;
    background:#0a0c10;
    border-bottom:1px solid var(--border);
    display:flex; align-items:stretch;
    padding:0 24px;
    gap:0;
  }
  .topbar-brand {
    font-size:13px; font-weight:700; letter-spacing:.12em;
    color:var(--text-muted); display:flex; align-items:center;
    padding-right:28px; border-right:1px solid var(--border);
    margin-right:4px; white-space:nowrap;
  }
  .topbar-brand span { color:var(--accent) }
  .tab-btn {
    padding:0 20px; height:46px; font-size:13px; font-weight:600;
    color:var(--text-muted); background:none; border:none;
    border-bottom:2px solid transparent; cursor:pointer;
    transition:.15s; white-space:nowrap;
  }
  .tab-btn:hover { color:var(--text) }
  .tab-btn.active { color:var(--text); border-bottom-color:var(--accent) }
  .topbar-right {
    margin-left:auto; display:flex; align-items:center; gap:14px;
  }
  .live-dot { display:inline-block; width:6px; height:6px; border-radius:50%;
              background:var(--ok); vertical-align:middle; margin-right:5px;
              animation:pulse 2s ease-in-out infinite }
  @keyframes pulse {
    0%,100%{ opacity:1; box-shadow:0 0 0 0 rgba(34,197,94,.5) }
    50%     { opacity:.6; box-shadow:0 0 0 4px rgba(34,197,94,0) }
  }
  .live-label { font-size:11px; color:var(--text-muted) }

  /* page content */
  .page { display:none; max-width:1140px; margin:0 auto; padding:28px 24px }
  .page.active { display:block }
  .page-title { font-size:18px; font-weight:700; margin-bottom:22px; color:var(--text) }

  /* cards */
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
           gap:14px; margin-bottom:28px }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px;
          padding:18px 20px }
  .card-label { font-size:11px; color:var(--text-muted); text-transform:uppercase;
                letter-spacing:.07em; margin-bottom:6px }
  .card-value { font-size:28px; font-weight:700 }
  .card-sub   { font-size:12px; color:var(--text-sec); margin-top:2px }

  /* badges */
  .badge { display:inline-block; padding:2px 10px; border-radius:20px;
           font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.07em }
  .badge-free       { background:#1e2435; color:var(--text-sec) }
  .badge-pro        { background:#1a3a6b; color:#60a5fa }
  .badge-enterprise { background:#2d1a5e; color:#a78bfa }
  .badge-beta       { background:#14311f; color:#22c55e; border:1px solid #22c55e44 }
  .badge-expired    { background:#3b1212; color:var(--danger) }
  .badge-active     { background:#14311f; color:var(--ok) }

  /* panel box */
  .panel-box { background:var(--card); border:1px solid var(--border); border-radius:8px;
               padding:20px 24px; margin-bottom:28px }
  .panel-box h2 { font-size:13px; font-weight:700; margin-bottom:18px;
                  color:var(--text-sec); text-transform:uppercase; letter-spacing:.08em }

  /* form */
  .form-row { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:12px }
  label  { display:block; font-size:11px; color:var(--text-muted); margin-bottom:5px;
           text-transform:uppercase; letter-spacing:.06em }
  input, select, textarea {
    width:100%; padding:8px 12px; background:var(--bg);
    border:1px solid var(--border-hi); border-radius:6px;
    color:var(--text); font-size:13px; outline:none; font-family:inherit }
  input:focus, select:focus, textarea:focus { border-color:var(--accent) }

  /* buttons */
  .btn { padding:9px 20px; border:none; border-radius:6px; cursor:pointer;
         font-size:13px; font-weight:600; transition:opacity .15s }
  .btn:hover { opacity:.85 }
  .btn-primary { background:var(--accent); color:#fff }
  .btn-danger  { background:var(--danger); color:#fff; padding:5px 12px; font-size:12px }
  .btn-copy    { background:var(--card2); color:var(--text-sec); border:1px solid var(--border-hi);
                 padding:4px 10px; font-size:11px; border-radius:4px }
  .btn-ghost   { background:var(--card); color:var(--text-sec); border:1px solid var(--border-hi);
                 font-size:12px; padding:6px 14px }

  /* table */
  table { width:100%; border-collapse:collapse }
  th { text-align:left; font-size:11px; color:var(--text-muted); text-transform:uppercase;
       letter-spacing:.07em; padding:0 12px 10px; font-weight:600 }
  td { padding:10px 12px; border-top:1px solid var(--border); font-size:13px; vertical-align:middle }
  tr:hover td { background:var(--card2) }
  .mono { font-family:var(--font-mono); font-size:11px; color:var(--text-muted);
          max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }

  /* filter bar */
  .filter-bar { display:flex; gap:6px; margin-bottom:14px; align-items:center }
  .filter-btn { padding:5px 14px; border-radius:5px; font-size:12px; font-weight:600;
                background:transparent; color:var(--text-muted);
                border:1px solid var(--border-hi); cursor:pointer; transition:.15s }
  .filter-btn:hover { color:var(--text); border-color:var(--text-muted) }
  .filter-btn.active { background:var(--accent); color:#fff; border-color:var(--accent) }

  /* label chips */
  .lbl-chip { display:inline-block; padding:2px 9px; border-radius:4px;
              font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.05em }
  .lbl-unverified { background:#1e2435; color:var(--text-muted) }
  .lbl-malicious  { background:#3b1212; color:#ef4444 }
  .lbl-benign     { background:#14311f; color:#22c55e }

  /* action buttons */
  .act-btn { padding:3px 9px; border-radius:4px; font-size:11px; font-weight:600;
             cursor:pointer; border:1px solid; transition:opacity .15s }
  .act-btn:hover { opacity:.8 }
  .act-mal  { background:#3b1212; color:#ef4444; border-color:#ef444466 }
  .act-ben  { background:#14311f; color:#22c55e; border-color:#22c55e66 }
  .act-undo { background:var(--card2); color:var(--text-muted); border-color:var(--border-hi) }

  /* labeled stripes */
  .stripe { border-radius:6px; margin-bottom:10px; overflow:hidden; border:1px solid }
  .stripe-benign   { border-color:rgba(34,197,94,.22);  background:rgba(34,197,94,.03)  }
  .stripe-malicious{ border-color:rgba(239,68,68,.22);  background:rgba(239,68,68,.03)  }
  .stripe-hdr {
    display:flex; align-items:center; gap:10px;
    padding:9px 14px; cursor:pointer; user-select:none; transition:.12s;
  }
  .stripe-hdr:hover { background:rgba(255,255,255,.03) }
  .stripe-arrow { font-size:10px; opacity:.6; transition:transform .2s }
  .stripe-arrow.open { transform:rotate(90deg) }
  .stripe-title { font-size:13px; font-weight:600; flex:1 }
  .stripe-benign    .stripe-title { color:#22c55e }
  .stripe-malicious .stripe-title { color:#ef4444 }
  .stripe-body { display:none; border-top:1px solid rgba(255,255,255,.06) }
  .stripe-body table { margin:0 }
  .stripe-body td { padding:7px 12px; font-size:12px }
  .stripe-body tr:first-child td { border-top:none }

  /* misc */
  .err   { color:var(--danger); font-size:12px; margin-top:8px }
  .ok    { color:var(--ok);     font-size:12px; margin-top:8px }
  .empty { text-align:center; padding:32px; color:var(--text-muted) }
  hr { border:none; border-top:1px solid var(--border); margin:20px 0 }
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
    <div class="cards">
      <div class="card">
        <div class="card-label">Online Agents</div>
        <div class="card-value" id="s-agents">—</div>
        <div class="card-sub">Last 60 s</div>
      </div>
      <div class="card">
        <div class="card-label">High Risk</div>
        <div class="card-value" id="s-highrisk" style="color:#ef4444">—</div>
        <div class="card-sub">ML ≥ 80% · all clients</div>
      </div>
      <div class="card"><div class="card-label">Issued Free</div><div class="card-value" id="s-free">—</div></div>
      <div class="card"><div class="card-label">Issued Pro</div><div class="card-value" id="s-pro" style="color:#60a5fa">—</div></div>
      <div class="card"><div class="card-label">Issued Enterprise</div><div class="card-value" id="s-ent" style="color:#a78bfa">—</div></div>
      <div class="card"><div class="card-label">Issued Beta</div><div class="card-value" id="s-beta" style="color:#22c55e">—</div></div>
      <div class="card">
        <div class="card-label">Labeled Malicious</div>
        <div class="card-value" id="s-lbl-mal" style="color:#ef4444">—</div>
        <div class="card-sub">Cumulative</div>
      </div>
      <div class="card">
        <div class="card-label">Labeled Benign</div>
        <div class="card-value" id="s-lbl-ben" style="color:#22c55e">—</div>
        <div class="card-sub">Cumulative</div>
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
      <table>
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
      <span style="font-size:12px;font-weight:400;color:var(--text-muted);margin-left:10px">High-risk processes from clients (ML ≥ 80%) · label to build training dataset</span>
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

      <table>
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
  if (name === 'labeling') { loadProcesses(_procFilter, 1); loadStripes() }
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
async function loadStats() {
  try {
    const r = await api('/admin/stats')
    if (!r.ok) return
    const d = await r.json()
    document.getElementById('s-agents').textContent   = d.online_agents
    document.getElementById('s-highrisk').textContent = d.high_risk.toLocaleString()
    document.getElementById('s-free').textContent     = d.by_tier.free || 0
    document.getElementById('s-pro').textContent      = d.by_tier.pro  || 0
    document.getElementById('s-ent').textContent      = d.by_tier.enterprise || 0
    document.getElementById('s-beta').textContent     = d.by_tier.beta || 0
    document.getElementById('s-lbl-mal').textContent  = d.labeled_malicious || 0
    document.getElementById('s-lbl-ben').textContent  = d.labeled_benign || 0
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
let _procFilter = 'unverified'
let _procPage   = 1
const _PROC_LIMIT = 50

async function loadProcesses(filter, page) {
  filter = filter || _procFilter
  page   = page   || _procPage
  _procFilter = filter; _procPage = page
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
