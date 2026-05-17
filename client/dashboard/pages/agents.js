import { api, fmtDate, ago, esc, parseUTC } from '../api.js'

const MODES = ['collect_only', 'detect', 'debug']
const MODE_COLOR = { collect_only: '#6b7280', detect: '#22c55e', debug: '#eab308' }

export async function render(el) {
  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">Agents</div>
      <div class="toolbar-controls" style="gap:8px">
        <button class="btn-sm" id="btn-new-token">+ New Token</button>
        <button class="btn-sm" id="btn-export-alerts" title="Export alerts CSV">↓ Alerts CSV</button>
        <button class="btn-sm" id="btn-export-tel" title="Export telemetry CSV">↓ Telemetry CSV</button>
      </div>
    </div>
    <div id="ag-agents" class="panel" style="margin-bottom:16px"></div>
    <div class="page-title" style="font-size:14px;margin-bottom:8px">Enrollment Tokens</div>
    <div id="ag-tokens" class="panel"></div>
    <div id="ag-modal" style="display:none"></div>
  `

  el.querySelector('#btn-export-alerts').addEventListener('click', () => {
    window.open(api.exportAlertsCSV(), '_blank')
  })
  el.querySelector('#btn-export-tel').addEventListener('click', () => {
    window.open(api.exportTelemetryCSV(), '_blank')
  })
  el.querySelector('#btn-new-token').addEventListener('click', () => showTokenModal(el))

  await Promise.all([loadAgents(el), loadTokens(el)])
}

async function loadAgents(el) {
  const wrap = el.querySelector('#ag-agents')
  let agents = []
  try { agents = await api.agents() } catch(e) {
    wrap.innerHTML = `<div class="empty">Error loading agents: ${esc(e.message)}</div>`
    return
  }

  if (!agents.length) {
    wrap.innerHTML = `<div class="empty">No agents registered yet.</div>`
    return
  }

  const table = document.createElement('table')
  table.className = 'data-table'
  table.innerHTML = `<thead><tr>
    <th></th>
    <th>Agent ID</th>
    <th>Hostname</th>
    <th>Mode</th>
    <th>Events</th>
    <th>Alerts</th>
    <th>Feedback</th>
    <th>Last Seen</th>
    <th></th>
  </tr></thead>`

  const tbody = document.createElement('tbody')
  for (const a of agents) {
    const online = (Date.now() - parseUTC(a.last_seen)) < 90_000
    const modeC  = MODE_COLOR[a.mode] || '#6b7280'
    const tr = document.createElement('tr')
    tr.innerHTML = `
      <td><span class="sbar-dot" style="background:${online ? '#22c55e' : '#4b5563'};display:inline-block;width:8px;height:8px;border-radius:50%"></span></td>
      <td class="mono" style="font-size:11px">${esc(a.agent_id)}</td>
      <td>${esc(a.hostname)}</td>
      <td>
        <select class="mode-select" data-agent="${esc(a.agent_id)}" style="background:transparent;color:${modeC};border:1px solid ${modeC}44;border-radius:4px;font-size:11px;padding:2px 4px">
          ${MODES.map(m => `<option value="${m}" ${m === a.mode ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
      </td>
      <td style="font-family:var(--font-mono)">${a.event_count.toLocaleString()}</td>
      <td style="font-family:var(--font-mono)">${a.alert_count}</td>
      <td style="font-family:var(--font-mono)">${a.feedback_count}</td>
      <td style="color:var(--text-muted);font-size:12px" data-ts="${a.last_seen}">${ago(a.last_seen)}</td>
      <td>
        <button class="btn-danger-sm" data-revoke="${esc(a.agent_id)}" title="Revoke agent">Revoke</button>
      </td>
    `
    tbody.appendChild(tr)
  }
  table.appendChild(tbody)
  wrap.innerHTML = ''
  wrap.appendChild(table)

  wrap.querySelectorAll('.mode-select').forEach(sel => {
    sel.addEventListener('change', async () => {
      const agentId = sel.dataset.agent
      const mode    = sel.value
      try {
        await api.setAgentMode(agentId, mode)
        sel.style.color = MODE_COLOR[mode] || '#6b7280'
      } catch(e) {
        alert('Failed to update mode: ' + e.message)
      }
    })
  })

  wrap.querySelectorAll('[data-revoke]').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm(`Revoke agent ${btn.dataset.revoke}? They will no longer be able to send telemetry.`)) return
      try {
        await api.revokeAgent(btn.dataset.revoke)
        btn.closest('tr').style.opacity = '0.4'
        btn.textContent = 'Revoked'
        btn.disabled = true
      } catch(e) {
        alert('Failed: ' + e.message)
      }
    })
  })
}

async function loadTokens(el) {
  const wrap = el.querySelector('#ag-tokens')
  let tokens = []
  try { tokens = await api.getTokens() } catch {
    wrap.innerHTML = `<div class="empty">Could not load tokens.</div>`
    return
  }

  if (!tokens.length) {
    wrap.innerHTML = `<div class="empty">No tokens yet. Create one to enroll a new agent.</div>`
    return
  }

  const table = document.createElement('table')
  table.className = 'data-table'
  table.innerHTML = `<thead><tr>
    <th>Token</th><th>Label</th><th>Created</th><th>Expires</th><th>Used</th>
  </tr></thead>`
  const tbody = document.createElement('tbody')
  for (const t of tokens) {
    const tr = document.createElement('tr')
    const usedStyle = t.used ? 'color:var(--text-muted);text-decoration:line-through' : 'color:#22c55e'
    tr.innerHTML = `
      <td class="mono" style="font-size:11px;${usedStyle}">${esc(t.token)}</td>
      <td>${esc(t.label || '—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtDate(t.created_at)}</td>
      <td style="font-size:12px;color:var(--text-muted)">${t.expires_at ? fmtDate(t.expires_at) : '—'}</td>
      <td style="font-size:12px">${t.used ? `<span style="color:var(--text-muted)">✓ ${esc(t.used_by || '')}</span>` : '<span style="color:#22c55e">Available</span>'}</td>
    `
    tbody.appendChild(tr)
  }
  table.appendChild(tbody)
  wrap.innerHTML = ''
  wrap.appendChild(table)
}

function showTokenModal(el) {
  const modal = el.querySelector('#ag-modal')
  modal.style.display = 'block'
  modal.innerHTML = `
    <div style="position:fixed;inset:0;background:#0008;z-index:100;display:flex;align-items:center;justify-content:center">
      <div class="panel" style="width:360px;padding:24px;display:flex;flex-direction:column;gap:14px">
        <div style="font-size:15px;font-weight:600">Create Enrollment Token</div>
        <div>
          <label style="font-size:12px;color:var(--text-muted)">Label (e.g. tester name)</label>
          <input id="tok-label" type="text" placeholder="tester-01"
            style="width:100%;margin-top:4px;padding:6px 8px;background:var(--input-bg,#1a1a2e);
                   border:1px solid var(--border);border-radius:4px;color:inherit;font-size:13px">
        </div>
        <div>
          <label style="font-size:12px;color:var(--text-muted)">Expires in (hours, blank = never)</label>
          <input id="tok-exp" type="number" placeholder="72"
            style="width:100%;margin-top:4px;padding:6px 8px;background:var(--input-bg,#1a1a2e);
                   border:1px solid var(--border);border-radius:4px;color:inherit;font-size:13px">
        </div>
        <div id="tok-result" style="font-family:var(--font-mono);font-size:12px;word-break:break-all;
             color:#22c55e;min-height:20px"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button id="tok-cancel" class="btn-sm">Cancel</button>
          <button id="tok-create" class="btn-sm" style="background:#22c55e22;color:#22c55e;border-color:#22c55e44">Create</button>
        </div>
      </div>
    </div>
  `
  modal.querySelector('#tok-cancel').addEventListener('click', () => { modal.style.display = 'none' })
  modal.querySelector('#tok-create').addEventListener('click', async () => {
    const label = modal.querySelector('#tok-label').value.trim()
    const exp   = parseInt(modal.querySelector('#tok-exp').value) || null
    try {
      const tok = await api.createToken(label, exp)
      modal.querySelector('#tok-result').textContent = '✓ Token: ' + tok.token
      await loadTokens(el)
    } catch(e) {
      modal.querySelector('#tok-result').style.color = '#ef4444'
      modal.querySelector('#tok-result').textContent = 'Error: ' + e.message
    }
  })
}
