import { api, fmt, fmtDate, MITRE_NAMES, riskColor } from '../api.js'

export async function render(el, params = {}) {
  if (params.id) { return renderDetail(el, params.id) }

  el.innerHTML = '<div class="loading">Loading alerts…</div>'
  try {
    const agents  = await api.agents()
    let alerts = await api.alerts({ limit: 500 })

    el.innerHTML = `
      <div class="page-title">Alerts <span class="sub">${alerts.length} total</span></div>

      <div class="filters" id="alert-filters">
        <span class="filter-label">Filter:</span>
        <select id="f-level">
          <option value="">All levels</option>
          <option>LOW</option><option>MEDIUM</option><option>HIGH</option>
          <option>CRITICAL</option><option>SEVERE</option>
        </select>
        <select id="f-agent">
          <option value="">All agents</option>
          ${agents.map(a => `<option value="${a.agent_id}">${a.hostname}</option>`).join('')}
        </select>
        <input id="f-process" placeholder="Process name…" style="width:160px" />
        <input id="f-mitre"   placeholder="MITRE technique…" style="width:140px" />
        <button class="btn" id="f-apply">Apply</button>
        <button class="btn btn-danger" id="f-reset">Reset</button>
      </div>

      <div class="alert-grid" id="alerts-list">
        ${renderCards(alerts)}
      </div>
    `

    function applyFilters() {
      const level   = el.querySelector('#f-level').value
      const agent   = el.querySelector('#f-agent').value
      const process = el.querySelector('#f-process').value.toLowerCase()
      const mitre   = el.querySelector('#f-mitre').value.toUpperCase()

      let filtered = alerts
      if (level)   filtered = filtered.filter(a => a.risk_level === level)
      if (agent)   filtered = filtered.filter(a => a.agent_id === agent)
      if (process) filtered = filtered.filter(a => a.process_name.toLowerCase().includes(process))
      if (mitre)   filtered = filtered.filter(a => a.mitre.some(m => m.includes(mitre)))

      el.querySelector('#alerts-list').innerHTML = renderCards(filtered)
      bindCards()
    }

    el.querySelector('#f-apply').addEventListener('click', applyFilters)
    el.querySelector('#f-reset').addEventListener('click', () => {
      el.querySelectorAll('#alert-filters input, #alert-filters select').forEach(i => i.value = '')
      el.querySelector('#alerts-list').innerHTML = renderCards(alerts)
      bindCards()
    })
    bindCards()

    function bindCards() {
      el.querySelectorAll('.alert-card[data-id]').forEach(card => {
        card.addEventListener('click', () => {
          window.location.hash = '#/alerts/' + card.dataset.id
        })
      })
    }
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}

function renderCards(alerts) {
  if (!alerts.length) return '<div class="empty">No alerts match filters</div>'
  return alerts.map(a => `
    <div class="alert-card level-${a.risk_level}" data-id="${a.id}">
      <div class="alert-top">
        <span class="badge badge-${a.risk_level}">${a.risk_level}</span>
        <span class="alert-process">${a.process_name}</span>
        ${a.parent_name ? `<span class="alert-parent">← ${a.parent_name}</span>` : ''}
        <span style="margin-left:auto">
          ${a.category ? `<span style="font-size:11px;color:var(--text-muted);background:var(--border);padding:2px 7px;border-radius:3px">${a.category}</span>` : ''}
        </span>
      </div>
      <div class="alert-meta">
        <div class="alert-meta-item"><span class="key">Risk Score: </span><span class="val" style="color:${riskColor(a.risk_level)}">${a.risk_score}</span></div>
        <div class="alert-meta-item"><span class="key">ML Probability: </span><span class="val">${Math.round(a.ml_score * 100)}%</span></div>
        <div class="alert-meta-item"><span class="key">Confidence: </span><span class="val">${a.confidence_label}</span></div>
        <div class="alert-meta-item"><span class="key">Agent: </span><span class="val">${a.agent_id}</span></div>
      </div>
      <ul class="alert-reasons">
        ${(a.reasons || []).slice(0,4).map(r => `<li>${r}</li>`).join('')}
      </ul>
      <div class="alert-footer">
        <div class="alert-mitre">
          ${(a.mitre || []).map(m => `<span class="mitre-tag">${m}</span>`).join('')}
        </div>
        <span class="alert-time">${fmtDate(a.timestamp)}</span>
      </div>
    </div>
  `).join('')
}

async function renderDetail(el, id) {
  el.innerHTML = '<div class="loading">Loading alert…</div>'
  try {
    const alerts = await api.alerts({ limit: 1000 })
    const a = alerts.find(x => String(x.id) === String(id))
    if (!a) { el.innerHTML = '<div class="empty">Alert not found</div>'; return }

    el.innerHTML = `
      <a class="back-btn clickable" href="#/alerts">← Back to Alerts</a>

      <div class="detail-hero">
        <div class="detail-level" style="color:${riskColor(a.risk_level)}">${a.risk_level} — ${a.category || 'Suspicious Behavior'}</div>
        <div class="detail-title">${a.process_name}</div>
        <div class="detail-stats">
          <div class="detail-stat">
            <div class="key">Risk Score</div>
            <div class="val" style="color:${riskColor(a.risk_level)}">${a.risk_score}</div>
          </div>
          <div class="detail-stat">
            <div class="key">Confidence</div>
            <div class="val">${a.confidence_label} <span style="font-size:13px;color:var(--text-muted)">(${a.confidence})</span></div>
          </div>
          <div class="detail-stat">
            <div class="key">ML Probability</div>
            <div class="val">${Math.round(a.ml_score * 100)}%</div>
          </div>
        </div>
      </div>

      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Process Info</div>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div><div style="font-size:11px;color:var(--text-muted)">Process</div><div class="detail-value">${a.process_name}</div></div>
            <div><div style="font-size:11px;color:var(--text-muted)">Parent</div><div class="detail-value">${a.parent_name || '—'}</div></div>
            <div><div style="font-size:11px;color:var(--text-muted)">PID</div><div class="detail-value">${a.pid}</div></div>
            <div><div style="font-size:11px;color:var(--text-muted)">Agent</div><div class="detail-value">${a.agent_id}</div></div>
            <div><div style="font-size:11px;color:var(--text-muted)">Timestamp</div><div class="detail-value">${fmtDate(a.timestamp)}</div></div>
          </div>
        </div>

        <div class="detail-section">
          <div class="detail-section-title">Detection Reasons</div>
          <ul class="detail-reasons">
            ${(a.reasons || []).map(r => `<li>${r}</li>`).join('')}
          </ul>
        </div>

        <div class="detail-section">
          <div class="detail-section-title">MITRE ATT&CK</div>
          <div class="mitre-list">
            ${(a.mitre || []).map(m => `
              <div class="mitre-item">
                <span class="code">${m}</span>
                <span class="name">${MITRE_NAMES[m] ?? MITRE_NAMES[m.split('.')[0]] ?? 'Unknown Technique'}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="detail-section">
          <div class="detail-section-title">Event Timeline</div>
          <div class="timeline-wrap" style="padding:0">
            <div class="timeline-list">
              ${(a.timeline || []).map(e => `
                <div class="tl-item p-${e.priority || 'LOW'}">
                  <div class="tl-time">${e.time}</div>
                  <div class="tl-event">${e.event}</div>
                </div>
              `).join('') || '<span style="color:var(--text-muted);font-size:12px">No timeline data</span>'}
            </div>
          </div>
        </div>
      </div>
    `
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}
