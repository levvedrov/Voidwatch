import { api, fmt, ago, scoreColor, mlColor, parseUTC } from '../api.js'

const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'SEVERE']
const HIGH_PLUS = new Set(['HIGH', 'CRITICAL', 'SEVERE'])

export async function render(el) {
  try {
    const [alerts, agents] = await Promise.all([
      api.alerts({ limit: 500 }),
      api.agents(),
    ])

    const today       = new Date().toDateString()
    const todayAlerts = alerts.filter(a => new Date(a.timestamp).toDateString() === today)
    const severeCount = alerts.filter(a => HIGH_PLUS.has(a.risk_level)).length
    const avgRisk     = alerts.length ? Math.round(alerts.reduce((s, a) => s + a.risk_score, 0) / alerts.length) : 0

    const latestAgent = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    const lastSeen    = latestAgent ? ago(latestAgent.last_seen) : '—'
    const onlineCount = agents.filter(a => (Date.now() - parseUTC(a.last_seen)) < 60000).length

    const dist = {}
    LEVELS.forEach(l => dist[l] = 0)
    alerts.forEach(a => { dist[a.risk_level] = (dist[a.risk_level] ?? 0) + 1 })
    const maxDist = Math.max(...Object.values(dist), 1)

    // HIGH+ alerts deduplicated by process name, highest score wins
    const highMap = {}
    alerts.filter(a => HIGH_PLUS.has(a.risk_level)).forEach(a => {
      if (!highMap[a.process_name] || a.risk_score > highMap[a.process_name].risk_score)
        highMap[a.process_name] = a
    })
    const highAlerts = Object.values(highMap)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 12)

    el.innerHTML = `
      <div class="page-title" style="margin-bottom:20px">Dashboard <span class="sub">Overview</span></div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">Online Agents</div>
          <div class="stat-value ${onlineCount > 0 ? 'accent' : ''}">${onlineCount}</div>
          <div class="stat-sub">${agents.length} registered</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Alerts Today</div>
          <div class="stat-value">${todayAlerts.length}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Total Alerts</div>
          <div class="stat-value">${alerts.length}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">High or above</div>
          <div class="stat-value ${severeCount > 0 ? 'danger' : ''}">${severeCount}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Avg Risk Score</div>
          <div class="stat-value ${avgRisk >= 80 ? 'danger' : avgRisk >= 50 ? 'warn' : ''}">${avgRisk}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Last Check</div>
          <div class="stat-value" data-ts="${latestAgent?.last_seen ?? ''}" style="font-size:16px;padding-top:4px">${lastSeen}</div>
        </div>
      </div>

      <div class="split">
        <div class="panel">
          <div class="panel-header">
            High+ Risk Processes
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${highAlerts.length} unique</span>
          </div>
          ${highAlerts.length ? `
            <table class="data-table">
              <thead><tr>
                <th style="width:16px"></th>
                <th>Process</th>
                <th>Parent</th>
                <th>Category</th>
                <th>Score</th>
                <th>ML</th>
              </tr></thead>
              <tbody>
                ${highAlerts.map(a => {
                  const ml = Math.round(a.ml_score * 100)
                  return `
                    <tr class="row-${a.risk_level}">
                      <td><span class="risk-dot rdot-${a.risk_level}"></span></td>
                      <td class="proc-name">${esc(a.process_name)}</td>
                      <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
                      <td style="font-size:12px;color:var(--text-muted)">${esc(a.category || '—')}</td>
                      <td style="font-weight:700;color:${scoreColor(a.risk_score)}">${a.risk_score}</td>
                      <td style="font-family:var(--font-mono);font-size:12px;color:${mlColor(ml)}">${ml}%</td>
                    </tr>
                  `
                }).join('')}
              </tbody>
            </table>
          ` : '<div class="empty" style="padding:32px">No high-risk processes detected</div>'}
        </div>

        <div class="panel">
          <div class="panel-header">Risk Distribution</div>
          <div class="risk-dist">
            ${LEVELS.map(l => `
              <div class="risk-row">
                <span class="risk-label">${l.charAt(0) + l.slice(1).toLowerCase()}</span>
                <div class="risk-bar-wrap">
                  <div class="risk-bar rbar-${l}" style="width:${Math.round((dist[l] / maxDist) * 100)}%"></div>
                </div>
                <span class="risk-count">${dist[l]}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load dashboard: ${e.message}</div>`
  }
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}
