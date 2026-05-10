import { api, fmt, ago, riskColor } from '../api.js'

const LEVELS = ['LOW','MEDIUM','HIGH','CRITICAL','SEVERE']

export async function render(el) {
  el.innerHTML = '<div class="loading">Loading dashboard…</div>'
  try {
    const [alerts, agents] = await Promise.all([
      api.alerts({ limit: 500 }),
      api.agents(),
    ])

    const today = new Date().toDateString()
    const todayAlerts  = alerts.filter(a => new Date(a.timestamp).toDateString() === today)
    const severeCount  = alerts.filter(a => a.risk_level === 'SEVERE' || a.risk_level === 'CRITICAL').length
    const avgRisk      = alerts.length ? Math.round(alerts.reduce((s,a) => s + a.risk_score, 0) / alerts.length) : 0
    const lastTs       = alerts.length ? alerts[0].timestamp : null

    const dist = {}
    LEVELS.forEach(l => dist[l] = 0)
    alerts.forEach(a => { dist[a.risk_level] = (dist[a.risk_level] ?? 0) + 1 })
    const maxDist = Math.max(...Object.values(dist), 1)

    const recent = alerts.slice(0, 8)

    el.innerHTML = `
      <div class="page-title">Dashboard <span class="sub">Overview</span></div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">Online Agents</div>
          <div class="stat-value accent">${agents.length}</div>
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
          <div class="stat-label">Critical / Severe</div>
          <div class="stat-value ${severeCount > 0 ? 'danger' : ''}">${severeCount}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Avg Risk Score</div>
          <div class="stat-value ${avgRisk >= 80 ? 'danger' : avgRisk >= 50 ? 'warn' : ''}">${avgRisk}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Last Telemetry</div>
          <div class="stat-value" style="font-size:16px;">${lastTs ? ago(lastTs) : '—'}</div>
        </div>
      </div>

      <div class="split">
        <div class="panel">
          <div class="panel-header">
            Recent Alerts
            <a href="#/alerts" style="font-size:11px;color:var(--accent);font-weight:400;">view all →</a>
          </div>
          <table class="data-table">
            <thead><tr>
              <th>Time</th><th>Process</th><th>Parent</th><th>Score</th><th>Level</th>
            </tr></thead>
            <tbody>
              ${recent.length ? recent.map(a => `
                <tr class="row-${a.risk_level}" data-alert-id="${a.id}" style="cursor:pointer">
                  <td style="font-size:11px;font-family:var(--font-mono);white-space:nowrap">${fmt(a.timestamp)}</td>
                  <td class="process-name">${a.process_name}</td>
                  <td>${a.parent_name || '—'}</td>
                  <td style="color:${riskColor(a.risk_level)};font-weight:700">${a.risk_score}</td>
                  <td><span class="badge badge-${a.risk_level}">${a.risk_level}</span></td>
                </tr>
              `).join('') : '<tr><td colspan="5" class="empty">No alerts</td></tr>'}
            </tbody>
          </table>
        </div>

        <div class="panel">
          <div class="panel-header">Risk Distribution</div>
          <div class="risk-dist">
            ${LEVELS.map(l => `
              <div class="risk-row">
                <span class="risk-label rlabel-${l}">${l}</span>
                <div class="risk-bar-wrap">
                  <div class="risk-bar rbar-${l}" style="width:${Math.round((dist[l]/maxDist)*100)}%"></div>
                </div>
                <span class="risk-count">${dist[l]}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `

    el.querySelectorAll('tr[data-alert-id]').forEach(row => {
      row.addEventListener('click', () => {
        window.location.hash = '#/alerts/' + row.dataset.alertId
      })
    })
  } catch (e) {
    el.innerHTML = `<div class="empty">Failed to load dashboard: ${e.message}</div>`
  }
}
