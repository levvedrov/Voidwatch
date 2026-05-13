import { api, ago, mlColor, parseUTC } from '../api.js'

const HIGH_PLUS = new Set(['HIGH', 'CRITICAL', 'SEVERE'])

// Map ml_score (0–1) to a CSS level token using the 3-band scheme
function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}

export async function render(el) {
  try {
    const [alerts, agents] = await Promise.all([
      api.alerts({ limit: 500 }),
      api.agents(),
    ])

    const today       = new Date().toDateString()
    const todayAlerts = alerts.filter(a => new Date(a.timestamp).toDateString() === today)
    const highMlCount = alerts.filter(a => (a.ml_score ?? 0) >= 0.80).length
    const avgMl       = alerts.length
      ? Math.round(alerts.reduce((s, a) => s + (a.ml_score ?? 0), 0) / alerts.length * 100)
      : 0

    const latestAgent = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    const lastSeen    = latestAgent ? ago(latestAgent.last_seen) : '—'
    const onlineCount = agents.filter(a => (Date.now() - parseUTC(a.last_seen)) < 60000).length

    // ML score distribution — 3 bands
    const ML_BANDS = [
      { level: 'LOW',      label: 'Benign', min: 0.00, max: 0.40 },
      { level: 'MEDIUM',   label: 'Medium', min: 0.40, max: 0.80 },
      { level: 'CRITICAL', label: 'High',   min: 0.80, max: 1.01 },
    ]
    const dist = {}
    ML_BANDS.forEach(b => dist[b.level] = 0)
    alerts.forEach(a => {
      const ml   = a.ml_score ?? 0
      const band = ML_BANDS.find(b => ml >= b.min && ml < b.max) ?? ML_BANDS[0]
      dist[band.level]++
    })
    const maxDist = Math.max(...Object.values(dist), 1)

    // Suspicious processes: ml_score >= 0.40, deduplicated by process name, highest ml wins
    const highMap = {}
    alerts.filter(a => (a.ml_score ?? 0) >= 0.40).forEach(a => {
      if (!highMap[a.process_name] || (a.ml_score ?? 0) > (highMap[a.process_name].ml_score ?? 0))
        highMap[a.process_name] = a
    })
    const highAlerts = Object.values(highMap)
      .sort((a, b) => (b.ml_score ?? 0) - (a.ml_score ?? 0))
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
          <div class="stat-label">High ML (80%+)</div>
          <div class="stat-value ${highMlCount > 0 ? 'danger' : ''}">${highMlCount}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Avg ML Score</div>
          <div class="stat-value ${avgMl >= 80 ? 'danger' : avgMl >= 40 ? 'warn' : ''}">${avgMl}%</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Last Check</div>
          <div class="stat-value" data-ts="${latestAgent?.last_seen ?? ''}" style="font-size:16px;padding-top:4px">${lastSeen}</div>
        </div>
      </div>

      <div class="split">
        <div class="panel">
          <div class="panel-header">
            Suspicious Processes
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${highAlerts.length} unique</span>
          </div>
          ${highAlerts.length ? `
            <table class="data-table">
              <thead><tr>
                <th style="width:16px"></th>
                <th>Process</th>
                <th>Parent</th>
                <th>Category</th>
                <th>ML</th>
              </tr></thead>
              <tbody>
                ${highAlerts.map(a => {
                  const ml  = Math.round((a.ml_score ?? 0) * 100)
                  const lvl = mlLevel(a.ml_score ?? 0)
                  return `
                    <tr class="row-${lvl}">
                      <td><span class="risk-dot rdot-${lvl}"></span></td>
                      <td class="proc-name">${esc(a.process_name)}</td>
                      <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
                      <td style="font-size:12px;color:var(--text-muted)">${esc(a.category || '—')}</td>
                      <td style="font-family:var(--font-mono);font-weight:700;color:${mlColor(ml)}">${ml}%</td>
                    </tr>
                  `
                }).join('')}
              </tbody>
            </table>
          ` : '<div class="empty" style="padding:32px">No suspicious processes detected</div>'}
        </div>

        <div class="panel">
          <div class="panel-header">ML Score Distribution</div>
          <div class="risk-dist">
            ${ML_BANDS.map(b => `
              <div class="risk-row">
                <span class="risk-label" title="${Math.round(b.min*100)}–${Math.round(Math.min(b.max,1)*100)}%">${b.label}</span>
                <div class="risk-bar-wrap">
                  <div class="risk-bar rbar-${b.level}" style="width:${Math.round((dist[b.level] / maxDist) * 100)}%"></div>
                </div>
                <span class="risk-count">${dist[b.level]}</span>
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
