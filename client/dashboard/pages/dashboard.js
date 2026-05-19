import { api, ago, mlColor, parseUTC, esc } from '../api.js'

function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}


export async function render(el) {
  try {
    const [agents, procs] = await Promise.all([
      api.agents(),
      api.processes({ limit: 500 }),
    ])

    const today = new Date().toDateString()

    // Latest batch = all procs within 2 min of the most recent timestamp
    const latestBatchMs = procs.reduce((max, p) => {
      const t = parseUTC(p.timestamp).getTime()
      return t > max ? t : max
    }, 0)
    const batchProcs = latestBatchMs
      ? procs.filter(p => parseUTC(p.timestamp).getTime() >= latestBatchMs - 120_000)
      : procs

    // Active Alerts = unique high-risk process names in the latest batch
    const activeHighMap = {}
    batchProcs.forEach(p => {
      if ((p.ml_score ?? 0) < 0.80) return
      const key = (p.name || '').toLowerCase()
      if (!activeHighMap[key] || (p.ml_score ?? 0) > (activeHighMap[key].ml_score ?? 0))
        activeHighMap[key] = p
    })
    const activeHigh  = Object.values(activeHighMap)
    const alertsTotal = activeHigh.length
    const alertsToday = new Set(
      procs
        .filter(p => (p.ml_score ?? 0) >= 0.80 && new Date(p.timestamp).toDateString() === today)
        .map(p => (p.name || '').toLowerCase())
    ).size

    const topAlerts = [...activeHigh]
      .sort((a, b) => (b.ml_score ?? 0) - (a.ml_score ?? 0))
      .slice(0, 12)

    // Avg ML from all collected procs
    const avgMl = procs.length
      ? Math.round(procs.reduce((s, p) => s + (p.ml_score ?? 0), 0) / procs.length * 100)
      : 0

    const latestAgent = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    const lastSeen    = latestAgent ? ago(latestAgent.last_seen) : '—'

    // ML Distribution from latest batch — unique process names per band
    const distSeen = new Set()
    const dist = { LOW: 0, MEDIUM: 0, CRITICAL: 0 }
    batchProcs
      .slice()
      .sort((a, b) => (b.ml_score ?? 0) - (a.ml_score ?? 0))
      .forEach(p => {
        const key = (p.name || '').toLowerCase()
        if (distSeen.has(key)) return
        distSeen.add(key)
        const ml = p.ml_score ?? 0
        if      (ml >= 0.80) dist.CRITICAL++
        else if (ml >= 0.40) dist.MEDIUM++
        else                 dist.LOW++
      })
    const maxDist = Math.max(...Object.values(dist), 1)
    const ML_BANDS = [
      { level: 'CRITICAL', label: 'High',   count: dist.CRITICAL },
      { level: 'MEDIUM',   label: 'Medium',  count: dist.MEDIUM   },
      { level: 'LOW',      label: 'Benign',  count: dist.LOW      },
    ]

    el.innerHTML = `
      <div class="page-title" style="margin-bottom:20px">Dashboard <span class="sub">Overview</span></div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">Alerts Today</div>
          <div class="stat-value ${alertsToday > 0 ? 'danger' : ''}">${alertsToday}</div>
          <div class="stat-sub">ML ≥ 80%</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Active Alerts</div>
          <div class="stat-value ${alertsTotal > 0 ? 'danger' : ''}">${alertsTotal}</div>
          <div class="stat-sub">ML ≥ 80%</div>
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
            Active Alerts
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${topAlerts.length} unique · ML ≥ 80%</span>
          </div>
          ${topAlerts.length ? `
            <table class="data-table">
              <thead><tr>
                <th style="width:16px"></th>
                <th>Process</th>
                <th>Parent</th>
                <th>Agent</th>
                <th>ML</th>
              </tr></thead>
              <tbody>
                ${topAlerts.map(a => {
                  const ml = Math.round((a.ml_score ?? 0) * 100)
                  const c  = mlColor(ml)
                  return `<tr class="row-${mlLevel(a.ml_score ?? 0)}">
                    <td><span class="risk-dot" style="background:${c}"></span></td>
                    <td class="proc-name">${esc(a.name || '—')}</td>
                    <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
                    <td style="color:var(--text-muted);font-size:11px;font-family:var(--font-mono)">${esc(a.agent_id)}</td>
                    <td style="font-family:var(--font-mono);font-weight:700;color:${c}">${ml}%</td>
                  </tr>`
                }).join('')}
              </tbody>
            </table>
          ` : '<div class="empty" style="padding:32px">No alerts detected</div>'}
        </div>

        <div class="panel">
          <div class="panel-header">
            ML Score Distribution
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${batchProcs.length} processes · latest batch</span>
          </div>
          <div class="risk-dist">
            ${ML_BANDS.map(b => `
              <div class="risk-row">
                <span class="risk-label">${b.label}</span>
                <div class="risk-bar-wrap">
                  <div class="risk-bar rbar-${b.level}" style="width:${Math.round((b.count / maxDist) * 100)}%"></div>
                </div>
                <span class="risk-count">${b.count}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load dashboard: ${esc(e.message)}</div>`
  }
}
