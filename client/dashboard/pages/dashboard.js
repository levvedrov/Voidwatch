import { api, ago, mlColor, parseUTC, esc } from '../api.js'

function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}


export async function render(el) {
  try {
    const [alerts, agents, procs] = await Promise.all([
      api.alerts({ limit: 500 }),
      api.agents(),
      api.processes({ limit: 500 }),
    ])

    const today = new Date().toDateString()

    // All ML stats from procs so they're consistent with ML Distribution
    const highProcsAll = procs.filter(p => (p.ml_score ?? 0) >= 0.80)
    const highToday    = highProcsAll.filter(p => new Date(p.timestamp).toDateString() === today).length
    const highTotal    = highProcsAll.length
    const avgMl        = procs.length
      ? Math.round(procs.reduce((s, p) => s + (p.ml_score ?? 0), 0) / procs.length * 100)
      : 0

    const latestAgent = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    const lastSeen    = latestAgent ? ago(latestAgent.last_seen) : '—'

    // ML Distribution
    const dist = { LOW: 0, MEDIUM: 0, CRITICAL: 0 }
    procs.forEach(p => {
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

    // Active high-risk: deduplicate by process name, keep highest ml_score per name
    const highMap = {}
    highProcsAll.forEach(p => {
      const key = (p.name || '').toLowerCase()
      if (!highMap[key] || (p.ml_score ?? 0) > (highMap[key].ml_score ?? 0))
        highMap[key] = p
    })
    const highProcs = Object.values(highMap)
      .sort((a, b) => (b.ml_score ?? 0) - (a.ml_score ?? 0))
      .slice(0, 12)

    el.innerHTML = `
      <div class="page-title" style="margin-bottom:20px">Dashboard <span class="sub">Overview</span></div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">High Risk Today</div>
          <div class="stat-value ${highToday > 0 ? 'danger' : ''}">${highToday}</div>
          <div class="stat-sub">ML ≥ 80%</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">High Risk Total</div>
          <div class="stat-value ${highTotal > 0 ? 'danger' : ''}">${highTotal}</div>
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
            Active High-Risk Processes
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${highProcs.length} detected · ML ≥ 80%</span>
          </div>
          ${highProcs.length ? `
            <table class="data-table">
              <thead><tr>
                <th style="width:16px"></th>
                <th>Process</th>
                <th>Parent</th>
                <th>Agent</th>
                <th>ML</th>
              </tr></thead>
              <tbody>
                ${highProcs.map(p => {
                  const ml = Math.round((p.ml_score ?? 0) * 100)
                  const c  = mlColor(ml)
                  return `<tr class="row-${mlLevel(p.ml_score ?? 0)}">
                    <td><span class="risk-dot" style="background:${c}"></span></td>
                    <td class="proc-name">${esc(p.name || '—')}</td>
                    <td style="color:var(--text-muted)">${esc(p.parent_name || '—')}</td>
                    <td style="color:var(--text-muted);font-size:11px;font-family:var(--font-mono)">${esc(p.agent_id)}</td>
                    <td style="font-family:var(--font-mono);font-weight:700;color:${c}">${ml}%</td>
                  </tr>`
                }).join('')}
              </tbody>
            </table>
          ` : '<div class="empty" style="padding:32px">No high-risk processes detected</div>'}
        </div>

        <div class="panel">
          <div class="panel-header">
            ML Score Distribution
            <span style="font-size:11px;font-weight:400;color:var(--text-muted)">${procs.length} processes</span>
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
