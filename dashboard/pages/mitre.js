import { api, MITRE_NAMES, riskColor } from '../api.js'

const LEVEL_ORDER = { SEVERE:5, CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 }

export async function render(el) {
  el.innerHTML = '<div class="loading">Loading MITRE data…</div>'
  try {
    const alerts = await api.alerts({ limit: 1000 })

    const map = {}
    alerts.forEach(a => {
      ;(a.mitre || []).forEach(tech => {
        if (!map[tech]) map[tech] = { count: 0, maxScore: 0, maxLevel: 'LOW' }
        map[tech].count++
        if (a.risk_score > map[tech].maxScore) {
          map[tech].maxScore  = a.risk_score
          map[tech].maxLevel  = a.risk_level
        }
      })
    })

    const rows = Object.entries(map)
      .sort((a, b) => (LEVEL_ORDER[b[1].maxLevel] - LEVEL_ORDER[a[1].maxLevel]) || b[1].count - a[1].count)

    el.innerHTML = `
      <div class="page-title">MITRE ATT&CK Mapping <span class="sub">${rows.length} techniques observed</span></div>

      ${rows.length === 0
        ? '<div class="empty">No MITRE data yet — run the agent to collect alerts</div>'
        : `
        <div class="panel mitre-page-table">
          <table class="data-table">
            <thead><tr>
              <th>Technique</th>
              <th>Name</th>
              <th>Alerts</th>
              <th>Max Risk Score</th>
              <th>Max Level</th>
            </tr></thead>
            <tbody>
              ${rows.map(([tech, d]) => `
                <tr class="row-${d.maxLevel}">
                  <td><span class="mitre-tag">${tech}</span></td>
                  <td style="color:var(--text)">${MITRE_NAMES[tech] ?? MITRE_NAMES[tech.split('.')[0]] ?? '—'}</td>
                  <td style="color:var(--text)">${d.count}</td>
                  <td style="color:${riskColor(d.maxLevel)};font-weight:700">${d.maxScore}</td>
                  <td><span class="badge badge-${d.maxLevel}">${d.maxLevel}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `}
    `
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}
