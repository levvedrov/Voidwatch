import { api, MITRE_NAMES, scoreColor, esc, pageLoader } from '../api.js'

const LEVEL_ORDER = { SEVERE:5, CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 }

export async function render(el) {
  el.innerHTML = pageLoader('Loading threat map…')
  let alerts = []
  try {
    alerts = await api.alerts({ limit: 1000 })
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load MITRE data: ${esc(e.message)}</div>`
    return
  }

  const map = {}
    alerts.forEach(a => {
      ;(a.mitre || []).forEach(tech => {
        if (!map[tech]) map[tech] = { count: 0, maxScore: 0, maxLevel: 'LOW' }
        map[tech].count++
        if (a.risk_score > map[tech].maxScore) {
          map[tech].maxScore = a.risk_score
          map[tech].maxLevel = a.risk_level
        }
      })
    })

    const rows = Object.entries(map)
      .sort((a, b) => (LEVEL_ORDER[b[1].maxLevel] - LEVEL_ORDER[a[1].maxLevel]) || b[1].count - a[1].count)

    el.innerHTML = `
      <div class="page-title">MITRE ATT&CK <span class="sub">${rows.length} techniques observed</span></div>

      ${rows.length === 0
        ? '<div class="empty">No MITRE data yet — run the agent to collect alerts</div>'
        : `<div class="panel">
            <table class="data-table">
              <thead><tr>
                <th style="width:16px"></th>
                <th>Technique</th>
                <th>Name</th>
                <th>Alerts</th>
                <th>Max Score</th>
              </tr></thead>
              <tbody>
                ${rows.map(([tech, d]) => `
                  <tr class="row-${d.maxLevel}">
                    <td><span class="risk-dot rdot-${d.maxLevel}"></span></td>
                    <td><span class="mitre-tag">${tech}</span></td>
                    <td style="color:var(--text)">${MITRE_NAMES[tech] ?? MITRE_NAMES[tech.split('.')[0]] ?? '—'}</td>
                    <td style="color:var(--text-sec)">${d.count}</td>
                    <td style="font-weight:700;color:${scoreColor(d.maxScore)}">${d.maxScore}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>`
      }
  `
}
