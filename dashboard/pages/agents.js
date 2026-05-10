import { api, fmtDate, ago } from '../api.js'

const ONLINE_THRESHOLD_MS = 30 * 1000  // 30s

export async function render(el) {
  el.innerHTML = '<div class="loading">Loading agents…</div>'
  try {
    const [agents, alerts] = await Promise.all([
      api.agents(),
      api.alerts({ limit: 1000 }),
    ])

    el.innerHTML = `
      <div class="page-title">Agents <span class="sub">${agents.length} registered</span></div>
      ${agents.length === 0
        ? '<div class="empty">No agents have connected yet</div>'
        : `<div class="agent-grid">${agents.map(a => agentCard(a, alerts)).join('')}</div>`
      }
    `
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}

function agentCard(agent, alerts) {
  const isOnline   = (Date.now() - new Date(agent.last_seen)) < ONLINE_THRESHOLD_MS
  const myAlerts   = alerts.filter(a => a.agent_id === agent.agent_id)
  const severe     = myAlerts.filter(a => a.risk_level === 'SEVERE' || a.risk_level === 'CRITICAL')
  const maxRisk    = myAlerts.reduce((m, a) => a.risk_score > m ? a.risk_score : m, 0)
  const maxLevel   = myAlerts.sort((a,b) => b.risk_score - a.risk_score)[0]?.risk_level ?? '—'

  return `
    <div class="agent-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
        <div class="agent-name">${agent.hostname}</div>
        <span>
          <span class="status-dot ${isOnline ? 'status-online' : 'status-offline'}"></span>
          <span style="font-size:11px;color:${isOnline ? 'var(--low)' : 'var(--text-muted)'}">${isOnline ? 'Online' : 'Offline'}</span>
        </span>
      </div>
      <div class="agent-os">${agent.os}</div>
      <div class="agent-props">
        <div class="agent-prop"><span class="k">Agent ID</span><span class="v" style="font-size:11px;font-family:var(--font-mono)">${agent.agent_id}</span></div>
        <div class="agent-prop"><span class="k">IP Address</span><span class="v">${agent.ip}</span></div>
        <div class="agent-prop"><span class="k">Username</span><span class="v">${agent.username}</span></div>
        <div class="agent-prop"><span class="k">Last Seen</span><span class="v">${ago(agent.last_seen)}</span></div>
        <div class="agent-prop"><span class="k">Alerts</span><span class="v">${myAlerts.length}</span></div>
        <div class="agent-prop"><span class="k">Critical/Severe</span><span class="v" style="color:${severe.length ? 'var(--crit)' : 'var(--text)'}">${severe.length}</span></div>
        <div class="agent-prop"><span class="k">Highest Risk</span>
          <span class="v">${maxLevel !== '—' ? `<span class="badge badge-${maxLevel}">${maxLevel}</span>` : '—'}</span>
        </div>
        <div class="agent-prop"><span class="k">First Seen</span><span class="v">${fmtDate(agent.first_seen)}</span></div>
      </div>
    </div>
  `
}
