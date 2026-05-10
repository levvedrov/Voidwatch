import { api, fmtDate } from '../api.js'

export async function render(el) {
  el.innerHTML = '<div class="loading">Loading timeline…</div>'
  try {
    const [events, agents] = await Promise.all([
      api.timeline({ limit: 200 }),
      api.agents(),
    ])

    const agentIds = [...new Set(events.map(e => e.agent_id))]

    el.innerHTML = `
      <div class="page-title">Event Timeline <span class="sub">${events.length} events</span></div>

      <div class="filters">
        <span class="filter-label">Agent:</span>
        <select id="tl-agent">
          <option value="">All agents</option>
          ${agentIds.map(id => {
            const a = agents.find(ag => ag.agent_id === id)
            return `<option value="${id}">${a ? a.hostname : id}</option>`
          }).join('')}
        </select>
      </div>

      <div class="panel">
        <div class="timeline-wrap">
          <div class="timeline-list" id="tl-list">
            ${buildTimeline(events)}
          </div>
        </div>
      </div>
    `

    el.querySelector('#tl-agent').addEventListener('change', e => {
      const agent = e.target.value
      const filtered = agent ? events.filter(ev => ev.agent_id === agent) : events
      el.querySelector('#tl-list').innerHTML = buildTimeline(filtered)
    })
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}

function buildTimeline(events) {
  if (!events.length) return '<div class="empty">No events yet</div>'
  return events.map(e => `
    <div class="tl-item p-${severityToPriority(e.risk_level)}">
      <div class="tl-time">${e.time ?? '—'}</div>
      <div class="tl-event">${e.event}</div>
      <div class="tl-process">
        ${e.process ? `<strong>${e.process}</strong>` : ''}
        ${e.risk_level ? `<span class="badge badge-${e.risk_level}" style="margin-left:6px">${e.risk_level}</span>` : ''}
        ${e.agent_id ? `<span style="color:var(--text-muted);font-size:10px;margin-left:6px">${e.agent_id}</span>` : ''}
      </div>
    </div>
  `).join('')
}

function severityToPriority(level) {
  return { SEVERE:'SEVERE', CRITICAL:'HIGH', HIGH:'HIGH', MEDIUM:'MEDIUM', LOW:'LOW' }[level] ?? 'LOW'
}
