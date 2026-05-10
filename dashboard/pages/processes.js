import { api, fmtDate, riskColor } from '../api.js'
import { openModal } from '../app.js'

export async function render(el) {
  el.innerHTML = '<div class="loading">Loading processes…</div>'
  try {
    const [procs, alerts] = await Promise.all([
      api.processes({ limit: 500 }),
      api.alerts({ limit: 1000 }),
    ])

    // Build risk map: process_name → highest alert
    const riskMap = {}
    alerts.forEach(a => {
      const key = a.process_name
      if (!riskMap[key] || a.risk_score > riskMap[key].risk_score) riskMap[key] = a
    })

    const agentIds = [...new Set(procs.map(p => p.agent_id))]

    el.innerHTML = `
      <div class="page-title">Processes <span class="sub">${procs.length} collected</span></div>

      <div class="filters" id="proc-filters">
        <span class="filter-label">Filter:</span>
        <input id="fp-search" placeholder="Search process…" style="width:160px" />
        <select id="fp-agent">
          <option value="">All agents</option>
          ${agentIds.map(id => `<option value="${id}">${id}</option>`).join('')}
        </select>
        <select id="fp-risk">
          <option value="">All risks</option>
          <option>LOW</option><option>MEDIUM</option><option>HIGH</option>
          <option>CRITICAL</option><option>SEVERE</option>
        </select>
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--text-sec);cursor:pointer">
          <input type="checkbox" id="fp-unsigned" /> Unsigned only
        </label>
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--text-sec);cursor:pointer">
          <input type="checkbox" id="fp-network" /> With network
        </label>
        <button class="btn" id="fp-apply">Apply</button>
        <button class="btn btn-danger" id="fp-reset">Reset</button>
      </div>

      <div class="panel">
        <div id="proc-table-wrap" style="overflow-x:auto">
          ${buildTable(procs, riskMap)}
        </div>
      </div>
    `

    function applyFilters() {
      const search   = el.querySelector('#fp-search').value.toLowerCase()
      const agent    = el.querySelector('#fp-agent').value
      const risk     = el.querySelector('#fp-risk').value
      const unsigned = el.querySelector('#fp-unsigned').checked
      const network  = el.querySelector('#fp-network').checked

      let filtered = procs
      if (search)   filtered = filtered.filter(p =>
        p.name.toLowerCase().includes(search) ||
        (p.command_line || '').toLowerCase().includes(search)
      )
      if (agent)    filtered = filtered.filter(p => p.agent_id === agent)
      if (risk)     filtered = filtered.filter(p => riskMap[p.name]?.risk_level === risk)
      if (unsigned) filtered = filtered.filter(p => !p.is_signed)
      if (network)  filtered = filtered.filter(p => p.connection_count > 0)

      el.querySelector('#proc-table-wrap').innerHTML = buildTable(filtered, riskMap)
      bindCmdClick()
    }

    el.querySelector('#fp-apply').addEventListener('click', applyFilters)
    el.querySelector('#fp-reset').addEventListener('click', () => {
      el.querySelectorAll('#proc-filters input[type=text], #proc-filters select').forEach(i => i.value = '')
      el.querySelectorAll('#proc-filters input[type=checkbox]').forEach(i => i.checked = false)
      el.querySelector('#proc-table-wrap').innerHTML = buildTable(procs, riskMap)
      bindCmdClick()
    })
    bindCmdClick()

    function bindCmdClick() {
      el.querySelectorAll('.cmd-cell').forEach(cell => {
        cell.addEventListener('click', () => {
          openModal('Command Line', cell.dataset.full)
        })
      })
    }
  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load: ${e.message}</div>`
  }
}

function buildTable(procs, riskMap) {
  if (!procs.length) return '<div class="empty">No processes</div>'
  return `
    <table class="data-table">
      <thead><tr>
        <th>Process</th><th>PID</th><th>Parent</th>
        <th>Command Line</th><th>CPU%</th><th>RAM MB</th>
        <th>Signed</th><th>Conns</th><th>Risk</th><th>ML%</th>
      </tr></thead>
      <tbody>
        ${procs.map(p => {
          const alert = riskMap[p.name]
          const level = alert?.risk_level ?? ''
          const score = alert?.risk_score ?? ''
          const ml    = alert ? Math.round(alert.ml_score * 100) : ''
          return `
            <tr class="${level ? 'row-' + level : ''}">
              <td class="process-name">${p.name}</td>
              <td style="font-family:var(--font-mono);font-size:11px">${p.pid}</td>
              <td style="color:var(--text-muted)">${p.parent_name || '—'}</td>
              <td class="monospace cmd-cell clickable"
                  data-full="${escHtml(p.command_line || '')}"
                  title="Click to expand">
                ${escHtml((p.command_line || '').slice(0, 60))}${p.command_line?.length > 60 ? '…' : ''}
              </td>
              <td>${p.cpu_usage ?? '—'}</td>
              <td>${p.mem_usage ?? '—'}</td>
              <td>${p.is_signed
                ? '<span style="color:var(--low)">✓</span>'
                : '<span style="color:var(--crit)">✗</span>'}</td>
              <td style="${p.connection_count > 0 ? 'color:var(--high)' : ''}">${p.connection_count}</td>
              <td>${level ? `<span class="badge badge-${level}">${level}</span>` : '—'}</td>
              <td style="${ml >= 80 ? 'color:var(--crit)' : ''}">${ml !== '' ? ml + '%' : '—'}</td>
            </tr>
          `
        }).join('')}
      </tbody>
    </table>
  `
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
}
