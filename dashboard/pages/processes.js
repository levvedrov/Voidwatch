import { api, scoreColor } from '../api.js'

export async function render(el) {
  try {
    const [procs, alerts] = await Promise.all([
      api.processes({ limit: 1000 }),
      api.alerts({ limit: 2000 }),
    ])

    // Build risk map: pid → highest alert for that pid
    const riskByPid = {}
    alerts.forEach(a => {
      if (!riskByPid[a.pid] || a.risk_score > riskByPid[a.pid].risk_score)
        riskByPid[a.pid] = a
    })

    // Also map by name for processes without a pid match
    const riskByName = {}
    alerts.forEach(a => {
      if (!riskByName[a.process_name] || a.risk_score > riskByName[a.process_name].risk_score)
        riskByName[a.process_name] = a
    })

    let visible = procs

    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <div class="page-title" style="margin-bottom:0">
          Processes <span class="sub" id="proc-count">${procs.length} running</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="ps-search" placeholder="Search…"
            style="background:#111;border:1px solid #1e1e1e;border-radius:5px;padding:5px 10px;color:#f1f5f9;font-size:13px;outline:none;width:200px" />
          <select id="ps-filter"
            style="background:#111;border:1px solid #1e1e1e;border-radius:5px;padding:5px 10px;color:#94a3b8;font-size:13px;outline:none">
            <option value="">All</option>
            <option value="risk">Has risk only</option>
            <option value="net">With connections</option>
            <option value="unsigned">Unsigned</option>
          </select>
        </div>
      </div>

      <div class="proc-list" id="proc-list">
        ${buildRows(procs, riskByPid, riskByName)}
      </div>
    `

    function applyFilters() {
      const q    = el.querySelector('#ps-search').value.toLowerCase()
      const mode = el.querySelector('#ps-filter').value

      visible = procs
      if (q)              visible = visible.filter(p =>
        p.name.toLowerCase().includes(q) ||
        (p.parent_name || '').toLowerCase().includes(q) ||
        (p.command_line || '').toLowerCase().includes(q)
      )
      if (mode === 'risk')     visible = visible.filter(p => riskByPid[p.pid] || riskByName[p.name])
      if (mode === 'net')      visible = visible.filter(p => p.connection_count > 0)
      if (mode === 'unsigned') visible = visible.filter(p => !p.is_signed)

      el.querySelector('#proc-count').textContent = `${visible.length} of ${procs.length}`
      el.querySelector('#proc-list').innerHTML = buildRows(visible, riskByPid, riskByName)
    }

    el.querySelector('#ps-search').addEventListener('input', applyFilters)
    el.querySelector('#ps-filter').addEventListener('change', applyFilters)

  } catch(e) {
    el.innerHTML = `<div class="empty">Failed to load processes: ${e.message}</div>`
  }
}

function buildRows(procs, riskByPid, riskByName) {
  if (!procs.length) return '<div class="empty">No processes found</div>'

  // Sort: risky processes first, then by name
  const sorted = [...procs].sort((a, b) => {
    const ra = riskByPid[a.pid] || riskByName[a.name]
    const rb = riskByPid[b.pid] || riskByName[b.name]
    const sa = ra?.risk_score ?? 0
    const sb = rb?.risk_score ?? 0
    return sb - sa || a.name.localeCompare(b.name)
  })

  return sorted.map(p => {
    const alert = riskByPid[p.pid] || riskByName[p.name]
    const level = alert?.risk_level ?? ''
    const score = alert?.risk_score ?? null

    const leftBorder = level
      ? { SEVERE:'#a855f7', CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e' }[level]
      : 'transparent'

    return `
      <div class="proc-row" style="border-left:2px solid ${leftBorder}">
        <div class="proc-main">
          <span class="proc-name">${esc(p.name)}</span>
          <span class="proc-parent">${esc(p.parent_name || '—')}</span>
        </div>
        <div class="proc-meta">
          <span class="proc-pid">${p.pid}</span>
          <span class="proc-stat">CPU ${p.cpu_usage ?? 0}%</span>
          <span class="proc-stat">RAM ${p.mem_usage ?? 0} MB</span>
          ${p.connection_count > 0
            ? `<span class="proc-stat" style="color:#f97316">${p.connection_count} conn</span>`
            : ''}
          ${!p.is_signed
            ? `<span class="proc-stat" style="color:#ef4444">unsigned</span>`
            : ''}
          ${score !== null
            ? `<span class="proc-score" style="color:${scoreColor(score)}">${score}</span>`
            : ''}
        </div>
      </div>
    `
  }).join('')
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}
