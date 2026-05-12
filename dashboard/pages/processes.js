import { api, scoreColor, esc } from '../api.js'

const PAGE = 50

export async function render(el) {
  const [procs, alerts] = await Promise.all([
    api.processes({ limit: 1000 }),
    api.alerts({ limit: 500 }),
  ])

  const riskByPid = {}
  alerts.forEach(a => {
    if (!riskByPid[a.pid] || a.risk_score > riskByPid[a.pid].risk_score)
      riskByPid[a.pid] = a
  })
  const riskByName = {}
  alerts.forEach(a => {
    if (!riskByName[a.process_name] || a.risk_score > riskByName[a.process_name].risk_score)
      riskByName[a.process_name] = a
  })

  let visible = procs
  let page = 0

  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">
        Processes <span class="sub" id="proc-count"></span>
      </div>
      <div class="toolbar-controls">
        <input id="ps-search" class="toolbar-input" placeholder="Search…" />
        <select id="ps-filter" class="toolbar-select">
          <option value="">All</option>
          <option value="risk">Has risk only</option>
          <option value="net">With connections</option>
          <option value="unsigned">Unsigned</option>
        </select>
      </div>
    </div>
    <div class="proc-list" id="proc-list"></div>
    <div class="pagination" id="proc-pag"></div>
  `

  function displayPage() {
    const start      = page * PAGE
    const slice      = visible.slice(start, start + PAGE)
    const totalPages = Math.ceil(visible.length / PAGE)

    el.querySelector('#proc-count').textContent =
      `${visible.length} of ${procs.length}` +
      (totalPages > 1 ? ` — page ${page + 1}/${totalPages}` : '')

    el.querySelector('#proc-list').innerHTML = buildRows(slice, riskByPid, riskByName)

    const pag = el.querySelector('#proc-pag')
    if (totalPages <= 1) { pag.innerHTML = ''; return }
    pag.innerHTML = `
      <button class="pag-btn" id="pag-prev" ${page === 0 ? 'disabled' : ''}>&#8592; Prev</button>
      <span class="pag-info">Page ${page + 1} of ${totalPages}</span>
      <button class="pag-btn" id="pag-next" ${page >= totalPages - 1 ? 'disabled' : ''}>Next &#8594;</button>
    `
    pag.querySelector('#pag-prev').addEventListener('click', () => { page--; displayPage() })
    pag.querySelector('#pag-next').addEventListener('click', () => { page++; displayPage() })
  }

  function applyFilters() {
    const q    = el.querySelector('#ps-search').value.toLowerCase()
    const mode = el.querySelector('#ps-filter').value
    visible = procs
    if (q)              visible = visible.filter(p =>
      p.name.toLowerCase().includes(q) ||
      (p.parent_name || '').toLowerCase().includes(q) ||
      (p.command_line || '').toLowerCase().includes(q))
    if (mode === 'risk')     visible = visible.filter(p => riskByPid[p.pid] || riskByName[p.name])
    if (mode === 'net')      visible = visible.filter(p => p.connection_count > 0)
    if (mode === 'unsigned') visible = visible.filter(p => !p.is_signed)
    page = 0
    displayPage()
  }

  el.querySelector('#ps-search').addEventListener('input', applyFilters)
  el.querySelector('#ps-filter').addEventListener('change', applyFilters)
  displayPage()
}

function buildRows(procs, riskByPid, riskByName) {
  if (!procs.length) return '<div class="empty">No processes found</div>'

  const sorted = [...procs].sort((a, b) => {
    const sa = (riskByPid[a.pid] || riskByName[a.name])?.risk_score ?? 0
    const sb = (riskByPid[b.pid] || riskByName[b.name])?.risk_score ?? 0
    return sb - sa || a.name.localeCompare(b.name)
  })

  return sorted.map(p => {
    const alert = riskByPid[p.pid] || riskByName[p.name]
    const level = alert?.risk_level ?? ''
    const score = alert?.risk_score ?? null
    const border = level
      ? { SEVERE:'#a855f7', CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e' }[level]
      : 'transparent'
    return `
      <div class="proc-row" style="border-left:2px solid ${border}">
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
      </div>`
  }).join('')
}
