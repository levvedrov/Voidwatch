import { api, mlColor, esc, pageLoader } from '../api.js'

const PAGE = 50

export async function render(el) {
  el.innerHTML = pageLoader('Loading processes…')
  const raw = await api.processes({ limit: 1000 })

  // Deduplicate by name — keep highest ML score per unique process name
  const seen = {}
  raw.forEach(p => {
    const key = (p.name || '').toLowerCase()
    if (!seen[key] || (p.ml_score ?? 0) > (seen[key].ml_score ?? 0))
      seen[key] = p
  })
  const procs = Object.values(seen)

  // Sort highest ML first, then alphabetically
  procs.sort((a, b) => (b.ml_score ?? 0) - (a.ml_score ?? 0) || a.name.localeCompare(b.name))

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
          <option value="risk">ML ≥ 40%</option>
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
    const totalPages = Math.ceil(visible.length / PAGE)

    el.querySelector('#proc-count').textContent =
      `${visible.length} of ${procs.length}` +
      (totalPages > 1 ? ` — page ${page + 1}/${totalPages}` : '')

    el.querySelector('#proc-list').innerHTML = buildRows(visible.slice(start, start + PAGE))

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
    visible = procs.filter(p => {
      if (q && !(
        p.name.toLowerCase().includes(q) ||
        (p.parent_name  || '').toLowerCase().includes(q) ||
        (p.command_line || '').toLowerCase().includes(q)
      )) return false
      if (mode === 'risk'    && (p.ml_score ?? 0) < 0.40) return false
      if (mode === 'net'     && !p.connection_count)       return false
      if (mode === 'unsigned' && p.is_signed)              return false
      return true
    })
    page = 0
    displayPage()
  }

  el.querySelector('#ps-search').addEventListener('input', applyFilters)
  el.querySelector('#ps-filter').addEventListener('change', applyFilters)
  displayPage()
}

function buildRows(procs) {
  if (!procs.length) return '<div class="empty">No processes found</div>'
  return procs.map(p => {
    const ml     = p.ml_score ?? 0
    const mlPct  = Math.round(ml * 100)
    const border = ml >= 0.80 ? '#ef4444' : ml >= 0.40 ? '#eab308' : 'transparent'
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
          ${mlPct > 0
            ? `<span class="proc-score" style="color:${mlColor(mlPct)}">${mlPct}%</span>`
            : ''}
        </div>
      </div>`
  }).join('')
}
