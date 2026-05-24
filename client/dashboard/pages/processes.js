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
          <option value="risk">Risk ≥ 40%</option>
          <option value="net">With connections</option>
          <option value="unsigned">Unsigned</option>
        </select>
      </div>
    </div>
    <div class="panel" id="proc-panel">
      <table class="data-table">
        <thead><tr>
          <th style="width:16px"></th>
          <th>Process</th>
          <th>Parent</th>
          <th>PID</th>
          <th>CPU</th>
          <th>RAM</th>
          <th>Conns</th>
          <th>Risk</th>
        </tr></thead>
        <tbody id="proc-list"></tbody>
      </table>
    </div>
    <div class="pagination" id="proc-pag"></div>
  `

  function displayPage() {
    const start      = page * PAGE
    const totalPages = Math.ceil(visible.length / PAGE)

    const countEl = el.querySelector('#proc-count')
    if (countEl) countEl.textContent =
      `${visible.length} of ${procs.length}` +
      (totalPages > 1 ? ` — page ${page + 1}/${totalPages}` : '')

    const tbody = el.querySelector('#proc-list')
    if (!visible.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty">No processes found</div></td></tr>`
    } else {
      tbody.innerHTML = ''
      visible.slice(start, start + PAGE).forEach(p => {
        const ml    = p.ml_score ?? 0
        const mlPct = Math.round(ml * 100)
        const mlC   = mlColor(mlPct)
        const border = ml >= 0.80 ? '#ef4444' : ml >= 0.40 ? '#eab308' : 'transparent'

        const tr = document.createElement('tr')
        tr.className = 'clickable'
        tr.innerHTML = `
          <td><span class="risk-dot" style="background:${border === 'transparent' ? 'var(--border)' : border}"></span></td>
          <td class="proc-name">${esc(p.name)}</td>
          <td style="color:var(--text-muted)">${esc(p.parent_name || '—')}</td>
          <td class="mono">${p.pid ?? '—'}</td>
          <td class="mono">${(p.cpu_usage ?? 0).toFixed(1)}%</td>
          <td class="mono">${(p.mem_usage ?? 0).toFixed(0)} MB</td>
          <td class="mono" style="${p.connection_count > 0 ? 'color:#f97316' : ''}">${p.connection_count ?? 0}</td>
          <td style="font-family:var(--font-mono);font-weight:700;color:${mlC}">${mlPct > 0 ? mlPct + '%' : '—'}</td>
        `

        const detailTr = document.createElement('tr')
        detailTr.className = 'detail-row'
        detailTr.style.display = 'none'
        const detailTd = document.createElement('td')
        detailTd.colSpan = 8
        detailTd.style.padding = '0'
        detailTd.innerHTML = buildDetail(p)
        wireDetail(detailTd, p)
        detailTr.appendChild(detailTd)

        tr.addEventListener('click', () => {
          const isOpen = detailTr.style.display !== 'none'
          tbody.querySelectorAll('.detail-row').forEach(d => { d.style.display = 'none' })
          tbody.querySelectorAll('tr.clickable.open').forEach(r => r.classList.remove('open'))
          if (!isOpen) { detailTr.style.display = ''; tr.classList.add('open') }
        })

        tbody.appendChild(tr)
        tbody.appendChild(detailTr)
      })
    }

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
      if (mode === 'risk'     && (p.ml_score ?? 0) < 0.40) return false
      if (mode === 'net'      && !p.connection_count)       return false
      if (mode === 'unsigned' && p.is_signed)               return false
      return true
    })
    page = 0
    displayPage()
  }

  el.querySelector('#ps-search').addEventListener('input', applyFilters)
  el.querySelector('#ps-filter').addEventListener('change', applyFilters)
  displayPage()
}

function buildDetail(p) {
  const ml  = Math.round((p.ml_score ?? 0) * 100)
  const ips = Array.isArray(p.destination_ips) ? p.destination_ips : []

  const lbl = t => `<div style="font-size:10px;color:var(--text-muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:3px">${t}</div>`
  const val = t => `<div style="font-family:var(--font-mono);font-size:11px;color:var(--text-sec);word-break:break-all;line-height:1.6">${t}</div>`
  const row = (k, v) => `
    <div style="display:flex;justify-content:space-between;align-items:baseline;font-size:11px;padding:3px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text-muted);flex-shrink:0;margin-right:12px">${k}</span>
      <span style="font-family:var(--font-mono);color:var(--text-sec);text-align:right">${v}</span>
    </div>`

  return `
    <div style="border-top:1px solid var(--border);background:#080a10">
      <div style="display:grid;grid-template-columns:1fr 1fr 196px;border-bottom:1px solid var(--border)">

        <div style="padding:16px 20px;border-right:1px solid var(--border)">
          ${lbl('Path')}
          ${val(esc(p.path || p.name))}
          ${p.command_line ? `<div style="margin-top:10px">${lbl('Command Line')}${val(esc(p.command_line))}</div>` : ''}
          <div style="display:flex;gap:24px;margin-top:10px">
            ${p.parent_name ? `<div>${lbl('Parent')}${val(esc(p.parent_name))}</div>` : ''}
            <div>${lbl('PID')}${val(p.pid ?? '—')}</div>
            <div>${lbl('Signed')}${val(p.is_signed ? 'Yes' : 'No')}</div>
          </div>
        </div>

        <div style="padding:16px 20px;border-right:1px solid var(--border)">
          ${lbl('Network')}
          ${ips.length
            ? `<div style="font-size:11px;color:var(--text-sec);margin-top:4px;line-height:1.7">${ips.slice(0, 6).map(esc).join('<br>')}</div>`
            : `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">No outbound connections</div>`}
        </div>

        <div style="padding:16px 20px">
          ${lbl('Runtime')}
          <div style="margin-top:2px">
            ${row('CPU',    `${(p.cpu_usage  ?? 0).toFixed(1)}%`)}
            ${row('Memory', `${(p.mem_usage  ?? 0).toFixed(1)} MB`)}
            ${row('Conns',  `${p.connection_count ?? 0}`)}
            ${ml > 0 ? row('Risk', `${ml}%`) : ''}
            ${row('Agent',  esc((p.agent_id || '').slice(0, 16)))}
          </div>
        </div>
      </div>

      <div style="padding:8px 20px;display:flex;gap:6px">
        <button data-action="copy-path" class="det-btn">Copy Path</button>
        <button data-action="copy-name" class="det-btn">Copy Name</button>
      </div>
    </div>
  `
}

function wireDetail(td, p) {
  td.querySelector('[data-action="copy-path"]')?.addEventListener('click', () => {
    navigator.clipboard.writeText(p.path || p.name)
  })
  td.querySelector('[data-action="copy-name"]')?.addEventListener('click', () => {
    navigator.clipboard.writeText(p.name)
  })
}
