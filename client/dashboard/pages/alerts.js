import { api, fmtDate, mlColor, esc, MITRE_NAMES } from '../api.js'

const PAGE = 50

function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}

export async function render(el) {
  let page = 0

  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">
        Alerts <span class="sub" id="al-sub"></span>
      </div>
      <div class="toolbar-controls">
        <span style="font-size:12px;color:var(--text-muted)">ML ≥ 80% · all time</span>
      </div>
    </div>
    <div id="al-wrap"></div>
    <div class="pagination" id="al-pag"></div>
  `

  let filtered = []
  try {
    filtered = await api.alertProcesses()
  } catch(e) {
    el.querySelector('#al-wrap').innerHTML =
      `<div class="empty panel">Error loading alerts: ${esc(e.message)}</div>`
    return
  }

  function renderPage() {
    const wrap    = el.querySelector('#al-wrap')
    const start   = page * PAGE
    const slice   = filtered.slice(start, start + PAGE)
    const hasNext = start + PAGE < filtered.length

    el.querySelector('#al-sub').textContent =
      `${filtered.length} total · page ${page + 1} of ${Math.max(1, Math.ceil(filtered.length / PAGE))}`

    if (filtered.length === 0) {
      wrap.innerHTML = `<div class="panel"><div class="empty">No high-risk alerts (ML ≥ 80%)</div></div>`
      el.querySelector('#al-pag').innerHTML = ''
      return
    }

    const panel = document.createElement('div')
    panel.className = 'panel'

    const table = document.createElement('table')
    table.className = 'data-table'
    table.innerHTML = `<thead><tr>
      <th style="width:16px"></th>
      <th>Time</th>
      <th>Process</th>
      <th>Parent</th>
      <th>Category</th>
      <th>ML</th>
    </tr></thead>`

    const tbody = document.createElement('tbody')

    slice.forEach(a => {
      const ml   = Math.round((a.ml_score ?? 0) * 100)
      const mlC  = mlColor(ml)
      const lvl  = mlLevel(a.ml_score ?? 0)

      const tr = document.createElement('tr')
      tr.className = `row-${lvl} clickable`
      tr.innerHTML = `
        <td><span class="risk-dot" style="background:${mlC}"></span></td>
        <td class="mono">${fmtDate(a.timestamp)}</td>
        <td class="proc-name">${esc(a.name)}</td>
        <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(a.path || '—')}</td>
        <td style="font-family:var(--font-mono);font-weight:700;color:${mlC}">${ml}%</td>
      `

      const detailTr = document.createElement('tr')
      detailTr.className = 'detail-row'
      detailTr.style.display = 'none'
      detailTr.innerHTML = `<td colspan="6" style="padding:0">${buildDetail(a)}</td>`

      tr.addEventListener('click', () => {
        const isOpen = detailTr.style.display !== 'none'
        tbody.querySelectorAll('.detail-row').forEach(d => { d.style.display = 'none' })
        tbody.querySelectorAll('tr.clickable.open').forEach(r => r.classList.remove('open'))
        if (!isOpen) {
          detailTr.style.display = ''
          tr.classList.add('open')
        }
      })

      tbody.appendChild(tr)
      tbody.appendChild(detailTr)
    })

    table.appendChild(tbody)
    panel.appendChild(table)
    wrap.innerHTML = ''
    wrap.appendChild(panel)

    const pag = el.querySelector('#al-pag')
    pag.innerHTML = `
      <button class="pag-btn" id="pag-prev" ${page === 0 ? 'disabled' : ''}>&#8592; Prev</button>
      <span class="pag-info">Page ${page + 1} of ${Math.max(1, Math.ceil(filtered.length / PAGE))}</span>
      <button class="pag-btn" id="pag-next" ${!hasNext ? 'disabled' : ''}>Next &#8594;</button>
    `
    pag.querySelector('#pag-prev').addEventListener('click', () => { page--; renderPage() })
    pag.querySelector('#pag-next').addEventListener('click', () => { page++; renderPage() })
  }

  function buildDetail(a) {
    const ml  = Math.round((a.ml_score ?? 0) * 100)
    const mlC = mlColor(ml)
    return `
      <div style="padding:16px 20px;background:var(--card-hover);border-top:1px solid var(--border-hi)">
        <div style="display:grid;grid-template-columns:1fr 240px;gap:24px">
          <div>
            <div style="font-size:11px;color:var(--text-muted);font-weight:600;text-transform:uppercase;
                        letter-spacing:.07em;margin-bottom:8px">Process Info</div>
            <div style="display:flex;flex-direction:column;gap:6px">
              ${kv('Path',    `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-sec)">${esc(a.path || '—')}</span>`)}
              ${kv('Cmd',     `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-sec)">${esc(a.command_line || '—')}</span>`)}
              ${kv('Parent',  `<span style="font-family:var(--font-mono);color:var(--text-muted)">${esc(a.parent_name || '—')}</span>`)}
              ${kv('Signed',  `<span style="font-family:var(--font-mono);color:${a.is_signed ? '#22c55e' : '#ef4444'}">${a.is_signed ? 'Yes' : 'No'}</span>`)}
            </div>
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-muted);font-weight:600;text-transform:uppercase;
                        letter-spacing:.07em;margin-bottom:8px">Metrics</div>
            <div style="display:flex;flex-direction:column;gap:8px">
              ${kv('ML Score',  `<span style="font-family:var(--font-mono);font-weight:700;color:${mlC}">${ml}%</span>`)}
              ${kv('CPU',       `<span style="font-family:var(--font-mono);color:var(--text-sec)">${(a.cpu_usage ?? 0).toFixed(1)}%</span>`)}
              ${kv('Memory',    `<span style="font-family:var(--font-mono);color:var(--text-sec)">${(a.mem_usage ?? 0).toFixed(1)} MB</span>`)}
              ${kv('PID',       `<span style="font-family:var(--font-mono);color:var(--text-muted)">${a.pid}</span>`)}
              ${kv('Agent',     `<span style="font-family:var(--font-mono);color:var(--text-muted);font-size:11px">${esc(a.agent_id)}</span>`)}
              ${kv('Net Conns', `<span style="font-family:var(--font-mono);color:var(--text-muted)">${a.connection_count ?? 0}</span>`)}
            </div>
          </div>
        </div>
      </div>
    `
  }

  function kv(label, valHtml) {
    return `<div style="display:flex;justify-content:space-between;align-items:center;font-size:12px">
      <span style="color:var(--text-muted)">${label}</span>${valHtml}
    </div>`
  }

  renderPage()
}
