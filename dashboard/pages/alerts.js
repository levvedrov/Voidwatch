import { api, fmtDate, scoreColor, esc } from '../api.js'

const PAGE = 50

export async function render(el) {
  let page = 0
  const filters = { risk_level: '', min_score: 0 }

  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">
        Alerts <span class="sub" id="al-sub"></span>
      </div>
      <div class="toolbar-controls">
        <select id="al-risk" class="toolbar-select">
          <option value="">All levels</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
          <option value="SEVERE">Severe</option>
        </select>
        <input id="al-score" class="toolbar-input" type="number" min="0"
               placeholder="Min score" style="width:100px" />
      </div>
    </div>
    <div class="panel" id="al-panel"></div>
    <div class="pagination" id="al-pag"></div>
  `

  async function load() {
    const panel = el.querySelector('#al-panel')
    panel.innerHTML = '<div class="empty">Loading…</div>'

    const params = { limit: PAGE + 1, offset: page * PAGE }
    if (filters.risk_level) params.risk_level = filters.risk_level
    if (filters.min_score > 0) params.min_score = filters.min_score

    try {
      const items   = await api.alerts(params)
      const hasNext = items.length > PAGE
      const rows    = items.slice(0, PAGE)

      el.querySelector('#al-sub').textContent =
        `page ${page + 1}${hasNext ? '+' : ''}, ${rows.length} shown`

      panel.innerHTML = rows.length === 0
        ? '<div class="empty">No alerts match the current filter</div>'
        : `<table class="data-table">
            <thead><tr>
              <th style="width:16px"></th>
              <th>Time</th>
              <th>Process</th>
              <th>Parent</th>
              <th>Category</th>
              <th>Score</th>
              <th>ML</th>
              <th>Reasons</th>
            </tr></thead>
            <tbody>
              ${rows.map(a => {
                const ml      = Math.round(a.ml_score * 100)
                const reasons = (a.reasons || []).slice(0, 2).join('; ')
                return `
                  <tr class="row-${a.risk_level}">
                    <td><span class="risk-dot rdot-${a.risk_level}"></span></td>
                    <td class="mono">${fmtDate(a.timestamp)}</td>
                    <td class="proc-name">${esc(a.process_name)}</td>
                    <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
                    <td style="font-size:12px;color:var(--text-muted)">${esc(a.category || '—')}</td>
                    <td style="font-weight:700;color:${scoreColor(a.risk_score)}">${a.risk_score}</td>
                    <td style="font-family:var(--font-mono);font-size:12px">${ml}%</td>
                    <td style="font-size:11px;color:var(--text-muted);max-width:220px;
                               overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                        title="${esc((a.reasons || []).join('; '))}">${esc(reasons)}</td>
                  </tr>`
              }).join('')}
            </tbody>
           </table>`

      const pag = el.querySelector('#al-pag')
      pag.innerHTML = `
        <button class="pag-btn" id="pag-prev" ${page === 0 ? 'disabled' : ''}>&#8592; Prev</button>
        <span class="pag-info">Page ${page + 1}</span>
        <button class="pag-btn" id="pag-next" ${!hasNext ? 'disabled' : ''}>Next &#8594;</button>
      `
      pag.querySelector('#pag-prev').addEventListener('click', () => { page--; load() })
      pag.querySelector('#pag-next').addEventListener('click', () => { page++; load() })
    } catch (e) {
      panel.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`
    }
  }

  el.querySelector('#al-risk').addEventListener('change', e => {
    filters.risk_level = e.target.value; page = 0; load()
  })
  el.querySelector('#al-score').addEventListener('input', e => {
    filters.min_score = parseInt(e.target.value) || 0; page = 0; load()
  })

  load()
}
