import { api, fmtDate, mlColor, esc, MITRE_NAMES } from '../api.js'

const PAGE = 50

function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}

export async function render(el) {
  let page = 0

  const cfg         = await api.getSettings().catch(() => ({ alert_retain_days: 30 }))
  const retainDays  = cfg.alert_retain_days || 30
  const windowStart = new Date(Date.now() - retainDays * 864e5)

  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">
        Alerts <span class="sub" id="al-sub"></span>
      </div>
      <div class="toolbar-controls">
        <span style="font-size:12px;color:var(--text-muted)">ML ≥ 80% · last ${retainDays} days</span>
      </div>
    </div>
    <div id="al-wrap"></div>
    <div class="pagination" id="al-pag"></div>
  `

  let all = []
  try {
    all = await api.alerts({ limit: 500 })
  } catch(e) {
    el.querySelector('#al-wrap').innerHTML =
      `<div class="empty panel">Error loading alerts: ${esc(e.message)}</div>`
    return
  }

  // Filter purely by ML score — no rule-level involvement
  const filtered = all.filter(a =>
    (a.ml_score ?? 0) >= 0.80 &&
    new Date(a.timestamp) >= windowStart
  )

  function renderPage() {
    const wrap    = el.querySelector('#al-wrap')
    const start   = page * PAGE
    const slice   = filtered.slice(start, start + PAGE)
    const hasNext = start + PAGE < filtered.length

    el.querySelector('#al-sub').textContent =
      `${filtered.length} total · page ${page + 1} of ${Math.max(1, Math.ceil(filtered.length / PAGE))}`

    if (filtered.length === 0) {
      wrap.innerHTML = `<div class="panel"><div class="empty">No high-risk alerts (ML ≥ 80%) in the last ${retainDays} days</div></div>`
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
        <td class="proc-name">${esc(a.process_name)}</td>
        <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(a.category || '—')}</td>
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
    const ml      = Math.round((a.ml_score ?? 0) * 100)
    const mlC     = mlColor(ml)
    const reasons = a.reasons || []
    const mitre   = a.mitre   || []

    const reasonsHtml = reasons.length
      ? reasons.map(r => `
          <div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
            <span style="color:${mlC};font-size:15px;line-height:1;margin-top:1px">›</span>
            <span style="font-size:12px;color:var(--text-sec);line-height:1.5">${esc(r)}</span>
          </div>`).join('')
      : `<span style="font-size:12px;color:var(--text-muted)">No causes recorded</span>`

    const mitreHtml = mitre.length
      ? `<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:12px">
           ${mitre.map(t => `<span class="mitre-tag" title="${esc(MITRE_NAMES[t] || '')}">${esc(t)}</span>`).join('')}
         </div>`
      : ''

    return `
      <div style="padding:16px 20px;background:var(--card-hover);border-top:1px solid var(--border-hi)">
        <div style="display:grid;grid-template-columns:1fr 240px;gap:24px">
          <div>
            <div style="font-size:11px;color:var(--text-muted);font-weight:600;text-transform:uppercase;
                        letter-spacing:.07em;margin-bottom:8px">Detection Causes</div>
            <div>${reasonsHtml}</div>
            ${mitreHtml}
            <div style="margin-top:14px;display:flex;gap:6px;flex-wrap:wrap" id="fb-${a.id}">
              <span style="font-size:11px;color:var(--text-muted);align-self:center">Feedback:</span>
              ${fbBtn(a.id, 'true_positive',  '✓ True Positive',  '#22c55e')}
              ${fbBtn(a.id, 'false_positive', '✗ False Positive', '#ef4444')}
              ${fbBtn(a.id, 'ignore',         '— Ignore',         '#6b7280')}
              ${fbBtn(a.id, 'suspicious_ok',  '~ Acceptable',     '#eab308')}
            </div>
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-muted);font-weight:600;text-transform:uppercase;
                        letter-spacing:.07em;margin-bottom:8px">Metrics</div>
            <div style="display:flex;flex-direction:column;gap:8px">
              ${kv('ML Score',   `<span style="font-family:var(--font-mono);font-weight:700;color:${mlC}">${ml}%</span>`)}
              ${kv('Risk',       `<span style="font-family:var(--font-mono);color:${mlC}">${ml >= 80 ? 'High' : ml >= 40 ? 'Medium' : 'Low'}</span>`)}
              ${kv('Confidence', `<span style="font-family:var(--font-mono);color:var(--text-sec)">${a.confidence_label} · ${Math.round((a.confidence ?? 0) * 100)}%</span>`)}
              ${kv('PID',        `<span style="font-family:var(--font-mono);color:var(--text-muted)">${a.pid}</span>`)}
              ${kv('Agent',      `<span style="font-family:var(--font-mono);color:var(--text-muted);font-size:11px">${esc(a.agent_id)}</span>`)}
            </div>
          </div>
        </div>
      </div>
    `
  }

  function fbBtn(alertId, type, label, color) {
    return `<button onclick="window._vwFeedback(${alertId},'${type}',this)"
      style="font-size:11px;padding:3px 8px;border:1px solid ${color}33;border-radius:4px;
             background:transparent;color:${color};cursor:pointer;transition:background .15s"
      onmouseover="this.style.background='${color}22'" onmouseout="this.style.background='transparent'">
      ${label}
    </button>`
  }

  window._vwFeedback = async (alertId, type, btn) => {
    try {
      await api.submitFeedback(alertId, type)
      const row = document.getElementById(`fb-${alertId}`)
      if (row) row.innerHTML = `<span style="font-size:11px;color:#22c55e">✓ Feedback saved: ${type.replace('_',' ')}</span>`
    } catch(e) {
      btn.textContent = 'Error'
    }
  }

  function kv(label, valHtml) {
    return `<div style="display:flex;justify-content:space-between;align-items:center;font-size:12px">
      <span style="color:var(--text-muted)">${label}</span>${valHtml}
    </div>`
  }

  renderPage()
}
