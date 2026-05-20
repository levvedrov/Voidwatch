import { api, fmtDate, mlColor, esc, parseUTC, panelLoader } from '../api.js'

const PAGE = 50

function mlLevel(ml) {
  if (ml >= 0.80) return 'CRITICAL'
  if (ml >= 0.40) return 'MEDIUM'
  return 'LOW'
}

// ── Timeline chart ────────────────────────────────────────────
function bucketByMinute(alerts) {
  const map = {}
  alerts.forEach(a => {
    const t   = parseUTC(a.timestamp).getTime()
    const key = Math.floor(t / 60_000) * 60_000
    if (!map[key]) map[key] = {}
    const ml = a.ml_score ?? 0
    if (!map[key][a.name] || ml > map[key][a.name].ml_score) map[key][a.name] = a
  })
  return Object.entries(map)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([ts, byName]) => ({ ts: Number(ts), items: Object.values(byName) }))
}

function drawChart(canvas, buckets) {
  const dpr     = window.devicePixelRatio || 1
  const W       = canvas.offsetWidth
  const H       = 180
  canvas.width  = W * dpr
  canvas.height = H * dpr
  const ctx = canvas.getContext('2d')
  ctx.scale(dpr, dpr)

  const PAD     = { top: 24, right: 20, bottom: 32, left: 38 }
  const cW      = W - PAD.left - PAD.right
  const cH      = H - PAD.top  - PAD.bottom
  const n       = buckets.length
  const dataMax = Math.max(...buckets.map(b => b.items.length), 1)
  const yMax    = dataMax + 1

  const base = PAD.top + cH
  const xOf  = i => PAD.left + (n < 2 ? cW / 2 : (i / (n - 1)) * cW)
  const yOf  = v => PAD.top  + cH - (v / yMax) * cH

  // Baseline
  ctx.strokeStyle = 'rgba(255,255,255,0.06)'
  ctx.lineWidth   = 1
  ctx.beginPath(); ctx.moveTo(PAD.left, base); ctx.lineTo(W - PAD.right, base); ctx.stroke()

  // Grid lines + Y labels
  ctx.font      = '9px Consolas, monospace'
  ctx.textAlign = 'right'
  const ticks = [...new Set([1, 2, 3, 4].map(i => Math.round(dataMax * i / 4)))]
  ticks.forEach(val => {
    const yy = yOf(val)
    ctx.strokeStyle = 'rgba(255,255,255,0.04)'
    ctx.lineWidth   = 1
    ctx.setLineDash([3, 5])
    ctx.beginPath(); ctx.moveTo(PAD.left, yy); ctx.lineTo(W - PAD.right, yy); ctx.stroke()
    ctx.setLineDash([])
    ctx.fillStyle = 'rgba(255,255,255,0.22)'
    ctx.fillText(val, PAD.left - 6, yy + 3)
  })

  if (n >= 2) {
    // Catmull-Rom spline: control points derived with the standard 1/6 factor
    // guarantees C1 continuity (smooth tangent at every knot, no overshoot)
    const pts = buckets.map((b, i) => [xOf(i), yOf(b.items.length)])
    function catmullCP(p0, p1, p2, p3) {
      return {
        cp1: [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6],
        cp2: [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6],
      }
    }

    function drawSpline(close) {
      for (let i = 0; i < pts.length - 1; i++) {
        const { cp1, cp2 } = catmullCP(
          pts[Math.max(0, i - 1)],
          pts[i],
          pts[i + 1],
          pts[Math.min(pts.length - 1, i + 2)],
        )
        ctx.bezierCurveTo(cp1[0], cp1[1], cp2[0], cp2[1], pts[i + 1][0], pts[i + 1][1])
      }
    }

    // Area fill
    const areaGrad = ctx.createLinearGradient(0, PAD.top, 0, base)
    areaGrad.addColorStop(0,   'rgba(255,255,255,0.10)')
    areaGrad.addColorStop(0.6, 'rgba(255,255,255,0.03)')
    areaGrad.addColorStop(1,   'rgba(255,255,255,0.00)')
    ctx.fillStyle = areaGrad
    ctx.beginPath()
    ctx.moveTo(pts[0][0], base)
    ctx.lineTo(pts[0][0], pts[0][1])
    drawSpline()
    ctx.lineTo(pts[pts.length - 1][0], base)
    ctx.closePath()
    ctx.fill()

    // Line
    ctx.strokeStyle = 'rgba(255,255,255,0.85)'
    ctx.lineWidth   = 1.5
    ctx.lineJoin    = 'round'
    ctx.lineCap     = 'round'
    ctx.beginPath()
    ctx.moveTo(pts[0][0], pts[0][1])
    drawSpline()
    ctx.stroke()
  }

  // Dots with glow
  buckets.forEach((b, i) => {
    const x = xOf(i), y = yOf(b.items.length)
    ctx.shadowColor = 'rgba(255,255,255,0.35)'
    ctx.shadowBlur  = 8
    ctx.beginPath()
    ctx.arc(x, y, 4, 0, Math.PI * 2)
    ctx.fillStyle = '#ffffff'
    ctx.fill()
    ctx.shadowBlur  = 0
    ctx.shadowColor = 'transparent'
    ctx.strokeStyle = 'rgba(255,255,255,0.2)'
    ctx.lineWidth   = 1.5
    ctx.stroke()
  })

  // X-axis time labels
  const step = Math.max(1, Math.ceil(n / 8))
  ctx.fillStyle = 'rgba(255,255,255,0.22)'
  ctx.font      = '9px Consolas, monospace'
  ctx.textAlign = 'center'
  buckets.forEach((b, i) => {
    if (i % step !== 0 && i !== n - 1) return
    const d   = new Date(b.ts)
    const lbl = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
    ctx.fillText(lbl, xOf(i), H - 8)
  })

  return { xOf, PAD }
}

function wireTimeline(el, initialBuckets) {
  const canvas  = el.querySelector('#tl-canvas')
  const tooltip = el.querySelector('#tl-tooltip')
  if (!canvas) return null

  let buckets = initialBuckets
  let pos     = buckets.length > 0 ? drawChart(canvas, buckets) : null

  function update(newBuckets) {
    buckets = newBuckets
    if (buckets.length > 0) pos = drawChart(canvas, buckets)
  }

  const onResize = () => { if (pos && buckets.length > 0) pos = drawChart(canvas, buckets) }
  window.addEventListener('resize', onResize)

  canvas.addEventListener('mousemove', e => {
    if (!pos || !buckets.length) return
    const rect = canvas.getBoundingClientRect()
    const mx   = e.clientX - rect.left
    const n    = buckets.length

    let best = -1, bestDist = Infinity
    buckets.forEach((b, i) => {
      const d = Math.abs(pos.xOf(i) - mx)
      if (d < bestDist && d < (canvas.offsetWidth / n) * 0.75) {
        bestDist = d; best = i
      }
    })

    if (best === -1) { tooltip.style.display = 'none'; return }

    const b    = buckets[best]
    const d    = new Date(b.ts)
    const time = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`

    tooltip.innerHTML = `
      <div style="font-weight:700;color:var(--text);margin-bottom:8px;font-size:12px">
        ${time}
        <span style="font-weight:400;color:var(--text-muted);margin-left:6px">${b.items.length} process${b.items.length !== 1 ? 'es' : ''}</span>
      </div>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;font-size:10px;color:var(--text-muted);padding:0 8px 4px 0;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Process</th>
          <th style="text-align:right;font-size:10px;color:var(--text-muted);padding:0 0 4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Risk</th>
        </tr></thead>
        <tbody>
          ${[...b.items].sort((x, y) => (y.ml_score ?? 0) - (x.ml_score ?? 0)).map(a => {
            const score = Math.round((a.ml_score ?? 0) * 100)
            const col   = score >= 80 ? '#ef4444' : score >= 40 ? '#eab308' : '#22c55e'
            return `<tr>
              <td style="padding:3px 8px 3px 0;font-size:11px;color:var(--text-sec);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.name || '—')}</td>
              <td style="text-align:right;font-family:Consolas,monospace;font-size:11px;font-weight:700;color:${col};white-space:nowrap">${score}%</td>
            </tr>`
          }).join('')}
        </tbody>
      </table>
    `

    const tw = 260
    let tx = e.clientX + 18
    let ty = e.clientY - (tooltip.offsetHeight || 80) / 2
    if (tx + tw > window.innerWidth  - 8) tx = e.clientX - tw - 18
    if (ty < 8) ty = 8
    if (ty + (tooltip.offsetHeight || 80) > window.innerHeight - 8)
      ty = window.innerHeight - (tooltip.offsetHeight || 80) - 8
    tooltip.style.left    = `${tx}px`
    tooltip.style.top     = `${ty}px`
    tooltip.style.display = 'block'
  })

  canvas.addEventListener('mouseleave', () => { tooltip.style.display = 'none' })

  return { update }
}

// ── Main render ───────────────────────────────────────────────
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

    <div class="panel" style="margin-bottom:16px" id="tl-panel">
      <div class="panel-header">
        Alert Timeline
        <span style="display:flex;align-items:center;gap:8px">
          <span style="font-size:11px;font-weight:400;color:var(--text-muted)" id="tl-sub">loading…</span>
          <span id="tl-live" style="display:none;align-items:center;gap:4px;font-size:10px;font-weight:600;color:#22c55e;letter-spacing:.05em;text-transform:uppercase">
            <span style="width:6px;height:6px;border-radius:50%;background:#22c55e;display:inline-block;animation:pulse-dot 1.4s ease-in-out infinite"></span>
            Live
          </span>
        </span>
      </div>
      <div style="padding:12px 16px 10px;position:relative">
        <canvas id="tl-canvas" style="display:block;width:100%;height:180px;cursor:crosshair"></canvas>
        <div id="tl-tooltip" style="
          display:none;position:fixed;z-index:300;
          background:var(--card);border:1px solid var(--border-hi);border-radius:7px;
          padding:10px 14px;min-width:200px;max-width:280px;
          box-shadow:0 8px 28px rgba(0,0,0,.55);pointer-events:none;
        "></div>
      </div>
    </div>

    <div id="al-wrap"><div class="panel">${panelLoader('Loading alerts…')}</div></div>
    <div class="pagination" id="al-pag"></div>
  `

  let filtered = [], rawAlerts = []
  try {
    ;[filtered, rawAlerts] = await Promise.all([
      api.alertProcesses(),
      api.alertProcesses({ raw: true }),
    ])
  } catch(e) {
    el.querySelector('#al-wrap').innerHTML =
      `<div class="empty panel">Error loading alerts: ${esc(e.message)}</div>`
    return
  }

  // Timeline — initial draw + live polling
  const tlSub  = el.querySelector('#tl-sub')
  const tlLive = el.querySelector('#tl-live')

  function applyTimelineData(records) {
    const cutoff  = Date.now() - 20 * 60_000
    const recent  = records.filter(r => parseUTC(r.timestamp).getTime() >= cutoff)
    const buckets = bucketByMinute(recent)
    tlSub.textContent = recent.length
      ? `${recent.length} events · last 20 min`
      : 'no data'
    return buckets
  }

  const initBuckets = applyTimelineData(rawAlerts)
  let tl = null

  if (initBuckets.length === 0) {
    el.querySelector('#tl-panel').style.display = 'none'
  } else {
    requestAnimationFrame(() => {
      tl = wireTimeline(el, initBuckets)
      tlLive.style.display = 'flex'
    })
  }

  const pollInterval = setInterval(async () => {
    if (!el.isConnected) { clearInterval(pollInterval); return }
    try {
      const fresh   = await api.alertProcesses({ raw: true })
      const buckets = applyTimelineData(fresh)
      if (buckets.length === 0) return
      const panel = el.querySelector('#tl-panel')
      if (panel && panel.style.display === 'none') panel.style.display = ''
      if (!tl) {
        requestAnimationFrame(() => { tl = wireTimeline(el, buckets); tlLive.style.display = 'flex' })
      } else {
        tl.update(buckets)
      }
    } catch {}
  }, 15_000)

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
      <th>Path</th>
      <th>ML</th>
    </tr></thead>`

    const tbody = document.createElement('tbody')

    slice.forEach(a => {
      const ml  = Math.round((a.ml_score ?? 0) * 100)
      const mlC = mlColor(ml)
      const lvl = mlLevel(a.ml_score ?? 0)

      const tr = document.createElement('tr')
      tr.className = `row-${lvl} clickable`
      tr.innerHTML = `
        <td><span class="risk-dot" style="background:${mlC}"></span></td>
        <td class="mono">${fmtDate(a.timestamp)}</td>
        <td class="proc-name">${esc(a.name)}</td>
        <td style="color:var(--text-muted)">${esc(a.parent_name || '—')}</td>
        <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.path || '—')}</td>
        <td style="font-family:var(--font-mono);font-weight:700;color:${mlC}">${ml}%</td>
      `

      const detailTr = document.createElement('tr')
      detailTr.className = 'detail-row'
      detailTr.style.display = 'none'
      const detailTd = document.createElement('td')
      detailTd.colSpan = 6
      detailTd.style.padding = '0'
      detailTd.innerHTML = buildDetail(a)
      wireDetail(detailTd, a)
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
    const ips = Array.isArray(a.destination_ips) ? a.destination_ips : []

    const flags = []
    flags.push(`ML score ${ml}% exceeds 80% detection threshold`)
    if (!a.is_signed)                  flags.push('Binary is not code-signed')
    if ((a.connection_count ?? 0) > 0) flags.push(`${a.connection_count} outbound network connection${a.connection_count !== 1 ? 's' : ''}`)
    if (ips.length)                    flags.push(`Remote endpoints: ${ips.slice(0, 4).map(esc).join(', ')}${ips.length > 4 ? ` +${ips.length - 4} more` : ''}`)
    if ((a.cpu_usage  ?? 0) > 40)      flags.push(`CPU usage: ${a.cpu_usage.toFixed(1)}%`)
    if ((a.mem_usage  ?? 0) > 500)     flags.push(`Memory: ${a.mem_usage.toFixed(0)} MB`)

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
            ${val(esc(a.path || a.name))}
            ${a.command_line ? `<div style="margin-top:10px">${lbl('Command Line')}${val(esc(a.command_line))}</div>` : ''}
            <div style="display:flex;gap:24px;margin-top:10px">
              ${a.parent_name ? `<div>${lbl('Parent')}${val(esc(a.parent_name))}</div>` : ''}
              <div>${lbl('PID')}${val(a.pid)}</div>
              <div>${lbl('Signed')}${val(a.is_signed ? 'Yes' : 'No')}</div>
            </div>
          </div>

          <div style="padding:16px 20px;border-right:1px solid var(--border)">
            ${lbl('Detection Indicators')}
            <div style="display:flex;flex-direction:column;gap:0;margin-top:2px">
              ${flags.map(f => `
                <div style="display:flex;gap:8px;align-items:baseline;padding:4px 0;border-bottom:1px solid var(--border)">
                  <span style="font-size:8px;color:var(--crit);flex-shrink:0;line-height:1.8">&#9679;</span>
                  <span style="font-size:11px;color:var(--crit)">${f}</span>
                </div>`).join('')}
            </div>
          </div>

          <div style="padding:16px 20px">
            ${lbl('Runtime')}
            <div style="margin-top:2px">
              ${row('CPU',    `${(a.cpu_usage  ?? 0).toFixed(1)}%`)}
              ${row('Memory', `${(a.mem_usage  ?? 0).toFixed(1)} MB`)}
              ${row('Conns',  `${a.connection_count ?? 0}`)}
              ${row('Agent',  esc((a.agent_id || '').slice(0, 16)))}
            </div>
          </div>
        </div>

        <div style="padding:8px 20px;display:flex;gap:6px">
          <button data-action="copy-path"  class="det-btn">Copy Path</button>
          <button data-action="copy-name"  class="det-btn">Copy Name</button>
          <button data-action="allowlist"  class="det-btn">Add to Allowlist</button>
        </div>
      </div>
    `
  }

  function wireDetail(td, a) {
    td.querySelector('[data-action="copy-path"]')?.addEventListener('click', () => {
      navigator.clipboard.writeText(a.path || a.name)
    })
    td.querySelector('[data-action="copy-name"]')?.addEventListener('click', () => {
      navigator.clipboard.writeText(a.name)
    })
    td.querySelector('[data-action="allowlist"]')?.addEventListener('click', async e => {
      const btn = e.currentTarget
      btn.textContent = 'Adding…'
      btn.disabled = true
      try {
        await api.addAllowlist({ kind: 'process', value: a.name, note: 'Flagged from Alerts' })
        btn.textContent = '✓ Added'
        btn.style.color = '#22c55e'
      } catch {
        btn.textContent = 'Failed'
        btn.style.color = '#ef4444'
        btn.disabled = false
      }
    })
  }

  renderPage()
}
