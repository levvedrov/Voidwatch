import { api, esc, pageLoader } from '../api.js'

export async function render(el) {
  el.innerHTML = pageLoader('Loading settings…')

  let cfg = { process_retain_days: 7, alert_retain_days: 30, license: null }
  let stats = { db_size_mb: 0, db_type: '—', process_records: 0, alert_records: 0 }
  try { [cfg, stats] = await Promise.all([api.getSettings(), api.getStats()]) } catch {}
  const lic = cfg.license || { tier: 'free', display: 'Free', features: [], customer: '', expires: null }

  let elCfg = { serverUrl: 'http://0.0.0.0:8000', apiKey: '' }
  try { elCfg = await __vw.getConfig() } catch {}

  el.innerHTML = `
    <div class="page-title">Settings</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:760px">

      <div class="panel" style="grid-column:1/-1">
        <div class="panel-header">Connection</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px">
          <div class="settings-row">
            <div>
              <div style="font-size:13px;color:var(--text)">Server URL</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Voidwatch backend address</div>
            </div>
            <input id="inp-server" class="toolbar-input" type="text"
                   value="${esc(elCfg.serverUrl || '')}"
                   style="width:220px;font-family:var(--font-mono);font-size:11px" />
          </div>
          <div class="settings-row">
            <div>
              <div style="font-size:13px;color:var(--text)">API Key</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">From server .env VOIDWATCH_API_KEY</div>
            </div>
            <input id="inp-apikey" class="toolbar-input" type="password"
                   value="${esc(elCfg.apiKey || '')}"
                   style="width:220px;font-family:var(--font-mono);font-size:11px" />
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <button class="action-btn" id="btn-conn-save">Save & Reload</button>
            <span id="msg-conn" style="font-size:12px;color:var(--low);display:none">Saved — reloading…</span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">Data Retention</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:18px">
          <div class="settings-row">
            <div>
              <div style="font-size:13px;color:var(--text)">Process records</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Raw process snapshots</div>
            </div>
            <div style="display:flex;align-items:center;gap:6px">
              <input id="inp-proc" class="toolbar-input" type="number" min="1" max="365"
                     value="${cfg.process_retain_days}" style="width:64px;text-align:center" />
              <span style="font-size:12px;color:var(--text-muted)">days</span>
            </div>
          </div>
          <div class="settings-row">
            <div>
              <div style="font-size:13px;color:var(--text)">Alert records</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Scored threat alerts</div>
            </div>
            <div style="display:flex;align-items:center;gap:6px">
              <input id="inp-alert" class="toolbar-input" type="number" min="1" max="365"
                     value="${cfg.alert_retain_days}" style="width:64px;text-align:center" />
              <span style="font-size:12px;color:var(--text-muted)">days</span>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <button class="action-btn" id="btn-save">Save</button>
            <span id="msg-save" style="font-size:12px;color:var(--low);display:none">Saved</span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">License</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:10px">
          <div class="settings-stat-row">
            <span>Tier</span>
            <span style="font-family:var(--font-mono);font-size:11px;color:${lic.tier === 'free' ? 'var(--text-muted)' : '#22c55e'}">${esc(lic.display)}</span>
          </div>
          ${lic.customer ? `<div class="settings-stat-row"><span>Customer</span><span>${esc(lic.customer)}</span></div>` : ''}
          ${lic.expires  ? `<div class="settings-stat-row"><span>Expires</span><span style="font-size:11px">${esc(lic.expires.slice(0,10))}</span></div>` : ''}
          <div class="settings-stat-row">
            <span>Features</span>
            <span style="font-size:11px;color:var(--text-sec)">
              ${lic.features.length ? lic.features.join(', ') : 'rules only'}
            </span>
          </div>
          <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
            ${lic.tier !== 'free' ? `
              <button class="action-btn" id="btn-deactivate"
                style="color:#ef4444;border-color:#ef444444;background:transparent">
                Deactivate License
              </button>
              <span id="msg-deactivate" style="font-size:12px;display:none"></span>
            ` : `
              <span style="font-size:11px;color:var(--text-muted)">
                No active license. Restart the app to activate at startup.
              </span>
            `}
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">Database</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:10px">
          <div class="settings-stat-row">
            <span>Type</span>
            <span style="text-transform:uppercase;font-family:var(--font-mono);font-size:11px">${esc(stats.db_type || '—')}</span>
          </div>
          <div class="settings-stat-row">
            <span>Size</span>
            <span id="db-size">${stats.db_size_mb > 0 ? stats.db_size_mb + ' MB' : '—'}</span>
          </div>
          <div class="settings-stat-row">
            <span>Process records</span>
            <span>${stats.process_records.toLocaleString()}</span>
          </div>
          <div class="settings-stat-row">
            <span>Alert records</span>
            <span>${stats.alert_records.toLocaleString()}</span>
          </div>
          <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
            <button class="action-btn" id="btn-prune">Prune Now</button>
            <span id="msg-prune" style="font-size:12px;color:var(--text-muted);display:none"></span>
          </div>
        </div>
      </div>

    </div>
  `

  // Save connection
  el.querySelector('#btn-conn-save').addEventListener('click', async () => {
    const serverUrl = el.querySelector('#inp-server').value.trim()
    const apiKey    = el.querySelector('#inp-apikey').value.trim()
    if (!serverUrl) return
    try {
      await __vw.saveConfig({ serverUrl, apiKey })
      localStorage.setItem('voidwatch_server_url', serverUrl)
      localStorage.setItem('voidwatch_api_key',    apiKey)
      const msg = el.querySelector('#msg-conn')
      msg.style.display = 'inline'
      setTimeout(() => location.reload(), 800)
    } catch (e) {
      const msg = el.querySelector('#msg-conn')
      msg.textContent = 'Failed: ' + e.message
      msg.style.color = 'var(--crit)'
      msg.style.display = 'inline'
    }
  })

  // Save retention
  el.querySelector('#btn-save').addEventListener('click', async () => {
    const pd = parseInt(el.querySelector('#inp-proc').value)
    const ad = parseInt(el.querySelector('#inp-alert').value)
    if (!pd || !ad || pd < 1 || ad < 1) return
    try {
      await api.saveSettings({ process_retain_days: pd, alert_retain_days: ad })
      const msg = el.querySelector('#msg-save')
      msg.style.display = 'inline'
      setTimeout(() => { msg.style.display = 'none' }, 2000)
    } catch (e) {
      const msg = el.querySelector('#msg-save')
      msg.textContent = 'Failed: ' + e.message
      msg.style.color = 'var(--crit)'
      msg.style.display = 'inline'
    }
  })

  // Deactivate license
  const deactivateBtn = el.querySelector('#btn-deactivate')
  if (deactivateBtn) {
    deactivateBtn.addEventListener('click', async () => {
      if (!confirm('Deactivate license and return to Free tier?')) return
      const msg = el.querySelector('#msg-deactivate')
      try {
        await api.deactivateLicense()
        msg.style.color = 'var(--low)'
        msg.textContent = 'Deactivated'
        msg.style.display = 'inline'
        setTimeout(() => render(el), 1000)
      } catch (e) {
        msg.style.color = '#ef4444'
        msg.textContent = 'Failed: ' + e.message
        msg.style.display = 'inline'
      }
    })
  }

  // Prune now
  el.querySelector('#btn-prune').addEventListener('click', async () => {
    const btn = el.querySelector('#btn-prune')
    const msg = el.querySelector('#msg-prune')
    btn.disabled = true
    msg.style.display = 'inline'
    msg.textContent = 'Pruning…'
    try {
      const r = await api.pruneNow()
      msg.textContent = `Removed ${r.deleted_processes} process + ${r.deleted_alerts} alert rows`
      setTimeout(() => render(el), 1200)
    } catch (e) {
      msg.textContent = 'Error: ' + e.message
      btn.disabled = false
    }
  })
}
