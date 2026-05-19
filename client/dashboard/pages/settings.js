import { api, esc } from '../api.js'

export async function render(el) {
  el.innerHTML = '<div class="empty">Loading…</div>'

  // Load stats but don't fail the whole page if server is unreachable
  let cfg = { process_retain_days: 7, alert_retain_days: 30, license: null }
  let stats = { db_size_mb: 0, db_type: '—', process_records: 0, alert_records: 0 }
  try { [cfg, stats] = await Promise.all([api.getSettings(), api.getStats()]) } catch {}
  const lic = cfg.license || { tier: 'free', display: 'Free', features: [], customer: '', expires: null }

  const currentUrl = localStorage.getItem('voidwatch_server_url') || 'http://localhost:8000'
  const currentKey = localStorage.getItem('voidwatch_api_key') || ''

  el.innerHTML = `
    <div class="page-title">Settings</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:760px">

      <div class="panel" style="grid-column:1/-1">
        <div class="panel-header">Server Connection</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px">
          <div style="font-size:12px;color:var(--text-muted)">
            Voidwatch backend address. The agent will also report to this server.
          </div>
          <div class="settings-row">
            <div>
              <div style="font-size:13px;color:var(--text)">Server URL</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">e.g. http://192.168.1.100:8000</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <input id="inp-server" class="toolbar-input" type="text"
                     placeholder="http://localhost:8000"
                     value="${esc(currentUrl)}"
                     style="width:260px" />
              <button class="action-btn" id="btn-test">Test</button>
              <span id="msg-test" style="font-size:12px;display:none"></span>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <button class="action-btn" id="btn-server-save">Save & Reconnect</button>
            <span id="msg-server" style="font-size:12px;color:var(--low);display:none">Saved — reload to reconnect</span>
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
        <div class="panel-header">Authentication</div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px">
          <div style="font-size:12px;color:var(--text-muted)">
            Set if <code>VOIDWATCH_API_KEY</code> is enabled on the backend.
          </div>
          <div class="settings-row">
            <div style="font-size:13px;color:var(--text)">API Key</div>
            <input id="inp-apikey" class="toolbar-input" type="password"
                   placeholder="leave blank if not set"
                   value="${esc(currentKey)}"
                   style="width:180px" />
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <button class="action-btn" id="btn-savekey">Save Key</button>
            <span id="msg-key" style="font-size:12px;color:var(--low);display:none">Saved</span>
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
                Activate a license key from Settings → Server Connection or contact your admin.
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

  // Server URL test
  el.querySelector('#btn-test').addEventListener('click', async () => {
    const url = el.querySelector('#inp-server').value.trim()
    const msg = el.querySelector('#msg-test')
    msg.textContent = 'Testing…'
    msg.style.color = 'var(--text-muted)'
    msg.style.display = 'inline'
    try {
      const result = await __vw.checkServer(url)
      if (result.ok) {
        msg.textContent = 'Connected'
        msg.style.color = 'var(--low)'
      } else {
        msg.textContent = result.error ? `Failed: ${result.error}` : 'Unreachable'
        msg.style.color = 'var(--crit)'
      }
    } catch (e) {
      msg.textContent = 'Error: ' + e.message
      msg.style.color = 'var(--crit)'
    }
  })

  // Save server URL
  el.querySelector('#btn-server-save').addEventListener('click', async () => {
    const url = el.querySelector('#inp-server').value.trim()
    if (!url) return
    localStorage.setItem('voidwatch_server_url', url)
    try { await __vw.saveConfig({ serverUrl: url }) } catch {}
    const msg = el.querySelector('#msg-server')
    msg.style.display = 'inline'
    setTimeout(() => { msg.style.display = 'none' }, 3000)
  })

  // Save API key
  el.querySelector('#btn-savekey').addEventListener('click', async () => {
    const key = el.querySelector('#inp-apikey').value.trim()
    if (key) localStorage.setItem('voidwatch_api_key', key)
    else localStorage.removeItem('voidwatch_api_key')
    try { await __vw.saveConfig({ apiKey: key }) } catch {}
    const msg = el.querySelector('#msg-key')
    msg.style.display = 'inline'
    setTimeout(() => { msg.style.display = 'none' }, 2000)
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
      alert('Save failed: ' + e.message)
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
