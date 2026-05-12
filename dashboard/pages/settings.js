import { api, esc } from '../api.js'

export async function render(el) {
  el.innerHTML = '<div class="empty">Loading…</div>'

  try {
    const [cfg, stats] = await Promise.all([api.getSettings(), api.getStats()])

    el.innerHTML = `
      <div class="page-title">Settings</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:760px">

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
          <div class="panel-header">Database</div>
          <div style="padding:20px;display:flex;flex-direction:column;gap:10px">
            <div class="settings-stat-row">
              <span>Size</span>
              <span id="db-size">${stats.db_size_mb} MB</span>
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
  } catch (e) {
    el.innerHTML = `<div class="empty">Failed to load settings: ${esc(e.message)}</div>`
  }
}
