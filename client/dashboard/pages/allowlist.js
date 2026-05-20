import { api, fmtDate, esc, panelLoader } from '../api.js'

const KIND_LABELS = {
  process_name: 'Process Name',
  hash:         'SHA-256 Hash',
  cmdline:      'Command Line',
}

export async function render(el) {
  el.innerHTML = `
    <div class="toolbar">
      <div class="page-title" style="margin-bottom:0">Allowlist</div>
      <div class="toolbar-controls">
        <button class="btn-sm" id="al-add-btn">+ Add Entry</button>
      </div>
    </div>
    <div class="panel" style="margin-bottom:12px;padding:12px 16px;font-size:12px;color:var(--text-muted)">
      Allowlisted processes are skipped by the scoring engine — no alerts will be generated for them.
      Use this to suppress false positives from known-good internal tools.
    </div>
    <div id="al-list" class="panel">${panelLoader()}</div>
    <div id="al-modal" style="display:none"></div>
  `

  el.querySelector('#al-add-btn').addEventListener('click', () => showAddModal(el))
  await loadAllowlist(el)
}

async function loadAllowlist(el) {
  const wrap = el.querySelector('#al-list')
  let entries = []
  try { entries = await api.getAllowlist() } catch(e) {
    wrap.innerHTML = `<div class="empty">Error loading allowlist: ${esc(e.message)}</div>`
    return
  }

  if (!entries.length) {
    wrap.innerHTML = `<div class="empty">No entries. Add process names, hashes, or command-line patterns to suppress false positives.</div>`
    return
  }

  const table = document.createElement('table')
  table.className = 'data-table'
  table.innerHTML = `<thead><tr>
    <th>Kind</th><th>Value</th><th>Note</th><th>Added</th><th></th>
  </tr></thead>`
  const tbody = document.createElement('tbody')
  for (const e of entries) {
    const tr = document.createElement('tr')
    tr.innerHTML = `
      <td style="font-size:11px;color:var(--text-muted)">${esc(KIND_LABELS[e.kind] || e.kind)}</td>
      <td class="mono" style="font-size:11px">${esc(e.value)}</td>
      <td style="font-size:12px;color:var(--text-muted)">${esc(e.note || '—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtDate(e.created_at)}</td>
      <td>
        <button class="btn-danger-sm" data-del="${e.id}" title="Remove">Remove</button>
      </td>
    `
    tbody.appendChild(tr)
  }
  table.appendChild(tbody)
  wrap.innerHTML = ''
  wrap.appendChild(table)

  wrap.querySelectorAll('[data-del]').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('Remove this allowlist entry?')) return
      try {
        await api.removeAllowlist(parseInt(btn.dataset.del))
        btn.closest('tr').remove()
        if (!tbody.children.length) {
          wrap.innerHTML = `<div class="empty">No entries.</div>`
        }
      } catch(e) {
        alert('Failed: ' + e.message)
      }
    })
  })
}

function showAddModal(el) {
  const modal = el.querySelector('#al-modal')
  modal.style.display = 'block'
  modal.innerHTML = `
    <div style="position:fixed;inset:0;background:#0008;z-index:100;display:flex;align-items:center;justify-content:center">
      <div class="panel" style="width:400px;padding:24px;display:flex;flex-direction:column;gap:14px">
        <div style="font-size:15px;font-weight:600">Add Allowlist Entry</div>
        <div>
          <label style="font-size:12px;color:var(--text-muted)">Kind</label>
          <select id="al-kind"
            style="width:100%;margin-top:4px;padding:6px 8px;background:var(--input-bg,#1a1a2e);
                   border:1px solid var(--border);border-radius:4px;color:inherit;font-size:13px">
            <option value="process_name">Process Name (e.g. myapp.exe)</option>
            <option value="hash">SHA-256 Hash</option>
            <option value="cmdline">Command Line (substring match)</option>
          </select>
        </div>
        <div>
          <label style="font-size:12px;color:var(--text-muted)">Value</label>
          <input id="al-value" type="text" placeholder="e.g. backup.exe"
            style="width:100%;margin-top:4px;padding:6px 8px;background:var(--input-bg,#1a1a2e);
                   border:1px solid var(--border);border-radius:4px;color:inherit;font-size:13px">
        </div>
        <div>
          <label style="font-size:12px;color:var(--text-muted)">Note (optional)</label>
          <input id="al-note" type="text" placeholder="Internal monitoring agent"
            style="width:100%;margin-top:4px;padding:6px 8px;background:var(--input-bg,#1a1a2e);
                   border:1px solid var(--border);border-radius:4px;color:inherit;font-size:13px">
        </div>
        <div id="al-err" style="font-size:12px;color:#ef4444;min-height:16px"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button id="al-cancel" class="btn-sm">Cancel</button>
          <button id="al-save" class="btn-sm" style="background:#22c55e22;color:#22c55e;border-color:#22c55e44">Add</button>
        </div>
      </div>
    </div>
  `
  modal.querySelector('#al-cancel').addEventListener('click', () => { modal.style.display = 'none' })
  modal.querySelector('#al-save').addEventListener('click', async () => {
    const kind  = modal.querySelector('#al-kind').value
    const value = modal.querySelector('#al-value').value.trim()
    const note  = modal.querySelector('#al-note').value.trim()
    const errEl = modal.querySelector('#al-err')

    if (!value) { errEl.textContent = 'Value is required.'; return }

    try {
      await api.addAllowlist(kind, value, note)
      modal.style.display = 'none'
      await loadAllowlist(el)
    } catch(e) {
      errEl.textContent = 'Error: ' + e.message
    }
  })
}
