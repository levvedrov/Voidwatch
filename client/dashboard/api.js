function _serverUrl() {
  try { return localStorage.getItem('voidwatch_server_url') || 'https://api.voidwatch.eranoid.com' }
  catch { return 'https://api.voidwatch.eranoid.com' }
}

const _DEFAULT_KEY = '4d8313223e4f6d9965618a4e3c502f55c4a912a78264fa6e211571fab11e468b'

function _apiKey() {
  try { return localStorage.getItem('voidwatch_api_key') || _DEFAULT_KEY } catch { return _DEFAULT_KEY }
}

function _licenseKey() {
  try { return localStorage.getItem('voidwatch_license_key') || '' } catch { return '' }
}

export function myAgentId() {
  try { return localStorage.getItem('voidwatch_agent_id') || '' } catch { return '' }
}

function _headers(extra = {}) {
  const key = _apiKey()
  const lic = _licenseKey()
  const h = key ? { ...extra, 'X-API-Key': key } : { ...extra }
  if (lic) h['X-License-Key'] = lic
  return h
}

async function get(path) {
  const resp = await fetch(_serverUrl() + path, { headers: _headers() })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

async function put(path, body) {
  const resp = await fetch(_serverUrl() + path, {
    method: 'PUT',
    headers: _headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

async function post(path, body) {
  const resp = await fetch(_serverUrl() + path, {
    method: 'POST',
    headers: _headers(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

async function del(path) {
  const resp = await fetch(_serverUrl() + path, { method: 'DELETE', headers: _headers() })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

export const api = {
  get base() { return _serverUrl() },
  async ping() {
    try { const r = await fetch(_serverUrl() + '/health'); return r.ok }
    catch { return false }
  },
  alerts(params = {})         { const id = myAgentId(); if (id) params = { ...params, agent_id: id }; return get('/alerts?' + new URLSearchParams(params)) },
  alertProcesses(params = {}) { const id = myAgentId(); if (id) params = { ...params, agent_id: id }; return get('/processes/alerts?' + new URLSearchParams(params)) },
  processes(params = {})      { const id = myAgentId(); if (id) params = { ...params, agent_id: id }; return get('/processes?' + new URLSearchParams(params)) },
  agents()                    { return get('/agents') },
  timeline(params = {})     { return get('/timeline?'  + new URLSearchParams(params)) },
  getSettings()             { return get('/settings') },
  activateLicense(key)      { return post('/license/activate', { key }) },
  deactivateLicense()       { return del('/license') },
  getStats()                { return get('/settings/stats') },
  saveSettings(data)        { return put('/settings', data) },
  pruneNow()                { return post('/settings/prune') },
  submitFeedback(alertId, type, reason = '') {
    return post(`/alerts/${alertId}/feedback`, { feedback_type: type, reason })
  },
  getFeedback()             { return get('/feedback') },
  getTokens()               { return get('/agents/tokens') },
  createToken(label, expiresHours) {
    return post('/agents/tokens', { label, expires_hours: expiresHours || null })
  },
  setAgentMode(agentId, mode) {
    return put(`/agents/${agentId}/mode`, { mode })
  },
  revokeAgent(agentId) { return post(`/agents/${agentId}/revoke`) },
  getAllowlist()         { return get('/allowlist') },
  addAllowlist(kind, value, note = '') { return post('/allowlist', { kind, value, note }) },
  removeAllowlist(id)   { return del(`/allowlist/${id}`) },
  exportAlertsCSV(agentId = '') {
    const q = agentId ? '?agent_id=' + encodeURIComponent(agentId) : ''
    return _serverUrl() + '/reports/alerts.csv' + q
  },
  exportTelemetryCSV(agentId = '') {
    const q = agentId ? '?agent_id=' + encodeURIComponent(agentId) : ''
    return _serverUrl() + '/reports/telemetry.csv' + q
  },
}

export const MITRE_NAMES = {
  'T1059':     'Command and Scripting Interpreter',
  'T1059.001': 'PowerShell',
  'T1059.003': 'Windows Command Shell',
  'T1059.005': 'Visual Basic',
  'T1027':     'Obfuscated Files or Information',
  'T1027.010': 'Command Obfuscation',
  'T1105':     'Ingress Tool Transfer',
  'T1140':     'Deobfuscate / Decode Files',
  'T1218.005': 'System Binary Proxy: Mshta',
  'T1218.010': 'System Binary Proxy: Regsvr32',
  'T1218.011': 'System Binary Proxy: Rundll32',
  'T1547.001': 'Boot Autostart: Registry Run Keys',
  'T1053.005': 'Scheduled Task',
  'T1204':     'User Execution',
  'T1566':     'Phishing / Initial Access',
  'T1071':     'Application Layer Protocol',
  'T1036':     'Masquerading',
  'T1003':     'Credential Dumping',
}

export function riskColor(level) {
  return { LOW:'#22c55e', MEDIUM:'#eab308', HIGH:'#f97316', CRITICAL:'#ef4444', SEVERE:'#a855f7' }[level] ?? '#5a6478'
}

export function scoreColor(score) {
  if (score >= 120) return '#a855f7'
  if (score >= 80)  return '#ef4444'
  if (score >= 50)  return '#f97316'
  if (score >= 25)  return '#eab308'
  return '#22c55e'
}

export function mlColor(pct) {
  if (pct >= 80) return '#ef4444'
  if (pct >= 40) return '#eab308'
  return '#22c55e'
}

// Force UTC interpretation for Python naive datetime strings (no timezone suffix)
function toUTC(ts) {
  const s = String(ts)
  return new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z')
}

export function parseUTC(ts) {
  return ts ? toUTC(ts) : new Date(0)
}

export function ago(ts) {
  if (!ts) return '—'
  const diff = Math.floor((Date.now() - toUTC(ts)) / 1000)
  if (diff < 5)    return 'just now'
  if (diff < 60)   return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

export function fmt(ts) {
  if (!ts) return '—'
  return toUTC(ts).toLocaleTimeString('en-GB', { hour12: false })
}

export function fmtDate(ts) {
  if (!ts) return '—'
  const d = toUTC(ts)
  return d.toLocaleDateString('en-GB') + ' ' + d.toLocaleTimeString('en-GB', { hour12: false })
}

export function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export function pageLoader(msg = '') {
  return `<div class="ld-screen"><div class="ld-wordmark">VOIDWATCH</div><div class="ld-track"><div class="ld-bar loading"></div></div><div class="ld-status">${msg}</div></div>`
}

export function panelLoader(msg = '') {
  return `<div style="display:flex;flex-direction:column;align-items:center;gap:12px;padding:40px 24px;user-select:none"><div class="ld-track"><div class="ld-bar loading"></div></div>${msg ? `<div class="ld-status">${msg}</div>` : ''}</div>`
}
