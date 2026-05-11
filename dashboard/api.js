const BASE = (typeof __vw !== 'undefined') ? __vw.apiBase : 'http://localhost:8000'

async function get(path) {
  const resp = await fetch(BASE + path)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

export const api = {
  base: BASE,
  async ping() { try { const r = await fetch(BASE + '/health'); return r.ok } catch { return false } },
  alerts(params = {})    { return get('/alerts?'  + new URLSearchParams(params)) },
  processes(params = {}) { return get('/processes?' + new URLSearchParams(params)) },
  agents()               { return get('/agents') },
  timeline(params = {})  { return get('/timeline?' + new URLSearchParams(params)) },
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
  if (pct >= 60) return '#f97316'
  if (pct >= 30) return '#eab308'
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
