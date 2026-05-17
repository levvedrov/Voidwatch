import { api, parseUTC, ago } from './api.js'
import { render as renderDashboard }  from './pages/dashboard.js'
import { render as renderProcesses }  from './pages/processes.js'
import { render as renderMitre }      from './pages/mitre.js'
import { render as renderAlerts }     from './pages/alerts.js'
import { render as renderSettings }   from './pages/settings.js'
import { render as renderAgents }    from './pages/agents.js'
import { render as renderAllowlist } from './pages/allowlist.js'

const content = document.getElementById('content')

// ── Window controls ──────────────────────────────────────────
document.getElementById('btn-minimize').addEventListener('click', () => __vw.minimize())
document.getElementById('btn-maximize').addEventListener('click', () => __vw.maximize())
document.getElementById('btn-close').addEventListener('click',    () => __vw.close())

// ── Router ───────────────────────────────────────────────────
function parseHash() {
  const raw = window.location.hash.replace(/^#\/?/, '') || 'dashboard'
  return raw.split('/')[0]
}

let _firstRoute = true

async function route() {
  const page = parseHash()

  document.querySelectorAll('.nav-tab').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page)
  })

  // First route after startup: content is already faded out, skip the dim so
  // the dashboard fades in cleanly from invisible rather than flickering.
  if (_firstRoute) {
    _firstRoute = false
  } else {
    content.style.opacity = '0.35'
  }

  try {
    switch (page) {
      case 'processes': await renderProcesses(content); break
      case 'mitre':     await renderMitre(content);     break
      case 'alerts':    await renderAlerts(content);    break
      case 'settings':  await renderSettings(content);  break
      case 'agents':    await renderAgents(content);    break
      case 'allowlist': await renderAllowlist(content); break
      default:          await renderDashboard(content);
    }
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${e.message}</div>`
    console.error(e)
  }
  content.style.opacity = '1'
}

window.addEventListener('hashchange', route)

// ── Startup loading screen ───────────────────────────────────
async function poll(fn, timeoutMs, intervalMs = 600) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try { if (await fn()) return true } catch {}
    await new Promise(r => setTimeout(r, intervalMs))
  }
  return false
}

function setBar(state, msg) {
  const bar    = document.getElementById('ld-bar')
  const status = document.getElementById('ld-status')
  if (bar) bar.className = 'ld-bar ' + state
  if (status && msg !== undefined) {
    status.style.opacity = '0'
    setTimeout(() => {
      const s = document.getElementById('ld-status')
      if (s) { s.textContent = msg; s.style.opacity = '1' }
    }, 150)
  }
}

async function startup() {
  // Sync server URL + API key from electron config into localStorage
  try {
    const cfg = await __vw.getConfig()
    if (cfg.serverUrl) localStorage.setItem('voidwatch_server_url', cfg.serverUrl)
    if (cfg.apiKey)    localStorage.setItem('voidwatch_api_key',    cfg.apiKey)
  } catch {}

  content.style.opacity = '1'
  content.innerHTML = `
    <div class="ld-screen">
      <div class="ld-wordmark">VOIDWATCH</div>
      <div class="ld-track"><div class="ld-bar loading" id="ld-bar"></div></div>
      <div class="ld-status" id="ld-status">Connecting to server…</div>
    </div>
  `

  const backendReady = await poll(() => api.ping(), 45_000)
  if (!backendReady) {
    setBar('fail', 'Cannot reach server — check Server URL in Settings')
    return
  }

  setBar('loading', 'Waiting for agent...')
  const agentReady = await poll(async () => {
    const agents = await api.agents()
    if (!agents.length) return false
    const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    return (Date.now() - parseUTC(latest.last_seen)) < 60_000
  }, 25_000, 10_000)

  setBar('done', agentReady ? 'Agent online' : 'No agent detected')
  await new Promise(r => setTimeout(r, 380))   // let green bar be visible
  content.style.opacity = '0'                  // fade loading screen out
  await new Promise(r => setTimeout(r, 140))   // wait for .content transition (0.12s)
  content.innerHTML = ''                        // clear; dashboard renders into empty invisible area
  route()                                       // renders, then fades to opacity 1
}

// ── Boot ─────────────────────────────────────────────────────
window.addEventListener('load', async () => {
  await startup()
  updateStatus()
  setInterval(updateStatus, 10_000)
  setInterval(() => {
    if (parseHash() === 'dashboard') renderDashboard(content)
  }, 15_000)
  setInterval(() => {
    document.querySelectorAll('[data-ts]').forEach(el => {
      if (el.dataset.ts) el.textContent = ago(el.dataset.ts)
    })
  }, 1000)

  // Keep Last Check fresh without a full dashboard re-render
  setInterval(async () => {
    if (parseHash() !== 'dashboard') return
    try {
      const agents = await api.agents()
      if (!agents.length) return
      const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
      const el = document.querySelector('[data-ts]')
      if (el && latest.last_seen) el.dataset.ts = latest.last_seen
    } catch {}
  }, 5_000)
})

// ── Status bar ───────────────────────────────────────────────
async function updateStatus() {
  const el = document.getElementById('conn-status')
  if (!el) return

  const serverOk = await api.ping()
  let agentOnline = false
  if (serverOk) {
    try {
      const agents = await api.agents()
      if (agents.length) {
        const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
        agentOnline = (Date.now() - parseUTC(latest.last_seen)) < 60_000
      }
    } catch {}
  }

  el.innerHTML = `
    <span class="sbar-item ${agentOnline ? 'online' : 'offline'}">
      <span class="sbar-dot"></span>Agent
    </span>
    <span class="sbar-sep"></span>
    <span class="sbar-item ${serverOk ? 'online' : 'offline'}">
      <span class="sbar-dot"></span>Server
    </span>
  `
}
