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

  // Check license — show activation screen if Free tier
  try {
    const cfg = await api.getSettings()
    if (cfg.license?.tier === 'free') {
      setBar('done', '')
      await showLicenseScreen()
    }
  } catch {}

  setBar('loading', 'Waiting for agent...')
  const agentReady = await poll(async () => {
    const agents = await api.agents()
    if (!agents.length) return false
    const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    return (Date.now() - parseUTC(latest.last_seen)) < 60_000
  }, 25_000, 10_000)

  setBar('done', agentReady ? 'Agent online' : 'No agent detected')
  await new Promise(r => setTimeout(r, 380))
  content.style.opacity = '0'
  await new Promise(r => setTimeout(r, 140))
  content.innerHTML = ''
  route()
}

function showLicenseScreen() {
  return new Promise(resolve => {
    content.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:400px">
        <div style="width:480px;display:flex;flex-direction:column;gap:20px">
          <div>
            <div style="font-size:22px;font-weight:700;letter-spacing:.04em">VOIDWATCH</div>
            <div style="font-size:13px;color:var(--text-muted);margin-top:4px">Activate your license to unlock all features</div>
          </div>
          <textarea id="lic-input" rows="5" placeholder="Paste your license key here…"
            style="width:100%;padding:10px 12px;background:#0d0d1a;border:1px solid var(--border);
                   border-radius:6px;color:inherit;font-family:var(--font-mono);font-size:11px;
                   resize:none;line-height:1.5;box-sizing:border-box"></textarea>
          <div id="lic-err" style="font-size:12px;color:#ef4444;min-height:16px"></div>
          <div style="display:flex;gap:10px">
            <button id="lic-activate"
              style="flex:1;padding:10px;background:#22c55e22;color:#22c55e;
                     border:1px solid #22c55e44;border-radius:5px;font-size:13px;cursor:pointer">
              Activate
            </button>
            <button id="lic-skip"
              style="padding:10px 20px;background:transparent;color:var(--text-muted);
                     border:1px solid var(--border);border-radius:5px;font-size:13px;cursor:pointer">
              Skip — use Free tier
            </button>
          </div>
          <div style="font-size:11px;color:var(--text-muted);line-height:1.6">
            Free tier: rule-based detection only, 7-day retention.<br>
            Pro / Enterprise: ML scoring, CSV export, feedback, allowlist, longer retention.
          </div>
        </div>
      </div>
    `
    content.style.opacity = '1'

    content.querySelector('#lic-skip').addEventListener('click', () => {
      content.style.opacity = '0'
      setTimeout(resolve, 140)
    })

    content.querySelector('#lic-activate').addEventListener('click', async () => {
      const key = content.querySelector('#lic-input').value.trim()
      const err = content.querySelector('#lic-err')
      const btn = content.querySelector('#lic-activate')
      if (!key) { err.textContent = 'Please paste your license key.'; return }
      btn.textContent = 'Activating…'
      btn.disabled = true
      try {
        const lic = await api.activateLicense(key)
        err.style.color = '#22c55e'
        err.textContent = `✓ Activated — ${lic.display} tier${lic.customer ? ' · ' + lic.customer : ''}`
        setTimeout(() => { content.style.opacity = '0'; setTimeout(resolve, 140) }, 1200)
      } catch (e) {
        err.style.color = '#ef4444'
        err.textContent = e.message || 'Invalid key'
        btn.textContent = 'Activate'
        btn.disabled = false
      }
    })
  })
}

// ── Tier badge ───────────────────────────────────────────────
async function updateTierBadge() {
  const el = document.getElementById('tier-badge')
  if (!el) return
  try {
    const cfg  = await api.getSettings()
    const tier = cfg.license?.tier || 'free'
    el.className = `tier-badge tier-${tier}`
    el.textContent = tier
  } catch {
    el.className = 'tier-badge tier-free'
    el.textContent = ''
  }
}

// ── Boot ─────────────────────────────────────────────────────
window.addEventListener('load', async () => {
  await startup()
  updateStatus()
  updateTierBadge()
  setInterval(updateStatus, 10_000)
  setInterval(updateTierBadge, 30_000)
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
