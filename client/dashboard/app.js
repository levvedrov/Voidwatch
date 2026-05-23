import { api, parseUTC, ago } from './api.js'
import { render as renderDashboard }  from './pages/dashboard.js'
import { render as renderProcesses }  from './pages/processes.js'
import { render as renderMitre }      from './pages/mitre.js'
import { render as renderAlerts }     from './pages/alerts.js'
import { render as renderSettings }   from './pages/settings.js'

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

  setBar('loading', 'Waiting for agent…')
  await poll(async () => {
    const agents = await api.agents()
    if (!agents.length) return false
    const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    return (Date.now() - parseUTC(latest.last_seen)) < 60_000
  }, 25_000, 10_000)

  // Wait for the agent to have submitted at least one process batch
  setBar('loading', 'Collecting telemetry…')
  await poll(async () => {
    const procs = await api.processes({ limit: 1 })
    return procs.length > 0
  }, 20_000, 2_000)

  // Pre-render the dashboard while the loading screen is still visible
  setBar('loading', 'Analysing threat intelligence…')
  const scratch = document.createElement('div')
  try { await renderDashboard(scratch) } catch {}

  setBar('done', '')
  await new Promise(r => setTimeout(r, 300))
  content.style.opacity = '0'
  await new Promise(r => setTimeout(r, 150))
  content.innerHTML = scratch.innerHTML
  _firstRoute = false
  document.querySelectorAll('.nav-tab').forEach(el =>
    el.classList.toggle('active', el.dataset.page === 'dashboard')
  )
  document.body.classList.remove('app-loading')
  content.style.opacity = '1'
}

function showLicenseScreen() {
  const wait = ms => new Promise(r => setTimeout(r, ms))

  return new Promise(resolve => {
    content.innerHTML = `
      <div id="lic-screen" style="
        position:relative;height:100%;
        display:flex;flex-direction:column;align-items:center;justify-content:center;
        transition:background 1s ease;
        background:
          radial-gradient(ellipse 60% 50% at 50% 40%, rgba(255,255,255,.025) 0%, transparent 70%),
          repeating-linear-gradient(0deg, transparent, transparent 39px, var(--border) 39px, var(--border) 40px),
          repeating-linear-gradient(90deg, transparent, transparent 39px, var(--border) 39px, var(--border) 40px);
      ">
        <div style="position:absolute;inset:0;pointer-events:none;
          background:radial-gradient(ellipse 80% 80% at 50% 50%, transparent 30%, var(--bg) 100%)"></div>

        <div style="position:relative;width:360px;display:flex;flex-direction:column;align-items:center">

          <!-- branding (stays visible through loading) -->
          <div id="lic-brand" style="text-align:center;margin-bottom:44px;transition:margin .6s ease">
            <div style="font-size:9px;font-weight:700;letter-spacing:.45em;color:var(--text-muted);text-transform:uppercase;margin-bottom:16px">by Eranoid</div>
            <div style="font-size:32px;font-weight:700;letter-spacing:.12em;color:var(--text);text-transform:uppercase;line-height:1;margin-bottom:10px">VOIDWATCH</div>
            <div id="lic-tier-badge" style="
              min-height:18px;margin-bottom:14px;
              font-size:13px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;
              color:var(--text-muted);font-family:var(--font-mono);
              opacity:0;transform:translateY(-18px) scale(0.85);
              transition:opacity .45s ease,transform .8s cubic-bezier(0.34,1.56,0.64,1);
            "></div>
            <div id="lic-divider" style="width:32px;height:1px;background:var(--border-hi);margin:0 auto 16px;transition:opacity .4s ease"></div>
            <div id="lic-welcome" style="font-size:11px;color:var(--text-muted);letter-spacing:.08em;text-transform:uppercase;transition:opacity .4s ease">Welcome to demo testing</div>
          </div>

          <!-- form -->
          <div id="lic-form" style="width:100%;display:flex;flex-direction:column;gap:10px;transition:opacity .4s ease">
            <textarea id="lic-input" rows="3" placeholder="Paste license key"
              style="width:100%;padding:11px 14px;background:rgba(255,255,255,.03);
                     border:1px solid var(--border);border-radius:6px;color:var(--text);
                     font-family:var(--font-mono);font-size:11px;resize:none;line-height:1.6;
                     box-sizing:border-box;outline:none;transition:border-color .15s"
              onfocus="this.style.borderColor='var(--border-hi)'"
              onblur="this.style.borderColor='var(--border)'"></textarea>
            <div id="lic-err" style="font-size:11px;min-height:14px;letter-spacing:.03em;text-align:center"></div>
            <button id="lic-activate"
              style="width:100%;padding:11px 0;background:var(--text);color:var(--bg);
                     border:none;border-radius:6px;font-size:11px;font-weight:700;
                     letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:opacity .15s">
              Activate License
            </button>
            <button id="lic-skip"
              style="width:100%;padding:9px 0;background:transparent;color:var(--text-muted);
                     border:none;font-size:11px;letter-spacing:.04em;cursor:pointer;transition:color .15s"
              onmouseover="this.style.color='var(--text-sec)'"
              onmouseout="this.style.color='var(--text-muted)'">
              Continue without license
            </button>
          </div>

          <!-- tier note -->
          <div id="lic-note" style="margin-top:28px;font-size:11px;color:var(--text-muted);letter-spacing:.02em;text-align:center;transition:opacity .4s ease">
            Don't have a license? Visit <span style="color:var(--text-sec)">eranoid.com</span>
          </div>

          <!-- loading bar (hidden until activation animation) -->
          <div id="lic-loading" style="opacity:0;transform:translateY(14px);transition:opacity .5s ease,transform .6s cubic-bezier(0.25,0.46,0.45,0.94);margin-top:32px;width:180px;display:flex;flex-direction:column;align-items:center;gap:14px">
            <div class="ld-track"><div class="ld-bar loading" id="ld-bar"></div></div>
            <div class="ld-status" id="ld-status" style="letter-spacing:.06em;text-transform:uppercase"></div>
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
      if (!key) { err.style.color = 'var(--text-muted)'; err.textContent = 'Paste a license key first.'; return }
      btn.textContent = 'Activating...'
      btn.style.opacity = '.6'
      btn.disabled = true
      try {
        const lic = await api.activateLicense(key)
        const tier = (lic.display || lic.tier || 'pro').toUpperCase()
        const isPaid = !['free'].includes((lic.tier || '').toLowerCase())

        if (isPaid) {
          // ── Activation animation sequence ──────────────────
          const form    = content.querySelector('#lic-form')
          const note    = content.querySelector('#lic-note')
          const welcome = content.querySelector('#lic-welcome')
          const divEl   = content.querySelector('#lic-divider')
          const badge   = content.querySelector('#lic-tier-badge')
          const loading = content.querySelector('#lic-loading')
          const brand   = content.querySelector('#lic-brand')
          const screen  = content.querySelector('#lic-screen')

          // Step 1: fade form first
          form.style.opacity = '0'; form.style.pointerEvents = 'none'
          await wait(80)
          // then stagger note / welcome / divider
          ;[note, welcome, divEl].forEach(el => { el.style.opacity = '0'; el.style.pointerEvents = 'none' })
          await wait(420)
          ;[form, note, divEl].forEach(el => { el.style.display = 'none' })
          welcome.style.display = 'none'

          // Step 2: dissolve grid background
          screen.style.background = 'var(--bg)'

          // Step 3: spring-drop the tier badge and shift branding up simultaneously
          const tierColors = { beta: '#22c55e', pro: '#d4a843', enterprise: '#a855f7' }
          badge.textContent = tier
          badge.style.color = tierColors[(lic.tier || '').toLowerCase()] || 'var(--text-sec)'
          await wait(30) // allow paint
          badge.style.opacity = '1'
          badge.style.transform = 'translateY(0) scale(1)'
          brand.style.marginBottom = '24px'
          await wait(850)

          // Step 4: slide loading bar up into view
          loading.style.opacity = '1'
          loading.style.transform = 'translateY(0)'
          await wait(450)

          resolve()
        } else {
          // free tier — just proceed
          content.style.opacity = '0'
          setTimeout(resolve, 140)
        }
      } catch (e) {
        err.style.color = 'var(--crit)'
        err.textContent = e.message || 'Invalid license key'
        btn.textContent = 'Activate License'
        btn.style.opacity = '1'
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
  setInterval(async () => {
    if (parseHash() !== 'dashboard') return
    const scratch = document.createElement('div')
    try {
      await renderDashboard(scratch)
      content.innerHTML = scratch.innerHTML
    } catch {}
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
