import { api, parseUTC, ago } from './api.js'
import { render as renderDashboard }  from './pages/dashboard.js'
import { render as renderProcesses }  from './pages/processes.js'
import { render as renderMitre }      from './pages/mitre.js'

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

async function route() {
  const page = parseHash()

  document.querySelectorAll('.nav-tab').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page)
  })

  content.style.opacity = '0.35'
  try {
    switch (page) {
      case 'processes': await renderProcesses(content);  break
      case 'mitre':     await renderMitre(content);      break
      default:          await renderDashboard(content);
    }
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${e.message}</div>`
    console.error(e)
  }
  content.style.opacity = '1'
}

window.addEventListener('hashchange', route)

async function waitForBackend(timeoutMs = 40_000, intervalMs = 800) {
  const deadline = Date.now() + timeoutMs
  let dots = 0
  const el = document.getElementById('content')

  while (Date.now() < deadline) {
    if (await api.ping()) return true
    dots = (dots + 1) % 4
    el.innerHTML = `<div class="startup-screen">
      <div class="startup-spinner"></div>
      <span>Starting Voidwatch${'.'.repeat(dots)}</span>
    </div>`
    await new Promise(r => setTimeout(r, intervalMs))
  }
  return false
}

window.addEventListener('load', async () => {
  const ok = await waitForBackend()
  if (!ok) {
    content.innerHTML = `<div class="empty">Backend failed to start.<br>Check that Python and dependencies are installed, then restart.</div>`
    return
  }
  route()
})

// ── Status bar ───────────────────────────────────────────────
async function updateStatus() {
  const ok = await api.ping()
  const el = document.getElementById('conn-status')

  if (!ok) {
    el.textContent = 'Backend offline'
    el.className = 'conn-status offline'
    return
  }

  try {
    const agents = await api.agents()
    if (!agents.length) {
      el.textContent = 'Waiting for agent'
      el.className = 'conn-status waiting'
      return
    }
    const latest = agents.sort((a, b) => parseUTC(b.last_seen) - parseUTC(a.last_seen))[0]
    const online = (Date.now() - parseUTC(latest.last_seen)) < 30000
    el.textContent = `${latest.hostname}  (${latest.username})  ${online ? 'Online' : 'Offline'}`
    el.className = 'conn-status ' + (online ? 'online' : 'offline')
  } catch {
    el.textContent = 'Connected'
    el.className = 'conn-status online'
  }
}

updateStatus()
setInterval(updateStatus, 10_000)

// Dashboard auto-refresh
setInterval(async () => {
  if (parseHash() !== 'dashboard') return
  try { await renderDashboard(content) } catch (e) { console.error('auto-refresh:', e) }
}, 15_000)

// Live-tick all [data-ago] timestamps every second
setInterval(() => {
  document.querySelectorAll('[data-ago]').forEach(el => {
    const ts = el.dataset.ago
    if (ts) el.textContent = ago(ts)
  })
}, 1000)
