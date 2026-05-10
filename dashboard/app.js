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
window.addEventListener('load', route)

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
      el.textContent = 'No agents'
      el.className = 'conn-status'
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
setInterval(() => {
  if (parseHash() === 'dashboard') renderDashboard(content)
}, 15_000)
