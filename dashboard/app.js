import { api, ago } from './api.js'
import { render as renderDashboard }  from './pages/dashboard.js'
import { render as renderAlerts }     from './pages/alerts.js'
import { render as renderProcesses }  from './pages/processes.js'
import { render as renderTimeline }   from './pages/timeline.js'
import { render as renderMitre }      from './pages/mitre.js'
import { render as renderAgents }     from './pages/agents.js'

const content   = document.getElementById('content')
const overlay   = document.getElementById('modal-overlay')
const modalBody = document.getElementById('modal-body')
const modalTitle = document.getElementById('modal-title')
document.getElementById('modal-close').addEventListener('click', closeModal)
overlay.addEventListener('click', e => { if (e.target === overlay) closeModal() })

export function openModal(title, text) {
  modalTitle.textContent = title
  modalBody.textContent  = text
  overlay.classList.add('open')
}
export function closeModal() {
  overlay.classList.remove('open')
}

// ── Router ──────────────────────────────────────────────────
function parseHash() {
  const raw = window.location.hash.replace(/^#\/?/, '') || 'dashboard'
  const parts = raw.split('/')
  return { page: parts[0], id: parts[1] ?? null }
}

async function route() {
  const { page, id } = parseHash()

  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page)
  })

  content.innerHTML = '<div class="loading">Loading…</div>'
  try {
    switch (page) {
      case 'dashboard':  await renderDashboard(content);            break
      case 'agents':     await renderAgents(content);               break
      case 'processes':  await renderProcesses(content);            break
      case 'alerts':     await renderAlerts(content, { id });       break
      case 'timeline':   await renderTimeline(content);             break
      case 'mitre':      await renderMitre(content);                break
      default:           await renderDashboard(content);
    }
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${e.message}</div>`
    console.error(e)
  }
}

window.addEventListener('hashchange', route)
window.addEventListener('load',       route)

// ── Header updater ───────────────────────────────────────────
async function updateHeader() {
  const ok = await api.ping()
  const statusEl = document.getElementById('backend-status')
  statusEl.textContent = ok ? '● backend connected' : '● backend offline'
  statusEl.className = 'backend-status ' + (ok ? 'ok' : 'err')

  if (!ok) {
    document.getElementById('header-telemetry').textContent = 'Backend offline'
    return
  }

  try {
    const [agents, alerts] = await Promise.all([api.agents(), api.alerts({ limit: 1 })])
    const latest = agents.sort((a,b) => new Date(b.last_seen) - new Date(a.last_seen))[0]
    if (latest) {
      document.getElementById('header-agent').textContent =
        `${latest.hostname}  (${latest.username})  ` +
        `● ${(Date.now() - new Date(latest.last_seen)) < 30000 ? 'Online' : 'Offline'}`
    }
    if (alerts.length) {
      document.getElementById('header-telemetry').textContent =
        'Last telemetry: ' + ago(alerts[0].timestamp)
    }
  } catch {}
}

updateHeader()
setInterval(updateHeader, 10_000)

// Dashboard auto-refresh
setInterval(() => {
  const { page } = parseHash()
  if (page === 'dashboard') renderDashboard(content)
}, 15_000)
