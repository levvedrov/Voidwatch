const { app, BrowserWindow, ipcMain } = require('electron')
const path   = require('path')
const http   = require('http')
const https  = require('https')
const fs     = require('fs')
const { spawn, execFileSync } = require('child_process')

const ROOT        = app.isPackaged
  ? path.dirname(process.execPath)
  : path.join(__dirname, '..')
function getConfigPath() {
  return path.join(app.getPath('userData'), 'voidwatch-config.json')
}

let win, agentProc
let _stopping          = false
let _agentRestartDelay = 3000

// ── Config persistence ────────────────────────────────────
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(getConfigPath(), 'utf8')) }
  catch { return { serverUrl: 'https://api.voidwatch.eranoid.com', apiKey: '4d8313223e4f6d9965618a4e3c502f55c4a912a78264fa6e211571fab11e468b' } }
}

function saveConfig(data) {
  const cfg = { ...loadConfig(), ...data }
  fs.writeFileSync(getConfigPath(), JSON.stringify(cfg, null, 2))
  return cfg
}

// ── IPC handlers ──────────────────────────────────────────
ipcMain.handle('config:get',  ()      => loadConfig())
ipcMain.handle('config:set',  (_, d)  => saveConfig(d))
ipcMain.handle('config:check-server', async (_, url) => {
  return new Promise(resolve => {
    const mod = (url || '').startsWith('https') ? https : http
    try {
      mod.get(url + '/health', { timeout: 5000 }, res => {
        let body = ''
        res.on('data', d => body += d)
        res.on('end', () => {
          try { resolve({ ok: res.statusCode === 200, data: JSON.parse(body) }) }
          catch { resolve({ ok: res.statusCode === 200 }) }
        })
      }).on('error', err => resolve({ ok: false, error: err.message }))
    } catch (err) {
      resolve({ ok: false, error: err.message })
    }
  })
})

const AGENT_EXE    = path.join(ROOT, 'agent', 'voidwatch_agent.exe')
const AUTOSTART_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
const AUTOSTART_NAME = 'VoidwatchAgent'

// ── Autostart (Windows registry HKCU\Run) ────────────────
function setupAutostart() {
  if (!fs.existsSync(AGENT_EXE)) return
  try {
    execFileSync('reg', [
      'add', AUTOSTART_KEY,
      '/v', AUTOSTART_NAME,
      '/t', 'REG_SZ',
      '/d', `"${AGENT_EXE}"`,
      '/f',
    ], { windowsHide: true, stdio: 'pipe' })
    console.log('[main] Autostart registered')
  } catch (e) {
    console.error('[main] Autostart registration failed:', e.message)
  }
}

// ── Check if agent process is already running ─────────────
function isAgentRunning() {
  try {
    const out = execFileSync(
      'tasklist',
      ['/FI', 'IMAGENAME eq voidwatch_agent.exe', '/NH'],
      { windowsHide: true, stdio: 'pipe', encoding: 'utf8', timeout: 5000 }
    )
    return out.toLowerCase().includes('voidwatch_agent.exe')
  } catch {
    return false
  }
}

// ── Process management ────────────────────────────────────
function killProc(proc) {
  if (!proc) return
  try { spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true }) }
  catch { proc.kill() }
}

function spawnAgent(serverUrl, apiKey) {
  if (!fs.existsSync(AGENT_EXE)) {
    console.error('[main] voidwatch_agent.exe not found — run compile.bat inside client/agent/')
    return null
  }
  const env = {
    ...process.env,
    VOIDWATCH_SERVER_URL: serverUrl || 'https://api.voidwatch.eranoid.com',
    VOIDWATCH_API_KEY:    apiKey    || '',
  }
  const proc = spawn(AGENT_EXE, [], {
    cwd: path.join(ROOT, 'agent'),
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env,
  })
  proc.stderr?.on('data', d => {
    const msg = d.toString().trim()
    if (msg) console.error('[agent]', msg)
  })
  const startTime = Date.now()
  proc.on('close', code => {
    if (_stopping) return
    if (Date.now() - startTime > 60_000) _agentRestartDelay = 3000
    console.error(`[main] Agent exited (code ${code}), restarting in ${_agentRestartDelay}ms`)
    setTimeout(() => {
      const cfg = loadConfig()
      agentProc = spawnAgent(cfg.serverUrl, cfg.apiKey)
    }, _agentRestartDelay)
    _agentRestartDelay = Math.min(_agentRestartDelay * 2, 30_000)
  })
  return proc
}

function startAgent() {
  setupAutostart()
  if (isAgentRunning()) {
    console.log('[main] Agent already running — skipping spawn')
    // Still watch for it going down; poll every 15s
    _watchExternal()
    return
  }
  const cfg = loadConfig()
  agentProc = spawnAgent(cfg.serverUrl, cfg.apiKey)
}

// Poll for externally-started agent going offline (no proc handle available)
let _watchTimer = null
function _watchExternal() {
  if (_watchTimer) return
  _watchTimer = setInterval(() => {
    if (_stopping) { clearInterval(_watchTimer); _watchTimer = null; return }
    if (!agentProc && !isAgentRunning()) {
      console.log('[main] External agent gone — restarting')
      clearInterval(_watchTimer); _watchTimer = null
      const cfg = loadConfig()
      agentProc = spawnAgent(cfg.serverUrl, cfg.apiKey)
    }
  }, 15_000)
}

function stopAgent() {
  _stopping = true
  if (_watchTimer) { clearInterval(_watchTimer); _watchTimer = null }
  killProc(agentProc)
  agentProc = null
}

// ── Window ────────────────────────────────────────────────
function createWindow() {
  win = new BrowserWindow({
    width: 1440, height: 900,
    minWidth: 900, minHeight: 600,
    frame: false,
    backgroundColor: '#000000',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    title: 'Voidwatch',
  })
  win.loadFile(path.join(__dirname, 'index.html'))
}

ipcMain.on('win-minimize', () => win?.minimize())
ipcMain.on('win-maximize', () => win?.isMaximized() ? win.unmaximize() : win?.maximize())
ipcMain.on('win-close',    () => win?.close())

app.whenReady().then(() => {
  createWindow()
  startAgent()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('before-quit', stopAgent)
app.on('window-all-closed', () => {
  stopAgent()
  if (process.platform !== 'darwin') app.quit()
})
