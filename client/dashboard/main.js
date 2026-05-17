const { app, BrowserWindow, ipcMain } = require('electron')
const path   = require('path')
const http   = require('http')
const https  = require('https')
const fs     = require('fs')
const { spawn, execFileSync } = require('child_process')

const ROOT        = path.join(__dirname, '..')
const CONFIG_PATH = path.join(app.getPath('userData'), 'voidwatch-config.json')

let win, agentProc
let _stopping          = false
let _agentRestartDelay = 3000

// ── Config persistence ────────────────────────────────────
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) }
  catch { return { serverUrl: 'http://localhost:8000', apiKey: '' } }
}

function saveConfig(data) {
  const cfg = { ...loadConfig(), ...data }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2))
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

// ── Python detection ──────────────────────────────────────
function findPython() {
  for (const cmd of ['python', 'py', 'python3']) {
    try {
      execFileSync(cmd, ['--version'], { timeout: 3000, windowsHide: true, stdio: 'pipe' })
      return cmd
    } catch {}
  }
  return null
}

const PYTHON = findPython()

// ── Process management ────────────────────────────────────
function killProc(proc) {
  if (!proc) return
  try { spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true }) }
  catch { proc.kill() }
}

function spawnAgent(serverUrl, apiKey) {
  if (!PYTHON) {
    console.error('[main] Python not found — install Python 3.9+ and add it to PATH')
    return null
  }
  const env = {
    ...process.env,
    VOIDWATCH_SERVER_URL: serverUrl || 'http://localhost:8000',
    VOIDWATCH_API_KEY:    apiKey    || '',
  }
  const proc = spawn(PYTHON, [path.join(ROOT, 'agent', 'main.py')], {
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
  const cfg = loadConfig()
  agentProc = spawnAgent(cfg.serverUrl, cfg.apiKey)
}

function stopAgent() {
  _stopping = true
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
