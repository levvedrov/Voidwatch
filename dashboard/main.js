const { app, BrowserWindow, ipcMain } = require('electron')
const path   = require('path')
const http   = require('http')
const { spawn, execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
let win, backendProc, agentProc
let _stopping = false          // set true during shutdown to suppress restarts
let _agentRestartDelay = 3000  // ms; doubles on each crash, resets after stable run

// ── Python detection ─────────────────────────────────────
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

function spawnPython(script, cwd) {
  if (!PYTHON) {
    console.error('[main] Python not found — install Python 3.9+ and add it to PATH')
    return null
  }
  const proc = spawn(PYTHON, [script], { cwd, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
  proc.stderr?.on('data', d => {
    const msg = d.toString().trim()
    if (msg) console.error(`[${path.basename(script)}]`, msg)
  })
  return proc
}

// ── Backend health poll ───────────────────────────────────
function waitForBackend(timeoutMs = 40000, intervalMs = 500) {
  return new Promise(resolve => {
    const deadline = Date.now() + timeoutMs
    function check() {
      http.get('http://127.0.0.1:8000/health', res => {
        if (res.statusCode === 200) return resolve(true)
        retry()
      }).on('error', retry)
      function retry() {
        if (Date.now() < deadline) setTimeout(check, intervalMs)
        else resolve(false)
      }
    }
    check()
  })
}

// ── Process management ───────────────────────────────────
function killProc(proc) {
  if (!proc) return
  try { spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true }) }
  catch { proc.kill() }
}

function spawnAgent() {
  const proc = spawnPython(path.join(ROOT, 'agent', 'main.py'), path.join(ROOT, 'agent'))
  if (!proc) return null
  const startTime = Date.now()
  proc.on('close', code => {
    if (_stopping) return
    if (Date.now() - startTime > 60_000) _agentRestartDelay = 3000
    console.error(`[main] Agent exited (code ${code}), restarting in ${_agentRestartDelay}ms`)
    setTimeout(() => { agentProc = spawnAgent() }, _agentRestartDelay)
    _agentRestartDelay = Math.min(_agentRestartDelay * 2, 30_000)
  })
  return proc
}

async function startPython() {
  backendProc = spawnPython(path.join(ROOT, 'backend', 'main.py'), path.join(ROOT, 'backend'))
  const ready = await waitForBackend()
  if (!ready) console.error('[main] Backend did not become ready in time')
  agentProc = spawnAgent()
}

function stopPython() {
  _stopping = true
  killProc(backendProc); backendProc = null
  killProc(agentProc);   agentProc   = null
}

// ── Window ───────────────────────────────────────────────
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
  startPython()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('before-quit', stopPython)
app.on('window-all-closed', () => {
  stopPython()
  if (process.platform !== 'darwin') app.quit()
})
