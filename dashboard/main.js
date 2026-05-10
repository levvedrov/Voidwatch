const { app, BrowserWindow } = require('electron')
const path = require('path')
const { spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
let win, backendProc, agentProc

function spawnPython(script, cwd) {
  return spawn('python', [script], {
    cwd,
    windowsHide: true,
    stdio: 'ignore',
  })
}

function killProc(proc) {
  if (!proc) return
  try {
    // On Windows, kill the whole process tree so subprocesses don't linger
    spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true })
  } catch { proc.kill() }
}

function startPython() {
  backendProc = spawnPython(
    path.join(ROOT, 'backend', 'main.py'),
    path.join(ROOT, 'backend')
  )
  // Give backend 3 s to bind its port before the agent starts sending
  setTimeout(() => {
    agentProc = spawnPython(
      path.join(ROOT, 'agent', 'main.py'),
      path.join(ROOT, 'agent')
    )
  }, 3000)
}

function stopPython() {
  killProc(backendProc); backendProc = null
  killProc(agentProc);   agentProc   = null
}

function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0b0f14',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    title: 'Voidwatch',
  })
  win.loadFile('index.html')
}

app.whenReady().then(() => {
  startPython()
  // Show window after backend has had time to start
  setTimeout(createWindow, 2500)
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('before-quit', stopPython)
app.on('window-all-closed', () => {
  stopPython()
  if (process.platform !== 'darwin') app.quit()
})
