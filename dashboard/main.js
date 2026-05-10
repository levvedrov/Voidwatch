const { app, BrowserWindow, ipcMain } = require('electron')
const path   = require('path')
const { spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
let win, backendProc, agentProc

function spawnPython(script, cwd) {
  return spawn('python', [script], { cwd, windowsHide: true, stdio: 'ignore' })
}

function killProc(proc) {
  if (!proc) return
  try { spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true }) }
  catch { proc.kill() }
}

function startPython() {
  backendProc = spawnPython(path.join(ROOT, 'backend', 'main.py'), path.join(ROOT, 'backend'))
  setTimeout(() => {
    agentProc = spawnPython(path.join(ROOT, 'agent', 'main.py'), path.join(ROOT, 'agent'))
  }, 3000)
}

function stopPython() {
  killProc(backendProc); backendProc = null
  killProc(agentProc);   agentProc   = null
}

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
  win.loadFile('index.html')
}

ipcMain.on('win-minimize', () => win?.minimize())
ipcMain.on('win-maximize', () => win?.isMaximized() ? win.unmaximize() : win?.maximize())
ipcMain.on('win-close',    () => win?.close())

app.whenReady().then(() => {
  startPython()
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
