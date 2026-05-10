const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('__vw', {
  apiBase:  'http://localhost:8000',
  minimize: () => ipcRenderer.send('win-minimize'),
  maximize: () => ipcRenderer.send('win-maximize'),
  close:    () => ipcRenderer.send('win-close'),
})
