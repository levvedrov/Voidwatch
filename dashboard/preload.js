const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('__vw', {
  minimize:    () =>      ipcRenderer.send('win-minimize'),
  maximize:    () =>      ipcRenderer.send('win-maximize'),
  close:       () =>      ipcRenderer.send('win-close'),
  getConfig:   ()  =>     ipcRenderer.invoke('config:get'),
  saveConfig:  (d) =>     ipcRenderer.invoke('config:set', d),
  checkServer: (url) =>   ipcRenderer.invoke('config:check-server', url),
})
