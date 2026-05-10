const { contextBridge } = require('electron')
contextBridge.exposeInMainWorld('__vw', {
  apiBase: 'http://localhost:8000'
})
