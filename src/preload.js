const { contextBridge, ipcRenderer } = require('electron');

// 建立一個安全的橋樑，將主進程的功能暴露給前端 UI
contextBridge.exposeInMainWorld('electronAPI', {
  // 暴露「開始監控」功能
  startMonitoring: (config) => ipcRenderer.send('start-monitoring', config),
  // 暴露「停止監控」功能
  stopMonitoring: () => ipcRenderer.send('stop-monitoring'),
  // 暴露一個監聽器，讓前端可以接收來自後端的事件
  onPythonEvent: (callback) => ipcRenderer.on('python-event', (event, data) => callback(data))
});
