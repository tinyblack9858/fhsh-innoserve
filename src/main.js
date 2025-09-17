const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let pythonProcess = null;
const isDev = !app.isPackaged;

function getBackendPath() {
    // 根據是開發模式還是打包後的產品模式，決定後端執行檔的路徑
    if (isDev) {
        return 'python'; // 在開發模式下，直接使用系統環境的 python
    }
    // 在打包後的應用中，執行檔位於 resources/python_dist/ 目錄下
    return path.join(process.resourcesPath, 'python_dist/backend_controller.exe');
}

function createWindow() {
const mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
    preload: path.join(__dirname, 'preload.js')
    }
});
mainWindow.loadFile(path.join(__dirname, 'index.html'));
  // if (isDev) { mainWindow.webContents.openDevTools(); } // 開發時可取消註解此行來除錯
}

app.whenReady().then(createWindow);

// 監聽來自前端的「開始監控」指令
ipcMain.on('start-monitoring', (event, config) => {
  if (pythonProcess) return; // 如果已經在運行，則不重複啟動

const backendExe = getBackendPath();
const scriptPath = path.join(__dirname, '../python/backend_controller.py');
  // 根據模式設定傳遞給子進程的參數
const args = isDev ? [scriptPath, JSON.stringify(config)] : [JSON.stringify(config)];

  // 啟動 Python 後端子進程
pythonProcess = spawn(backendExe, args);

const sendToUI = (data) => event.sender.send('python-event', data);

  // 監聽 Python 的標準輸出 (stdout)
pythonProcess.stdout.on('data', (data) => {
    // 將收到的數據按行分割，因為可能一次收到多條訊息
    data.toString().split('\n').filter(Boolean).forEach(line => {
    try {
        // 嘗試將每一行解析為 JSON 並發送給前端
        sendToUI(JSON.parse(line));
    } catch (e) {
        // 如果解析失敗，當作原始日誌發送
        sendToUI({ type: 'log', level: 'raw', message: line });
        }
    });
});

  // 監聽 Python 的標準錯誤 (stderr)
pythonProcess.stderr.on('data', (data) => sendToUI({ type: 'log', level: 'error', message: data.toString() }));

  // 監聽子進程的關閉事件
pythonProcess.on('close', (code) => {
    sendToUI({ type: 'log', level: 'info', message: `Backend process exited with code ${code}.` });
    pythonProcess = null;
});
});

// 監聽來自前端的「停止監控」指令
ipcMain.on('stop-monitoring', () => {
if (pythonProcess) {
    pythonProcess.kill('SIGINT'); // 發送終止信號 (等同於 Ctrl+C)
}
});

// 當所有視窗關閉時，確保後端也關閉並退出應用
app.on('window-all-closed', () => {
if (pythonProcess) pythonProcess.kill('SIGINT');
if (process.platform !== 'darwin') app.quit();
});