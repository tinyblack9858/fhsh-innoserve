// src/main.js (最终修正版 - 固定 Python 路径)

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

let pythonProcess = null;
const isDev = !app.isPackaged;
const FIXED_PYTHON_PATH = 'C:\\Users\\User\\.pyenv\\pyenv-win\\shims\\python';

function resolvePythonExecutable() {
  return FIXED_PYTHON_PATH;
}

function getBackendPath() {
  // 在开发模式下...
  if (isDev) {
    return resolvePythonExecutable();
  }
  
  // 在生产模式（打包后），逻辑保持不变，它会使用打包进来的 backend_controller.exe
  let exeName = 'backend_controller';
  if (process.platform === 'win32') {
    exeName += '.exe';
  }
  return path.join(process.resourcesPath, 'python_dist', exeName);
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
  // if (isDev) { mainWindow.webContents.openDevTools({ mode: 'detach' }); } // 开发时可取消注解此行来除错
}

app.whenReady().then(createWindow);

ipcMain.handle('scan-network', async () => {
  const scannerScript = path.resolve(__dirname, '../python/network_scanner.py');
  if (!fs.existsSync(scannerScript)) {
    return { success: false, error: '找不到掃描腳本。' };
  }

  let pythonExecutable;
  try {
    pythonExecutable = resolvePythonExecutable();
  } catch (error) {
    return { success: false, error: error.message || '找不到 Python 執行檔。' };
  }

  return new Promise((resolve, reject) => {
    const child = spawn(pythonExecutable, [scannerScript]);
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('error', (error) => {
      reject({ success: false, error: error.message });
    });

    child.on('close', (code) => {
      if (code !== 0) {
        const message = stdout.trim() || stderr.trim() || `掃描腳本異常退出 (code=${code})`;
        resolve({ success: false, error: message });
        return;
      }

      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (parseError) {
        resolve({ success: false, error: `解析掃描結果失敗: ${parseError.message}` });
      }
    });
  }).catch((error) => ({ success: false, error: error.error || error.message }));
});

// 监听来自前端的「开始监控」指令
ipcMain.on('start-monitoring', (event, config) => {
  if (pythonProcess) return; // 如果已经在运行，则不重复启动

  let backendExe;
  try {
    backendExe = getBackendPath();
  } catch (error) {
    const message = error?.message || '無法找到 Python 執行檔。';
    if (!event.sender.isDestroyed()) {
      event.sender.send('python-event', { type: 'log', level: 'error', message });
    }
    return;
  }
  const scriptPath = path.resolve(__dirname, '../python/backend_controller.py');
  
  // 根据模式设定传递给子进程的参数
  const args = isDev ? [scriptPath, JSON.stringify(config)] : [JSON.stringify(config)];
  
  // 启动 Python 后端子进程
  pythonProcess = spawn(backendExe, args);

  const sendToUI = (data) => {
    if (event.sender.isDestroyed()) return;
    event.sender.send('python-event', data);
  }

  // 监听 Python 的标准输出 (stdout)
  pythonProcess.stdout.on('data', (data) => {
    data.toString().split('\n').filter(Boolean).forEach(line => {
      try {
        sendToUI(JSON.parse(line));
      } catch (e) {
        sendToUI({ type: 'log', level: 'raw', message: line });
      }
    });
  });

  // 监听 Python 的标准错误 (stderr)
  pythonProcess.stderr.on('data', (data) => sendToUI({ type: 'log', level: 'error', message: data.toString() }));
  
  // 监听子进程的关闭事件
  pythonProcess.on('close', (code) => {
    sendToUI({ type: 'log', level: 'info', message: `Backend process exited with code ${code}.` });
    pythonProcess = null;
  });
});

// 监听来自前端的「停止监控」指令，采用正确的异步处理逻辑
ipcMain.on('stop-monitoring', () => {
  if (pythonProcess) {
    const processToKill = pythonProcess;
    pythonProcess = null;
    processToKill.kill('SIGINT');
    const forceKillTimer = setTimeout(() => {
        console.warn('Python process did not exit gracefully, forcing kill with SIGKILL.');
        processToKill.kill('SIGKILL');
    }, 3000);
    processToKill.once('close', () => {
      clearTimeout(forceKillTimer);
    });
  }
});

// 当所有视窗关闭时，确保后端也关闭并退出应用
app.on('window-all-closed', () => {
  if (pythonProcess) {
    pythonProcess.kill('SIGINT');
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
