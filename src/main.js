// src/main.js (最终修正版 - 固定 Python 路径)

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let pythonProcess = null;
const isDev = !app.isPackaged;

function getBackendPath() {
    // 在开发模式下...
    if (isDev) {
        // 【关键修正】
        // 直接返回你 pyenv 环境中 Python.exe 的绝对路径。
        // 这将强制应用程式使用这个你已经确认安装了 scapy 的 Python 版本。
        // 注意：路径中的反斜杠 \ 必须用 \\ 来转义。
        return 'C:\\Users\\User\\.pyenv\\pyenv-win\\versions\\3.11.9\\python.exe';
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

// 监听来自前端的「开始监控」指令
ipcMain.on('start-monitoring', (event, config) => {
  if (pythonProcess) return; // 如果已经在运行，则不重复启动

  const backendExe = getBackendPath();
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


// 修正版（自動判斷py路徑）

/*
// src/main.js (最终修正版 - 固定 Python 路径)

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, spawnSync } = require('child_process');

let pythonProcess = null;
const isDev = !app.isPackaged;
let cachedPythonPath = null;

function resolvePythonExecutable() {
  if (cachedPythonPath) {
    return cachedPythonPath;
  }

  const envPython = process.env.PYTHON_EXECUTABLE || process.env.PYTHON_PATH;
  if (envPython) {
    cachedPythonPath = envPython;
    return cachedPythonPath;
  }

  const pipPath = resolvePythonFromPip();
  if (pipPath) {
    cachedPythonPath = pipPath;
    return cachedPythonPath;
  }

  const commandPath = resolvePythonFromCommands();
  if (commandPath) {
    cachedPythonPath = commandPath;
    return cachedPythonPath;
  }

  // Fallback to `python` if nothing else worked.
  cachedPythonPath = process.platform === 'win32' ? 'python.exe' : 'python';
  return cachedPythonPath;
}

function resolvePythonFromCommands() {
  const commands = [
    ['python', []],
    ['python3', []],
    ['py', ['-3']],
    ['py', ['-2']]
  ];

  for (const [command, extraArgs] of commands) {
    const result = spawnSync(command, [...extraArgs, '-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' });
    if (result.status === 0 && typeof result.stdout === 'string') {
      const executablePath = result.stdout.trim();
      if (executablePath) {
        return executablePath;
      }
    }
  }

  return null;
}

function resolvePythonFromPip() {
  const result = spawnSync('pip', ['--version'], { encoding: 'utf8' });
  if (result.status !== 0 || !result.stdout) {
    return null;
  }

  const match = result.stdout.match(/from\s+(\S+)\s+\(python/i);
  if (!match) {
    return null;
  }

  const pipModulePath = match[1];
  let dir = path.dirname(pipModulePath);
  const maxDepth = 6;
  const candidateNames = process.platform === 'win32'
    ? ['python.exe', 'python']
    : ['bin/python3', 'bin/python'];

  for (let depth = 0; depth < maxDepth && dir !== path.dirname(dir); depth += 1) {
    for (const candidate of candidateNames) {
      const candidatePath = path.join(dir, candidate);
      try {
        fs.accessSync(candidatePath, fs.constants.X_OK);
        return candidatePath;
      } catch (err) {
        // Ignore and continue searching upwards.
      }
    }
    dir = path.dirname(dir);
  }

  return null;
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

  const pythonExecutable = resolvePythonExecutable();

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

  const backendExe = getBackendPath();
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


*/
