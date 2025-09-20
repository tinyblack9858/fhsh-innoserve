const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let pythonProcess = null;
const isDev = !app.isPackaged;

function getBackendPath() {
    if (isDev) {
        return 'python'; // 在开发模式下，直接使用系统环境的 python
    }
    
    // 根据平台决定执行档名称，增强跨平台相容性
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
  // if (isDev) { mainWindow.webContents.openDevTools(); } // 开发时可取消注解此行来除错
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
    // 只有在进程真正关闭后才将全局变量设为 null
    pythonProcess = null;
  });
});

// 【已修正】监听来自前端的「停止监控」指令，采用正确的异步处理逻辑
ipcMain.on('stop-monitoring', () => {
  if (pythonProcess) {
    // 立即将全局进程引用保存到局部变数中，以供后续异步操作使用
    const processToKill = pythonProcess;

    // 将全局引用设为 null，这可以立即阻止新的监控任务重复启动
    // 注意：此时 processToKill 仍然指向旧的进程物件
    pythonProcess = null;

    // 1. 发送礼貌的终止信号
    processToKill.kill('SIGINT');
    
    // 2. 设定一个计时器作为保险，防止进程卡死
    const forceKillTimer = setTimeout(() => {
        console.warn('Python process did not exit gracefully, forcing kill with SIGKILL.');
        // 即使 pythonProcess 已经是 null，processToKill 依然有效
        processToKill.kill('SIGKILL');
    }, 3000); // 3秒超时

    // 3. 监听进程的 'close' 事件，一旦进程成功关闭，就清除强制终止的计时器
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
