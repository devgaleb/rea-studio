const { app, BrowserWindow } = require('electron');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
let bridge, win;
const token = crypto.randomBytes(32).toString('base64url');
function startBridge() {
  const bundled = path.join(process.resourcesPath || __dirname, 'local-service', 'rea-bridge.exe');
  const script = path.join(process.resourcesPath || __dirname, 'local-service', 'server.py');
  const env = { ...process.env, REA_STUDIO_TOKEN: token, REA_STUDIO_PORT: '8765' };
  if (fs.existsSync(bundled)) bridge = spawn(bundled, [], { env, windowsHide: true, stdio: 'ignore' });
  else bridge = spawn(process.platform === 'win32' ? 'py' : 'python3', process.platform === 'win32' ? ['-3', script] : [script], { env, windowsHide: true, stdio: 'ignore' });
  bridge.on('error', e => console.error('Local bridge failed to start:', e.message));
}
function createWindow() {
  win = new BrowserWindow({ width: 1440, height: 960, minWidth: 900, minHeight: 650, webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, additionalArguments: ['--rea-bridge-token=' + token] } });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html')); 
}
app.whenReady().then(() => { startBridge(); createWindow(); });
app.on('before-quit', () => { if (bridge && !bridge.killed) bridge.kill(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
