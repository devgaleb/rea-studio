const { contextBridge } = require('electron');
const arg = process.argv.find(x => x.startsWith('--rea-bridge-token=')) || '';
contextBridge.exposeInMainWorld('reaDesktop', Object.freeze({ bridgeUrl: 'http://127.0.0.1:8765', token: arg.slice('--rea-bridge-token='.length) }));
