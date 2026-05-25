/**
 * SYSACK Agent Desktop v2.0
 * Monitora o computador e reporta ao Firebase Firestore
 * Roda como serviço Windows (SYSTEM)
 */

'use strict';

const os      = require('os');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const { execSync, exec } = require('child_process');
// Força encoding UTF-8 no Windows
if (process.platform === 'win32') {
  try { execSync('chcp 65001', { stdio: 'ignore' }); } catch(e) {}
}

// ── Configuração ──────────────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'config.json');
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch(e) {}

const PROJECT_ID = cfg.firebaseProjectId || 'sysack-829e2';
const API_KEY    = cfg.firebaseApiKey    || 'AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww';
const AGENT_ID   = cfg.agentId          || os.hostname();
const INTERVAL   = (cfg.intervalSeconds || 60) * 1000;

// ── Log ───────────────────────────────────────────────────────────
const LOG_FILE = path.join(__dirname, 'agent.log');
function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  try {
    fs.appendFileSync(LOG_FILE, line + '\n', 'utf8');
    // Mantém log com máximo 1MB
    const stat = fs.statSync(LOG_FILE);
    if (stat.size > 1_000_000) {
      const content = fs.readFileSync(LOG_FILE, 'utf8');
      fs.writeFileSync(LOG_FILE, content.slice(-500_000));
    }
  } catch(e) {}
}

// ── Coleta de dados do sistema ────────────────────────────────────
function getCpuUsage() {
  const cpus = os.cpus();
  const total = cpus.reduce((acc, cpu) => {
    const times = Object.values(cpu.times);
    return acc + times.reduce((a, b) => a + b, 0);
  }, 0);
  const idle = cpus.reduce((acc, cpu) => acc + cpu.times.idle, 0);
  return Math.round((1 - idle / total) * 100);
}

function getMemoryInfo() {
  const total = os.totalmem();
  const free  = os.freemem();
  const used  = total - free;
  return {
    totalGB: +(total / 1e9).toFixed(1),
    usedGB:  +(used  / 1e9).toFixed(1),
    pct:     Math.round((used / total) * 100),
  };
}

function getDiskInfo() {
  try {
    if (process.platform === 'win32') {
      const out = execSync('wmic logicaldisk get size,freespace,caption /format:csv', { timeout: 5000 })
        .toString().trim().split('\n').slice(1);
      return out.filter(Boolean).map(line => {
        const parts = line.trim().split(',');
        if (parts.length < 4) return null;
        const [, caption, free, size] = parts;
        if (!size || size === '0') return null;
        const totalGB = +(parseInt(size)  / 1e9).toFixed(1);
        const freeGB  = +(parseInt(free)  / 1e9).toFixed(1);
        const usedGB  = +(totalGB - freeGB).toFixed(1);
        return { drive: caption, totalGB, usedGB, freeGB, pct: Math.round((usedGB / totalGB) * 100) };
      }).filter(Boolean);
    }
  } catch(e) {}
  return [];
}

function getLoggedUser() {
  try {
    if (process.platform === 'win32') {
      // WMIC é mais confiável rodando como SYSTEM
      try {
        const out = execSync('wmic computersystem get username /format:value', { timeout: 5000, windowsHide: true }).toString();
        const match = out.match(/UserName=(.+)/i);
        if (match && match[1].trim()) {
          const full = match[1].trim();
          return full.includes('\\') ? full.split('\\').pop() : full;
        }
      } catch(e2) {}
      // fallback: query session
      try {
        const out = execSync('query session', { timeout: 5000, windowsHide: true }).toString();
        for (const line of out.split('\n')) {
          if (line.toLowerCase().includes('active')) {
            const user = line.trim().replace(/^>/, '').trim().split(/\s+/)[0];
            if (user && !['services','sistema','system','services#'].includes(user.toLowerCase())) return user;
          }
        }
      } catch(e3) {}
      return '';
    }
    return os.userInfo().username;
  } catch(e) { return ''; }
}

function getOsInfo() {
  try {
    if (process.platform === 'win32') {
      // wmic retorna ASCII puro sem problemas de encoding
      try {
        const out = execSync('wmic os get Caption,Version /format:value', { timeout: 5000, windowsHide: true }).toString();
        const caption = (out.match(/Caption=(.+)/i)||[])[1]?.trim() || '';
        const version = (out.match(/Version=(.+)/i)||[])[1]?.trim() || '';
        if (caption) return caption + (version ? ' [' + version + ']' : '');
      } catch(e2) {}
      // fallback: usa dados do Node.js
      return 'Windows ' + os.release();
    }
    return os.type() + ' ' + os.release();
  } catch(e) { return os.type(); }
}

function getUptime() {
  return Math.round(os.uptime()); // segundos numérico — uptimeH calculado no payload
}

// ── Monitores conectados ──────────────────────────────────────────
function getMonitores() {
  try {
    if (process.platform !== 'win32') return [];
    // WMI: captura monitores plug-and-play com número de série
    const out = execSync(
      'wmic path Win32_DesktopMonitor get Caption,MonitorManufacturer,MonitorType,ScreenHeight,ScreenWidth /format:csv',
      { timeout: 8000, windowsHide: true }
    ).toString();
    const monitores = [];
    const lines = out.split('\n').filter(l => l.trim() && !l.startsWith('Node'));
    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length < 5) continue;
      const caption = (parts[1]||'').trim();
      const fab     = (parts[2]||'').trim();
      const tipo    = (parts[3]||'').trim();
      const h       = parseInt(parts[4]||'0');
      const w       = parseInt(parts[5]||'0');
      if (!caption && !fab) continue;
      monitores.push({ caption, fabricante: fab, tipo, resolucao: w && h ? `${w}x${h}` : '' });
    }

    // Tenta pegar número de série via WMI (requer permissão)
    try {
      const out2 = execSync(
        'wmic path WmiMonitorID get SerialNumberID,UserFriendlyName,ManufacturerName /format:csv',
        { timeout: 8000, windowsHide: true }
      ).toString();
      const lines2 = out2.split('\n').filter(l => l.trim() && !l.startsWith('Node'));
      lines2.forEach((line, i) => {
        const parts = line.split(',');
        if (parts.length < 4) return;
        // SerialNumberID e UserFriendlyName vêm como arrays de bytes decimais
        const toStr = arr => arr.split(';').map(n=>parseInt(n)).filter(n=>n>0).map(n=>String.fromCharCode(n)).join('').trim();
        const serial = toStr(parts[1]||'');
        const nome   = toStr(parts[2]||'');
        const fab2   = toStr(parts[3]||'');
        if (monitores[i]) {
          if (serial) monitores[i].serial = serial;
          if (nome)   monitores[i].nome   = nome;
          if (fab2)   monitores[i].fabricante = fab2;
        } else {
          monitores.push({ serial, nome, fabricante: fab2 });
        }
      });
    } catch(e2) {}

    return monitores.filter(m => m.caption || m.nome || m.serial);
  } catch(e) {
    return [];
  }
}


// ── Firebase REST API ─────────────────────────────────────────────
function firestoreSet(docPath, data) {
  return new Promise((resolve, reject) => {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}?key=${API_KEY}`;

    // Converte objeto JS para formato Firestore
    function toFirestore(val) {
      if (val === null || val === undefined) return { nullValue: null };
      if (typeof val === 'boolean')  return { booleanValue: val };
      if (typeof val === 'number' && isFinite(val)) return { doubleValue: val };
      if (typeof val === 'number')   return { doubleValue: 0 }; // NaN/Infinity
      if (typeof val === 'string')   return { stringValue: val };
      if (Array.isArray(val)) {
        const values = val.map(toFirestore).filter(v => v !== null);
        return { arrayValue: values.length ? { values } : {} };
      }
      if (typeof val === 'object') {
        const fields = {};
        for (const [k, v] of Object.entries(val)) {
          if (v !== undefined) fields[k] = toFirestore(v);
        }
        return { mapValue: { fields } };
      }
      return { stringValue: String(val) };
    }

    const fields = {};
    for (const [k, v] of Object.entries(data)) fields[k] = toFirestore(v);

    const body = JSON.stringify({ fields });
    const urlObj = new URL(url);

    const req = https.request({
      hostname: urlObj.hostname,
      path:     urlObj.pathname + urlObj.search,
      method:   'PATCH',
      rejectUnauthorized: false, // aceita proxy CESAN com certificado autoassinado
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(raw);
        else reject(new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Ciclo principal ───────────────────────────────────────────────
async function reportar() {
  try {
    const cpu    = getCpuUsage();
    const mem    = getMemoryInfo();
    const discos = getDiskInfo();
    const user   = getLoggedUser();
    const now    = new Date().toISOString();

    const discoC = discos.find(d => d.drive === 'C:') || null;
    const uptimeSec = getUptime();

    const dados = {
      hostname:          AGENT_ID,
      ip:                Object.values(os.networkInterfaces())
                           .flat().find(n => n.family === 'IPv4' && !n.internal)?.address || '',
      so:                getOsInfo(),
      osNome:            getOsInfo(),
      // campos esperados pelo renderAssistenciaRemota
      cpuPct:            cpu,
      ramPct:            mem.pct,
      memPct:            mem.pct,
      ramUsadoGB:        mem.usedGB,
      ramTotalGB:        mem.totalGB,
      discoC_usadoPct:   discoC ? discoC.pct : null,
      discoC_livreGB:    discoC ? discoC.freeGB : null,
      discoC_totalGB:    discoC ? discoC.totalGB : null,
      discoC:            discoC,
      outrosDiscos:      discos.filter(d => d.drive !== 'C:'),
      usuarioLogado:     user,
      uptime:            uptimeSec,
      uptimeH:           Math.floor(uptimeSec / 3600),
      monitores:         getMonitores(),
      versaoAgente:      '2.0.0',
      ultimaAtualizacao: now,
      lastSeen:          now,
      status:            'online',
      plataforma:        process.platform,
    };

    await firestoreSet(`agents/${AGENT_ID}`, dados);
    log(`[OK] Dados enviados - CPU: ${cpu}% | RAM: ${mem.pct}% | Usuario: ${user}`);
  } catch(e) {
    log(`[ERRO] ${e.message}`);
  }
}

// ── Inicialização ─────────────────────────────────────────────────
log(`[SYSACK Agent Desktop] Iniciando - hostname: ${AGENT_ID}`);
log(`[SYSACK Agent Desktop] Projeto Firebase: ${PROJECT_ID}`);
log(`[SYSACK Agent Desktop] Intervalo: ${INTERVAL / 1000}s`);

reportar(); // Primeira execução imediata
setInterval(reportar, INTERVAL);

// Mantém o processo vivo
process.on('uncaughtException', err => log(`[UNCAUGHT] ${err.message}`));
process.on('unhandledRejection', err => log(`[UNHANDLED] ${err}`));
