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
    fs.appendFileSync(LOG_FILE, line + '\n');
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
      return execSync('query session', { timeout: 3000 })
        .toString().split('\n')
        .find(l => l.includes('Active'))
        ?.trim().split(/\s+/)[1] || '';
    }
    return os.userInfo().username;
  } catch(e) { return ''; }
}

function getOsInfo() {
  try {
    if (process.platform === 'win32') {
      const ver = execSync('ver', { timeout: 3000 }).toString().trim();
      return ver;
    }
    return `${os.type()} ${os.release()}`;
  } catch(e) { return os.type(); }
}

function getUptime() {
  const secs = os.uptime();
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

// ── Firebase REST API ─────────────────────────────────────────────
function firestoreSet(docPath, data) {
  return new Promise((resolve, reject) => {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}?key=${API_KEY}`;

    // Converte objeto JS para formato Firestore
    function toFirestore(val) {
      if (val === null || val === undefined) return { nullValue: null };
      if (typeof val === 'boolean')  return { booleanValue: val };
      if (typeof val === 'number')   return { doubleValue: val };
      if (typeof val === 'string')   return { stringValue: val };
      if (Array.isArray(val))        return { arrayValue: { values: val.map(toFirestore) } };
      if (typeof val === 'object') {
        const fields = {};
        for (const [k, v] of Object.entries(val)) fields[k] = toFirestore(v);
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

    const dados = {
      hostname:       AGENT_ID,
      ip:             Object.values(os.networkInterfaces())
                        .flat().find(n => n.family === 'IPv4' && !n.internal)?.address || '',
      so:             getOsInfo(),
      cpu:            cpu,
      ramPct:         mem.pct,
      ramUsadoGB:     mem.usedGB,
      ramTotalGB:     mem.totalGB,
      discoC:         discos.find(d => d.drive === 'C:') || null,
      outrosDiscos:   discos.filter(d => d.drive !== 'C:'),
      usuarioLogado:  user,
      uptime:         getUptime(),
      versaoAgente:   '2.0.0',
      ultimaAtualizacao: now,
      lastSeen:       now,
      osNome:         getOsInfo(),
      status:         'online',
      plataforma:     process.platform,
    };

    await firestoreSet(`agents/${AGENT_ID}`, dados);
    log(`[OK] Dados enviados — CPU: ${cpu}% | RAM: ${mem.pct}% | Usuário: ${user}`);
  } catch(e) {
    log(`[ERRO] ${e.message}`);
  }
}

// ── Inicialização ─────────────────────────────────────────────────
log(`[SYSACK Agent Desktop] Iniciando — hostname: ${AGENT_ID}`);
log(`[SYSACK Agent Desktop] Projeto Firebase: ${PROJECT_ID}`);
log(`[SYSACK Agent Desktop] Intervalo: ${INTERVAL / 1000}s`);

reportar(); // Primeira execução imediata
setInterval(reportar, INTERVAL);

// Mantém o processo vivo
process.on('uncaughtException', err => log(`[UNCAUGHT] ${err.message}`));
process.on('unhandledRejection', err => log(`[UNHANDLED] ${err}`));
