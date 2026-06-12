/**
 * SYSACK Agent Desktop v2.1
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
const SOFTWARE_INTERVAL = (cfg.softwareIntervalHours || 6) * 60 * 60 * 1000; // coleta completa de softwares a cada 6h
let _softwareCache = { at: 0, list: [] };

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

    // Pega serial via arquivo .ps1 temporário (evita problemas de escape)
    try {
      const psScript = [
        '$monitors = Get-WmiObject -Namespace root\\wmi -Class WmiMonitorID -ErrorAction SilentlyContinue',
        'foreach ($m in $monitors) {',
        '  $serial = ($m.SerialNumberID | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""',
        '  $name   = ($m.UserFriendlyName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""',
        '  $mfr    = ($m.ManufacturerName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""',
        '  Write-Output ("SERIAL=" + $serial + "|NAME=" + $name + "|MFR=" + $mfr)',
        '}'
      ].join('\n');
      const psFile = path.join(__dirname, '_mon.ps1');
      fs.writeFileSync(psFile, psScript, 'utf8');
      const out2 = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
        { timeout: 10000, windowsHide: true }).toString();
      try { fs.unlinkSync(psFile); } catch(e3) {}
      const lines2 = out2.split('\n').filter(l => l.includes('SERIAL='));
      lines2.forEach((line, i) => {
        const get = key => (line.match(new RegExp(key + '=([^|\r\n]*)')) || [])[1]?.trim() || '';
        const serial = get('SERIAL');
        const nome   = get('NAME');
        const fab2   = get('MFR');
        if (monitores[i]) {
          if (serial) monitores[i].serial = serial;
          if (nome)   monitores[i].nome   = nome;
          if (fab2)   monitores[i].fabricante = fab2;
        } else if (serial || nome) {
          monitores.push({ serial, nome, fabricante: fab2 });
        }
      });
    } catch(e2) {}

    return monitores.filter(m => m.caption || m.nome || m.serial);
  } catch(e) {
    return [];
  }
}



// ── Informações de hardware ───────────────────────────────────────
function getHardwareInfo() {
  const info = { fabricante: '', modelo: '', serial: '', cpu: '', nucleos: 0, build: '' };
  if (process.platform !== 'win32') return info;
  try {
    const psScript = [
      '$cs  = Get-WmiObject Win32_ComputerSystem',
      '$bios = Get-WmiObject Win32_BIOS',
      '$cpu  = Get-WmiObject Win32_Processor | Select-Object -First 1',
      '$os   = Get-WmiObject Win32_OperatingSystem',
      'Write-Output ("FAB="   + $cs.Manufacturer)',
      'Write-Output ("MOD="   + $cs.Model)',
      'Write-Output ("SER="   + $bios.SerialNumber)',
      'Write-Output ("CPU="   + $cpu.Name)',
      'Write-Output ("NUC="   + $cpu.NumberOfLogicalProcessors)',
      'Write-Output ("BUILD=" + $os.BuildNumber)',
    ].join('\n');
    const psFile = path.join(__dirname, '_hw.ps1');
    fs.writeFileSync(psFile, psScript, 'utf8');
    const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
      { timeout: 10000, windowsHide: true }).toString();
    try { fs.unlinkSync(psFile); } catch(e) {}
    const get = key => (out.match(new RegExp(key + '=([^\r\n]*)')) || [])[1]?.trim() || '';
    info.fabricante = get('FAB');
    info.modelo     = get('MOD');
    info.serial     = get('SER');
    info.cpu        = get('CPU');
    info.nucleos    = parseInt(get('NUC')) || 0;
    info.build      = get('BUILD');
  } catch(e) {}
  return info;
}

function getSegurancaInfo() {
  const info = { antivirus: '', bitlocker: '', firewall: '', patches: 0 };
  if (process.platform !== 'win32') return info;
  try {
    const psScript = [
      '# Antivirus detection',
      '$avName = ""',
      '$av = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct -EA SilentlyContinue | Select-Object -First 1',
      'if ($av) { $avName = $av.displayName }',
      '$knownAV = @(',
      '  [pscustomobject]@{Name="Trend Micro";Svcs="TMBMSRV,ntrtscan,TmPfw"},',
      '  [pscustomobject]@{Name="Symantec";Svcs="SepMasterService,SAVRT"},',
      '  [pscustomobject]@{Name="McAfee";Svcs="McShield,McAfeeFramework"},',
      '  [pscustomobject]@{Name="Kaspersky";Svcs="AVP,klnagent"},',
      '  [pscustomobject]@{Name="Sophos";Svcs="SAVService,SophosHealth"}',
      ')',
      'foreach ($corp in $knownAV) {',
      '  foreach ($svc in $corp.Svcs.Split(",")) {',
      '    $s = Get-Service -Name $svc.Trim() -EA SilentlyContinue',
      '    if ($s -and $s.Status -eq "Running") { $avName = $corp.Name; break }',
      '  }',
      '  if ($avName -eq $corp.Name) { break }',
      '}',
      'Write-Output ("AV=" + $avName)',
      // BitLocker
      'try { $bl = Get-BitLockerVolume -MountPoint C: -EA SilentlyContinue; Write-Output ("BL=" + $bl.ProtectionStatus) } catch { Write-Output "BL=" }',
      // Firewall
      'try { $fw = Get-NetFirewallProfile -EA SilentlyContinue | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1; Write-Output ("FW=" + $fw.Name) } catch { Write-Output "FW=" }',
      // Patches (últimos 30 dias)
      'try { $p = (Get-HotFix -EA SilentlyContinue | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)}).Count; Write-Output ("PATCHES=" + $p) } catch { Write-Output "PATCHES=0" }',
    ].join('\n');
    const psFile = path.join(__dirname, '_sec.ps1');
    fs.writeFileSync(psFile, psScript, 'utf8');
    const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
      { timeout: 15000, windowsHide: true }).toString();
    try { fs.unlinkSync(psFile); } catch(e) {}
    const get = key => (out.match(new RegExp(key + '=([^\r\n]*)')) || [])[1]?.trim() || '';
    info.antivirus = get('AV');
    info.bitlocker = get('BL') === '1' ? 'Ativo' : get('BL') === '0' ? 'Inativo' : '';
    info.firewall  = get('FW') ? 'Ativo (' + get('FW') + ')' : '';
    info.patches   = parseInt(get('PATCHES')) || 0;
  } catch(e) {}
  return info;
}


// ── Inventário de Software instalado ──────────────────────────────
function normalizarSoftwareNome(nome) {
  return String(nome || '')
    .replace(/\s+/g, ' ')
    .replace(/\s*\(.*?\)\s*$/g, '')
    .trim();
}

function getInstalledSoftware(force = false) {
  const now = Date.now();
  if (!force && _softwareCache.list.length && (now - _softwareCache.at) < SOFTWARE_INTERVAL) {
    return _softwareCache.list;
  }

  try {
    if (process.platform !== 'win32') return [];

    const psScript = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$paths = @(',
      '  "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",',
      '  "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"',
      ')',
      '# Quando o serviço roda como SYSTEM, HKCU não representa o usuário logado.',
      '# Por isso também verificamos HKU para softwares instalados por usuário.',
      '$userPaths = Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {',
      '  "Registry::" + $_.Name + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"',
      '}',
      '$items = @()',
      '$items += Get-ItemProperty $paths -ErrorAction SilentlyContinue',
      '$items += Get-ItemProperty $userPaths -ErrorAction SilentlyContinue',
      '$items | Where-Object {',
      '  $_.DisplayName -and',
      '  $_.SystemComponent -ne 1 -and',
      '  $_.ReleaseType -ne "Update" -and',
      '  $_.ParentKeyName -eq $null',
      '} | Select-Object @{n="nome";e={$_.DisplayName}},',
      '                  @{n="versao";e={$_.DisplayVersion}},',
      '                  @{n="fabricante";e={$_.Publisher}},',
      '                  @{n="dataInstalacao";e={$_.InstallDate}},',
      '                  @{n="localInstalacao";e={$_.InstallLocation}},',
      '                  @{n="origem";e={ if ($_.PSPath -like "*WOW6432Node*") { "win32" } elseif ($_.PSPath -like "*HKEY_USERS*") { "usuario" } else { "win64" } }} |',
      '  Sort-Object nome, versao -Unique |',
      '  ConvertTo-Json -Depth 4 -Compress'
    ].join('\n');

    const psFile = path.join(__dirname, '_software.ps1');
    fs.writeFileSync(psFile, psScript, 'utf8');

    const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"', {
      timeout: 60000,
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024
    }).toString().trim();

    try { fs.unlinkSync(psFile); } catch(e) {}
    if (!out) return [];

    const parsed = JSON.parse(out);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    const seen = new Set();

    const softwares = arr.map(s => {
      const nome = normalizarSoftwareNome(s.nome);
      const versao = String(s.versao || '').trim();
      const fabricante = String(s.fabricante || '').trim();
      const key = (nome + '|' + versao + '|' + fabricante).toLowerCase();
      if (!nome || seen.has(key)) return null;
      seen.add(key);
      return {
        nome,
        nomeLower: nome.toLowerCase(),
        versao,
        fabricante,
        dataInstalacao: String(s.dataInstalacao || '').trim(),
        localInstalacao: String(s.localInstalacao || '').trim().slice(0, 180),
        origem: String(s.origem || '').trim(),
      };
    }).filter(Boolean).slice(0, 1000);

    _softwareCache = { at: now, list: softwares };
    log('[Software] ' + softwares.length + ' programas inventariados');
    return softwares;
  } catch(e) {
    log('[Software] Erro ao coletar programas: ' + e.message);
    return _softwareCache.list || [];
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

    // Remove undefined/NaN antes de serializar
    function sanitize(obj) {
      if (obj === null || obj === undefined) return null;
      if (typeof obj === 'number' && !isFinite(obj)) return 0;
      if (Array.isArray(obj)) return obj.map(sanitize).filter(v => v !== undefined);
      if (typeof obj === 'object') {
        const r = {};
        for (const [k, v] of Object.entries(obj)) {
          if (v !== undefined) r[k] = sanitize(v);
        }
        return r;
      }
      return obj;
    }

    const fields = {};
    const cleanData = sanitize(data);
    for (const [k, v] of Object.entries(cleanData)) fields[k] = toFirestore(v);

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

function firestoreAddDoc(collectionPath, data) {
  return new Promise((resolve, reject) => {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${collectionPath}?key=${API_KEY}`;
    function toFirestore(val) {
      if (val === null || val === undefined) return { nullValue: null };
      if (typeof val === 'boolean')  return { booleanValue: val };
      if (typeof val === 'number' && isFinite(val)) return { doubleValue: val };
      if (typeof val === 'string')   return { stringValue: val };
      if (Array.isArray(val)) return { arrayValue: val.length ? { values: val.map(toFirestore) } : {} };
      if (typeof val === 'object') {
        const fields = {};
        for (const [k, v] of Object.entries(val)) if (v !== undefined) fields[k] = toFirestore(v);
        return { mapValue: { fields } };
      }
      return { stringValue: String(val) };
    }
    const fields = {};
    for (const [k, v] of Object.entries(data || {})) if (v !== undefined) fields[k] = toFirestore(v);
    const body = JSON.stringify({ fields });
    const urlObj = new URL(url);
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
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

function loginKeyDiario(login) {
  return String(login || '').trim().toLowerCase().replace(/^.*\\/, '').replace(/^.*\//, '').replace(/@.*$/, '') + '|' + new Date().toISOString().slice(0, 10);
}
let _ultimoLoginRegistradoKey = '';
async function registrarLoginAtivo(docId, dados) {
  try {
    const login = String(dados.usuarioLogado || '').trim();
    if (!login) return;
    const dia = new Date().toISOString().slice(0, 10);
    const key = `${docId}|${loginKeyDiario(login)}`;
    if (_ultimoLoginRegistradoKey === key) return;
    _ultimoLoginRegistradoKey = key;
    const item = {
      ativoId: docId,
      assetId: docId,
      hostname: AGENT_ID,
      computador: AGENT_ID,
      ip: dados.ip || '',
      login,
      loginNorm: login.toLowerCase().replace(/^.*\\/, '').replace(/^.*\//, '').replace(/@.*$/, ''),
      usuario: login,
      usuarioLogado: login,
      data: dados.lastSeen || new Date().toISOString(),
      dataLogin: dados.lastSeen || new Date().toISOString(),
      createdAt: dados.lastSeen || new Date().toISOString(),
      updatedAt: dados.lastSeen || new Date().toISOString(),
      timestamp: dados.lastSeen || new Date().toISOString(),
      ultimoLogin: dados.lastSeen || new Date().toISOString(),
      dia,
      origem: 'agent-desktop',
      tipo: 'login',
      versaoAgente: dados.versaoAgente || ''
    };
    await firestoreAddDoc(`ativos/${docId}/usuarios_historico`, item).catch(e => log('[LoginHist] usuarios_historico: ' + e.message));
    await firestoreAddDoc('login_history', item).catch(e => log('[LoginHist] login_history: ' + e.message));
  } catch(e) {
    log('[LoginHist] erro ao registrar login: ' + e.message);
  }
}

async function reportar() {
  try {
    const cpu    = getCpuUsage();
    const mem    = getMemoryInfo();
    const discos = getDiskInfo();
    const user   = getLoggedUser();
    const now    = new Date().toISOString();

    const discoC = discos.find(d => d.drive === 'C:') || null;
    const uptimeSec = getUptime();

    const hw  = getHardwareInfo();
    const sec = getSegurancaInfo();
    const software = getInstalledSoftware(false);

    const dados = {
      hostname:          AGENT_ID,
      fabricante:        hw.fabricante,
      modelo:            hw.modelo,
      serial:            hw.serial,
      cpuModelo:         hw.cpu,
      nucleos:           hw.nucleos,
      build:             hw.build,
      antivirus:         sec.antivirus,
      bitlocker:         sec.bitlocker,
      firewall:          sec.firewall,
      patches:           sec.patches,
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
      software:          software,
      softwareCount:     software.length,
      softwareAtualizadoEm: _softwareCache.at ? new Date(_softwareCache.at).toISOString() : now,
      versaoAgente:      '2.1.0',
      ultimaAtualizacao: now,
      lastSeen:          now,
      status:            'online',
      plataforma:        process.platform,
    };

    await firestoreSet(`agents/${AGENT_ID}`, dados);
    log(`[OK] Dados enviados - CPU: ${cpu}% | RAM: ${mem.pct}% | Usuario: ${user}`);
    // Atualiza o ativo correspondente a cada ciclo: hostname, sessão, inventário e métricas.
    atualizarAtivoComHostname(dados);
  } catch(e) {
    log(`[ERRO] ${e.message}`);
  }
}

// ── Inicialização ─────────────────────────────────────────────────
log(`[SYSACK Agent Desktop v2.1] Iniciando - hostname: ${AGENT_ID}`);
log(`[SYSACK Agent Desktop] Projeto Firebase: ${PROJECT_ID}`);
log(`[SYSACK Agent Desktop] Intervalo: ${INTERVAL / 1000}s`);


// ── Servidor WebSocket para sessão remota ─────────────────────────
const http = require('http');
const WS_PORT = 9000;

function iniciarServidorRemoto() {
  try {
    // Usa ws nativo sem dependência externa via upgrade do http
    const server = http.createServer();
    const clients = new Set();

    server.on('upgrade', (req, socket, head) => {
      // Handshake WebSocket manual
      const key = req.headers['sec-websocket-key'];
      if (!key) { socket.destroy(); return; }
      const crypto = require('crypto');
      const accept = crypto.createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        .digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
      );

      clients.add(socket);
      log('[WS] Cliente conectado — total: ' + clients.size);

      socket.on('data', buf => {
        try {
          // Decodifica frame WebSocket
          const fin = (buf[0] & 0x80) !== 0;
          const opcode = buf[0] & 0x0f;
          const masked = (buf[1] & 0x80) !== 0;
          let len = buf[1] & 0x7f;
          let offset = 2;
          if (len === 126) { len = buf.readUInt16BE(2); offset = 4; }
          const mask = masked ? buf.slice(offset, offset + 4) : null;
          offset += masked ? 4 : 0;
          const payload = buf.slice(offset, offset + len);
          if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
          
          if (opcode === 8) { socket.destroy(); return; } // close
          if (opcode !== 1) return; // só texto

          const msg = JSON.parse(payload.toString());
          handleRemoteCommand(msg, socket);
        } catch(e) {}
      });

      socket.on('close', () => { clients.delete(socket); });
      socket.on('error', () => { clients.delete(socket); });
    });

    server.listen(WS_PORT, '0.0.0.0', () => {
      log('[WS] Servidor remoto ativo na porta ' + WS_PORT);
    });

    server.on('error', e => log('[WS] Erro servidor: ' + e.message));
  } catch(e) {
    log('[WS] Falha ao iniciar servidor: ' + e.message);
  }
}

function wsSend(socket, data) {
  try {
    const str = JSON.stringify(data);
    const buf = Buffer.from(str);
    const frame = Buffer.allocUnsafe(2 + buf.length);
    frame[0] = 0x81; // FIN + text opcode
    frame[1] = buf.length;
    buf.copy(frame, 2);
    socket.write(frame);
  } catch(e) {}
}

function handleRemoteCommand(msg, socket) {
  const { type, cmd } = msg;
  
  if (type === 'ping') {
    wsSend(socket, { type: 'pong', ts: Date.now() });
    return;
  }
  
  if (type === 'info') {
    wsSend(socket, {
      type: 'info',
      hostname: AGENT_ID,
      ip: Object.values(os.networkInterfaces()).flat().find(n => n.family === 'IPv4' && !n.internal)?.address || '',
      cpu: getCpuUsage(),
      ram: getMemoryInfo().pct,
      uptime: getUptime(),
      user: getLoggedUser(),
    });
    return;
  }

  if (type === 'powershell' && cmd) {
    try {
      const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -Command "' + cmd.replace(/"/g, '\\"') + '"',
        { timeout: 15000, windowsHide: true }).toString();
      wsSend(socket, { type: 'output', data: out });
    } catch(e) {
      wsSend(socket, { type: 'output', data: '[ERRO] ' + e.message });
    }
    return;
  }

  if (type === 'screenshot') {
    try {
      // Captura tela via PowerShell
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms',
        '$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
        '$b = New-Object System.Drawing.Bitmap($s.Width, $s.Height)',
        '$g = [System.Drawing.Graphics]::FromImage($b)',
        '$g.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)',
        '$ms = New-Object System.IO.MemoryStream',
        '$b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg)',
        '[Convert]::ToBase64String($ms.ToArray())',
      ].join(';');
      const psFile = require('path').join(__dirname, '_sc.ps1');
      require('fs').writeFileSync(psFile, ps);
      const b64 = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
        { timeout: 20000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }).toString().trim();
      try { require('fs').unlinkSync(psFile); } catch(e) {}
      wsSend(socket, { type: 'screenshot', data: b64 });
    } catch(e) {
      wsSend(socket, { type: 'error', msg: e.message });
    }
    return;
  }
}

iniciarServidorRemoto();


// ── Relay Firestore — escuta comandos do técnico ──────────────────
async function firestoreQuery(collectionPath, filters) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = JSON.stringify({
    structuredQuery: {
      from: [{ collectionId: collectionPath }],
      where: {
        compositeFilter: {
          op: 'AND',
          filters: filters.map(([field, op, value]) => ({
            fieldFilter: { field: { fieldPath: field }, op, value: { stringValue: value } }
          }))
        }
      },
      limit: 10
    }
  });
  const urlObj = new URL(url);
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve(JSON.parse(raw)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function firestorePatch(docPath, data) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}`;
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    if (typeof v === 'string') fields[k] = { stringValue: v };
    else if (typeof v === 'number') fields[k] = { doubleValue: v };
    else if (typeof v === 'boolean') fields[k] = { booleanValue: v };
  }
  const body = JSON.stringify({ fields });
  const urlObj = new URL(url + '?' + Object.keys(data).map(k => 'updateMask.fieldPaths=' + k).join('&'));
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'PATCH',
      rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve(raw));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function executarComando(doc) {
  const fields = doc.document?.fields || {};
  const getId = f => f?.stringValue || '';
  const id       = doc.document?.name?.split('/').pop();
  const tipo     = getId(fields.tipo);
  const dados    = (() => { try { return JSON.parse(getId(fields.dados) || '{}'); } catch { return {}; } })();
  const agentId  = getId(fields.agentId);

  if (agentId !== AGENT_ID) return;

  // Marca como processando IMEDIATAMENTE para não processar duas vezes
  await firestorePatch('agent_commands/' + id, { status: 'processando' }).catch(() => {});

  // Verifica token de segurança
  const tokenRecebido = getId(fields.token);
  if (!tokenRecebido || tokenRecebido !== 'CESAN_SYSACK_3e295269119f7e67887d523a9ab607c9') {
    // Token inválido ou ausente (comando antigo) — descarta silenciosamente
    await firestorePatch('agent_commands/' + id, { status: 'descartado' }).catch(() => {});
    return;
  }

  log('[Relay] Comando recebido: ' + tipo);

  // Marca como processando
  await firestorePatch('agent_commands/' + id, { status: 'executando' }).catch(() => {});

  let resultado = '';
  try {
    if (tipo === 'iniciar_acesso_remoto' || tipo === 'usar_firebase_relay') {
      resultado = JSON.stringify({ ok: true, porta: 9000, hostname: AGENT_ID });

    } else if (tipo === 'powershell') {
      const cmd = dados.cmd || '';
      const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -Command "' + cmd.replace(/"/g, '\\"') + '"',
        { timeout: 15000, windowsHide: true }).toString();
      resultado = out;

    } else if (tipo === 'screenshot') {
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
        '$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
        '$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height)',
        '$g=[System.Drawing.Graphics]::FromImage($b)',
        '$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size)',
        '$ms=New-Object System.IO.MemoryStream',
        '$b.Save($ms,[System.Drawing.Imaging.ImageFormat]::Jpeg)',
        '[Convert]::ToBase64String($ms.ToArray())',
      ].join(';');
      const psFile = path.join(__dirname, '_sc.ps1');
      fs.writeFileSync(psFile, ps);
      resultado = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
        { timeout: 20000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }).toString().trim();
      try { fs.unlinkSync(psFile); } catch(e) {}

    } else if (tipo === 'encerrar_acesso_remoto') {
      resultado = 'ok';
    } else {
      resultado = 'tipo desconhecido: ' + tipo;
    }
  } catch(e) {
    resultado = '[ERRO] ' + e.message;
  }

  // Grava resultado de volta
  const sessaoId = dados.sessaoId || '';
  if (sessaoId) {
    await firestorePatch('sessoes_remotas/' + sessaoId + '/relay/resposta', {
      resultado, tipo, ts: new Date().toISOString(), agentId: AGENT_ID
    }).catch(() => {});
  }
  await firestorePatch('agent_commands/' + id, { status: 'concluido', resultado: resultado.slice(0, 500) }).catch(() => {});
}

// Poll de comandos a cada 3 segundos
async function pollComandos() {
  try {
    const docs = await firestoreQuery('agent_commands', [
      ['agentId', 'EQUAL', AGENT_ID],
      ['status', 'EQUAL', 'pendente']
    ]);
    if (Array.isArray(docs)) {
      for (const doc of docs) {
        if (doc.document) await executarComando(doc);
      }
    }
  } catch(e) {}
}

setInterval(pollComandos, 3000);


// ── Atualiza ativo correspondente com hostname ────────────────────
async function atualizarAtivoComHostname(dados) {
  try {
    const ip = dados.ip;
    if (!ip) return;

    // Busca ativo pelo IP no Firestore
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
    const body = JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: 'ativos' }],
        where: {
          compositeFilter: {
            op: 'AND',
            filters: [
              { fieldFilter: { field: { fieldPath: 'ip' }, op: 'EQUAL', value: { stringValue: ip } } }
            ]
          }
        },
        limit: 1
      }
    });

    const urlObj = new URL(url);
    const result = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path: urlObj.pathname,
        method: 'POST',
        rejectUnauthorized: false,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => resolve(JSON.parse(raw)));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });

    if (!Array.isArray(result) || !result[0]?.document) return;

    const doc = result[0].document;
    const docId = doc.name.split('/').pop();
    const ativoHostname = doc.fields?.hostname?.stringValue || '';

    // Atualiza sempre: mesmo com hostname igual, sessão, usuário e métricas mudam a cada ciclo.

    await firestorePatch(`ativos/${docId}`, {
      hostname:          AGENT_ID,
      ip:                ip,
      status:            'em-uso',
      ultimoAgente:      new Date().toISOString(),
      lastSeen:          dados.lastSeen,
      usuarioLogado:     dados.usuarioLogado || '',
      usuarioPrincipal:  dados.usuarioLogado || '',
      usuarioPrincipalLogin: dados.usuarioLogado || '',
      ultimoLoginUsuario:dados.usuarioLogado || '',
      ultimoLoginEm:     dados.lastSeen,
      osNome:            dados.osNome || dados.so || '',
      so:                dados.so || dados.osNome || '',
      fabricante:        dados.fabricante || '',
      modelo:            dados.modelo || '',
      serial:            dados.serial || '',
      cpuModelo:         dados.cpuModelo || '',
      nucleos:           dados.nucleos || '',
      ramTotalGB:        dados.ramTotalGB ?? null,
      ramUsadoGB:        dados.ramUsadoGB ?? null,
      ramPct:            dados.ramPct ?? null,
      memPct:            dados.memPct ?? null,
      discoC_livreGB:    dados.discoC_livreGB ?? null,
      discoC_totalGB:    dados.discoC_totalGB ?? null,
      discoC_usadoPct:   dados.discoC_usadoPct ?? null,
      antivirus:         dados.antivirus || '',
      bitlocker:         dados.bitlocker || '',
      firewall:          dados.firewall || '',
      patches:           dados.patches ?? null,
      monitores:         dados.monitores || [],
      versaoAgente:      dados.versaoAgente || '',
      plataforma:        dados.plataforma || '',
      uptimeH:           dados.uptimeH ?? null,
    });

    await registrarLoginAtivo(docId, dados);
    log(`[OK] Ativo ${docId} atualizado com hostname: ${AGENT_ID}`);
  } catch(e) {
    // Silencioso — não crítico
  }
}


// ── Cloudflare Tunnel — acesso remoto seguro ─────────────────────
const { spawn } = require('child_process');
const CLOUDFLARED_PATH = path.join(__dirname, 'cloudflared.exe');
const CLOUDFLARED_URL  = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe';

// ─── Credenciais do proxy CESAN ───────────────────────────────
// Buscadas do Firestore em sysack_config/proxy (documento global, um só lugar).
// Fallback: config.json local ou variável de ambiente.
// Para configurar centralmente, salve no Firestore:
//   coleção: sysack_config  documento: proxy
//   campos: user (string), pass (string)
let PROXY_USER = cfg.proxyUser || process.env.PROXY_USER || '';
let PROXY_PASS = cfg.proxyPass || process.env.PROXY_PASS || '';
let PROXY_URL  = 'http://proxy.sistemas.cesan.com.br:8080';

async function carregarCredenciaisProxy() {
  // Tenta buscar do Firestore (sem autenticação — documento público de config)
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/sysack_config/proxy?key=${API_KEY}`;
  return new Promise(resolve => {
    const req = https.request(url, { method: 'GET', rejectUnauthorized: false }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try {
          const doc = JSON.parse(raw);
          const u = doc.fields?.user?.stringValue || '';
          const p = doc.fields?.pass?.stringValue || '';
          if (u && p) {
            PROXY_USER = u;
            PROXY_PASS = p;
            log('[Proxy] Credenciais carregadas do Firestore');
          }
        } catch { /* usa fallback */ }
        // Monta URL com ou sem credenciais
        PROXY_URL = PROXY_USER
          ? `http://${encodeURIComponent(PROXY_USER)}:${encodeURIComponent(PROXY_PASS)}@proxy.sistemas.cesan.com.br:8080`
          : 'http://proxy.sistemas.cesan.com.br:8080';
        resolve();
      });
    });
    req.on('error', () => resolve()); // sem rede — usa fallback
    req.end();
  });
}

async function baixarCloudflared() {
  if (fs.existsSync(CLOUDFLARED_PATH)) return true;
  log('[Tunnel] Baixando cloudflared...');
  return new Promise((resolve) => {
    const file = fs.createWriteStream(CLOUDFLARED_PATH);
    const PROXY_HOST = 'proxy.sistemas.cesan.com.br';
    const PROXY_PORT = 8080;
    const download = (url, redirects = 0) => {
      if (redirects > 5) { resolve(false); return; }
      const urlObj = new URL(url);
      // Download via proxy CESAN
      const req = require('http').request({
        host: PROXY_HOST, port: PROXY_PORT, method: 'GET',
        path: url, rejectUnauthorized: false,
        headers: {
          Host: urlObj.hostname,
          ...(PROXY_USER ? { 'Proxy-Authorization': 'Basic ' + Buffer.from(PROXY_USER + ':' + PROXY_PASS).toString('base64') } : {}),
        }
      }, res => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          download(res.headers.location, redirects + 1); return;
        }
        if (res.statusCode === 301 || res.statusCode === 302) {
          download(res.headers.location, redirects + 1);
          return;
        }
        res.pipe(file);
        file.on('finish', () => { file.close(); resolve(true); });
        file.on('error', () => resolve(false));
      }).on('error', () => resolve(false));
    };
    download(CLOUDFLARED_URL);
  });
}

async function iniciarTunnel() {
  try {
    // Carrega credenciais do proxy do Firestore antes de tentar o tunnel
    await carregarCredenciaisProxy();
    const ok = await baixarCloudflared();
    if (!ok) { log('[Tunnel] Falha ao baixar cloudflared'); return; }

    log('[Tunnel] Iniciando tunnel Cloudflare...');

    const proc = spawn(CLOUDFLARED_PATH, [
      'tunnel', '--url', 'ws://localhost:9000',
      '--no-autoupdate',
      '--logfile', path.join(__dirname, 'cloudflared.log'),
    ], {
      windowsHide: true,
      detached: false,
      env: {
        ...process.env,
        HTTPS_PROXY: PROXY_URL,
        HTTP_PROXY:  PROXY_URL,
        NO_PROXY:    'localhost,127.0.0.1,172.23.*,10.*,192.168.*',
      }
    });

    let tunnelUrl = null;

    proc.stderr.on('data', async data => {
      const txt = data.toString();
      // Cloudflared imprime a URL no stderr
      const match = txt.match(/https:\/\/[a-z0-9\-]+\.trycloudflare\.com/);
      if (match && !tunnelUrl) {
        tunnelUrl = match[0].replace('https://', 'wss://');
        log('[Tunnel] URL gerada: ' + tunnelUrl);

        // Grava no Firestore para o app ler (merge — não apaga outros campos)
        await firestorePatch('agents/' + AGENT_ID, { tunnelUrl, tunnelAtivo: true });
        log('[Tunnel] URL gravada no Firestore');
      }
    });

    proc.on('close', async code => {
      log('[Tunnel] Processo encerrado — código: ' + code + (code===1?' (provável bloqueio de rede/proxy)':''));
      tunnelUrl = null;
      try { await firestorePatch('agents/' + AGENT_ID, { tunnelUrl: '', tunnelAtivo: false }); } catch(e) {}
      // Reinicia após 60s se encerrou com erro
      const delay = code === 0 ? 5000 : 60000;
      setTimeout(iniciarTunnel, delay);
    });

    proc.on('error', e => log('[Tunnel] Erro: ' + e.message));

  } catch(e) {
    log('[Tunnel] Falha: ' + e.message);
  }
}

iniciarTunnel();


// ── Monitor SNMP de Impressoras ───────────────────────────────────
const dgram = require('dgram');

// OIDs padrão para impressoras (RFC 3805 / Printer MIB)
const PRINTER_OIDS = {
  nome:           '1.3.6.1.2.1.1.5.0',           // sysName
  descricao:      '1.3.6.1.2.1.1.1.0',           // sysDescr
  uptime:         '1.3.6.1.2.1.1.3.0',           // sysUpTime
  status:         '1.3.6.1.2.1.25.3.2.1.5.1',   // hrDeviceStatus (2=ok,3=warning,4=error)
  paginasTotal:   '1.3.6.1.2.1.43.10.2.1.4.1.1', // prtMarkerLifeCount
  // Suprimentos (toner/papel) — índices variam por modelo
  suprimento0pct: '1.3.6.1.2.1.43.11.1.1.9.1.1', // prtMarkerSuppliesLevel[1]
  suprimento1pct: '1.3.6.1.2.1.43.11.1.1.9.1.2', // prtMarkerSuppliesLevel[2]
  suprimento2pct: '1.3.6.1.2.1.43.11.1.1.9.1.3', // prtMarkerSuppliesLevel[3]
  suprimento3pct: '1.3.6.1.2.1.43.11.1.1.9.1.4', // prtMarkerSuppliesLevel[4]
  suprimento0max: '1.3.6.1.2.1.43.11.1.1.8.1.1', // prtMarkerSuppliesMaxCapacity[1]
  suprimento1max: '1.3.6.1.2.1.43.11.1.1.8.1.2',
  suprimento2max: '1.3.6.1.2.1.43.11.1.1.8.1.3',
  suprimento3max: '1.3.6.1.2.1.43.11.1.1.8.1.4',
  suprimento0nome:'1.3.6.1.2.1.43.12.1.1.4.1.1', // prtMarkerColorantValue[1]
  suprimento1nome:'1.3.6.1.2.1.43.12.1.1.4.1.2',
  suprimento2nome:'1.3.6.1.2.1.43.12.1.1.4.1.3',
  suprimento3nome:'1.3.6.1.2.1.43.12.1.1.4.1.4',
  // Bandejas de papel
  bandeja0status: '1.3.6.1.2.1.43.8.2.1.10.1.1', // prtInputCurrentLevel[1]
  bandeja0max:    '1.3.6.1.2.1.43.8.2.1.9.1.1',  // prtInputMaxCapacity[1]
  bandeja1status: '1.3.6.1.2.1.43.8.2.1.10.1.2',
  bandeja1max:    '1.3.6.1.2.1.43.8.2.1.9.1.2',
  erros:          '1.3.6.1.2.1.43.18.1.1.8.1.1', // prtAlertDescription
};

function encodeOID(oid) {
  const parts = oid.split('.').map(Number);
  const encoded = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    const v = parts[i];
    if (v < 128) { encoded.push(v); }
    else {
      const bytes = [];
      let n = v;
      while (n > 0) { bytes.unshift(n & 0x7f); n >>= 7; }
      for (let j = 0; j < bytes.length - 1; j++) bytes[j] |= 0x80;
      encoded.push(...bytes);
    }
  }
  return Buffer.from([0x06, encoded.length, ...encoded]);
}

function buildSNMPGet(oids, community = 'public', reqId = 1) {
  const oidBuffers = oids.map(oid => {
    const enc = encodeOID(oid);
    return Buffer.from([0x30, enc.length + 4, 0x06, ...enc.slice(1), 0x05, 0x00]);
  });

  // Cada VarBind: SEQUENCE { OID, NULL }
  const varBinds = oids.map(oid => {
    const oidEnc = encodeOID(oid);
    const nullVal = Buffer.from([0x05, 0x00]);
    const inner = Buffer.concat([oidEnc, nullVal]);
    return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
  });

  const varBindList = Buffer.concat(varBinds);
  const varBindListSeq = Buffer.concat([Buffer.from([0x30, varBindList.length]), varBindList]);

  const comm = Buffer.from(community);
  const commTlv = Buffer.concat([Buffer.from([0x04, comm.length]), comm]);

  const version = Buffer.from([0x02, 0x01, 0x00]); // v1
  const reqIdBuf = Buffer.from([0x02, 0x04,
    (reqId >> 24) & 0xff, (reqId >> 16) & 0xff, (reqId >> 8) & 0xff, reqId & 0xff]);
  const errStatus = Buffer.from([0x02, 0x01, 0x00]);
  const errIndex  = Buffer.from([0x02, 0x01, 0x00]);

  const pdu = Buffer.concat([reqIdBuf, errStatus, errIndex, varBindListSeq]);
  const pduSeq = Buffer.concat([Buffer.from([0xa0, pdu.length]), pdu]); // GetRequest

  const msg = Buffer.concat([version, commTlv, pduSeq]);
  return Buffer.concat([Buffer.from([0x30, msg.length]), msg]);
}

function parseSNMPResponse(buf) {
  const results = {};
  try {
    // Navega até o VarBindList
    let pos = 0;
    if (buf[pos++] !== 0x30) return results; // SEQUENCE
    pos += buf[pos] < 128 ? 1 : (buf[pos] & 0x7f) + 1;

    // version
    pos += 2 + buf[pos + 1];
    // community
    pos += 2 + buf[pos + 1];
    // GetResponse PDU (0xa2)
    if (buf[pos++] !== 0xa2) return results;
    pos += buf[pos] < 128 ? 1 : (buf[pos] & 0x7f) + 1;
    // reqId, errStatus, errIndex
    pos += 2 + buf[pos + 1]; // reqId
    pos += 2 + buf[pos + 1]; // errStatus
    pos += 2 + buf[pos + 1]; // errIndex
    // VarBindList SEQUENCE
    if (buf[pos++] !== 0x30) return results;
    pos += buf[pos] < 128 ? 1 : (buf[pos] & 0x7f) + 1;

    while (pos < buf.length) {
      if (buf[pos++] !== 0x30) break;
      pos += buf[pos] < 128 ? 1 : (buf[pos] & 0x7f) + 1;
      // OID
      if (buf[pos++] !== 0x06) break;
      const oidLen = buf[pos++];
      const oidBytes = buf.slice(pos, pos + oidLen);
      pos += oidLen;
      // Decodifica OID
      const oidParts = [Math.floor(oidBytes[0] / 40), oidBytes[0] % 40];
      for (let i = 1; i < oidBytes.length; i++) {
        if (oidBytes[i] & 0x80) {
          let val = 0;
          while (oidBytes[i] & 0x80) val = (val << 7) | (oidBytes[i++] & 0x7f);
          val = (val << 7) | oidBytes[i];
          oidParts.push(val);
        } else {
          oidParts.push(oidBytes[i]);
        }
      }
      const oidStr = oidParts.join('.');

      // Valor
      const valType = buf[pos++];
      const valLen  = buf[pos++];
      const valBytes = buf.slice(pos, pos + valLen);
      pos += valLen;

      let value = null;
      if (valType === 0x02 || valType === 0x41 || valType === 0x42 || valType === 0x43) {
        // Integer, Counter32, Gauge32, TimeTicks
        value = valBytes.reduce((a, b) => (a << 8) | b, 0);
      } else if (valType === 0x04) {
        // OctetString
        value = valBytes.toString('utf8').replace(/\x00/g, '').trim();
      } else if (valType === 0x05) {
        value = null; // NULL
      } else {
        value = valBytes.toString('hex');
      }
      results[oidStr] = value;
    }
  } catch(e) {}
  return results;
}

function snmpGet(ip, oids, community = 'public', timeout = 3000) {
  return new Promise(resolve => {
    const sock = dgram.createSocket('udp4');
    const reqId = Math.floor(Math.random() * 0xFFFF);
    const pkt = buildSNMPGet(oids, community, reqId);
    let done = false;

    const tid = setTimeout(() => {
      if (!done) { done = true; sock.close(); resolve(null); }
    }, timeout);

    sock.on('message', buf => {
      if (!done) {
        done = true;
        clearTimeout(tid);
        sock.close();
        resolve(parseSNMPResponse(buf));
      }
    });

    sock.on('error', () => { if (!done) { done = true; resolve(null); } });
    sock.send(pkt, 0, pkt.length, 161, ip, err => {
      if (err && !done) { done = true; resolve(null); }
    });
  });
}

async function monitorarImpressoras() {
  try {
    // Busca lista de impressoras do Firestore
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/impressoras?pageSize=200`;
    const urlObj = new URL(url);
    const docs = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        rejectUnauthorized: false,
      }, res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => {
          try { resolve(JSON.parse(raw).documents || []); }
          catch(e) { resolve([]); }
        });
      });
      req.on('error', reject);
      req.end();
    });

    for (const doc of docs) {
      const f = doc.fields || {};
      const ip = f.ip?.stringValue || f.ipAddress?.stringValue;
      if (!ip) continue;
      const docId = doc.name.split('/').pop();

      // Coleta via SNMP
      const oidList = Object.values(PRINTER_OIDS);
      const resp = await snmpGet(ip, oidList);
      if (!resp) continue; // impressora não respondeu

      // Mapeia OIDs para campos legíveis
      const get = key => resp[PRINTER_OIDS[key]];

      const statusCode = get('status');
      const status = statusCode === 2 ? 'ok' : statusCode === 3 ? 'alerta' : statusCode === 4 ? 'critico' : 'ok';

      // Calcula % de suprimentos
      const calcPct = (nivel, max) => {
        if (nivel == null || max == null || max <= 0) return null;
        if (nivel === -3) return 100; // sem restrição
        return Math.max(0, Math.round((nivel / max) * 100));
      };

      const suprimentos = [];
      for (let i = 0; i < 4; i++) {
        const nivel = get(`suprimento${i}pct`);
        const max   = get(`suprimento${i}max`);
        const nome  = get(`suprimento${i}nome`) || `Suprimento ${i+1}`;
        const pct   = calcPct(nivel, max);
        if (pct !== null) suprimentos.push({ nome, pct });
      }

      const bandejas = [];
      for (let i = 0; i < 2; i++) {
        const nivel = get(`bandeja${i}status`);
        const max   = get(`bandeja${i}max`);
        const pct   = calcPct(nivel, max);
        if (pct !== null) bandejas.push({ bandeja: i + 1, pct });
      }

      const tonerMin = suprimentos.length > 0
        ? Math.min(...suprimentos.map(s => s.pct))
        : null;

      const papelMin = bandejas.length > 0
        ? Math.min(...bandejas.map(b => b.pct))
        : null;

      const dados = {
        status,
        statusLegivel:  status === 'ok' ? 'Online' : status === 'alerta' ? 'Atenção' : 'Erro',
        paginasTotal:   get('paginasTotal') || 0,
        suprimentos:    JSON.stringify(suprimentos),
        bandejas:       JSON.stringify(bandejas),
        tonerMin:       tonerMin,
        papelMin:       papelMin,
        ultimoSnmp:     new Date().toISOString(),
        snmpOnline:     true,
      };

      await firestoreSet(`impressoras/${docId}`, dados);
    }
    log(`[SNMP] ${docs.length} impressoras verificadas`);
  } catch(e) {
    log('[SNMP] Erro: ' + e.message);
  }
}

// Roda 2 minutos após iniciar e depois a cada 5 minutos
setTimeout(monitorarImpressoras, 2 * 60 * 1000);
setInterval(monitorarImpressoras, 5 * 60 * 1000);


// ── Impressoras locais via WMI ────────────────────────────────────
async function coletarImpressorasLocais() {
  try {
    if (process.platform !== 'win32') return;

    const ps = [
      '$printers = Get-WmiObject -Class Win32_Printer -EA SilentlyContinue',
      'foreach ($p in $printers) {',
      '  $jobs = (Get-WmiObject -Class Win32_PrintJob -EA SilentlyContinue | Where-Object {$_.Name -like ($p.Name + "*")}).Count',
      '  $status = switch ($p.PrinterStatus) {',
      '    1 {"outro"} 2 {"desconhecida"} 3 {"pronta"} 4 {"impresssando"}',
      '    5 {"aquecendo"} 6 {"parada"} 7 {"offline"} default {"desconhecida"}',
      '  }',
      '  Write-Output ("NOME=" + $p.Name + "|STATUS=" + $status + "|REDE=" + $p.Network + "|DEFAULT=" + $p.Default + "|JOBS=" + $jobs + "|PORT=" + $p.PortName)',
      '}',
    ].join("\n");

    const psFile = path.join(__dirname, '_printers.ps1');
    fs.writeFileSync(psFile, ps, 'utf8');
    const out = execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}"`,
      { timeout: 15000, windowsHide: true }).toString();
    try { fs.unlinkSync(psFile); } catch(e) {}

    const impressoras = [];
    for (const line of out.split('\n')) {
      if (!line.includes('NOME=')) continue;
      const get = key => (line.match(new RegExp(key + '=([^|\r\n]*)')) || [])[1]?.trim() || '';
      const nome   = get('NOME');
      const status = get('STATUS');
      const rede   = get('REDE') === 'True';
      const def    = get('DEFAULT') === 'True';
      const jobs   = parseInt(get('JOBS')) || 0;
      const porta  = get('PORT');
      if (!nome || nome.includes('Microsoft') || nome.includes('PDF') || nome.includes('XPS') || nome.includes('OneNote') || nome.includes('Fax')) continue;
      impressoras.push({ nome, status, rede, default: def, jobsNaFila: jobs, porta });
    }

    if (!impressoras.length) return;

    // Grava no documento do agente
    await firestoreSet(`agents/${AGENT_ID}`, {
      impressorasLocais: JSON.stringify(impressoras),
      impressorasCount: impressoras.length,
    });

    // Grava também na coleção impressoras para cada uma
    for (const imp of impressoras) {
      const impId = AGENT_ID + '_' + imp.nome.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30);
      const online = ['pronta','imprimindo','outro'].includes(imp.status);
      await firestoreSet(`impressoras/${impId}`, {
        nome:         imp.nome,
        hostname:     AGENT_ID,
        tipo:         imp.rede ? 'rede' : 'usb',
        status:       online ? 'ok' : imp.status === 'offline' ? 'critico' : 'alerta',
        statusLegivel: imp.status,
        jobsNaFila:   imp.jobsNaFila,
        isDefault:    imp.default,
        porta:        imp.porta,
        ultimoCheck:  new Date().toISOString(),
        fonte:        'agente-wmi',
      });
    }

    log(`[WMI] ${impressoras.length} impressoras locais coletadas`);
  } catch(e) {
    log('[WMI] Impressoras erro: ' + e.message);
  }
}

// Roda 3 minutos após iniciar e depois a cada 10 minutos
setTimeout(coletarImpressorasLocais, 3 * 60 * 1000);
setInterval(coletarImpressorasLocais, 10 * 60 * 1000);


// ── Coleta VLANs dos switches via SNMP ───────────────────────────
async function coletarVLANs() {
  try {
    // Busca switches do Firestore
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/switches?pageSize=100`;
    const urlObj = new URL(url);
    const docs = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        rejectUnauthorized: false,
      }, res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => { try { resolve(JSON.parse(raw).documents || []); } catch(e) { resolve([]); } });
      });
      req.on('error', reject);
      req.end();
    });

    for (const doc of docs) {
      const f = doc.fields || {};
      const ip        = f.ip?.stringValue;
      const community = f.snmpCommunity?.stringValue || 'public';
      if (!ip) continue;
      const docId = doc.name.split('/').pop();

      // OIDs de VLAN — tenta padrão 802.1Q e HP ProCurve proprietário
      const VLAN_OIDS_STD = [
        '1.3.6.1.2.1.17.7.1.4.3.1.1.1',   // dot1qVlanStaticName VLAN 1
        '1.3.6.1.2.1.17.7.1.4.3.1.1.2',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.10',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.20',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.30',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.100',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.200',
        '1.3.6.1.2.1.17.7.1.4.3.1.1.999',
      ];
      // HP ProCurve OIDs
      const VLAN_OIDS_HP = [
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.1',  // hpSwitchVlanName VLAN 1
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.2',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.10',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.20',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.30',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.100',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.200',
        '1.3.6.1.4.1.11.2.14.11.5.1.7.1.3.1.1.999',
      ];

      // Detecta se é HP pelo sysOid
      const sysOid = f.sysOid?.stringValue || '';
      const isHP = sysOid.startsWith('1.3.6.1.4.1.11');
      const oidList = isHP ? VLAN_OIDS_HP : VLAN_OIDS_STD;

      let resp = await snmpGet(ip, oidList, community, 4000);
      // Se não retornou nada, tenta o outro padrão
      const hasData = resp && Object.values(resp).some(v => v && v !== 'NULL');
      if (!hasData) resp = await snmpGet(ip, isHP ? VLAN_OIDS_STD : VLAN_OIDS_HP, community, 4000);

      if (!resp) continue;

      const vlans = [];
      for (const [oid, val] of Object.entries(resp)) {
        if (!val || val === 'NULL') continue;
        const id = parseInt(oid.split('.').pop());
        if (isNaN(id) || id === 0) continue;
        vlans.push({ id, nome: String(val).trim() });
      }

      if (vlans.length) {
        await firestoreSet(`switches/${docId}`, {
          vlans: JSON.stringify(vlans),
          vlansAtualizadoEm: new Date().toISOString(),
        });
      }
    }
    log(`[SNMP] VLANs coletadas de ${docs.length} switches`);
  } catch(e) {
    log('[SNMP] VLANs erro: ' + e.message);
  }
}

// Roda 4 minutos após iniciar e depois a cada 30 minutos
setTimeout(coletarVLANs, 4 * 60 * 1000);
setInterval(coletarVLANs, 30 * 60 * 1000);

// ── Coleta mapa de portas dos switches via SNMP ───────────────────
async function coletarPortasSwitches() {
  try {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/switches?pageSize=100`;
    const urlObj = new URL(url);
    const docs = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'GET', rejectUnauthorized: false,
      }, res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => { try { resolve(JSON.parse(raw).documents || []); } catch(e) { resolve([]); } });
      });
      req.on('error', reject);
      req.end();
    });

    for (const doc of docs) {
      const f = doc.fields || {};
      const ip        = f.ip?.stringValue;
      const community = f.snmpCommunity?.stringValue || 'public';
      if (!ip) continue;
      const docId = doc.name.split('/').pop();

      // OIDs de interface
      const IF_OIDS = [];
      for (let i = 1; i <= 48; i++) {
        IF_OIDS.push('1.3.6.1.2.1.2.2.1.8.'  + i); // ifOperStatus (1=up, 2=down)
        IF_OIDS.push('1.3.6.1.2.1.2.2.1.2.'  + i); // ifDescr (nome da porta)
        IF_OIDS.push('1.3.6.1.2.1.31.1.1.1.18.' + i); // ifAlias (descrição)
      }

      const resp = await snmpGet(ip, IF_OIDS, community, 5000);
      if (!resp) continue;

      const portas = [];
      for (let i = 1; i <= 48; i++) {
        const status = resp['1.3.6.1.2.1.2.2.1.8.'  + i];
        const nome   = resp['1.3.6.1.2.1.2.2.1.2.'  + i];
        const alias  = resp['1.3.6.1.2.1.31.1.1.1.18.' + i];
        if (status == null) continue;
        portas.push({
          porta: i,
          status: status === 1 ? 'up' : 'down',
          nome:  String(nome||'').trim(),
          alias: String(alias||'').trim(),
        });
      }

      if (portas.length) {
        const portasUp   = portas.filter(p => p.status === 'up').length;
        const portasDown = portas.filter(p => p.status === 'down').length;
        await firestoreSet(`switches/${docId}`, {
          portasMap:       JSON.stringify(portas),
          portasUso:       portasUp,
          portasLivres:    portasDown,
          totalPortas:     portas.length,
          portasAtualizadoEm: new Date().toISOString(),
        });
        log(`[SNMP] Switch ${ip}: ${portasUp}/${portas.length} portas ativas`);
      }
    }
  } catch(e) {
    log('[SNMP] Portas erro: ' + e.message);
  }
}

// Roda 5 minutos após iniciar e depois a cada 15 minutos
setTimeout(coletarPortasSwitches, 5 * 60 * 1000);
setInterval(coletarPortasSwitches, 15 * 60 * 1000);


reportar(); // Primeira execução imediata
setInterval(reportar, INTERVAL);

// Mantém o processo vivo
process.on('uncaughtException', err => log(`[UNCAUGHT] ${err.message}`));
process.on('unhandledRejection', err => log(`[UNHANDLED] ${err}`));
