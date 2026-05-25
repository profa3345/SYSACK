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

    const hw  = getHardwareInfo();
    const sec = getSegurancaInfo();

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
      versaoAgente:      '2.0.0',
      ultimaAtualizacao: now,
      lastSeen:          now,
      status:            'online',
      plataforma:        process.platform,
    };

    await firestoreSet(`agents/${AGENT_ID}`, dados);
    log(`[OK] Dados enviados - CPU: ${cpu}% | RAM: ${mem.pct}% | Usuario: ${user}`);
    // Atualiza ativo correspondente com hostname (roda apenas uma vez por sessão)
    if (!global._ativoAtualizado) {
      global._ativoAtualizado = true;
      atualizarAtivoComHostname(dados);
    }
  } catch(e) {
    log(`[ERRO] ${e.message}`);
  }
}

// ── Inicialização ─────────────────────────────────────────────────
log(`[SYSACK Agent Desktop] Iniciando - hostname: ${AGENT_ID}`);
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

  // Verifica token de segurança
  const tokenRecebido = getId(fields.token);
  if (tokenRecebido !== 'CESAN_SYSACK_3e295269119f7e67887d523a9ab607c9') {
    log('[Relay] SEGURANÇA: comando rejeitado — token inválido');
    await firestorePatch('agent_commands/' + id, { status: 'rejeitado' }).catch(() => {});
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

    // Só atualiza se o hostname estiver vazio ou diferente
    if (ativoHostname === AGENT_ID) return;

    await firestorePatch(`ativos/${docId}`, {
      hostname:     AGENT_ID,
      ip:           ip,
      status:       'em-uso',
      ultimoAgente: new Date().toISOString(),
    });

    log(`[OK] Ativo ${docId} atualizado com hostname: ${AGENT_ID}`);
  } catch(e) {
    // Silencioso — não crítico
  }
}

reportar(); // Primeira execução imediata
setInterval(reportar, INTERVAL);

// Mantém o processo vivo
process.on('uncaughtException', err => log(`[UNCAUGHT] ${err.message}`));
process.on('unhandledRejection', err => log(`[UNHANDLED] ${err}`));
