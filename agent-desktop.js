/**
 * SYSACK Agent Desktop v2.2.2
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
let _fsErrosConsecutivos = 0; // contador de falhas consecutivas no Firestore
let TUNNEL_TOKEN = cfg.tunnelToken || process.env.TUNNEL_TOKEN || '';
const SOFTWARE_INTERVAL = (cfg.softwareIntervalHours || 6) * 60 * 60 * 1000;
let _softwareCache = { at: 0, list: [] };


// ── Segurança corporativa para comandos administrativos ──────────────
// Não há senha compartilhada no código. O agente deve ser instalado/rodar como
// serviço Windows com conta de serviço AD de menor privilégio OU LocalSystem.
// Exemplo recomendado no AD: CESAN\svc-sysack-agent com permissão local apenas
// nas estações-alvo, sem logon interativo, com rotação de senha/gMSA se possível.
const ADMIN_COMMANDS = new Set([
  'bloquear_maquina',
  'desbloquear_maquina',
  'atualizar_agente',
  'powershell',
  'coletar_eventviewer',
  'analisar_eventviewer_ia',
  'instalar_software'
]);
const ALLOWED_COMMANDS = new Set([
  'iniciar_acesso_remoto',
  'usar_firebase_relay',
  'encerrar_acesso_remoto',
  ...ADMIN_COMMANDS
]);

function isWindowsAdminContext() {
  if (process.platform !== 'win32') return process.getuid && process.getuid() === 0;
  try {
    const who = execSync('whoami', { timeout: 3000, windowsHide: true }).toString().toUpperCase().trim();
    if (who.includes('SYSTEM')) return true;
  } catch(e) {}
  try {
    const who2 = execSync('whoami /user', { timeout: 3000, windowsHide: true }).toString().toUpperCase();
    if (who2.includes('S-1-5-18') || who2.includes('SYSTEM')) return true;
  } catch(e) {}
  try {
    execSync('net session', { stdio: 'ignore', timeout: 3000, windowsHide: true });
    return true;
  } catch(e) { return false; }
}

function parseFirestoreBool(f) { return !!(f && f.booleanValue === true); }
function parseFirestoreDate(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}
function sanitizeAuditText(v) {
  return String(v || '').replace(/[\r\n\t]+/g, ' ').slice(0, 500);
}

async function firestoreCreate(collectionPath, data) {
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    if (v === null || v === undefined) continue;
    if (typeof v === 'string') fields[k] = { stringValue: v };
    else if (typeof v === 'number') fields[k] = { doubleValue: v };
    else if (typeof v === 'boolean') fields[k] = { booleanValue: v };
    else fields[k] = { stringValue: JSON.stringify(v) };
  }
  const body = JSON.stringify({ fields });
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${collectionPath}?key=${API_KEY}`;
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
      res.on('end', () => resolve(raw));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function auditAgentCommand(commandId, action, details = {}) {
  const entry = {
    action,
    module: 'agent-desktop',
    resourceId: AGENT_ID,
    resourceType: 'agent',
    commandId: commandId || '',
    hostname: os.hostname(),
    agentId: AGENT_ID,
    serviceContextAdmin: isWindowsAdminContext(),
    createdAt: new Date().toISOString(),
    ...details
  };
  try { await firestoreCreate('audit_logs', entry); } catch(e) { log('[AUDIT] Falha Firestore: ' + e.message); }
  try { fs.appendFileSync(path.join(__dirname, 'audit.log'), JSON.stringify(entry) + '\n', 'utf8'); } catch(e) {}
}


async function reportAgentResult(commandId, tipo, status, resultado, extra = {}) {
  const entry = {
    commandId: commandId || '',
    tipo: tipo || '',
    status: status || '',
    resultado: String(resultado || '').slice(0, 2000),
    hostname: os.hostname(),
    agentId: AGENT_ID,
    serviceContextAdmin: isWindowsAdminContext(),
    createdAt: new Date().toISOString(),
    ...extra
  };
  try { await firestoreCreate('agent_results', entry); } catch(e) { log('[AGENT_RESULT] Falha Firestore: ' + e.message); }
}

async function validarComandoSeguro(id, tipo, fields, dados) {
  if (!ALLOWED_COMMANDS.has(tipo)) {
    await auditAgentCommand(id, 'AGENT_COMMAND_REJECTED', { tipo, motivo: 'tipo_nao_permitido' });
    await firestorePatch('agent_commands/' + id, { status: 'descartado', resultado: 'Tipo de comando não permitido pelo agente.' }).catch(() => {});
    return false;
  }

  const expiresAt = parseFirestoreDate((fields.expiresAt || {}).stringValue || dados.expiresAt || '');
  if (expiresAt && expiresAt.getTime() < Date.now()) {
    await auditAgentCommand(id, 'AGENT_COMMAND_REJECTED', { tipo, motivo: 'comando_expirado' });
    await firestorePatch('agent_commands/' + id, { status: 'expirado', resultado: 'Comando expirado antes da execução.' }).catch(() => {});
    return false;
  }

  const requiresAdmin = parseFirestoreBool(fields.requiresAdmin) || ADMIN_COMMANDS.has(tipo);
  if (requiresAdmin && !isWindowsAdminContext()) {
    await auditAgentCommand(id, 'AGENT_COMMAND_REJECTED', { tipo, motivo: 'servico_sem_privilegio_admin' });
    await firestorePatch('agent_commands/' + id, { status: 'erro', resultado: 'Agente não está rodando como serviço administrativo/SYSTEM ou conta de serviço AD autorizada.' }).catch(() => {});
    return false;
  }

  const role = (fields.requestedByRole || {}).stringValue || dados.requestedByRole || '';
  if (requiresAdmin && role && !['admin','gestor','tecnico','mdm_admin'].includes(role)) {
    await auditAgentCommand(id, 'AGENT_COMMAND_REJECTED', { tipo, motivo: 'perfil_sem_permissao', requestedByRole: role });
    await firestorePatch('agent_commands/' + id, { status: 'descartado', resultado: 'Perfil do solicitante sem permissão para comando administrativo.' }).catch(() => {});
    return false;
  }

  // Motivo obrigatório apenas para bloqueio/desbloqueio/powershell
  const tiposComJustificativa = new Set(['bloquear_maquina','desbloquear_maquina','powershell']);
  if (tiposComJustificativa.has(tipo) && !String((fields.motivo || {}).stringValue || dados.motivo || '').trim()) {
    await auditAgentCommand(id, 'AGENT_COMMAND_REJECTED', { tipo, motivo: 'justificativa_obrigatoria' });
    await firestorePatch('agent_commands/' + id, { status: 'descartado', resultado: 'Justificativa obrigatória não informada.' }).catch(() => {});
    return false;
  }

  return true;
}

// ── Instância única — impede dois processos rodando ao mesmo tempo ──
const PID_FILE = path.join(__dirname, 'agent.pid');
(function garantirInstanciaUnica() {
  try {
    if (fs.existsSync(PID_FILE)) {
      const pidAntigo = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
      if (pidAntigo && pidAntigo !== process.pid) {
        try {
          // Tenta matar o processo anterior
          process.kill(pidAntigo, 0); // verifica se existe
          process.kill(pidAntigo);    // mata
          console.log(`[SYSACK] Processo anterior (PID ${pidAntigo}) encerrado.`);
          // Aguarda 1s para o processo encerrar antes de continuar
          const fim = Date.now() + 1000;
          while (Date.now() < fim) {} // busy wait curto
        } catch(e) {
          // Processo não existe mais — OK
        }
      }
    }
  } catch(e) {}
  // Registra PID atual
  try { fs.writeFileSync(PID_FILE, String(process.pid), 'utf8'); } catch(e) {}
  // Remove PID ao encerrar normalmente
  process.on('exit',    () => { try { fs.unlinkSync(PID_FILE); } catch(e) {} });
  process.on('SIGINT',  () => { try { fs.unlinkSync(PID_FILE); } catch(e) {} process.exit(0); });
  process.on('SIGTERM', () => { try { fs.unlinkSync(PID_FILE); } catch(e) {} process.exit(0); });
})();

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


function agendarReinicioAgent() {
  try {
    const nodeExe  = process.execPath;
    const script   = process.argv[1] || path.join(__dirname, 'agent-desktop.js');
    const bat      = path.join(__dirname, '_restart_sysack_agent.cmd');
    const pidClean = 'del /f /q "' + PID_FILE + '" >nul 2>nul';
    const nodeCmd  = '"' + nodeExe + '" "' + script + '"';
    const linhas = [
      '@echo off',
      'timeout /t 5 /nobreak >nul',
      pidClean,
      '',
      ':: Para o servico e mata processos node antes de mover o arquivo',
      'schtasks /End /TN "SYSACK-Agent" >nul 2>nul',
      'sc stop "SYSACK Agent" >nul 2>nul',
      'sc stop "SYSACK-Agent" >nul 2>nul',
      'timeout /t 3 /nobreak >nul',
      'taskkill /F /IM node.exe >nul 2>nul',
      'timeout /t 2 /nobreak >nul',
      '',
      ':: Move arquivo temporario para o definitivo',
      'if exist "' + script + '.new.js" (',
      '  move /y "' + script + '.new.js" "' + script + '" >nul',
      ')',
      '',
      ':: Reinicia — schtasks → direto',
      'schtasks /Run /TN "SYSACK-Agent" >nul 2>nul',
      'if not errorlevel 1 goto :FIM',
      'sc start "SYSACK Agent" >nul 2>nul',
      'if not errorlevel 1 goto :FIM',
      'start "SYSACK Agent" /min ' + nodeCmd,
      ':FIM',
    ].join('\r\n');
    fs.writeFileSync(bat, linhas, 'utf8');
    exec('cmd /c start "" /min "' + bat + '"', { windowsHide: true });
    log('[UPDATE] Reinício agendado — bat: ' + bat);
  } catch(e) {
    log('[UPDATE] Falha ao agendar reinício: ' + e.message);
    try {
      const { spawn } = require('child_process');
      const child = spawn(process.execPath, [process.argv[1]], { detached: true, stdio: 'ignore', windowsHide: true });
      child.unref();
    } catch(e2) { log('[UPDATE] Spawn também falhou: ' + e2.message); }
  }
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
      // MÉTODO 1: query session — funciona com RDP, mas exige Remote Desktop Services ativo
      try {
        const out = execSync('query session', { timeout: 5000, windowsHide: true }).toString();
        const lines = out.split('\n').slice(1);
        for (const line of lines) {
          const trimmed = line.trim().replace(/^>/, '').trim();
          if (!trimmed) continue;
          const cols = trimmed.split(/\s{2,}/).map(s => s.trim()).filter(Boolean);
          const parts = cols.length >= 3 ? cols : trimmed.split(/\s+/);
          const estados = ['active','ativo','disc','desconectado','listen','conn'];
          let usuario = '';
          for (const p of parts) {
            const pl = p.toLowerCase();
            if (estados.includes(pl)) continue;
            if (/^\d+$/.test(p)) continue;
            if (['console','rdp-tcp','services','sistema','system'].includes(pl)) continue;
            usuario = p;
            break;
          }
          if (usuario && (trimmed.toLowerCase().includes('active') || trimmed.toLowerCase().includes('ativo'))) {
            return usuario;
          }
        }
      } catch(e1) {
        log('[getLoggedUser] query session falhou: ' + e1.message);
      }

      // MÉTODO 2: query user
      try {
        const out = execSync('query user', { timeout: 5000, windowsHide: true }).toString();
        for (const line of out.split('\n').slice(1)) {
          const trimmed = line.trim().replace(/^>/, '').trim();
          if (!trimmed) continue;
          const parts = trimmed.split(/\s+/);
          const user = parts[0];
          if (user && !['services','sistema','system'].includes(user.toLowerCase())) {
            if (line.toLowerCase().includes('active') || line.toLowerCase().includes('ativo')) {
              return user;
            }
          }
        }
        const firstLine = out.split('\n').slice(1).find(l => l.trim());
        if (firstLine) {
          const user = firstLine.trim().replace(/^>/, '').trim().split(/\s+/)[0];
          if (user && !['services','sistema','system'].includes(user.toLowerCase())) return user;
        }
      } catch(e2) {
        log('[getLoggedUser] query user falhou: ' + e2.message);
      }

      // MÉTODO 3: WMIC computersystem — usuário logado no console local
      try {
        const out = execSync('wmic computersystem get username /format:value', { timeout: 5000, windowsHide: true }).toString();
        const match = out.match(/UserName=(.+)/i);
        if (match && match[1].trim()) {
          const full = match[1].trim();
          return full.includes('\\') ? full.split('\\').pop() : full;
        }
      } catch(e3) {
        log('[getLoggedUser] wmic computersystem falhou: ' + e3.message);
      }

      // MÉTODO 4: PowerShell Get-CimInstance — funciona em Server Core e quando WMIC falha
      try {
        const out = execSync(
          'powershell -NoProfile -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).UserName"',
          { timeout: 8000, windowsHide: true }
        ).toString().trim();
        if (out && out.toLowerCase() !== 'null' && out.length > 0) {
          return out.includes('\\') ? out.split('\\').pop() : out;
        }
      } catch(e4) {
        log('[getLoggedUser] PowerShell Get-CimInstance falhou: ' + e4.message);
      }

      // MÉTODO 5: dono do processo explorer.exe — último recurso
      try {
        const out = execSync(
          'powershell -NoProfile -Command "Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty UserName"',
          { timeout: 8000, windowsHide: true }
        ).toString().trim();
        if (out && out.length > 0) {
          return out.includes('\\') ? out.split('\\').pop() : out;
        }
      } catch(e5) {
        log('[getLoggedUser] explorer owner falhou: ' + e5.message);
      }

      log('[getLoggedUser] Nenhum método detectou usuário logado nesta coleta.');
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

function getBootTimeIso(uptimeSec = getUptime()) {
  return new Date(Date.now() - (Number(uptimeSec) || 0) * 1000).toISOString();
}

// Estado local para detectar mudanças técnicas mesmo quando o portal não está aberto.
// Mantém a linha do tempo preenchida automaticamente em agents/{id}/historico.
const STATE_FILE = path.join(__dirname, 'agent-state.json');
function carregarEstadoLocal() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch(e) { return {}; }
}
function salvarEstadoLocal(st) {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(st || {}, null, 2), 'utf8'); } catch(e) {}
}
function monitoresAssinatura(monitores) {
  if (!Array.isArray(monitores)) return '';
  return monitores.map(m => [m.nome || m.caption || 'Monitor', m.serial || '', m.resolucao || ''].join('#'))
    .sort().join('|');
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


// ── Informações de rede detalhadas para alertas ────────────────────────
function getNetworkInfo() {
  const info = { ip: '', mac: '', gateway: '', dns: '', dnsServers: [], adapter: '' };
  try {
    const nets = os.networkInterfaces();
    for (const [name, arr] of Object.entries(nets)) {
      const ipv4 = (arr || []).find(n => n.family === 'IPv4' && !n.internal);
      if (ipv4 && !info.ip) {
        info.ip = ipv4.address || '';
        info.mac = ipv4.mac || '';
        info.adapter = name || '';
      }
    }
    if (process.platform === 'win32') {
      try {
        const psScript = [
          '$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1',
          'if ($cfg) {',
          '  Write-Output ("GW=" + (($cfg.IPv4DefaultGateway.NextHop | Select-Object -First 1) -as [string]))',
          '  Write-Output ("DNS=" + (($cfg.DNSServer.ServerAddresses -join ",")))',
          '  Write-Output ("ALIAS=" + $cfg.InterfaceAlias)',
          '}',
          '$ad = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1',
          'if ($ad) { Write-Output ("MAC=" + $ad.MacAddress) }'
        ].join('\n');
        const psFile = path.join(__dirname, '_net.ps1');
        fs.writeFileSync(psFile, psScript, 'utf8');
        const out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"', { timeout: 10000, windowsHide: true }).toString();
        try { fs.unlinkSync(psFile); } catch(e) {}
        const get = key => (out.match(new RegExp(key + '=([^\r\n]*)')) || [])[1]?.trim() || '';
        const gw = get('GW');
        const dns = get('DNS');
        const mac = get('MAC');
        const alias = get('ALIAS');
        if (gw) info.gateway = gw;
        if (dns) { info.dns = dns; info.dnsServers = dns.split(',').map(s => s.trim()).filter(Boolean); }
        if (mac) info.mac = mac;
        if (alias) info.adapter = alias;
      } catch(e) {
        // fallback ipconfig
        try {
          const out = execSync('ipconfig /all', { timeout: 8000, windowsHide: true }).toString();
          const gw = (out.match(/Default Gateway[^:]*:\s*([^\r\n]+)/i) || [])[1]?.trim();
          if (gw) info.gateway = gw;
          const dnsMatches = [...out.matchAll(/DNS Servers[^:]*:\s*([^\r\n]+)/gi)].map(m => m[1].trim()).filter(Boolean);
          if (dnsMatches.length) { info.dnsServers = dnsMatches; info.dns = dnsMatches.join(','); }
        } catch(e2) {}
      }
    }
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

    const makeReq = (attempt) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path:     urlObj.pathname + urlObj.search,
        method:   'PATCH',
        rejectUnauthorized: false,
        timeout:  15000,
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      }, res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            _fsErrosConsecutivos = 0; // reset contador de erros
            if (global._watchdogOk) global._watchdogOk();
            resolve(raw);
          } else if ((res.statusCode === 429 || res.statusCode >= 500) && attempt < 3) {
            // Rate limit ou erro servidor — retry com backoff
            const delay = attempt * 2000;
            log(`[Firestore] HTTP ${res.statusCode} em ${docPath} — retry em ${delay}ms (tentativa ${attempt})`);
            setTimeout(() => makeReq(attempt + 1), delay);
          } else {
            _fsErrosConsecutivos++;
            const errMsg = `HTTP ${res.statusCode} em ${docPath}: ${raw.slice(0, 200)}`;
            log(`[Firestore] ERRO gravação — ${errMsg} (erros consecutivos: ${_fsErrosConsecutivos})`);
            reject(new Error(errMsg));
          }
        });
      });
      req.on('timeout', () => {
        req.destroy();
        if (attempt < 3) {
          log(`[Firestore] Timeout em ${docPath} — retry ${attempt}`);
          setTimeout(() => makeReq(attempt + 1), attempt * 1500);
        } else {
          _fsErrosConsecutivos++;
          reject(new Error('Timeout após 3 tentativas: ' + docPath));
        }
      });
      req.on('error', (e) => {
        if (attempt < 3) {
          setTimeout(() => makeReq(attempt + 1), attempt * 1500);
        } else {
          _fsErrosConsecutivos++;
          reject(e);
        }
      });
      req.write(body);
      req.end();
    };
    makeReq(1);
  });
}


// ── Histórico de login / usuário principal ────────────────────────────────
// Regras:
//   - grava 1 documento por usuário + máquina + dia em /login_history
//   - calcula usuário principal pelo maior número de dias distintos nos últimos 90 dias
//   - atualiza /agents, /agentes_desktop, /login_resumo_maquina e /ativos correspondente
const LOGIN_PRINCIPAL_DIAS = 90;

function normalizarTextoId(v) {
  return String(v || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120);
}

function normalizarUsuarioLogin(user) {
  let u = String(user || '').trim();
  if (!u) return '';
  // Remove domínio AD ou UPN
  if (u.includes('\\')) u = u.split('\\').pop();
  if (u.includes('@')) u = u.split('@')[0];
  return u.trim().toLowerCase();
}

function yyyyMmDdLocal(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

function firestoreValueToJs(v) {
  if (!v || typeof v !== 'object') return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return parseInt(v.integerValue, 10) || 0;
  if ('doubleValue' in v) return Number(v.doubleValue) || 0;
  if ('booleanValue' in v) return !!v.booleanValue;
  if ('timestampValue' in v) return v.timestampValue;
  if ('nullValue' in v) return null;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(firestoreValueToJs);
  if ('mapValue' in v) {
    const out = {};
    for (const [k, val] of Object.entries(v.mapValue.fields || {})) out[k] = firestoreValueToJs(val);
    return out;
  }
  return null;
}

function firestoreDocToJs(doc) {
  if (!doc || !doc.fields) return null;
  const out = { _name: doc.name, _id: String(doc.name || '').split('/').pop() };
  for (const [k, v] of Object.entries(doc.fields || {})) out[k] = firestoreValueToJs(v);
  return out;
}

function firestoreRunQuery(collectionId, filters = [], limitN = 500) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery?key=${API_KEY}`;

  const structuredQuery = {
    from: [{ collectionId }],
    limit: limitN
  };

  if (filters.length === 1) {
    const [field, op, value] = filters[0];
    structuredQuery.where = {
      fieldFilter: { field: { fieldPath: field }, op, value: { stringValue: String(value) } }
    };
  } else if (filters.length > 1) {
    structuredQuery.where = {
      compositeFilter: {
        op: 'AND',
        filters: filters.map(([field, op, value]) => ({
          fieldFilter: { field: { fieldPath: field }, op, value: { stringValue: String(value) } }
        }))
      }
    };
  }

  const body = JSON.stringify({ structuredQuery });
  const urlObj = new URL(url);

  return new Promise(resolve => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        // CORREÇÃO: loga erros HTTP (400 = índice ausente, 403 = regras Firestore bloqueando)
        if (res.statusCode < 200 || res.statusCode >= 300) {
          log(`[LoginHistory] runQuery HTTP ${res.statusCode} em ${collectionId}: ${raw.slice(0, 300)}`);
          log('[LoginHistory] DICA: HTTP 403 = verifique as Firestore Rules para login_history. HTTP 400 = crie o índice: login_history / hostname ASC');
          return resolve([]);
        }
        try {
          const arr = JSON.parse(raw);
          if (!Array.isArray(arr)) return resolve([]);
          const docs = arr.map(x => x.document ? firestoreDocToJs(x.document) : null).filter(Boolean);
          resolve(docs);
        } catch(e) {
          log('[LoginHistory] Erro parse runQuery: ' + e.message);
          resolve([]);
        }
      });
    });
    req.on('error', e => {
      log('[LoginHistory] runQuery falhou: ' + e.message);
      resolve([]);
    });
    req.write(body);
    req.end();
  });
}

async function localizarAtivoRelacionado(dados) {
  try {
    // 1) procura por hostname
    let docs = await firestoreRunQuery('ativos', [['hostname', 'EQUAL', AGENT_ID]], 2);
    if (docs.length) return docs[0]._id;

    // 2) procura por hostname em campos alternativos comuns
    docs = await firestoreRunQuery('ativos', [['nome', 'EQUAL', AGENT_ID]], 2);
    if (docs.length) return docs[0]._id;

    // 3) procura por IP
    if (dados && dados.ip) {
      docs = await firestoreRunQuery('ativos', [['ip', 'EQUAL', dados.ip]], 2);
      if (docs.length) return docs[0]._id;
    }
  } catch(e) {
    log('[LoginHistory] Falha ao localizar ativo: ' + e.message);
  }
  return '';
}

function calcularResumoUsuarios90d(docs, usuarioAtual, diaAtual) {
  const cutoff = yyyyMmDdLocal(addDays(new Date(), -LOGIN_PRINCIPAL_DIAS + 1));
  const anoAtual = String(new Date().getFullYear());
  const porUsuario = new Map();

  for (const d of docs || []) {
    const dia = String(d.dia || d.dateKey || '').slice(0, 10);
    const usuario = normalizarUsuarioLogin(d.usuarioNorm || d.usuario || '');
    if (!dia || dia < cutoff || !usuario) continue;

    if (!porUsuario.has(usuario)) {
      porUsuario.set(usuario, {
        usuario,
        diasSet: new Set(),
        diasAnoSet: new Set(), // dias logados apenas no ano corrente
        primeiroDia: dia,
        ultimoDia: dia,
        ultimoLoginEm: d.ultimoLogin || d.ultimoLoginEm || '',
      });
    }

    const item = porUsuario.get(usuario);
    item.diasSet.add(dia);
    if (dia.startsWith(anoAtual)) item.diasAnoSet.add(dia);
    if (dia < item.primeiroDia) item.primeiroDia = dia;
    if (dia > item.ultimoDia) item.ultimoDia = dia;
    const ult = d.ultimoLogin || d.ultimoLoginEm || '';
    if (ult && (!item.ultimoLoginEm || ult > item.ultimoLoginEm)) item.ultimoLoginEm = ult;
  }

  // Garante que o login atual conte imediatamente, mesmo antes da query retornar o doc recém-criado.
  const uAtualNorm = normalizarUsuarioLogin(usuarioAtual);
  if (uAtualNorm && diaAtual) {
    if (!porUsuario.has(uAtualNorm)) {
      porUsuario.set(uAtualNorm, {
        usuario: uAtualNorm,
        diasSet: new Set(),
        diasAnoSet: new Set(),
        primeiroDia: diaAtual,
        ultimoDia: diaAtual,
        ultimoLoginEm: new Date().toISOString(),
      });
    }
    const item = porUsuario.get(uAtualNorm);
    item.diasSet.add(diaAtual);
    if (String(diaAtual).startsWith(anoAtual)) item.diasAnoSet.add(diaAtual);
    if (diaAtual < item.primeiroDia) item.primeiroDia = diaAtual;
    if (diaAtual > item.ultimoDia) item.ultimoDia = diaAtual;
  }

  const usuarios = Array.from(porUsuario.values())
    .map(x => ({
      usuario: x.usuario,
      diasLogados90d: x.diasSet.size,
      diasLogadosAno: x.diasAnoSet.size,
      primeiroDia: x.primeiroDia,
      ultimoDia: x.ultimoDia,
      ultimoLoginEm: x.ultimoLoginEm || '',
    }))
    .sort((a, b) => {
      if (b.diasLogados90d !== a.diasLogados90d) return b.diasLogados90d - a.diasLogados90d;
      return String(b.ultimoDia).localeCompare(String(a.ultimoDia));
    });

  const principal = usuarios[0] || null;
  // Soma de todos os usuários que logaram nessa máquina no ano corrente —
  // representa o total de dias com atividade na máquina, usado na coluna "Dias A."
  const diasAnoTotal = usuarios.reduce((acc, u) => Math.max(acc, u.diasLogadosAno), 0);
  return {
    usuarios,
    usuarioPrincipal: principal ? principal.usuario : '',
    usuarioPrincipalDias90d: principal ? principal.diasLogados90d : 0,
    diasLogadosAno: diasAnoTotal,
  };
}

async function registrarHistoricoLogin(dados, usuarioLogado, nowIso) {
  const usuarioNorm = normalizarUsuarioLogin(usuarioLogado);
  const hostname = AGENT_ID;
  const dia = yyyyMmDdLocal(new Date(nowIso));
  const mes = dia.slice(0, 7);

  const vazio = {
    usuarioPrincipal: '',
    usuarioPrincipalDias90d: 0,
    usuariosLogin90d: [],
    totalUsuarios90d: 0,
  };

  if (!usuarioNorm) {
    log('[LoginHistory] Nenhum usuário interativo detectado nesta coleta.');
    return vazio;
  }

  const safeHost = normalizarTextoId(hostname);
  const safeUser = normalizarTextoId(usuarioNorm);
  const loginDocId = `${safeHost}_${safeUser}_${dia}`;

  // CORREÇÃO: grava o documento com PATCH normal (upsert).
  // primeiroLogin é preservado porque usamos um segundo PATCH com field mask
  // apenas nos campos que devem ser atualizados — o campo primeiroLogin
  // só é incluído quando não existia antes (verificamos via GET leve).
  const docPath = `login_history/${loginDocId}`;

  try {
    // Leitura leve para saber se o doc já existe
    const getUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}?key=${API_KEY}&mask.fieldPaths=primeiroLogin`;
    const jaExiste = await new Promise(resolve => {
      const u = new URL(getUrl);
      const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET', rejectUnauthorized: false }, res => {
        let raw = ''; res.on('data', c => raw += c);
        res.on('end', () => resolve(res.statusCode === 200));
      });
      r.on('error', () => resolve(false));
      r.end();
    });

    if (!jaExiste) {
      // Documento novo: grava tudo incluindo primeiroLogin
      await firestoreSet(docPath, {
        hostname, agentId: hostname, usuario: usuarioNorm, usuarioNorm,
        dia, mes,
        primeiroLogin: nowIso,
        ultimoLogin: nowIso, ultimoLoginEm: nowIso,
        ip: dados.ip || '', fonte: 'agent-desktop',
        versaoAgente: '2.2.0',
      });
      log(`[LoginHistory] Documento criado: ${loginDocId}`);
    } else {
      // Documento já existe: atualiza só ultimoLogin — NÃO sobrescreve primeiroLogin
      await firestorePatch(docPath, {
        ultimoLogin: nowIso, ultimoLoginEm: nowIso,
        ip: dados.ip || '',
        versaoAgente: '2.2.0',
      });
      log(`[LoginHistory] Documento atualizado (ultimoLogin): ${loginDocId}`);
    }
  } catch(e) {
    log('[LoginHistory] Falha ao gravar login_history: ' + e.message);
  }

  let docs = [];
  try {
    docs = await firestoreRunQuery('login_history', [['hostname', 'EQUAL', hostname]], 800);
  } catch(e) {
    log('[LoginHistory] Falha ao consultar histórico: ' + e.message);
  }

  const resumo = calcularResumoUsuarios90d(docs, usuarioNorm, dia);
  const payloadResumo = {
    hostname,
    agentId: hostname,
    usuarioLogado: usuarioNorm,
    usuarioAtual: usuarioNorm,
    ultimoLoginUsuario: usuarioNorm,
    ultimoLoginEm: nowIso,
    loginAtualizadoEm: nowIso,
    usuarioPrincipal: resumo.usuarioPrincipal,
    usuarioPrincipalDias90d: resumo.usuarioPrincipalDias90d,
    usuarioPrincipalPeriodoDias: LOGIN_PRINCIPAL_DIAS,
    usuariosLogin90d: JSON.stringify(resumo.usuarios),
    usuariosLogin90dArray: resumo.usuarios,
    totalUsuarios90d: resumo.usuarios.length,
    diasLogadosAno: resumo.diasLogadosAno, // total de dias com login na máquina no ano corrente
  };

  try {
    await firestoreSet(`login_resumo_maquina/${safeHost}`, payloadResumo);
  } catch(e) {
    log('[LoginHistory] Falha ao gravar resumo: ' + e.message);
  }

  try {
    const ativoId = await localizarAtivoRelacionado(dados);
    if (ativoId) {
      await firestorePatch(`ativos/${ativoId}`, {
        ...payloadResumo,
        hostname,
        ip: dados.ip || '',
        status: 'em-uso',
        ultimoAgente: nowIso,
      });
      log(`[LoginHistory] Ativo ${ativoId} atualizado: atual=${usuarioNorm}, principal=${resumo.usuarioPrincipal || '-'} (${resumo.usuarioPrincipalDias90d} dias/90d)`);
    }
  } catch(e) {
    log('[LoginHistory] Falha ao atualizar ativo: ' + e.message);
  }

  try {
    log(`[LoginHistory] Login registrado: ${usuarioNorm} em ${hostname} | principal=${resumo.usuarioPrincipal || '-'} (${resumo.usuarioPrincipalDias90d} dias/90d)`);
  } catch(e) {}

  return payloadResumo;
}


// ── Rastreamento de sessão de usuário ────────────────────────────
// Detecta troca de usuário, login remoto (RDP) e registra
// horário de início/fim de sessão em login_sessions.
let _sessaoAtual = null; // { usuario, loginAt, tipo }
let _ipAnterior  = null;
let _statusAnterior = null;

function detectarSessoesRDP() {
  // Detecta sessões RDP/TS ativas via query session
  try {
    const out = require('child_process').execSync('query session', { timeout: 5000, windowsHide: true }).toString();
    const sessoes = [];
    for (const line of out.split('\n').slice(1)) {
      const l = line.trim().replace(/^>/, '').trim();
      if (!l) continue;
      const parts = l.split(/\s+/);
      const usuario = parts[0];
      const tipo    = String(parts[1] || '').toLowerCase();
      if (!usuario || ['services','sistema','system','rdp-tcp'].some(x => usuario.toLowerCase().includes(x))) continue;
      const isRdp = tipo.includes('rdp') || tipo.includes('tcp') || String(parts[2] || '').toLowerCase().includes('rdp');
      const isAtivo = line.toLowerCase().includes('active') || line.toLowerCase().includes('ativo');
      if (isAtivo) sessoes.push({ usuario, tipo: isRdp ? 'remoto' : 'local', rdp: isRdp });
    }
    return sessoes;
  } catch { return []; }
}

async function rastrearSessaoUsuario(userAtual, nowIso) {
  if (!userAtual) {
    // Usuário deslogou
    if (_sessaoAtual) {
      log(`[Sessao] Logout detectado: ${_sessaoAtual.usuario}`);
      await firestoreCreate('login_sessions', {
        hostname:   AGENT_ID,
        agentId:    AGENT_ID,
        usuario:    _sessaoAtual.usuario,
        usuarioNorm: normalizarUsuarioLogin(_sessaoAtual.usuario),
        loginAt:    _sessaoAtual.loginAt,
        logoutAt:   nowIso,
        tipo:       _sessaoAtual.tipo || 'local',
        rdp:        _sessaoAtual.tipo === 'remoto',
        dia:        nowIso.slice(0, 10),
        createdAt:  nowIso,
      }).catch(() => {});
      _sessaoAtual = null;
    }
    return;
  }

  const userNorm = normalizarUsuarioLogin(userAtual);

  if (!_sessaoAtual || normalizarUsuarioLogin(_sessaoAtual.usuario) !== userNorm) {
    // Novo login — fecha sessão anterior se havia
    if (_sessaoAtual) {
      log(`[Sessao] Troca de usuário: ${_sessaoAtual.usuario} → ${userAtual}`);
      await firestoreCreate('login_sessions', {
        hostname:   AGENT_ID,
        agentId:    AGENT_ID,
        usuario:    _sessaoAtual.usuario,
        usuarioNorm: normalizarUsuarioLogin(_sessaoAtual.usuario),
        loginAt:    _sessaoAtual.loginAt,
        logoutAt:   nowIso,
        tipo:       _sessaoAtual.tipo || 'local',
        rdp:        _sessaoAtual.tipo === 'remoto',
        dia:        _sessaoAtual.loginAt.slice(0, 10),
        createdAt:  _sessaoAtual.loginAt,
      }).catch(() => {});
    }
    // Detecta se é sessão RDP
    const sessoesRdp = detectarSessoesRDP();
    const sessaoRdp  = sessoesRdp.find(s => normalizarUsuarioLogin(s.usuario) === userNorm);
    const tipo = sessaoRdp?.rdp ? 'remoto' : 'local';
    _sessaoAtual = { usuario: userAtual, loginAt: nowIso, tipo };
    log(`[Sessao] Login detectado: ${userAtual} (${tipo})`);
  }

  // Grava também sessões RDP simultâneas (outros usuários remotos além do principal)
  try {
    const sessoesRdp = detectarSessoesRDP();
    for (const s of sessoesRdp) {
      const sNorm = normalizarUsuarioLogin(s.usuario);
      if (sNorm === userNorm) continue; // já rastreado acima
      const chave = AGENT_ID + '_' + sNorm + '_' + nowIso.slice(0, 10);
      // Grava uma entrada por dia por usuário remoto (não duplica)
      await firestoreCreate('login_sessions', {
        hostname:   AGENT_ID,
        agentId:    AGENT_ID,
        usuario:    s.usuario,
        usuarioNorm: sNorm,
        loginAt:    nowIso,
        logoutAt:   null,
        tipo:       'remoto',
        rdp:        true,
        dia:        nowIso.slice(0, 10),
        chaveDedup: chave,
        createdAt:  nowIso,
      }).catch(() => {});
    }
  } catch {}
}

async function rastrearMudancasStatus(dados, nowIso) {
  // Registra mudanças técnicas na subcoleção historico do agente.
  // Isso independe do frontend estar aberto e alimenta a aba Histórico do painel.
  const estado = carregarEstadoLocal();
  const prev = estado.ultimoSnapshot || null;
  const atual = {
    ip: dados.ip || '',
    hostname: dados.hostname || AGENT_ID,
    usuarioPrincipal: dados.usuarioPrincipal || '',
    usuarioLogado: dados.usuarioLogado || '',
    monitorSig: monitoresAssinatura(dados.monitores),
    monitores: Array.isArray(dados.monitores) ? dados.monitores : [],
    mac: dados.macAddress || dados.mac || '',
    gateway: dados.gateway || '',
    bootTime: dados.bootTime || '',
    uptime: dados.uptime || 0,
  };

  async function hist(tipo, titulo, desc, extras = {}) {
    log(`[Historico] ${desc}`);
    await firestoreCreate(`agents/${AGENT_ID}/historico`, {
      tipo, titulo, desc,
      dot: extras.dot || 'orange',
      agentId: AGENT_ID,
      hostname: AGENT_ID,
      origem: 'agente-desktop',
      createdAt: nowIso,
      data: nowIso,
      ...extras,
    }).catch(e => log('[Historico] Falha ao gravar: ' + e.message));
  }

  if (prev) {
    if (prev.ip && atual.ip && prev.ip !== atual.ip) {
      const faixaAntes  = String(prev.ip).split('.').slice(0,3).join('.');
      const faixaDepois = String(atual.ip).split('.').slice(0,3).join('.');
      if (faixaAntes !== faixaDepois) {
        await hist('mudanca_faixa_ip', '🚨 Mudou de faixa de rede',
          `Faixa de IP alterada: ${faixaAntes}.0/24 → ${faixaDepois}.0/24 · IP: ${prev.ip} → ${atual.ip}`,
          { dot:'red', ipAnterior:prev.ip, ipNovo:atual.ip, faixaAnterior:`${faixaAntes}.0/24`, faixaNova:`${faixaDepois}.0/24` });
      } else {
        await hist('mudanca_ip', '✏️ IP alterado', `IP alterado: ${prev.ip} → ${atual.ip}`,
          { dot:'orange', ipAnterior:prev.ip, ipNovo:atual.ip });
      }
    }

    if (prev.hostname && atual.hostname && prev.hostname !== atual.hostname) {
      await hist('mudanca_hostname', '✏️ Hostname alterado', `Hostname: ${prev.hostname} → ${atual.hostname}`,
        { dot:'orange', campo:'hostname', de:prev.hostname, para:atual.hostname });
    }

    if (prev.monitorSig && atual.monitorSig && prev.monitorSig !== atual.monitorSig) {
      await hist('troca_monitor', '🖥️ Monitor alterado',
        `Monitor(es) alterado(s): ${prev.monitorSig || '—'} → ${atual.monitorSig || '—'}`,
        { dot:'blue', campo:'monitores', de:prev.monitorSig, para:atual.monitorSig, monitoresAntigos:prev.monitores || [], monitoresNovos:atual.monitores || [] });
    }

    if (prev.usuarioPrincipal && atual.usuarioPrincipal && prev.usuarioPrincipal !== atual.usuarioPrincipal) {
      await hist('troca_responsavel', '👥 Usuário principal alterado',
        `Usuário principal: ${prev.usuarioPrincipal} → ${atual.usuarioPrincipal}`,
        { dot:'blue', campo:'usuarioPrincipal', de:prev.usuarioPrincipal, para:atual.usuarioPrincipal });
    }

    // Se o bootTime mudou, a máquina reiniciou. Útil para auditar uptime.
    if (prev.bootTime && atual.bootTime && prev.bootTime !== atual.bootTime) {
      await hist('reinicializacao', '🔄 Máquina reiniciada',
        `Boot anterior: ${prev.bootTime} · boot atual: ${atual.bootTime}`,
        { dot:'green', campo:'bootTime', de:prev.bootTime, para:atual.bootTime });
    }
  }

  estado.ultimoSnapshot = atual;
  estado.atualizadoEm = nowIso;
  salvarEstadoLocal(estado);
  _ipAnterior = atual.ip || _ipAnterior;
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
    const bootTimeIso = getBootTimeIso(uptimeSec);

    const hw  = getHardwareInfo();
    const sec = getSegurancaInfo();
    const net = getNetworkInfo();
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
      ip:                net.ip || Object.values(os.networkInterfaces()).flat().find(n => n.family === 'IPv4' && !n.internal)?.address || '',
      mac:               net.mac || '',
      macAddress:        net.mac || '',
      gateway:           net.gateway || '',
      defaultGateway:    net.gateway || '',
      dns:               net.dns || '',
      dnsServers:        net.dnsServers || [],
      networkAdapter:    net.adapter || '',
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
      uptimeSeconds:     uptimeSec,
      uptimeH:           Math.floor(uptimeSec / 3600),
      bootTime:          bootTimeIso,
      lastBootTime:      bootTimeIso,
      monitores:         getMonitores(),
      software:          software,
      softwareCount:     software.length,
      softwareAtualizadoEm: _softwareCache.at ? new Date(_softwareCache.at).toISOString() : now,
      versaoAgente:      '2.2.0',
      ultimaAtualizacao: now,
      lastSeen:          now,
      status:            'online',
      plataforma:        process.platform,
    };

    const loginResumo = await registrarHistoricoLogin(dados, user, now);
    Object.assign(dados, loginResumo);

    // Rastreia sessão do usuário (horário de login/logout, RDP)
    await rastrearSessaoUsuario(user, now).catch(e => log('[Sessao] ' + e.message));
    // Rastreia mudanças de IP/faixa de rede
    await rastrearMudancasStatus(dados, now).catch(e => log('[Status] ' + e.message));

    await firestoreSet(`agents/${AGENT_ID}`, dados);
    // Espelho para compatibilidade com telas/consultas que usam agentes_desktop
    await firestoreSet(`agentes_desktop/${AGENT_ID}`, dados).catch(e => log('[WARN] Falha ao gravar agentes_desktop: ' + e.message));
    // Heartbeat dedicado — garante que lastSeen e status chegam mesmo se o payload completo falhar
    await firestorePatch(`agents/${AGENT_ID}`, {
      lastSeen: now, status: 'online', versaoAgente: '2.2.0',
      uptime: dados.uptime, uptimeSeconds: dados.uptimeSeconds, uptimeH: dados.uptimeH, bootTime: dados.bootTime, lastBootTime: dados.lastBootTime, cpuPct: dados.cpuPct, ramPct: dados.ramPct,
    }).catch(() => {});

    log(`[OK] Dados enviados - CPU: ${cpu}% | RAM: ${mem.pct}% | Usuario: ${user || '-'} | Principal 90d: ${dados.usuarioPrincipal || '-'}`);
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
log(`[SYSACK Agent Desktop v2.2.2] Iniciando - hostname: ${AGENT_ID}`);
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
    let header;
    if (buf.length < 126) {
      header = Buffer.allocUnsafe(2);
      header[0] = 0x81;
      header[1] = buf.length;
    } else if (buf.length < 65536) {
      header = Buffer.allocUnsafe(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(buf.length, 2);
    } else {
      header = Buffer.allocUnsafe(10);
      header[0] = 0x81;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(buf.length), 2);
    }
    socket.write(Buffer.concat([header, buf]));
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
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery?key=${API_KEY}`;
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
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          // Firestore retorna array — se primeiro item tem 'error', logar
          if (Array.isArray(parsed) && parsed[0]?.error) {
            log('[Firestore] Query erro: ' + JSON.stringify(parsed[0].error));
          }
          resolve(parsed);
        } catch(e) { resolve([]); }
      });
    });
    req.on('error', e => { log('[Firestore] Query falhou: ' + e.message); resolve([]); });
    req.write(body);
    req.end();
  });
}

async function firestorePatch(docPath, data) {
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    if (typeof v === 'string') fields[k] = { stringValue: v };
    else if (typeof v === 'number') fields[k] = { doubleValue: v };
    else if (typeof v === 'boolean') fields[k] = { booleanValue: v };
  }
  const body = JSON.stringify({ fields });
  const maskParams = Object.keys(data).map(k => 'updateMask.fieldPaths=' + k).join('&');
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}?key=${API_KEY}&${maskParams}`;
  const urlObj = new URL(url);
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

// ════════════════════════════════════════════════════════════════
// RELAY FIREBASE REALTIME DATABASE — push em tempo real
// Substitui polling de 3s por SSE persistente na porta 443 HTTPS.
// Zero dependências npm — usa apenas https nativo do Node.js.
// Latência: ~100–200ms vs 2–6s do Firestore polling anterior.
// ════════════════════════════════════════════════════════════════

const RTDB_HOST = (cfg.rtdbHost || (cfg.databaseURL || '').replace(/^https?:\/\//,'').replace(/\/$/,'') || '');

let _rtdbListeners = new Map(); // sessaoId → req
let _sessoesAtivas = new Set(); // sessoes com listener ativo

// Abre conexão SSE persistente e chama callback a cada comando recebido
function rtdbListen(sessaoId, callback) {
  if (!RTDB_HOST) { log('[RTDB] Sem databaseURL/rtdbHost — usando somente Firestore relay'); return; }
  rtdbUnlisten(sessaoId);

  const req = https.request({
    hostname: RTDB_HOST,
    path:     `/relay/${sessaoId}/cmd.json?auth=${API_KEY}`,
    method:   'GET',
    rejectUnauthorized: false,
    headers: { 'Accept': 'text/event-stream', 'Cache-Control': 'no-cache' },
  }, res => {
    log(`[RTDB] Listener SSE ativo — sessão ${sessaoId} (HTTP ${res.statusCode})`);
    let ultimoTs = 0;
    let buf = '';

    res.on('data', chunk => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      let event = '', data = '';
      for (const line of lines) {
        if (line.startsWith('event: '))     { event = line.slice(7).trim(); }
        else if (line.startsWith('data: ')) { data  = line.slice(6).trim(); }
        else if (line === '' && event && data) {
          if (event === 'put' || event === 'patch') {
            try {
              const val = JSON.parse(data)?.data;
              if (val && val.ts && val.ts > ultimoTs && val.payload) {
                ultimoTs = val.ts;
                callback(val.payload);
              }
            } catch(e) {}
          }
          event = ''; data = '';
        }
      }
    });

    res.on('end', () => {
      log(`[RTDB] SSE encerrado — sessão ${sessaoId}`);
      _rtdbListeners.delete(sessaoId);
      if (_sessoesAtivas.has(sessaoId)) {
        setTimeout(() => { if (_sessoesAtivas.has(sessaoId)) rtdbListen(sessaoId, callback); }, 5000);
      }
    });

    res.on('error', e => log('[RTDB] SSE erro: ' + e.message));
  });

  req.setTimeout(0);
  req.on('error', e => {
    log('[RTDB] Conexão falhou: ' + e.message);
    if (_sessoesAtivas.has(sessaoId)) {
      setTimeout(() => { if (_sessoesAtivas.has(sessaoId)) rtdbListen(sessaoId, callback); }, 10000);
    }
  });
  req.end();
  _rtdbListeners.set(sessaoId, req);
}

function rtdbUnlisten(sessaoId) {
  const req = _rtdbListeners.get(sessaoId);
  if (req) { try { req.destroy(); } catch(e) {} }
  _rtdbListeners.delete(sessaoId);
}

// Escreve dados no RTDB via REST (PUT)
function rtdbEscrever(rtdbPath, data) {
  if (!RTDB_HOST) return Promise.reject(new Error('RTDB não configurado'));
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const req  = https.request({
      hostname: RTDB_HOST,
      path:     `/${rtdbPath}.json?auth=${API_KEY}`,
      method:   'PUT',
      rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => res.statusCode < 300 ? resolve() : reject(new Error('HTTP ' + res.statusCode)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Processa comando recebido via RTDB e escreve resposta de volta
async function processarComandoRtdb(sessaoId, msg) {
  if (!msg || !msg.tipo) return;
  log(`[RTDB] Sessão ${sessaoId} — tipo: ${msg.tipo}`);

  let resposta = {};
  try {
    if (msg.tipo === 'ping') {
      resposta = { tipo: 'pong', ts: Date.now(), hostname: AGENT_ID };

    } else if (msg.tipo === 'exec') {
      const cmd = msg.cmd || '';
      try {
        const out = execSync(
          'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + cmd.replace(/"/g, '\\"') + '"',
          { timeout: 15000, windowsHide: true }
        ).toString();
        resposta = { tipo: 'result', stdout: out, cmd };
      } catch(e) {
        resposta = { tipo: 'result', stderr: e.stderr?.toString() || '', erro: e.message, cmd };
      }

    } else if (msg.tipo === 'screenshot') {
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
        '$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
        '$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height)',
        '$g=[System.Drawing.Graphics]::FromImage($b)',
        '$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size)',
        '$ms=New-Object System.IO.MemoryStream',
        '$enc=New-Object System.Drawing.Imaging.EncoderParameters(1)',
        '$enc.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]55)',
        '$jpg=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType -eq "image/jpeg"}',
        '$b.Save($ms,$jpg,$enc)',
        '[Convert]::ToBase64String($ms.ToArray())',
      ].join(';');
      const psFile = path.join(__dirname, '_sc_rtdb.ps1');
      fs.writeFileSync(psFile, ps);
      const b64 = execSync(
        'powershell -NoProfile -ExecutionPolicy Bypass -File "' + psFile + '"',
        { timeout: 25000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }
      ).toString().trim();
      try { fs.unlinkSync(psFile); } catch(e) {}
      resposta = { tipo: 'screenshot', data: b64 };

    } else if (msg.tipo === 'metrics') {
      const mem = getMemoryInfo();
      const discos = getDiskInfo();
      const discoC = discos.find(d => d.drive === 'C:') || {};
      resposta = { tipo:'metrics', cpu:getCpuUsage(), mem:mem.pct, disk:discoC.pct||0, uptime:Math.floor(getUptime()/3600), usuario:getLoggedUser() };

    } else if (msg.tipo === 'atualizar_agente') {
      const urlNova    = msg.url    || '';
      const versaoNova = msg.versao || '';
      if (!urlNova) throw new Error('URL não informada');
      log(`[UPDATE/RTDB] Atualizando para v${versaoNova}`);
      const novoConteudo = await new Promise((resolve, reject) => {
        const urlObj = new URL(urlNova);
        const mod = urlNova.startsWith('https') ? require('https') : require('http');
        const req = mod.get({hostname:urlObj.hostname,path:urlObj.pathname+urlObj.search,headers:{'User-Agent':'SYSACK-Agent/auto-update'},rejectUnauthorized:false}, res=>{
          if (res.statusCode>=300&&res.statusCode<400&&res.headers.location){const r2=mod.get(res.headers.location,res2=>{let d='';res2.on('data',c=>d+=c);res2.on('end',()=>res2.statusCode===200?resolve(d):reject(new Error('HTTP '+res2.statusCode)));});r2.on('error',reject);r2.end();return;}
          if (res.statusCode!==200) return reject(new Error('HTTP '+res.statusCode));
          let d='';res.on('data',c=>d+=c);res.on('end',()=>resolve(d));
        });
        req.on('error',reject);req.setTimeout(30000,()=>{req.destroy();reject(new Error('Timeout'));});req.end();
      });
      if (!novoConteudo||novoConteudo.length<1000) throw new Error('Arquivo inválido');
      const sp=path.join(__dirname,'agent-desktop.js'), bp=path.join(__dirname,'agent-desktop.backup.js');
      try{fs.copyFileSync(sp,bp);}catch(e){}
      fs.writeFileSync(sp,novoConteudo,'utf8');
      log(`[UPDATE/RTDB] Substituído (${novoConteudo.length} bytes). Reiniciando...`);
      resposta = {tipo:'update_ok',versao:versaoNova,agentId:AGENT_ID};
      await firestorePatch('agents/'+AGENT_ID,{versaoAgente:versaoNova,ultimaAtualizacao:new Date().toISOString(), agentVersion: versaoNova}).catch(()=>{});
      agendarReinicioAgent();
      setTimeout(()=>process.exit(0),2000);

    } else {
      resposta = { tipo: 'error', msg: 'tipo desconhecido: ' + msg.tipo };
    }
  } catch(e) {
    resposta = { tipo: 'error', msg: e.message };
  }

  // Escreve resposta — técnico recebe em <200ms via onValue
  try {
    await rtdbEscrever(`relay/${sessaoId}/resp`, {
      payload: resposta,
      ts:      Date.now(),
      agentId: AGENT_ID,
    });
  } catch(e) {
    log('[RTDB] Erro ao gravar resposta: ' + e.message + ' — usando Firestore relay');
    try {
      await firestorePatch('sessoes_remotas/' + sessaoId, {
        relay_resp: JSON.stringify(resposta),
        relay_resp_ts: Date.now(),
        relay_modo: 'firestore'
      });
    } catch(e2) {
      log('[Firestore Relay] Erro ao gravar resposta: ' + e2.message);
    }
  }
}

function iniciarRelayRtdb(sessaoId) {
  if (_sessoesAtivas.has(sessaoId)) return;
  _sessoesAtivas.add(sessaoId);
  log(`[RTDB] Iniciando relay para sessão ${sessaoId}`);

  // Grava handshake no Firestore SEMPRE (independente do RTDB)
  // O app lê este campo para saber que o agente está pronto
  firestorePatch('sessoes_remotas/' + sessaoId, {
    relay_status: 'ready',
    relay_handshake_ts: Date.now(),
    relay_modo: 'firestore',
    agentId: AGENT_ID,
    hostname: require('os').hostname(),
  }).then(() => log('[Relay] Handshake gravado no Firestore — sessão ' + sessaoId))
    .catch(e => log('[Relay] Handshake Firestore falhou: ' + e.message));

  // Tenta também RTDB (baixa latência se disponível)
  rtdbEscrever(`relay/${sessaoId}/handshake`, {
    agentId:  AGENT_ID,
    hostname: require('os').hostname(),
    ts:       Date.now(),
    status:   'ready',
  }).then(() => log(`[RTDB] Handshake gravado no RTDB — sessão ${sessaoId}`))
    .catch(() => {}); // silencia — Firestore é o canal principal

  // Escuta comandos via RTDB (baixa latência quando disponível)
  rtdbListen(sessaoId, msg => processarComandoRtdb(sessaoId, msg));

  // Fallback: escuta comandos via Firestore sessoes_remotas
  _iniciarPollFirestoreRelay(sessaoId);
}

function _iniciarPollFirestoreRelay(sessaoId) {
  let ultimoTs = 0;
  const poll = setInterval(async () => {
    if (!_sessoesAtivas.has(sessaoId)) { clearInterval(poll); return; }
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/sessoes_remotas/${sessaoId}?key=${API_KEY}`;
      const res = await fetch(url);
      if (!res.ok) return;
      const doc = await res.json();
      const ts  = Number(doc.fields?.relay_ts?.integerValue || doc.fields?.relay_ts?.doubleValue || 0);
      const cmd = doc.fields?.relay_cmd?.stringValue || '';
      if (ts > ultimoTs && cmd) {
        ultimoTs = ts;
        try {
          const msg = JSON.parse(cmd);
          log(`[Firestore Relay] Cmd: ${msg.tipo || JSON.stringify(msg).slice(0,50)}`);
          await processarComandoRtdb(sessaoId, msg);
        } catch(e) { log(`[Firestore Relay] Erro: ${e.message}`); }
      }
    } catch {}
  }, 1500);
}

function encerrarRelayRtdb(sessaoId) {
  _sessoesAtivas.delete(sessaoId);
  rtdbUnlisten(sessaoId);
  // Remove dados da sessão do RTDB
  rtdbEscrever(`relay/${sessaoId}`, null).catch(() => {});
  log(`[RTDB] Relay encerrado — sessão ${sessaoId}`);
}

// ════════════════════════════════════════════════════════════════
// executarComando — Firestore (recebe sessaoId e inicia RTDB relay)
// pollComandos    — poll 5s só para iniciar/encerrar sessões
// ════════════════════════════════════════════════════════════════

const _comandosEmProcessamento = new Set(); // lock em memória — evita reprocessar o mesmo doc concorrentemente

async function executarComando(doc) {
  const fields = doc.document?.fields || {};
  const getId  = f => f?.stringValue || '';
  const id     = doc.document?.name?.split('/').pop();
  const tipo   = getId(fields.tipo);
  const dados  = (() => { try { return JSON.parse(getId(fields.dados) || '{}'); } catch { return {}; } })();
  const aId    = getId(fields.agentId);

  if (aId !== AGENT_ID) return;
  if (!id) return;

  // Lock em memória — evita que pollComandos (Firestore) e o relay RTDB
  // processem o mesmo comando ao mesmo tempo, gerando race condition
  if (_comandosEmProcessamento.has(id)) return;
  _comandosEmProcessamento.add(id);

  try {
    // Ignora comandos de atualização "presos" há muito tempo na fila —
    // evita reprocessar lixo acumulado de tentativas antigas que falharam
    if (tipo === 'atualizar_agente') {
      const criadoEmStr = getId(fields.criadoEm) || dados.criadoEm || '';
      if (criadoEmStr) {
        const idadeMs = Date.now() - new Date(criadoEmStr).getTime();
        if (idadeMs > 10 * 60 * 1000) { // mais de 10 minutos = comando obsoleto
          log(`[UPDATE] Ignorando comando obsoleto (${Math.round(idadeMs/60000)} min) — id: ${id}`);
          await firestorePatch('agent_commands/' + id, {
            status: 'descartado', resultado: 'Comando expirado — não processado por estar obsoleto.'
          }).catch(() => {});
          return;
        }
      }
    }

    // Marca imediatamente para não processar duas vezes
    await firestorePatch('agent_commands/' + id, { status: 'processando' }).catch(() => {});

    // Segurança corporativa: não aceita token fixo nem senha enviada pelo portal.
    // Valida tipo, expiração, perfil solicitante, justificativa e contexto administrativo local.
    if (!(await validarComandoSeguro(id, tipo, fields, dados))) return;

    const requestedBy = getId(fields.requestedBy) || dados.requestedBy || dados.operador || '';
    log('[Relay] Comando Firestore seguro: ' + tipo + ' solicitado por ' + requestedBy);
    await auditAgentCommand(id, 'AGENT_COMMAND_ACCEPTED', {
      tipo,
      requestedBy: sanitizeAuditText(requestedBy),
      requestedByRole: sanitizeAuditText(getId(fields.requestedByRole) || dados.requestedByRole || ''),
      motivo: sanitizeAuditText(getId(fields.motivo) || dados.motivo || '')
    });
    await firestorePatch('agent_commands/' + id, { status: 'executando', executandoEm: new Date().toISOString() }).catch(() => {});

    return await _processarComandoInterno(id, tipo, dados, fields);
  } finally {
    // Libera o lock depois de um tempo — permite reprocessar se necessário no futuro
    setTimeout(() => _comandosEmProcessamento.delete(id), 30000);
  }
}

async function _processarComandoInterno(id, tipo, dados, fields) {
  const sessaoId = dados.sessaoId || '';

  if (tipo === 'iniciar_acesso_remoto' || tipo === 'usar_firebase_relay') {
    // A partir daqui todos os comandos vão pelo RTDB (push em tempo real)
    if (sessaoId) iniciarRelayRtdb(sessaoId);
    await firestorePatch('agent_commands/' + id, { status: 'concluido', resultado: RTDB_HOST ? 'rtdb-relay-ativo' : 'firestore-relay-ativo' }).catch(() => {});
    return;
  }

  if (tipo === 'encerrar_acesso_remoto') {
    if (sessaoId) encerrarRelayRtdb(sessaoId);
    await firestorePatch('agent_commands/' + id, { status: 'concluido' }).catch(() => {});
    return;
  }

  // ── BLOQUEIO DE MÁQUINA (todos os usuários) ──────────────────────
  if (tipo === 'bloquear_maquina') {
    try {
      const motivo    = dados.motivo    || 'Bloqueado pelo TI';
      const operador  = dados.operador  || 'TI';
      const adminUser = (dados.adminUser || '').replace(/['"]/g, '').trim();
      const adminPass = (dados.adminPass || '').replace(/'/g,  '').trim();

      const blockedUsersFile = path.join(__dirname, 'blocked_users.txt').replace(/\\/g, '\\\\');
      const lockFile         = path.join(__dirname, 'machine.lock');

      const motivoSafe = motivo.replace(/'/g, '').replace(/\n/g, ' ').replace(/"/g, '');

      // ── Script PowerShell com verificações explícitas e saída estruturada ──
      // Cada etapa crítica emite ERRO:<etapa>:<mensagem> se falhar.
      // Só emite BLOQUEIO_CONCLUIDO se TUDO teve êxito.
      const credBlock = adminUser && adminPass ? `
$adminUserRaw = '${adminUser}'
$adminPassRaw = '${adminPass}'
$secPass = ConvertTo-SecureString $adminPassRaw -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential ($adminUserRaw, $secPass)

# Valida usuário/senha antes de fazer qualquer alteração.
# Correção v2.1.12:
# - aceita usuario de dominio CESAN\\usuario e usuario@dominio;
# - tenta vários tipos de logon, pois alguns domínios bloqueiam logon interativo;
# - NÃO reprova falsamente domínio admin que chega por grupo AD aninhado;
# - o bloqueio local é executado pelo próprio agente rodando como SYSTEM/admin.
# ── Validação de credencial v3 ─────────────────────────────────────
# Estratégia em cascata para ambientes onde SYSTEM não consegue LogonUser:
# 1) net use contra o próprio compartilhamento IPC$ local (mais confiável em AD)
# 2) net use contra o DC (se domínio identificado)
# 3) LogonUser tipos 3/9/8/2 como último recurso
# O agente já roda como SYSTEM — a validação é apenas para confirmar que a senha
# informada pertence a um admin local, não para executar as etapas seguintes.

$ok = $false
$metodo = ''

# Detecta formato: DOMINIO\\usuario, usuario@dominio ou usuário local
$domain   = $null
$userOnly = $adminUserRaw
$isDomain = $false

if ($adminUserRaw -match '\\') {
  $parts    = $adminUserRaw.Split('\\', 2)
  $domain   = $parts[0]
  $userOnly = $parts[1]
  $isDomain = $true
} elseif ($adminUserRaw -match '@') {
  $domain   = ($adminUserRaw -split '@')[1]
  $isDomain = $true
}

# MÉTODO 1 — net use IPC$ local (funciona mesmo via SYSTEM, valida senha AD/local)
if (-not $ok) {
  try {
    $share = "\\\\$($env:COMPUTERNAME)\\IPC\`$"
    net use $share /delete /y 2>$null | Out-Null
    $out = net use $share /user:$adminUserRaw $adminPassRaw 2>&1
    if ($LASTEXITCODE -eq 0) {
      net use $share /delete /y 2>$null | Out-Null
      $ok = $true; $metodo = 'net_use_local'
      Write-Host "OK_CREDENCIAL_VALIDADA:metodo=$metodo;usuario=$adminUserRaw"
    }
  } catch {}
}

# MÉTODO 2 — net use IPC$ no DC (para contas de domínio)
if (-not $ok -and $isDomain -and $domain) {
  try {
    $dcShare = "\\\\$domain\\IPC\`$"
    net use $dcShare /delete /y 2>$null | Out-Null
    $out2 = net use $dcShare /user:$adminUserRaw $adminPassRaw 2>&1
    if ($LASTEXITCODE -eq 0) {
      net use $dcShare /delete /y 2>$null | Out-Null
      $ok = $true; $metodo = 'net_use_dc'
      Write-Host "OK_CREDENCIAL_VALIDADA:metodo=$metodo;usuario=$adminUserRaw"
    }
  } catch {}
}

# MÉTODO 3 — LogonUser (fallback; pode falhar em SYSTEM+GPO restritiva)
if (-not $ok) {
  try {
    Add-Type @"
using System; using System.Runtime.InteropServices;
public class LogonUtilV3 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool LogonUser(string u, string d, string p, int lt, int lp, out IntPtr t);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@ -ErrorAction SilentlyContinue
    $token = [IntPtr]::Zero
    $lastErr = 0
    foreach ($lt in @(3,9,8,2)) {
      $token = [IntPtr]::Zero
      $prov  = if ($adminUserRaw -match '@') { 3 } else { 0 }
      if ([LogonUtilV3]::LogonUser($userOnly, $domain, $adminPassRaw, $lt, $prov, [ref]$token)) {
        [LogonUtilV3]::CloseHandle($token) | Out-Null
        $ok = $true; $metodo = "logon_type_$lt"
        Write-Host "OK_CREDENCIAL_VALIDADA:metodo=$metodo;usuario=$adminUserRaw"
        break
      }
      $lastErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      if ($token -ne [IntPtr]::Zero) { [LogonUtilV3]::CloseHandle($token) | Out-Null }
    }
  } catch { Write-Host "AVISO_LOGONUSER:$_" }
}

if (-not $ok) {
  Write-Host "ERRO_CREDENCIAL_INVALIDA:Nenhum metodo de validacao obteve exito. Verifique usuario/senha. Usuario=$adminUserRaw"
  exit 10
}

# Verifica pertencimento ao grupo Administradores local (não abortivo)
$adminComprovado = $false
try {
  $adminGroup = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\\')[-1]
  $members = net localgroup "$adminGroup" 2>$null
  $n1 = $adminUserRaw.ToLower(); $n2 = $userOnly.ToLower()
  foreach ($m in $members) {
    $ml = $m.Trim().ToLower()
    if ($ml -eq $n1 -or $ml -eq $n2 -or $ml.EndsWith('\\' + $n2)) { $adminComprovado = $true }
    if ($ml -match 'domain admins|administradores do dom') { $adminComprovado = $true }
  }
} catch { Write-Host "AVISO_LOCALGROUP:$_" }

if ($adminComprovado) {
  Write-Host "OK_CREDENCIAL_ADMIN:$adminUserRaw"
} else {
  Write-Host "AVISO_ADMIN_NAO_COMPROVADO:Prosseguindo (agente roda como SYSTEM). Usuario=$adminUserRaw"
}
` : `
Write-Host "ERRO_CREDENCIAL_OBRIGATORIA:Informe usuario e senha de administrador local."
exit 13
`;

      const disableBlock = `
foreach ($u in $usuarios) {
  try { Disable-LocalUser -Name $u.Name -ErrorAction Stop; Write-Host "OK_DESATIVADO:$($u.Name)" }
  catch { Write-Host "ERRO_CONTA:$($u.Name):$_" }
}`;

      const psBlock = `
$ErrorActionPreference = 'Stop'
${credBlock}

# ETAPA 1 — Salvar lista de usuários ativos
try {
  $usuarios = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notmatch 'Admin|SYSTEM|DefaultAccount|WDAGUtilityAccount|Guest' }
  $lista = ($usuarios.Name) -join ','
  Set-Content -Path '${blockedUsersFile}' -Value $lista -Encoding UTF8 -ErrorAction Stop
  Write-Host "OK_LISTA:$lista"
} catch {
  Write-Host "ERRO_LISTA:$_"
  exit 1
}

# ETAPA 2 — Desativar contas
${disableBlock}

# ETAPA 3 — Verificar se todas foram desativadas
$ainda = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notmatch 'Admin|SYSTEM|DefaultAccount|WDAGUtilityAccount|Guest' }
if ($ainda.Count -gt 0) {
  Write-Host "ERRO_CONTAS_ATIVAS:$($ainda.Name -join ',')"
  exit 2
}

# ETAPA 4 — Escrever chave de aviso no Registry
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
try {
  Set-ItemProperty -Path $regPath -Name 'legalnoticecaption' -Value 'MAQUINA BLOQUEADA - TI CESAN' -Type String -Force -ErrorAction Stop
  Set-ItemProperty -Path $regPath -Name 'legalnoticetext'    -Value 'Esta maquina foi bloqueada pelo TI. Motivo: ${motivoSafe}. Para desbloquear, contate o TI CESAN.' -Type String -Force -ErrorAction Stop
  Write-Host "OK_REGISTRY"
} catch {
  Write-Host "ERRO_REGISTRY:$_"
  exit 3
}

# ETAPA 5 — Encerrar sessões ativas
query session 2>$null | Select-String 'Active|Ativo' | ForEach-Object {
  $parts = ($_ -replace '\s+', ' ').Trim() -split ' '
  $sid = $parts | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
  if ($sid) { logoff $sid /server:localhost 2>$null; Write-Host "OK_LOGOFF:$sid" }
}

# ETAPA 6 — Bloquear tela (melhor esforço)
try {
  Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class LW { [DllImport("user32.dll")] public static extern bool LockWorkStation(); }'
  [LW]::LockWorkStation() | Out-Null
  Write-Host "OK_LOCKSCREEN"
} catch { Write-Host "AVISO_LOCKSCREEN:$_" }

Write-Host "BLOQUEIO_CONCLUIDO"
`.trim();

      const psPath = path.join(__dirname, '_sysack_block.ps1');
      fs.writeFileSync(psPath, psBlock, 'utf8');

      let saida = '';
      let psErro = null;
      try {
        saida = execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psPath}"`, { timeout: 30000, windowsHide: true }).toString();
      } catch(ePow) {
        // execSync lança se o processo sair com código != 0 (nossos exit 1/2/3)
        saida = (ePow.stdout || '').toString() + (ePow.stderr || '').toString();
        psErro = ePow;
      }
      try { fs.unlinkSync(psPath); } catch {}

      // ── Interpretar saída estruturada ──────────────────────────────────────
      const linhas = saida.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      const erros  = linhas.filter(l => l.startsWith('ERRO_'));
      const avisos = linhas.filter(l => l.startsWith('AVISO_'));
      const concluido = linhas.some(l => l === 'BLOQUEIO_CONCLUIDO');

      // Log detalhado sempre
      for (const l of linhas) log(`[BLOQUEIO] ${l}`);

      if (!concluido || erros.length > 0) {
        // Identifica a falha mais específica para reportar
        let motFalha = 'Falha desconhecida durante o bloqueio.';
        if (erros.some(e => e.startsWith('ERRO_CREDENCIAL_INVALIDA')))
          motFalha = 'Usuário ou senha inválidos, ou a conta não tem permissão de logon nesta máquina.';
        else if (erros.some(e => e.startsWith('ERRO_SEM_PERMISSAO_ADMIN')))
          motFalha = 'A conta informada é válida, mas NÃO pertence ao grupo Administradores local desta máquina.';
        else if (erros.some(e => e.startsWith('ERRO_CREDENCIAL_OBRIGATORIA')))
          motFalha = 'Credenciais de administrador local são obrigatórias.';
        else if (erros.some(e => e.startsWith('ERRO_VALIDACAO_CREDENCIAL')))
          motFalha = 'Falha ao validar credenciais administrativas.';
        else if (erros.some(e => e.startsWith('ERRO_LISTA')))
          motFalha = 'Não foi possível salvar a lista de usuários (sem permissão de escrita no diretório do agente?).';
        else if (erros.some(e => e.startsWith('ERRO_CONTA'))) {
          const contas = erros.filter(e => e.startsWith('ERRO_CONTA')).map(e => e.split(':')[1]).join(', ');
          motFalha = `Não foi possível desativar as contas: ${contas}. Verifique se as credenciais de administrador estão corretas e se o usuário tem permissão para gerenciar contas locais.`;
        } else if (erros.some(e => e.startsWith('ERRO_CONTAS_ATIVAS'))) {
          const contas = erros.find(e => e.startsWith('ERRO_CONTAS_ATIVAS'))?.split(':')[1] || '';
          motFalha = `Contas ainda ativas após tentativa de desativação: ${contas}. Credencial de administrador pode ser inválida ou insuficiente.`;
        } else if (erros.some(e => e.startsWith('ERRO_REGISTRY'))) {
          motFalha = 'Sem permissão para alterar o Registry (HKLM\\...\\Policies\\System). O agente precisa rodar como SYSTEM ou administrador local.';
        } else if (psErro) {
          motFalha = `PowerShell retornou erro: ${psErro.message}`;
        }

        const msgErro = `[BLOQUEIO ABORTADO] ${motFalha}`;
        log(msgErro);
        await auditAgentCommand(id, 'MACHINE_LOCK_ABORTED', { tipo, operador: sanitizeAuditText(operador), motivo: sanitizeAuditText(motivo), falha: sanitizeAuditText(motFalha) });
        await reportAgentResult(id, tipo, 'erro', msgErro, { operador: sanitizeAuditText(operador), motivo: sanitizeAuditText(motivo), falha: sanitizeAuditText(motFalha) });
        // Reverte o campo bloqueado no Firestore para não enganar o painel
        await firestorePatch('agents/' + AGENT_ID, { bloqueado: false }).catch(() => {});
        await firestorePatch('agent_commands/' + id, { status: 'erro', resultado: msgErro, concluidoEm: new Date().toISOString() }).catch(() => {});
        return;
      }

      if (avisos.length) {
        for (const a of avisos) log(`[BLOQUEIO] ⚠️ ${a}`);
      }

      // Tudo OK — grava estado e confirma
      fs.writeFileSync(lockFile, JSON.stringify({ bloqueado: true, motivo, operador, bloqueadoEm: new Date().toISOString(), hostname: require('os').hostname() }), 'utf8');
      resultado = `Máquina bloqueada com sucesso. Contas desativadas, registro atualizado. Motivo: ${motivo}`;
      log(`[BLOQUEIO] ✅ ${resultado}`);
      await firestorePatch('agent_commands/' + id, { status: 'concluido', resultado, concluidoEm: new Date().toISOString() }).catch(() => {});
      await reportAgentResult(id, tipo, 'concluido', resultado, { operador: sanitizeAuditText(operador), motivo: sanitizeAuditText(motivo) });
      await auditAgentCommand(id, 'MACHINE_LOCK_EXECUTED', { tipo, operador: sanitizeAuditText(operador), motivo: sanitizeAuditText(motivo), resultado: sanitizeAuditText(resultado) });
    } catch(e) {
      log('[BLOQUEIO] Erro inesperado: ' + e.message);
      await auditAgentCommand(id, 'MACHINE_LOCK_ERROR', { tipo, erro: sanitizeAuditText(e.message) });
      await reportAgentResult(id, tipo, 'erro', '[BLOQUEIO ABORTADO] ' + e.message, { erro: sanitizeAuditText(e.message) });
      await firestorePatch('agents/' + AGENT_ID, { bloqueado: false }).catch(() => {});
      await firestorePatch('agent_commands/' + id, { status: 'erro', resultado: '[BLOQUEIO ABORTADO] ' + e.message }).catch(() => {});
    }
    return;
  }

  if (tipo === 'desbloquear_maquina') {
    try {
      const operador         = dados.operador || 'TI';
      const blockedUsersFile = path.join(__dirname, 'blocked_users.txt').replace(/\\/g, '\\\\');

      const psUnblock = `
# 1. Remove aviso da tela de logon
$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
Remove-ItemProperty -Path $regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $regPath -Name 'legalnoticetext'    -ErrorAction SilentlyContinue

# 2. Reativa usuarios que foram desativados
$listaFile = '${blockedUsersFile}'
if (Test-Path $listaFile) {
  $nomes = (Get-Content $listaFile -Encoding UTF8) -split ','
  foreach ($n in $nomes) {
    $n = $n.Trim()
    if ($n) {
      try { Enable-LocalUser -Name $n; Write-Host "Reativado: $n" } catch { Write-Host "Erro ao reativar $n: $_" }
    }
  }
  Remove-Item $listaFile -Force
} else {
  # Fallback: reativa todos os desativados (exceto contas do sistema)
  Get-LocalUser | Where-Object { $_.Enabled -eq $false -and $_.Name -notmatch 'Guest|DefaultAccount|WDAGUtilityAccount' } | ForEach-Object {
    try { Enable-LocalUser -Name $_.Name; Write-Host "Reativado (fallback): $($_.Name)" } catch {}
  }
}

Write-Host "DESBLOQUEIO_CONCLUIDO"
`.trim();

      const psPath = path.join(__dirname, '_sysack_unblock.ps1');
      fs.writeFileSync(psPath, psUnblock, 'utf8');
      const saida = execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psPath}"`, { timeout: 30000, windowsHide: true }).toString();
      try { fs.unlinkSync(psPath); } catch {}
      try { fs.unlinkSync(path.join(__dirname, 'machine.lock')); } catch {}

      log(`[DESBLOQUEIO] ${saida.includes('DESBLOQUEIO_CONCLUIDO') ? 'Concluído' : saida.trim()}`);
      log(`[DESBLOQUEIO] Máquina desbloqueada por ${operador}`);
      resultado = `Desbloqueio aplicado por ${operador}. Usuários reativados.`;
      await firestorePatch('agent_commands/' + id, { status: 'concluido', resultado, concluidoEm: new Date().toISOString() }).catch(() => {});
      await auditAgentCommand(id, 'MACHINE_UNLOCK_EXECUTED', { tipo, operador: sanitizeAuditText(operador), resultado: sanitizeAuditText(resultado) });
    } catch(e) {
      log('[DESBLOQUEIO] Erro: ' + e.message);
      await auditAgentCommand(id, 'MACHINE_UNLOCK_ERROR', { tipo, erro: sanitizeAuditText(e.message) });
      await firestorePatch('agent_commands/' + id, { status: 'erro', resultado: e.message }).catch(() => {});
    }
    return;
  }


  // ── COLETA SEGURA DO EVENT VIEWER PARA ANÁLISE IA ───────────────
  if (tipo === 'coletar_eventviewer' || tipo === 'analisar_eventviewer_ia') {
    try {
      const maxEvents = Math.min(Number(dados.maxEvents || 250), 1000);
      const logs = Array.isArray(dados.logs) && dados.logs.length ? dados.logs : ['System', 'Application'];
      const logsSafe = logs.map(x => String(x).replace(/[^A-Za-z0-9_\-]/g, '')).filter(Boolean).slice(0, 5);
      const ps = `
$ErrorActionPreference = 'SilentlyContinue'
$logs = @(${logsSafe.map(l => "'" + l + "'").join(',')})
$out = @()
foreach ($log in $logs) {
  Get-WinEvent -LogName $log -MaxEvents ${maxEvents} | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message | ForEach-Object {
    $out += [pscustomobject]@{
      Log=$log; TimeCreated=$_.TimeCreated; Provider=$_.ProviderName; Id=$_.Id; Level=$_.LevelDisplayName; Message=($_.Message -replace "[\r\n]", ' ')
    }
  }
}
$out | ConvertTo-Json -Depth 4 -Compress
`.trim();
      const psPath = path.join(__dirname, '_sysack_eventviewer.ps1');
      fs.writeFileSync(psPath, ps, 'utf8');
      const raw = execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psPath}"`, { timeout: 45000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }).toString();
      try { fs.unlinkSync(psPath); } catch {}
      const saida = raw.slice(0, 900000); // evita documento gigante
      await firestoreCreate('agent_eventviewer', {
        agentId: AGENT_ID,
        hostname: os.hostname(),
        commandId: id,
        requestedBy: sanitizeAuditText(dados.requestedBy || dados.operador || ''),
        logs: logsSafe.join(','),
        maxEvents,
        payload: saida,
        createdAt: new Date().toISOString(),
        status: 'coletado'
      });
      resultado = `Event Viewer coletado com sucesso (${logsSafe.join(', ')} / até ${maxEvents} eventos por log).`;
      await auditAgentCommand(id, 'EVENTVIEWER_COLLECTED', { tipo, logs: logsSafe.join(','), maxEvents, resultado });
      await firestorePatch('agent_commands/' + id, { status: 'concluido', resultado, concluidoEm: new Date().toISOString() }).catch(() => {});
    } catch(e) {
      log('[EVENTVIEWER] Erro: ' + e.message);
      await auditAgentCommand(id, 'EVENTVIEWER_ERROR', { tipo, erro: sanitizeAuditText(e.message) });
      await firestorePatch('agent_commands/' + id, { status: 'erro', resultado: e.message }).catch(() => {});
    }
    return;
  }

  // Comandos legados via Firestore (compatibilidade com agentes antigos)
  let resultado = '';
  let erroExec = false;
  try {
    if (tipo === 'powershell') {
      const cmd = dados.cmd || '';
      resultado = execSync(
        'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + cmd.replace(/"/g, '\\"') + '"',
        { timeout: 15000, windowsHide: true }
      ).toString();

    } else if (tipo === 'atualizar_agente') {
      const urlNova    = dados.url    || '';
      const versaoNova = dados.versao || '';
      if (!urlNova) throw new Error('URL do novo agente não informada');
      log(`[UPDATE] Iniciando atualização para v${versaoNova || '(sem versão informada)'} via ${urlNova}`);

      const selfPath   = process.argv[1] || path.join(__dirname, 'agent.js');
      const tempPath   = selfPath + '.new.js';
      const backupPath = selfPath.replace(/\.js$/i, '.backup.js');

      async function marcarUpdate(status, texto, extra = {}) {
        try {
          await firestorePatch('agent_commands/' + id, {
            status,
            resultado: texto,
            atualizadoEm: new Date().toISOString(),
            ...extra,
          });
        } catch(e) {
          log('[UPDATE] Falha ao atualizar status do comando: ' + e.message);
        }
      }

      try {
        // Heartbeat imediato — painel sabe que agente recebeu antes do timeout
        await marcarUpdate('processando', 'Agente recebeu o comando — preparando download...', {
          processandoEm: new Date().toISOString(), etapa: 'preparando_download'
        });

        function baixarArquivoRobusto(urlInicial) {
          return new Promise((resolve, reject) => {
            const chunks = [];
            let finalizado = false;
            let total = 0;
            const MAX_BYTES = 5 * 1024 * 1024; // proteção contra HTML/erro gigante

            function falhar(err) {
              if (finalizado) return;
              finalizado = true;
              reject(err instanceof Error ? err : new Error(String(err)));
            }
            function ok(txt) {
              if (finalizado) return;
              finalizado = true;
              resolve(txt);
            }
            function baixar(urlAtual, redirects = 0) {
              if (redirects > 8) return falhar(new Error('Muitos redirecionamentos no download'));
              let urlObj;
              try { urlObj = new URL(urlAtual); }
              catch(e) { return falhar(new Error('URL inválida para atualização: ' + urlAtual)); }

              const mod = urlObj.protocol === 'https:' ? require('https') : require('http');
              log(`[UPDATE] Download passo ${redirects + 1}: ${urlObj.href}`);
              const req = mod.get({
                protocol: urlObj.protocol,
                hostname: urlObj.hostname,
                port: urlObj.port || undefined,
                path: urlObj.pathname + urlObj.search,
                headers: {
                  'User-Agent': 'SYSACK-Agent/auto-update',
                  'Cache-Control': 'no-cache, no-store, max-age=0',
                  'Pragma': 'no-cache',
                },
                rejectUnauthorized: false,
              }, res => {
                log(`[UPDATE] HTTP ${res.statusCode} recebido de ${urlObj.hostname}`);
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                  res.resume();
                  let prox;
                  try { prox = new URL(res.headers.location, urlObj).href; }
                  catch(e) { return falhar(new Error('Redirect inválido: ' + res.headers.location)); }
                  return baixar(prox, redirects + 1);
                }
                if (res.statusCode !== 200) {
                  let body = '';
                  res.setEncoding('utf8');
                  res.on('data', c => { body += c; if (body.length > 500) body = body.slice(0, 500); });
                  res.on('end', () => falhar(new Error('HTTP ' + res.statusCode + ' ao baixar agente. Corpo: ' + body.slice(0, 200))));
                  return;
                }
                res.on('data', c => {
                  total += c.length;
                  if (total > MAX_BYTES) {
                    req.destroy();
                    return falhar(new Error('Arquivo baixado excedeu limite de segurança (' + MAX_BYTES + ' bytes)'));
                  }
                  chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
                });
                res.on('end', () => ok(Buffer.concat(chunks).toString('utf8')));
                res.on('error', falhar);
              });
              req.on('error', falhar);
              req.setTimeout(60000, () => {
                req.destroy();
                falhar(new Error('Timeout de 60s no download do agente'));
              });
            }
            baixar(urlInicial, 0);
          });
        }

        await marcarUpdate('processando', 'Baixando nova versão do agente...', { etapa: 'download' });
        const novoConteudo = await baixarArquivoRobusto(urlNova);
        log(`[UPDATE] Download concluído: ${novoConteudo.length} bytes`);

        if (!novoConteudo || novoConteudo.length < 1000) {
          throw new Error(`Arquivo inválido (${novoConteudo?.length ?? 0} bytes)`);
        }
        if (!novoConteudo.includes('SYSACK Agent Desktop')) {
          throw new Error('Arquivo baixado não parece ser o agent-desktop.js do SYSACK');
        }
        const versaoBaixadaMatch = novoConteudo.match(/SYSACK Agent Desktop v([0-9.]+)/);
        const versaoBaixada = versaoBaixadaMatch ? versaoBaixadaMatch[1] : '';
        log(`[UPDATE] Versão detectada no arquivo baixado: ${versaoBaixada || 'não identificada'}`);
        if (versaoNova && versaoBaixada && versaoBaixada !== versaoNova) {
          throw new Error(`Versão baixada (${versaoBaixada}) diferente da solicitada (${versaoNova}). Verifique o deploy no Vercel.`);
        }

        await marcarUpdate('processando', 'Download concluído — gravando arquivo temporário...', { etapa: 'gravando_temp', versaoBaixada });
        try {
          fs.copyFileSync(selfPath, backupPath);
          log('[UPDATE] Backup: ' + backupPath);
        } catch(e) {
          log('[UPDATE] Aviso: não foi possível criar backup: ' + e.message);
        }
        fs.writeFileSync(tempPath, novoConteudo, 'utf8');
        const tempLen = fs.readFileSync(tempPath, 'utf8').length;
        if (tempLen < 1000) throw new Error('Arquivo temporário inválido');
        log(`[UPDATE] Temp OK — ${tempPath} (${tempLen} bytes). Agendando reinício...`);

        resultado = `Atualização v${versaoNova || versaoBaixada || '?'} baixada e agendada. Reiniciando serviço.`;
        await firestorePatch('agents/' + AGENT_ID, {
          versaoAgente: versaoNova || versaoBaixada || '',
          agentVersion: versaoNova || versaoBaixada || '',
          ultimaAtualizacao: new Date().toISOString(),
          updateStatus: 'reiniciando',
          updateCommandId: id,
        }).catch(e => log('[UPDATE] Aviso: falha ao atualizar agents/' + AGENT_ID + ': ' + e.message));

        await marcarUpdate('concluido', resultado, {
          etapa: 'reiniciando', concluidoEm: new Date().toISOString(), versaoBaixada,
        });
        log('[UPDATE] Confirmação gravada no Firestore. Reiniciando em 2s...');
        agendarReinicioAgent();
        setTimeout(() => process.exit(0), 2000);
        return;
      } catch(e) {
        const msgErro = (e && (e.stack || e.message)) ? String(e.stack || e.message) : String(e);
        erroExec = true;
        resultado = 'Falha na atualização do agente: ' + msgErro.slice(0, 1500);
        log('[UPDATE] ERRO: ' + msgErro);
        try {
          await firestorePatch('agent_commands/' + id, {
            status: 'erro',
            resultado,
            erro: msgErro.slice(0, 1500),
            etapa: 'erro_update',
            erroEm: new Date().toISOString(),
          });
        } catch(e2) {
          log('[UPDATE] Falha ao gravar erro no Firestore: ' + e2.message);
        }
        try {
          await reportAgentResult(id, tipo, 'erro', resultado, { erro: msgErro.slice(0, 1500) });
        } catch(e3) {}
        return;
      }

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

    } else {
      resultado = 'tipo desconhecido: ' + tipo;
    }
  } catch(e) {
    erroExec = true;
    resultado = '[ERRO] ' + e.message;
  }

  if (sessaoId) {
    await firestorePatch('sessoes_remotas/' + sessaoId + '/relay/resposta', {
      resultado, tipo, ts: new Date().toISOString(), agentId: AGENT_ID,
    }).catch(() => {});
  }
  // atualizar_agente já gravou o status antes do process.exit — não duplicar
  if (tipo !== 'atualizar_agente') {
    await firestorePatch('agent_commands/' + id, { status: erroExec ? 'erro' : 'concluido', resultado: resultado.slice(0, 500) }).catch(() => {});
  }
}

// Poll Firestore — somente para receber "iniciar_acesso_remoto" com sessaoId
// Intervalo de 5s (era 3s) — depois que o relay RTDB inicia, não é mais usado
async function pollComandos() {
  try {
    const docs = await firestoreQuery('agent_commands', [
      ['agentId', 'EQUAL', AGENT_ID],
      ['status',  'EQUAL', 'pendente']
    ]);
    if (Array.isArray(docs)) {
      for (const doc of docs) {
        if (doc.document) await executarComando(doc);
      }
    }
  } catch(e) {}
}

setInterval(pollComandos, 800);
setTimeout(pollComandos, 200);


// ── Atualiza ativo correspondente com hostname ────────────────────
async function atualizarAtivoComHostname(dados) {
  try {
    const ip = dados.ip;
    if (!ip) return;

    // Busca ativo pelo IP no Firestore
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery?key=${API_KEY}`;
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

// Token do tunnel Cloudflare — buscado do Firestore (sysack_config/tunnel)
// Para configurar: Firebase Console → Firestore → sysack_config → tunnel → campo "token"
// TUNNEL_TOKEN já declarado no topo do arquivo

async function carregarConfigTunnel() {
  // Busca token do Firestore — um lugar só, distribui para todos os agentes
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/sysack_config/tunnel?key=${API_KEY}`;
  return new Promise(resolve => {
    const req = https.request(url, { method: 'GET', rejectUnauthorized: false }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try {
          const doc = JSON.parse(raw);
          const t = doc.fields?.token?.stringValue || '';
          if (t) {
            TUNNEL_TOKEN = t;
            log('[Tunnel] Token carregado do Firestore (sysack_config/tunnel)');
          } else if (!TUNNEL_TOKEN) {
            log('[Tunnel] Sem token — tunnel automático ficará desativado');
          }
        } catch { /* usa fallback do config.json */ }
        resolve();
      });
    });
    req.on('error', () => resolve());
    req.end();
  });
}

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
    // Carrega token do tunnel do Firestore.
    // IMPORTANTE: sem token NÃO inicia quick tunnel automaticamente.
    // Isso evita loop de tentativas, rate limit do Cloudflare e bloqueios pelo proxy/rede.
    await carregarConfigTunnel();

    if (!TUNNEL_TOKEN) {
      log('[Tunnel] Sem token configurado — tunnel automático desativado');
      try {
        await firestorePatch('agents/' + AGENT_ID, {
          tunnelAtivo: false,
          tunnelUrl: '',
          tunnelModo: 'disabled',
          tunnelStatus: 'sem_token',
          tunnelMensagem: 'Tunnel automático desativado: configure sysack_config/tunnel.token para habilitar acesso remoto.'
        });
      } catch(e) {}
      return;
    }

    await carregarCredenciaisProxy();
    const ok = await baixarCloudflared();
    if (!ok) { log('[Tunnel] Falha ao baixar cloudflared'); return; }

    log('[Tunnel] Iniciando tunnel Cloudflare...');

    // ── Tunnel NOMEADO com token (sem rate limit, recomendado) ──
    // Token configurado em: Firebase Console → sysack_config → tunnel → campo "token"
    if (TUNNEL_TOKEN) {
      log('[Tunnel] Usando tunnel NOMEADO (sysack_config/tunnel) — sem rate limit');
      const proc = spawn(CLOUDFLARED_PATH, [
        'tunnel', '--no-autoupdate', 'run', '--token', TUNNEL_TOKEN,
      ], { windowsHide: true, detached: false, env: { ...process.env } });

      proc.stderr.on('data', data => {
        const txt = data.toString();
        if (txt.includes('Registered tunnel') || txt.includes('Connection') && txt.includes('established')) {
          log('[Tunnel] Tunnel nomeado conectado!');
          // Grava status ativo — URL fixa configurada no dashboard Cloudflare
          firestorePatch('agents/' + AGENT_ID, { tunnelAtivo: true, tunnelModo: 'named' }).catch(() => {});
        }
      });
      proc.stdout.on('data', data => {
        const txt = data.toString();
        if (txt.includes('Registered') || txt.includes('established')) {
          log('[Tunnel] ' + txt.trim());
        }
      });
      proc.on('close', async code => {
        log('[Tunnel] Tunnel nomeado encerrado — código: ' + code);
        try { await firestorePatch('agents/' + AGENT_ID, { tunnelAtivo: false }); } catch(e) {}
        setTimeout(iniciarTunnel, code === 0 ? 5000 : 30000);
      });
      proc.on('error', e => log('[Tunnel] Erro: ' + e.message));
      return;
    }

    // ── Modo 2: Quick tunnel gratuito (trycloudflare.com — sujeito a rate limit) ──
    log('[Tunnel] Sem token configurado — quick tunnel bloqueado/desativado');
    return;
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
      const match = txt.match(/https:\/\/[a-z0-9\-]+\.trycloudflare\.com/);
      if (match && !tunnelUrl) {
        tunnelUrl = match[0].replace('https://', 'wss://');
        log('[Tunnel] URL gerada: ' + tunnelUrl);
        await firestorePatch('agents/' + AGENT_ID, { tunnelUrl, tunnelAtivo: true });
        log('[Tunnel] URL gravada no Firestore');
      }
    });

    proc.on('close', async code => {
      log('[Tunnel] Processo encerrado — código: ' + code + (code===1?' (provável bloqueio de rede/proxy)':''));
      tunnelUrl = null;
      try { await firestorePatch('agents/' + AGENT_ID, { tunnelUrl: '', tunnelAtivo: false }); } catch(e) {}
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
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/impressoras?key=${API_KEY}&pageSize=200`;
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
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/switches?key=${API_KEY}&pageSize=100`;
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
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/switches?key=${API_KEY}&pageSize=100`;
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


// ── Diagnóstico de conectividade ao iniciar ────────────────────
async function verificarConectividade() {
  return new Promise(resolve => {
    const req = https.request({
      hostname: 'firestore.googleapis.com',
      path: '/',
      method: 'GET',
      rejectUnauthorized: false,
      timeout: 8000,
    }, res => {
      log(`[CONECTIVIDADE] Firestore googleapis.com: HTTP ${res.statusCode} — OK`);
      resolve(true);
    });
    req.on('error', e => {
      log(`[CONECTIVIDADE] FALHA ao acessar firestore.googleapis.com: ${e.message}`);
      log('[CONECTIVIDADE] Verifique: 1) acesso à internet 2) proxy/firewall bloqueando googleapis.com 3) Node.js tem permissão de rede');
      resolve(false);
    });
    req.on('timeout', () => {
      req.destroy();
      log('[CONECTIVIDADE] TIMEOUT ao acessar firestore.googleapis.com — proxy ou firewall bloqueando');
      resolve(false);
    });
    req.end();
  });
}

// ── Watchdog: reloga o agente se lastSeen parar de atualizar ───
let _ultimoSucessoGravacao = Date.now();
const _origFirestoreSet = firestoreSet;
// Override transparente para rastrear último sucesso
global._watchdogOk = () => { _ultimoSucessoGravacao = Date.now(); };
setInterval(() => {
  const inativo = Date.now() - _ultimoSucessoGravacao;
  if (inativo > 5 * 60 * 1000) { // 5 minutos sem gravar
    log(`[WATCHDOG] Sem gravação no Firestore há ${Math.round(inativo/60000)}min — forçando novo ciclo`);
    reportar().catch(e => log('[WATCHDOG] Erro no ciclo forçado: ' + e.message));
    _ultimoSucessoGravacao = Date.now(); // evita loop
  }
}, 2 * 60 * 1000);

// ── Inicialização ───────────────────────────────────────────────
verificarConectividade().then(ok => {
  if (!ok) {
    log('[AVISO] Sem conectividade ao Firestore. O agente tentará mesmo assim (pode ser falso positivo de proxy).');
  }
  reportar(); // Primeira execução imediata
  setInterval(reportar, INTERVAL);
});

// Mantém o processo vivo
process.on('uncaughtException', err => log(`[UNCAUGHT] ${err.message}`));
process.on('unhandledRejection', err => log(`[UNHANDLED] ${err}`));
