/**
 * SYSACK Agent — src/agent.js
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  ARQUITETURA DE DADOS — EMPREGADOS                              │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  Fonte PRINCIPAL → AD CESAN (LDAPS :636)                        │
 * │    name, sAMAccountName (login), department (lotação),          │
 * │    physicalDeliveryOfficeName (local), telephoneNumber,         │
 * │    mobile, ipPhone, mail, userAccountControl (status AD),       │
 * │    accountExpires                                               │
 * │                                                                 │
 * │  Fonte COMPLEMENTAR → SQL Server (PowerShell)                   │
 * │    mat (matrícula), ausencia, dataInicioAusencia,               │
 * │    dataFimAusencia  ← ÚNICO dado que vem do SQL                 │
 * │                                                                 │
 * │  Persistência → Firestore empregados/{mat}                      │
 * │    Gravado a cada ciclo. Serve como cache/failover:             │
 * │    se o AD estiver fora, o frontend lê daqui.                   │
 * │                                                                 │
 * │  Fluxo da Cloud Function buscarEmpregados (index.js):           │
 * │    1. Tenta AD (LDAP search em tempo real)                      │
 * │    2. Se falhar → lê Firestore (último snapshot válido)         │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Status interpretados do userAccountControl:
 *   adAtivo         → conta habilitada e não expirada
 *   adDesativada    → bit 0x0002 (ACCOUNTDISABLE)
 *   adBloqueada     → bit 0x0010 (LOCKOUT)
 *   adSenhaExpirada → bit 0x0800 (PASSWORD_EXPIRED)
 *   adContaExpirada → accountExpires < agora
 *   statusAD        → 'ativo'|'desativado'|'bloqueado'|'senha_expirada'|'expirado'
 */

'use strict';

const { exec }     = require('child_process');
const path         = require('path');
const fs           = require('fs');
const https        = require('https');
const tls          = require('tls');
const os           = require('os');
const firebaseAuth = require('./firebase-auth');

// ─── Config ───────────────────────────────────────────────────
// Procura config.json primeiro no mesmo diretório do script (src/),
// depois no diretório pai (raiz do projeto) — ambos são válidos.
const CONFIG_PATH = (() => {
  const local  = path.join(__dirname, 'config.json');
  const parent = path.join(__dirname, '..', 'config.json');
  if (fs.existsSync(local))  return local;
  if (fs.existsSync(parent)) return parent;
  return parent; // fallback com mensagem de erro adequada
})();

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    console.error('[Agent] config.json não encontrado. Execute setup.js primeiro.');
    process.exit(1);
  }
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); }
  catch (e) { console.error('[Agent] config.json inválido:', e.message); process.exit(1); }
}

const cfg = loadConfig();

const SYNC_INTERVAL_MS = (cfg.syncIntervalMinutes || 5) * 60 * 1000;
const BATCH_SIZE       = cfg.batchSize || 20;

// Cache de hashes para evitar writes desnecessários no Firestore
// Chave: docId  →  valor: hash da última gravação
// Limpo a cada reinício do agente (memória, sem persistência)
const _hashCache = new Map();

// ─── LDAP config ──────────────────────────────────────────────
// Adicione ao config.json:
// "ldap": {
//   "url":     "cesan.com.br",
//   "port":    636,
//   "bindDN":  "ldapuser",
//   "bindPwd": "eb*jo2k-",
//   "baseDN":  "OU=Organograma,OU=CESAN,DC=cesan,DC=com,DC=br",
//   "filter":  "(&(objectClass=user)(objectCategory=person)(sAMAccountName=*))"
// }
const LDAP_CFG  = cfg.ldap || {};
const LDAP_HOST = LDAP_CFG.url     || 'cesan.com.br';
const LDAP_PORT = LDAP_CFG.port    || 636;
const LDAP_BIND = LDAP_CFG.bindDN  || 'ldapuser';
const LDAP_PWD  = LDAP_CFG.bindPwd || '';
const LDAP_BASE = LDAP_CFG.baseDN  || 'OU=Organograma,OU=CESAN,DC=cesan,DC=com,DC=br';
const LDAP_FILT = LDAP_CFG.filter  || '(&(objectClass=user)(objectCategory=person)(sAMAccountName=*))';

// Atributos solicitados ao AD — inclui campos de status de conta
const LDAP_ATTRS = [
  'name',
  'sAMAccountName',
  'employeeID',                  // matrícula corporativa (campo principal)
  'employeeNumber',              // matrícula alternativa (alguns ADs usam este)
  'department',
  'physicalDeliveryOfficeName',
  'title',                       // cargo/função no AD
  'initials',                    // matrícula CESAN completa (com dígito verificador)
  'telephoneNumber',
  'mobile',
  'ipPhone',
  'mail',
  'userAccountControl',
  'accountExpires',
];

// ─── Firebase REST ────────────────────────────────────────────
const FB_PROJECT = cfg.firebaseProjectId || 'sysack-829e2';
const FB_API_KEY = cfg.firebaseApiKey    || '';
const FS_BASE    = `https://firestore.googleapis.com/v1/projects/${FB_PROJECT}/databases/(default)/documents`;

async function firestoreRequest(method, fsPath, body = null) {
  const token = await firebaseAuth.obterToken();
  return new Promise((resolve, reject) => {
    const sep     = fsPath.includes('?') ? '&' : '?';
  const url     = `${FS_BASE}${fsPath}${sep}key=${encodeURIComponent(FB_API_KEY)}`;
    const data    = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (data)  headers['Content-Length'] = Buffer.byteLength(data);
    if (token) headers['Authorization']  = `Bearer ${token}`;
    const urlObj = new URL(url);
    const req = https.request({
      method, headers,
      hostname: urlObj.hostname,
      path:     urlObj.pathname + urlObj.search,
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); }
        } else {
          let msg = `HTTP ${res.statusCode}`;
          try { const e = JSON.parse(raw); msg = e.error?.message || e.error?.status || msg; } catch {}
          reject(new Error(`Firestore ${method} ${fsPath.split('/').slice(-2).join('/')}: ${msg}`));
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function toField(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean')  return { booleanValue: val };
  if (typeof val === 'number')   return { integerValue: String(Math.round(val)) };
  if (val instanceof Date)       return { timestampValue: val.toISOString() };
  return { stringValue: String(val) };
}


// ─── Hash leve para detectar mudança de dados ─────────────────
// Evita writes desnecessários no Firestore quando os dados não mudaram
function hashDoc(data) {
  const keys = ['nome','login','mat','setor','cargo','local','email','status','statusAD',
                 'adAtivo','adDesativada','adBloqueada','adSenhaExpirada','adContaExpirada',
                 'bloquearRecursosTI','emAusencia','tipoAusencia','ativo'];
  return keys.map(k => `${k}:${data[k] ?? ''}`).join('|');
}

async function fsSet(collection, docId, data) {
  const safeId = String(docId).replace(/[/\\]/g, '_').slice(0, 1500);
  const fields  = {};
  for (const [k, v] of Object.entries(data)) fields[k] = toField(v);
  fields['updatedAt']  = { timestampValue: new Date().toISOString() };
  fields['syncSource'] = { stringValue: 'sysack-agent' };
  return firestoreRequest('PATCH', `/${collection}/${safeId}`, { fields });
}

async function verificarConexao() {
  try { await firestoreRequest('GET', '/sync_logs?pageSize=1'); return true; }
  catch { return false; }
}

// ─── Sanitização de texto (encoding SQL Server) ───────────────
const CHAR_FIX_MAP = {
  '\u00c3\u00a3':'ã','\u00c3\u00a0':'à','\u00c3\u00a1':'á','\u00c3\u00a2':'â',
  '\u00c3\u00a4':'ä','\u00c3\u00a7':'ç','\u00c3\u00a8':'è','\u00c3\u00a9':'é',
  '\u00c3\u00aa':'ê','\u00c3\u00ab':'ë','\u00c3\u00ac':'ì','\u00c3\u00ad':'í',
  '\u00c3\u00ae':'î','\u00c3\u00af':'ï','\u00c3\u00b2':'ò','\u00c3\u00b3':'ó',
  '\u00c3\u00b4':'ô','\u00c3\u00b5':'õ','\u00c3\u00b6':'ö','\u00c3\u00b9':'ù',
  '\u00c3\u00ba':'ú','\u00c3\u00bb':'û','\u00c3\u00bc':'ü',
  '\u00c3\u0083':'Ã','\u00c3\u0081':'Á','\u00c3\u0082':'Â','\u00c3\u0087':'Ç',
  '\u00c3\u0089':'É','\u00c3\u008a':'Ê','\u00c3\u008d':'Í','\u00c3\u0093':'Ó',
  '\u00c3\u0094':'Ô','\u00c3\u0095':'Õ','\u00c3\u009a':'Ú','\ufffd':'',
};
const WIN1252 = {
  0x80:'€',0x82:'‚',0x83:'ƒ',0x84:'„',0x85:'…',0x86:'†',0x87:'‡',0x88:'ˆ',
  0x89:'‰',0x8A:'Š',0x8B:'‹',0x8C:'Œ',0x8E:'Ž',0x91:'\u2018',0x92:'\u2019',
  0x93:'\u201C',0x94:'\u201D',0x95:'•',0x96:'–',0x97:'—',0x98:'˜',0x99:'™',
  0x9A:'š',0x9B:'›',0x9C:'œ',0x9E:'ž',0x9F:'Ÿ',
};

function sanitizarTexto(str) {
  if (!str || typeof str !== 'string') return str;
  let s = str.replace(/\ufffd/g, '');
  for (const [e, c] of Object.entries(CHAR_FIX_MAP)) {
    if (s.includes(e)) s = s.split(e).join(c);
  }
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  s = s.replace(/[\x80-\x9F]/g, c => WIN1252[c.charCodeAt(0)] || '');
  return s.trim();
}

function sanitizarObjeto(obj) {
  if (typeof obj === 'string') return sanitizarTexto(obj);
  if (Array.isArray(obj)) return obj.map(sanitizarObjeto);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) out[k] = sanitizarObjeto(obj[k]);
    return out;
  }
  return obj;
}

// ─── Status do AD via userAccountControl + accountExpires ─────
// Ref: https://support.microsoft.com/kb/305144
const UAC_DISABLE          = 0x0002;
const UAC_LOCKOUT          = 0x0010;
const UAC_PASSWORD_EXPIRED = 0x0800;

// accountExpires: inteiro de 100ns desde 01/01/1601 UTC
// 0 ou 9223372036854775807 significa "nunca expira"
const NEVER_EXPIRES     = BigInt('9223372036854775807');
const WIN_EPOCH_DIFF_MS = BigInt(11644473600000); // ms entre 1601 e 1970

function interpretarStatusAD(uacStr, accountExpiresStr) {
  const uac = parseInt(uacStr || '0', 10) || 0;

  const adDesativada    = !!(uac & UAC_DISABLE);
  const adBloqueada     = !!(uac & UAC_LOCKOUT);
  const adSenhaExpirada = !!(uac & UAC_PASSWORD_EXPIRED);

  let adContaExpirada = false;
  try {
    const exp = BigInt(accountExpiresStr || '0');
    if (exp !== BigInt(0) && exp !== NEVER_EXPIRES) {
      const expMs = exp / BigInt(10000) - WIN_EPOCH_DIFF_MS;
      adContaExpirada = expMs < BigInt(Date.now());
    }
  } catch { /* campo ausente ou inválido — ignora */ }

  // Prioridade: desativado > expirado > bloqueado > senha > ativo
  let statusAD = 'ativo';
  if (adDesativada)         statusAD = 'desativado';
  else if (adContaExpirada) statusAD = 'expirado';
  else if (adBloqueada)     statusAD = 'bloqueado';
  else if (adSenhaExpirada) statusAD = 'senha_expirada';

  return {
    statusAD,
    adAtivo:          !adDesativada && !adContaExpirada,
    adDesativada,
    adBloqueada,
    adSenhaExpirada,
    adContaExpirada,
  };
}

// ─── Ausências (SQL Server) ───────────────────────────────────
const AUSENCIAS_SUPRIME = new Set([
  'FERIAS','FERIAS_COLETIVAS','LICENCA','LICENCA_MEDICA',
  'LICENCA_MATERNIDADE','LICENCA_PATERNIDADE','AFASTAMENTO',
  'AFASTAMENTO_MEDICO','SUSPENSAO','FOLGA',
]);

function normalizarAusencia(tipo) {
  if (!tipo) return '';
  return tipo.toUpperCase().replace(/\s+/g,'_')
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'');
}

function isAusenciaQueSuprime(tipo) {
  const n = normalizarAusencia(tipo);
  return AUSENCIAS_SUPRIME.has(n) || [...AUSENCIAS_SUPRIME].some(a => n.includes(a));
}

const PS_SCRIPT = path.join(__dirname, '..', 'scripts', 'Get-Empregados.ps1');

function runPowerShell(script) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(script)) {
      reject(new Error(`Script não encontrado: ${script}`)); return;
    }
    const cmd = [
      'powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-Command',
      `$OutputEncoding = [System.Text.Encoding]::UTF8; ` +
      `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ` +
      `& "${script}"`,
    ].join(' ');
    exec(cmd, { maxBuffer: 50*1024*1024, timeout: 60000, encoding: 'buffer' },
      (err, stdoutBuf, stderrBuf) => {
        if (err) {
          reject(new Error(stderrBuf
            ? Buffer.from(stderrBuf).toString('utf8', 0, 500)
            : err.message));
          return;
        }
        resolve(Buffer.from(stdoutBuf).toString('utf8').trim());
      });
  });
}

/**
 * Busca ausências do SQL Server.
 * Retorna Map: matricula (string) → { bloquearRecursosTI, tipoAusencia, nomeSql, emailSql, localTrabalho, cargoSql, grupoEmpregado, matriculaGestor }
 * O LDAP (initials) e o SQL (Matricula) usam o mesmo formato de matrícula.
 * Cruzamento direto: sqlMap.get(mat)
 */
async function buscarAusenciasSql() {
  const mapa = new Map();
  try {
    log('INFO', '[SQL] Executando Get-Empregados.ps1...');
    const jsonStr = await runPowerShell(PS_SCRIPT);
    const rows    = sanitizarObjeto(
      (() => { try { const p = JSON.parse(jsonStr); return Array.isArray(p) ? p : []; } catch { return []; } })()
    );

    for (const emp of rows) {
      const mat = String(emp.Matricula || emp.matricula || emp.MATRICULA || '').trim();
      if (!mat) continue;
      const bloquear = emp.BloquearRecursosTI === true
        || emp.BloquearRecursosTI === 'true'
        || emp.BloquearRecursosTI === 'True'
        || emp.BloquearRecursosTI === 1
        || emp.BloquearRecursosTI === '1'
        || String(emp.BloquearRecursosTI).toLowerCase() === 'true';
      const tipoAusencia = String(emp.TipoAusencia || '').trim();
      mapa.set(mat, {
        bloquearRecursosTI: bloquear,
        tipoAusencia,
        nomeSql:         String(emp.Nome           || '').trim(),
        emailSql:        String(emp.Email          || '').trim(),
        localTrabalho:   String(emp.LocalTrabalho  || '').trim(),
        cargoSql:        String(emp.Cargo          || '').trim(),
        grupoEmpregado:  String(emp.GrupoEmpregado  || '').trim(),
        matriculaGestor: String(emp.MatriculaGestor || '').trim(),
      });
    }
    const ausentes_sql = [...mapa.values()].filter(v => v.bloquearRecursosTI).length;
    log('INFO', `[SQL] ${mapa.size} registros lidos | ${ausentes_sql} ausentes (BloquearRecursosTI=1)`);
  } catch (e) {
    log('WARN', `[SQL] Falha: ${e.message} — continuando sem dados SQL`);
  }
  return mapa;
}

// ─── LDAP client nativo (LDAPS, sem dependência externa) ──────
const TAG = {
  INTEGER:0x02, OCTET_STR:0x04, BOOLEAN:0x01, SEQUENCE:0x30,
  BIND_REQ:0x60, BIND_RES:0x61, UNBIND:0x42,
  SEARCH_REQ:0x63, SEARCH_RES:0x64, SEARCH_DON:0x65,
};

function berLen(n) {
  if (n < 0x80)    return Buffer.from([n]);
  if (n < 0x100)   return Buffer.from([0x81, n]);
  if (n < 0x10000) return Buffer.from([0x82, (n>>8)&0xff, n&0xff]);
  return Buffer.from([0x83, (n>>16)&0xff, (n>>8)&0xff, n&0xff]);
}
function berTLV(tag, value) {
  const v = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([Buffer.from([tag]), berLen(v.length), v]);
}
function berStr(s)  { return berTLV(TAG.OCTET_STR, Buffer.from(s,'utf8')); }
function berInt(n)  { return berTLV(TAG.INTEGER, Buffer.from([n & 0xff])); }
function berSeq(b)  { return berTLV(TAG.SEQUENCE, b); }
function berEnum(n) { return berTLV(0x0a, Buffer.from([n & 0xff])); }
function ldapMsg(id, op) { return berSeq(Buffer.concat([berInt(id), op])); }

function bindRequest(id, dn, pwd) {
  return ldapMsg(id, berTLV(TAG.BIND_REQ, Buffer.concat([
    berInt(3), berStr(dn), berTLV(0x80, Buffer.from(pwd,'utf8')),
  ])));
}

function searchRequest(id, base, filter, attrs) {
  return ldapMsg(id, berTLV(TAG.SEARCH_REQ, Buffer.concat([
    berStr(base),
    berEnum(2),   // scope: wholeSubtree
    berEnum(3),   // derefAliases: derefAlways
    berInt(0),    // sizeLimit: sem limite
    berInt(0),    // timeLimit: sem limite
    berTLV(TAG.BOOLEAN, Buffer.from([0x00])), // typesOnly: false
    encodeFilter(filter),
    berTLV(TAG.SEQUENCE, Buffer.concat(attrs.map(berStr))),
  ])));
}

function encodeFilter(f) {
  f = f.trim();
  if (f.startsWith('(&')) {
    return berTLV(0xa0, Buffer.concat(splitFilters(f.slice(2,-1).trim()).map(encodeFilter)));
  }
  if (f.startsWith('(|')) {
    return berTLV(0xa1, Buffer.concat(splitFilters(f.slice(2,-1).trim()).map(encodeFilter)));
  }
  if (f.startsWith('(') && f.endsWith(')')) f = f.slice(1,-1);
  const eq = f.indexOf('=');
  if (eq < 0) return berTLV(0x87, Buffer.from('objectClass','utf8'));
  const attr = f.slice(0, eq);
  const val  = f.slice(eq + 1);
  // presente filter: attr=*
  if (val === '*') return berTLV(0x87, Buffer.from(attr, 'utf8'));
  // substring filter: attr=prefix* ou attr=*suffix ou attr=*mid*
  if (val.includes('*')) {
    const parts = val.split('*');
    const subParts = [];
    if (parts[0]) subParts.push(berTLV(0x80, Buffer.from(parts[0], 'utf8'))); // initial
    for (let i = 1; i < parts.length - 1; i++) {
      if (parts[i]) subParts.push(berTLV(0x81, Buffer.from(parts[i], 'utf8'))); // any
    }
    if (parts[parts.length - 1]) subParts.push(berTLV(0x82, Buffer.from(parts[parts.length - 1], 'utf8'))); // final
    return berTLV(0xa4, Buffer.concat([berStr(attr), berTLV(0x30, Buffer.concat(subParts))]));
  }
  // equality filter: attr=value
  return berTLV(0xa3, Buffer.concat([berStr(attr), berStr(val)]));
}

function splitFilters(s) {
  const parts = []; let depth=0, start=0;
  for (let i=0; i<s.length; i++) {
    if (s[i]==='(') { if(depth===0) start=i; depth++; }
    else if (s[i]===')') { depth--; if(depth===0) parts.push(s.slice(start,i+1)); }
  }
  return parts;
}

function readTLV(buf, offset) {
  if (offset >= buf.length) return null;
  const tag = buf[offset++];
  let len = buf[offset++];
  if (len & 0x80) {
    const n = len & 0x7f; len = 0;
    for (let i=0; i<n; i++) len = (len<<8) | buf[offset++];
  }
  return { tag, value: buf.slice(offset, offset+len), next: offset+len };
}

function parseSearchEntry(value) {
  const entry = {};
  let pos = 0;
  const dn = readTLV(value, pos); if (!dn) return null;
  entry._dn = dn.value.toString('utf8'); pos = dn.next;
  const al = readTLV(value, pos); if (!al) return entry;
  let ap = 0;
  while (ap < al.value.length) {
    const as = readTLV(al.value, ap); if (!as) break; ap = as.next;
    let ip = 0;
    const nt = readTLV(as.value, ip); if (!nt) continue; ip = nt.next;
    const name = nt.value.toString('utf8');
    const vs = readTLV(as.value, ip); if (!vs) continue;
    const vals = []; let vp = 0;
    while (vp < vs.value.length) {
      const vt = readTLV(vs.value, vp); if (!vt) break;
      vals.push(vt.value.toString('utf8')); vp = vt.next;
    }
    // Grava com nome original E com lowercase para garantir compatibilidade
    entry[name] = vals.length === 1 ? vals[0] : vals;
    const nameLower = name.toLowerCase();
    if (nameLower !== name) entry[nameLower] = entry[name];
  }
  return entry;
}

function parseLdapResponse(buf) {
  const entries = []; let done=false, resultCode=-1, pos=0;
  while (pos < buf.length) {
    const msg = readTLV(buf, pos); if (!msg) break; pos = msg.next;
    let mp = 0;
    const mi = readTLV(msg.value, mp); if (!mi) continue; mp = mi.next;
    const op = readTLV(msg.value, mp); if (!op) continue;
    if (op.tag === TAG.SEARCH_RES) {
      const e = parseSearchEntry(op.value); if (e) entries.push(e);
    } else if (op.tag === TAG.SEARCH_DON) {
      done = true;
      const rc = readTLV(op.value, 0); if (rc) resultCode = rc.value[0] || 0;
    }
  }
  return { entries, done, resultCode };
}

/**
 * Abre conexão LDAPS e executa um Search.
 * Retorna array de objetos com os atributos solicitados.
 */
function ldapSearch(opts = {}) {
  const host    = opts.host    || LDAP_HOST;
  const port    = opts.port    || LDAP_PORT;
  const bindDN  = opts.bindDN  || LDAP_BIND;
  const bindPwd = opts.bindPwd || LDAP_PWD;
  const baseDN  = opts.baseDN  || LDAP_BASE;
  const filter  = opts.filter  || LDAP_FILT;
  const attrs   = opts.attrs   || LDAP_ATTRS;

  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, rejectUnauthorized: false });
    socket.setTimeout(120000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('LDAP timeout (120s)')); });
    socket.on('error',   err => reject(new Error(`LDAP socket: ${err.message}`)));

    let msgId=1, allBuf=Buffer.alloc(0), entries=[], bindOk=false;

    socket.on('data', chunk => {
      allBuf = Buffer.concat([allBuf, chunk]);
      const result = parseLdapResponse(allBuf);

      if (!bindOk) {
        let p = 0;
        while (p < allBuf.length) {
          const m = readTLV(allBuf, p); if (!m) break; p = m.next;
          let mp = 0;
          const mi = readTLV(m.value, mp); if (!mi) continue; mp = mi.next;
          const op = readTLV(m.value, mp); if (!op) continue;
          if (op.tag === TAG.BIND_RES) {
            const rc = readTLV(op.value, 0);
            if (rc && rc.value[0] !== 0) {
              socket.destroy();
              reject(new Error(`LDAP Bind falhou (code=${rc.value[0]}). Verifique bindDN e bindPwd no config.json.`));
              return;
            }
            bindOk = true;
            allBuf = Buffer.alloc(0);
            entries = [];
            socket.write(searchRequest(++msgId, baseDN, filter, attrs));
            break;
          }
        }
        return;
      }

      // Adiciona apenas entries ainda não vistos (deduplicação por _dn)
      for (const e of result.entries) {
        if (e._dn && !entries.some(x => x._dn === e._dn)) {
          entries.push(e);
        }
      }

      if (result.done) {
        if (result.resultCode !== 0 && result.resultCode !== 4 && result.resultCode !== -1) {
          socket.destroy();
          reject(new Error(`LDAP Search resultCode=${result.resultCode}`));
          return;
        }
        try { socket.write(ldapMsg(++msgId, Buffer.from([TAG.UNBIND, 0x00]))); } catch {}
        socket.destroy();
        resolve(entries);
      }
    });

    socket.on('connect', () => socket.write(bindRequest(msgId, bindDN, bindPwd)));
  });
}

/**
 * Extrai a sigla da lotação a partir do Distinguished Name (DN) do usuário.
 * DN exemplo: CN=Alyce,OU=Usuarios,OU=E-DCA,OU=D-AC,OU=Organograma,...
 * Retorna a OU imediatamente acima de "Usuarios" (ex: "E-DCA").
 * Usado como fallback quando o atributo department está vazio.
 */
function lotacaoDoDN(dn) {
  if (!dn) return '';
  // Extrai todas as OUs do DN na ordem (de dentro para fora)
  const ous = dn.split(',')
    .map(s => s.trim())
    .filter(s => s.toLowerCase().startsWith('ou='))
    .map(s => s.substring(3));
  // A estrutura é: OU=Usuarios, OU=<SIGLA>, OU=<GERENCIA>, OU=Organograma, ...
  // Encontra o índice de "Usuarios" e pega a próxima OU
  const idxUsuarios = ous.findIndex(s => s.toLowerCase() === 'usuarios');
  if (idxUsuarios >= 0 && idxUsuarios + 1 < ous.length) {
    const sigla = ous[idxUsuarios + 1];
    // Ignora OUs genéricas que não são siglas de setor
    if (!['organograma', 'cesan', 'grupos'].includes(sigla.toLowerCase())) {
      return sigla;
    }
  }
  return '';
}

/**
 * Busca todos os empregados do AD CESAN em lotes por inicial do sAMAccountName.
 * Contorna o limite de 1000 resultados do AD sem precisar de paginação LDAP.
 * Retorna Map: login (lowercase) → { nome, login, lotacao, ... }
 */
async function buscarEmpregadosAD() {
  log('INFO', `[LDAP] Conectando em ${LDAP_HOST}:${LDAP_PORT}...`);
  log('INFO', `[LDAP] Base DN : ${LDAP_BASE}`);

  // Busca em lotes por inicial do sAMAccountName (a*, b*, ... z*)
  // Cada letra tem <200 usuários — bem abaixo do limite de 1000 do AD
  // Isso garante que todos os usuários são capturados independente do MaxPageSize
  const rawMap = new Map();
  for (const letra of 'abcdefghijklmnopqrstuvwxyz') {
    const filtro = `(&(objectClass=user)(objectCategory=person)(sAMAccountName=${letra}*))`;
    const lote = await ldapSearch({ filter: filtro });
    if (lote.length > 0) {
      for (const e of lote) {
        const login = String(e.sAMAccountName || '').trim().toLowerCase();
        if (login && !rawMap.has(login)) rawMap.set(login, e);
      }
    }
  }
  const raw = [...rawMap.values()];
  log('INFO', `[LDAP] ${raw.length} entradas retornadas (26 lotes por inicial)`);

  const mapa = new Map();
  for (const entry of raw) {
    const login = String(entry.sAMAccountName || '').trim().toLowerCase();
    if (!login) continue;

    const statusInfo = interpretarStatusAD(
      entry.userAccountControl,
      entry.accountExpires
    );

    mapa.set(login, {
      nome:       String(entry.name                          || '').trim(),
      login,                                                              // sAMAccountName
      mat:        String(entry.initials || '').trim(),                            // initials = matrícula CESAN completa (ex: 100332)
      lotacao:    String(entry.department                    || '').trim()
                  || lotacaoDoDN(entry._dn || ''),                        // fallback: extrai OU do DN quando department está vazio
      local:      String(entry.physicalDeliveryOfficeName    || '').trim(),
      cargo:      String(entry.title                         || '').trim(),
      telefone:   String(entry.telephoneNumber               || '').trim(),
      celular:    String(entry.mobile                        || '').trim(),
      ramal:      String(entry.ipPhone                       || '').trim(),
      email:      String(entry.mail                          || '').trim().toLowerCase(),
      ...statusInfo,
    });
  }

  const ativos    = [...mapa.values()].filter(e => e.adAtivo).length;
  const inativos  = mapa.size - ativos;
  log('INFO', `[LDAP] ${mapa.size} usuários (${ativos} ativos, ${inativos} inativos/expirados/bloqueados)`);

  return mapa;
}

// ─── SINCRONIZAÇÃO PRINCIPAL ──────────────────────────────────
async function sincronizar() {
  log('INFO', '🔄 Iniciando sincronização...');
  const inicio = Date.now();

  try {
    // 1. AD — fonte principal (dados cadastrais + status da conta)
    const adMap = await buscarEmpregadosAD();

    if (adMap.size === 0) {
      log('WARN', '[LDAP] Nenhum resultado — sincronização abortada');
      return;
    }

    // 2. SQL — fonte complementar (matrícula + ausências)
    const sqlMap = await buscarAusenciasSql();

    // 3. Mescla AD + SQL e prepara lote

    // Índice normalizado do SQL: chave sem zeros à esquerda → entrada original
    // Resolve divergências de formato entre AD (initials) e SQL (Matricula)
    // Ex: AD="0100332" bate com SQL="100332", ou AD="100332-1" bate com SQL="100332"
    const sqlNorm = new Map();
    for (const [mat, val] of sqlMap.entries()) {
      // chave original
      sqlNorm.set(mat, val);
      // sem zeros à esquerda
      const semZero = mat.replace(/^0+/, '') || '0';
      if (!sqlNorm.has(semZero)) sqlNorm.set(semZero, val);
      // com zeros à esquerda até 6 dígitos
      const comZero6 = mat.replace(/^0+/, '').padStart(6, '0');
      if (!sqlNorm.has(comZero6)) sqlNorm.set(comZero6, val);
      // sem dígito verificador (remove último char se tiver hífen ex: "100332-1")
      const semDV = mat.replace(/-\w+$/, '');
      if (!sqlNorm.has(semDV)) sqlNorm.set(semDV, val);
    }

    function buscarSql(mat) {
      if (!mat) return null;
      const m = mat.trim();
      // 1. exato
      if (sqlNorm.has(m)) return sqlNorm.get(m);
      // 2. sem zeros à esquerda
      const semZero = m.replace(/^0+/, '') || '0';
      if (sqlNorm.has(semZero)) return sqlNorm.get(semZero);
      // 3. com zeros até 6 dígitos
      const com6 = semZero.padStart(6, '0');
      if (sqlNorm.has(com6)) return sqlNorm.get(com6);
      // 4. sem dígito verificador
      const semDV = m.replace(/-\w+$/, '');
      if (sqlNorm.has(semDV)) return sqlNorm.get(semDV);
      // 5. só os dígitos numéricos
      const soNum = m.replace(/\D/g, '');
      if (sqlNorm.has(soNum)) return sqlNorm.get(soNum);
      return null;
    }

    const docs = [];
    let semMatSql = 0, ausentes = 0;

    for (const [login, ad] of adMap.entries()) {
      // mat = initials do LDAP (ex: "100332") bate diretamente com Matricula do SQL
      const mat = ad.mat || login;
      const sql = buscarSql(mat);
      if (!sql) semMatSql++;

      // BloquearRecursosTI=1 indica ausência (férias, licença, afastamento, etc.)
      const bloquearTI      = sql?.bloquearRecursosTI ?? false;
      const tipoAusencia    = sql?.tipoAusencia || '';
      const emAusencia      = bloquearTI;
      const suprimirAlertas = bloquearTI;

      // Campo consolidado: conta AD ativa E sem ausência que suprima
      const ativo = ad.adAtivo && !emAusencia;

      if (emAusencia) ausentes++;

      docs.push({
        id: mat,
        data: {
          // ── AD — fonte principal ─────────────────────────────
          nome:             ad.nome,
          login:            ad.login,           // sAMAccountName — gravado explicitamente
// Nomes alinhados ao que o app.js lê:
          setor:            ad.lotacao,          // department  → e.setor
          cargo:            ad.cargo,            // title       → e.cargo
          local:            ad.local,            // physicalDeliveryOfficeName
          lotacao:          ad.lotacao,          // alias retrocompat
          telefone:         ad.telefone,
          celular:          ad.celular,
          ramal:            ad.ramal,
          email:            ad.email,
          status:           ad.statusAD,         // → e.status (frontend)
          statusAD:         ad.statusAD,         // alias retrocompat
          adAtivo:          ad.adAtivo,          // true = pode logar no AD
          adDesativada:     ad.adDesativada,
          adBloqueada:      ad.adBloqueada,
          adSenhaExpirada:  ad.adSenhaExpirada,
          adContaExpirada:  ad.adContaExpirada,

          // ── SQL — fonte complementar ─────────────────────────────
          mat,
          bloquearRecursosTI:    bloquearTI,
          bloqueioTI:            bloquearTI,   // alias usado pelo app.js (renderBloqueioTIBadge)
          suprimirAlertas,
          emAusencia,
          ausencia:              emAusencia ? 'Ausente Férias/Licença' : 'Não',
          tipoAusencia,
          dataInicioAusencia:    '',
          dataFimAusencia:       '',
          // campos extras do SQL
          nomeSql:         sql?.nomeSql         || '',
          emailSql:        sql?.emailSql        || '',
          localTrabalho:   sql?.localTrabalho   || '',
          cargoSql:        sql?.cargoSql        || '',
          grupoEmpregado:  sql?.grupoEmpregado  || '',
          matriculaGestor: sql?.matriculaGestor || '',

          // ── Campo consolidado ────────────────────────────────
          ativo,   // AD ativo + sem ausência supressora

          // ── Metadados ────────────────────────────────────────
          syncAt:   new Date().toISOString(),
          syncLdap: new Date().toISOString(),
          syncSql:  sql ? new Date().toISOString() : '',
        },
      });
    }

    // 4. Grava no Firestore em lotes paralelos
    //    Esta gravação é o que alimenta o FAILOVER:
    //    quando o AD estiver indisponível, o frontend/index.js
    //    lê estes dados do Firestore automaticamente.
    let gravados = 0;
    for (let i = 0; i < docs.length; i += BATCH_SIZE) {
      const lote = docs.slice(i, i + BATCH_SIZE);
      await Promise.all(
        lote.map(({ id, data }) => {
          // Só grava se os dados mudaram desde o último ciclo
          const h = hashDoc(data);
          if (_hashCache.get(id) === h) return Promise.resolve(); // sem mudança → pula write
          _hashCache.set(id, h);
          return fsSet('empregados', id, data).catch(e =>
            log('WARN', `  ✗ ${id}: ${e.message}`)
          );
        })
      );
      gravados += lote.filter(({ id, data }) => _hashCache.get(id) === hashDoc(data)).length;
      if (Math.floor(i / BATCH_SIZE) % 5 === 0 && i > 0) {
        log('INFO', `  ... ${gravados}/${docs.length} gravados`);
      }
    }

    // 5. Atualiza organograma_unidades com empregados por unidade
    try {
      log('INFO', '[LDAP] Atualizando organograma_unidades...');

      // Monta mapa: sigla → { empregados[], total, ativos }
      const unidadeMap = new Map();
      for (const [, ad] of adMap.entries()) {
        const mat   = ad.mat || ad.login;
        const sigla = (ad.lotacao || '').toUpperCase();
        if (!sigla) continue;
        if (!unidadeMap.has(sigla)) unidadeMap.set(sigla, { empregados: [], total: 0, ativos: 0 });
        const u = unidadeMap.get(sigla);
        u.total++;
        if (ad.adAtivo) u.ativos++;
        u.empregados.push({
          mat,
          nome:   ad.nome   || '',
          login:  ad.login  || '',
          email:  ad.email  || '',
          ramal:  ad.ramal  || '',
          celular: ad.celular || '',
          cargo:  ad.cargo  || '',
          ativo:  ad.adAtivo,
        });
      }

      // Lê unidades existentes no Firestore
      const unidadesSnap = await firestoreRequest('GET', '/organograma_unidades?pageSize=500');
      const unidadesExist = new Set(
        (unidadesSnap.documents || []).map(d => d.name.split('/').pop())
      );

      // Atualiza ou cria cada unidade que tem empregados no AD
      // Só grava se totalEmpregados ou totalAtivos mudou (evita writes desnecessários)
      let atualizadas = 0, criadas = 0, puladas = 0;
      for (const [sigla, dados] of unidadeMap.entries()) {
        const docId = sigla;
        const existe = unidadesExist.has(docId);
        const hOrg = `${sigla}:${dados.total}:${dados.ativos}`;
        const cacheKey = `org_${sigla}`;
        if (_hashCache.get(cacheKey) === hOrg) { puladas++; continue; } // sem mudança → pula
        _hashCache.set(cacheKey, hOrg);
        await fsSet('organograma_unidades', docId, {
          sigla,
          totalEmpregados: dados.total,
          totalAtivos:     dados.ativos,
          empregados:      dados.empregados,
          orgSyncAt:       new Date().toISOString(),
        });
        if (existe) atualizadas++; else criadas++;
      }

      log('INFO', `[LDAP] organograma_unidades: ${atualizadas} atualizadas, ${criadas} criadas`);
    } catch (eOrg) {
      log('WARN', `[LDAP] Falha ao atualizar organograma_unidades: ${eOrg.message}`);
    }

    // 6. Log de sincronização
    await fsSet('sync_logs', `agent_${Date.now()}`, {
      tipo:             'empregados',
      totalAD:          adMap.size,
      totalSql:         sqlMap.size,
      gravados,
      ausentes,
      semMatriculaSql:  semMatSql,
      duracaoMs:        Date.now() - inicio,
      status:           'sucesso',
      agente:           cfg.agentName || 'sysack-agent',
      host:             os.hostname(),
    });

    const dur = ((Date.now() - inicio) / 1000).toFixed(1);
    log('INFO', `✅ Concluído: ${gravados} gravados | ${ausentes} em ausência | ${semMatSql} sem matrícula SQL | ${dur}s`);

  } catch (err) {
    log('ERROR', `❌ Erro: ${err.message}`);

    if (err.message?.includes('LDAP')) {
      log('ERROR', '══ ERRO LDAP ════════════════════════════════════════════');
      log('ERROR', `  Host : ${LDAP_HOST}:${LDAP_PORT}`);
      log('ERROR', '  Verifique conectividade, credenciais e porta 636 (LDAPS).');
      log('ERROR', '  ATENÇÃO: o Firestore mantém snapshot da última sync OK.');
      log('ERROR', '           O frontend fará failover automático para ele.');
      log('ERROR', '═════════════════════════════════════════════════════════');
    }
    if (err.message?.includes('403') || err.message?.includes('PERMISSION_DENIED')) {
      log('ERROR', '══ PERMISSÃO FIRESTORE ══════════════════════════════════');
      log('ERROR', '  Verifique a Service Account e as regras do Firestore.');
      log('ERROR', '═════════════════════════════════════════════════════════');
    }

    try {
      await fsSet('sync_logs', `agent_err_${Date.now()}`, {
        tipo: 'empregados', status: 'erro',
        erro: err.message.slice(0, 500),
        agente: cfg.agentName || 'sysack-agent',
        syncAt: new Date().toISOString(),
      });
    } catch { /* falha no log não trava o processo */ }
  }
}

// ─── Logger ──────────────────────────────────────────────────
const LOG_DIR  = path.join(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'agent.log');
const LOG_MAX  = 10 * 1024 * 1024;

function log(level, msg) {
  const ts   = new Date().toLocaleString('pt-BR');
  const line = `[${ts}] [${level}] ${msg}`;
  console.log(line);
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(LOG_FILE, line + '\n');
    if (fs.statSync(LOG_FILE).size > LOG_MAX) fs.renameSync(LOG_FILE, LOG_FILE + '.old');
  } catch { /* I/O não trava o agente */ }
}

// ─── Main ────────────────────────────────────────────────────
async function main() {
  log('INFO', '');
  log('INFO', '════════════════════════════════════════════════');
  log('INFO', '  SYSACK Agent');
  log('INFO', `  Firebase  : ${FB_PROJECT}`);
  log('INFO', `  AD (LDAP) : ${LDAP_HOST}:${LDAP_PORT}`);
  log('INFO', `  Base DN   : ${LDAP_BASE}`);
  log('INFO', `  Intervalo : ${cfg.syncIntervalMinutes || 5} min`);
  log('INFO', `  Lote      : ${BATCH_SIZE} docs/ciclo`);
  log('INFO', `  Host      : ${os.hostname()}`);
  log('INFO', '════════════════════════════════════════════════');

  const authOk = await firebaseAuth.inicializar(
    path.join(__dirname, '..'), cfg, log
  );
  if (!authOk) log('ERROR', 'Auth Firebase falhou. Verifique sysack-service-account.json.');

  const online = await verificarConexao();
  if (!online) log('WARN', 'Sem conexão com Firebase. Tentando mesmo assim.');

  await sincronizar();
  setInterval(sincronizar, SYNC_INTERVAL_MS);
  log('INFO', `⏱ Próxima sync em ${cfg.syncIntervalMinutes || 5} min`);
}

main().catch(err => { log('ERROR', `Fatal: ${err.message}`); process.exit(1); });
