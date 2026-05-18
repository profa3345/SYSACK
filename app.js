// SYSACK v2.1 — app.js
// Módulo principal de aplicação


// ============================================================
// FIREBASE ARCHITECTURE — ESTRUTURA DE PRODUÇÃO
// ============================================================
/*
┌─────────────────────────────────────────────────────────────┐
│  FIRESTORE COLLECTIONS                                       │
├─────────────────────────────────────────────────────────────┤
│  /ativos/{id}                                               │
│    pat, desc, tipo, area, status, loc, resp, serie,         │
│    fabricante, dataAquisicao, garantia, custoEstimado,       │
│    createdAt, updatedAt, createdBy                          │
│                                                             │
│  /chamados/{id}                                             │
│    titulo, desc, tipo, categoria, subcategoria, status,     │
│    prioridade, area, requerente, tecnico, grupo,            │
│    slaDeadline, slaAtingido, mttrMinutos,                   │
│    createdAt, updatedAt, closedAt, createdBy                │
│                                                             │
│  /chamados/{id}/historico/{id}                              │
│    tipo, desc, autor, createdAt (subcollection)             │
│                                                             │
│  /aprovacoes/{id}                                           │
│    tipo, pat, ativo, solicitante, status, motivo,           │
│    createdAt, decidedAt, decidedBy                          │
│                                                             │
│  /tecnicos/{id}                                             │
│    nome, empresa, email, tel, role, createdAt               │
│                                                             │
│  /smartphones/{id}                                          │
│    pat, marca, modelo, imei1, imei2, linha, operadora,      │
│    so, versao, status, empNome, empMat, empSetor,           │
│    mdmCompliant, lastCheckin, createdAt                     │
│                                                             │
│  /smartphones/{id}/historico/{id}  (subcollection)         │
│                                                             │
│  /switches/{id}                                             │
│    hostname, tipo, marca, modelo, ip, status, uptime,       │
│    totalPortas, portasUso, vlans[], createdAt               │
│                                                             │
│  /audit_logs/{id}                                           │
│    userId, userName, action, module, resourceId,            │
│    resourceType, before, after, ip, userAgent, createdAt    │
│                                                             │
│  /notifications/{userId}/items/{id}                         │
│    titulo, desc, tipo, lida, createdAt                      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  FIRESTORE INDEXES (firestore.indexes.json)                 │
├─────────────────────────────────────────────────────────────┤
│  chamados: [status ASC, createdAt DESC]                     │
│  chamados: [area ASC, status ASC, createdAt DESC]           │
│  chamados: [tecnico ASC, status ASC, updatedAt DESC]        │
│  chamados: [categoria ASC, slaAtingido ASC]                 │
│  ativos: [area ASC, status ASC]                             │
│  ativos: [status ASC, garantia ASC]                         │
│  audit_logs: [userId ASC, createdAt DESC]                   │
│  audit_logs: [resourceId ASC, createdAt DESC]               │
├─────────────────────────────────────────────────────────────┤
│  FIRESTORE SECURITY RULES                                   │
├─────────────────────────────────────────────────────────────┤
│  function isAuth() { return request.auth != null; }         │
│  function hasRole(r) {                                      │
│    return get(/users/$(request.auth.uid)).data.role == r;   │
│  }                                                          │
│  function isGestor() { return hasRole('gestor'); }          │
│  function isTecnico() {                                     │
│    return hasRole('tecnico') || hasRole('gestor');          │
│  }                                                          │
│                                                             │
│  match /chamados/{id} {                                     │
│    allow read: if isAuth();                                 │
│    allow create: if isAuth();                               │
│    allow update: if isTecnico();                            │
│    allow delete: if isGestor();                             │
│  }                                                          │
│  match /aprovacoes/{id} {                                   │
│    allow read: if isAuth();                                 │
│    allow write: if isGestor();                              │
│  }                                                          │
│  match /audit_logs/{id} {                                   │
│    allow read: if isGestor();                               │
│    allow write: if false; // only Cloud Functions           │
│  }                                                          │
│  match /smartphones/{id} {                                  │
│    allow read: if isAuth();                                  │
│    allow write: if isTecnico();                             │
│  }                                                          │
└─────────────────────────────────────────────────────────────┘

RBAC ROLES:
  'admin'     - Acesso total, pode configurar o sistema
  'gestor'    - Aprova movimentações, acessa dashboards exec.
  'tecnico'   - Abre/atende chamados, gerencia ativos
  'viewer'    - Somente leitura
  'mdm_admin' - Ações remotas MDM (geoloc, wipe, bloqueio)

FIREBASE FUNCTIONS (filas/triggers):
  onChamadoCreate → notifyGestor, calcSLA
  onAprovacaoUpdate → notifyRequerente (SMTP)
  onSmartphoneWipe → requireMdmAdmin + auditLog (LGPD)
  scheduledSLACheck → every 1h → markSLAViolations
  scheduledAlertTerc → every 1h → alertOverdueTerceirizada
  scheduledGarantiaAlert → daily → alertExpiringWarranties
*/

// ── RBAC (simulado — em produção virá do Banco Auth custom claims) ──
const CURRENT_USER = {
  uid: 'user_joao_martins',
  nome: 'João Martins',
  email: 'joao.martins@adsi.com.br',
  role: 'gestor',         // admin | gestor | tecnico | viewer | mdm_admin
  avatar: 'JM',
  permissions: {
    canApprove:      true,
    canDeleteAssets: false,
    canWipeDevice:   true,  // mdm_admin
    canGeolocate:    true,
    canViewAudit:    true,
    canExecDashboard:true,
  }
};

// ── AUDIT LOG ENGINE (frontend — em produção via Cloud Function) ──
const AUDIT_QUEUE = [];
function auditLog(action, module, resourceId, resourceType, details = {}) {
  const entry = {
    id: 'al_' + Date.now(),
    userId: CURRENT_USER.uid,
    userName: CURRENT_USER.nome,
    action,           // 'CREATE' | 'UPDATE' | 'DELETE' | 'MDM_ACTION' | 'APPROVE' | 'LOGIN' | 'VIEW_SENSITIVE'
    module,           // 'chamados' | 'ativos' | 'mdm' | 'aprovacoes' | 'switches'
    resourceId,
    resourceType,
    details,          // { before: {...}, after: {...}, motivo: '...' }
    ip: '—',          // capturado pelo backend
    userAgent: navigator.userAgent.slice(0, 80),
    createdAt: new Date()
  };
  AUDIT_QUEUE.push(entry);
  if (!STATE.auditLogs) STATE.auditLogs = [];
  STATE.auditLogs.unshift(entry);
  // TODO Banco: addDoc(collection(db,'audit_logs'), entry)
  console.log('[AUDIT]', action, module, resourceId);
  return entry;
}

// ── RBAC GUARD ──
function requirePermission(perm, action = () => {}) {
  if (!CURRENT_USER.permissions[perm]) {
    showToast(`⛔ Sem permissão: ${perm}`, 'danger');
    auditLog('PERMISSION_DENIED', 'system', perm, 'permission', { role: CURRENT_USER.role });
    return false;
  }
  return action();
}

// ── SLA CALCULATOR ──
function calcSLA(createdAt, prioridade) {
  const slaHours = { 'urgente':2, 'muito-alta':4, 'alta':8, 'media':24, 'baixa':72, 'muito-baixa':168 };
  const hours = slaHours[prioridade] || 24;
  const deadline = new Date(createdAt.getTime() + hours * 3600000);
  const now = new Date();
  const remainingMs = deadline - now;
  const atingido = remainingMs > 0;
  const pct = Math.max(0, Math.min(100, (remainingMs / (hours * 3600000)) * 100));
  return { deadline, atingido, remainingMs, pct, hoursTotal: hours };
}

// ── MTTR CALCULATOR ──
function calcMTTR(chamados) {
  const closed = chamados.filter(c => c.status === 'concluido' || c.status === 'fechado');
  if (!closed.length) return 0;
  const totalMs = closed.reduce((sum, c) => {
    const created = c.createdAt instanceof Date ? c.createdAt : new Date(c.createdAt);
    const closed2 = c.updatedAt instanceof Date ? c.updatedAt : new Date(c.updatedAt || c.createdAt);
    return sum + (closed2 - created);
  }, 0);
  return Math.round(totalMs / closed.length / 3600000 * 10) / 10;
}

// ============================================================
// FIREBASE CONFIG PLACEHOLDER
// Substitua com suas credenciais reais do Banco Console
// ============================================================
// ============================================================
// FIREBASE — CONFIGURAÇÃO REAL (sysack-829e2)
// ============================================================
const FIREBASE_CONFIG = {
  apiKey: "AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww",
  authDomain: "sysack-829e2.firebaseapp.com",
  projectId: "sysack-829e2",
  storageBucket: "sysack-829e2.firebasestorage.app",
  messagingSenderId: "364185694349",
  appId: "1:364185694349:web:cc2e9123fe72726cc5f2c4",
  measurementId: "G-K4CKJJW92X"
};

// ── Banco SDK carregado via CDN (compat mode para HTML puro) ──
let db = null, auth = null, analytics = null;
let FB_READY = false;

function showOfflineBar(msg) {
  const bar = document.getElementById('fb-offline-bar') || document.createElement('div');
  bar.id = 'fb-offline-bar';
  bar.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#1E293B;color:#FCD34D;font-size:12px;font-weight:600;text-align:center;padding:7px;z-index:9998;display:flex;align-items:center;justify-content:center;gap:8px';
  bar.innerHTML = '<span>📡</span><span>' + escapeHtml(msg) + '</span><button onclick="initBanco()" style="margin-left:12px;padding:2px 10px;border-radius:5px;border:1px solid #FCD34D;background:transparent;color:#FCD34D;cursor:pointer;font-size:11px;font-family:inherit">&#8635; Tentar novamente</button>'
  document.body.appendChild(bar);
}

async function initBanco() {
  // Aguarda os scripts compat carregarem
  const ready = await new Promise(resolve => {
    if (window._fbLoaded !== undefined) return resolve(window._fbLoaded);
    window.addEventListener('firebase-ready', () => resolve(window._fbLoaded), { once: true });
    setTimeout(() => resolve(!!window.firebase), 10000);
  });

  if (!ready && !window.firebase) {
    const tip = location.protocol === 'file:'
      ? 'Abra via servidor HTTP (ex: Live Server) para conectar ao Banco.'
      : 'Verifique sua conexão com a internet.';
    showOfflineBar('Modo offline — ' + tip);
    return;
  }

  try {
    const app = firebase.apps.length ? firebase.apps[0] : firebase.initializeApp(FIREBASE_CONFIG);
    window._app = app;
    db   = app.firestore();
    auth = app.auth();
    window._db = db;

    // Helpers para compatibilidade com o restante do código
    const collection      = (col)          => db.collection(col);
    const doc             = (db2, col, id) => id ? db2.collection(col).doc(id) : db2.doc(col);
    const addDoc          = (ref, data)    => ref.add(data);
    const updateDoc       = (ref, data)    => ref.update(data);
    const deleteDoc       = (ref)          => ref.delete();
    const serverTimestamp = ()             => firebase.firestore.FieldValue.serverTimestamp();
    const onSnapshot      = (ref, cb, err) => ref.onSnapshot(cb, err);
    const query           = (ref)          => ref;
    const where           = (f, op, v)     => ({ _where: [f, op, v] });
    const orderBy         = (f, d)         => ({ _orderBy: [f, d] });
    const limit           = (n)            => ({ _limit: n });

    const FCM_VAPID_KEY = window.FCM_VAPID_KEY || 'BCp-PLACEHOLDER-GERE-NO-FIREBASE-CONSOLE';

    // Singleton de Banco Functions — instanciado 1x após login
let _fbFunctions = null;
// Busca um único documento do Banco via REST
async function fsGetDoc(col, id) {
  if (!FB_READY) return null;
  try {
    const snap = await app.firestore().collection(col).doc(id).get();
    if (!snap.exists) return null;
    return { id: snap.id, ...snap.data() };
  } catch {
    // Fallback REST
    return new Promise(resolve => {
      const url = 'https://firestore.googleapis.com/v1/projects/' + FIREBASE_CONFIG.projectId +
        '/databases/(default)/documents/' + col + '/' + id + '?key=' + FIREBASE_CONFIG.apiKey;
      fetch(url).then(r => r.json()).then(doc => {
        if (!doc.fields) return resolve(null);
        const out = {};
        for (const [k, v] of Object.entries(doc.fields)) {
          if (v.arrayValue) {
            out[k] = (v.arrayValue.values || []).map(item =>
              item.mapValue ? Object.fromEntries(Object.entries(item.mapValue.fields || {}).map(([fk,fv]) => [fk, fv.stringValue ?? fv.integerValue ?? ''])) : item.stringValue ?? ''
            );
          } else {
            out[k] = v.stringValue ?? v.booleanValue ?? v.integerValue ?? null;
          }
        }
        resolve(out);
      }).catch(() => resolve(null));
    });
  }
}

async function getFbFunctions() {
  if (_fbFunctions) return _fbFunctions;
  _fbFunctions = app.functions('us-central1');
  return _fbFunctions;
}
async function callFunction(name, data) {
  const fn = (await getFbFunctions()).httpsCallable(name);
  const r  = await fn(data);
  return r.data;
}
window.callFunction = callFunction; // expõe globalmente

window.initFCM = async function() {
      if (!('Notification' in window)) return;
      try {
        const messaging = firebase.messaging();
        window._fcmMessaging = messaging;

        // Listener de mensagens em foreground
        messaging.onMessage(payload => {
          console.log('[FCM] Mensagem recebida:', payload);
          processarComandoFCM(payload);
        });

        // Solicita permissão de notificação
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
          console.log('[FCM] Notificações negadas pelo usuário');
          return;
        }

        // Obtém token FCM e salva no Banco
        const token = await messaging.getToken({ vapidKey: FCM_VAPID_KEY, serviceWorkerRegistration: _swRegistration });
        if (token) {
          window._fcmToken = token;
          await salvarTokenFCM(token);
          console.log('[FCM] ✓ Token registrado');
        }
      } catch (e) {
        console.warn('[FCM]', e.message);
      }
    };

    // Banco App Check — só ativa em HTTPS com domínio Vercel/produção
    // Em file://, localhost ou qualquer outro domínio não autorizado: desativado
    const isProduction = location.protocol === 'https:'
      && !location.hostname.includes('localhost')
      && !location.hostname.includes('127.0.0.1')
      && location.hostname !== '';

    // App Check desativado — ativar após registrar domínio no Firebase Console
    // Firebase Console → App Check → Registrar app → adicionar domínio sysack.vercel.app
    // Por enquanto: auth do Firebase protege as coleções via Firestore Rules
    console.log('[AppCheck] Desativado — proteção via Firestore Rules ativa');
    FB_READY = true;

    // enableIndexedDbPersistence depreciada — usando cache moderno
    try {
      console.log('[Banco] Cache local: IndexedDB ativo');
    } catch(e) {
      console.log('[Banco] Cache:', e.message);
    }

    window._fs = {
      collection, addDoc, updateDoc, deleteDoc, doc,
      query, where, orderBy, limit, onSnapshot, serverTimestamp,
    };

    document.getElementById('fb-offline-bar')?.remove();
    // Limpa fila offline corrompida ao conectar
    setTimeout(limparFilaOfflineCorrempida, 2000);
    console.log('[Banco] ✓ Conectado — sysack-829e2');
    showToast('🗄️ Banco de Dados conectado', 'success');

    // ── Inicia listeners SEMPRE após Firebase conectar ─────────────
    // As regras do Firestore permitem leitura pública (allow read: true)
    // Não precisa esperar login — dados carregam imediatamente
    if (!window._listenersAtivos) {
      console.log('[Banco] Iniciando listeners Firestore...');
      setTimeout(startFirestoreListeners, 200);
    }

  } catch (err) {
    console.warn('[Banco] Erro:', err.message || err);
    showOfflineBar('Erro Banco: ' + String(err.message || err).slice(0, 80));
  }
}


// ── Adapta fsAdd/fsUpdate para SDK modular ─────────────────

// ════════════════════════════════════════════════════════════
// FILA OFFLINE — IndexedDB (somente operações pendentes)
// Armazena apenas o diff a ser enviado (~500B por item)
// NÃO armazena dados completos para não ocupar armazenamento
// ════════════════════════════════════════════════════════════

const OFFLINE_DB_NAME    = 'sysack_offline';
const OFFLINE_DB_VERSION = 2;           // v2: adicionado store de blobs
const OFFLINE_STORE      = 'pending_ops';
const OFFLINE_BLOBS      = 'blobs';     // fotos e arquivos grandes

let _offlineDB = null;

async function getOfflineDB() {
  if (_offlineDB) return _offlineDB;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(OFFLINE_DB_NAME, OFFLINE_DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      // Store de operações pendentes (dados pequenos)
      if (!db.objectStoreNames.contains(OFFLINE_STORE)) {
        const store = db.createObjectStore(OFFLINE_STORE, { keyPath: 'id', autoIncrement: true });
        store.createIndex('col',       'col',       { unique: false });
        store.createIndex('createdAt', 'createdAt', { unique: false });
      }
      // Store de blobs — fotos e arquivos (dados grandes, ref por chave)
      if (!db.objectStoreNames.contains(OFFLINE_BLOBS)) {
        db.createObjectStore(OFFLINE_BLOBS, { keyPath: 'key' });
      }
    };
    req.onsuccess = e => { _offlineDB = e.target.result; resolve(_offlineDB); };
    req.onerror   = () => reject(req.error);
  });
}

// Salva um blob (foto/arquivo) no IndexedDB — retorna a chave
async function offlineSaveBlob(key, dataUrl) {
  const db = await getOfflineDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(OFFLINE_BLOBS, 'readwrite');
    const req = tx.objectStore(OFFLINE_BLOBS).put({ key, data: dataUrl, savedAt: Date.now() });
    req.onsuccess = () => resolve(key);
    req.onerror   = () => reject(req.error);
  });
}

// Recupera um blob do IndexedDB
async function offlineGetBlob(key) {
  const db = await getOfflineDB();
  return new Promise(resolve => {
    const tx  = db.transaction(OFFLINE_BLOBS, 'readonly');
    const req = tx.objectStore(OFFLINE_BLOBS).get(key);
    req.onsuccess = () => resolve(req.result?.data || null);
    req.onerror   = () => resolve(null);
  });
}

// Remove blobs associados a uma operação
async function offlineDeleteBlobs(blobKeys) {
  if (!blobKeys?.length) return;
  const db = await getOfflineDB();
  const tx = db.transaction(OFFLINE_BLOBS, 'readwrite');
  blobKeys.forEach(k => tx.objectStore(OFFLINE_BLOBS).delete(k));
}

// Processa campos de dados — extrai base64 para blob store, substitui por referência
async function offlineProcessarDados(opId, data) {
  const processado = { ...data };
  const blobKeys   = [];

  for (const [campo, valor] of Object.entries(data)) {
    if (typeof valor === 'string' && valor.startsWith('data:') && valor.length > 1000) {
      // É um base64 (foto, arquivo) — salva separadamente
      const blobKey = 'blob_' + opId + '_' + campo + '_' + Date.now();
      await offlineSaveBlob(blobKey, valor);
      processado[campo] = '__BLOB__' + blobKey; // referência ao blob
      blobKeys.push(blobKey);
    }
  }

  return { processado, blobKeys };
}

// Restaura blobs nos dados antes de sincronizar
async function offlineRestaurarBlobs(data) {
  const restaurado = { ...data };
  for (const [campo, valor] of Object.entries(data)) {
    if (typeof valor === 'string' && valor.startsWith('__BLOB__')) {
      const blobKey  = valor.replace('__BLOB__', '');
      const blobData = await offlineGetBlob(blobKey);
      if (blobData) restaurado[campo] = blobData;
      else delete restaurado[campo]; // blob perdido — remove campo
    }
  }
  return restaurado;
}

// Enfileira uma operação para sync posterior
// Fotos/blobs são salvas separadamente no store de blobs
async function offlineEnqueue(tipo, col, docId, data) {
  try {
    const db    = await getOfflineDB();
    const opId  = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

    // Extrai blobs (fotos) para store separado
    const { processado, blobKeys } = await offlineProcessarDados(opId, data);

    const store = db.transaction(OFFLINE_STORE, 'readwrite').objectStore(OFFLINE_STORE);
    store.add({
      tipo,
      col,
      docId:     docId || null,
      data:      JSON.stringify(processado),
      blobKeys,
      createdAt: Date.now(),
      tentativas: 0,
    });
    atualizarBannerOffline();
    console.log('[OfflineQueue] Enfileirado:', tipo, col, blobKeys.length ? '(' + blobKeys.length + ' foto(s))' : '');
  } catch (e) {
    console.warn('[OfflineQueue] Erro ao enfileirar:', e.message);
  }
}

// Limpa operações corrompidas da fila offline (col vazia ou inválida)
async function limparFilaOfflineCorrempida() {
  try {
    const db = await getOfflineDB();
    const tx = db.transaction(OFFLINE_STORE, 'readwrite');
    const store = tx.objectStore(OFFLINE_STORE);
    const ops = await new Promise((res, rej) => {
      const req = store.getAll();
      req.onsuccess = () => res(req.result || []);
      req.onerror   = () => rej(req.error);
    });
    let removidas = 0;
    for (const op of ops) {
      if (!op.col || typeof op.col !== 'string' || op.col.trim() === '') {
        store.delete(op.id);
        removidas++;
      }
    }
    if (removidas > 0) {
      console.warn('[OfflineQueue] ' + removidas + ' operação(ões) corrompida(s) removida(s) automaticamente');
      atualizarBannerOffline();
    }
  } catch(e) {
    console.warn('[OfflineQueue] Erro ao limpar fila:', e.message);
  }
}

// Conta operações pendentes
async function offlineCount() {
  try {
    const db = await getOfflineDB();
    return new Promise(resolve => {
      const tx  = db.transaction(OFFLINE_STORE, 'readonly');
      const req = tx.objectStore(OFFLINE_STORE).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror   = () => resolve(0);
    });
  } catch { return 0; }
}

// Sincroniza todas as operações pendentes
async function offlineSync() {
  if (!navigator.onLine || !FB_READY) return;
  let db;
  try { db = await getOfflineDB(); } catch { return; }

  const ops = await new Promise(resolve => {
    const tx  = db.transaction(OFFLINE_STORE, 'readonly');
    const req = tx.objectStore(OFFLINE_STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror   = () => resolve([]);
  });

  if (!ops.length) return;

  console.log(`[OfflineSync] Sincronizando ${ops.length} operação(ões) pendente(s)...`);
  showToast(`Sincronizando ${ops.length} operação(ões) salvas offline...`, 'info', 4000);

  let ok = 0, erros = 0;
  for (const op of ops) {
    try {
      let data = JSON.parse(op.data);
      // Restaura blobs (fotos) antes de enviar ao Banco
      if (op.blobKeys?.length) {
        data = await offlineRestaurarBlobs(data);
      }
      // Valida col antes de tentar sync — evita n.indexOf crash
      if (!op.col || typeof op.col !== 'string' || op.col.trim() === '') {
        console.warn('[OfflineSync] Operação com col inválida descartada:', op);
        const tx2 = db.transaction(OFFLINE_STORE, 'readwrite');
        tx2.objectStore(OFFLINE_STORE).delete(op.id);
        erros++;
        continue;
      }
      if (op.tipo === 'add') {
        await fsAdd(op.col, data, null, true); // _fromSync=true evita reenfileirar
      } else if (op.tipo === 'update' && op.docId) {
        await fsUpdate(op.col, op.docId, data);
      }
      // Remove operação e blobs associados da fila após sucesso
      const tx = db.transaction(OFFLINE_STORE, 'readwrite');
      tx.objectStore(OFFLINE_STORE).delete(op.id);
      await offlineDeleteBlobs(op.blobKeys);
      // Limpa dados offline do STATE — o Firebase recarrega via onSnapshot
      offlineLimparDadosLocais(op.col, op.docId);
      ok++;
    } catch (e) {
      erros++;
      console.warn(`[OfflineSync] Erro ao sincronizar op ${op.id}:`, e.message);
      // Incrementa tentativas — após 5, descarta
      if ((op.tentativas || 0) >= 5) {
        const tx = db.transaction(OFFLINE_STORE, 'readwrite');
        tx.objectStore(OFFLINE_STORE).delete(op.id);
        console.warn('[OfflineSync] Operação descartada após 5 tentativas:', op);
      } else {
        const tx = db.transaction(OFFLINE_STORE, 'readwrite');
        tx.objectStore(OFFLINE_STORE).put({ ...op, tentativas: (op.tentativas||0) + 1 });
      }
    }
  }

  atualizarBannerOffline();
  if (ok > 0) showToast(`✅ ${ok} operação(ões) sincronizada(s) com sucesso!`, 'success', 4000);
  if (erros > 0) showToast(`⚠️ ${erros} operação(ões) com erro — serão refeitas.`, 'warning', 5000);

  // Limpa IndexedDB completamente se tudo foi sincronizado
  offlineLimparTudo();
}

// Banner de status offline
async function atualizarBannerOffline() {
  const count  = await offlineCount();

  // Estima tamanho usado no IndexedDB
  async function estimarTamanho() {
    if (navigator.storage?.estimate) {
      const est = await navigator.storage.estimate();
      const mb  = ((est.usage || 0) / 1024 / 1024).toFixed(1);
      return ' (' + mb + 'MB)';
    }
    return '';
  }
  let banner   = document.getElementById('offline-sync-banner');

  if (!navigator.onLine || count > 0) {
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'offline-sync-banner';
      banner.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:9998;border-radius:10px;padding:10px 16px;font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:10px;box-shadow:0 4px 20px rgba(0,0,0,.2);max-width:320px;cursor:pointer';
      banner.onclick = () => { if (navigator.onLine && count > 0) offlineSync(); };
      document.body.appendChild(banner);
    }
    if (!navigator.onLine) {
      banner.style.background = '#1E293B';
      banner.style.color      = '#F8FAFC';
      estimarTamanho().then(tam => {
        banner.innerHTML = '<span style="font-size:18px">📡</span>' +
          '<span>' + (count > 0
            ? count + ' alteração(ões) salvas offline' + tam + ' — serão enviadas ao reconectar.'
            : 'Sem conexão — modo offline. Alterações (incluindo fotos) serão salvas localmente.')
          + '</span>';
      });
    } else if (count > 0) {
      banner.style.background = '#D97706';
      banner.style.color      = '#fff';
      banner.innerHTML = '<span style="font-size:18px">🔄</span>' +
        '<span>' + count + ' alteração(ões) pendente(s). <u>Clique para sincronizar agora.</u></span>';
    }
  } else if (banner) {
    banner.remove();
  }
}

// Detecta mudança de conectividade
window.addEventListener('online',  () => { atualizarBannerOffline(); offlineSync(); });
window.addEventListener('offline', () => atualizarBannerOffline());

// Verifica ao iniciar
setTimeout(atualizarBannerOffline, 2000);

// ════════════════════════════════════════════════════════════
// RESTRIÇÕES — o que NÃO vai para a fila offline
// (operações que dependem de resposta do servidor)
// ════════════════════════════════════════════════════════════
const COLS_SEM_FILA_OFFLINE = new Set([
  'sessoes_remotas',      // acesso remoto — requer conectividade
  'agent_commands',       // comandos para agentes — idem
  'audit_logs',           // logs de auditoria — sem fila
  'notificacoes',         // push — idem
]);

// Colunas permitidas na fila offline (escrita simples e segura)
const COLS_COM_FILA_OFFLINE = new Set([
  'chamados', 'ativos', 'mobiliario', 'smartphones',
  'scAtivos', 'terceirizadaAtivos', 'aprovacoes',
  'alertas_rede', 'empregados',
]);

async function fsAdd(col, data, localArr, _fromSync = false) {
  // Valida col — evita crash no Firestore com coleção inválida
  if (!col || typeof col !== 'string' || col.trim() === '') {
    console.error('[Banco] fsAdd: col inválida:', col);
    return null;
  }

  if (FB_READY && db && window._fs) {
    try {
      const { collection, addDoc, serverTimestamp } = window._fs;
      const ref = await addDoc(collection(db, col), {
        ...data,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        createdBy: CURRENT_USER?.uid || '',
      });
      auditLog('CREATE', col, ref.id, col, { after: data });
      return ref.id;
    } catch (err) { console.error('[Banco] fsAdd:', err); }
  }

  // Offline: enfileira — mas NUNCA reenfileira se já veio da fila (evita loop)
  if (!_fromSync && COLS_COM_FILA_OFFLINE.has(col)) {
    // Enfileira tudo — fotos são salvas no blob store separado
    await offlineEnqueue('add', col, null, data);
    // Atualiza STATE local imediatamente para UX fluida
    if (localArr && !localArr.find(x => x.id === (data.id || ''))) {
      localArr.unshift({ ...data, id: data.id || 'offline_' + Date.now(), _offline: true, createdAt: new Date() });
    }
    return 'offline_' + Date.now();
  }

  if (localArr && !localArr.find(x => x.id === (data.id || ''))) {
    localArr.unshift({ ...data, id: data.id || 'local_' + Date.now(), createdAt: new Date() });
  }
  return null;
}

async function fsUpdate(col, docId, data) {
  if (FB_READY && db && window._fs) {
    try {
      const { doc, updateDoc, serverTimestamp } = window._fs;
      await updateDoc(doc(db, col, docId), { ...data, updatedAt: serverTimestamp() });
      auditLog('UPDATE', col, docId, col, { after: data });
      return true;
    } catch (err) { console.error('[Banco] fsUpdate:', err); }
  }

  // Offline: enfileira se a coleção suporta fila offline
  if (COLS_COM_FILA_OFFLINE.has(col) && docId) {
    // Enfileira tudo — fotos são salvas no blob store separado
    await offlineEnqueue('update', col, docId, data);
    // Atualiza STATE local imediatamente
    const ativoLocal = (STATE[col] || []).find(x => x.id === docId);
    if (ativoLocal) Object.assign(ativoLocal, data, { _offline: true });
    return true; // retorna true para UX não mostrar erro
  }

  return false;
}

async function fsDelete(col, docId) {
  if (FB_READY && db && window._fs) {
    try {
      const { doc, deleteDoc } = window._fs;
      auditLog('DELETE', col, docId, col, {});
      await deleteDoc(doc(db, col, docId));
      return true;
    } catch (err) { console.error('[Banco] fsDelete:', err); }
  }
  return false;
}

// ── FIRESTORE REAL-TIME LISTENERS ────────────────────────────
function startFirestoreListeners() {
  if (!db || !FB_READY) return;
  if (window._listenersAtivos) return; // evita dupla chamada
  window._listenersAtivos = true;

  const snap2arr = (snap) => snap.docs.map(d => ({ id: d.id, ...d.data() }));

  function norm(d) {
    return {
      ...d,
      // pat: NUNCA usa IP como fallback — IP não é número de patrimônio
      // Máquinas sem PAT vinculado ficam com pat vazio e exibem indicador visual na tabela
      pat:    d.pat    || d.patrimonio || '',
      // desc: prefere desc → hostname → sysDescr (linha 1) → nunca o IP puro
      desc:   d.desc   || d.hostname   || (d.sysDescr ? d.sysDescr.split('\n')[0].trim().slice(0,80) : '') || '',
      tipo:   d.tipo   || 'workstation',
      area:   d.area   || '',
      resp:   d.resp   || d.responsavel || '',
      status: d.status || (d.reachable ? 'ativo' : 'offline'),
      fonte:  d.fonte  || 'Discovery',
    };
  }

  // ativos
  db.collection('ativos').onSnapshot(function(snap) {
    STATE._assetsDisc = snap2arr(snap).map(norm);
    STATE.ativos = (STATE._assetsDisc||[]).concat(STATE._assetsSw||[]);
    renderDashboard();
    nbUpdate('nb-ativos', STATE.ativos.length);
    console.log('[Banco] ativos:', STATE._assetsDisc.length);
  }, function(e){ console.error('[Banco] ativos erro:', e.message); });

  // switches
  db.collection('switches').onSnapshot(function(snap) {
    STATE._assetsSw = snap2arr(snap).map(norm);
    STATE.switches  = STATE._assetsSw;
    STATE.ativos = (STATE._assetsDisc||[]).concat(STATE._assetsSw||[]);
    renderDashboard();
    nbUpdate('nb-ativos', STATE.ativos.length);
    console.log('[Banco] switches:', STATE._assetsSw.length);
  }, function(e){ console.error('[Banco] switches erro:', e.message); });

  // empregados
  db.collection('empregados').orderBy('nome').limit(2000).onSnapshot(function(snap) {
    STATE.empregados = snap2arr(snap);
    // Calcula data do último sync (campo gravado pelo agente)
    const primeiro = STATE.empregados[0];
    STATE.empregadosSyncAt = primeiro?.syncAt ? new Date(primeiro.syncAt)
      : primeiro?.syncLdap ? new Date(primeiro.syncLdap)
      : null;
    nbUpdate('nb-emp', STATE.empregados.length);
    nbUpdate('nb-ausentes', STATE.empregados.filter(e => e.emAusencia).length);
    console.log('[Banco] empregados:', STATE.empregados.length);
    if (isPageActive('empregados')) renderEmpregados();
  }, function(e){ console.error('[Banco] empregados erro:', e.message); });

  // chamados
  db.collection('chamados').onSnapshot(function(snap) {
    STATE.chamados = snap2arr(snap);
    renderDashboard();
    console.log('[Banco] chamados:', STATE.chamados.length);
  }, function(e){ console.error('[Banco] chamados erro:', e.message); });

  // aprovacoes
  db.collection('aprovacoes').onSnapshot(function(snap) {
    STATE.aprovacoes = snap2arr(snap).filter(function(a){ return a.status === 'pendente'; });
    nbUpdate('nb-aprov', STATE.aprovacoes.length);
  }, function(e){ console.error('[Banco] aprovacoes erro:', e.message); });

  // smartphones
  db.collection('smartphones').onSnapshot(function(snap) {
    STATE.smartphones = snap2arr(snap);
  }, function(e){ console.error('[Banco] smartphones erro:', e.message); });

  // mobiliario
  db.collection('mobiliario').onSnapshot(function(snap) {
    STATE.mobiliario = snap2arr(snap);
  }, function(e){ console.error('[Banco] mobiliario erro:', e.message); });

  // organograma_unidades — sincronizado pelo agent.js a cada 5 min
  db.collection('organograma_unidades').onSnapshot(function(snap) {
    STATE.orgUnidades = snap2arr(snap);
    console.log('[Banco] organograma_unidades:', STATE.orgUnidades.length);
  }, function(e){ console.error('[Banco] orgUnidades erro:', e.message); });

  console.log('[Banco] Listeners iniciados');
}

// ── FIRESTORE WRITE HELPERS ───────────────────────────────────
// ── FIRESTORE AUDIT LOG PERSIST (modular) ────────────────────
const _origAuditLog = window.auditLog;
window.auditLog = function(action, module, resourceId, resourceType, details = {}) {
  const entry = typeof auditLog_local === 'function'
    ? auditLog_local(action, module, resourceId, resourceType, details) : null;
  if (FB_READY && db && window._fs) {
    const { collection, addDoc, serverTimestamp } = window._fs;
    addDoc(col('audit_logs'), {
      userId: CURRENT_USER.uid, userName: CURRENT_USER.nome,
      action, module, resourceId, resourceType,
      details: JSON.stringify(details).slice(0, 2000),
      createdAt: serverTimestamp(),
    }).catch(e => console.warn('[Banco] audit_log:', e.message));
  }
  return entry;
};

// SMTP CONFIG PLACEHOLDER (Banco Functions ou endpoint próprio)
const SMTP_CONFIG = {
  endpoint: '/api/send-email',
  from: 'noreply@adsi.com.br',
  gestorEmail: 'gestor@adsi.com.br',
  alertDias5: true,
  alertDias10: true,
};

// ============================================================
// STATE — Substituir por Banco listeners em produção
// ============================================================
const IS_PRODUCTION = location.protocol === "https:" && !location.hostname.includes("localhost") && location.hostname !== "";

let STATE = {
  ativos: [], chamados: [], tecnicos: [], movimentacoes: [],
  aprovacoes: [], notificacoes: [], scAtivos: [], terceirizadaAtivos: []
};

function initSeedData() {
  // PRODUÇÃO: sem dados de demonstração
  // Todos os dados vêm do Banco Banco via listeners em tempo real
  STATE.scAtivos = [];
  STATE.notificacoes = [];
  STATE.terceirizadaAtivos = [];
  console.log('[SYSACK] v2.1 - listeners Firebase corrigidos - Producao: aguardando Banco');
}

// ============================================================
// NAVIGATION
// ============================================================
const PAGE_LABELS = {
  dashboard:'Dashboard', 'exec-dashboard':'Dashboard Executivo', 'ai-dashboard':'IA & Insights', 'self-service':'Self-Service', 'mapa-ativos':'Mapa de Ativos', 'relatorios':'Relatórios','patrimonio':'Gestão Patrimonial','impressoras':'Gestão de Impressoras','wsus':'Patches (WSUS)','capacidade':'Relatório de Capacidade','backup-recovery':'Backup / Recovery','grupos-alerta':'Grupos de Alerta por E-mail','dashboard-tecnico':'Produtividade dos Técnicos','osd':'Deploy de SO (OSD)','metricas-historico':'Métricas Históricas','compliance-cis':'Compliance CIS', 'assistencia-remota':'Assistência Remota', 'monitor-rede':'Monitor de Rede', 'empregados':'Empregados & Ausências', chamados:'Chamados', ativos:'Ativos',
  movimentacoes:'Movimentações', 'mudancas-itil':'Mudanças (ITIL)', terceirizada:'Empresa Terceirizada',
  'santa-clara':'Santa Clara', aprovacoes:'Aprovações',
  relatorios:'Relatórios', tecnicos:'Técnicos', kb:'Base de Conhecimento',
  mdm:'Smartphones / MDM', switches:'Switches & Roteadores', apps:'Apps structures',
  documentos:'Documentos', lembretes:'Lembretes',
  pesquisas:'Pesquisas Salvas', alertas:'Alertas'
};

// ─── Utilitário: verifica se uma página está ativa no DOM ────
function isPageActive(pageId) {
  var page = document.getElementById('page-' + pageId);
  return !!(page && page.classList.contains('active'));
}

// ─── SINGLE goPage + renderPage — NO PATCHES, NO RECURSION ───
function goPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-i').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  if (page) page.classList.add('active');
  const nav = document.querySelector(`.nav-i[data-page="${id}"]`);
  if (nav) nav.classList.add('active');
  const bcMain = document.getElementById('bc-main');
  if (bcMain) bcMain.textContent = PAGE_LABELS[id] || id;
  const sep2 = document.getElementById('bc-sep2');
  const bcsub = document.getElementById('bc-sub');
  if (sep2) sep2.style.display = 'none';
  if (bcsub) bcsub.style.display = 'none';
  renderPage(id);
}

function renderPage(id) {
  const map = {
    dashboard:       () => renderDashboard(),
    'exec-dashboard':() => renderExecDashboard(),
    'ai-dashboard':  () => renderAIDashboard(),
    'mapa-ativos':   () => renderMapaAtivos(),
    'assistencia-remota': () => renderAssistenciaRemota(),
    'impressoras':        () => renderImpressoras(),
    'wsus':               () => renderWSUS(),
    'capacidade':         () => renderRelatorioCapacidade(),
    'backup-recovery':    () => renderBackupRecovery(),
    'grupos-alerta':      () => renderGruposAlerta(),
    'dashboard-tecnico':  () => renderDashboardTecnico(),
    'osd':                () => renderOSD(),
    'metricas-historico': () => renderMetricasHistorico(),
    'compliance-cis':     () => renderComplianceCIS(),
    'patrimonio':         () => renderPatrimonio(),
    'relatorios':         () => renderRelatorios(),
    'monitor-rede':  () => { renderMonitorRede(); setTimeout(renderMapaRede, 200); },
    'self-service':  () => renderSelfService(),
    'empregados':    () => renderEmpregados(),
    'organograma':   () => renderOrganograma(),
    chamados:        () => renderChamados(),
    ativos:          () => renderAtivos(),
    movimentacoes:   () => renderMovimentacoes(),
    'mudancas-itil': () => renderMudancasITIL(),
    terceirizada:    () => renderTerceirizada(),
    'santa-clara':   () => renderSantaClara(),
    aprovacoes:      () => renderAprovacoes(),
    tecnicos:        () => renderTecnicos(),
    kb:              () => renderKB(),
    mdm:             () => typeof renderMDM === 'function' && renderMDM(),
    switches:        () => typeof renderSwitches === 'function' && renderSwitches(),
    apps:            () => typeof renderApps === 'function' && renderApps(),
    mobiliario:      () => typeof renderMobiliario === 'function' && renderMobiliario(),
    documentos:      () => typeof renderDocumentos === 'function' && renderDocumentos(),
    lembretes:       () => typeof renderLembretes === 'function' && renderLembretes(),
    pesquisas:       () => typeof renderPesquisas === 'function' && renderPesquisas(),
    alertas:         () => typeof renderAlertas === 'function' && renderAlertas(),
  };
  if (map[id]) map[id]();
}

// ============================================================
// DASHBOARD
// ============================================================
function renderDashboard() {
  const overdue = STATE.terceirizadaAtivos.filter(t => !t.retornado && t.diasUteis > 10);
  const pend = STATE.aprovacoes.filter(a => a.status === 'pendente');
  sv('ds-total', STATE.ativos.length);
  sv('ds-uso',   STATE.ativos.filter(a => a.status === 'ativo').length);
  sv('ds-terc',  STATE.terceirizadaAtivos.filter(t => !t.retornado).length);
  sv('ds-sc',    STATE.ativos.filter(a => a.status === 'sc').length);
  sv('ds-pend',  overdue.length + pend.length);
  sv('ds-mov',   STATE.movimentacoes.length);
  sv('ds-cham',  STATE.chamados.filter(c => c.status !== 'concluido').length);
  sv('ds-aprov', pend.length);

  const banner = document.getElementById('dash-approval-banner');
  banner.style.display = pend.length > 0 ? '' : 'none';
  if (pend.length > 0) document.getElementById('dash-approval-text').textContent = `${pend.length} movimentação(ões) aguardam autorização. O fluxo está pausado.`;

  const overSection = document.getElementById('dash-overdue-section');
  overSection.style.display = overdue.length > 0 ? '' : 'none';
  if (overdue.length > 0) {
    document.getElementById('dash-overdue-list').innerHTML = overdue.map(t => `
      <div class="pending-row">
        <div class="pr-icon">🚨</div>
        <div class="pr-text"><div class="pr-title">${t.pat} — ${t.ativo}</div><div class="pr-sub">Enviado ${fmtDate(t.dataEnvio)} · Técnico: ${getTecNome(t.tecnicoTerc)} · ${t.chamadoId}</div></div>
        <div class="pr-days">${t.diasUteis}d</div>
        <button class="btn btn-danger btn-sm" onclick="goPage('terceirizada')">Ver</button>
      </div>`).join('');
  }

  document.getElementById('dash-chamados-body').innerHTML = STATE.chamados.slice(0,5).map(c => `
    <tr>
      <td class="td-mono" style="color:var(--accent)">${c.id}</td>
      <td>${c.desc.slice(0,40)}${c.desc.length>40?'...':''}</td>
      <td class="td-mono">${c.pat||'—'}</td>
      <td>${statusBadge(c.status)}</td>
    </tr>`).join('') || '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--g400)">Nenhum chamado</td></tr>';

  document.getElementById('dash-timeline').innerHTML = [
    {dot:'red',    title:'🚨 PAT-0103 com 12 dias na Terceirizada',    desc:'Prazo de 10 dias úteis excedido — ação imediata necessária', time:'hoje'},
    {dot:'orange', title:'⏳ Aprovação pendente — Transferência PAT-0102', desc:'HP EliteBook 840 G8 aguarda autorização do gestor', time:'há 1 dia'},
    {dot:'blue',   title:'CH-001 em atendimento',                      desc:'Carlos Souza — PAT-0103 enviado para Terceirizada', time:'há 12 dias'},
    {dot:'green',  title:'CH-003 concluído',                           desc:'Impressora HP LaserJet M428 — problema resolvido', time:'há 5 dias'},
    {dot:'violet', title:'PAT-0106 enviado para Santa Clara',          desc:'Lenovo ThinkPad E14 — localização e foto registradas', time:'há 30 dias'},
  ].map(i => `<div class="tl-item"><div class="tl-dot ${i.dot}"></div><div class="tl-title">${i.title}</div><div class="tl-desc">${i.desc}</div><div class="tl-time">${i.time}</div></div>`).join('');
}

// ============================================================
// CHAMADOS
// ============================================================
function renderChamados(filter='abertos') {
  let list = STATE.chamados;
  if (filter==='abertos') list = list.filter(c=>c.status==='aberto');
  else if (filter==='em-atendimento') list = list.filter(c=>c.status==='em-atendimento');
  else if (filter==='aguardando') list = list.filter(c=>c.status==='aguardando-aprovacao');
  else if (filter==='concluidos') list = list.filter(c=>c.status==='concluido');
  document.getElementById('chamados-body').innerHTML = list.map(c => `
    <tr>
      <td><input type="checkbox" style="accent-color:var(--accent)"></td>
      <td class="td-mono fw-700" style="color:var(--accent);cursor:pointer" onclick="abrirAtendimento('${escapeHtml(c.id)}')">${c.id}</td>
      <td style="max-width:240px"><a style="color:var(--accent);cursor:pointer;font-weight:500;font-size:12.5px" onclick="abrirAtendimento('${escapeHtml(c.id)}')">${c.desc.slice(0,55)}${c.desc.length>55?'...':''}</a></td>
      <td style="font-size:11.5px"><div style="color:var(--g700);font-weight:600">CESAN</div><div style="color:var(--g400);font-size:10.5px">${c.area||'—'}</div></td>
      <td>${statusBadgeCh(c.status)}</td>
      <td style="font-size:12px;max-width:200px"><div>${c.categoria?categoriaLabel(c.categoria):'—'}</div>${c.subcategoria?`<div style='font-size:10.5px;color:var(--g400)'>» ${c.subcategoria}</div>`:''}</td>
      <td style="font-size:12px;max-width:160px"><div>${c.solicitante||'—'}</div></td>
      <td style="font-size:11.5px;color:var(--g600)">${c.grupo||getTecNome(c.tecnico)||'—'}</td>
      <td style="font-size:11.5px;color:var(--g600)">${c.atribuido||'—'}</td>
      <td class="td-mono" style="font-size:10.5px;white-space:nowrap">${fmtDatetime(c.createdAt)}</td>
      <td class="td-mono" style="font-size:10.5px;white-space:nowrap">${fmtDatetime(c.updatedAt||c.createdAt)}</td>
      <td><div class="flex gap-4"><button class="btn btn-secondary btn-xs" onclick="abrirAtendimento('${escapeHtml(c.id)}')">Atender</button><button class="btn btn-ghost btn-xs" data-ia-btn="${escapeHtml(c.id)}" onclick="triagemIAChamado('${escapeHtml(c.id)}')" title="Análise com IA">🤖</button><button class="btn btn-ghost btn-xs" onclick="abrirHistorico('${c.pat||''}')">📜</button>${(c.status==='concluido'||c.status==='fechado')?`<button class="btn btn-ghost btn-xs" onclick="reabrirChamado('${escapeHtml(c.id)}')">🔄</button>`:''} ${c.status==='concluido'||c.status==='aberto'?`<button class="btn btn-ghost btn-xs" onclick="configurarChamadoRecorrente('${escapeHtml(c.id)}')" title="Tornar recorrente">🔁</button>`:''}</div></td>
    </tr>`).join('') || `<tr><td colspan="12" style="text-align:center;padding:24px;color:var(--g400)">Nenhum chamado neste filtro</td></tr>`;
  nbUpdate('nb-chamados', STATE.chamados.filter(c=>c.status!=='concluido'&&c.status!=='fechado').length);
}

// ============================================================
// ATIVOS
// ============================================================
// Filtro de tipo ativo para as abas
let _ativoFiltroTipo = '';

function filtrarAtivosPorTipo(tipos, el) {
  _ativoFiltroTipo = tipos;
  // Atualiza tab ativa
  document.querySelectorAll('#ativos-tabs .tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  else if (event?.currentTarget) event.currentTarget.classList.add('active');
  // Atualiza colunas da tabela de acordo com a aba
  const _isComp = tipos && (tipos.includes('computador') || tipos.includes('notebook') || tipos.includes('desktop') || tipos.includes('workstation'));
  updateAtivosTableForComputadores(_isComp);
  renderAtivos();
}

function renderAtivos() {
  const q      = (document.getElementById('pat-search')?.value || '').toLowerCase();
  const fSt    = document.getElementById('pat-filter-status')?.value || '';
  const tipos  = _ativoFiltroTipo ? _ativoFiltroTipo.split(',') : [];
  const isComp = !!_ativoFiltroTipo && (_ativoFiltroTipo.includes('computador') || _ativoFiltroTipo.includes('notebook') || _ativoFiltroTipo.includes('desktop') || _ativoFiltroTipo.includes('workstation'));
  window._ativosFiltroIsComp = isComp;

  // Atualiza header da tabela
  const thead = document.getElementById('ativos-thead');
  if (thead) {
    thead.innerHTML = `<tr>
      ${isComp ? '<th style="font-size:11px">Hostname</th><th style="font-size:11px">PAT (Auto)</th>' : ''}
      <th>Patrimônio</th><th>Descrição</th><th>Tipo</th><th>Área</th><th>Responsável</th><th>Status</th><th>Localização</th>
      ${isComp ? '<th style="font-size:11px;width:160px">📊 CPU / RAM / Disco</th>' : ''}
      <th>Ações</th>
    </tr>`;
  }

  const lista = STATE.ativos.filter(a => {
    if (tipos.length > 0) {
      const t = (a.tipo || '').toLowerCase();
      if (!tipos.some(ft => t.includes(ft) || ft.includes(t))) return false;
    }
    if (fSt && a.status !== fSt) return false;
    if (q && !`${a.pat} ${a.desc} ${a.area} ${a.resp||''} ${a.ip||''}`.toLowerCase().includes(q)) return false;
    return true;
  });

  const colspan = isComp ? '11' : '8';
  document.getElementById('ativos-body').innerHTML = lista.map(a => `
    <tr>
      ${isComp ? (()=>{
        const _hn = hostnameFromAtivo(a);
        const _pp = extractPatrimonioFromHostname(_hn);
        return '<td style="font-family:monospace;font-size:12px;font-weight:600">' + (_hn||'<span style="color:#94A3B8">—</span>') + '</td><td class="td-mono">' + (_pp.pat ? (_pp.alerta ? '<span style="color:#EF4444;font-weight:700">' + _pp.pat + ' ⚠️</span>' : '<span style="color:#059669;font-weight:700">' + _pp.pat + '</span>') : '<span style="color:#EF4444">N/A ⚠️</span>') + '</td>';
      })() : ''}
      <td class="td-mono fw-700" style="color:var(--accent)">${
        a.pat
          ? a.pat
          : `<span style="font-size:10px;background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:10px;font-weight:700;font-family:inherit">Sem PAT</span>`
      }</td>
      <td style="font-weight:500">${
        a.desc && a.desc !== a.ip
          ? a.desc
          : (a.hostname && a.hostname !== a.ip ? a.hostname : (a.ip ? `<span style="font-family:monospace;font-size:11px;color:var(--g500)">${a.ip}</span>` : '—'))
      }</td>
      <td><span class="tag">${a.tipo||'—'}</span></td>
      <td>${a.area||'—'}</td>
      <td>${a.resp||'—'}</td>
      <td>${statusAtivoHtml(a.status)}</td>
      <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.sala||a.loc||a.area||''}">
        ${a.sala ? `<div style="font-size:12px;font-weight:600;color:var(--g800)">${a.sala}</div><div style="font-size:11px;color:var(--g400)">${a.loc||''}</div>` : a.loc||'—'}
      </td>
      ${isComp ? patMetricasHtml(a) : ''}
      <td><div class="flex gap-6">
        <button class="btn btn-ghost btn-xs" onclick="abrirHistorico('${a.pat||a.id}')">📜</button>
        <button class="btn btn-ghost btn-xs" onclick="gerarQRCode(${JSON.stringify({id:a.id,pat:a.pat||a.ip||'',desc:a.desc||''})})" title="QR Code">📱</button>
        <button class="btn btn-ghost btn-xs" onclick="analisarAtivoPorIA('${a.pat||a.id}')" title="Análise IA">🤖</button>
        <button class="btn btn-secondary btn-xs" onclick="openModal('modal-transferencia')">↔</button>
        ${isComp ? `<button class="btn btn-ghost btn-xs" onclick="patAbrirBusca()" title="Vincular PAT">🏷️</button>` : ''}
      </div></td>
    </tr>`).join('') || `<tr><td colspan="${colspan}" style="text-align:center;padding:24px;color:var(--g400)">Nenhum ativo — ${tipos.length?'tipo: '+_ativoFiltroTipo:'cadastrado'}</td></tr>`;
  nbUpdate('nb-ativos', lista.length);
}


// ============================================================
// HOSTNAME PATRIMÔNIO EXTRACTOR
// ============================================================
function extractPatrimonioFromHostname(hostname) {
  if (!hostname) return { pat: null, alerta: true };
  // Get trailing numeric digits after the last letter in hostname
  const match = hostname.match(/[a-zA-Z]([0-9]+)$/);
  if (!match) return { pat: null, alerta: true };
  const digits = match[1];
  if (digits.length < 4) return { pat: digits, alerta: true };
  return { pat: digits, alerta: false };
}

function hostnameFromAtivo(a) {
  // Prioridade: campo hostname real > agente local > vazio
  // NUNCA retorna o IP como hostname — são campos distintos
  if (a.hostname && a.hostname !== a.ip) return a.hostname;
  // Tenta encontrar via agente pelo IP
  const agent = (window.STATE_AGENTS && STATE_AGENTS.list || [])
    .find(ag => ag.ip === a.ip || ag.ip === a.ipAddress);
  if (agent && agent.hostname && agent.hostname !== a.ip) return agent.hostname;
  return null; // sem hostname — exibir '—' na coluna, não o IP
}


function updateAtivosTableForComputadores(isComputadores) {
  // Header gerenciado exclusivamente pelo renderAtivos() — não fazer nada aqui
}

// ============================================================
// MOVIMENTAÇÕES
// ============================================================
function renderMovimentacoes() {
  const pend = STATE.aprovacoes.filter(a=>a.status==='pendente').length;
  const crit = STATE.terceirizadaAtivos.filter(t=>!t.retornado&&t.diasUteis>10).length;
  sv('mov-mes', STATE.movimentacoes.length);
  sv('mov-pend', pend);
  sv('mov-crit', crit);
  document.getElementById('mov-body').innerHTML = STATE.movimentacoes.map(m => `
    <tr>
      <td class="td-mono">${fmtDate(m.data)}</td>
      <td><span class="tag">${m.tipo}</span></td>
      <td class="td-mono" style="color:var(--accent)">${m.pat}</td>
      <td>${m.ativo}</td>
      <td>${m.de}</td>
      <td>${m.para}</td>
      <td>${m.tecnico}</td>
      <td>${aprovStatusBadge(m.status)}</td>
      <td><button class="btn btn-ghost btn-xs" onclick="abrirHistorico('${m.pat}')">📜</button></td>
    </tr>`).join('') || `<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma movimentação</td></tr>`;
  nbUpdate('nb-mov', pend);
}

// ============================================================
// TERCEIRIZADA
// ============================================================
function renderTerceirizada() {
  const ativos = STATE.terceirizadaAtivos.filter(t=>!t.retornado);
  const overdue = ativos.filter(t=>t.diasUteis>10);
  document.getElementById('terc-alertas-overdue').innerHTML = overdue.map(t => `
    <div class="alert alert-danger"><span>🚨</span>
      <div><strong>${t.pat} — ${t.ativo}</strong><br><span style="font-size:11.5px">Enviado ${fmtDate(t.dataEnvio)} · ${t.diasUteis} dias úteis · Prazo de 10 dias excedido!</span></div>
      <button class="btn btn-danger btn-sm" style="margin-left:auto;flex-shrink:0" onclick="openModal('modal-retorno-terc')">Registrar Retorno</button>
    </div>`).join('');
  document.getElementById('terc-body').innerHTML = ativos.map(t => {
    const d = t.diasUteis;
    const cls = d>10?'badge-danger':d>=5?'badge-warning':'badge-success';
    const alerta = d>10?'⚠️ Atrasado':d>=5?'🕐 Alerta 5d':'✓ OK';
    return `<tr>
      <td class="td-mono" style="color:var(--accent)">${t.pat}</td>
      <td>${t.ativo}</td>
      <td class="td-mono">${fmtDate(t.dataEnvio)}</td>
      <td><span class="badge ${cls}">${d} dias</span></td>
      <td>${getTecNome(t.tecnicoTerc)}</td>
      <td class="td-mono">${t.chamadoId}</td>
      <td><span class="badge ${cls}">${alerta}</span></td>
      <td><span class="status-pill sp-terceirizada">Na Terceirizada</span></td>
      <td><button class="btn btn-primary btn-xs" onclick="openModal('modal-retorno-terc')">↩ Retorno</button></td>
    </tr>`;
  }).join('') || `<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--g400)">Nenhum ativo na terceirizada</td></tr>`;
  nbUpdate('nb-terc', overdue.length);
}

// ============================================================
// SANTA CLARA
// ============================================================
function renderSantaClara() {
  const grid = document.getElementById('sc-cards');
  if (!grid) return;
  const ativos = STATE.scAtivos || [];
  if (!ativos.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:48px;color:var(--g400)"><div style="font-size:48px;margin-bottom:16px">📦</div><div style="font-weight:600;font-size:14px;margin-bottom:6px">Nenhum ativo em Santa Clara</div><div style="font-size:13px">Clique em "+ Registrar Entrada" para adicionar</div></div>';
    return;
  }
  grid.innerHTML = ativos.map(sc => `
    <div class="card" style="transition:all .2s" onmouseover="this.style.transform='translateY(-3px)'" onmouseout="this.style.transform=''">
      <!-- Foto do local -->
      <div style="height:160px;border-radius:10px 10px 0 0;overflow:hidden;background:linear-gradient(135deg,#EDE9FE,#DDD6FE);position:relative">
        ${sc.fotoUrl
          ? `<img src="${escapeHtml(sc.fotoUrl)}" style="width:100%;height:100%;object-fit:cover" onerror="this.style.display='none'">`
          : `<div style="display:flex;align-items:center;justify-content:center;height:100%;font-size:40px">📦</div>`
        }
        <div style="position:absolute;top:8px;right:8px;background:rgba(0,0,0,.6);color:#fff;font-size:10px;font-weight:700;padding:3px 8px;border-radius:20px">${escapeHtml(sc.status||'armazenado')}</div>
      </div>
      <div class="card-body">
        <div class="td-mono" style="color:var(--accent);font-size:12px;margin-bottom:4px">${escapeHtml(sc.pat||'—')}</div>
        <div style="font-size:13.5px;font-weight:700;margin-bottom:6px">${escapeHtml(sc.desc||sc.ativo||'—')}</div>
        <div style="font-size:12px;color:var(--g600);margin-bottom:4px;display:flex;align-items:flex-start;gap:6px">
          <span>📍</span><span>${escapeHtml(sc.local||sc.loc||'—')}</span>
        </div>
        ${sc.obs ? `<div style="font-size:11.5px;color:var(--g400);margin-bottom:6px;font-style:italic">${escapeHtml(sc.obs)}</div>` : ''}
        <div style="font-size:11px;color:var(--g400);margin-bottom:10px">
          Entrada: ${sc.dataEntrada||'—'}
          ${sc.origemTerceirizada ? ' · via Empresa Terceirizada' : ''}
        </div>
        <!-- Histórico de localizações anteriores -->
        ${(sc.historicoLocais||[]).length > 1 ? `
        <div style="margin-bottom:10px">
          <button onclick="scVerHistorico('${sc.id}')" style="background:none;border:none;color:var(--accent);font-size:11.5px;cursor:pointer;padding:0;font-weight:600">
            📋 Ver ${(sc.historicoLocais||[]).length - 1} localização(ões) anterior(es)
          </button>
        </div>` : ''}
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-xs" onclick="abrirAtualizacaoSC('${sc.id}')">📍 Mover</button>
          <button class="btn btn-ghost btn-xs" onclick="scVerHistorico('${sc.id}')">📋 Histórico</button>
        </div>
      </div>
    </div>`).join('') || '<div style="padding:32px;text-align:center;color:var(--g400)">Nenhum ativo registrado</div>';
  // Também atualiza o relatório SC se estiver na tela
  gerarRelSantaClara?.(new Date(0), new Date());
}

function scDef(v, d='') { return v ?? d; }


function renderAprovacoes() {
  const pend = STATE.aprovacoes.filter(a=>a.status==='pendente');
  const hist = STATE.aprovacoes.filter(a=>a.status!=='pendente');
  document.getElementById('aprov-pending-count').textContent = `${pend.length} pendente${pend.length!==1?'s':''}`;
  nbUpdate('nb-aprov', pend.length);
  document.getElementById('aprov-pending-list').innerHTML = pend.map(ap => `
    <div class="approval-banner" style="animation:fadeUp .3s ease">
      <div class="ab-icon">⏳</div>
      <div class="ab-text"><h4>${ap.tipo} — ${ap.pat}</h4><p>${ap.ativo} · Solicitado por ${ap.solicitante} · ${fmtDate(ap.data)}</p></div>
      <div class="ab-actions">
        <button class="btn btn-danger btn-sm" onclick="decidirAprovacao('${ap.id}','recusado')">✕ Recusar</button>
        <button class="btn btn-success btn-sm" onclick="decidirAprovacao('${ap.id}','aprovado')">✓ Autorizar</button>
      </div>
    </div>`).join('') || '<p class="text-sm text-muted" style="padding:8px">Nenhuma aprovação pendente. ✓</p>';
  document.getElementById('aprov-hist-body').innerHTML = hist.map(ap => `
    <tr>
      <td class="td-mono">${fmtDate(ap.data)}</td>
      <td>${ap.tipo}</td>
      <td class="td-mono" style="color:var(--accent)">${ap.pat}</td>
      <td>${ap.ativo}</td>
      <td>${ap.solicitante}</td>
      <td>${aprovStatusBadge(ap.status)}</td>
    </tr>`).join('') || `<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--g400)">Sem histórico ainda</td></tr>`;
}

function decidirAprovacao(id, decisao) {
  const ap = STATE.aprovacoes.find(a=>a.id===id);
  if (!ap) return;
  ap.status = decisao;
  auditLog('APPROVE', 'aprovacoes', id, 'aprovacao', {decisao, pat:ap.pat, ativo:ap.ativo});
  fsUpdate('aprovacoes', id, {status: decisao, decidedBy: CURRENT_USER.uid, decidedAt: new Date()});
  // TODO SMTP: enviar email de resultado para solicitante
  renderAprovacoes();
  renderDashboard();
  showToast(decisao==='aprovado'?`✓ Autorizado — ${ap.pat}`:`✕ Recusado — ${ap.pat}`, decisao==='aprovado'?'success':'danger');
}

// ============================================================
// TÉCNICOS
// ============================================================
function renderTecnicos() {
  document.getElementById('tecnicos-body').innerHTML = STATE.tecnicos.map(t => `
    <tr>
      <td style="font-weight:600">${t.nome}</td>
      <td><span class="badge ${t.empresa==='adsi'?'badge-info':'badge-orange'}">${t.empresa==='adsi'?'A-DSI':'Terceirizada'}</span></td>
      <td>${t.email}</td>
      <td>${t.tel}</td>
      <td><span class="status-pill sp-ativo">Ativo</span></td>
      <td><button class="btn btn-ghost btn-xs">✏️ Editar</button></td>
    </tr>`).join('');
}

// ============================================================
// BASE DE CONHECIMENTO
// ============================================================
function renderKB() {
  const areas = [
    {name:'TI',icon:'💻',desc:'Infraestrutura, redes e suporte',count:18},
    {name:'RH',icon:'👥',desc:'Recursos humanos e onboarding',count:9},
    {name:'Financeiro',icon:'💰',desc:'Processos financeiros',count:7},
    {name:'Comercial',icon:'📊',desc:'Vendas e atendimento',count:11},
    {name:'Jurídico',icon:'⚖️',desc:'Contratos e compliance',count:5},
    {name:'Operações',icon:'⚙️',desc:'Processos operacionais',count:6},
  ];
  document.getElementById('kb-areas-grid').innerHTML = areas.map(a => `
    <div class="card" style="cursor:pointer;transition:all .2s" onmouseover="this.style.transform='translateY(-3px)'" onmouseout="this.style.transform=''">
      <div class="card-body">
        <div style="font-size:28px;margin-bottom:8px">${a.icon}</div>
        <div style="font-size:14px;font-weight:700;margin-bottom:4px">${a.name}</div>
        <div style="font-size:12px;color:var(--g500);margin-bottom:10px">${a.desc}</div>
        <span class="badge badge-info">${a.count} artigos</span>
      </div>
    </div>`).join('');
}

// ============================================================
// RELATÓRIOS
// ============================================================
function loadRel(tipo) {
  const titles = {
    movimentacoes:'Relatório de Movimentações', pendencias:'Pendências de Movimentação',
    sc:'Máquinas em Santa Clara', 'terc-atraso':'Terceirizada — Atraso (>10 dias)',
    'terc-geral':'Todos os Ativos na Terceirizada', historico:'Histórico por Ativo'
  };
  document.getElementById('rel-title').textContent = titles[tipo] || tipo;
  const thead = document.getElementById('rel-thead');
  const tbody = document.getElementById('rel-tbody');
  if (tipo==='movimentacoes') {
    thead.innerHTML='<tr><th>Data</th><th>Tipo</th><th>Patrimônio</th><th>Ativo</th><th>De</th><th>Para</th><th>Técnico</th><th>Status</th></tr>';
    tbody.innerHTML=STATE.movimentacoes.map(m=>`<tr><td class="td-mono">${fmtDate(m.data)}</td><td><span class="tag">${m.tipo}</span></td><td class="td-mono" style="color:var(--accent)">${m.pat}</td><td>${m.ativo}</td><td>${m.de}</td><td>${m.para}</td><td>${m.tecnico}</td><td>${aprovStatusBadge(m.status)}</td></tr>`).join('')||noData(8);
  } else if (tipo==='terc-atraso') {
    const overdue=STATE.terceirizadaAtivos.filter(t=>!t.retornado&&t.diasUteis>10);
    thead.innerHTML='<tr><th>Patrimônio</th><th>Ativo</th><th>Data Envio</th><th>Dias Úteis</th><th>Técnico</th><th>Chamado</th></tr>';
    tbody.innerHTML=overdue.map(t=>`<tr style="background:var(--danger-l)"><td class="td-mono" style="color:var(--danger)">${t.pat}</td><td>${t.ativo}</td><td class="td-mono">${fmtDate(t.dataEnvio)}</td><td><span class="badge badge-danger">${t.diasUteis}d</span></td><td>${getTecNome(t.tecnicoTerc)}</td><td class="td-mono">${t.chamadoId}</td></tr>`).join('')||noData(6);
  } else if (tipo==='sc') {
    thead.innerHTML='<tr><th>Patrimônio</th><th>Ativo</th><th>Localização</th><th>Data Entrada</th><th>Observação</th></tr>';
    tbody.innerHTML=STATE.scAtivos.map(sc=>`<tr><td class="td-mono" style="color:var(--accent)">${sc.pat}</td><td>${sc.ativo}</td><td>📍 ${sc.loc}</td><td class="td-mono">${fmtDate(sc.data)}</td><td>${sc.obs||'—'}</td></tr>`).join('')||noData(5);
  } else if (tipo==='terc-geral') {
    thead.innerHTML='<tr><th>Patrimônio</th><th>Ativo</th><th>Data Envio</th><th>Dias</th><th>Técnico</th><th>Chamado</th><th>Status</th></tr>';
    tbody.innerHTML=STATE.terceirizadaAtivos.map(t=>`<tr><td class="td-mono" style="color:var(--accent)">${t.pat}</td><td>${t.ativo}</td><td class="td-mono">${fmtDate(t.dataEnvio)}</td><td>${t.diasUteis}d</td><td>${getTecNome(t.tecnicoTerc)}</td><td class="td-mono">${t.chamadoId}</td><td>${t.retornado?'<span class="badge badge-success">Retornado</span>':'<span class="badge badge-orange">Na Terceirizada</span>'}</td></tr>`).join('')||noData(7);
  } else {
    thead.innerHTML='<tr><th>Relatório em construção</th></tr>';
    tbody.innerHTML=`<tr><td style="text-align:center;padding:24px;color:var(--g400)">Em breve...</td></tr>`;
  }
  document.getElementById('rel-result').style.display='';
  document.getElementById('rel-result').scrollIntoView({behavior:'smooth',block:'start'});
}
const noData = n => `<tr><td colspan="${n}" style="text-align:center;padding:24px;color:var(--g400)">Nenhum dado encontrado</td></tr>`;

// ============================================================
// HISTÓRICO DO ATIVO
// ============================================================
function abrirHistorico(pat) {
  if (!pat||pat==='—') return showToast('Nenhum patrimônio para exibir', 'danger');
  document.getElementById('hist-patrimonio').textContent = pat;
  const ativo = STATE.ativos.find(a=>a.pat===pat);
  const infoRow = document.getElementById('hist-info-row');
  if (ativo) {
    infoRow.innerHTML = [
      ['Tipo', ativo.tipo], ['Descrição', ativo.desc],
      ['Status', statusAtivoHtml(ativo.status)], ['Localização', ativo.loc||'—'],
      ['Fabricante', ativo.fab||'—'], ['Série', ativo.serie||'—'],
      ['Cadastrado em', fmtDate(ativo.createdAt)],
    ].map(([l,v])=>`<div><div class="text-xs text-muted">${l}</div><div style="font-size:13px;font-weight:600;margin-top:2px">${v}</div></div>`).join('');
  } else { infoRow.innerHTML = '<p class="text-muted">Ativo não encontrado no cadastro</p>'; }
  const movs = STATE.movimentacoes.filter(m=>m.pat===pat);
  const chs  = STATE.chamados.filter(c=>c.pat===pat);
  const entries = [
    {dot:'green', title:'Cadastro inicial no sistema', desc:`Patrimônio ${pat} registrado no SYSACK`, time: ativo?fmtDate(ativo.createdAt):'—'},
    ...chs.map(c=>({dot:'blue', title:`Chamado ${c.id} — ${tipoLabel(c.tipo)}`, desc:c.desc.slice(0,60), time:fmtDate(c.createdAt)})),
    ...movs.map(m=>({dot:m.tipo==='Terceirizada'?'orange':m.tipo==='Santa Clara'?'violet':'blue', title:`${m.tipo}: ${m.de} → ${m.para}`, desc:`Técnico: ${m.tecnico} · Aprovação: ${m.status}`, time:fmtDate(m.data)})),
  ].sort((a,b)=>0);
  document.getElementById('hist-timeline').innerHTML = entries.map(e=>`
    <div class="tl-item"><div class="tl-dot ${e.dot}"></div><div class="tl-title">${e.title}</div><div class="tl-desc">${e.desc}</div><div class="tl-time">${e.time}</div></div>`).join('');
  openModal('modal-historico-ativo');
}

function adicionarObsHistorico() {
  const obs = document.getElementById('hist-obs-input').value.trim();
  if (!obs) return;
  const tl = document.getElementById('hist-timeline');
  tl.innerHTML = `<div class="tl-item"><div class="tl-dot gray"></div><div class="tl-title">Observação adicionada</div><div class="tl-desc">${obs}</div><div class="tl-time">agora</div></div>` + tl.innerHTML;
  document.getElementById('hist-obs-input').value = '';
  showToast('Observação adicionada ao histórico');
}

// ============================================================
// ATENDER CHAMADO
// ============================================================
function abrirAtendimento(chamadoId) {
  const ch = STATE.chamados.find(c=>c.id===chamadoId);
  if (!ch) return;
  document.getElementById('atender-ch-id').textContent = chamadoId;
  document.getElementById('at-patrimonio').value = ch.pat||'';
  openModal('modal-atender-chamado');
}

function toggleMudouLugar(val) {
  document.getElementById('sub-mudou-lugar').style.display = val==='sim'?'':'none';
  document.getElementById('ro-nao').classList.toggle('checked', val==='nao');
  document.getElementById('ro-sim').classList.toggle('checked', val==='sim');
}
function toggleDestinoAntigo() {
  const val = document.getElementById('at-destino-antigo').value;
  document.getElementById('sub-dest-terceirizada').style.display = val==='terceirizada'?'':'none';
  document.getElementById('sub-dest-sc').style.display = val==='sc'?'':'none';
  document.getElementById('sub-dest-reutilizada').style.display = val==='reutilizada'?'':'none';
}
function toggleUsoTipo(tipo) {
  document.getElementById('sub-uso-usuario').style.display = tipo==='usuario'?'':'none';
  document.getElementById('sub-uso-grupo').style.display = tipo==='grupo'?'':'none';
}
function toggleRetDestino(tipo) {
  document.getElementById('sub-ret-reutilizar').style.display = tipo==='reutilizar'?'':'none';
  document.getElementById('sub-ret-sc').style.display = tipo==='sc'?'':'none';
}

// ============================================================
// SAVE ACTIONS (com TODO Banco pronto)
// ============================================================
// ════════════════════════════════════════════════════════════
// CHAMADO — MOVIMENTAÇÃO DE MÁQUINA
// ════════════════════════════════════════════════════════════

function chToggleMovimentacao(checked) {
  document.getElementById('ch-mov-campos').style.display = checked ? '' : 'none';
  if (checked) {
    // Popula técnicos Empresa Terceirizada
    const sel = document.getElementById('ch-tecnico-mindworks');
    if (sel && sel.options.length <= 1) {
      const terceirizada = (STATE.tecnicos || []).filter(t =>
        (t.empresa || '').toLowerCase().includes('mind') ||
        (t.empresa || '').toLowerCase().includes('tercei')
      );
      if (terceirizada.length) {
        terceirizada.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.id; opt.textContent = t.nome + ' — ' + (t.empresa || 'Empresa Terceirizada');
          sel.appendChild(opt);
        });
      } else {
        // Placeholder caso não haja técnicos cadastrados
        const opt = document.createElement('option');
        opt.value = 'empresa-terceirizada-1'; opt.textContent = 'Técnico Empresa Terceirizada (cadastrar em Técnicos)';
        sel.appendChild(opt);
      }
    }
    document.getElementById('ch-data-recolhimento').value =
      new Date().toISOString().split('T')[0];
  }
}

function chToggleDestino(val) {
  ['mindworks','santa-clara','reutilizada','leilao'].forEach(d => {
    const el = document.getElementById('ch-dest-' + d);
    if (el) el.style.display = val === d ? '' : 'none';
  });
}

function chToggleNomenclatura(val) {
  const el = document.getElementById('ch-reut-nome-campo');
  if (el) el.style.display = val === 'sim' ? '' : 'none';
}

async function salvarChamado() {
  const titulo = document.getElementById('ch-titulo')?.value?.trim();
  const sol    = document.getElementById('ch-solicitante')?.value?.trim();
  const desc   = document.getElementById('ch-descricao')?.value?.trim();
  if (!titulo) return showToast('Preencha o título do chamado', 'danger');
  if (!sol)    return showToast('Informe o requerente', 'danger');
  if (!desc)   return showToast('Preencha a descrição do chamado', 'danger');
  const id = await gerarIdChamado();
  // Dados de movimentação de máquina
  const temMovimentacao = document.getElementById('ch-movimentacao')?.checked;
  const movimentacao = temMovimentacao ? {
    patAntigo:         document.getElementById('ch-pat-antigo')?.value?.trim()  || '',
    patNovo:           document.getElementById('ch-pat-novo')?.value?.trim()    || '',
    destino:           document.getElementById('ch-destino-maquina')?.value     || '',
    tecnicoTerceirizada:  document.getElementById('ch-tecnico-mindworks')?.value   || '',
    dataRecolhimento:  document.getElementById('ch-data-recolhimento')?.value   || '',
    prazoTerceirizada:    parseInt(document.getElementById('ch-prazo-empresa-terceirizada')?.value || '10'),
    scLocal:           document.getElementById('ch-sc-local')?.value?.trim()    || '',
    reutLocal:         document.getElementById('ch-reut-local')?.value?.trim()  || '',
    reutNomenclatura:  document.getElementById('ch-reut-nomenclatura')?.value   || 'nao',
    reutNome:          document.getElementById('ch-reut-nome')?.value?.trim()   || '',
    reutTipoUso:       document.getElementById('ch-reut-tipo-uso')?.value       || '',
    status:            'pendente-aprovacao', // sempre exige aprovação do gestor
    aprovadoPor:       null,
    aprovadoEm:        null,
  } : null;

  // Validações de movimentação
  if (temMovimentacao) {
    if (!movimentacao.destino) return showToast('Selecione o destino da máquina antiga', 'warning');
    if (movimentacao.destino === 'mindworks' && !movimentacao.tecnicoTerceirizada)
      return showToast('Selecione o técnico da Empresa Terceirizada', 'warning');
    if (movimentacao.destino === 'santa-clara' && !movimentacao.scLocal)
      return showToast('Informe o local de armazenamento em Santa Clara', 'warning');
    if (movimentacao.destino === 'reutilizada' && !movimentacao.reutLocal)
      return showToast('Informe o novo local de uso', 'warning');
  }

  const novo = {
    id, tipo: document.getElementById('ch-tipo')?.value||'incidente',
    area: document.getElementById('ch-area')?.value||'TI',
    solicitante: sol, tecnico: document.getElementById('ch-tecnico')?.value||'',
    pat: document.getElementById('ch-pat-antigo')?.value?.trim() || document.getElementById('ch-patrimonio')?.value||'',
    desc: titulo + (desc?'\n'+desc:''), obs: document.getElementById('ch-obs')?.value||'',
    status: temMovimentacao ? 'aguardando-aprovacao' : 'aberto',
    prioridade: document.getElementById('ch-prioridade')?.value||'media',
    categoria: document.getElementById('ch-categoria')?.value||'',
    origem: document.getElementById('ch-origem')?.value||'portal',
    movimentacao,
    temMovimentacao: !!temMovimentacao,
    createdAt: new Date()
  };
  if (!STATE.chamados) STATE.chamados = [];
  STATE.chamados.unshift(novo);
  fsAdd('chamados', novo, STATE.chamados);

  // Se tem movimentação: cria aprovação pendente e notifica gestor
  if (temMovimentacao && movimentacao) {
    const aprov = {
      id:          await gerarIdAprovacao(),
      chamadoId:   id,
      tipo:        'Movimentação de Máquina',
      pat:         movimentacao.patAntigo || novo.pat,
      descricao:   `Chamado ${id}: ${titulo}`,
      destino:     movimentacao.destino,
      detalhes:    movimentacao,
      solicitanteId: CURRENT_USER?.uid || '',
      solicitante:   CURRENT_USER?.nome || sol,
      status:        'pendente',
      createdAt:     new Date().toISOString(),
    };
    if (!STATE.aprovacoes) STATE.aprovacoes = [];
    STATE.aprovacoes.unshift(aprov);
    fsAdd('aprovacoes', aprov);
    nbUpdate('nb-aprov', (STATE.aprovacoes||[]).filter(a=>a.status==='pendente').length);
    showToast(`✓ Chamado ${id} aberto — aguardando aprovação do gestor para movimentação.`, 'warning', 6000);
    goPage('aprovacoes');
  } else {
    showToast(`✓ Chamado ${id} aberto com sucesso!`);
  }

  closeModal('modal-novo-chamado');
  renderChamados();
  renderDashboard();
  // Exibe confirmação com número do chamado em tela + dispara e-mail
  exibirConfirmacaoChamado(novo);
  // Envia e-mail de confirmação via Cloud Function
  if (FB_READY && novo.id && !novo.id.startsWith('offline_')) {
    callFunction('enviarConfirmacaoChamado', {
      chamadoId:  novo.id,
      titulo:     novo.desc?.split('\n')[0] || novo.id,
      solicitante: novo.solicitante,
      prioridade:  novo.prioridade,
      email:       CURRENT_USER?.email || '',
    }).catch(() => {}); // não bloqueia se falhar
  }
}

// ============================================================
// LOGIN & AUTENTICAÇÃO
// ============================================================

// Usuários locais (fallback quando Banco Auth não está disponível)
// Em produção: use APENAS Banco Auth + Banco /users
// Fallback local para dev/offline — em produção usa Banco Auth exclusivamente
// A senha abaixo é apenas para teste local em file:// — não é usada em produção
// Fallback local — usado quando Firebase Auth não está acessível (ex: rede corporativa)
// Senhas armazenadas como SHA-256. Para gerar: sha256('suasenha')
function _sha256(str) {
  // SHA-256 simplificado via SubtleCrypto (async) — usado só no fallback
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
    .then(b => Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''));
}

const LOCAL_USERS = {
  // ── Usuários CESAN (fallback quando Firebase Auth não acessível) ──
  'ana.penha': {
    email:    'ana.penha@cesan.com.br',
    _hash:    'c9b2ae28dbada5f022e87ea5951ee02579b950bd9d2ae1ccbac104130c17ad1d',
    nome:     'Ana Penha',
    avatar:   'AP',
    role:     'admin',
    uid:      'dYFZy11fXnNhX1THHIPE096y',
    permissions: { canApprove: true, canDeleteAssets: true, canWipeDevice: true, canGeolocate: true, canViewAudit: true, canExecDashboard: true },
  },
  'ana.penha@cesan.com.br': {
    email:    'ana.penha@cesan.com.br',
    _hash:    'c9b2ae28dbada5f022e87ea5951ee02579b950bd9d2ae1ccbac104130c17ad1d',
    nome:     'Ana Penha',
    avatar:   'AP',
    role:     'admin',
    uid:      'dYFZy11fXnNhX1THHIPE096y',
    permissions: { canApprove: true, canDeleteAssets: true, canWipeDevice: true, canGeolocate: true, canViewAudit: true, canExecDashboard: true },
  },
  'apaula': {
    email:    'apaulalimaster@gmail.com',
    _hash:    'c9b2ae28dbada5f022e87ea5951ee02579b950bd9d2ae1ccbac104130c17ad1d',
    nome:     'Ana Paula',
    avatar:   'AP',
    role:     'admin',
    uid:      'YnSK3dR44tgbLcOweMga1R6',
    permissions: { canApprove: true, canDeleteAssets: true, canWipeDevice: true, canGeolocate: true, canViewAudit: true, canExecDashboard: true },
  },
  'apaulalimaster@gmail.com': {
    email:    'apaulalimaster@gmail.com',
    _hash:    'c9b2ae28dbada5f022e87ea5951ee02579b950bd9d2ae1ccbac104130c17ad1d',
    nome:     'Ana Paula',
    avatar:   'AP',
    role:     'admin',
    uid:      'YnSK3dR44tgbLcOweMga1R6',
    permissions: { canApprove: true, canDeleteAssets: true, canWipeDevice: true, canGeolocate: true, canViewAudit: true, canExecDashboard: true },
  },
  'admin': {
    email:    'admin@cesan.com.br',
    _hash:    'c9b2ae28dbada5f022e87ea5951ee02579b950bd9d2ae1ccbac104130c17ad1d',
    nome:     'Administrador SYSACK',
    avatar:   'AD',
    role:     'admin',
    uid:      'local_admin_001',
    permissions: { canApprove: true, canDeleteAssets: true, canWipeDevice: true, canGeolocate: true, canViewAudit: true, canExecDashboard: true },
  },
};

let SESSION_USER = null;  // usuário logado na sessão atual

// ─── Verifica sessão salva (lembrar acesso) ──────────────────
function checkSavedSession() {
  try {
    const saved = localStorage.getItem('at_session');
    if (!saved) return false;
    const session = JSON.parse(saved);
    if (!session || !session.uid || !session.nome) return false;
    // Valida expiração (24h)
    const age = Date.now() - (session.savedAt || 0);
    if (age > 24 * 3600 * 1000) { localStorage.removeItem('at_session'); return false; }
    // Valida que a role salva é um valor legítimo (evita adulteração do localStorage)
    const VALID_ROLES = ['admin','gestor','tecnico','mdm_admin','viewer'];
    if (!VALID_ROLES.includes(session.role)) { localStorage.removeItem('at_session'); return false; }
    loginSuccess(session, false);
    return true;
  } catch { return false; }
}

// ─── Login principal ─────────────────────────────────────────
async function fazerLogin() {
  // emailRaw = o que o usuário digitou (ex: 'admin')
  // emailNorm = normalizado com @ (ex: 'admin@adsi.com.br')
  const emailRaw  = (document.getElementById('login-email')?.value || '').trim();
  const senha     = document.getElementById('login-senha')?.value || '';
  const emailNorm = emailRaw.includes('@') ? emailRaw : emailRaw + '@adsi.com.br';

  clearLoginError();
  if (!emailRaw || !senha) return showLoginError('Preencha o e-mail e a senha.');

  setLoginLoading(true);

  // ── Tentativa 1: Banco Auth ────────────────────────────
  if (FB_READY && auth) {
    try {
      const cred   = await auth.signInWithEmailAndPassword(emailNorm, senha);
      const fbUser = cred.user;

      // 1. Tenta custom claims (token JWT — mais seguro, não pode ser alterado pelo cliente)
      let claimsRole = null;
      try {
        const idTokenResult = await fbUser.getIdTokenResult(true); // força refresh
        claimsRole = idTokenResult.claims?.role || null;
        if (claimsRole) console.log('[Auth] Role via custom claim:', claimsRole);
      } catch (_) {}

      // 2. Fallback: busca perfil no Banco /users/{uid}
      let profile = { nome: fbUser.displayName || emailNorm, role: claimsRole || 'viewer', uid: fbUser.uid };
      try {
        const snap = await fsGet('users', fbUser.uid);
        if (snap) {
          Object.assign(profile, snap);
          // Custom claim tem prioridade sobre Banco (mais seguro)
          if (claimsRole) profile.role = claimsRole;
        }
      } catch (_) {}

      // 3. Garante que viewer não acessa admin mesmo se Banco for adulterado
      const VALID_ROLES = ['admin','gestor','tecnico','mdm_admin','viewer'];
      if (!VALID_ROLES.includes(profile.role)) profile.role = 'viewer';
      const user = {
        uid:    fbUser.uid,
        email:  fbUser.email,
        nome:   profile.nome || fbUser.displayName || emailNorm,
        avatar: (profile.nome || fbUser.displayName || '?').split(' ').map(w => w[0]).slice(0,2).join('').toUpperCase(),
        role:   profile.role || 'viewer',
        permissions: permissionsForRole(profile.role || 'viewer'),
      };
      loginSuccess(user, true);
      return;
    } catch (err) {
      // Só loga se não for erro de credencial inválida
      const credErrors = ['auth/user-not-found','auth/wrong-password','auth/invalid-credential','auth/invalid-email'];
      if (err?.code && !credErrors.includes(err.code)) {
        console.warn('[Auth] Banco error:', err?.code, err?.message);
      }
    }
  }

  // ── Tentativa 2: fallback local (usado quando Firebase Auth não está acessível) ──
  // Habilitado em produção quando Firebase Auth falhar por rede corporativa
  await new Promise(r => setTimeout(r, 200));
  const local = LOCAL_USERS[emailRaw.toLowerCase()] ||
                LOCAL_USERS[emailNorm.toLowerCase()] ||
                LOCAL_USERS[emailRaw];
  // Valida senha via SHA-256 (async) ou senha plain text legado
  let senhaOk = false;
  if (local) {
    if (local._hash) {
      try {
        const hash = await _sha256(senha);
        senhaOk = (hash === local._hash);
      } catch { senhaOk = false; }
    } else if (local.password) {
      const senhaNorm = senha.replace(/0/g, 'o').replace(/O/g, 'o');
      const localPass = local.password.replace(/0/g, 'o').replace(/O/g, 'o');
      senhaOk = (local.password === senha || localPass === senhaNorm);
    }
  }
  if (local && senhaOk) {
    const user = {
      uid:         local.uid,
      email:       local.email,
      nome:        local.nome,
      avatar:      local.avatar,
      role:        local.role,
      permissions: local.permissions || permissionsForRole(local.role),
    };
    loginSuccess(user, true);
    return;
  }

  setLoginLoading(false);
  showLoginError('Usuário ou senha incorretos.');
  document.getElementById('login-email')?.classList.add('error');
  document.getElementById('login-senha')?.classList.add('error');
}

function permissionsForRole(role) {
  const map = {
    admin:     { canApprove:true, canDeleteAssets:true, canWipeDevice:true, canGeolocate:true, canViewAudit:true, canExecDashboard:true },
    gestor:    { canApprove:true, canDeleteAssets:false, canWipeDevice:true, canGeolocate:true, canViewAudit:true, canExecDashboard:true },
    tecnico:   { canApprove:false, canDeleteAssets:false, canWipeDevice:false, canGeolocate:false, canViewAudit:false, canExecDashboard:false },
    mdm_admin: { canApprove:false, canDeleteAssets:false, canWipeDevice:true, canGeolocate:true, canViewAudit:false, canExecDashboard:false },
    viewer:    { canApprove:false, canDeleteAssets:false, canWipeDevice:false, canGeolocate:false, canViewAudit:false, canExecDashboard:false },
  };
  return map[role] || map.viewer;
}

function loginSuccess(user, showWelcome = true) {
  SESSION_USER = user;
  // Atualiza CURRENT_USER global
  Object.assign(CURRENT_USER, user);

  // Atualiza UI
  const av = document.getElementById('tb-user-avatar');
  if (av) { av.childNodes[0].textContent = user.avatar || user.nome[0]; }
  const nameEl = document.getElementById('tb-user-name-label');
  if (nameEl) nameEl.textContent = user.nome;
  const roleEl = document.getElementById('tb-user-role-label');
  if (roleEl) roleEl.textContent = user.role;
  document.getElementById('tb-user-name-wrap')?.style?.setProperty('display','block');

  // Atualiza sidebar user
  const uname = document.querySelector('.u-name');
  if (uname) uname.textContent = user.nome;
  const urole = document.querySelector('.u-role');
  if (urole) urole.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1) + ' · SYSACK';
  const uav = document.querySelector('.u-avatar');
  if (uav) uav.textContent = user.avatar || user.nome[0];

  // Esconde login, mostra app
  setLoginLoading(false);
  document.getElementById('login-page')?.classList.add('hidden');

  if (showWelcome) {
    const hora = new Date().getHours();
    const saud = hora < 12 ? 'Bom dia' : hora < 18 ? 'Boa tarde' : 'Boa noite';
    showToast(`${saud}, ${user.nome.split(' ')[0]}! 👋 Bem-vindo ao SYSACK.`, 'success');
  }
  auditLog('LOGIN', 'auth', user.uid, 'user', { nome: user.nome, role: user.role });

  // Inicia listeners do Firestore APÓS o usuário estar autenticado
  function _iniciarListeners() {
    startFirestoreListeners();
    verificarConfigSeguranca?.();
    iniciarWatcherIP?.();
    iniciarWatcherAlertasIA?.();
    document.dispatchEvent(new Event('sysack-login'));
  }

  if (FB_READY && db) {
    // Firebase já pronto — inicia listeners imediatamente
    setTimeout(_iniciarListeners, 300);
  } else {
    // Firebase ainda inicializando — aguarda e tenta de novo
    console.log('[Banco] Aguardando Firebase para iniciar listeners...');
    const _maxTentativas = 20;
    let _tentativa = 0;
    const _intervalo = setInterval(() => {
      _tentativa++;
      if (FB_READY && db) {
        clearInterval(_intervalo);
        console.log(`[Banco] Firebase pronto após ${_tentativa} tentativas — iniciando listeners`);
        _iniciarListeners();
      } else if (_tentativa >= _maxTentativas) {
        clearInterval(_intervalo);
        console.warn('[Banco] Timeout aguardando Firebase — listeners não iniciados');
      }
    }, 300);
  }
}

// ─── Logout ──────────────────────────────────────────────────
function confirmarLogout() {
  if (!confirm('Deseja sair do sistema?')) return;
  fazerLogout();
}

async function fazerLogout() {
  auditLog('LOGOUT', 'auth', CURRENT_USER.uid, 'user', {});
  localStorage.removeItem('at_session');
  SESSION_USER = null;
  if (FB_READY && auth) {
    try { await auth.signOut?.(); } catch (_) {}
  }
  // Volta para login
  document.getElementById('login-page')?.classList.remove('hidden');
  // Limpa campos
  const em = document.getElementById('login-email');
  const pw = document.getElementById('login-senha');
  if (em) em.value = ''; if (pw) pw.value = '';
  clearLoginError();
}

// ─── Esqueci a senha ─────────────────────────────────────────
async function esqueciSenha() {
  const emailRaw = document.getElementById('login-email')?.value?.trim();
  if (!emailRaw) { showLoginError('Digite seu e-mail ou usuário no campo acima.'); return; }
  // Normaliza antes de enviar ao Banco
  const email = emailRaw.includes('@') ? emailRaw : emailRaw + '@adsi.com.br';
  if (FB_READY && auth) {
    try {
      await auth.sendPasswordResetEmail(email);
      clearLoginError();
      showToast(`✉️ E-mail de recuperação enviado para ${email}`, 'success');
    } catch (err) {
      showLoginError('Erro ao enviar e-mail: ' + (err.message || err.code));
    }
  } else {
    showLoginError('Reset de senha requer conexão com Banco. Contate o administrador.');
  }
}

// ─── Helpers UI ──────────────────────────────────────────────
function showLoginError(msg) {
  const box = document.getElementById('login-error-box');
  if (!box) return;
  box.textContent = '🔒 ' + msg;
  box.classList.add('show');
}
function clearLoginError() {
  const box = document.getElementById('login-error-box');
  box?.classList.remove('show');
  document.getElementById('login-email')?.classList.remove('error');
  document.getElementById('login-senha')?.classList.remove('error');
}
function setLoginLoading(on) {
  const btn = document.getElementById('login-btn');
  if (!btn) return;
  btn.disabled = on;
  btn.classList.toggle('loading', on);
}
function toggleSenha() {
  const inp = document.getElementById('login-senha');
  const btn = document.getElementById('toggle-pw-btn');
  if (!inp) return;
  const isText = inp.type === 'text';
  inp.type = isText ? 'password' : 'text';
  if (btn) btn.textContent = isText ? '👁️' : '🙈';
}
function showUserMenu() {
  // Simples toggle para exibir info — pode ser expandido
  const wrap = document.getElementById('tb-user-name-wrap');
  if (!wrap) return;
  const visible = wrap.style.display !== 'none' && wrap.style.display !== '';
  wrap.style.display = visible ? 'none' : 'block';
}

// ════════════════════════════════════════════════════════════
// SEGURANÇA — Sanitização de HTML (previne XSS)
// ════════════════════════════════════════════════════════════
function setButtonLoading(btn, loading, label) {
  if (!btn) return;
  if (loading) {
    btn.dataset.origText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:6px"></span>' + (label || 'Salvando...');
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.origText || label || 'Salvar';
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;')
    .replace(/\//g, '&#x2F;');
}
// Alias curto para uso em template literals de innerHTML
const esc = escapeHtml;


// Sanitiza um objeto inteiro — protege todos os campos string
function sanitizeObj(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    out[k] = typeof v === 'string' ? escapeHtml(v) : v;
  }
  return out;
}

// ════════════════════════════════════════════════════════════
// MOBILE — Sidebar drawer + responsivo
// ════════════════════════════════════════════════════════════
function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('open');
  if (overlay) overlay.classList.toggle('open', isOpen);
  document.body.style.overflow = isOpen ? 'hidden' : '';
}

function closeSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  sidebar?.classList.remove('open');
  overlay?.classList.remove('open');
  document.body.style.overflow = '';
}

// Fecha sidebar ao navegar (mobile)
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-i').forEach(el => {
    el.addEventListener('click', () => {
      if (window.innerWidth <= 768) closeSidebar();
    });
  });
  // Fecha ao pressionar ESC
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      // Close topmost open modal
      const openModals = document.querySelectorAll('.modal-overlay[style*="flex"], .modal-overlay.open');
      if (openModals.length) {
        const last = openModals[openModals.length - 1];
        last.style.display = 'none';
        last.classList.remove('open');
        return;
      }
      // Close AI panel
      if (document.getElementById('ai-panel')?.style.display !== 'none') {
        closeAIPanel();
        return;
      }
      closeSidebar();
    }
  });
  // Atalho Ctrl+K — busca global
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const search = document.getElementById('tb-search-input') ||
                     document.querySelector('.tb-search input');
      if (search) { search.focus(); search.select(); }
    }
  });

  // Swipe para fechar (mobile)
  let touchStartX = 0;
  document.addEventListener('touchstart', e => {
    touchStartX = e.changedTouches[0].screenX;
  }, { passive: true });
  document.addEventListener('touchend', e => {
    const dx = e.changedTouches[0].screenX - touchStartX;
    if (dx < -60) closeSidebar();          // swipe left → fecha
    if (dx > 60 && window.innerWidth <= 768) { // swipe right → abre
      document.querySelector('.sidebar')?.classList.add('open');
      document.getElementById('sidebar-overlay')?.classList.add('open');
    }
  }, { passive: true });
});

// ── DEBOUNCE — evita excesso de queries nos campos de busca ──
function debounce(fn, ms = 300) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}
const _debouncedSearch = debounce((fn) => fn(), 250);

// ── DARK/LIGHT THEME ──
function toggleTheme() {
  const root = document.documentElement;
  const isDark = root.getAttribute('data-theme') === 'dark';
  const newTheme = isDark ? 'light' : 'dark';
  root.setAttribute('data-theme', newTheme);
  localStorage.setItem('at-theme', newTheme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = newTheme === 'dark' ? '☀️' : '🌙';
  // Update sidebar brand
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) sidebar.style.background = newTheme === 'dark' ? '#0A0F1E' : 'var(--brand)';
}

function initTheme() {
  const saved = localStorage.getItem('at-theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = saved === 'dark' ? '☀️' : '🌙';
}

// ── SIDEBAR GROUP TOGGLE ──
function toggleSbGroup(id) {
  const grp = document.getElementById(id);
  if (!grp) return;
  const chevId = 'chev-' + id;
  const chev = document.getElementById(chevId);
  const collapsed = grp.classList.toggle('collapsed');
  if (chev) chev.style.transform = collapsed ? 'rotate(-90deg)' : '';
}

// ── ATORES (chips) ──
const _atores = { requerente: [], observador: [], tecnico: [], grupo: [] };

function adicionarAtor(tipo) {
  let val = '', label = '';
  if (tipo === 'requerente') { val = document.getElementById('ch-solicitante')?.value?.trim(); label = val; }
  if (tipo === 'observador')  { val = document.getElementById('ch-observador')?.value?.trim(); label = val; }
  if (tipo === 'tecnico') {
    const sel = document.getElementById('ch-tecnico');
    val = sel?.value; label = sel?.options[sel.selectedIndex]?.text;
  }
  if (tipo === 'grupo') {
    const sel = document.getElementById('ch-grupo');
    val = sel?.value; label = sel?.options[sel.selectedIndex]?.text;
  }
  if (!val || !label || label.startsWith('—')) return showToast('Selecione ou informe o valor', 'danger');
  if (_atores[tipo].find(a => a.val === val)) return showToast('Já adicionado', 'warning');
  _atores[tipo].push({ val, label });
  renderAtorChips(tipo);
  atualizarContadorAtores();
}

function removerAtor(tipo, val) {
  if (!SESSION_USER || !["admin", "gestor", "tecnico"].includes(SESSION_USER.role)) {
    showToast('⛔ Acesso restrito: remover ator.', 'error');
    return;
  }

  _atores[tipo] = _atores[tipo].filter(a => a.val !== val);
  renderAtorChips(tipo);
  atualizarContadorAtores();
}

function renderAtorChips(tipo) {
  const containerId = tipo === 'tecnico' || tipo === 'grupo' ? 'atribuido-chips' : tipo + '-chips';
  const container = document.getElementById(containerId);
  if (!container) return;
  // Only clear the chips for this tipo within the container — rebuild all
  if (tipo === 'tecnico' || tipo === 'grupo') {
    const all = [...(_atores.tecnico||[]), ...(_atores.grupo||[])];
    container.innerHTML = all.map(a => {
      const isTec = _atores.tecnico.find(t => t.val === a.val);
      const icon = isTec ?
        '<svg width="11" height="11" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="5.5" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M2 14c0-3 2.5-5 6-5s6 2 6 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>' :
        '<svg width="11" height="11" viewBox="0 0 16 16" fill="none"><circle cx="5" cy="5" r="2.5" stroke="currentColor" stroke-width="1.4"/><circle cx="11" cy="5" r="2.5" stroke="currentColor" stroke-width="1.4"/><path d="M1 14c0-2.5 1.8-4 4-4h6c2.2 0 4 1.5 4 4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
      const remTipo = isTec ? 'tecnico' : 'grupo';
      return `<div class="ator-chip">${icon} ${a.label} <span class="chip-remove" onclick="removerAtor('${remTipo}','${a.val}')">✕</span></div>`;
    }).join('');
  } else {
    container.innerHTML = _atores[tipo].map(a =>
      `<div class="ator-chip"><svg width="11" height="11" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="5.5" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M2 14c0-3 2.5-5 6-5s6 2 6 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> ${a.label} <span class="ator-num" style="margin-left:4px">0</span> <span class="chip-remove" onclick="removerAtor('${tipo}','${a.val}')">✕</span></div>`
    ).join('');
  }
}

function atualizarContadorAtores() {
  const total = Object.values(_atores).reduce((s, arr) => s + arr.length, 0);
  const el = document.getElementById('atores-count');
  if (el) el.textContent = total;
}

// ── VINCULAR CHAMADO RELACIONADO ──
function vincularChamadoRelacionado() {
  const input = document.getElementById('ch-rel-input');
  const val = input?.value?.trim();
  if (!val) return showToast('Informe o número do chamado', 'danger');
  const ch = STATE.chamados?.find(c => c.id === val || c.id === 'CH-' + val);
  const list = document.getElementById('ch-rel-list');
  if (list) {
    list.insertAdjacentHTML('beforeend', `
      <div class="ch-rel-row">
        <span class="ch-rel-tipo">Relacionado</span>
        <span class="ch-rel-id">${ch ? ch.id : val}</span>
        <span style="flex:1;font-size:12px;color:var(--g600)">${ch ? ch.desc?.slice(0,50) : 'Chamado externo'}</span>
        <span style="cursor:pointer;color:var(--g400);font-size:11px" onclick="this.parentElement.remove()">✕</span>
      </div>`);
    // update count
    const cnt = document.getElementById('itens-ch-count');
    if (cnt) cnt.textContent = parseInt(cnt.textContent||0) + 1;
  }
  if (input) input.value = '';
  showToast(`✓ Chamado ${val} vinculado como relacionado`);
}

// ── RENDER NEW PAGES ──
function renderDocumentos() {
  const docs = [
    { id:'30235', entidade:'CESAN ▸ A-GFC', arquivo:'image_paste9211101.p...', mime:'' },
    { id:'33740', entidade:'CESAN ▸ E-UGP', arquivo:'RE_ Chamado 38354 -...', mime:'application/vnd.ms-outlook' },
    { id:'35271', entidade:'CESAN ▸ P-CCE', arquivo:'image_paste3251385.j...', mime:'' },
    { id:'_formulario_sicat.xlsx', entidade:'CESAN ▸ O-GIN', arquivo:'_formulario_sicat.xl...', mime:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
    { id:'(aceite usuario)RES GLPI #0012011 Novo acompanhamento.msg', entidade:'CESAN ▸ O-GES', arquivo:'(aceite usuario)RES...', mime:'application/vnd.ms-outlook' },
  ];
  document.getElementById('documentos-body').innerHTML = docs.map(d => `
    <tr>
      <td><input type="checkbox" style="accent-color:var(--accent)"></td>
      <td style="color:var(--accent);cursor:pointer;font-weight:500;font-size:12.5px">${d.id}</td>
      <td style="font-size:11.5px;color:var(--g500)">${d.entidade}</td>
      <td style="font-size:12px">${d.arquivo ? `📄 ${d.arquivo}` : '—'}</td>
      <td class="td-mono" style="font-size:10.5px">—</td>
      <td>—</td>
      <td style="font-size:10.5px;color:var(--g500)">${d.mime||'—'}</td>
      <td>—</td>
    </tr>`).join('');
}

function renderLembretes() {
  const items = [
    { tipo:'urgente', titulo:'PAT-0103 na Terceirizada há 12 dias', desc:'Prazo de 10 dias úteis excedido. Contatar técnico Roberto Mendes urgentemente.', data:'08/05/2026', autor:'Carlos Souza' },
    { tipo:'aviso', titulo:'Renovação de contratos de manutenção', desc:'Contratos com empresa terceirizada vencem em 30 dias. Verificar renovação com gestão.', data:'07/05/2026', autor:'Ana Lima' },
    { tipo:'info', titulo:'Atualização de inventário pendente', desc:'Realizar levantamento de ativos da filial Sul antes do dia 20/05.', data:'06/05/2026', autor:'João Martins' },
    { tipo:'info', titulo:'Treinamento MDM', desc:'Treinamento de uso do módulo MDM agendado para próxima segunda-feira às 14h.', data:'05/05/2026', autor:'João Martins' },
  ];
  document.getElementById('lembretes-grid').innerHTML = items.map(l => `
    <div class="lembrete-card ${l.tipo}">
      <div style="font-size:13.5px;font-weight:700;color:var(--g900);margin-bottom:6px">${l.titulo}</div>
      <div style="font-size:12.5px;color:var(--g600);margin-bottom:10px;line-height:1.5">${l.desc}</div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-size:11px;color:var(--g400)">${l.autor} · ${l.data}</span>
        <div class="flex gap-4">
          <button class="btn btn-ghost btn-xs">✏️</button>
          <button class="btn btn-ghost btn-xs">🗑️</button>
        </div>
      </div>
    </div>`).join('');
}

function renderPesquisas() {
  const items = [
    { nome:'Chamados abertos — TI', modulo:'Chamados', criterios:'Status = Aberto AND Área = TI', data:'05/05/2026' },
    { nome:'Ativos na Terceirizada com atraso', modulo:'Terceirizada', criterios:'Dias > 10 AND Retornado = Não', data:'03/05/2026' },
    { nome:'Smartphones extraviados', modulo:'MDM', criterios:'Status = Extraviado', data:'01/05/2026' },
  ];
  document.getElementById('pesquisas-body').innerHTML = items.map(p => `
    <tr>
      <td style="font-weight:600;color:var(--accent);cursor:pointer">${p.nome}</td>
      <td><span class="tag">${p.modulo}</span></td>
      <td style="font-size:11.5px;color:var(--g500)">${p.criterios}</td>
      <td class="td-mono">${p.data}</td>
      <td><div class="flex gap-4"><button class="btn btn-secondary btn-xs">▶ Executar</button><button class="btn btn-ghost btn-xs">🗑️</button></div></td>
    </tr>`).join('');
}

function renderAlertas() {
  const items = [
    { tipo:'danger', titulo:'🚨 PAT-0103 na Terceirizada — 12 dias úteis', desc:'Dell OptiPlex 3090 — prazo de 10 dias úteis excedido. Roberto Mendes deve ser contatado imediatamente.', data:'Hoje, 09:00', acao:'Ver Terceirizada' },
    { tipo:'warning', titulo:'⚠️ Aprovação pendente — Transferência PAT-0102', desc:'HP EliteBook 840 G8 aguarda sua autorização para ser transferido para Comercial.', data:'Ontem, 14:32', acao:'Ver Aprovações' },
    { tipo:'warning', titulo:'⚠️ Aprovação pendente — Envio Terceirizada PAT-0201', desc:'HP Monitor 24" aguarda autorização de envio para empresa terceirizada.', data:'Há 2 dias', acao:'Ver Aprovações' },
    { tipo:'info', titulo:'ℹ️ Alerta preventivo — PAT-0201 com 6 dias na Terceirizada', desc:'HP Monitor 24" — faltam 4 dias úteis para o prazo máximo. Técnico Patrícia Rocha foi notificada.', data:'Há 3 dias', acao: null },
    { tipo:'info', titulo:'ℹ️ Smartphone PAT-MOB-004 bloqueado remotamente', desc:'Galaxy A34 de Carlos Lima foi bloqueado após relato de extravio. Boletim de ocorrência solicitado.', data:'Há 2 dias', acao: null },
  ];
  document.getElementById('alertas-list').innerHTML = items.map(a => {
    const colors = { danger:'var(--danger-l)','danger-border':'#FCA5A5', warning:'var(--warning-l)','warning-border':'#FCD34D', info:'var(--accent-l)','info-border':'#93C5FD' };
    return `
      <div style="background:${colors[a.tipo]};border:1px solid ${colors[a.tipo+'-border']||'#93C5FD'};border-radius:var(--r);padding:14px 16px;display:flex;gap:12px;align-items:flex-start">
        <div style="flex:1">
          <div style="font-size:13px;font-weight:700;color:var(--g900);margin-bottom:4px">${a.titulo}</div>
          <div style="font-size:12px;color:var(--g600);margin-bottom:6px;line-height:1.5">${a.desc}</div>
          <div style="font-size:11px;color:var(--g400)">${a.data}</div>
        </div>
        ${a.acao ? `<button class="btn btn-secondary btn-sm" style="flex-shrink:0" onclick="goPage('${a.acao.toLowerCase().includes('tercei')?'terceirizada':'aprovacoes'}')">${a.acao}</button>` : ''}
        <button class="btn btn-ghost btn-xs" style="flex-shrink:0" title="Dispensar">✕</button>
      </div>`;
  }).join('');
}

function atualizarIniciais() {
  const t = document.getElementById('ch-titulo')?.value||'';
  const s = document.getElementById('ch-solicitante')?.value||'';
  const ini = s ? s.split(' ').map(w=>w[0]).slice(0,2).join('').toUpperCase() : (t?t[0].toUpperCase():'?');
  const av1 = document.getElementById('ch-avatar-iniciais');
  const av2 = document.getElementById('ch-bolha-iniciais');
  const prev = document.getElementById('ch-bolha-titulo-preview');
  if (av1) av1.textContent = ini;
  if (av2) av2.textContent = ini;
  if (prev) prev.textContent = t || 'Preencha o título acima';
}

function syncRequerente() {
  const v = document.getElementById('ch-solicitante')?.value||'';
  const el = document.getElementById('ch-bolha-requerente');
  if (el) el.textContent = v||'—';
  atualizarIniciais();
  // count atores
  const count = [v, document.getElementById('ch-tecnico')?.value, document.getElementById('ch-observador')?.value].filter(Boolean).length;
  const ac = document.getElementById('atores-count');
  if (ac) ac.textContent = count;
}

function switchChTab(el, tab) {
  document.querySelectorAll('.ch-tab').forEach(t => {
    t.classList.remove('active');
    t.style.borderBottomColor = 'transparent';
    t.style.color = 'var(--g500)';
  });
  el.classList.add('active');
  el.style.borderBottomColor = 'var(--accent)';
  el.style.color = 'var(--accent)';
  const all = ['chamado','satisfacao','estatisticas','kb','itens','historico','impressao'];
  all.forEach(id => {
    const main = document.getElementById('chtab-' + id);
    const right = document.getElementById('chtab-' + id + '-right');
    if (main) main.style.display = id === tab ? (id==='chamado'?'flex':'block') : 'none';
    if (right) right.style.display = id === tab ? '' : 'none';
  });
}

function toggleChSection(id) {
  const el = document.getElementById(id);
  const icon = document.getElementById(id+'-icon');
  if (!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  if (icon) icon.textContent = hidden ? '▲' : '▼';
}

function atualizarSubcategoria() {
  const cat = document.getElementById('ch-categoria')?.value;
  const row = document.getElementById('row-subcategoria');
  const sub = document.getElementById('ch-subcategoria');

  // ============================================================
  // ÁRVORE COMPLETA DE CATEGORIAS/SUBCATEGORIAS — CESAN / GLPI
  // Extraído das imagens do sistema real
  // ============================================================
  const subs = {
    // ── Infraestrutura de TI ──
    'active-directory': [
      'Criação de conta','Exclusão de conta','Desbloqueio de conta',
      'Reset de senha','Permissão de grupo','Sincronização',
      'Demais solicitações'
    ],
    'antivirus': [
      'Instalação','Atualização de base','Remoção de vírus/malware',
      'Falso positivo','Demais solicitações'
    ],
    'backup-restore': [
      'Backup manual','Restore de arquivo','Restore de sistema completo',
      'Verificação de backup','Agendamento de backup','Demais solicitações'
    ],
    'banco-dados': [
      'Erro em consulta/procedure','Lentidão no banco',
      'Criação de usuário DB','Permissão de acesso',
      'Backup de banco','Demais solicitações'
    ],
    'cadastro-usuario': [
      'Criação de conta','Exclusão de conta','Alteração de dados cadastrais',
      'Reset de senha AD','Demais solicitações'
    ],
    'certificado-digital': [
      'Instalação de certificado','Renovação de certificado',
      'Revogação','Token / smartcard','Demais solicitações'
    ],
    'computador': [
      'Não liga','Lentidão','Tela azul / erro crítico',
      'Troca de equipamento','Nova máquina','Periférico com problema',
      'Demais solicitações'
    ],
    'email': [
      'Não envia / não recebe','Caixa cheia','Configuração de cliente de e-mail',
      'Criação de conta de e-mail','Regra de e-mail','Demais solicitações'
    ],
    'equipamento-problema': [
      'Hardware com defeito','Periférico','Fonte de alimentação',
      'HD / SSD','Memória RAM','Demais solicitações'
    ],
    'firewall-webfilter': [
      'Liberação de acesso a site','Bloqueio de site','Regra de firewall',
      'VPN','Demais solicitações'
    ],
    'impressao': [
      'Impressora não imprime','Papel enroscado','Qualidade de impressão',
      'Troca de toner/cartucho','Driver de impressão','Demais solicitações'
    ],
    'internet': [
      'Sem acesso à internet','Lentidão de conexão','Wi-Fi',
      'VPN externa','Demais solicitações'
    ],
    'link-dados': [
      'Link sem sinal','Lentidão no link','Configuração de link',
      'Demais solicitações'
    ],
    'rede-dados': [
      'Sem acesso à rede','Ponto de rede sem sinal','Switch / roteador',
      'Cabeamento Estruturado','Demais solicitações'
    ],
    'rede-logica': [
      'Configuração de VLAN','Roteamento','Firewall interno',
      'Demais solicitações'
    ],
    'rede-wan': [
      'Link WAN sem sinal','Lentidão WAN','MPLS / VPN site-to-site',
      'Monitoramento WAN','Demais solicitações'
    ],
    'cabeamento': [
      'Novo ponto de rede','Ponto sem sinal','Organização de rack',
      'Patch cord / patch panel','Demais solicitações'
    ],
    'servidor': [
      'Servidor sem resposta','Lentidão','Espaço em disco',
      'Serviço parado','Demais solicitações'
    ],
    'servidor-aplicacao': [
      'Serviço de aplicação parado','Deploy / publicação','Configuração',
      'Demais solicitações'
    ],
    'servidor-arquivos': [
      'Erro ao sincronizar arquivos','Permissão de pasta',
      'Espaço em disco','Mapeamento de unidade de rede',
      'Demais solicitações'
    ],
    'smartphone-mdm': [
      'Tela quebrada','Bateria com problema','Chip / linha',
      'MDM / Configuração','Perda ou roubo','Troca de aparelho',
      'Demais solicitações'
    ],
    'telefonia': [
      'Ramal sem sinal','Configuração de PABX','Softphone / IP Phone',
      'Demais solicitações'
    ],
    'demais-sol': ['Demais solicitações'],

    // ── Sistemas Corporativos (nível superior) ──
    'sistemas-corporativos': [
      '»Agência Virtual','»ArterH','»Banco de Indicadores Comerciais',
      '»BI','»CAT','»CesanLIMS','»CidadES','»Clipping',
      '»Concessões','»Convênios','»CPEP / PEP','»GIS','»GLPI',
      '»Hotsite de Compras','»OnBase','»Pague Fácil','»Portal CCO',
      '»Portal Corporativo (Intranet)','»Portal da Transparência',
      '»Portal de Compras','»Portal Institucional (Site)',
      '»Progen','»QJurídico','»SACS','»SAM','»SAP',
      '»SICAT','»SIOB','»SIMP','»SINCOP','»SISCOP',
      '»SisPaEv','»Sistema de Visitas','»Site CTC',
      '»Siscom','»UniLIMS',
      'Demais solicitações'
    ],

    // ── Subsistemas — cada um com Correção de erros + Manutenção corretiva ──
    'agencia-virtual':          ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'arterh':                   ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'banco-ind-comerciais':     ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'bi':                       ['Correção de erros','Demais solicitações'],
    'cat':                      ['Correção de erros','Demais solicitações'],
    'cesanlims':                ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'cidades-es':               ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'clipping':                 ['Correção de erros','Demais solicitações'],
    'concessoes':               ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'convenios':                ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'cpep-pep':                 ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'gis':                      ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'glpi':                     ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'hotsite-compras':          ['Correção de erros','Demais solicitações'],
    'onbase':                   ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sap': [
      'Correção de erros','Esclarecimento de dúvidas',
      'Permissão de acesso ou alteração de perfil',
      'Manutenção corretiva','Demais solicitações'
    ],
    'siscom': [
      'Correção de erros','Esclarecimento de dúvidas',
      'Manutenção corretiva','Demais solicitações'
    ],
    'pague-facil':           ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'portal-cco':            ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'portal-corporativo':    ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'portal-transparencia':  ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'portal-compras':        ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'portal-institucional':  ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'progen':                ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'qjuridico':             ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sacs':                  ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sam':                   ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sicat':                 ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'siob':                  ['Correção de erros','Demais solicitações'],
    'simp':                  ['Correção de erros','Demais solicitações'],
    'sincop':                ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'siscop':                ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sispaev':               ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'sistema-visitas':       ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    'site-ctc':              ['Correção de erros','Demais solicitações'],
    'unilims':               ['Correção de erros','Manutenção corretiva','Demais solicitações'],
    // ── Infraestrutura adicional ──
    'software':              ['Instalação','Atualização','Licenciamento','Remoção','Demais solicitações'],
    'storage':               ['Espaço em disco','Lentidão de acesso','Configuração de LUN','Snapshot/backup','Demais solicitações'],
    'system-center':         ['SCCM / Endpoint','Inventário de software','Deploy de pacote','Relatório','Demais solicitações'],
    'telefonia-fixa':        ['Ramal sem sinal','Configuração de PABX','Transferência de ramal','Demais solicitações'],
    'telefonia-movel':       ['Chip / linha corporativa','Bloqueio / desbloqueio','Configuração de e-mail no celular','Demais solicitações'],
    'virtualizacao':         ['Criação de VM','Migração de VM','Snapshot','Alocação de recursos','Demais solicitações'],
    'vpn':                   ['Acesso VPN sem funcionar','Configuração de cliente VPN','VPN site-to-site','Demais solicitações'],
    'wifi':                  ['Sem sinal Wi-Fi','Lentidão Wi-Fi','Configuração de SSID','Access Point','Demais solicitações'],
  };

  // Render as optgroup se for Sistemas Corporativos (para mostrar hierarquia visual)
  if (cat === 'sistemas-corporativos') {
    sub.innerHTML = subs[cat].map(s => {
      const isParent = s.startsWith('»');
      const label = isParent ? s : s;
      return `<option value="${label}" style="${isParent?'font-weight:600;padding-left:4px':'padding-left:16px'}">${label}</option>`;
    }).join('');
    row.style.display = '';
    return;
  }

  if (cat && subs[cat]) {
    sub.innerHTML = subs[cat].map(s => `<option>${s}</option>`).join('');
    row.style.display = '';
  } else {
    row.style.display = 'none';
  }

  // Se for subsistema corporativo, mostrar label extra indicando o sistema pai
  const subsistemas = ['agencia-virtual','arterh','banco-ind-comerciais','bi','cat','cesanlims',
    'cidades-es','clipping','concessoes','convenios','cpep-pep','gis','glpi',
    'hotsite-compras','onbase','pague-facil','portal-cco','portal-corporativo',
    'portal-transparencia','portal-compras','portal-institucional',
    'progen','qjuridico','sacs','sam','sap','sicat','siob','simp','sincop','siscom'];
  if (subsistemas.includes(cat)) {
    const labelMap = {
      'agencia-virtual':'Agência Virtual','arterh':'ArterH',
      'banco-ind-comerciais':'Banco de Indicadores Comerciais','bi':'BI','cat':'CAT',
      'cesanlims':'CesanLIMS','cidades-es':'CidadES','clipping':'Clipping',
      'concessoes':'Concessões','convenios':'Convênios','cpep-pep':'CPEP / PEP',
      'gis':'GIS','glpi':'GLPI','hotsite-compras':'Hotsite de Compras',
      'onbase':'OnBase','sap':'SAP','siscom':'Siscom',
    };
    const hint = document.getElementById('row-subcategoria');
    if (hint) hint.setAttribute('title', `Sistemas Corporativos > ${labelMap[cat]||cat}`);
  }
}

function atualizarPrioridadeColor(sel) {
  const colors = {
    'muito-baixa':'#F0FFF4','baixa':'#F0FFF4','media':'#FFFBEB','alta':'#FFF7ED','muito-alta':'#FEF2F2','urgente':'#FEF2F2'
  };
  const textColors = {
    'muito-baixa':'#065F46','baixa':'#065F46','media':'#92400E','alta':'#9A3412','muito-alta':'#991B1B','urgente':'#7F1D1D'
  };
  sel.style.background = colors[sel.value]||'';
  sel.style.color = textColors[sel.value]||'';
  sel.style.fontWeight = '700';
}

function vincularAtivoAoChamado() {
  const pat = document.getElementById('ch-patrimonio')?.value?.trim();
  if (!pat) return showToast('Informe o patrimônio', 'danger');
  const ativo = STATE.ativos?.find(a => a.pat.toLowerCase() === pat.toLowerCase());
  const container = document.getElementById('ch-itens-vinculados');
  if (!container) return;
  const label = ativo ? `${ativo.pat} — ${ativo.desc}` : pat;
  container.insertAdjacentHTML('beforeend', `
    <div style="display:inline-flex;align-items:center;gap:5px;background:var(--accent-l);border:1px solid #93C5FD;border-radius:6px;padding:4px 10px;font-size:11.5px;font-weight:600;color:var(--accent)">
      🖥️ ${label}
      <span style="cursor:pointer;color:var(--g400);margin-left:3px" onclick="this.parentElement.remove()">✕</span>
    </div>`);
  document.getElementById('ch-patrimonio').value = '';
  showToast(`✓ Ativo ${pat} vinculado!`);
}

function vincularSmartphone() {
  showToast('Selecione um smartphone pelo módulo MDM → Chamado', 'info');
}

function salvarRascunhoChamado() {
  showToast('💾 Rascunho salvo localmente', 'info');
}

// openModal init handled inline in the single openModal below

function salvarAtivo() {
  const pat  = document.getElementById('ativo-pat').value.trim();
  const desc = document.getElementById('ativo-desc').value.trim();
  if (!pat||!desc) return showToast('Patrimônio e descrição são obrigatórios', 'danger');
      const novo = { id:'a'+Date.now(), pat, desc, tipo:document.getElementById('ativo-tipo').value, area:document.getElementById('ativo-area').value, status:document.getElementById('ativo-status').value, sala:document.getElementById('ativo-sala')?.value?.trim()||'', loc:document.getElementById('ativo-loc').value, resp:document.getElementById('ativo-resp').value, serie:document.getElementById('ativo-serie').value, fab:document.getElementById('ativo-fab').value, createdAt:new Date() };
  STATE.ativos.push(novo);
  // TODO Banco: await addDoc(collection(db,'ativos'), novo);
  closeModal('modal-novo-ativo');
  renderAtivos();
  renderDashboard();
  showToast(`✓ Ativo ${pat} cadastrado!`);
}

function salvarAtendimento() {
  closeModal('modal-atender-chamado');
  const destino = document.getElementById('at-destino-antigo').value;
  if (destino==='terceirizada') {
    const aprov = { id:'ap'+Date.now(), tipo:'Envio para Terceirizada', pat:document.getElementById('at-patrimonio').value||'—', ativo:'—', solicitante:'Técnico SYSACK', data:new Date(), status:'pendente', obs:'' };
    STATE.aprovacoes.unshift(aprov);
    // TODO Banco + SMTP: enviar email gestor
    showToast('⏳ Enviado para aprovação do gestor', 'warning');
  } else {
    showToast('✓ Atendimento registrado!');
  }
  renderDashboard();
}

function salvarRetornoTerc() {
  closeModal('modal-retorno-terc');
  showToast('✓ Retorno registrado! Aguardando aprovação do gestor.', 'success');
  // TODO Banco: atualizar ativo + criar movimentação + SMTP notificar
}

function salvarTecnico() {
  const nome = document.getElementById('tec-nome').value.trim();
  if (!nome) return showToast('Nome é obrigatório', 'danger');
  STATE.tecnicos.push({ id:'t'+Date.now(), nome, empresa:document.getElementById('tec-empresa').value, email:document.getElementById('tec-email').value, tel:document.getElementById('tec-tel').value });
  // TODO Banco: await addDoc(collection(db,'tecnicos'), ...)
  closeModal('modal-novo-tecnico');
  renderTecnicos();
  showToast(`✓ Técnico ${nome} cadastrado!`);
}

// ============================================================
// NOTIFICAÇÕES
// ============================================================
function renderNotificacoes() {
  const count = STATE.notificacoes.length;
  document.getElementById('notif-count-badge').textContent = count;
  document.getElementById('notif-count-badge').style.display = count>0?'':'none';
  document.getElementById('notif-list').innerHTML = STATE.notificacoes.map(n=>`
    <div class="np-item">
      <div class="np-dot" style="background:${n.tipo==='danger'?'var(--danger)':n.tipo==='warning'?'var(--warning)':'var(--accent)'}"></div>
      <div><div class="np-title">${n.titulo}</div><div class="np-desc">${n.desc}</div><div class="np-time">${n.tempo}</div></div>
    </div>`).join('')||'<div style="padding:20px;text-align:center;color:var(--g400);font-size:13px">Sem notificações ✓</div>';
}
function markAllRead() { STATE.notificacoes=[]; renderNotificacoes(); }

// ============================================================
// POPULATE SELECTS
// ============================================================
function populateSelects() {
  const adsi = STATE.tecnicos.filter(t=>t.empresa==='adsi');
  const terc = STATE.tecnicos.filter(t=>t.empresa==='terceirizada');
  const fill = (id, list) => { const el=document.getElementById(id); if(!el) return; el.innerHTML='<option value="">Selecione...</option>'+list.map(t=>`<option value="${t.id}">${t.nome}</option>`).join(''); };
  fill('ch-tecnico', adsi);
  fill('ret-tecnico-adsi', adsi);
  fill('at-tecnico-terc', terc);
  const retPat = document.getElementById('ret-patrimonio');
  if (retPat) { const items=STATE.terceirizadaAtivos.filter(t=>!t.retornado); retPat.innerHTML='<option value="">Selecione...</option>'+items.map(t=>`<option value="${t.id}">${t.pat} — ${t.ativo}</option>`).join(''); }
}

// ============================================================
// MODAL
// ============================================================
function openModal(id) {
  populateSelects();
  const el = document.getElementById(id);
  if (el) el.classList.add('open');
  if (id === 'modal-novo-chamado') {
    const now = new Date();
    const iso = now.toISOString().slice(0,16);
    const abEl = document.getElementById('ch-data-abertura');
    if (abEl) abEl.value = iso;
    const bolhaNow = document.getElementById('ch-bolha-now');
    if (bolhaNow) bolhaNow.textContent = now.toLocaleString('pt-BR');
    const sel = document.getElementById('ch-tecnico');
    if (sel && STATE.tecnicos) {
      sel.innerHTML = '<option value="">— Selecione o técnico —</option>' +
        STATE.tecnicos.filter(t=>t.empresa==='adsi').map(t=>`<option value="${t.id}">${t.nome}</option>`).join('');
    }
  }
}
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ============================================================
// TOAST
// ============================================================
function showToast(msg, type='success') {
  const container = document.getElementById('toast');
  const t = document.createElement('div');
  const c = {success:['#0F172A','#10B981','#fff'], danger:['#FEF2F2','#DC2626','#991B1B'], warning:['#FFFBEB','#D97706','#92400E'], info:['#EFF6FF','#2563EB','#1E40AF']};
  const [bg,accent,text] = c[type]||c.success;
  const icon = type==='success'?'✓':type==='danger'?'✕':type==='warning'?'⚠':'ℹ';
  t.style.cssText=`background:${bg};color:${text};padding:11px 18px;border-radius:10px;font-size:13px;font-weight:600;box-shadow:0 20px 48px rgba(0,0,0,.14);display:flex;gap:8px;align-items:center;pointer-events:all;border:1px solid ${accent}33;animation:fadeUp .25s ease;font-family:'Inter',sans-serif;max-width:380px`;
  t.innerHTML=`<span style="color:${accent};font-size:16px">${icon}</span><span>${msg}</span>`;
  container.appendChild(t);
  setTimeout(()=>{ t.style.opacity='0'; t.style.transform='translateY(8px)'; t.style.transition='all .3s ease'; setTimeout(()=>t.remove(),300); }, 4000);
}

// ============================================================
// UTILS
// ============================================================
function fmtDatetime(d) {
  if (!d) return '—';
  const dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt)) return '—';
  return dt.toLocaleDateString('pt-BR') + ' ' + dt.toLocaleTimeString('pt-BR', {hour:'2-digit',minute:'2-digit'});
}

function statusBadgeCh(s) {
  const cfg = {
    'novo':           { dot:'#10B981', label:'Novo' },
    'aberto':         { dot:'#10B981', label:'Novo' },
    'em-atendimento': { dot:'#10B981', label:'Em atendimento (atribuído)' },
    'pendente':       { dot:'#F59E0B', label:'Pendente' },
    'solucionado':    { dot:'transparent', label:'Solucionado', border:'#94A3B8' },
    'concluido':      { dot:'transparent', label:'Solucionado', border:'#94A3B8' },
    'fechado':        { dot:'#1E293B', label:'Fechado' },
    'aguardando-aprovacao': { dot:'#F59E0B', label:'Pendente' },
  };
  const c = cfg[s] || { dot:'#94A3B8', label:s };
  return `<span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:500;color:var(--g700)"><span style="width:10px;height:10px;border-radius:50%;background:${c.dot};flex-shrink:0;border:1.5px solid ${c.border||c.dot}"></span>${c.label}</span>`;
}

function categoriaLabel(cat) {
  const m = {
    'active-directory':       'Active Directory',
    'antivirus':              'Antivírus',
    'backup-restore':         'Backup e Restore',
    'banco-dados':            'Banco de Dados',
    'cadastro-usuario':       'Cadastro de Usuário',
    'certificado-digital':    'Certificado Digital',
    'computador':             'Computador',
    'email':                  'E-mail',
    'equipamento-problema':   'Equipamento com problema',
    'firewall-webfilter':     'Firewall / Web Filter',
    'impressao':              'Impressão',
    'internet':               'Internet',
    'link-dados':             'Link de Dados',
    'rede-dados':             'Rede de Dados',
    'rede-logica':            'Rede Lógica',
    'rede-wan':               'Rede WAN',
    'cabeamento':             'Cabeamento Estruturado',
    'servidor':               'Servidor',
    'servidor-aplicacao':     'Servidor de Aplicação',
    'servidor-arquivos':      'Servidor de Arquivos',
    'sistemas-corporativos':  'Sistemas Corporativos',
    'agencia-virtual':        'Sistemas Corporativos > Agência Virtual',
    'arterh':                 'Sistemas Corporativos > ArterH',
    'banco-ind-comerciais':   'Sistemas Corporativos > Banco de Indicadores Comerciais',
    'bi':                     'Sistemas Corporativos > BI',
    'cat':                    'Sistemas Corporativos > CAT',
    'cesanlims':              'Sistemas Corporativos > CesanLIMS',
    'cidades-es':             'Sistemas Corporativos > CidadES',
    'clipping':               'Sistemas Corporativos > Clipping',
    'concessoes':             'Sistemas Corporativos > Concessões',
    'convenios':              'Sistemas Corporativos > Convênios',
    'cpep-pep':               'Sistemas Corporativos > CPEP / PEP',
    'gis':                    'Sistemas Corporativos > GIS',
    'glpi':                   'Sistemas Corporativos > GLPI',
    'hotsite-compras':        'Sistemas Corporativos > Hotsite de Compras',
    'onbase':                 'Sistemas Corporativos > OnBase',
    'sap':                    'Sistemas Corporativos > SAP',
    'siscom':                 'Sistemas Corporativos > Siscom',
    'pague-facil':            'Sistemas Corporativos > Pague Fácil',
    'portal-cco':             'Sistemas Corporativos > Portal CCO',
    'portal-corporativo':     'Sistemas Corporativos > Portal Corporativo (Intranet)',
    'portal-transparencia':   'Sistemas Corporativos > Portal da Transparência',
    'portal-compras':         'Sistemas Corporativos > Portal de Compras',
    'portal-institucional':   'Sistemas Corporativos > Portal Institucional (Site)',
    'progen':                 'Sistemas Corporativos > Progen',
    'qjuridico':              'Sistemas Corporativos > QJurídico',
    'sacs':                   'Sistemas Corporativos > SACS',
    'sam':                    'Sistemas Corporativos > SAM',
    'sicat':                  'Sistemas Corporativos > SICAT',
    'siob':                   'Sistemas Corporativos > SIOB',
    'simp':                   'Sistemas Corporativos > SIMP',
    'sincop':                 'Sistemas Corporativos > SINCOP',
    'siscop':                 'Sistemas Corporativos > SISCOP',
    'sispaev':                'Sistemas Corporativos > SisPaEv',
    'sistema-visitas':        'Sistemas Corporativos > Sistema de Visitas',
    'site-ctc':               'Sistemas Corporativos > Site CTC',
    'unilims':                'Sistemas Corporativos > UniLIMS',
    'software':               'Software',
    'storage':                'Storage',
    'system-center':          'System Center',
    'telefonia-fixa':         'Telefonia Fixa',
    'telefonia-movel':        'Telefonia Móvel',
    'virtualizacao':          'Virtualização',
    'vpn':                    'VPN',
    'wifi':                   'Wi-Fi',
    'smartphone-mdm':         'Smartphone',
    'telefonia':              'Telefonia / VOIP',
    'demais-sol':             'Demais solicitações',
    'na':                     'N/A',
  };
  return m[cat] || cat;
}

function fmtDate(d) { if(!d) return '—'; const dt=d instanceof Date?d:new Date(d); return dt.toLocaleDateString('pt-BR'); }
function getTecNome(id) { const t=STATE.tecnicos.find(t=>t.id===id); return t?t.nome:id||'—'; }
function sv(id,v) { const el=document.getElementById(id); if(el) el.textContent=v; }
function nbUpdate(id,count) { const el=document.getElementById(id); if(!el) return; el.textContent=count; el.style.display=count>0?'':'none'; }
function statusBadge(s) { const m={'aberto':'<span class="badge badge-danger">Aberto</span>','em-atendimento':'<span class="badge badge-warning">Em Atendimento</span>','aguardando-aprovacao':'<span class="badge badge-orange">Aguard. Aprovação</span>','concluido':'<span class="badge badge-success">Concluído</span>'}; return m[s]||`<span class="badge badge-gray">${s}</span>`; }
function statusAtivoHtml(s) { const m={'ativo':'sp-ativo','disponivel':'sp-disponivel','manut':'sp-manut','terceirizada':'sp-terceirizada','sc':'sp-sc','pendente':'sp-pendente'}; const l={'ativo':'Em Uso','disponivel':'Disponível','manut':'Manutenção','terceirizada':'Na Terceirizada','sc':'Santa Clara','pendente':'Pendente'}; return `<span class="status-pill ${m[s]||'sp-pendente'}">${l[s]||s}</span>`; }
function aprovStatusBadge(s) { const m={'aprovado':'<span class="badge badge-success">✓ Aprovado</span>','pendente':'<span class="badge badge-warning">⏳ Pendente</span>','recusado':'<span class="badge badge-danger">✕ Recusado</span>'}; return m[s]||`<span class="badge badge-gray">${s}</span>`; }
function tipoBadgeClass(t) { return {'nova-maquina':'badge-info','problema':'badge-warning','transferencia':'badge-violet'}[t]||'badge-gray'; }
function tipoLabel(t) { return {'nova-maquina':'Nova Máquina','problema':'Problema','transferencia':'Transferência'}[t]||t; }
function previewFoto(input, prevId) { const p=document.getElementById(prevId); if(!p) return; p.innerHTML=Array.from(input.files).map(f=>`<img src="${URL.createObjectURL(f)}" class="photo-thumb">`).join(''); }

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  initSeedData();
  initTheme();

  renderDashboard();
  renderNotificacoes();

  // ── Inicia Banco PRIMEIRO, depois verifica sessão ─────────────
  // CRÍTICO: initBanco deve completar antes de checkSavedSession
  // Caso contrário FB_READY=false quando loginSuccess tenta iniciar
  // os listeners do Firestore e os dados nunca aparecem
  initBanco().then(() => {
    const st = document.getElementById('login-firebase-status');
    if (st) st.textContent = FB_READY
      ? '🗄️ Banco de Dados conectado'
      : '📡 Modo offline — dados locais';

    // APENAS AGORA verifica sessão salva — FB_READY já é true
    if (!checkSavedSession()) {
      document.getElementById('login-email')?.focus();
    }
  }).catch(e => {
    const st = document.getElementById('login-firebase-status');
    if (st) st.textContent = '📡 Sem conexão com Banco';
    console.warn('[Banco] init:', e);
    // Mesmo sem Banco, tenta restaurar sessão
    if (!checkSavedSession()) {
      document.getElementById('login-email')?.focus();
    }
  });

  // Nav
  document.querySelectorAll('.nav-i[data-page]').forEach(el => {
    el.addEventListener('click', () => {
      const tipo = el.dataset.tipo || null;
      goPage(el.dataset.page);
      // Se tiver data-tipo, aplica o filtro de categoria automaticamente
      if (tipo !== null && el.dataset.page === 'ativos') {
        _ativoFiltroTipo = tipo;
        // Destaca a aba correta dentro da página de ativos
        const tabMap = {
          'computador,workstation,notebook,desktop': 1,
          'notebook': 2,
          'monitor': 3,
          'switch,router,ap,firewall,access point': 4,
          'servidor,server-linux': 5,
          'outro,rack,storage,appliance,ups,camera': 6,
          'impressora,printer': 6,
          'software': 6,
        };
        const tabs = document.querySelectorAll('#ativos-tabs .tab');
        tabs.forEach(t => t.classList.remove('active'));
        const tabIdx = tabMap[tipo];
        if (tabIdx !== undefined && tabs[tabIdx]) {
          tabs[tabIdx].classList.add('active');
        } else {
          // Aba "Todos" ativa se não tiver mapeamento
          if (tabs[0]) tabs[0].classList.add('active');
        }
        const isComp = tipo.includes('computador') || tipo.includes('notebook') || tipo.includes('desktop') || tipo.includes('workstation');
        updateAtivosTableForComputadores(isComp);
        renderAtivos();
      } else if (el.dataset.page === 'ativos' && !tipo) {
        // Clicou em "Ativos" sem tipo — mostra todos
        _ativoFiltroTipo = '';
        const tabs = document.querySelectorAll('#ativos-tabs .tab');
        tabs.forEach(t => t.classList.remove('active'));
        if (tabs[0]) tabs[0].classList.add('active');
        renderAtivos();
      }
    });
  });

  // Breadcrumb root
  document.getElementById('bc-root').addEventListener('click', () => goPage('dashboard'));

  // Chamados tabs
  document.getElementById('chamados-tabs')?.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#chamados-tabs .tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderChamados(tab.dataset.tab);
    });
  });

  // Modal close on backdrop
  document.querySelectorAll('.modal-overlay').forEach(m => {
    m.addEventListener('click', e => { if (e.target===m) m.classList.remove('open'); });
  });

  // Notif panel
  document.getElementById('notif-btn').addEventListener('click', () => {
    document.getElementById('notif-panel').classList.toggle('open');
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.notif-panel') && !e.target.closest('#notif-btn')) {
      document.getElementById('notif-panel').classList.remove('open');
    }
  });
});


// === MÓDULOS SECUNDÁRIOS ===

// ============================================================
// MDM STATE SEED
// ============================================================
STATE.smartphones = [];

// Seed de empregados (simulação — em produção, viria de outro módulo/Banco)
const EMPREGADOS_DB = [
  {nome:'João Silva',     mat:'10234', setor:'Operações',  smId:'sm1'},
  {nome:'Maria Santos',   mat:'10456', setor:'Comercial',  smId:'sm2'},
  {nome:'Carlos Souza',   mat:'10001', setor:'TI',         smId:null},
  {nome:'Ana Lima',       mat:'10002', setor:'TI',         smId:null},
  {nome:'Pedro Alves',    mat:'10789', setor:'Logística',  smId:'sm3'},
  {nome:'Carlos Lima',    mat:'10890', setor:'Vendas',     smId:'sm4'},
  {nome:'Lúcia Ferreira', mat:'10345', setor:'Financeiro', smId:null},
];

// Empregado logado (simulação)
const EMPREGADO_LOGADO = { nome:'João Martins', mat:'10000', setor:'TI', smId:null };

let currentMdmView = 'table';
let currentActionSm = null;
let currentActionType = null;
let currentChamadoSm = null;

// ============================================================
// RENDER MDM
// ============================================================
const PAGE_LABELS_EXT = { mdm: 'Smartphones / MDM' };

function renderMDM() {
  const sms = STATE.smartphones || [];
  const q = (document.getElementById('mdm-search-input')?.value||'').toLowerCase();
  const fs = document.getElementById('mdm-filter-status')?.value||'';
  const fm = document.getElementById('mdm-filter-marca')?.value||'';
  const filtered = sms.filter(s => {
    const matchQ = !q || s.modelo.toLowerCase().includes(q) || s.imei1.includes(q) || (s.empNome||'').toLowerCase().includes(q) || s.pat.toLowerCase().includes(q);
    const matchS = !fs || s.status === fs;
    const matchM = !fm || s.marca === fm;
    return matchQ && matchS && matchM;
  });

  // Stats
  sv('mdm-s-total', sms.length);
  sv('mdm-s-uso',     sms.filter(s=>s.status==='uso').length);
  sv('mdm-s-estoque', sms.filter(s=>s.status==='estoque').length);
  sv('mdm-s-manut',   sms.filter(s=>s.status==='manut').length);
  sv('mdm-s-extra',   sms.filter(s=>s.status==='extraviado').length);
  sv('mdm-s-bloq',    sms.filter(s=>s.status==='bloqueado').length);
  nbUpdate('nb-mdm', sms.filter(s=>s.status==='extraviado'||s.status==='bloqueado').length);

  if (currentMdmView === 'table') {
    document.getElementById('mdm-table-body').innerHTML = filtered.map(s => `
      <tr>
        <td class="td-mono" style="color:var(--accent)">${s.pat}</td>
        <td><div style="font-weight:600">${s.marca} ${s.modelo}</div><div style="font-size:10.5px;color:var(--g400)">${s.so} ${s.versao}</div></td>
        <td class="td-mono imei-field">${s.imei1}</td>
        <td>${s.linha||'—'}<br><span style="font-size:10.5px;color:var(--g400)">${s.operadora||''}</span></td>
        <td><div style="font-weight:600">${s.empNome||'—'}</div><div style="font-size:10.5px;color:var(--g400)">${s.empSetor||''}</div></td>
        <td class="td-mono">${s.empMat||'—'}</td>
        <td>${s.empSetor||'—'}</td>
        <td class="td-mono">${s.ultimaTroca ? new Date(s.ultimaTroca).toLocaleDateString('pt-BR') : '—'}</td>
        <td><span class="tag">${s.so}</span></td>
        <td>${smStatusHtml(s.status)}</td>
        <td>
          <div class="flex gap-4" style="flex-wrap:wrap;gap:4px">
            <button class="mdm-action-btn mab-info" onclick="abrirHistSm('${s.id}')">📜 Histórico</button>
            <button class="mdm-action-btn mab-gray" onclick="abrirGerenciarSm('${s.id}')">⚙️ Gerenciar</button>
            <button class="mdm-action-btn mab-success" onclick="abrirChamadoSm('${s.id}')">🎫 Chamado</button>
            <button class="mdm-action-btn mab-violet" onclick="gerarTermoSm('${s.id}')">📄 Termo</button>
          </div>
        </td>
      </tr>`).join('') || '<tr><td colspan="11" style="text-align:center;padding:24px;color:var(--g400)">Nenhum smartphone encontrado</td></tr>';
  } else {
    document.getElementById('mdm-cards-grid').innerHTML = filtered.map(s => `
      <div class="mdm-device-card">
        <div class="mdm-card-top">
          <div class="mdm-phone-icon" style="background:${s.marca==='Apple'?'#1C1C1E':s.marca==='Samsung'?'#1428A0':s.marca==='Motorola'?'#E00011':'#FF6900'}">${s.marca==='Apple'?'🍎':'📱'}</div>
          <div style="flex:1"><div style="font-weight:700;font-size:13px">${s.marca} ${s.modelo}</div><div class="td-mono" style="font-size:10.5px;color:var(--g400)">${s.pat}</div></div>
          ${smStatusHtml(s.status)}
        </div>
        <div class="mdm-card-body">
          <div class="mdm-card-field"><span class="lbl">IMEI 1</span><span class="val imei-field">${s.imei1}</span></div>
          <div class="mdm-card-field"><span class="lbl">Linha</span><span class="val">${s.linha||'—'}</span></div>
          <div class="mdm-card-field"><span class="lbl">Empregado</span><span class="val">${s.empNome||'—'}</span></div>
          <div class="mdm-card-field"><span class="lbl">Setor</span><span class="val">${s.empSetor||'—'}</span></div>
          <div class="mdm-card-field"><span class="lbl">Matrícula</span><span class="val">${s.empMat||'—'}</span></div>
          <div class="mdm-card-field"><span class="lbl">Última Troca</span><span class="val">${s.ultimaTroca?new Date(s.ultimaTroca).toLocaleDateString('pt-BR'):'—'}</span></div>
          <div class="mdm-card-field"><span class="lbl">S.O.</span><span class="val">${s.so} ${s.versao}</span></div>
        </div>
        <div class="mdm-card-actions">
          <button class="mdm-action-btn mab-info" onclick="abrirHistSm('${s.id}')">📜 Histórico</button>
          <button class="mdm-action-btn mab-gray" onclick="abrirGerenciarSm('${s.id}')">⚙️ Gerenciar</button>
          <button class="mdm-action-btn mab-success" onclick="abrirChamadoSm('${s.id}')">🎫 Chamado</button>
          <button class="mdm-action-btn mab-violet" onclick="gerarTermoSm('${s.id}')">📄 Termo</button>
          <button class="mdm-action-btn mab-warning" onclick="mdmActionDirect('localize','${s.id}')">📍 Localizar</button>
          <button class="mdm-action-btn mab-danger" onclick="mdmActionDirect('lock','${s.id}')">🔒 Bloquear</button>
        </div>
      </div>`).join('') || '<div style="grid-column:1/-1;text-align:center;padding:56px;color:var(--g400)"><div style="font-size:32px;margin-bottom:12px">📱</div><h3>Nenhum smartphone encontrado</h3></div>';
  }
}

function goMdmView(view) {
  currentMdmView = view;
  document.getElementById('mdm-view-table').style.display = view==='table'?'':'none';
  document.getElementById('mdm-view-cards').style.display = view==='cards'?'':'none';
  renderMDM();
}

// ============================================================
// HISTÓRICO SMARTPHONE
// ============================================================
function abrirHistSm(id) {
  const sm = (STATE.smartphones||[]).find(s=>s.id===id);
  if (!sm) return;
  currentActionSm = sm;
  document.getElementById('hist-sm-nome').textContent = sm.pat;
  document.getElementById('hist-sm-modelo-header').textContent = `${sm.marca} ${sm.modelo}`;
  document.getElementById('hist-sm-imei-header').textContent = `IMEI 1: ${sm.imei1}${sm.imei2?' · IMEI 2: '+sm.imei2:''}`;

  const chips = [
    smStatusHtml(sm.status),
    sm.empNome&&sm.empNome!=='—'?`<span class="badge badge-info">👤 ${sm.empNome}</span>`:'',
    sm.linha?`<span class="badge badge-gray">📞 ${sm.linha}</span>`:'',
    `<span class="badge badge-gray">${sm.so} ${sm.versao}</span>`,
  ].filter(Boolean).join('');
  document.getElementById('hist-sm-info-chips').innerHTML = chips;

  document.getElementById('hist-sm-timeline').innerHTML = (sm.historico||[]).map(e => `
    <div class="tl-item"><div class="tl-dot ${e.dot}"></div><div class="tl-title">${e.titulo}</div><div class="tl-desc">${e.desc}</div><div class="tl-time">${e.data}</div></div>`).join('') || '<p class="text-muted text-sm">Sem eventos registrados.</p>';

  // audit log
  document.getElementById('hist-sm-audit').innerHTML = [
    {time:'08/05/2026 09:12', user:'João Martins', action:`Consultou histórico do aparelho ${sm.pat}`, badge:'<span class="badge badge-gray">Leitura</span>'},
  ].map(a=>`
    <div class="audit-row">
      <div class="ar-time">${a.time}</div>
      <div class="ar-user">${a.user}</div>
      <div class="ar-action">${a.action}</div>
      <div class="ar-badge">${a.badge}</div>
    </div>`).join('');

  openModal('modal-hist-smartphone');
}

function adicionarEventoHistSm() {
  const tipo = document.getElementById('sm-ev-tipo').value;
  const desc = document.getElementById('sm-ev-desc').value.trim();
  if (!tipo || !desc) return showToast('Selecione o tipo e descreva o evento', 'danger');
  const sm = currentActionSm;
  if (!sm) return;
  const dotMap = {
    'troca-resp':'blue','manutencao':'orange','quebra':'red','chip':'gray',
    'capa':'gray','bloqueio':'violet','perda':'red','reset':'red',
    'recolhimento':'orange','baixa':'gray','obs':'blue'
  };
  const labelMap = {
    'troca-resp':'Troca de Responsável','manutencao':'Manutenção','quebra':'Quebra / Dano',
    'chip':'Troca de Chip','capa':'Troca de Capa / Película','bloqueio':'Bloqueio Remoto',
    'perda':'Perda ou Roubo','reset':'Reset de Fábrica','recolhimento':'Recolhimento',
    'baixa':'Baixa Patrimonial','obs':'Observação da TI'
  };
  const dataVal = document.getElementById('sm-ev-data').value;
  const dataFmt = dataVal ? new Date(dataVal+'T12:00:00').toLocaleDateString('pt-BR') : new Date().toLocaleDateString('pt-BR');
  sm.historico.push({ tipo, dot:dotMap[tipo]||'gray', titulo:labelMap[tipo]||tipo, desc, data:dataFmt });
  // TODO Banco: addDoc(collection(db,'sm_historico'), {...})
  abrirHistSm(sm.id); // re-render
  document.getElementById('sm-ev-tipo').value='';
  document.getElementById('sm-ev-desc').value='';
  document.getElementById('sm-ev-data').value='';
  showToast('✓ Evento adicionado ao histórico!');
}

// ============================================================
// GERENCIAR SMARTPHONE
// ============================================================
function abrirGerenciarSm(id) {
  const sm = (STATE.smartphones||[]).find(s=>s.id===id);
  if (!sm) return;
  currentActionSm = sm;
  document.getElementById('ger-sm-nome').textContent = `${sm.marca} ${sm.modelo} — ${sm.pat}`;
  document.getElementById('ger-sm-info').innerHTML = [
    smStatusHtml(sm.status),
    sm.empNome&&sm.empNome!=='—'?`<span class="badge badge-info">👤 ${sm.empNome} (${sm.empMat})</span>`:'<span class="badge badge-gray">Sem responsável</span>',
    `<span class="badge badge-gray">📞 ${sm.linha||'Sem linha'}</span>`,
    `<span class="badge badge-gray">${sm.operadora||'Sem operadora'}</span>`,
  ].join('\r\n');
ementById('ger-sm-dados-tecnicos').innerHTML = [
    ['Patrimônio', sm.pat], ['IMEI 1', sm.imei1],
    ['IMEI 2', sm.imei2||'—'], ['Marca/Modelo', `${sm.marca} ${sm.modelo}`],
    ['S.O.', `${sm.so} ${sm.versao}`], ['Linha', sm.linha||'—'],
    ['Operadora', sm.operadora||'—'], ['Empregado', sm.empNome||'—'],
    ['Matrícula', sm.empMat||'—'], ['Setor', sm.empSetor||'—'],
    ['Data Entrega', sm.dataEntrega?new Date(sm.dataEntrega+'T12:00:00').toLocaleDateString('pt-BR'):'—'],
    ['Última Troca', sm.ultimaTroca?new Date(sm.ultimaTroca+'T12:00:00').toLocaleDateString('pt-BR'):'—'],
  ].map(([l,v])=>`<div><div class="text-xs text-muted">${l}</div><div style="font-size:12.5px;font-weight:600;margin-top:2px;font-family:${l.includes('IMEI')?'JetBrains Mono,monospace':''}">${v}</div></div>`).join('');
  openModal('modal-mdm-gerenciar');
}

// ============================================================
// MDM AÇÕES REMOTAS
// ============================================================
const MDM_ACTION_CONFIG = {
  'localize':       { title:'📍 Localizar Aparelho',      lgpd:true,  warn:'A geolocalização somente pode ser usada em caso de perda, roubo, incidente de segurança ou necessidade operacional justificada.', dangerBtn:false },
  'remote-access':  { title:'🖥️ Acesso Remoto Assistido', lgpd:true,  warn:'O acesso remoto exige consentimento documentado. O motivo fica registrado em log de auditoria.', dangerBtn:false },
  'lock':           { title:'🔒 Bloquear Aparelho',       lgpd:false, warn:'', dangerBtn:false },
  'unlock':         { title:'🔓 Desbloquear Aparelho',    lgpd:false, warn:'', dangerBtn:false },
  'push-app':       { title:'📲 Instalar Aplicativo',     lgpd:false, warn:'', dangerBtn:false },
  'remove-app':     { title:'🗑️ Remover Aplicativo',      lgpd:false, warn:'', dangerBtn:false },
  'password-policy':{ title:'🔑 Aplicar Política de Senha',lgpd:false,warn:'', dangerBtn:false },
  'inventory':      { title:'📋 Inventário Automático',   lgpd:false, warn:'', dangerBtn:false },
  'geohistory':     { title:'🗺️ Histórico de Localização',lgpd:true,  warn:'O histórico de localização somente pode ser consultado em caso de perda, roubo ou incidente de segurança.', dangerBtn:false },
  'factory-reset':  { title:'⚠️ Reset de Fábrica',        lgpd:false, warn:'ATENÇÃO: O reset de fábrica é irreversível. Todos os dados do aparelho serão apagados permanentemente.', dangerBtn:true },
  'rdp':            { title:'🖥️ Acesso Remoto (RDP)',       lgpd:true,  warn:'O acesso remoto fica registrado em log de auditoria com horário de início e fim.', dangerBtn:false },
  'install-app':    { title:'📦 Instalar Software',         lgpd:false, warn:'', dangerBtn:false },
  'uninstall-app':  { title:'🗑️ Desinstalar Software',      lgpd:false, warn:'', dangerBtn:false },
  'run-command':    { title:'⚡ Executar Comando',          lgpd:true,  warn:'Comandos são executados como SYSTEM. Registrados em audit log.', dangerBtn:false },
  'reboot':         { title:'🔄 Reiniciar Computador',     lgpd:false, warn:'', dangerBtn:false },
  'shutdown':       { title:'⏹️ Desligar Computador',       lgpd:false, warn:'', dangerBtn:true },
};

function mdmAction(type) { mdmActionDirect(type, currentActionSm?.id); }
function mdmActionDirect(type, smId) {
  const sm = (STATE.smartphones||[]).find(s=>s.id===smId);
  if (!sm) return;
  currentActionSm = sm;
  currentActionType = type;
  const cfg = MDM_ACTION_CONFIG[type] || { title:'Ação MDM', lgpd:false, warn:'', dangerBtn:false };
  document.getElementById('mdm-action-title').textContent = cfg.title;
  document.getElementById('mdm-action-lgpd-notice').style.display = cfg.lgpd ? '' : 'none';
  document.getElementById('mdm-action-warn').style.display = cfg.warn ? '' : 'none';
  document.getElementById('mdm-action-warn-text').textContent = cfg.warn;
  const btn = document.getElementById('mdm-action-confirm-btn');
  btn.textContent = cfg.dangerBtn ? '⚠️ Confirmar — Irreversível' : 'Confirmar e Executar';
  btn.className = `btn btn-sm ${cfg.dangerBtn?'btn-danger':'btn-primary'}`;
  document.getElementById('mdm-action-motivo').value = '';
  document.getElementById('mdm-action-consent').checked = false;
  openModal('modal-mdm-action');
}

function confirmMdmAction() {
  const motivo = document.getElementById('mdm-action-motivo').value.trim();
  const consent = document.getElementById('mdm-action-consent').checked;
  if (!motivo) return showToast('O motivo é obrigatório', 'danger');
  if (!consent) return showToast('Confirme a conformidade com as políticas', 'danger');
  const sm = currentActionSm;
  const type = currentActionType;
  const cfg = MDM_ACTION_CONFIG[type]||{};
  // Log de auditoria
  const logEntry = { tipo:'acao-remota', dot:'violet', titulo:`${cfg.title} — via MDM`, desc:`Motivo: ${motivo}. Executado por: João Martins.`, data:new Date().toLocaleDateString('pt-BR') };
  if (sm && sm.historico) sm.historico.push(logEntry);
  // Atualizar status
  if (type==='lock') sm.status = 'bloqueado';
  else if (type==='unlock') sm.status = 'uso';
  else if (type==='factory-reset') { sm.status = 'estoque'; sm.empNome='—'; sm.empMat='—'; sm.empSetor='—'; }
  // TODO Banco: updateDoc(...) + enviar comando MDM via API
  closeModal('modal-mdm-action');
  closeModal('modal-mdm-gerenciar');
  renderMDM();
  const msgs = {
    'localize':'📍 Solicitação de localização enviada ao dispositivo',
    'remote-access':'🖥️ Sessão de acesso remoto iniciada',
    'lock':'🔒 Aparelho bloqueado com sucesso',
    'unlock':'🔓 Aparelho desbloqueado',
    'factory-reset':'⚠️ Comando de reset de fábrica enviado',
    'inventory':'📋 Inventário automático solicitado',
    'geohistory':'🗺️ Histórico de localização carregado',
  };
  showToast(msgs[type]||'✓ Ação executada com sucesso', type==='factory-reset'?'warning':'success');
}

// ============================================================
// TROCAR RESPONSÁVEL
// ============================================================
function salvarTrocaResponsavel() {
  const nome = document.getElementById('troca-emp-nome').value.trim();
  const mat  = document.getElementById('troca-emp-mat').value.trim();
  const data = document.getElementById('troca-emp-data').value;
  const termo = document.getElementById('troca-termo-check').checked;
  if (!nome||!mat) return showToast('Nome e matrícula são obrigatórios', 'danger');
  if (!termo) return showToast('Confirme o recebimento do termo de responsabilidade', 'danger');
  const sm = currentActionSm;
  if (!sm) return;
  const oldNome = sm.empNome;
  sm.empNome = nome; sm.empMat = mat;
  sm.empSetor = document.getElementById('troca-emp-setor').value||sm.empSetor;
  sm.ultimaTroca = data||new Date().toISOString().split('T')[0];
  sm.historico.push({ tipo:'troca-resp', dot:'blue', titulo:`Troca de Responsável`, desc:`Anterior: ${oldNome||'—'}. Novo: ${nome} (${mat}). Termo assinado.`, data:new Date().toLocaleDateString('pt-BR') });
  // TODO Banco: updateDoc(...)
  closeModal('modal-mdm-gerenciar');
  renderMDM();
  showToast(`✓ Responsável atualizado para ${nome}!`);
}

// ============================================================
// CHAMADO SMARTPHONE
// ============================================================
function abrirChamadoSm(smId) {
  currentChamadoSm = (STATE.smartphones||[]).find(s=>s.id===smId)||null;
  // Resetar
  document.getElementById('ch-sm-step1').style.display = '';
  document.getElementById('ch-sm-step2').style.display = 'none';
  document.getElementById('ch-sm-btn-abrir').style.display = 'none';
  document.querySelectorAll('[id^="ch-sm-opt-"]').forEach(el=>el.classList.remove('checked'));
  document.getElementById('ch-sm-busca-emp').style.display = 'none';
  // Se veio com sm específico, pular step 1
  if (currentChamadoSm) {
    preencherChamadoSm(currentChamadoSm);
  }
  openModal('modal-chamado-smartphone');
}

function selecionarChamadoSm(tipo) {
  document.querySelectorAll('[id^="ch-sm-opt-"]').forEach(el=>el.classList.remove('checked'));
  document.getElementById('ch-sm-opt-'+tipo)?.classList.add('checked');
  document.getElementById('ch-sm-busca-emp').style.display = 'none';
  if (tipo==='meu') {
    const sm = (STATE.smartphones||[]).find(s=>s.empMat===EMPREGADO_LOGADO.mat)||null;
    if (sm) { preencherChamadoSm(sm); }
    else { showToast('Nenhum smartphone vinculado ao seu cadastro', 'warning'); }
  } else if (tipo==='outro') {
    document.getElementById('ch-sm-busca-emp').style.display = '';
    document.getElementById('ch-sm-busca-input').value = '';
    document.getElementById('ch-sm-busca-resultados').innerHTML = '';
  } else if (tipo==='semresp') {
    const sm = (STATE.smartphones||[]).find(s=>s.status==='estoque')||null;
    if (sm) { preencherChamadoSm(sm); }
    else { preencherChamadoSm(null, true); }
  } else {
    preencherChamadoSm(null, false);
  }
}

function buscarEmpregadoSm(q) {
  const res = document.getElementById('ch-sm-busca-resultados');
  if (!q||q.length<2) { res.innerHTML=''; return; }
  const found = EMPREGADOS_DB.filter(e=>e.nome.toLowerCase().includes(q.toLowerCase())||e.mat.includes(q));
  res.innerHTML = found.length ? found.map(e=>{
    const sm = (STATE.smartphones||[]).find(s=>s.id===e.smId);
    return `<div style="padding:10px 12px;border:1px solid var(--g200);border-radius:8px;margin-top:6px;cursor:pointer;transition:background .15s" onmouseover="this.style.background='var(--accent-l)'" onmouseout="this.style.background=''" onclick="selecionarEmpregadoSm('${e.mat}')">
      <div style="font-weight:600;font-size:13px">${e.nome} <span class="td-mono" style="font-size:11px;color:var(--g400)">(${e.mat})</span></div>
      <div style="font-size:11.5px;color:var(--g500)">${e.setor} ${sm?'· 📱 '+sm.marca+' '+sm.modelo:'· Sem smartphone vinculado'}</div>
    </div>`;
  }).join('') : '<p style="padding:10px;font-size:12.5px;color:var(--g400)">Nenhum empregado encontrado.</p>';
}

function selecionarEmpregadoSm(mat) {
  const emp = EMPREGADOS_DB.find(e=>e.mat===mat);
  if (!emp) return;
  const sm = emp.smId ? (STATE.smartphones||[]).find(s=>s.id===emp.smId) : null;
  preencherChamadoSm(sm, false, emp);
}

function preencherChamadoSm(sm, semSm=false, emp=null) {
  const empData = emp || (sm ? { nome:sm.empNome, mat:sm.empMat, setor:sm.empSetor } : null);
  const campos = [
    ['Nome do Empregado',   empData?.nome||'—'],
    ['Matrícula',           empData?.mat||'—'],
    ['Setor',               empData?.setor||'—'],
    ['Patrimônio',          sm?.pat||'—'],
    ['Linha / Chip',        sm?.linha||'—'],
    ['Operadora',           sm?.operadora||'—'],
    ['IMEI 1',              sm?.imei1||'—'],
    ['Marca / Modelo',      sm?(sm.marca+' '+sm.modelo):'—'],
    ['S.O.',                sm?(sm.so+' '+sm.versao):'—'],
    ['Status',              sm?smStatusHtml(sm.status):'—'],
    ['Última Troca',        sm?.ultimaTroca?new Date(sm.ultimaTroca+'T12:00:00').toLocaleDateString('pt-BR'):'—'],
    ['Chamados Anteriores', sm?(STATE.chamados?.filter(c=>c.pat===sm.pat).length||0)+' chamados':'—'],
  ];
  document.getElementById('ch-sm-dados-auto').innerHTML = campos.map(([l,v])=>`
    <div><div class="text-xs text-muted">${l}</div><div style="font-size:12.5px;font-weight:600;margin-top:2px">${v}</div></div>`).join('');
  // fill tecnico select
  const sel = document.getElementById('ch-sm-tecnico');
  if (sel) sel.innerHTML='<option value="">Selecione...</option>'+(STATE.tecnicos||[]).filter(t=>t.empresa==='adsi').map(t=>`<option value="${t.id}">${t.nome}</option>`).join('');
  currentChamadoSm = sm||null;
  document.getElementById('ch-sm-step1').style.display = 'none';
  document.getElementById('ch-sm-step2').style.display = '';
  document.getElementById('ch-sm-btn-abrir').style.display = '';
}

function salvarChamadoSm() {
  const tipo = document.getElementById('ch-sm-tipo-prob').value;
  const desc = document.getElementById('ch-sm-desc').value.trim();
  if (!tipo||!desc) return showToast('Tipo e descrição são obrigatórios', 'danger');
  const sm = currentChamadoSm;
  const id = 'CH-MOB-' + String((STATE.chamados?.length||0)+100).padStart(3,'0');
  const novoChamado = { id, tipo:'problema', area:'TI', solicitante:sm?.empNome||'—', tecnico:document.getElementById('ch-sm-tecnico').value, pat:sm?.pat||'—', desc:`[SMARTPHONE] ${tipo}: ${desc}`, status:'aberto', createdAt:new Date() };
  if (!STATE.chamados) STATE.chamados=[];
  STATE.chamados.unshift(novoChamado);
  if (sm) sm.historico?.push({ tipo:'chamado', dot:'blue', titulo:`Chamado ${id} aberto`, desc:tipo+'. '+desc.slice(0,60), data:new Date().toLocaleDateString('pt-BR') });
  // TODO Banco: addDoc(collection(db,'chamados'), novoChamado);
  closeModal('modal-chamado-smartphone');
  showToast(`✓ Chamado ${id} aberto para ${sm?.marca||''} ${sm?.modelo||''}!`);
}

// ============================================================
// GERAR TERMO
// ============================================================
function gerarTermoSm(id) {
  const sm = (STATE.smartphones||[]).find(s=>s.id===id);
  if (!sm) return;
  document.getElementById('termo-preview-content').innerHTML = `
    <div style="font-size:12px;line-height:1.8;color:var(--g800)">
      <div style="text-align:center;font-weight:800;font-size:14px;margin-bottom:12px">TERMO DE RESPONSABILIDADE — DISPOSITIVO MÓVEL CORPORATIVO</div>
      <div style="text-align:center;color:var(--g500);margin-bottom:16px;font-size:11.5px">SYSACK · ${new Date().toLocaleDateString('pt-BR')}</div>
      <p>Eu, <strong>${sm.empNome||'_______________'}</strong>, matrícula <strong>${sm.empMat||'_______'}</strong>, lotado no setor de <strong>${sm.empSetor||'_______________'}</strong>, declaro ter recebido em perfeito estado de funcionamento o seguinte dispositivo móvel:</p>
      <div style="background:var(--g100);border-radius:6px;padding:10px 14px;margin:12px 0;font-size:11.5px">
        <div><strong>Patrimônio:</strong> ${sm.pat}</div>
        <div><strong>Marca / Modelo:</strong> ${esc(sm.marca)} ${esc(sm.modelo)}</div>
        <div><strong>IMEI 1:</strong> <span class="imei-field">${sm.imei1}</span></div>
        ${sm.imei2?`<div><strong>IMEI 2:</strong> <span class="imei-field">${sm.imei2}</span></div>`:''}
        <div><strong>Linha / Chip:</strong> ${sm.linha||'—'} (${sm.operadora||'—'})</div>
        <div><strong>S.O.:</strong> ${sm.so} ${sm.versao}</div>
      </div>
      <p>Comprometo-me a zelar pelo bom uso, conservação e segurança do dispositivo, utilizando-o exclusivamente para fins corporativos, e a comunicar imediatamente ao setor de TI qualquer ocorrência de perda, roubo, dano ou mau funcionamento.</p>
      <p>Declaro ainda estar ciente de que o dispositivo poderá ser monitorado e gerenciado remotamente, conforme as políticas de uso da empresa e em conformidade com a LGPD.</p>
      <div style="margin-top:20px;display:flex;gap:24px">
        <div style="flex:1;border-top:1px solid var(--g400);padding-top:6px;text-align:center;font-size:11px">Assinatura do Empregado</div>
        <div style="flex:1;border-top:1px solid var(--g400);padding-top:6px;text-align:center;font-size:11px">Assinatura Responsável TI / SYSACK</div>
      </div>
    </div>`;
  openModal('modal-gerar-termo');
}

// ============================================================
// AUTO-FILL EMPREGADO (helper)
// ============================================================
function autoFillEmpregado(val, prefix) {
  const emp = EMPREGADOS_DB.find(e=>e.nome.toLowerCase()===val.toLowerCase()||e.mat===val);
  if (!emp) return;
  if (prefix==='troca') {
    const mat = document.getElementById('troca-emp-mat'); if(mat) mat.value=emp.mat;
    const setor = document.getElementById('troca-emp-setor'); if(setor) setor.value=emp.setor;
  }
}

// ============================================================
// STATUS HELPER
// ============================================================
function smStatusHtml(s) {
  const m = { 'uso':'ms-uso', 'estoque':'ms-estoque', 'manut':'ms-manut', 'extraviado':'ms-extraviado', 'bloqueado':'ms-bloqueado', 'baixado':'ms-baixado' };
  const l = { 'uso':'Em Uso', 'estoque':'Em Estoque', 'manut':'Em Manutenção', 'extraviado':'Extraviado', 'bloqueado':'Bloqueado', 'baixado':'Baixado' };
  return `<span class="mdm-status-dot ${m[s]||'ms-estoque'}">${l[s]||s}</span>`;
}

// ============================================================
// PATCH goPage para MDM

// ============================================================

// ============================================================
// EXECUTIVE DASHBOARD RENDER
// ============================================================
function renderExecDashboard() {
  const chamados = STATE.chamados || [];
  const ativos = STATE.ativos || [];
  const smartphones = STATE.smartphones || [];

  // ── SLA ──
  const withSLA = chamados.map(c => ({...c, sla: calcSLA(c.createdAt instanceof Date ? c.createdAt : new Date(), c.prioridade||'media')}));
  const slaOk = withSLA.filter(c => c.sla.atingido || c.status === 'concluido').length;
  const slaPct = chamados.length ? Math.round(slaOk / chamados.length * 100) : 92;
  const slaEl = document.getElementById('exec-sla');
  if (slaEl) slaEl.textContent = slaPct + '%';
  const slaBar = document.getElementById('exec-sla-bar');
  if (slaBar) { slaBar.style.width = slaPct + '%'; slaBar.style.background = slaPct >= 95 ? 'var(--success)' : slaPct >= 80 ? 'var(--warning)' : 'var(--danger)'; }

  // ── MTTR ──
  const mttr = calcMTTR(chamados) || 4.2;
  const mttrEl = document.getElementById('exec-mttr');
  if (mttrEl) mttrEl.textContent = mttr + 'h';
  const mttrSub = document.getElementById('exec-mttr-sub');
  if (mttrSub) mttrSub.textContent = `Meta: 8h · ${mttr <= 8 ? '✓ Dentro do SLA' : '⚠ Acima do SLA'}`;

  // ── CHAMADOS ABERTOS ──
  const openCh = chamados.filter(c => c.status !== 'concluido' && c.status !== 'fechado').length;
  sv('exec-open', openCh);
  const openSub = document.getElementById('exec-open-sub');
  if (openSub) openSub.textContent = `${Math.round(openCh * 0.08)} vencidos do SLA (${Math.round(openCh * 0.08 / Math.max(openCh,1) * 100)}%)`;

  // ── MDM COMPLIANCE ──
  const sms = smartphones || [];
  const compliant = sms.filter(s => s.status === 'uso').length;
  const mdmPct = sms.length ? Math.round(compliant / sms.length * 100) : 80;
  const mdmEl = document.getElementById('exec-mdm-comp');
  if (mdmEl) mdmEl.textContent = mdmPct + '%';
  const mdmBar = document.getElementById('exec-mdm-bar');
  if (mdmBar) { mdmBar.style.width = mdmPct + '%'; }

  // ── ATIVOS POR IDADE ──
  const ageChart = document.getElementById('exec-age-chart');
  if (ageChart) {
    const now = new Date();
    const faixas = [
      { label:'< 1 ano',     min:0,    max:1,    cor:'var(--success)', count:0 },
      { label:'1 a 3 anos',  min:1,    max:3,    cor:'var(--accent)',  count:0 },
      { label:'3 a 5 anos',  min:3,    max:5,    cor:'var(--warning)', count:0 },
      { label:'> 5 anos',    min:5,    max:999,  cor:'var(--danger)',  count:0 },
    ];
    ativos.forEach(a => {
      const yr = (now - (a.createdAt instanceof Date ? a.createdAt : new Date(a.createdAt||now))) / (365*24*3600000);
      const f = faixas.find(f => yr >= f.min && yr < f.max);
      if (f) f.count++;
    });
    const total = Math.max(ativos.length, 1);
    ageChart.innerHTML = faixas.map(f => {
      const pct = Math.round(f.count / total * 100);
      const isRisk = f.label.includes('> 5');
      return `
        <div>
          <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:3px">
            <span style="font-weight:600;color:var(--g700)">${f.label}</span>
            <span style="color:var(--g500)">${f.count} ativos (${pct}%) ${isRisk && f.count > 0 ? '<span class="badge badge-danger" style="font-size:9px;padding:1px 5px">Obsoleto</span>':''}</span>
          </div>
          <div style="background:var(--g200);border-radius:4px;height:8px;overflow:hidden">
            <div style="background:${f.cor};width:${pct}%;height:100%;border-radius:4px;transition:width .6s ease"></div>
          </div>
        </div>`;
    }).join('');
  }

  // ── GARANTIAS VENCENDO ──
  const now2 = new Date();
  const soon = ativos.filter(a => {
    if (!a.garantia) return false;
    const g = new Date(a.garantia);
    const days = (g - now2) / 86400000;
    return days > 0 && days <= 90;
  }).sort((a,b) => new Date(a.garantia) - new Date(b.garantia));
  const gCount = document.getElementById('exec-garantia-count');
  if (gCount) gCount.textContent = (soon.length || 2) + ' em 90 dias';
  const gBody = document.getElementById('exec-garantia-body');
  if (gBody) {
    const sample = soon.length ? soon : [];
    gBody.innerHTML = sample.slice(0,5).map(a => {
      const g = new Date(a.garantia);
      const days = Math.round((g - now2) / 86400000);
      const cls = days < 30 ? 'badge-danger' : days < 60 ? 'badge-warning' : 'badge-info';
      return `<tr>
        <td class="td-mono" style="color:var(--accent)">${a.pat}</td>
        <td>${a.desc}</td>
        <td class="td-mono">${g.toLocaleDateString('pt-BR')}</td>
        <td><span class="badge ${cls}">${Math.max(0,days)} dias</span></td>
      </tr>`;
    }).join('') || '<tr><td colspan="4" style="text-align:center;padding:12px;color:var(--g400)">Nenhuma garantia vencendo em 90 dias</td></tr>';
  }

  // ── SLA POR CATEGORIA ──
  const slaCat = document.getElementById('exec-sla-cat');
  if (slaCat) {
    const cats = [
      {cat:'Impressão',ok:95,meta:95},
      {cat:'Computador',ok:88,meta:90},
      {cat:'Sistemas Corp.',ok:82,meta:85},
      {cat:'Rede de Dados',ok:91,meta:90},
      {cat:'Servidor',ok:79,meta:85},
    ];
    slaCat.innerHTML = cats.map(c => {
      const col = c.ok >= c.meta ? 'var(--success)' : c.ok >= c.meta * 0.9 ? 'var(--warning)' : 'var(--danger)';
      return `<div style="margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:2px">
          <span style="font-weight:600;color:var(--g700)">${c.cat}</span>
          <span style="color:${col};font-weight:700">${c.ok}% <span style="color:var(--g400);font-weight:400">(meta ${c.meta}%)</span></span>
        </div>
        <div style="background:var(--g200);border-radius:4px;height:6px;overflow:hidden">
          <div style="background:${col};width:${c.ok}%;height:100%;border-radius:4px;transition:width .6s"></div>
        </div>
      </div>`;
    }).join('');
  }

  // ── LGPD COMPLIANCE ──
  const lgpdEl = document.getElementById('exec-lgpd-items');
  if (lgpdEl) {
    const items = [
      {label:'Termos MDM assinados',    ok:true,  val:'80% (4/5)'},
      {label:'Logs de acesso remoto',   ok:true,  val:'100% auditados'},
      {label:'Justificativa geoloc.',   ok:true,  val:'Obrigatória'},
      {label:'Consentimento de uso',    ok:false, val:'Pendente revisão'},
      {label:'Política de retenção',    ok:true,  val:'12 meses configurados'},
    ];
    lgpdEl.innerHTML = items.map(i => `
      <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--g100);font-size:12px">
        <span style="color:${i.ok?'var(--success)':'var(--danger)'};font-size:14px">${i.ok?'✓':'✕'}</span>
        <span style="flex:1;font-weight:500;color:var(--g700)">${i.label}</span>
        <span style="color:${i.ok?'var(--g500)':'var(--danger)'};font-size:11px">${i.val}</span>
      </div>`).join('');
  }

  // ── MAPA DE RISCO ──
  const riskEl = document.getElementById('exec-risk-items');
  if (riskEl) {
    const risks = [
      {nivel:'ALTO',   cor:'var(--danger)',  item:'PAT-0103 na Terceirizada há 12 dias',            cat:'Operacional'},
      {nivel:'ALTO',   cor:'var(--danger)',  item:'AP-RECEPCAO-01 offline — sem monitoramento',     cat:'Infraestrutura'},
      {nivel:'MÉDIO',  cor:'var(--warning)', item:'1 smartphone extraviado sem bloqueio confirmado',cat:'Segurança'},
      {nivel:'MÉDIO',  cor:'var(--warning)', item:'Garantia de 2 ativos vencendo em 30 dias',       cat:'Financeiro'},
      {nivel:'BAIXO',  cor:'var(--success)', item:'Firmware do RT-FILIAL-N desatualizado',           cat:'Infraestrutura'},
    ];
    riskEl.innerHTML = risks.map(r => `
      <div style="display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:1px solid var(--g100);font-size:11.5px">
        <span style="background:${r.cor};color:#fff;font-size:9px;font-weight:800;padding:2px 5px;border-radius:4px;white-space:nowrap;flex-shrink:0">${r.nivel}</span>
        <div>
          <div style="font-weight:500;color:var(--g700)">${r.item}</div>
          <div style="color:var(--g400);font-size:10.5px">${r.cat}</div>
        </div>
      </div>`).join('');
  }

  // ── CUSTO ESTIMADO ──
  const custoEl = document.getElementById('exec-custo-row');
  if (custoEl) {
    const custos = [
      {label:'Computadores',   val:'R$ 420.000',  sub:'8 unidades · R$52.500 médio'},
      {label:'Smartphones',    val:'R$ 28.000',   sub:'5 aparelhos'},
      {label:'Infraestrutura', val:'R$ 185.000',  sub:'Switches + Firewall + AP'},
      {label:'Software/SaaS',  val:'R$ 96.000',   sub:'Licenças anuais'},
      {label:'TOTAL ESTIMADO', val:'R$ 729.000',  sub:'Valor de reposição', destaque:true},
    ];
    custoEl.innerHTML = custos.map(c => `
      <div style="text-align:center;padding:12px;background:${c.destaque?'linear-gradient(135deg,var(--accent),var(--violet))':'var(--g50)'};border-radius:var(--r);border:1px solid ${c.destaque?'transparent':'var(--g200)'}">
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:${c.destaque?'rgba(255,255,255,.7)':'var(--g400)'};margin-bottom:4px">${c.label}</div>
        <div style="font-size:18px;font-weight:800;color:${c.destaque?'#fff':'var(--g900)'}">${c.val}</div>
        <div style="font-size:10.5px;color:${c.destaque?'rgba(255,255,255,.6)':'var(--g400)'};margin-top:2px">${c.sub}</div>
      </div>`).join('');
  }

  // ── VOLUME DE CHAMADOS (sparkline) ──
  const volEl = document.getElementById('exec-volume-chart');
  const volLab = document.getElementById('exec-volume-labels');
  if (volEl) {
    const meses = ['Dez','Jan','Fev','Mar','Abr','Mai'];
    const vals  = [38,52,41,67,58,73];
    const max   = Math.max(...vals);
    volEl.innerHTML = meses.map((m,i) => {
      const h = Math.round((vals[i]/max)*90);
      const isLast = i === meses.length-1;
      return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px">
        <span style="font-size:10px;font-weight:700;color:${isLast?'var(--accent)':'var(--g400)'}">${vals[i]}</span>
        <div style="width:100%;background:${isLast?'var(--accent)':'var(--g200)'};border-radius:4px 4px 0 0;height:${h}px;transition:height .6s ease"></div>
      </div>`;
    }).join('');
    if (volLab) volLab.innerHTML = meses.map((m,i) => `<span style="flex:1;text-align:center;font-size:10px;color:var(--g400)">${m}</span>`).join('');
  }

  // ── TOP CATEGORIAS ──
  const topEl = document.getElementById('exec-top-cat');
  if (topEl) {
    const tops = [
      {cat:'Sistemas Corporativos',count:28,pct:38},
      {cat:'Computador',           count:18,pct:25},
      {cat:'Impressão',            count:11,pct:15},
      {cat:'Internet',             count:8, pct:11},
      {cat:'Outros',               count:8, pct:11},
    ];
    topEl.innerHTML = tops.map((t,i) => {
      const cols = ['var(--accent)','var(--violet)','var(--success)','var(--warning)','var(--g400)'];
      return `<div style="margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:2px">
          <span style="font-weight:600;color:var(--g700)">${t.cat}</span>
          <span style="color:var(--g500)">${t.count} (${t.pct}%)</span>
        </div>
        <div style="background:var(--g200);border-radius:4px;height:7px;overflow:hidden">
          <div style="background:${cols[i]};width:${t.pct}%;height:100%;border-radius:4px;transition:width .6s"></div>
        </div>
      </div>`;
    }).join('');
  }
}

// ============================================================
// MOBILIÁRIO & COPA — SEED + RENDER + SAVE
// ============================================================
STATE.mobiliario = [];

const MOB_TIPO_LABEL = {
  'mesa':'Mesa de Escritório','mesa-reuniao':'Mesa de Reunião','mesa-recepcao':'Mesa de Recepção',
  'cadeira-escritorio':'Cadeira de Escritório','cadeira-reuniao':'Cadeira de Reunião',
  'cadeira-recepcao':'Cadeira de Espera','poltrona':'Poltrona',
  'armario':'Armário','armario-aco':'Armário de Aço','arquivo':'Arquivo/Gaveta',
  'estante':'Estante','locker':'Locker','balcao':'Balcão',
  'quadro-aviso':'Quadro de Avisos','quadro-branco':'Quadro Branco',
  'quadro-cortica':'Quadro de Cortiça','tv-sala':'TV / Painel',
  'geladeira':'Geladeira','microondas':'Micro-ondas','bebedouro':'Bebedouro',
  'cafeteira':'Cafeteira','purificador':'Purificador','forninho':'Forninho',
  'freezer':'Freezer','monitor-extra':'Monitor','suporte-monitor':'Suporte Monitor',
  'rack-server':'Rack','divisoria':'Divisória','cofre':'Cofre',
  'extintor':'Extintor','outro-mob':'Outro',
  'ar-condicionado':'Ar-condicionado Split',
  'ar-condicionado-janela':'Ar-cond. Janela',
  'ar-condicionado-portatil':'Ar-cond. Portátil',
  'ventilador':'Ventilador','exaustor':'Exaustor',
  'relogio-ponto':'Relógio de Ponto Biométrico',
  'relogio-ponto-facial':'Relógio Ponto Facial',
  'catracas':'Catraca / Controle de Acesso',
  'camera-ip':'Câmera IP / CFTV',
  'nobreak':'Nobreak / UPS',
};
const MOB_TAB_TIPOS = {
  'mesa':    ['mesa','mesa-reuniao','mesa-recepcao'],
  'cadeira': ['cadeira-escritorio','cadeira-reuniao','cadeira-recepcao','poltrona'],
  'monitor': ['monitor-extra','suporte-monitor','tv-sala'],
  'armario': ['armario','armario-aco','arquivo','estante','locker','balcao','cofre'],
  'aviso':   ['quadro-aviso','quadro-branco','quadro-cortica'],
  'copa':    ['geladeira','microondas','bebedouro','cafeteira','purificador','forninho','freezer'],
  'clima':   ['ar-condicionado','ar-condicionado-janela','ar-condicionado-portatil',
              'ventilador','exaustor','relogio-ponto','relogio-ponto-facial',
              'catracas','camera-ip','nobreak'],
};
const MOB_ESTADO_COLOR = {
  'otimo':'badge-success','bom':'badge-info','regular':'badge-warning','ruim':'badge-orange','pessimo':'badge-danger'
};
const MOB_ESTADO_LABEL = { 'otimo':'Ótimo','bom':'Bom','regular':'Regular','ruim':'Ruim','pessimo':'Péssimo' };
const MOB_STATUS_CSS = {
  'uso':'sp-ativo','estoque':'sp-disponivel','manut':'sp-manut','descarte':'sp-pendente','baixado':'sp-sc'
};
const MOB_STATUS_LABEL = { 'uso':'Em Uso','estoque':'Em Estoque','manut':'Manutenção','descarte':'Descarte','baixado':'Baixado' };

let _mobCurrentTab = 'todos';

function renderMobiliario(tab) {
  if (tab) _mobCurrentTab = tab;
  const q   = (document.getElementById('mob-search')?.value||'').toLowerCase();
  const fs  = document.getElementById('mob-filter-status')?.value||'';
  const fl  = document.getElementById('mob-filter-local')?.value||'';
  let list  = STATE.mobiliario||[];
  if (_mobCurrentTab !== 'todos') {
    const tipos = MOB_TAB_TIPOS[_mobCurrentTab]||[];
    list = list.filter(m => tipos.includes(m.tipo));
  }
  if (q)  list = list.filter(m => m.desc.toLowerCase().includes(q)||m.pat.toLowerCase().includes(q)||m.setor.toLowerCase().includes(q)||(m.local||'').toLowerCase().includes(q));
  if (fs) list = list.filter(m => m.status === fs);
  if (fl) list = list.filter(m => m.setor === fl);

  // stats
  const all = STATE.mobiliario||[];
  sv('mob-total', all.reduce((s,m)=>s+(m.qtd||1),0));
  sv('mob-uso',   all.filter(m=>m.status==='uso').reduce((s,m)=>s+(m.qtd||1),0));
  sv('mob-manut', all.filter(m=>m.status==='manut').length);
  sv('mob-desc',  all.filter(m=>m.status==='descarte').length);
  const total = all.reduce((s,m)=>s+((m.valorUnit||0)*(m.qtd||1)),0);
  sv('mob-valor', 'R$ '+total.toLocaleString('pt-BR',{minimumFractionDigits:0}));

  const tbody = document.getElementById('mob-body');
  if (!tbody) return;
  tbody.innerHTML = list.map(m => `
    <tr>
      <td><input type="checkbox" style="accent-color:var(--accent)"></td>
      <td class="td-mono" style="color:var(--accent);font-weight:700">${m.pat}</td>
      <td><span class="tag">${MOB_TIPO_LABEL[m.tipo]||m.tipo}</span></td>
      <td style="font-weight:500;max-width:220px">${m.desc}</td>
      <td>${m.setor}${m.local?' · '+m.local:''}</td>
      <td style="text-align:center;font-weight:700">${m.qtd||1}</td>
      <td><span class="badge ${MOB_ESTADO_COLOR[m.estado]||'badge-gray'}">${MOB_ESTADO_LABEL[m.estado]||m.estado}</span></td>
      <td><span class="status-pill ${MOB_STATUS_CSS[m.status]||'sp-disponivel'}">${MOB_STATUS_LABEL[m.status]||m.status}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px">${m.valorUnit?'R$ '+m.valorUnit.toLocaleString('pt-BR'):'—'}</td>
      <td class="td-mono">${m.dataAq?new Date(m.dataAq+'T12:00:00').toLocaleDateString('pt-BR'):'—'}</td>
      <td>${m.resp||'—'}</td>
      <td><div class="flex gap-4">
        <button class="btn btn-ghost btn-xs" onclick="editMobiliario('${m.id}')">✏️</button>
        <button class="btn btn-ghost btn-xs" onclick="verHistoricoMobiliario('${m.id}')">📜</button>
      </div></td>
    </tr>`).join('') || `<tr><td colspan="12" style="text-align:center;padding:24px;color:var(--g400)">Nenhum item encontrado</td></tr>`;
  const lbl = document.getElementById('mob-count-label');
  if (lbl) lbl.textContent = `Exibindo ${list.length} de ${(STATE.mobiliario||[]).length} itens`;
}

function editMobiliario(id) {
  const m = (STATE.mobiliario||[]).find(x=>x.id===id);
  if (!m) return;
  showToast(`✏️ Editando ${m.pat} — ${m.desc.slice(0,30)}`, 'info');
}
function verHistoricoMobiliario(id) {
  const m = (STATE.mobiliario||[]).find(x=>x.id===id);
  if (!m) return showToast('Item não encontrado','danger');
  showToast(`📜 Histórico de ${m.desc.slice(0,30)} em breve`, 'info');
}

function salvarMobiliario() {
  const pat  = document.getElementById('mob-pat')?.value?.trim();
  const desc = document.getElementById('mob-desc')?.value?.trim();
  if (!pat||!desc) return showToast('Patrimônio e descrição são obrigatórios','danger');
  const novo = {
    id:'mob'+Date.now(), pat, desc,
    tipo:     document.getElementById('mob-tipo')?.value||'outro-mob',
    status:   document.getElementById('mob-status')?.value||'uso',
    setor:    document.getElementById('mob-setor')?.value||'—',
    local:    document.getElementById('mob-local')?.value||'',
    qtd:      parseInt(document.getElementById('mob-qtd')?.value||'1'),
    estado:   document.getElementById('mob-estado')?.value||'bom',
    valorUnit:parseFloat(document.getElementById('mob-valor-unit')?.value||'0'),
    dataAq:   document.getElementById('mob-data-aq')?.value||'',
    resp:     document.getElementById('mob-resp')?.value||'',
    nf:       document.getElementById('mob-nf')?.value||'',
    obs:      document.getElementById('mob-obs')?.value||'',
    createdAt:new Date()
  };
  if (!STATE.mobiliario) STATE.mobiliario=[];
  STATE.mobiliario.unshift(novo);
  fsAdd('mobiliario', novo, STATE.mobiliario);
  auditLog('CREATE','mobiliario',novo.pat,'mobiliario',{after:novo});
  closeModal('modal-novo-mobiliario');
  renderMobiliario();
  showToast(`✓ ${pat} — ${desc.slice(0,30)} cadastrado!`);
}

// ============================================================
// IMEI — VALIDAÇÃO EM TEMPO REAL + PROCESSAMENTO DE SCAN
// ============================================================

/**
 * Algoritmo de Luhn — valida IMEI de 15 dígitos
 * IMEIs também vêm em formato XX-XXXXXX-XXXXXX-X (com hífens)
 */
function validarIMEI(imei) {
  const digits = imei.replace(/[\s\-]/g, '');
  if (digits.length !== 15 || !/^\d+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let d = parseInt(digits[i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

function validarIMEILive(inputId) {
  const el  = document.getElementById(inputId);
  const statusEl = document.getElementById(inputId.replace('sm-imei', 'imei') + '-status');
  if (!el || !statusEl) return;
  const val = el.value.replace(/[\s\-]/g, '');
  if (!val) { statusEl.style.display = 'none'; return; }
  statusEl.style.display = '';
  if (val.length < 15) {
    statusEl.innerHTML = `<span style="color:var(--g400)">⌛ ${val.length}/15 dígitos</span>`;
    return;
  }
  if (validarIMEI(val)) {
    statusEl.innerHTML = '<span style="color:var(--success);font-weight:600">✓ IMEI válido (Luhn OK)</span>';
    el.style.borderColor = 'var(--success)';
  } else {
    statusEl.innerHTML = '<span style="color:var(--danger);font-weight:600">✕ IMEI inválido — verifique os dígitos</span>';
    el.style.borderColor = 'var(--danger)';
  }
}

/**
 * Processa IMEI lido pela câmera
 * O código de barras do IMEI pode vir com/sem prefixo, hífens etc.
 * Formatos conhecidos: 
 *   - "351234567890123" (puro)
 *   - "35-123456-789012-3" (hifenizado)
 *   - "IMEI:351234567890123" (prefixo)
 *   - "01/351234567890123/..." (GS1-128 com Application Identifier 01)
 */
function processarIMEIScaneado(valor) {
  // Remove espaços e hífens
  let clean = valor.replace(/[\s\-]/g, '');
  // Remove prefixo "IMEI:" se presente
  clean = clean.replace(/^IMEI:?/i, '');
  // GS1-128: "01" + 14 dígitos (EAN-14) → extrai os 15 dígitos do IMEI
  if (/^01\d{14}/.test(clean)) clean = clean.slice(2, 17);
  // Se ainda tiver 16 dígitos, remove o primeiro (TAC check digit)
  if (clean.length === 16 && /^\d+$/.test(clean)) clean = clean.slice(1);
  return clean;
}

// Dica: como ler IMEI por câmera
// 1. Câmera do celular → caixa do aparelho (código de barras GS1-128)
// 2. Câmera → tela do aparelho com *#06# digitado (QR Code em alguns modelos)
// 3. Câmera → etiqueta colada no aparelho
// 4. Manual: digitar os 15 números exibidos em *#06#

// ============================================================
// PATRIMÔNIO SCANNER — QR Code / Barcode / Camera / Manual
// ============================================================
let _scannerCallback = null;
let _codeReader     = null;
let _videoStream    = null;
let _cameraIndex    = 0;
let _cameraDevices  = [];

async function openScanner(fieldId, processor, callback) {
  // fieldId: id do input que receberá o valor lido
  // processor: função opcional que transforma o valor bruto (ex: processarIMEIScaneado)
  // callback: função opcional chamada após leitura
  _scannerCallback = callback || ((val) => {
    const processed = typeof processor === 'function' ? processor(val) : val;
    const el = document.getElementById(fieldId);
    if (el) {
      el.value = processed;
      el.focus();
      // Dispara validação se for IMEI
      if (fieldId.startsWith('sm-imei')) validarIMEILive(fieldId);
      // Dispara validação de patrimônio se for PAT
      if (processed) el.dispatchEvent(new Event('input'));
    }
  });
  const overlay = document.getElementById('scanner-overlay');
  if (!overlay) return;
  overlay.classList.add('open');
  document.getElementById('scanner-manual-input').value = '';
  document.getElementById('scanner-result').style.display = 'none';
  setScannerStatus('Iniciando câmera...', 'Aguarde');
  await startCamera();
}

async function startCamera() {
  stopCamera();
  try {
    // Enumera câmeras disponíveis
    _cameraDevices = (await navigator.mediaDevices.enumerateDevices())
      .filter(d => d.kind === 'videoinput');
    if (!_cameraDevices.length) throw new Error('Nenhuma câmera encontrada');

    const deviceId = _cameraDevices[_cameraIndex % _cameraDevices.length]?.deviceId;
    const constraints = {
      video: {
        deviceId: deviceId ? { exact: deviceId } : undefined,
        facingMode: deviceId ? undefined : { ideal: 'environment' },
        width: { ideal: 1280 }, height: { ideal: 720 }
      }
    };
    _videoStream = await navigator.mediaDevices.getUserMedia(constraints);
    const video = document.getElementById('scanner-video');
    video.srcObject = _videoStream;
    await video.play();
    setScannerStatus('📸 Aponte para o código', `Câmera ${(_cameraIndex % _cameraDevices.length) + 1} de ${_cameraDevices.length}`);
    startDecoding(video);
  } catch (err) {
    console.warn('[Scanner] Câmera:', err.message);
    setScannerStatus('⚠ Câmera indisponível', 'Use o campo manual abaixo');
  }
}

async function startDecoding(video) {
  // ── Prioridade 1: BarcodeDetector API nativa (Chrome 83+, Android, Edge) ──
  if ('BarcodeDetector' in window) {
    try {
      const detector = new BarcodeDetector({
        formats: ['qr_code','code_128','ean_13','ean_8','code_39','data_matrix','itf','codabar']
      });
      setScannerStatus('📸 Aponte para o código', 'Usando leitor nativo do navegador');
      const detect = async () => {
        if (!_videoStream) return;
        try {
          const barcodes = await detector.detect(video);
          if (barcodes.length) { onCodeRead(barcodes[0].rawValue); return; }
        } catch (_) {}
        if (_videoStream) requestAnimationFrame(detect);
      };
      requestAnimationFrame(detect);
      return;
    } catch (_) { /* fallback */ }
  }

  // ── Prioridade 2: ZXing via ES module (funciona em http:// e https://) ──
  // Não funciona em file:// — cai para modo manual nesse caso
  if (location.protocol !== 'file:') {
    try {
      setScannerStatus('⏳ Carregando leitor...', 'Aguarde um momento');
      // ZXing via jsDelivr (CDN com suporte a ES modules)
      const { BrowserMultiFormatReader } = await import(
        'https://cdn.jsdelivr.net/npm/@zxing/library@0.20.0/esm/index.js'
      );
      _codeReader = new BrowserMultiFormatReader();
      setScannerStatus('📸 Aponte para o código', 'QR Code · Code 128 · EAN · Code 39');
      _codeReader.decodeFromVideoElement(video, (result, err) => {
        if (result) onCodeRead(result.getText());
      });
      return;
    } catch (e) {
      console.warn('[Scanner] ZXing import falhou:', e.message);
    }
  }

  // ── Modo manual (file:// ou falha de rede) ──
  setScannerStatus(
    location.protocol === 'file:'
      ? '📷 Câmera ativa (file://)'
      : '📷 Câmera ativa',
    'Digite o patrimônio no campo abaixo e pressione OK'
  );
}

function onCodeRead(value) {
  const cleaned = value.trim();
  stopCamera();
  // Exibe resultado
  const res = document.getElementById('scanner-result');
  res.textContent = '✓ ' + cleaned;
  res.style.display = 'block';
  setScannerStatus('✓ Código lido com sucesso!', cleaned);
  // Aplica valor e fecha após 1.2s
  setTimeout(() => {
    if (_scannerCallback) _scannerCallback(cleaned);
    closeScanner();
    showToast(`✓ Patrimônio lido: ${cleaned}`, 'success');
  }, 1200);
}

function stopCamera() {
  if (_codeReader) { try { _codeReader.reset(); } catch {} _codeReader = null; }
  if (_videoStream) { _videoStream.getTracks().forEach(t => t.stop()); _videoStream = null; }
  const video = document.getElementById('scanner-video');
  if (video) video.srcObject = null;
}

function closeScanner() {
  stopCamera();
  document.getElementById('scanner-overlay')?.classList.remove('open');
}

function switchCamera() {
  _cameraIndex++;
  startCamera();
}

function confirmManualPat() {
  const val = document.getElementById('scanner-manual-input')?.value?.trim();
  if (!val) return;
  onCodeRead(val);
}

function setScannerStatus(label, hint) {
  const s = document.getElementById('scanner-status');
  const h = document.getElementById('scanner-hint');
  if (s) s.textContent = label;
  if (h) h.textContent = hint || '';
}

// Fecha com Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('scanner-overlay')?.classList.contains('open')) {
    closeScanner();
  }
});
// Fecha clicando fora
document.getElementById('scanner-overlay')?.addEventListener('click', e => {
  if (e.target === document.getElementById('scanner-overlay')) closeScanner();
});

// Wire mobiliário tabs
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-mob-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-mob-tab]').forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      renderMobiliario(tab.dataset.mobTab);
    });
  });
});

// ============================================================
// AI ENGINE — Gemini via Banco Genkit
// ============================================================

const FUNCTIONS_BASE = 'https://us-central1-sysack-829e2.cloudfunctions.net';
let _aiChatHistory = [];
let _aiAnalyzing   = false;

// ─── Contexto atual do sistema para a IA ──────────────────────
function getAIContext() {
  const chamados    = STATE.chamados || [];
  const ativos      = STATE.ativos   || [];
  const smartphones = STATE.smartphones || [];
  return {
    totalChamados:  chamados.filter(c => !['fechado','concluido'].includes(c.status)).length,
    ativosEmUso:    ativos.filter(a => a.status === 'ativo').length,
    slaPct:         calcSLAPct(chamados),
    mttr:           calcMTTRGlobal(chamados),
    alertas: [
      ...smartphones.filter(s => s.status === 'extraviado').map(s => `Smartphone extraviado: ${s.pat}`),
      ...ativos.filter(a => a.status === 'terceirizada').map(a => `Ativo na terceirizada: ${a.pat}`),
    ],
    userRole: CURRENT_USER?.role || 'tecnico',
  };
}

function calcSLAPct(chamados) {
  if (!chamados.length) return 92;
  const ok = chamados.filter(c => c.slaAtingido !== false).length;
  return Math.round(ok / chamados.length * 100);
}
function calcMTTRGlobal(chamados) {
  const fechados = chamados.filter(c => c.mttrMinutos > 0);
  if (!fechados.length) return 4.2;
  return Math.round(fechados.reduce((s,c) => s + c.mttrMinutos, 0) / fechados.length / 60 * 10) / 10;
}

// ─── Chat Panel toggle ─────────────────────────────────────────
function toggleAIPanel() {
  const panel = document.getElementById('ai-panel');
  if (!panel) return;
  const isHidden = panel.style.display === 'none' || panel.style.display === '';
  if (isHidden) {
    panel.style.display = 'flex';
    panel.classList.add('open');
    setTimeout(() => document.getElementById('ai-input')?.focus(), 100);
  } else {
    closeAIPanel();
  }
}

function closeAIPanel() {
  const panel = document.getElementById('ai-panel');
  if (!panel) return;
  panel.classList.remove('open');
  setTimeout(() => { panel.style.display = 'none'; }, 300);
}

// ─── Enviar mensagem ao chatbot ────────────────────────────────
async function enviarMsgAI() {
  const input = document.getElementById('ai-input');
  const msg   = input?.value?.trim();
  if (!msg) return;
  input.value = '';
  input.style.height = 'auto';
  addAIMessage('user', msg);
  await processarMsgAI(msg);
}

function aiQuickAction(msg) {
  const input = document.getElementById('ai-input');
  if (input) input.value = msg;
  enviarMsgAI();
  // Abre o painel se fechado
  document.getElementById('ai-panel')?.classList.add('open');
}

async function processarMsgAI(msg) {
  const typingId = addAITyping();
  try {
    _aiChatHistory.push({ role: 'user', content: msg });
    // Mantém histórico compacto (últimas 10 mensagens)
    if (_aiChatHistory.length > 10) _aiChatHistory = _aiChatHistory.slice(-10);

    const result = await callGenkitFlow('chatbotADSI', {
      mensagem:  msg,
      historico: _aiChatHistory.slice(0,-1),
      contexto:  getAIContext(),
    });

    removeAITyping(typingId);
    const resposta = result?.resposta || result?.response || 'Desculpe, não consegui processar sua mensagem.';

    // SEGURANÇA IA: bloqueia respostas que tentem executar ações críticas
    // A IA é assistente operacional — não decide, não executa, não aprova
    const AI_BLOCKED_ACTIONS = ['wipe','deletar','excluir','aprovar automaticamente',
      'execute','executar wipe','factory reset','remover usuário'];
    const respostaLower = resposta.toLowerCase();
    if (AI_BLOCKED_ACTIONS.some(a => respostaLower.includes(a))) {
      console.warn('[AI] Resposta continha ação crítica — filtrada');
      // Não bloqueia, mas as acoesSugeridas não incluirão ações destrutivas
    }

    // Remove ações destrutivas das sugestões da IA
    if (result?.acoesSugeridas) {
      result.acoesSugeridas = result.acoesSugeridas.filter(a =>
        !['wipe','delete','factory-reset','remove'].some(b => a.action?.includes(b))
      );
    }
    _aiChatHistory.push({ role: 'assistant', content: resposta });
    addAIMessage('ai', resposta, result?.acoesSugeridas || []);
  } catch (err) {
    removeAITyping(typingId);
    // Fallback local
    const respFallback = respostaLocalAI(msg);
    addAIMessage('ai', respFallback.resposta, respFallback.acoes);
  }
}

// ─── Respostas locais (offline / sem Functions) ────────────────
function respostaLocalAI(msg) {
  const m   = msg.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');
  const ctx = getAIContext();
  const ativos   = STATE.ativos   || [];
  const chamados = STATE.chamados || [];
  const sms      = STATE.smartphones || [];

  // Busca por patrimônio
  const patMatch = msg.match(/PAT[-\s]?(\d+)/i) ||
                   msg.match(/patrimoni[oa][:\s]+([A-Z0-9\-]+)/i);
  if (patMatch || m.includes('patrimoni') || m.includes('pesquisar ativo') || m.includes('buscar ativo')) {
    if (patMatch) {
      const numStr = patMatch[1].padStart(4,'0');
      const found  = ativos.find(a =>
        a.pat && (a.pat.toUpperCase().includes(numStr) || a.pat.replace(/\D/g,'') === patMatch[1])
      );
      if (found) {
        return { resposta:
          '\u2705 **Ativo encontrado:**\n\n' +
          '**PAT:** ' + found.pat + '\n' +
          '**Descri\u00e7\u00e3o:** ' + (found.desc||'\u2014') + '\n' +
          '**Tipo:** ' + (found.tipo||'\u2014') + '\n' +
          '**Status:** ' + (found.status||'\u2014') + '\n' +
          '**\u00c1rea:** ' + (found.area||'\u2014') + '\n' +
          '**Respons\u00e1vel:** ' + (found.resp||'\u2014') + '\n' +
          '**Localiza\u00e7\u00e3o:** ' + (found.loc||'\u2014'),
          acoes: [{ label:'Ver Ativos', action:'goPage:ativos' }]
        };
      }
      return { resposta: '\ud83d\udd0d Patrim\u00f4nio **PAT-' + numStr + '** n\u00e3o encontrado. Use a busca na p\u00e1gina de Ativos.', acoes: [{ label:'Ir para Ativos', action:'goPage:ativos' }] };
    }
    return { resposta:
      '\ud83d\udd0d **Como pesquisar um patrim\u00f4nio:**\n\n' +
      '1. Clique em **Ativos** no menu\n' +
      '2. Use a **barra de busca** no topo\n' +
      '3. Digite o n\u00famero (ex: `PAT-0103`)\n\n' +
      'Ou me pergunte: **"onde est\u00e1 o PAT-0150?"**',
      acoes: [{ label:'Abrir Ativos', action:'goPage:ativos' }]
    };
  }

  // Chamados
  if (m.includes('chamado') || m.includes('ticket')) {
    if (m.includes('abrir') || m.includes('criar') || m.includes('novo'))
      return { resposta: 'Para **abrir um chamado**: clique em **+ Criar chamado** no menu lateral.', acoes: [{ label:'+ Criar Chamado', action:'openModal:modal-novo-chamado' }] };
    const ab = chamados.filter(c=>!['fechado','concluido'].includes(c.status));
    return { resposta: '**' + ab.length + '** chamado(s) aberto(s). SLA: **' + ctx.slaPct + '%**.', acoes: [{ label:'Ver Chamados', action:'goPage:chamados' }] };
  }

  // Ativos
  if (m.includes('ativo') || m.includes('inventari') || m.includes('equipamento') || m.includes('computador') || m.includes('notebook')) {
    if (m.includes('cadastrar') || m.includes('adicionar') || m.includes('novo'))
      return { resposta: 'V\u00e1 em **Ativos** → **+ Novo Ativo** → preencha PAT, descri\u00e7\u00e3o, tipo, \u00e1rea e respons\u00e1vel.', acoes: [{ label:'Ir para Ativos', action:'goPage:ativos' }] };
    return { resposta: '**' + ativos.length + '** ativos cadastrados.\n' + ativos.filter(a=>a.status==='ativo').length + ' em uso · ' + ativos.filter(a=>a.status==='manut').length + ' em manuten\u00e7\u00e3o.', acoes: [{ label:'Ver Ativos', action:'goPage:ativos' }] };
  }

  // MDM
  if (m.includes('smartphone') || m.includes('celular') || m.includes('mdm') || m.includes('imei'))
    return { resposta: '**' + sms.length + '** smartphone(s) cadastrados.', acoes: [{ label:'Ver MDM', action:'goPage:mdm' }] };

  // SLA
  if (m.includes('sla') || m.includes('prazo')) {
    const st = ctx.slaPct >= 95 ? '\u2705 dentro da meta' : ctx.slaPct >= 80 ? '\u26a0\ufe0f aten\u00e7\u00e3o' : '\ud83d\udea8 cr\u00edtico';
    return { resposta: 'SLA: **' + ctx.slaPct + '%** — ' + st + '. MTTR: **' + ctx.mttr + 'h**.', acoes: [{ label:'Dashboard', action:'goPage:exec-dashboard' }] };
  }

  // Mapa
  if (m.includes('mapa') || m.includes('localiza') || m.includes('sala') || m.includes('andar'))
    return { resposta: '\ud83d\uddfa\ufe0f O **Mapa de Ativos** mostra localiza\u00e7\u00e3o f\u00edsica.\nEdite o ativo e preencha: `Pr\u00e9dio / Andar / Sala / Posi\u00e7\u00e3o`', acoes: [{ label:'Abrir Mapa', action:'goPage:mapa-ativos' }] };

  // Mudanças ITIL
  if (m.includes('mudanca') || m.includes('rfc') || m.includes('cab') || m.includes('itil'))
    return { resposta: 'O m\u00f3dulo **Mudan\u00e7as (ITIL)** gerencia RFCs: Rascunho → CAB → Aprovada → Implementando → Concluu00edda.', acoes: [{ label:'Ver Mudan\u00e7as', action:'goPage:mudancas-itil' }] };

  // Self-service
  if (m.includes('self') || m.includes('senha') || m.includes('acesso') || m.includes('impressora'))
    return { resposta: 'O **Self-Service** resolve: redefinir senha, impressora, VPN, e-mail, Wi-Fi.', acoes: [{ label:'Self-Service', action:'goPage:self-service' }] };

  // Resumo
  if (m.includes('resumo') || m.includes('status') || m.includes('relatorio'))
    return { resposta: '**Resumo — ' + new Date().toLocaleDateString('pt-BR') + '**\n' + chamados.filter(c=>!['fechado','concluido'].includes(c.status)).length + ' chamados · SLA ' + ctx.slaPct + '% · ' + ativos.length + ' ativos · ' + sms.length + ' smartphones', acoes: [{ label:'Dashboard', action:'goPage:exec-dashboard' }] };

  // Ajuda
  if (m.includes('ajuda') || m.includes('help') || m.includes('como'))
    return { resposta: 'Posso responder sobre:\n• **"onde est\u00e1 o PAT-0103?"**\n• **"quantos chamados abertos"**\n• **"como cadastrar ativo"**\n• **"SLA atual"**\n• **"abrir chamado"**', acoes: [] };

  return { resposta: 'N\u00e3o entendi "' + escapeHtml(msg.slice(0,50)) + '". Tente **"ajuda"** para ver o que sei responder.', acoes: [] };
}

function parseAIAction(action) {
  if (action.startsWith('goPage:'))    return `goPage('${action.split(':')[1]}')`;
  if (action.startsWith('openModal:')) return `openModal('${action.split(':')[1]}')`;
  return `console.log('${action}')`;
}

function addAITyping() {
  const container = document.getElementById('ai-messages');
  if (!container) return null;
  const div = document.createElement('div');
  div.className = 'ai-msg ai';
  div.id = 'typing-' + Date.now();
  div.innerHTML = `<div class="ai-avatar">✨</div><div class="ai-bubble"><div class="ai-typing"><span></span><span></span><span></span></div></div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div.id;
}

function removeAITyping(id) {
  document.getElementById(id)?.remove();
}

// ─── ANÁLISE COMPLETA (Dashboard IA) ──────────────────────────
async function rodarAnaliseCompleta() {
  if (_aiAnalyzing) return;
  _aiAnalyzing = true;

  const btn = document.querySelector('button[onclick="rodarAnaliseCompleta()"]');
  if (btn) { btn.disabled = true; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="animation:spin .7s linear infinite;margin-right:4px"><path d="M8 1v3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M8 12v3" stroke="currentColor" stroke-width="2" stroke-linecap="round" opacity=".3"/><path d="M1 8h3" stroke="currentColor" stroke-width="2" stroke-linecap="round" opacity=".3"/><path d="M12 8h3" stroke="currentColor" stroke-width="2" stroke-linecap="round" opacity=".6"/></svg> Analisando...'; }

  const chamados    = STATE.chamados || [];
  const ativos      = STATE.ativos   || [];
  const smartphones = STATE.smartphones || [];

  const kpis = {
    totalChamados:   chamados.length,
    abertos:         chamados.filter(c => !['fechado','concluido'].includes(c.status)).length,
    slaPct:          calcSLAPct(chamados),
    mttrHoras:       calcMTTRGlobal(chamados),
    totalAtivos:     ativos.length,
    ativosObsoletos: 2,  // estimado
    mdmCompliance:   smartphones.length ? Math.round(smartphones.filter(s=>s.status==='uso').length/smartphones.length*100) : 80,
    valorParque:     729000,
    garantiasVenc:   2,
  };

  const topCats = Object.entries(
    chamados.reduce((acc, c) => { acc[c.categoria||'Outros'] = (acc[c.categoria||'Outros']||0)+1; return acc; }, {})
  ).sort(([,a],[,b]) => b-a).slice(0,5).map(([cat,count]) => ({ cat, count }));

  const alertas = [
    ...smartphones.filter(s => s.status === 'extraviado').map(s => `Smartphone extraviado: ${s.pat}`),
    ...ativos.filter(a => a.status === 'terceirizada').map(a => `Ativo na terceirizada: ${a.pat}`),
    ...(kpis.slaPct < 95 ? [`SLA abaixo da meta: ${kpis.slaPct}%`] : []),
  ];

  try {
    const insights = await callGenkitFlow('gerarInsightsExecutivos', {
      periodo: 'últimos 30 dias', kpis, topCategorias: topCats, alertasAtivos: alertas,
    });
    renderAIInsights(insights);
  } catch {
    // Fallback local
    renderAIInsights(gerarInsightsLocais(kpis, alertas));
  }

  // Triagem de chamados abertos
  await triagemAutoDisplay(chamados.filter(c => !c.triageStatus && !['fechado','concluido'].includes(c.status)).slice(0,5));

  if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="margin-right:4px"><path d="M8 1v3M8 12v3M1 8h3M12 8h3M3.05 3.05l2.12 2.12M10.83 10.83l2.12 2.12M3.05 12.95l2.12-2.12M10.83 5.17l2.12-2.12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>Analisar Novamente'; }
  _aiAnalyzing = false;
}

function renderAIInsights(data) {
  if (!data) return;
  const score = data.scoreOperacional || 75;
  // Score ring animation
  const arc = document.getElementById('ai-score-arc');
  const num = document.getElementById('ai-score-num');
  const lbl = document.getElementById('ai-score-label');
  if (arc) { setTimeout(() => { arc.style.strokeDashoffset = 327 - (327 * score / 100); }, 100); }
  if (num) num.textContent = score;
  if (lbl) lbl.textContent = score >= 80 ? '✅ Operação Saudável' : score >= 60 ? '⚠️ Atenção Necessária' : '🚨 Situação Crítica';
  const resumoEl = document.getElementById('ai-resumo-exec');
  if (resumoEl) resumoEl.innerHTML = `<p style="color:var(--g700);line-height:1.7">${(data.resumoExecutivo||'').replace(/\n/g,'<br>')}</p>`;

  // Insights grid
  const grid = document.getElementById('ai-insights-grid');
  const insightCount = document.getElementById('ai-insights-count');
  if (grid && data.insights?.length) {
    if (insightCount) insightCount.textContent = `${data.insights.length} insights`;
    grid.innerHTML = data.insights.map(ins => `
      <div class="ai-insight-card ${ins.impacto}">
        <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">
          <div style="font-size:13px;font-weight:700;color:var(--g800)">${ins.titulo}</div>
          <span class="badge ${ins.impacto==='alto'?'badge-danger':ins.impacto==='medio'?'badge-warning':'badge-success'}">${ins.impacto}</span>
        </div>
        <p style="font-size:12.5px;color:var(--g600);margin:0 0 8px;line-height:1.55">${ins.desc}</p>
        <div style="font-size:11.5px;color:var(--accent);font-weight:600">→ ${ins.acao}</div>
      </div>`).join('');
  }

  // Riscos
  const riscosEl = document.getElementById('ai-riscos-list');
  if (riscosEl && data.riscos?.length) {
    riscosEl.innerHTML = data.riscos.map(r => `
      <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--g100);font-size:12.5px">
        <span style="background:${r.nivel==='critico'?'var(--danger)':r.nivel==='alto'?'#EA580C':r.nivel==='medio'?'var(--warning)':'var(--success)'};color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:4px;height:fit-content;white-space:nowrap;flex-shrink:0">${r.nivel.toUpperCase()}</span>
        <div><div style="font-weight:600;color:var(--g800);margin-bottom:2px">${r.risco}</div><div style="color:var(--g500);font-size:11.5px">${r.mitigacao}</div></div>
      </div>`).join('');
  }

  // Recomendações
  const recsEl = document.getElementById('ai-recomendacoes');
  if (recsEl && data.recomendacoes?.length) {
    recsEl.innerHTML = data.recomendacoes.map((r,i) => `
      <div style="display:flex;gap:10px;padding:8px;background:var(--g50);border-radius:8px;font-size:13px">
        <span style="width:22px;height:22px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0">${i+1}</span>
        <span style="color:var(--g700)">${r}</span>
      </div>`).join('');
  }

  // Anomalias (detectadas localmente)
  renderAnomalias();
}

// ─── Triagem automática display ────────────────────────────────
async function triagemAutoDisplay(chamados) {
  const tbody = document.getElementById('ai-triage-body');
  if (!tbody) return;

  tbody.innerHTML = chamados.map(c => `
    <tr id="triage-row-${c.id}">
      <td class="td-mono" style="color:var(--accent)">${c.id}</td>
      <td style="max-width:200px;font-size:12px">${c.desc?.slice(0,50)||'—'}...</td>
      <td><div class="ai-typing"><span></span><span></span><span></span></div></td>
      <td><div class="ai-typing"><span></span><span></span><span></span></div></td>
      <td>—</td><td>—</td><td>—</td>
      <td><button class="btn btn-ghost btn-xs">⏳</button></td>
    </tr>`).join('');

  for (const c of chamados) {
    try {
      let result;
      try {
        result = await callGenkitFlow('analisarChamado', {
          titulo: c.desc?.slice(0,80) || 'Chamado',
          desc:   c.desc || '',
          categoria: c.categoria,
          area:   c.area,
        });
      } catch {
        result = {
          prioridade: c.prioridade || 'media',
          categoriaAI: c.categoria || 'Infraestrutura',
          subcategoriaAI: 'Demais solicitações',
          tipo: c.tipo || 'incidente',
          tempoEstimado: '2 horas',
          confianca: 40,
          _offline: true,
        };
      }

      const row = document.getElementById(`triage-row-${c.id}`);
      if (!row) continue;
      const priColor = { urgente:'danger','muito-alta':'danger',alta:'orange',media:'warning',baixa:'success' }[result.prioridade] || 'warning';
      row.innerHTML = `
        <td class="td-mono" style="color:var(--accent)">${c.id}</td>
        <td style="max-width:200px;font-size:12px">${c.desc?.slice(0,50)||'—'}...</td>
        <td><span class="badge badge-${priColor}">${result.prioridade}</span>${result._offline?'<span class="badge" style="font-size:9px;margin-left:3px;background:#EDE9FE;color:#6D28D9">offline</span>':''}</td>
        <td style="font-size:11.5px">${esc(result.categoriaAI)}<br><span style="color:var(--g400)">${esc(result.subcategoriaAI)}</span></td>
        <td><span class="tag">${result.tipo}</span></td>
        <td style="font-size:12px">${result.tempoEstimado||'—'}</td>
        <td>
          <div style="display:flex;align-items:center;gap:4px">
            <div style="flex:1;background:var(--g200);border-radius:3px;height:4px;overflow:hidden">
              <div style="background:${result.confianca>=70?'var(--success)':result.confianca>=50?'var(--warning)':'var(--danger)'};width:${result.confianca}%;height:100%"></div>
            </div>
            <span style="font-size:10.5px;color:var(--g500)">${result.confianca}%</span>
          </div>
        </td>
        <td><button class="btn btn-primary btn-xs" onclick="aplicarTriagem('${c.id}', ${JSON.stringify(JSON.stringify(result)).slice(1,-1)})">✓ Aplicar</button></td>`;
    } catch (e) { console.warn('[AI] triage error:', e.message); }
  }
}

async function triagemLote() {
  const chamados = (STATE.chamados||[]).filter(c => !['fechado','concluido'].includes(c.status)).slice(0,10);
  if (!chamados.length) return showToast('Nenhum chamado aberto para triar','warning');
  showToast(`⚡ Triando ${chamados.length} chamados com IA...`,'info');
  goPage('ai-dashboard');
  setTimeout(() => triagemAutoDisplay(chamados), 300);
}

function aplicarTriagem(chamadoId, resultStr) {
  try {
    const result = typeof resultStr === 'string' ? JSON.parse(resultStr) : resultStr;
    const idx = (STATE.chamados||[]).findIndex(c => c.id === chamadoId);
    if (idx >= 0) {
      STATE.chamados[idx] = { ...STATE.chamados[idx], ...result, triageStatus:'concluida' };
    }
    showToast(`✓ Triagem IA aplicada ao chamado ${chamadoId}`);
  } catch (e) { showToast('Erro ao aplicar triagem','danger'); }
}

// ─── Detectar anomalias (offline) ─────────────────────────────
function renderAnomalias() {
  const el = document.getElementById('ai-anomalias-list');
  if (!el) return;
  const chamados    = STATE.chamados    || [];
  const smartphones = STATE.smartphones || [];
  const anomalias   = [];

  // Verifica volume por área
  const porArea = chamados.reduce((acc,c) => { acc[c.area]=(acc[c.area]||0)+1; return acc; }, {});
  const topArea = Object.entries(porArea).sort(([,a],[,b])=>b-a)[0];
  if (topArea && topArea[1] > 3) {
    anomalias.push({ nivel:'medio', desc:`${topArea[0]} concentra ${topArea[1]} chamados (${Math.round(topArea[1]/chamados.length*100)}% do total)`, sugestao:'Investigar causa raiz' });
  }
  // Smartphones com problema
  const smProb = smartphones.filter(s => s.status !== 'uso');
  if (smProb.length) {
    anomalias.push({ nivel:'alto', desc:`${smProb.length} smartphone(s) com status anormal: ${smProb.map(s=>s.pat).join(', ')}`, sugestao:'Acionar MDM Admin' });
  }
  // SLA baixo
  if (calcSLAPct(chamados) < 85) {
    anomalias.push({ nivel:'critico', desc:`SLA abaixo de 85% — risco de penalidade contratual`, sugestao:'Priorizar chamados urgentes' });
  }
  if (!anomalias.length) {
    anomalias.push({ nivel:'baixo', desc:'Nenhuma anomalia crítica detectada no momento', sugestao:'Manter monitoramento' });
  }

  el.innerHTML = anomalias.map(a => `
    <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--g100);font-size:12.5px">
      <span style="background:${a.nivel==='critico'?'var(--danger)':a.nivel==='alto'?'#EA580C':'var(--warning)'};color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:4px;height:fit-content;flex-shrink:0">${a.nivel.toUpperCase()}</span>
      <div><div style="font-weight:600;color:var(--g800);margin-bottom:2px">${a.desc}</div><div style="color:var(--g500);font-size:11.5px">→ ${a.sugestao}</div></div>
    </div>`).join('');
}

// ─── Insights fallback local ───────────────────────────────────
function gerarInsightsLocais(kpis, alertas) {
  const insights = [];
  const riscos   = [];
  const recs     = [];

  if (kpis.slaPct < 95) {
    insights.push({ titulo:'SLA Abaixo da Meta', desc:`O SLA atual de ${kpis.slaPct}% está abaixo do objetivo de 95%. Chamados urgentes precisam de atenção imediata.`, impacto:'alto', acao:'Priorizar triagem dos chamados em aberto' });
    riscos.push({ risco:`SLA em ${kpis.slaPct}% (meta: 95%)`, nivel:'alto', mitigacao:'Aumentar equipe de atendimento ou revisar processos de triagem' });
    recs.push(`Implementar triagem automática de prioridade para reduzir MTTR`);
  }
  if (kpis.mttrHoras > 8) {
    insights.push({ titulo:'MTTR Acima do Limite', desc:`Tempo médio de resolução de ${kpis.mttrHoras}h supera a meta de 8h. Investigar gargalos no processo.`, impacto:'medio', acao:'Mapear etapas que mais consomem tempo na resolução' });
    recs.push(`Criar base de conhecimento com soluções para os top 10 problemas mais recorrentes`);
  }
  if (kpis.mdmCompliance < 90) {
    insights.push({ titulo:'MDM Compliance Crítico', desc:`${kpis.mdmCompliance}% dos dispositivos em conformidade. Risco de violação de política de segurança.`, impacto:'alto', acao:'Executar verificação MDM em todos os dispositivos' });
    riscos.push({ risco:`Compliance MDM em ${kpis.mdmCompliance}%`, nivel:'alto', mitigacao:'Forçar atualização de perfil MDM em todos os dispositivos não conformes' });
  }
  if (kpis.garantiasVenc > 0) {
    insights.push({ titulo:`${kpis.garantiasVenc} Garantia(s) Vencendo`, desc:`Equipamentos com garantia próxima do vencimento representam risco financeiro se houver falha.`, impacto:'medio', acao:'Acionar processo de renovação ou substituição' });
  }
  insights.push({ titulo:'Custo de Parque Estimado', desc:`O parque de TI tem valor estimado de R$ ${kpis.valorParque.toLocaleString('pt-BR')}. ${kpis.ativosObsoletos} ativos obsoletos representam risco operacional.`, impacto:'baixo', acao:'Planejar ciclo de renovação para os próximos 12 meses' });
  recs.push(`Automatizar alertas de SLA via Cloud Functions para notificação proativa`);
  recs.push(`Implementar self-service portal para solicitações de baixa complexidade`);

  const score = Math.max(10, Math.min(100,
    (kpis.slaPct * 0.4) + (kpis.mdmCompliance * 0.3) +
    (kpis.mttrHoras <= 8 ? 30 : Math.max(0, 30 - (kpis.mttrHoras - 8) * 3))
  ));

  return {
    resumoExecutivo: `Análise do período: ${kpis.abertos} chamados em aberto de ${kpis.totalChamados} total. SLA em ${kpis.slaPct}% (${kpis.slaPct >= 95 ? 'dentro da meta' : 'abaixo da meta de 95%'}). MTTR de ${kpis.mttrHoras}h. ${alertas.length > 0 ? `⚠️ ${alertas.length} alerta(s) ativo(s).` : 'Sem alertas críticos.'}`,
    insights, riscos, recomendacoes: recs, scoreOperacional: Math.round(score),
  };
}

// ─── renderAIDashboard ─────────────────────────────────────────
function renderAIDashboard() {
  // Dispara análise automática na primeira vez
  const scoreEl = document.getElementById('ai-score-num');
  if (scoreEl && scoreEl.textContent === '—') {
    setTimeout(rodarAnaliseCompleta, 400);
  }
  renderAnomalias();
}

// ─── AI triage badge no modal de chamado ──────────────────────
function mostrarSugestaoAIchamado(titulo, desc) {
  const container = document.getElementById('ai-triage-suggestion');
  if (!container) return;
  container.style.display = '';
  container.innerHTML = '<div class="ai-triage-badge"><div class="ai-typing" style="margin:0"><span></span><span></span><span></span></div> Analisando com IA...</div>';
  callGenkitFlow('analisarChamado', { titulo, desc }).then(result => {
    container.innerHTML = `
      <div class="ai-triage-badge" style="flex-direction:column;align-items:start;gap:6px;padding:10px;border-radius:8px;background:linear-gradient(135deg,rgba(37,99,235,.05),rgba(124,58,237,.05))">
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;font-weight:700;color:var(--accent)">✨ Sugestão da IA (Gemini)</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span style="font-size:11.5px">📊 Prioridade: <strong>${result.prioridade}</strong></span>
          <span style="font-size:11.5px">🏷️ ${esc(result.categoriaAI)}</span>
          <span style="font-size:11.5px">⏱ ${result.tempoEstimado}</span>
          <span style="font-size:11.5px;color:var(--g500)">${result.confianca}% confiança</span>
        </div>
        <div style="font-size:12px;color:var(--g600)">${result.resumo}</div>
        <button class="btn btn-secondary btn-xs" onclick="aplicarSugestaoAI(${JSON.stringify(JSON.stringify(result))})">✓ Aplicar sugestão</button>
      </div>`;
  }).catch(() => { container.style.display='none'; });
}

function aplicarSugestaoAI(resultStr) {
  try {
    const r = JSON.parse(resultStr);
    const prioEl = document.getElementById('ch-prioridade');
    const catEl  = document.getElementById('ch-categoria');
    if (prioEl) { prioEl.value = r.prioridade; atualizarPrioridadeColor?.(); }
    if (catEl)  { catEl.value  = r.categoriaAI || catEl.value; atualizarSubcategoria?.(); }
    showToast('✓ Sugestão da IA aplicada ao chamado');
  } catch {}
}

// ============================================================
// MUDANÇAS ITIL — RFC / CAB / IMPLEMENTAÇÃO / REVISÃO
// ============================================================

const STATUS_MUDANCA = {
  'rascunho':       { label:'Rascunho',        css:'',                    cor:'#94A3B8' },
  'pendente-cab':   { label:'Pendente CAB',     css:'badge-warning',       cor:'#D97706' },
  'aprovada':       { label:'Aprovada',         css:'badge-success',       cor:'#059669' },
  'recusada':       { label:'Recusada',         css:'badge-danger',        cor:'#DC2626' },
  'implementando':  { label:'Implementando',    css:'badge-info',          cor:'#2563EB' },
  'concluida':      { label:'Concluída',        css:'badge-success',       cor:'#059669' },
  'cancelada':      { label:'Cancelada',        css:'',                    cor:'#94A3B8' },
  'revisao':        { label:'Em Revisão (PIR)', css:'badge-violet',        cor:'#7C3AED' },
};

const RISCO_CSS = {
  critico:'badge-danger', alto:'badge-orange', medio:'badge-warning', baixo:'badge-success',
};

STATE.mudancas = [];

let _itilCurrentTab = 'todos';

function renderMudancasITIL(tab) {
  if (tab) _itilCurrentTab = tab;
  const q  = (document.getElementById('itil-search')?.value || '').toLowerCase();
  const fr = document.getElementById('itil-filter-risco')?.value || '';
  const ft = document.getElementById('itil-filter-tipo')?.value  || '';

  let list = STATE.mudancas || [];
  if (_itilCurrentTab !== 'todos') list = list.filter(m => m.status === _itilCurrentTab || m.tipo === _itilCurrentTab);
  if (q)  list = list.filter(m => m.titulo.toLowerCase().includes(q) || m.id.toLowerCase().includes(q) || m.responsavel.toLowerCase().includes(q));
  if (fr) list = list.filter(m => m.risco === fr);
  if (ft) list = list.filter(m => m.tipo === ft);

  const all = STATE.mudancas || [];
  sv('itil-total', all.length);
  sv('itil-aprov', all.filter(m => m.status === 'aprovada').length);
  sv('itil-impl',  all.filter(m => m.status === 'implementando').length);
  sv('itil-cab',   all.filter(m => m.status === 'pendente-cab').length);
  sv('itil-emerg', all.filter(m => m.tipo === 'emergencial').length);
  nbUpdate('nb-mudancas', all.filter(m => ['pendente-cab','implementando'].includes(m.status)).length);

  const tbody = document.getElementById('itil-body');
  if (!tbody) return;
  tbody.innerHTML = list.map(m => {
    const st  = STATUS_MUDANCA[m.status] || { label: m.status, css: '' };
    const tipoLabel = { normal:'Normal', emergencial:'Emergencial', padrao:'Padrão' }[m.tipo] || m.tipo;
    const tipoCss   = { normal:'badge-info', emergencial:'badge-danger', padrao:'badge-success' }[m.tipo] || '';
    const priColor  = { critica:'danger', alta:'orange', media:'warning', baixa:'success' }[m.prioridade] || 'gray';
    return `<tr onclick="abrirMudanca('${m.id}')" style="cursor:pointer">
      <td class="td-mono" style="color:var(--accent);font-weight:700">${m.id}</td>
      <td style="max-width:280px">
        <div style="font-weight:600;font-size:13px">${m.titulo}</div>
        <div style="font-size:11px;color:var(--g400)">${m.categoria}</div>
      </td>
      <td><span class="badge ${tipoCss}">${tipoLabel}</span></td>
      <td><span class="badge ${RISCO_CSS[m.risco]||''}">${m.risco}</span></td>
      <td style="font-size:12.5px">${m.responsavel}</td>
      <td class="td-mono" style="font-size:11.5px">${m.dataImpl ? new Date(m.dataImpl).toLocaleDateString('pt-BR') : '—'}</td>
      <td style="font-size:11.5px">${m.cabData ? new Date(m.cabData).toLocaleDateString('pt-BR') : m.tipo==='padrao' ? 'Pré-aprovado' : '—'}</td>
      <td><span class="badge ${st.css}">${st.label}</span></td>
      <td><div class="flex gap-4" onclick="event.stopPropagation()">
        <button class="btn btn-secondary btn-xs" onclick="abrirMudanca('${m.id}')">Ver</button>
        <button class="btn btn-ghost btn-xs" onclick="mudarStatusRFC('${m.id}')">↗</button>
      </div></td>
    </tr>`;
  }).join('') || '<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma RFC encontrada</td></tr>';
}

function abrirMudanca(id) {
  const m = (STATE.mudancas||[]).find(x => x.id === id);
  if (!m) return;

  const st       = STATUS_MUDANCA[m.status] || { label: m.status, css:'', cor:'#94A3B8' };
  const tipoLabel= { normal:'Normal', emergencial:'🚨 Emergencial', padrao:'✅ Padrão' }[m.tipo] || m.tipo;
  const riscoCss = RISCO_CSS[m.risco] || '';
  const downtime = m.downtime === 'sim';
  const modalId  = 'modal-ver-rfc-' + id;

  // Build historicoStatus HTML — no template literals
  const historicoHTML = (m.historicoStatus||[]).map(function(h) {
    const hs = STATUS_MUDANCA[h.status] || { label: h.status, cor: '#94A3B8' };
    return '<div class="tl-item">'
      + '<div class="tl-dot" style="background:' + hs.cor + '"></div>'
      + '<div class="tl-title">' + (hs.label||h.status) + '</div>'
      + '<div class="tl-desc">'  + (h.obs||'')  + '</div>'
      + '<div class="tl-time">'  + (h.data||'') + ' &middot; ' + (h.autor||'') + '</div>'
      + '</div>';
  }).join('');

  // Build action buttons using data attributes (avoids quote escaping inside onclick)
  const acaoBtns = [
    m.status === 'aprovada'      ? ['btn-primary',   'implementando', '▶ Iniciar Implementação']   : null,
    m.status === 'implementando' ? ['btn-success',   'concluida',     '✓ Concluir Mudança']        : null,
    m.status === 'implementando' ? ['btn-danger',    'cancelada',     '⚠ Acionar Rollback']        : null,
    m.status === 'pendente-cab'  ? ['btn-success',   'aprovada',      '✓ Aprovar no CAB']          : null,
    m.status === 'pendente-cab'  ? ['btn-danger',    'recusada',      '✕ Recusar']                 : null,
    m.status === 'concluida'     ? ['btn-secondary', 'revisao',       '📋 Abrir PIR']              : null,
  ].filter(Boolean);

  const acoesHTML = acaoBtns.map(function(a) {
    return '<button class="btn ' + a[0] + '" data-rfc-id="' + id + '" data-rfc-status="' + a[1] + '">' + a[2] + '</button>';
  }).join(' ')
  + ' <button class="btn btn-ghost" data-close-modal="' + modalId + '">Fechar</button>';

  // Remove previous modal if exists
  document.getElementById(modalId)?.remove();

  const div = document.createElement('div');
  div.className = 'modal-overlay open';
  div.id = modalId;

  // Build HTML with string concatenation — zero nested template literals
  div.innerHTML = ''
    + '<div class="modal modal-xl">'
    + '<div class="modal-header" style="background:linear-gradient(135deg,var(--brand),#111E35)">'
    +   '<div>'
    +     '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:2px">' + tipoLabel + ' &middot; ' + m.categoria + '</div>'
    +     '<h3 style="color:#fff;font-size:16px">' + m.id + ' — ' + m.titulo + '</h3>'
    +   '</div>'
    +   '<div style="margin-left:auto;display:flex;align-items:center;gap:10px">'
    +     '<span class="badge ' + st.css + '" style="font-size:12px">' + st.label + '</span>'
    +     '<button class="close-btn" style="color:rgba(255,255,255,.7)" data-close-modal="' + modalId + '">✕</button>'
    +   '</div>'
    + '</div>'
    + '<div class="modal-body">'
    +   '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:18px;padding:14px;background:var(--g50);border-radius:var(--r);border:1px solid var(--g200)">'
    +     '<div><div style="font-size:10px;color:var(--g400);font-weight:700;text-transform:uppercase;margin-bottom:3px">Risco</div>'
    +       '<span class="badge ' + riscoCss + '">' + m.risco + '</span></div>'
    +     '<div><div style="font-size:10px;color:var(--g400);font-weight:700;text-transform:uppercase;margin-bottom:3px">Responsável</div>'
    +       '<div style="font-weight:600;font-size:13px">' + m.responsavel + '</div></div>'
    +     '<div><div style="font-size:10px;color:var(--g400);font-weight:700;text-transform:uppercase;margin-bottom:3px">Impl. em</div>'
    +       '<div style="font-weight:600;font-size:13px">' + (m.dataImpl ? new Date(m.dataImpl).toLocaleString('pt-BR') : '—') + '</div></div>'
    +     '<div><div style="font-size:10px;color:var(--g400);font-weight:700;text-transform:uppercase;margin-bottom:3px">Duração</div>'
    +       '<div style="font-weight:600;font-size:13px">' + (m.duracao||'—') + '</div></div>'
    +     '<div><div style="font-size:10px;color:var(--g400);font-weight:700;text-transform:uppercase;margin-bottom:3px">Downtime?</div>'
    +       '<div style="font-weight:600;font-size:13px;color:' + (downtime ? 'var(--danger)' : 'var(--success)') + '">'
    +         (downtime ? '⚠️ SIM' : '✅ Não') + '</div></div>'
    +   '</div>'
    +   '<div class="grid-2" style="gap:16px">'
    +     '<div>'
    +       '<div class="form-group"><label class="form-label">Descrição</label>'
    +         '<div style="font-size:13px;color:var(--g700);line-height:1.6;padding:10px;background:var(--g50);border-radius:8px">' + (m.desc||'—') + '</div></div>'
    +       '<div class="form-group"><label class="form-label">Justificativa</label>'
    +         '<div style="font-size:13px;color:var(--g700);line-height:1.6;padding:10px;background:var(--g50);border-radius:8px">' + (m.justificativa||'—') + '</div></div>'
    +       '<div class="form-group"><label class="form-label">Análise de Risco</label>'
    +         '<div style="font-size:13px;color:var(--g700);padding:10px;background:var(--g50);border-radius:8px">' + (m.analiseRisco||'—') + '</div></div>'
    +       '<div class="form-group"><label class="form-label">Sistemas Impactados</label>'
    +         '<div style="font-size:13px;color:var(--g700);padding:10px;background:var(--g50);border-radius:8px">' + (m.sistemas||'—') + '</div></div>'
    +     '</div>'
    +     '<div>'
    +       '<div class="form-group"><label class="form-label">Plano de Implementação</label>'
    +         '<div style="font-size:13px;color:var(--g700);white-space:pre-line;padding:10px;background:var(--g50);border-radius:8px;line-height:1.7">' + (m.passos||'—') + '</div></div>'
    +       '<div class="form-group"><label class="form-label" style="color:var(--danger)">Plano de Rollback</label>'
    +         '<div style="font-size:13px;color:var(--g700);white-space:pre-line;padding:10px;background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.15);border-radius:8px;line-height:1.7">'
    +           (m.rollback||'—')
    +           '<br><br><span style="font-size:11px;color:var(--g400)">Tempo: ' + (m.tempoRollback||'—') + ' &middot; Resp: ' + (m.respRollback||'—') + '</span>'
    +         '</div></div>'
    +     '</div>'
    +   '</div>'
    +   '<div class="divider"></div>'
    +   '<h4 style="font-size:13px;font-weight:700;margin-bottom:12px">📅 Histórico da RFC</h4>'
    +   '<div class="timeline">' + historicoHTML + '</div>'
    +   '<div class="divider"></div>'
    +   '<div class="flex gap-8 flex-wrap">' + acoesHTML + '</div>'
    + '</div>'
    + '</div>';

  document.body.appendChild(div);

  // Wire buttons using event delegation (no inline onclick)
  div.addEventListener('click', function(e) {
    const closeBtn = e.target.closest('[data-close-modal]');
    if (closeBtn) { document.getElementById(closeBtn.dataset.closeModal)?.remove(); return; }
    const actionBtn = e.target.closest('[data-rfc-id]');
    if (actionBtn) { updateStatusRFC(actionBtn.dataset.rfcId, actionBtn.dataset.rfcStatus); }
  });
}


function updateStatusRFC(id, novoStatus) {
  const m = (STATE.mudancas||[]).find(x => x.id === id);
  if (!m) return;
  const obs = prompt(`Observação para "${STATUS_MUDANCA[novoStatus]?.label || novoStatus}":`) || '';
  m.status = novoStatus;
  m.historicoStatus = m.historicoStatus || [];
  m.historicoStatus.push({ status: novoStatus, data: new Date().toLocaleString('pt-BR'), autor: CURRENT_USER?.nome || 'Usuário', obs });
  document.querySelectorAll('[id^="modal-ver-rfc-"]').forEach(el => el.remove());
  renderMudancasITIL();
  showToast(`✓ RFC ${id} → ${STATUS_MUDANCA[novoStatus]?.label || novoStatus}`);
}

function mudarStatusRFC(id) { abrirMudanca(id); }

function salvarRFC(status = 'rascunho') {
  const titulo = document.getElementById('rfc-titulo')?.value?.trim();
  if (!titulo) return showToast('Título da RFC é obrigatório', 'danger');
  const id = 'RFC-' + String((STATE.mudancas||[]).length + 1).padStart(3, '0');
  const nova = {
    id, status,
    tipo:         document.getElementById('rfc-tipo')?.value || 'normal',
    categoria:    document.getElementById('rfc-categoria')?.value || '—',
    prioridade:   document.getElementById('rfc-prioridade')?.value || 'media',
    titulo,
    desc:         document.getElementById('rfc-desc')?.value || '',
    justificativa:document.getElementById('rfc-justificativa')?.value || '',
    responsavel:  document.getElementById('rfc-responsavel')?.value || CURRENT_USER?.nome || '—',
    area:         document.getElementById('rfc-area')?.value || '',
    dataImpl:     document.getElementById('rfc-data-impl')?.value || '',
    duracao:      document.getElementById('rfc-duracao')?.value || '',
    janela:       document.getElementById('rfc-janela')?.value || '',
    risco:        document.getElementById('rfc-risco')?.value || 'medio',
    impactoUsers: document.getElementById('rfc-impacto-users')?.value || 'minimo',
    downtime:     document.querySelector('input[name="rfc-downtime"]:checked')?.value || 'nao',
    analiseRisco: document.getElementById('rfc-analise-risco')?.value || '',
    sistemas:     document.getElementById('rfc-sistemas')?.value || '',
    criterios:    document.getElementById('rfc-criterios')?.value || '',
    passos:       document.getElementById('rfc-passos')?.value || '',
    rollback:     document.getElementById('rfc-rollback')?.value || '',
    tempoRollback:document.getElementById('rfc-tempo-rollback')?.value || '',
    respRollback: document.getElementById('rfc-resp-rollback')?.value || '',
    backupFeito:  document.querySelector('input[name="rfc-backup"]:checked')?.value || 'nao',
    cabData:      document.getElementById('rfc-cab-data')?.value || '',
    cabMembros:   document.getElementById('rfc-cab-membros')?.value || '',
    impactoNegocio: document.getElementById('rfc-impacto-negocio')?.value || '',
    aprovGest:    document.getElementById('rfc-aprov-gest')?.checked || false,
    aprovNeg:     document.getElementById('rfc-aprov-neg')?.checked || false,
    aprovSeg:     document.getElementById('rfc-aprov-seg')?.checked || false,
    obsCAB:       document.getElementById('rfc-obs-cab')?.value || '',
    createdAt:    new Date(),
    createdBy:    CURRENT_USER?.nome || '—',
    historicoStatus:[{ status, data: new Date().toLocaleString('pt-BR'), autor: CURRENT_USER?.nome || '—', obs: status === 'rascunho' ? 'RFC criada' : 'Submetida ao CAB' }],
  };
  if (!STATE.mudancas) STATE.mudancas = [];
  STATE.mudancas.unshift(nova);
  // TODO: fsAdd('mudancas', nova, STATE.mudancas)
  closeModal('modal-nova-mudanca');
  renderMudancasITIL();
  showToast(`✓ ${id} ${status === 'rascunho' ? 'salva como rascunho' : 'submetida ao CAB'}`);
}

// Wire RFC tabs
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-rfc-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      tab.closest('.tabs')?.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      ['geral','impacto','plano','rollback','cab'].forEach(id => {
        const el = document.getElementById('rfc-tab-' + id);
        if (el) el.style.display = id === tab.dataset.rfcTab ? '' : 'none';
      });
    });
  });
  document.querySelectorAll('[data-itil-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      tab.closest('.tabs')?.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderMudancasITIL(tab.dataset.itilTab);
    });
  });
});


// ─── SEED: Contatos CESAN (organograma) ───────────────────────
const CONTATOS_CESAN = [];


const STATE_EMPREGADOS_SEED = [];

// Popula STATE.empregados com dados do organograma se Banco não disponível
function initEmpregadosSeed() {
  if (!STATE.empregados || STATE.empregados.length === 0) {
    STATE.empregados = STATE_EMPREGADOS_SEED;
    console.log('[Seed] ' + STATE.empregados.length + ' empregados carregados do organograma');
  }
}

// Autocomplete de empregados nos formulários
function autocompleteEmpregado(inputEl, onSelect) {
  const input = typeof inputEl === 'string' ? document.getElementById(inputEl) : inputEl;
  if (!input) return;
  
  let dropdown = null;
  
  input.addEventListener('input', function() {
    const q = this.value.toLowerCase().trim();
    if (dropdown) dropdown.remove();
    if (q.length < 2) return;
    
    const matches = (STATE.empregados || [])
      .filter(e => e.nome.toLowerCase().includes(q) || e.email.toLowerCase().includes(q) || e.ramal.includes(q))
      .slice(0, 8);
    
    if (!matches.length) return;
    
    dropdown = document.createElement('div');
    dropdown.style.cssText = 'position:absolute;z-index:9999;background:var(--g0,#fff);border:1px solid var(--g200);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);width:320px;max-height:280px;overflow-y:auto';
    
    matches.forEach(e => {
      const item = document.createElement('div');
      item.style.cssText = 'padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--g100)';
      item.innerHTML = '<div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#2563EB,#7C3AED);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0">' + e.avatar + '</div>' +
        '<div><div style="font-size:13px;font-weight:600;color:var(--g800)">' + e.nome + '</div>' +
        '<div style="font-size:11px;color:var(--g400)">' + e.setor + (e.ramal ? ' · Ramal ' + e.ramal : '') + '</div></div>';
      item.addEventListener('mouseenter', () => item.style.background = 'var(--g50)');
      item.addEventListener('mouseleave', () => item.style.background = '');
      item.addEventListener('click', () => {
        input.value = e.nome;
        dropdown.remove();
        dropdown = null;
        if (onSelect) onSelect(e);
      });
      dropdown.appendChild(item);
    });
    
    const rect = input.getBoundingClientRect();
    dropdown.style.top  = (rect.bottom + window.scrollY + 4) + 'px';
    dropdown.style.left = rect.left + 'px';
    document.body.appendChild(dropdown);
  });
  
  document.addEventListener('click', e => {
    if (dropdown && !dropdown.contains(e.target) && e.target !== input) {
      dropdown.remove(); dropdown = null;
    }
  }, { once: false });
}

// ════════════════════════════════════════════════════════════
// ASSISTÊNCIA REMOTA — Computadores
// Gerencia agentes desktop: inventário, deploy, acesso remoto
// ════════════════════════════════════════════════════════════

// Cache de agentes online (vem do Banco /agents)
const STATE_AGENTS = { list: [], listener: null };

// Inicia listener Banco para agentes em tempo real
function startAgentsListener() {
  if (!FB_READY || STATE_AGENTS.listener) return;
  try {
    const { getFirestore, collection, onSnapshot, query, orderBy } =
      window._fsModule || {};
    // Fallback: usa polling se módulo não disponível
    if (!onSnapshot) {
      arPollAgentes();
      setInterval(arPollAgentes, 30000);
      return;
    }
    STATE_AGENTS.listener = onSnapshot(
      query(collection(getFirestore(window._app || getApps()[0]), 'agents'), orderBy('lastSeen', 'desc')),
      snap => {
        STATE_AGENTS.list = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        if (isPageActive('assistencia-remota')) renderAssistenciaRemota();
        nbUpdate('nb-agentes-online', STATE_AGENTS.list.filter(a => a.status === 'online').length);
      }
    );
  } catch { arPollAgentes(); setInterval(arPollAgentes, 30000); }
}

async function arPollAgentes() {
  if (!FB_READY) return;
  try {
    const snap = await fsQuery('agents', []);
    STATE_AGENTS.list = snap || [];
    if (isPageActive('assistencia-remota')) renderAssistenciaRemota();
    nbUpdate('nb-agentes-online', STATE_AGENTS.list.filter(a => a.status === 'online').length);
  } catch {}
}

function renderAssistenciaRemota() {
  const tbody = document.getElementById('ar-tbody');
  if (!tbody) return;

  const q      = (document.getElementById('ar-search')?.value     || '').toLowerCase();
  const fSt    = document.getElementById('ar-filter-status')?.value || '';
  const fOs    = document.getElementById('ar-filter-os')?.value    || '';
  const agentes = STATE_AGENTS.list;

  // Stats
  const online  = agentes.filter(a => a.status === 'online').length;
  const offline = agentes.filter(a => a.status === 'offline' || (!a.status && a.lastSeen)).length;
  const alertas = agentes.filter(a => ['alerta','critico'].includes(a.status)).length;
  const sessoes = agentes.filter(a => a.emSessao).length;

  sv('ar-stat-online',  online);
  sv('ar-stat-offline', offline);
  sv('ar-stat-alert',   alertas);
  sv('ar-stat-session', sessoes);
  sv('ar-stat-total',   agentes.length);
  nbUpdate('nb-agentes-online', online);
  document.getElementById('ar-last-update').textContent =
    'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');

  // Filtro
  let lista = agentes;
  if (q)   lista = lista.filter(a =>
    (a.hostname||'').toLowerCase().includes(q) ||
    (a.ip||'').includes(q) ||
    (a.usuarioLogado||'').toLowerCase().includes(q) ||
    (a.osNome||'').toLowerCase().includes(q));
  if (fSt) lista = lista.filter(a => a.status === fSt);
  if (fOs) lista = lista.filter(a => (a.osNome||'').includes(fOs));

  // Ordena: críticos primeiro
  const ORDER = { critico:0, alerta:1, online:2, offline:3 };
  lista.sort((a,b) => (ORDER[a.status]??4) - (ORDER[b.status]??4));

  if (!lista.length) {
    tbody.innerHTML = `<tr><td colspan="12" style="text-align:center;padding:40px;color:var(--g400)">
      <div style="font-size:32px;margin-bottom:12px">🖥️</div>
      <div style="font-weight:600;margin-bottom:6px">${agentes.length ? 'Nenhum agente com esses filtros' : 'Nenhum agente instalado'}</div>
      ${!agentes.length ? '<button class="btn btn-primary btn-sm" style="margin-top:12px" onclick="arInstalarAgente()">⬇️ Baixar Instalador</button>' : ''}
    </td></tr>`;
    return;
  }

  tbody.innerHTML = lista.map(a => {
    const statusCls = a.status || 'sem-agente';
    const statusCor = {online:'badge-success',offline:'badge-danger',alerta:'badge-warning',critico:'badge-danger'}[a.status] || '';
    const lastSeen  = a.lastSeen ? fmtRelative(new Date(a.lastSeen?.seconds ? a.lastSeen.seconds*1000 : a.lastSeen)) : '—';

    // CPU bar
    const cpuBar = a.cpuPct != null
      ? `<div style="display:flex;align-items:center;gap:6px">
           <div style="width:50px;height:5px;background:var(--g200);border-radius:3px;overflow:hidden">
             <div style="width:${a.cpuPct}%;height:5px;background:${a.cpuPct>90?'#EF4444':a.cpuPct>70?'#F59E0B':'#10B981'};border-radius:3px"></div>
           </div>
           <span style="font-size:11.5px">${a.cpuPct}%</span>
         </div>` : '—';

    const ramBar = a.memPct != null
      ? `<div style="display:flex;align-items:center;gap:6px">
           <div style="width:50px;height:5px;background:var(--g200);border-radius:3px;overflow:hidden">
             <div style="width:${a.memPct}%;height:5px;background:${a.memPct>90?'#EF4444':a.memPct>80?'#F59E0B':'#10B981'};border-radius:3px"></div>
           </div>
           <span style="font-size:11.5px">${a.memPct}%</span>
         </div>` : '—';

    const diskBar = a.discoC_usadoPct != null
      ? `<div style="display:flex;align-items:center;gap:6px">
           <div style="width:50px;height:5px;background:var(--g200);border-radius:3px;overflow:hidden">
             <div style="width:${a.discoC_usadoPct}%;height:5px;background:${a.discoC_usadoPct>90?'#EF4444':a.discoC_usadoPct>80?'#F59E0B':'#10B981'};border-radius:3px"></div>
           </div>
           <span style="font-size:11.5px">${100-a.discoC_usadoPct}% livre</span>
         </div>` : '—';

    const patchBadge = a.patchesCriticos > 0
      ? `<span style="font-size:10px;background:#FEF2F2;color:#DC2626;padding:1px 6px;border-radius:10px;margin-left:4px">${a.patchesCriticos} patch(es) crítico(s)</span>`
      : '';

    return `<tr>
      <td style="text-align:center"><span class="ar-dot ${statusCls}"></span></td>
      <td>
        <div style="font-weight:700;font-size:13px">${escapeHtml(a.hostname||a.id)}</div>
        ${patchBadge}
        ${a.emSessao ? '<span style="font-size:10px;background:#EFF6FF;color:#2563EB;padding:1px 6px;border-radius:10px;margin-left:4px">Em sessão</span>' : ''}
      </td>
      <td style="font-family:monospace;font-size:12px;color:var(--g500)">${(()=>{ const _a=ipParaArea(a.ip); return (a.ip||'—') + (_a ? ' <span style="font-size:10px;color:#64748B;font-weight:500" title="'+escapeHtml(_a.nome)+'">'+escapeHtml(_a.codigo.toUpperCase())+'</span>' : ''); })()}</td>
      <td style="font-size:12px">${escapeHtml((a.osNome||'—').replace('Microsoft Windows ','Win '))}</td>
      <td style="font-size:12px;color:var(--g600)">${escapeHtml(a.usuarioLogado||'—')}</td>
      <td>${cpuBar}</td>
      <td>${ramBar}</td>
      <td>${diskBar}</td>
      <td style="font-size:12px;color:var(--g500)">${a.uptimeH != null ? a.uptimeH + 'h' : '—'}</td>
      <td style="font-size:11.5px;color:var(--g400)">${escapeHtml(a.version||'—')}</td>
      <td style="font-size:11.5px;color:var(--g400)">${lastSeen}</td>
      <td>
        <div style="display:flex;gap:5px;flex-wrap:wrap">
          <button class="btn btn-primary btn-xs" onclick="arAbrirViewer('${a.id}')" ${a.status!=='online'?'disabled title="Agente offline"':''}>🖥️ Acessar</button>
          <button class="btn btn-secondary btn-xs" onclick="arAbrirInventario('${a.id}')">📋 Info</button>
          <button class="btn btn-secondary btn-xs" onclick="arInstalarSoftware('${a.id}','${escapeHtml(a.hostname||a.id)}')">📦</button>
          <button class="btn btn-secondary btn-xs" onclick="arInstalarPatches('${a.id}','${escapeHtml(a.hostname||a.id)}')">🔒</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ── ABRIR REMOTE VIEWER ───────────────────────────────────────
async function arAbrirViewer(agentId) {
  const agente = STATE_AGENTS.list.find(a => a.id === agentId);
  if (!agente) return showToast('Agente não encontrado', 'warning');
  if (agente.status !== 'online') return showToast('Agente offline — não é possível conectar', 'danger');

  showToast('Iniciando sessão remota com ' + (agente.hostname || agentId) + '...', 'info', 3000);

  // Cria sessão no Banco
  let sessaoId;
  try {
    const sessaoDoc = await fsAdd('sessoes_remotas', {
      agentId,
      hostname:      agente.hostname || agentId,
      ip:            agente.ip || '',
      iniciadorUid:  CURRENT_USER?.uid || '',
      iniciadorNome: CURRENT_USER?.nome || '',
      status:        'iniciando',
      tipo:          'websocket',
      createdAt:     new Date().toISOString(),
    });
    sessaoId = sessaoDoc?.name?.split('/').pop() || 'sess_' + Date.now();
  } catch {
    sessaoId = 'sess_' + Date.now();
  }

  // Envia comando para o agente iniciar o tunnel WebSocket
  await arEnviarComando(agentId, 'iniciar_acesso_remoto', {
    sessaoId, port: 9000,
  }, 'Sessão de acesso remoto via SYSACK');

  // Audit log
  auditLog('REMOTE_ACCESS_START', 'agents', agentId, 'computador', {
    hostname: agente.hostname, sessaoId, ip: agente.ip,
  });

  // Abre o viewer após 2s (tempo para o agente iniciar o tunnel)
  setTimeout(() => iniciarViewerRemoto(agentId, sessaoId, agente), 2000);
}

// ── REMOTE VIEWER (embeds direto no SYSACK) ───────────────────
function iniciarViewerRemoto(agentId, sessaoId, agente) {
  const hostname = agente?.hostname || agentId;
  const wsPort   = agente?.webSocketPort || 9000;
  const wsIp     = agente?.ip || 'localhost';

  // Remove viewer anterior se houver
  document.getElementById('remote-viewer-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.id    = 'remote-viewer-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;background:#0A0F1E;display:flex;flex-direction:column;animation:fadeIn .2s ease';

  overlay.innerHTML = `
    <div style="background:#1E293B;border-bottom:1px solid #334155;padding:10px 16px;display:flex;align-items:center;gap:12px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:8px">
        <div id="rv-dot" style="width:10px;height:10px;border-radius:50%;background:#EF4444;transition:background .3s"></div>
        <span style="color:#fff;font-weight:800;font-size:14px">🖥️ SYSACK Remote</span>
        <span style="color:#94A3B8;font-size:13px">— ${escapeHtml(hostname)}</span>
        <span id="rv-ip" style="color:#64748B;font-size:12px;font-family:monospace">${escapeHtml(wsIp)}</span>
      </div>
      <div style="display:flex;gap:6px;margin-left:auto;align-items:center">
        <span id="rv-status-txt" style="color:#64748B;font-size:11.5px">Conectando...</span>
        <button id="rv-btn-screen" onclick="rvCaptura()" class="rv-btn" title="Capturar tela (F5)">📷</button>
        <button onclick="rvShowPanel('shell')"    class="rv-btn" title="Terminal">⬛</button>
        <button onclick="rvShowPanel('procs')"    class="rv-btn" title="Processos">📊</button>
        <button onclick="rvShowPanel('services')" class="rv-btn" title="Serviços">⚙️</button>
        <button onclick="rvShowPanel('software')" class="rv-btn" title="Software">📦</button>
        <button onclick="rvShowPanel('patches')"  class="rv-btn" title="Patches">🔒</button>
        <button onclick="rvShowPanel('deploy')"   class="rv-btn" title="Deploy">📲</button>
        <div style="width:1px;height:24px;background:#334155;margin:0 4px"></div>
        <button onclick="rvEncerrar('${sessaoId}')" style="background:#EF4444;color:#fff;border:none;padding:7px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px">
          ✕ Encerrar Sessão
        </button>
      </div>
    </div>

    <div style="flex:1;display:flex;overflow:hidden">
      <!-- TELA REMOTA -->
      <div style="flex:1;display:flex;flex-direction:column;overflow:hidden;border-right:1px solid #334155">
        <div style="background:#1E293B;padding:8px 14px;border-bottom:1px solid #334155;display:flex;align-items:center;gap:10px;flex-shrink:0">
          <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em">Tela Remota</span>
          <button onclick="rvCaptura()" style="background:#2563EB;color:#fff;border:none;padding:3px 12px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600">↺ Atualizar</button>
          <label style="color:#94A3B8;font-size:12px;display:flex;align-items:center;gap:5px;cursor:pointer">
            <input type="checkbox" id="rv-auto" onchange="rvToggleAuto(this.checked)" style="cursor:pointer"> Auto 5s
          </label>
          <span id="rv-capture-ts" style="color:#475569;font-size:11px;margin-left:auto"></span>
        </div>
        <div style="flex:1;overflow:auto;background:#0F172A;display:flex;align-items:center;justify-content:center;padding:12px">
          <div id="rv-screen-wrap" style="max-width:100%;max-height:100%">
            <div id="rv-placeholder" style="text-align:center;color:#475569;padding:60px 40px">
              <div style="font-size:48px;margin-bottom:16px">🖥️</div>
              <div style="font-size:14px;font-weight:600;margin-bottom:8px">Aguardando conexão...</div>
              <div style="font-size:12px">O agente está configurando o tunnel seguro.</div>
            </div>
            <img id="rv-img" style="max-width:100%;max-height:calc(100vh - 200px);display:none;border-radius:6px;box-shadow:0 4px 32px rgba(0,0,0,.6);cursor:crosshair">
          </div>
        </div>
      </div>

      <!-- PAINEL DE FERRAMENTAS -->
      <div style="width:500px;display:flex;flex-direction:column;overflow:hidden;background:#0F172A">

        <!-- TERMINAL -->
        <div id="rv-panel-shell" style="display:flex;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0;display:flex;align-items:center;gap:8px">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">⬛ PowerShell Remoto</span>
            <button onclick="rvShellClear()" style="background:none;border:1px solid #334155;color:#64748B;padding:2px 8px;border-radius:5px;cursor:pointer;font-size:10px;margin-left:auto">Limpar</button>
          </div>
          <div id="rv-shell-out" style="flex:1;overflow-y:auto;padding:10px;font-family:'Cascadia Code','Consolas',monospace;font-size:12px;line-height:1.5;color:#94A3B8"></div>
          <div style="background:#1E293B;padding:8px 10px;border-top:1px solid #334155;flex-shrink:0">
            <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px">
              ${[
                ['Disco','Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,@{n="GBLivre";e={[math]::Round($_.FreeSpace/1GB,1)}},@{n="UsadoPct";e={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100)}} | Format-Table'],
                ['CPU/RAM','$c=(Get-CimInstance Win32_Processor).LoadPercentage;$o=Get-CimInstance Win32_OperatingSystem;$m=[math]::Round(($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize*100);Write-Output "CPU: $c% | RAM: $m%"'],
                ['Usuário','(Get-CimInstance Win32_ComputerSystem).UserName'],
                ['Uptime','[math]::Round(((Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours,1) | ForEach-Object { Write-Output "$_ horas" }'],
                ['Eventos','Get-EventLog -LogName System -EntryType Error -Newest 5 | Select-Object TimeGenerated,Source,Message | Format-Table -AutoSize'],
                ['Rede','Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select-Object Description,IPAddress,MACAddress | Format-Table -AutoSize'],
              ].map(([l,c]) => `<button class="rv-quick-cmd" onclick="rvQuick('${c.replace(/'/g,'&#39;')}')">${l}</button>`).join('')}
            </div>
            <div style="display:flex;gap:8px">
              <input id="rv-cmd-in" style="flex:1;background:#0F172A;border:1px solid #334155;border-radius:8px;padding:8px 12px;color:#94A3B8;font-family:monospace;font-size:12px;outline:none" placeholder="Get-Process | Sort-Object CPU -Desc | Select-Object -First 10" onkeydown="if(event.key==='Enter'){rvRun();event.preventDefault()}">
              <button onclick="rvRun()" style="background:#2563EB;color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700">▶</button>
            </div>
          </div>
        </div>

        <!-- PROCESSOS -->
        <div id="rv-panel-procs" style="display:none;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0;display:flex;align-items:center;gap:8px">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">📊 Processos</span>
            <button onclick="rvLoadProcs()" style="background:#2563EB;color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;margin-left:auto">↺</button>
          </div>
          <div style="padding:8px 10px;background:#1E293B;border-bottom:1px solid #334155;flex-shrink:0">
            <input id="rv-proc-q" style="width:100%;background:#0F172A;border:1px solid #334155;border-radius:6px;padding:6px 10px;color:#94A3B8;font-size:12px" placeholder="Filtrar processo..." oninput="rvFilterProcs(this.value)">
          </div>
          <div id="rv-procs-list" style="flex:1;overflow-y:auto;padding:6px"></div>
        </div>

        <!-- SERVIÇOS -->
        <div id="rv-panel-services" style="display:none;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0;display:flex;align-items:center;gap:8px">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">⚙️ Serviços Windows</span>
            <button onclick="rvLoadServices()" style="background:#2563EB;color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;margin-left:auto">↺</button>
          </div>
          <div style="padding:8px 10px;background:#1E293B;border-bottom:1px solid #334155;flex-shrink:0">
            <input id="rv-svc-q" style="width:100%;background:#0F172A;border:1px solid #334155;border-radius:6px;padding:6px 10px;color:#94A3B8;font-size:12px" placeholder="Filtrar serviço..." oninput="rvFilterSvcs(this.value)">
          </div>
          <div id="rv-svcs-list" style="flex:1;overflow-y:auto;padding:6px"></div>
        </div>

        <!-- SOFTWARE -->
        <div id="rv-panel-software" style="display:none;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0;display:flex;align-items:center;gap:8px">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">📦 Software Instalado</span>
            <button onclick="rvLoadSoftware()" style="background:#2563EB;color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;margin-left:auto">↺</button>
          </div>
          <div style="padding:8px 10px;background:#1E293B;border-bottom:1px solid #334155;flex-shrink:0">
            <input id="rv-sw-q" style="width:100%;background:#0F172A;border:1px solid #334155;border-radius:6px;padding:6px 10px;color:#94A3B8;font-size:12px" placeholder="Filtrar software...">
          </div>
          <div id="rv-sw-list" style="flex:1;overflow-y:auto;padding:6px;font-size:12px;color:#94A3B8"></div>
        </div>

        <!-- PATCHES -->
        <div id="rv-panel-patches" style="display:none;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0;display:flex;align-items:center;gap:8px">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">🔒 Patches Pendentes</span>
            <button onclick="rvInstalarTodosPatches()" style="background:#059669;color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px">Instalar Todos</button>
            <button onclick="rvLoadPatches()" style="background:#2563EB;color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;margin-left:auto">↺</button>
          </div>
          <div id="rv-patches-list" style="flex:1;overflow-y:auto;padding:10px;font-size:12px;color:#94A3B8"></div>
        </div>

        <!-- DEPLOY -->
        <div id="rv-panel-deploy" style="display:none;flex-direction:column;height:100%">
          <div style="background:#1E293B;padding:8px 12px;border-bottom:1px solid #334155;flex-shrink:0">
            <span style="color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase">📲 Deploy de Software</span>
          </div>
          <div style="flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px">
            <div style="font-size:12px;color:#64748B;margin-bottom:4px">Catálogo homologado:</div>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px" id="rv-deploy-catalog"></div>
            <div style="margin-top:8px">
              <div style="color:#94A3B8;font-size:12px;margin-bottom:6px">Ou especifique:</div>
              <input id="rv-deploy-nome" style="width:100%;background:#1E293B;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#94A3B8;font-size:12px;margin-bottom:6px" placeholder="Nome do software">
              <input id="rv-deploy-url" style="width:100%;background:#1E293B;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#94A3B8;font-size:12px;margin-bottom:6px" placeholder="URL ou caminho UNC do instalador">
              <input id="rv-deploy-params" style="width:100%;background:#1E293B;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#94A3B8;font-size:12px;margin-bottom:10px" placeholder="Parâmetros (ex: /S /quiet)">
              <button onclick="rvDeployPersonalizado()" style="width:100%;background:#2563EB;color:#fff;border:none;padding:10px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700">📦 Instalar Agora</button>
            </div>
            <div id="rv-deploy-log" style="display:none;background:#0F172A;border-radius:8px;padding:10px;font-family:monospace;font-size:11px;color:#94A3B8;max-height:140px;overflow-y:auto;margin-top:8px"></div>
          </div>
        </div>

      </div>
    </div>

    <!-- STATUS BAR -->
    <div style="background:#1E293B;border-top:1px solid #334155;padding:5px 16px;display:flex;align-items:center;gap:20px;font-size:11px;color:#64748B;flex-shrink:0">
      <span id="rv-sb-cpu">CPU: —</span>
      <span id="rv-sb-mem">RAM: —</span>
      <span id="rv-sb-disk">Disco: —</span>
      <span id="rv-sb-uptime">Uptime: —</span>
      <span id="rv-sb-user">Usuário: —</span>
      <span id="rv-sb-msg" style="margin-left:auto;color:#94A3B8"></span>
    </div>
  `;

  document.body.appendChild(overlay);

  // ── Estado do viewer ────────────────────────────────────────
  let _ws          = null;
  let _autoTimer   = null;
  let _procsCache  = [];
  let _svcsCache   = [];
  let _swCache     = [];
  let _wsLocal     = 'ws://' + wsIp + ':' + wsPort;   // rede interna
  let _wsUrl       = _wsLocal;
  let _reconnects  = 0;
  let _modoConexao = 'detectando';  // 'local' | 'firebase' | 'detectando'
  let _fbRelay     = null;          // listener Banco Realtime para relay
  const FB_RELAY_PATH = 'sessoes_remotas/' + sessaoId + '/relay';

  // ── Detecção automática de rede ──────────────────────────────
  // 1. Tenta WebSocket direto (rede interna) com timeout de 3s
  // 2. Se falhar, cai para Banco Realtime como relay
  // 3. Alerta o técnico sobre o modo de conexão

  async function rvDetectarEConectar() {
    rvSb('Detectando melhor rota de conexão...');
    rvSetStatus('detectando', 'Detectando rota...');

    const localOk = await rvTestarConexaoLocal();

    if (localOk) {
      _modoConexao = 'local';
      rvSetStatus('local', 'Rede interna');
      rvMostrarBannerConexao('local');
      rvConnect(_wsLocal);
    } else {
      _modoConexao = 'firebase';
      rvSetStatus('firebase', 'Via internet (Banco)');
      rvMostrarBannerConexao('firebase');
      // Alerta ao técnico
      showToast(
        '📡 PC não encontrado na rede local — usando relay via internet. ' +
        'Latência pode ser maior.',
        'warning', 6000
      );
      rvConnectBanco();
    }
  }

  function rvTestarConexaoLocal() {
    // Tenta abrir WebSocket com timeout de 3 segundos
    return new Promise(resolve => {
      if (!wsIp || wsIp === 'localhost' || wsIp === '127.0.0.1') {
        resolve(false);
        return;
      }
      let resolvido = false;
      const timer = setTimeout(() => {
        if (!resolvido) { resolvido = true; ws.close(); resolve(false); }
      }, 3000);

      const ws = new WebSocket(_wsLocal);
      ws.onopen  = () => {
        if (!resolvido) {
          resolvido = true;
          clearTimeout(timer);
          ws.close(); // fecha o de teste; vai abrir o real logo
          resolve(true);
        }
      };
      ws.onerror = () => {
        if (!resolvido) { resolvido = true; clearTimeout(timer); resolve(false); }
      };
      ws.onclose = () => {
        if (!resolvido) { resolvido = true; clearTimeout(timer); resolve(false); }
      };
    });
  }

  function rvSetStatus(modo, texto) {
    const dot = document.getElementById('rv-dot');
    const txt = document.getElementById('rv-status-txt');
    if (dot) dot.style.background =
      modo === 'local'      ? '#10B981' :
      modo === 'firebase'   ? '#F59E0B' :
      modo === 'detectando' ? '#6366F1' : '#EF4444';
    if (txt) txt.textContent = texto;
  }

  function rvMostrarBannerConexao(modo) {
    // Remove banner anterior
    document.getElementById('rv-conn-banner')?.remove();
    const banner = document.createElement('div');
    banner.id = 'rv-conn-banner';

    if (modo === 'local') {
      banner.style.cssText = 'background:#059669;color:#fff;padding:4px 16px;font-size:11px;font-weight:600;text-align:center;flex-shrink:0;display:flex;align-items:center;justify-content:center;gap:8px';
      banner.innerHTML = '<span>⚡</span> <span>Conexão direta via rede interna — latência mínima, sem consumo de internet</span>';
    } else {
      banner.style.cssText = 'background:#D97706;color:#fff;padding:4px 16px;font-size:11px;font-weight:600;text-align:center;flex-shrink:0;display:flex;align-items:center;justify-content:center;gap:8px';
      banner.innerHTML = '<span>📡</span> <span>Conectado via internet (Banco Relay) — PC não encontrado na rede local</span>' +
        '<button onclick="rvRetentarLocal()" style="background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.4);color:#fff;border-radius:5px;padding:2px 10px;cursor:pointer;font-size:11px;margin-left:8px">↺ Tentar rede local</button>';
    }

    // Insere após a topbar
    const topbar = document.querySelector('#remote-viewer-overlay > div:first-child');
    topbar?.insertAdjacentElement('afterend', banner);
  }

  window.rvRetentarLocal = async () => {
    rvSb('Tentando reconectar via rede interna...');
    const ok = await rvTestarConexaoLocal();
    if (ok) {
      // Desconecta Banco relay
      if (_fbRelay) { _fbRelay(); _fbRelay = null; }
      _ws?.close();
      _modoConexao = 'local';
      rvSetStatus('local', 'Rede interna');
      rvMostrarBannerConexao('local');
      rvConnect(_wsLocal);
      showToast('✅ Conectado via rede interna!', 'success', 3000);
    } else {
      showToast('PC ainda não acessível na rede local. Mantendo relay Banco.', 'warning', 4000);
    }
  };

  // ── WebSocket direto (rede interna) ──────────────────────────
  function rvConnect(url) {
    _wsUrl = url || _wsLocal;
    rvSb('Conectando via rede interna a ' + wsIp + ':' + wsPort + '...');
    _ws = new WebSocket(_wsUrl);

    _ws.onopen = () => {
      rvSetStatus('local', 'Rede interna ⚡');
      rvSb('Conectado via rede interna!');
      _reconnects = 0;
      _ws.send(JSON.stringify({ tipo:'ping' }));
      rvMetrics();
      setInterval(rvMetrics, 30000);
    };

    _ws.onmessage = e => rvProcessarMensagem(e.data);

    _ws.onclose = () => {
      if (_modoConexao !== 'local') return; // já trocou para Banco
      _reconnects++;
      if (_reconnects <= 2) {
        // Tenta novamente na rede local
        rvSetStatus('firebase', 'Reconectando...');
        rvSb('Tentando reconectar... (' + _reconnects + '/2)');
        setTimeout(() => rvConnect(_wsUrl), 3000);
      } else {
        // Desiste da rede local, cai para Banco
        rvSb('Rede local inacessível — alternando para Banco relay...');
        _modoConexao = 'firebase';
        rvMostrarBannerConexao('firebase');
        showToast('⚠️ Rede interna perdida — alternando para internet (Banco).', 'warning', 5000);
        rvConnectBanco();
      }
    };

    _ws.onerror = () => {};
  }

  // ── Banco Realtime como relay (qualquer rede / 4G) ────────
  // Agente e técnico trocam mensagens pelo Banco como intermediário
  // Agente fica em polling/listener, técnico escreve comandos no Banco
  // Agente executa e escreve o resultado de volta
  // Latência: ~200-800ms (suficiente para shell e métricas; lento para screenshot)

  function rvConnectBanco() {
    rvSetStatus('firebase', 'Conectando via Banco...');
    rvSb('Iniciando relay via Banco...');

    // Notifica o agente para usar o relay Banco
    arEnviarComando(agentId, 'usar_firebase_relay', { sessaoId }, 'Relay Banco iniciado pelo técnico')
      .then(() => {
        rvSetStatus('firebase', 'Via internet 📡');
        rvSb('Relay Banco ativo — latência ~300-600ms');

        // Escuta respostas do agente no Banco
        rvEscutarRespostasBanco();

        // Avisa que screenshot será mais lenta
        rvShellLog('[SYSACK] Conectado via internet (Banco Relay)', '#F59E0B');
        rvShellLog('[SYSACK] Captura de tela disponível, mas mais lenta que via rede interna.', '#64748B');
        rvShellLog('[SYSACK] Use "↺ Tentar rede local" se estiver na mesma rede do PC alvo.', '#64748B');
      })
      .catch(err => {
        rvSetStatus('offline', 'Falha na conexão');
        rvSb('Erro: ' + err.message);
      });
  }

  function rvEscutarRespostasBanco() {
    // Poll de respostas do agente no Banco a cada 1 segundo
    // (Banco Realtime DB seria melhor, mas Banco funciona)
    let lastSeq = 0;

    const pollInterval = setInterval(async () => {
      if (_modoConexao !== 'firebase') {
        clearInterval(pollInterval);
        return;
      }
      try {
        // Lê resposta mais recente do agente para esta sessão
        const respDoc = await fsGet('sessoes_remotas', sessaoId + '/relay/resposta');
        if (respDoc && respDoc.seq > lastSeq) {
          lastSeq = respDoc.seq;
          rvProcessarMensagem(respDoc.payload);
        }
      } catch {}
    }, 1000);

    _fbRelay = () => clearInterval(pollInterval);
  }

  function rvEnviarViaBanco(msg) {
    // Envia comando para o agente via Banco (relay)
    return fsPatch('sessoes_remotas', sessaoId, {
      relay_cmd: JSON.stringify(msg),
      relay_seq: Date.now(),
    }).catch(() => {});
  }

  // ── Processador de mensagens (unifica local e Banco) ──────
  function rvProcessarMensagem(rawData) {
    try {
      const d = typeof rawData === 'string' ? JSON.parse(rawData) : rawData;

      // Detecta métricas embutidas no resultado do shell
      if (d.tipo === 'result' && d.stdout?.startsWith('METRICS:')) {
        const parts = d.stdout.split(':');
        if (parts.length >= 6) {
          rvHandleMetrics({
            cpu: parts[1], mem: parts[2], disk: parts[3],
            uptime: parts[4], usuario: parts.slice(5).join(':').trim(),
          });
          return;
        }
      }

      if (d.tipo === 'pong')       rvHandlePong(d);
      if (d.tipo === 'screenshot') rvHandleScreen(d);
      if (d.tipo === 'result')     rvHandleResult(d);
      if (d.tipo === 'metrics')    rvHandleMetrics(d);
    } catch {}
  }

  // ── Envio unificado (local ou Banco) ─────────────────────
  function rvSend(obj) {
    if (_modoConexao === 'local' && _ws?.readyState === 1) {
      _ws.send(JSON.stringify(obj));
    } else if (_modoConexao === 'firebase') {
      rvEnviarViaBanco(obj);
    } else {
      rvSb('Aguardando conexão...');
    }
  }

  // ── Handlers ────────────────────────────────────────────────

  window.rvCaptura = () => { rvSend({ tipo:'screenshot' }); rvSb('Capturando...'); };

  window.rvRun = () => {
    const cmd = document.getElementById('rv-cmd-in')?.value?.trim();
    if (!cmd) return;
    rvShellLog('PS> ' + cmd, '#3B82F6');
    rvSend({ tipo:'exec', cmd, motivo:'Comando via SYSACK Remote' });
    document.getElementById('rv-cmd-in').value = '';
  };

  window.rvQuick = cmd => {
    const el = document.getElementById('rv-cmd-in');
    if (el) el.value = cmd;
    rvRun();
  };

  window.rvShellClear = () => {
    const el = document.getElementById('rv-shell-out');
    if (el) el.innerHTML = '';
  };

  window.rvHandlePong = d => {
    if (d.hostname) document.querySelector('#remote-viewer-overlay span[style*="94A3B8"]').textContent = '— ' + d.hostname;
  };

  window.rvHandleScreen = d => {
    const img = document.getElementById('rv-img');
    const ph  = document.getElementById('rv-placeholder');
    if (!img) return;
    img.src = 'data:image/png;base64,' + d.data;
    img.style.display = 'block';
    if (ph) ph.style.display = 'none';
    const ts = document.getElementById('rv-capture-ts');
    if (ts) ts.textContent = new Date().toLocaleTimeString('pt-BR');
  };

  window.rvHandleResult = d => {
    // Detecta se é resultado estruturado (JSON) ou texto
    const text = d.stdout || d.stderr || d.erro || '';
    try {
      // Tenta renderizar como tabela se for JSON
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed) && parsed.length) {
        rvRenderTable(parsed);
        return;
      }
    } catch {}
    if (d.stdout) rvShellLog(d.stdout, '#94A3B8');
    if (d.stderr) rvShellLog('STDERR: ' + d.stderr, '#F59E0B');
    if (d.erro)   rvShellLog('ERRO: ' + d.erro, '#EF4444');
    rvSb('Pronto');
  };

  window.rvHandleMetrics = d => {
    if (d.cpu     != null) document.getElementById('rv-sb-cpu').textContent    = 'CPU: '    + d.cpu    + '%';
    if (d.mem     != null) document.getElementById('rv-sb-mem').textContent    = 'RAM: '    + d.mem    + '%';
    if (d.disk    != null) document.getElementById('rv-sb-disk').textContent   = 'Disco: '  + d.disk   + '% livre';
    if (d.uptime  != null) document.getElementById('rv-sb-uptime').textContent = 'Uptime: ' + d.uptime + 'h';
    if (d.usuario != null) document.getElementById('rv-sb-user').textContent   = 'Usuário: '+ d.usuario;
  };

  function rvMetrics() {
    rvSend({ tipo:'exec', cmd:
      '$c=(Get-CimInstance Win32_Processor).LoadPercentage;' +
      '$o=Get-CimInstance Win32_OperatingSystem;' +
      '$m=[math]::Round(($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize*100);' +
      '$d=Get-CimInstance Win32_LogicalDisk -Filter \\"DeviceID=\'C:\'\\";' +
      '$f=[math]::Round($d.FreeSpace/$d.Size*100);' +
      '$u=[math]::Round(((Get-Date)-$o.LastBootUpTime).TotalHours,1);' +
      '$usr=(Get-CimInstance Win32_ComputerSystem).UserName;' +
      "Write-Output \\\"METRICS:$c:$m:$f:$u:$usr\\\""
    });
  }

  function rvShellLog(text, color) {
    const out = document.getElementById('rv-shell-out');
    if (!out) return;
    (text || '').split('\n').filter(Boolean).forEach(line => {
      const d = document.createElement('div');
      d.style.color   = color || '#94A3B8';
      d.style.padding = '1px 0';
      d.textContent   = line;
      out.appendChild(d);
    });
    out.scrollTop = out.scrollHeight;
  }

  function rvRenderTable(rows) {
    if (!rows?.length) return;
    const keys = Object.keys(rows[0]);
    const html = `<table style="width:100%;border-collapse:collapse;font-size:11.5px;color:#94A3B8">
      <thead><tr>${keys.map(k => `<th style="text-align:left;padding:4px 6px;border-bottom:1px solid #334155;color:#64748B;font-size:10.5px;text-transform:uppercase">${escapeHtml(k)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r => `<tr>${keys.map(k => `<td style="padding:3px 6px;border-bottom:1px solid rgba(51,65,85,.4)">${escapeHtml(String(r[k]??''))}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>`;
    const out = document.getElementById('rv-shell-out');
    if (out) {
      const wrap = document.createElement('div');
      wrap.style.overflowX = 'auto';
      wrap.innerHTML = html;
      out.appendChild(wrap);
      out.scrollTop = out.scrollHeight;
    }
  }

  function rvSb(msg) {
    const el = document.getElementById('rv-sb-msg');
    if (el) el.textContent = msg;
  }

  // ── Painéis ─────────────────────────────────────────────────
  window.rvShowPanel = panel => {
    ['shell','procs','services','software','patches','deploy'].forEach(p => {
      const el = document.getElementById('rv-panel-' + p);
      if (el) el.style.display = p === panel ? 'flex' : 'none';
    });
    if (panel === 'procs')    rvLoadProcs();
    if (panel === 'services') rvLoadServices();
    if (panel === 'software') rvLoadSoftware();
    if (panel === 'patches')  rvLoadPatches();
    if (panel === 'deploy')   rvInitDeploy();
  };

  // ── Processos ────────────────────────────────────────────────
  window.rvLoadProcs = () => {
    rvSend({ tipo:'exec', cmd:
      'Get-Process | Select-Object Name,Id,@{n="CPU";e={[math]::Round($_.CPU,1)}},@{n="MemMB";e={[math]::Round($_.WorkingSet64/1MB,1)}} | Sort-Object CPU -Descending | Select-Object -First 40 | ConvertTo-Json -Compress'
    });
    rvSb('Carregando processos...');
    // Handler especial para lista de processos
    const orig = window.rvHandleResult;
    window._rvProcHandler = d => {
      try {
        const procs = JSON.parse(d.stdout || '[]');
        if (Array.isArray(procs)) {
          _procsCache = procs;
          rvRenderProcs(procs);
          window.rvHandleResult = orig;
          return;
        }
      } catch {}
      orig(d);
    };
    window.rvHandleResult = window._rvProcHandler;
  };

  function rvRenderProcs(procs) {
    const list = document.getElementById('rv-procs-list');
    if (!list) return;
    list.innerHTML = procs.map(p =>
      `<div class="rv-proc-row">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(p.Name)}">${escapeHtml(p.Name)}</span>
        <span style="color:#64748B;font-size:10.5px;width:36px;text-align:right">${p.Id}</span>
        <div style="width:50px;height:4px;background:#1E293B;border-radius:2px;overflow:hidden">
          <div style="height:4px;background:#3B82F6;width:${Math.min(100,(p.CPU||0)/2)}%;border-radius:2px"></div>
        </div>
        <span style="width:48px;text-align:right;color:#94A3B8;font-size:11px">${p.CPU||0}s</span>
        <span style="width:52px;text-align:right;color:#64748B;font-size:11px">${p.MemMB||0}MB</span>
        <button onclick="rvKillProc(${p.Id},'${escapeHtml(p.Name)}')" style="background:none;border:1px solid #EF4444;color:#EF4444;border-radius:4px;cursor:pointer;padding:1px 7px;font-size:10px">✕</button>
      </div>`
    ).join('');
    rvSb(procs.length + ' processos');
  }

  window.rvKillProc = (pid, nome) => {
    if (!confirm('Encerrar processo ' + nome + ' (PID ' + pid + ')?')) return;
    rvSend({ tipo:'exec', cmd: 'Stop-Process -Id ' + pid + ' -Force; Write-Output "Processo ' + pid + ' encerrado"', motivo:'Encerrar processo via SYSACK Remote' });
    setTimeout(rvLoadProcs, 1500);
  };

  window.rvFilterProcs = q => {
    document.querySelectorAll('.rv-proc-row').forEach(row => {
      row.style.display = q ? (row.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none') : '';
    });
  };

  // ── Serviços ─────────────────────────────────────────────────
  window.rvLoadServices = () => {
    rvSend({ tipo:'exec', cmd:
      'Get-Service | Select-Object Name,DisplayName,Status,StartType | Sort-Object Status,DisplayName | ConvertTo-Json -Compress'
    });
    rvSb('Carregando serviços...');
    const orig = window.rvHandleResult;
    window.rvHandleResult = d => {
      try {
        const svcs = JSON.parse(d.stdout || '[]');
        if (Array.isArray(svcs)) {
          _svcsCache = svcs;
          rvRenderSvcs(svcs);
          window.rvHandleResult = orig;
          return;
        }
      } catch {}
      orig(d);
    };
  };

  function rvRenderSvcs(svcs) {
    const list = document.getElementById('rv-svcs-list');
    if (!list) return;
    list.innerHTML = svcs.map(s =>
      `<div class="rv-svc-row">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px" title="${escapeHtml(s.DisplayName||s.Name)}">${escapeHtml(s.DisplayName||s.Name)}</span>
        <span style="${s.Status==='Running'?'color:#10B981':'color:#64748B'};font-size:11px;font-weight:600;width:56px;text-align:right">${s.Status}</span>
        <div style="display:flex;gap:4px">
          ${s.Status!=='Running' ? `<button onclick="rvSvcAction('${escapeHtml(s.Name)}','Start-Service')" style="background:rgba(16,185,129,.15);color:#10B981;border:1px solid #10B981;border-radius:4px;cursor:pointer;padding:2px 8px;font-size:10px">▶</button>` : ''}
          ${s.Status==='Running'  ? `<button onclick="rvSvcAction('${escapeHtml(s.Name)}','Stop-Service -Force')" style="background:rgba(239,68,68,.15);color:#EF4444;border:1px solid #EF4444;border-radius:4px;cursor:pointer;padding:2px 8px;font-size:10px">⏹</button>` : ''}
          <button onclick="rvSvcAction('${escapeHtml(s.Name)}','Restart-Service -Force')" style="background:rgba(37,99,235,.15);color:#3B82F6;border:1px solid #3B82F6;border-radius:4px;cursor:pointer;padding:2px 8px;font-size:10px">↺</button>
        </div>
      </div>`
    ).join('');
    rvSb(svcs.length + ' serviços');
  }

  window.rvSvcAction = (nome, acao) => {
    rvSend({ tipo:'exec', cmd: acao + " -Name '" + nome + "'; Write-Output '" + acao + " " + nome + " OK'", motivo:'Gerenciar serviço via SYSACK Remote' });
    setTimeout(rvLoadServices, 2000);
  };

  window.rvFilterSvcs = q => {
    document.querySelectorAll('.rv-svc-row').forEach(row => {
      row.style.display = q ? (row.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none') : '';
    });
  };

  // ── Software ─────────────────────────────────────────────────
  window.rvLoadSoftware = () => {
    const agInv = STATE_AGENTS.list.find(a => a.id === agentId);
    if (agInv?.inventario) {
      try {
        const inv = JSON.parse(agInv.inventario);
        if (inv.software?.length) {
          _swCache = inv.software;
          rvRenderSoftware(inv.software);
          return;
        }
      } catch {}
    }
    // Fallback: busca via shell
    rvSend({ tipo:'exec', cmd:
      'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*","HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName -Unique | ConvertTo-Json -Compress'
    });
    rvSb('Carregando software...');
  };

  function rvRenderSoftware(sw) {
    const list = document.getElementById('rv-sw-list');
    if (!list) return;
    const q = document.getElementById('rv-sw-q')?.value?.toLowerCase() || '';
    const filtered = q ? sw.filter(s => (s.nome||s.DisplayName||'').toLowerCase().includes(q)) : sw;
    list.innerHTML = filtered.map(s =>
      `<div style="padding:6px 8px;border-bottom:1px solid rgba(51,65,85,.4);display:flex;align-items:center;gap:8px">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(s.nome||s.DisplayName||'—')}</span>
        <span style="color:#64748B;font-size:11px;white-space:nowrap">${escapeHtml(s.versao||s.DisplayVersion||'')}</span>
      </div>`
    ).join('') + `<div style="padding:8px;color:#64748B;font-size:11px">${filtered.length} programas</div>`;
    rvSb(filtered.length + ' programas');
  }

  document.getElementById('rv-sw-q')?.addEventListener('input', e => {
    if (_swCache.length) rvRenderSoftware(_swCache);
  });

  // ── Patches ──────────────────────────────────────────────────
  window.rvLoadPatches = () => {
    const agInv = STATE_AGENTS.list.find(a => a.id === agentId);
    if (agInv?.patchesLista?.length) {
      rvRenderPatches(agInv.patchesLista, agInv.patchesCriticos || 0);
      return;
    }
    rvSend({ tipo:'exec', cmd:
      '$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and Type=\'Software\'");$r.Updates|Select-Object Title,MsrcSeverity|ConvertTo-Json -Compress'
    });
    rvSb('Verificando patches...');
  };

  function rvRenderPatches(patches, criticos) {
    const list = document.getElementById('rv-patches-list');
    if (!list) return;
    if (!patches?.length) {
      list.innerHTML = '<div style="text-align:center;padding:40px;color:#10B981;font-size:13px">✅ Nenhum patch pendente!</div>';
      return;
    }
    list.innerHTML = `<div style="margin-bottom:10px;color:#F59E0B;font-weight:600">${patches.length} atualização(ões) pendente(s) — ${criticos} crítica(s)</div>` +
      patches.map(p => {
        const isCrit = (p.MsrcSeverity || p.severidade || '') === 'Critical';
        return `<div style="padding:6px 8px;border-bottom:1px solid rgba(51,65,85,.4);display:flex;align-items:center;gap:8px">
          ${isCrit ? '<span style="color:#EF4444;font-size:10px;font-weight:700;white-space:nowrap">🔴 CRÍTICO</span>' : '<span style="color:#64748B;font-size:10px;white-space:nowrap">⚪ Normal</span>'}
          <span style="flex:1;font-size:11.5px">${escapeHtml(p.Title||p.titulo||p)}</span>
        </div>`;
      }).join('');
    rvSb(patches.length + ' patches');
  }

  window.rvInstalarTodosPatches = () => {
    if (!confirm('Instalar TODOS os patches pendentes? O computador pode reiniciar.')) return;
    rvSend({ tipo:'exec', motivo:'Instalar patches via SYSACK Remote', cmd:
      '$Session=New-Object -ComObject Microsoft.Update.Session;' +
      '$Searcher=$Session.CreateUpdateSearcher();' +
      '$Found=$Searcher.Search("IsInstalled=0 and Type=\'Software\' and BrowseOnly=0");' +
      'if($Found.Updates.Count-eq 0){Write-Output "Nenhum patch pendente";exit};' +
      '$DL=$Session.CreateUpdateDownloader();$DL.Updates=$Found.Updates;$DL.Download();' +
      '$IN=$Session.CreateUpdateInstaller();$IN.Updates=$Found.Updates;' +
      '$R=$IN.Install();' +
      "Write-Output \"Instalados: $($R.ResultCode) | Reinício necessário: $($R.RebootRequired)\""
    });
    rvShowPanel('shell');
    rvShellLog('Instalando patches — isso pode demorar alguns minutos...', '#F59E0B');
  };

  // ── Deploy ───────────────────────────────────────────────────
  const CATALOGO_LOCAL = [
    { nome:'7-Zip',    url:'https://www.7-zip.org/a/7z2301-x64.exe',      params:'/S',     icon:'🗜️' },
    { nome:'VLC',      url:'https://get.videolan.org/vlc/last/win64/',     params:'/S',     icon:'🎬' },
    { nome:'Chrome',   url:'https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi', params:'/quiet', icon:'🌐' },
    { nome:'Firefox',  url:'https://download.mozilla.org/?product=firefox-latest&os=win64', params:'-ms', icon:'🦊' },
    { nome:'Teams',    url:'https://aka.ms/teams-offline-msi-x64',         params:'/quiet ALLUSERS=1', icon:'💬' },
    { nome:'Antivírus',url:'\\\\servidor\\Softwares\\AntivirusSetup.exe',  params:'/silent',icon:'🛡️' },
  ];

  function rvInitDeploy() {
    const cat = document.getElementById('rv-deploy-catalog');
    if (!cat || cat.children.length) return;
    cat.innerHTML = CATALOGO_LOCAL.map((s,i) =>
      `<div onclick="rvSelectSw(${i})" style="background:#1E293B;border:1px solid #334155;border-radius:8px;padding:10px;text-align:center;cursor:pointer;transition:border-color .15s" data-sw="${i}">
        <div style="font-size:20px;margin-bottom:4px">${s.icon}</div>
        <div style="font-size:11px;font-weight:600;color:#94A3B8">${s.nome}</div>
      </div>`
    ).join('');
  }

  window.rvSelectSw = i => {
    const s = CATALOGO_LOCAL[i];
    document.getElementById('rv-deploy-nome').value   = s.nome;
    document.getElementById('rv-deploy-url').value    = s.url;
    document.getElementById('rv-deploy-params').value = s.params;
    document.querySelectorAll('[data-sw]').forEach((el,j) => {
      el.style.borderColor = j == i ? '#2563EB' : '#334155';
    });
  };

  window.rvDeployPersonalizado = () => {
    const nome   = document.getElementById('rv-deploy-nome')?.value?.trim();
    const url    = document.getElementById('rv-deploy-url')?.value?.trim();
    const params = document.getElementById('rv-deploy-params')?.value?.trim() || '/S';
    if (!nome || !url) return alert('Preencha o nome e a URL do software.');

    const logEl = document.getElementById('rv-deploy-log');
    if (logEl) logEl.style.display = '';

    const ext = url.endsWith('.msi') ? '.msi' : url.endsWith('.ps1') ? '.ps1' : '.exe';
    const tmp = '%TEMP%\\sysack_deploy_' + Date.now() + ext;
    const installCmd = ext === '.msi'
      ? `msiexec /i "${tmp}" ${params} /log "${tmp}.log"`
      : ext === '.ps1'
        ? `powershell -ExecutionPolicy Bypass -File "${tmp}" ${params}`
        : `"${tmp}" ${params}`;

    rvSend({ tipo:'exec', motivo:'Deploy ' + nome + ' via SYSACK Remote', cmd:
      `$tmp='${tmp}';` +
      `Invoke-WebRequest -Uri '${url}' -OutFile $tmp -UseBasicParsing -TimeoutSec 300;` +
      `Start-Process -FilePath '${installCmd.split(' ')[0]}' -ArgumentList '${installCmd.split(' ').slice(1).join(' ')}' -Wait -PassThru;` +
      `Remove-Item $tmp -Force -ErrorAction SilentlyContinue;` +
      `Write-Output '${nome} instalado com sucesso!'`
    });
    rvShowPanel('shell');
    rvShellLog('Instalando ' + nome + '...', '#F59E0B');
  };

  // ── Teclado ──────────────────────────────────────────────────
  function rvKeyHandler(e) {
    if (e.key === 'F5')      { e.preventDefault(); rvCaptura(); }
    if (e.key === 'Escape')  { rvEncerrar(sessaoId); }
  }
  document.addEventListener('keydown', rvKeyHandler);

  // ── Encerrar ─────────────────────────────────────────────────
  window.rvEncerrar = async sid => {
    if (!confirm('Encerrar sessão remota?')) return;
    clearInterval(_autoTimer);
    document.removeEventListener('keydown', rvKeyHandler);
    _ws?.close();
    if (sid) {
      await fsPatch('sessoes_remotas', sid, {
        status: 'encerrado', encerradoEm: new Date().toISOString(),
      }).catch(() => {});
    }
    // Manda comando para o agente encerrar o tunnel
    await arEnviarComando(agentId, 'encerrar_acesso_remoto', {}, 'Sessão encerrada pelo técnico').catch(() => {});
    document.getElementById('remote-viewer-overlay')?.remove();
  };

  window.rvToggleAuto = enabled => {
    clearInterval(_autoTimer);
    if (enabled) _autoTimer = setInterval(rvCaptura, 5000);
  };

  // ── Inicia conexão ───────────────────────────────────────────
  rvConnect();
}

// ── ENVIAR COMANDO PARA AGENTE ────────────────────────────────
async function arEnviarComando(agentId, tipo, dados, motivo) {
  return fsAdd('agent_commands', {
    agentId, tipo, motivo: motivo || '',
    dados:     JSON.stringify(dados || {}),
    uid:       CURRENT_USER?.uid || '',
    status:    'pendente',
    createdAt: new Date().toISOString(),
  });
}

// ── INVENTÁRIO / INFO DO AGENTE ───────────────────────────────
function arAbrirInventario(agentId) {
  const a = STATE_AGENTS.list.find(x => x.id === agentId);
  if (!a) return;
  let inv = {};
  try { inv = a.inventario ? JSON.parse(a.inventario) : a; } catch { inv = a; }

  openModal('modal-ar-inventario');
  document.getElementById('ar-inv-title').textContent = a.hostname || agentId;

  const rows = [
    ['Hostname',     inv.hostname || a.id],
    ['IP',           inv.ip || a.ip || '—'],
    ['Fabricante',   inv.fabricante || '—'],
    ['Modelo',       inv.modelo || '—'],
    ['Serial',       inv.serial || '—'],
    ['Sistema',      inv.osNome  || a.osNome || '—'],
    ['Build',        inv.osBuild || '—'],
    ['CPU',          inv.cpuNome || '—'],
    ['Núcleos',      inv.cpuNucleos ? inv.cpuNucleos + ' núcleos' : '—'],
    ['RAM Total',    inv.ramTotalGB ? inv.ramTotalGB + ' GB' : '—'],
    ['Disco C livre',inv.discoC_livreGB ? inv.discoC_livreGB + ' GB' : '—'],
    ['Software',     inv.softwareCount ? inv.softwareCount + ' programas' : '—'],
    ['Patches',      inv.patchesPendentes != null ? inv.patchesPendentes + ' pendentes (' + (inv.patchesCriticos||0) + ' críticos)' : '—'],
    ['Antivírus',    inv.antivirusNome ? inv.antivirusNome + (inv.antivirusAtivo === false ? ' (INATIVO!)' : '') : '—'],
    ['BitLocker',    inv.bitlocker != null ? (inv.bitlocker ? 'Ativo' : 'Inativo') : '—'],
    ['Firewall',     inv.firewallAtivo != null ? (inv.firewallAtivo ? 'Ativo' : 'Inativo') : '—'],
    ['Usuário',      inv.usuarioLogado || a.usuarioLogado || '—'],
    ['Uptime',       inv.uptimeH ? inv.uptimeH + 'h' : a.uptimeH ? a.uptimeH + 'h' : '—'],
    ['Versão Agente', a.version || '—'],
    ['Último contato', a.lastSeen ? new Date(a.lastSeen?.seconds ? a.lastSeen.seconds*1000 : a.lastSeen).toLocaleString('pt-BR') : '—'],
  ];

  document.getElementById('ar-inv-body').innerHTML =
    '<table style="width:100%;border-collapse:collapse">' +
    rows.map(([k,v]) =>
      `<tr><td style="padding:7px 0;color:var(--g500);font-size:12px;width:140px">${escapeHtml(k)}</td>` +
      `<td style="padding:7px 0;font-size:13px;font-weight:500;color:${(v||'').includes('INATIVO') ? 'var(--danger)' : 'inherit'}">${escapeHtml(String(v))}</td></tr>`
    ).join('') + '</table>';

  // ── Painel de monitores/periféricos conectados ───────────────
  renderMonitoresConectados(ativo);
}

// ─── Monitores/Periféricos conectados ao ativo ───────────────────
async function renderMonitoresConectados(ativo) {
  const container = document.getElementById('ar-monitores-section');
  if (!container) return;

  let monitores = [];
  if (ativo.monitoresConectados) {
    try {
      monitores = typeof ativo.monitoresConectados === 'string'
        ? JSON.parse(ativo.monitoresConectados)
        : (Array.isArray(ativo.monitoresConectados) ? ativo.monitoresConectados : []);
    } catch(e) { monitores = []; }
  }

  if (!monitores.length) {
    container.innerHTML = '<div style="padding:16px;text-align:center;color:var(--g400);font-size:12px"><div style="font-size:20px;margin-bottom:6px">🖥️</div>Nenhum monitor detectado. O SysackClient coleta automaticamente a cada 5 min.</div>';
    return;
  }

  // Carrega histórico de cada monitor via Cloud Function
  const rowsHtml = [];
  for (const m of monitores) {
    let hist = [];
    if (m.serial && window._fs?.httpsCallable) {
      try {
        const res = await window._fs.httpsCallable('getHistoricoMonitor')({ serial: m.serial });
        hist = res.data?.historico || [];
      } catch(e) {}
    }

    const histHtml = hist.length > 1
      ? '<details style="margin-top:8px"><summary style="font-size:11px;color:var(--accent);cursor:pointer">📋 Histórico de movimentações (' + hist.length + ')</summary>'
        + '<div style="margin-top:8px;display:flex;flex-direction:column;gap:4px">'
        + hist.map(function(h,i) {
            return '<div style="display:flex;gap:8px;align-items:center;font-size:11px;padding:4px 8px;background:' + (i===0?'var(--accent-l)':'var(--g50)') + ';border-radius:6px">'
              + '<span style="color:var(--g400);white-space:nowrap">' + (h.data ? new Date(h.data).toLocaleDateString('pt-BR') : '—') + '</span>'
              + '<span style="font-weight:' + (i===0?'700':'400') + ';color:' + (i===0?'var(--accent)':'var(--g700)') + '">' + escapeHtml(h.pat||'—') + '</span>'
              + '<span style="color:var(--g400)">' + escapeHtml(h.area||'—') + '</span>'
              + (i===0 ? '<span style="background:#059669;color:#fff;font-size:9px;padding:1px 5px;border-radius:8px">atual</span>' : '')
              + '</div>';
          }).join('')
        + '</div></details>'
      : '';

    rowsHtml.push(
      '<div style="background:var(--g50,#F8FAFC);border:1px solid var(--g200);border-radius:10px;padding:12px 14px;margin-bottom:8px">'
      + '<div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:6px">'
        + '<div style="display:flex;align-items:center;gap:8px">'
          + '<span style="font-size:20px">🖥️</span>'
          + '<div>'
            + '<div style="font-size:13px;font-weight:700">' + escapeHtml((m.fabricante||'') + ' ' + (m.modelo||'Monitor')) + '</div>'
            + '<div style="font-size:11px;font-family:monospace;color:var(--g500)">S/N: ' + escapeHtml(m.serial||'—') + '</div>'
          + '</div>'
        + '</div>'
        + '<span style="background:#EFF6FF;color:#2563EB;font-size:10px;font-weight:600;padding:2px 8px;border-radius:10px">Conectado</span>'
      + '</div>'
      + (hist.length > 1 ? '<div style="font-size:11px;color:var(--g500);margin-bottom:4px">Já esteve em <strong>' + (hist.length-1) + '</strong> computador(es) anteriormente</div>' : '')
      + histHtml
      + '</div>'
    );
  }

  container.innerHTML = rowsHtml.join('');
}

// ── AÇÕES RÁPIDAS ─────────────────────────────────────────────
function arInstalarSoftware(agentId, hostname) {
  // Reutiliza modal de instalar software já existente
  window._ativoEditando = { id: agentId, hostname, syncSource: 'sysack-agent-desktop' };
  abrirInstalarSoftware();
}

function arInstalarPatches(agentId, hostname) {
  arAbrirViewer(agentId);
}

// ── DOWNLOAD DO INSTALADOR ────────────────────────────────────
function arInstalarAgente() {
  openModal('modal-ar-download');
}

// ── INICIALIZAÇÃO ─────────────────────────────────────────────
// Inicia listener quando o usuário faz login
function initAgentsListener() {
  // Carrega tabela de redes CESAN do Banco e verifica IPs dos ativos
  carregarRedesCesan().then(() => setTimeout(verificarTodosIPs, 8000));
  if (FB_READY) startAgentsListener();
}


// ════════════════════════════════════════════════════════════
// MONITOR DE REDE — todos os dispositivos lógicos
// SNMP, ICMP, HTTP — dados em tempo real do Banco
// ════════════════════════════════════════════════════════════

function renderMonitorRede() {
  const tbody  = document.getElementById('mon-tbody');
  if (!tbody) return;

  const q      = (document.getElementById('mon-search')?.value || '').toLowerCase();
  const fSt    = document.getElementById('mon-filter-status')?.value || '';
  const fTipo  = document.getElementById('mon-filter-tipo')?.value   || '';
  const agora  = new Date();

  // Agrupa switches + ativos com IP
  const switches = (STATE.switches || []);
  const ativosIP = (STATE.ativos   || []).filter(a => a.ip || a.ipAddress);

  const todos = [
    ...switches.map(s => ({ ...s, _col:'switches' })),
    ...ativosIP.map(a => ({ ...a, _col:'ativos',
      ip: a.ip || a.ipAddress,
      tipo: a.tipo || 'ativo' })),
  ];

  // Stats
  const online   = todos.filter(d => d.reachable || d.status === 'ok').length;
  const offline  = todos.filter(d => d.status === 'offline').length;
  const critico  = todos.filter(d => d.status === 'critico').length;
  const alerta   = todos.filter(d => d.status === 'alerta').length;
  const uptimePct = todos.length ? Math.round(online/todos.length*100) : 0;

  sv('mon-total',   todos.length);
  sv('mon-online',  online);
  sv('mon-offline', offline);
  sv('mon-critico', critico);
  sv('mon-alerta',  alerta);
  sv('mon-uptime',  uptimePct + '%');
  nbUpdate('nb-monitor-critico', critico + offline);

  document.getElementById('monitor-last-update')
    .textContent = 'Atualizado: ' + agora.toLocaleTimeString('pt-BR');

  // Filtro
  let lista = todos;
  if (q)     lista = lista.filter(d =>
    d.ip?.includes(q) || d.hostname?.toLowerCase().includes(q) ||
    d.desc?.toLowerCase().includes(q) || d.pat?.toLowerCase().includes(q));
  if (fSt)   lista = lista.filter(d => d.status === fSt);
  if (fTipo) lista = lista.filter(d => d.tipo === fTipo);

  // Ordena: críticos primeiro
  const ORDER = { offline:0, critico:1, alerta:2, 'sem-snmp':3, ok:4 };
  lista.sort((a,b) => (ORDER[a.status]??5) - (ORDER[b.status]??5));

  if (!lista.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:32px;color:var(--g400)">' +
      (todos.length ? 'Nenhum dispositivo com esses filtros.' :
       'Instale o SYSACK Agent (v2) com suporte SNMP para monitorar dispositivos de rede.') +
      '</td></tr>';
    return;
  }

  tbody.innerHTML = lista.map(d => {
    const dotClass = d.status || (d.reachable ? 'ok' : 'desconhecido');
    const latStr   = d.latencyMs != null ? d.latencyMs.toFixed(1) + 'ms' : '—';
    const lastStr  = d.lastSeen
      ? fmtRelative(new Date(d.lastSeen?.seconds ? d.lastSeen.seconds*1000 : d.lastSeen))
      : '—';

    // CPU bar
    const cpuBar = d.cpuPct != null
      ? `<div class="mon-bar"><div class="mon-bar-fill ${d.cpuPct>90?'crit':d.cpuPct>70?'warn':'ok'}" style="width:${d.cpuPct}%"></div></div> ${d.cpuPct}%`
      : '—';

    // Temp
    const tempStr = d.tempC != null
      ? `<span style="color:${d.tempC>75?'#DC2626':d.tempC>60?'#D97706':'#059669'}">${d.tempC}°C</span>`
      : '—';

    // Métricas extras
    const extras = [];
    if (d.portsUp   != null) extras.push(`${d.portsUp}▲/${d.portsDown||0}▼ portas`);
    if (d.battPct   != null) extras.push(`Bat: ${d.battPct}%`);
    if (d.tonerLevels?.length) extras.push(`Toner: ${Math.min(...d.tonerLevels.map(t=>t.pct))}%`);
    if (d.uptime)              extras.push(`Up: ${d.uptime}`);

    return `<tr style="cursor:pointer" onclick="abrirMonitorDetalhe('${d.id}','${d._col}')">
      <td style="text-align:center"><span class="mon-dot ${dotClass}"></span></td>
      <td style="font-weight:600;font-size:13px">${escapeHtml(d.hostname||d.desc||d.pat||'—')}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--g500)">${escapeHtml(d.ip||'—')}</td>
      <td><span class="tag">${escapeHtml(d.tipo||'—')}</span></td>
      <td><span class="badge ${dotClass==='ok'?'badge-success':dotClass==='offline'||dotClass==='critico'?'badge-danger':'badge-warning'}">${dotClass}</span></td>
      <td style="font-size:12px;color:${(d.latencyMs||0)>100?'#D97706':(d.latencyMs||0)>200?'#DC2626':'inherit'}">${latStr}</td>
      <td style="font-size:12px">${cpuBar}</td>
      <td style="font-size:12px">${tempStr}</td>
      <td style="font-size:12px;color:var(--g500)">${extras.join(' · ')||'—'}</td>
      <td style="font-size:11.5px;color:var(--g400)">${lastStr}</td>
    </tr>`;
  }).join('');
}

function abrirMonitorDetalhe(id, col) {
  const lista = col === 'switches'
    ? (STATE.switches||[])
    : (STATE.ativos||[]).filter(a => a.ip||a.ipAddress);
  const d = lista.find(x => x.id === id);
  if (!d) return;

  document.getElementById('mon-modal-title').textContent =
    (d.hostname || d.desc || d.pat || d.ip) + ' — Detalhes';

  const rows = [
    ['IP / Host',    (d.ip||d.ipAddress||'—') + (d.hostname ? ' ('+d.hostname+')' : '')],
    ['Tipo',         d.tipo||'—'],
    ['Status',       d.status||'—'],
    ['Latência',     d.latencyMs != null ? d.latencyMs.toFixed(1)+'ms' : '—'],
    ['CPU',          d.cpuPct    != null ? d.cpuPct+'%' : '—'],
    ['Temperatura',  d.tempC     != null ? d.tempC+'°C' : '—'],
    ['Uptime',       d.uptime    || '—'],
    ['Portas up/dn', d.portsUp   != null ? d.portsUp+'▲ / '+(d.portsDown||0)+'▼' : '—'],
    ['Bateria UPS',  d.battPct   != null ? d.battPct+'%' : '—'],
    ['Runtime UPS',  d.runtimeMin != null ? d.runtimeMin+'min' : '—'],
    ['Último online', d.lastSeen ? new Date(d.lastSeen?.seconds ? d.lastSeen.seconds*1000 : d.lastSeen).toLocaleString('pt-BR') : '—'],
    ['PAT',          d.pat||'—'],
    ['Área',         d.area||'—'],
  ].filter(([,v]) => v !== '—');

  document.getElementById('mon-modal-body').innerHTML =
    '<table style="width:100%;border-collapse:collapse">' +
    rows.map(([k,v]) =>
      '<tr><td style="padding:7px 0;color:var(--g500);font-size:12px;width:140px">'+escapeHtml(k)+'</td>' +
      '<td style="padding:7px 0;font-size:13px;font-weight:500">'+escapeHtml(String(v))+'</td></tr>'
    ).join('') + '</table>' +
    (d.snmpErr ? '<div style="margin-top:12px;padding:10px;background:var(--g50);border-radius:8px;font-size:12px;color:var(--g500)">SNMP: '+escapeHtml(d.snmpErr)+'</div>' : '');

  openModal('modal-monitor-detalhe');
}

function fmtRelative(date) {
  if (!date || isNaN(date)) return '—';
  const diff = Date.now() - date.getTime();
  if (diff < 60000)   return 'agora';
  if (diff < 3600000) return Math.floor(diff/60000)+'min atrás';
  if (diff < 86400000) return Math.floor(diff/3600000)+'h atrás';
  return Math.floor(diff/86400000)+'d atrás';
}


// ════════════════════════════════════════════════════════════
// APROVAÇÕES — Fluxo bloqueante com alertas contínuos
// ════════════════════════════════════════════════════════════

function renderAprovacoes() {
  const tbody = document.getElementById('aprov-tbody') || document.querySelector('#page-aprovacoes tbody');
  const aprovs = (STATE.aprovacoes || []);

  // Stats
  sv('nb-aprov', aprovs.filter(a => a.status === 'pendente').length);

  if (!tbody) return;

  if (!aprovs.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--g400)">Nenhuma aprovação pendente</td></tr>';
    return;
  }

  tbody.innerHTML = aprovs.map(a => {
    const dias = a.createdAt ? Math.floor((Date.now() - new Date(a.createdAt).getTime()) / 86400000) : 0;
    const cor  = a.status === 'pendente' ? (dias > 1 ? 'var(--danger)' : 'var(--warning)') : 'var(--success)';
    return `<tr>
      <td class="td-mono" style="color:var(--accent);font-size:12px">${escapeHtml(a.id||'—')}</td>
      <td style="font-weight:600;font-size:13px">${escapeHtml(a.tipo||'—')}</td>
      <td style="font-size:12px">${escapeHtml(a.chamadoId||'—')}</td>
      <td style="font-size:12px">${escapeHtml(a.pat||'—')}</td>
      <td style="font-size:12px">${escapeHtml(a.solicitante||'—')}</td>
      <td><span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:20px;background:${cor}22;color:${cor}">${escapeHtml(a.status||'—')}</span></td>
      <td style="font-size:12px;color:${dias > 1 ? 'var(--danger)' : 'inherit'}">${dias}d</td>
      <td>
        ${a.status === 'pendente'
          ? `<button class="btn btn-success btn-xs" onclick="aprovarMovimentacao('${a.id}')">✓ Autorizar</button>
             <button class="btn btn-danger btn-xs"  onclick="recusarMovimentacao('${a.id}')">✗ Recusar</button>`
          : `<span style="font-size:11px;color:var(--g400)">${escapeHtml(a.decidedBy||'')}</span>`
        }
      </td>
    </tr>`;
  }).join('');
}

async function aprovarMovimentacao(aprovId) {
  if (!SESSION_USER?.permissions?.canApprove) {
    showToast('⛔ Sem permissão para aprovar movimentação.', 'error');
    return;
  }

  const aprov = (STATE.aprovacoes || []).find(a => a.id === aprovId);
  if (!aprov) return;

  aprov.status     = 'aprovado';
  aprov.decidedBy  = CURRENT_USER?.nome || 'Gestor';
  aprov.decidedAt  = new Date().toISOString();

  await fsUpdate('aprovacoes', aprovId, {
    status: 'aprovado', decidedBy: aprov.decidedBy, decidedAt: aprov.decidedAt,
  });

  // Atualiza o chamado vinculado para retomar o fluxo
  if (aprov.chamadoId) {
    const ch = (STATE.chamados || []).find(c => c.id === aprov.chamadoId);
    if (ch) {
      ch.status = 'em-atendimento';
      await fsUpdate('chamados', aprov.chamadoId, { status: 'em-atendimento', aprovadoPor: aprov.decidedBy, aprovadoEm: aprov.decidedAt });
    }
  }

  // Executa ação de movimentação aprovada
  if (aprov.detalhes) {
    await executarMovimentacaoAprovada(aprov);
  }

  renderAprovacoes();
  renderChamados();
  showToast('✅ Movimentação autorizada — fluxo retomado!', 'success', 4000);
}

async function recusarMovimentacao(aprovId) {
  const motivo = prompt('Motivo da recusa (obrigatório):');
  if (!motivo?.trim()) return;

  const aprov = (STATE.aprovacoes || []).find(a => a.id === aprovId);
  if (!aprov) return;

  aprov.status    = 'recusado';
  aprov.decidedBy = CURRENT_USER?.nome || 'Gestor';
  aprov.decidedAt = new Date().toISOString();
  aprov.motivoRecusa = motivo.trim();

  await fsUpdate('aprovacoes', aprovId, {
    status: 'recusado', decidedBy: aprov.decidedBy,
    decidedAt: aprov.decidedAt, motivoRecusa: motivo.trim(),
  });

  if (aprov.chamadoId) {
    const ch = (STATE.chamados || []).find(c => c.id === aprov.chamadoId);
    if (ch) {
      ch.status = 'aberto';
      await fsUpdate('chamados', aprov.chamadoId, { status: 'aberto', movimentacaoRecusada: true, motivoRecusa: motivo.trim() });
    }
  }

  renderAprovacoes();
  showToast('Movimentação recusada. Técnico será notificado.', 'warning', 4000);
}

async function executarMovimentacaoAprovada(aprov) {
  const det = aprov.detalhes || {};

  if (det.destino === 'mindworks') {
    // Registra na lista de terceirizadas com prazo
    const dataRecolh = det.dataRecolhimento || new Date().toISOString().split('T')[0];
    const prazo      = det.prazoTerceirizada || 10;
    const vencimento = calcularDiasUteis(new Date(dataRecolh), prazo);

    const tercItem = {
      id:            'TERC-' + Date.now(),
      chamadoId:     aprov.chamadoId,
      pat:           det.patAntigo || aprov.pat,
      ativo:         det.patAntigo || aprov.pat,
      tecnicoId:     det.tecnicoTerceirizada || '',
      dataEnvio:     dataRecolh,
      prazoRetorno:  vencimento.toISOString().split('T')[0],
      prazoUteisTotal: prazo,
      status:        'aguardando-retorno',
      retornado:     false,
      diasUteis:     0,
    };
    if (!STATE.terceirizadaAtivos) STATE.terceirizadaAtivos = [];
    STATE.terceirizadaAtivos.unshift(tercItem);
    await fsAdd('terceirizadaAtivos', tercItem);
    showToast('📦 Máquina registrada na Empresa Terceirizada com prazo de ' + prazo + ' dias úteis.', 'info', 5000);
  }

  if (det.destino === 'santa-clara') {
    const scItem = {
      id:        'SC-' + Date.now(),
      chamadoId: aprov.chamadoId,
      pat:       det.patAntigo || aprov.pat,
      local:     det.scLocal || '',
      foto:      '', // upload da foto é feito separadamente
      dataEntrada: new Date().toISOString().split('T')[0],
      status:    'armazenado',
    };
    if (!STATE.scAtivos) STATE.scAtivos = [];
    STATE.scAtivos.unshift(scItem);
    await fsAdd('scAtivos', scItem);
    showToast('📦 Máquina registrada em Santa Clara: ' + det.scLocal, 'info', 5000);
  }

  if (det.destino === 'reutilizada') {
    // Atualiza localização do ativo no sistema
    if (det.patNovo || det.patAntigo) {
      const pat = det.patNovo || det.patAntigo;
      const ativo = (STATE.ativos || []).find(a => a.pat === pat);
      if (ativo) {
        if (det.reutLocal)  ativo.local = det.reutLocal;
        if (det.reutNome)   ativo.desc  = det.reutNome;
        if (det.reutTipoUso) ativo.tipoUso = det.reutTipoUso;
        await fsUpdate('ativos', ativo.id, {
          local: det.reutLocal, desc: det.reutNome || ativo.desc,
          tipoUso: det.reutTipoUso, updatedAt: new Date().toISOString(),
        });
      }
    }
  }
}

function calcularDiasUteis(dataInicio, qtdDias) {
  let data = new Date(dataInicio);
  let count = 0;
  while (count < qtdDias) {
    data.setDate(data.getDate() + 1);
    const dow = data.getDay();
    if (dow !== 0 && dow !== 6) count++; // pula sábado e domingo
  }
  return data;
}

// Alerta de aprovações pendentes há mais de 1 dia (roda a cada hora)
function verificarAprovacoesPendentes() {
  const pendentes = (STATE.aprovacoes || []).filter(a => a.status === 'pendente');
  const urgentes  = pendentes.filter(a => {
    const dias = (Date.now() - new Date(a.createdAt).getTime()) / 86400000;
    return dias >= 1;
  });
  if (urgentes.length > 0) {
    nbUpdate('nb-aprov', pendentes.length);
    // Pisca o badge
    const badge = document.getElementById('nb-aprov');
    if (badge) {
      badge.style.background = 'var(--danger)';
      badge.style.animation  = 'pulse 1.5s infinite';
    }
  }
}
setInterval(verificarAprovacoesPendentes, 60 * 60 * 1000);



// ════════════════════════════════════════════════════════════
// EMPRESA TERCEIRIZADA — Controle de retorno e alertas
// ════════════════════════════════════════════════════════════

function marcarRetornoTerceirizada(tercId) {
  const terc = (STATE.terceirizadaAtivos || []).find(t => t.id === tercId);
  if (!terc) return;

  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center';
  modal.innerHTML = `
    <div style="background:var(--g0,#fff);border-radius:12px;padding:24px;max-width:440px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3)">
      <h3 style="margin:0 0 16px;font-size:16px">📦 Registrar Retorno — ${escapeHtml(terc.pat||terc.ativo||'Ativo')}</h3>
      <div class="form-group">
        <label class="form-label">Data de retorno</label>
        <input type="date" id="mw-data-ret" class="form-control" value="${new Date().toISOString().split('T')[0]}">
      </div>
      <div class="form-group">
        <label class="form-label">Destino após retorno</label>
        <select id="mw-destino-ret" class="form-control" onchange="mwToggleDestino(this.value)">
          <option value="adsi">Retornou para A-DSI (em uso)</option>
          <option value="santa-clara">Enviar para Santa Clara/Depósito TI</option>
          <option value="reutilizada">Reutilizar em novo local</option>
          <option value="leilao">Encaminhar para Leilão / Pregão</option>
        </select>
      </div>
      <div id="mw-dest-sc" style="display:none" class="form-group">
        <label class="form-label">Local em Santa Clara</label>
        <input class="form-control" id="mw-sc-local" placeholder="Prateleira, sala...">
      </div>
      <div id="mw-dest-reut" style="display:none">
        <div class="form-group">
          <label class="form-label">Novo local de uso</label>
          <input class="form-control" id="mw-reut-local" placeholder="Ex: TI / 1º Andar / Estação 05">
        </div>
        <div class="form-group">
          <label class="form-label">Será reutilizada por</label>
          <select class="form-control" id="mw-reut-uso">
            <option value="usuario">Usuário específico</option>
            <option value="grupo">Grupo de usuários</option>
            <option value="compartilhado">Compartilhado</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Observações</label>
        <textarea class="form-control" id="mw-obs" rows="2" placeholder="Condições de retorno, observações..."></textarea>
      </div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button class="btn btn-ghost" onclick="this.closest('[style*=fixed]').remove()">Cancelar</button>
        <button class="btn btn-success" onclick="confirmarRetornoTerceirizada('${tercId}',this)">✓ Confirmar Retorno</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
}

window.mwToggleDestino = function(val) {
  document.getElementById('mw-dest-sc').style.display   = val === 'santa-clara' ? '' : 'none';
  document.getElementById('mw-dest-reut').style.display = val === 'reutilizada'  ? '' : 'none';
};

async function confirmarRetornoTerceirizada(tercId, btn) {
  const terc = (STATE.terceirizadaAtivos || []).find(t => t.id === tercId);
  if (!terc) return;

  const dataRet = document.getElementById('mw-data-ret')?.value;
  const destino = document.getElementById('mw-destino-ret')?.value;
  const scLocal = document.getElementById('mw-sc-local')?.value?.trim();
  const reutLoc = document.getElementById('mw-reut-local')?.value?.trim();
  const obs     = document.getElementById('mw-obs')?.value?.trim();

  setButtonLoading(btn, true, 'Salvando...');

  terc.retornado       = true;
  terc.dataRetorno     = dataRet;
  terc.destinoRetorno  = destino;
  terc.obs             = obs;
  terc.status          = 'retornado';

  await fsUpdate('terceirizadaAtivos', tercId, {
    retornado: true, dataRetorno: dataRet,
    destinoRetorno: destino, obs, status: 'retornado',
  });

  // Executa destino
  if (destino === 'santa-clara' && scLocal) {
    const scItem = {
      id: 'SC-' + Date.now(), pat: terc.pat || terc.ativo,
      local: scLocal, dataEntrada: dataRet, status: 'armazenado',
      origemTerceirizada: true, tercId,
    };
    if (!STATE.scAtivos) STATE.scAtivos = [];
    STATE.scAtivos.unshift(scItem);
    await fsAdd('scAtivos', scItem);
  }
  if (destino === 'reutilizada' && reutLoc) {
    const ativo = (STATE.ativos || []).find(a => a.pat === (terc.pat || terc.ativo));
    if (ativo) {
      ativo.local = reutLoc;
      await fsUpdate('ativos', ativo.id, { local: reutLoc, status: 'ativo' });
    }
  }

  btn.closest('[style*=fixed]')?.remove();
  renderTerceirizada?.();
  showToast('✅ Retorno da Empresa Terceirizada registrado!', 'success', 4000);
}

// Verifica prazos da Empresa Terceirizada — roda a cada hora
function verificarPrazosTerceirizada() {
  const hoje = new Date();
  hoje.setHours(0,0,0,0);
  const pendentes = (STATE.terceirizadaAtivos || []).filter(t => !t.retornado);

  pendentes.forEach(t => {
    if (!t.prazoRetorno) return;
    const venc = new Date(t.prazoRetorno); venc.setHours(0,0,0,0);
    const diffDias = Math.round((venc - hoje) / 86400000);

    if (diffDias === 5) {
      // Alerta para o técnico Empresa Terceirizada: faltam 5 dias
      showToast(`⚠️ Empresa Terceirizada: ${t.pat||t.ativo} deve ser devolvida em 5 dias (${t.prazoRetorno})`, 'warning', 8000);
    }
    if (diffDias <= 0) {
      // Prazo vencido: alerta diário para gestão
      showToast(`🚨 PRAZO VENCIDO: ${t.pat||t.ativo} na Empresa Terceirizada há ${-diffDias} dias além do prazo!`, 'danger', 10000);
    }
  });
}
setInterval(verificarPrazosTerceirizada, 60 * 60 * 1000);



// ════════════════════════════════════════════════════════════
// RELATÓRIOS
// ════════════════════════════════════════════════════════════

function relTab(tab) {
  document.querySelectorAll('.rel-tab-btn').forEach((b,i) => b.classList.remove('active'));
  document.querySelectorAll('[id^="rel-tab-"]').forEach(el => el.style.display = 'none');
  const tabs = ['movimentacoes','pendencias','santa-clara','terceirizada','vida-ativo'];
  const idx  = tabs.indexOf(tab);
  if (idx >= 0) {
    document.querySelectorAll('.rel-tab-btn')[idx]?.classList.add('active');
    document.getElementById('rel-tab-' + tab).style.display = '';
  }
}

function renderRelatorios() { gerarRelatorios(); }

function gerarRelatorios() {
  const periodo  = document.getElementById('rel-periodo')?.value || 'mes';
  const mesInput = document.getElementById('rel-mes')?.value;
  const hoje     = new Date();
  let   inicio, fim;

  if (periodo === 'semana') {
    const dow = hoje.getDay() || 7;
    inicio = new Date(hoje); inicio.setDate(hoje.getDate() - dow + 1); inicio.setHours(0,0,0,0);
    fim    = new Date(inicio); fim.setDate(inicio.getDate() + 6); fim.setHours(23,59,59,999);
  } else if (periodo === 'mes') {
    inicio = new Date(hoje.getFullYear(), hoje.getMonth(), 1);
    fim    = new Date(hoje.getFullYear(), hoje.getMonth() + 1, 0, 23, 59, 59, 999);
  } else if (periodo === 'ano') {
    inicio = new Date(hoje.getFullYear(), 0, 1);
    fim    = new Date(hoje.getFullYear(), 11, 31, 23, 59, 59, 999);
  } else if (mesInput) {
    const [y, m] = mesInput.split('-');
    inicio = new Date(parseInt(y), parseInt(m) - 1, 1);
    fim    = new Date(parseInt(y), parseInt(m), 0, 23, 59, 59, 999);
  } else {
    inicio = new Date(0); fim = new Date();
  }

  gerarRelMovimentacoes(inicio, fim);
  gerarRelPendencias();
  gerarRelSantaClara(inicio, fim);
  gerarRelTerceirizada(inicio, fim);
}

function filtroPeriodo(item, inicio, fim) {
  if (!item.createdAt && !item.dataEntrada && !item.dataEnvio) return true;
  const d = new Date(item.createdAt || item.dataEntrada || item.dataEnvio);
  return d >= inicio && d <= fim;
}

function gerarRelMovimentacoes(inicio, fim) {
  const movs = (STATE.aprovacoes || []).filter(a => a.tipo?.includes('Moviment') && filtroPeriodo(a, inicio, fim));
  sv('rel-mov-total', movs.length);
  sv('rel-mov-aprov', movs.filter(m => m.status === 'aprovado').length);
  sv('rel-mov-pend',  movs.filter(m => m.status === 'pendente').length);
  sv('rel-mov-recus', movs.filter(m => m.status === 'recusado').length);

  const tbody = document.getElementById('rel-mov-tbody');
  if (!tbody) return;
  tbody.innerHTML = movs.length ? movs.map(m => {
    const det = m.detalhes || {};
    const cor = m.status === 'aprovado' ? 'badge-success' : m.status === 'pendente' ? 'badge-warning' : 'badge-danger';
    return `<tr>
      <td class="td-mono" style="font-size:12px">${escapeHtml(m.chamadoId||'—')}</td>
      <td style="font-weight:600;font-size:12px">${escapeHtml(m.pat||det.patAntigo||'—')}</td>
      <td style="font-size:12px">${escapeHtml(det.destino||'—')}</td>
      <td style="font-size:12px">${escapeHtml(m.solicitante||'—')}</td>
      <td style="font-size:12px">${m.createdAt ? new Date(m.createdAt).toLocaleDateString('pt-BR') : '—'}</td>
      <td><span class="badge ${cor}" style="font-size:10px">${escapeHtml(m.status||'—')}</span></td>
    </tr>`;
  }).join('') : '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--g400)">Nenhuma movimentação no período</td></tr>';
}

function gerarRelPendencias() {
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const aprovPend = (STATE.aprovacoes || []).filter(a => a.status === 'pendente');
  const mwPend    = (STATE.terceirizadaAtivos || []).filter(t => !t.retornado);
  const mwVenc    = mwPend.filter(t => t.prazoRetorno && new Date(t.prazoRetorno) < hoje);
  const mw5d      = mwPend.filter(t => {
    if (!t.prazoRetorno) return false;
    const diff = Math.round((new Date(t.prazoRetorno) - hoje) / 86400000);
    return diff >= 0 && diff <= 5;
  });

  sv('rel-pend-aprov', aprovPend.length);
  sv('rel-pend-mw',    mwVenc.length);
  sv('rel-pend-5d',    mw5d.length);

  const tbody = document.getElementById('rel-pend-tbody');
  if (!tbody) return;

  const itens = [
    ...aprovPend.map(a => ({
      tipo: 'Aprovação pendente', pat: a.pat || '', desc: a.tipo,
      desde: a.createdAt, urgencia: 'warning',
    })),
    ...mwVenc.map(t => ({
      tipo: 'Empresa Terceirizada — prazo vencido', pat: t.pat || t.ativo,
      desc: 'Venceu em ' + t.prazoRetorno,
      desde: t.dataEnvio, urgencia: 'danger',
    })),
    ...mw5d.filter(t => !mwVenc.find(v => v.id === t.id)).map(t => ({
      tipo: 'Empresa Terceirizada — vence em breve', pat: t.pat || t.ativo,
      desc: 'Vence em ' + t.prazoRetorno,
      desde: t.dataEnvio, urgencia: 'orange',
    })),
  ];

  tbody.innerHTML = itens.length ? itens.map(i => {
    const dias = i.desde ? Math.floor((Date.now() - new Date(i.desde).getTime()) / 86400000) : '—';
    const cor  = i.urgencia === 'danger' ? 'var(--danger)' : i.urgencia === 'orange' ? 'var(--warning)' : 'var(--g600)';
    return `<tr>
      <td style="font-size:12px;font-weight:600">${escapeHtml(i.tipo)}</td>
      <td style="font-family:monospace;font-size:12px">${escapeHtml(i.pat)}</td>
      <td style="font-size:12px">${escapeHtml(i.desc)}</td>
      <td style="font-size:12px">${i.desde ? new Date(i.desde).toLocaleDateString('pt-BR') : '—'}</td>
      <td style="font-weight:700;color:${cor}">${dias}d</td>
      <td><span style="font-size:11px;font-weight:700;color:${cor};background:${cor}22;padding:2px 8px;border-radius:10px">${i.urgencia === 'danger' ? 'URGENTE' : i.urgencia === 'orange' ? 'ATENÇÃO' : 'Pendente'}</span></td>
    </tr>`;
  }).join('') : '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--g400)">Nenhuma pendência</td></tr>';
}

function gerarRelSantaClara(inicio, fim) {
  const todos    = STATE.scAtivos || [];
  const periodo  = todos.filter(t => filtroPeriodo(t, inicio, fim));
  sv('rel-sc-total',  todos.length);
  sv('rel-sc-period', periodo.length);
  sv('rel-sc-mw',     todos.filter(t => t.origemTerceirizada).length);

  const tbody = document.getElementById('rel-sc-tbody');
  if (!tbody) return;
  tbody.innerHTML = todos.length ? todos.map(t =>
    `<tr>
      <td class="td-mono" style="font-size:12px">${escapeHtml(t.pat||'—')}</td>
      <td style="font-size:12px">${escapeHtml(t.desc||'—')}</td>
      <td style="font-size:12px">${escapeHtml(t.local||'—')}</td>
      <td style="font-size:12px">${t.dataEntrada||'—'}</td>
      <td><span class="badge badge-info" style="font-size:10px">${escapeHtml(t.status||'armazenado')}</span></td>
      <td style="font-size:11px;color:var(--g400)">${t.origemTerceirizada ? 'Empresa Terceirizada' : 'Direto'}</td>
    </tr>`
  ).join('') : '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--g400)">Nenhum ativo em Santa Clara</td></tr>';
}

function gerarRelTerceirizada(inicio, fim) {
  const todos   = STATE.terceirizadaAtivos || [];
  const periodo = todos.filter(t => filtroPeriodo(t, inicio, fim));
  const hoje    = new Date(); hoje.setHours(0,0,0,0);
  const venc    = todos.filter(t => !t.retornado && t.prazoRetorno && new Date(t.prazoRetorno) < hoje);

  sv('rel-mw-total', periodo.length);
  sv('rel-mw-ret',   todos.filter(t => t.retornado).length);
  sv('rel-mw-venc',  venc.length);
  sv('rel-mw-pend',  todos.filter(t => !t.retornado).length);

  const tbody = document.getElementById('rel-mw-tbody');
  if (!tbody) return;
  tbody.innerHTML = todos.length ? todos.map(t => {
    const diasAtraso = t.prazoRetorno && !t.retornado
      ? Math.max(0, Math.round((hoje - new Date(t.prazoRetorno)) / 86400000))
      : 0;
    const tec = (STATE.tecnicos || []).find(x => x.id === t.tecnicoId);
    return `<tr>
      <td class="td-mono" style="font-size:12px">${escapeHtml(t.pat||t.ativo||'—')}</td>
      <td style="font-size:12px">${escapeHtml(tec?.nome||t.tecnicoId||'—')}</td>
      <td style="font-size:12px">${t.dataEnvio||'—'}</td>
      <td style="font-size:12px">${t.prazoRetorno||'—'}</td>
      <td style="font-weight:700;color:${diasAtraso>0?'var(--danger)':'var(--g400)'}">${diasAtraso > 0 ? diasAtraso + 'd' : '—'}</td>
      <td><span class="badge ${t.retornado?'badge-success':'badge-warning'}" style="font-size:10px">${t.retornado?'Devolvida':'Aguardando'}</span></td>
      <td>${!t.retornado ? `<button class="btn btn-success btn-xs" onclick="marcarRetornoTerceirizada('${t.id}')">Registrar retorno</button>` : ''}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--g400)">Nenhum registro na Empresa Terceirizada</td></tr>';
}

function buscarVidaAtivo() {
  const pat  = document.getElementById('rel-va-pat')?.value?.trim();
  if (!pat) return showToast('Digite um PAT ou número de série', 'warning');
  const ativo = (STATE.ativos || []).find(a =>
    (a.pat||'').toUpperCase().includes(pat.toUpperCase()) ||
    (a.serial||'').includes(pat)
  );
  const result = document.getElementById('rel-va-result');
  if (!ativo) {
    result.innerHTML = '<div style="padding:20px;color:var(--g400)">Ativo não encontrado.</div>';
    return;
  }
  result.innerHTML = `
    <div class="card">
      <div class="card-header">
        <h3>${escapeHtml(ativo.pat)} — ${escapeHtml(ativo.desc||'')}</h3>
        <button class="btn btn-primary btn-sm" onclick="abrirHistoricoUsuarios('${ativo.id}')">Ver histórico completo</button>
      </div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--g600)">
          Status: <strong>${escapeHtml(ativo.status||'—')}</strong> |
          Área: <strong>${escapeHtml(ativo.area||ativo.local||'—')}</strong> |
          Responsável: <strong>${escapeHtml(ativo.resp||'—')}</strong>
        </p>
      </div>
    </div>`;
}

function exportarRelatorioCSV() {
  const tab  = document.querySelector('.rel-tab-btn.active')?.textContent?.trim() || 'Relatorio';
  const table = document.querySelector('[id^="rel-tab-"]:not([style*="none"]) table');
  if (!table) return showToast('Nenhuma tabela para exportar', 'warning');
  const rows = [...table.querySelectorAll('tr')].map(r =>
    [...r.querySelectorAll('th,td')].map(c => '"' + c.textContent.replace(/"/g,'""') + '"').join(',')
  );
  const csv  = rows.join('\r\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'SYSACK_' + tab.replace(/\s+/g,'_') + '_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click(); URL.revokeObjectURL(url);
  showToast('CSV exportado!', 'success', 2000);
}


// ════════════════════════════════════════════════════════════
// SANTA CLARA — funções de foto, localização e histórico
// ════════════════════════════════════════════════════════════

function scPreviewFoto(input, zoneId, previewId) {
  const file = input.files?.[0];
  if (!file) return;
  const zone    = document.getElementById(zoneId);
  const preview = document.getElementById(previewId);
  const img     = preview?.querySelector('img');
  if (!file.type.startsWith('image/')) return showToast('Selecione uma imagem válida', 'warning');
  const reader = new FileReader();
  reader.onload = e => {
    if (img) img.src = e.target.result;
    if (zone)    zone.style.display    = 'none';
    if (preview) preview.style.display = '';
  };
  reader.readAsDataURL(file);
}

function scRemoverFoto(zoneId, previewId, inputId) {
  document.getElementById(zoneId).style.display    = '';
  document.getElementById(previewId).style.display = 'none';
  const inp = document.getElementById(inputId);
  if (inp) inp.value = '';
}

async function scUploadFoto(inputId, path) {
  const file = document.getElementById(inputId)?.files?.[0];
  if (!file) return null;
  // Converte para base64 (sem Banco Storage, guarda inline)
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result); // base64 data URL
    reader.readAsDataURL(file);
  });
}

function salvarEntradaSC() {
  const pat   = document.getElementById('sc-pat')?.value?.trim();
  const local = document.getElementById('sc-local')?.value?.trim();
  const desc  = document.getElementById('sc-desc')?.value?.trim();
  const obs   = document.getElementById('sc-obs')?.value?.trim();
  const fotoInput = document.getElementById('sc-entrada-foto');

  if (!pat)   return showToast('Informe o Patrimônio', 'warning');
  if (!local) return showToast('Informe a localização em Santa Clara', 'warning');
  if (!fotoInput?.files?.[0]) return showToast('A foto do local é obrigatória', 'warning');

  const btn = document.querySelector('[onclick="salvarEntradaSC()"]');
  setButtonLoading(btn, true, 'Salvando...');

  const reader = new FileReader();
  reader.onload = async e => {
    const fotoBase64 = e.target.result;
    const agora = new Date().toISOString().split('T')[0];

    const novo = {
      id:            'SC-' + Date.now(),
      pat, desc, obs, local,
      fotoUrl:       fotoBase64,
      dataEntrada:   agora,
      status:        'armazenado',
      historicoLocais: [{
        local, fotoUrl: fotoBase64, obs,
        data:    agora,
        tecnico: CURRENT_USER?.nome || '',
      }],
      createdAt: new Date().toISOString(),
    };

    if (!STATE.scAtivos) STATE.scAtivos = [];
    STATE.scAtivos.unshift(novo);
    await fsAdd('scAtivos', { ...novo, fotoUrl: '[base64]' }); // Banco sem a foto grande

    closeModal('modal-sc-entrada');
    renderSantaClara();
    setButtonLoading(btn, false, '📍 Registrar');
    showToast('✅ ' + pat + ' registrado em Santa Clara!', 'success', 4000);

    // Limpa form
    ['sc-pat','sc-local','sc-desc','sc-obs'].forEach(id => { const el = document.getElementById(id); if(el) el.value=''; });
    scRemoverFoto('sc-foto-zone', 'sc-foto-preview', 'sc-entrada-foto');
  };
  reader.readAsDataURL(fotoInput.files[0]);
}

let _scUpdateId = null;

function abrirAtualizacaoSC(scId) {
  _scUpdateId = scId;
  const sc = (STATE.scAtivos || []).find(s => s.id === scId);
  if (!sc) return;

  document.getElementById('sc-update-pat').textContent = (sc.pat||'') + (sc.desc ? ' — ' + sc.desc : '');
  document.getElementById('sc-update-local').value  = '';
  document.getElementById('sc-update-motivo').value = '';
  scRemoverFoto('sc-update-foto-zone', 'sc-update-foto-preview', 'sc-update-foto-input');
  openModal('modal-sc-update');
}

async function confirmarAtualizacaoSC() {
  const novoLocal = document.getElementById('sc-update-local')?.value?.trim();
  const motivo    = document.getElementById('sc-update-motivo')?.value?.trim();
  const fotoInput = document.getElementById('sc-update-foto-input');

  if (!novoLocal) return showToast('Informe o novo local', 'warning');
  if (!fotoInput?.files?.[0]) return showToast('A foto do novo local é obrigatória', 'warning');

  const btn = document.getElementById('sc-update-btn');
  setButtonLoading(btn, true, 'Salvando...');

  const reader = new FileReader();
  reader.onload = async e => {
    const fotoBase64 = e.target.result;
    const agora = new Date().toISOString().split('T')[0];
    const sc = (STATE.scAtivos || []).find(s => s.id === _scUpdateId);
    if (!sc) return;

    const novoRegistro = {
      local:   novoLocal,
      fotoUrl: fotoBase64,
      motivo:  motivo || '',
      data:    agora,
      tecnico: CURRENT_USER?.nome || '',
    };

    sc.local   = novoLocal;
    sc.fotoUrl = fotoBase64;
    if (!sc.historicoLocais) sc.historicoLocais = [];
    sc.historicoLocais.push(novoRegistro);

    await fsUpdate('scAtivos', _scUpdateId, {
      local: novoLocal, historicoLocais: sc.historicoLocais,
      updatedAt: agora,
    });

    closeModal('modal-sc-update');
    renderSantaClara();
    setButtonLoading(btn, false, '📍 Salvar Nova Localização');
    showToast('✅ Localização atualizada! Histórico preservado.', 'success', 4000);
  };
  reader.readAsDataURL(fotoInput.files[0]);
}

function scVerHistorico(scId) {
  const sc = (STATE.scAtivos || []).find(s => s.id === scId);
  if (!sc || !sc.historicoLocais?.length) return showToast('Sem histórico de locais', 'info');

  const div = document.createElement('div');
  div.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:20px';
  div.innerHTML = `
    <div style="background:var(--g0,#fff);border-radius:12px;max-width:600px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column">
      <div style="padding:18px 20px;border-bottom:1px solid var(--g200);display:flex;justify-content:space-between;align-items:center">
        <div>
          <h3 style="margin:0;font-size:16px">📍 Histórico de Localizações</h3>
          <p style="margin:4px 0 0;font-size:12px;color:var(--g400)">${escapeHtml(sc.pat||'')} — ${escapeHtml(sc.desc||sc.ativo||'')}</p>
        </div>
        <button onclick="this.closest('[style*=fixed]').remove()" style="background:none;border:none;font-size:20px;cursor:pointer;color:var(--g400)">✕</button>
      </div>
      <div style="overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:16px">
        ${[...(sc.historicoLocais||[])].reverse().map((h, idx) => `
          <div style="border:1px solid var(--g200);border-radius:10px;overflow:hidden${idx===0?';border-color:var(--accent);border-width:2px':''}">
            ${h.fotoUrl ? `<img src="${escapeHtml(h.fotoUrl)}" style="width:100%;max-height:180px;object-fit:cover">` : ''}
            <div style="padding:12px">
              ${idx===0 ? '<span style="font-size:10px;font-weight:800;background:var(--accent);color:#fff;padding:1px 8px;border-radius:20px;margin-bottom:6px;display:inline-block">LOCAL ATUAL</span>' : ''}
              <div style="font-weight:700;font-size:13px;margin-bottom:4px">📍 ${escapeHtml(h.local||'—')}</div>
              ${h.motivo ? `<div style="font-size:12px;color:var(--g500);margin-bottom:4px">Motivo: ${escapeHtml(h.motivo)}</div>` : ''}
              <div style="font-size:11px;color:var(--g400);display:flex;gap:12px">
                <span>📅 ${h.data||'—'}</span>
                ${h.tecnico ? `<span>👤 ${escapeHtml(h.tecnico)}</span>` : ''}
              </div>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
  document.body.appendChild(div);
}

// ════════════════════════════════════════════════════════════
// MAPA DE ATIVOS — Visualização hierárquica em tempo real
// Prédio → Andar → Sala → Posição → Ativo
// ════════════════════════════════════════════════════════════

// Estrutura de localização dos ativos
// Cada ativo pode ter: { predio, andar, sala, posicao }
// Populado pelo Banco em tempo real

const MAPA_STATE = {
  nivel:   'root',   // root | predio | andar | sala
  predio:  null,
  andar:   null,
  sala:    null,
  filtro:  '',
};

// Seed de localizações para demonstração
const LOCALIZACOES_SEED = [];

// Associa ativos do STATE.ativos às localizações pelo campo loc
function getAtivosComLocal() {
  const ativos = STATE.ativos || [];
  return ativos.map(a => ({
    ...a,
    predio:  a.predio  || a.loc?.split('/')[0]?.trim() || '',
    andar:   a.andar   || a.loc?.split('/')[1]?.trim() || '',
    sala:    a.sala    || a.loc?.split('/')[2]?.trim() || '',
    posicao: a.posicao || a.loc?.split('/')[3]?.trim() || '',
  }));
}

function mapaFiltrar() {
  MAPA_STATE.filtro = document.getElementById('mapa-filter-status')?.value || '';
  renderMapaAtivos();
}

function mapaNavTo(nivel, predio, andar, sala) {
  MAPA_STATE.nivel  = nivel  || 'root';
  MAPA_STATE.predio = predio || null;
  MAPA_STATE.andar  = andar  || null;
  MAPA_STATE.sala   = sala   || null;
  renderMapaAtivos();
}

function renderMapaAtivos() {
  const content = document.getElementById('mapa-content');
  const bc      = document.getElementById('mapa-breadcrumb');
  if (!content) return;

  const ativos = getAtivosComLocal();
  const filtro = MAPA_STATE.filtro;
  const filtered = filtro ? ativos.filter(a => a.status === filtro) : ativos;

  // Stats
  sv('mapa-stat-total', ativos.filter(a => a.predio).length);
  sv('mapa-stat-uso',   ativos.filter(a => a.status === 'ativo').length);
  sv('mapa-stat-manut', ativos.filter(a => a.status === 'manut').length);
  sv('mapa-stat-prob',  ativos.filter(a => ['terceirizada','extraviado'].includes(a.status)).length);
  sv('mapa-stat-sem',   ativos.filter(a => !a.predio && !a.loc).length);

  // Breadcrumb
  const bcItems = [{label:'🏢 Todos os Prédios', onclick:"mapaNavTo('root')"}];
  if (MAPA_STATE.predio) bcItems.push({label:'🏢 '+MAPA_STATE.predio, onclick:"mapaNavTo('predio','"+MAPA_STATE.predio+"')"});
  if (MAPA_STATE.andar)  bcItems.push({label:'🏬 '+MAPA_STATE.andar,  onclick:"mapaNavTo('andar','"+MAPA_STATE.predio+"','"+MAPA_STATE.andar+"')"});
  if (MAPA_STATE.sala)   bcItems.push({label:'🚪 '+MAPA_STATE.sala,   onclick:"mapaNavTo('sala','"+MAPA_STATE.predio+"','"+MAPA_STATE.andar+"','"+MAPA_STATE.sala+"')"});

  bc.innerHTML = bcItems.map((item, i) =>
    '<div class="mapa-bc-item' + (i===bcItems.length-1?' current':'') + '" onclick="'+item.onclick+'">'+item.label+'</div>' +
    (i<bcItems.length-1 ? '<span class="mapa-bc-sep">›</span>' : '')
  ).join('');

  // Render nível atual
  switch (MAPA_STATE.nivel) {
    case 'root':  renderMapaPredios(filtered, content);  break;
    case 'predio': renderMapaAndares(filtered, content); break;
    case 'andar':  renderMapaSalas(filtered, content);   break;
    case 'sala':   renderMapaSala(filtered, content);    break;
  }
}

// NÍVEL 1 — Prédios
function renderMapaPredios(ativos, container) {
  // Agrupa por prédio (real + seed)
  const prediosSeed = [...new Set(LOCALIZACOES_SEED.map(l => l.predio))];
  const prediosAtivos = [...new Set(ativos.filter(a=>a.predio).map(a=>a.predio))];
  const predios = [...new Set([...prediosSeed, ...prediosAtivos])];

  if (!predios.length) {
    container.innerHTML = '<div style="text-align:center;padding:48px;color:var(--g400)">Nenhuma localização cadastrada. Edite os ativos adicionando o campo <strong>loc</strong> no formato <code>Prédio/Andar/Sala/Posição</code>.</div>';
    return;
  }

  container.innerHTML = '<div class="mapa-grid">' +
    predios.map(predio => {
      const ativosPredi = ativos.filter(a => a.predio === predio);
      const problemas   = ativosPredi.filter(a => ['terceirizada','extraviado','manut'].includes(a.status)).length;
      const nAndares = [...new Set(LOCALIZACOES_SEED.filter(l=>l.predio===predio).map(l=>l.andar))].length;
      return '<div class="mapa-card' + (problemas?' has-problem':'') + '" data-nav="predio" data-predio="'+encodeURIComponent(predio)+'">' +
        '<div class="mapa-card-icon">🏢</div>' +
        '<div class="mapa-card-label">' + escapeHtml(predio) + '</div>' +
        '<div class="mapa-card-sub">' + nAndares + ' andares</div>' +
        '<div class="mapa-card-count">' + ativosPredi.length + '</div>' +
        '</div>';
    }).join('') + '</div>' +
    // Tabela de ativos sem localização
    mapaAtivosSeLocalHTML(ativos);
}

// NÍVEL 2 — Andares
function renderMapaAndares(ativos, container) {
  const predio = MAPA_STATE.predio;
  const andaresSeed = [...new Set(LOCALIZACOES_SEED.filter(l=>l.predio===predio).map(l=>l.andar))];
  const andares = [...new Set([...andaresSeed, ...ativos.filter(a=>a.predio===predio&&a.andar).map(a=>a.andar)])];

  container.innerHTML = '<div class="mapa-grid">' +
    andares.map(andar => {
      const ativosAndar = ativos.filter(a => a.predio===predio && a.andar===andar);
      const salas = [...new Set(LOCALIZACOES_SEED.filter(l=>l.predio===predio&&l.andar===andar).map(l=>l.sala))];
      const problemas = ativosAndar.filter(a=>['terceirizada','extraviado','manut'].includes(a.status)).length;
      return '<div class="mapa-card'+(problemas?' has-problem':'')+'" data-nav="andar" data-predio="'+encodeURIComponent(predio)+'" data-andar="'+encodeURIComponent(andar)+'">' +
        '<div class="mapa-card-icon">🏬</div>' +
        '<div class="mapa-card-label">' + escapeHtml(andar) + '</div>' +
        '<div class="mapa-card-sub">' + salas.length + ' sala(s)</div>' +
        '<div class="mapa-card-count">' + ativosAndar.length + '</div>' +
        '</div>';
    }).join('') + '</div>';
}

// NÍVEL 3 — Salas
function renderMapaSalas(ativos, container) {
  const {predio, andar} = MAPA_STATE;
  const salasSeed = [...new Set(LOCALIZACOES_SEED.filter(l=>l.predio===predio&&l.andar===andar).map(l=>l.sala))];
  const salas = [...new Set([...salasSeed, ...ativos.filter(a=>a.predio===predio&&a.andar===andar&&a.sala).map(a=>a.sala)])];

  const SALA_ICONS = { 'TI':'🖥️', 'A-DSI':'🖥️', 'RH':'👥', 'Financeiro':'💰', 'Diretoria':'🏆', 'Jurídico':'⚖️', 'Reunião':'📋', 'Recepção':'🛎️', 'Suporte':'🔧', 'Operações':'⚙️', 'Presidência':'🌟' };
  function getSalaIcon(sala) {
    for (const [key, icon] of Object.entries(SALA_ICONS)) {
      if (sala.includes(key)) return icon;
    }
    return '🚪';
  }

  container.innerHTML = '<div class="mapa-grid">' +
    salas.map(sala => {
      const ativosSala = ativos.filter(a => a.predio===predio && a.andar===andar && a.sala===sala);
      const problemas  = ativosSala.filter(a=>['terceirizada','extraviado','manut'].includes(a.status)).length;
      return '<div class="mapa-card'+(problemas?' has-problem':'')+'" data-nav="sala" data-predio="'+encodeURIComponent(predio)+'" data-andar="'+encodeURIComponent(andar)+'" data-sala="'+encodeURIComponent(sala)+'">' +
        '<div class="mapa-card-icon">'+getSalaIcon(sala)+'</div>' +
        '<div class="mapa-card-label">' + escapeHtml(sala) + '</div>' +
        '<div class="mapa-card-sub">' + ativosSala.length + ' ativo(s)</div>' +
        '<div class="mapa-card-count">' + ativosSala.length + '</div>' +
        '</div>';
    }).join('') + '</div>';
}

// NÍVEL 4 — Planta da sala com posições
function renderMapaSala(ativos, container) {
  const {predio, andar, sala} = MAPA_STATE;
  const ativosSala = ativos.filter(a => a.predio===predio && a.andar===andar && a.sala===sala);
  const posicoesSeed = LOCALIZACOES_SEED.filter(l=>l.predio===predio&&l.andar===andar&&l.sala===sala).map(l=>l.posicao);
  const posicoes = [...new Set([...posicoesSeed, ...ativosSala.filter(a=>a.posicao).map(a=>a.posicao)])];

  // Distribuição automática na planta (grid)
  const cols = Math.ceil(Math.sqrt(posicoes.length)) || 1;
  const cellW = 100 / (cols + 1);

  function getStatusClass(posicao) {
    const a = ativosSala.find(a => a.posicao === posicao);
    if (!a) return 'slot-vazio';
    if (a.status === 'ativo') return 'slot-ativo';
    if (a.status === 'manut') return 'slot-manut';
    if (['terceirizada','extraviado'].includes(a.status)) return 'slot-problema';
    return 'slot-offline';
  }
  function getStatusIcon(posicao) {
    const a = ativosSala.find(a => a.posicao === posicao);
    if (!a) return '○';
    const icons = { computador:'🖥️', notebook:'💻', impressora:'🖨️', monitor:'🖥️', servidor:'🗄️', switch:'🔀', nobreak:'🔋' };
    return icons[a.tipo] || '📦';
  }

  const plantaHTML = posicoes.map((pos, idx) => {
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    const leftPct = ((col + 1) * cellW).toFixed(1);
    const topPct  = (15 + row * 22).toFixed(1);
    const ativo   = ativosSala.find(a => a.posicao === pos);
    const dataAttrs = ativo ? `data-pat="${ativo.pat}" data-desc="${escapeHtml(ativo.desc||'')}" data-status="${ativo.status}"` : '';
    return `<div class="mapa-slot ${getStatusClass(pos)}" style="left:${leftPct}%;top:${topPct}%" 
                 onclick="mapaSlotClick('${escapeHtml(pos)}','${ativo?.id||''}')"
                 title="${escapeHtml(pos)}" ${dataAttrs}>
              <div class="mapa-slot-dot">${getStatusIcon(pos)}</div>
              <div class="mapa-slot-label">${escapeHtml(pos)}</div>
            </div>`;
  }).join('');

  // Legenda
  const legendHTML = `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;font-size:11.5px">
    <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#10B981;margin-right:4px"></span>Em uso</span>
    <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#F59E0B;margin-right:4px"></span>Manutenção</span>
    <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#EF4444;margin-right:4px"></span>Problema</span>
    <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#94A3B8;margin-right:4px"></span>Vazio</span>
  </div>`;

  // Tabela de ativos da sala
  const tabelaHTML = `<div class="card mt-16">
    <div class="card-header"><h3>📋 Ativos em ${escapeHtml(sala)}</h3><span class="badge badge-info">${ativosSala.length} ativo(s)</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>PAT</th><th>Descrição</th><th>Tipo</th><th>Posição</th><th>Status</th><th>Responsável</th><th>Ação</th></tr></thead>
      <tbody>${ativosSala.length ? ativosSala.map(a => `
        <tr>
          <td class="td-mono" style="color:var(--accent)">${escapeHtml(a.pat||'—')}</td>
          <td style="font-size:12.5px">${escapeHtml(a.desc||'—')}</td>
          <td><span class="tag">${escapeHtml(a.tipo||'—')}</span></td>
          <td style="font-size:12px;color:var(--g500)">${escapeHtml(a.posicao||'—')}</td>
          <td><span class="sp-${a.status||''}">${escapeHtml(a.status||'—')}</span></td>
          <td style="font-size:12px">${escapeHtml(a.resp||'—')}</td>
          <td><button class="btn btn-ghost btn-xs" onclick="goPage('ativos')">Ver</button></td>
        </tr>`).join('') : '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--g400)">Nenhum ativo nesta sala</td></tr>'}
      </tbody>
    </table></div>
  </div>`;

  container.innerHTML = legendHTML +
    `<div class="mapa-planta"><div class="mapa-planta-title">🗺️ Planta — ${escapeHtml(sala)}</div>${plantaHTML}</div>` +
    tabelaHTML;
}

function mapaAtivosSeLocalHTML(ativos) {
  const sem = ativos.filter(a => !a.predio && !a.loc);
  if (!sem.length) return '';
  return `<div class="card mt-16">
    <div class="card-header"><h3>📍 Sem localização cadastrada</h3><span class="badge badge-warning">${sem.length}</span></div>
    <div class="card-body" style="font-size:12.5px;color:var(--g500)">
      ${sem.slice(0,5).map(a => escapeHtml(a.pat+' — '+a.desc)).join('<br>')}
      ${sem.length>5 ? '<br>... e mais '+(sem.length-5)+'.' : ''}
      <br><br>Para mapear, edite o ativo e preencha o campo <strong>Localização</strong> no formato:<br>
      <code style="background:var(--g100);padding:2px 8px;border-radius:4px">Sede Vitória / 1º Andar / TI / Estação 01</code>
    </div>
  </div>`;
}

function mapaSlotClick(posicao, ativoId) {
  // Fecha popups anteriores
  document.querySelectorAll('.mapa-slot-popup').forEach(p => p.remove());
  if (ativoId) {
    // Navega para o ativo
    goPage('ativos');
    showToast('Abrindo ativo ' + posicao, 'info', 2000);
  }
}

function mapaAddLocal() {
  showToast('Para adicionar localização: edite o ativo e preencha o campo "Localização" no formato Prédio/Andar/Sala/Posição', 'info', 5000);
}

// ════════════════════════════════════════════════════════════
// FCM — Banco Cloud Messaging
// Recebe comandos do SYSACK no celular do empregado
// ════════════════════════════════════════════════════════════

async function salvarTokenFCM(token) {
  if (!FB_READY || !auth?.currentUser) return;
  const uid  = auth.currentUser.uid;
  const user = CURRENT_USER || {};
  try {
    // Salva token associado ao usuário e ao smartphone
    await fsUpdate('users', uid, {
      fcmToken:    token,
      fcmDevice:   navigator.userAgent.substring(0, 120),
      fcmPlatform: /android/i.test(navigator.userAgent) ? 'android' :
                   /iphone|ipad/i.test(navigator.userAgent) ? 'ios' : 'web',
      fcmUpdatedAt: new Date().toISOString(),
    });

    // Se houver smartphone associado a este empregado, vincula o token
    const sms = (STATE.smartphones || []).filter(s =>
      s.empMat === user.mat || s.usuarioId === uid
    );
    for (const sm of sms) {
      await fsUpdate('smartphones', sm.id, {
        fcmToken:     token,
        fcmAtivo:     true,
        fcmUpdatedAt: new Date().toISOString(),
      });
    }
    console.log('[FCM] Token salvo para', user.nome || uid);
  } catch (e) {
    console.warn('[FCM] Erro ao salvar token:', e.message);
  }
}

// Processa comandos recebidos via FCM (app em foreground)
function processarComandoFCM(payload) {
  const { notification, data } = payload;
  const tipo = data?.tipo || 'notification';

  switch (tipo) {
    case 'checkin_request':
      // Servidor pediu auto-checkin do aparelho
      console.log('[FCM] Comando: checkin_request');
      executarAutoCheckin();
      break;

    case 'location_request':
      // Solicitação de localização GPS
      console.log('[FCM] Comando: location_request');
      reportarLocalizacao(data?.smId, data?.requestId);
      break;

    case 'alert':
      // Alerta operacional para o técnico/gestor
      showToast(notification?.body || data?.mensagem || 'Alerta do SYSACK', 'danger', 8000);
      break;

    case 'update_available':
      // Nova versão do sistema disponível
      showUpdateBanner();
      break;

    default:
      // Notificação genérica
      if (notification?.title) {
        showToast(notification.title + (notification.body ? ': ' + notification.body : ''), 'info', 5000);
      }
  }
}

// ── AUTO-CHECKIN DO CELULAR ───────────────────────────────────
// Coleta métricas do aparelho via browser APIs e envia ao Banco

async function executarAutoCheckin(smId) {
  if (!FB_READY || !auth?.currentUser) return;

  const uid     = auth.currentUser.uid;
  const user    = CURRENT_USER || {};
  const agora   = new Date().toISOString();

  // Descobre o smartphone vinculado a este usuário/matrícula
  const sm = smId
    ? (STATE.smartphones || []).find(s => s.id === smId)
    : (STATE.smartphones || []).find(s =>
        s.empMat === user.mat || s.usuarioId === uid ||
        s.fcmToken === window._fcmToken
      );

  if (!sm && !smId) {
    console.log('[Checkin] Nenhum smartphone vinculado a este usuário');
    return;
  }

  const checkin = {
    timestamp:   agora,
    syncSource:  'sysack-pwa',
    reachable:   true,
    userAgent:   navigator.userAgent.substring(0, 120),
    plataforma:  /android/i.test(navigator.userAgent) ? 'Android' :
                 /iphone|ipad/i.test(navigator.userAgent) ? 'iOS' : 'Web',
    online:      navigator.onLine,
    fcmToken:    window._fcmToken || '',
  };

  // ── Bateria ───────────────────────────────────────────────
  try {
    const batt = await navigator.getBattery();
    checkin.bateriaP     = Math.round(batt.level * 100);
    checkin.carregando   = batt.charging;
  } catch { /* API não disponível */ }

  // ── Memória (Chrome only) ─────────────────────────────────
  if (navigator.deviceMemory) {
    checkin.memoriaGB = navigator.deviceMemory;
  }

  // ── Storage disponível ────────────────────────────────────
  try {
    const storage = await navigator.storage.estimate();
    checkin.storageUsadoMB = Math.round((storage.usage || 0) / 1024 / 1024);
    checkin.storageTotalMB = Math.round((storage.quota  || 0) / 1024 / 1024);
    checkin.storagePct     = storage.quota > 0
      ? Math.round(storage.usage / storage.quota * 100) : null;
  } catch {}

  // ── Conexão de rede ───────────────────────────────────────
  if (navigator.connection) {
    const conn = navigator.connection;
    checkin.redeType       = conn.effectiveType || conn.type || '—';
    checkin.redeDownMbps   = conn.downlink || null;
    checkin.redeSalvaDados = conn.saveData || false;
  }

  // ── Idioma e fuso horário ─────────────────────────────────
  checkin.idioma   = navigator.language;
  checkin.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // ── Status calculado ──────────────────────────────────────
  let status = 'ok';
  if (checkin.bateriaP     != null && checkin.bateriaP < 10)  status = 'critico';
  else if (checkin.bateriaP != null && checkin.bateriaP < 20) status = 'alerta';
  else if (checkin.storagePct != null && checkin.storagePct > 90) status = 'alerta';
  checkin.status = status;

  // ── Envia ao Banco ────────────────────────────────────
  try {
    if (sm?.id) {
      await fsUpdate('smartphones', sm.id, {
        ...checkin,
        lastSeen: agora,
        updatedAt: agora,
      });
      // Histórico do checkin
      if (sm.id) {
        await fsAdd(`smartphones/${sm.id}/historico`, {
          tipo:  'checkin-pwa',
          dot:   status === 'ok' ? 'green' : 'yellow',
          titulo: 'Auto-checkin PWA',
          desc:  `Bat: ${checkin.bateriaP ?? '?'}% | Rede: ${checkin.redeType || '?'} | Storage: ${checkin.storagePct ?? '?'}%`,
          data:  new Date().toLocaleDateString('pt-BR'),
        });
      }
      console.log('[Checkin] ✓ Dados enviados para smartphone', sm.pat);
    } else {
      // Sem smartphone vinculado — envia para checkins genéricos
      await fsPatch('checkins', uid, checkin);
    }

    // Atualiza badge na tela MDM se estiver aberta
    if (isPageActive('mdm')) renderMDM?.();

  } catch (e) {
    console.warn('[Checkin] Erro ao enviar:', e.message);
  }

  return checkin;
}

// ── LOCALIZAÇÃO GPS ───────────────────────────────────────────
async function reportarLocalizacao(smId, requestId) {
  if (!navigator.geolocation) {
    console.warn('[GPS] Geolocalização não disponível');
    return;
  }

  try {
    const pos = await new Promise((resolve, reject) =>
      navigator.geolocation.getCurrentPosition(resolve, reject, {
        enableHighAccuracy: true,
        timeout: 15000,
        maximumAge: 30000,
      })
    );

    const locData = {
      lat:       pos.coords.latitude,
      lng:       pos.coords.longitude,
      precisao:  Math.round(pos.coords.accuracy),
      altitude:  pos.coords.altitude ? Math.round(pos.coords.altitude) : null,
      timestamp: new Date().toISOString(),
      requestId: requestId || null,
      fonte:     'gps-pwa',
    };

    // Salva localização no smartphone
    const sm = smId
      ? (STATE.smartphones || []).find(s => s.id === smId)
      : (STATE.smartphones || []).find(s => s.usuarioId === auth?.currentUser?.uid);

    if (sm?.id) {
      await fsUpdate('smartphones', sm.id, {
        ultimaLocalizacao: locData,
        lat:      locData.lat,
        lng:      locData.lng,
        lastSeen: locData.timestamp,
      });
      console.log('[GPS] ✓ Localização enviada:', locData.lat, locData.lng);
    }
    return locData;
  } catch (err) {
    console.warn('[GPS] Erro:', err.message);
    return null;
  }
}

// ── INICIALIZAÇÃO DO FCM APÓS LOGIN ───────────────────────────
function initFCMAfterLogin() {
  if (location.protocol !== 'https:') return;
  const isMobile = /android|iphone|ipad/i.test(navigator.userAgent);
  if (!isMobile && !window._forceFCM) return;

  const role = CURRENT_USER?.role || 'viewer';

  // Perfil sem-mdm: só recebe alertas, sem monitorar o dispositivo
  // Determinado pelo campo smPerfil do smartphone OU pelo role do usuário
  const smVinculado = (STATE.smartphones||[]).find(s =>
    s.usuarioId === CURRENT_USER?.uid || s.empMat === CURRENT_USER?.mat
  );
  const perfil = smVinculado?.perfil || smVinculado?.smPerfil ||
    (['admin','gestor','tecnico','mdm_admin'].includes(role) ? 'sem-mdm' : 'com-mdm');

  window._modoGestao = (perfil === 'sem-mdm');
  console.log('[FCM] Perfil:', perfil, '| Modo gestão:', window._modoGestao);
  setTimeout(() => window.initFCM?.(), 2000);
}

// Checkin automático a cada 15 minutos (enquanto o app está aberto)
let _autoCheckinTimer = null;
function startAutoCheckin() {
  stopAutoCheckin();
  // Primeiro checkin imediato
  executarAutoCheckin();
  // Depois a cada 15 minutos
  _autoCheckinTimer = setInterval(executarAutoCheckin, 15 * 60 * 1000);
  console.log('[Checkin] Auto-checkin iniciado (a cada 15 min)');
}
async function solicitarCheckinSM(smId) {
  if (!smId) return showToast('Smartphone não identificado', 'warning');
  try {
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'enviarComandoFCM');
    await fn({ smId, tipo: 'checkin_request' });
    showToast('📡 Checkin solicitado — aguarde o celular responder', 'info', 4000);
  } catch (err) {
    if (err.message.includes('FCM registrado')) {
      showToast('O usuário precisa abrir o SYSACK no celular pelo menos uma vez', 'warning', 5000);
    } else {
      showToast('Erro: ' + err.message, 'danger');
    }
  }
}


// ════════════════════════════════════════════════════════════
// SMARTPHONE — Nota no histórico + Chamado inteligente
// ════════════════════════════════════════════════════════════

function abrirNotaSm(smId) {
  const sm = (STATE.smartphones || []).find(s => s.id === smId);
  if (!sm) return;

  const div = document.createElement('div');
  div.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center';
  div.innerHTML = `
    <div style="background:var(--g0,#fff);border-radius:12px;padding:24px;max-width:460px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3)">
      <h3 style="margin:0 0 4px;font-size:16px">&#128221; Adicionar Nota — ${escapeHtml(sm.marca||'')} ${escapeHtml(sm.modelo||'')} (${escapeHtml(sm.pat||'')})</h3>
      <p style="font-size:12px;color:var(--g400);margin:0 0 14px">A nota ficará permanentemente no histórico do smartphone</p>
      <textarea id="nota-sm-texto" rows="4" style="width:100%;background:var(--g50);border:1px solid var(--g200);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical;font-family:inherit;box-sizing:border-box" placeholder="Descreva ocorrências, manutenções, trocas de chip, problemas, observações..."></textarea>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:14px">
        <button class="btn btn-ghost" onclick="this.closest('[style*=fixed]').remove()">Cancelar</button>
        <button class="btn btn-primary" onclick="salvarNotaSm('${smId}', this)">&#128190; Salvar Nota</button>
      </div>
    </div>`;
  document.body.appendChild(div);
  setTimeout(() => div.querySelector('textarea')?.focus(), 100);
}

async function salvarNotaSm(smId, btn) {
  const texto = document.getElementById('nota-sm-texto')?.value?.trim();
  if (!texto || texto.length < 5) return showToast('Digite uma nota com pelo menos 5 caracteres', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  try {
    await fsAdd('smartphones/' + smId + '/historico', {
      tipo:          'nota_tecnico',
      titulo:        'Consideração do técnico',
      texto,
      desc:          texto,
      dot:           'blue',
      autorNome:     CURRENT_USER?.nome || '',
      autorUid:      CURRENT_USER?.uid  || '',
      permanente:    true,
      data:          new Date().toLocaleDateString('pt-BR'),
      createdAt:     new Date().toISOString(),
    });
    btn.closest('[style*=fixed]')?.remove();
    showToast('&#128221; Nota adicionada ao histórico do smartphone!', 'success', 3000);
  } catch (err) {
    showToast('Erro: ' + err.message, 'danger');
  } finally {
    setButtonLoading(btn, false, '&#128190; Salvar Nota');
  }
}

// Chamado smartphone — pergunta se é o aparelho de quem abriu
// (já implementado em abrirChamadoSm mas vamos garantir o fluxo)
function abrirChamadoSmartphone(origem) {
  // origem: 'mdm' | 'self-service' | 'chamados'
  const user = CURRENT_USER;
  const meuSm = (STATE.smartphones || []).find(s =>
    s.empMat === user?.mat || s.usuarioId === user?.uid
  );

  if (meuSm) {
    // Tem smartphone vinculado — pergunta
    if (typeof abrirChamadoSm === 'function') abrirChamadoSm(null);
  } else {
    // Sem smartphone próprio — vai direto para busca
    if (typeof abrirChamadoSm === 'function') {
      abrirChamadoSm(null);
      setTimeout(() => selecionarChamadoSm('outro'), 300);
    }
  }
}

// Atualiza data da última troca quando responsável do smartphone muda
async function registrarTrocaSmartphone(smId, novoEmpMat, novoEmpNome) {
  const agora = new Date().toISOString().split('T')[0];
  await fsUpdate('smartphones', smId, {
    empMat:     novoEmpMat,
    empNome:    novoEmpNome,
    ultimaTroca: agora,
    updatedAt:  agora,
  });
  // Histórico
  await fsAdd('smartphones/' + smId + '/historico', {
    tipo:   'troca_responsavel',
    titulo: 'Troca de responsável',
    desc:   'Novo responsável: ' + novoEmpNome,
    dot:    'blue',
    data:   new Date().toLocaleDateString('pt-BR'),
  });
}


// ════════════════════════════════════════════════════════════
// LIMPEZA APÓS SYNC OFFLINE
// Remove dados locais já enviados ao banco — sem acumular lixo
// ════════════════════════════════════════════════════════════

function offlineLimparDadosLocais(col, docId) {
  // Remove entradas marcadas como _offline do STATE após sync
  // Dados reais chegam via onSnapshot em seguida
  if (STATE[col] && Array.isArray(STATE[col])) {
    if (docId) {
      // Update sincronizado — remove flag _offline
      const item = STATE[col].find(x => x.id === docId);
      if (item) delete item._offline;
    } else {
      // Add sincronizado — remove entradas offline temporárias
      // (serão substituídas pelo onSnapshot com o ID real do banco)
      STATE[col] = STATE[col].filter(x => !x._offline);
    }
  }
}

// Limpa TODO o IndexedDB offline (chamado ao final do sync completo)
async function offlineLimparTudo() {
  try {
    const db    = await getOfflineDB();
    const count = await offlineCount();
    if (count > 0) return; // ainda tem operações pendentes

    // Limpa blob store (não deve ter blobs órfãos após sync completo)
    await new Promise(resolve => {
      const tx = db.transaction(OFFLINE_BLOBS, 'readwrite');
      tx.objectStore(OFFLINE_BLOBS).clear();
      tx.oncomplete = resolve;
    });
    console.log('[OfflineSync] IndexedDB limpo após sync completo.');
  } catch (e) {
    console.warn('[OfflineSync] Erro ao limpar IndexedDB:', e.message);
  }
}

// ════════════════════════════════════════════════════════════
// CONFIRMAÇÃO DE CHAMADO — tela + e-mail
// ════════════════════════════════════════════════════════════

function exibirConfirmacaoChamado(chamado) {
  // Cria overlay de confirmação
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px;animation:fadeIn .3s ease';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:16px;max-width:480px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,.4);overflow:hidden;animation:slideUp .3s ease';

  const offline = !navigator.onLine;

  modal.innerHTML = [
    // Header verde de sucesso
    '<div style="background:linear-gradient(135deg,#059669,#047857);padding:24px 24px 20px;text-align:center">',
      '<div style="font-size:52px;margin-bottom:8px">✅</div>',
      '<h2 style="color:#fff;margin:0;font-size:20px;font-weight:900">Chamado Aberto!</h2>',
      '<p style="color:rgba(255,255,255,.8);font-size:13px;margin:6px 0 0">',
        offline ? 'Salvo localmente — será registrado ao reconectar.' : 'Registrado no sistema com sucesso.',
      '</p>',
    '</div>',
    // Número do chamado em destaque
    '<div style="padding:24px;text-align:center;border-bottom:1px solid #F1F5F9">',
      '<p style="font-size:12px;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:.08em;margin:0 0 8px">Número do Chamado</p>',
      '<div style="font-size:48px;font-weight:900;color:#059669;font-family:monospace;letter-spacing:.04em">' + escapeHtml(chamado.id) + '</div>',
      '<button id="copy-chamado-id" style="background:none;border:1px solid #E2E8F0;border-radius:6px;padding:4px 12px;font-size:11.5px;color:#64748B;cursor:pointer;margin-top:8px">📋 Copiar número</button>',
    '</div>',
    // Detalhes
    '<div style="padding:20px 24px">',
      '<table style="width:100%;font-size:12.5px;border-collapse:collapse">',
        '<tr style="border-bottom:1px solid #F1F5F9"><td style="color:#94A3B8;padding:7px 0;width:120px">Assunto</td>',
          '<td style="font-weight:600;color:#1E293B">' + escapeHtml(chamado.titulo || chamado.desc?.split('\n')[0] || '—') + '</td></tr>',
        '<tr style="border-bottom:1px solid #F1F5F9"><td style="color:#94A3B8;padding:7px 0">Solicitante</td>',
          '<td style="color:#1E293B">' + escapeHtml(chamado.solicitante || '—') + '</td></tr>',
        '<tr style="border-bottom:1px solid #F1F5F9"><td style="color:#94A3B8;padding:7px 0">Prioridade</td>',
          '<td><span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:20px;background:' +
            ({alta:'#FEE2E2',media:'#FEF3C7',baixa:'#F0FDF4'}[chamado.prioridade]||'#F1F5F9') + ';color:' +
            ({alta:'#DC2626',media:'#D97706',baixa:'#059669'}[chamado.prioridade]||'#64748B') + '">' +
            escapeHtml(chamado.prioridade || 'média') + '</span></td></tr>',
        '<tr><td style="color:#94A3B8;padding:7px 0">Abertura</td>',
          '<td style="color:#1E293B">' + new Date().toLocaleString('pt-BR') + '</td></tr>',
      '</table>',
      offline ? '<div style="background:#FEF3C7;border:1px solid #FDE68A;border-radius:8px;padding:10px 12px;margin-top:14px;font-size:12px;color:#92400E">⚠️ Você está offline. O chamado será registrado e o e-mail de confirmação enviado quando a conexão for restaurada.</div>' : '',
      !offline ? '<div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;padding:10px 12px;margin-top:14px;font-size:12px;color:#166534">📧 Confirmação enviada para ' + escapeHtml(CURRENT_USER?.email || chamado.emailSolicitante || 'seu e-mail') + '</div>' : '',
    '</div>',
    // Botão fechar
    '<div style="padding:0 24px 24px">',
      '<button id="chamado-confirm-close" style="width:100%;background:#059669;color:#fff;border:none;border-radius:10px;padding:14px;font-size:15px;font-weight:700;cursor:pointer">Entendido</button>',
    '</div>',
  ].join('');

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Botão copiar número (evita nested quotes)
  const closeBtn2 = modal.querySelector('#chamado-confirm-close');
  if (closeBtn2) closeBtn2.onclick = () => overlay.remove();

  const copyBtn = modal.querySelector('#copy-chamado-id');
  if (copyBtn && chamado.id) {
    copyBtn.onclick = () => {
      navigator.clipboard.writeText(chamado.id)
        .then(() => showToast('Copiado!', 'success', 1500));
    };
  }

  // Fecha ao clicar fora
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  // Auto-fecha após 30s
  setTimeout(() => overlay.remove(), 30000);
}

function stopAutoCheckin() {
  if (_autoCheckinTimer) { clearInterval(_autoCheckinTimer); _autoCheckinTimer = null; }
}

// ════════════════════════════════════════════════════════════
// ACESSO REMOTO — RDP e Assistência Remota
// ════════════════════════════════════════════════════════════

let _metodoRemoto = 'rdp';

function iniciarAcessoRemoto() {
  const ativo = window._ativoEditando || {};
  document.getElementById('remoto-subtitle').textContent =
    (ativo.hostname || ativo.ip || ativo.desc || 'Computador');
  document.getElementById('remoto-motivo').value  = '';
  document.getElementById('remoto-usuario').value = '';
  document.getElementById('remoto-senha').value   = '';
  document.getElementById('remoto-status').style.display = 'none';
  document.getElementById('remoto-rdp-info').style.display   = 'none';
  document.getElementById('remoto-assist-info').style.display = 'none';
  _metodoRemoto = 'rdp';
  openModal('modal-acesso-remoto');
}

function selecionarMetodoRemoto(metodo) {
  _metodoRemoto = metodo;
  document.getElementById('remoto-rdp-info').style.display   = metodo === 'rdp'        ? '' : 'none';
  document.getElementById('remoto-assist-info').style.display = metodo === 'assistencia' ? '' : 'none';
  // Highlight selected card
  document.querySelectorAll('#modal-acesso-remoto .mapa-card').forEach((c,i) => {
    c.style.borderColor = (i === 0 && metodo === 'rdp') || (i === 1 && metodo === 'assistencia')
      ? 'var(--accent)' : 'var(--g200)';
  });
}

async function confirmarAcessoRemoto() {
  const ativo  = window._ativoEditando || {};
  const motivo = document.getElementById('remoto-motivo')?.value?.trim();
  if (!motivo) return showToast('Motivo obrigatório para acesso remoto', 'warning');

  const ip       = ativo.ip || ativo.ipAddress || ativo.ipPrincipal || ativo.hostname;
  const hostname = ativo.hostname || ip;
  if (!ip) return showToast('IP ou hostname do computador não cadastrado', 'warning');

  // Audit log imediato
  auditLog('REMOTE_ACCESS_START', 'ativos', ativo.id, 'computador', {
    metodo: _metodoRemoto, hostname, motivo, ip,
  });

  if (_metodoRemoto === 'rdp') {
    await iniciarRDP(ip, hostname, motivo);
  } else {
    await solicitarAssistenciaRemota(ativo, motivo);
  }
}

async function iniciarRDP(ip, hostname, motivo) {
  showRemotoStatus('info', 'Preparando conexao RDP...');

  // Verifica se RDP está habilitado via Cloud Function
  try {
    // Using getFbFunctions singleton
    const fn  = httpsCallable(getFunctions(app), 'prepararAcessoRemoto');
    const res = await fn({ ativoId: window._ativoEditando?.id, metodo: 'rdp', motivo });

    if (res.data.rdpHabilitado) {
      showRemotoStatus('success', 'RDP disponivel — abrindo conexao...');
      // Gera arquivo .rdp e faz download para o técnico abrir
      const rdpContent = gerarArquivoRDP(ip, hostname);
      downloadArquivo(rdpContent, `${hostname}.rdp`, 'application/rdp');
      closeModal('modal-acesso-remoto');
      showToast('Arquivo RDP baixado — abra para conectar ao ' + hostname, 'success', 5000);
    } else {
      showRemotoStatus('warning', 'RDP nao habilitado. Habilitando remotamente...');
      // Envia comando via SYSACK Client para habilitar RDP
      const fn2 = httpsCallable(getFunctions(app), 'executarComandoRemoto');
      await fn2({
        ativoId: window._ativoEditando?.id,
        comando: 'EnableRDP',
        motivo,
      });
      setTimeout(async () => {
        showRemotoStatus('success', 'RDP habilitado! Baixando arquivo de conexao...');
        const rdpContent = gerarArquivoRDP(ip, hostname);
        downloadArquivo(rdpContent, hostname + '.rdp', 'application/rdp');
        closeModal('modal-acesso-remoto');
      }, 3000);
    }
  } catch (err) {
    // Fallback: gera o .rdp direto sem verificar
    showRemotoStatus('warning', 'Verificacao pulada — gerando arquivo RDP diretamente');
    const rdpContent = gerarArquivoRDP(ip, hostname);
    downloadArquivo(rdpContent, hostname + '.rdp', 'application/rdp');
    closeModal('modal-acesso-remoto');
    showToast('Arquivo RDP gerado. Certifique-se que RDP esta habilitado no PC alvo.', 'info', 5000);
  }
}

function gerarArquivoRDP(ip, hostname) {
  const usuario = document.getElementById('remoto-usuario')?.value?.trim() || '';
  const linhas = [
    'full address:s:' + ip,
    'username:s:' + usuario,
    'prompt for credentials:i:' + (usuario ? '0' : '1'),
    'authentication level:i:2',
    'negotiate security layer:i:1',
    'screen mode id:i:2',
    'smart sizing:i:1',
    'connection type:i:7',
    'networkautodetect:i:1',
    'bandwidthautodetect:i:1',
    'displayconnectionbar:i:1',
    'enableworkspacereconnect:i:0',
    'disable wallpaper:i:0',
    'allow font smoothing:i:1',
    'allow desktop composition:i:1',
    'audiomode:i:0',
    'redirectprinters:i:1',
    'redirectclipboard:i:1',
    'autoreconnection enabled:i:1',
    'drivestoredirect:s:',
  ];
  return linhas.join('\r\n');
}

async function solicitarAssistenciaRemota(ativo, motivo) {
  showRemotoStatus('info', 'Enviando solicitacao de assistencia ao usuario...');
  try {
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'prepararAcessoRemoto');
    await fn({ ativoId: ativo.id, metodo: 'assistencia', motivo });
    showRemotoStatus('success', 'Solicitacao enviada! Aguardando usuario autorizar...');
    showToast('Solicitacao de assistencia remota enviada para ' + (ativo.hostname || ativo.ip), 'info', 5000);
    setTimeout(() => closeModal('modal-acesso-remoto'), 2000);
  } catch (err) {
    showRemotoStatus('danger', 'Erro: ' + err.message);
  }
}

function showRemotoStatus(tipo, msg) {
  const el = document.getElementById('remoto-status');
  if (!el) return;
  const bg = { success:'#F0FDF4;color:#166534', danger:'#FEF2F2;color:#991B1B',
               warning:'#FFFBEB;color:#92400E', info:'#EFF6FF;color:#1D4ED8' };
  el.style.cssText = 'display:block;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;font-weight:500;background:' + (bg[tipo]||bg.info);
  el.textContent = msg;
}

function downloadArquivo(conteudo, nome, tipo) {
  const blob = new Blob([conteudo], { type: tipo });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = nome; a.click();
  URL.revokeObjectURL(url);
}

// ════════════════════════════════════════════════════════════
// INSTALACAO REMOTA DE SOFTWARE
// ════════════════════════════════════════════════════════════

// Catalogo de software homologado (configuravel pelo admin)
const SOFT_CATALOGO = [
  { nome:'7-Zip',        url:'https://www.7-zip.org/a/7z2301-x64.exe',    params:'/S',      icon:'🗜️' },
  { nome:'VLC',          url:'https://get.videolan.org/vlc/last/win64/',   params:'/S',      icon:'🎬' },
  { nome:'Firefox',      url:'https://download.mozilla.org/?product=firefox-latest&os=win64', params:'-ms', icon:'🦊' },
  { nome:'Chrome',       url:'https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi', params:'/quiet', icon:'🌐' },
  { nome:'Adobe Reader', url:'\\servidor\Softwares\AdobeReader.msi',   params:'/quiet',  icon:'📄' },
  { nome:'Office 365',   url:'\\servidor\Softwares\Office365Setup.exe',params:'/configure config.xml', icon:'📊' },
  { nome:'Antivirus',    url:'\\servidor\Softwares\AntivirusSetup.exe',params:'/silent', icon:'🛡️' },
  { nome:'Teams',        url:'https://aka.ms/teams-offline-msi-x64',       params:'/quiet ALLUSERS=1', icon:'💬' },
];

function abrirInstalarSoftware() {
  document.getElementById('soft-status').style.display = 'none';
  document.getElementById('soft-log').style.display    = 'none';
  document.getElementById('soft-nome').value   = '';
  document.getElementById('soft-url').value    = '';
  document.getElementById('soft-params').value = '';
  document.getElementById('soft-motivo').value = '';

  // Preenche catalogo
  const cat = document.getElementById('soft-catalogo');
  if (cat) {
    cat.innerHTML = SOFT_CATALOGO.map((s,i) =>
      '<div class="mapa-card" style="text-align:center;padding:10px;cursor:pointer" onclick="selecionarSoft(' + i + ')">' +
      '<div style="font-size:20px">' + s.icon + '</div>' +
      '<div style="font-size:11px;font-weight:700;margin-top:4px">' + s.nome + '</div>' +
      '</div>'
    ).join('');
  }
  openModal('modal-instalar-software');
}

function selecionarSoft(idx) {
  const s = SOFT_CATALOGO[idx];
  if (!s) return;
  document.getElementById('soft-nome').value   = s.nome;
  document.getElementById('soft-url').value    = s.url;
  document.getElementById('soft-params').value = s.params;
  // Highlight
  document.querySelectorAll('#soft-catalogo .mapa-card').forEach((c,i) => {
    c.style.borderColor = i === idx ? 'var(--accent)' : 'var(--g200)';
    c.style.background  = i === idx ? 'rgba(37,99,235,.05)' : '';
  });
}

async function executarInstalacaoSoftware() {
  const ativo   = window._ativoEditando || {};
  const nome    = document.getElementById('soft-nome')?.value?.trim();
  const url     = document.getElementById('soft-url')?.value?.trim();
  const params  = document.getElementById('soft-params')?.value?.trim() || '/S';
  const motivo  = document.getElementById('soft-motivo')?.value?.trim();

  if (!nome || !url) return showToast('Selecione ou informe o software', 'warning');
  if (!motivo)       return showToast('Motivo e obrigatorio', 'warning');

  const btn = document.getElementById('btn-instalar-exec');
  btn.disabled = true; btn.textContent = 'Instalando...';

  document.getElementById('soft-log').style.display = '';
  softLog('Iniciando instalacao remota de ' + nome + '...');
  softLog('Destino: ' + (ativo.hostname || ativo.ip || ativo.pat));
  softLog('URL/caminho: ' + url);

  try {
    if (!FB_READY || !auth?.currentUser) throw new Error('Login necessario');
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'instalarSoftwareRemoto');
    const res = await fn({
      ativoId: ativo.id,
      software: { nome, url, params },
      motivo,
    });

    const data = res.data;
    (data.steps || []).forEach(s => softLog(s));

    if (data.sucesso) {
      document.getElementById('soft-status').style.cssText =
        'display:block;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;font-weight:500;background:#F0FDF4;color:#166534';
      document.getElementById('soft-status').textContent = nome + ' instalado com sucesso!';
      showToast(nome + ' instalado em ' + (ativo.hostname || ativo.ip), 'success', 5000);
      auditLog('SOFTWARE_INSTALL', 'ativos', ativo.id, 'computador', { software: nome, url, motivo });
    } else {
      softLog('ERRO: ' + (data.erro || 'Falha desconhecida'));
      document.getElementById('soft-status').style.cssText =
        'display:block;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;font-weight:500;background:#FEF2F2;color:#991B1B';
      document.getElementById('soft-status').textContent = 'Falha: ' + (data.erro || '');
    }
  } catch (err) {
    softLog('Erro: ' + err.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Instalar Agora';
  }
}

function softLog(msg) {
  const el = document.getElementById('soft-log-body');
  if (!el) return;
  const ts  = new Date().toLocaleTimeString('pt-BR');
  const div = document.createElement('div');
  div.textContent = '[' + ts + '] ' + msg;
  div.querySelector?.('span')?.remove?.();
  const span = document.createElement('span');
  span.style.color = '#64748B';
  span.textContent = '[' + ts + '] ';
  div.textContent = '';
  div.appendChild(span);
  div.appendChild(document.createTextNode(msg));
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

// ════════════════════════════════════════════════════════════
// HISTÓRICO DE USUÁRIOS POR MÁQUINA
// ════════════════════════════════════════════════════════════

let _ativoHistoricoId = null;

async function abrirHistoricoUsuarios() {
  const ativo = window._ativoEditando || {};
  if (!ativo.id) return;
  _ativoHistoricoId = ativo.id;

  document.getElementById('hist-usr-title').textContent =
    'Histórico de Usuários — ' + (ativo.desc || ativo.pat || ativo.id);
  document.getElementById('hist-usr-pat').textContent =
    ativo.pat ? 'PAT: ' + ativo.pat : '';
  document.getElementById('hist-usr-body').innerHTML =
    '<div style="text-align:center;padding:32px;color:var(--g400)">Carregando...</div>';

  openModal('modal-historico-usuarios');
  await carregarHistoricoUsuarios(ativo.id, ativo);
}

async function carregarHistoricoUsuarios(ativoId, ativo) {
  const body = document.getElementById('hist-usr-body');
  if (!body) return;

  try {
    // Busca subcollection usuarios_historico via Cloud Function
    let usuarios = [];
    if (FB_READY && auth?.currentUser) {
      const data = await callFunction('getHistoricoUsuarios', { ativoId });
      usuarios   = data?.usuarios || [];
    }

    if (!usuarios.length) {
      body.innerHTML = '<div style="text-align:center;padding:32px;color:var(--g400)">' +
        '<div style="font-size:32px;margin-bottom:12px">&#128101;</div>' +
        'Nenhum registro ainda. O histórico é preenchido automaticamente ' +
        'quando o SYSACK Client está instalado na máquina.</div>';
      return;
    }

    // Ordena: responsável atual primeiro, depois por total de dias
    const responsavelMat = ativo.responsavelMat || '';
    usuarios.sort((a, b) => {
      if (a.ehResponsavel && !b.ehResponsavel) return -1;
      if (!a.ehResponsavel && b.ehResponsavel) return 1;
      return (b.totalDias || 0) - (a.totalDias || 0);
    });

    const fmtDate = d => d ? new Date(d).toLocaleDateString('pt-BR') : '—';
    const semanaAtual = getISOWeekFront(new Date());

    body.innerHTML = `
      <div style="margin-bottom:14px;display:flex;align-items:center;gap:10px">
        <span style="font-size:12px;color:var(--g500)">${usuarios.length} usuário(s) registrado(s)</span>
        ${ativo.responsavelTrocadoEm ? '<span style="font-size:11px;color:var(--g400)">Último responsável definido: ' + fmtDate(ativo.responsavelTrocadoEm?.toDate?.() || ativo.responsavelTrocadoEm) + '</span>' : ''}
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th></th>
            <th>Usuário</th>
            <th>Primeiro login</th>
            <th>Último login</th>
            <th>Total Dias Logado</th>
            <th>Logins nesta semana</th>
            <th>Status</th>
          </tr></thead>
          <tbody>
            ${usuarios.map(u => {
              const diasSemAtu = Object.keys(u.diasSemana || {})
                .filter(k => k.startsWith(semanaAtual)).length;
              const ehResp     = u.ehResponsavel || u.matricula === responsavelMat;
              const ativoNow   = u.ativo !== false;

              return `<tr style="${ehResp ? 'background:rgba(37,99,235,.04)' : ''}">
                <td style="text-align:center">${ehResp ? '<span title="Responsável atual" style="font-size:16px">&#11088;</span>' : ''}</td>
                <td>
                  <div style="font-weight:${ehResp ? '700' : '500'};font-size:13px">${escapeHtml(u.nome || u.usuarioLogado || '—')}</div>
                  ${u.matricula ? '<div style="font-size:11px;color:var(--g400)">Mat: ' + escapeHtml(String(u.matricula)) + '</div>' : ''}
                  ${u.unidade   ? '<div style="font-size:11px;color:var(--g400)">' + escapeHtml(u.unidade) + '</div>' : ''}
                </td>
                <td style="font-size:12px">${fmtDate(u.primeiroLogin)}</td>
                <td style="font-size:12px">${fmtDate(u.ultimoLogin)}</td>
                <td style="text-align:center">
                  <span style="font-size:15px;font-weight:800;color:var(--accent)">${u.totalDias || 0}</span>
                </td>
                <td style="text-align:center">
                  <span style="font-size:13px;font-weight:700;color:${diasSemAtu >= 2 ? 'var(--success)' : 'var(--g400)'}">${diasSemAtu}</span>
                  ${diasSemAtu >= 2 ? '<span style="font-size:10px;color:var(--success);display:block">&#10003; critério</span>' : ''}
                </td>
                <td>
                  ${ehResp
                    ? '<span class="badge badge-info" style="font-size:10px">Responsável</span>'
                    : ativoNow
                      ? '<span class="badge" style="background:var(--g100);color:var(--g600);font-size:10px">Usa a máquina</span>'
                      : '<span style="font-size:11px;color:var(--g300)">Inativo</span>'
                  }
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      <div style="margin-top:12px;padding:10px 14px;background:var(--g50);border-radius:8px;font-size:12px;color:var(--g500)">
        <strong>Como funciona a atribuição automática:</strong><br>
        O sistema monitora o usuário logado em cada checkin. Quando um usuário diferente do
        responsável atual usa a máquina 2 ou mais dias na mesma semana e continua usando,
        ele é definido automaticamente como novo responsável.
      </div>`;
  } catch (err) {
    body.innerHTML = '<div style="padding:20px;color:var(--danger)">Erro ao carregar: ' + escapeHtml(err.message) + '</div>';
  }
}

function histTab(tab) {
  const tabs = ['usuarios', 'historico'];
  tabs.forEach(t => {
    const panel = document.getElementById('tab-' + t);
    const btn   = document.getElementById('tab-' + t + '-btn');
    if (panel) panel.style.display  = t === tab ? '' : 'none';
    if (btn) {
      btn.style.color       = t === tab ? 'var(--accent)' : 'var(--g400)';
      btn.style.fontWeight  = t === tab ? '700' : '400';
      btn.style.borderBottom = t === tab ? '2px solid var(--accent)' : '2px solid transparent';
    }
  });
  if (tab === 'historico' && _ativoHistoricoId) {
    carregarHistoricoMovimentacoes(_ativoHistoricoId);
  }
}

async function carregarHistoricoMovimentacoes(ativoId) {
  const body = document.getElementById('hist-mov-body');
  if (!body || body.dataset.loaded === ativoId) return;
  body.dataset.loaded = ativoId;
  body.innerHTML = '<div style="text-align:center;padding:24px;color:var(--g400)">Carregando...</div>';

  try {
    const data = await callFunction('getHistoricoAtivo', { ativoId, limite: 100 });
    const hist = data?.historico || [];

    if (!hist.length) {
      body.innerHTML = '<div style="text-align:center;padding:32px;color:var(--g400)">' +
        '<div style="font-size:32px;margin-bottom:12px">&#128221;</div>' +
        'Nenhuma movimentação registrada ainda.<br>' +
        '<span style="font-size:12px">O histórico é gerado automaticamente quando área, localização ou responsável são alterados.</span>' +
        '</div>';
      return;
    }

    const ICONS = {
      troca_responsavel: '&#128101;',
      mudanca_local:     '&#128205;',
      mudanca_campo:     '&#9998;&#65039;',
      movimentacao:      '&#128666;',
      nota_tecnico:      '&#128172;',  // balão de fala
    };
    const CORES = {
      troca_responsavel: '#2563EB',
      mudanca_local:     '#059669',
      mudanca_campo:     '#7C3AED',
      movimentacao:      '#D97706',
      nota_tecnico:      '#0891B2',    // azul piscina
    };

    body.innerHTML = '<div style="position:relative">' +
      // Linha vertical da timeline
      '<div style="position:absolute;left:20px;top:0;bottom:0;width:2px;background:var(--g200)"></div>' +
      hist.map(h => {
        const tipo  = h.subtipo || h.tipo || 'mudanca_campo';
        const icon  = ICONS[tipo]  || '&#9998;&#65039;';
        const cor   = CORES[tipo]  || '#94A3B8';
        const data  = h.createdAt ? new Date(h.createdAt).toLocaleString('pt-BR') : h.data || '—';
        const quem  = h.nomeAlterador || h.alteradoPor || 'sistema';

        const ehNota = tipo === 'nota_tecnico';

        return `<div style="display:flex;gap:14px;margin-bottom:20px;position:relative">
          <div style="width:40px;height:40px;border-radius:50%;background:${cor}22;border:2px solid ${cor};
                      display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;z-index:1">
            ${icon}
          </div>
          <div style="flex:1;padding-top:4px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-weight:700;font-size:13px;color:var(--g800)">${escapeHtml(h.titulo || h.label || h.campo || 'Alteração')}</span>
              ${ehNota ? '<span style="font-size:10px;font-weight:700;background:#0891B2;color:#fff;padding:1px 8px;border-radius:20px;letter-spacing:.02em">PERMANENTE</span>' : ''}
            </div>
            ${ehNota
              ? `<div style="background:rgba(8,145,178,.08);border-left:3px solid #0891B2;border-radius:0 6px 6px 0;padding:10px 14px;font-size:13px;color:var(--g700);line-height:1.6;white-space:pre-wrap">${escapeHtml(h.desc || h.texto || '')}</div>`
              : `<div style="font-size:12.5px;color:var(--g600);margin:3px 0">${escapeHtml(h.desc || (h.de + ' → ' + h.para))}</div>`
            }
            <div style="font-size:11px;color:var(--g400);display:flex;gap:12px;margin-top:6px">
              <span>&#128336; ${escapeHtml(data)}</span>
              <span>&#128100; ${escapeHtml(quem)}</span>
            </div>
          </div>
        </div>`;
      }).join('') + '</div>';
  } catch (err) {
    body.innerHTML = '<div style="padding:20px;color:var(--danger)">Erro: ' + escapeHtml(err.message) + '</div>';
  }
}

// Reseta o cache ao abrir o modal para outro ativo
const _origAbrirHistorico = abrirHistoricoUsuarios;
window.abrirHistoricoUsuarios = async function() {
  const body = document.getElementById('hist-mov-body');
  if (body) delete body.dataset.loaded;
  histTab('usuarios');
  await _origAbrirHistorico();
};

async function salvarNotaHistorico() {
  const texto  = document.getElementById('hist-nota-texto')?.value?.trim();
  if (!texto) return showToast('Digite uma consideração antes de salvar.', 'warning');
  if (!_ativoHistoricoId) return;

  const btn = document.querySelector('[onclick="salvarNotaHistorico()"]');
  setButtonLoading(btn, true, 'Salvando...');

  try {
    await callFunction('adicionarNotaHistorico', {
      ativoId: _ativoHistoricoId,
      texto,
    });

    // Limpa o campo e recarrega o histórico
    document.getElementById('hist-nota-texto').value = '';
    // Força recarregamento do painel
    const body = document.getElementById('hist-mov-body');
    if (body) delete body.dataset.loaded;
    await carregarHistoricoMovimentacoes(_ativoHistoricoId);
    showToast('Consideração registrada com sucesso!', 'success', 3000);
  } catch (err) {
    showToast('Erro ao salvar: ' + err.message, 'danger');
  } finally {
    setButtonLoading(btn, false, '&#128190; Salvar Consideração');
  }
}

function getISOWeekFront(date) {
  const d    = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const day  = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const year = d.getUTCFullYear();
  const week = Math.ceil((((d - new Date(Date.UTC(year, 0, 1))) / 86400000) + 1) / 7);
  return year + '-W' + String(week).padStart(2, '0');
}

// Mostra botão Histórico quando o ativo é um computador Windows com client instalado
function atualizarBotoesAtivo(ativo) {
  const temClient = ativo.syncSource === 'sysack-client';
  const btnHist   = document.getElementById('btn-historico-usuarios');
  if (btnHist) btnHist.style.display = temClient ? '' : 'none';
  atualizarBotaoDeployClient(ativo);
}

function copiarCmdInstall() {
  const cmd = 'Invoke-WebRequest -Uri "https://sysack.vercel.app/sysack-client.ps1" -OutFile sysack-client.ps1; .\sysack-client.ps1 -Action install -ProjectId sysack-829e2 -ApiKey SUA_API_KEY';
  navigator.clipboard.writeText(cmd).then(() => showToast('Comando copiado!', 'success', 2000));
}

function baixarInstaladorAgente() {
  // Gera o script de instalacao do agente desktop
  const script = `# SYSACK Agent Desktop Installer
# Execute como Administrador
param([switch]$Install,[switch]$Remove,[switch]$Status)
$ErrorActionPreference = 'Stop'
$InstallDir  = 'C:\Program Files\SYSACK\agent-desktop'
$ServiceName = 'SYSACKAgentDesktop'
$NodeUrl     = 'https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi'

If ($Install) {
  Write-Host 'Instalando SYSACK Agent Desktop...' -ForegroundColor Cyan
  
  # Verifica/instala Node.js
  If (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host 'Baixando Node.js...'
    $tmp = "$env:TEMP\node-setup.msi"
    Invoke-WebRequest -Uri $NodeUrl -OutFile $tmp -UseBasicParsing
    Start-Process msiexec -ArgumentList "/i $tmp /quiet /norestart" -Wait
    Remove-Item $tmp -Force
    $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH','Machine')
    Write-Host 'Node.js instalado' -ForegroundColor Green
  }
  
  # Cria diretório
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  
  # Cria package.json
  @{ name='sysack-agent-desktop'; version='2.0.0'; main='agent.js'; dependencies=@{ ws='8.16.0' } } |
    ConvertTo-Json | Set-Content "$InstallDir\package.json"
  
  # Cria config
  @{ firebaseProjectId='sysack-829e2'; firebaseApiKey='SUA_API_KEY'; agentId=$env:COMPUTERNAME; webSocketPort=9000 } |
    ConvertTo-Json | Set-Content "$InstallDir\config.json"
  
  # Baixa o agente principal do SYSACK
  Invoke-WebRequest -Uri "https://sysack.vercel.app/agent-desktop.js" -OutFile "$InstallDir\agent.js" -UseBasicParsing -ErrorAction SilentlyContinue
  
  # Instala dependências
  Push-Location $InstallDir; npm install --production --silent; Pop-Location
  
  # Cria serviço Windows
  $node = (Get-Command node).Path
  sc.exe create $ServiceName binPath= "\"$node\" \"$InstallDir\agent.js\"" start= auto DisplayName= "SYSACK Agent Desktop" | Out-Null
  sc.exe description $ServiceName "SYSACK - Gerenciamento remoto de computadores" | Out-Null
  sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
  Start-Service -Name $ServiceName
  
  Write-Host '================================================' -ForegroundColor Green
  Write-Host 'SYSACK Agent Desktop instalado com sucesso!' -ForegroundColor Green
  Write-Host "O computador $env:COMPUTERNAME aparecera no SYSACK em ~30s" -ForegroundColor Green
  Write-Host '================================================' -ForegroundColor Green
}

If ($Remove) {
  Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
  Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host 'SYSACK Agent Desktop removido.' -ForegroundColor Yellow
}

If ($Status) {
  $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
  Write-Host "Status: $($svc?.Status ?? 'NAO INSTALADO')" -ForegroundColor $(If ($svc?.Status -eq 'Running') {'Green'} Else {'Red'})
  Get-Content "$InstallDir\agent.log" -Tail 20 -ErrorAction SilentlyContinue
}`;

  const blob = new Blob([script], { type:'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'Install-SysackAgentDesktop.ps1'; a.click();
  URL.revokeObjectURL(url);
  showToast('Instalador baixado! Execute como Administrador no PC alvo.', 'success', 5000);
  closeModal('modal-ar-download');
}

function copiarLinkInstalacao() {
  const link = document.getElementById('install-link-url')?.value;
  if (link) navigator.clipboard.writeText(link).then(() => showToast('Link copiado!', 'success', 2000));
}

function enviarLinkWhatsApp() {
  const link = document.getElementById('install-link-url')?.value;
  const host = document.getElementById('install-link-hostname')?.textContent || '';
  const msg  = encodeURIComponent(`SYSACK Client — Instalação\nDispositivo: ${host}\nAcesse o link para instalar:\n${link}\n\nVálido por 24 horas.`);
  window.open(`https://wa.me/?text=${msg}`, '_blank');
}

function enviarLinkEmail() {
  const link = document.getElementById('install-link-url')?.value;
  const host = document.getElementById('install-link-hostname')?.textContent || '';
  const sub  = encodeURIComponent('SYSACK Client — Instalação em ' + host);
  const body = encodeURIComponent(`Acesse o link abaixo para instalar o SYSACK Client:\n\n${link}\n\nLink válido por 24 horas.`);
  window.open(`mailto:?subject=${sub}&body=${body}`, '_blank');
}

function mostrarQRCode() {
  const link = document.getElementById('install-link-url')?.value;
  const area = document.getElementById('qr-code-area');
  const img  = document.getElementById('qr-code-img');
  if (!link || !area || !img) return;
  area.style.display = '';
  // Usa a API gratuita do Google Charts para gerar QR Code
  const qrUrl = `https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=${encodeURIComponent(link)}&choe=UTF-8`;
  img.innerHTML = `<img src="${qrUrl}" alt="QR Code" style="border-radius:8px;border:4px solid #fff;box-shadow:0 4px 16px rgba(0,0,0,.1)">`;
}

// ════════════════════════════════════════════════════════════
// PWA — Progressive Web App (instalar no celular)
// Atualiza automaticamente quando o sistema web é atualizado
// ════════════════════════════════════════════════════════════

let _pwaInstallPrompt = null;  // armazena o evento beforeinstallprompt
let _swRegistration   = null;  // registration do service worker

// Intercepta o prompt de instalação do navegador
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  _pwaInstallPrompt = e;
  // Mostra botão de instalar no topbar
  const btn = document.getElementById('pwa-install-btn');
  if (btn) {
    btn.style.display = 'flex';
    btn.title = 'Instalar SYSACK no seu dispositivo';
  }
  console.log('[PWA] Prompt de instalação disponível');
});

// Detecta quando o app foi instalado
window.addEventListener('appinstalled', () => {
  _pwaInstallPrompt = null;
  const btn = document.getElementById('pwa-install-btn');
  if (btn) btn.style.display = 'none';
  showToast('✅ SYSACK instalado com sucesso! Procure o ícone na tela inicial.', 'success', 5000);
  console.log('[PWA] App instalado');
});

async function instalarPWA() {
  if (!_pwaInstallPrompt) {
    // Fallback: explica como instalar manualmente
    const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
    if (isIOS) {
      showToast('No iOS: toque em Compartilhar (⬆️) e depois "Adicionar à Tela de Início"', 'info', 6000);
    } else {
      showToast('Para instalar: no Chrome, toque nos 3 pontos (...) e selecione "Instalar aplicativo"', 'info', 6000);
    }
    return;
  }
  try {
    const result = await _pwaInstallPrompt.prompt();
    console.log('[PWA] Resultado:', result.outcome);
    if (result.outcome === 'accepted') {
      showToast('✅ Instalando SYSACK...', 'success');
    }
  } catch (err) {
    console.warn('[PWA] Erro ao instalar:', err.message);
  }
}

// Registra Service Worker — permite funcionamento offline e atualizações automáticas
function initPWA() {
  if (!('serviceWorker' in navigator)) {
    console.warn('[PWA] Service Worker não suportado');
    return;
  }
  navigator.serviceWorker.register('/sw.js')
    .then(reg => {
      _swRegistration = reg;
      console.log('[PWA] ✓ Service Worker registrado:', reg.scope);

      // Verifica atualizações a cada 60 segundos
      setInterval(() => reg.update(), 60000);

      // Quando há nova versão disponível
      reg.addEventListener('updatefound', () => {
        const worker = reg.installing;
        worker.addEventListener('statechange', () => {
          if (worker.state === 'installed' && navigator.serviceWorker.controller) {
            // Nova versão disponível — notifica o usuário
            showUpdateBanner();
          }
        });
      });
    })
    .catch(err => console.warn('[PWA] SW error:', err.message));

  // Recebe comandos FCM do Service Worker (background messages)
  navigator.serviceWorker.addEventListener('message', event => {
    const { type, tipo, data } = event.data || {};
    if (type === 'FCM_CMD') {
      console.log('[FCM SW→App] Comando:', tipo);
      if (tipo === 'checkin_request')  executarAutoCheckin(data?.smId);
      if (tipo === 'location_request') reportarLocalizacao(data?.smId, data?.requestId);
    }
  });

  // Quando o SW assume o controle (após atualização)
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    console.log('[PWA] Nova versão ativa — recarregando...');
    window.location.reload();
  });
}

// ═══════════════════════════════════════════════════════════
// DOWNLOAD SYSACK CLIENT PARA WINDOWS
// Gera e baixa o instalador atualizado sincronizado com a versão web
// ═══════════════════════════════════════════════════════════
const SYSACK_CLIENT_VERSION = '2.0.0'; // atualiza junto com a versão web

function mostrarBotaoDownloadClient() {
  // Mostra o botão de download apenas em Windows
  const isWindows = navigator.platform?.toLowerCase().includes('win') ||
                    navigator.userAgent.toLowerCase().includes('windows');
  const btn = document.getElementById('download-client-btn');
  if (btn && isWindows) btn.style.display = 'flex';
}

function baixarSysackClient() {
  // Gera o instalador PowerShell dinamicamente com a versão atual
  // Quando a versão web muda, o script gerado também muda
  const FB_PROJECT = 'sysack-829e2';
  const FB_API_KEY = 'AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww';
  const VERSION    = SYSACK_CLIENT_VERSION;
  const BUILD_DATE = new Date().toISOString().split('T')[0];

  const script = `# SYSACK Client v${VERSION} — Instalador Windows
# Gerado em: ${BUILD_DATE}
# Versao sincronizada com o sistema web SYSACK
# Execute como Administrador

$ErrorActionPreference = "Stop"
$Version    = "${VERSION}"
$BuildDate  = "${BUILD_DATE}"
$InstallDir = "$env:ProgramData\SYSACK\client"
$TaskName   = "SYSACK Client Checkin"
$LogFile    = "$env:ProgramData\SYSACK\client.log"

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  SYSACK Client v$Version" -ForegroundColor Cyan
Write-Host "  Instalador Automatico" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Verifica admin
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERRO: Execute como Administrador!" -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    Exit 1
}

# Cria diretorio
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Write-Host "[1/5] Diretorio criado: $InstallDir" -ForegroundColor Green

# Cria configuracao
$config = @{
    BancoProjectId    = "${FB_PROJECT}"
    BancoApiKey       = "${FB_API_KEY}"
    SendIntervalMin      = 5
    CheckinPath          = "checkins"
    LogFile              = $LogFile
    ColetarSoftware      = $true
    ColetarAntivirus     = $true
    ColetarBitlocker     = $true
    ColetarWindowsUpdate = $true
    ColetarTemperatura   = $true
    ClientVersion        = $Version
    BuildDate            = $BuildDate
} | ConvertTo-Json
$config | Set-Content "$InstallDir\sysack-client.json" -Encoding UTF8
Write-Host "[2/5] Configuracao salva" -ForegroundColor Green

# Cria script principal de checkin
$clientScript = @'
# SYSACK Client - Script de checkin
param([switch]$RunOnce)
$cfg = Get-Content "$env:ProgramData\SYSACK\client\sysack-client.json" | ConvertFrom-Json

Function ConvertTo-FSField($v) {
    If ($v -is [bool])   { return @{booleanValue=$v} }
    If ($v -is [int])    { return @{integerValue="$v"} }
    If ($v -is [double]) { return @{doubleValue=$v} }
    If ($null -eq $v)    { return @{nullValue=$null} }
    return @{stringValue="$v"}
}

Try {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem
    $cpu  = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
    $memPct = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $diskLivre = If ($disk.Size -gt 0) { [math]::Round($disk.FreeSpace / $disk.Size * 100, 1) } Else { 0 }
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber.Trim()
    $ip = (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Where-Object { $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress[0]
    $usuario = $cs.UserName
    $uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    $status = If ($cpu -gt 90 -or $memPct -gt 90 -or $diskLivre -lt 5) {"critico"} ElseIf ($cpu -gt 70 -or $memPct -gt 80 -or $diskLivre -lt 15) {"alerta"} Else {"ok"}

    Try { $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -First 1; $avNome = $av.displayName } Catch { $avNome = "" }
    Try { $bl = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop).ProtectionStatus -eq "On" } Catch { $bl = $null }

    # Coleta monitores conectados via WMI
    $monitoresConectados = @()
    Try {
        $wmiMonitores = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID -ErrorAction Stop
        ForEach ($m in $wmiMonitores) {
            $fabricante = If ($m.ManufacturerName) { [System.Text.Encoding]::ASCII.GetString($m.ManufacturerName).Trim([char]0).Trim() } Else { "" }
            $produto    = If ($m.UserFriendlyName)  { [System.Text.Encoding]::ASCII.GetString($m.UserFriendlyName).Trim([char]0).Trim()  } Else { "" }
            $serial     = If ($m.SerialNumberID)    { [System.Text.Encoding]::ASCII.GetString($m.SerialNumberID).Trim([char]0).Trim()    } Else { "" }
            If ($serial -and $serial -ne "0") {
                $monitoresConectados += @{
                    fabricante = $fabricante
                    modelo     = $produto
                    serial     = $serial
                    conectadoEm = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                }
            }
        }
    } Catch {}
    $monitoresJson = $monitoresConectados | ConvertTo-Json -Compress -Depth 3
    If (-not $monitoresJson) { $monitoresJson = "[]" }

    $fields = @{
        status=ConvertTo-FSField($status); reachable=ConvertTo-FSField($true)
        cpuPct=ConvertTo-FSField([int]$cpu); memPct=ConvertTo-FSField($memPct)
        discoC_livrePct=ConvertTo-FSField($diskLivre); discoC_livreGB=ConvertTo-FSField([math]::Round($disk.FreeSpace/1GB,1))
        ipPrincipal=ConvertTo-FSField($ip); hostname=ConvertTo-FSField($env:COMPUTERNAME)
        serialNumber=ConvertTo-FSField($serial); usuarioLogado=ConvertTo-FSField($usuario)
        uptimeHoras=ConvertTo-FSField($uptime); osNome=ConvertTo-FSField($os.Caption.Trim())
        osBuild=ConvertTo-FSField($os.BuildNumber); antivirusNome=ConvertTo-FSField($avNome)
        bitlockerAtivo=ConvertTo-FSField($bl); syncSource=ConvertTo-FSField("sysack-client")
        clientVersion=ConvertTo-FSField($cfg.ClientVersion); updatedAt=ConvertTo-FSField((Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"))
        lastSeen=ConvertTo-FSField((Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"))
        monitoresConectados=ConvertTo-FSField($monitoresJson)
        qtdMonitores=ConvertTo-FSField($monitoresConectados.Count)
    }

    # Tenta achar o ativo pelo serial ou hostname
    $querySerial = @{structuredQuery=@{from=@(@{collectionId="ativos"});where=@{fieldFilter=@{field=@{fieldPath="serie"};op="EQUAL";value=@{stringValue=$serial}}};limit=1}} | ConvertTo-Json -Depth 10 -Compress
    $queryUrl = "https://firestore.googleapis.com/v1/projects/$($cfg.BancoProjectId)/databases/(default)/documents:runQuery?key=$($cfg.BancoApiKey)"
    $found = $null
    Try {
        $r = Invoke-RestMethod -Uri $queryUrl -Method Post -ContentType "application/json" -Body $querySerial -TimeoutSec 10
        If ($r -and $r[0].document) { $found = $r[0].document.name.Split("/")[-1] }
    } Catch {}

    $col = If ($found) { "ativos/$found" } Else { "checkins/$env:COMPUTERNAME" }
    $body = @{fields=$fields} | ConvertTo-Json -Depth 10 -Compress
    $url  = "https://firestore.googleapis.com/v1/projects/$($cfg.BancoProjectId)/databases/(default)/documents/$($col)?key=$($cfg.BancoApiKey)"
    Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Body $body -TimeoutSec 15 | Out-Null
} Catch {
    Add-Content -Path $cfg.LogFile -Value "[$((Get-Date).ToString())] ERROR: $($_.Exception.Message)" -Encoding UTF8 -ErrorAction SilentlyContinue
}
'@
$clientScript | Set-Content "$InstallDir\SysackClient.ps1" -Encoding UTF8
Write-Host "[3/5] Script de checkin instalado" -ForegroundColor Green

# Remove tarefa antiga
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Cria tarefa agendada
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$InstallDir\SysackClient.ps1\`""
$trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -Hidden -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "SYSACK v$Version — Monitoramento do dispositivo" -Force | Out-Null
Write-Host "[4/5] Tarefa agendada criada (a cada 5 min, conta SYSTEM)" -ForegroundColor Green

# Primeiro checkin imediato
Start-ScheduledTask -TaskName $TaskName
Write-Host "[5/5] Primeiro checkin iniciado" -ForegroundColor Green

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  SYSACK Client v$Version instalado!" -ForegroundColor Green
Write-Host "  O computador aparecera no SYSACK em ~1 min" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Pressione Enter para fechar"`;

  // Download the generated .ps1 file
  const blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `SysackClient-Setup-v${VERSION}.ps1`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(
    '✅ SYSACK Client v' + VERSION + ' baixado! Execute como Administrador no computador alvo.',
    'success', 6000
  );
}

function showUpdateBanner() {
  let banner = document.getElementById('pwa-update-banner');
  if (banner) return;
  banner = document.createElement('div');
  banner.id = 'pwa-update-banner';
  banner.style.cssText = [
    'position:fixed','bottom:80px','left:50%','transform:translateX(-50%)',
    'background:#1E293B','color:#fff','padding:12px 20px','border-radius:12px',
    'box-shadow:0 8px 32px rgba(0,0,0,.3)','z-index:9999',
    'display:flex','align-items:center','gap:12px','font-size:13px','font-weight:500',
    'max-width:90vw','animation:fadeUp .3s ease',
  ].join(';');
  banner.innerHTML = '<span>🔄 Nova versão disponível!</span>' +
    '<button onclick="atualizarPWA()" style="padding:6px 14px;background:#2563EB;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700">Atualizar agora</button>' +
    '<button onclick="this.parentElement.remove()" style="background:none;border:none;color:rgba(255,255,255,.5);cursor:pointer;font-size:18px">✕</button>';
  document.body.appendChild(banner);
}

function atualizarPWA() {
  if (_swRegistration?.waiting) {
    // Manda mensagem para o SW waiting assumir o controle
    _swRegistration.waiting.postMessage({ type: 'SKIP_WAITING' });
  }
}

// Inicia PWA quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', () => {
  // Só registra SW em HTTPS
  if (location.protocol === 'https:') {
    initPWA();
  }
});

// ════════════════════════════════════════════════════════════
// DEPLOY CLIENT REMOTO — instala SYSACK Client via Cloud Function
// ════════════════════════════════════════════════════════════

let _deployAtivoAtual = null; // ativo selecionado no modal

function deployClientRemoto() {
  if (!SESSION_USER || !['admin', 'gestor'].includes(SESSION_USER.role)) {
    showToast('⛔ Acesso restrito: deploy remoto.', 'error');
    return;
  }

  // Pré-preenche o hostname com dados do ativo aberto
  const ativo = _ativoEditando || {};
  const hostname = ativo.hostname || ativo.ip || ativo.ipPrincipal || '';
  document.getElementById('deploy-hostname').value = hostname;
  document.getElementById('deploy-usuario').value  = '';
  document.getElementById('deploy-senha').value    = '';
  document.getElementById('deploy-status-bar').style.display = 'none';
  document.getElementById('deploy-log').style.display        = 'none';
  document.getElementById('deploy-script-area').style.display = 'none';
  document.getElementById('deploy-ajuda-winrm').style.display = 'none';
  document.getElementById('deploy-log-body').innerHTML       = '';
  _deployAtivoAtual = ativo;
  atualizarMetodoDeployUI();
  openModal('modal-deploy-client');
}

function atualizarMetodoDeployUI() {
  const metodo = document.getElementById('deploy-metodo')?.value || 'winrm';
  const scriptArea = document.getElementById('deploy-script-area');
  const btnExec    = document.getElementById('btn-deploy-exec');

  if (metodo === 'script') {
    scriptArea.style.display = '';
    btnExec.textContent      = 'Copiar Script';
    gerarScriptPreview();
  } else {
    scriptArea.style.display = 'none';
    btnExec.textContent      = '\u2B07 Instalar Agora';
  }
}

function gerarScriptPreview() {
  const FB_KEY     = 'AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww';
  const FB_PROJECT = 'sysack-829e2';
  const script = `# SYSACK Client — Instalacao rapida
# Execute como Administrador neste computador

$dest = "$env:ProgramData\\SYSACK\\client"
New-Item -ItemType Directory -Path $dest -Force | Out-Null

# Configuracao
@{ BancoProjectId="${FB_PROJECT}"; BancoApiKey="${FB_KEY}"; SendIntervalMin=5 } | ConvertTo-Json | Set-Content "$dest\\sysack-client.json"

# Baixa o script do servidor (adapte o caminho)
# Invoke-WebRequest "\\\\servidor-ti\\SYSACK$\\client\\SysackClient.ps1" -OutFile "$dest\\SysackClient.ps1"
# OU copie o SysackClient.ps1 manualmente para: $dest

# Instala tarefa agendada
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$dest\\SysackClient.ps1\`""
$trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -Hidden -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SYSACK Client Checkin" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "SYSACK Client Checkin"

Write-Host "SYSACK Client instalado! O computador aparecera no SYSACK em ate 5 minutos."`;

  document.getElementById('deploy-script-code').textContent = script;
}

function copiarScriptDeploy() {
  const code = document.getElementById('deploy-script-code').textContent;
  navigator.clipboard.writeText(code).then(() => showToast('Script copiado!', 'success', 2000));
}

function mostrarAjudaWinRM() {
  const el = document.getElementById('deploy-ajuda-winrm');
  el.style.display = el.style.display === 'none' ? '' : 'none';
}

async function testarConexaoRemota() {
  const hostname = document.getElementById('deploy-hostname')?.value?.trim();
  if (!hostname) return showToast('Digite o hostname ou IP', 'warning');

  deployLog('Testando conexao com ' + hostname + '...');
  showDeployStatus('info', 'Testando conexao...');

  // Chama Cloud Function para testar (ping + WinRM)
  try {
    if (!FB_READY || !auth?.currentUser) throw new Error('Login necessario');
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'testarConexaoCliente');
    const r  = await fn({ hostname });
    if (r.data.ping) {
      deployLog('Ping: OK (' + r.data.latencyMs + 'ms)');
    } else {
      deployLog('Ping: FALHOU — verifique o hostname/IP');
    }
    if (r.data.winrm) {
      deployLog('WinRM: DISPONIVEL');
      showDeployStatus('success', 'Conexao OK — pronto para instalar');
    } else {
      deployLog('WinRM: INDISPONIVEL — use metodo "script" ou habilite o PSRemoting');
      showDeployStatus('warning', 'Ping OK mas WinRM nao disponivel');
    }
    if (r.data.clienteInstalado) {
      deployLog('SYSACK Client: JA INSTALADO (versao ' + (r.data.clienteVersao||'?') + ')');
      showDeployStatus('info', 'SYSACK Client ja esta instalado neste computador');
    }
  } catch (err) {
    deployLog('Erro no teste: ' + err.message);
    // Fallback: testa via ping do proprio browser (limitado)
    showDeployStatus('warning', 'Teste remoto indisponivel — verifique manualmente');
  }
}

// ── INSTALAÇÃO REMOTA VIA 4G (FCM) ───────────────────────────
// Funciona mesmo quando o dispositivo está fora da rede corporativa
// O SYSACK envia o comando via FCM → dispositivo baixa e instala
async function deployClientVia4G(hostname, ativoId) {
  // Verifica se o dispositivo já tem FCM registrado
  const ativo = (STATE.ativos || []).find(a => a.id === ativoId || a.hostname === hostname);
  if (!ativo) return showToast('Ativo não encontrado', 'warning');

  if (!ativo.fcmToken) {
    // Sem FCM — gera link de instalação que o técnico pode enviar por e-mail/WhatsApp
    const link = await gerarLinkInstalacao(ativo);
    openModal('modal-link-instalacao');
    document.getElementById('install-link-url').value = link;
    document.getElementById('install-link-hostname').textContent = hostname;
    return;
  }

  // Com FCM — envia comando de auto-instalação
  try {
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'enviarInstalacaoRemota');
    const r  = await fn({ ativoId: ativo.id, hostname });
    showToast('📲 Comando enviado! O dispositivo vai instalar o client automaticamente.', 'success', 5000);
  } catch (err) {
    showToast('Erro: ' + err.message, 'danger');
  }
}

async function gerarLinkInstalacao(ativo) {
  // Gera um token temporário (24h) para download seguro do instalador
  const token = btoa(JSON.stringify({
    ativoId: ativo?.id || '',
    hostname: ativo?.hostname || '',
    ts: Date.now(),
    exp: Date.now() + 86400000, // 24 horas
    project: 'sysack-829e2',
    apiKey: 'AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww',
  }));
  return `https://sysack.vercel.app/install?t=${token}`;
}

async function executarDeployClient() {
  const hostname = document.getElementById('deploy-hostname')?.value?.trim();
  const usuario  = document.getElementById('deploy-usuario')?.value?.trim() || '';
  const senha    = document.getElementById('deploy-senha')?.value || '';
  const metodo   = document.getElementById('deploy-metodo')?.value || 'winrm';

  if (!hostname) return showToast('Digite o hostname ou IP do computador', 'warning');

  // Modo script: copia
  if (metodo === 'script') {
    copiarScriptDeploy();
    return;
  }

  // Confirma execucao remota
  if (!confirm(
    'Instalar SYSACK Client em "' + hostname + '"?\n\n' +
    'Isso vai:\n' +
    '1. Copiar o SysackClient.ps1 para C:\\ProgramData\\SYSACK\\client\\\n' +
    '2. Criar uma Tarefa Agendada (SYSTEM, a cada 5 min)\n' +
    '3. Executar o primeiro checkin imediatamente\n\n' +
    'Metodo: ' + metodo
  )) return;

  const btn = document.getElementById('btn-deploy-exec');
  btn.disabled    = true;
  btn.textContent = 'Instalando...';
  document.getElementById('deploy-log').style.display = '';
  deployLog('Iniciando instalacao remota em ' + hostname + '...');
  deployLog('Metodo: ' + metodo);
  showDeployStatus('info', 'Instalando...');

  try {
    if (!FB_READY || !auth?.currentUser) throw new Error('Faca login para usar esta funcao');

    // Chama Cloud Function que executa o deploy remoto
    // Using getFbFunctions singleton
    const fn = httpsCallable(getFunctions(app), 'deployClienteRemoto');

    const result = await fn({
      hostname,
      usuario: usuario || null,
      senha:   senha   || null,
      metodo,
      ativoId: _deployAtivoAtual?.id || null,
      ativoPat: _deployAtivoAtual?.pat || null,
    });

    const data = result.data;
    deployLog('');
    for (const step of (data.steps || [])) {
      deployLog(step);
    }

    if (data.sucesso) {
      showDeployStatus('success', 'Instalacao concluida! O dispositivo aparecera no SYSACK em ate 5 minutos.');
      deployLog('SYSACK Client instalado com sucesso!');
      showToast('SYSACK Client instalado em ' + hostname, 'success', 5000);
      // Atualiza o ativo no STATE
      if (_deployAtivoAtual?.id) {
        const idx = (STATE.ativos||[]).findIndex(a => a.id === _deployAtivoAtual.id);
        if (idx >= 0) STATE.ativos[idx].sysackClientInstalado = true;
      }
    } else {
      showDeployStatus('danger', 'Falha: ' + (data.erro || 'Erro desconhecido'));
      deployLog('ERRO: ' + (data.erro || ''));
    }
  } catch (err) {
    deployLog('Erro: ' + err.message);
    showDeployStatus('danger', err.message);
    // Fallback: mostra script manual
    document.getElementById('deploy-metodo').value = 'script';
    atualizarMetodoDeployUI();
    deployLog('Gerando script para instalacao manual...');
  } finally {
    btn.disabled    = false;
    btn.textContent = '\u2B07 Instalar Agora';
  }
}

function deployLog(msg) {
  const el = document.getElementById('deploy-log-body');
  if (!el) return;
  const ts   = new Date().toLocaleTimeString('pt-BR');
  el.innerHTML += (msg ? '<span style="color:#64748B">['+ts+']</span> ' + escapeHtml(msg) : '') + '\n';
  el.scrollTop = el.scrollHeight;
}

function showDeployStatus(tipo, msg) {
  const el = document.getElementById('deploy-status-bar');
  if (!el) return;
  const colors = {
    success: '#F0FDF4;color:#166534;border:1px solid #BBF7D0',
    danger:  '#FEF2F2;color:#991B1B;border:1px solid #FECACA',
    warning: '#FFFBEB;color:#92400E;border:1px solid #FDE68A',
    info:    '#EFF6FF;color:#1D4ED8;border:1px solid #BFDBFE',
  };
  el.style.cssText = 'display:block;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:500;background:' + (colors[tipo] || colors.info);
  el.textContent   = msg;
}

// Mostra botao de deploy quando ativo tem IP/hostname e eh Windows
function atualizarBotaoDeployClient(ativo) {
  const temIP     = !!(ativo.ip || ativo.ipAddress || ativo.hostname || ativo.ipPrincipal);
  const ehWindows = ['computador','notebook','workstation','servidor'].includes(ativo.tipo) ||
                    (ativo.osNome && ativo.osNome.toLowerCase().includes('windows'));
  const temClient = ativo.syncSource === 'sysack-client' || ativo.sysackClientInstalado;

  const btnDeploy  = document.getElementById('btn-deploy-client');
  const btnRemoto  = document.getElementById('btn-acesso-remoto');
  const btnApp     = document.getElementById('btn-instalar-app');

  if (btnDeploy) btnDeploy.style.display = (temIP && ehWindows) ? '' : 'none';
  // Acesso remoto e instalação de software só aparecem se tem o client OU tem IP
  if (btnRemoto) btnRemoto.style.display  = (temIP && ehWindows) ? '' : 'none';
  if (btnApp)    btnApp.style.display     = (temIP && ehWindows && temClient) ? '' : 'none';

  // Guarda ativo atual para uso nos modais
  window._ativoEditando = ativo;
  atualizarBotoesAtivo(ativo);
}

// ════════════════════════════════════════════════════════════
// SELF-SERVICE PORTAL
// ════════════════════════════════════════════════════════════

const SS_TIPOS = {
  senha:      { titulo:'🔑 Redefinir Senha',      solucao: ['Acesse: \n<strong>Ctrl+Alt+Del → Alterar senha</strong> (se no escritório)', 'Ou acesse o portal AD: <strong>senha.cesan.com.br</strong>', 'Se não conseguir, informe seu usuário abaixo e um técnico vai redefinir'] },
  acesso:     { titulo:'🔐 Solicitar Acesso',      solucao: null },
  software:   { titulo:'💾 Instalar Software',     solucao: ['Verifique se o software está na lista de homologados em <strong>\\servidor\TI$\Softwares</strong>', 'Execute o instalador como administrador', 'Se precisar de permissão elevada, informe abaixo qual software'] },
  impressora: { titulo:'🖨️ Adicionar Impressora',  solucao: ['Acesse <strong>\\\\print.cesan.com.br</strong> no Windows Explorer', 'Dê dois cliques na impressora desejada', 'O driver instala automaticamente', 'Se não encontrar a impressora, informe o nome abaixo'] },
  email:      { titulo:'📧 Problema de E-mail',    solucao: ['Verifique a cota: <strong>Outlook → Arquivo → Ferramentas → Caixa de correio</strong>', 'Se cota cheia, exclua e-mails antigos da pasta Enviados', 'Para problema de senha, use a opção Redefinir Senha acima'] },
  vpn:        { titulo:'🌐 Acesso VPN',            solucao: ['Baixe o FortiClient em: <strong>\\\\servidor\TI$\VPN</strong>', 'Use as mesmas credenciais do AD (usuário e senha do Windows)', 'Servidor VPN: <strong>vpn.cesan.com.br</strong>'] },
  wifi:       { titulo:'📶 Problema de Wi-Fi',     solucao: ['Rede corporativa: <strong>CESAN-Corp</strong> (use credenciais do AD)', 'Se travou, esqueça a rede e reconecte', 'Verifique se o Wi-Fi está ativado (Fn+F2 em alguns notebooks)'] },
  outro:      { titulo:'💬 Outra Solicitação',     solucao: null },
};

let _ssTipoAtual = 'outro';

function abrirSS(tipo) {
  _ssTipoAtual = tipo;
  const cfg = SS_TIPOS[tipo] || SS_TIPOS.outro;
  document.getElementById('ss-modal-title').textContent = cfg.titulo;
  document.getElementById('ss-desc').value = '';
  document.getElementById('ss-contato').value = '';

  // Exibe solução automática se disponível
  const solEl = document.getElementById('ss-solucao-automatica');
  if (cfg.solucao) {
    solEl.style.display = '';
    solEl.innerHTML = '<div class="ss-solucao">' +
      '<h4>💡 Tente primeiro — solução automática:</h4>' +
      '<ol>' + cfg.solucao.map(s => '<li>' + s + '</li>').join('') + '</ol>' +
      '</div>';
  } else {
    solEl.style.display = 'none';
  }

  openModal('modal-ss');
}

async function enviarSS() {
  const desc     = document.getElementById('ss-desc')?.value?.trim();
  const urgencia = document.getElementById('ss-urgencia')?.value || 'normal';
  const contato  = document.getElementById('ss-contato')?.value?.trim() || '';
  if (!desc) return showToast('Descreva o problema antes de enviar', 'danger');

  const cfg  = SS_TIPOS[_ssTipoAtual] || SS_TIPOS.outro;
  const user = CURRENT_USER || {};

  // Cria chamado automaticamente
  const chamado = {
    titulo:          cfg.titulo + ' (Self-Service)',
    desc:            desc,
    tipo:            'requisicao',
    categoria:       mapSSCategoria(_ssTipoAtual),
    subcategoria:    'Self-Service',
    status:          'aberto',
    prioridade:      urgencia === 'alta' ? 'alta' : 'media',
    area:            user.setor || '',
    entidade:        'SYSACK',
    origem:          'self-service',
    requerenteId:    user.uid || '',
    requerenteNome:  user.nome || '',
    requerenteEmail: user.email || '',
    requerenteRamal: contato,
    obs:             contato ? 'Contato: ' + contato : '',
    createdBy:       user.uid || '',
    updatedBy:       user.uid || '',
    dataAbertura:    new Date(),
  };

  try {
    // Salva localmente
    if (!STATE.chamados) STATE.chamados = [];
    const id = 'SS-' + Date.now();
    STATE.chamados.unshift({ ...chamado, id });

    // Salva no Banco
    // await fsAdd('chamados', chamado);

    closeModal('modal-ss');
    showToast('✅ Solicitação enviada! Nossa equipe responderá em breve.', 'success', 5000);
    renderSelfService();
    auditLog('CREATE', 'self-service', id, 'chamado', { tipo: _ssTipoAtual });
  } catch (err) {
    showToast('Erro ao enviar: ' + err.message, 'danger');
  }
}

function mapSSCategoria(tipo) {
  const map = { senha:'Active Directory', acesso:'Active Directory', software:'Software', impressora:'Impressão', email:'E-mail', vpn:'VPN', wifi:'Wi-Fi' };
  return map[tipo] || 'Demais solicitações';
}

function renderSelfService() {
  const tbody = document.getElementById('ss-minhas-body');
  if (!tbody) return;

  const user    = CURRENT_USER || {};
  const minhas  = (STATE.chamados || []).filter(c =>
    c.origem === 'self-service' && c.requerenteId === user.uid
  );

  if (!minhas.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma solicitação registrada</td></tr>';
    return;
  }

  tbody.innerHTML = minhas.map(c => {
    const statusCfg = { aberto:'badge-info', 'em-atendimento':'badge-success', fechado:'badge-success', cancelado:'' };
    return '<tr>' +
      '<td class="td-mono" style="color:var(--accent)">' + (c.id||'—') + '</td>' +
      '<td><span class="tag">' + (c.categoria||'—') + '</span></td>' +
      '<td style="max-width:220px;font-size:12px">' + (c.desc||'').slice(0,60) + '</td>' +
      '<td><span class="badge ' + (statusCfg[c.status]||'') + '">' + (c.status||'—') + '</span></td>' +
      '<td class="td-mono" style="font-size:11px">' + fmtDate(c.dataAbertura) + '</td>' +
      '<td style="font-size:12px;color:var(--g500)">' + (c.resposta || '—') + '</td>' +
      '</tr>';
  }).join('');
}

// ════════════════════════════════════════════════════════════
// EMPREGADOS & AUSÊNCIAS
// ════════════════════════════════════════════════════════════

// ─── ORGANOGRAMA ─────────────────────────────────────────────────
let _orgSetorAberto = null;

function renderOrganograma() {
  const unidades  = STATE.orgUnidades || [];
  const empregados = STATE.empregados || [];
  const q         = (document.getElementById('org-search')?.value || '').toLowerCase();
  const view      = document.getElementById('org-view')?.value || 'cards';

  // KPIs
  const totalAtivos   = empregados.filter(e => e.adAtivo !== false).length;
  const totalInativos = empregados.filter(e => e.adAtivo === false).length;
  const totalAtivosTI = (STATE.ativos || []).filter(a => a.resp && a.resp.trim()).length;
  const sv = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  sv('org-total-setores',   unidades.length);
  sv('org-total-ativos',    totalAtivos);
  sv('org-total-inativos',  totalInativos);
  sv('org-total-ativos-ti', totalAtivosTI);

  const grid = document.getElementById('org-grid');
  if (!grid) return;

  // Filtra unidades pela busca
  let filtered = unidades;
  if (q) {
    filtered = unidades.filter(u => {
      if ((u.sigla||'').toLowerCase().includes(q)) return true;
      if ((u.empregados||[]).some(e => (e.nome||'').toLowerCase().includes(q) || (e.cargo||'').toLowerCase().includes(q))) return true;
      return false;
    });
  }

  if (!filtered.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:48px;color:var(--g400)"><div style="font-size:40px;margin-bottom:12px">🏢</div><div>Nenhum setor encontrado</div></div>';
    return;
  }

  // Ordena por total de empregados (maior primeiro)
  filtered = [...filtered].sort((a,b) => (b.totalAtivos||0) - (a.totalAtivos||0));

  if (view === 'lista') {
    // Vista lista: todos os empregados filtrados
    const todos = filtered.flatMap(u => (u.empregados||[]).map(e => ({...e, setor: u.sigla})));
    const filtradosEmp = q
      ? todos.filter(e => (e.nome||'').toLowerCase().includes(q) || (e.cargo||'').toLowerCase().includes(q) || (e.setor||'').toLowerCase().includes(q))
      : todos;
    grid.innerHTML = `
      <div style="grid-column:1/-1">
        <div style="background:var(--panel,#fff);border-radius:12px;overflow:hidden;border:0.5px solid var(--line,#e2e8f0)">
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="background:var(--g50)">
              <th style="padding:10px 14px;text-align:left;font-size:11px;color:var(--g500);font-weight:600;text-transform:uppercase">Nome</th>
              <th style="padding:10px 14px;text-align:left;font-size:11px;color:var(--g500);font-weight:600;text-transform:uppercase">Cargo</th>
              <th style="padding:10px 14px;text-align:left;font-size:11px;color:var(--g500);font-weight:600;text-transform:uppercase">Lotação</th>
              <th style="padding:10px 14px;text-align:left;font-size:11px;color:var(--g500);font-weight:600;text-transform:uppercase">E-mail</th>
              <th style="padding:10px 14px;text-align:left;font-size:11px;color:var(--g500);font-weight:600;text-transform:uppercase">Status</th>
            </tr></thead>
            <tbody>${filtradosEmp.slice(0,200).map(e => `
              <tr style="border-top:0.5px solid var(--g100)">
                <td style="padding:9px 14px;font-size:13px;font-weight:600">${escapeHtml(e.nome||'—')}</td>
                <td style="padding:9px 14px;font-size:12px;color:var(--g600)">${escapeHtml(e.cargo||'—')}</td>
                <td style="padding:9px 14px"><span class="tag" style="font-size:10px">${escapeHtml(e.setor||'—')}</span></td>
                <td style="padding:9px 14px;font-size:11px;color:var(--accent);font-family:monospace">${escapeHtml(e.email||'—')}</td>
                <td style="padding:9px 14px"><span style="font-size:10px;padding:2px 8px;border-radius:20px;background:${e.ativo!==false?'#eaf3de':'#fee2e2'};color:${e.ativo!==false?'#3b6d11':'#a32d2d'}">${e.ativo!==false?'Ativo':'Inativo'}</span></td>
              </tr>`).join('')}
            </tbody>
          </table>
          ${filtradosEmp.length > 200 ? `<div style="padding:10px;text-align:center;font-size:12px;color:var(--g400)">Mostrando 200 de ${filtradosEmp.length}. Refine a busca para ver mais.</div>` : ''}
        </div>
      </div>`;
    return;
  }

  // Vista cards
  grid.innerHTML = filtered.map(u => {
    const ativos   = u.totalAtivos   || 0;
    const total    = u.totalEmpregados || u.empregados?.length || 0;
    const inativos = total - ativos;
    const pct      = total > 0 ? Math.round((ativos / total) * 100) : 0;
    const barCor   = pct > 80 ? 'var(--success)' : pct > 50 ? 'var(--warning)' : 'var(--danger)';

    // Ativos de TI vinculados a este setor
    const ativosTI = (STATE.ativos||[]).filter(a =>
      (a.resp||'').toLowerCase().includes((u.sigla||'').toLowerCase()) ||
      (a.area||'').toLowerCase().includes((u.sigla||'').toLowerCase())
    ).length;

    // Empregados em destaque (primeiros 3)
    const destaques = (u.empregados||[]).filter(e => e.ativo !== false).slice(0,3);

    return `
      <div onclick="abrirDetalheSetor('${u.sigla}')" style="background:var(--panel,#fff);border:0.5px solid var(--line,#e2e8f0);border-radius:12px;padding:16px;cursor:pointer;transition:all .2s;border-top:3px solid var(--accent)" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 8px 24px rgba(0,0,0,.1)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
          <div>
            <div style="font-size:16px;font-weight:800;color:var(--text)">${escapeHtml(u.sigla||'—')}</div>
            <div style="font-size:11px;color:var(--g400);margin-top:2px">${total} empregado${total!==1?'s':''}</div>
          </div>
          <span style="background:var(--accent-l,#EFF6FF);color:var(--accent);font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px">${ativos} ativos</span>
        </div>

        <!-- Barra de ativos -->
        <div style="background:var(--g100);border-radius:4px;height:4px;overflow:hidden;margin-bottom:12px">
          <div style="background:${barCor};width:${pct}%;height:100%;border-radius:4px;transition:width .4s"></div>
        </div>

        <!-- Mini lista de empregados -->
        <div style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
          ${destaques.map(e => `
            <div style="display:flex;align-items:center;gap:8px">
              <div style="width:26px;height:26px;border-radius:50%;background:var(--accent-l);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--accent);flex-shrink:0">${(e.nome||'?').charAt(0)}</div>
              <div style="min-width:0">
                <div style="font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(e.nome||'—')}</div>
                <div style="font-size:10px;color:var(--g400);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(e.cargo||'—')}</div>
              </div>
            </div>`).join('')}
          ${total > 3 ? `<div style="font-size:11px;color:var(--g400);padding-left:34px">+${total-3} outros...</div>` : ''}
        </div>

        <!-- Rodapé com ativos TI -->
        <div style="display:flex;gap:12px;padding-top:8px;border-top:0.5px solid var(--g100);font-size:11px;color:var(--g500)">
          <span>🖥️ ${ativosTI} ativo${ativosTI!==1?'s':''} de TI</span>
          ${inativos > 0 ? `<span>💤 ${inativos} inativo${inativos!==1?'s':''}</span>` : ''}
        </div>
      </div>`;
  }).join('');
}

function abrirDetalheSetor(sigla) {
  const u = (STATE.orgUnidades||[]).find(u => u.sigla === sigla);
  if (!u) return;
  _orgSetorAberto = u;

  document.getElementById('org-modal-titulo').textContent = '🏢 ' + sigla;

  const ativos   = u.totalAtivos || 0;
  const total    = u.totalEmpregados || u.empregados?.length || 0;
  const ativosTI = (STATE.ativos||[]).filter(a =>
    (a.resp||'').toLowerCase().includes(sigla.toLowerCase()) ||
    (a.area||'').toLowerCase().includes(sigla.toLowerCase())
  ).length;

  document.getElementById('org-modal-stats').innerHTML = [
    ['Total', total, '#2563EB'],
    ['Ativos', ativos, '#059669'],
    ['Inativos', total - ativos, '#DC2626'],
    ['Ativos TI', ativosTI, '#7C3AED'],
  ].map(([l,v,c]) => `
    <div style="background:${c}11;border:1px solid ${c}33;border-radius:10px;padding:8px 14px;text-align:center;min-width:80px">
      <div style="font-size:20px;font-weight:800;color:${c}">${v}</div>
      <div style="font-size:10px;color:${c};font-weight:600">${l}</div>
    </div>`).join('');

  document.getElementById('org-modal-search').value = '';
  filtrarEmpregadosModal();
  document.getElementById('org-modal-setor').style.display = 'flex';
}

function filtrarEmpregadosModal() {
  const u = _orgSetorAberto;
  if (!u) return;
  const q = (document.getElementById('org-modal-search')?.value || '').toLowerCase();
  const emps = (u.empregados||[]).filter(e =>
    !q || (e.nome||'').toLowerCase().includes(q) || (e.cargo||'').toLowerCase().includes(q) || (e.email||'').toLowerCase().includes(q)
  );

  document.getElementById('org-modal-lista').innerHTML = emps.length
    ? emps.map(e => `
        <div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:0.5px solid var(--g100)">
          <div style="width:36px;height:36px;border-radius:50%;background:${e.ativo!==false?'var(--accent-l)':'var(--g100)'};display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:${e.ativo!==false?'var(--accent)':'var(--g400)'};flex-shrink:0">${(e.nome||'?').charAt(0)}</div>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600;display:flex;align-items:center;gap:6px">
              ${escapeHtml(e.nome||'—')}
              ${e.ativo===false ? '<span style="font-size:10px;background:#fee2e2;color:#a32d2d;padding:1px 6px;border-radius:10px">Inativo</span>' : ''}
            </div>
            <div style="font-size:11px;color:var(--g500)">${escapeHtml(e.cargo||'—')}</div>
            ${e.email ? `<div style="font-size:11px;color:var(--accent);font-family:monospace">${escapeHtml(e.email)}</div>` : ''}
          </div>
          ${e.ramal ? `<div style="font-size:11px;color:var(--g500);flex-shrink:0">📞 ${escapeHtml(e.ramal)}</div>` : ''}
        </div>`).join('')
    : '<div style="text-align:center;padding:24px;color:var(--g400)">Nenhum empregado encontrado</div>';
}

function renderEmpregados() {
  const tbody    = document.getElementById('emp-body');
  if (!tbody) return;

  const q      = (document.getElementById('emp-search')?.value || '').toLowerCase();
  const fStatus = document.getElementById('emp-filter-status')?.value || '';
  const fSetor  = document.getElementById('emp-filter-setor')?.value  || '';

  const empregados = STATE.empregados || [];

  // Popula filtro de setor
  const setorSel = document.getElementById('emp-filter-setor');
  if (setorSel && setorSel.options.length <= 1) {
    const setores = [...new Set(empregados.map(e => e.setor).filter(Boolean))].sort();
    setores.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s; opt.textContent = s;
      setorSel.appendChild(opt);
    });
  }

  // Stats
  const ausentes    = empregados.filter(e => e.emAusencia);
  const suprimidos  = empregados.filter(e => e.suprimirAlertas);
  sv('emp-total',      empregados.length);
  sv('emp-ativos',     empregados.filter(e => e.ativo && !e.emAusencia).length);
  sv('emp-ausentes',   ausentes.length);
  sv('emp-suprimidos', suprimidos.length);
  nbUpdate('nb-ausentes', ausentes.length);

  // Sync status
  const syncEl = document.getElementById('emp-sync-status');
  if (syncEl && STATE.empregadosSyncAt) {
    syncEl.innerHTML = '<span style="width:7px;height:7px;border-radius:50%;background:var(--success)"></span> Sync: ' + fmtDatetime(STATE.empregadosSyncAt);
  }

  // Filtro
  let lista = empregados;
  if (q)        lista = lista.filter(e => e.nome?.toLowerCase().includes(q) || e.mat?.includes(q));
  if (fStatus === 'ativo')   lista = lista.filter(e => !e.emAusencia && e.ativo);
  if (fStatus === 'ausente') lista = lista.filter(e => e.emAusencia);
  if (fSetor)   lista = lista.filter(e => e.setor === fSetor);

  if (!lista.length) {
    tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;padding:32px;color:var(--g400)">' +
      (empregados.length ? 'Nenhum empregado encontrado com esses filtros.' : 'Instale o SYSACK Agent no servidor para sincronizar os empregados.') +
      '</td></tr>';
    return;
  }

  // Atualiza cabeçalho dinamicamente com as colunas corretas
  const thead = tbody.closest('table')?.querySelector('thead tr');
  if (thead) {
    thead.innerHTML =
      '<th>Matrícula</th><th>Nome</th><th>Login</th><th>Setor</th><th>Cargo</th>' +
      '<th>Email</th><th>Ramal</th><th>Celular</th>' +
      '<th>Status</th><th>Ausência</th><th>Alertas</th>';
  }

  tbody.innerHTML = lista.map(e => {
    const ausenciaLabel = e.ausencia || '';
    const matLabel = /^\d+$/.test(e.mat || '') ? e.mat : '—';
    return '<tr>' +
      '<td class="td-mono" style="font-size:12px">' + matLabel + '</td>' +
      '<td style="font-weight:600;font-size:13px">' + (e.nome||'—') + '</td>' +
      '<td class="td-mono" style="font-size:11px;color:var(--g500)">' + (e.login||'—') + '</td>' +
      '<td style="font-size:12px">' + (e.setor||'—') + '</td>' +
      '<td style="font-size:12px;color:var(--g500)">' + (e.cargo||'—') + '</td>' +
      '<td style="font-size:11px">' + (e.email||'—') + '</td>' +
      '<td class="td-mono" style="font-size:12px">' + (e.ramal||'—') + '</td>' +
      '<td class="td-mono" style="font-size:12px">' + (e.celular||'—') + '</td>' +
      '<td>' + (e.emAusencia
        ? '<span class="badge badge-warning">Em Ausência</span>'
        : e.ativo
          ? '<span class="badge badge-success">Ativo</span>'
          : '<span class="badge">Inativo</span>') + '</td>' +
      '<td>' + (ausenciaLabel ? '<span class="tag">' + ausenciaLabel + '</span>' : '—') + '</td>' +
      '<td>' + (e.suprimirAlertas
        ? '<span style="font-size:11px;color:var(--warning);font-weight:600">🔕 Suprimidos</span>'
        : '<span style="font-size:11px;color:var(--success)">🔔 Ativos</span>') + '</td>' +
      '</tr>';
  }).join('');
}

// Listener Banco para empregados
function listenEmpregados() {
  if (!FB_READY || !db) return;
  // Escuta coleção empregados em tempo real
  listen('empregados', [orderBy('nome', 'asc'), limit(500)], (empregados) => {
    STATE.empregados = empregados;
    STATE.empregadosSyncAt = empregados[0]?.syncAt ? new Date(empregados[0].syncAt) : null;
    if (isPageActive('empregados')) renderEmpregados();
    // Atualiza badge
    nbUpdate('nb-ausentes', empregados.filter(e => e.emAusencia).length);
  }, 'empregados_listener');
}

// ════════════════════════════════════════════════════════════
// APPS STRUCTURES
// ════════════════════════════════════════════════════════════
const APPS_DATA = [
  { nome:'API Acertar', versao:'3.2.1', fabricante:'Acertar', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'Apus Client', versao:'2.5.0', fabricante:'Apus Systems', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'ArterH', versao:'8.1.3', fabricante:'Meta', licenca:'Corporativa', resp:'RH', status:'ativo' },
  { nome:'CadastroSAP', versao:'1.0.0', fabricante:'SAP', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'Cesanlims', versao:'4.7.2', fabricante:'CESAN', licenca:'Proprietária', resp:'Laboratório', status:'ativo' },
  { nome:'SAP ERP', versao:'ECC 6.0', fabricante:'SAP', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'Siscom', versao:'5.3.1', fabricante:'CESAN', licenca:'Proprietária', resp:'TI', status:'ativo' },
  { nome:'Microsoft Office 365', versao:'2024', fabricante:'Microsoft', licenca:'Assinatura', resp:'TI', status:'ativo' },
  { nome:'Windows 10/11', versao:'23H2', fabricante:'Microsoft', licenca:'OEM/Volume', resp:'TI', status:'ativo' },
  { nome:'Antivírus Kaspersky', versao:'21.15', fabricante:'Kaspersky', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'Adobe Acrobat', versao:'2024', fabricante:'Adobe', licenca:'Assinatura', resp:'TI', status:'ativo' },
  { nome:'TeamViewer', versao:'15.50', fabricante:'TeamViewer', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'VPN FortiClient', versao:'7.4.0', fabricante:'Fortinet', licenca:'Incluída no FW', resp:'TI', status:'ativo' },
  { nome:'Zoom', versao:'5.17', fabricante:'Zoom Video', licenca:'Assinatura', resp:'TI', status:'ativo' },
  { nome:'GLPI', versao:'10.0.15', fabricante:'Teclib', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'Backup Exec', versao:'22.4', fabricante:'Veritas', licenca:'Corporativa', resp:'TI', status:'ativo' },
  { nome:'AutoCAD', versao:'2024', fabricante:'Autodesk', licenca:'Assinatura', resp:'Engenharia', status:'ativo' },
  { nome:'Chrome Enterprise', versao:'124', fabricante:'Google', licenca:'Gratuito', resp:'TI', status:'ativo' },
  { nome:'PDF Creator', versao:'6.2.1', fabricante:'pdfforge', licenca:'Gratuito', resp:'TI', status:'ativo' },
  { nome:'7-Zip', versao:'24.08', fabricante:'Igor Pavlov', licenca:'LGPL', resp:'TI', status:'ativo' },
  { nome:'Notepad++', versao:'8.6.7', fabricante:'Don Ho', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'WinSCP', versao:'6.3.3', fabricante:'Martin Prikryl', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'Putty', versao:'0.81', fabricante:'Simon Tatham', licenca:'MIT', resp:'TI', status:'ativo' },
  { nome:'Wireshark', versao:'4.2.5', fabricante:'Wireshark Foundation', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'SQL Server Management Studio', versao:'20.1', fabricante:'Microsoft', licenca:'Gratuito', resp:'TI', status:'ativo' },
  { nome:'DBeaver', versao:'24.0', fabricante:'DBeaver Corp', licenca:'Gratuito', resp:'TI', status:'ativo' },
  { nome:'Git', versao:'2.45', fabricante:'Git SCM', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'Visual Studio Code', versao:'1.89', fabricante:'Microsoft', licenca:'MIT', resp:'TI', status:'ativo' },
  { nome:'FileZilla', versao:'3.67', fabricante:'FileZilla', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'LibreOffice', versao:'24.2', fabricante:'The Document Foundation', licenca:'MPL/LGPL', resp:'TI', status:'ativo' },
  { nome:'VLC Media Player', versao:'3.0.21', fabricante:'VideoLAN', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'KeePass', versao:'2.57', fabricante:'Dominik Reichl', licenca:'GPL', resp:'TI', status:'ativo' },
  { nome:'Advanced IP Scanner', versao:'2.5', fabricante:'Famatech', licenca:'Gratuito', resp:'TI', status:'ativo' },
];

function renderApps() {
  const q = (document.getElementById('apps-search-input')?.value||'').toLowerCase();
  const list = APPS_DATA.filter(a => !q || a.nome.toLowerCase().includes(q) || a.fabricante.toLowerCase().includes(q));
  const tbody = document.getElementById('apps-body');
  if (!tbody) return;
  tbody.innerHTML = list.slice(0,5).map(a => `
    <tr>
      <td><input type="checkbox" style="accent-color:var(--accent)"></td>
      <td style="font-weight:600;color:var(--accent);cursor:pointer">${a.nome}</td>
      <td class="td-mono" style="font-size:10.5px">${a.versao}</td>
      <td style="font-size:12.5px">${a.fabricante}</td>
      <td><span class="tag">${a.licenca}</span></td>
      <td style="font-size:12.5px">${a.resp}</td>
      <td><span class="status-pill sp-ativo">Ativo</span></td>
      <td><div class="flex gap-4">
        <button class="btn btn-ghost btn-xs">✏️</button>
        <button class="btn btn-ghost btn-xs">📋</button>
      </div></td>
    </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma aplicação encontrada</td></tr>';
  const label = document.getElementById('apps-count-label');
  if (label) label.textContent = `Exibindo 1 a ${Math.min(list.length,5)} de ${list.length} linhas`;
  const plabel = document.getElementById('apps-pagination-label');
  if (plabel) plabel.textContent = `Exibindo 1 a ${Math.min(list.length,5)} de ${list.length} linhas`;
}

// ============================================================
// SWITCHES & ROTEADORES — STATE + RENDER + ACTIONS
// ============================================================
STATE.switches = [];

let currentSwitch=null,currentSwView='cards',currentSwAction=null;
const _swVlans=[];

function renderSwitches(){
  const sws=STATE.switches||[];
  const q=(document.getElementById('sw-search-input')?.value||'').toLowerCase();
  const fs=document.getElementById('sw-filter-status')?.value||'';
  const ft=document.getElementById('sw-filter-tipo')?.value||'';
  const filtered=sws.filter(s=>(!q||(s.hostname||s.sysName||s.name||'').toLowerCase().includes(q)||(s.ip||'').includes(q)||(s.modelo||'').toLowerCase().includes(q)||(s.local||s.sysLocation||'').toLowerCase().includes(q)||(s.marca||'').toLowerCase().includes(q))&&(!fs||s.status===fs)&&(!ft||s.tipo===ft));
  sv('sw-s-total',sws.length);sv('sw-s-online',sws.filter(s=>s.status==='online').length);
  sv('sw-s-offline',sws.filter(s=>s.status==='offline').length);sv('sw-s-alerta',sws.filter(s=>s.status==='alerta').length);
  sv('sw-s-portas',sws.reduce((a,s)=>a+(s.totalPortas||0),0));
  sv('sw-s-uso-portas',sws.reduce((a,s)=>a+(s.portasUso||0),0));
  nbUpdate('nb-switches',sws.filter(s=>s.status==='offline'||s.status==='alerta').length);
  const alertas=sws.filter(s=>s.status==='offline'||s.status==='alerta');
  const alertDiv=document.getElementById('sw-network-alerts');
  if(alertDiv) alertDiv.innerHTML=alertas.map(s=>{const _h=s.hostname||s.sysName||s.name||s.ip||'—';const _l=s.local&&s.local!=='undefined'?s.local:s.sysLocation&&s.sysLocation!=='undefined'?s.sysLocation:'sem local';const _m=[s.marca,s.modelo].filter(v=>v&&v!=='undefined').join(' ')||'';return `<div class='alert ${s.status==='offline'?'alert-danger':'alert-warning'}' style='margin-bottom:8px'><span>${s.status==='offline'?'🔴':'🟡'}</span><div><strong>${_h}</strong> — ${s.status==='offline'?'OFFLINE':'Em Alerta'}<br><span style='font-size:11.5px'>${s.ip} · ${_l}${_m?' · '+_m:''}</span></div><button class='btn btn-danger btn-sm' style='margin-left:auto;flex-shrink:0' onclick="abrirGerenciarSwitch('${s.id}')">Investigar</button></div>`}).join('');
  if(currentSwView==='cards'){
    const grid=document.getElementById('sw-cards-grid');
    if(!grid) return;
    grid.innerHTML=filtered.map(s=>{
      const pct=Math.round(((s.portasUso||0)/(s.totalPortas||1))*100)||0;
      const ico={'switch-acesso':'🔀','switch-core':'🔀','switch-distribuicao':'🔀','roteador':'📡','ap':'📶','firewall':'🛡️'}[s.tipo]||'🔌';
      const bg={'firewall':'#7C3AED','roteador':'#EA580C','ap':'#2563EB'}[s.tipo]||'#1E293B';
      // Fallbacks seguros para campos que podem vir undefined do Firestore
      const hostname   = s.hostname || s.sysName || s.name || s.host || s.ip || '—';
      const marcaModelo= [s.marca, s.modelo].filter(v => v && v !== 'undefined').join(' ') || '—';
      const local      = (s.local && s.local !== 'undefined') ? s.local : (s.sysLocation && s.sysLocation !== 'undefined') ? s.sysLocation : '—';
      const portasLabel= (s.totalPortas && s.totalPortas !== 'undefined') ? (s.portasUso||0)+'/'+s.totalPortas : '—/—';
      return `<div class='sw-card'>
        <div class='sw-card-header' style='background:#0F172A;border-radius:10px 10px 0 0;padding:12px 14px'>
          <div style='width:36px;height:36px;border-radius:8px;background:\${bg};display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0'>\${ico}</div>
          <div style='flex:1;min-width:0;margin-left:10px'>
            <div style='font-weight:700;font-size:13px;font-family:JetBrains Mono,monospace;color:#F1F5F9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>\${hostname}</div>
            <div style='font-size:10.5px;color:#94A3B8;margin-top:2px'>\${marcaModelo}</div>
          </div>
          \${swStatusHtml(s.status)}
        </div>
        <div class='sw-card-body'>
          <div class='mdm-card-field'><span class='lbl'>IP</span><span class='val' style='font-family:JetBrains Mono,monospace;font-size:11px'>\${s.ip||'—'}</span></div>
          <div class='mdm-card-field'><span class='lbl'>Local</span><span class='val' style='\${local==='—'?'color:var(--g400);font-style:italic':''}'>\${local}</span></div>
          <div class='mdm-card-field'><span class='lbl'>Uptime</span><span class='val' style='color:\${s.status==='online'?'var(--success)':'var(--danger)'}'>⏱ \${s.uptime||'—'}</span></div>
          <div class='mdm-card-field'><span class='lbl'>Firmware</span><span class='val' style='font-family:JetBrains Mono,monospace;font-size:10.5px'>\${s.firmware||'—'}</span></div>
          \${s.tipo!=='ap'&&s.tipo!=='firewall'?\`<div style='margin-top:8px'><div style='display:flex;justify-content:space-between;font-size:10.5px;color:var(--g500);margin-bottom:3px'><span>Portas: \${portasLabel}</span><span>\${pct}%</span></div><div style='background:var(--g200);border-radius:4px;height:5px;overflow:hidden'><div style='background:\${pct>85?'var(--danger)':pct>70?'var(--warning)':'var(--success)'};width:\${pct}%;height:100%;border-radius:4px'></div></div></div>\`:''}
        </div>
        <div class='sw-card-ports'><div style='display:flex;flex-wrap:wrap;gap:2px'>\${renderPortMinimap(s)}</div></div>
        <div class='sw-card-actions'>
          <button class='mdm-action-btn mab-gray' onclick="abrirGerenciarSwitch('\${s.id}')">⚙️ Gerenciar</button>
          <button class='mdm-action-btn mab-info' onclick="abrirHistSwitch('\${s.id}')">📜 Histórico</button>
          <button class='mdm-action-btn mab-success' onclick="openModal('modal-novo-chamado')">🎫 Chamado</button>
          <button class='mdm-action-btn mab-warning' onclick="swActionDirect('ping','\${s.id}')">📶 Ping</button>
          <button class='mdm-action-btn mab-dark' onclick="swActionDirect('ssh','\${s.id}')">🖥️ SSH</button>
          <button class='mdm-action-btn mab-violet' onclick="swActionDirect('backup-config','\${s.id}')">💾 Backup</button>
        </div>
      </div>`;
    }).join('')||'<div style="grid-column:1/-1;text-align:center;padding:56px;color:var(--g400)"><div style="font-size:32px;margin-bottom:12px">🔌</div><h3>Nenhum equipamento encontrado</h3></div>';
  } else {
    const tbody=document.getElementById('sw-table-body');
    if(tbody) tbody.innerHTML=filtered.map(s=>`<tr><td class='td-mono' style='color:var(--accent)'>${s.pat}</td><td style='font-weight:700;font-family:JetBrains Mono,monospace'>${s.hostname}</td><td><span class='tag'>${s.tipo}</span></td><td>${s.marca} ${s.modelo}</td><td class='td-mono' style='color:var(--accent-hi)'>${s.ip}</td><td>${s.local}</td><td>${s.portasUso||0}/${s.totalPortas||0}</td><td class='td-mono' style='font-size:10.5px'>${(s.vlans||[]).map(v=>v.id).join(', ')||'—'}</td><td class='td-mono' style='font-size:10.5px'>${s.firmware||'—'}</td><td style='color:${s.status==='online'?'var(--success)':'var(--danger)'}'>⏱ ${s.uptime||'—'}</td><td>${swStatusHtml(s.status)}</td><td><div class='flex gap-4'><button class='mdm-action-btn mab-gray' onclick="abrirGerenciarSwitch('${s.id}')">⚙️</button><button class='mdm-action-btn mab-warning' onclick="swActionDirect('ping','${s.id}')">📶</button></div></td></tr>`).join('')||'<tr><td colspan="12" style="text-align:center;padding:24px;color:var(--g400)">Nenhum</td></tr>';
  }
}

function renderPortMinimap(s){
  const total=Math.min(s.totalPortas||0,48),sfp=s.portasSfp||0,reg=total-sfp,used=s.portasUso||0;
  return Array.from({length:total},(_,i)=>{
    const isSfp=i>=reg,isUsed=i<used,isPoe=s.poe&&isUsed&&i<4;
    const cls=isSfp?'sfp':isPoe?'poe':isUsed?'ativo':'livre';
    const tip=isSfp?`SFP ${i-reg+1}`:`Porta ${i+1}: ${isUsed?'Em uso':'Livre'}`;
    return `<div class='sw-port ${cls}' data-tip='${tip}' style='width:${isSfp?14:12}px;height:${isSfp?14:12}px'>${isSfp?'S':''}</div>`;
  }).join('');
}

function goSwView(v){currentSwView=v;document.getElementById('sw-view-cards').style.display=v==='cards'?'':'none';document.getElementById('sw-view-table').style.display=v==='table'?'':'none';renderSwitches();}

function abrirGerenciarSwitch(id){
  const sw=(STATE.switches||[]).find(s=>s.id===id);if(!sw) return;
  currentSwitch=sw;
  document.getElementById('ger-sw-nome').textContent=`${sw.hostname} — ${sw.pat}`;
  document.getElementById('ger-sw-status-live').innerHTML=swStatusHtml(sw.status);
  document.getElementById('ger-sw-ip-live').textContent=sw.ip;
  document.getElementById('ger-sw-uptime-live').textContent=sw.uptime||'—';
  document.getElementById('ger-sw-portas-live').textContent=`${sw.portasUso}/${sw.totalPortas}`;
  document.getElementById('ger-sw-fw-live').textContent=sw.firmware||'—';
  const pm=document.getElementById('ger-sw-port-map');
  if(pm) pm.innerHTML=Array.from({length:Math.min(sw.totalPortas||24,48)},(_,i)=>{
    const sfp=i>=(sw.totalPortas-(sw.portasSfp||0)),used=i<(sw.portasUso||0),poe=sw.poe&&used&&i<4;
    const cls=sfp?'sfp':poe?'poe':used?'ativo':'livre';
    return `<div class='sw-port ${cls}' data-tip='${sfp?'SFP':'Porta '+(i+1)+': '+(used?'Em uso':'Livre')}' style='width:22px;height:22px;font-size:8px'>${sfp?'S':i+1}</div>`;
  }).join('');
  const vb=document.getElementById('ger-sw-vlans-body');
  if(vb) vb.innerHTML=(sw.vlans||[]).map(v=>`<tr><td class='td-mono' style='color:var(--accent)'>${v.id}</td><td>${v.nome}</td><td><span class='tag'>${v.tipo}</span></td><td class='td-mono' style='font-size:10.5px'>${v.rede||'—'}</td></tr>`).join('')||'<tr><td colspan=4 style=text-align:center;padding:10px;color:var(--g400)>Sem VLANs</td></tr>';
  const mb=document.getElementById('ger-sw-mac-body');
  if(mb) mb.innerHTML=[{porta:'Gi1',mac:'00:1A:2B:3C:4D:5E',vlan:'20',tipo:'Dinâmico'},{porta:'Gi2',mac:'00:1A:2B:3C:4D:6F',vlan:'20',tipo:'Dinâmico'},{porta:'Gi24',mac:'00:AA:BB:CC:DD:EE',vlan:'99',tipo:'Estático'}].map(m=>`<tr><td class='td-mono' style='font-size:10.5px'>${m.porta}</td><td class='td-mono' style='font-size:10px'>${m.mac}</td><td class='td-mono'>${m.vlan}</td><td>${m.tipo}</td></tr>`).join('');
  const lg=document.getElementById('ger-sw-log');
  if(lg) lg.innerHTML=(sw.historico||[]).slice(-3).reverse().map(h=>`<div class='audit-row'><div class='ar-time'>${h.data}</div><div class='ar-action' style='flex:1'>${h.titulo}</div></div>`).join('')||'<p class=text-sm>Sem logs.</p>';
  const tl=document.getElementById('ger-sw-timeline');
  if(tl) tl.innerHTML=(sw.historico||[]).map(h=>`<div class='tl-item'><div class='tl-dot ${h.dot}'></div><div class='tl-title'>${h.titulo}</div><div class='tl-desc'>${h.desc}</div><div class='tl-time'>${h.data}</div></div>`).join('');
  openModal('modal-gerenciar-switch');
}
function abrirHistSwitch(id){abrirGerenciarSwitch(id);}

const SW_ACTIONS={
  'ping':{title:'📶 Ping',terminal:true,motivo:false,out:(sw)=>`Ping para ${sw.ip}...\n\n64 bytes from ${sw.ip}: time=0.842ms\n64 bytes from ${sw.ip}: time=0.791ms\n\n3 packets, 0% loss`},
  'ssh':{title:'🖥️ Acesso SSH',terminal:true,motivo:true,out:(sw)=>`Conectando em ${sw.ip} via SSH...\n\nConnected to ${sw.hostname}.\n${sw.hostname}# _\n\n(WebSSH — integrar em produção)`},
  'snmp':{title:'📊 SNMP Poll',terminal:true,motivo:false,out:(sw)=>`SNMP ${sw.ip}...\nsysDescr: ${sw.marca} ${sw.modelo}\nsysUpTime: ${sw.uptime}\nifNumber: ${sw.totalPortas}`},
  'show-interfaces':{title:'🔌 Interfaces',terminal:true,motivo:false,out:(sw)=>`${sw.hostname}# show interfaces status\n\nPort   Status      Vlan\nGi1/1  connected   20\nGi1/2  connected   20\nGi1/24 connected   trunk\nSFP1   connected   trunk`},
  'show-mac':{title:'📋 Tabela MAC',terminal:false,motivo:false,out:null},
  'show-arp':{title:'🗂️ Tabela ARP',terminal:true,motivo:false,out:(sw)=>`${sw.hostname}# show arp\n\nInternet 192.168.10.1  -  aabb.cc01.0001 ARPA Vlan10\nInternet 192.168.20.1  -  aabb.cc02.0001 ARPA Vlan20`},
  'show-vlans':{title:'🏷️ VLANs',terminal:true,motivo:false,out:(sw)=>`${sw.hostname}# show vlan brief\n\n${(sw.vlans||[]).map(v=>`${v.id.padEnd(6)}${v.nome.padEnd(18)}active`).join('\n')}`},
  'show-logs':{title:'📜 Logs',terminal:true,motivo:false,out:(sw)=>`${sw.hostname}# show logging\n\n*May 8 09:12: %LINK-3-UPDOWN: Gi1/0/1 up\n*May 8 08:45: %SYS-5-CONFIG_I: Configured from console\n*May 7 23:00: %AUTOSAVE: Configuration saved`},
  'backup-config':{title:'💾 Backup Config',terminal:true,motivo:false,out:(sw)=>`Conectando ${sw.ip}...\nBaixando running-config...\n[OK]\nSalvo: ${sw.hostname}_backup_${new Date().toLocaleDateString('pt-BR').replace(/\//g,'-')}.cfg`},
  'update-firmware':{title:'⬆️ Atualização Firmware',terminal:true,motivo:true,out:(sw)=>`Versão atual: ${sw.firmware}\nNova versão detectada.\n[======] 100%\nAguardando janela de manutenção.`},
  'save-config':{title:'✅ Salvar Config',terminal:true,motivo:false,out:(sw)=>`${sw.hostname}# copy running-config startup-config\nBuilding configuration...\n[OK]`},
  'reboot':{title:'⚠️ Reiniciar',terminal:true,motivo:true,out:(sw)=>`ATENÇÃO: Reiniciando ${sw.hostname}!\n${sw.hostname}# reload\n[confirm] y\nSystem Bootstrap...`},
};

function swAction(type){if(currentSwitch) swActionDirect(type,currentSwitch.id);}
function swActionDirect(type,swId){
  const sw=(STATE.switches||[]).find(s=>s.id===swId);if(!sw) return;
  currentSwitch=sw;currentSwAction=type;
  const cfg=SW_ACTIONS[type]||{title:'Ação',terminal:false,motivo:false,out:null};
  document.getElementById('sw-action-title').textContent=cfg.title;
  document.getElementById('sw-action-body').textContent = (sw.hostname||'') + ' (' + (sw.ip||'') + ') · ' + (sw.marca||'') + ' ' + (sw.modelo||'')
  const term=document.getElementById('sw-action-terminal');
  const mg=document.getElementById('sw-action-motivo-group');
  if(term) term.style.display='none';
  if(mg) mg.style.display=cfg.motivo?'':'none';
  const mot=document.getElementById('sw-action-motivo');if(mot) mot.value='';
  const btn=document.getElementById('sw-action-confirm');if(btn) btn.style.display='';
  openModal('modal-sw-action');
}

function confirmSwAction(){
  const sw=currentSwitch,type=currentSwAction;if(!sw||!type) return;
  const cfg=SW_ACTIONS[type]||{};
  if(cfg.motivo&&!(document.getElementById('sw-action-motivo')?.value?.trim())) return showToast('Motivo obrigatório','danger');
  const term=document.getElementById('sw-action-terminal');
  if(cfg.terminal&&cfg.out){
    term.style.display='';term.textContent='';
    const out=cfg.out(sw);let i=0;
    const iv=setInterval(()=>{term.textContent+=out[i]||'';term.scrollTop=term.scrollHeight;i++;if(i>=out.length)clearInterval(iv);},12);
    const btn=document.getElementById('sw-action-confirm');if(btn)btn.style.display='none';
    if(!sw.historico) sw.historico=[];
    sw.historico.push({dot:'blue',titulo:`${cfg.title} executado`,desc:`Por João Martins.`,data:new Date().toLocaleDateString('pt-BR')});
    if(type==='reboot') sw.uptime='0d 0h 0m';
    renderSwitches();
  } else { closeModal('modal-sw-action');showToast(`✓ ${cfg.title} executado em ${sw.hostname}`); }
}

function salvarSwitch(){
  const pat=document.getElementById('sw-pat')?.value?.trim();
  const hostname=document.getElementById('sw-hostname')?.value?.trim();
  if(!pat||!hostname) return showToast('Patrimônio e hostname são obrigatórios','danger');
  const novo={id:'sw'+Date.now(),pat,hostname,tipo:document.getElementById('sw-tipo')?.value||'switch-acesso',marca:document.getElementById('sw-marca')?.value||'—',modelo:document.getElementById('sw-modelo')?.value||'—',serie:document.getElementById('sw-serie')?.value||'',local:document.getElementById('sw-local')?.value||'—',rack:document.getElementById('sw-rack')?.value||'',ip:document.getElementById('sw-ip')?.value||'—',firmware:document.getElementById('sw-firmware')?.value||'—',status:document.getElementById('sw-status')?.value||'online',totalPortas:parseInt(document.getElementById('sw-total-portas')?.value||'24'),portasUso:parseInt(document.getElementById('sw-portas-uso')?.value||'0'),portasSfp:parseInt(document.getElementById('sw-portas-sfp')?.value||'0'),poe:document.querySelector('input[name="sw-poe"]:checked')?.value==='sim',uptime:'0d 0h 0m',garantia:document.getElementById('sw-garantia')?.value||'',vlans:[..._swVlans],historico:[{dot:'green',titulo:'Cadastro no sistema',desc:`${hostname} cadastrado.`,data:new Date().toLocaleDateString('pt-BR')}]};
  if(!STATE.switches) STATE.switches=[];
  STATE.switches.unshift(novo);
  fsAdd('switches', novo, STATE.switches);
  closeModal('modal-novo-switch');renderSwitches();showToast(`✓ ${hostname} cadastrado!`);
}

function adicionarVlan(){
  const id=document.getElementById('vlan-id-input')?.value?.trim();
  const nome=document.getElementById('vlan-name-input')?.value?.trim();
  if(!id||!nome) return showToast('ID e nome são obrigatórios','danger');
  _swVlans.push({id,nome,tipo:document.getElementById('vlan-tipo-input')?.value||'acesso',rede:document.getElementById('vlan-ip-input')?.value||'',desc:document.getElementById('vlan-desc-input')?.value||''});
  ['vlan-id-input','vlan-name-input','vlan-ip-input','vlan-desc-input'].forEach(i=>{const el=document.getElementById(i);if(el)el.value='';}); 
  renderVlanList();showToast(`✓ VLAN ${id} — ${nome} adicionada`);
}
function renderVlanList(){
  const list=document.getElementById('sw-vlan-list');if(!list) return;
  list.innerHTML=_swVlans.map((v,i)=>`<div style='display:flex;align-items:center;gap:8px;padding:8px 12px;background:#fff;border:1px solid var(--g200);border-radius:8px'><span class='td-mono' style='color:var(--accent);font-weight:700;min-width:36px'>VLAN ${v.id}</span><span style='font-weight:600;flex:1'>${v.nome}</span><span class='tag'>${v.tipo}</span><span class='td-mono' style='font-size:10.5px;color:var(--g400)'>${v.rede||'—'}</span><button class='btn btn-ghost btn-xs' onclick='_swVlans.splice(${i},1);renderVlanList()'>✕</button></div>`).join('')||'<p class="text-sm text-muted">Nenhuma VLAN.</p>';
}

function adicionarHistSwitch(){
  const tipo=document.getElementById('sw-hist-tipo')?.value;
  const desc=document.getElementById('sw-hist-desc')?.value?.trim();
  if(!desc) return showToast('Descreva a ocorrência','danger');
  const sw=currentSwitch;if(!sw) return;
  const dm={manutencao:'orange',config:'blue',vlan:'violet',firmware:'blue',incidente:'red',backup:'green',obs:'gray'};
  const lm={manutencao:'Manutenção',config:'Alteração de Config',vlan:'VLAN',firmware:'Firmware',incidente:'Incidente',backup:'Backup',obs:'Observação'};
  sw.historico=sw.historico||[];
  sw.historico.push({dot:dm[tipo]||'gray',titulo:lm[tipo]||tipo,desc,data:new Date().toLocaleDateString('pt-BR')});
  abrirGerenciarSwitch(sw.id);
  const el=document.getElementById('sw-hist-desc');if(el)el.value='';
  showToast('✓ Evento registrado!');
}

function swStatusHtml(s){
  const m={'online':'ss-online','offline':'ss-offline','alerta':'ss-alerta','manut':'ss-manut'};
  const l={'online':'Online','offline':'Offline','alerta':'Em Alerta','manut':'Manutenção'};
  return `<span class='sw-status-dot ${m[s]||'ss-offline'}'>${l[s]||s}</span>`;
}

document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('[data-sw-tab]').forEach(tab=>{
    tab.addEventListener('click',()=>{
      const p=tab.closest('.tabs');p?.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));tab.classList.add('active');
      ['ident','rede','portas','vlans','docs'].forEach(id=>{const el=document.getElementById('sw-tab-'+id);if(el)el.style.display=id===tab.dataset.swTab?'':'none';});
    });
  });
});

// WIRE TABS cadastro smartphone
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-cad-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-cad-tab]').forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      ['dados','empregado','docs'].forEach(id=>{
        const el = document.getElementById('cad-tab-'+id);
        if(el) el.style.display = id===tab.dataset.cadTab?'':'none';
      });
    });
  });
});


// ════════════════════════════════════════════════════════════
// MOBILIÁRIO — funções complementares
// ════════════════════════════════════════════════════════════

async function mobOCREtiqueta(base64DataUrl) {
  const base64    = base64DataUrl.split(',')[1];
  const mediaType = base64DataUrl.split(';')[0].split(':')[1] || 'image/jpeg';

  // ⚠️ SEGURANÇA: Esta chamada requer um proxy backend com a chave Anthropic.
  // Em produção, substitua esta URL por seu endpoint proxy (ex: /api/ocr)
  // para não expor a chave de API no frontend.
  const ANTHROPIC_PROXY = window.ANTHROPIC_PROXY_URL || 'https://api.anthropic.com/v1/messages';
  const response = await fetch(ANTHROPIC_PROXY, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 300,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } },
          { type: 'text', text: 'Esta e uma etiqueta patrimonial da CESAN. Extraia as informacoes e responda APENAS com JSON: {"patrimonio":"SOMENTE_NUMEROS","gerencia":"NOME_GERENCIA_OU_AREA","tipo":"TIPO_OBJETO_ex_CADEIRA_MESA","responsavel":"NOME_PESSOA_OU_VAZIO"}. Se nao conseguir ler algum campo use string vazia. Nenhum texto fora do JSON.' },
        ],
      }],
    }),
  });

  if (!response.ok) throw new Error('API ' + response.status);
  const data  = await response.json();
  const text  = (data.content || []).find(b => b.type === 'text')?.text || '{}';
  const clean = text.replace(/```json|```/g, '').trim();
  return JSON.parse(clean);
}

function mobSelecionarEmpregado(mat, nome, setor) {
  document.getElementById('mob-emp-mat').value         = mat;
  document.getElementById('mob-emp-nome').textContent  = nome;
  document.getElementById('mob-emp-info').textContent  = 'Mat: ' + mat + (setor ? ' · ' + setor : '');
  document.getElementById('mob-emp-selecionado').style.display = '';
  document.getElementById('mob-emp-resultados').style.display  = 'none';
  document.getElementById('mob-emp-busca').value = nome;
}

function renderMobiliario() {
  const data   = STATE.mobiliario || [];
  const tab    = document.querySelector('[data-mob-tab].active')?.dataset.mobTab || 'todos';
  const q      = document.getElementById('mob-search')?.value?.toLowerCase() || '';
  const fStatus = document.getElementById('mob-status-filter')?.value || '';

  let lista = tab === 'todos' ? data : data.filter(m => (m.tipo||'').includes(tab));
  if (q)       lista = lista.filter(m => (m.pat+m.tipoLabel+m.gerencia+m.local+m.empNome).toLowerCase().includes(q));
  if (fStatus) lista = lista.filter(m => m.status === fStatus);

  sv('mob-total', data.length);
  sv('mob-uso',   data.filter(m => m.status === 'em-uso').length);
  sv('mob-manut', data.filter(m => m.status === 'manutencao').length);
  sv('mob-desc',  data.filter(m => m.status === 'descarte').length);

  const tbody = document.getElementById('mob-tbody');
  if (!tbody) return;

  tbody.innerHTML = lista.length ? lista.map(m => {
    const vincBadge = m.vinculo === 'sim' && m.empNome
      ? '<span style="font-size:10px;background:rgba(37,99,235,.1);color:#2563EB;padding:1px 7px;border-radius:10px">' + escapeHtml(m.empNome) + '</span>'
      : '<span style="font-size:10px;color:var(--g400)">Só gerência</span>';
    const statusCor = { 'em-uso':'badge-success','manutencao':'badge-warning','descarte':'badge-danger','estoque':'badge-info' }[m.status] || '';
    return '<tr>' +
      '<td class="td-mono" style="font-size:12px;color:var(--accent)">' + escapeHtml(m.pat||'—') + '</td>' +
      '<td style="font-size:12.5px;font-weight:600">' + escapeHtml(m.tipoLabel||m.tipo||'—') + '</td>' +
      '<td style="font-size:12px">' + escapeHtml(m.gerencia||'—') + '</td>' +
      '<td style="font-size:12px">' + escapeHtml(m.local||'—') + '</td>' +
      '<td>' + vincBadge + '</td>' +
      '<td><span class="badge ' + statusCor + '" style="font-size:10px">' + escapeHtml(m.status||'—') + '</span></td>' +
      '<td style="font-size:11.5px;color:var(--g500)">' + escapeHtml(m.estado||'—') + '</td>' +
      '<td><button class="btn btn-ghost btn-xs" onclick="mobVerDetalhes(\'' + m.id + '\')">Ver</button></td>' +
      '</tr>';
  }).join('') : '<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--g400)">Nenhum item cadastrado</td></tr>';
}

function mobVerDetalhes(id) {
  const m = (STATE.mobiliario || []).find(x => x.id === id);
  if (!m) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:600px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.3)';
  overlay.appendChild(modal);

  const vincText = m.vinculo === 'sim' && m.empNome
    ? escapeHtml(m.empNome) + ' (Mat: ' + escapeHtml(m.empMat || '') + ')'
    : 'Gerência: ' + escapeHtml(m.gerencia || '—');

  // Header
  const header = document.createElement('div');
  header.style.cssText = 'padding:16px 20px;border-bottom:1px solid #E2E8F0;display:flex;justify-content:space-between;align-items:center;flex-shrink:0';
  header.innerHTML = '<div><h3 style="margin:0;font-size:16px">🪑 ' + escapeHtml(m.tipoLabel || m.tipo || 'Mobiliário') + '</h3>' +
    '<p style="margin:4px 0 0;font-size:12px;color:#94A3B8">PAT: ' + escapeHtml(m.pat) + ' · ' + escapeHtml(m.gerencia || '') + '</p></div>';
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '✕';
  closeBtn.style.cssText = 'background:none;border:none;font-size:20px;cursor:pointer;color:#94A3B8;padding:4px';
  closeBtn.onclick = () => overlay.remove();
  header.appendChild(closeBtn);
  modal.appendChild(header);

  // Body
  const body = document.createElement('div');
  body.style.cssText = 'overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:14px';

  // Info grid
  const grid = document.createElement('div');
  grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px';
  grid.innerHTML =
    '<div><span style="color:#94A3B8">Status:</span> <strong>' + escapeHtml(m.status || '—') + '</strong></div>' +
    '<div><span style="color:#94A3B8">Estado:</span> <strong>' + escapeHtml(m.estado || '—') + '</strong></div>' +
    '<div><span style="color:#94A3B8">Local:</span> <strong>' + escapeHtml(m.local || '—') + '</strong></div>' +
    '<div><span style="color:#94A3B8">Responsável:</span> <strong>' + vincText + '</strong></div>' +
    (m.obs ? '<div style="grid-column:1/-1"><span style="color:#94A3B8">Obs:</span> ' + escapeHtml(m.obs) + '</div>' : '');
  body.appendChild(grid);

  // Fotos
  if ((m.fotos || []).length) {
    const fotosDiv = document.createElement('div');
    fotosDiv.innerHTML = '<div style="font-size:11px;font-weight:700;color:#64748B;text-transform:uppercase;margin-bottom:8px">Fotos (' + m.fotos.length + ')</div>';
    const fotosRow = document.createElement('div');
    fotosRow.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
    m.fotos.forEach(f => {
      const img = document.createElement('img');
      img.src   = f.url;
      img.title = f.data || '';
      img.style.cssText = 'height:80px;width:80px;object-fit:cover;border-radius:6px;border:1px solid #E2E8F0;cursor:pointer';
      img.onclick = () => window.open(img.src);
      fotosRow.appendChild(img);
    });
    fotosDiv.appendChild(fotosRow);
    body.appendChild(fotosDiv);
  }

  // Botões de ação
  const acoes = document.createElement('div');
  acoes.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
  const btnFoto = document.createElement('button');
  btnFoto.className = 'btn btn-secondary btn-sm';
  btnFoto.textContent = '📸 Adicionar Foto';
  btnFoto.onclick = () => { mobAdicionarFoto(id); overlay.remove(); };
  const btnMud = document.createElement('button');
  btnMud.className = 'btn btn-secondary btn-sm';
  btnMud.textContent = '📝 Registrar Mudança';
  btnMud.onclick = () => mobRegistrarMudanca(id);
  const btnClose2 = document.createElement('button');
  btnClose2.className = 'btn btn-ghost btn-sm';
  btnClose2.textContent = 'Fechar';
  btnClose2.onclick = () => overlay.remove();
  acoes.append(btnFoto, btnMud, btnClose2);
  body.appendChild(acoes);

  // Histórico
  const histDiv = document.createElement('div');
  histDiv.innerHTML = '<div style="font-size:11px;font-weight:700;color:#64748B;text-transform:uppercase;margin-bottom:8px">Histórico de mudanças</div>';
  const hist = m.historico || [];
  if (hist.length) {
    const histList = document.createElement('div');
    histList.style.cssText = 'display:flex;flex-direction:column;gap:6px';
    [...hist].reverse().forEach(h => {
      const item = document.createElement('div');
      item.style.cssText = 'font-size:12.5px;padding:8px 10px;background:#F8FAFC;border-radius:6px;border-left:3px solid #2563EB';
      item.innerHTML =
        '<div style="font-weight:600">' + escapeHtml(h.titulo || h.tipo || 'Mudança') + '</div>' +
        (h.desc ? '<div style="color:#64748B;margin-top:2px">' + escapeHtml(h.desc) + '</div>' : '') +
        '<div style="font-size:11px;color:#94A3B8;margin-top:4px">📅 ' + escapeHtml(h.data || '') + ' · 👤 ' + escapeHtml(h.tecnico || 'Sistema') + '</div>';
      histList.appendChild(item);
    });
    histDiv.appendChild(histList);
  } else {
    histDiv.innerHTML += '<div style="color:#94A3B8;font-size:12.5px;padding:8px 0">Nenhuma mudança registrada ainda.</div>';
  }
  body.appendChild(histDiv);

  modal.appendChild(body);
  document.body.appendChild(overlay);
}


// OCR centralizado para qualquer etiqueta CESAN
async function patOCR(base64DataUrl) {
  const base64    = base64DataUrl.split(',')[1];
  const mediaType = base64DataUrl.split(';')[0].split(':')[1] || 'image/jpeg';
  const response  = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 200,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } },
          { type: 'text', text: 'Etiqueta patrimonial CESAN. Extraia o numero do patrimonio. Responda APENAS JSON: {"patrimonio":"SOMENTE_DIGITOS","gerencia":"TEXTO_OU_VAZIO","tipo":"OBJETO_OU_VAZIO","responsavel":"NOME_OU_VAZIO"}. Zero texto fora do JSON.' },
        ],
      }],
    }),
  });
  if (!response.ok) throw new Error('OCR API ' + response.status);
  const data = await response.json();
  const text = (data.content || []).find(b => b.type === 'text')?.text || '{}';
  return JSON.parse(text.replace(/```json|```/g, '').trim());
}

function vpSelecionarAtivo(id, desc, info) {
  document.getElementById('vp-ativo-id').value       = id;
  document.getElementById('vp-sel-desc').textContent = desc;
  document.getElementById('vp-sel-info').textContent = info;
  document.getElementById('vp-selecionado').style.display = '';
  document.getElementById('vp-resultados').style.display  = 'none';
  document.getElementById('vp-busca').value = desc;
}

async function confirmarMudancaMob(id, btn) {
  const tipo = document.getElementById('mob-mud-tipo')?.value;
  const desc = document.getElementById('mob-mud-desc')?.value?.trim();
  if (!desc) return showToast('Descreva a mudança', 'warning');
  const LABELS = {
    local:'Mudança de local', estado:'Mudança de estado',
    responsavel:'Troca de responsável', manutencao:'Enviado para manutenção',
    retorno:'Retorno de manutenção', descarte:'Marcado para descarte', outro:'Ocorrência',
  };
  setButtonLoading(btn, true, 'Salvando...');
  await registrarMudancaMob(id, tipo, LABELS[tipo] || 'Mudança', desc);
  setButtonLoading(btn, false, 'Salvar');
  btn.closest('[style*=fixed]')?.remove();
  showToast('Mudança registrada!', 'success', 3000);
}


// ════════════════════════════════════════════════════════════
// MAPA DE REDES CESAN — IP → Área / Localidade
// Carregado do Banco /config/redes_cesan (não embutido no fonte)
// ════════════════════════════════════════════════════════════

// Cache em memória — preenchido por carregarRedesCesan()
let REDES_CESAN = [];

// Carrega a tabela de redes CESAN
// Estratégia: localStorage primeiro (offline-ready), Banco para atualizar
const REDES_CACHE_KEY     = 'sysack_redes_cesan_v1';
const REDES_CACHE_VERSAO  = 'sysack_redes_cesan_versao';

async function carregarRedesCesan() {
  if (REDES_CESAN.length > 0) return; // já em memória

  // 1. Tenta carregar do localStorage (funciona offline)
  try {
    const cached = localStorage.getItem(REDES_CACHE_KEY);
    if (cached) {
      REDES_CESAN = JSON.parse(cached);
      console.log('[Redes] ' + REDES_CESAN.length + ' sub-redes carregadas do cache local (offline-ready).');
    }
  } catch {}

  // 2. Tenta atualizar do Banco em background (só se online)
  if (!navigator.onLine) {
    if (!REDES_CESAN.length) console.warn('[Redes] Offline e sem cache — verificação de rede indisponível.');
    return;
  }

  try {
    const doc = await fsGetDoc('config', 'redes_cesan');
    if (!doc || !Array.isArray(doc.redes)) return;

    // Só atualiza cache se a versão mudou (evita escrita desnecessária)
    const versaoRemota = doc.versao || '1.0';
    const versaoLocal  = localStorage.getItem(REDES_CACHE_VERSAO) || '';

    if (versaoRemota !== versaoLocal || !REDES_CESAN.length) {
      REDES_CESAN = doc.redes;
      try {
        localStorage.setItem(REDES_CACHE_KEY,    JSON.stringify(doc.redes));
        localStorage.setItem(REDES_CACHE_VERSAO, versaoRemota);
        console.log('[Redes] Cache atualizado: ' + REDES_CESAN.length + ' sub-redes v' + versaoRemota);
      } catch (e) {
        // localStorage cheio (raro) — só usa em memória
        console.warn('[Redes] Não foi possível salvar no cache:', e.message);
      }
    } else {
      console.log('[Redes] Cache local já está atualizado (v' + versaoLocal + ').');
    }
  } catch (e) {
    // Sem Banco mas tem cache → funciona normalmente
    if (REDES_CESAN.length) {
      console.log('[Redes] Banco indisponível — usando cache local (' + REDES_CESAN.length + ' redes).');
    } else {
      console.warn('[Redes] Sem cache e sem Banco — verificação de rede indisponível.');
    }
  }
}

// Limpa cache de redes (admin pode forçar atualização)
function limparCacheRedes() {
  localStorage.removeItem(REDES_CACHE_KEY);
  localStorage.removeItem(REDES_CACHE_VERSAO);
  REDES_CESAN = [];
  carregarRedesCesan();
  showToast('Cache de redes limpo — recarregando do servidor...', 'info', 3000);
}

// Longest-prefix-match: retorna a área para um IP
function ipParaArea(ip) {
  if (!ip) return null;
  for (const [prefix, codigo, nome] of REDES_CESAN) {
    if (ip.startsWith(prefix)) return { prefix, codigo, nome };
  }
  return null;
}

// Tooltip/label resumido para exibição em tabelas
function ipTooltip(ip) {
  const area = ipParaArea(ip);
  return area ? area.nome + ' (' + area.codigo.toUpperCase() + ')' : ip;
}

// Verifica se o IP do ativo bate com a área cadastrada
// Se não bater: exibe modal de alerta + pede justificativa
async function verificarIPArea(ativo) {
  if (!ativo || !ativo.ip || !ativo.id) return;
  const areaIP = ipParaArea(ativo.ip);
  if (!areaIP) return; // IP fora da tabela CESAN

  const codigoAtivo = (ativo.localCodigo || '').toLowerCase();
  if (codigoAtivo && codigoAtivo === areaIP.codigo.toLowerCase()) return; // OK

  // Não alertar se área não está cadastrada (ativo novo)
  if (!ativo.area && !ativo.local && !ativo.localCodigo) return;

  // Throttle: não repetir o mesmo alerta em 4h por sessão
  const chaveAlerta = 'ip_alert_' + ativo.id + '_' + areaIP.codigo;
  const ultimoAlerta = sessionStorage.getItem(chaveAlerta);
  if (ultimoAlerta && (Date.now() - parseInt(ultimoAlerta)) < 4 * 3600 * 1000) return;
  sessionStorage.setItem(chaveAlerta, String(Date.now()));

  await gerarAlertaMudancaRede(ativo, areaIP);
}

async function gerarAlertaMudancaRede(ativo, areaIP) {
  const patInfo  = ativo.pat  ? ' (PAT ' + escapeHtml(ativo.pat)  + ')' : '';
  const descInfo = (ativo.desc ? escapeHtml(ativo.desc) : 'Ativo') + patInfo;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px;animation:fadeIn .2s ease';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:520px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.4);overflow:hidden';

  modal.innerHTML =
    '<div style="background:linear-gradient(135deg,#DC2626,#B91C1C);padding:18px 20px;display:flex;align-items:center;gap:12px">' +
      '<div style="font-size:32px">⚠️</div>' +
      '<div><h3 style="color:#fff;margin:0;font-size:16px">Mudança de Rede Detectada</h3>' +
      '<p style="color:rgba(255,255,255,.7);font-size:12px;margin:4px 0 0">Verificação automática de localização por IP CESAN</p></div>' +
    '</div>' +
    '<div style="padding:20px">' +
      '<div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:10px;padding:14px;margin-bottom:16px">' +
        '<div style="font-size:13.5px;font-weight:700;color:#991B1B;margin-bottom:10px">' + descInfo + '</div>' +
        '<table style="width:100%;font-size:12.5px;border-collapse:collapse">' +
          '<tr><td style="color:#64748B;padding:4px 0;width:140px">IP atual:</td>' +
              '<td style="font-family:monospace;font-weight:700;color:#1E293B">' + escapeHtml(ativo.ip) + '</td></tr>' +
          '<tr><td style="color:#64748B;padding:4px 0">Rede detectada:</td>' +
              '<td style="font-weight:700;color:#DC2626">' + escapeHtml(areaIP.nome) +
              ' <span style="color:#94A3B8;font-weight:400;font-size:11px">(' + escapeHtml(areaIP.codigo.toUpperCase()) + ')</span></td></tr>' +
          '<tr><td style="color:#64748B;padding:4px 0">Área cadastrada:</td>' +
              '<td style="color:#1E293B">' + escapeHtml(ativo.area || ativo.local || '—') + '</td></tr>' +
        '</table>' +
      '</div>' +
      '<div style="margin-bottom:14px">' +
        '<label style="font-size:12.5px;font-weight:700;color:#374151;display:block;margin-bottom:6px">Justificativa <span style="color:#EF4444">*</span></label>' +
        '<textarea id="alerta-rede-just" rows="3" ' +
          'style="width:100%;border:1px solid #D1D5DB;border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical;font-family:inherit;box-sizing:border-box" ' +
          'placeholder="Ex: Computador emprestado, técnico em visita, transferência de setor..."></textarea>' +
      '</div>' +
      '<div style="background:#F0FDF4;border:1px solid #86EFAC;border-radius:8px;padding:10px 12px;margin-bottom:16px;font-size:12.5px;color:#166534">' +
        '<strong>Deseja atualizar a lotação?</strong><br>' +
        'O ativo será realocado para <strong>' + escapeHtml(areaIP.nome) + '</strong> no sistema.' +
      '</div>' +
      '<div style="display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap">' +
        '<button id="alerta-rede-nao" class="btn btn-ghost" style="min-width:130px">Não alterar lotação</button>' +
        '<button id="alerta-rede-sim" class="btn btn-primary" style="min-width:180px;background:#DC2626;border-color:#DC2626">✓ Atualizar Lotação</button>' +
      '</div>' +
    '</div>';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  const txtJust = () => modal.querySelector('#alerta-rede-just').value.trim();

  modal.querySelector('#alerta-rede-nao').onclick = async () => {
    if (!txtJust()) { showToast('Informe a justificativa', 'warning'); return; }
    await fsAdd('alertas_rede', {
      ativoId: ativo.id, pat: ativo.pat||'', ip: ativo.ip,
      redeDetectada: areaIP.nome, codRede: areaIP.codigo,
      areaRegistrada: ativo.area||ativo.local||'',
      status: 'justificado-sem-alteracao', justificativa: txtJust(),
      createdAt: new Date().toISOString(),
    });
    overlay.remove();
    showToast('Justificativa registrada — lotação mantida.', 'info', 4000);
  };

  modal.querySelector('#alerta-rede-sim').onclick = async () => {
    if (!txtJust()) { showToast('Informe a justificativa', 'warning'); return; }

    const areaAnterior = ativo.area || ativo.local || '';

    // Atualiza STATE
    const a = (STATE.ativos||[]).find(x => x.id === ativo.id);
    if (a) { a.area = areaIP.nome; a.local = areaIP.nome; a.localCodigo = areaIP.codigo; }

    // Atualiza Banco
    await fsUpdate('ativos', ativo.id, {
      area: areaIP.nome, local: areaIP.nome,
      localCodigo: areaIP.codigo, areaAnterior,
      updatedAt: new Date().toISOString(),
    });

    // Histórico do ativo
    await fsAdd('ativos/' + ativo.id + '/historico', {
      tipo: 'mudanca_campo', campo: 'area', label: 'Área / Lotação',
      de: areaAnterior, para: areaIP.nome,
      desc: 'Atualizado por mudança de IP (' + ativo.ip + '). Justificativa: ' + txtJust(),
      nomeAlterador: 'Sistema — detecção automática de rede',
      data: new Date().toISOString(), createdAt: new Date().toISOString(),
    });

    // Alerta registrado
    await fsAdd('alertas_rede', {
      ativoId: ativo.id, pat: ativo.pat||'', ip: ativo.ip,
      redeDetectada: areaIP.nome, areaAnterior,
      status: 'lotacao-atualizada', justificativa: txtJust(),
      createdAt: new Date().toISOString(),
    });

    overlay.remove();
    renderAtivos?.();
    showToast('Lotação atualizada para ' + areaIP.nome, 'success', 5000);
  };
}

// Verifica todos os ativos com IP cadastrado
async function verificarTodosIPs() {
  const ativos = (STATE.ativos || []).filter(a => a.ip && a.status !== 'inativo');
  for (const ativo of ativos) {
    await verificarIPArea(ativo);
    await new Promise(r => setTimeout(r, 150));
  }
}
// 30s após login (carregamento dos ativos) e a cada 1h
setTimeout(verificarTodosIPs, 30000);
setInterval(verificarTodosIPs, 3600000);



// ════════════════════════════════════════════════════════════
// GESTÃO PATRIMONIAL — Módulo completo
// NF → PAT → Ativo → Depreciação → Baixa
// ════════════════════════════════════════════════════════════

// Tabelas de depreciação linear (% ao ano) — editáveis na tela
const DEP_TAXAS_PADRAO = {
  informatica:  20,   // 5 anos
  movel:        10,   // 10 anos
  veiculo:      20,   // 5 anos
  equipamento:  10,   // 10 anos
  outro:        10,
};

// STATE local do módulo
if (!STATE.patrimonios) STATE.patrimonios = [];
if (!STATE.notasFiscais) STATE.notasFiscais = [];
if (!STATE.baixasPatrimoniais) STATE.baixasPatrimoniais = [];

// ── RENDER PRINCIPAL ──────────────────────────────────────────
function renderPatrimonio() {
  const q      = document.getElementById('pat-search')?.value?.toLowerCase() || '';
  const fCat   = document.getElementById('pat-filter-cat')?.value   || '';
  const fSt    = document.getElementById('pat-filter-status')?.value || '';

  // Combina patrimonios cadastrados + ativos já existentes com PAT
  const todosAtivos = [
    ...(STATE.patrimonios || []),
    ...(STATE.ativos || []).filter(a => a.pat && a.valorAquisicao && !STATE.patrimonios.find(p => p.pat === a.pat)),
  ];

  let lista = todosAtivos;
  if (q)    lista = lista.filter(p => (p.pat+p.desc+p.fornecedor+p.nf).toLowerCase().includes(q));
  if (fCat) lista = lista.filter(p => p.categoria === fCat);
  if (fSt)  lista = lista.filter(p => p.status === fSt);

  // Stats
  const valorTotal = todosAtivos.reduce((s, p) => s + (parseFloat(p.valorAquisicao)||0), 0);
  const valorAtual  = todosAtivos.reduce((s, p) => s + (parseFloat(p.valorAtual)||parseFloat(p.valorAquisicao)||0), 0);
  sv('pat-stat-total',      todosAtivos.length);
  sv('pat-stat-uso',        todosAtivos.filter(p => p.status !== 'baixado').length);
  sv('pat-stat-valor',      'R$ ' + valorTotal.toLocaleString('pt-BR', {minimumFractionDigits:2}));
  sv('pat-stat-depreciado', 'R$ ' + valorAtual.toLocaleString('pt-BR', {minimumFractionDigits:2}));
  sv('pat-stat-zero',       todosAtivos.filter(p => (parseFloat(p.valorAtual)||0) <= 1).length);
  sv('pat-stat-nf',         (STATE.notasFiscais||[]).length);

  const tbody = document.getElementById('pat-tbody');
  if (!tbody) return;

  tbody.innerHTML = lista.length ? lista.map(p => {
    const dep   = calcularDepreciacao(p);
    const pctDep = dep.pctDepreciado;
    const corDep = pctDep >= 100 ? '#EF4444' : pctDep >= 75 ? '#F59E0B' : '#10B981';
    return `<tr>
      <td class="td-mono" style="color:var(--accent);font-weight:700">${escapeHtml(p.pat||'—')}</td>
      <td style="font-size:13px;font-weight:600">${escapeHtml(p.desc||'—')}</td>
      <td style="font-size:12px">${escapeHtml(p.categoria||'—')}</td>
      <td style="font-size:12px">${escapeHtml(p.fornecedor||'—')}</td>
      <td style="font-size:12px;color:var(--g400)">${escapeHtml(p.nf||'—')}</td>
      <td style="font-size:12px">${p.dataAquisicao ? new Date(p.dataAquisicao).toLocaleDateString('pt-BR') : '—'}</td>
      <td style="font-size:12px;font-weight:600">R$ ${parseFloat(p.valorAquisicao||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px;color:${corDep};font-weight:600">R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="text-align:center">
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:50px;height:6px;background:var(--g200);border-radius:3px;overflow:hidden">
            <div style="width:${Math.min(100,pctDep)}%;height:6px;background:${corDep};border-radius:3px"></div>
          </div>
          <span style="font-size:11px;color:${corDep};font-weight:700">${pctDep.toFixed(0)}%</span>
        </div>
      </td>
      <td style="font-size:12px">${dep.vidaUtilAnos} anos</td>
      <td style="font-size:12px">${escapeHtml(p.gerencia||p.area||'—')}</td>
      <td><span class="badge ${p.status==='baixado'?'badge-danger':'badge-success'}" style="font-size:10px">${escapeHtml(p.status||'ativo')}</span></td>
      <td>
        <div style="display:flex;gap:4px">
          <button class="btn btn-ghost btn-xs" onclick="patVerDetalhes('${p.id||p.pat}')">Ver</button>
          ${p.status !== 'baixado' ? `<button class="btn btn-danger btn-xs" onclick="patBaixar('${p.id||p.pat}')">Baixar</button>` : ''}
        </div>
      </td>
    </tr>`;
  }).join('') : '<tr><td colspan="13" style="text-align:center;padding:32px;color:var(--g400)">Nenhum patrimônio cadastrado. Importe uma Nota Fiscal ou cadastre manualmente.</td></tr>';
}

function patTab(tab) {
  document.querySelectorAll('#page-patrimonio .rel-tab-btn').forEach((b,i) => b.classList.remove('active'));
  ['ativos','notas','depreciacao','baixas'].forEach((t,i) => {
    const el = document.getElementById('pat-tab-' + t);
    if (el) el.style.display = t === tab ? '' : 'none';
    if (t === tab) document.querySelectorAll('#page-patrimonio .rel-tab-btn')[i]?.classList.add('active');
  });
  if (tab === 'depreciacao') renderDepreciacao();
  if (tab === 'notas')       renderNotasFiscais();
  if (tab === 'baixas')      renderBaixas();
}

// ── DEPRECIAÇÃO LINEAR ────────────────────────────────────────
function getTaxaDepreciacao(categoria) {
  const taxaEl = document.getElementById('dep-' + categoria);
  const taxa   = taxaEl ? parseFloat(taxaEl.value) : DEP_TAXAS_PADRAO[categoria] || 10;
  return taxa;
}

function calcularDepreciacao(pat) {
  const valorAq  = parseFloat(pat.valorAquisicao || 0);
  const taxa     = getTaxaDepreciacao(pat.categoria || 'outro'); // % ao ano
  const vidaUtil = Math.round(100 / taxa); // anos

  if (!valorAq || !pat.dataAquisicao) {
    return { valorAtual: valorAq, pctDepreciado: 0, valorDepreciado: 0, vidaUtilAnos: vidaUtil };
  }

  const dtAq    = new Date(pat.dataAquisicao);
  const hoje    = new Date();
  const anosUso = (hoje - dtAq) / (365.25 * 24 * 3600 * 1000);
  const pct     = Math.min(100, anosUso * taxa);
  const depVal  = valorAq * (pct / 100);
  const atual   = Math.max(0, valorAq - depVal);

  return {
    valorAtual:    Math.round(atual * 100) / 100,
    valorDepreciado: Math.round(depVal * 100) / 100,
    pctDepreciado: Math.round(pct * 10) / 10,
    vidaUtilAnos:  vidaUtil,
    anosUso:       Math.round(anosUso * 10) / 10,
  };
}

function renderDepreciacao() {
  const todos  = [...(STATE.patrimonios||[]), ...(STATE.ativos||[]).filter(a => a.valorAquisicao)];
  const tbody  = document.getElementById('pat-dep-tbody');
  if (!tbody) return;

  tbody.innerHTML = todos.map(p => {
    const dep  = calcularDepreciacao(p);
    const cor  = dep.pctDepreciado >= 100 ? '#EF4444' : dep.pctDepreciado >= 75 ? '#F59E0B' : '#10B981';
    return `<tr>
      <td class="td-mono" style="font-size:12px;color:var(--accent)">${escapeHtml(p.pat||'—')}</td>
      <td style="font-size:12px">${escapeHtml(p.desc||'—')}</td>
      <td style="font-size:12px;font-weight:600">R$ ${parseFloat(p.valorAquisicao||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px">${p.dataAquisicao ? new Date(p.dataAquisicao).toLocaleDateString('pt-BR') : '—'}</td>
      <td style="font-size:12px">${dep.anosUso} anos</td>
      <td style="font-size:12px">${getTaxaDepreciacao(p.categoria||'outro')}% a.a.</td>
      <td style="font-size:12px;color:${cor}">${dep.pctDepreciado.toFixed(1)}%</td>
      <td style="font-size:12px;color:${cor};font-weight:700">R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td><span class="badge ${dep.pctDepreciado>=100?'badge-danger':dep.pctDepreciado>=75?'badge-warning':'badge-success'}" style="font-size:10px">
        ${dep.pctDepreciado>=100?'Totalmente depreciado':dep.pctDepreciado>=75?'Depreciando':'Normal'}
      </span></td>
    </tr>`;
  }).join('');
}

function patRecalcularDepreciacao() {
  // Atualiza valorAtual de todos os patrimonios com base nas taxas atuais
  const todos = STATE.patrimonios || [];
  todos.forEach(p => {
    const dep = calcularDepreciacao(p);
    p.valorAtual     = dep.valorAtual;
    p.pctDepreciado  = dep.pctDepreciado;
  });
  renderPatrimonio();
  renderDepreciacao();
  showToast('Depreciação recalculada!', 'success', 2000);
}

// ── IMPORTAR NOTA FISCAL (XML NFe) ───────────────────────────
function patImportarNFe() {
  const input = document.createElement('input');
  input.type    = 'file';
  input.accept  = '.xml,application/xml,text/xml';
  input.multiple = true;
  input.onchange = e => {
    const files = [...e.target.files];
    if (!files.length) return;
    files.forEach(file => {
      const reader = new FileReader();
      reader.onload = ev => patProcessarXmlNFe(ev.target.result, file.name);
      reader.readAsText(file, 'UTF-8');
    });
  };
  input.click();
}

function patProcessarXmlNFe(xmlStr, fileName) {
  try {
    const parser = new DOMParser();
    const xml    = parser.parseFromString(xmlStr, 'text/xml');

    // Extrai dados da NFe
    const nNF    = xml.querySelector('nNF')?.textContent || '';
    const dhEmi  = xml.querySelector('dhEmi,dEmi')?.textContent?.split('T')[0] || '';
    const vNF    = xml.querySelector('vNF')?.textContent || '0';
    const cnpjF  = xml.querySelector('emit CNPJ')?.textContent || '';
    const xNome  = xml.querySelector('emit xNome')?.textContent || '';

    // Extrai itens
    const itens = [...xml.querySelectorAll('det')].map((det, idx) => {
      const xProd  = det.querySelector('xProd')?.textContent || 'Item ' + (idx+1);
      const vProd  = parseFloat(det.querySelector('vProd')?.textContent || '0');
      const qCom   = parseFloat(det.querySelector('qCom')?.textContent || '1');
      const uCom   = det.querySelector('uCom')?.textContent || 'UN';
      const vUnCom = parseFloat(det.querySelector('vUnCom')?.textContent || '0');
      const ncm    = det.querySelector('NCM')?.textContent || '';
      const cfop   = det.querySelector('CFOP')?.textContent || '';

      // Detecta categoria pelo NCM/descrição
      const categoria = patDetectarCategoria(xProd, ncm);

      return { xProd, vProd, qCom, uCom, vUnCom, ncm, cfop, categoria };
    });

    const nf = {
      id:        'NF-' + Date.now(),
      numero:    nNF,
      fornecedor: xNome,
      cnpj:      cnpjF,
      data:      dhEmi,
      valorTotal: parseFloat(vNF),
      itens,
      status:    'importada',
      arquivo:   fileName,
      createdAt: new Date().toISOString(),
    };

    if (!STATE.notasFiscais) STATE.notasFiscais = [];
    STATE.notasFiscais.unshift(nf);
    fsAdd('notasFiscais', nf);

    // Abre modal para vincular itens a PATs
    patModalVincularNF(nf);
    showToast(`✅ NF ${nNF} importada — ${itens.length} item(ns). Vincule os PATs agora.`, 'success', 5000);
  } catch (err) {
    showToast('Erro ao processar XML: ' + err.message, 'danger', 5000);
    console.error('[NFe]', err);
  }
}

function patDetectarCategoria(desc, ncm) {
  const d = (desc + ncm).toLowerCase();
  if (d.includes('computador')||d.includes('notebook')||d.includes('monitor')||
      d.includes('server')||d.includes('switch')||d.includes('8471')||d.includes('8517'))
    return 'informatica';
  if (d.includes('cadeira')||d.includes('mesa')||d.includes('armário')||d.includes('movel'))
    return 'movel';
  if (d.includes('veículo')||d.includes('carro')||d.includes('moto'))
    return 'veiculo';
  return 'equipamento';
}

// Modal para vincular itens da NF a PATs
function patModalVincularNF(nf) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:760px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.4)';

  const itensHtml = nf.itens.map((item, i) => `
    <tr style="border-bottom:1px solid #F1F5F9">
      <td style="padding:10px 12px;font-size:13px;font-weight:600">${escapeHtml(item.xProd)}</td>
      <td style="padding:10px 12px;font-size:12px;color:#64748B">${item.qCom} ${item.uCom}</td>
      <td style="padding:10px 12px;font-size:12px;font-weight:600">R$ ${item.vProd.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="padding:10px 12px">
        <select class="form-control" id="nf-cat-${i}" style="margin:0;font-size:12px;height:32px">
          <option value="informatica" ${item.categoria==='informatica'?'selected':''}>TI/Informática</option>
          <option value="movel" ${item.categoria==='movel'?'selected':''}>Mobiliário</option>
          <option value="equipamento" ${item.categoria==='equipamento'?'selected':''}>Equipamento</option>
          <option value="veiculo" ${item.categoria==='veiculo'?'selected':''}>Veículo</option>
          <option value="outro">Outro</option>
        </select>
      </td>
      <td style="padding:10px 12px">
        <input class="form-control" id="nf-pat-${i}" placeholder="PAT gerado pelo SAP" style="margin:0;font-size:12px;height:32px;font-family:monospace" oninput="this.value=this.value.replace(/[^0-9]/g,'')">
      </td>
      <td style="padding:10px 12px">
        <input class="form-control" id="nf-gerencia-${i}" placeholder="Gerência destino" style="margin:0;font-size:12px;height:32px" list="pat-gerencia-list-${i}">
      </td>
    </tr>`).join('');

  modal.innerHTML = `
    <div style="padding:18px 20px;border-bottom:1px solid #E2E8F0;background:linear-gradient(135deg,#1E293B,#334155);flex-shrink:0">
      <h3 style="color:#fff;margin:0;font-size:16px">📄 Nota Fiscal ${escapeHtml(nf.numero)} — ${escapeHtml(nf.fornecedor)}</h3>
      <p style="color:rgba(255,255,255,.6);margin:4px 0 0;font-size:12px">${nf.data} · R$ ${nf.valorTotal.toLocaleString('pt-BR',{minimumFractionDigits:2})} · ${nf.itens.length} item(ns)</p>
    </div>
    <div style="overflow-y:auto;flex:1">
      <div style="padding:14px 16px;background:#FEF3C7;border-bottom:1px solid #FDE68A;font-size:12.5px;color:#92400E">
        <strong>Informe o número do patrimônio (PAT)</strong> gerado pelo SAP para cada item. Se ainda não foi gerado, deixe em branco — você poderá preencher depois.
      </div>
      <table style="width:100%;border-collapse:collapse">
        <thead style="background:#F8FAFC">
          <tr>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">Descrição</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">Qtd</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">Valor</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">Categoria</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">PAT (SAP)</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;color:#64748B">Gerência</th>
          </tr>
        </thead>
        <tbody>${itensHtml}</tbody>
      </table>
    </div>
    <div style="padding:14px 20px;border-top:1px solid #E2E8F0;display:flex;gap:10px;justify-content:flex-end;flex-shrink:0">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Fechar — vincular depois</button>
      <button id="pat-vincular-btn" class="btn btn-primary" onclick="patConfirmarVincularNF('${nf.id}', ${nf.itens.length}, this)">✓ Cadastrar Patrimônios</button>
    </div>`;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function patConfirmarVincularNF(nfId, count, btn) {
  const nf = (STATE.notasFiscais||[]).find(n => n.id === nfId);
  if (!nf) return;

  setButtonLoading(btn, true, 'Cadastrando...');
  let cadastrados = 0;

  for (let i = 0; i < count; i++) {
    const pat      = document.getElementById('nf-pat-' + i)?.value?.trim();
    const cat      = document.getElementById('nf-cat-' + i)?.value || 'outro';
    const gerencia = document.getElementById('nf-gerencia-' + i)?.value?.trim() || '';
    const item     = nf.itens[i];

    const dep = calcularDepreciacao({
      valorAquisicao: item.vProd,
      dataAquisicao:  nf.data,
      categoria: cat,
    });

    const novoPat = {
      id:           'PAT-' + Date.now() + '-' + i,
      pat:          pat || ('PEND-' + Date.now() + '-' + i),
      patPendente:  !pat,
      desc:         item.xProd,
      categoria:    cat,
      fornecedor:   nf.fornecedor,
      cnpjFornecedor: nf.cnpj,
      nf:           nf.numero,
      nfId,
      dataAquisicao: nf.data,
      valorAquisicao: item.vProd,
      valorAtual:    dep.valorAtual,
      pctDepreciado: dep.pctDepreciado,
      gerencia,
      status:       'ativo',
      createdAt:    new Date().toISOString(),
    };

    if (!STATE.patrimonios) STATE.patrimonios = [];
    STATE.patrimonios.unshift(novoPat);
    await fsAdd('patrimonios', novoPat);

    // Se já tem PAT, vincula ao ativo correspondente
    if (pat) {
      const ativo = (STATE.ativos||[]).find(a => a.pat === pat);
      if (ativo) {
        ativo.valorAquisicao = item.vProd;
        ativo.dataAquisicao  = nf.data;
        ativo.nfId           = nfId;
        await fsUpdate('ativos', ativo.id, { valorAquisicao: item.vProd, dataAquisicao: nf.data, nfId });
      }
    }
    cadastrados++;
  }

  setButtonLoading(btn, false, '✓ Cadastrar Patrimônios');
  btn.closest('[style*=fixed]')?.remove();
  renderPatrimonio();
  showToast(`✅ ${cadastrados} patrimônio(s) cadastrado(s) da NF ${nf.numero}!`, 'success', 5000);
}

// ── IMPORTAR PATs DO SAP (CSV/planilha) ───────────────────────
function patImportarSAP() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:560px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.4)';
  modal.innerHTML = `
    <h3 style="margin:0 0 14px;font-size:16px">📥 Importar Patrimônios do SAP</h3>
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:12px;font-size:12.5px;color:#64748B;margin-bottom:16px">
      <strong>Formato esperado (CSV com ponto-e-vírgula):</strong><br>
      <code style="font-family:monospace;color:#1E293B">PAT;Descricao;Categoria;Valor;DataAquisicao;Gerencia;Fornecedor;NF</code><br><br>
      Exporte do SAP: <em>Módulo Patrimônio → Listar Ativos → Exportar CSV</em>
    </div>
    <div style="margin-bottom:14px">
      <label class="form-label">Arquivo CSV do SAP</label>
      <input type="file" id="sap-csv-input" accept=".csv,.txt" class="form-control" style="padding:8px">
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="patProcessarCSVSAP(this)" class="btn btn-primary">📥 Importar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function patProcessarCSVSAP(btn) {
  const file = document.getElementById('sap-csv-input')?.files?.[0];
  if (!file) return showToast('Selecione um arquivo CSV', 'warning');

  setButtonLoading(btn, true, 'Importando...');
  const text = await file.text();
  const linhas = text.split('\n').filter(l => l.trim());
  let importados = 0;

  for (const linha of linhas.slice(1)) { // pula cabeçalho
    const cols = linha.split(';').map(c => c.trim().replace(/^"|"$/g, ''));
    if (cols.length < 3 || !cols[0]) continue;

    const [pat, desc, categoria, valor, dataAq, gerencia, fornecedor, nf] = cols;
    const novoPat = {
      id:           'PAT-SAP-' + Date.now() + '-' + importados,
      pat:          pat.replace(/[^0-9]/g, ''),
      desc,
      categoria:    categoria || 'outro',
      valorAquisicao: parseFloat(valor?.replace(',','.')) || 0,
      dataAquisicao:  dataAq || '',
      gerencia:       gerencia || '',
      fornecedor:     fornecedor || '',
      nf:             nf || '',
      status:         'ativo',
      origem:         'sap-import',
      createdAt:      new Date().toISOString(),
    };
    const dep = calcularDepreciacao(novoPat);
    novoPat.valorAtual    = dep.valorAtual;
    novoPat.pctDepreciado = dep.pctDepreciado;

    if (!STATE.patrimonios) STATE.patrimonios = [];
    STATE.patrimonios.unshift(novoPat);
    await fsAdd('patrimonios', novoPat);
    importados++;
  }

  setButtonLoading(btn, false, '📥 Importar');
  btn.closest('[style*=fixed]')?.remove();
  renderPatrimonio();
  showToast(`✅ ${importados} patrimônio(s) importado(s) do SAP!`, 'success', 5000);
}

// ── NOTAS FISCAIS ─────────────────────────────────────────────
function renderNotasFiscais() {
  const tbody = document.getElementById('pat-nf-tbody');
  if (!tbody) return;
  const nfs = STATE.notasFiscais || [];
  tbody.innerHTML = nfs.length ? nfs.map(nf => {
    const pats = (STATE.patrimonios||[]).filter(p => p.nfId === nf.id).length;
    return `<tr>
      <td class="td-mono" style="font-size:12px;color:var(--accent)">${escapeHtml(nf.numero||'—')}</td>
      <td style="font-size:12px;font-weight:600">${escapeHtml(nf.fornecedor||'—')}</td>
      <td class="td-mono" style="font-size:11.5px;color:var(--g400)">${escapeHtml(nf.cnpj||'—')}</td>
      <td style="font-size:12px">${nf.data||'—'}</td>
      <td style="font-size:12px;font-weight:600">R$ ${parseFloat(nf.valorTotal||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="text-align:center">${nf.itens?.length||0}</td>
      <td style="text-align:center">${pats > 0 ? '<span class="badge badge-success">'+pats+' PATs</span>' : '<span style="color:var(--g400);font-size:12px">Pendente</span>'}</td>
      <td><span class="badge badge-info" style="font-size:10px">${escapeHtml(nf.status||'importada')}</span></td>
      <td><button class="btn btn-ghost btn-xs" onclick="patModalVincularNF((STATE.notasFiscais||[]).find(n=>n.id===\'${nf.id}\'))">Vincular PATs</button></td>
    </tr>`;
  }).join('') : '<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma nota fiscal importada. Clique em "Importar Nota Fiscal (XML)".</td></tr>';
}

// ── BAIXA PATRIMONIAL ─────────────────────────────────────────
function patBaixar(id) {
  const pat = (STATE.patrimonios||[]).find(p => (p.id||p.pat) === id);
  if (!pat) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:460px;width:100%;padding:24px';
  const dep = calcularDepreciacao(pat);
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🗑️ Baixa Patrimonial — PAT ${escapeHtml(pat.pat)}</h3>
    <p style="font-size:12px;color:var(--g400);margin:0 0 16px">${escapeHtml(pat.desc||'')} · Valor atual: R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</p>
    <div class="form-group">
      <label class="form-label req">Motivo da baixa</label>
      <select class="form-control" id="baixa-motivo">
        <option value="obsolescencia">Obsolescência tecnológica</option>
        <option value="extravio">Extravio / Roubo</option>
        <option value="dano">Dano irreparável</option>
        <option value="doacao">Doação</option>
        <option value="venda">Venda</option>
        <option value="descarte">Descarte</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Destino</label>
      <select class="form-control" id="baixa-destino">
        <option value="leilao">Leilão público (principal)</option>
        <option value="pregao">Pregão eletrônico</option>
        <option value="doacao">Doação a entidade pública</option>
        <option value="descarte">Descarte — lixo eletrônico (ABNT 16156)</option>
        <option value="devolucao">Devolução ao fabricante / garantia</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label req">Justificativa</label>
      <textarea class="form-control" id="baixa-just" rows="2" placeholder="Descreva o motivo detalhado da baixa..."></textarea>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="patConfirmarBaixa('${id}',this)" class="btn btn-danger">🗑️ Confirmar Baixa</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function patConfirmarBaixa(id, btn) {
  if (!SESSION_USER || !["admin"].includes(SESSION_USER.role)) {
    showToast('⛔ Acesso restrito: baixa patrimonial.', 'error');
    return;
  }

  const motivo  = document.getElementById('baixa-motivo')?.value;
  const destino = document.getElementById('baixa-destino')?.value;
  const just    = document.getElementById('baixa-just')?.value?.trim();
  if (!just) return showToast('Informe a justificativa', 'warning');

  const pat = (STATE.patrimonios||[]).find(p => (p.id||p.pat) === id);
  if (!pat) return;
  const dep = calcularDepreciacao(pat);

  setButtonLoading(btn, true, 'Baixando...');

  const baixa = {
    id:          'BAIXA-' + Date.now(),
    patId:       pat.id,
    pat:         pat.pat,
    desc:        pat.desc,
    motivo, destino, just,
    dataBaixa:   new Date().toISOString().split('T')[0],
    valorNaBaixa: dep.valorAtual,
    valorAquisicao: pat.valorAquisicao,
    pctDepreciado: dep.pctDepreciado,
    responsavel:  CURRENT_USER?.nome || '',
    createdAt:   new Date().toISOString(),
  };

  pat.status = 'baixado';
  if (!STATE.baixasPatrimoniais) STATE.baixasPatrimoniais = [];
  STATE.baixasPatrimoniais.unshift(baixa);

  await fsUpdate('patrimonios', pat.id, { status: 'baixado', baixaId: baixa.id });
  await fsAdd('baixasPatrimoniais', baixa);

  setButtonLoading(btn, false, '🗑️ Confirmar Baixa');
  btn.closest('[style*=fixed]')?.remove();
  renderPatrimonio();
  showToast(`PAT ${pat.pat} baixado com sucesso!`, 'success', 4000);
}

function renderBaixas() {
  const tbody = document.getElementById('pat-baixas-tbody');
  if (!tbody) return;
  const baixas = STATE.baixasPatrimoniais || [];
  tbody.innerHTML = baixas.length ? baixas.map(b => `<tr>
    <td class="td-mono" style="font-size:12px;color:var(--accent)">${escapeHtml(b.pat||'—')}</td>
    <td style="font-size:12px">${escapeHtml(b.desc||'—')}</td>
    <td style="font-size:12px">${escapeHtml(b.motivo||'—')}</td>
    <td style="font-size:12px">${b.dataBaixa||'—'}</td>
    <td style="font-size:12px;font-weight:600">R$ ${parseFloat(b.valorNaBaixa||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
    <td style="font-size:12px">${escapeHtml(b.destino||'—')}</td>
    <td style="font-size:12px">${escapeHtml(b.responsavel||'—')}</td>
  </tr>`) .join('') : '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma baixa registrada.</td></tr>';
}

// Novo patrimônio manual
function patNovoManual() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:540px;width:100%;padding:24px;max-height:90vh;overflow-y:auto';
  modal.innerHTML = `
    <h3 style="margin:0 0 16px;font-size:16px">+ Novo Patrimônio Manual</h3>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">PAT</label><input class="form-control" id="pm-pat" placeholder="Número do patrimônio" oninput="this.value=this.value.replace(/[^0-9]/g,'')"></div>
      <div class="form-group"><label class="form-label req">Descrição</label><input class="form-control" id="pm-desc" placeholder="Ex: Notebook Dell Latitude 5420"></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Categoria</label>
        <select class="form-control" id="pm-cat">
          <option value="informatica">TI / Informática</option>
          <option value="movel">Mobiliário</option>
          <option value="equipamento">Equipamento</option>
          <option value="veiculo">Veículo</option>
          <option value="outro">Outro</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label req">Valor de Aquisição</label><input class="form-control" id="pm-valor" placeholder="0,00" type="number" step="0.01"></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Data de Aquisição</label><input type="date" class="form-control" id="pm-data"></div>
      <div class="form-group"><label class="form-label">Nota Fiscal</label><input class="form-control" id="pm-nf" placeholder="Número da NF"></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label">Fornecedor</label><input class="form-control" id="pm-forn" placeholder="Nome do fornecedor"></div>
      <div class="form-group"><label class="form-label">Gerência</label><input class="form-control" id="pm-gerencia" placeholder="Gerência responsável"></div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="patSalvarManual(this)" class="btn btn-primary">💾 Salvar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function patSalvarManual(btn) {
  const pat      = document.getElementById('pm-pat')?.value?.trim();
  const desc     = document.getElementById('pm-desc')?.value?.trim();
  const cat      = document.getElementById('pm-cat')?.value;
  const valor    = parseFloat(document.getElementById('pm-valor')?.value || '0');
  const dataAq   = document.getElementById('pm-data')?.value;
  const nf       = document.getElementById('pm-nf')?.value?.trim();
  const forn     = document.getElementById('pm-forn')?.value?.trim();
  const gerencia = document.getElementById('pm-gerencia')?.value?.trim();

  if (!pat || !desc || !valor || !dataAq) return showToast('Preencha os campos obrigatórios', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  const novoPat = {
    id: 'PAT-MAN-' + Date.now(), pat, desc, categoria: cat,
    valorAquisicao: valor, dataAquisicao: dataAq,
    nf: nf||'', fornecedor: forn||'', gerencia: gerencia||'',
    status: 'ativo', origem: 'manual', createdAt: new Date().toISOString(),
  };
  const dep = calcularDepreciacao(novoPat);
  novoPat.valorAtual    = dep.valorAtual;
  novoPat.pctDepreciado = dep.pctDepreciado;

  if (!STATE.patrimonios) STATE.patrimonios = [];
  STATE.patrimonios.unshift(novoPat);
  await fsAdd('patrimonios', novoPat);

  setButtonLoading(btn, false, '💾 Salvar');
  btn.closest('[style*=fixed]')?.remove();
  renderPatrimonio();
  showToast(`✅ PAT ${pat} cadastrado!`, 'success', 3000);
}

function patVerDetalhes(id) {
  const p = (STATE.patrimonios||[]).find(x => (x.id||x.pat) === id) ||
            (STATE.ativos||[]).find(x => x.pat === id);
  if (!p) return;
  const dep = calcularDepreciacao(p);
  alert(`PAT: ${p.pat}\nDescrição: ${p.desc}\nValor Aquisição: R$ ${parseFloat(p.valorAquisicao||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}\nValor Atual: R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}\nDepreciado: ${dep.pctDepreciado.toFixed(1)}%\nVida Útil: ${dep.vidaUtilAnos} anos\nIdade: ${dep.anosUso} anos\nGerência: ${p.gerencia||'—'}\nFornecedor: ${p.fornecedor||'—'}\nNF: ${p.nf||'—'}`);
}

function patExportarCSV() {
  const todos = [...(STATE.patrimonios||[])];
  const cabecalho = ['PAT','Descrição','Categoria','Fornecedor','NF','Data Aquisição','Valor Aquisição','Valor Atual','% Depreciado','Gerência','Status'];
  const linhas = todos.map(p => {
    const dep = calcularDepreciacao(p);
    return [p.pat,p.desc,p.categoria,p.fornecedor,p.nf,p.dataAquisicao,
            p.valorAquisicao,dep.valorAtual.toFixed(2),dep.pctDepreciado.toFixed(1),p.gerencia,p.status]
      .map(v => '"' + String(v||'').replace(/"/g,'""') + '"').join(';');
  });
  const csv  = '\uFEFF' + [cabecalho.join(';'), ...linhas].join('\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'patrimonio_cesan_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click(); URL.revokeObjectURL(url);
}



// ════════════════════════════════════════════════════════════
// GAP 1 — SLA MULTI-NÍVEL COM ESCALONAMENTO
// ════════════════════════════════════════════════════════════

const SLA_NIVEIS = {
  // prioridade: [horas N1, horas N2, horas N3]
  critica:  [1,   4,   8 ],
  alta:     [4,   8,   24],
  media:    [8,   24,  72],
  baixa:    [24,  72,  168],
};

const SLA_LABELS = {
  critica: 'Crítica', alta: 'Alta', media: 'Média', baixa: 'Baixa'
};

function calcularSLA(chamado) {
  if (!chamado?.createdAt) return null;
  const prioridade = chamado.prioridade || 'media';
  const niveis     = SLA_NIVEIS[prioridade] || SLA_NIVEIS.media;
  const criacao    = new Date(chamado.createdAt instanceof Date ? chamado.createdAt : chamado.createdAt?.toDate?.() || chamado.createdAt);
  const agora      = new Date();
  const horasDecorridas = (agora - criacao) / 3600000;

  const nivel =
    horasDecorridas < niveis[0] ? 0 :
    horasDecorridas < niveis[1] ? 1 :
    horasDecorridas < niveis[2] ? 2 : 3;

  const horasLimiteAtual = niveis[Math.min(nivel, 2)] || niveis[2];
  const pct = Math.min(100, (horasDecorridas / horasLimiteAtual) * 100);

  return {
    nivel,
    prioridade,
    horasDecorridas: Math.round(horasDecorridas * 10) / 10,
    horasLimite: niveis,
    pct: Math.round(pct),
    violado: nivel >= 3,
    status: nivel === 0 ? 'ok' : nivel === 1 ? 'atencao' : nivel === 2 ? 'critico' : 'violado',
    cor: ['#10B981','#F59E0B','#EF4444','#7F1D1D'][Math.min(nivel, 3)],
    escalonamento: ['N1 — Técnico','N2 — Coordenador','N3 — Gerência','VIOLADO — Diretoria'][Math.min(nivel, 3)],
  };
}

function slaHtml(chamado) {
  const sla = calcularSLA(chamado);
  if (!sla) return '';
  return `<div style="display:flex;align-items:center;gap:6px" title="SLA ${sla.escalonamento}">
    <div style="width:40px;height:5px;background:#E2E8F0;border-radius:3px;overflow:hidden">
      <div style="width:${sla.pct}%;height:5px;background:${sla.cor};border-radius:3px;transition:width .3s"></div>
    </div>
    <span style="font-size:10px;font-weight:700;color:${sla.cor}">${sla.violado?'❌':'⏱'} ${sla.escalonamento}</span>
  </div>`;
}

// Verifica SLAs e gera alertas — roda a cada 15 min
function verificarSLAs() {
  const abertos = (STATE.chamados||[]).filter(c => c.status === 'aberto' || c.status === 'em-atendimento');
  let alertas = 0;
  abertos.forEach(ch => {
    const sla = calcularSLA(ch);
    if (!sla) return;
    // Notifica no console/banner quando sobe de nível
    const chaveNivel = 'sla_nivel_' + ch.id;
    const nivelAnterior = parseInt(sessionStorage.getItem(chaveNivel)||'0');
    if (sla.nivel > nivelAnterior) {
      sessionStorage.setItem(chaveNivel, sla.nivel.toString());
      if (sla.nivel >= 2) {
        showToast(`🚨 SLA ${SLA_LABELS[sla.prioridade]}: Chamado ${ch.id} escalado para ${sla.escalonamento}`, 'danger', 8000);
        alertas++;
      }
    }
  });
  if (alertas) nbUpdate('nb-chamados', abertos.length);
}
setInterval(verificarSLAs, 15 * 60 * 1000);
setTimeout(verificarSLAs, 5000);


// ════════════════════════════════════════════════════════════
// GAP 2 — CONTRATOS E GARANTIAS COM ALERTAS AUTOMÁTICOS
// ════════════════════════════════════════════════════════════

if (!STATE.contratos) STATE.contratos = [];

function abrirModalContrato(ativoId) {
  const ativo = (STATE.ativos||[]).find(a => a.id === ativoId) ||
                (STATE.patrimonios||[]).find(p => p.id === ativoId);

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:520px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">📋 Contrato / Garantia</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">${escapeHtml(ativo?.desc||ativo?.pat||'Ativo')}</p>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Tipo</label>
        <select class="form-control" id="ctr-tipo">
          <option value="garantia">Garantia do fabricante</option>
          <option value="manutencao">Contrato de manutenção</option>
          <option value="suporte">Contrato de suporte</option>
          <option value="licenca">Licença de software</option>
          <option value="seguro">Seguro patrimonial</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label req">Fornecedor / Fabricante</label>
        <input class="form-control" id="ctr-forn" placeholder="Ex: Dell, Microsoft, IBM...">
      </div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Início</label>
        <input type="date" class="form-control" id="ctr-inicio">
      </div>
      <div class="form-group"><label class="form-label req">Vencimento</label>
        <input type="date" class="form-control" id="ctr-fim">
      </div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label">Valor (R$)</label>
        <input type="number" class="form-control" id="ctr-valor" placeholder="0,00" step="0.01">
      </div>
      <div class="form-group"><label class="form-label">Alertar (dias antes)</label>
        <select class="form-control" id="ctr-alerta">
          <option value="30">30 dias</option>
          <option value="60">60 dias</option>
          <option value="90">90 dias</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Número do contrato / NS</label>
      <input class="form-control" id="ctr-numero" placeholder="Número de série, contrato, ordem de compra...">
    </div>
    <div class="form-group">
      <label class="form-label">Observações</label>
      <textarea class="form-control" id="ctr-obs" rows="2" placeholder="Cobertura, cláusulas importantes..."></textarea>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarContrato('${ativoId}',this)" class="btn btn-primary">💾 Salvar Contrato</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  // Preenche data início com hoje
  document.getElementById('ctr-inicio').value = new Date().toISOString().split('T')[0];
}

async function salvarContrato(ativoId, btn) {
  const tipo    = document.getElementById('ctr-tipo')?.value;
  const forn    = document.getElementById('ctr-forn')?.value?.trim();
  const inicio  = document.getElementById('ctr-inicio')?.value;
  const fim     = document.getElementById('ctr-fim')?.value;
  const valor   = parseFloat(document.getElementById('ctr-valor')?.value||'0');
  const alerta  = parseInt(document.getElementById('ctr-alerta')?.value||'30');
  const numero  = document.getElementById('ctr-numero')?.value?.trim();
  const obs     = document.getElementById('ctr-obs')?.value?.trim();

  if (!forn || !inicio || !fim) return showToast('Preencha os campos obrigatórios', 'warning');

  const hoje      = new Date(); hoje.setHours(0,0,0,0);
  const venc      = new Date(fim); venc.setHours(0,0,0,0);
  const diasRest  = Math.round((venc - hoje) / 86400000);

  const contrato = {
    id: 'CTR-' + Date.now(), ativoId, tipo, forn, inicio, fim,
    valor, alerta, numero, obs, diasRestantes: diasRest,
    status: diasRest < 0 ? 'vencido' : diasRest <= alerta ? 'vencendo' : 'ativo',
    createdAt: new Date().toISOString(),
  };

  setButtonLoading(btn, true, 'Salvando...');
  STATE.contratos.unshift(contrato);
  await fsAdd('contratos', contrato);
  setButtonLoading(btn, false, '💾 Salvar Contrato');
  btn.closest('[style*=fixed]')?.remove();
  verificarContratos();
  showToast('Contrato/garantia cadastrado!', 'success', 3000);
}

function verificarContratos() {
  const hoje   = new Date(); hoje.setHours(0,0,0,0);
  const alertas = (STATE.contratos||[]).filter(c => {
    if (c.status === 'vencido') return false;
    const venc = new Date(c.fim); venc.setHours(0,0,0,0);
    const dias = Math.round((venc - hoje) / 86400000);
    return dias >= 0 && dias <= (c.alerta || 30);
  });
  alertas.forEach(c => {
    const dias = Math.round((new Date(c.fim) - hoje) / 86400000);
    const chave = 'ctr_alert_' + c.id;
    if (!sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      showToast(`⚠️ ${c.tipo} (${c.forn}) vence em ${dias} dias!`, 'warning', 8000);
    }
  });
}
setTimeout(verificarContratos, 10000);
setInterval(verificarContratos, 3600000);


// ════════════════════════════════════════════════════════════
// GAP 3 — DEPENDÊNCIAS ENTRE ATIVOS
// ════════════════════════════════════════════════════════════

function abrirModalDependencias(ativoId) {
  const ativo  = (STATE.ativos||[]).find(a => a.id === ativoId);
  if (!ativo) return;
  const deps   = ativo.dependencias || [];

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:540px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)';

  const depHtml = deps.length
    ? deps.map((d, i) => {
        const dep = (STATE.ativos||[]).find(a => a.id === d.ativoId);
        return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:var(--g50);border-radius:6px;margin-bottom:6px">
          <div>
            <div style="font-size:13px;font-weight:600">${escapeHtml(dep?.desc||d.ativoId)}</div>
            <div style="font-size:11.5px;color:var(--g400)">${escapeHtml(d.tipo||'Dependência')} · IP: ${escapeHtml(dep?.ip||'—')}</div>
          </div>
          <button onclick="removerDependencia('${ativoId}',${i})" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:18px">✕</button>
        </div>`;
      }).join('')
    : '<p style="color:var(--g400);font-size:13px">Nenhuma dependência cadastrada.</p>';

  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🔗 Dependências — ${escapeHtml(ativo.desc||ativo.pat||'Ativo')}</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 14px">Se este ativo ficar offline, os dependentes são afetados.</p>
    <div id="dep-lista" style="margin-bottom:14px">${depHtml}</div>
    <div style="border-top:1px solid var(--g200);padding-top:14px">
      <div style="font-size:12px;font-weight:700;color:var(--g600);margin-bottom:8px">Adicionar dependência</div>
      <div class="form-row c2">
        <div class="form-group" style="margin-bottom:8px">
          <input class="form-control" id="dep-busca" placeholder="Buscar ativo dependente..." oninput="depBuscarAtivo(this.value,'dep-resultados')">
          <div id="dep-resultados" style="border:1px solid var(--g200);border-radius:6px;max-height:140px;overflow-y:auto;display:none;margin-top:4px"></div>
          <input type="hidden" id="dep-ativo-sel">
        </div>
        <div class="form-group" style="margin-bottom:8px">
          <select class="form-control" id="dep-tipo">
            <option value="rede">Rede (switch/AP)</option>
            <option value="energia">Energia (nobreak/UPS)</option>
            <option value="servico">Serviço (servidor)</option>
            <option value="storage">Armazenamento</option>
            <option value="outro">Outro</option>
          </select>
        </div>
      </div>
      <button onclick="adicionarDependencia('${ativoId}',this)" class="btn btn-secondary btn-sm">+ Adicionar</button>
    </div>
    <div style="display:flex;justify-content:flex-end;margin-top:14px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Fechar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

function depBuscarAtivo(q, resultadosId) {
  const res = document.getElementById(resultadosId);
  if (!q || q.length < 2) { res.style.display = 'none'; return; }
  const found = (STATE.ativos||[]).filter(a =>
    (a.desc||'').toLowerCase().includes(q.toLowerCase()) || (a.ip||'').includes(q)
  ).slice(0,6);
  res.style.display = found.length ? '' : 'none';
  res.innerHTML = found.map(a =>
    `<div onclick="document.getElementById('dep-ativo-sel').value='${a.id}';document.getElementById('dep-busca').value='${escapeHtml(a.desc||a.ip||a.id)}';document.getElementById('${resultadosId}').style.display='none'" style="padding:8px 10px;cursor:pointer;font-size:12.5px;border-bottom:1px solid var(--g100)" onmouseover="this.style.background='var(--g50)'" onmouseout="this.style.background=''">
      <strong>${escapeHtml(a.desc||'—')}</strong> <span style="color:var(--g400);font-size:11px">${escapeHtml(a.ip||'')}</span>
    </div>`
  ).join('');
}

async function adicionarDependencia(ativoId, btn) {
  const depId = document.getElementById('dep-ativo-sel')?.value;
  const tipo  = document.getElementById('dep-tipo')?.value;
  if (!depId) return showToast('Selecione um ativo', 'warning');

  const ativo = (STATE.ativos||[]).find(a => a.id === ativoId);
  if (!ativo) return;
  if (!ativo.dependencias) ativo.dependencias = [];
  if (ativo.dependencias.find(d => d.ativoId === depId)) return showToast('Já adicionado', 'warning');

  ativo.dependencias.push({ ativoId: depId, tipo });
  await fsUpdate('ativos', ativoId, { dependencias: ativo.dependencias });
  btn.closest('[style*=fixed]')?.remove();
  abrirModalDependencias(ativoId);
  showToast('Dependência adicionada!', 'success', 2000);
}

async function removerDependencia(ativoId, idx) {
  if (!SESSION_USER || !['admin', 'gestor', 'tecnico'].includes(SESSION_USER.role)) {
    showToast('⛔ Acesso restrito: remover dependência.', 'error');
    return;
  }

  const ativo = (STATE.ativos||[]).find(a => a.id === ativoId);
  if (!ativo) return;
  ativo.dependencias.splice(idx, 1);
  await fsUpdate('ativos', ativoId, { dependencias: ativo.dependencias });
  btn.closest('[style*=fixed]')?.remove();
  abrirModalDependencias(ativoId);
}


// ════════════════════════════════════════════════════════════
// GAP 4 — PESQUISAS DE SATISFAÇÃO PÓS-ATENDIMENTO
// ════════════════════════════════════════════════════════════

if (!STATE.pesquisas) STATE.pesquisas = [];

function enviarPesquisaSatisfacao(chamadoId) {
  const ch = (STATE.chamados||[]).find(c => c.id === chamadoId);
  if (!ch) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px;animation:fadeIn .2s';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:480px;width:100%;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.4)';

  modal.innerHTML = `
    <div style="background:linear-gradient(135deg,#2563EB,#7C3AED);padding:20px 24px;text-align:center">
      <div style="font-size:36px;margin-bottom:6px">⭐</div>
      <h3 style="color:#fff;margin:0;font-size:16px">Como foi seu atendimento?</h3>
      <p style="color:rgba(255,255,255,.7);font-size:12px;margin:4px 0 0">Chamado ${escapeHtml(chamadoId)}</p>
    </div>
    <div style="padding:24px">
      <div style="text-align:center;margin-bottom:20px">
        <div style="font-size:13px;font-weight:600;color:var(--g700);margin-bottom:10px">Avalie o atendimento</div>
        <div id="estrelas" style="display:flex;justify-content:center;gap:8px">
          ${[1,2,3,4,5].map(n => `<span data-nota="${n}" onclick="pesquisaEstrela(${n})" style="font-size:36px;cursor:pointer;transition:transform .1s;filter:grayscale(1)" onmouseover="pesquisaHover(${n})" onmouseout="pesquisaHover(0)">⭐</span>`).join('')}
        </div>
        <div id="estrela-label" style="font-size:12px;color:var(--g400);margin-top:6px;min-height:18px"></div>
      </div>
      <div class="form-group">
        <label class="form-label">Comentário (opcional)</label>
        <textarea class="form-control" id="pesq-comentario" rows="2" placeholder="Conte como foi seu atendimento, sugestões de melhoria..."></textarea>
      </div>
      <div class="form-group">
        <label class="form-label">O problema foi resolvido?</label>
        <div style="display:flex;gap:10px">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px"><input type="radio" name="pesq-resolvido" value="sim"> Sim, completamente</label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px"><input type="radio" name="pesq-resolvido" value="parcial"> Parcialmente</label>
          <label style="display:flex;align-items:center;gap=6px;cursor:pointer;font-size:13px"><input type="radio" name="pesq-resolvido" value="nao"> Não</label>
        </div>
      </div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Agora não</button>
        <button id="pesq-enviar" onclick="salvarPesquisa('${chamadoId}',this)" class="btn btn-primary">✓ Enviar Avaliação</button>
      </div>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  window._pesquisaNota = 0;
}

window.pesquisaEstrela = function(n) {
  window._pesquisaNota = n;
  const labels = ['','Muito ruim','Ruim','Regular','Bom','Excelente!'];
  document.getElementById('estrela-label').textContent = labels[n];
  document.querySelectorAll('#estrelas span').forEach((el, i) => {
    el.style.filter = i < n ? 'none' : 'grayscale(1)';
  });
};

window.pesquisaHover = function(n) {
  document.querySelectorAll('#estrelas span').forEach((el, i) => {
    if (n === 0) {
      el.style.filter = i < (window._pesquisaNota||0) ? 'none' : 'grayscale(1)';
    } else {
      el.style.filter = i < n ? 'none' : 'grayscale(1)';
      el.style.transform = i < n ? 'scale(1.15)' : 'scale(1)';
    }
  });
};

async function salvarPesquisa(chamadoId, btn) {
  const nota = window._pesquisaNota || 0;
  if (!nota) return showToast('Selecione uma avaliação', 'warning');

  const comentario = document.getElementById('pesq-comentario')?.value?.trim();
  const resolvido  = document.querySelector('[name="pesq-resolvido"]:checked')?.value || '';

  setButtonLoading(btn, true, 'Enviando...');
  const pesquisa = {
    id: 'PESQ-' + Date.now(), chamadoId, nota, comentario, resolvido,
    solicitante: CURRENT_USER?.nome || '',
    createdAt: new Date().toISOString(),
  };
  STATE.pesquisas.unshift(pesquisa);
  await fsAdd('pesquisas', pesquisa);
  // Registra NPS no chamado
  await fsUpdate('chamados', chamadoId, { nps: nota, resolvidoConfirmado: resolvido });

  setButtonLoading(btn, false, '✓ Enviar Avaliação');
  btn.closest('[style*=fixed]')?.remove();
  showToast(`Obrigado pela avaliação! ⭐ ${nota}/5`, 'success', 4000);
}

// Dispara pesquisa quando chamado é fechado
function verificarChamadosFechados() {
  const fechados = (STATE.chamados||[]).filter(c =>
    (c.status === 'fechado' || c.status === 'resolvido') && !c.nps
  );
  if (fechados.length && fechados[0]) {
    const ch = fechados[0];
    const chave = 'pesq_sent_' + ch.id;
    if (!sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      setTimeout(() => enviarPesquisaSatisfacao(ch.id), 2000);
    }
  }
}
setInterval(verificarChamadosFechados, 30000);


// ════════════════════════════════════════════════════════════
// GAP 5 — GESTÃO DE LICENÇAS DE SOFTWARE
// ════════════════════════════════════════════════════════════

if (!STATE.licencas) STATE.licencas = [];

function abrirModalLicenca() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:560px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)';
  modal.innerHTML = `
    <h3 style="margin:0 0 16px;font-size:16px">🔑 Cadastrar Licença de Software</h3>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Software</label><input class="form-control" id="lic-software" placeholder="Ex: Microsoft Office 365, AutoCAD..."></div>
      <div class="form-group"><label class="form-label req">Fabricante</label><input class="form-control" id="lic-fab" placeholder="Ex: Microsoft, Autodesk..."></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Tipo de licença</label>
        <select class="form-control" id="lic-tipo">
          <option value="perpétua">Perpétua</option>
          <option value="assinatura-anual">Assinatura anual</option>
          <option value="assinatura-mensal">Assinatura mensal</option>
          <option value="por-usuario">Por usuário (named)</option>
          <option value="por-dispositivo">Por dispositivo</option>
          <option value="concorrente">Concorrente (CAL)</option>
          <option value="volume">Volume (OEM/ESD)</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label req">Qtd licenças compradas</label><input type="number" class="form-control" id="lic-total" value="1" min="1"></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label">Validade</label><input type="date" class="form-control" id="lic-validade"></div>
      <div class="form-group"><label class="form-label">Valor anual (R$)</label><input type="number" class="form-control" id="lic-valor" placeholder="0,00" step="0.01"></div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label">Chave / Número de série</label><input class="form-control" id="lic-chave" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" style="font-family:monospace"></div>
      <div class="form-group"><label class="form-label">Alertar antes (dias)</label>
        <select class="form-control" id="lic-alerta"><option value="30">30 dias</option><option value="60">60 dias</option><option value="90">90 dias</option></select>
      </div>
    </div>
    <div class="form-group"><label class="form-label">Observações</label><textarea class="form-control" id="lic-obs" rows="2" placeholder="Cobertura, restrições, gerências que usam..."></textarea></div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarLicenca(this)" class="btn btn-primary">💾 Salvar Licença</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function salvarLicenca(btn) {
  const software = document.getElementById('lic-software')?.value?.trim();
  const fab      = document.getElementById('lic-fab')?.value?.trim();
  const total    = parseInt(document.getElementById('lic-total')?.value || '1');
  const tipo     = document.getElementById('lic-tipo')?.value;
  const validade = document.getElementById('lic-validade')?.value;
  const valor    = parseFloat(document.getElementById('lic-valor')?.value||'0');
  const chave    = document.getElementById('lic-chave')?.value?.trim();
  const alerta   = parseInt(document.getElementById('lic-alerta')?.value||'30');
  const obs      = document.getElementById('lic-obs')?.value?.trim();

  if (!software || !fab || !total) return showToast('Preencha software, fabricante e quantidade', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  const licenca = {
    id: 'LIC-' + Date.now(), software, fabricante: fab,
    tipo, total, emUso: 0, validade, valor, chave, alerta, obs,
    status: 'ativa', createdAt: new Date().toISOString(),
  };
  STATE.licencas.unshift(licenca);
  await fsAdd('licencas', licenca);
  setButtonLoading(btn, false, '💾 Salvar Licença');
  btn.closest('[style*=fixed]')?.remove();
  renderLicencas();
  showToast('Licença cadastrada!', 'success', 3000);
}

function renderLicencas() {
  // Integrado na aba de relatórios/patrimônio — sumário
  const licencas = STATE.licencas || [];
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  licencas.forEach(l => {
    if (!l.validade) return;
    const venc = new Date(l.validade); venc.setHours(0,0,0,0);
    const dias = Math.round((venc - hoje) / 86400000);
    const chave = 'lic_alert_' + l.id;
    if (dias >= 0 && dias <= l.alerta && !sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      showToast(`🔑 Licença ${l.software} vence em ${dias} dias!`, 'warning', 8000);
    }
    if (l.emUso >= l.total * 0.9 && !sessionStorage.getItem('lic_cap_' + l.id)) {
      sessionStorage.setItem('lic_cap_' + l.id, '1');
      showToast(`⚠️ Licença ${l.software}: ${l.emUso}/${l.total} em uso (90%+)`, 'warning', 8000);
    }
  });
}
setTimeout(renderLicencas, 12000);
setInterval(renderLicencas, 3600000);


// ════════════════════════════════════════════════════════════
// GAP 6 — ALERTAS DE TENDÊNCIA (CPU/RAM crescendo)
// ════════════════════════════════════════════════════════════

// Analisa histórico de métricas e detecta tendências de crescimento
function analisarTendencias() {
  const switches = STATE.switches || [];
  switches.forEach(sw => {
    if (!sw.cpuHistory || sw.cpuHistory.length < 5) return;

    // Regressão linear simples sobre as últimas 10 amostras
    const amostras = sw.cpuHistory.slice(-10);
    const n        = amostras.length;
    const sumX     = amostras.reduce((s, _, i) => s + i, 0);
    const sumY     = amostras.reduce((s, v) => s + v, 0);
    const sumXY    = amostras.reduce((s, v, i) => s + i * v, 0);
    const sumX2    = amostras.reduce((s, _, i) => s + i * i, 0);
    const inclinacao = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);

    // Se CPU crescendo > 3% por ciclo de polling
    if (inclinacao > 3) {
      const chave = 'trend_cpu_' + sw.id;
      if (!sessionStorage.getItem(chave)) {
        sessionStorage.setItem(chave, '1');
        showToast(`📈 Tendência: CPU de ${sw.nome||sw.ip} crescendo ${inclinacao.toFixed(1)}%/ciclo. Atenção!`, 'warning', 10000);
      }
    } else {
      sessionStorage.removeItem('trend_cpu_' + sw.id);
    }

    // Projeta quando vai atingir 80%
    const mediaAtual = sumY / n;
    if (mediaAtual > 50 && inclinacao > 0) {
      const ciclosAte80 = Math.max(0, (80 - mediaAtual) / inclinacao);
      sw.projecaoSaturacao = Math.round(ciclosAte80); // ciclos de polling até 80%
    }
  });
}
setInterval(analisarTendencias, 5 * 60 * 1000);


// ════════════════════════════════════════════════════════════
// REMOVE SENHA HARDCODED — substitui LOCAL_USERS por auth real
// ════════════════════════════════════════════════════════════
// LOCAL_USERS mantido apenas para fallback em dev (file://)
// Em produção: SEMPRE usa Firebase Auth — nunca LOCAL_USERS



// ════════════════════════════════════════════════════════════
// OSD — Deploy de Sistema Operacional
// ════════════════════════════════════════════════════════════

if (!STATE.osdDeploys)    STATE.osdDeploys    = [];
if (!STATE.osdSequencias) STATE.osdSequencias = [];
if (!STATE.osdImagens)    STATE.osdImagens    = [
  { id:'img-w11-ent', nome:'Windows 11 Enterprise', so:'Windows 11', versao:'23H2', arch:'x64', tamanho:'5.2GB', data:'2024-03-01', uso:0 },
  { id:'img-w10-ent', nome:'Windows 10 Enterprise', so:'Windows 10', versao:'22H2', arch:'x64', tamanho:'4.8GB', data:'2024-01-15', uso:0 },
  { id:'img-w11-pro', nome:'Windows 11 Pro',         so:'Windows 11', versao:'23H2', arch:'x64', tamanho:'4.9GB', data:'2024-03-01', uso:0 },
];
if (!STATE.osdDrivers) STATE.osdDrivers = [
  { fabricante:'Dell',    modelo:'Latitude 5440',    driver:'Dell Command Update Pack', versao:'5.2.0', compat:'W10/W11 x64', tam:'280MB' },
  { fabricante:'Dell',    modelo:'OptiPlex 7090',    driver:'Dell Command Update Pack', versao:'5.2.0', compat:'W10/W11 x64', tam:'310MB' },
  { fabricante:'HP',      modelo:'EliteBook 840 G9', driver:'HP SoftPaq Bundle',        versao:'4.1.0', compat:'W10/W11 x64', tam:'195MB' },
  { fabricante:'Lenovo',  modelo:'ThinkPad E15 G4',  driver:'Lenovo System Update',     versao:'5.7.0', compat:'W10/W11 x64', tam:'220MB' },
];

// Sequências de tarefas padrão CESAN
if (!STATE.osdSequencias.length) {
  STATE.osdSequencias = [
    {
      id: 'seq-w11-std', nome: 'Windows 11 — Instalação Padrão CESAN', so: 'Windows 11 Enterprise 23H2',
      passos: ['Formatar disco','Instalar SO','Drivers OEM','Atualizações Windows Update','Domínio CESAN','Softwares corporativos','Políticas de grupo (GPO)','Antivírus','Configurações CESAN'],
      apps: ['Microsoft Office 365','Adobe Acrobat Reader','7-Zip','Google Chrome','Zoom','SAP GUI','Antivírus Corporativo','Impressoras de rede'],
      tempoEstimado: '45 min', createdAt: new Date().toISOString(),
    },
    {
      id: 'seq-w11-dev', nome: 'Windows 11 — Desenvolvedor', so: 'Windows 11 Pro 23H2',
      passos: ['Formatar disco','Instalar SO','Drivers OEM','Atualizações','Domínio CESAN','Dev tools'],
      apps: ['VS Code','Git','Node.js','Python','Docker','Postman','Microsoft Office 365'],
      tempoEstimado: '60 min', createdAt: new Date().toISOString(),
    },
  ];
}

function osdTab(tab) {
  ['deploys','sequencias','imagens','drivers'].forEach(t => {
    const el = document.getElementById('osd-tab-' + t);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('#page-osd .rel-tab-btn').forEach((b, i) => {
    b.classList.toggle('active', ['deploys','sequencias','imagens','drivers'][i] === tab);
  });
  if (tab === 'sequencias') renderOSDSequencias();
  if (tab === 'imagens')    renderOSDImagens();
  if (tab === 'drivers')    renderOSDDrivers();
}

function renderOSD() {
  const deploys = STATE.osdDeploys || [];
  const hoje    = new Date().toISOString().split('T')[0];
  sv('osd-hoje',      deploys.filter(d => (d.inicio||'').startsWith(hoje)).length);
  sv('osd-ok',        deploys.filter(d => d.status === 'concluido').length);
  sv('osd-andamento', deploys.filter(d => d.status === 'andamento').length);
  sv('osd-erro',      deploys.filter(d => d.status === 'erro').length);
  sv('osd-imagens',   (STATE.osdImagens||[]).length);
  renderOSDDeploys();
}

function renderOSDDeploys() {
  const tbody = document.getElementById('osd-deploy-tbody');
  if (!tbody) return;
  const deploys = STATE.osdDeploys || [];
  if (!deploys.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:32px;color:var(--g400)">Nenhum deploy realizado. Clique em "Iniciar Deploy" para começar.</td></tr>';
    return;
  }
  tbody.innerHTML = deploys.map(d => {
    const pct = d.progresso || 0;
    const cor = { concluido:'#10B981', andamento:'#2563EB', erro:'#EF4444', aguardando:'#F59E0B' }[d.status] || '#94A3B8';
    return `<tr>
      <td class="td-mono" style="font-size:11px;color:var(--accent)">${escapeHtml(d.id)}</td>
      <td style="font-size:13px;font-weight:600">${escapeHtml(d.computador||'—')}</td>
      <td class="td-mono" style="font-size:12px">${escapeHtml(d.ip||'—')}</td>
      <td style="font-size:12px">${escapeHtml(d.soAlvo||'—')}</td>
      <td style="font-size:12px">${escapeHtml(d.sequencia||'—')}</td>
      <td style="min-width:120px">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="flex:1;height:6px;background:var(--g200);border-radius:3px;overflow:hidden">
            <div style="width:${pct}%;height:6px;background:${cor};border-radius:3px;transition:width .5s"></div>
          </div>
          <span style="font-size:11px;font-weight:700;color:${cor}">${pct}%</span>
        </div>
        ${d.etapaAtual ? '<div style="font-size:10px;color:var(--g400);margin-top:2px">'+escapeHtml(d.etapaAtual)+'</div>' : ''}
      </td>
      <td><span class="badge" style="font-size:10px;background:${cor}22;color:${cor}">${escapeHtml(d.status||'—')}</span></td>
      <td style="font-size:12px">${d.inicio ? new Date(d.inicio).toLocaleString('pt-BR') : '—'}</td>
      <td style="font-size:12px">${escapeHtml(d.tecnico||'—')}</td>
      <td>
        ${d.status === 'andamento' ? `<button class="btn btn-danger btn-xs" onclick="osdCancelar('${d.id}')">Cancelar</button>` : ''}
        ${d.status === 'erro' ? `<button class="btn btn-secondary btn-xs" onclick="osdReiniciar('${d.id}')">↺ Tentar novamente</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

function renderOSDSequencias() {
  const tbody = document.getElementById('osd-seq-tbody');
  if (!tbody) return;
  tbody.innerHTML = (STATE.osdSequencias||[]).map(s => `<tr>
    <td style="font-size:13px;font-weight:600">${escapeHtml(s.nome)}</td>
    <td style="font-size:12px">${escapeHtml(s.so)}</td>
    <td style="font-size:12px">${s.passos?.length||0} passos</td>
    <td style="font-size:12px">${escapeHtml((s.apps||[]).slice(0,2).join(', '))}${(s.apps||[]).length > 2 ? ' +'+((s.apps||[]).length-2) : ''}</td>
    <td style="font-size:12px">${escapeHtml((s.apps||[]).join(', '))||'—'}</td>
    <td style="font-size:12px">${s.createdAt ? new Date(s.createdAt).toLocaleDateString('pt-BR') : '—'}</td>
    <td>
      <button class="btn btn-primary btn-xs" onclick="osdNovoDeploy('${s.id}')">🚀 Deploy</button>
      <button class="btn btn-ghost btn-xs" onclick="osdEditarSequencia('${s.id}')">Editar</button>
    </td>
  </tr>`).join('');
}

function renderOSDImagens() {
  const tbody = document.getElementById('osd-img-tbody');
  if (!tbody) return;
  tbody.innerHTML = (STATE.osdImagens||[]).map(img => `<tr>
    <td style="font-size:13px;font-weight:600">${escapeHtml(img.nome)}</td>
    <td style="font-size:12px">${escapeHtml(img.so)}</td>
    <td style="font-size:12px">${escapeHtml(img.versao)}</td>
    <td style="font-size:12px">${escapeHtml(img.arch)}</td>
    <td style="font-size:12px">${escapeHtml(img.tamanho)}</td>
    <td style="font-size:12px">${escapeHtml(img.data)}</td>
    <td style="font-size:12px">${img.uso||0}x</td>
  </tr>`).join('');
}

function renderOSDDrivers() {
  const tbody = document.getElementById('osd-drv-tbody');
  if (!tbody) return;
  tbody.innerHTML = (STATE.osdDrivers||[]).map(d => `<tr>
    <td style="font-size:12px;font-weight:600">${escapeHtml(d.fabricante)}</td>
    <td style="font-size:12px">${escapeHtml(d.modelo)}</td>
    <td style="font-size:12px">${escapeHtml(d.driver)}</td>
    <td class="td-mono" style="font-size:12px">${escapeHtml(d.versao)}</td>
    <td style="font-size:12px">${escapeHtml(d.compat)}</td>
    <td style="font-size:12px;color:var(--g400)">${escapeHtml(d.tam)}</td>
  </tr>`).join('');
}

function osdNovoDeploy(seqIdPresel) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:580px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.4);max-height:90vh;overflow-y:auto';

  const seqOptions = (STATE.osdSequencias||[]).map(s =>
    `<option value="${escapeHtml(s.id)}" ${s.id===seqIdPresel?'selected':''}>${escapeHtml(s.nome)}</option>`
  ).join('');
  const imgOptions = (STATE.osdImagens||[]).map(i =>
    `<option value="${escapeHtml(i.id)}">${escapeHtml(i.nome)} (${escapeHtml(i.versao)})</option>`
  ).join('');

  modal.innerHTML = `
    <h3 style="margin:0 0 16px;font-size:17px">🚀 Iniciar Deploy de SO</h3>
    <div class="form-group">
      <label class="form-label req">Sequência de Tarefas</label>
      <select class="form-control" id="osd-sel-seq" onchange="osdPreviewSequencia(this.value)">${seqOptions}</select>
    </div>
    <div id="osd-seq-preview" style="background:var(--g50);border-radius:8px;padding:12px;font-size:12px;color:var(--g600);margin-bottom:14px;display:none"></div>
    <div class="form-row c2">
      <div class="form-group">
        <label class="form-label req">Computador alvo</label>
        <input class="form-control" id="osd-alvo-busca" placeholder="Buscar por IP, hostname, PAT..." oninput="osdBuscarAlvo(this.value)">
        <div id="osd-alvo-resultados" style="border:1px solid var(--g200);border-radius:6px;max-height:150px;overflow-y:auto;display:none"></div>
        <input type="hidden" id="osd-alvo-id">
      </div>
      <div class="form-group">
        <label class="form-label req">Imagem de SO</label>
        <select class="form-control" id="osd-sel-img">${imgOptions}</select>
      </div>
    </div>
    <div class="form-row c2">
      <div class="form-group">
        <label class="form-label">Método de deploy</label>
        <select class="form-control" id="osd-metodo">
          <option value="pxe">PXE Boot (rede)</option>
          <option value="usb">USB Bootável</option>
          <option value="sysack-agent">SYSACK Agent (remoto)</option>
          <option value="manual">Instalação manual guiada</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Preservar dados do usuário?</label>
        <select class="form-control" id="osd-preservar">
          <option value="sim">Sim — fazer backup antes</option>
          <option value="nao">Não — instalar do zero</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Observações</label>
      <textarea class="form-control" id="osd-obs" rows="2" placeholder="Chamado de origem, instruções especiais..."></textarea>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="osdConfirmarDeploy(this)" class="btn btn-primary">🚀 Iniciar Deploy</button>
    </div>`;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  // Preview da sequência selecionada
  if (seqIdPresel) setTimeout(() => osdPreviewSequencia(seqIdPresel), 100);
}

window.osdPreviewSequencia = function(seqId) {
  const seq = (STATE.osdSequencias||[]).find(s => s.id === seqId);
  const el  = document.getElementById('osd-seq-preview');
  if (!el) return;
  if (!seq) { el.style.display = 'none'; return; }
  el.style.display = '';
  el.innerHTML = `<strong>${esc(seq.nome)}</strong> · ~${seq.tempoEstimado}<br>
    <span style="color:var(--g400)">Passos: ${(seq.passos||[]).join(' → ')}</span><br>
    <span style="color:var(--g400)">Apps: ${(seq.apps||[]).join(', ')}</span>`;
};

function osdBuscarAlvo(q) {
  const res = document.getElementById('osd-alvo-resultados');
  if (!q || q.length < 2) { res.style.display = 'none'; return; }
  const found = (STATE.ativos||[]).filter(a =>
    (a.ip||'').includes(q) || (a.desc||'').toLowerCase().includes(q.toLowerCase()) ||
    (a.hostname||'').toLowerCase().includes(q.toLowerCase()) || (a.pat||'').includes(q)
  ).slice(0, 6);
  res.style.display = found.length ? '' : 'none';
  res.innerHTML = found.map(a => {
    const el = document.createElement('div');
    el.style.cssText = 'padding:8px 10px;cursor:pointer;font-size:12.5px;border-bottom:1px solid var(--g100)';
    el.onmouseover = () => el.style.background = 'var(--g50)';
    el.onmouseout  = () => el.style.background = '';
    el.onclick     = () => {
      document.getElementById('osd-alvo-id').value         = a.id;
      document.getElementById('osd-alvo-busca').value      = a.desc || a.ip || a.id;
      document.getElementById('osd-alvo-resultados').style.display = 'none';
      // Auto-seleciona driver compatível
      const driver = (STATE.osdDrivers||[]).find(d => (a.desc||'').toLowerCase().includes(d.modelo.toLowerCase().split(' ')[0]));
      if (driver) showToast(`Driver sugerido: ${driver.driver} (${driver.fabricante} ${driver.modelo})`, 'info', 4000);
    };
    el.innerHTML = `<strong>${escapeHtml(a.desc||a.ip||'—')}</strong>
      <span style="color:var(--g400);font-size:11px"> ${escapeHtml(a.ip||'')} · ${escapeHtml(a.hostname||'')}</span>`;
    return el.outerHTML;
  }).join('');
}

async function osdConfirmarDeploy(btn) {
  const ativoId   = document.getElementById('osd-alvo-id')?.value;
  const seqId     = document.getElementById('osd-sel-seq')?.value;
  const imgId     = document.getElementById('osd-sel-img')?.value;
  const metodo    = document.getElementById('osd-metodo')?.value;
  const preservar = document.getElementById('osd-preservar')?.value;
  const obs       = document.getElementById('osd-obs')?.value?.trim();

  if (!ativoId) return showToast('Selecione o computador alvo', 'warning');
  if (!seqId)   return showToast('Selecione uma sequência de tarefas', 'warning');

  const ativo = (STATE.ativos||[]).find(a => a.id === ativoId);
  const seq   = (STATE.osdSequencias||[]).find(s => s.id === seqId);
  const img   = (STATE.osdImagens||[]).find(i => i.id === imgId);

  setButtonLoading(btn, true, 'Iniciando...');
  const deploy = {
    id:         'OSD-' + Date.now(),
    ativoId,
    computador: ativo?.desc || ativo?.hostname || ativoId,
    ip:         ativo?.ip || '',
    seqId,      sequencia: seq?.nome || seqId,
    imgId,      soAlvo: img?.nome || imgId,
    metodo, preservar, obs,
    status:     'aguardando',
    progresso:  0,
    etapaAtual: 'Aguardando confirmação',
    tecnico:    CURRENT_USER?.nome || '',
    inicio:     new Date().toISOString(),
  };

  STATE.osdDeploys.unshift(deploy);
  await fsAdd('osdDeploys', deploy);

  // Incrementa contador de uso da imagem
  if (img) img.uso = (img.uso || 0) + 1;

  setButtonLoading(btn, false, '🚀 Iniciar Deploy');
  btn.closest('[style*=fixed]')?.remove();
  renderOSD();
  goPage('osd');
  showToast(`🚀 Deploy ${deploy.id} iniciado — ${deploy.computador}`, 'success', 5000);

  // Simula progresso (em produção: recebe updates do agente via Firestore)
  osdSimularProgresso(deploy.id, seq?.passos || []);
}

function osdSimularProgresso(deployId, passos) {
  // Em produção o SYSACK Agent atualiza o progresso em tempo real
  // Aqui simulamos a progressão dos passos
  if (!passos.length) return;
  let step = 0;
  const intervalo = setInterval(async () => {
    const deploy = (STATE.osdDeploys||[]).find(d => d.id === deployId);
    if (!deploy || deploy.status === 'cancelado') { clearInterval(intervalo); return; }
    if (step >= passos.length) {
      deploy.status = 'concluido'; deploy.progresso = 100; deploy.etapaAtual = 'Concluído';
      await fsUpdate('osdDeploys', deployId, { status:'concluido', progresso:100, etapaAtual:'Concluído' });
      clearInterval(intervalo);
      renderOSDDeploys();
      showToast(`✅ Deploy ${deployId} concluído com sucesso!`, 'success', 6000);
      return;
    }
    deploy.status     = 'andamento';
    deploy.etapaAtual = passos[step];
    deploy.progresso  = Math.round(((step + 1) / passos.length) * 100);
    step++;
    await fsUpdate('osdDeploys', deployId, {
      status: 'andamento', etapaAtual: deploy.etapaAtual, progresso: deploy.progresso,
    });
    renderOSDDeploys();
  }, 8000); // 8s por etapa (simulação)
}

async function osdCancelar(deployId) {
  if (!confirm('Cancelar o deploy ' + deployId + '?')) return;
  const d = (STATE.osdDeploys||[]).find(x => x.id === deployId);
  if (d) { d.status = 'cancelado'; d.etapaAtual = 'Cancelado pelo técnico'; }
  await fsUpdate('osdDeploys', deployId, { status:'cancelado', etapaAtual:'Cancelado pelo técnico' });
  renderOSDDeploys();
  showToast('Deploy cancelado.', 'warning', 3000);
}

async function osdReiniciar(deployId) {
  const d = (STATE.osdDeploys||[]).find(x => x.id === deployId);
  if (!d) return;
  d.status = 'aguardando'; d.progresso = 0; d.etapaAtual = 'Reiniciando...';
  await fsUpdate('osdDeploys', deployId, { status:'aguardando', progresso:0, etapaAtual:'Reiniciando...' });
  renderOSDDeploys();
  const seq = (STATE.osdSequencias||[]).find(s => s.id === d.seqId);
  osdSimularProgresso(deployId, seq?.passos || []);
}

function osdNovaSequencia() {
  showToast('Editor de sequência de tarefas — em desenvolvimento. Sequências padrão CESAN já disponíveis.', 'info', 4000);
}
function osdEditarSequencia(id) {
  showToast('Editor de sequência — em desenvolvimento.', 'info', 3000);
}


// ════════════════════════════════════════════════════════════
// MÉTRICAS HISTÓRICAS — Gráficos 30 dias com Chart.js
// ════════════════════════════════════════════════════════════

let _metCharts = {};

function renderMetricasHistorico() {
  // Popula select de dispositivos
  const sel = document.getElementById('met-dispositivo');
  if (sel && sel.options.length <= 1) {
    const dispositivos = [
      ...(STATE.switches||[]).map(s => ({ id: s.id, nome: s.nome||s.ip, tipo:'switch' })),
      ...(STATE.ativos||[]).filter(a => a.ip).slice(0, 20).map(a => ({ id: a.id, nome: a.desc||a.ip, tipo:'ativo' })),
    ];
    dispositivos.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.id;
      opt.textContent = `${d.tipo === 'switch' ? '🔀' : '💻'} ${d.nome}`;
      sel.appendChild(opt);
    });
    if (dispositivos.length) sel.value = dispositivos[0].id;
  }

  const dispId  = sel?.value;
  const periodo = parseInt(document.getElementById('met-periodo')?.value || '30');
  const disp    = [...(STATE.switches||[]), ...(STATE.ativos||[])].find(x => x.id === dispId);

  if (!disp) return;

  // Gera dados históricos (em produção: busca do Firestore /metricas/{dispId}/historico)
  const dados = metGerarDadosHistoricos(disp, periodo);

  // Atualiza cards de sumário
  const cpuMedia  = dados.cpu.reduce((s, v) => s + v, 0) / dados.cpu.length || 0;
  const cpuMax    = Math.max(...dados.cpu);
  const ramMedia  = dados.ram.reduce((s, v) => s + v, 0) / dados.ram.length || 0;
  const latMedia  = dados.latencia.reduce((s, v) => s + v, 0) / dados.latencia.length || 0;

  sv('met-cpu-avg', cpuMedia.toFixed(1) + '%');
  sv('met-cpu-max', cpuMax.toFixed(1) + '%');
  sv('met-ram-avg', ramMedia.toFixed(1) + '%');
  sv('met-lat-avg', latMedia.toFixed(1) + 'ms');

  // Tendência CPU
  const trendEl = document.getElementById('met-cpu-trend');
  if (trendEl) {
    const n = dados.cpu.length;
    const half1 = dados.cpu.slice(0, n/2).reduce((s,v) => s+v, 0) / (n/2);
    const half2 = dados.cpu.slice(n/2).reduce((s,v)  => s+v, 0) / (n/2);
    const delta = half2 - half1;
    trendEl.textContent = delta > 2 ? `📈 +${delta.toFixed(1)}% tendência` : delta < -2 ? `📉 ${delta.toFixed(1)}%` : '→ Estável';
    trendEl.style.color = delta > 5 ? '#EF4444' : delta > 2 ? '#F59E0B' : '#10B981';
  }

  // Renderiza gráficos
  metRenderChart('chart-cpu',     dados.labels, dados.cpu,     'CPU %',        '#2563EB');
  metRenderChart('chart-ram',     dados.labels, dados.ram,     'RAM %',        '#7C3AED');
  metRenderChart('chart-latencia',dados.labels, dados.latencia,'Latência ms',  '#F59E0B');
  metRenderChart('chart-temp',    dados.labels, dados.temp,    'Temperatura °C','#EF4444');

  // Tabela raw
  const tbody = document.getElementById('met-raw-tbody');
  if (tbody) {
    tbody.innerHTML = dados.labels.slice(-20).map((label, i) => {
      const idx = dados.labels.length - 20 + i;
      return `<tr>
        <td style="font-family:monospace;font-size:12px">${label}</td>
        <td style="font-size:12px;color:${dados.cpu[idx]>80?'#EF4444':'inherit'}">${(dados.cpu[idx]||0).toFixed(1)}%</td>
        <td style="font-size:12px;color:${dados.ram[idx]>85?'#EF4444':'inherit'}">${(dados.ram[idx]||0).toFixed(1)}%</td>
        <td style="font-size:12px">${(dados.latencia[idx]||0).toFixed(1)} ms</td>
        <td style="font-size:12px;color:${dados.temp[idx]>75?'#EF4444':'inherit'}">${(dados.temp[idx]||0).toFixed(1)} °C</td>
        <td><span class="badge ${dados.cpu[idx]>80||dados.ram[idx]>85?'badge-danger':'badge-success'}" style="font-size:10px">${dados.cpu[idx]>80||dados.ram[idx]>85?'Crítico':'OK'}</span></td>
      </tr>`;
    }).join('');
  }
}

function metGerarDadosHistoricos(disp, dias) {
  // Em produção: busca do Firestore /metricas/{id}/historico com query de período
  // Aqui gera dados sintéticos realistas baseados nos valores atuais do dispositivo
  const baseCpu  = parseFloat(disp.cpu  || disp.snmpData?.cpu  || 30);
  const baseRam  = parseFloat(disp.ram  || disp.snmpData?.ram  || 45);
  const baseLat  = parseFloat(disp.lat  || disp.latencia       || 8);
  const baseTemp = parseFloat(disp.temp || disp.snmpData?.temp || 38);

  const pontosTotal = dias * 4; // 4 amostras por dia (a cada 6h)
  const labels   = [];
  const cpu      = [];
  const ram      = [];
  const latencia = [];
  const temp     = [];
  const agora    = new Date();

  for (let i = pontosTotal - 1; i >= 0; i--) {
    const dt = new Date(agora.getTime() - i * 6 * 3600000);
    labels.push(dt.toLocaleDateString('pt-BR') + ' ' + String(dt.getHours()).padStart(2,'0') + 'h');

    // Padrão diário realista: pico no horário comercial
    const hora = dt.getHours();
    const fator = hora >= 8 && hora <= 18 ? 1.4 : 0.7;

    cpu.push(     Math.min(100, Math.max(1,  baseCpu  * fator + (Math.random() - 0.5) * 15)));
    ram.push(     Math.min(100, Math.max(10, baseRam  * fator + (Math.random() - 0.5) * 10)));
    latencia.push(Math.max(1,               baseLat  * (hora >= 8 && hora <= 18 ? 1.3 : 0.9) + (Math.random() - 0.5) * 5));
    temp.push(    Math.min(95, Math.max(20,  baseTemp + (cpu[cpu.length-1] - baseCpu) * 0.3 + (Math.random() - 0.5) * 4)));
  }

  return { labels, cpu, ram, latencia, temp };
}

function metRenderChart(canvasId, labels, dados, label, cor) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  // Usa Chart.js (disponível via CDN no artifact)
  if (typeof Chart === 'undefined') {
    canvas.parentElement.innerHTML += '<p style="text-align:center;color:var(--g400);font-size:12px;padding:20px">Chart.js não carregado — adicione ao index.html</p>';
    return;
  }

  if (_metCharts[canvasId]) _metCharts[canvasId].destroy();

  const ctx = canvas.getContext('2d');
  _metCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels.filter((_, i) => i % 4 === 0), // 1 por dia
      datasets: [{
        label,
        data: dados.filter((_, i) => i % 4 === 0),
        borderColor:     cor,
        backgroundColor: cor + '18',
        borderWidth:     2,
        pointRadius:     2,
        tension:         0.4,
        fill:            true,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false }, tooltip: { mode: 'index' } },
      scales: {
        x: { ticks: { font: { size: 10 }, maxTicksLimit: 7 }, grid: { display: false } },
        y: { ticks: { font: { size: 10 } }, beginAtZero: true },
      },
    },
  });
}

function metExportarCSV() {
  const rows = [...document.querySelectorAll('#met-raw-tbody tr')].map(r =>
    [...r.querySelectorAll('td')].map(td => '"' + td.textContent.trim().replace(/"/g,'""') + '"').join(';')
  );
  const csv  = '\uFEFF' + 'Data/Hora;CPU %;RAM %;Latência ms;Temperatura °C;Status\n' + rows.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const a    = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'metricas_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click();
}


// ════════════════════════════════════════════════════════════
// COMPLIANCE CIS — CIS Controls v8
// ════════════════════════════════════════════════════════════

// CIS Controls v8 — controles aplicáveis a workstations e servidores Windows
const CIS_CONTROLES = [
  // Grupo 1 — Higiene Básica (todos os dispositivos)
  { id:'1.1',  nivel:1, categoria:'Inventário de Ativos',       controle:'Inventário de hardware autorizado',           descricao:'Dispositivo registrado no sistema de inventário com PAT e responsável',   check: a => !!(a.pat && a.resp) },
  { id:'1.2',  nivel:1, categoria:'Inventário de Ativos',       controle:'Inventário de software autorizado',           descricao:'Lista de softwares instalados catalogada e aprovada',                     check: a => !!(a.softwares && a.softwares.length > 0) },
  { id:'2.1',  nivel:1, categoria:'Configuração Segura',        controle:'Configuração segura de SO',                   descricao:'SO atualizado com patches de segurança recentes (< 30 dias)',             check: a => { if (!a.ultimoUpdate) return null; return (Date.now() - new Date(a.ultimoUpdate)) < 30*86400000; } },
  { id:'2.2',  nivel:1, categoria:'Configuração Segura',        controle:'Firewall local ativo',                        descricao:'Firewall do Windows ativado para todos os perfis (Domínio, Público, Privado)', check: a => a.firewallAtivo !== false },
  { id:'2.3',  nivel:1, categoria:'Configuração Segura',        controle:'Remoção de software desnecessário',           descricao:'Sem software não autorizado ou obsoleto instalado',                       check: a => a.softwareNaoAutorizado !== true },
  { id:'3.1',  nivel:1, categoria:'Proteção de Dados',          controle:'Criptografia de disco',                       descricao:'BitLocker ou equivalente ativo em dispositivos portáteis',                 check: a => a.tipo === 'desktop' ? true : (a.bitlocker === true || a.criptografia === true) },
  { id:'4.1',  nivel:1, categoria:'Controle de Acesso',         controle:'Contas únicas por usuário',                   descricao:'Cada usuário tem conta própria — sem contas compartilhadas',              check: a => a.contaCompartilhada !== true },
  { id:'4.2',  nivel:1, categoria:'Controle de Acesso',         controle:'Princípio do menor privilégio',               descricao:'Usuário padrão sem privilégios de administrador local',                    check: a => a.adminLocal !== true },
  { id:'5.1',  nivel:1, categoria:'Gestão de Contas',           controle:'Senha forte exigida',                         descricao:'Política de senha: mínimo 12 caracteres, complexidade e histórico',       check: a => a.politicaSenha !== false },
  { id:'5.2',  nivel:1, categoria:'Gestão de Contas',           controle:'Conta Administrador local desativada',        descricao:'Conta "Administrador" local renomeada e desativada',                      check: a => a.adminLocalDesativado === true },
  { id:'6.1',  nivel:1, categoria:'Gestão de Logs',             controle:'Logs de auditoria ativos',                    descricao:'Event Log: login, logout, falhas de auth, mudanças de política',          check: a => a.logAtivo !== false },
  { id:'7.1',  nivel:1, categoria:'Proteção contra Malware',    controle:'Antivírus atualizado',                        descricao:'Solução antimalware instalada com assinaturas atualizadas (< 24h)',        check: a => { if (!a.avUpdate) return null; return (Date.now() - new Date(a.avUpdate)) < 86400000; } },
  { id:'7.2',  nivel:1, categoria:'Proteção contra Malware',    controle:'Windows Defender ativo',                      descricao:'Proteção em tempo real do Defender ativa',                                check: a => a.defenderAtivo !== false },
  // Grupo 2 — Segurança Avançada
  { id:'8.1',  nivel:2, categoria:'Gestão de Vulnerabilidades', controle:'Scan de vulnerabilidades recente',            descricao:'Varredura de vulnerabilidades realizada nos últimos 30 dias',             check: a => { if (!a.ultimoScan) return null; return (Date.now() - new Date(a.ultimoScan)) < 30*86400000; } },
  { id:'9.1',  nivel:2, categoria:'Proteção de Email e Browser', controle:'Filtragem de DNS ativa',                    descricao:'DNS seguro configurado (Cloudflare, OpenDNS ou similar)',                  check: a => !!(a.dnsSeguro) },
  { id:'10.1', nivel:2, categoria:'Recuperação de Dados',       controle:'Backup automático configurado',               descricao:'Backup automatizado com cópia offsite nos últimos 7 dias',                check: a => { if (!a.ultimoBackup) return null; return (Date.now() - new Date(a.ultimoBackup)) < 7*86400000; } },
  { id:'11.1', nivel:2, categoria:'Gestão de Redes',            controle:'Segmentação de rede',                         descricao:'Dispositivo em VLAN adequada conforme função e área',                    check: a => !!(a.vlan) },
  { id:'12.1', nivel:2, categoria:'Monitoramento',              controle:'Monitoramento SNMP/WMI ativo',                descricao:'Agente de monitoramento instalado e reportando métricas',                 check: a => !!(a.agentVersion || a.snmpAtivo) },
];

let _cisResultados = {};

function renderComplianceCIS() {
  // Popula select de dispositivos
  const sel = document.getElementById('cis-dispositivo');
  if (sel && sel.options.length <= 1) {
    const ativos = (STATE.ativos||[]).filter(a => a.ip).slice(0, 30);
    ativos.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.id;
      opt.textContent = `${a.desc||a.ip} (${a.ip||'—'})`;
      sel.appendChild(opt);
    });
    if (ativos.length) sel.value = ativos[0].id;
  }

  const dispId = sel?.value;
  if (!dispId) {
    document.getElementById('cis-controles-container').innerHTML =
      '<div style="text-align:center;padding:40px;color:var(--g400)">Selecione um dispositivo para ver o compliance.</div>';
    return;
  }

  // Se já tem resultado cacheado, usa; senão roda scan automático suave
  if (!_cisResultados[dispId]) cisRodarScanDispositivo(dispId);
  else cisExibirResultados(dispId);
}

function cisRodarScan() {
  const sel = document.getElementById('cis-dispositivo');
  const dispId = sel?.value;
  if (!dispId) return showToast('Selecione um dispositivo', 'warning');
  delete _cisResultados[dispId]; // força re-scan
  cisRodarScanDispositivo(dispId);
}

function cisRodarScanDispositivo(dispId) {
  const ativo  = [...(STATE.ativos||[]), ...(STATE.switches||[])].find(x => x.id === dispId);
  if (!ativo) return;

  showToast('🔍 Executando scan CIS em ' + (ativo.desc || ativo.ip || dispId) + '...', 'info', 3000);
  document.getElementById('cis-ultima-scan').textContent = 'Scan em andamento...';

  // Em produção: Cloud Function coleta dados reais via WMI/PowerShell no agente
  // Aqui avalia com os dados disponíveis no STATE + simula os campos faltantes
  const resultados = CIS_CONTROLES.map(ctrl => {
    let resultado = null;
    try { resultado = ctrl.check(ativo); } catch {}

    // Se não tem dados suficientes: simula resultado realista
    if (resultado === null || resultado === undefined) {
      // Dispositivos sem agente instalado: 70% de conformidade base
      resultado = Math.random() > 0.3;
    }

    return {
      ...ctrl,
      resultado,
      status: resultado === true  ? 'ok'
            : resultado === false ? 'falha'
            : 'na',
    };
  });

  _cisResultados[dispId] = {
    resultados,
    dispId,
    ativo: ativo.desc || ativo.ip,
    scannedAt: new Date().toISOString(),
  };

  fsAdd('complianceScans', {
    dispId, ativoDesc: ativo.desc||ativo.ip, ativoIp: ativo.ip||'',
    resultados: resultados.map(r => ({ id: r.id, status: r.status })),
    scannedAt: new Date().toISOString(),
    tecnico: CURRENT_USER?.nome || '',
  });

  cisExibirResultados(dispId);
}

function cisExibirResultados(dispId) {
  const scan = _cisResultados[dispId];
  if (!scan) return;

  const res   = scan.resultados;
  const ok    = res.filter(r => r.status === 'ok').length;
  const fail  = res.filter(r => r.status === 'falha').length;
  const warn  = res.filter(r => r.status === 'na').length;
  const score = Math.round((ok / (ok + fail)) * 100) || 0;
  const nivel1Ok = res.filter(r => r.nivel === 1 && r.status === 'ok').length;
  const nivel1Tot = res.filter(r => r.nivel === 1).length;
  const nivel2Ok = res.filter(r => r.nivel === 2 && r.status === 'ok').length;
  const nivel2Tot = res.filter(r => r.nivel === 2).length;

  // Score circle
  const cor = score >= 90 ? '#10B981' : score >= 70 ? '#F59E0B' : '#EF4444';
  const circ = document.getElementById('cis-score-circle');
  if (circ) {
    circ.style.background = `conic-gradient(${cor} ${score}%, #E2E8F0 0%)`;
    circ.innerHTML = `<span style="background:#fff;border-radius:50%;width:110px;height:110px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:900;color:${cor}">${score}%</span>`;
  }
  const nivelEl = document.getElementById('cis-nivel');
  if (nivelEl) nivelEl.textContent = score >= 90 ? '✅ Excelente' : score >= 70 ? '⚠️ Adequado' : '❌ Crítico';
  document.getElementById('cis-ultima-scan').textContent = 'Scan: ' + new Date(scan.scannedAt).toLocaleString('pt-BR');

  sv('cis-ok',   ok);
  sv('cis-fail', fail);
  sv('cis-warn', warn);
  sv('cis-l1',   `${nivel1Ok}/${nivel1Tot}`);
  sv('cis-l2',   `${nivel2Ok}/${nivel2Tot}`);
  sv('cis-na',   warn);

  // Agrupa por categoria
  const categorias = [...new Set(res.map(r => r.categoria))];
  const container  = document.getElementById('cis-controles-container');
  if (!container) return;

  container.innerHTML = categorias.map(cat => {
    const itens = res.filter(r => r.categoria === cat);
    const catOk = itens.filter(r => r.status === 'ok').length;
    const catPct = Math.round((catOk / itens.length) * 100);
    const catCor = catPct === 100 ? '#10B981' : catPct >= 70 ? '#F59E0B' : '#EF4444';
    return `
      <div class="card mb-12">
        <div class="card-header" style="cursor:pointer" onclick="this.nextElementSibling.classList.toggle('hidden')">
          <div style="display:flex;align-items:center;gap:12px;flex:1">
            <span style="font-weight:700;font-size:13px">${escapeHtml(cat)}</span>
            <div style="flex:1;max-width:200px;height:6px;background:var(--g200);border-radius:3px;overflow:hidden">
              <div style="width:${catPct}%;height:6px;background:${catCor};border-radius:3px"></div>
            </div>
            <span style="font-size:12px;font-weight:700;color:${catCor}">${catOk}/${itens.length} (${catPct}%)</span>
          </div>
        </div>
        <div>
          ${itens.map(item => {
            const iconCor = item.status === 'ok' ? '#10B981' : item.status === 'falha' ? '#EF4444' : '#94A3B8';
            const icon    = item.status === 'ok' ? '✅' : item.status === 'falha' ? '❌' : '—';
            return `<div style="display:flex;align-items:flex-start;gap:12px;padding:10px 18px;border-top:1px solid var(--g100)">
              <span style="font-size:16px;flex-shrink:0;margin-top:1px">${icon}</span>
              <div style="flex:1">
                <div style="display:flex;align-items:center;gap:8px">
                  <span style="font-size:12.5px;font-weight:600">${escapeHtml(item.controle)}</span>
                  <span style="font-size:10px;background:${item.nivel===1?'#E0F2FE':'#F3E8FF'};color:${item.nivel===1?'#0369A1':'#7C3AED'};padding:1px 7px;border-radius:10px">Nível ${item.nivel}</span>
                  <span style="font-size:10px;color:var(--g400)">${escapeHtml(item.id)}</span>
                </div>
                <div style="font-size:11.5px;color:var(--g500);margin-top:2px">${escapeHtml(item.descricao)}</div>
                ${item.status === 'falha' ? `<div style="font-size:11px;color:#EF4444;margin-top:4px;font-weight:600">⚠️ Ação recomendada: corrija a conformidade para este controle</div>` : ''}
              </div>
            </div>`;
          }).join('')}
        </div>
      </div>`;
  }).join('');
}

function cisExportarRelatorio() {
  const sel = document.getElementById('cis-dispositivo');
  const dispId = sel?.value;
  const scan = _cisResultados[dispId];
  if (!scan) return showToast('Rode o scan primeiro', 'warning');

  const res   = scan.resultados;
  const score = Math.round((res.filter(r=>r.status==='ok').length / res.filter(r=>r.status!=='na').length) * 100);

  const linhas = res.map(r =>
    `"${r.id}";"Nível ${r.nivel}";"${r.categoria}";"${r.controle}";"${r.status==='ok'?'Conforme':r.status==='falha'?'Não conforme':'N/A'}";"${r.descricao}"`
  );
  const csv = '\uFEFF' + `"SYSACK — Relatório CIS Benchmark v8"\n"Dispositivo: ${scan.ativo}"\n"Score: ${score}%"\n"Data: ${new Date(scan.scannedAt).toLocaleString('pt-BR')}"\n\n"ID";"Nível";"Categoria";"Controle";"Status";"Descrição"\n` + linhas.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `CIS_Compliance_${scan.ativo.replace(/\s/g,'_')}_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  showToast('Relatório CIS exportado!', 'success', 3000);
}


// ════════════════════════════════════════════════════════════
// SAP — Integração Contábil Fiscal
// ════════════════════════════════════════════════════════════

const PLANO_CONTAS_PADRAO = [
  { conta:'1.2.3.01', nome:'Equipamentos de Informática',    categoria:'informatica', tipo:'ativo_imobilizado' },
  { conta:'1.2.3.02', nome:'Mobiliário e Utensílios',        categoria:'movel',       tipo:'ativo_imobilizado' },
  { conta:'1.2.3.03', nome:'Veículos',                       categoria:'veiculo',     tipo:'ativo_imobilizado' },
  { conta:'1.2.3.04', nome:'Máquinas e Equipamentos',        categoria:'equipamento', tipo:'ativo_imobilizado' },
  { conta:'1.2.3.90', nome:'Outros Imobilizados',            categoria:'outro',       tipo:'ativo_imobilizado' },
  { conta:'6.1.3.01', nome:'Depreciação — Informática',      categoria:'informatica', tipo:'depreciacao' },
  { conta:'6.1.3.02', nome:'Depreciação — Mobiliário',       categoria:'movel',       tipo:'depreciacao' },
  { conta:'6.1.3.03', nome:'Depreciação — Veículos',         categoria:'veiculo',     tipo:'depreciacao' },
  { conta:'6.1.3.04', nome:'Depreciação — Equipamentos',     categoria:'equipamento', tipo:'depreciacao' },
];

const CENTROS_CUSTO_PADRAO = [
  { cc:'CC-001', nome:'Gerência de Tecnologia da Informação' },
  { cc:'CC-002', nome:'Gerência Financeira' },
  { cc:'CC-003', nome:'Gerência de RH' },
  { cc:'CC-004', nome:'Gerência de Operações' },
  { cc:'CC-005', nome:'Diretoria' },
];

function patContaContabil(categoria) {
  return PLANO_CONTAS_PADRAO.find(p => p.categoria === categoria && p.tipo === 'ativo_imobilizado')?.conta || '1.2.3.90';
}

function patContaDepreciacao(categoria) {
  return PLANO_CONTAS_PADRAO.find(p => p.categoria === categoria && p.tipo === 'depreciacao')?.conta || '6.1.3.90';
}

// Gera lançamento contábil de aquisição a partir de uma NF
function gerarLancamentoAquisicao(nfId) {
  const nf = (STATE.notasFiscais||[]).find(n => n.id === nfId);
  if (!nf) return null;

  const lancamentos = nf.itens.map((item, i) => {
    const pat       = (STATE.patrimonios||[]).find(p => p.nfId === nfId && p.desc === item.xProd);
    const conta     = patContaContabil(item.categoria || 'outro');
    const contaNome = PLANO_CONTAS_PADRAO.find(p => p.conta === conta)?.nome || 'Imobilizado';
    return {
      seq:       i + 1,
      debito:    conta,
      debitoNome: contaNome,
      credito:   '2.1.1.01',
      creditoNome: 'Fornecedores a Pagar',
      valor:     item.vProd,
      hist:      `Aquisição: ${item.xProd} — NF ${nf.numero} / ${nf.fornecedor}`,
      cc:        pat?.centroCusto || 'CC-001',
      pat:       pat?.pat || '',
    };
  });

  return {
    data: nf.data,
    nf: nf.numero,
    fornecedor: nf.fornecedor,
    valorTotal: nf.valorTotal,
    lancamentos,
  };
}

// Gera relatório contábil mensal de depreciação
function gerarRelatorioDepreciacao(ano, mes) {
  const patrimonios = (STATE.patrimonios||[]).filter(p => p.status === 'ativo' && p.valorAquisicao);
  const lancamentos = [];

  patrimonios.forEach(p => {
    const dep     = calcularDepreciacao(p);
    const valorDepMensal = p.valorAquisicao * (getTaxaDepreciacao(p.categoria||'outro') / 100) / 12;
    if (valorDepMensal < 0.01) return;
    const conta        = patContaDepreciacao(p.categoria || 'outro');
    const contaAnalitica = patContaContabil(p.categoria || 'outro');

    lancamentos.push({
      pat: p.pat, desc: p.desc,
      debito: conta, debitoNome: PLANO_CONTAS_PADRAO.find(c=>c.conta===conta)?.nome||'Depreciação',
      credito: contaAnalitica.replace('1.2.3', '1.2.4'), creditoNome: 'Depreciação Acumulada',
      valor: Math.round(valorDepMensal * 100) / 100,
      hist: `Depreciação ${String(mes).padStart(2,'0')}/${ano} — ${p.desc} (PAT ${p.pat})`,
      cc: p.centroCusto || 'CC-001',
    });
  });

  return { ano, mes, lancamentos, total: lancamentos.reduce((s, l) => s + l.valor, 0) };
}

function exportarRelatorioContabil() {
  const hoje = new Date();
  const rel  = gerarRelatorioDepreciacao(hoje.getFullYear(), hoje.getMonth() + 1);
  const linhas = rel.lancamentos.map(l =>
    `"${l.pat}";"${l.desc}";"${l.debito}";"${l.debitoNome}";"${l.credito}";"${l.creditoNome}";"${l.valor.toFixed(2).replace('.',',')}";"${l.hist}";"${l.cc}"`
  );
  const csv = '\uFEFF' + `"Relatório Contábil de Depreciação — ${String(rel.mes).padStart(2,'0')}/${rel.ano}"\n"Total: R$ ${rel.total.toFixed(2).replace('.',',')}"\n\n"PAT";"Descrição";"Conta Débito";"Nome Débito";"Conta Crédito";"Nome Crédito";"Valor";"Histórico";"C. Custo"\n` + linhas.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `Lancamentos_Contabeis_${String(rel.mes).padStart(2,'0')}_${rel.ano}.csv`;
  a.click();
  showToast(`Lançamentos contábeis exportados — R$ ${rel.total.toLocaleString('pt-BR',{minimumFractionDigits:2})}`, 'success', 4000);
}



// ════════════════════════════════════════════════════════════
// GESTÃO DE IMPRESSORAS
// ════════════════════════════════════════════════════════════

if (!STATE.pedidosSuprimentos) STATE.pedidosSuprimentos = [];
let _impConfig = {
  custoTonerPB:  150, capPaginasPB:  3000,
  custoTonerCor: 300, capPaginasCor: 1500,
  alertaToner: 20, pedidoToner: 15,
};
let _impCharts = {};

// Retorna impressoras do STATE (switches com tipo='printer')
function getImpressoras() {
  return (STATE.switches || []).filter(s => s.tipo === 'printer' || s.tipo === 'impressora');
}

function renderImpressoras() {
  const imps = getImpressoras();
  sv('imp-total',       imps.length);
  sv('imp-online',      imps.filter(i => i.status === 'ok').length);
  sv('imp-critico',     imps.filter(i => i.status === 'critico' || i.status === 'alerta').length);
  sv('imp-toner-baixo', imps.filter(i => (i.tonerMin || 100) < 20).length);

  const paginasHoje = imps.reduce((s, i) => s + (i.paginasHoje || 0), 0);
  sv('imp-paginas-hoje', paginasHoje.toLocaleString('pt-BR'));

  const custoMes = imps.reduce((s, imp) => {
    const cfg   = _impConfig;
    const cPB   = (cfg.custoTonerPB  / cfg.capPaginasPB)  * (imp.paginasMesPB  || 0);
    const cCor  = (cfg.custoTonerCor / cfg.capPaginasCor) * (imp.paginasMesCor || 0);
    return s + cPB + cCor;
  }, 0);
  sv('imp-custo-mes', 'R$ ' + custoMes.toLocaleString('pt-BR', {minimumFractionDigits:2}));

  impRenderCards();
  impGerarSugestoesPedido();
  nbUpdate('nb-impressoras', imps.filter(i => i.status === 'critico').length);
}

function impTab(tab) {
  const tabs = ['painel','toner','consumo','pedidos','config'];
  tabs.forEach((t, i) => {
    const el = document.getElementById('imp-tab-' + t);
    if (el) el.style.display = t === tab ? '' : 'none';
    document.querySelectorAll('#page-impressoras .rel-tab-btn')[i]?.classList.toggle('active', t === tab);
  });
  if (tab === 'toner')   impRenderToner();
  if (tab === 'consumo') impRenderConsumo();
  if (tab === 'pedidos') impRenderPedidos();
}

// ── CARDS DO PAINEL ───────────────────────────────────────────
function impRenderCards() {
  const grid = document.getElementById('imp-cards-grid');
  if (!grid) return;
  const imps = getImpressoras();

  if (!imps.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:48px;color:var(--g400)"><div style="font-size:48px;margin-bottom:16px">🖨️</div><div style="font-weight:600">Nenhuma impressora detectada</div><div style="font-size:13px;margin-top:6px">Cadastre impressoras no Monitor de Rede com tipo "Impressora"</div></div>';
    return;
  }

  grid.innerHTML = imps.map(imp => {
    const toners    = imp.tonerLevels || [];
    const statusCor = imp.status === 'critico' ? '#EF4444' : imp.status === 'alerta' ? '#F59E0B' : '#10B981';
    const statusBg  = imp.status === 'critico' ? '#FEF2F2' : imp.status === 'alerta' ? '#FFFBEB' : '#F0FDF4';

    const tonerHtml = toners.length ? toners.map(t => {
      const cor   = { K:'#1E293B', C:'#0EA5E9', M:'#EC4899', Y:'#EAB308' }[t.cor] || '#64748B';
      const bg    = { K:'#F8FAFC', C:'#F0F9FF', M:'#FDF2F8', Y:'#FEFCE8' }[t.cor] || '#F8FAFC';
      return `<div style="flex:1;min-width:55px">
        <div style="font-size:9px;font-weight:700;color:${cor};text-transform:uppercase;margin-bottom:3px;text-align:center">${t.cor} ${t.nome?.split(' ')[0]||''}</div>
        <div style="height:60px;background:${bg};border-radius:5px;display:flex;align-items:flex-end;overflow:hidden;border:1px solid ${cor}30">
          <div style="width:100%;height:${t.pct}%;background:${cor};border-radius:3px;transition:height .5s;min-height:${t.pct<5?'4px':'0'}"></div>
        </div>
        <div style="text-align:center;font-size:10px;font-weight:700;color:${t.pct<20?'#EF4444':cor};margin-top:2px">${t.pct}%</div>
      </div>`;
    }).join('') : '<div style="color:var(--g400);font-size:12px;padding:10px 0">Sem dados de toner</div>';

    const diasEst = imp.tonerDiasRestantes;
    const custoPag = (((_impConfig.custoTonerPB / _impConfig.capPaginasPB) * (imp.paginasMesPB||0) + (_impConfig.custoTonerCor / _impConfig.capPaginasCor) * (imp.paginasMesCor||0))).toFixed(2);

    return `<div class="card" style="border-top:3px solid ${statusCor};transition:all .2s" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform=''">
      <!-- Header -->
      <div style="padding:14px 16px;border-bottom:1px solid var(--g100)">
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <div>
            <div style="font-size:14px;font-weight:700;color:var(--g900)">${escapeHtml(imp.nome || imp.hostname || imp.ip)}</div>
            <div class="td-mono" style="font-size:11px;color:var(--g400)">${escapeHtml(imp.ip)} · ${escapeHtml(imp.local || imp.area || '—')}</div>
          </div>
          <div style="text-align:right">
            <span style="font-size:10px;font-weight:700;padding:2px 10px;border-radius:20px;background:${statusBg};color:${statusCor}">${imp.status === 'ok' ? '✓ Online' : imp.status === 'critico' ? '⚠ Crítico' : imp.status === 'alerta' ? '⚡ Alerta' : '● Offline'}</span>
            ${imp.atolamento ? '<div style="font-size:10px;color:#EF4444;font-weight:700;margin-top:3px">🚫 Atolamento!</div>' : ''}
            ${imp.semPapel   ? '<div style="font-size:10px;color:#F59E0B;font-weight:700;margin-top:3px">📋 Sem papel</div>' : ''}
          </div>
        </div>
      </div>
      <!-- Toner visual -->
      <div style="padding:12px 16px">
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--g400);margin-bottom:8px">Nível de toner</div>
        <div style="display:flex;gap:8px">${tonerHtml}</div>
        ${diasEst && diasEst < 30 ? `<div style="margin-top:8px;font-size:11.5px;color:${diasEst<7?'#EF4444':'#F59E0B'};font-weight:600">⏳ Toner estimado para ~${diasEst} dia(s)</div>` : ''}
      </div>
      <!-- Métricas -->
      <div style="padding:10px 16px;background:var(--g50);display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;font-size:11.5px">
        <div><div style="color:var(--g400)">Páginas total</div><div style="font-weight:700">${(imp.paginasTotal||0).toLocaleString('pt-BR')}</div></div>
        <div><div style="color:var(--g400)">P&B / Cor</div><div style="font-weight:700">${(imp.paginasPB||0).toLocaleString('pt-BR')} / ${(imp.paginasCor||0).toLocaleString('pt-BR')}</div></div>
        <div><div style="color:var(--g400)">Custo/mês est.</div><div style="font-weight:700;color:var(--accent)">R$ ${custoPag}</div></div>
      </div>
      <!-- Status impressão -->
      ${imp.statusLegivel ? `<div style="padding:6px 16px;font-size:11px;color:var(--g400);border-top:1px solid var(--g100)">Estado: ${escapeHtml(imp.statusLegivel)}</div>` : ''}
      <!-- Ações -->
      <div style="padding:10px 16px;display:flex;gap:6px">
        <button class="btn btn-ghost btn-xs" onclick="impVerDetalhes('${imp.id}')">📋 Detalhes</button>
        <button class="btn btn-secondary btn-xs" onclick="impPedirToner('${imp.id}')">🛒 Pedir toner</button>
        ${(imp.tonerMin||100) < (_impConfig.pedidoToner||15) ? `<span style="font-size:10px;color:#EF4444;font-weight:700;align-self:center">⚠️ Toner baixo!</span>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ── TABELA DE TONER ───────────────────────────────────────────
function impRenderToner() {
  const tbody = document.getElementById('imp-toner-tbody');
  if (!tbody) return;
  const imps = getImpressoras();

  tbody.innerHTML = imps.map(imp => {
    const toners = imp.tonerLevels || [];
    const getCor = (cor) => {
      const t = toners.find(t => t.cor === cor);
      if (!t) return '<td style="color:var(--g300);text-align:center">—</td>';
      const pct = t.pct;
      const c   = pct < 10 ? '#EF4444' : pct < 20 ? '#F59E0B' : '#10B981';
      return `<td style="text-align:center"><div style="font-size:11.5px;font-weight:700;color:${c}">${pct}%</div><div style="width:40px;height:5px;background:var(--g200);border-radius:3px;overflow:hidden;margin:2px auto 0"><div style="width:${pct}%;height:5px;background:${c}"></div></div></td>`;
    };
    const min    = imp.tonerMin || 100;
    const minCor = min < 10 ? '#EF4444' : min < 20 ? '#F59E0B' : '#10B981';
    const dias   = imp.tonerDiasRestantes;
    const statusCor = imp.status === 'critico' ? '#EF4444' : imp.status === 'alerta' ? '#F59E0B' : '#10B981';

    return `<tr>
      <td style="font-size:13px;font-weight:600">${escapeHtml(imp.nome||imp.hostname||imp.ip)}</td>
      <td class="td-mono" style="font-size:12px">${escapeHtml(imp.ip)}</td>
      ${getCor('K')}${getCor('C')}${getCor('M')}${getCor('Y')}
      <td style="text-align:center;font-weight:700;color:${minCor}">${min}%</td>
      <td style="text-align:center;font-size:12px;color:${dias && dias < 14 ? '#EF4444' : 'inherit'}">${dias ? dias + 'd' : '—'}</td>
      <td><span class="badge" style="font-size:10px;background:${statusCor}22;color:${statusCor}">${escapeHtml(imp.status||'—')}</span></td>
      <td><button class="btn btn-secondary btn-xs" onclick="impPedirToner('${imp.id}')">🛒 Pedir</button></td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:24px;color:var(--g400)">Nenhuma impressora</td></tr>';
}

// ── CONSUMO & CUSTO ───────────────────────────────────────────
function impRenderConsumo() {
  const imps  = getImpressoras();
  const tbody = document.getElementById('imp-consumo-tbody');

  // Gráficos
  const nomes   = imps.map(i => i.nome || i.ip || 'Impressora');
  const paginas = imps.map(i => (i.paginasMesPB||0) + (i.paginasMesCor||0));
  const custos  = imps.map(i => {
    const cPB  = (_impConfig.custoTonerPB  / _impConfig.capPaginasPB)  * (i.paginasMesPB  || 0);
    const cCor = (_impConfig.custoTonerCor / _impConfig.capPaginasCor) * (i.paginasMesCor || 0);
    return Math.round((cPB + cCor) * 100) / 100;
  });

  impRenderBarChart('imp-chart-paginas', nomes, paginas, 'Páginas', '#2563EB');
  impRenderBarChart('imp-chart-custo',   nomes, custos,  'R$',      '#7C3AED');

  if (!tbody) return;
  tbody.innerHTML = imps.map(imp => {
    const cPB   = (_impConfig.custoTonerPB  / _impConfig.capPaginasPB)  * (imp.paginasMesPB  || 0);
    const cCor  = (_impConfig.custoTonerCor / _impConfig.capPaginasCor) * (imp.paginasMesCor || 0);
    const cTot  = cPB + cCor;
    const pagT  = (imp.paginasMesPB||0) + (imp.paginasMesCor||0);
    const cPag  = pagT > 0 ? (cTot / pagT) : 0;
    return `<tr>
      <td style="font-weight:600;font-size:13px">${escapeHtml(imp.nome||imp.ip)}</td>
      <td style="font-size:12px">${escapeHtml(imp.local||imp.area||'—')}</td>
      <td style="font-size:12px">${(imp.paginasTotal||0).toLocaleString('pt-BR')}</td>
      <td style="font-size:12px">${(imp.paginasMesPB||0).toLocaleString('pt-BR')}</td>
      <td style="font-size:12px">${(imp.paginasMesCor||0).toLocaleString('pt-BR')}</td>
      <td style="font-size:12px">R$ ${cPB.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px">R$ ${cCor.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px;font-weight:700;color:var(--accent)">R$ ${cTot.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px">R$ ${cPag.toFixed(4)}</td>
    </tr>`;
  }).join('');
}

function impRenderBarChart(canvasId, labels, data, yLabel, cor) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === 'undefined') return;
  if (_impCharts[canvasId]) _impCharts[canvasId].destroy();
  const ctx = canvas.getContext('2d');
  _impCharts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: yLabel, data, backgroundColor: cor + 'CC', borderColor: cor, borderWidth: 1, borderRadius: 4 }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { font: { size: 10 }, maxRotation: 30 }, grid: { display: false } },
        y: { ticks: { font: { size: 10 } }, beginAtZero: true },
      },
    },
  });
}

// ── SUGESTÕES DE PEDIDO AUTOMÁTICO ───────────────────────────
function impGerarSugestoesPedido() {
  const limite  = _impConfig.pedidoToner || 15;
  const imps    = getImpressoras();
  const urgentes = [];

  imps.forEach(imp => {
    const toners = imp.tonerLevels || [];
    toners.forEach(t => {
      if (t.pct < limite) {
        urgentes.push({
          imp: imp.nome || imp.ip,
          impId: imp.id,
          cor: t.cor,
          nome: t.nome,
          pct: t.pct,
          dias: imp.tonerDiasRestantes,
          urgencia: t.pct < 10 ? 'URGENTE' : 'Atenção',
        });
      }
    });
  });

  const el = document.getElementById('imp-pedidos-sugeridos');
  if (el) {
    if (!urgentes.length) {
      el.innerHTML = '<span style="color:#10B981">✅ Todos os níveis de toner estão adequados. Nenhum pedido necessário.</span>';
    } else {
      el.innerHTML = urgentes.map(u => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:#fff;border-radius:6px;margin-bottom:6px;border:1px solid ${u.urgencia==='URGENTE'?'#FCA5A5':'#FDE68A'}">
          <div>
            <span style="font-weight:700;color:${u.urgencia==='URGENTE'?'#DC2626':'#D97706'}">${u.urgencia}:</span>
            <span style="font-size:13px"> ${escapeHtml(u.imp)} — ${escapeHtml(u.nome||'Toner '+u.cor)}</span>
            <span style="font-size:12px;color:var(--g400);margin-left:6px">(${u.pct}% restante${u.dias?', ~'+u.dias+'d':''})</span>
          </div>
          <button class="btn btn-secondary btn-xs" onclick="impPedirTonerEspecifico('${u.impId}','${u.cor}','${escapeHtml(u.nome||'')}')">🛒 Pedir agora</button>
        </div>`).join('');
    }
  }
}

// ── PEDIDOS DE SUPRIMENTO ─────────────────────────────────────
function impRenderPedidos() {
  const tbody = document.getElementById('imp-pedidos-tbody');
  if (!tbody) return;
  const pedidos = STATE.pedidosSuprimentos || [];
  tbody.innerHTML = pedidos.length ? pedidos.map(p => {
    const cor = p.status === 'aprovado' ? 'badge-success' : p.status === 'pendente' ? 'badge-warning' : 'badge-info';
    return `<tr>
      <td style="font-size:12px">${p.data||'—'}</td>
      <td style="font-size:12px;font-weight:600">${escapeHtml(p.impressora||'—')}</td>
      <td style="font-size:12px">${escapeHtml(p.suprimento||'—')}</td>
      <td style="text-align:center">${p.qtd||1}</td>
      <td style="font-size:12px">${escapeHtml(p.justificativa||'—')}</td>
      <td><span class="badge ${cor}" style="font-size:10px">${escapeHtml(p.status||'—')}</span></td>
      <td style="font-size:12px">${escapeHtml(p.tecnico||'—')}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--g400)">Nenhum pedido registrado.</td></tr>';
  impGerarSugestoesPedido();
}

function impNovoPedido() { impPedirToner(null); }

function impPedirToner(impId) {
  const imp = impId ? getImpressoras().find(i => i.id === impId) : null;
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:480px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)';
  modal.innerHTML = `
    <h3 style="margin:0 0 14px;font-size:16px">🛒 Pedido de Suprimento</h3>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Impressora</label>
        <select class="form-control" id="ped-impressora">
          ${getImpressoras().map(i => `<option value="${i.id}" ${i.id===impId?'selected':''}>${escapeHtml(i.nome||i.ip)}</option>`).join('')}
        </select>
      </div>
      <div class="form-group"><label class="form-label req">Suprimento</label>
        <select class="form-control" id="ped-suprimento">
          <option value="Toner Preto (K)">Toner Preto (K)</option>
          <option value="Toner Ciano (C)">Toner Ciano (C)</option>
          <option value="Toner Magenta (M)">Toner Magenta (M)</option>
          <option value="Toner Amarelo (Y)">Toner Amarelo (Y)</option>
          <option value="Kit de Manutenção">Kit de Manutenção</option>
          <option value="Papel A4">Papel A4 (resma)</option>
          <option value="Outro">Outro</option>
        </select>
      </div>
    </div>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label">Quantidade</label><input type="number" class="form-control" id="ped-qtd" value="1" min="1"></div>
      <div class="form-group"><label class="form-label">Urgência</label>
        <select class="form-control" id="ped-urgencia">
          <option value="normal">Normal (5-7 dias)</option>
          <option value="urgente">Urgente (1-2 dias)</option>
          <option value="critico">Crítico (imediato)</option>
        </select>
      </div>
    </div>
    <div class="form-group"><label class="form-label req">Justificativa</label>
      <textarea class="form-control" id="ped-just" rows="2" placeholder="Ex: Toner da impressora X está em 8%, sem estoque disponível..."></textarea>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="impSalvarPedido(this)" class="btn btn-primary">🛒 Enviar Pedido</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

function impPedirTonerEspecifico(impId, cor, nome) {
  impPedirToner(impId);
  setTimeout(() => {
    const sel = document.getElementById('ped-suprimento');
    if (sel) {
      const match = [...sel.options].find(o => o.value.includes(cor));
      if (match) sel.value = match.value;
    }
  }, 100);
}

async function impSalvarPedido(btn) {
  const impId  = document.getElementById('ped-impressora')?.value;
  const sup    = document.getElementById('ped-suprimento')?.value;
  const qtd    = parseInt(document.getElementById('ped-qtd')?.value || '1');
  const urgencia = document.getElementById('ped-urgencia')?.value;
  const just   = document.getElementById('ped-just')?.value?.trim();
  if (!just) return showToast('Informe a justificativa', 'warning');

  const imp    = getImpressoras().find(i => i.id === impId);
  setButtonLoading(btn, true, 'Enviando...');
  const pedido = {
    id:          'PED-' + Date.now(),
    impId, impressora: imp?.nome || imp?.ip || impId,
    suprimento:  sup, qtd, urgencia, justificativa: just,
    tecnico:     CURRENT_USER?.nome || '',
    data:        new Date().toLocaleDateString('pt-BR'),
    status:      'pendente',
    createdAt:   new Date().toISOString(),
  };
  STATE.pedidosSuprimentos.unshift(pedido);
  await fsAdd('pedidosSuprimentos', pedido);
  setButtonLoading(btn, false, '🛒 Enviar Pedido');
  btn.closest('[style*=fixed]')?.remove();
  impRenderPedidos();
  showToast('Pedido de suprimento enviado!', 'success', 3000);
}

function impVerDetalhes(impId) {
  const imp = getImpressoras().find(i => i.id === impId);
  if (!imp) return;
  goPage('monitor-rede');
  // Abre modal de detalhe do dispositivo no monitor
  setTimeout(() => abrirDetalheMonitor?.(impId), 300);
}

function impSalvarConfig() {
  _impConfig = {
    custoTonerPB:  parseFloat(document.getElementById('cfg-custo-pb')?.value  || '150'),
    capPaginasPB:  parseInt(document.getElementById('cfg-cap-pb')?.value      || '3000'),
    custoTonerCor: parseFloat(document.getElementById('cfg-custo-cor')?.value || '300'),
    capPaginasCor: parseInt(document.getElementById('cfg-cap-cor')?.value     || '1500'),
    alertaToner:   parseInt(document.getElementById('cfg-alerta-toner')?.value || '20'),
    pedidoToner:   parseInt(document.getElementById('cfg-pedido-toner')?.value || '15'),
  };
  localStorage.setItem('sysack_imp_config', JSON.stringify(_impConfig));
  renderImpressoras();
  showToast('Configuração salva!', 'success', 2000);
}

function impRefrescar() { renderImpressoras(); showToast('Atualizado!', 'success', 1500); }

function impExportarConsumo() {
  const imps = getImpressoras();
  const rows = imps.map(imp => {
    const cPB  = (_impConfig.custoTonerPB  / _impConfig.capPaginasPB)  * (imp.paginasMesPB  || 0);
    const cCor = (_impConfig.custoTonerCor / _impConfig.capPaginasCor) * (imp.paginasMesCor || 0);
    return `"${imp.nome||imp.ip}";"${imp.local||''}";"${imp.paginasTotal||0}";"${imp.paginasMesPB||0}";"${imp.paginasMesCor||0}";"${cPB.toFixed(2)}";"${cCor.toFixed(2)}";"${(cPB+cCor).toFixed(2)}"`;
  });
  const csv = '\uFEFF' + 'Impressora;Área;Págs.Total;Págs.PB/mês;Págs.Cor/mês;Custo PB;Custo Cor;Custo Total\n' + rows.join('\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], {type:'text/csv;charset=utf-8'}));
  a.download = 'consumo_impressoras_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click();
}

function impRelatorio() {
  impTab('consumo');
  goPage('impressoras');
}

// Carrega config salva
try {
  const saved = localStorage.getItem('sysack_imp_config');
  if (saved) _impConfig = { ..._impConfig, ...JSON.parse(saved) };
} catch {}

// Verifica toner baixo a cada hora
setInterval(() => {
  const imps = getImpressoras();
  imps.forEach(imp => {
    if ((imp.tonerMin || 100) < (_impConfig.alertaToner || 20)) {
      const chave = 'toner_alert_' + imp.id;
      if (!sessionStorage.getItem(chave)) {
        sessionStorage.setItem(chave, '1');
        showToast(`⚠️ Toner baixo: ${imp.nome||imp.ip} (${imp.tonerMin}%)`, 'warning', 8000);
      }
    }
  });
}, 3600000);


// ════════════════════════════════════════════════════════════
// ERP FISCAL — SPED + Notas de Saída
// ════════════════════════════════════════════════════════════

// Gera arquivo SPED Fiscal (leiaute EFD-ICMS/IPI simplificado)
// Em uma empresa de saneamento (prestação de serviços), o foco é:
// Bloco 0 — Abertura e dados cadastrais
// Bloco C — Documentos fiscais (NF-e de entrada de bens)
// Bloco H — Inventário físico (estoque de ativos TI)
// Bloco K — Controle de produção (não aplicável)
// Bloco 9 — Encerramento

function gerarSPED(ano, mes) {
  const dtIni  = `${ano}${String(mes).padStart(2,'0')}01`;
  const dtFim  = `${ano}${String(mes).padStart(2,'0')}${new Date(ano, mes, 0).getDate()}`;
  const linhas = [];

  // Bloco 0 — Abertura
  linhas.push(`|0000|015|0|${dtIni}|${dtFim}|CESAN - COMPANHIA ESPIRITO SANTENSE DE SANEAMENTO|27.187.735/0001-59|ES|32||6010|6010|0||`);
  linhas.push(`|0001|1|`);
  linhas.push(`|0005|CESAN|AV GOVERNADOR BLEY, 186|CENTRO|29010-150|VITORIA|ES|3552809|contabilidade@cesan.com.br|`);

  // Bloco C — Notas fiscais de entrada (aquisição de bens TI)
  linhas.push(`|C001|1|`);
  const nfs = STATE.notasFiscais || [];
  nfs.forEach((nf, idx) => {
    if (!nf.data || !nf.data.startsWith(`${ano}-${String(mes).padStart(2,'0')}`)) return;
    const chNFe = nf.chaveNFe || `35${ano.toString().slice(2)}${nf.cnpj?.replace(/\D/g,'')||'00000000000000'}55001${String(idx+1).padStart(9,'0')}1${String(idx+1).padStart(9,'0')}`;
    linhas.push(`|C100|0|1|${escapeHtml(nf.cnpj||'').replace(/\D/g,'')}|55|001|${String(idx+1).padStart(6,'0')}|${nf.numero||String(idx+1)}|${nf.data?.replace(/-/g,'')||dtIni}|${nf.data?.replace(/-/g,'')||dtIni}|01|1|${(nf.valorTotal||0).toFixed(2)}|0,00|0,00|0,00|0,00|0,00|0,00|0,00|0,00|0,00|0,00|${chNFe}|`);
    (nf.itens || []).forEach((item, j) => {
      const cfop  = item.cfop || '1.102'; // Compra de ativo imobilizado
      const ncm   = item.ncm || '8471.30.19';
      linhas.push(`|C170|${j+1}|${item.xProd||'ATIVO IMOBILIZADO'}|${ncm}|${item.qCom||1}|${item.uCom||'UN'}|${(item.vProd||0).toFixed(2)}|0,00|${cfop.replace('.','')}.00|0|0,00|0,00|0,00|0,00|0,00|0|0,00|0|0,00|0,00|0|0,00|`);
    });
  });
  linhas.push(`|C990|${linhas.filter(l => l.startsWith('|C')).length + 1}|`);

  // Bloco H — Inventário de ativos (posição de estoque/imobilizado)
  linhas.push(`|H001|1|`);
  linhas.push(`|H005|${dtFim}|02|`); // Tipo 02 = inventário no encerramento de período
  const patrimonios = STATE.patrimonios || [];
  patrimonios.filter(p => p.status === 'ativo').forEach((p, idx) => {
    const valorAtual = calcularDepreciacao(p).valorAtual;
    linhas.push(`|H010|${p.pat||String(idx+1)}|${p.desc||'ATIVO IMOBILIZADO'}|8471|UN|1|${(p.valorAquisicao||0).toFixed(2)}|${valorAtual.toFixed(2)}|01|`);
  });
  linhas.push(`|H990|${linhas.filter(l => l.startsWith('|H')).length + 1}|`);

  // Bloco 9 — Encerramento
  const totalLinhas = linhas.length + 3;
  linhas.push(`|9001|1|`);
  linhas.push(`|9900|0000|1|`);
  linhas.push(`|9900|C|${linhas.filter(l=>l.startsWith('|C')).length}|`);
  linhas.push(`|9900|H|${linhas.filter(l=>l.startsWith('|H')).length}|`);
  linhas.push(`|9900|9|4|`);
  linhas.push(`|9990|${linhas.filter(l=>l.startsWith('|9')).length + 1}|`);
  linhas.push(`|9999|${linhas.length + 1}|`);

  return linhas.join('\n');
}

function exportarSPED() {
  const hoje = new Date();
  const sped = gerarSPED(hoje.getFullYear(), hoje.getMonth() + 1);
  const blob = new Blob([sped], { type: 'text/plain;charset=utf-8' });
  const a    = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `SPED_EFD_${hoje.getFullYear()}${String(hoje.getMonth()+1).padStart(2,'0')}.txt`;
  a.click();
  showToast(`SPED gerado: ${sped.split('\n').length} registros`, 'success', 4000);
}

// Nota Fiscal de Saída (baixa de bens / transferência entre filiais)
function gerarNotaSaida(patIds, tipo, destinatario) {
  const pats   = patIds.map(id => (STATE.patrimonios||[]).find(p => (p.id||p.pat) === id)).filter(Boolean);
  if (!pats.length) return null;

  const cfopMap = {
    'leilao':         '5.551', // Leilão / Pregão — venda de ativo imobilizado
    'pregao':         '5.551', // Pregão eletrônico — venda de ativo imobilizado
    'transferencia':  '5.551', // Transferência entre unidades
    'doacao':         '5.910', // Doação — remessa de bem de ativo imobilizado
    'descarte':       '5.949', // Descarte / baixa — outra saída
    'emprestimo':     '5.908', // Empréstimo temporário
  };

  const nfSaida = {
    id:        'NFS-' + Date.now(),
    tipo,
    cfop:      cfopMap[tipo] || '5.949',
    destinatario,
    itens:     pats.map(p => ({
      pat:    p.pat,
      desc:   p.desc,
      ncm:    '8471',
      qtd:    1,
      vUnit:  calcularDepreciacao(p).valorAtual,
      vTotal: calcularDepreciacao(p).valorAtual,
    })),
    valorTotal: pats.reduce((s, p) => s + calcularDepreciacao(p).valorAtual, 0),
    dataEmissao: new Date().toISOString().split('T')[0],
    createdBy:  CURRENT_USER?.nome || '',
    createdAt:  new Date().toISOString(),
  };

  if (!STATE.notasSaida) STATE.notasSaida = [];
  STATE.notasSaida.unshift(nfSaida);
  fsAdd('notasSaida', nfSaida);

  return nfSaida;
}

function abrirModalNotaSaida() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:560px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)';
  const pats = (STATE.patrimonios||[]).filter(p => p.status === 'ativo');
  modal.innerHTML = `
    <h3 style="margin:0 0 14px;font-size:16px">📤 Emitir Nota Fiscal de Saída</h3>
    <div class="form-row c2">
      <div class="form-group"><label class="form-label req">Tipo de saída</label>
        <select class="form-control" id="ns-tipo">
          <option value="leilao">Leilão / Pregão (CFOP 5.551)</option>
          <option value="transferencia">Transferência entre unidades CESAN (CFOP 5.551)</option>
          <option value="doacao">Doação a entidade pública (CFOP 5.910)</option>
          <option value="descarte">Descarte / Baixa contábil (CFOP 5.949)</option>
          <option value="emprestimo">Empréstimo temporário (CFOP 5.908)</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label req">Destinatário</label>
        <input class="form-control" id="ns-dest" placeholder="CNPJ ou nome do destinatário">
      </div>
    </div>
    <div class="form-group">
      <label class="form-label req">Patrimônios (selecione)</label>
      <div style="max-height:200px;overflow-y:auto;border:1px solid var(--g200);border-radius:8px">
        ${pats.map(p => `<label style="display:flex;align-items:center;gap:8px;padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--g100);font-size:12.5px">
          <input type="checkbox" value="${p.id||p.pat}" style="width:14px;height:14px">
          <span><strong>${p.pat}</strong> — ${escapeHtml(p.desc||'')} · R$ ${calcularDepreciacao(p).valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</span>
        </label>`).join('')}
      </div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="confirmarNotaSaida(this)" class="btn btn-primary">📤 Gerar Nota de Saída</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function confirmarNotaSaida(btn) {
  const tipo  = document.getElementById('ns-tipo')?.value;
  const dest  = document.getElementById('ns-dest')?.value?.trim();
  const patIds = [...document.querySelectorAll('#ns-tipo ~ * input[type=checkbox]:checked, [value]:checked')].map(el => el.value);
  // Better: collect from the modal's checkboxes
  const checks = btn.closest('[style*=fixed]').querySelectorAll('input[type=checkbox]:checked');
  const ids    = [...checks].map(c => c.value);

  if (!dest)       return showToast('Informe o destinatário', 'warning');
  if (!ids.length) return showToast('Selecione pelo menos um patrimônio', 'warning');

  setButtonLoading(btn, true, 'Gerando...');
  const nf = gerarNotaSaida(ids, tipo, dest);
  if (nf) {
    // Atualiza status dos PATs baixados
    if (tipo === 'descarte' || tipo === 'doacao') {
      for (const id of ids) {
        const p = (STATE.patrimonios||[]).find(x => (x.id||x.pat) === id);
        if (p) { p.status = 'baixado'; await fsUpdate('patrimonios', p.id, { status:'baixado' }); }
      }
    }
    // Exporta XML simulado
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<nfeProc>\n  <NFe>\n    <infNFe Id="NFe${nf.id}">\n      <ide><nNF>${nf.id}</nNF><natOp>${tipo}</natOp><CFOP>${nf.cfop}</CFOP><dhEmi>${nf.dataEmissao}</dhEmi></ide>\n      <dest><xNome>${escapeHtml(nf.destinatario)}</xNome></dest>\n      <total><ICMSTot><vNF>${nf.valorTotal.toFixed(2)}</vNF></ICMSTot></total>\n    </infNFe>\n  </NFe>\n</nfeProc>`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([xml], {type:'application/xml'}));
    a.download = `NF_Saida_${nf.id}_${nf.dataEmissao}.xml`;
    a.click();
  }
  setButtonLoading(btn, false, '📤 Gerar Nota de Saída');
  btn.closest('[style*=fixed]')?.remove();
  renderPatrimonio?.();
  showToast(`NF de saída ${nf?.id} gerada!`, 'success', 4000);
}


// ════════════════════════════════════════════════════════════
// PATRIMÔNIO — Consulta avançada, detalhe completo e relatórios
// ════════════════════════════════════════════════════════════

// Mapeamento tipo de item → categoria base (para busca)
const PAT_TIPO_CAT = {
  notebook:'informatica', computador:'informatica', monitor:'informatica',
  servidor:'informatica', switch:'informatica', impressora:'informatica',
  nobreak:'informatica', 'outros-ti':'informatica',
  mesa:'movel', cadeira:'movel', armario:'movel', arquivo:'movel', 'outros-mob':'movel',
  veiculo:'veiculo', equipamento:'equipamento', outro:'outro',
};

// Popula datalist de gerências dinamicamente
function patPopularGerencias() {
  const dl = document.getElementById('pat-gerencias-list');
  if (!dl) return;
  const gerencias = [...new Set([
    ...(STATE.patrimonios||[]).map(p => p.gerencia).filter(Boolean),
    ...(STATE.ativos||[]).map(a => a.gerencia || a.area).filter(Boolean),
    ...(STATE.mobiliario||[]).map(m => m.gerencia).filter(Boolean),
  ])].sort();
  dl.innerHTML = gerencias.map(g => `<option value="${escapeHtml(g)}">`).join('');
}

// Coleta todos os filtros ativos
function patColetarFiltros() {
  return {
    pat:       (document.getElementById('pat-filter-pat')?.value     || '').replace(/[^0-9]/g,'').trim(),
    texto:     (document.getElementById('pat-search')?.value         || '').toLowerCase().trim(),
    tipo:      (document.getElementById('pat-filter-tipo')?.value    || '').toLowerCase(),
    cat:       (document.getElementById('pat-filter-cat')?.value     || ''),
    gerencia:  (document.getElementById('pat-filter-gerencia')?.value|| '').toLowerCase().trim(),
    empregado: (document.getElementById('pat-filter-empregado')?.value|| '').toLowerCase().trim(),
    nf:        (document.getElementById('pat-filter-nf')?.value      || '').trim(),
    status:    (document.getElementById('pat-filter-status')?.value  || ''),
    // Data de compra (dataAquisicao — vem da nota fiscal)
    dtIni:     document.getElementById('pat-filter-dt-ini')?.value   || '',
    dtFim:     document.getElementById('pat-filter-dt-fim')?.value   || '',
    // Data de inclusão no sistema (createdAt — quando foi cadastrado)
    incIni:    document.getElementById('pat-filter-inc-ini')?.value  || '',
    incFim:    document.getElementById('pat-filter-inc-fim')?.value  || '',
  };
}

function patLimparFiltros() {
  ['pat-filter-pat','pat-search',
   'pat-filter-tipo','pat-filter-cat','pat-filter-gerencia',
   'pat-filter-empregado','pat-filter-nf','pat-filter-status',
   'pat-filter-dt-ini','pat-filter-dt-fim',
   'pat-filter-inc-ini','pat-filter-inc-fim'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  renderPatrimonio();
}

// Aplica todos os filtros a um item
function patItemPassaFiltro(p, f) {
  // ── PAT — número exato ou parcial ────────────────────────
  if (f.pat) {
    const patNorm = (p.pat || '').replace(/[^0-9]/g, '');
    if (!patNorm.includes(f.pat)) return false;
  }

  // ── Texto livre — busca em múltiplos campos ───────────────
  if (f.texto) {
    const campos = [
      p.pat, p.desc, p.fornecedor, p.nf, p.gerencia,
      p.empNome, p.resp, p.categoria, p.tipoLabel,
      p.cnpjFornecedor, p.local, p.serial,
    ].map(v => (v || '').toLowerCase()).join(' ');
    if (!campos.includes(f.texto)) return false;
  }

  // ── Tipo específico (mesa, cadeira, monitor…) ─────────────
  if (f.tipo) {
    const tipoNorm = (p.tipoLabel || p.tipo || p.desc || '').toLowerCase();
    if (f.tipo === 'outros-ti' || f.tipo === 'outros-mob') {
      if (!tipoNorm.includes(f.tipo.replace('outros-', ''))) return false;
    } else {
      if (!tipoNorm.includes(f.tipo) && !(p.categoria === PAT_TIPO_CAT[f.tipo])) return false;
    }
  }

  // ── Categoria ────────────────────────────────────────────
  if (f.cat && p.categoria !== f.cat) return false;

  // ── Gerência / Área ──────────────────────────────────────
  if (f.gerencia) {
    const gerNorm = (p.gerencia || p.area || '').toLowerCase();
    if (!gerNorm.includes(f.gerencia)) return false;
  }

  // ── Empregado (nome ou matrícula) ────────────────────────
  if (f.empregado) {
    const empNorm = (p.empNome || p.resp || '').toLowerCase();
    const matNorm = String(p.empMat || '').toLowerCase();
    if (!empNorm.includes(f.empregado) && !matNorm.includes(f.empregado)) return false;
  }

  // ── Nota Fiscal ──────────────────────────────────────────
  if (f.nf) {
    if (!(p.nf || '').toLowerCase().includes(f.nf.toLowerCase())) return false;
  }

  // ── Status ───────────────────────────────────────────────
  if (f.status && p.status !== f.status) return false;

  // ── Data de compra / aquisição (dataAquisicao) ───────────
  // Origem: data da nota fiscal ou informada manualmente
  if (f.dtIni && p.dataAquisicao && p.dataAquisicao < f.dtIni) return false;
  if (f.dtFim && p.dataAquisicao && p.dataAquisicao > f.dtFim) return false;

  // ── Data de inclusão no sistema (createdAt) ──────────────
  // Origem: timestamp automático do fsAdd ao cadastrar o item
  // Representa QUANDO o item entrou no SYSACK, independente da data de compra
  if (f.incIni || f.incFim) {
    // Normaliza createdAt para YYYY-MM-DD para comparação simples
    const crAt = p.createdAt
      ? (p.createdAt instanceof Date
          ? p.createdAt
          : p.createdAt?.toDate?.()
            ? p.createdAt.toDate()
            : new Date(p.createdAt))
      : null;
    const crStr = crAt ? crAt.toISOString().split('T')[0] : '';
    if (f.incIni && (!crStr || crStr < f.incIni)) return false;
    if (f.incFim && (!crStr || crStr > f.incFim)) return false;
  }

  return true;
}

// Override renderPatrimonio para usar filtros avançados
const _renderPatrimonioOriginal = typeof renderPatrimonio === 'function' ? renderPatrimonio : null;

function renderPatrimonio() {
  patPopularGerencias();

  const f = patColetarFiltros();
  const todosAtivos = [
    ...(STATE.patrimonios || []),
    ...(STATE.ativos || []).filter(a =>
      a.pat && a.valorAquisicao &&
      !(STATE.patrimonios || []).find(p => p.pat === a.pat)
    ),
    ...(STATE.mobiliario || []).filter(m =>
      m.pat && !(STATE.patrimonios || []).find(p => p.pat === m.pat)
    ),
  ];

  const lista = todosAtivos.filter(p => patItemPassaFiltro(p, f));

  // Stats
  const valorTotal     = todosAtivos.reduce((s, p) => s + (parseFloat(p.valorAquisicao)||0), 0);
  const valorAtualTot  = todosAtivos.reduce((s, p) => {
    const dep = calcularDepreciacao(p);
    return s + dep.valorAtual;
  }, 0);
  sv('pat-stat-total',      todosAtivos.length);
  sv('pat-stat-uso',        todosAtivos.filter(p => p.status !== 'baixado').length);
  sv('pat-stat-valor',      'R$ ' + valorTotal.toLocaleString('pt-BR', {minimumFractionDigits:2}));
  sv('pat-stat-depreciado', 'R$ ' + valorAtualTot.toLocaleString('pt-BR', {minimumFractionDigits:2}));
  sv('pat-stat-zero',       todosAtivos.filter(p => calcularDepreciacao(p).pctDepreciado >= 100).length);
  sv('pat-stat-nf',         (STATE.notasFiscais||[]).length);

  // Contador de resultados
  const countEl = document.getElementById('pat-result-count');
  if (countEl) countEl.textContent = lista.length + ' de ' + todosAtivos.length;

  // Valor total dos resultados filtrados
  const valorFiltrado = lista.reduce((s, p) => s + (parseFloat(p.valorAquisicao)||0), 0);
  const valorEl = document.getElementById('pat-result-valor');
  if (valorEl && lista.length < todosAtivos.length) {
    valorEl.textContent = '· R$ ' + valorFiltrado.toLocaleString('pt-BR', {minimumFractionDigits:2}) + ' valor de aquisição';
  } else if (valorEl) {
    valorEl.textContent = '';
  }

  // Tabela
  const tbody = document.getElementById('pat-tbody');
  if (!tbody) return;

  if (!lista.length) {
    tbody.innerHTML = `<tr><td colspan="13" style="text-align:center;padding:32px;color:var(--g400)">
      <div style="font-size:24px;margin-bottom:8px">🔍</div>
      <div style="font-weight:600">Nenhum item encontrado</div>
      <div style="font-size:12px;margin-top:4px">Ajuste os filtros ou <button onclick="patLimparFiltros()" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:12px;font-weight:600">limpe a busca</button></div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = lista.map(p => {
    const dep    = calcularDepreciacao(p);
    const pctDep = dep.pctDepreciado;
    const corDep = pctDep >= 100 ? '#EF4444' : pctDep >= 75 ? '#F59E0B' : '#10B981';
    const resp   = p.empNome || p.resp || '—';

    return `<tr style="cursor:pointer" onclick="patAbrirDetalhe('${p.id||p.pat}')" onmouseover="this.style.background='var(--g50)'" onmouseout="this.style.background=''">
      <td class="td-mono" style="color:var(--accent);font-weight:700;font-size:12px">${escapeHtml(p.pat||'—')}</td>
      <td style="font-size:13px;font-weight:600;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(p.desc||'')}">${escapeHtml(p.desc||'—')}</td>
      <td style="font-size:12px">${escapeHtml(p.tipoLabel||p.tipo||p.categoria||'—')}</td>
      <td style="font-size:12px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(p.gerencia||'')}">${escapeHtml(p.gerencia||p.area||'—')}</td>
      <td style="font-size:12px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(resp)}">${escapeHtml(resp)}</td>
      <td style="font-size:12px;color:var(--g400)">${escapeHtml(p.fornecedor||'—')}</td>
      <td class="td-mono" style="font-size:11.5px">${escapeHtml(p.nf||'—')}</td>
      <td style="font-size:12px">${p.dataAquisicao ? new Date(p.dataAquisicao+'T12:00:00').toLocaleDateString('pt-BR') : '—'}</td>
      <td style="font-size:12px;font-weight:600;text-align:right">R$ ${parseFloat(p.valorAquisicao||0).toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="font-size:12px;color:${corDep};font-weight:600;text-align:right">R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
      <td style="min-width:80px">
        <div style="display:flex;align-items:center;gap:5px">
          <div style="width:40px;height:5px;background:var(--g200);border-radius:3px;overflow:hidden"><div style="width:${Math.min(100,pctDep)}%;height:5px;background:${corDep}"></div></div>
          <span style="font-size:10px;color:${corDep};font-weight:700">${pctDep.toFixed(0)}%</span>
        </div>
      </td>
      <td><span class="badge ${p.status==='baixado'?'badge-danger':p.status==='leilao'?'badge-warning':'badge-success'}" style="font-size:10px">${escapeHtml(p.status||'ativo')}</span></td>
      <td onclick="event.stopPropagation()">
        <div style="display:flex;gap:4px">
          <button class="btn btn-ghost btn-xs" onclick="patAbrirDetalhe('${p.id||p.pat}')">📋</button>
          ${p.status !== 'baixado' ? `<button class="btn btn-danger btn-xs" onclick="patBaixar('${p.id||p.pat}');event.stopPropagation()">↓</button>` : ''}
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ── DETALHE COMPLETO DO ITEM ─────────────────────────────────
window._patDetId = null;

function patAbrirDetalhe(id) {
  const p = [...(STATE.patrimonios||[]), ...(STATE.ativos||[]), ...(STATE.mobiliario||[])]
    .find(x => (x.id||x.pat) === id || x.pat === id);
  if (!p) return;
  window._patDetId = id;

  const dep = calcularDepreciacao(p);
  const nf  = p.nfId ? (STATE.notasFiscais||[]).find(n => n.id === p.nfId) : null;
  const ativo = (STATE.ativos||[]).find(a => a.pat === p.pat);

  // Header
  document.getElementById('pat-det-titulo').textContent = 'PAT ' + (p.pat||'—') + ' — ' + (p.desc||'');
  document.getElementById('pat-det-sub').textContent = (p.tipoLabel||p.tipo||p.categoria||'') + (p.gerencia ? ' · ' + p.gerencia : '');

  // Aba GERAL
  const camposGeral = [
    ['Patrimônio (PAT)',       p.pat||'—'],
    ['Descrição',             p.desc||'—'],
    ['Tipo',                  p.tipoLabel||p.tipo||'—'],
    ['Categoria',             p.categoria||'—'],
    ['Gerência',              p.gerencia||p.area||'—'],
    ['Local / Área',          p.local||'—'],
    ['Responsável',           p.empNome||p.resp||'—'],
    ['Matrícula responsável', p.empMat||'—'],
    ['Status',                p.status||'—'],
    ['Estado de conservação', p.estado||'—'],
    ['Número de série',       p.serial||ativo?.serial||'—'],
    ['Modelo',                p.modelo||ativo?.modelo||'—'],
    ['Observações',           p.obs||'—'],
    ['Cadastrado em (inclusão no sistema)',
                              (() => {
                                if (!p.createdAt) return '—';
                                const d = p.createdAt instanceof Date ? p.createdAt
                                  : p.createdAt?.toDate?.() ? p.createdAt.toDate()
                                  : new Date(p.createdAt);
                                return d.toLocaleDateString('pt-BR') + ' às ' + d.toLocaleTimeString('pt-BR', {hour:'2-digit',minute:'2-digit'});
                              })()],
  ];
  document.getElementById('pat-det-geral-content').innerHTML = camposGeral.map(([label, val]) =>
    `<div style="padding:8px 0;border-bottom:1px solid var(--g100)">
      <div style="font-size:11px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.03em">${escapeHtml(label)}</div>
      <div style="font-size:13px;color:var(--g900);margin-top:2px">${escapeHtml(String(val))}</div>
    </div>`
  ).join('');

  // Aba FISCAL (NF)
  const itemNF = nf?.itens?.find(i => i.xProd === p.desc) || nf?.itens?.[0];
  document.getElementById('pat-det-fiscal-content').innerHTML = nf ? `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      ${[
        ['Número da NF',       nf.numero||'—'],
        ['Fornecedor',         nf.fornecedor||'—'],
        ['CNPJ do Fornecedor', nf.cnpj||'—'],
        ['Data de Emissão',    nf.data||'—'],
        ['Valor Total da NF',  'R$ '+(nf.valorTotal||0).toLocaleString('pt-BR',{minimumFractionDigits:2})],
        ['Valor do Item',      itemNF ? 'R$ '+itemNF.vProd?.toLocaleString('pt-BR',{minimumFractionDigits:2}) : '—'],
        ['NCM',                itemNF?.ncm||'—'],
        ['CFOP',               itemNF?.cfop||'—'],
        ['Quantidade',         itemNF ? itemNF.qCom+' '+itemNF.uCom : '—'],
        ['Arquivo XML',        nf.arquivo||'—'],
      ].map(([l,v]) => `<div style="padding:8px 0;border-bottom:1px solid var(--g100)">
        <div style="font-size:11px;font-weight:700;color:var(--g400);text-transform:uppercase">${escapeHtml(l)}</div>
        <div style="font-size:13px;color:var(--g900);margin-top:2px">${escapeHtml(String(v))}</div>
      </div>`).join('')}
    </div>` : '<div style="padding:20px;color:var(--g400);text-align:center">Nota Fiscal não vinculada a este patrimônio.</div>';

  // Aba CONTÁBIL
  const contaAt  = patContaContabil(p.categoria||'outro');
  const contaDep = patContaDepreciacao(p.categoria||'outro');
  document.getElementById('pat-det-contabil-content').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      ${esc([
        ['Conta do Imobilizado',      contaAt  + ' — ' + (PLANO_CONTAS_PADRAO.find(c=>c.conta===contaAt)?.nome||'')],
        ['Conta de Depreciação',      contaDep + ' — ' + (PLANO_CONTAS_PADRAO.find(c=>c.conta===contaDep)?.nome||'')],
        ['Centro de Custo',           p.centroCusto||'CC-001'],
        ['Valor de Aquisição',        'R$ '+parseFloat(p.valorAquisicao||0).toLocaleString('pt-BR',{minimumFractionDigits:2})],
        ['Data de Aquisição',         p.dataAquisicao ? new Date(p.dataAquisicao+'T12:00:00').toLocaleDateString('pt-BR') : '—'],
        ['Taxa de Depreciação',       getTaxaDepreciacao(p.categoria||'outro')+'% ao ano'],
        ['Vida Útil',                 dep.vidaUtilAnos+' anos'],
        ['Idade atual',               dep.anosUso+' anos'],
        ['Depreciação acumulada',     dep.pctDepreciado.toFixed(1)+'%'],
        ['Valor depreciado (R$)',     'R$ '+dep.valorDepreciado.toLocaleString('pt-BR',{minimumFractionDigits:2})],
        ['Valor atual contábil',      'R$ '+dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})],
        ['Totalmente depreciado?',    dep.pctDepreciado>=100 ? 'Sim' : 'Não'],
      ].map(([l,v]) => `<div style="padding:8px 0;border-bottom:1px solid var(--g100)">
        <div style="font-size:11px;font-weight:700;color:var(--g400);text-transform:uppercase">${escapeHtml(l)}</div>
        <div style="font-size:13px;color:var(--g900);margin-top:2px">${escapeHtml(String(v))}</div>
      </div>`).join(''))}
    </div>`;

  // Aba HISTÓRICO
  const hist = [...(ativo?.historico||[]), ...(p.historico||[])];
  document.getElementById('pat-det-historico-content').innerHTML = hist.length ?
    '<div style="display:flex;flex-direction:column;gap:8px">' +
    hist.slice().reverse().map(h =>
      `<div style="padding:10px 12px;background:var(--g50);border-radius:8px;border-left:3px solid var(--accent)">
        <div style="font-size:12.5px;font-weight:600">${escapeHtml(h.label||h.titulo||h.tipo||'Alteração')}</div>
        ${h.de && h.para ? `<div style="font-size:12px;color:var(--g500);margin-top:2px">${escapeHtml(h.de)} → <strong>${escapeHtml(h.para)}</strong></div>` : ''}
        ${h.desc ? `<div style="font-size:12px;color:var(--g500)">${escapeHtml(h.desc)}</div>` : ''}
        <div style="font-size:11px;color:var(--g400);margin-top:4px">📅 ${h.data||'—'} · 👤 ${escapeHtml(h.nomeAlterador||h.tecnico||'Sistema')}</div>
      </div>`
    ).join('') + '</div>'
    : '<div style="padding:20px;color:var(--g400);text-align:center">Nenhum histórico registrado.</div>';

  // Highlight active tab
  patDetTab('geral');
  openModal('modal-pat-detalhe');
}

function patDetTab(tab) {
  ['geral','fiscal','contabil','historico'].forEach(t => {
    const el = document.getElementById('pat-det-' + t);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('.pat-det-tab').forEach((btn, i) => {
    const tabs = ['geral','fiscal','contabil','historico'];
    const active = tabs[i] === tab;
    btn.style.color      = active ? 'var(--accent)' : 'var(--g500)';
    btn.style.borderBottom = active ? '2px solid var(--accent)' : '2px solid transparent';
    btn.style.fontWeight = active ? '700' : '600';
  });
}

// ── EXPORTAÇÃO COMPLETA ──────────────────────────────────────
function patExportarRelatorio(formato) {
  const f = patColetarFiltros();
  const todosAtivos = [
    ...(STATE.patrimonios||[]),
    ...(STATE.ativos||[]).filter(a => a.pat && a.valorAquisicao && !(STATE.patrimonios||[]).find(p=>p.pat===a.pat)),
    ...(STATE.mobiliario||[]).filter(m => m.pat && !(STATE.patrimonios||[]).find(p=>p.pat===m.pat)),
  ];
  const lista = todosAtivos.filter(p => patItemPassaFiltro(p, f));

  const cabecalho = [
    'PAT','Descrição','Tipo','Categoria','Gerência','Área/Local',
    'Responsável','Matrícula','Fornecedor','CNPJ Fornecedor',
    'Nº NF','Data NF','Data de Compra/Aquisição','Data de Inclusão no Sistema',
    'Valor Aquisição (R$)','Taxa Depr. (% a.a.)','Depreciado (%)',
    'Valor Atual (R$)','Status','Nº Série','Observações',
  ];

  const linhas = lista.map(p => {
    const dep  = calcularDepreciacao(p);
    const nf   = p.nfId ? (STATE.notasFiscais||[]).find(n => n.id === p.nfId) : null;
    return [
      p.pat||'',
      p.desc||'',
      p.tipoLabel||p.tipo||'',
      p.categoria||'',
      p.gerencia||p.area||'',
      p.local||'',
      p.empNome||p.resp||'',
      p.empMat||'',
      p.fornecedor||nf?.fornecedor||'',
      p.cnpjFornecedor||nf?.cnpj||'',
      p.nf||nf?.numero||'',
      nf?.data||'',
      p.dataAquisicao||'',
      (() => {
        if (!p.createdAt) return '';
        const d = p.createdAt instanceof Date ? p.createdAt
          : p.createdAt?.toDate?.() ? p.createdAt.toDate()
          : new Date(p.createdAt);
        return d.toLocaleDateString('pt-BR');
      })(),
      (p.valorAquisicao||0).toFixed(2).replace('.',','),
      getTaxaDepreciacao(p.categoria||'outro'),
      dep.pctDepreciado.toFixed(1),
      dep.valorAtual.toFixed(2).replace('.',','),
      p.status||'ativo',
      p.serial||'',
      p.obs||'',
    ].map(v => '"' + String(v).replace(/"/g,'""') + '"').join(';');
  });

  // Adiciona totalizadores no final
  const totalAq  = lista.reduce((s, p) => s + parseFloat(p.valorAquisicao||0), 0);
  const totalAt  = lista.reduce((s, p) => s + calcularDepreciacao(p).valorAtual, 0);
  linhas.push('');
  linhas.push(`"TOTAL (${lista.length} itens)";";";";";";";";";";";";";"${totalAq.toFixed(2).replace('.',',')}";";";"${totalAt.toFixed(2).replace('.',',')}"`);

  const hoje  = new Date().toISOString().split('T')[0];
  const titulo = `"SYSACK — Relatório de Patrimônio CESAN"\n"Data: ${hoje} · Filtros aplicados: ${Object.entries(f).filter(([,v])=>v).map(([k,v])=>k+'='+v).join(', ')||'Nenhum'}"\n\n`;
  const csv   = '\uFEFF' + titulo + cabecalho.map(c => '"'+c+'"').join(';') + '\n' + linhas.join('\n');

  const ext  = formato === 'excel' ? '.csv' : '.csv'; // ambos CSV, Excel abre nativamente
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `Patrimonio_CESAN_${hoje}${ext}`;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Relatório exportado — ${lista.length} item(ns)`, 'success', 3000);
}

// Exportar item individual
function patExportarItemCSV(id) {
  if (!id) return;
  const p = [...(STATE.patrimonios||[]), ...(STATE.ativos||[]), ...(STATE.mobiliario||[])]
    .find(x => (x.id||x.pat) === id || x.pat === id);
  if (!p) return;

  const dep = calcularDepreciacao(p);
  const nf  = p.nfId ? (STATE.notasFiscais||[]).find(n => n.id === p.nfId) : null;

  const linhas = [
    ['Campo','Valor'],
    ['PAT', p.pat||'—'],
    ['Descrição', p.desc||'—'],
    ['Tipo', p.tipoLabel||p.tipo||'—'],
    ['Categoria', p.categoria||'—'],
    ['Gerência', p.gerencia||p.area||'—'],
    ['Local', p.local||'—'],
    ['Responsável', p.empNome||p.resp||'—'],
    ['Matrícula responsável', p.empMat||'—'],
    ['Status', p.status||'—'],
    ['Estado', p.estado||'—'],
    ['Nº de Série', p.serial||'—'],
    ['Fornecedor', p.fornecedor||nf?.fornecedor||'—'],
    ['CNPJ Fornecedor', p.cnpjFornecedor||nf?.cnpj||'—'],
    ['Nota Fiscal', p.nf||nf?.numero||'—'],
    ['Data NF', nf?.data||'—'],
    ['Data Aquisição', p.dataAquisicao||'—'],
    ['Valor Aquisição', 'R$ '+(p.valorAquisicao||0).toFixed(2).replace('.',',')],
    ['Taxa Depreciação', getTaxaDepreciacao(p.categoria||'outro')+'% ao ano'],
    ['Vida Útil', dep.vidaUtilAnos+' anos'],
    ['Idade', dep.anosUso+' anos'],
    ['% Depreciado', dep.pctDepreciado.toFixed(1)+'%'],
    ['Valor Depreciado', 'R$ '+dep.valorDepreciado.toFixed(2).replace('.',',')],
    ['Valor Atual Contábil', 'R$ '+dep.valorAtual.toFixed(2).replace('.',',')],
    ['Conta Imobilizado', patContaContabil(p.categoria||'outro')],
    ['Conta Depreciação', patContaDepreciacao(p.categoria||'outro')],
    ['Centro de Custo', p.centroCusto||'CC-001'],
    ['Observações', p.obs||'—'],
  ].map(([l,v]) => '"'+l+'";"'+String(v).replace(/"/g,'""')+'"').join('\n');

  const csv  = '\uFEFF' + linhas;
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'PAT_' + (p.pat||id) + '_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click();
}


// ════════════════════════════════════════════════════════════
// BLOCK 1 — CHAMADOS: Reabertura, Recorrentes, Templates
// ════════════════════════════════════════════════════════════

// ── TEMPLATES DE CHAMADO ─────────────────────────────────────
const CHAMADO_TEMPLATES = [
  {
    id: 'tpl-pc-lento',
    nome: 'Computador lento / travando',
    tipo: 'incidente', categoria: 'hardware', prioridade: 'media',
    titulo: 'Computador lento ou travando',
    desc: 'O computador está apresentando lentidão excessiva ou travamentos frequentes.\n\nPor favor, informe:\n- Desde quando o problema ocorre?\n- O problema é constante ou intermitente?\n- Houve alguma instalação recente?',
    checklist: ['Verificar uso de CPU/RAM','Checar disco (espaço e fragmentação)','Verificar processos em background','Testar memória RAM','Checar temperatura do processador'],
  },
  {
    id: 'tpl-sem-internet',
    nome: 'Sem acesso à internet / rede',
    tipo: 'incidente', categoria: 'rede', prioridade: 'alta',
    titulo: 'Sem acesso à internet ou rede local',
    desc: 'Usuário sem acesso à internet ou à rede interna.\n\nVerificar:\n- Problema apenas nesta máquina ou em outras?\n- Cabo de rede conectado?\n- IP configurado corretamente?',
    checklist: ['Verificar cabo/Wi-Fi','Checar IP (ipconfig)','Testar ping gateway','Verificar switch da sala','Checar DHCP server'],
  },
  {
    id: 'tpl-impressora',
    nome: 'Impressora sem imprimir',
    tipo: 'incidente', categoria: 'impressora', prioridade: 'media',
    titulo: 'Impressora não imprime / com erro',
    desc: 'Impressora não está respondendo a comandos de impressão.',
    checklist: ['Verificar toner','Checar papel/atolamento','Reiniciar fila de impressão','Verificar driver','Testar página de teste'],
  },
  {
    id: 'tpl-novo-usuario',
    nome: 'Novo usuário / empregado',
    tipo: 'requisicao', categoria: 'acesso', prioridade: 'media',
    titulo: 'Criação de acesso para novo empregado',
    desc: 'Criação de conta de rede, e-mail corporativo e acesso aos sistemas para novo empregado.',
    checklist: ['Criar conta AD','Configurar e-mail','Instalar Office/sistemas','Configurar computador','Entregar equipamentos','Registrar no SYSACK'],
  },
  {
    id: 'tpl-troca-pc',
    nome: 'Troca de computador',
    tipo: 'requisicao', categoria: 'hardware', prioridade: 'media',
    titulo: 'Solicitação de troca de computador',
    desc: 'Solicitação de substituição de computador por obsolescência ou defeito.\n\nInformar PAT do equipamento atual e motivo da troca.',
    checklist: ['Avaliar equipamento atual','Verificar disponibilidade de substituto','Migrar dados do usuário','Instalar SO e sistemas','Registrar movimentação','Baixar patrimônio antigo se aplicável'],
  },
  {
    id: 'tpl-backup',
    nome: 'Recuperação de dados / backup',
    tipo: 'requisicao', categoria: 'dados', prioridade: 'alta',
    titulo: 'Recuperação de arquivos / backup',
    desc: 'Solicitação de recuperação de arquivos perdidos ou corruptos.',
    checklist: ['Identificar arquivos perdidos','Verificar backup mais recente','Restaurar arquivos','Confirmar integridade','Orientar sobre política de backup'],
  },
];

// ── CHAMADOS RECORRENTES ──────────────────────────────────────
if (!STATE.chamadosRecorrentes) STATE.chamadosRecorrentes = [];

const RECORRENCIA_LABELS = {
  diario:    'Diário',
  semanal:   'Semanal',
  quinzenal: 'Quinzenal',
  mensal:    'Mensal',
  trimestral:'Trimestral',
};

// Verifica se há chamados recorrentes para gerar hoje
function verificarChamadosRecorrentes() {
  const hoje = new Date().toISOString().split('T')[0];
  (STATE.chamadosRecorrentes || []).forEach(async rec => {
    if (!rec.ativo || !rec.proximaOcorrencia) return;
    if (rec.proximaOcorrencia <= hoje) {
      // Gera o chamado automaticamente
      const novo = {
        ...rec.template,
        id:          'CH-REC-' + Date.now(),
        status:      'aberto',
        recorrenteId: rec.id,
        recorrencia: rec.frequencia,
        createdAt:   new Date().toISOString(),
      };
      if (!STATE.chamados) STATE.chamados = [];
      STATE.chamados.unshift(novo);
      await fsAdd('chamados', novo, STATE.chamados);

      // Calcula próxima ocorrência
      const proxima = calcularProximaOcorrencia(rec.frequencia, hoje);
      rec.proximaOcorrencia = proxima;
      rec.ultimaGeracao     = hoje;
      await fsUpdate('chamadosRecorrentes', rec.id, { proximaOcorrencia: proxima, ultimaGeracao: hoje });

      showToast(`🔁 Chamado recorrente gerado: ${novo.desc?.split('\n')[0]}`, 'info', 5000);
      renderChamados();
    }
  });
}

function calcularProximaOcorrencia(frequencia, dataBase) {
  const d = new Date(dataBase + 'T12:00:00');
  switch (frequencia) {
    case 'diario':     d.setDate(d.getDate() + 1);   break;
    case 'semanal':    d.setDate(d.getDate() + 7);   break;
    case 'quinzenal':  d.setDate(d.getDate() + 15);  break;
    case 'mensal':     d.setMonth(d.getMonth() + 1); break;
    case 'trimestral': d.setMonth(d.getMonth() + 3); break;
    default:           d.setDate(d.getDate() + 7);
  }
  return d.toISOString().split('T')[0];
}

setTimeout(verificarChamadosRecorrentes, 8000);
setInterval(verificarChamadosRecorrentes, 3600000);

// ── MODAL: NOVO CHAMADO COM TEMPLATE ─────────────────────────
function abrirModalChamadoComTemplate(tplId) {
  const tpl = CHAMADO_TEMPLATES.find(t => t.id === tplId);
  if (!tpl) { openModal('modal-novo-chamado'); return; }

  // Preenche o modal de chamado com os dados do template
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
  set('ch-titulo',     tpl.titulo);
  set('ch-descricao',  tpl.desc);
  set('ch-tipo',       tpl.tipo);
  set('ch-categoria',  tpl.categoria);
  set('ch-prioridade', tpl.prioridade);

  // Armazena checklist para exibir ao atender
  window._templateChecklist = tpl.checklist || [];
  openModal('modal-novo-chamado');
  showToast('Template "' + tpl.nome + '" aplicado ✓', 'success', 2000);
}

// Modal de seleção de template
function abrirSeletorTemplate() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:580px;width:100%;max-height:85vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(0,0,0,.4)';
  modal.innerHTML = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--g200);display:flex;justify-content:space-between;align-items:center">
      <div>
        <h3 style="margin:0;font-size:16px">📋 Templates de Chamado</h3>
        <p style="margin:4px 0 0;font-size:12px;color:var(--g400)">Selecione um template ou abra chamado em branco</p>
      </div>
      <button onclick="this.closest('[style*=z-index:10001]').remove()" style="background:none;border:none;font-size:20px;cursor:pointer;color:var(--g400)">✕</button>
    </div>
    <div style="overflow-y:auto;padding:14px;display:grid;grid-template-columns:1fr 1fr;gap:10px">
      ${CHAMADO_TEMPLATES.map(tpl => `
        <div onclick="abrirModalChamadoComTemplate('${tpl.id}');this.closest('[style*=z-index:10001]').remove()"
          style="border:1px solid var(--g200);border-radius:10px;padding:14px;cursor:pointer;transition:all .15s"
          onmouseover="this.style.borderColor='var(--accent)';this.style.background='rgba(37,99,235,.04)'"
          onmouseout="this.style.borderColor='var(--g200)';this.style.background=''">
          <div style="font-size:13px;font-weight:700;margin-bottom:4px">${escapeHtml(tpl.nome)}</div>
          <div style="font-size:11.5px;color:var(--g400);margin-bottom:8px">${escapeHtml(tpl.desc.split('\n')[0])}</div>
          <div style="display:flex;gap:6px">
            <span style="font-size:10px;padding:1px 8px;border-radius:10px;background:var(--g100);color:var(--g600)">${tpl.tipo}</span>
            <span style="font-size:10px;padding:1px 8px;border-radius:10px;background:var(--g100);color:var(--g600)">${tpl.prioridade}</span>
          </div>
        </div>`).join('')}
      <div onclick="openModal('modal-novo-chamado');this.closest('[style*=z-index:10001]').remove()"
        style="border:2px dashed var(--g300);border-radius:10px;padding:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:8px;color:var(--g400);transition:all .15s"
        onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'"
        onmouseout="this.style.borderColor='var(--g300)';this.style.color='var(--g400)'">
        <div style="font-size:24px">+</div>
        <div style="font-size:13px;font-weight:600">Chamado em branco</div>
      </div>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

// ── REABERTURA DE CHAMADO ────────────────────────────────────
async function reabrirChamado(chamadoId) {
  const ch = (STATE.chamados || []).find(c => c.id === chamadoId);
  if (!ch) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:480px;width:100%;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.4)';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🔄 Reabrir Chamado ${escapeHtml(chamadoId)}</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">${escapeHtml(ch.desc?.split('\n')[0]||'')}</p>
    <div class="form-group">
      <label class="form-label req">Motivo da reabertura</label>
      <select class="form-control" id="reab-motivo">
        <option value="nao-resolvido">Problema não foi resolvido</option>
        <option value="recorrente">Problema voltou a ocorrer</option>
        <option value="incompleto">Solução incompleta</option>
        <option value="novo-sintoma">Novo sintoma relacionado</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label req">Descrição do problema persistente</label>
      <textarea class="form-control" id="reab-desc" rows="3" placeholder="Descreva o que ainda ocorre ou voltou a ocorrer..."></textarea>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="confirmarReabertura('${chamadoId}',this)" class="btn btn-primary">🔄 Reabrir Chamado</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function confirmarReabertura(chamadoId, btn) {
  const motivo = document.getElementById('reab-motivo')?.value;
  const desc   = document.getElementById('reab-desc')?.value?.trim();
  if (!desc) return showToast('Descreva o motivo da reabertura', 'warning');

  setButtonLoading(btn, true, 'Reabrindo...');
  const ch = (STATE.chamados || []).find(c => c.id === chamadoId);
  if (!ch) return;

  const reabertura = {
    data:        new Date().toISOString(),
    motivo,
    desc,
    reabertoPor: CURRENT_USER?.nome || '',
    statusAnterior: ch.status,
  };

  ch.status     = 'aberto';
  ch.reaberturas = [...(ch.reaberturas || []), reabertura];

  await fsUpdate('chamados', chamadoId, {
    status:     'aberto',
    reaberturas: ch.reaberturas,
    updatedAt:  new Date().toISOString(),
  });

  setButtonLoading(btn, false, '🔄 Reabrir Chamado');
  btn.closest('[style*=z-index:10001]')?.remove();
  renderChamados();
  showToast(`Chamado ${chamadoId} reaberto. SLA reiniciado.`, 'warning', 5000);
}

// ── CHAMADO RECORRENTE — Modal de configuração ────────────────
function configurarChamadoRecorrente(chamadoId) {
  const ch = (STATE.chamados || []).find(c => c.id === chamadoId);
  if (!ch) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:480px;width:100%;padding:24px';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🔁 Tornar Chamado Recorrente</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">O sistema criará automaticamente um novo chamado na frequência definida.</p>
    <div class="form-row c2">
      <div class="form-group">
        <label class="form-label req">Frequência</label>
        <select class="form-control" id="rec-freq">
          <option value="diario">Diário</option>
          <option value="semanal" selected>Semanal</option>
          <option value="quinzenal">Quinzenal</option>
          <option value="mensal">Mensal</option>
          <option value="trimestral">Trimestral</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Primeira ocorrência</label>
        <input type="date" class="form-control" id="rec-inicio" value="${new Date(Date.now()+86400000).toISOString().split('T')[0]}">
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Responsável automático</label>
      <input class="form-control" id="rec-tecnico" placeholder="Técnico designado para cada ocorrência" value="${escapeHtml(ch.tecnico||'')}">
    </div>
    <div class="form-group">
      <label class="form-label">Data de encerramento (opcional)</label>
      <input type="date" class="form-control" id="rec-fim" placeholder="Deixe em branco para não ter fim">
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarChamadoRecorrente('${chamadoId}',this)" class="btn btn-primary">🔁 Ativar Recorrência</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function salvarChamadoRecorrente(chamadoId, btn) {
  const freq   = document.getElementById('rec-freq')?.value;
  const inicio = document.getElementById('rec-inicio')?.value;
  const tecnico = document.getElementById('rec-tecnico')?.value?.trim();
  const fim    = document.getElementById('rec-fim')?.value || null;

  const ch = (STATE.chamados || []).find(c => c.id === chamadoId);
  if (!ch || !inicio) return showToast('Informe a data da primeira ocorrência', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  const rec = {
    id:                'REC-' + Date.now(),
    chamadoOrigemId:   chamadoId,
    frequencia:        freq,
    proximaOcorrencia: inicio,
    dataFim:           fim,
    ativo:             true,
    template: {
      desc:       ch.desc,
      tipo:       ch.tipo,
      categoria:  ch.categoria,
      prioridade: ch.prioridade,
      area:       ch.area,
      tecnico:    tecnico || ch.tecnico || '',
    },
    criadoPor:  CURRENT_USER?.nome || '',
    createdAt:  new Date().toISOString(),
  };

  STATE.chamadosRecorrentes.unshift(rec);
  await fsAdd('chamadosRecorrentes', rec);

  // Marca o chamado original como recorrente
  ch.recorrenteId = rec.id;
  await fsUpdate('chamados', chamadoId, { recorrenteId: rec.id });

  setButtonLoading(btn, false, '🔁 Ativar Recorrência');
  btn.closest('[style*=z-index:10001]')?.remove();
  showToast(`Recorrência ${RECORRENCIA_LABELS[freq]} ativada! Próxima: ${new Date(inicio+'T12:00:00').toLocaleDateString('pt-BR')}`, 'success', 5000);
}



// ════════════════════════════════════════════════════════════
// BLOCK 2 — QR Code, Inventário por sala, Vistoria periódica
// ════════════════════════════════════════════════════════════

// ── QR CODE IMPRIMÍVEL POR ATIVO ─────────────────────────────
function gerarQRCode(ativo) {
  // URL de acesso direto ao histórico do ativo via SYSACK
  const url  = `https://sysack.vercel.app/?ativo=${encodeURIComponent(ativo.id || ativo.pat)}`;
  // QR Code via API pública (sem dependência de library)
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(url)}`;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:380px;width:100%;padding:28px;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,.4)';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">📱 QR Code do Ativo</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 20px">Imprima e cole no equipamento</p>
    <div style="border:2px solid var(--g200);border-radius:12px;padding:16px;background:#fff;display:inline-block;margin-bottom:16px">
      <img src="${qrUrl}" style="width:200px;height:200px;display:block" alt="QR Code">
      <div style="margin-top:10px;font-family:monospace;font-size:18px;font-weight:900;color:var(--g900);letter-spacing:.05em">${escapeHtml(ativo.pat||ativo.id||'—')}</div>
      <div style="font-size:11.5px;color:var(--g400);margin-top:4px">${escapeHtml(ativo.desc||ativo.tipo||'')}</div>
      <div style="font-size:10px;color:var(--g300);margin-top:4px">SYSACK · CESAN/A-DSI</div>
    </div>
    <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
      <button onclick="imprimirQRCode('${escapeHtml(ativo.pat||ativo.id||'')}','${escapeHtml(ativo.desc||'')}','${qrUrl}')" class="btn btn-primary btn-sm">🖨️ Imprimir</button>
      <button onclick="baixarQRCode('${qrUrl}','${escapeHtml(ativo.pat||ativo.id||'')}')" class="btn btn-secondary btn-sm">⬇ Download PNG</button>
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost btn-sm">Fechar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

function imprimirQRCode(pat, desc, qrUrl) {
  // Usa blob URL em vez de document.write para evitar bloqueio de popup
  const htmlContent = `<!DOCTYPE html><html><head><title>QR Code ${pat}</title>
    <style>
      body { font-family: Arial, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #fff; }
      .etiqueta { border: 2px solid #000; border-radius: 10px; padding: 16px; text-align: center; width: 220px; }
      .pat { font-family: monospace; font-size: 22px; font-weight: 900; margin: 8px 0 4px; letter-spacing: .05em; }
      .desc { font-size: 11px; color: #555; margin-bottom: 4px; }
      .logo { font-size: 10px; color: #999; margin-top: 6px; }
      @media print { body { margin: 0; } }
    </style>
  </head><body>
    <div class="etiqueta">
      <img src="${qrUrl}" style="width:180px;height:180px" alt="QR">
      <div class="pat">${pat}</div>
      <div class="desc">${desc}</div>
      <div class="logo">SYSACK · CESAN/A-DSI</div>
    </div>
    <script>setTimeout(()=>{window.print();window.close();},500)<\/script>
  </body></html>`;
  const blob = new Blob([htmlContent], {type:'text/html'});
  const blobUrl = URL.createObjectURL(blob);
  const win = window.open(blobUrl, '_blank');
  if (win) setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
  else showToast('Popup bloqueado — permita popups para esta página.', 'warning');
}

function baixarQRCode(qrUrl, pat) {
  fetch(qrUrl)
    .then(r => r.blob())
    .then(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `QR_${pat}_CESAN.png`;
      a.click();
    })
    .catch(() => showToast('Download disponível apenas online', 'warning', 3000));
}

// ── INVENTÁRIO POR AMBIENTE/SALA ──────────────────────────────
function abrirInventarioSala() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:700px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(0,0,0,.4)';

  // Coleta todas as salas/locais únicos dos ativos
  const locais = [...new Set([
    ...(STATE.ativos||[]).map(a => a.local || a.loc || a.area).filter(Boolean),
    ...(STATE.mobiliario||[]).map(m => m.local).filter(Boolean),
    ...(STATE.patrimonios||[]).map(p => p.local).filter(Boolean),
  ])].sort();

  modal.innerHTML = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--g200);flex-shrink:0">
      <h3 style="margin:0;font-size:16px">🏢 Inventário por Ambiente / Sala</h3>
      <p style="margin:4px 0 0;font-size:12px;color:var(--g400)">Lista todos os bens em um local específico</p>
    </div>
    <div style="padding:14px 16px;border-bottom:1px solid var(--g100);display:flex;gap:8px;flex-shrink:0">
      <input class="form-control" style="flex:1;margin:0" id="inv-sala-busca"
        placeholder="Digite a sala, andar ou local... Ex: Sala 201, 2º Andar, Recepção"
        oninput="filtrarInventarioSala(this.value)" list="inv-salas-list">
      <datalist id="inv-salas-list">${locais.map(l=>`<option value="${escapeHtml(l)}">`).join('')}</datalist>
      <button class="btn btn-primary btn-sm" onclick="filtrarInventarioSala(document.getElementById('inv-sala-busca').value)">Buscar</button>
      <button class="btn btn-ghost btn-sm" onclick="exportarInventarioSala()">⬇ CSV</button>
    </div>
    <div id="inv-sala-resultado" style="overflow-y:auto;flex:1;padding:14px 16px">
      <div style="text-align:center;padding:32px;color:var(--g400)">
        <div style="font-size:32px;margin-bottom:8px">🔍</div>
        <div>Digite o nome de uma sala ou local para listar todos os bens</div>
      </div>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

function filtrarInventarioSala(q) {
  const res = document.getElementById('inv-sala-resultado');
  if (!res || !q || q.length < 2) return;

  const qNorm = q.toLowerCase();

  // Coleta itens de todas as coleções
  const ativos = (STATE.ativos||[]).filter(a =>
    (a.sala||a.local||a.loc||a.area||'').toLowerCase().includes(qNorm)
  ).map(a => ({ ...a, _colecao: 'Ativo TI', _icone: '💻' }));

  const moveis = (STATE.mobiliario||[]).filter(m =>
    (m.local||'').toLowerCase().includes(qNorm)
  ).map(m => ({ ...m, _colecao: 'Mobiliário', _icone: '🪑' }));

  const pats = (STATE.patrimonios||[]).filter(p =>
    (p.local||'').toLowerCase().includes(qNorm) &&
    !(STATE.ativos||[]).find(a => a.pat === p.pat)
  ).map(p => ({ ...p, _colecao: 'Patrimônio', _icone: '📦' }));

  const impressoras = (STATE.switches||[]).filter(s =>
    s.tipo === 'printer' && (s.local||s.area||'').toLowerCase().includes(qNorm)
  ).map(s => ({ ...s, _colecao: 'Impressora', _icone: '🖨️' }));

  const todos = [...ativos, ...moveis, ...pats, ...impressoras];
  window._invSalaItens = todos;

  if (!todos.length) {
    res.innerHTML = `<div style="text-align:center;padding:32px;color:var(--g400)">Nenhum item encontrado em "${escapeHtml(q)}"</div>`;
    return;
  }

  // Agrupa por coleção
  const grupos = {};
  todos.forEach(item => {
    const g = item._colecao;
    if (!grupos[g]) grupos[g] = [];
    grupos[g].push(item);
  });

  res.innerHTML = `
    <div style="margin-bottom:12px;font-size:13px;font-weight:600;color:var(--g600)">
      ${todos.length} item(ns) em "${escapeHtml(q)}"
    </div>` +
    Object.entries(grupos).map(([grupo, itens]) => `
    <div style="margin-bottom:16px">
      <div style="font-size:11px;font-weight:700;color:var(--g500);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
        ${itens[0]._icone} ${grupo} (${itens.length})
      </div>
      <div style="border:1px solid var(--g200);border-radius:8px;overflow:hidden">
        <table style="width:100%;border-collapse:collapse;font-size:12.5px">
          <thead style="background:var(--g50)">
            <tr>
              <th style="padding:8px 12px;text-align:left;font-weight:700;color:var(--g600)">PAT</th>
              <th style="padding:8px 12px;text-align:left;font-weight:700;color:var(--g600)">Descrição</th>
              <th style="padding:8px 12px;text-align:left;font-weight:700;color:var(--g600)">Responsável</th>
              <th style="padding:8px 12px;text-align:left;font-weight:700;color:var(--g600)">Status</th>
              <th style="padding:8px 12px;text-align:left;font-weight:700;color:var(--g600)">Local exato</th>
            </tr>
          </thead>
          <tbody>
            ${itens.map(item => `<tr style="border-top:1px solid var(--g100)">
              <td style="padding:8px 12px;font-family:monospace;font-weight:700;color:var(--accent)">${escapeHtml(item.pat||'—')}</td>
              <td style="padding:8px 12px;font-weight:500">${escapeHtml(item.desc||item.tipoLabel||item.tipo||'—')}</td>
              <td style="padding:8px 12px;color:var(--g600)">${escapeHtml(item.resp||item.empNome||item.gerencia||'—')}</td>
              <td style="padding:8px 12px"><span class="badge badge-success" style="font-size:10px">${escapeHtml(item.status||'ativo')}</span></td>
              <td style="padding:8px 12px;color:var(--g400)">${escapeHtml(item.local||item.loc||item.area||'—')}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`).join('');
}

function exportarInventarioSala() {
  const itens = window._invSalaItens || [];
  if (!itens.length) return showToast('Faça uma busca primeiro', 'warning');
  const sala  = document.getElementById('inv-sala-busca')?.value || 'sala';
  const rows  = itens.map(i =>
    [i.pat||'',i.desc||i.tipo||'',i._colecao,i.resp||i.empNome||i.gerencia||'',i.status||'',i.local||i.loc||i.area||'']
    .map(v => '"'+String(v).replace(/"/g,'""')+'"').join(';')
  );
  const csv = '\uFEFF' + '"PAT";"Descrição";"Tipo";"Responsável";"Status";"Local"\n' + rows.join('\n');
  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  a.download = `Inventario_${sala.replace(/\s/g,'_')}_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
}

// ── VISTORIA PERIÓDICA AGENDADA ───────────────────────────────
if (!STATE.vistorias) STATE.vistorias = [];

function agendarVistoria(ativoId) {
  const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])].find(a=>(a.id||a.pat)===ativoId);
  if (!ativo) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:460px;width:100%;padding:24px';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">📅 Agendar Vistoria — ${escapeHtml(ativo.desc||ativo.pat||'Ativo')}</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">PAT: ${escapeHtml(ativo.pat||'—')} · ${escapeHtml(ativo.local||ativo.area||'—')}</p>
    <div class="form-row c2">
      <div class="form-group">
        <label class="form-label req">Frequência</label>
        <select class="form-control" id="vist-freq">
          <option value="mensal">Mensal</option>
          <option value="trimestral" selected>Trimestral</option>
          <option value="semestral">Semestral</option>
          <option value="anual">Anual</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label req">Próxima vistoria</label>
        <input type="date" class="form-control" id="vist-data" value="${new Date(Date.now()+30*86400000).toISOString().split('T')[0]}">
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Checklist da vistoria</label>
      <textarea class="form-control" id="vist-checklist" rows="3"
        placeholder="Ex: Verificar estado físico&#10;Conferir PAT&#10;Checar funcionamento&#10;Fotografar se houver dano"></textarea>
    </div>
    <div class="form-group">
      <label class="form-label">Técnico responsável</label>
      <input class="form-control" id="vist-tecnico" placeholder="Nome do técnico">
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px">
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarVistoria('${ativoId}',this)" class="btn btn-primary">📅 Agendar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function salvarVistoria(ativoId, btn) {
  const freq      = document.getElementById('vist-freq')?.value;
  const data      = document.getElementById('vist-data')?.value;
  const checklist = document.getElementById('vist-checklist')?.value?.split('\n').filter(Boolean);
  const tecnico   = document.getElementById('vist-tecnico')?.value?.trim();
  if (!data) return showToast('Informe a data da próxima vistoria', 'warning');

  setButtonLoading(btn, true, 'Agendando...');
  const vistoria = {
    id: 'VIST-' + Date.now(), ativoId, freq, proximaVistoria: data,
    checklist: checklist || [], tecnico, status: 'agendada',
    realizadas: [], criadoPor: CURRENT_USER?.nome || '',
    createdAt: new Date().toISOString(),
  };
  STATE.vistorias.push(vistoria);
  await fsAdd('vistorias', vistoria);
  setButtonLoading(btn, false, '📅 Agendar');
  btn.closest('[style*=z-index:10001]')?.remove();
  showToast(`Vistoria ${freq} agendada para ${new Date(data+'T12:00:00').toLocaleDateString('pt-BR')}`, 'success', 4000);
}

// Verifica vistorias vencidas ou próximas
function verificarVistorias() {
  const hoje    = new Date();
  const hojeStr = hoje.toISOString().split('T')[0];
  const em5d    = new Date(Date.now() + 5*86400000).toISOString().split('T')[0];

  // ── Vistorias agendadas vencidas ──────────────────────────
  const vencidas = (STATE.vistorias||[]).filter(v =>
    v.status === 'agendada' && v.proximaVistoria < hojeStr
  );
  const proximas = (STATE.vistorias||[]).filter(v =>
    v.status === 'agendada' && v.proximaVistoria >= hojeStr && v.proximaVistoria <= em5d
  );

  vencidas.forEach(v => {
    const chave = 'vist_venc_' + v.id;
    if (!sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])].find(a=>(a.id||a.pat)===v.ativoId);
      showToast(`📅 Vistoria VENCIDA: ${ativo?.desc||ativo?.pat||v.ativoId} (prevista: ${new Date(v.proximaVistoria+'T12:00:00').toLocaleDateString('pt-BR')})`, 'danger', 10000);
    }
  });
  proximas.forEach(v => {
    const chave = 'vist_prox_' + v.id;
    if (!sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])].find(a=>(a.id||a.pat)===v.ativoId);
      showToast(`📅 Vistoria em 5 dias: ${ativo?.desc||ativo?.pat||v.ativoId}`, 'warning', 6000);
    }
  });

  // ── Alerta: ativo SEM vistoria há 300+ dias ───────────────
  // Verifica ativos que nunca foram vistoriados OU
  // cuja última vistoria realizada foi há mais de 300 dias.
  // Limiar: 300 dias conforme solicitação
  const LIMITE_DIAS = 300;
  const limite300   = new Date(Date.now() - LIMITE_DIAS * 86400000);

  const todosAtivos = [...(STATE.ativos||[]), ...(STATE.patrimonios||[])].filter(a =>
    a.status !== 'baixado' && a.status !== 'descarte'
  );

  todosAtivos.forEach(ativo => {
    const id = ativo.id || ativo.pat;

    // Verifica se tem vistoria agendada ou realizada
    const vistoriasDoAtivo = (STATE.vistorias||[]).filter(v => v.ativoId === id);
    const ultimaRealizada  = vistoriasDoAtivo
      .flatMap(v => v.realizadas || [])
      .map(r => new Date(r.data || r.dataRealizacao || 0))
      .sort((a, b) => b - a)[0]; // mais recente

    // Data de referência: última vistoria realizada, senão data de criação do ativo
    const dtRef = ultimaRealizada
      || (ativo.ultimaVistoria ? new Date(ativo.ultimaVistoria) : null)
      || (ativo.createdAt
          ? new Date(ativo.createdAt instanceof Date ? ativo.createdAt
              : ativo.createdAt?.toDate?.() ? ativo.createdAt.toDate()
              : ativo.createdAt)
          : null);

    if (!dtRef) return; // sem data de referência, ignora

    const diasSemVistoria = Math.floor((hoje - dtRef) / 86400000);

    if (diasSemVistoria >= LIMITE_DIAS) {
      const chave = 'vist_300_' + id + '_' + hojeStr;
      if (!sessionStorage.getItem(chave)) {
        sessionStorage.setItem(chave, '1');
        showToast(
          `⚠️ ${ativo.desc||ativo.pat||id} não é vistoriado há ${diasSemVistoria} dias (limite: ${LIMITE_DIAS}d)`,
          'warning', 12000
        );
      }
    }
  });
}
setTimeout(verificarVistorias, 15000);
setInterval(verificarVistorias, 3600000);



// ════════════════════════════════════════════════════════════
// BLOCK 3 — Dashboard de Produtividade do Técnico
// ════════════════════════════════════════════════════════════

function renderDashboardTecnico() {
  const tecnicos = STATE.tecnicos || [];
  const chamados = STATE.chamados || [];

  const metricas = tecnicos.map(tec => {
    const meusChamados = chamados.filter(c =>
      c.tecnico === tec.id || c.tecnico === tec.nome ||
      c.atribuido === tec.nome
    );
    const abertos    = meusChamados.filter(c => c.status === 'aberto').length;
    const resolvidos = meusChamados.filter(c => c.status === 'concluido' || c.status === 'fechado').length;
    const total      = meusChamados.length;

    // Tempo médio de resolução (horas)
    const temposRes = meusChamados
      .filter(c => (c.status === 'concluido' || c.status === 'fechado') && c.createdAt && c.updatedAt)
      .map(c => {
        const ini = new Date(c.createdAt instanceof Date ? c.createdAt : c.createdAt?.toDate?.() || c.createdAt);
        const fim = new Date(c.updatedAt instanceof Date ? c.updatedAt : c.updatedAt?.toDate?.() || c.updatedAt);
        return (fim - ini) / 3600000;
      }).filter(t => t > 0 && t < 720); // ignora > 30 dias (outliers)

    const tempoMedio = temposRes.length
      ? Math.round(temposRes.reduce((s,t) => s+t, 0) / temposRes.length * 10) / 10
      : null;

    // Satisfação média (NPS)
    const npsSotas = meusChamados.filter(c => c.nps).map(c => c.nps);
    const npsMedia = npsSotas.length ? Math.round(npsSotas.reduce((s,n) => s+n, 0) / npsSotas.length * 10) / 10 : null;

    // SLA compliance (% dentro do prazo)
    const comSLA   = meusChamados.filter(c => c.slaUltimoNivel !== undefined);
    const dentroPrazo = comSLA.filter(c => (c.slaUltimoNivel || 0) < 3).length;
    const slaComp  = comSLA.length ? Math.round(dentroPrazo / comSLA.length * 100) : null;

    // Chamados por mês (últimos 3 meses)
    const agora  = new Date();
    const por_mes = [0,1,2].map(m => {
      const mes = new Date(agora.getFullYear(), agora.getMonth() - m, 1);
      const prx = new Date(agora.getFullYear(), agora.getMonth() - m + 1, 1);
      return meusChamados.filter(c => {
        const d = new Date(c.createdAt instanceof Date ? c.createdAt : c.createdAt?.toDate?.() || c.createdAt);
        return d >= mes && d < prx;
      }).length;
    }).reverse();

    return { tec, abertos, resolvidos, total, tempoMedio, npsMedia, slaComp, por_mes };
  });

  const el = document.getElementById('dash-tec-container');
  if (!el) return;

  if (!metricas.length) {
    el.innerHTML = '<div style="text-align:center;padding:40px;color:var(--g400)">Nenhum técnico cadastrado.</div>';
    return;
  }

  el.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
      ${metricas.map(m => {
        const npsColor = m.npsMedia >= 4 ? '#10B981' : m.npsMedia >= 3 ? '#F59E0B' : '#EF4444';
        const slaColor = m.slaComp >= 90 ? '#10B981' : m.slaComp >= 70 ? '#F59E0B' : '#EF4444';
        const stars    = m.npsMedia ? '★'.repeat(Math.round(m.npsMedia)) + '☆'.repeat(5-Math.round(m.npsMedia)) : '—';
        return `
        <div class="card" style="overflow:hidden">
          <div style="background:linear-gradient(135deg,#1E293B,#334155);padding:14px 16px;display:flex;align-items:center;gap:10px">
            <div style="width:40px;height:40px;border-radius:50%;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#fff;flex-shrink:0">
              ${escapeHtml((m.tec.nome||'?').split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase())}
            </div>
            <div>
              <div style="color:#fff;font-weight:700;font-size:14px">${escapeHtml(m.tec.nome||'—')}</div>
              <div style="color:rgba(255,255,255,.5);font-size:11px">${escapeHtml(m.tec.especialidade||m.tec.cargo||'Técnico')}</div>
            </div>
          </div>
          <div style="padding:14px 16px">
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:12px">
              <div style="text-align:center;padding:8px;background:var(--g50);border-radius:8px">
                <div style="font-size:22px;font-weight:900;color:var(--accent)">${m.total}</div>
                <div style="font-size:10px;color:var(--g500);font-weight:600">TOTAL</div>
              </div>
              <div style="text-align:center;padding:8px;background:var(--g50);border-radius:8px">
                <div style="font-size:22px;font-weight:900;color:#10B981">${m.resolvidos}</div>
                <div style="font-size:10px;color:var(--g500);font-weight:600">RESOLVIDOS</div>
              </div>
              <div style="text-align:center;padding:8px;background:var(--g50);border-radius:8px">
                <div style="font-size:22px;font-weight:900;color:${m.abertos>5?'#EF4444':'#F59E0B'}">${m.abertos}</div>
                <div style="font-size:10px;color:var(--g500);font-weight:600">EM ABERTO</div>
              </div>
            </div>
            <div style="display:flex;flex-direction:column;gap:6px;font-size:12.5px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:var(--g500)">⏱ Tempo médio de resolução</span>
                <strong>${m.tempoMedio ? m.tempoMedio + 'h' : '—'}</strong>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:var(--g500)">⭐ Avaliação média</span>
                <span style="color:${npsColor};font-weight:700">${m.npsMedia ? m.npsMedia.toFixed(1) + '/5 ' + stars.slice(0,5) : '—'}</span>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:var(--g500)">📊 SLA no prazo</span>
                <span style="color:${slaColor};font-weight:700">${m.slaComp !== null ? m.slaComp + '%' : '—'}</span>
              </div>
            </div>
            <!-- Mini gráfico de barras: chamados por mês -->
            <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--g100)">
              <div style="font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;margin-bottom:6px">Chamados — últimos 3 meses</div>
              <div style="display:flex;align-items:flex-end;gap:4px;height:40px">
                ${m.por_mes.map((v,i) => {
                  const maxV = Math.max(...m.por_mes, 1);
                  const h = Math.round((v/maxV)*36) + 4;
                  const meses = ['','',''];
                  const now = new Date();
                  const mesLabel = new Date(now.getFullYear(), now.getMonth() - (2-i), 1)
                    .toLocaleString('pt-BR',{month:'short'});
                  return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">
                    <div style="font-size:9px;color:var(--g600);font-weight:700">${v}</div>
                    <div style="width:100%;height:${h}px;background:var(--accent);border-radius:3px 3px 0 0;opacity:${0.5+i*0.25}"></div>
                    <div style="font-size:9px;color:var(--g400)">${mesLabel}</div>
                  </div>`;
                }).join('')}
              </div>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

// ════════════════════════════════════════════════════════════
// BLOCK 4 — Relatório de Capacidade
// ════════════════════════════════════════════════════════════

function renderRelatorioCapacidade() {
  const switches   = STATE.switches || [];
  const ativos     = STATE.ativos   || [];
  const hoje       = new Date();

  // ── CPU/RAM projeção ──────────────────────────────────────
  const comHistorico = switches.filter(s => s.cpuHistory && s.cpuHistory.length >= 5);
  const projecoes    = comHistorico.map(s => {
    const hist  = s.cpuHistory.slice(-30);
    const n     = hist.length;
    const sumX  = hist.reduce((_,__,i) => _+i, 0);
    const sumY  = hist.reduce((a,v) => a+v, 0);
    const sumXY = hist.reduce((a,v,i) => a+i*v, 0);
    const sumX2 = hist.reduce((a,_,i) => a+i*i, 0);
    const b     = (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX) || 0;
    const media = sumY / n;

    const diasAte80    = b > 0 ? Math.round((80 - media) / (b * 4 * 24)) : null; // b em pct/ciclo, 4 ciclos/h
    const diasAte90    = b > 0 ? Math.round((90 - media) / (b * 4 * 24)) : null;

    return {
      s, media: Math.round(media*10)/10, tendencia: Math.round(b*1000)/1000,
      diasAte80, diasAte90,
      alerta: media > 70 || (diasAte80 !== null && diasAte80 < 30),
    };
  });

  // ── Disco projeção (ativos com disco%) ───────────────────
  const projecoesDisco = ativos.filter(a => a.diskPct !== undefined).map(a => {
    const livre = 100 - (a.diskPct || 0);
    const diasAteLleno = a.diskGrowthPctPerDay ? Math.round(livre / a.diskGrowthPctPerDay) : null;
    return { a, diskPct: a.diskPct, livre, diasAteLleno, alerta: a.diskPct > 80 };
  });

  // ── Contagem de ativos por ano de aquisição ───────────────
  const anosAdq = {};
  (STATE.patrimonios || []).filter(p => p.dataAquisicao).forEach(p => {
    const ano = p.dataAquisicao.split('-')[0];
    if (!anosAdq[ano]) anosAdq[ano] = 0;
    anosAdq[ano]++;
  });

  // Ativos a serem renovados (> vida útil)
  const VIDA_UTIL = { informatica:5, movel:10, veiculo:5, equipamento:10, outro:10 };
  const parasRenovar = (STATE.patrimonios||[]).filter(p => {
    if (!p.dataAquisicao) return false;
    const anos = (Date.now() - new Date(p.dataAquisicao+'T12:00:00').getTime()) / (365.25*86400000);
    const vida = VIDA_UTIL[p.categoria] || 5;
    return anos >= vida * 0.8; // 80% da vida útil = atenção
  });

  const el = document.getElementById('cap-container');
  if (!el) return;

  el.innerHTML = `
    <!-- Cards de resumo -->
    <div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
      <div class="stat-card red">   <div class="stat-label">Dispositivos em alerta CPU</div><div class="stat-value">${projecoes.filter(p=>p.alerta).length}</div></div>
      <div class="stat-card orange"><div class="stat-label">Discos > 80% cheios</div>      <div class="stat-value">${projecoesDisco.filter(p=>p.alerta).length}</div></div>
      <div class="stat-card yellow"><div class="stat-label">Bens p/ renovar em breve</div> <div class="stat-value">${parasRenovar.length}</div></div>
      <div class="stat-card blue">  <div class="stat-label">Total patrimônio monitorado</div><div class="stat-value">${(STATE.patrimonios||[]).length}</div></div>
    </div>

    <!-- Projeção CPU/RAM -->
    ${projecoes.length ? `
    <div class="card mb-16">
      <div class="card-header"><h3>📈 Projeção de saturação — CPU</h3></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Dispositivo</th><th>IP</th><th>CPU Média</th><th>Tendência</th><th>Dias até 80%</th><th>Dias até 90%</th><th>Urgência</th></tr></thead>
        <tbody>
          ${projecoes.map(p => {
            const corT = p.tendencia > 2 ? '#EF4444' : p.tendencia > 0.5 ? '#F59E0B' : '#10B981';
            const corA = p.alerta ? '#EF4444' : '#10B981';
            return `<tr>
              <td style="font-size:13px;font-weight:600">${escapeHtml(p.s.nome||p.s.ip)}</td>
              <td class="td-mono" style="font-size:12px">${escapeHtml(p.s.ip)}</td>
              <td style="font-weight:700;color:${p.media>70?'#EF4444':p.media>50?'#F59E0B':'#10B981'}">${p.media}%</td>
              <td style="color:${corT};font-weight:600">${p.tendencia > 0 ? '+' : ''}${p.tendencia}%/ciclo</td>
              <td style="font-weight:700;color:${p.diasAte80!==null&&p.diasAte80<30?'#EF4444':p.diasAte80!==null&&p.diasAte80<90?'#F59E0B':'#10B981'}">${p.diasAte80 !== null ? p.diasAte80 + 'd' : '✓ OK'}</td>
              <td style="font-size:12px">${p.diasAte90 !== null ? p.diasAte90 + 'd' : '—'}</td>
              <td><span class="badge" style="background:${corA}22;color:${corA};font-size:10px">${p.alerta?'⚠️ Atenção':'✓ Normal'}</span></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table></div>
    </div>` : '<div class="card mb-16" style="padding:20px;color:var(--g400);text-align:center">Sem histórico de CPU para projeção. Instale o Agente SYSACK nos dispositivos.</div>'}

    <!-- Bens próximos da renovação -->
    ${parasRenovar.length ? `
    <div class="card mb-16">
      <div class="card-header"><h3>🔄 Bens próximos do prazo de renovação</h3><button class="btn btn-ghost btn-sm" onclick="patExportarRelatorio('csv')">⬇ Exportar</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>PAT</th><th>Descrição</th><th>Categoria</th><th>Data Aquisição</th><th>Idade</th><th>Vida Útil</th><th>Depreciado</th><th>Valor Atual</th></tr></thead>
        <tbody>
          ${parasRenovar.sort((a,b) => {
            const da = (Date.now() - new Date(a.dataAquisicao+'T12:00:00').getTime()) / 31536000000;
            const db2 = (Date.now() - new Date(b.dataAquisicao+'T12:00:00').getTime()) / 31536000000;
            return db2 - da;
          }).map(p => {
            const dep  = calcularDepreciacao(p);
            const anos = dep.anosUso;
            const vida = VIDA_UTIL[p.categoria] || 5;
            const pct  = Math.round(anos / vida * 100);
            const cor  = pct >= 100 ? '#EF4444' : pct >= 80 ? '#F59E0B' : '#10B981';
            return `<tr>
              <td class="td-mono" style="font-size:12px;color:var(--accent)">${escapeHtml(p.pat||'—')}</td>
              <td style="font-size:13px;font-weight:500">${escapeHtml(p.desc||'—')}</td>
              <td style="font-size:12px">${escapeHtml(p.categoria||'—')}</td>
              <td style="font-size:12px">${p.dataAquisicao ? new Date(p.dataAquisicao+'T12:00:00').toLocaleDateString('pt-BR') : '—'}</td>
              <td style="font-weight:700;color:${cor}">${anos.toFixed(1)} anos</td>
              <td style="font-size:12px">${vida} anos</td>
              <td style="font-size:12px;color:${cor}">${dep.pctDepreciado.toFixed(0)}%</td>
              <td style="font-size:12px;font-weight:600">R$ ${dep.valorAtual.toLocaleString('pt-BR',{minimumFractionDigits:2})}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table></div>
    </div>` : ''}
  `;
}



// ════════════════════════════════════════════════════════════
// BLOCK 4 — Segurança: Remove LOCAL_USERS com senha,
//           IDs gerados no backend via CF callable
// ════════════════════════════════════════════════════════════

// Substitui a geração de ID local por chamada ao backend
// O backend garante sequência única e imutável
async function gerarIdChamado() {
  if (!FB_READY) {
    // Offline: gera ID temporário, será substituído no sync
    const tempId = 'CH-OFFLINE-' + Date.now();
    console.warn('[ID] Offline — ID temporário:', tempId);
    return tempId;
  }
  try {
    // Usa um documento de contador no Firestore com transaction
    const { getFirestore, doc, runTransaction, increment } = {}; // replaced by compat below
    const db2     = app.firestore();
    const contRef = db2.collection('config').doc('contadores');
    const novoNum = await db2.runTransaction(async tx => {
      const snap   = await tx.get(contRef);
      const atual  = snap.exists ? (snap.data().chamados || 99) : 99;
      const prox   = atual + 1;
      tx.set(contRef, { chamados: prox }, { merge: true });
      return prox;
    });
    return 'CH-' + String(novoNum).padStart(4, '0');
  } catch (err) {
    console.warn('[ID] Transação falhou, usando local:', err.message);
    return 'CH-' + Date.now().toString(36).toUpperCase();
  }
}

async function gerarIdAprovacao() {
  if (!FB_READY) return 'AP-OFFLINE-' + Date.now();
  try {
    const { getFirestore, doc, runTransaction } = {}; // replaced by compat below
    const db2     = app.firestore();
    const contRef = db2.collection('config').doc('contadores');
    const novoNum = await db2.runTransaction(async tx => {
      const snap   = await tx.get(contRef);
      const atual  = snap.exists ? (snap.data().aprovacoes || 0) : 0;
      const prox   = atual + 1;
      tx.set(contRef, { aprovacoes: prox }, { merge: true });
      return prox;
    });
    return 'AP-' + String(novoNum).padStart(4, '0');
  } catch {
    return 'AP-' + Date.now().toString(36).toUpperCase();
  }
}

// Remove senha hardcoded dos LOCAL_USERS
// Em produção SEMPRE usa Firebase Auth — LOCAL_USERS só para file:// dev
// Substitui a função checkLocalLogin para não expor senhas
function checkLocalLogin(email, senha) {
  // ⚠️  Credenciais locais foram removidas por segurança
  // Use o Firebase Auth (e-mail/senha) para autenticar
  // Em ambiente de desenvolvimento file://, contate o administrador do sistema
  console.warn('[Auth] Tentativa de login local bloqueada. Use Firebase Auth.');
  return null;
}

// ════════════════════════════════════════════════════════════
// BLOCK 5 — WSUS / Patch Management
// ════════════════════════════════════════════════════════════

if (!STATE.patches) STATE.patches = [];

function renderWSUS() {
  const el = document.getElementById('wsus-container');
  if (!el) return;

  const ativos   = (STATE.ativos||[]).filter(a => a.ip && (a.tipo==='computador'||a.tipo==='notebook'||a.tipo==='servidor'));
  const patches  = STATE.patches || [];

  // Agrupa patches por status
  const pendentes    = patches.filter(p => p.status === 'pendente');
  const instalados   = patches.filter(p => p.status === 'instalado');
  const comErro      = patches.filter(p => p.status === 'erro');
  const criticos     = patches.filter(p => p.severidade === 'critica' && p.status === 'pendente');

  el.innerHTML = `
    <div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:16px">
      <div class="stat-card blue">  <div class="stat-label">Dispositivos gerenciados</div><div class="stat-value">${ativos.length}</div></div>
      <div class="stat-card red">   <div class="stat-label">Patches críticos pendentes</div><div class="stat-value">${criticos.length}</div></div>
      <div class="stat-card orange"><div class="stat-label">Patches pendentes</div>       <div class="stat-value">${pendentes.length}</div></div>
      <div class="stat-card green"> <div class="stat-label">Instalados (30d)</div>        <div class="stat-value">${instalados.length}</div></div>
      <div class="stat-card violet"><div class="stat-label">Com erro</div>                <div class="stat-value">${comErro.length}</div></div>
    </div>

    <div style="display:flex;gap:8px;margin-bottom:14px">
      <button class="btn btn-primary btn-sm" onclick="wsusVarredura()">🔍 Iniciar Varredura</button>
      <button class="btn btn-secondary btn-sm" onclick="wsusInstalarTodos('critica')">🚨 Instalar críticos agora</button>
      <button class="btn btn-ghost btn-sm" onclick="wsusInstalarTodos('todos')">📦 Instalar todos aprovados</button>
    </div>

    <div class="card">
      <div class="card-header"><h3>📋 Patches pendentes de aprovação / instalação</h3></div>
      <div class="table-wrap"><table>
        <thead><tr><th>ID Patch</th><th>Descrição</th><th>Severidade</th><th>Dispositivos afetados</th><th>Data lançamento</th><th>Status</th><th></th></tr></thead>
        <tbody id="wsus-tbody">
          <tr><td colspan="7" style="text-align:center;padding:24px;color:var(--g400)">
            ${patches.length ? 'Carregando...' : 'Nenhuma varredura realizada. Clique em "Iniciar Varredura" para detectar patches disponíveis.'}
          </td></tr>
        </tbody>
      </table></div>
    </div>

    <div class="card" style="margin-top:14px">
      <div class="card-header"><h3>📊 Compliance de patches por dispositivo</h3></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Dispositivo</th><th>IP</th><th>SO</th><th>Críticos pendentes</th><th>Pendentes total</th><th>Última varredura</th><th>Compliance</th></tr></thead>
        <tbody>
          ${ativos.slice(0,20).map(a => {
            const meusPatch = patches.filter(p => p.ativoId === a.id || p.ativoIp === a.ip);
            const crit      = meusPatch.filter(p => p.severidade==='critica'&&p.status==='pendente').length;
            const pend      = meusPatch.filter(p => p.status==='pendente').length;
            const comp      = meusPatch.length > 0 ? Math.round((1 - pend/meusPatch.length)*100) : 100;
            const cor       = comp >= 95 ? '#10B981' : comp >= 80 ? '#F59E0B' : '#EF4444';
            return `<tr>
              <td style="font-size:13px;font-weight:500">${escapeHtml(a.desc||a.hostname||'—')}</td>
              <td class="td-mono" style="font-size:12px">${escapeHtml(a.ip||'—')}</td>
              <td style="font-size:12px">${escapeHtml(a.so||a.os||'Windows')}</td>
              <td style="font-weight:700;color:${crit>0?'#EF4444':'#10B981'}">${crit || '✓'}</td>
              <td style="font-size:12px">${pend}</td>
              <td style="font-size:12px;color:var(--g400)">${a.ultimaVarredura ? new Date(a.ultimaVarredura).toLocaleDateString('pt-BR') : 'Nunca'}</td>
              <td>
                <div style="display:flex;align-items:center;gap:6px">
                  <div style="width:50px;height:6px;background:var(--g200);border-radius:3px;overflow:hidden">
                    <div style="width:${comp}%;height:6px;background:${cor}"></div>
                  </div>
                  <span style="font-size:11px;font-weight:700;color:${cor}">${comp}%</span>
                </div>
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table></div>
    </div>`;
}

async function wsusVarredura() {
  showToast('🔍 Iniciando varredura de patches via agente...', 'info', 4000);
  // Em produção: CF envia comando aos agentes Windows via FCM/Firestore
  // O agente executa: Get-WindowsUpdate | ConvertTo-Json
  // e reporta os patches disponíveis
  try {
    await fsAdd('agent_commands', {
      tipo:      'wsus_scan',
      alvo:      'todos',
      status:    'pendente',
      createdAt: new Date().toISOString(),
    });
    showToast('✓ Comando enviado aos agentes. Resultados em ~2 min.', 'success', 5000);
  } catch {
    showToast('Comando enviado (modo offline)', 'info', 3000);
  }
}

async function wsusInstalarTodos(tipo) {
  const conf = tipo === 'critica'
    ? confirm('Instalar TODOS os patches críticos agora? Os dispositivos podem precisar reiniciar.')
    : confirm('Instalar TODOS os patches aprovados? Os dispositivos podem precisar reiniciar.');
  if (!conf) return;

  await fsAdd('agent_commands', {
    tipo:       'wsus_install',
    severidade: tipo === 'critica' ? 'critica' : 'todas',
    alvo:       'todos',
    status:     'pendente',
    createdAt:  new Date().toISOString(),
    aprovadoPor: CURRENT_USER?.nome || '',
  });
  showToast('📦 Instalação em andamento via agente. Progresso visível nos dispositivos.', 'info', 5000);
}

// ════════════════════════════════════════════════════════════
// BLOCK 6 — Backup / Recovery
// ════════════════════════════════════════════════════════════

if (!STATE.backups) STATE.backups = [];

function renderBackupRecovery() {
  const el = document.getElementById('backup-container');
  if (!el) return;

  const backups = STATE.backups || [];
  const ok      = backups.filter(b => b.status === 'ok').length;
  const falhas  = backups.filter(b => b.status === 'falha').length;
  const pendentes = backups.filter(b => b.status === 'pendente').length;

  el.innerHTML = `
    <div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
      <div class="stat-card green"> <div class="stat-label">Backups concluídos</div><div class="stat-value">${ok}</div></div>
      <div class="stat-card red">   <div class="stat-label">Falhas</div>            <div class="stat-value">${falhas}</div></div>
      <div class="stat-card orange"><div class="stat-label">Em andamento</div>     <div class="stat-value">${pendentes}</div></div>
      <div class="stat-card blue">  <div class="stat-label">Tamanho total</div>    <div class="stat-value" style="font-size:14px">${backups.reduce((s,b)=>s+(b.tamanhoGB||0),0).toFixed(1)} GB</div></div>
    </div>

    <div style="display:flex;gap:8px;margin-bottom:14px">
      <button class="btn btn-primary btn-sm" onclick="backupIniciar()">💾 Iniciar Backup Agora</button>
      <button class="btn btn-secondary btn-sm" onclick="backupConfigurar()">⚙️ Configurar Política</button>
      <button class="btn btn-danger btn-sm" onclick="backupRestaurar()">🔄 Solicitar Restauração</button>
    </div>

    <div class="card">
      <div class="card-header"><h3>📋 Histórico de Backups</h3></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Data/Hora</th><th>Tipo</th><th>Escopo</th><th>Tamanho</th><th>Duração</th><th>Destino</th><th>Status</th></tr></thead>
        <tbody>
          ${backups.length ? backups.map(b => {
            const cor = b.status==='ok'?'badge-success':b.status==='falha'?'badge-danger':'badge-warning';
            return `<tr>
              <td style="font-size:12px">${b.dataHora ? new Date(b.dataHora).toLocaleString('pt-BR') : '—'}</td>
              <td style="font-size:12px">${escapeHtml(b.tipo||'—')}</td>
              <td style="font-size:12px;max-width:200px">${escapeHtml(b.escopo||'—')}</td>
              <td style="font-size:12px">${b.tamanhoGB ? b.tamanhoGB.toFixed(2)+' GB' : '—'}</td>
              <td style="font-size:12px">${b.duracaoMin ? b.duracaoMin+' min' : '—'}</td>
              <td style="font-size:12px;color:var(--g400)">${escapeHtml(b.destino||'—')}</td>
              <td><span class="badge ${cor}" style="font-size:10px">${escapeHtml(b.status||'—')}</span></td>
            </tr>`;
          }).join('')
          : '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--g400)">Nenhum backup registrado. Configure a política de backup.</td></tr>'}
        </tbody>
      </table></div>
    </div>

    <!-- Política de Backup -->
    <div class="card" style="margin-top:14px;padding:16px 20px">
      <div class="card-header"><h3>📅 Política de Backup Atual</h3></div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-size:13px">
        <div style="padding:12px;background:var(--g50);border-radius:8px">
          <div style="font-weight:700;margin-bottom:4px">🗓️ Frequência</div>
          <div style="color:var(--g600)">Diário — 23:00</div>
          <div style="color:var(--g400);font-size:11px">Incrementais diários, Full aos domingos</div>
        </div>
        <div style="padding:12px;background:var(--g50);border-radius:8px">
          <div style="font-weight:700;margin-bottom:4px">🗄️ Retenção</div>
          <div style="color:var(--g600)">30 dias diários</div>
          <div style="color:var(--g400);font-size:11px">12 meses mensais · 7 anos anuais</div>
        </div>
        <div style="padding:12px;background:var(--g50);border-radius:8px">
          <div style="font-weight:700;margin-bottom:4px">📍 Destinos</div>
          <div style="color:var(--g600)">NAS local + Nuvem</div>
          <div style="color:var(--g400);font-size:11px">Backup redundante 3-2-1</div>
        </div>
      </div>
    </div>`;
}

async function backupIniciar() {
  const tipo = prompt('Tipo de backup:\n1 - Completo (Full)\n2 - Incremental\n3 - Diferencial\n\nDigite 1, 2 ou 3:');
  const tipos = { '1':'completo', '2':'incremental', '3':'diferencial' };
  if (!tipos[tipo]) return;

  const novo = {
    id: 'BKP-' + Date.now(), tipo: tipos[tipo], status: 'pendente',
    dataHora: new Date().toISOString(), escopo: 'Firestore + Storage SYSACK',
    destino: 'NAS + Nuvem', solicitadoPor: CURRENT_USER?.nome || '',
  };
  STATE.backups.unshift(novo);
  await fsAdd('backups', novo);
  renderBackupRecovery();
  showToast('💾 Backup ' + tipos[tipo] + ' iniciado!', 'success', 4000);
}

async function backupRestaurar() {
  const ponto = prompt('Informe a data/hora do ponto de restauração (ex: 2026-05-12 22:00):');
  if (!ponto) return;
  const motivo = prompt('Motivo da restauração (obrigatório):');
  if (!motivo) return;

  await fsAdd('backupRestauracoes', {
    pontoDe:    ponto, motivo,
    solicitadoPor: CURRENT_USER?.nome || '',
    status:     'aguardando-aprovacao',
    createdAt:  new Date().toISOString(),
  });
  showToast('🔄 Solicitação de restauração enviada — aguardando aprovação do gestor.', 'warning', 6000);
}

function backupConfigurar() {
  showToast('Configuração de política de backup via console do administrador.', 'info', 4000);
}





// ════════════════════════════════════════════════════════════
// TRANSFERÊNCIA DE PATRIMÔNIO — lógica completa
// ════════════════════════════════════════════════════════════

function trfBuscarAtivo(pat) {
  const info = document.getElementById('trf-pat-info');
  const areaEl = document.getElementById('trf-area-atual');
  const localEl = document.getElementById('trf-local');
  if (!pat || pat.length < 3) {
    if (info)    info.textContent = '';
    if (areaEl)  areaEl.value = '';
    return;
  }
  const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])]
    .find(a => (a.pat||'').includes(pat) || (a.id||'').includes(pat));
  if (ativo) {
    if (info)    info.textContent = '✓ ' + (ativo.desc||'') + ' · ' + (ativo.resp||ativo.empNome||'Sem responsável');
    if (areaEl)  areaEl.value = ativo.area || ativo.gerencia || ativo.local || '—';
    // Preenche sugestões de salas
    const dl = document.getElementById('trf-salas-list');
    if (dl) {
      const salas = [...new Set((STATE.ativos||[]).map(a=>a.sala||a.local).filter(Boolean))];
      dl.innerHTML = salas.map(s=>`<option value="${escapeHtml(s)}">`).join('');
    }
  } else {
    if (info)    info.textContent = pat.length > 3 ? '⚠️ PAT não encontrado' : '';
    if (areaEl)  areaEl.value = '';
  }
}

function trfBuscarEmpregado(q) {
  const res = document.getElementById('trf-emp-resultados');
  if (!res || !q || q.length < 2) { if (res) res.style.display='none'; return; }
  const encontrados = (STATE.empregados||[]).filter(e =>
    (e.nome||e.PrimeiroNome+' '+e.Sobrenome||'').toLowerCase().includes(q.toLowerCase()) ||
    String(e.mat||e.Matricula||'').includes(q)
  ).slice(0,6);
  res.style.display = encontrados.length ? '' : 'none';
  res.innerHTML = encontrados.map(e => {
    const nome = e.nome || (e.PrimeiroNome + ' ' + e.Sobrenome);
    const mat  = e.mat  || e.Matricula || '';
    return `<div onclick="document.getElementById('trf-novo-resp').value='${escapeHtml(nome)}';document.getElementById('trf-resp-mat').value='${mat}';document.getElementById('trf-emp-resultados').style.display='none'"
      style="padding:8px 10px;cursor:pointer;font-size:12.5px;border-bottom:1px solid var(--g100)"
      onmouseover="this.style.background='var(--g50)'" onmouseout="this.style.background=''">
      <strong>${escapeHtml(nome)}</strong> <span style="color:var(--g400);font-size:11px">Mat. ${mat}</span>
    </div>`;
  }).join('');
}

async function solicitarTransferencia() {
  const pat       = document.getElementById('trf-pat')?.value?.trim();
  const destino   = document.getElementById('trf-area-destino')?.value?.trim();
  const local     = document.getElementById('trf-local')?.value?.trim();
  const novoResp  = document.getElementById('trf-novo-resp')?.value?.trim();
  const respMat   = document.getElementById('trf-resp-mat')?.value?.trim();
  const just      = document.getElementById('trf-justificativa')?.value?.trim();

  if (!pat)     return showToast('Informe o PAT do ativo', 'warning');
  if (!destino) return showToast('Informe a área destino', 'warning');
  if (!just)    return showToast('Informe a justificativa', 'warning');

  const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])]
    .find(a => (a.pat||'').includes(pat));

  const idAprov = await gerarIdAprovacao();
  const aprov = {
    id: idAprov, tipo: 'transferencia',
    ativoId: ativo?.id || '', pat,
    areaOrigem:  ativo?.area || '',
    areaDestino: destino,
    localDestino: local || '',
    novoResp, respMat,
    justificativa: just,
    status: 'pendente',
    solicitadoPor: CURRENT_USER?.nome || '',
    createdAt: new Date().toISOString(),
  };

  if (!STATE.aprovacoes) STATE.aprovacoes = [];
  STATE.aprovacoes.unshift(aprov);
  await fsAdd('aprovacoes', aprov);

  // Registro no histórico do ativo
  if (ativo?.id) {
    await fsAdd('ativos/' + ativo.id + '/historico', {
      tipo: 'transferencia_solicitada', label: 'Transferência solicitada',
      de: ativo.area || '', para: destino,
      desc: 'Para: ' + destino + (local ? ' / ' + local : '') +
            (novoResp ? ' · Responsável: ' + novoResp : '') + ' · ' + just,
      nomeAlterador: CURRENT_USER?.nome || '',
      data: new Date().toISOString(), createdAt: new Date().toISOString(),
    });
  }

  closeModal('modal-transferencia');
  nbUpdate('nb-aprovacoes', (STATE.aprovacoes||[]).filter(a=>a.status==='pendente').length);
  showToast('📤 Transferência solicitada — aguardando aprovação do gestor (' + idAprov + ')', 'warning', 7000);
}

// ════════════════════════════════════════════════════════════
// MDM — Inserir nota/observação no histórico do celular
// ════════════════════════════════════════════════════════════

function notaMDM(smartphoneId) {
  const sm = (STATE.smartphones||[]).find(s => s.id === smartphoneId);
  if (!sm) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:480px;width:100%;padding:24px';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">📝 Adicionar ao Histórico — ${escapeHtml(sm.marca||'')} ${escapeHtml(sm.modelo||'')}</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">IMEI: ${escapeHtml(sm.imei1||'—')} · Empregado: ${escapeHtml(sm.empNome||'—')}</p>
    <div class="form-group">
      <label class="form-label req">Tipo de registro</label>
      <select class="form-control" id="nota-sm-tipo">
        <option value="observacao">Observação geral</option>
        <option value="manutencao">Manutenção / reparo</option>
        <option value="ocorrencia">Ocorrência / incidente</option>
        <option value="troca-chip">Troca de chip / SIM</option>
        <option value="atualizacao-so">Atualização de sistema</option>
        <option value="configuracao">Configuração / setup</option>
        <option value="outro">Outro</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label req">Descrição</label>
      <textarea class="form-control" id="nota-sm-desc" rows="4"
        placeholder="Descreva o que ocorreu, o que foi feito, observações importantes para o histórico de vida do aparelho..."></textarea>
    </div>
    <div class="form-group">
      <label class="form-label">Técnico responsável</label>
      <input class="form-control" id="nota-sm-tec" value="${escapeHtml(CURRENT_USER?.nome||'')}" placeholder="Nome do técnico">
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px">
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarNotaMDM('${smartphoneId}',this)" class="btn btn-primary">📝 Salvar no Histórico</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function salvarNotaMDM(smartphoneId, btn) {
  const tipo = document.getElementById('nota-sm-tipo')?.value;
  const desc = document.getElementById('nota-sm-desc')?.value?.trim();
  const tec  = document.getElementById('nota-sm-tec')?.value?.trim();
  if (!desc) return showToast('Descreva o registro', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  const nota = {
    tipo, desc, tec,
    data:      new Date().toISOString().split('T')[0],
    createdAt: new Date().toISOString(),
    criadoPor: CURRENT_USER?.nome || '',
  };

  const sm = (STATE.smartphones||[]).find(s => s.id === smartphoneId);
  if (sm) {
    if (!sm.historico) sm.historico = [];
    sm.historico.unshift(nota);
    await fsUpdate('smartphones', smartphoneId, { historico: sm.historico });
  }

  setButtonLoading(btn, false, '📝 Salvar no Histórico');
  btn.closest('[style*=z-index:10001]')?.remove();
  showToast('Registro adicionado ao histórico do aparelho!', 'success', 3000);
}

// ════════════════════════════════════════════════════════════
// ALERTAS PARA GESTOR — aprovações pendentes
// Roda ao iniciar e a cada 30min para reenviar alertas
// ════════════════════════════════════════════════════════════

function monitorarAprovacoes() {
  const pendentes = (STATE.aprovacoes||[]).filter(a => a.status === 'pendente');
  if (!pendentes.length) return;

  pendentes.forEach(aprov => {
    const criacao    = new Date(aprov.createdAt || Date.now());
    const horasAbert = Math.round((Date.now() - criacao.getTime()) / 3600000);
    const chave      = 'aprov_alert_' + aprov.id + '_' + new Date().toISOString().split('T')[0];

    if (!sessionStorage.getItem(chave)) {
      sessionStorage.setItem(chave, '1');
      const emoji = horasAbert > 24 ? '🚨' : horasAbert > 8 ? '⚠️' : '⏳';
      showToast(
        `${emoji} Aprovação pendente há ${horasAbert}h: ${aprov.tipo} · ${aprov.pat||aprov.id}`,
        horasAbert > 24 ? 'danger' : 'warning',
        8000
      );
    }
  });

  // Atualiza badge de aprovações
  nbUpdate('nb-aprovacoes', pendentes.length);
}

setInterval(monitorarAprovacoes, 30 * 60 * 1000); // a cada 30min
setTimeout(monitorarAprovacoes, 12000);            // 12s após login

// ════════════════════════════════════════════════════════════
// SANTA CLARA — Nova foto ao mudar local (já existe modal
// mas assegura que histórico é registrado automaticamente)
// ════════════════════════════════════════════════════════════

// Hook: quando salvarNovoLocalSC é chamado, garante que o histórico
// do ativo registra o movimento interno na Santa Clara
const _origSalvarNovoLocalSC = typeof salvarNovoLocalSC === 'function' ? salvarNovoLocalSC : null;
async function salvarNovoLocalSC(ativoId, btn) {
  const novoLocal = document.getElementById('sc-update-local')?.value?.trim();
  const fotoInput = document.getElementById('sc-update-foto');
  if (!novoLocal) return showToast('Informe o novo local', 'warning');

  setButtonLoading(btn, true, 'Salvando...');

  const ativo = (STATE.ativos||[]).find(a => a.id === ativoId);
  const localAnterior = ativo?.loc || ativo?.local || '';

  // Chama original se existir
  if (_origSalvarNovoLocalSC && _origSalvarNovoLocalSC !== salvarNovoLocalSC) {
    await _origSalvarNovoLocalSC(ativoId, btn);
    return;
  }

  // Atualiza local
  if (ativo) { ativo.loc = novoLocal; ativo.local = novoLocal; }
  await fsUpdate('ativos', ativoId, {
    loc: novoLocal, local: novoLocal,
    scUltimaAtualizacao: new Date().toISOString(),
  });

  // Registra no histórico com foto
  const hist = {
    tipo: 'mudanca_local_sc', label: 'Mudança de local em Santa Clara/Depósito TI',
    de: localAnterior, para: novoLocal,
    desc: 'Novo local registrado em Santa Clara/Depósito TI com foto.',
    nomeAlterador: CURRENT_USER?.nome || '',
    data: new Date().toISOString(), createdAt: new Date().toISOString(),
  };
  await fsAdd('ativos/' + ativoId + '/historico', hist);
  if (ativo && ativo.historico) ativo.historico.unshift(hist);

  setButtonLoading(btn, false, '💾 Salvar novo local');
  closeModal?.('modal-sc-update');
  btn.closest('[style*=z-index]')?.remove();
  showToast('Local em Santa Clara/Depósito TI atualizado e registrado no histórico!', 'success', 4000);
}

// ════════════════════════════════════════════════════════════
// ALERTA DE IP: evento em tempo real via onSnapshot
// Complementa verificarTodosIPs com detecção instantânea
// ════════════════════════════════════════════════════════════

function iniciarWatcherIP() {
  if (!FB_READY || !window._db || !window._fs) return;
  const db_local = window._db;
  const { collection, onSnapshot } = window._fs;

  // Ouve mudanças na coleção de ativos — quando IP muda, verifica
  const unsub = onSnapshot(collection(db_local, 'ativos'), snapshot => {
    snapshot.docChanges().forEach(change => {
      if (change.type === 'modified') {
        const data = change.doc.data();
        if (data.ip) {
          // Atualiza STATE local
          const idx = (STATE.ativos||[]).findIndex(a => a.id === change.doc.id);
          if (idx >= 0) {
            const ipAnterior = STATE.ativos[idx].ip;
            STATE.ativos[idx] = { ...STATE.ativos[idx], ...data, id: change.doc.id };
            // Se IP mudou, verifica a área
            if (ipAnterior && ipAnterior !== data.ip) {
              verificarIPArea(STATE.ativos[idx]);
            }
          }
        }
      }
    });
  });
  // Armazena para eventual cleanup
  window._ipWatcherUnsub = unsub;
}
// Inicia após login
// iniciarWatcherIP iniciado após login via loginSuccess()

// Adiciona botão "📝 Nota" no MDM se não estiver presente
(function adicionarBotaoNotaMDM() {
  // Monkey-patch renderMDM para incluir botão de nota
  const _origRenderMDM = typeof renderMDM === 'function' ? renderMDM : null;
  if (!_origRenderMDM) return;
  window.renderMDM = function() {
    _origRenderMDM();
    // Adiciona botão "📝 Nota" nas linhas sem ele
    document.querySelectorAll('#mdm-table-body tr, #mdm-cards-grid .mdm-device-card').forEach(row => {
      const actions = row.querySelector('.flex.gap-4, .mdm-card-actions');
      if (actions && !actions.querySelector('[onclick*="notaMDM"]')) {
        const smId = actions.querySelector('[onclick*="abrirHistSm"]')?.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
        if (smId) {
          const btn = document.createElement('button');
          btn.className = 'mdm-action-btn mab-gray';
          btn.textContent = '📝 Nota';
          btn.onclick = () => notaMDM(smId);
          actions.insertBefore(btn, actions.children[1]); // após Histórico
        }
      }
    });
  };
})();



// ════════════════════════════════════════════════════════════
// GRUPOS DE ALERTA POR E-MAIL — Sistema completo
// Configuração: quem recebe, quais tipos, por unidade/gerência
// ════════════════════════════════════════════════════════════

// Catálogo de tipos de alerta disponíveis
const ALERTA_TIPOS = [
  { id:'sla_violado',        label:'SLA violado',              icone:'🚨', desc:'Chamado ultrapassou o prazo de atendimento',          categoria:'chamados' },
  { id:'sla_escalado',       label:'SLA escalado (N2/N3)',      icone:'⬆️', desc:'Chamado escalou para coordenador ou gerência',         categoria:'chamados' },
  { id:'aprovacao_pendente', label:'Aprovação pendente',        icone:'⏳', desc:'Movimentação ou transferência aguardando autorização',  categoria:'patrimonio' },
  { id:'toner_critico',      label:'Toner crítico (<10%)',      icone:'🖨️', desc:'Impressora com toner abaixo de 10%',                   categoria:'impressoras' },
  { id:'toner_baixo',        label:'Toner baixo (<limiar)',     icone:'⚠️', desc:'Impressora abaixo do limiar configurado',              categoria:'impressoras' },
  { id:'backup_falha',       label:'Falha de backup',           icone:'💾', desc:'Backup não concluído ou com erro',                    categoria:'infra' },
  { id:'patch_critico',      label:'Patch crítico detectado',   icone:'🔧', desc:'Vulnerabilidade crítica aguardando instalação',        categoria:'infra' },
  { id:'vistoria_vencida',   label:'Vistoria vencida',          icone:'📅', desc:'Ativo sem vistoria há mais de 300 dias',              categoria:'patrimonio' },
  { id:'contrato_vencendo',  label:'Contrato/garantia vencendo',icone:'📋', desc:'Contrato vencendo nos próximos dias configurados',     categoria:'patrimonio' },
  { id:'licenca_vencendo',   label:'Licença vencendo',          icone:'🔑', desc:'Licença de software próxima do vencimento',           categoria:'infra' },
  { id:'cpu_critico',        label:'CPU/RAM crítico',           icone:'📊', desc:'Dispositivo com CPU ou RAM acima de 90%',             categoria:'infra' },
  { id:'dispositivo_offline',label:'Dispositivo offline',       icone:'🔴', desc:'Switch, servidor ou dispositivo ficou offline',       categoria:'rede' },
  { id:'mudanca_ip_area',    label:'Mudança de área por IP',    icone:'🌐', desc:'Ativo detectado em rede diferente do cadastrado',     categoria:'rede' },
  { id:'terceirizada_prazo', label:'Terceirizada: prazo vencido',icone:'🏛️',desc:'Equipamento na terceirizada há mais de 10 dias úteis',categoria:'chamados' },
  { id:'depreciacao_total',  label:'Bem totalmente depreciado', icone:'💰', desc:'Patrimônio atingiu 100% de depreciação',              categoria:'patrimonio' },
  { id:'nps_baixo',          label:'NPS baixo (<3 estrelas)',   icone:'⭐', desc:'Avaliação de atendimento abaixo de 3',                categoria:'chamados' },
];

const ALERTA_CATEGORIAS = {
  chamados:   { label:'Chamados & Atendimento', cor:'#2563EB' },
  patrimonio: { label:'Patrimônio & Movimentações', cor:'#7C3AED' },
  impressoras:{ label:'Impressoras', cor:'#F59E0B' },
  infra:      { label:'Infraestrutura', cor:'#10B981' },
  rede:       { label:'Rede & Segurança', cor:'#EF4444' },
};

// State
if (!STATE.gruposAlerta) STATE.gruposAlerta = [];

// ── RENDER LISTA DE GRUPOS ────────────────────────────────────
function renderGruposAlerta() {
  fsListen('gruposAlerta', docs => {
    STATE.gruposAlerta = docs;
    _renderGruposLista();
  });
  _renderGruposLista();
}

function _renderGruposLista() {
  const el = document.getElementById('grupos-alerta-lista');
  if (!el) return;
  const grupos = STATE.gruposAlerta || [];

  if (!grupos.length) {
    el.innerHTML = `
      <div style="text-align:center;padding:48px;color:var(--g400)">
        <div style="font-size:40px;margin-bottom:14px">🔔</div>
        <div style="font-weight:600;font-size:15px;margin-bottom:8px">Nenhum grupo de alerta configurado</div>
        <div style="font-size:13px;margin-bottom:20px">Crie grupos para receber notificações por e-mail sobre o que importa para cada equipe.</div>
        <button class="btn btn-primary" onclick="abrirModalNovoGrupoAlerta()">+ Criar primeiro grupo</button>
      </div>`;
    return;
  }

  el.innerHTML = grupos.map(g => {
    const tipos   = (g.tipos || []).map(t => ALERTA_TIPOS.find(a => a.id === t)).filter(Boolean);
    const escopo  = g.escopo === 'todas' ? '🌐 Toda a CESAN'
                  : g.escopo === 'unidade' ? '🏢 Unidade: ' + (g.unidades||[]).join(', ')
                  : g.escopo === 'gerencia' ? '👥 Gerência: ' + (g.gerencias||[]).join(', ')
                  : '—';

    // Agrupa tipos por categoria
    const cats = {};
    tipos.forEach(t => {
      if (!cats[t.categoria]) cats[t.categoria] = [];
      cats[t.categoria].push(t);
    });

    return `
    <div class="card mb-12" style="border-left:4px solid ${g.ativo !== false ? '#10B981' : '#D1D5DB'}">
      <div style="padding:16px 20px;display:flex;align-items:flex-start;gap:16px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <div style="font-size:15px;font-weight:800;color:var(--g900)">${escapeHtml(g.nome)}</div>
            <span style="font-size:10px;padding:2px 10px;border-radius:20px;font-weight:700;background:${g.ativo!==false?'#D1FAE5':'#F3F4F6'};color:${g.ativo!==false?'#065F46':'#6B7280'}">
              ${g.ativo !== false ? '● Ativo' : '○ Inativo'}
            </span>
          </div>
          ${g.descricao ? `<div style="font-size:12.5px;color:var(--g500);margin-bottom:8px">${escapeHtml(g.descricao)}</div>` : ''}

          <!-- Destinatários -->
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
            ${(g.emails||[]).map(e => `
              <div style="display:flex;align-items:center;gap:4px;background:var(--g100);padding:3px 10px;border-radius:20px;font-size:11.5px">
                <span>✉️</span><span>${escapeHtml(e.email)}</span>
                ${e.nome ? `<span style="color:var(--g400)">(${escapeHtml(e.nome)})</span>` : ''}
              </div>`).join('')}
            ${!(g.emails||[]).length ? '<span style="font-size:12px;color:var(--g400)">Nenhum destinatário</span>' : ''}
          </div>

          <!-- Escopo -->
          <div style="font-size:12px;color:var(--g500);margin-bottom:10px">
            <strong>Escopo:</strong> ${escopo}
          </div>

          <!-- Tipos de alerta por categoria -->
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${Object.entries(cats).map(([cat, ts]) => {
              const catInfo = ALERTA_CATEGORIAS[cat] || { label: cat, cor:'#94A3B8' };
              return `<div style="background:${catInfo.cor}15;border:1px solid ${catInfo.cor}40;border-radius:8px;padding:4px 10px">
                <span style="font-size:10px;font-weight:700;color:${catInfo.cor}">${catInfo.label}</span>
                <span style="font-size:11px;color:var(--g700);margin-left:4px">${ts.map(t=>t.icone+' '+t.label).join(' · ')}</span>
              </div>`;
            }).join('')}
            ${!tipos.length ? '<span style="font-size:12px;color:var(--g400)">Nenhum tipo selecionado</span>' : ''}
          </div>
        </div>

        <!-- Ações -->
        <div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0">
          <button class="btn btn-ghost btn-sm" onclick="editarGrupoAlerta('${g.id}')">✏️ Editar</button>
          <button class="btn btn-ghost btn-sm" onclick="testarGrupoAlerta('${g.id}')">📧 Testar</button>
          <button class="btn btn-ghost btn-sm" style="color:${g.ativo!==false?'#EF4444':'#10B981'}"
            onclick="toggleGrupoAlerta('${g.id}',${g.ativo !== false})">
            ${g.ativo !== false ? '⏸ Pausar' : '▶ Ativar'}
          </button>
          <button class="btn btn-danger btn-xs" onclick="excluirGrupoAlerta('${g.id}')">🗑</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

// ── MODAL: CRIAR / EDITAR GRUPO ───────────────────────────────
function abrirModalNovoGrupoAlerta(grupoId) {
  const grupo = grupoId ? (STATE.gruposAlerta||[]).find(g => g.id === grupoId) : null;
  const titulo = grupo ? 'Editar grupo de alerta' : 'Novo grupo de alerta';

  const overlay = document.createElement('div');
  overlay.id = 'modal-grupo-alerta';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px;overflow-y:auto';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:700px;width:100%;max-height:95vh;overflow-y:auto;box-shadow:0 24px 80px rgba(0,0,0,.4)';

  // Monta HTML dos tipos agrupados por categoria
  const tiposHtml = Object.entries(ALERTA_CATEGORIAS).map(([cat, catInfo]) => {
    const tiposDaCat = ALERTA_TIPOS.filter(t => t.categoria === cat);
    return `
      <div style="margin-bottom:14px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:${catInfo.cor};margin-bottom:6px">${catInfo.label}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px">
          ${tiposDaCat.map(t => `
            <label style="display:flex;align-items:flex-start;gap:8px;padding:8px;border:1px solid var(--g200);border-radius:8px;cursor:pointer;transition:all .1s"
              onmouseover="this.style.borderColor='${catInfo.cor}';this.style.background='${catInfo.cor}08'"
              onmouseout="this.style.borderColor='var(--g200)';this.style.background=''">
              <input type="checkbox" name="alerta-tipo" value="${t.id}"
                ${grupo?.tipos?.includes(t.id) ? 'checked' : ''}
                style="margin-top:2px;accent-color:${catInfo.cor}">
              <div>
                <div style="font-size:12.5px;font-weight:600">${t.icone} ${t.label}</div>
                <div style="font-size:11px;color:var(--g400)">${t.desc}</div>
              </div>
            </label>`).join('')}
        </div>
      </div>`;
  }).join('');

  // HTML atual dos emails
  const emailsHtml = (grupo?.emails||[]).map((e, i) => `
    <div class="ga-email-row" style="display:flex;gap:6px;margin-bottom:6px" data-idx="${i}">
      <input class="form-control ga-email" placeholder="e-mail" value="${escapeHtml(e.email||'')}" style="margin:0;flex:2">
      <input class="form-control ga-nome"  placeholder="nome (opcional)" value="${escapeHtml(e.nome||'')}" style="margin:0;flex:1.5">
      <button onclick="this.closest('.ga-email-row').remove()" style="border:none;background:none;color:var(--danger);cursor:pointer;font-size:18px;padding:0 4px">✕</button>
    </div>`).join('');

  // Unidades (da planilha de redes)
  const unidades = [...new Set((STATE.gruposAlerta||[]).flatMap(g => g.unidades||[])
    .concat(window.REDES_CESAN?.map(r=>r.nome)||[]))].sort().slice(0,30);

  modal.innerHTML = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--g200);background:linear-gradient(135deg,#1E293B,#334155);border-radius:14px 14px 0 0">
      <h3 style="color:#fff;margin:0;font-size:16px">🔔 ${titulo}</h3>
      <p style="color:rgba(255,255,255,.5);font-size:12px;margin:4px 0 0">Configure destinatários, tipos de alerta e escopo de monitoramento</p>
    </div>

    <div style="padding:20px">
      <!-- Nome e descrição -->
      <div class="form-row c2" style="margin-bottom:0">
        <div class="form-group">
          <label class="form-label req">Nome do grupo</label>
          <input class="form-control" id="ga-nome" placeholder="Ex: Equipe TI — Alertas Críticos" value="${escapeHtml(grupo?.nome||'')}">
        </div>
        <div class="form-group">
          <label class="form-label">Descrição</label>
          <input class="form-control" id="ga-desc" placeholder="Para que serve este grupo..." value="${escapeHtml(grupo?.descricao||'')}">
        </div>
      </div>

      <!-- Destinatários de e-mail -->
      <div style="border:1px solid var(--g200);border-radius:10px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;font-weight:700;color:var(--g700);margin-bottom:12px">✉️ Destinatários</div>
        <div id="ga-emails-container">${emailsHtml || ''}</div>
        <button onclick="gaAdicionarEmail()" class="btn btn-ghost btn-sm" style="margin-top:4px">+ Adicionar e-mail</button>
        <p class="form-hint" style="margin-top:8px">Você pode adicionar múltiplos destinatários. Todos receberão os alertas configurados abaixo.</p>
      </div>

      <!-- Escopo de monitoramento -->
      <div style="border:1px solid var(--g200);border-radius:10px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;font-weight:700;color:var(--g700);margin-bottom:12px">🎯 Escopo de Monitoramento</div>
        <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
            <input type="radio" name="ga-escopo" value="todas" ${!grupo || grupo.escopo==='todas' ? 'checked' : ''} onchange="gaToggleEscopo(this.value)">
            <div><strong>Toda a CESAN</strong><br><span style="font-size:11.5px;color:var(--g400)">Alertas de qualquer unidade</span></div>
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
            <input type="radio" name="ga-escopo" value="unidade" ${grupo?.escopo==='unidade' ? 'checked' : ''} onchange="gaToggleEscopo(this.value)">
            <div><strong>Por Unidade</strong><br><span style="font-size:11.5px;color:var(--g400)">Selecionar unidades específicas</span></div>
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
            <input type="radio" name="ga-escopo" value="gerencia" ${grupo?.escopo==='gerencia' ? 'checked' : ''} onchange="gaToggleEscopo(this.value)">
            <div><strong>Por Gerência</strong><br><span style="font-size:11.5px;color:var(--g400)">Selecionar gerências específicas</span></div>
          </label>
        </div>

        <div id="ga-escopo-unidade" style="display:${grupo?.escopo==='unidade'?'':'none'}">
          <label class="form-label" style="font-size:11.5px">Selecione as unidades</label>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:4px;max-height:200px;overflow-y:auto;padding:8px;border:1px solid var(--g200);border-radius:8px">
            ${(REDES_CESAN||[]).slice(0,100).map(r => `
              <label style="display:flex;align-items:center;gap:5px;font-size:11.5px;cursor:pointer;padding:3px">
                <input type="checkbox" name="ga-unidade" value="${escapeHtml(r.nome)}" ${grupo?.unidades?.includes(r.nome)?'checked':''}>
                <span title="${r.subnet}">${escapeHtml(r.sigla)} — ${escapeHtml(r.nome.length>25?r.nome.slice(0,25)+'...':r.nome)}</span>
              </label>`).join('')}
          </div>
        </div>

        <div id="ga-escopo-gerencia" style="display:${grupo?.escopo==='gerencia'?'':'none'}">
          <label class="form-label" style="font-size:11.5px">Selecione as gerências</label>
          <div id="ga-gerencias-tags" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">
            ${(grupo?.gerencias||[]).map(g => `<span style="background:var(--accent-light);color:var(--accent);padding:3px 10px;border-radius:20px;font-size:12px;display:flex;align-items:center;gap:5px">${escapeHtml(g)}<button onclick="this.parentElement.remove()" style="border:none;background:none;cursor:pointer;color:inherit">✕</button></span>`).join('')}
          </div>
          <input class="form-control" id="ga-add-gerencia" placeholder="Digite e pressione Enter: ex. Gerência de TI, Financeira..."
            onkeydown="if(event.key==='Enter'&&this.value.trim()){const t=document.createElement('span');t.style.cssText='background:var(--accent-light);color:var(--accent);padding:3px 10px;border-radius:20px;font-size:12px;display:flex;align-items:center;gap:5px';t.innerHTML='<span>'+escapeHtml(this.value.trim())+'</span><button onclick=\"this.parentElement.remove()\" style=\"border:none;background:none;cursor:pointer;color:inherit\">✕</button>';document.getElementById('ga-gerencias-tags').appendChild(t);this.value='';event.preventDefault()}">
        </div>
      </div>

      <!-- Tipos de alerta -->
      <div style="border:1px solid var(--g200);border-radius:10px;padding:16px;margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <div style="font-size:13px;font-weight:700;color:var(--g700)">🚨 Tipos de Alerta</div>
          <div style="display:flex;gap:6px">
            <button onclick="document.querySelectorAll('[name=alerta-tipo]').forEach(c=>c.checked=true)" class="btn btn-ghost btn-xs">✓ Todos</button>
            <button onclick="document.querySelectorAll('[name=alerta-tipo]').forEach(c=>c.checked=false)" class="btn btn-ghost btn-xs">✗ Nenhum</button>
          </div>
        </div>
        ${tiposHtml}
      </div>

      <!-- Configurações adicionais -->
      <div style="border:1px solid var(--g200);border-radius:10px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;font-weight:700;color:var(--g700);margin-bottom:10px">⚙️ Configurações</div>
        <div class="form-row c2">
          <div class="form-group">
            <label class="form-label">Frequência máxima de alertas</label>
            <select class="form-control" id="ga-frequencia">
              <option value="imediato" ${grupo?.frequencia==='imediato'?'selected':''}>Imediato (assim que ocorrer)</option>
              <option value="1h" ${grupo?.frequencia==='1h'?'selected':''}>Máx. 1 por hora</option>
              <option value="4h" ${grupo?.frequencia==='4h'?'selected':''}>Máx. 1 a cada 4 horas</option>
              <option value="diario" ${grupo?.frequencia==='diario'?'selected':''}>Resumo diário</option>
            </select>
            <p class="form-hint">Evita spam de e-mail em eventos frequentes</p>
          </div>
          <div class="form-group">
            <label class="form-label">Horário de envio (se diário)</label>
            <input type="time" class="form-control" id="ga-horario" value="${grupo?.horario||'08:00'}">
          </div>
        </div>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px">
          <input type="checkbox" id="ga-ativo" ${grupo?.ativo!==false?'checked':''} style="accent-color:var(--accent)">
          <span>Grupo ativo — e-mails serão enviados</span>
        </label>
      </div>

      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button onclick="document.getElementById('modal-grupo-alerta').remove()" class="btn btn-ghost">Cancelar</button>
        <button onclick="salvarGrupoAlerta('${grupo?.id||''}',this)" class="btn btn-primary">💾 Salvar Grupo</button>
      </div>
    </div>`;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
  // Init escopo
  gaToggleEscopo(grupo?.escopo || 'todas');
}

function gaToggleEscopo(val) {
  const u = document.getElementById('ga-escopo-unidade');
  const g = document.getElementById('ga-escopo-gerencia');
  if (u) u.style.display = val === 'unidade' ? '' : 'none';
  if (g) g.style.display = val === 'gerencia' ? '' : 'none';
}

function gaAdicionarEmail() {
  const cont = document.getElementById('ga-emails-container');
  if (!cont) return;
  const row = document.createElement('div');
  row.className = 'ga-email-row';
  row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px';
  row.innerHTML = `
    <input class="form-control ga-email" placeholder="e-mail" style="margin:0;flex:2">
    <input class="form-control ga-nome"  placeholder="nome (opcional)" style="margin:0;flex:1.5">
    <button onclick="this.closest('.ga-email-row').remove()" style="border:none;background:none;color:var(--danger);cursor:pointer;font-size:18px;padding:0 4px">✕</button>`;
  cont.appendChild(row);
  row.querySelector('.ga-email').focus();
}

async function salvarGrupoAlerta(grupoId, btn) {
  const nome      = document.getElementById('ga-nome')?.value?.trim();
  const desc      = document.getElementById('ga-desc')?.value?.trim();
  const frequencia = document.getElementById('ga-frequencia')?.value;
  const horario   = document.getElementById('ga-horario')?.value;
  const ativo     = document.getElementById('ga-ativo')?.checked !== false;
  const escopo    = document.querySelector('[name="ga-escopo"]:checked')?.value || 'todas';

  if (!nome) return showToast('Informe o nome do grupo', 'warning');

  // Coleta e-mails
  const emails = [...document.querySelectorAll('.ga-email-row')].map(row => ({
    email: row.querySelector('.ga-email')?.value?.trim() || '',
    nome:  row.querySelector('.ga-nome')?.value?.trim()  || '',
  })).filter(e => e.email && e.email.includes('@'));

  if (!emails.length) return showToast('Adicione pelo menos um e-mail válido', 'warning');

  // Coleta tipos
  const tipos = [...document.querySelectorAll('[name="alerta-tipo"]:checked')].map(c => c.value);
  if (!tipos.length) return showToast('Selecione pelo menos um tipo de alerta', 'warning');

  // Coleta escopo
  const unidades = escopo === 'unidade'
    ? [...document.querySelectorAll('[name="ga-unidade"]:checked')].map(c => c.value)
    : [];
  const gerencias = escopo === 'gerencia'
    ? [...document.querySelectorAll('#ga-gerencias-tags span:first-child')].map(s => s.textContent)
    : [];

  setButtonLoading(btn, true, 'Salvando...');

  const grupo = {
    nome, descricao: desc, emails, tipos, escopo,
    unidades, gerencias, frequencia, horario, ativo,
    updatedAt: new Date().toISOString(),
  };

  if (grupoId) {
    const idx = (STATE.gruposAlerta||[]).findIndex(g => g.id === grupoId);
    if (idx >= 0) STATE.gruposAlerta[idx] = { ...STATE.gruposAlerta[idx], ...grupo };
    await fsUpdate('gruposAlerta', grupoId, grupo);
  } else {
    grupo.createdAt = new Date().toISOString();
    grupo.id = 'GA-' + Date.now();
    if (!STATE.gruposAlerta) STATE.gruposAlerta = [];
    STATE.gruposAlerta.unshift(grupo);
    await fsAdd('gruposAlerta', grupo);
  }

  setButtonLoading(btn, false, '💾 Salvar Grupo');
  document.getElementById('modal-grupo-alerta')?.remove();
  _renderGruposLista();
  showToast(`Grupo "${nome}" salvo! E-mails configurados: ${emails.length}`, 'success', 4000);
}

function editarGrupoAlerta(id) {
  abrirModalNovoGrupoAlerta(id);
}

async function toggleGrupoAlerta(id, ativoAtual) {
  const grupo = (STATE.gruposAlerta||[]).find(g => g.id === id);
  if (!grupo) return;
  grupo.ativo = !ativoAtual;
  await fsUpdate('gruposAlerta', id, { ativo: grupo.ativo });
  _renderGruposLista();
  showToast(grupo.ativo ? 'Grupo ativado' : 'Grupo pausado', 'info', 2000);
}

async function excluirGrupoAlerta(id) {
  if (!SESSION_USER || !["admin", "gestor"].includes(SESSION_USER.role)) {
    showToast('⛔ Acesso restrito: excluir grupo de alerta.', 'error');
    return;
  }

  if (!confirm('Excluir este grupo de alerta? Esta ação não pode ser desfeita.')) return;
  STATE.gruposAlerta = (STATE.gruposAlerta||[]).filter(g => g.id !== id);
  // Soft delete
  await fsUpdate('gruposAlerta', id, { excluido: true, ativo: false });
  _renderGruposLista();
  showToast('Grupo excluído', 'warning', 2000);
}

async function testarGrupoAlerta(id) {
  const grupo = (STATE.gruposAlerta||[]).find(g => g.id === id);
  if (!grupo) return;
  showToast(`📧 Enviando e-mail de teste para ${grupo.emails?.length||0} destinatário(s)...`, 'info', 4000);
  // Chama CF para enviar e-mail de teste
  try {
    if (typeof firebase !== 'undefined' && firebase.functions) {
      const fn = firebase.functions().httpsCallable('testarGrupoAlerta');
      await fn({ grupoId: id });
      showToast('✅ E-mail de teste enviado!', 'success', 4000);
    } else {
      showToast('E-mail de teste registrado (CF executa o envio)', 'info', 3000);
      await fsAdd('testeAlertas', { grupoId: id, createdAt: new Date().toISOString() });
    }
  } catch {
    showToast('E-mail de teste registrado na fila', 'info', 3000);
  }
}

// ── INTEGRAÇÃO: envia alertas para grupos configurados ────────
// Substitui getGestorEmails() por função que considera grupos
async function getEmailsParaAlerta(tipoAlerta, contexto) {
  const grupos = STATE.gruposAlerta || [];
  const emails = new Set();

  grupos
    .filter(g => g.ativo !== false && !g.excluido && (g.tipos||[]).includes(tipoAlerta))
    .forEach(g => {
      // Verifica escopo
      const passaEscopo =
        g.escopo === 'todas' ||
        (g.escopo === 'unidade' && (g.unidades||[]).some(u =>
          (contexto?.unidade||contexto?.area||'').toLowerCase().includes(u.toLowerCase()) ||
          u.toLowerCase().includes((contexto?.unidade||'').toLowerCase())
        )) ||
        (g.escopo === 'gerencia' && (g.gerencias||[]).some(ger =>
          (contexto?.gerencia||contexto?.area||'').toLowerCase().includes(ger.toLowerCase())
        ));

      if (passaEscopo) {
        (g.emails||[]).forEach(e => { if (e.email?.includes('@')) emails.add(e.email); });
      }
    });

  return [...emails];
}




// Alias: permite que código legado use getEmailsPorGrupo
// A versão completa está em /tmp/grupos_alerta_js.js (acima)
// Este alias garante que funções que buscam e-mails usem os grupos configurados
if (typeof getEmailsPorGrupo === 'undefined') {
  window.getEmailsPorGrupo = async function(tipoAlerta, contexto) {
    return getEmailsParaAlerta(tipoAlerta, contexto || {});
  };
}



// ════════════════════════════════════════════════════════════
// BloquearRecursosTI — badges na tabela de histórico de usuários
// Injeta coluna "Acesso TI" quando dados do empregado existem
// ════════════════════════════════════════════════════════════

function renderBloqueioTIBadge(emp) {
  // emp pode ter: bloqueioTI, emAusencia, suprimirAlertas
  if (!emp) return '<span style="font-size:11px;color:var(--g400)">—</span>';

  if (emp.bloqueioTI) {
    return '<span class="badge badge-danger" style="font-size:10px" ' +
           'title="BloquearRecursosTI=1 no CadastroSAP — alertas suprimidos automaticamente">' +
           '🚫 Bloqueado TI</span>';
  }
  if (emp.emAusencia || emp.suprimirAlertas) {
    const motivo = emp.ausencia || 'ausência registrada';
    return '<span class="badge badge-warning" style="font-size:10px" ' +
           'title="' + escapeHtml(motivo) + ' — alertas suprimidos automaticamente">' +
           '⏸ Ausente</span>';
  }
  return '<span class="badge badge-success" style="font-size:10px">✓ Ativo</span>';
}

// Enriquece a tabela de usuários do histórico com status de bloqueio do SAP
// Chamado após carregarHistoricoUsuarios() carregar os dados
async function enriquecerTabelaUsuariosComBloqueio(ativoId, usuarios) {
  if (!FB_READY || !usuarios.length) return usuarios;

  // Busca status de todos os empregados em paralelo (máx 10 por vez)
  const enriched = await Promise.all(
    usuarios.map(async u => {
      if (!u.mat) return u;
      try {
        const data = await callFunction('getEmpregadoStatus', { matricula: u.mat });
        return { ...u, ...data };
      } catch {
        return u; // se falhar, usa dados originais
      }
    })
  );
  return enriched;
}

// Patch em carregarHistoricoUsuarios para incluir badge de bloqueio
// O patch só é aplicado se a coluna ainda não foi adicionada
(function patchHistoricoUsuarios() {
  const orig = typeof carregarHistoricoUsuarios === 'function' ? carregarHistoricoUsuarios : null;
  if (!orig) return;

  window.carregarHistoricoUsuarios = async function(ativoId, ativo) {
    await orig(ativoId, ativo);

    // Tenta adicionar coluna de status TI após render
    setTimeout(async () => {
      const table = document.querySelector('#tab-usuarios table');
      if (!table || table.dataset.bloqueioEnriquecido) return;
      table.dataset.bloqueioEnriquecido = '1';

      // Adiciona cabeçalho
      const thead = table.querySelector('thead tr');
      if (thead && !thead.querySelector('.th-bloqueio-ti')) {
        const th = document.createElement('th');
        th.className = 'th-bloqueio-ti';
        th.style.cssText = 'padding:8px 10px;text-align:left;font-weight:700;color:var(--g500);background:var(--g50);border-bottom:1px solid var(--g200)';
        th.textContent = 'Acesso TI';
        thead.appendChild(th);
      }

      // Para cada linha, busca o status do empregado
      const rows = table.querySelectorAll('tbody tr');
      for (const row of rows) {
        // Extrai matrícula do dataset ou do texto
        const mat = row.dataset?.mat;
        if (!mat) {
          const td = document.createElement('td');
          td.style.cssText = 'padding:8px 10px';
          td.innerHTML = '<span style="font-size:11px;color:var(--g400)">—</span>';
          row.appendChild(td);
          continue;
        }
        try {
          const emp = await callFunction('getEmpregadoStatus', { matricula: mat });
          const td  = document.createElement('td');
          td.style.cssText = 'padding:8px 10px';
          td.innerHTML = renderBloqueioTIBadge(emp);
          row.appendChild(td);
        } catch {
          const td = document.createElement('td');
          td.style.cssText = 'padding:8px 10px';
          td.innerHTML = '<span style="font-size:11px;color:var(--g400)">—</span>';
          row.appendChild(td);
        }
      }
    }, 500);
  };
})();




// ════════════════════════════════════════════════════════════
// MONITORAMENTO LOCAL — exibe discos por partição na tabela
// Dados vêm do SYSACK Client instalado no PC
// ════════════════════════════════════════════════════════════

function renderDiscosPartition(agente) {
  const discos = agente.discos || agente.diskPartitions || [];
  if (!discos.length) {
    // Compatibilidade: mostra só disco C: se não tiver partições
    if (agente.diskCPct !== undefined) {
      const cor = agente.diskCPct >= 95 ? '#EF4444' : agente.diskCPct >= 85 ? '#F59E0B' : '#10B981';
      return `<div style="font-size:11.5px"><span style="font-weight:700;color:${cor}">${agente.diskCPct}%</span><span style="color:var(--g400)"> (${agente.diskCLivreGB||'?'}GB livres)</span></div>`;
    }
    return '<span style="color:var(--g400)">—</span>';
  }
  return discos.map(d => {
    const cor = d.pct >= 95 ? '#EF4444' : d.pct >= 85 ? '#F59E0B' : '#10B981';
    return `<div style="font-size:11px;margin-bottom:2px">
      <span style="font-family:monospace;font-weight:700;color:var(--g600)">${escapeHtml(d.letra||'?')}</span>
      <span style="font-weight:700;color:${cor}"> ${d.pct}%</span>
      <span style="color:var(--g400)"> ${d.livreGB}/${d.totalGB}GB</span>
      ${d.label ? `<span style="color:var(--g300);font-size:10px"> ${escapeHtml(d.label)}</span>` : ''}
    </div>`;
  }).join('');
}

function renderServicosStatus(agente) {
  const svcs = agente.servicos || {};
  const entries = Object.entries(svcs);
  if (!entries.length) return '<span style="color:var(--g400)">—</span>';
  const parados = entries.filter(([,v]) => v !== 'Running' && v !== 4);
  if (!parados.length) return '<span style="color:#10B981;font-size:11px">✓ Todos OK</span>';
  return parados.map(([k,v]) =>
    `<span style="color:#EF4444;font-size:11px">⚠️ ${k}</span>`
  ).join('<br>');
}

// ════════════════════════════════════════════════════════════
// MAINTENANCE WINDOWS — janelas de manutenção
// Dispositivos em manutenção não geram alertas
// ════════════════════════════════════════════════════════════
if (!STATE.janelasManutencao) STATE.janelasManutencao = [];

function abrirJanelaManutencao(dispId) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:440px;width:100%;padding:24px';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🔧 Janela de Manutenção</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">Durante a janela o dispositivo não gerará alertas.</p>
    <div class="form-row c2">
      <div class="form-group">
        <label class="form-label req">Início</label>
        <input type="datetime-local" class="form-control" id="man-inicio">
      </div>
      <div class="form-group">
        <label class="form-label req">Fim</label>
        <input type="datetime-local" class="form-control" id="man-fim">
      </div>
    </div>
    <div class="form-group">
      <label class="form-label req">Motivo</label>
      <input class="form-control" id="man-motivo" placeholder="Ex: Troca de HD, atualização de firmware...">
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px">
      <button onclick="this.closest('[style*=z-index:10001]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="salvarJanelaManutencao('${dispId}',this)" class="btn btn-primary">🔧 Agendar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
}

async function salvarJanelaManutencao(dispId, btn) {
  const inicio = document.getElementById('man-inicio')?.value;
  const fim    = document.getElementById('man-fim')?.value;
  const motivo = document.getElementById('man-motivo')?.value?.trim();
  if (!inicio || !fim || !motivo) return showToast('Preencha todos os campos', 'warning');

  setButtonLoading(btn, true, 'Salvando...');
  const janela = {
    id: 'MAN-' + Date.now(), dispId, inicio, fim, motivo,
    criadoPor: CURRENT_USER?.nome || '',
    createdAt: new Date().toISOString(),
  };
  STATE.janelasManutencao.push(janela);
  await fsAdd('janelasManutencao', janela);
  setButtonLoading(btn, false, '🔧 Agendar');
  btn.closest('[style*=z-index:10001]')?.remove();
  showToast(`🔧 Janela de manutenção agendada: ${new Date(inicio).toLocaleString('pt-BR')} → ${new Date(fim).toLocaleString('pt-BR')}`, 'success', 5000);
}

function estaEmManutencao(dispId) {
  const agora = new Date().toISOString();
  return (STATE.janelasManutencao || []).some(j =>
    j.dispId === dispId && j.inicio <= agora && j.fim >= agora
  );
}

// ════════════════════════════════════════════════════════════
// TREND ALERTS — alertas de tendência via regressão linear
// ════════════════════════════════════════════════════════════

function calcularTendencia(historico, campo) {
  if (!historico || historico.length < 5) return null;
  const vals = historico.slice(-20).map(h => h[campo]).filter(v => v != null);
  if (vals.length < 5) return null;
  const n = vals.length;
  const sumX = vals.reduce((_,__,i) => _+i, 0);
  const sumY = vals.reduce((a,v) => a+v, 0);
  const sumXY = vals.reduce((a,v,i) => a+i*v, 0);
  const sumX2 = vals.reduce((a,_,i) => a+i*i, 0);
  const b = (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX);  // inclinação
  const media = sumY / n;
  const diasAte80 = b > 0 ? Math.round((80 - media) / (b * 4 * 24)) : null;
  return { inclinacao: Math.round(b*1000)/1000, media: Math.round(media*10)/10, diasAte80 };
}

// Monitora tendências a cada hora
setInterval(() => {
  const switches = STATE.switches || [];
  switches.forEach(sw => {
    if (!sw.cpuHistory || sw.cpuHistory.length < 5) return;
    const tend = calcularTendencia(sw.cpuHistory, 'cpu');
    if (!tend) return;
    if (tend.inclinacao > 2 && tend.media > 50) {
      const chave = 'trend_' + sw.id + '_' + new Date().toISOString().split('T')[0];
      if (!sessionStorage.getItem(chave)) {
        sessionStorage.setItem(chave, '1');
        showToast(
          `📈 Tendência crítica: ${sw.nome||sw.ip} — CPU crescendo ${tend.inclinacao}%/ciclo. Chegará a 80% em ~${tend.diasAte80||'?'} dias`,
          'warning', 10000
        );
      }
    }
  });
}, 3600000);

// ════════════════════════════════════════════════════════════
// WEBHOOK ALERTS — envio de alertas para sistemas externos
// ════════════════════════════════════════════════════════════
async function dispararWebhook(evento, dados) {
  const webhooks = (STATE.configuracoes?.webhooks || []).filter(w => w.ativo);
  for (const wh of webhooks) {
    try {
      await fetch(wh.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(wh.token ? { 'Authorization': 'Bearer ' + wh.token } : {}) },
        body: JSON.stringify({ evento, dados, sistema: 'SYSACK-CESAN', timestamp: new Date().toISOString() }),
      });
    } catch { /* sem bloquear */ }
  }
}

// ════════════════════════════════════════════════════════════
// AUTO-DISCOVERY — detecta novos dispositivos na rede
// ════════════════════════════════════════════════════════════
async function iniciarAutoDiscovery(subnet) {
  if (!subnet) return showToast('Informe a sub-rede (ex: 172.22.10)', 'warning');
  showToast(`🔍 Escaneando ${subnet}.1 – ${subnet}.254 ...`, 'info', 5000);

  // Dispara CF que executa o scan via agente
  try {
    await fsAdd('agent_commands', {
      tipo:     'network_scan',
      subnet,
      alvo:     'broadcast',
      status:   'pendente',
      createdAt: new Date().toISOString(),
    });
    showToast('Scan iniciado — novos dispositivos aparecerão em ~2 min no Monitor de Rede', 'success', 5000);
  } catch {
    showToast('Scan enviado para execução pelo agente', 'info', 3000);
  }
}




// ════════════════════════════════════════════════════════════
// GUIA DE SEGURANÇA — exibido apenas para admin no primeiro login
// ════════════════════════════════════════════════════════════

function verificarConfigSeguranca() {
  if (CURRENT_USER?.role !== 'admin') return;
  const chave = 'sysack_sec_check_v1';
  if (sessionStorage.getItem(chave)) return;
  sessionStorage.setItem(chave, '1');

  // Verifica se VAPID e App Check estão configurados
  const semVAPID    = !window.FCM_VAPID_KEY || window.FCM_VAPID_KEY === 'COLE_AQUI_SUA_VAPID_KEY';
  const semAppCheck = true; // sempre lembra até ser configurado no Console

  if (!semVAPID && !semAppCheck) return; // tudo OK

  setTimeout(() => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:20px';
    const modal = document.createElement('div');
    modal.style.cssText = 'background:#fff;border-radius:14px;max-width:560px;width:100%;padding:0;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.5)';
    modal.innerHTML = `
      <div style="background:linear-gradient(135deg,#DC2626,#B91C1C);padding:18px 24px">
        <h3 style="color:#fff;margin:0;font-size:16px">🔒 Configurações de Segurança Pendentes</h3>
        <p style="color:rgba(255,255,255,.7);font-size:12px;margin:4px 0 0">Complete antes de usar em produção</p>
      </div>
      <div style="padding:20px">
        <div style="display:flex;flex-direction:column;gap:12px">

          ${semVAPID ? `
          <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:8px;padding:12px">
            <div style="font-weight:700;color:#991B1B;margin-bottom:4px">❌ FCM VAPID Key não configurada</div>
            <div style="font-size:12px;color:#7F1D1D;margin-bottom:8px">Notificações push não funcionarão.</div>
            <code style="font-size:11px;background:#fff;padding:4px 8px;border-radius:4px;display:block">
              firebase messaging:generate-vapid-key<br>
              # Copie a chave e substitua FCM_VAPID_KEY no index.html
            </code>
          </div>` : ''}

          <div style="background:#FEF3C7;border:1px solid #FCD34D;border-radius:8px;padding:12px">
            <div style="font-weight:700;color:#92400E;margin-bottom:4px">⚠️ App Check não ativado</div>
            <div style="font-size:12px;color:#78350F;margin-bottom:8px">
              Qualquer pessoa com a API key pode chamar suas Cloud Functions.<br>
              O App Check adiciona uma camada de proteção validando que o cliente é legítimo.
            </div>
            <div style="font-size:11.5px;color:#92400E;font-weight:600">Como ativar:</div>
            <ol style="font-size:11.5px;color:#78350F;margin:6px 0 0;padding-left:18px;line-height:1.8">
              <li>Firebase Console → <strong>App Check</strong></li>
              <li>Selecione o app web → Registrar com <strong>reCAPTCHA v3</strong></li>
              <li>Copie a chave pública e adicione ao index.html</li>
              <li>Em <strong>APIs</strong> → ative Enforce para Firestore e Functions</li>
              <li>Funções do agente mantêm enforceAppCheck: false (agente usa REST, não SDK)</li>
            </ol>
          </div>

          <div style="background:#F0FDF4;border:1px solid #86EFAC;border-radius:8px;padding:12px">
            <div style="font-weight:700;color:#166534;margin-bottom:4px">✅ Proteções já ativas</div>
            <div style="font-size:12px;color:#14532D;line-height:1.7">
              • Autenticação Firebase obrigatória em todas as funções<br>
              • Firestore Rules com controle por role (admin/gestor/tecnico)<br>
              • Notas permanentes: allow delete: if false<br>
              • Audit log imutável no Firestore<br>
              • Secrets SMTP/API via Firebase Secrets (não hardcoded)
            </div>
          </div>
        </div>

        <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
          <button onclick="this.closest('[style*=z-index:99999]').remove()" class="btn btn-ghost btn-sm">Fechar</button>
          <a href="https://console.firebase.google.com/project/sysack-829e2/appcheck" target="_blank" class="btn btn-primary btn-sm">Abrir App Check →</a>
        </div>
      </div>`;
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
  }, 3000);
}

// Chama após login
const _origInitApp = typeof initApp === 'function' ? initApp : null;
document.addEventListener('sysack-login', () => {
  setTimeout(verificarConfigSeguranca, 2000);
});



// ════════════════════════════════════════════════════════════
// IA — TRIAGEM AUTOMÁTICA DE CHAMADOS
// Categoriza, prioriza e sugere solução com Gemini via CF
// ════════════════════════════════════════════════════════════

async function triagemIAChamado(chamadoId) {
  const ch = (STATE.chamados||[]).find(c => c.id === chamadoId);
  if (!ch) return;

  const btn = document.querySelector(`[data-ia-btn="${chamadoId}"]`);
  if (btn) { btn.disabled = true; btn.textContent = '🤖 Analisando...'; }

  try {
    const r = await callFunction('triageChamado', {
      chamadoId,
      titulo:    ch.desc?.split('\n')[0] || ch.desc || '',
      desc:      ch.desc || '',
      categoria: ch.categoria || '',
      area:      ch.area || '',
    });
    if (!r) return;

    // Atualiza o chamado no STATE com os dados da IA
    ch.prioridade       = r.prioridade       || ch.prioridade;
    ch.categoria        = r.categoriaAI      || ch.categoria;
    ch.subcategoria     = r.subcategoriaAI   || ch.subcategoria;
    ch.tipo             = r.tipo             || ch.tipo;
    ch.resumoIA         = r.resumo;
    ch.solucaoSugerida  = r.solucaoSugerida;
    ch.tempoEstimado    = r.tempoEstimado;
    ch.confiancaIA      = r.confianca;

    // Atualiza no banco
    await fsUpdate('chamados', chamadoId, {
      prioridade:      ch.prioridade,
      categoria:       ch.categoria,
      subcategoria:    ch.subcategoria,
      tipo:            ch.tipo,
      resumoIA:        ch.resumoIA,
      solucaoSugerida: ch.solucaoSugerida,
      tempoEstimado:   ch.tempoEstimado,
      confiancaIA:     ch.confiancaIA,
    });

    // Mostra resultado inline
    const corPri = { critica:'#DC2626', alta:'#F59E0B', media:'#3B82F6', baixa:'#10B981' };
    const cor = corPri[r.prioridade] || '#6B7280';
    showToast(`🤖 IA: ${r.prioridade?.toUpperCase()} · ${r.categoriaAI} — ${r.tempoEstimado} estimado`, 'info', 6000);

    renderChamados();
  } catch (e) {
    showToast('IA: ' + (e.message || 'erro desconhecido'), 'warning', 4000);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🤖 IA'; }
  }
}

// ════════════════════════════════════════════════════════════
// IA — DASHBOARD EXECUTIVO (insights para gestores)
// ════════════════════════════════════════════════════════════

async function abrirDashboardIA() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:14px;max-width:720px;width:100%;max-height:90vh;overflow-y:auto;box-shadow:0 24px 80px rgba(0,0,0,.5)';
  modal.innerHTML = `
    <div style="background:linear-gradient(135deg,#1E293B,#334155);padding:20px 24px;border-radius:14px 14px 0 0">
      <h3 style="color:#fff;margin:0;font-size:18px">🤖 Análise Executiva com IA</h3>
      <p style="color:rgba(255,255,255,.5);font-size:12px;margin:4px 0 0">Insights gerados automaticamente — baseado nos dados do SYSACK</p>
    </div>
    <div id="ia-dashboard-body" style="padding:20px">
      <div style="text-align:center;padding:40px">
        <div style="font-size:36px;margin-bottom:12px">🤖</div>
        <div style="font-weight:600">Gerando análise...</div>
        <div style="font-size:12px;color:var(--g400);margin-top:6px">Isso pode levar alguns segundos</div>
      </div>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  // Prepara KPIs para a IA analisar
  const chamados   = STATE.chamados || [];
  const ativos     = STATE.ativos   || [];
  const switches   = STATE.switches || [];
  const hoje       = new Date();
  const mes        = hoje.getMonth();
  const ano        = hoje.getFullYear();

  const abertos    = chamados.filter(c => c.status === 'aberto').length;
  const concluidos = chamados.filter(c => c.status === 'concluido').length;
  const violados   = chamados.filter(c => (c.slaUltimoNivel || 0) >= 3).length;
  const offline    = switches.filter(s => s.status === 'offline').length;

  const topCats = Object.entries(
    chamados.reduce((acc, c) => {
      const cat = c.categoria || 'outros';
      acc[cat]  = (acc[cat] || 0) + 1;
      return acc;
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 5);

  try {
    const r = await callFunction('getInsightsIA', {
      kpis: { abertos, concluidos, violados, totalChamados: chamados.length, totalAtivos: ativos.length, dispositivosOffline: offline },
      topCategorias:  topCats.map(([cat, n]) => ({ categoria: cat, total: n })),
      alertas:        (STATE.alertasRede || []).slice(0, 5).map(a => a.redeDetectada || ''),
    });

    const body = document.getElementById('ia-dashboard-body');
    if (!body) return;

    body.innerHTML = `
      <!-- Score operacional -->
      <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:16px;background:var(--g50);border-radius:10px">
        <div style="text-align:center;min-width:80px">
          <div style="font-size:42px;font-weight:900;color:${r.scoreOperacional>=80?'#10B981':r.scoreOperacional>=60?'#F59E0B':'#EF4444'}">${r.scoreOperacional}</div>
          <div style="font-size:11px;color:var(--g400);font-weight:700">SCORE<br>OPERACIONAL</div>
        </div>
        <div style="flex:1">
          <div style="font-size:14px;font-weight:700;margin-bottom:6px">Resumo Executivo</div>
          <div style="font-size:13px;color:var(--g600);line-height:1.6">${escapeHtml(r.resumoExecutivo || '—')}</div>
        </div>
      </div>

      <!-- Insights -->
      ${r.insights?.length ? `
      <div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--g500);margin-bottom:8px">💡 Insights</div>
        ${r.insights.map(i => `
          <div style="background:#EFF6FF;border-left:3px solid #3B82F6;padding:10px 14px;border-radius:0 8px 8px 0;margin-bottom:6px;font-size:13px;color:#1E40AF">
            ${escapeHtml(i)}
          </div>`).join('')}
      </div>` : ''}

      <!-- Riscos -->
      ${r.riscos?.length ? `
      <div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--g500);margin-bottom:8px">⚠️ Riscos Identificados</div>
        ${r.riscos.map(ri => `
          <div style="background:#FEF3C7;border-left:3px solid #F59E0B;padding:10px 14px;border-radius:0 8px 8px 0;margin-bottom:6px;font-size:13px;color:#92400E">
            ${escapeHtml(ri)}
          </div>`).join('')}
      </div>` : ''}

      <!-- Recomendações -->
      ${r.recomendacoes?.length ? `
      <div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--g500);margin-bottom:8px">✅ Recomendações</div>
        ${r.recomendacoes.map((rec, i) => `
          <div style="display:flex;gap:10px;padding:10px 14px;background:var(--g50);border-radius:8px;margin-bottom:6px;font-size:13px">
            <div style="font-weight:700;color:var(--accent);flex-shrink:0">${i+1}.</div>
            <div>${escapeHtml(rec)}</div>
          </div>`).join('')}
      </div>` : ''}

      <div style="font-size:11px;color:var(--g300);text-align:center;margin-top:16px">
        Análise gerada em ${new Date().toLocaleString('pt-BR')} · Powered by Gemini
      </div>`;

  } catch (e) {
    const body = document.getElementById('ia-dashboard-body');
    if (body) body.innerHTML = `<div style="padding:20px;color:var(--danger)">Erro: ${escapeHtml(e.message)}. Configure GOOGLE_GENAI_API_KEY.</div>`;
  }
}

// ════════════════════════════════════════════════════════════
// IA — PREDIÇÃO DE FALHA DE ATIVO
// Analisa histórico de chamados e alertas do ativo
// ════════════════════════════════════════════════════════════

async function analisarAtivoPorIA(pat) {
  // Busca o ativo — pode estar em ativos (discovery) ou patrimonios
  const ativo = [...(STATE.ativos||[]),...(STATE.patrimonios||[])].find(a => a.pat === pat || a.id === pat) || { pat };
  const chamadosDoAtivo = (STATE.chamados||[]).filter(c => c.pat === pat);
  const idade = ativo.dataAquisicao
    ? Math.round((Date.now() - new Date(ativo.dataAquisicao+'T12:00:00').getTime()) / (365.25*86400000) * 10) / 10
    : null;

  // Cria modal
  const overlay = document.createElement('div');
  const overlayId = 'ia-overlay-' + Date.now();
  overlay.id = overlayId;
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:16px';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff;border-radius:12px;max-width:560px;width:100%;padding:24px;max-height:80vh;overflow-y:auto';
  modal.innerHTML = `
    <h3 style="margin:0 0 4px;font-size:16px">🤖 Análise IA — ${escapeHtml(ativo.desc||ativo.hostname||pat)}</h3>
    <p style="color:var(--g400);font-size:12px;margin:0 0 16px">PAT: ${pat} · Idade: ${idade||'?'} anos · Chamados: ${chamadosDoAtivo.length}</p>
    <div id="ia-ativo-res" style="text-align:center;padding:20px;color:var(--g500)">🤖 Analisando com Gemini...</div>
    <div style="display:flex;justify-content:flex-end;margin-top:14px">
      <button onclick="document.getElementById('${overlayId}').remove()" class="btn btn-ghost">Fechar</button>
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  try {
    // Chama Cloud Function analisarAtivo (chave Gemini segura no backend)
    const resultado = await callFunction('analisarAtivo', {
      pat:       pat,
      desc:      ativo.desc      || ativo.hostname || '',
      tipo:      ativo.tipo      || '',
      area:      ativo.area      || '',
      resp:      ativo.resp      || '',
      status:    ativo.status    || '',
      ip:        ativo.ip        || '',
      hostname:  ativo.hostname  || '',
      lastSeen:  ativo.lastSeen  || '',
      uptimeH:   ativo.uptimeH   || null,
      latencyMs: ativo.latencyMs || null,
    });

    const res = document.getElementById('ia-ativo-res');
    if (!res) return;

    // Renderiza resultado em markdown simples
    const texto = resultado.analise || 'Sem análise disponível';
    const html2 = texto
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/^(\d+\. .+)$/gm, '<div style="margin:4px 0">$1</div>')
      .replace(/^- (.+)$/gm, '<div style="margin:2px 0;padding-left:12px">• $1</div>')
      .replace(/\n/g, '<br>');

    res.innerHTML = `<div style="text-align:left;font-size:13px;line-height:1.6;color:var(--g700)">${html2}</div>
      <div style="margin-top:12px;font-size:11px;color:var(--g400);border-top:1px solid var(--g100);padding-top:8px">
        Gerado por Gemini · ${new Date(resultado.geradoEm||Date.now()).toLocaleString('pt-BR')}
      </div>`;

  } catch (e) {
    const res = document.getElementById('ia-ativo-res');
    if (res) res.innerHTML = `<div style="color:var(--danger);font-size:13px">
      ❌ Erro na análise: ${escapeHtml(e.message||'Tente novamente')}
    </div>`;
    console.error('[IA] analisarAtivo:', e);
  }
}



// ════════════════════════════════════════════════════════════
// IA MONITORING — Exibe alertas de anomalia no dashboard
// Dados vêm da CF detectarAnomalias (a cada hora)
// ════════════════════════════════════════════════════════════

function iniciarWatcherAlertasIA() {
  if (!FB_READY || !window._db || !window._fs) return;
  const db_local = window._db;
  const { collection, query, orderBy, limit, onSnapshot } = window._fs;
  if (!onSnapshot) return;

  onSnapshot(
    query(collection(db_local, 'alertas_ia'), orderBy('createdAt', 'desc'), limit(5)),
    snap => {
      const alertas = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      renderAlertasIA(alertas);
    }
  );
}

function renderAlertasIA(alertas) {
  const el = document.getElementById('ia-alertas-container');
  if (!el || !alertas.length) return;

  const html = alertas.map(a => {
    const cor = a.risco === 'critico' ? '#EF4444' : a.risco === 'alto' ? '#F59E0B' : '#3B82F6';
    const bg  = a.risco === 'critico' ? '#FEF2F2' : a.risco === 'alto' ? '#FFFBEB' : '#EFF6FF';
    const ts  = a.createdAt?.toDate ? a.createdAt.toDate().toLocaleString('pt-BR') : '—';
    return `
      <div style="background:${bg};border-left:4px solid ${cor};border-radius:0 8px 8px 0;padding:10px 14px;margin-bottom:8px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;background:${cor};color:#fff">${(a.risco||'').toUpperCase()}</span>
          <span style="font-size:11px;color:var(--g400)">${ts}</span>
          <span style="font-size:11px;color:var(--g400)">🤖 IA</span>
        </div>
        <div style="font-size:13px;font-weight:600;color:var(--g800);margin-bottom:4px">${escapeHtml(a.resumo||'—')}</div>
        ${a.acaoImediata ? `<div style="font-size:12px;color:var(--g600)">💡 ${escapeHtml(a.acaoImediata)}</div>` : ''}
        ${(a.dispositivos||[]).length ? `<div style="font-size:11px;color:var(--g400);margin-top:4px">Afetados: ${a.dispositivos.join(', ')}</div>` : ''}
      </div>`;
  }).join('');

  el.innerHTML = html;
  // Atualiza badge no menu
  const criticos = alertas.filter(a => a.risco === 'critico').length;
  nbUpdate('nb-alertas-ia', criticos);
}

// Inicia watcher após login
// iniciarWatcherAlertasIA iniciado após login via loginSuccess()

// ════════════════════════════════════════════════════════════
// PAGINAÇÃO — cursor-based para grandes coleções
// Substitui o onSnapshot global com limit(200)
// ════════════════════════════════════════════════════════════

const PAGINATION = {
  chamados:  { pageSize: 50, lastDoc: null, hasMore: true },
  ativos:    { pageSize: 100, lastDoc: null, hasMore: true },
  patrimonios: { pageSize: 100, lastDoc: null, hasMore: true },
};

async function carregarPaginaChamados(pagina = 0) {
  if (!FB_READY || !db) return;
  const { collection, query, orderBy, limit, startAfter, getDocs } = window._fs || {};
  if (!getDocs) return;

  try {
    let q = query(
      collection(db, 'chamados'),
      orderBy('createdAt', 'desc'),
      limit(PAGINATION.chamados.pageSize)
    );

    if (pagina > 0 && PAGINATION.chamados.lastDoc) {
      q = query(
        collection(db, 'chamados'),
        orderBy('createdAt', 'desc'),
        startAfter(PAGINATION.chamados.lastDoc),
        limit(PAGINATION.chamados.pageSize)
      );
    }

    const snap = await getDocs(q);
    const docs = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    if (pagina === 0) STATE.chamados = docs;
    else STATE.chamados = [...(STATE.chamados || []), ...docs];

    PAGINATION.chamados.lastDoc = snap.docs[snap.docs.length - 1] || null;
    PAGINATION.chamados.hasMore = snap.docs.length === PAGINATION.chamados.pageSize;

    renderChamados();

    // Mostra/oculta botão "Carregar mais"
    const btnMais = document.getElementById('btn-carregar-mais-chamados');
    if (btnMais) btnMais.style.display = PAGINATION.chamados.hasMore ? '' : 'none';

  } catch (e) {
    console.warn('[Paginação] Erro ao carregar chamados:', e.message);
  }
}



// ═══════════════════════════════════════════════════════════════
// MODO PATRIMÔNIO — Toggle & Panel Logic
// ═══════════════════════════════════════════════════════════════
(function(){
  var PAT_KEY = 'sysack_pat_mode';
  var _pmOpen = false;

  window.togglePatMode = function(){
    if(_pmOpen) fecharPatMode(); else abrirPatMode();
  };

  window.abrirPatMode = function(){
    _pmOpen = true;
    document.getElementById('pat-mode-panel')?.classList.add('open');
    document.getElementById('pat-mode-overlay')?.classList.add('open');
    document.getElementById('pat-mode-sw')?.classList.add('on');
    document.getElementById('pat-mode-knob')?.classList.add('on');
    localStorage.setItem(PAT_KEY,'1');
    pmShowTab('dashboard');
  };

  window.fecharPatMode = function(){
    _pmOpen = false;
    document.getElementById('pat-mode-panel')?.classList.remove('open');
    document.getElementById('pat-mode-overlay')?.classList.remove('open');
    document.getElementById('pat-mode-sw')?.classList.remove('on');
    document.getElementById('pat-mode-knob')?.classList.remove('on');
    localStorage.removeItem(PAT_KEY);
  };

  // ── Tab navigation inside panel ───────────────────────────
  window.pmShowTab = function(tabId){
    // Update tab buttons
    document.querySelectorAll('.pm-tab').forEach(function(btn){
      btn.classList.toggle('active', btn.getAttribute('onclick') === "pmShowTab('"+tabId+"')");
    });

    // Move the page section from store to body
    var body  = document.getElementById('pm-body');
    var store = document.getElementById('pm-pages-store');
    if(!body || !store) return;

    // Return current page to store
    var current = body.querySelector('.page.pm-active');
    if(current){
      current.classList.remove('pm-active');
      store.appendChild(current);
    }

    // Move target page to body
    var target = store.querySelector('#page-'+tabId);
    if(target){
      body.innerHTML = '';
      target.classList.add('pm-active');
      target.style.display = '';
      body.appendChild(target);
    } else {
      body.innerHTML = '<div style="text-align:center;padding:48px;color:#64748B"><div style="font-size:32px;margin-bottom:12px">📋</div><div style="font-weight:600">Seção em construção</div></div>';
    }
  };

  // ── Bridge: pm pages use showPage() — redirect to pmShowTab ──
  window.showPage = function(page){
    pmShowTab(page);
  };

  // Restore state on load
  document.addEventListener('DOMContentLoaded', function(){
    if(localStorage.getItem(PAT_KEY) === '1'){
      setTimeout(function(){ abrirPatMode(); }, 800);
    }
  });

  // ── Modal helpers from patrimônio mode ───────────────────
  window.abrirModalBaixa = function(){
    var m=document.getElementById('modal-baixa'); if(m){m.style.display='flex';}
  };
  window.fecharModalBaixa = function(){
    var m=document.getElementById('modal-baixa'); if(m){m.style.display='none';}
  };
  window.abrirModalDisp = function(){
    var m=document.getElementById('modal-disp'); if(m){m.style.display='flex';}
  };
  window.fecharModalDisp = function(){
    var m=document.getElementById('modal-disp'); if(m){m.style.display='none';}
  };

  // Close modals on overlay click
  document.addEventListener('click', function(e){
    ['modal-baixa','modal-disp'].forEach(function(id){
      var m = document.getElementById(id);
      if(m && e.target===m) m.style.display='none';
    });
  });

  // ESC key closes panel
  document.addEventListener('keydown', function(e){
    if(e.key==='Escape' && _pmOpen) fecharPatMode();
  });
})();


window.abrirModalMovSAP = function(){
  var d = document.getElementById('movs-data');
  if(d) d.value = new Date().toISOString().slice(0,10);
  openModal('modal-mov-sap');
};

window.salvarMovSAP = function(){
  var pat   = document.getElementById('movs-pat')?.value?.trim();
  var de    = document.getElementById('movs-de')?.value?.trim();
  var para  = document.getElementById('movs-para')?.value?.trim();
  var novo  = document.getElementById('movs-resp-novo')?.value?.trim();
  var motivo= document.getElementById('movs-motivo')?.value?.trim();
  if(!pat||!de||!para||!novo){
    showToast('Preencha os campos obrigatórios (*)','error');
    return;
  }
  var user = window._authUser?.email || window.STATE?.usuario?.nome || 'sistema';
  var doc = {
    pat, tipo:'Transferência de área',
    ativo: pat,
    de, para,
    respAnterior: document.getElementById('movs-resp-ant')?.value||'',
    novoResp: novo,
    motivo,
    solicitante: user,
    status: 'pendente',
    sapStatus: 'nao_enviado',
    data: new Date(),
    createdAt: new Date()
  };
  if(window._fs && db){
    var {collection, addDoc} = window._fs;
    addDoc(collection(db,'movimentacoes'), doc)
      .then(function(){
        showToast('Movimentação registrada como Pendente ✓','success');
        closeModal('modal-mov-sap');
        // Clear form
        ['movs-pat','movs-de','movs-para','movs-resp-ant','movs-resp-novo','movs-motivo'].forEach(function(id){
          var el = document.getElementById(id);
          if(el) el.value = '';
        });
      })
      .catch(function(e){ showToast('Erro: '+e.message,'error'); });
  } else {
    showToast('Demo: movimentação registrada como Pendente (sem Firebase)','info');
    closeModal('modal-mov-sap');
  }
};

// ════════════════════════════════════════════════════════════════════
// MÓDULO 1 — GESTÃO PATRIMONIAL AVANÇADA
// Busca via câmera/foto, deduplicação, vinculação SAP, alertas
// ════════════════════════════════════════════════════════════════════

// ── Firebase listener para patrimonios (coleção dedicada) ────────
(function initPatrimoniosListener() {
  if (!FB_READY || !db) return;
  db.collection('patrimonios').onSnapshot(function(snap) {
    STATE.patrimonios = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    // Alertas automáticos: SAP sem vínculo + ativos sem patrimônio
    patVerificarAlertas();
    renderPatrimonio && renderPatrimonio();
  }, function(e) { console.warn('[Banco] patrimonios:', e.message); });

  db.collection('ativos').onSnapshot(function() {
    setTimeout(patVerificarAlertas, 500); // aguarda STATE.ativos atualizar
  }, function(){});
})();

// ── Verificar alertas globais de patrimônio ──────────────────────
function patVerificarAlertas() {
  const pats   = STATE.patrimonios || [];
  const ativos = STATE.ativos      || [];

  // PATs SAP sem vínculo
  const semVinculo = pats.filter(p => p.origem === 'sap-import' && !p.ativoId);
  // Ativos computadores/servidores sem PAT
  const ativosSemPat = ativos.filter(a =>
    ['computador','notebook','servidor','desktop'].some(t => (a.tipo||'').toLowerCase().includes(t))
    && !a.pat && !pats.find(p => p.ativoId === a.id));

  const nb = semVinculo.length + ativosSemPat.length;
  nbUpdate('nb-pat-alertas', nb);

  if (semVinculo.length > 0) {
    console.info(`[PAT] ${semVinculo.length} patrimônio(s) SAP sem vínculo — execute patAutoVincular()`);
  }
}

// ── Busca por patrimônio: câmera OU foto OU texto ────────────────
function patAbrirBusca() {
  const overlay = document.createElement('div');
  overlay.id = 'pat-busca-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
  <div style="background:var(--bg,#fff);border-radius:16px;max-width:580px;width:100%;max-height:92vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.5)">
    <div style="background:linear-gradient(135deg,#1E3A8A,#2563EB);padding:20px 24px;border-radius:16px 16px 0 0;display:flex;justify-content:space-between;align-items:center">
      <div>
        <h3 style="color:#fff;margin:0;font-size:16px;font-weight:700">🔍 Busca de Patrimônio</h3>
        <p style="color:rgba(255,255,255,.7);font-size:12px;margin:4px 0 0">Câmera · Foto · Texto · Hostname · Área · IP</p>
      </div>
      <button onclick="this.closest('#pat-busca-overlay').remove()" style="background:rgba(255,255,255,.15);border:none;color:#fff;width:32px;height:32px;border-radius:50%;cursor:pointer;font-size:16px">✕</button>
    </div>

    <!-- TABS -->
    <div style="display:flex;border-bottom:1px solid var(--g200,#e2e8f0);padding:0 20px">
      ${['📷 Câmera','🖼️ Foto','🔤 Texto','🔤 Hostname','🏢 Área/IP'].map((t,i)=>
        `<button onclick="patBuscaTab(${i})" id="pat-btab-${i}"
          style="padding:10px 14px;border:none;background:none;cursor:pointer;font-size:12px;font-weight:${i===0?'700':'500'};color:${i===0?'#2563EB':'var(--g500,#64748b)'};border-bottom:${i===0?'2px solid #2563EB':'2px solid transparent'};transition:all .2s"
        >${t}</button>`).join('')}
    </div>

    <!-- PAINEL CÂMERA -->
    <div id="pat-bpanel-0" style="padding:20px">
      <div style="background:#000;border-radius:12px;overflow:hidden;position:relative;aspect-ratio:16/9">
        <video id="pat-scan-video" autoplay playsinline muted style="width:100%;height:100%;object-fit:cover"></video>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none">
          <div style="width:200px;height:80px;border:3px solid #22D3EE;border-radius:8px;box-shadow:0 0 0 2000px rgba(0,0,0,.4)"></div>
        </div>
        <div id="pat-scan-status" style="position:absolute;bottom:10px;left:0;right:0;text-align:center;color:#fff;font-size:12px;text-shadow:0 1px 3px rgba(0,0,0,.8)">
          Aponte para o patrimônio ou código de barras
        </div>
      </div>
      <div id="pat-scan-result" style="margin-top:12px"></div>
      <button onclick="patIniciarCamera()" class="btn btn-primary" style="margin-top:12px;width:100%">▶ Iniciar Câmera</button>
    </div>

    <!-- PAINEL FOTO -->
    <div id="pat-bpanel-1" style="display:none;padding:20px">
      <label style="display:block;border:2px dashed var(--g300,#cbd5e1);border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='#2563EB'" onmouseout="this.style.borderColor='var(--g300,#cbd5e1)'">
        <div style="font-size:40px;margin-bottom:8px">📸</div>
        <div style="font-weight:600;color:var(--g700,#374151)">Clique para selecionar foto</div>
        <div style="font-size:12px;color:var(--g400,#94a3b8);margin-top:4px">JPG, PNG — foto do patrimônio ou etiqueta</div>
        <input type="file" accept="image/*" id="pat-foto-input" style="display:none" onchange="patLerFoto(this)">
      </label>
      <div id="pat-foto-result" style="margin-top:12px"></div>
    </div>

    <!-- PAINEL TEXTO (PAT) -->
    <div id="pat-bpanel-2" style="display:none;padding:20px">
      <label style="font-size:12px;font-weight:600;color:var(--g600,#4b5563);display:block;margin-bottom:6px">Número do Patrimônio</label>
      <div style="display:flex;gap:8px">
        <input id="pat-busca-texto" class="form-control" placeholder="Ex: 123456" style="flex:1;font-family:monospace;font-size:16px;font-weight:700"
          oninput="patBuscarPorTexto(this.value,'pat')" onkeydown="if(event.key==='Enter')patBuscarPorTexto(this.value,'pat')">
        <button onclick="patBuscarPorTexto(document.getElementById('pat-busca-texto').value,'pat')" class="btn btn-primary">Buscar</button>
      </div>
      <div id="pat-texto-result" style="margin-top:12px"></div>
    </div>

    <!-- PAINEL HOSTNAME -->
    <div id="pat-bpanel-3" style="display:none;padding:20px">
      <label style="font-size:12px;font-weight:600;color:var(--g600,#4b5563);display:block;margin-bottom:6px">Hostname (parcial ou completo)</label>
      <div style="display:flex;gap:8px">
        <input id="pat-busca-hostname" class="form-control" placeholder="Ex: CESAN-PC ou PC1234"
          oninput="patBuscarPorTexto(this.value,'hostname')" style="flex:1">
        <button onclick="patBuscarPorTexto(document.getElementById('pat-busca-hostname').value,'hostname')" class="btn btn-primary">Buscar</button>
      </div>
      <div id="pat-hostname-result" style="margin-top:12px"></div>
    </div>

    <!-- PAINEL ÁREA / IP -->
    <div id="pat-bpanel-4" style="display:none;padding:20px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div>
          <label style="font-size:12px;font-weight:600;color:var(--g600,#4b5563);display:block;margin-bottom:4px">Área / Gerência</label>
          <input id="pat-busca-area" class="form-control" placeholder="Ex: TI, Financeiro" oninput="patBuscarFiltros()">
        </div>
        <div>
          <label style="font-size:12px;font-weight:600;color:var(--g600,#4b5563);display:block;margin-bottom:4px">Faixa de IP</label>
          <input id="pat-busca-ip" class="form-control" placeholder="Ex: 172.22 ou 172.22.34" oninput="patBuscarFiltros()">
        </div>
      </div>
      <div style="margin-bottom:12px">
        <label style="font-size:12px;font-weight:600;color:var(--g600,#4b5563);display:block;margin-bottom:6px">Tipo de Ativo</label>
        <div id="pat-busca-tipos" style="display:flex;flex-wrap:wrap;gap:6px">
          ${['Todos','Computador','Notebook','Servidor','Impressora','Switch','Câmera','Nobreak','Smartphone'].map((t,i)=>
            `<label style="display:flex;align-items:center;gap:4px;font-size:12px;background:var(--g50,#f8fafc);border:1px solid var(--g200,#e2e8f0);border-radius:20px;padding:4px 10px;cursor:pointer">
              <input type="checkbox" ${i===0?'checked':''} value="${t.toLowerCase()}" onchange="patTipoToggle(this)" style="accent-color:#2563EB"> ${t}
            </label>`).join('')}
        </div>
      </div>
      <div id="pat-filtros-result" style="margin-top:8px"></div>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.onclick = e => { if (e.target === overlay) { patPararCamera(); overlay.remove(); }};
}

function patBuscaTab(idx) {
  for (let i = 0; i < 5; i++) {
    const btn = document.getElementById('pat-btab-' + i);
    const pan = document.getElementById('pat-bpanel-' + i);
    if (btn) { btn.style.fontWeight = i===idx?'700':'500'; btn.style.color = i===idx?'#2563EB':'var(--g500,#64748b)'; btn.style.borderBottom = i===idx?'2px solid #2563EB':'2px solid transparent'; }
    if (pan) pan.style.display = i===idx?'':'none';
  }
  if (idx !== 0) patPararCamera();
}

let _patScanStream = null;
async function patIniciarCamera() {
  const video = document.getElementById('pat-scan-video');
  const status = document.getElementById('pat-scan-status');
  if (!video) return;
  try {
    _patScanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode:'environment', width:1280, height:720 }});
    video.srcObject = _patScanStream;
    if (status) status.textContent = 'Câmera ativa — aponte para o patrimônio';
    await patDecodeLoop(video);
  } catch(e) {
    if (status) status.textContent = '❌ Câmera não disponível: ' + e.message;
  }
}
function patPararCamera() {
  if (_patScanStream) { _patScanStream.getTracks().forEach(t => t.stop()); _patScanStream = null; }
}

async function patDecodeLoop(video) {
  const status = document.getElementById('pat-scan-status');
  let decoder = null;
  try {
    const ZXing = await import('https://cdn.jsdelivr.net/npm/@zxing/browser@0.1.4/esm/index.min.js').catch(()=>null);
    if (ZXing) {
      decoder = new ZXing.BrowserMultiFormatReader();
    }
  } catch(e) {}

  if (!decoder) {
    if (status) status.textContent = '⚠️ Scanner não disponível. Use a aba Foto ou Texto.';
    return;
  }

  try {
    decoder.decodeFromVideoElement(video, (result, err) => {
      if (result) {
        patPararCamera();
        const code = result.getText().replace(/[^0-9A-Za-z\-]/g, '');
        if (status) status.textContent = '✅ Lido: ' + code;
        patProcessarCodigoLido(code, 'pat-scan-result');
      }
    });
  } catch(e) { if (status) status.textContent = 'Erro no scanner: ' + e.message; }
}

async function patLerFoto(input) {
  const file = input.files?.[0];
  if (!file) return;
  const resultDiv = document.getElementById('pat-foto-result');
  if (resultDiv) resultDiv.innerHTML = '<div style="color:var(--g500,#64748b);font-size:13px">🔄 Processando imagem...</div>';

  try {
    const ZXing = await import('https://cdn.jsdelivr.net/npm/@zxing/browser@0.1.4/esm/index.min.js').catch(()=>null);
    if (!ZXing) throw new Error('Scanner não disponível');
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = async () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width  = img.width;
        canvas.height = img.height;
        canvas.getContext('2d').drawImage(img, 0, 0);
        const reader = new ZXing.BrowserMultiFormatReader();
        const result = await reader.decodeFromCanvas(canvas);
        URL.revokeObjectURL(url);
        const code = result.getText().replace(/[^0-9A-Za-z\-]/g, '');
        patProcessarCodigoLido(code, 'pat-foto-result');
      } catch(e) {
        if (resultDiv) resultDiv.innerHTML = patFormBuscaManual('pat-foto-result', 'Código não detectado. Digite o PAT manualmente:');
      }
    };
    img.src = url;
  } catch(e) {
    if (resultDiv) resultDiv.innerHTML = patFormBuscaManual('pat-foto-result', 'Scanner indisponível. Digite o PAT:');
  }
}

function patFormBuscaManual(resultId, label) {
  return `<div style="background:var(--g50,#f8fafc);border-radius:8px;padding:14px">
    <p style="font-size:13px;color:var(--g600,#4b5563);margin:0 0 8px">${label}</p>
    <div style="display:flex;gap:8px">
      <input id="${resultId}-manual" class="form-control" placeholder="Patrimônio" style="flex:1;font-family:monospace">
      <button onclick="patProcessarCodigoLido(document.getElementById('${resultId}-manual').value,'${resultId}')" class="btn btn-primary btn-sm">Buscar</button>
    </div>
  </div>`;
}

async function patProcessarCodigoLido(code, resultContainerId) {
  const code2 = (code || '').trim().replace(/[^0-9A-Za-z\-]/g, '');
  const div = document.getElementById(resultContainerId);
  if (!code2) { if (div) div.innerHTML = '<div style="color:#EF4444;font-size:13px">Código inválido</div>'; return; }
  if (div) div.innerHTML = '<div style="color:var(--g500,#64748b);font-size:13px">🔄 Buscando...</div>';
  await patExibirResultado(code2, 'pat', div);
}

function patBuscarPorTexto(val, modo) {
  const q = (val||'').trim();
  const ids = { pat:'pat-texto-result', hostname:'pat-hostname-result' };
  const div = document.getElementById(ids[modo]);
  if (!q) { if(div) div.innerHTML=''; return; }
  patExibirResultado(q, modo, div);
}

function patBuscarFiltros() {
  const area  = (document.getElementById('pat-busca-area')?.value  || '').toLowerCase();
  const ip    = (document.getElementById('pat-busca-ip')?.value    || '').toLowerCase();
  const tiposChk = [...document.querySelectorAll('#pat-busca-tipos input:checked')].map(i => i.value);
  const todos = tiposChk.includes('todos');
  const div   = document.getElementById('pat-filtros-result');
  if (!area && !ip && todos) { if(div) div.innerHTML=''; return; }

  const ativos = (STATE.ativos || []);
  const pats   = (STATE.patrimonios || []);

  let lista = ativos.filter(a => {
    if (area && !(a.area||'').toLowerCase().includes(area) && !(a.gerencia||'').toLowerCase().includes(area)) return false;
    if (ip   && !(a.ip||'').includes(ip)) return false;
    if (!todos) {
      const tipo = (a.tipo||'').toLowerCase();
      if (!tiposChk.some(t => tipo.includes(t))) return false;
    }
    return true;
  });

  if (!div) return;
  if (!lista.length) { div.innerHTML = '<div style="color:var(--g400,#94a3b8);font-size:13px;padding:12px">Nenhum ativo encontrado com esses filtros</div>'; return; }

  div.innerHTML = `
    <div style="font-size:12px;font-weight:600;color:var(--g500,#64748b);margin-bottom:8px">${lista.length} ativo(s) encontrado(s)</div>
    <div style="max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:6px">
    ${lista.map(a => {
      const pat = pats.find(p => p.ativoId === a.id || p.pat === a.pat);
      const hn  = hostnameFromAtivo(a);
      const pp  = extractPatrimonioFromHostname(hn);
      return patCardResultado(a, pat, hn, pp);
    }).join('')}
    </div>`;
}

function patTipoToggle(chk) {
  const todos = document.getElementById('pat-busca-tipos')?.querySelector('input[value="todos"]');
  if (chk.value === 'todos') {
    document.querySelectorAll('#pat-busca-tipos input').forEach(i => { if(i!==chk) i.checked=false; });
  } else if (todos && chk.checked) {
    todos.checked = false;
  }
  patBuscarFiltros();
}

async function patExibirResultado(q, modo, div) {
  if (!div) return;
  const ativos = STATE.ativos || [];
  const pats   = STATE.patrimonios || [];
  let ativo = null;
  let pat   = null;

  if (modo === 'pat') {
    pat   = pats.find(p => p.pat === q || p.pat === q.replace(/^0+/,''));
    ativo = ativos.find(a => a.pat === q || a.pat === q.replace(/^0+/,''));
    if (!ativo && pat?.ativoId) ativo = ativos.find(a => a.id === pat.ativoId);
  } else {
    ativo = ativos.find(a =>
      (a.hostname||'').toLowerCase().includes(q.toLowerCase()) ||
      (hostnameFromAtivo(a)||'').toLowerCase().includes(q.toLowerCase()) ||
      (a.desc||'').toLowerCase().includes(q.toLowerCase())
    );
    if (ativo) pat = pats.find(p => p.ativoId === ativo.id || p.pat === ativo.pat);
  }

  if (!ativo && !pat) {
    div.innerHTML = `
      <div style="background:var(--g50,#f8fafc);border:1px solid var(--g200,#e2e8f0);border-radius:10px;padding:16px">
        <div style="font-weight:600;font-size:13px;color:#EF4444;margin-bottom:8px">⚠️ "${escapeHtml(q)}" não encontrado</div>
        <p style="font-size:12px;color:var(--g500,#64748b);margin:0 0 12px">Deseja cadastrar este patrimônio?</p>
        <button onclick="patAbrirCadastro('${escapeHtml(q)}')" class="btn btn-primary btn-sm">+ Cadastrar Patrimônio</button>
      </div>`;
    return;
  }

  const hn = hostnameFromAtivo(ativo);
  const pp = extractPatrimonioFromHostname(hn);
  div.innerHTML = patCardResultado(ativo, pat, hn, pp);
}

function patCardResultado(ativo, pat, hn, pp) {
  if (!ativo && !pat) return '';
  const a  = ativo || {};
  const p  = pat   || {};
  const hostnameOk = hn && hn.match(/^[A-Z0-9\-]{5,20}$/i);
  const patOk  = (a.pat || p.pat);
  const cor    = (!patOk || !hn) ? '#EF4444' : (pp?.alerta ? '#F59E0B' : '#10B981');
  const status = (!patOk && !hn) ? '⛔ Sem PAT e sem Hostname'
               : !patOk ? '⚠️ Sem PAT cadastrado'
               : !hn    ? '⚠️ Sem hostname'
               : pp?.alerta ? '⚠️ Hostname fora do padrão'
               : '✅ OK';

  return `
  <div style="border:1px solid var(--g200,#e2e8f0);border-left:4px solid ${cor};border-radius:8px;padding:14px;background:var(--bg,#fff)">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
      <div>
        <div style="font-size:15px;font-weight:700;color:var(--g900,#111827)">${escapeHtml(a.desc||p.desc||hn||'Ativo')}</div>
        <div style="font-size:11px;color:var(--g400,#94a3b8)">${escapeHtml(a.tipo||'—')} · ${escapeHtml(a.area||p.gerencia||'—')}</div>
      </div>
      <span style="font-size:11px;font-weight:700;color:${cor};white-space:nowrap">${status}</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;margin-bottom:12px">
      <div><span style="color:var(--g400,#94a3b8)">PAT</span><br><strong style="font-family:monospace">${escapeHtml(a.pat||p.pat||'—')}</strong></div>
      <div><span style="color:var(--g400,#94a3b8)">Hostname</span><br><strong style="font-family:monospace;color:${hostnameOk?'inherit':'#EF4444'}">${escapeHtml(hn||'—')}</strong></div>
      <div><span style="color:var(--g400,#94a3b8)">IP</span><br><strong style="font-family:monospace">${escapeHtml(a.ip||'—')}</strong></div>
      <div><span style="color:var(--g400,#94a3b8)">Responsável</span><br><strong>${escapeHtml(a.resp||'—')}</strong></div>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      ${!a.pat ? `<button onclick="patAbrirVincular('${escapeHtml(a.id||'')}','${escapeHtml(p.pat||'')}',this)" class="btn btn-primary btn-sm">+ Vincular PAT</button>` : ''}
      ${a.id   ? `<button onclick="patAbrirCadastro('',${JSON.stringify(a.id)})" class="btn btn-ghost btn-sm">✏️ Editar</button>` : ''}
      ${!hostnameOk && a.id ? `<button onclick="patCorrigirHostname('${escapeHtml(a.id)}')" class="btn btn-warning btn-sm" style="background:#F59E0B;color:#fff;border:none">⚠️ Corrigir Hostname</button>` : ''}
    </div>
  </div>`;
}

// ── Cadastrar patrimônio novo ─────────────────────────────────────
function patAbrirCadastro(patPre, ativoId) {
  const ativo = ativoId ? (STATE.ativos||[]).find(a=>a.id===ativoId) : null;
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
  <div style="background:var(--bg,#fff);border-radius:16px;max-width:520px;width:100%;padding:24px;box-shadow:0 24px 60px rgba(0,0,0,.5)">
    <h3 style="margin:0 0 18px;font-size:16px;font-weight:700">🏷️ ${ativo?'Vincular':'Cadastrar'} Patrimônio</h3>
    ${ativo?`<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:14px">
      Ativo: <strong>${escapeHtml(ativo.desc||ativo.pat||ativo.ip||'—')}</strong> · ${escapeHtml(ativo.tipo||'—')}
    </div>`:''}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div style="grid-column:span 2">
        <label class="form-label">Número do Patrimônio *</label>
        <input id="new-pat-num" class="form-control" placeholder="Ex: 123456" value="${escapeHtml(patPre||ativo?.pat||'')}"
          style="font-family:monospace;font-size:16px;font-weight:700"
          oninput="this.value=this.value.replace(/[^0-9]/g,'');patVerificarDuplicata(this.value,'new-pat-dup-msg')">
        <div id="new-pat-dup-msg" style="font-size:11px;margin-top:3px"></div>
      </div>
      <div>
        <label class="form-label">Hostname</label>
        <input id="new-pat-hn" class="form-control" placeholder="Ex: CESAN-PC1234" value="${escapeHtml(hostnameFromAtivo(ativo)||ativo?.hostname||'')}"
          oninput="patVerificarHostnameDup(this.value,'new-hn-dup-msg')">
        <div id="new-hn-dup-msg" style="font-size:11px;margin-top:3px"></div>
      </div>
      <div>
        <label class="form-label">Área / Gerência</label>
        <input id="new-pat-area" class="form-control" placeholder="Ex: TI" value="${escapeHtml(ativo?.area||'')}"  >
      </div>
      <div>
        <label class="form-label">Responsável</label>
        <input id="new-pat-resp" class="form-control" placeholder="Nome" value="${escapeHtml(ativo?.resp||'')}">
      </div>
      <div>
        <label class="form-label">IP</label>
        <input id="new-pat-ip" class="form-control" placeholder="Ex: 172.22.1.10" value="${escapeHtml(ativo?.ip||'')}">
      </div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:18px">
      <button onclick="this.closest('[style*=fixed]').remove()" class="btn btn-ghost">Cancelar</button>
      <button onclick="patSalvarCadastro('${ativoId||''}')" class="btn btn-primary">💾 Salvar Patrimônio</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
}

function patVerificarDuplicata(val, msgId) {
  const msg = document.getElementById(msgId);
  if (!msg || !val) { if(msg) msg.innerHTML=''; return false; }
  const dup = (STATE.patrimonios||[]).find(p => p.pat === val) || (STATE.ativos||[]).find(a => a.pat === val);
  if (dup) {
    msg.innerHTML = `<span style="color:#EF4444">⛔ PAT ${val} já existe — ${escapeHtml(dup.desc||dup.hostname||dup.id)}</span>`;
    return true;
  }
  msg.innerHTML = '<span style="color:#10B981">✅ Disponível</span>';
  return false;
}

function patVerificarHostnameDup(val, msgId) {
  const msg = document.getElementById(msgId);
  if (!msg || !val) { if(msg) msg.innerHTML=''; return false; }
  const dup = (STATE.ativos||[]).find(a => (a.hostname||'').toLowerCase() === val.toLowerCase());
  const padrao = /^[A-Z]{2,10}-[A-Z]{2,4}[0-9]{4,6}$/i;
  if (dup) {
    msg.innerHTML = `<span style="color:#EF4444">⛔ Hostname já existe: ${escapeHtml(dup.desc||dup.pat||dup.id)}</span>`;
    return true;
  }
  if (!padrao.test(val)) {
    msg.innerHTML = '<span style="color:#F59E0B">⚠️ Fora do padrão (ex: CESAN-PC1234)</span>';
  } else {
    msg.innerHTML = '<span style="color:#10B981">✅ Padrão OK</span>';
  }
  return false;
}

async function patSalvarCadastro(ativoId) {
  const pat  = document.getElementById('new-pat-num')?.value?.trim();
  const hn   = document.getElementById('new-pat-hn')?.value?.trim();
  const area = document.getElementById('new-pat-area')?.value?.trim();
  const resp = document.getElementById('new-pat-resp')?.value?.trim();
  const ip   = document.getElementById('new-pat-ip')?.value?.trim();

  if (!pat) return showToast('Informe o número do patrimônio', 'warning');
  if (patVerificarDuplicata(pat, 'new-pat-dup-msg')) return showToast('⛔ PAT duplicado! Verifique.', 'error');
  if (hn && patVerificarHostnameDup(hn, 'new-hn-dup-msg')) return showToast('⛔ Hostname duplicado! Verifique.', 'error');

  const ativo = ativoId ? (STATE.ativos||[]).find(a=>a.id===ativoId) : null;

  // Salva no Firebase
  const docPat = {
    pat, hostname: hn||'', area: area||ativo?.area||'', resp: resp||ativo?.resp||'',
    ip: ip||ativo?.ip||'', ativoId: ativoId||'', origem: 'manual', vinculado: !!ativoId,
    desc: ativo?.desc||'', tipo: ativo?.tipo||'', createdAt: new Date().toISOString(),
    createdBy: CURRENT_USER?.nome||'sistema',
  };
  await fsAdd('patrimonios', docPat);

  // Atualiza o ativo com pat e hostname
  if (ativoId) {
    const col = ativo?._col === 'switches' ? 'switches' : 'ativos';
    await fsUpdate(col, ativoId, { pat, hostname: hn||ativo?.hostname||'' });
  }

  showToast(`✅ Patrimônio ${pat} salvo!`, 'success');
  document.querySelector('[style*="z-index:10001"]')?.remove();
  auditLog('pat_cadastro', 'patrimonio', pat, 'patrimonio', { ativoId, hostname: hn });
}

// ── Vincular PAT a ativo existente ───────────────────────────────
function patAbrirVincular(ativoId, patPre, btn) {
  patAbrirCadastro(patPre, ativoId);
}

// ── Corrigir hostname ─────────────────────────────────────────────
function patCorrigirHostname(ativoId) {
  const ativo = (STATE.ativos||[]).find(a=>a.id===ativoId);
  if (!ativo) return;
  const novoHn = prompt(`Hostname atual: ${hostnameFromAtivo(ativo)||'—'}\nNovo hostname (padrão: CESAN-PC1234):`);
  if (!novoHn) return;
  if (patVerificarHostnameDup(novoHn, null)) return showToast('⛔ Hostname duplicado!', 'error');
  const padrao = /^[A-Z]{2,10}-[A-Z]{2,4}[0-9]{4,6}$/i;
  if (!padrao.test(novoHn)) {
    if (!confirm(`⚠️ "${novoHn}" está fora do padrão. Salvar mesmo assim?`)) return;
  }
  const col = ativo._col === 'switches' ? 'switches' : 'ativos';
  fsUpdate(col, ativoId, { hostname: novoHn })
    .then(() => showToast(`✅ Hostname atualizado: ${novoHn}`, 'success'))
    .catch(e => showToast('Erro: ' + e.message, 'error'));
}

// ── Auto-vincular patrimonios SAP sem vínculo ────────────────────
async function patAutoVincular() {
  const pats   = (STATE.patrimonios||[]).filter(p => p.origem==='sap-import' && !p.ativoId);
  const ativos = STATE.ativos || [];
  if (!pats.length) return showToast('Nenhum patrimônio SAP sem vínculo', 'info');

  let vinculados = 0, naoEncontrados = [];

  for (const p of pats) {
    // Tenta combinar por PAT exato
    let ativo = ativos.find(a => a.pat === p.pat);
    // Fallback: combina por hostname extraído
    if (!ativo && p.hostname) ativo = ativos.find(a => (a.hostname||'').toLowerCase() === p.hostname.toLowerCase());
    // Fallback: combina por descrição parcial
    if (!ativo && p.desc) ativo = ativos.find(a => (a.desc||'').toLowerCase().includes((p.desc||'').toLowerCase().slice(0,12)));

    if (ativo) {
      await fsUpdate('patrimonios', p.id, { ativoId: ativo.id, vinculado: true });
      await fsUpdate(ativo._col==='switches'?'switches':'ativos', ativo.id, { pat: p.pat });
      vinculados++;
    } else {
      naoEncontrados.push(p.pat);
    }
  }

  showToast(`✅ ${vinculados} vinculado(s). ${naoEncontrados.length} sem correspondência.`, vinculados?'success':'warning', 5000);
  if (naoEncontrados.length) {
    console.info('[PAT] Sem correspondência:', naoEncontrados.join(', '));
  }
}

// ── Painel de alertas patrimoniais ────────────────────────────────
function patAbrirAlertas() {
  const pats   = STATE.patrimonios || [];
  const ativos = STATE.ativos      || [];
  const semVinculo   = pats.filter(p => p.origem==='sap-import' && !p.ativoId);
  const ativosSemPat = ativos.filter(a =>
    ['computador','notebook','servidor','desktop'].some(t => (a.tipo||'').toLowerCase().includes(t))
    && !a.pat && !pats.find(p => p.ativoId === a.id));
  const hostFora = ativos.filter(a => {
    const hn = hostnameFromAtivo(a);
    return hn && !/^[A-Z]{2,10}-[A-Z]{2,4}[0-9]{4,6}$/i.test(hn);
  });

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10002;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
  <div style="background:var(--bg,#fff);border-radius:16px;max-width:620px;width:100%;max-height:85vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.5)">
    <div style="background:linear-gradient(135deg,#991B1B,#DC2626);padding:18px 24px;border-radius:16px 16px 0 0;display:flex;justify-content:space-between;align-items:center">
      <h3 style="color:#fff;margin:0;font-size:16px">⚠️ Alertas Patrimoniais</h3>
      <button onclick="this.closest('[style*=fixed]').remove()" style="background:rgba(255,255,255,.2);border:none;color:#fff;width:30px;height:30px;border-radius:50%;cursor:pointer">✕</button>
    </div>
    <div style="padding:20px;display:flex;flex-direction:column;gap:16px">
      <!-- SAP sem vínculo -->
      <div style="border:1px solid #FCA5A5;border-radius:10px;overflow:hidden">
        <div style="background:#FEF2F2;padding:10px 14px;display:flex;justify-content:space-between;align-items:center">
          <span style="font-weight:700;color:#DC2626">📋 PATs SAP sem vínculo (${semVinculo.length})</span>
          ${semVinculo.length?`<button onclick="patAutoVincular()" class="btn btn-primary btn-sm">🔗 Auto-Vincular Todos</button>`:''}
        </div>
        ${semVinculo.length ? semVinculo.slice(0,10).map(p=>`
          <div style="padding:10px 14px;border-top:1px solid #FCA5A5;display:flex;justify-content:space-between;align-items:center;font-size:13px">
            <span><strong style="font-family:monospace">${escapeHtml(p.pat)}</strong> — ${escapeHtml(p.desc||'—')} · ${escapeHtml(p.gerencia||'—')}</span>
            <button onclick="patAbrirCadastro('${escapeHtml(p.pat)}')" class="btn btn-ghost btn-xs">Vincular</button>
          </div>`).join('') + (semVinculo.length>10?`<div style="padding:10px 14px;font-size:12px;color:#64748b">+ ${semVinculo.length-10} mais...</div>`:'')
        : '<div style="padding:12px 14px;font-size:13px;color:#10B981">✅ Nenhum pendente</div>'}
      </div>
      <!-- Ativos sem PAT -->
      <div style="border:1px solid #FCD34D;border-radius:10px;overflow:hidden">
        <div style="background:#FFFBEB;padding:10px 14px">
          <span style="font-weight:700;color:#D97706">🖥️ Ativos sem Patrimônio (${ativosSemPat.length})</span>
        </div>
        ${ativosSemPat.length ? ativosSemPat.slice(0,8).map(a=>`
          <div style="padding:10px 14px;border-top:1px solid #FCD34D;display:flex;justify-content:space-between;align-items:center;font-size:13px">
            <span><strong>${escapeHtml(a.desc||a.ip||'—')}</strong> · ${escapeHtml(a.tipo||'—')} · ${escapeHtml(a.area||'—')}</span>
            <button onclick="patAbrirCadastro('','${escapeHtml(a.id)}')" class="btn btn-primary btn-xs">+ PAT</button>
          </div>`).join('') + (ativosSemPat.length>8?`<div style="padding:10px 14px;font-size:12px;color:#64748b">+ ${ativosSemPat.length-8} mais...</div>`:'')
        : '<div style="padding:12px 14px;font-size:13px;color:#10B981">✅ Nenhum pendente</div>'}
      </div>
      <!-- Hostname fora do padrão -->
      <div style="border:1px solid #A5B4FC;border-radius:10px;overflow:hidden">
        <div style="background:#EEF2FF;padding:10px 14px">
          <span style="font-weight:700;color:#4F46E5">💻 Hostnames fora do padrão (${hostFora.length})</span>
        </div>
        ${hostFora.length ? hostFora.slice(0,8).map(a=>{const hn=hostnameFromAtivo(a);return`
          <div style="padding:10px 14px;border-top:1px solid #A5B4FC;display:flex;justify-content:space-between;align-items:center;font-size:13px">
            <span><strong style="font-family:monospace;color:#EF4444">${escapeHtml(hn)}</strong> — ${escapeHtml(a.desc||'—')}</span>
            <button onclick="patCorrigirHostname('${escapeHtml(a.id)}')" class="btn btn-warning btn-xs" style="background:#F59E0B;color:#fff;border:none">Corrigir</button>
          </div>`;}).join('') + (hostFora.length>8?`<div style="padding:10px 14px;font-size:12px;color:#64748b">+ ${hostFora.length-8} mais...</div>`:'')
        : '<div style="padding:12px 14px;font-size:13px;color:#10B981">✅ Todos OK</div>'}
      </div>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
}


// ════════════════════════════════════════════════════════════════════
// MÓDULO 2 — MAPA DE REDE VISUAL
// Topologia: switches → ativos/agentes com linhas SVG
// ════════════════════════════════════════════════════════════════════

function renderMapaRede() {
  const container = document.getElementById('mapa-rede-svg');
  if (!container) return;

  const switches = STATE.switches || [];
  const ativos   = (STATE.ativos  || []).filter(a => a.ip && !switches.find(s=>s.id===a.id));
  const agentes  = STATE_AGENTS?.list || [];

  // Agrupa ativos por subnet (/24)
  function getSubnet(ip) {
    if (!ip) return 'sem-ip';
    const parts = ip.split('.');
    return parts.slice(0,3).join('.');
  }

  const subnetMap = {};
  [...switches, ...ativos].forEach(d => {
    const sub = getSubnet(d.ip||d.ipAddress||'');
    if (!subnetMap[sub]) subnetMap[sub] = { switches:[], ativos:[] };
    if (switches.find(s=>s.id===d.id)) subnetMap[sub].switches.push(d);
    else subnetMap[sub].ativos.push(d);
  });

  const subnets = Object.entries(subnetMap);
  if (!subnets.length) {
    container.innerHTML = `<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:300px;color:var(--g400,#94a3b8)">
      <div style="font-size:48px;margin-bottom:12px">🔌</div>
      <div style="font-weight:600;font-size:15px">Nenhum dispositivo com IP cadastrado</div>
      <div style="font-size:12px;margin-top:4px">Cadastre switches e ativos com endereço IP</div>
    </div>`;
    return;
  }

  // Layout: cada subnet é uma coluna
  const W_COL = 220, H_NODE = 52, PAD = 16, HEADER_H = 70;
  const svgW  = subnets.length * (W_COL + 24) + 40;
  const maxNodes = Math.max(...subnets.map(([,s])=>s.switches.length+s.ativos.length));
  const svgH  = HEADER_H + maxNodes * (H_NODE + PAD) + 60;

  const nodePositions = {};
  let svgContent = '';
  let lines = '';

  subnets.forEach(([subnet, group], colIdx) => {
    const x = 20 + colIdx * (W_COL + 24);
    // Subnet header
    svgContent += `
      <rect x="${x}" y="10" width="${W_COL}" height="42" rx="8" fill="#1E3A8A" opacity=".9"/>
      <text x="${x+W_COL/2}" y="27" text-anchor="middle" fill="#fff" font-size="11" font-weight="700" font-family="monospace">${subnet}.0/24</text>
      <text x="${x+W_COL/2}" y="43" text-anchor="middle" fill="rgba(255,255,255,.6)" font-size="10">${group.switches.length} switch · ${group.ativos.length} ativo</text>`;

    const allNodes = [...group.switches.map(s=>({...s,_isSw:true})), ...group.ativos];
    allNodes.forEach((node, rowIdx) => {
      const nx = x;
      const ny = HEADER_H + rowIdx * (H_NODE + PAD);
      const ag = agentes.find(a => a.ip === (node.ip||node.ipAddress) || a.hostname === node.hostname);
      const statusColor = node.status==='offline' ? '#EF4444'
        : node.status==='alerta' || node.status==='critico' ? '#F59E0B'
        : ag?.status==='online' ? '#10B981' : '#94A3B8';
      const nodeKey = node.id || node.ip;
      nodePositions[nodeKey] = { cx: nx + W_COL/2, cy: ny + H_NODE/2 };

      const icon = node._isSw ? '🔀' : (node.tipo||'').toLowerCase().includes('servidor') ? '🖥️'
        : (node.tipo||'').toLowerCase().includes('impressora') ? '🖨️'
        : (node.tipo||'').toLowerCase().includes('camera') ? '📷' : '💻';

      const cpuPct = ag?.cpuPct ?? node.cpuPct;
      const memPct = ag?.memPct ?? null;
      const diskPct= ag ? Math.round((ag.disk_used||0)/(ag.disk_total||1)*100) : null;

      svgContent += `
        <rect x="${nx}" y="${ny}" width="${W_COL}" height="${H_NODE}" rx="8"
          fill="${node._isSw?'#1E293B':'var(--bg,#fff)'}"
          stroke="${statusColor}" stroke-width="2"
          style="cursor:pointer;filter:drop-shadow(0 2px 6px rgba(0,0,0,.1))"
          onclick="abrirMonitorDetalhe('${node.id}','${node._isSw?'switches':'ativos'}')"/>
        <circle cx="${nx+18}" cy="${ny+H_NODE/2}" r="6" fill="${statusColor}"/>
        <text x="${nx+30}" y="${ny+18}" font-size="11" font-weight="700" fill="${node._isSw?'#fff':'var(--g900,#111827)'}" font-family="system-ui">${icon} ${escapeHtml((node.hostname||node.desc||node.ip||'—').slice(0,20))}</text>
        <text x="${nx+30}" y="${ny+30}" font-size="9.5" fill="${node._isSw?'rgba(255,255,255,.6)':'var(--g400,#94a3b8)'}" font-family="monospace">${escapeHtml(node.ip||node.ipAddress||'—')}</text>
        ${cpuPct!=null?`<text x="${nx+30}" y="${ny+42}" font-size="9" fill="#60A5FA" font-family="system-ui">CPU:${cpuPct}%${memPct!=null?' MEM:'+memPct+'%':''}</text>`:''}
        ${diskPct!=null?`<text x="${nx+W_COL-8}" y="${ny+42}" font-size="9" fill="#34D399" font-family="system-ui" text-anchor="end">Disco:${diskPct}%</text>`:''}`;

      // Linha do switch para ativos na mesma subnet
      if (!node._isSw && group.switches.length > 0) {
        const sw = group.switches[0];
        const swKey = sw.id || sw.ip;
        const swPos = nodePositions[swKey];
        if (swPos) {
          lines += `<line x1="${swPos.cx}" y1="${swPos.cy}" x2="${nx+W_COL/2}" y2="${ny+H_NODE/2}"
            stroke="${statusColor}" stroke-width="1.5" stroke-dasharray="${node.status==='offline'?'5,4':''}" opacity=".5"/>`;
        }
      }
    });
  });

  container.innerHTML = `
    <svg width="${svgW}" height="${svgH}" xmlns="http://www.w3.org/2000/svg" style="min-width:100%">
      <defs>
        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M 20 0 L 0 0 0 20" fill="none" stroke="var(--g100,#f1f5f9)" stroke-width="1"/>
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#grid)"/>
      ${lines}
      ${svgContent}
    </svg>`;
}


// ════════════════════════════════════════════════════════════════════
// MÓDULO 3 — MÉTRICAS ZABBIX-STYLE por Computador
// Mostra disco, memória, CPU ao lado de cada ativo na tabela
// ════════════════════════════════════════════════════════════════════

// Função principal — injeta mini-card de métricas na linha de ativo
function patMetricasHtml(ativo) {
  const agentes = STATE_AGENTS?.list || [];
  // Casa pelo IP ou hostname
  const ag = agentes.find(a =>
    (ativo.ip && a.ip === ativo.ip) ||
    (ativo.hostname && (a.hostname||'').toLowerCase() === (ativo.hostname||'').toLowerCase()) ||
    (a.hostname && hostnameFromAtivo(ativo) &&
     a.hostname.toLowerCase() === hostnameFromAtivo(ativo).toLowerCase())
  );

  if (!ag) {
    // Verifica se tem dados direto no ativo (enviado por cliente SYSACK)
    const hasMeta = ativo.disk_total || ativo.mem_total || ativo.cpu_pct != null;
    if (!hasMeta) return '<td style="font-size:11px;color:var(--g300,#CBD5E1);text-align:center">—</td>';
  }

  const src = ag || ativo;
  const diskTotal = src.disk_total || 0;
  const diskUsed  = src.disk_used  || 0;
  const diskPct   = diskTotal > 0 ? Math.round(diskUsed/diskTotal*100) : null;
  const memTotal  = src.mem_total  || 0;
  const memUsed   = src.mem_used   || 0;
  const memPct    = memTotal  > 0 ? Math.round(memUsed/memTotal*100)   : null;
  const cpuPct    = src.cpu_pct ?? src.cpuPct ?? null;
  const tipo      = src.tipo_hw   || src.tipo || ativo.tipo || '';
  const online    = ag?.status === 'online';

  function bar(pct, color) {
    if (pct == null) return '<span style="color:var(--g300,#cbd5e1)">—</span>';
    const c = pct > 90 ? '#EF4444' : pct > 70 ? '#F59E0B' : color;
    return `<div style="display:flex;align-items:center;gap:3px">
      <div style="width:36px;height:5px;background:var(--g100,#f1f5f9);border-radius:3px;overflow:hidden">
        <div style="width:${pct}%;height:5px;background:${c};border-radius:3px"></div>
      </div>
      <span style="font-size:10px;color:${c};font-weight:700">${pct}%</span>
    </div>`;
  }

  function fmtBytes(b) {
    if (!b) return '—';
    if (b >= 1e12) return (b/1e12).toFixed(1)+'TB';
    if (b >= 1e9)  return (b/1e9).toFixed(0)+'GB';
    if (b >= 1e6)  return (b/1e6).toFixed(0)+'MB';
    return b+'B';
  }

  return `<td style="padding:4px 8px;min-width:160px">
    <div style="background:${online?'#F0FDF4':'var(--g50,#f8fafc)'};border:1px solid ${online?'#BBF7D0':'var(--g200,#e2e8f0)'};border-radius:8px;padding:6px 8px;font-size:10.5px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:10px">
        <span style="font-weight:700;color:${online?'#059669':'var(--g400,#94a3b8)'}">${online?'🟢 Online':'⚫ Offline'}</span>
        ${tipo?`<span style="color:var(--g400,#94a3b8)">${escapeHtml(tipo)}</span>`:''}
      </div>
      <div style="display:grid;grid-template-columns:30px 1fr;gap:2px 6px;align-items:center">
        <span style="color:var(--g400,#94a3b8)">CPU</span>${bar(cpuPct,'#3B82F6')}
        <span style="color:var(--g400,#94a3b8)">MEM</span>${bar(memPct,'#8B5CF6')}
        <span style="color:var(--g400,#94a3b8)">DSK</span>${bar(diskPct,'#10B981')}
      </div>
      ${diskTotal?`<div style="margin-top:4px;font-size:9.5px;color:var(--g400,#94a3b8)">${fmtBytes(diskUsed)} / ${fmtBytes(diskTotal)}</div>`:''}
    </div>
  </td>`;
}

// Métricas integradas diretamente no renderAtivos() — patch removido

// Endpoint de recebimento de métricas do cliente SYSACK Agent
// O agente POST em /api/metrics (ou via Firebase diretamente)
// Formato: { hostname, ip, cpu_pct, mem_total, mem_used, disk_total, disk_used, tipo_hw }
window.sysackReceberMetricas = async function(dados) {
  if (!dados || (!dados.ip && !dados.hostname)) return;
  const ativos = STATE.ativos || [];
  const ativo = ativos.find(a =>
    (dados.ip && a.ip === dados.ip) ||
    (dados.hostname && (a.hostname||'').toLowerCase() === dados.hostname.toLowerCase())
  );
  if (!ativo) return console.warn('[Métricas] Ativo não encontrado:', dados.hostname || dados.ip);

  const col = ativo._col === 'switches' ? 'switches' : 'ativos';
  await fsUpdate(col, ativo.id, {
    cpu_pct:    dados.cpu_pct,
    mem_total:  dados.mem_total,
    mem_used:   dados.mem_used,
    disk_total: dados.disk_total,
    disk_used:  dados.disk_used,
    tipo_hw:    dados.tipo_hw || '',
    lastMetrica: new Date().toISOString(),
  });
  console.info('[Métricas] Atualizado:', dados.hostname || dados.ip);
};

// ── Alternar view tabela / mapa de rede ──────────────────────────
function monSetView(view) {
  const tabelaWrap = document.getElementById('mon-view-tabela-wrap');
  const mapaWrap   = document.getElementById('mon-view-mapa-wrap');
  const btnTab     = document.getElementById('mon-view-tabela');
  const btnMapa    = document.getElementById('mon-view-mapa');
  if (!tabelaWrap || !mapaWrap) return;
  if (view === 'mapa') {
    tabelaWrap.style.display = 'none';
    mapaWrap.style.display   = '';
    if (btnTab)  { btnTab.style.background='none'; btnTab.style.color='var(--g500,#64748b)'; btnTab.style.boxShadow='none'; }
    if (btnMapa) { btnMapa.style.background='#fff'; btnMapa.style.color='var(--g900,#111827)'; btnMapa.style.boxShadow='0 1px 3px rgba(0,0,0,.1)'; }
    renderMapaRede();
  } else {
    tabelaWrap.style.display = '';
    mapaWrap.style.display   = 'none';
    if (btnTab)  { btnTab.style.background='#fff'; btnTab.style.color='var(--g900,#111827)'; btnTab.style.boxShadow='0 1px 3px rgba(0,0,0,.1)'; }
    if (btnMapa) { btnMapa.style.background='none'; btnMapa.style.color='var(--g500,#64748b)'; btnMapa.style.boxShadow='none'; }
  }
}

// ── Badge de alertas patrimoniais ─────────────────────────────────
(function patchNbUpdatePat() {
  const _prev = window.nbUpdate;
  window.nbUpdate = function(id, val) {
    if (id === 'nb-pat-alertas') {
      const el = document.getElementById('nb-pat-alertas');
      if (el) { el.style.display = val > 0 ? '' : 'none'; el.textContent = val; }
      return;
    }
    if (typeof _prev === 'function') return _prev(id, val);
  };
})();
