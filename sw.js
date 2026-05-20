// sw.js — SYSACK Service Worker v7
// Fix: clone ANTES de retornar a response, nunca depois

importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey:            'AIzaSyBGb4GY-0nMbGg82AnG8tMySWrZxMvogww',
  authDomain:        'sysack-829e2.firebaseapp.com',
  projectId:         'sysack-829e2',
  storageBucket:     'sysack-829e2.firebasestorage.app',
  messagingSenderId: '364185694349',
  appId:             '1:364185694349:web:cc2e9123fe72726cc5f2c4',
});

const messaging = firebase.messaging();

// ── FCM: mensagens em background ─────────────────────────────────
messaging.onBackgroundMessage(payload => {
  const { notification, data } = payload;
  const tipo = data?.tipo || 'notification';

  if (['checkin_request', 'location_request'].includes(tipo)) {
    self.clients.matchAll({ type: 'window' }).then(clients =>
      clients.forEach(c => c.postMessage({ type: 'FCM_CMD', tipo, data }))
    );
    return;
  }

  self.registration.showNotification(notification?.title || 'SYSACK', {
    body:     notification?.body || data?.mensagem || '',
    icon:     '/icon-192.png',
    badge:    '/icon-192.png',
    tag:      tipo,
    renotify: true,
    data:     { url: data?.url || '/', tipo },
  });
});

// ── Clique na notificação ─────────────────────────────────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      const ex = clients.find(c => c.url.includes(self.location.origin));
      if (ex) { ex.focus(); ex.navigate(url); }
      else self.clients.openWindow(url);
    })
  );
});

// ── Cache ─────────────────────────────────────────────────────────
const CACHE_VER    = 'sysack-v7';
const STATIC_CACHE = CACHE_VER + '-static';

const NO_CACHE_PATTERNS = [
  /firestore\.googleapis\.com/,
  /identitytoolkit/,
  /cloudfunctions\.net/,
  /fcm\.googleapis/,
  /firebase-messaging/,
  /recaptcha/,
  /gstatic\.com/,
  /fonts\./,
  /googleapis\.com/,
  /firebaseio\.com/,
];

const PRECACHE_URLS = ['/', '/index.html', '/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => Promise.allSettled(
        PRECACHE_URLS.map(u => cache.add(u).catch(() => {}))
      ))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(k => k.startsWith('sysack-') && k !== STATIC_CACHE)
          .map(k => {
            console.log('[SW] Removendo cache antigo:', k);
            return caches.delete(k);
          })
      ))
      .then(() => self.clients.claim())
  );
});

// ── Função auxiliar: fetch → cache → return ───────────────────────
// A regra de ouro: clone() ANTES de qualquer operação assíncrona.
// res.body só pode ser lido uma vez; clonar preserva a cópia para o cache.
function fetchAndCache(req, cacheName) {
  return fetch(req).then(res => {
    // Só cacheia respostas válidas e clonable
    if (res && res.ok && res.status < 400) {
      const resParaCache = res.clone(); // clone PRIMEIRO, antes de retornar
      caches.open(cacheName).then(c => c.put(req, resParaCache)).catch(() => {});
    }
    return res; // retorna o original (ainda não consumido)
  });
}

self.addEventListener('fetch', event => {
  const req = event.request;

  // Só intercepta GET
  if (req.method !== 'GET') return;

  const url = req.url;

  // Nunca intercepta extensões Chrome
  if (url.startsWith('chrome-extension://')) return;

  // Nunca intercepta requisições externas
  if (!url.startsWith(self.location.origin)) return;

  // Nunca intercepta padrões Firebase / Google
  if (NO_CACHE_PATTERNS.some(p => p.test(url))) return;

  // ── HTML: network-first, fallback cache se offline ──────────────
  if (url.endsWith('.html') || url.endsWith('/') || url === self.location.origin) {
    event.respondWith(
      fetchAndCache(req, STATIC_CACHE)
        .catch(() => caches.match(req))
    );
    return;
  }

  // ── JS e CSS: network-first (garante versão mais recente) ────────
  if (/\.(js|css)(\?.*)?$/.test(url)) {
    event.respondWith(
      fetchAndCache(req, STATIC_CACHE)
        .catch(() => caches.match(req))
    );
    return;
  }

  // ── Imagens e fontes locais: cache-first ─────────────────────────
  if (/\.(png|jpg|jpeg|svg|ico|woff2?)(\?.*)?$/.test(url)) {
    event.respondWith(
      caches.match(req).then(cached => {
        if (cached) return cached;
        return fetchAndCache(req, STATIC_CACHE)
          .catch(() => new Response('', { status: 404 }));
      })
    );
    return;
  }
});

// ── Mensagens do app ──────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});
