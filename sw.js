// sw.js — SYSACK Service Worker v4
// Corrigido: network-first para JS/CSS após modularização

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
// v4: mudou para network-first em JS/CSS para suportar modularização.
// Cache-first apenas para imagens e fontes (raramente mudam).

const CACHE_VER    = 'sysack-v4';   // ← incrementado para forçar limpeza do v3
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

// Apenas HTML e manifest no precache — JS/CSS são buscados da rede
const PRECACHE_URLS = ['/', '/index.html', '/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => Promise.allSettled(PRECACHE_URLS.map(u => cache.add(u).catch(() => {}))))
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

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = event.request.url;

  if (url.startsWith('chrome-extension://')) return;
  if (!url.startsWith(self.location.origin)) return;
  if (NO_CACHE_PATTERNS.some(p => p.test(url))) return;

  // HTML: network-first, fallback para cache se offline
  if (url.endsWith('.html') || url.endsWith('/') || url === self.location.origin) {
    event.respondWith(
      fetch(event.request)
        .then(r => {
          if (r.ok) {
            const clone = r.clone();
            caches.open(STATIC_CACHE).then(c => c.put(event.request, clone));
          }
          return r;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // JS e CSS: network-first (crítico após modularização — nunca servir do cache sem tentar rede)
  if (/\.(js|css)(\?.*)?$/.test(url)) {
    event.respondWith(
      fetch(event.request)
        .then(r => {
          if (r.ok) {
            const clone = r.clone();
            caches.open(STATIC_CACHE).then(c => c.put(event.request, clone));
          }
          return r;
        })
        .catch(() => {
          // Offline: tenta servir do cache como último recurso
          return caches.match(event.request);
        })
    );
    return;
  }

  // Imagens e fontes locais: cache-first (raramente mudam)
  if (/\.(png|jpg|jpeg|svg|ico|woff2?)(\?.*)?$/.test(url)) {
    event.respondWith(
      caches.match(event.request)
        .then(cached => cached || fetch(event.request).then(r => {
          if (r.ok) {
            const clone = r.clone();
            caches.open(STATIC_CACHE).then(c => c.put(event.request, clone));
          }
          return r;
        }))
    );
    return;
  }
});

// ── Mensagens do app ──────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});
