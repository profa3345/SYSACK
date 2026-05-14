// sw.js — SYSACK Service Worker v3
// Offline cache + FCM background messages + auto-update

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

  // Comandos silenciosos: repassa para a aba aberta sem exibir notificação
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
// CORREÇÃO: havia dois blocos install/activate/fetch conflitantes.
// Unificados aqui em um único conjunto de listeners com lógica combinada.

const CACHE_VER    = 'sysack-v3';
const STATIC_CACHE = CACHE_VER + '-static';

// URLs externas que nunca devem ser interceptadas pelo SW
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
          .map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = event.request.url;

  // Nunca intercepta extensões Chrome ou padrões externos
  if (url.startsWith('chrome-extension://')) return;
  if (!url.startsWith(self.location.origin)) return;
  if (NO_CACHE_PATTERNS.some(p => p.test(url))) return;

  // Páginas HTML: network-first (sempre tenta buscar versão atualizada)
  if (url.endsWith('.html') || url.endsWith('/') || url === self.location.origin) {
    event.respondWith(
      fetch(event.request)
        .then(r => {
          if (r.ok) {
            caches.open(STATIC_CACHE).then(c => c.put(event.request, r.clone()));
          }
          return r;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Assets estáticos (JS, CSS, imagens, fontes): cache-first
  if (/\.(js|css|png|jpg|jpeg|svg|ico|woff2?)(\?.*)?$/.test(url)) {
    event.respondWith(
      caches.match(event.request).then(cached => cached || fetch(event.request))
    );
    return;
  }
});

// ── Mensagens do app ──────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});
