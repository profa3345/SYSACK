// sw.js — SYSACK Service Worker v8
// Fix crítico: clone() ANTES de qualquer await/then, nunca depois
// v8 força substituição do v6/v7 que tinham o bug de bodyUsed

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

// ─────────────────────────────────────────────────────────────────
// Cache config
// ─────────────────────────────────────────────────────────────────
const CACHE_NAME = 'sysack-v8';

const BYPASS = [
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

self.addEventListener('install', event => {
  // skipWaiting imediatamente — substitui o SW antigo sem esperar aba fechar
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      Promise.allSettled(
        ['/', '/index.html', '/manifest.json', '/icon-192.png', '/icon-512.png']
          .map(u => cache.add(u).catch(() => {}))
      )
    )
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k.startsWith('sysack-') && k !== CACHE_NAME)
          .map(k => { console.log('[SW v8] Limpando cache antigo:', k); return caches.delete(k); })
      )
    ).then(() => self.clients.claim())
  );
});

// ─────────────────────────────────────────────────────────────────
// fetchAndCache — a correção do bug
//
// REGRA: res.clone() deve ser chamado IMEDIATAMENTE ao receber a
// resposta, ANTES de qualquer operação assíncrona (incluindo abrir
// o cache). O body de um Response é um ReadableStream que só pode
// ser lido uma vez; após qualquer leitura assíncrona ele fica
// marcado como bodyUsed=true e clone() lança TypeError.
//
// ERRADO (padrão antigo com bug):
//   fetch(req).then(res => {
//     caches.open(n).then(c => c.put(req, res.clone())); // BOOM
//     return res;
//   })
//
// CORRETO (este arquivo):
//   fetch(req).then(res => {
//     const copy = res.clone();   // clone PRIMEIRO, síncrono
//     caches.open(n).then(c => c.put(req, copy)); // usa a cópia
//     return res;                 // retorna o original intacto
//   })
// ─────────────────────────────────────────────────────────────────
function networkFirst(event) {
  const req = event.request;
  event.respondWith(
    fetch(req).then(res => {
      if (res && res.ok) {
        const copy = res.clone();                          // clone síncrono
        caches.open(CACHE_NAME)
          .then(c => c.put(req, copy))
          .catch(() => {});
      }
      return res;
    }).catch(() => caches.match(req))
  );
}

function cacheFirst(event) {
  const req = event.request;
  event.respondWith(
    caches.match(req).then(cached => {
      if (cached) return cached;
      return fetch(req).then(res => {
        if (res && res.ok) {
          const copy = res.clone();                        // clone síncrono
          caches.open(CACHE_NAME)
            .then(c => c.put(req, copy))
            .catch(() => {});
        }
        return res;
      }).catch(() => new Response('', { status: 408 }));
    })
  );
}

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = req.url;
  if (url.startsWith('chrome-extension://')) return;
  if (!url.startsWith(self.location.origin)) return;
  if (BYPASS.some(p => p.test(url))) return;

  // HTML e JS/CSS: sempre network-first (garante código atualizado)
  if (/\.(html|js|css)(\?.*)?$/.test(url) ||
      url.endsWith('/') ||
      url === self.location.origin) {
    networkFirst(event);
    return;
  }

  // Imagens e fontes: cache-first
  if (/\.(png|jpg|jpeg|svg|ico|woff2?)(\?.*)?$/.test(url)) {
    cacheFirst(event);
    return;
  }
});

self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});
