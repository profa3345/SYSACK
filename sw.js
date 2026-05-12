// sw.js — SYSACK Service Worker v2
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

// FCM — background messages
messaging.onBackgroundMessage(payload => {
  const { notification, data } = payload;
  const tipo = data?.tipo || 'notification';

  // Checkin/localização silenciosos — repassa para aba aberta
  if (['checkin_request','location_request'].includes(tipo)) {
    self.clients.matchAll({ type:'window' }).then(clients =>
      clients.forEach(c => c.postMessage({ type: 'FCM_CMD', tipo, data }))
    );
    return; // sem notificação visual
  }

  // Notificação visual
  self.registration.showNotification(notification?.title || 'SYSACK', {
    body:    notification?.body || data?.mensagem || '',
    icon:    '/icon-192.png',
    badge:   '/icon-192.png',
    tag:     tipo,
    renotify: true,
    data:    { url: data?.url || '/', tipo },
  });
});

// Clique na notificação
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    self.clients.matchAll({ type:'window', includeUncontrolled:true }).then(clients => {
      const ex = clients.find(c => c.url.includes(self.location.origin));
      if (ex) { ex.focus(); ex.navigate(url); }
      else self.clients.openWindow(url);
    })
  );
});

// Mensagens do app
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

// Cache offline
const VER    = 'sysack-v2.1-fcm';
const STATIC = VER + '-static';
const NO_CACHE = [/firestore\.googleapis\.com/,/identitytoolkit/,/cloudfunctions/,/fcm\.googleapis/,/firebase-messaging/,/recaptcha/];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(STATIC)
      .then(c => Promise.allSettled(['/','/index.html','/manifest.json'].map(u => c.add(u).catch(()=>{}))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k=>k.startsWith('sysack-')&&!k.startsWith(VER)).map(k=>caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = e.request.url;
  if (NO_CACHE.some(p=>p.test(url)) || url.startsWith('chrome-extension://')) return;
  if (url.endsWith('.html') || url.endsWith('/')) {
    e.respondWith(fetch(e.request).then(r=>{if(r.ok){caches.open(STATIC).then(c=>c.put(e.request,r.clone()));}return r;}).catch(()=>caches.match(e.request)));
  } else if (/\.(js|css|png|jpg|svg|ico|woff2?)$/.test(url)) {
    e.respondWith(caches.match(e.request).then(c=>c||fetch(e.request)));
  }
});
