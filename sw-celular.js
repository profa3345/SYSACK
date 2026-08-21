// SYSACK Mobile Agent — Service Worker
// Versão: 1.0.0
// Cache offline para funcionamento sem internet

const CACHE_NAME = 'sysack-mobile-v1';
const ASSETS = [
  '/instalar-celular.html',
  '/manifest-celular.json',
  '/app.css',
];

// Instala e cacheia os assets
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(ASSETS).catch(() => {});
    })
  );
  self.skipWaiting();
});

// Ativa e limpa caches antigos
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys
        .filter(k => k !== CACHE_NAME)
        .map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

// Serve do cache, fallback para rede
self.addEventListener('fetch', e => {
  // Requisições ao Firestore sempre vão para a rede
  if (e.request.url.includes('firestore.googleapis.com') ||
      e.request.url.includes('firebase')) {
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(resp => {
        // Cacheia novas respostas válidas
        if (resp && resp.status === 200 && resp.type === 'basic') {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => cached);
    })
  );
});
