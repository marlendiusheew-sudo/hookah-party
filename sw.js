// Офлайн-режим Hookah Party. Страница берётся из сети (если сети нет — из кеша),
// файлы с версией в адресе (?v=N) — сразу из кеша. API и панель администратора не кешируются никогда.
// Версию VERSION повышать вместе с ?v= в index.html (это проверяет npm test).
const VERSION = 28;
const CACHE = 'hp-v' + VERSION;
const CORE = ['./', `styles.css?v=${VERSION}`, `app.js?v=${VERSION}`, `art.js?v=${VERSION}`, `map-data.js?v=${VERSION}`, 'manifest.webmanifest', 'icon-192.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.includes('/api/') || url.pathname.endsWith('/admin.js')) return;
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put('./', copy)); }
      return res;
    }).catch(() => caches.match('./')));
    return;
  }
  e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => {
    if (res.ok && url.search.startsWith('?v=')) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
    return res;
  })));
});
