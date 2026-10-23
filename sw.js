// Офлайн-режим Hookah Party. Страница берётся из сети (если сети нет — из кеша),
// файлы с версией в адресе (?v=N) и шрифты (версия в имени файла) — сразу из кеша. API и панель администратора не кешируются никогда.
// Версию VERSION повышать вместе с ?v= в index.html (это проверяет npm test).
const VERSION = 29;
const CACHE = 'hp-v' + VERSION;
// Шрифты для русского и английского текста — заранее; остальные наборы (киргизские буквы) — когда понадобятся.
const FONTS = ['unbounded-v12', 'golostext-v7', 'jetbrainsmono-v24'].flatMap(f => [`fonts/${f}-latin.woff2`, `fonts/${f}-cyrillic.woff2`]);
const CORE = ['./', `styles.css?v=${VERSION}`, `app.js?v=${VERSION}`, `art.js?v=${VERSION}`, `map-data.js?v=${VERSION}`, 'manifest.webmanifest', 'icon-192.png'];
// Сама страница сайта: корень или index.html. Только она хранится как офлайн-версия './'.
const ROOT = new URL('./', self.location).pathname;
const isShell = url => url.pathname === ROOT || url.pathname === ROOT + 'index.html';

self.addEventListener('install', e => {
  // Шрифты — по возможности: без них сайт всё равно работает (системными шрифтами), и офлайн-режим из-за них не должен ломаться.
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE).then(() => c.addAll(FONTS).catch(() => {}))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.includes('/api/') || url.pathname.endsWith('/admin.js')) return;
  if (req.mode === 'navigate') {
    // Офлайн-версию обновляет только сама страница сайта и только HTML: переход на картинку или файл сайта
    // (например, на /og.png по чужой ссылке) не должен подменить её. Сервер ответил ошибкой 5xx — тоже показываем сохранённую.
    if (!isShell(url)) return;
    e.respondWith(fetch(req).then(res => {
      if (res.ok && /^text\/html\b/i.test(res.headers.get('content-type') || '')) { const copy = res.clone(); caches.open(CACHE).then(c => c.put('./', copy)); }
      return res.status >= 500 ? caches.match('./').then(hit => hit || res) : res;
    }).catch(() => caches.match('./')));
    return;
  }
  e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => {
    if (res.ok && (url.search.startsWith('?v=') || /\/fonts\/[a-z0-9-]+\.woff2$/.test(url.pathname))) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
    return res;
  })));
});
