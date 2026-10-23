'use strict';
// Сервер Hookah Party: сайт + API на одном адресе. Только встроенные модули Node 24 — ни одной сторонней зависимости.
// Запуск: npm start (или node server/index.js). Настройки — переменные окружения или файл .env.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

// .env без сторонних библиотек: KEY=VALUE, строки с # — комментарии. Уже заданные переменные не перезаписываются.
(function loadEnv() {
  const file = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

const { open } = require('./lib/db');
const { seed } = require('./lib/seed');
const { match } = require('./lib/api');
const { ApiError } = require('./lib/util');
const { LIMITS, hit, ipNet, audit, log } = require('./lib/guard');
const { sha256, sameHash } = require('./lib/secure');
const { isAdminUser, panelCode } = require('./lib/panel');
const { purgeOld } = require('./lib/retention');

const ROOT = path.join(__dirname, '..');
const PROD = process.env.NODE_ENV === 'production';

// Отдаём только эти файлы сайта — никаких произвольных путей с диска.
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'], '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/art.js': ['art.js', 'text/javascript; charset=utf-8'], '/map-data.js': ['map-data.js', 'text/javascript; charset=utf-8'],
  '/.well-known/security.txt': ['.well-known/security.txt', 'text/plain; charset=utf-8'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'], '/icon-192.png': ['icon-192.png', 'image/png'],
  '/icon-512.png': ['icon-512.png', 'image/png'], '/apple-touch-icon.png': ['apple-touch-icon.png', 'image/png'],
  '/sw.js': ['sw.js', 'text/javascript; charset=utf-8'], '/og.png': ['og.png', 'image/png']
};
// Шрифты сайта лежат в fonts/ (не на Google Fonts). Отдаём только файлы .woff2 с простыми именами, найденные при запуске.
// В имени файла есть версия шрифта (unbounded-v12-…), поэтому файл не меняется и кешируется надолго.
try {
  for (const f of fs.readdirSync(path.join(ROOT, 'fonts'))) if (/^[a-z0-9-]+\.woff2$/.test(f)) STATIC['/fonts/' + f] = ['fonts/' + f, 'font/woff2'];
} catch (e) { /* папки нет — сайт покажется системными шрифтами */ }

// Та же политика, что в <meta> index.html (тест сверяет их). hp-sanitize — политика Trusted Types, которой фильтр разметки
// в app.js разбирает строку в отдельном документе.
const CSP = ["default-src 'none'", "script-src 'self'", "style-src 'self' 'unsafe-inline'",
  "style-src-elem 'self'", "style-src-attr 'unsafe-inline'", "font-src 'self'",
  "img-src 'self' data: blob:", "connect-src 'self'", "manifest-src 'self'", "media-src 'none'", "object-src 'none'", "frame-src 'none'",
  "worker-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "require-trusted-types-for 'script'", "trusted-types default hp-sanitize"].join('; ');

function securityHeaders(req, res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (PROD || req.headers['x-forwarded-proto'] === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

// За nginx берём ПОСЛЕДНИЙ адрес из X-Forwarded-For: его дописал наш прокси, а первые клиент может подделать.
const clientIp = req => (process.env.TRUST_PROXY === '1' && String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()) || req.socket.remoteAddress || 'unknown';
const cookies = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
// Картинка из API (фото профиля): свой тип, ETag и кеш только в браузере этого человека (private) — адрес с версией (?v=) меняется вместе с фото.
function sendImage(req, res, { type, body, etag }) {
  const head = { 'Content-Type': type, ETag: etag, 'Cache-Control': 'private, max-age=86400' };
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, head); return res.end(); }
  res.writeHead(200, { ...head, 'Content-Length': body.length });
  res.end(body);
}
function readBody(req, limit = 512 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(new ApiError(413, 'too_large', 'Слишком большой запрос.', 'Request too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!size) return resolve({});
      try {
        // Отбрасываем ключи, которыми подменяют прототипы объектов, и toString/valueOf —
        // иначе объект-ловушка вида {"toString":1} ломает приведение String(...) в проверках и даёт 500 вместо чистого ответа.
        const obj = JSON.parse(Buffer.concat(chunks).toString('utf8'), (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype' || k === 'toString' || k === 'valueOf') ? undefined : v);
        resolve(obj && typeof obj === 'object' ? obj : {});
      } catch (e) { reject(new ApiError(400, 'bad_json', 'Некорректный запрос.', 'Malformed request.')); }
    });
    req.on('error', reject);
  });
}

function createServer(db) {
  const srv = http.createServer(async (req, res) => {
    securityHeaders(req, res);
    // Кривой адрес запроса (например, «//[» или битое %-кодирование) не должен ронять процесс: new URL бросает исключение,
    // поэтому разбираем до try и на ошибке отвечаем 400, а не падаем необработанным отклонением промиса.
    let url;
    try { url = new URL(req.url, 'http://local'); }
    catch (e) { return sendJson(res, 400, { error: 'bad_request', message: { ru: 'Некорректный адрес запроса.', en: 'Malformed request target.' } }); }
    // ip — полный адрес (в журнал), net — он же для лимитов: у IPv6 — сеть /64 (lib/guard.js ipNet).
    const ip = clientIp(req), net = ipNet(ip);
    try {
      if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url, db);
      // GET /api/health в общий лимит не входит: он ничего не стоит, а по нему страница решает, есть ли сервер. Упрись он в лимит
      // у людей за одним адресом (мобильный оператор, Wi-Fi заведения) — у всех них вместо сайта был бы экран «сервер недоступен».
      if (!(req.method === 'GET' && url.pathname === '/api/health')) {
        const lim = hit('api:' + net, LIMITS.apiPerIp);
        if (!lim.ok) throw new ApiError(429, 'rate_limited', 'Слишком много запросов. Подождите немного.', 'Too many requests. Please wait a moment.', { retryAfter: lim.retryAfter });
      }
      const found = match(req.method, url.pathname);
      if (!found) throw new ApiError(404, 'not_found', 'Неизвестный адрес API.', 'Unknown API endpoint.');
      const write = req.method !== 'GET';
      if (write) {
        // Запросы на изменение — только с нашего сайта: проверяем Origin и тип содержимого.
        const origin = req.headers.origin, host = req.headers.host;
        // Кривой или «null» Origin разобрать нельзя — значит, точно не наш сайт: отклоняем как чужой, а не падаем с 500.
        if (origin) { let oh = null; try { oh = new URL(origin).host; } catch (e) { /* не разбирается — чужой */ } if (oh !== host) throw new ApiError(403, 'bad_origin', 'Запрос с чужого сайта отклонён.', 'Cross-site request rejected.'); }
        const hasBody = +(req.headers['content-length'] || 0) > 0 || !!req.headers['transfer-encoding'];
        if (hasBody && !/^application\/json\b/.test(req.headers['content-type'] || '')) throw new ApiError(415, 'bad_type', 'Нужен JSON.', 'JSON required.');
      }
      const ctx = { db, req, res, ip, net, params: found.params, body: write ? await readBody(req) : {} };
      ctx.setCookie = (value, maxAgeMs) => res.setHeader('Set-Cookie', `hp_sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${PROD ? '; Secure' : ''}`);
      // Сессия по cookie: в базе хранится только хэш токена.
      const sid = cookies(req).hp_sid;
      if (sid) {
        const s = db.q('SELECT * FROM sessions WHERE token_hash = ?').get(sha256(sid));
        if (s && s.expires_at > Date.now()) {
          ctx.session = s; ctx.user = db.q('SELECT * FROM users WHERE id = ?').get(s.user_id);
          if (Date.now() - s.last_seen > 60e3) db.q('UPDATE sessions SET last_seen = ? WHERE token_hash = ?').run(Date.now(), s.token_hash);
        } else if (s) db.q('DELETE FROM sessions WHERE token_hash = ?').run(s.token_hash);
      }
      if (found.route.opt.auth && !ctx.user) throw new ApiError(401, 'auth_required', 'Войдите, чтобы продолжить.', 'Sign in to continue.');
      // Для вошедших — CSRF-токен в заголовке на каждое изменение.
      if (write && ctx.session && !sameHash(String(req.headers['x-csrf-token'] || ''), ctx.session.csrf)) throw new ApiError(403, 'bad_csrf', 'Сессия устарела. Обновите страницу.', 'Session out of date. Reload the page.');
      if (write && ctx.user) {
        const w = hit('write:' + ctx.user.id, LIMITS.writePerUser);
        if (!w.ok) throw new ApiError(429, 'rate_limited', 'Слишком много действий подряд. Подождите немного.', 'Too many actions in a row. Please wait.', { retryAfter: w.retryAfter });
      }
      const out = await found.route.fn(ctx);
      if (out?.image) return sendImage(req, res, out.image);
      const payload = found.route.opt.data ? { ok: true, data: require('./lib/api').bootstrap(db, ctx.user, ctx.session) } : (out ?? { ok: true });
      sendJson(res, 200, payload);
    } catch (e) {
      // Все потоки для проверки паролей заняты, очередь полна (lib/secure.js): просим повторить через пару секунд.
      const err = e?.code === 'ARGON_BUSY' ? new ApiError(503, 'busy', 'Сервер сейчас занят. Попробуйте через несколько секунд.', 'The server is busy right now. Try again in a few seconds.', { retryAfter: 5 }) : e;
      if (err instanceof ApiError) {
        if (err.status === 403 && /bad_origin|bad_csrf/.test(err.code)) audit(db, { type: 'csrf_blocked', ip, detail: url.pathname });
        // Лимиты и «занято» — со стандартным заголовком Retry-After (секунды), не только в теле ответа.
        if (err.extra?.retryAfter > 0) res.setHeader('Retry-After', String(Math.ceil(err.extra.retryAfter)));
        return sendJson(res, err.status, { error: err.code, message: { ru: err.ru, en: err.en }, ...err.extra });
      }
      log('error', 'Ошибка обработки запроса', { path: url.pathname, err: err.message });
      sendJson(res, 500, { error: 'server_error', message: { ru: 'Ошибка сервера. Мы уже разбираемся.', en: 'Server error. We are on it.' } });
    }
  });
  // Медленные клиенты не держат соединения бесконечно (nginx режет раньше, это вторая линия).
  srv.headersTimeout = 15e3; srv.requestTimeout = 30e3;
  return srv;
}

// Код панели администратора отдаётся только вошедшему администратору — остальным его просто нет.
function isAdminRequest(req, db) {
  const sid = cookies(req).hp_sid;
  if (!sid) return false;
  const s = db.q('SELECT s.expires_at, u.role, u.phone_idx FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').get(sha256(sid));
  return !!s && s.expires_at > Date.now() && isAdminUser(s);
}
function serveStatic(req, res, url, db) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  if (url.pathname === '/admin.js') {
    // Панель хранится зашифрованной; расшифровываем в памяти и отдаём только администратору. Остальным её «нет».
    const code = isAdminRequest(req, db) ? panelCode() : null;
    if (!code) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'private, no-store' });
    return res.end(req.method === 'HEAD' ? undefined : code);
  }
  const entry = STATIC[url.pathname];
  if (!entry) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
  const [file, type] = entry;
  fs.readFile(path.join(ROOT, file), (err, data) => {
    if (err) { res.writeHead(404); return res.end(); }
    // HTML — всегда свежий, шрифты (версия в имени) — на год, остальное — на сутки (в адресах файлов есть ?v=версия).
    const cache = type.startsWith('text/html') || file === 'sw.js' ? 'no-cache' : type === 'font/woff2' ? 'public, max-age=31536000, immutable' : 'public, max-age=86400';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': cache });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

async function start() {
  const db = open(process.env.DB_PATH || path.join(__dirname, 'data', 'hookah.db'));
  // Демо-пользователи с известным паролем нужны только для разработки — в рабочую базу их не добавляем никогда.
  if (process.env.SEED !== '0' && !PROD && await seed(db)) log('info', 'База пустая — добавлены демо-данные (пароль у тестовых пользователей: hookah)');
  // Сроки хранения (lib/retention.js): при запуске и раз в час удаляем журнал старше 90 дней, истёкшие сессии и коды,
  // устройства, с которых не входили год, IP регистрации старше 90 дней.
  const purge = () => { try { const n = purgeOld(db); if (n.audit || n.eventLog || n.devices || n.createdIp || n.sessionUa) log('info', 'Удалены устаревшие записи', n); } catch (e) { log('error', 'Чистка устаревших данных не удалась', { err: e.message }); } };
  purge();
  setInterval(purge, 3600e3).unref();
  const port = +process.env.PORT || 3000;
  const server = createServer(db);
  // В production Node слушает только 127.0.0.1: снаружи к нему можно попасть лишь через nginx (HOST= — чтобы изменить).
  server.listen(port, process.env.HOST || (PROD ? '127.0.0.1' : undefined), () => log('info', `Hookah Party: http://localhost:${port}`, { sms: process.env.SMS_PROVIDER || 'dev', env: process.env.NODE_ENV || 'development' }));
  const stop = () => server.close(() => { db.close(); process.exit(0); });
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  return server;
}

if (require.main === module) start().catch(e => { log('error', 'Сервер не запустился', { err: e.message }); process.exit(1); });
module.exports = { createServer, start };
