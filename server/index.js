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
const { LIMITS, hit, audit, log } = require('./lib/guard');
const { sha256, sameHash } = require('./lib/secure');
const { isAdminUser, panelCode } = require('./lib/panel');

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

const CSP = ["default-src 'none'", "script-src 'self'", "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
  "style-src-elem 'self' https://fonts.googleapis.com", "style-src-attr 'unsafe-inline'", "font-src https://fonts.gstatic.com",
  "img-src 'self' data: blob:", "connect-src 'self'", "manifest-src 'self'", "media-src 'none'", "object-src 'none'", "frame-src 'none'",
  "worker-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "require-trusted-types-for 'script'", "trusted-types default"].join('; ');

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

const clientIp = req => (process.env.TRUST_PROXY === '1' && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
const cookies = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, limit = 512 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(new ApiError(413, 'too_large', 'Слишком большой запрос.', 'Request too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!size) return resolve({});
      try {
        // Отбрасываем ключи, которыми подменяют прототипы объектов.
        const obj = JSON.parse(Buffer.concat(chunks).toString('utf8'), (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v);
        resolve(obj && typeof obj === 'object' ? obj : {});
      } catch (e) { reject(new ApiError(400, 'bad_json', 'Некорректный запрос.', 'Malformed request.')); }
    });
    req.on('error', reject);
  });
}

function createServer(db) {
  return http.createServer(async (req, res) => {
    securityHeaders(req, res);
    const url = new URL(req.url, 'http://local');
    const ip = clientIp(req);
    try {
      if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url, db);
      const lim = hit('api:' + ip, LIMITS.apiPerIp);
      if (!lim.ok) { res.setHeader('Retry-After', lim.retryAfter); throw new ApiError(429, 'rate_limited', 'Слишком много запросов. Подождите немного.', 'Too many requests. Please wait a moment.', { retryAfter: lim.retryAfter }); }
      const found = match(req.method, url.pathname);
      if (!found) throw new ApiError(404, 'not_found', 'Неизвестный адрес API.', 'Unknown API endpoint.');
      const write = req.method !== 'GET';
      if (write) {
        // Запросы на изменение — только с нашего сайта: проверяем Origin и тип содержимого.
        const origin = req.headers.origin, host = req.headers.host;
        if (origin && new URL(origin).host !== host) throw new ApiError(403, 'bad_origin', 'Запрос с чужого сайта отклонён.', 'Cross-site request rejected.');
        const hasBody = +(req.headers['content-length'] || 0) > 0 || !!req.headers['transfer-encoding'];
        if (hasBody && !/^application\/json\b/.test(req.headers['content-type'] || '')) throw new ApiError(415, 'bad_type', 'Нужен JSON.', 'JSON required.');
      }
      const ctx = { db, req, res, ip, params: found.params, body: write ? await readBody(req) : {} };
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
      const payload = found.route.opt.data ? { ok: true, data: require('./lib/api').bootstrap(db, ctx.user, ctx.session) } : (out ?? { ok: true });
      sendJson(res, 200, payload);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403 && /bad_origin|bad_csrf/.test(err.code)) audit(db, { type: 'csrf_blocked', ip, detail: url.pathname });
        return sendJson(res, err.status, { error: err.code, message: { ru: err.ru, en: err.en }, ...err.extra });
      }
      log('error', 'Ошибка обработки запроса', { path: url.pathname, err: err.message });
      sendJson(res, 500, { error: 'server_error', message: { ru: 'Ошибка сервера. Мы уже разбираемся.', en: 'Server error. We are on it.' } });
    }
  });
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
    // HTML — всегда свежий, остальное — кешируется (в адресах файлов есть ?v=версия).
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': type.startsWith('text/html') || file === 'sw.js' ? 'no-cache' : 'public, max-age=86400' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

async function start() {
  const db = open(process.env.DB_PATH || path.join(__dirname, 'data', 'hookah.db'));
  if (process.env.SEED !== '0' && await seed(db)) log('info', 'База пустая — добавлены демо-данные (пароль у тестовых пользователей: hookah)');
  // Раз в час чистим истёкшие сессии и коды.
  setInterval(() => { db.q('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()); db.q('DELETE FROM sms_codes WHERE expires_at < ?').run(Date.now()); }, 3600e3).unref();
  const port = +process.env.PORT || 3000;
  const server = createServer(db);
  server.listen(port, () => log('info', `Hookah Party: http://localhost:${port}`, { sms: process.env.SMS_PROVIDER || 'dev', env: process.env.NODE_ENV || 'development' }));
  const stop = () => server.close(() => { db.close(); process.exit(0); });
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  return server;
}

if (require.main === module) start().catch(e => { log('error', 'Сервер не запустился', { err: e.message }); process.exit(1); });
module.exports = { createServer, start };
