'use strict';
// Ограничение частоты запросов (скользящее окно, в памяти процесса) и журнал безопасности.
// Для нескольких серверов те же счётчики переносятся в Redis — интерфейс останется прежним.

const LIMITS = {
  apiPerIp: [600, 10 * 60e3],       // любые запросы к API с одного IP: 600 за 10 минут
  writePerUser: [120, 10 * 60e3],   // изменения от одного пользователя: 120 за 10 минут
  authPerIp: [17, 3600e3],          // вход, SMS, регистрация с одного IP: 17 в час
  authPerPhone: [17, 3600e3],       // то же для одного номера
  smsPerPhone: [3, 10 * 60e3],      // кодов на номер: 3 за 10 минут
  accountsPerIp: 3,                 // аккаунтов с одного IP
  failsBeforeLock: 5, lockMs: 5 * 60e3,
  codeTtlMs: 5 * 60e3, codeAttempts: 5,
  sessionMs: 30 * 864e5,
  chatCooldownMs: 3 * 60e3, chatPerEvent: [10, 864e5], chatGlobal: [144, 7 * 3600e3]
};

const windows = new Map();
function hit(key, [max, windowMs], consume = true) {
  const now = Date.now(), list = (windows.get(key) || []).filter(t => now - t < windowMs);
  if (list.length >= max) { windows.set(key, list); return { ok: false, retryAfter: Math.ceil((list[0] + windowMs - now) / 1000) }; }
  if (consume) list.push(now);
  windows.set(key, list);
  return { ok: true, left: max - list.length };
}
// Чистка устаревших счётчиков раз в 10 минут.
setInterval(() => { const now = Date.now(); for (const [k, v] of windows) if (!v.length || now - v[v.length - 1] > 3600e3) windows.delete(k); }, 10 * 60e3).unref();

const locks = new Map();
const lockLeft = key => { const l = locks.get(key); return l?.until > Date.now() ? l.until - Date.now() : 0; };
function failAttempt(key) {
  const l = locks.get(key);
  const cur = l && !(l.until && l.until <= Date.now()) ? l : { n: 0 };
  cur.n = (cur.n || 0) + 1;
  if (cur.n >= LIMITS.failsBeforeLock) { locks.set(key, { n: 0, until: Date.now() + LIMITS.lockMs }); return 0; }
  locks.set(key, cur);
  return LIMITS.failsBeforeLock - cur.n;
}
const clearFails = key => locks.delete(key);

// Журнал: запись в таблицу audit и строка JSON в stdout (без паролей, кодов и полных номеров).
function audit(db, { type, userId = null, ip = null, detail = '' }) {
  const at = new Date().toISOString();
  try { db.q('INSERT INTO audit (at, user_id, ip, type, detail) VALUES (?, ?, ?, ?, ?)').run(at, userId, ip, type, String(detail).slice(0, 200)); } catch (e) { /* журнал не должен ронять запрос */ }
  if (process.env.NODE_ENV !== 'test') process.stdout.write(JSON.stringify({ at, level: 'audit', type, userId, ip, detail }) + '\n');
}
function log(level, msg, extra = {}) {
  if (process.env.NODE_ENV === 'test' && level !== 'error') return;
  process.stdout.write(JSON.stringify({ at: new Date().toISOString(), level, msg, ...extra }) + '\n');
}

module.exports = { LIMITS, hit, lockLeft, failAttempt, clearFails, audit, log };
