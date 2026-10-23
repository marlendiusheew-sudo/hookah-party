'use strict';
// Ограничение частоты запросов (скользящее окно, в памяти процесса) и журнал безопасности.
// Для нескольких серверов те же счётчики переносятся в Redis — интерфейс останется прежним.
const net = require('node:net');

// В автотестах все запросы идут с одного адреса — там лимиты на адрес и на сервер выше (тесты на сами лимиты меняют их на время).
const TEST = process.env.NODE_ENV === 'test';
const envCount = (name, def) => { const n = parseInt(process.env[name], 10); return n > 0 ? n : def; };

// «Адрес» в лимитах — IP (ipNet): IPv4 целиком, у IPv6 — сеть /64.
const LIMITS = {
  apiPerIp: [600, 10 * 60e3],       // любые запросы к API с одного адреса: 600 за 10 минут
  writePerUser: [120, 10 * 60e3],   // изменения от одного пользователя: 120 за 10 минут
  authPerIp: [TEST ? 1000 : 17, 3600e3], // вход, SMS, регистрация с одного адреса: 17 в час
  // неверных паролей на один номер: 17 в час. Считаются только ошибки — удачный вход и запросы кода счётчик не тратят,
  // поэтому чужой человек не закроет владельцу вход, а исчерпанный счётчик закрывает только вход паролем, не по коду из SMS.
  authPerPhone: [17, 3600e3],
  smsPerPhone: [3, 10 * 60e3],      // кодов на номер: 3 за 10 минут
  smsPerIp: [TEST ? 1000 : 10, 3600e3], smsPerIpDay: [TEST ? 1000 : 30, 864e5], // запросов кода с одного адреса: 10 в час и 30 в сутки
  // всего SMS с сервера на все номера: в час и в сутки (SMS_PER_HOUR, SMS_PER_DAY в .env). С 80% суточного лимита — сигнал
  // владельцу, на 100% отправка останавливается (503), пока окно не освободится: так перебор чужих номеров не съест бюджет SMS.
  smsPerHour: envCount('SMS_PER_HOUR', TEST ? 1000 : 60), smsPerDay: envCount('SMS_PER_DAY', TEST ? 5000 : 300), smsAlertShare: 0.8,
  accountsPerIp: 3,                 // новых аккаунтов с одного адреса за сутки
  failsBeforeLock: 5, lockMs: 5 * 60e3,
  codeTtlMs: 5 * 60e3, codeAttempts: 5,
  sessionMs: 30 * 864e5,
  eventsPerDay: 12,                 // созданий сборов за сутки (и отдельно 12 отмен)
  adminStepUpMs: 15 * 60e3,         // доступ к панели администратора после ввода пароля
  smsResetMs: 15 * 60e3,            // после входа по коду из SMS пароль можно сменить без текущего — столько времени
  invitesPerEvent: 60,              // всего приглашённых в одном сборе (по ссылке больше не добавить)
  clientErrors: [20, 3600e3],       // отчётов об ошибках со страницы с одного адреса в час
  cspReports: [20, 3600e3],         // отчётов о заблокированном коде (CSP, Trusted Types) с одного адреса в час
  cspGlobal: [300, 3600e3],         // таких отчётов в журнал со всех адресов вместе за час
  chatCooldownMs: 3 * 60e3, chatPerEvent: [10, 864e5], chatGlobal: [144, 7 * 3600e3]
};

// Адрес для лимитов и квот: IPv4 — целиком, IPv6 — его сеть /64. Один абонент обычно получает целую /64 (2^64 адресов),
// и, если считать по полному адресу, перебор адресов внутри своей сети обходит любой лимит. IPv4 внутри IPv6 (::ffff:1.2.3.4) —
// это IPv4. В журнал безопасности по-прежнему пишется полный адрес.
function ipNet(ip) {
  const s = String(ip ?? '').trim().toLowerCase().replace(/%.*$/, '');
  if (!net.isIPv6(s)) return s || 'unknown';
  let t = s;
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(t);
  if (v4) { const b = v4.slice(1).map(Number); t = t.slice(0, v4.index) + ((b[0] << 8) + b[1]).toString(16) + ':' + ((b[2] << 8) + b[3]).toString(16); }
  const [head, tail] = t.split('::'), h = head ? head.split(':') : [], tl = tail ? tail.split(':') : [];
  const g = (t.includes('::') ? [...h, ...Array(8 - h.length - tl.length).fill('0'), ...tl] : h).map(x => parseInt(x, 16));
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) return [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.');
  return g.slice(0, 4).map(x => x.toString(16)).join(':') + '::/64';
}

// Счётчик помнит своё окно: чистка не должна забыть суточный лимит через час.
const windows = new Map();
function hit(key, [max, windowMs], consume = true) {
  const now = Date.now(), list = (windows.get(key)?.t || []).filter(t => now - t < windowMs);
  if (list.length >= max) { windows.set(key, { t: list, ms: windowMs }); return { ok: false, retryAfter: Math.ceil((list[0] + windowMs - now) / 1000) }; }
  if (consume) list.push(now);
  windows.set(key, { t: list, ms: windowMs });
  return { ok: true, left: max - list.length };
}
// Чистка устаревших счётчиков раз в 10 минут.
setInterval(() => { const now = Date.now(); for (const [k, v] of windows) if (!v.t.length || now - v.t[v.t.length - 1] > v.ms) windows.delete(k); }, 10 * 60e3).unref();

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
  // В journald — без userId: после удаления аккаунта строка не должна указывать на человека (fail2ban нужен только IP).
  if (process.env.NODE_ENV !== 'test') process.stdout.write(JSON.stringify({ at, level: 'audit', type, userId: null, ip, detail }) + '\n');
}
function log(level, msg, extra = {}) {
  if (process.env.NODE_ENV === 'test' && level !== 'error') return;
  process.stdout.write(JSON.stringify({ at: new Date().toISOString(), level, msg, ...extra }) + '\n');
}

module.exports = { LIMITS, hit, ipNet, lockLeft, failAttempt, clearFails, audit, log };
