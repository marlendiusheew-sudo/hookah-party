'use strict';
// Сигналы безопасности администратору: уведомление «security_alert» каждому владельцу (роль admin + номер в ADMIN_PHONES,
// lib/panel.js). Поводы: блокировка входа после неверных паролей, поиск скрытой панели, блокировка панели, всплеск отчётов CSP,
// вход в панель с нового адреса. Сигнал одного вида — не чаще раза в 30 минут: подробности всё равно в журнале (audit).
// В тексте сигнала нет секретов и полных номеров, у IP-адреса скрыты последние цифры. Счётчики — в памяти процесса.
const crypto = require('node:crypto');
const { isAdminUser } = require('./panel');
const { uid, nowIso } = require('./util');
const { log } = require('./guard');

const ALERTS = { throttleMs: 30 * 60e3, probe: [3, 10 * 60e3], cspBurst: [5, 10 * 60e3] };

// IP без последних цифр: 95.56.x.x; у IPv6 — первые три группы (2a02:8109:b6c0:…).
function maskIp(ip) {
  const s = String(ip ?? '').trim().split('%')[0];
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/i.exec(s);
  if (v4) return `${v4[1]}.${v4[2]}.x.x`;
  if (!/^[0-9a-f:]{2,39}$/i.test(s) || !s.includes(':')) return '?';
  const [head, tail] = s.split('::'), h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = s.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return groups.slice(0, 3).map(g => g.replace(/^0+(?=.)/, '').toLowerCase()).join(':') + ':…';
}

// Скользящее окно: true, когда за windowMs набралось n событий с этим ключом (хранятся только последние n отметок).
const recent = new Map();
function burst(key, [n, windowMs], now = Date.now()) {
  const list = (recent.get(key) || []).filter(t => now - t < windowMs);
  list.push(now);
  recent.set(key, list.slice(-n));
  return list.length >= n;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of recent) if (now - v[v.length - 1] > 3600e3) recent.delete(k); }, 10 * 60e3).unref();

const sent = new Map();
// kind — вид сигнала (login_locked, admin_probe, admin_lock, csp_burst, admin_new_ip), detail — короткие подробности через « · ».
// key — ключ ограничения частоты (по умолчанию сам вид). Возвращает, скольким администраторам ушёл сигнал.
function alertAdmins(db, kind, detail = '', { key = kind, now = Date.now() } = {}) {
  if (now - (sent.get(key) ?? -Infinity) < ALERTS.throttleMs) return 0;
  const admins = db.q("SELECT * FROM users WHERE role = 'admin'").all().filter(isAdminUser);
  if (!admins.length) return 0;
  sent.set(key, now);
  const ref = `${kind}:${String(detail).replace(/[\u0000-\u001f\u007f]/g, ' ')}`.slice(0, 160);
  for (const a of admins) db.q("INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES (?, ?, 'security_alert', NULL, NULL, ?, ?)").run(uid('n', crypto), a.id, ref, nowIso());
  log('warn', 'Сигнал безопасности администратору', { kind, detail: ref });
  return admins.length;
}
// Для тестов: забыть отправленные сигналы и счётчики.
const resetAlerts = () => { sent.clear(); recent.clear(); };

module.exports = { ALERTS, alertAdmins, burst, maskIp, resetAlerts };
