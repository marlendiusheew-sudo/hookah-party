'use strict';
// Сроки хранения и удаление данных — то, что обещано в политике конфиденциальности. Чистка запускается при старте
// сервера и раз в час (server/index.js), её можно вызвать и вручную: purgeOld(db).
//  · журнал безопасности (audit) — 90 дней;
//  · журнал созданий и отмен сборов (event_log) — 2 дня: он нужен только для суточных лимитов;
//  · истёкшие сессии и коды из SMS — сразу после истечения;
//  · устройства для уведомлений о входе (known_devices) — пока с них входят, но не дольше года после последнего входа;
//  · IP-адрес, с которого создан аккаунт (users.created_ip), — 90 дней, как журнал;
//  · в сессиях — только подпись устройства без версий (lib/ua.js): сырой User-Agent из сессий, записанных до этого правила, заменяется подписью.
// Удалённое база затирает нулями (secure_delete, lib/db.js), а после чистки и удаления аккаунта WAL переносится в файл базы
// и обнуляется (db.wipe): прежние версии страниц с удалённым текстом не остаются ни в файле, ни в новых резервных копиях.
const crypto = require('node:crypto');
const { uid: newId } = require('./util');
const { parseUA } = require('./ua');

const DAY = 864e5;
const RETENTION = { auditDays: 90, eventLogDays: 2, knownDevicesDays: 365, createdIpDays: 90, notificationsDays: 180 };

// now — момент «сейчас» в миллисекундах (для тестов). Возвращает, сколько строк удалено или обезличено в каждой таблице.
function purgeOld(db, now = Date.now()) {
  const n = r => Number(r.changes) || 0;
  // Сырой User-Agent узнаём по «/» или скобкам: в подписи («Chrome · macOS») их не бывает.
  const rawUa = db.q("SELECT token_hash, ua FROM sessions WHERE ua LIKE '%/%' OR ua LIKE '%(%'").all();
  for (const s of rawUa) db.q('UPDATE sessions SET ua = ? WHERE token_hash = ?').run(parseUA(s.ua).label, s.token_hash);
  const res = {
    // audit.at — строка ISO (toISOString), поэтому сравнение строк совпадает со сравнением времени.
    audit: n(db.q('DELETE FROM audit WHERE at < ?').run(new Date(now - RETENTION.auditDays * DAY).toISOString())),
    eventLog: n(db.q('DELETE FROM event_log WHERE at < ?').run(now - RETENTION.eventLogDays * DAY)),
    sessions: n(db.q('DELETE FROM sessions WHERE expires_at < ?').run(now)),
    smsCodes: n(db.q('DELETE FROM sms_codes WHERE expires_at < ?').run(now)),
    devices: n(db.q('DELETE FROM known_devices WHERE last_at < ?').run(now - RETENTION.knownDevicesDays * DAY)),
    // Уведомления старше полугода никому не нужны, а иначе таблица растёт бесконечно (и её можно засорять нарочно).
    notifications: n(db.q('DELETE FROM notifications WHERE at < ?').run(new Date(now - RETENTION.notificationsDays * DAY).toISOString())),
    createdIp: n(db.q('UPDATE users SET created_ip = NULL WHERE created_ip IS NOT NULL AND created_at < ?').run(new Date(now - RETENTION.createdIpDays * DAY).toISOString())),
    sessionUa: rawUa.length
  };
  // Раз в час — и всё, что удалили за час (отменённые сборы, сообщения), уходит и из WAL. Занято — через час ещё раз.
  db.wipe?.();
  return res;
}

// Удаление аккаунта: стираем пользователя и всё, что с ним связано. Вызывается внутри транзакции (db.tx), см. POST /api/me/delete.
// Журнал безопасности не удаляется, а обезличивается: записи остаются без привязки к человеку и уходят через 90 дней.
function eraseUser(db, user) {
  const uid = user.id, idx = user.phone_idx, HOSTED = 'SELECT id FROM events WHERE host_id = ?';
  const run = (sql, ...args) => db.q(sql).run(...args);
  // Сборы, которые он организует, — целиком: гости, голоса, складчина, сообщения и реакции, рассказ, уведомления о них.
  run(`DELETE FROM notifications WHERE event_id IN (${HOSTED})`, uid);
  run(`DELETE FROM reactions WHERE comment_id IN (SELECT id FROM comments WHERE event_id IN (${HOSTED}))`, uid);
  for (const t of ['comments', 'invites', 'picks', 'bowls', 'paid', 'stories', 'story_fire']) run(`DELETE FROM ${t} WHERE event_id IN (${HOSTED})`, uid);
  run('DELETE FROM events WHERE host_id = ?', uid);
  // Его следы у других: ответы, голоса, сообщения и реакции на них, отзывы, миксы и лайки, друзья, уведомления от него и для него.
  run('DELETE FROM reactions WHERE comment_id IN (SELECT id FROM comments WHERE user_id = ?)', uid);
  run('DELETE FROM mix_likes WHERE mix_id IN (SELECT id FROM mixes WHERE author_id = ?)', uid);
  for (const t of ['reactions', 'comments', 'invites', 'picks', 'bowls', 'paid', 'story_fire', 'favs', 'reviews', 'mix_likes', 'event_log', 'sessions', 'known_devices']) run(`DELETE FROM ${t} WHERE user_id = ?`, uid);
  run('DELETE FROM mixes WHERE author_id = ?', uid);
  run('DELETE FROM friends WHERE user_id = ? OR friend_id = ?', uid, uid);
  run('DELETE FROM notifications WHERE user_id = ? OR actor_id = ?', uid, uid);
  // Приглашения «по номеру» и коды из SMS на его номер. Тех, кого позвал он сам, приглашение остаётся — без отметки, кто позвал.
  run('DELETE FROM invites WHERE phone_idx = ?', idx);
  run('UPDATE invites SET invited_by = NULL WHERE invited_by = ?', uid);
  run('DELETE FROM sms_codes WHERE phone_idx = ?', idx);
  // Журнал безопасности: убираем ссылку на человека (и его id из записей о действиях администратора).
  run('UPDATE audit SET user_id = NULL WHERE user_id = ?', uid);
  run("UPDATE audit SET detail = replace(detail, ?, '(—)') WHERE instr(detail, ?) > 0", `(${uid})`, `(${uid})`);
  // Страховка на будущее: таблица, добавленная позже со ссылкой на пользователя или его номер, тоже очищается.
  const cols = new Map([['user_id', uid], ['actor_id', uid], ['host_id', uid], ['author_id', uid], ['friend_id', uid], ['owner_id', uid], ['phone_idx', idx]]);
  for (const { name } of db.q("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()) {
    if (name === 'audit' || name === 'users') continue;
    for (const { name: col } of db.q(`PRAGMA table_info("${name}")`).all()) if (cols.has(col)) run(`DELETE FROM "${name}" WHERE "${col}" = ?`, cols.get(col));
  }
  run('DELETE FROM users WHERE id = ?', uid);
}

// Гости предстоящих сборов, которые он организует: [кому, название сбора]. «Предстоящий» — как в lib/api.js (isPast):
// сбор ещё идёт или впереди, то есть начался не раньше чем 4 часа назад. Нужен и консоли — показать, кого коснётся удаление.
function upcomingGuests(db, userId, now = Date.now()) {
  return db.q('SELECT id, title, at FROM events WHERE host_id = ?').all(userId).filter(e => !(new Date(e.at).getTime() < now - 4 * 3600e3))
    .flatMap(e => db.q("SELECT user_id FROM invites WHERE event_id = ? AND status = 'going' AND user_id IS NOT NULL AND user_id != ?").all(e.id, userId)
      .map(r => [r.user_id, e.title.slice(0, 60)]));
}

// Удаление аккаунта целиком — одно и то же для POST /api/me/delete (lib/api.js) и консоли (server/admin.js delete):
// одной транзакцией стираем всё (eraseUser), а гостям его предстоящих сборов — уведомление «Сбор отменён: организатор
// удалил аккаунт» (без автора: аккаунта больше нет). Запись в журнал (account_deleted) делает вызывающий: он знает, откуда запрос.
// Возвращает, скольким гостям ушло уведомление, или null, если пользователя уже нет (удалён параллельным запросом).
function deleteAccount(db, user, now = Date.now()) {
  const res = db.tx(() => {
    if (!db.q('SELECT 1 FROM users WHERE id = ?').get(user.id)) return null;
    const notices = upcomingGuests(db, user.id, now);
    eraseUser(db, user);
    const at = new Date(now).toISOString();
    for (const [to, title] of notices)
      db.q("INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES (?, ?, 'cancelled', NULL, NULL, ?, ?)").run(newId('n', crypto), to, title, at);
    return notices.length;
  });
  // Удалённое уже затёрто в страницах базы (secure_delete); прежние версии страниц уходят и из WAL. Занято — при чистке через час.
  if (res !== null) db.wipe?.();
  return res;
}

module.exports = { purgeOld, eraseUser, deleteAccount, upcomingGuests, RETENTION };
