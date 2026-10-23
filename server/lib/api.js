'use strict';
// API Hookah Party. Каждая точка: проверка входа, прав, лимитов и данных; все SQL-запросы подготовленные.
const { crypto, encrypt, decrypt, phoneIndex, hashPassword, verifyPassword, burnTime, token: newToken, sha256, sameHash, smsCode } = require('./secure');
const { normPhone, validPhone, phonePrefixes, phoneAllowed, maskPhone, clean, validName, safeUrl, safeAvatar, AVATAR_MAX, isId, passIssue, fail, uid, nowIso } = require('./util');
const { LIMITS, hit, ipNet, lockLeft, failAttempt, clearFails, audit, log } = require('./guard');
const { TOBACCOS, BOWLS, EMOJI, venueById } = require('./catalog');
const { sendSms, exposeCode } = require('./sms');
const { isAdminUser } = require('./panel');
const { deleteAccount } = require('./retention');
const { parseUA } = require('./ua');
const { ALERTS, alertAdmins, burst, maskIp } = require('./alerts');
const totp = require('./totp');
const qr = require('./qr');

const id = p => uid(p, crypto);
const isPast = at => new Date(at).getTime() < Date.now() - 4 * 3600e3;
const wait = s => ({ retryAfter: s });
const minutes = s => Math.max(1, Math.ceil(s / 60));
// «Через сколько» для текста ошибки: до полутора часов — минуты, дальше — часы. [по-русски, по-английски]
const later = s => s > 90 * 60 ? [`${Math.ceil(s / 3600)} ч`, `${Math.ceil(s / 3600)} h`] : [`${minutes(s)} мин`, `${minutes(s)} min`];
// Номер пользователя для журнала и сигналов: код страны и последние три цифры.
const maskedOf = u => { try { return maskPhone(decrypt(u.phone_enc)); } catch (e) { return '••• ' + (u?.phone_tail || '?'); } };
// Сессия создана входом по коду из SMS меньше 15 минут назад: в ней пароль можно сменить без текущего («Забыли пароль?»).
const resetAllowed = s => !!s && s.via_sms_at > 0 && Date.now() - s.via_sms_at < LIMITS.smsResetMs;

// ---------- Данные для пользователя ----------
// Отдаём только то, что ему положено видеть:
//  · гостю без входа — вечера из «Истории» и имена с фото тех, кто в них и в каталоге что-то написал (PUBLIC_USERS).
//    Ни справочника людей, ни списков друзей, ни дат регистрации, ни цифр номеров;
//  · вошедшему — справочник людей (имя, фото, любимое заведение и табаки, последние цифры номера), свой список друзей
//    (чужие — никому), свои сборы целиком;
//  · чужой вечер из «Истории» — только то, что нужно рассказу: название, заведение, дата, организатор, рассказ, комментарии
//    и итоги вечера (сколько было гостей, какие табаки и чаши выбирали, кальяны и цена). Без адреса, описания, ссылки, списка гостей,
//    их ответов, голосов и оплат;
//  · полные номера — по правилу PHONE_VISIBLE, приглашения «по номеру» — организатору и тому, кто позвал.
// Фото — не сами картинки, а версия: картинка приходит по адресу /api/avatar/<id>?v=<версия> тем, кто видит имя.
// Кто «на виду»: организаторы вечеров с рассказом и авторы комментариев к рассказам, отзывов и миксов.
const PUBLIC_USERS = `SELECT host_id AS id FROM events WHERE id IN (SELECT event_id FROM stories)
  UNION SELECT user_id FROM comments WHERE kind = 'story' UNION SELECT user_id FROM reviews UNION SELECT author_id FROM mixes`;
// Полный номер пользователя X видит: сам X; взаимный друг (каждый добавил другого); организатор сбора, на который X идёт;
// гость, который идёт на сбор X. Остальным — последние три цифры. Ожидающие ответа и отказавшиеся номера не получают и не открывают.
const PHONE_VISIBLE = `SELECT f.friend_id AS id FROM friends f JOIN friends b ON b.user_id = f.friend_id AND b.friend_id = f.user_id WHERE f.user_id = ?1
  UNION SELECT i.user_id FROM invites i JOIN events e ON e.id = i.event_id WHERE e.host_id = ?1 AND i.status = 'going' AND i.user_id IS NOT NULL
  UNION SELECT e.host_id FROM invites i JOIN events e ON e.id = i.event_id WHERE i.user_id = ?1 AND i.status = 'going'`;
// Мои сборы: организую, приглашён по аккаунту или «по номеру» на мой номер (если организатор не убрал меня из сбора).
const MY_EVENTS = `SELECT id FROM events WHERE host_id = ?1 UNION SELECT event_id FROM invites WHERE user_id = ?1
  UNION SELECT event_id FROM invites WHERE phone_idx = ?2 AND user_id IS NULL AND event_id NOT IN (SELECT event_id FROM event_bans WHERE user_id = ?1)`;
const phoneOrNull = enc => { try { return decrypt(enc); } catch (e) { return null; } };
const masked = tail => `+996 ••• ••• ${tail}`;
function bootstrap(db, me, session) {
  const meId = me?.id || null;
  const mine = new Set(meId ? db.q(MY_EVENTS).all(meId, me.phone_idx).map(r => r.id) : []);
  const stories = new Map(db.q('SELECT * FROM stories').all().map(s => [s.event_id, s]));
  const evRows = db.q('SELECT * FROM events ORDER BY at').all().filter(e => mine.has(e.id) || stories.has(e.id));
  const group = (rows, key) => rows.reduce((m, r) => ((m[r[key]] ||= []).push(r), m), {});
  const invites = group(db.q('SELECT * FROM invites').all(), 'event_id');
  const picks = group(db.q('SELECT * FROM picks').all(), 'event_id');
  const bowls = group(db.q('SELECT * FROM bowls').all(), 'event_id');
  const paid = group(db.q('SELECT * FROM paid').all(), 'event_id');
  const comments = group(db.q('SELECT * FROM comments ORDER BY at').all(), 'event_id');
  const reacts = group(db.q('SELECT * FROM reactions').all(), 'comment_id');
  const fire = group(db.q('SELECT * FROM story_fire').all(), 'event_id');
  const favs = group(db.q('SELECT * FROM favs').all(), 'user_id');

  const visible = new Set(meId ? [meId, ...db.q(PHONE_VISIBLE).all(meId).map(r => r.id)] : []);
  const users = meId
    ? db.q('SELECT id, name, avatar_v, fav_venue, verified, phone_enc, phone_tail FROM users').all().map(u => ({
      id: u.id, name: u.name, avatar: u.avatar_v || null, favVenue: u.fav_venue, verified: !!u.verified,
      phone: visible.has(u.id) ? phoneOrNull(u.phone_enc) : null, phoneMasked: masked(u.phone_tail), favs: (favs[u.id] || []).map(f => f.tobacco_id),
      ...(u.id === meId ? { friends: db.q('SELECT friend_id FROM friends WHERE user_id = ?').all(meId).map(f => f.friend_id) } : {})
    }))
    : db.q(`SELECT id, name, avatar_v FROM users WHERE id IN (${PUBLIC_USERS})`).all().map(u => ({ id: u.id, name: u.name, avatar: u.avatar_v || null }));
  const comment = c => ({ id: c.id, userId: c.user_id, text: c.text, at: c.at, reactions: Object.fromEntries((reacts[c.id] || []).map(r => [r.user_id, r.emoji])) });
  // «Огонь»: сколько поставили и поставил ли я (кто именно — организатор узнаёт из уведомлений).
  const storyOf = (e, st) => st && { rating: st.rating, text: st.text, highlights: JSON.parse(st.highlights), at: st.at,
    fire: (fire[e.id] || []).length, fired: !!meId && (fire[e.id] || []).some(f => f.user_id === meId), comments: (comments[e.id] || []).filter(c => c.kind === 'story').map(comment) };
  const tally = (rows, key) => (rows || []).reduce((m, r) => ((m[r[key]] = (m[r[key]] || 0) + 1), m), {});
  const ownRow = new Set((meId ? db.q('SELECT event_id FROM invites WHERE user_id = ?').all(meId) : []).map(r => r.event_id));
  const events = evRows.map(e => {
    const member = mine.has(e.id), st = stories.get(e.id), inv = invites[e.id] || [];
    // Чужой вечер из «Истории»: без адреса, описания, ссылки, гостей и их голосов — только итоги.
    if (!member) return {
      id: e.id, title: e.title, venue: e.venue, venueId: e.venue_id, at: e.at, hostId: e.host_id, hookahs: e.hookahs, price: e.price, member,
      invites: [], picks: {}, bowls: {}, paid: {}, comments: [], remind: {}, notified: {},
      summary: { going: 1 + inv.filter(i => i.user_id && i.status === 'going').length, tobaccos: tally(picks[e.id], 'tobacco_id'), bowls: tally(bowls[e.id], 'bowl_id') },
      story: storyOf(e, st)
    };
    return {
      id: e.id, title: e.title, venue: e.venue, venueId: e.venue_id, address: e.address, mapUrl: e.map_url, at: e.at, hostId: e.host_id,
      createdAt: e.created_at, desc: e.descr, hookahs: e.hookahs, price: e.price, member,
      paid: Object.fromEntries((paid[e.id] || []).map(p => [p.user_id, true])),
      // Приглашение «по номеру» на мой номер — для меня это моё приглашение; остальные (и организатор) видят его как приглашение
      // по номеру, пока я не отвечу. Номер целиком — только организатору и тому, кто позвал.
      invites: inv.flatMap(i => i.user_id ? [{ userId: i.user_id, status: i.status, at: i.at }]
        : i.phone_idx === me.phone_idx ? (ownRow.has(e.id) ? [] : [{ userId: meId, status: i.status, at: i.at }])
          : [{ phone: e.host_id === meId || i.invited_by === meId ? phoneOrNull(i.phone_enc) : null, phoneMasked: masked(i.phone_tail), status: i.status }]),
      picks: (picks[e.id] || []).reduce((m, p) => ((m[p.user_id] ||= []).push(p.tobacco_id), m), {}),
      bowls: Object.fromEntries((bowls[e.id] || []).map(b => [b.user_id, b.bowl_id])),
      comments: (comments[e.id] || []).filter(c => c.kind === 'ev').map(comment),
      remind: {}, notified: {},
      story: storyOf(e, st) || undefined
    };
  });
  const reviews = db.q('SELECT * FROM reviews ORDER BY at DESC').all().map(r => ({ id: r.id, tobaccoId: r.tobacco_id, userId: r.user_id, rating: r.rating, text: r.text, at: r.at }));
  const likes = group(db.q('SELECT * FROM mix_likes').all(), 'mix_id');
  const mixes = db.q('SELECT * FROM mixes ORDER BY at DESC').all().map(m => ({ id: m.id, name: m.name, authorId: m.author_id, parts: JSON.parse(m.parts), likes: (likes[m.id] || []).map(l => l.user_id), at: m.at }));
  const notifications = meId ? db.q('SELECT * FROM notifications WHERE user_id = ? ORDER BY at DESC LIMIT 100').all(meId)
    .map(n => ({ id: n.id, type: n.type, actorId: n.actor_id, eventId: n.event_id, ref: n.ref, at: n.at, read: !!n.read })) : [];
  // Администратору — подключено ли приложение для кодов и открыта ли панель с кодом в этой сессии (сами секреты — никогда).
  const admin = isAdminUser(me);
  return {
    session: meId, role: me ? (admin ? 'admin' : 'user') : null, adminUntil: admin ? (session?.admin_until || 0) : 0, sessionAt: session?.created_at || null, sessionExp: session?.expires_at || null, csrf: session?.csrf || null,
    passwordResetAllowed: !!me && resetAllowed(session),
    // Коды стран, номера которых принимаются для регистрации и входа по SMS (ALLOWED_PHONE_PREFIXES): страница проверяет номер заранее.
    phoneCodes: phonePrefixes(),
    ...(admin ? { adminTotp: !!me.totp_secret_enc, adminMfa: !!session?.admin_mfa && session.admin_until > Date.now() } : {}),
    users, events, reviews, mixes, notifications, storiesSeeded: true
  };
}

// ---------- Помощники прав ----------
const getEvent = (db, eid) => { if (!isId(eid)) fail(404, 'not_found', 'Сбор не найден.', 'Event not found.'); return db.q('SELECT * FROM events WHERE id = ?').get(eid) || fail(404, 'not_found', 'Сбор не найден.', 'Event not found.'); };
// Убран ли человек из сбора организатором (DELETE /api/events/:id/invites): по ссылке и по приглашению «по номеру» он не вернётся.
const isBanned = (db, eid, uid2) => !!db.q('SELECT 1 FROM event_bans WHERE event_id = ? AND user_id = ?').get(eid, uid2);
// Приглашение человека: по аккаунту или «по номеру» на его номер (пока он не ответил, оно остаётся приглашением по номеру).
const myInvite = (db, eid, user) => db.q('SELECT * FROM invites WHERE event_id = ? AND user_id = ?').get(eid, user.id)
  || (isBanned(db, eid, user.id) ? undefined : db.q('SELECT * FROM invites WHERE event_id = ? AND phone_idx = ? AND user_id IS NULL').get(eid, user.phone_idx));
const isMember = (db, e, user) => e.host_id === user.id || !!myInvite(db, e.id, user);
const canVote = (db, e, user) => e.host_id === user.id || myInvite(db, e.id, user)?.status === 'going';
const needHost = (e, me) => { if (e.host_id !== me.id) fail(403, 'forbidden', 'Это может сделать только организатор.', 'Only the host can do this.'); };
const needMember = (db, e, me) => { if (!isMember(db, e, me)) fail(403, 'forbidden', 'Это закрытый сбор.', 'This is a private event.'); };
const needUpcoming = e => { if (isPast(e.at)) fail(409, 'past', 'Сбор уже прошёл.', 'The event has already passed.'); };
const goingIds = (db, e) => [e.host_id, ...db.q("SELECT user_id FROM invites WHERE event_id = ? AND status = 'going' AND user_id IS NOT NULL").all(e.id).map(r => r.user_id)];

function notify(db, userId, type, actorId, eventId = null, ref = null) {
  if (!userId || userId === actorId) return;
  db.q('INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id('n'), userId, type, actorId, eventId, ref, nowIso());
}
// Ответ на приглашение (и ответ по ссылке). Приглашение «по номеру» после ответа становится обычным — теперь организатор видит, кто это.
// У отказавшегося удаляются голоса, чаша и отметка об оплате; организатору — уведомление. Вызывается внутри транзакции.
function answer(db, e, user, status) {
  const own = db.q('SELECT id FROM invites WHERE event_id = ? AND user_id = ?').get(e.id, user.id);
  const byPhone = db.q('SELECT id FROM invites WHERE event_id = ? AND phone_idx = ? AND user_id IS NULL').get(e.id, user.phone_idx);
  if (own) db.q('UPDATE invites SET status = ?, at = ? WHERE id = ?').run(status, nowIso(), own.id);
  else if (byPhone) db.q('UPDATE invites SET user_id = ?, phone_idx = NULL, phone_enc = NULL, phone_tail = NULL, status = ?, at = ? WHERE id = ?').run(user.id, status, nowIso(), byPhone.id);
  else db.q('INSERT INTO invites (event_id, user_id, status, at) VALUES (?, ?, ?, ?)').run(e.id, user.id, status, nowIso());
  if (own && byPhone) db.q('DELETE FROM invites WHERE id = ?').run(byPhone.id);
  if (status !== 'going') for (const t of ['picks', 'bowls', 'paid']) db.q(`DELETE FROM ${t} WHERE event_id = ? AND user_id = ?`).run(e.id, user.id);
  notify(db, e.host_id, status === 'going' ? 'rsvp_going' : 'rsvp_declined', user.id, e.id);
}

// ---------- Сессии ----------
// viaSms — вход по коду из SMS: время входа запоминается в сессии (via_sms_at), см. resetAllowed и POST /api/me/password.
// Устройство сессии — только подпись без версий («Chrome · macOS», lib/ua.js), сырой User-Agent не храним.
function startSession(db, ctx, user, { viaSms = false } = {}) {
  const token = newToken(), csrf = newToken(), now = Date.now();
  db.q('INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen, ip, ua, via_sms_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sha256(token), user.id, csrf, now, now + LIMITS.sessionMs, now, ctx.ip, parseUA(ctx.req.headers['user-agent']).label, viaSms ? now : 0);
  ctx.setCookie(token, LIMITS.sessionMs);
  ctx.session = db.q('SELECT * FROM sessions WHERE token_hash = ?').get(sha256(token));
  ctx.user = user;
  knownDevice(db, ctx, user);
}
// Устройство входа (lib/ua.js): браузер, система и тип без версий. Регистрация и самый первый вход его просто запоминают;
// вход с устройства, которого ещё не было, когда другие уже есть, — уведомление пользователю и запись в журнал.
function knownDevice(db, ctx, user, { silent = false } = {}) {
  const d = parseUA(ctx.req.headers['user-agent']), now = Date.now();
  if (!silent && !db.q('SELECT 1 FROM known_devices WHERE user_id = ? AND fp = ?').get(user.id, d.fp) && db.q('SELECT 1 FROM known_devices WHERE user_id = ? LIMIT 1').get(user.id)) {
    notify(db, user.id, 'new_login', null, null, `${d.label} · ${maskIp(ctx.ip)}`);
    audit(db, { type: 'new_device_login', userId: user.id, ip: ctx.ip, detail: d.label });
  }
  db.q('INSERT INTO known_devices (user_id, fp, label, first_at, last_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (user_id, fp) DO UPDATE SET label = excluded.label, last_at = excluded.last_at')
    .run(user.id, d.fp, d.label, now, now);
  return d;
}

// ---------- Коды из SMS ----------
// Код привязан к запросу: POST /api/auth/sms отдаёт ключ запроса (challenge), в базе — только его хэш. Проверить код может лишь
// тот, у кого этот ключ: чужие неверные попытки не сжигают чужой код (иначе, перебирая коды, можно было бы не дать владельцу
// войти по SMS). Попыток на код — 5, новый запрос — новый код и новый ключ. keep — проверить, но пока не тратить.
const codeHash = (code, idx) => sha256(`${idx}:${code}`);
const CODE_MISSING = ['Сначала запросите код.', 'Request a code first.'];
function checkCode(db, idx, purpose, code, challenge, ip = null, { keep = false } = {}) {
  const row = db.q('SELECT * FROM sms_codes WHERE phone_idx = ?').get(idx);
  if (!row || row.purpose !== purpose || !row.challenge || typeof challenge !== 'string' || !sameHash(sha256(challenge), row.challenge)) fail(400, 'code_missing', ...CODE_MISSING);
  if (Date.now() > row.expires_at) fail(400, 'code_expired', 'Код устарел. Запросите новый.', 'The code has expired. Request a new one.');
  if (row.attempts >= LIMITS.codeAttempts) fail(429, 'code_attempts', 'Слишком много неверных попыток. Запросите новый код.', 'Too many wrong attempts. Request a new code.');
  if (!sameHash(codeHash(String(code || ''), idx), row.code_hash)) {
    db.q('UPDATE sms_codes SET attempts = attempts + 1 WHERE phone_idx = ?').run(idx);
    const left = LIMITS.codeAttempts - row.attempts - 1;
    audit(db, { type: 'code_fail', ip, detail: purpose });
    fail(400, 'code_wrong', `Код не подходит. Осталось попыток: ${left}.`, `Wrong code. Attempts left: ${left}.`, { left });
  }
  if (!keep) db.q('DELETE FROM sms_codes WHERE phone_idx = ?').run(idx);
}
// Попытки входа, запросы кода и регистрации с одного адреса (IPv4 или сеть /64 у IPv6, ctx.net): тратит каждый запрос.
function ipLimit(ctx) {
  const r = hit('auth:ip:' + ctx.net, LIMITS.authPerIp);
  if (!r.ok) { audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'ip' }); fail(429, 'rate_limited', `Слишком много попыток. Попробуйте через ${minutes(r.retryAfter)} мин.`, `Too many attempts. Try again in ${minutes(r.retryAfter)} min.`, wait(r.retryAfter)); }
}
// Неверные пароли на номер (LIMITS.authPerPhone): счётчик растёт только от ошибок — чужой человек, отправляя запросы на чужой
// номер, его не тратит, пока не ошибётся с паролем. Исчерпан — пароль этого номера до конца окна не проверяется (вход,
// смена пароля, удаление аккаунта), а вход по коду из SMS остаётся открытым: код сам доказывает, что телефон у владельца.
const passKey = idx => 'auth:ph:' + idx;
function passLimit(ctx, idx, detail) {
  const r = hit(passKey(idx), LIMITS.authPerPhone, false);
  if (r.ok) return;
  const m = minutes(r.retryAfter), sms = detail === 'ph';
  audit(ctx.db, { type: 'rate_limited', userId: ctx.user?.id, ip: ctx.ip, detail });
  fail(429, 'rate_limited', `Слишком много неверных паролей для этого номера. Попробуйте через ${m} мин${sms ? ' или войдите по коду из SMS' : ''}.`,
    `Too many wrong passwords for this number. Try again in ${m} min${sms ? ' or sign in with an SMS code' : ''}.`, wait(r.retryAfter));
}
const passFailed = idx => hit(passKey(idx), LIMITS.authPerPhone);
// sms — номер для входа по SMS и регистрации: только страны из ALLOWED_PHONE_PREFIXES (lib/util.js, по умолчанию +996).
function phoneOf(body, { sms = false } = {}) {
  const phone = normPhone(body.phone), bad = () => fail(400, 'bad_phone', 'Введите номер полностью, вместе с кодом страны.', 'Enter the full number including the country code.');
  if (!validPhone(phone)) bad();
  if (sms && !phoneAllowed(phone)) {
    const codes = phonePrefixes().map(p => '+' + p);
    if (codes.some(c => phone.startsWith(c.slice(1)))) bad();
    fail(400, 'phone_country', `Принимаем только номера с кодом ${codes.join(', ')}.`, `Only numbers starting with ${codes.join(', ')} are accepted.`);
  }
  return { phone, idx: phoneIndex(phone) };
}
// Новых аккаунтов с одного адреса (IPv4 или сеть /64) за сутки — по журналу регистраций: удаление аккаунта места не освобождает,
// а общий адрес мобильного оператора (много людей за одним IP) не закрывается навсегда. Проверяется и при запросе кода, и при
// самой регистрации: коды, запрошенные заранее, квоту не обходят.
function accountsQuota(ctx) {
  const since = new Date(Date.now() - 864e5).toISOString();
  const n = ctx.db.q("SELECT ip FROM audit WHERE type = 'register' AND at > ?").all(since).filter(r => ipNet(r.ip) === ctx.net).length;
  if (n < LIMITS.accountsPerIp) return;
  audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'accounts per ip' });
  fail(429, 'ip_accounts', `С одного адреса можно создать не больше ${LIMITS.accountsPerIp} аккаунтов в сутки.`, `At most ${LIMITS.accountsPerIp} accounts per day can be created from one address.`);
}

// ---------- Отправка SMS: лимиты и бюджет сервера ----------
// Бюджет — сколько SMS ушло за час и за сутки (по журналу, переживает перезапуск) плюс отправляемые прямо сейчас.
let smsInFlight = 0;
const smsSince = (db, ms) => db.q("SELECT COUNT(*) AS n FROM audit WHERE type = 'sms_sent' AND at > ?").get(new Date(Date.now() - ms).toISOString()).n + smsInFlight;
function smsLimits(ctx) {
  // С одного адреса — не больше LIMITS.smsPerIp кодов в час и smsPerIpDay в сутки (тратятся оба счётчика или ни одного).
  const lims = [['sms:ip:' + ctx.net, LIMITS.smsPerIp], ['sms:ipd:' + ctx.net, LIMITS.smsPerIpDay]];
  const over = lims.map(([k, l]) => hit(k, l, false)).find(r => !r.ok);
  if (over) {
    const [ru, en] = later(over.retryAfter);
    audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'sms ip' });
    fail(429, 'sms_ip_limit', `С этого адреса запрошено слишком много кодов. Попробуйте через ${ru}.`, `Too many codes have been requested from this address. Try again in ${en}.`, wait(over.retryAfter));
  }
  for (const [k, l] of lims) hit(k, l);
  // Бюджет сервера на все номера: исчерпан — SMS не отправляем, пока окно не освободится, владельцу — сигнал.
  const hour = smsSince(ctx.db, 3600e3), day = smsSince(ctx.db, 864e5);
  if (hour < LIMITS.smsPerHour && day < LIMITS.smsPerDay) return;
  const ms = day >= LIMITS.smsPerDay ? 864e5 : 3600e3;
  const first = ctx.db.q("SELECT MIN(at) AS at FROM audit WHERE type = 'sms_sent' AND at > ?").get(new Date(Date.now() - ms).toISOString()).at;
  const retry = Math.max(60, Math.ceil(((first ? new Date(first).getTime() : Date.now()) + ms - Date.now()) / 1000));
  audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: `sms budget ${hour}/${LIMITS.smsPerHour} ${day}/${LIMITS.smsPerDay}` });
  alertAdmins(ctx.db, 'sms_stopped', `${hour}/${LIMITS.smsPerHour} · ${day}/${LIMITS.smsPerDay}`);
  fail(503, 'sms_paused', 'Сейчас SMS не отправляются: на сервере исчерпан лимит сообщений. Войдите по паролю или попробуйте позже.',
    'SMS are paused right now: the server’s message limit has been reached. Sign in with your password or try again later.', wait(retry));
}
// SMS уходит уже после ответа (setImmediate): время ответа не зависит от того, отправляется ли что-то на этот номер, а значит,
// и от того, есть ли номер в базе. Не дошло — в журнал сервера; человек запросит код ещё раз. С 80% суточного бюджета — сигнал.
function queueSms(ctx, phone, text) {
  const { db, ip } = ctx;
  smsInFlight++;
  setImmediate(async () => {
    let sent = false;
    try { await sendSms(phone, text); sent = true; } catch (e) { log('error', 'SMS не отправлено', { err: e.message }); }
    smsInFlight--;
    if (!sent) return;
    try {
      audit(db, { type: 'sms_sent', ip, detail: maskPhone(phone) });
      const day = smsSince(db, 864e5);
      if (day >= Math.ceil(LIMITS.smsPerDay * LIMITS.smsAlertShare)) alertAdmins(db, 'sms_budget', `${day}/${LIMITS.smsPerDay}`);
    } catch (e) { log('error', 'Учёт SMS не записан', { err: e.message }); }
  });
}

// ---------- Сообщения: те же лимиты, что в интерфейсе ----------
function chatAllowed(db, me, eventId) {
  const now = Date.now(), t = r => new Date(r.at).getTime();
  const recent = db.q('SELECT at FROM comments WHERE user_id = ? AND at > ?').all(me.id, new Date(now - LIMITS.chatGlobal[1]).toISOString());
  if (recent.length >= LIMITS.chatGlobal[0]) fail(429, 'chat_global', `Лимит: ${LIMITS.chatGlobal[0]} сообщения за 7 часов.`, `Limit: ${LIMITS.chatGlobal[0]} messages per 7 hours.`);
  if (eventId) {
    const inEv = db.q("SELECT at FROM comments WHERE user_id = ? AND event_id = ? AND kind = 'ev' ORDER BY at").all(me.id, eventId);
    if (inEv.filter(r => now - t(r) < LIMITS.chatPerEvent[1]).length >= LIMITS.chatPerEvent[0]) fail(429, 'chat_event', 'В этом сборе за сутки уже 10 ваших сообщений.', 'You already sent 10 messages in this event today.');
    const last = inEv[inEv.length - 1];
    if (last && now - t(last) < LIMITS.chatCooldownMs) fail(429, 'chat_cooldown', 'Одно сообщение раз в 3 минуты.', 'One message every 3 minutes.', wait(Math.ceil((LIMITS.chatCooldownMs - (now - t(last))) / 1000)));
  }
}

// ---------- Проверка полей сбора ----------
function eventFields(body, partial = false) {
  const f = {};
  if (!partial || 'title' in body) { f.title = clean(body.title, 60); if (!f.title) fail(400, 'bad_title', 'Придумайте название сбора.', 'Give the event a title.'); }
  if (!partial || 'venue' in body) { f.venue = clean(body.venue, 60); if (!f.venue) fail(400, 'bad_venue', 'Укажите заведение.', 'Choose a venue.'); }
  if (!partial || 'address' in body) f.address = clean(body.address, 100);
  if (!partial || 'mapUrl' in body) { f.map_url = body.mapUrl ? safeUrl(body.mapUrl) : ''; if (body.mapUrl && !f.map_url) fail(400, 'bad_url', 'Ссылка должна начинаться с https://', 'The link must start with https://'); }
  if (!partial || 'desc' in body) f.descr = clean(body.desc, 400, true);
  if (!partial || 'at' in body) {
    const t = new Date(body.at);
    if (isNaN(t) || t < Date.now() - 60e3 || t > Date.now() + 365 * 864e5) fail(400, 'bad_date', 'Выберите время в будущем, не дальше года.', 'Pick a time in the future, within a year.');
    f.at = t.toISOString();
  }
  if (!partial || 'hookahs' in body) f.hookahs = Math.max(0, Math.min(20, parseInt(body.hookahs, 10) || 0));
  if (!partial || 'price' in body) f.price = Math.max(0, Math.min(100000, parseInt(body.price, 10) || 0));
  if (!partial || 'venueId' in body) { const v = isId(body.venueId) && venueById(body.venueId); f.venue_id = v ? v.id : null; if (v && !f.address) f.address = v.addr || ''; }
  return f;
}
// Приглашения. По аккаунту — сразу этому человеку. По номеру — строкой «по номеру», даже если номер уже зарегистрирован:
// кто его владелец, позвавший узнает, только когда тот ответит (иначе приглашение работало бы как поиск человека по номеру).
// Владельцу номера — обычное уведомление. Всего в сборе — не больше LIMITS.invitesPerEvent приглашённых, каким путём ни зови.
// Убранного из сбора (event_bans) может вернуть только организатор, позвав по аккаунту. Вызывается внутри транзакции.
function addInvites(db, e, me, list) {
  if (!Array.isArray(list)) return 0;
  if (list.length > 30) fail(400, 'too_many', 'За раз можно пригласить до 30 человек.', 'You can invite up to 30 people at once.');
  let n = 0, total = db.q('SELECT COUNT(*) AS n FROM invites WHERE event_id = ?').get(e.id).n;
  const room = () => { if (total++ >= LIMITS.invitesPerEvent) fail(409, 'event_full', `В сборе может быть не больше ${LIMITS.invitesPerEvent} приглашённых.`, `An event can have at most ${LIMITS.invitesPerEvent} invited people.`); };
  const invited = uid2 => !!db.q('SELECT 1 FROM invites WHERE event_id = ? AND user_id = ?').get(e.id, uid2);
  for (const it of list) {
    if (it?.userId && isId(it.userId) && it.userId !== e.host_id && db.q('SELECT 1 FROM users WHERE id = ?').get(it.userId)) {
      if (isBanned(db, e.id, it.userId)) { if (me.id !== e.host_id) continue; db.q('DELETE FROM event_bans WHERE event_id = ? AND user_id = ?').run(e.id, it.userId); }
      if (invited(it.userId)) continue;
      room();
      db.q("INSERT INTO invites (event_id, user_id, status, invited_by) VALUES (?, ?, 'pending', ?)").run(e.id, it.userId, me.id);
      n++; notify(db, it.userId, 'invite', me.id, e.id);
    } else if (it?.phone) {
      const p = normPhone(it.phone); if (!phoneAllowed(p)) continue; // номер, с которым нельзя зарегистрироваться, звать бессмысленно
      const idx = phoneIndex(p), owner = db.q('SELECT id FROM users WHERE phone_idx = ?').get(idx);
      if (owner?.id === e.host_id || owner?.id === me.id || db.q('SELECT 1 FROM invites WHERE event_id = ? AND phone_idx = ?').get(e.id, idx)) continue;
      room();
      db.q("INSERT INTO invites (event_id, phone_idx, phone_enc, phone_tail, status, invited_by) VALUES (?, ?, ?, ?, 'pending', ?)").run(e.id, idx, encrypt(p), p.slice(-3), me.id);
      n++;
      if (owner && !invited(owner.id) && !isBanned(db, e.id, owner.id)) notify(db, owner.id, 'invite', me.id, e.id);
    }
  }
  return n;
}

// ---------- Маршруты ----------
// [метод, путь, обработчик, параметры]. auth: нужен вход; data: ответ — свежие данные пользователя.
const routes = [];
// path — исходный шаблон (например, '/api/events/:id/comments'): он нужен автотестам (tests/attack.test.js), чтобы перебрать все маршруты.
const on = (method, path, fn, opt = {}) => routes.push({ method, path, re: new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, opt });

on('GET', '/api/health', ctx => ({ ok: true, mode: 'server', sms: require('./sms').providerName(), version: 1 }));
on('GET', '/api/bootstrap', ctx => bootstrap(ctx.db, ctx.user, ctx.session));

// Код для входа или регистрации. Ответ одинаковый, есть номер в базе или нет: тот же вид, ключ запроса и время (SMS уходит уже
// после ответа). Код приходит, только когда им можно воспользоваться: для входа — на зарегистрированный номер, для регистрации —
// на новый. На уже зарегистрированный номер при регистрации вместо кода приходит SMS «аккаунт уже есть», на незнакомый при
// входе — ничего. В базе и тогда лежит «код», который нельзя угадать, поэтому и ответы на неверный код одинаковые.
on('POST', '/api/auth/sms', ctx => {
  const { phone, idx } = phoneOf(ctx.body, { sms: true }), purpose = ctx.body.purpose === 'login' ? 'login' : 'register';
  ipLimit(ctx);
  smsLimits(ctx);
  if (purpose === 'register') accountsQuota(ctx);
  // Лимит номера — последним: отказ по любой другой причине не отнимает у владельца номера его запросы кода.
  const sms = hit('sms:' + idx, LIMITS.smsPerPhone);
  if (!sms.ok) { audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'sms ' + maskPhone(phone) }); fail(429, 'sms_limit', `Новый код можно запросить через ${minutes(sms.retryAfter)} мин.`, `You can request a new code in ${minutes(sms.retryAfter)} min.`, wait(sms.retryAfter)); }
  const known = !!ctx.db.q('SELECT 1 FROM users WHERE phone_idx = ?').get(idx), usable = purpose === 'login' ? known : !known;
  const code = smsCode(), challenge = newToken();
  ctx.db.q('INSERT OR REPLACE INTO sms_codes (phone_idx, code_hash, purpose, expires_at, attempts, sent_at, challenge) VALUES (?, ?, ?, ?, 0, ?, ?)')
    .run(idx, usable ? codeHash(code, idx) : sha256(newToken()), purpose, Date.now() + LIMITS.codeTtlMs, Date.now(), sha256(challenge));
  if (usable) queueSms(ctx, phone, `Hookah Party: код ${code}. Никому его не сообщайте.`);
  else if (known) queueSms(ctx, phone, 'Hookah Party: на этот номер уже есть аккаунт. Войдите паролем или по коду из SMS. Если это были не вы, ничего делать не нужно.');
  return { ok: true, ttl: LIMITS.codeTtlMs / 1000, challenge, ...(exposeCode() && usable ? { devCode: code } : {}) };
});

on('POST', '/api/auth/register', async ctx => {
  const b = ctx.body, { phone, idx } = phoneOf(b, { sms: true });
  const name = clean(b.name, 40);
  if (!validName(name)) fail(400, 'bad_name', 'Укажите имя буквами: от 2 до 40 символов.', 'Enter a name using letters: 2 to 40 characters.');
  const issue = passIssue(b.password, phone);
  if (issue) fail(400, issue, 'Пароль слишком простой: от 8 символов, буквы и цифры, без очевидных сочетаний.', 'The password is too weak: 8+ characters, letters and digits, nothing obvious.');
  if (b.adult !== true) fail(400, 'not_adult', 'Сервис доступен только совершеннолетним.', 'The service is for adults only.');
  ipLimit(ctx);
  accountsQuota(ctx);
  // Сначала код: на уже зарегистрированный номер код регистрации не отправляется, так что без верного кода ответ
  // не зависит от того, есть ли номер в базе. Тратим код в транзакции ниже — если сервер занят, код не пропадёт.
  checkCode(ctx.db, idx, 'register', b.code, b.challenge, ctx.ip, { keep: true });
  const pass = await hashPassword(b.password), uid2 = id('u');
  ctx.db.tx(() => {
    // Пока считался хэш пароля, параллельный запрос мог потратить этот код, квоту адреса или занять номер — проверяем ещё раз.
    if (!ctx.db.q('DELETE FROM sms_codes WHERE phone_idx = ? AND challenge = ?').run(idx, sha256(b.challenge)).changes) fail(400, 'code_missing', ...CODE_MISSING);
    accountsQuota(ctx);
    if (ctx.db.q('SELECT 1 FROM users WHERE phone_idx = ?').get(idx)) fail(409, 'phone_taken', 'Этот номер уже зарегистрирован. Войдите.', 'This number is already registered. Sign in instead.');
    // IP регистрации хранится 90 дней (lib/retention.js), лимит регистраций с адреса считается по журналу.
    ctx.db.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(uid2, name, encrypt(phone), idx, phone.slice(-3), pass, nowIso(), ctx.ip);
    // Приглашения «по номеру», отправленные до регистрации, новый пользователь видит как свои. Позвавшие узнают, кто это,
    // когда он ответит (см. answer), — сама регистрация номера им не видна.
    for (const inv of ctx.db.q('SELECT i.event_id, i.invited_by, e.host_id FROM invites i JOIN events e ON e.id = i.event_id WHERE i.phone_idx = ? AND i.user_id IS NULL').all(idx))
      notify(ctx.db, uid2, 'invite', inv.invited_by || inv.host_id, inv.event_id);
    // Запись о регистрации — в той же транзакции, что и проверка квоты: по ней квота и считается.
    audit(ctx.db, { type: 'register', userId: uid2, ip: ctx.ip, detail: maskPhone(phone) });
  });
  const user = ctx.db.q('SELECT * FROM users WHERE id = ?').get(uid2);
  startSession(ctx.db, ctx, user);
  return { data: bootstrap(ctx.db, ctx.user, ctx.session) };
});

// Вход паролем. Блокировка (5 неверных подряд) и счётчик неверных паролей номера закрывают только этот путь — вход по коду
// из SMS (POST /api/auth/login-sms) остаётся открытым, поэтому чужие неверные пароли не лишают владельца доступа.
on('POST', '/api/auth/login', async ctx => {
  const { phone, idx } = phoneOf(ctx.body);
  const lock = lockLeft('login:' + idx);
  if (lock) fail(429, 'locked', `Слишком много неверных попыток. Вход паролем закрыт ещё на ${minutes(lock / 1000)} мин — можно войти по коду из SMS.`, `Too many wrong attempts. Password sign-in is closed for ${minutes(lock / 1000)} more min — you can sign in with an SMS code.`, wait(Math.ceil(lock / 1000)));
  ipLimit(ctx);
  passLimit(ctx, idx, 'ph');
  const user = ctx.db.q('SELECT * FROM users WHERE phone_idx = ?').get(idx);
  const ok = user ? await verifyPassword(ctx.body.password, user.pass) : await burnTime(ctx.body.password);
  if (!ok || !user) {
    passFailed(idx);
    const left = failAttempt('login:' + idx);
    audit(ctx.db, { type: left ? 'login_fail' : 'lockout', userId: user?.id, ip: ctx.ip, detail: maskPhone(phone) });
    if (!left) alertAdmins(ctx.db, 'login_locked', `${maskPhone(phone)} · ${maskIp(ctx.ip)}`);
    fail(401, left ? 'bad_credentials' : 'locked', left ? `Неверный номер или пароль. Осталось попыток: ${left}.` : 'Неверный пароль 5 раз подряд. Вход паролем закрыт на 5 минут — можно войти по коду из SMS.',
      left ? `Wrong number or password. Attempts left: ${left}.` : 'Wrong password 5 times in a row. Password sign-in is closed for 5 minutes — you can sign in with an SMS code.', { left });
  }
  clearFails('login:' + idx);
  startSession(ctx.db, ctx, user);
  audit(ctx.db, { type: 'login_ok', userId: user.id, ip: ctx.ip });
  return { data: bootstrap(ctx.db, ctx.user, ctx.session) };
});

// Вход по коду из SMS: блокировка пароля и счётчик неверных паролей его не касаются — код доказывает, что телефон у владельца.
on('POST', '/api/auth/login-sms', ctx => {
  const { phone, idx } = phoneOf(ctx.body, { sms: true });
  ipLimit(ctx);
  checkCode(ctx.db, idx, 'login', ctx.body.code, ctx.body.challenge, ctx.ip);
  const user = ctx.db.q('SELECT * FROM users WHERE phone_idx = ?').get(idx) || fail(400, 'code_missing', ...CODE_MISSING);
  clearFails('login:' + idx);
  startSession(ctx.db, ctx, user, { viaSms: true });
  audit(ctx.db, { type: 'login_ok', userId: user.id, ip: ctx.ip, detail: 'sms ' + maskPhone(phone) });
  return { data: bootstrap(ctx.db, ctx.user, ctx.session) };
});

on('POST', '/api/auth/logout', ctx => {
  if (ctx.session) ctx.db.q('DELETE FROM sessions WHERE token_hash = ?').run(ctx.session.token_hash);
  ctx.setCookie('', 0);
  if (ctx.user) audit(ctx.db, { type: 'logout', userId: ctx.user.id, ip: ctx.ip });
  return { data: bootstrap(ctx.db, null, null) };
}, { auth: true });

on('POST', '/api/auth/logout-all', ctx => {
  ctx.db.q('DELETE FROM sessions WHERE user_id = ?').run(ctx.user.id);
  // Вместе с сессиями забываем другие устройства: если входил кто-то чужой, его следующий вход снова пришлёт уведомление.
  const here = knownDevice(ctx.db, ctx, ctx.user, { silent: true });
  ctx.db.q('DELETE FROM known_devices WHERE user_id = ? AND fp != ?').run(ctx.user.id, here.fp);
  ctx.setCookie('', 0);
  audit(ctx.db, { type: 'logout_all', userId: ctx.user.id, ip: ctx.ip });
  return { data: bootstrap(ctx.db, null, null) };
}, { auth: true });

// Журнал безопасности и устройства — только свои.
on('GET', '/api/security/log', ctx => {
  const here = parseUA(ctx.req.headers['user-agent']).fp;
  return {
    log: ctx.db.q('SELECT at, type, ip, detail FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT 30').all(ctx.user.id).map(r => ({ ...r, ip: r.ip ? maskIp(r.ip) : null })),
    sessions: ctx.db.q('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?').get(ctx.user.id, Date.now()).n,
    devices: ctx.db.q('SELECT fp, label, first_at, last_at FROM known_devices WHERE user_id = ? ORDER BY last_at DESC LIMIT 20').all(ctx.user.id)
      .map(d => ({ label: d.label, firstAt: d.first_at, lastAt: d.last_at, current: d.fp === here }))
  };
}, { auth: true });

on('POST', '/api/notifications/read', ctx => {
  if (ctx.body.all) ctx.db.q('UPDATE notifications SET read = 1 WHERE user_id = ?').run(ctx.user.id);
  else for (const nid of (Array.isArray(ctx.body.ids) ? ctx.body.ids : []).slice(0, 100)) if (isId(nid)) ctx.db.q('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(nid, ctx.user.id);
}, { auth: true, data: true });

// ---------- Профиль ----------
on('PATCH', '/api/me', ctx => {
  const b = ctx.body;
  if ('name' in b) { const n = clean(b.name, 40); if (!validName(n)) fail(400, 'bad_name', 'Укажите имя буквами: от 2 до 40 символов.', 'Enter a name using letters: 2 to 40 characters.'); ctx.db.q('UPDATE users SET name = ? WHERE id = ?').run(n, ctx.user.id); }
  if ('favVenue' in b) ctx.db.q('UPDATE users SET fav_venue = ? WHERE id = ?').run(clean(b.favVenue, 60), ctx.user.id);
}, { auth: true, data: true });
// Фото профиля: в bootstrap — только версия (хэш картинки), сама картинка — GET /api/avatar/:uid.
on('PUT', '/api/me/avatar', ctx => {
  const a = safeAvatar(ctx.body.dataUrl) || fail(400, 'bad_avatar', `Нужна картинка JPG, PNG или WebP до ${AVATAR_MAX / 1024} КБ.`, `An image (JPG, PNG or WebP) up to ${AVATAR_MAX / 1024} KB is required.`);
  ctx.db.q('UPDATE users SET avatar = ?, avatar_v = ? WHERE id = ?').run(a, sha256(a).slice(0, 16), ctx.user.id);
}, { auth: true, data: true });
on('DELETE', '/api/me/avatar', ctx => { ctx.db.q('UPDATE users SET avatar = NULL, avatar_v = NULL WHERE id = ?').run(ctx.user.id); }, { auth: true, data: true });
// Картинку видят те же, кто видит имя: вошедшие — любого, гости без входа — только тех, кто «на виду» (PUBLIC_USERS).
// Остальным — 404, как будто фото нет. Тип — по формату картинки, кеш — только в браузере (private) и ETag.
on('GET', '/api/avatar/:uid', ctx => {
  const u = isId(ctx.params.uid) && ctx.db.q('SELECT id, avatar, avatar_v FROM users WHERE id = ?').get(ctx.params.uid);
  const m = u && /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(u.avatar || '');
  if (!m || (!ctx.user && !ctx.db.q(`SELECT 1 FROM (${PUBLIC_USERS}) WHERE id = ?`).get(u.id))) fail(404, 'not_found', 'Фото нет.', 'No photo.');
  return { image: { type: 'image/' + (m[1].startsWith('jp') ? 'jpeg' : m[1]), body: Buffer.from(m[2], 'base64'), etag: `"${u.avatar_v || sha256(u.avatar).slice(0, 16)}"` } };
});
on('POST', '/api/me/favs/:tid', ctx => {
  const t = ctx.params.tid; if (!TOBACCOS.has(t)) fail(404, 'not_found', 'Такого табака нет.', 'No such tobacco.');
  if (!ctx.db.q('DELETE FROM favs WHERE user_id = ? AND tobacco_id = ?').run(ctx.user.id, t).changes) ctx.db.q('INSERT INTO favs VALUES (?, ?)').run(ctx.user.id, t);
}, { auth: true, data: true });
// Смена пароля (Профиль → Настройки → «Безопасность»). Нужен текущий пароль — или эта сессия создана входом по коду из SMS
// меньше 15 минут назад («Забыли пароль?»): код уже подтвердил, что телефон в руках владельца. Неверный текущий пароль
// считается как при входе и удалении аккаунта: 5 подряд — блокировка на 5 минут; каждый неверный — в общий с входом
// часовой счётчик неверных паролей номера (passLimit). После смены завершаются все остальные сессии и забываются другие устройства (вход с них снова пришлёт
// уведомление); эта сессия остаётся, но с новым токеном и CSRF-токеном. Пользователю — уведомление «Пароль изменён».
const PASS_WEAK = ['Пароль слишком простой: от 8 символов, буквы и цифры, без очевидных сочетаний.', 'The password is too weak: 8+ characters, letters and digits, nothing obvious.'];
const PASS_SAME = ['Новый пароль совпадает с текущим. Придумайте другой.', 'The new password is the same as the current one. Choose a different one.'];
on('POST', '/api/me/password', async ctx => {
  const me = ctx.user, key = 'pass:' + me.id, b = ctx.body;
  const viaSms = resetAllowed(ctx.session);
  // После входа по SMS текущий пароль не нужен и не проверяется, даже если его прислали.
  const current = viaSms ? null : typeof b.current === 'string' ? b.current : '';
  const next = typeof b.next === 'string' ? b.next : '';
  if (!viaSms) {
    const lock = lockLeft(key);
    if (lock) fail(429, 'locked', `Слишком много неверных попыток. Подождите ${minutes(lock / 1000)} мин.`, `Too many wrong attempts. Wait ${minutes(lock / 1000)} min.`, wait(Math.ceil(lock / 1000)));
    if (!current) fail(400, 'current_required', 'Введите текущий пароль: без него пароль можно сменить только в первые 15 минут после входа по коду из SMS.',
      'Enter your current password: without it, the password can only be changed within 15 minutes of signing in with an SMS code.');
  }
  // Новый пароль проверяем до текущего: опечатка в новом не тратит попытки.
  const issue = passIssue(next, decrypt(me.phone_enc));
  if (issue) fail(400, issue, ...PASS_WEAK);
  if (current === next) fail(400, 'same_password', ...PASS_SAME);
  if (!viaSms) passLimit(ctx, me.phone_idx, 'password');
  if (!viaSms && !(current.length <= 128 && await verifyPassword(current, me.pass))) {
    passFailed(me.phone_idx);
    const left = failAttempt(key);
    audit(ctx.db, { type: left ? 'password_change_fail' : 'password_change_locked', userId: me.id, ip: ctx.ip });
    fail(401, left ? 'bad_password' : 'locked', left ? `Неверный текущий пароль. Осталось попыток: ${left}.` : 'Неверный пароль 5 раз подряд. Смена пароля заблокирована на 5 минут.',
      left ? `Wrong current password. Attempts left: ${left}.` : 'Wrong password 5 times in a row. Password change is locked for 5 minutes.', { left });
  }
  // Текущий пароль после входа по SMS не вводили — повтор узнаём по хэшу.
  if (viaSms && await verifyPassword(next, me.pass)) fail(400, 'same_password', ...PASS_SAME);
  clearFails(key);
  const pass = await hashPassword(next), token = newToken(), csrf = newToken(), old = ctx.session.token_hash;
  const ended = ctx.db.tx(() => {
    // Пока считались хэши, сессию могли завершить, а пароль — сменить из другой сессии: тогда не трогаем ничего.
    if (!ctx.db.q('SELECT 1 FROM sessions WHERE token_hash = ?').get(old)) fail(401, 'auth_required', 'Войдите, чтобы продолжить.', 'Sign in to continue.');
    if (!ctx.db.q('UPDATE users SET pass = ? WHERE id = ? AND pass = ?').run(pass, me.id, me.pass).changes)
      fail(409, 'pass_conflict', 'Пароль только что сменили в другом окне. Обновите страницу.', 'The password was just changed in another window. Reload the page.');
    const n = Number(ctx.db.q('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(me.id, old).changes);
    // Новый токен у этой сессии: копия прежнего cookie, если её украли, больше не действует.
    ctx.db.q('UPDATE sessions SET token_hash = ?, csrf = ?, via_sms_at = 0 WHERE token_hash = ?').run(sha256(token), csrf, old);
    // Как при «Выйти на всех устройствах»: другие устройства забываем — если входил чужой, его следующий вход снова пришлёт уведомление.
    const here = knownDevice(ctx.db, ctx, me, { silent: true });
    ctx.db.q('DELETE FROM known_devices WHERE user_id = ? AND fp != ?').run(me.id, here.fp);
    notify(ctx.db, me.id, 'password_changed', null, null, `${here.label} · ${maskIp(ctx.ip)}`);
    return n;
  });
  ctx.setCookie(token, ctx.session.expires_at - Date.now());
  Object.assign(ctx.session, { token_hash: sha256(token), csrf, via_sms_at: 0 });
  ctx.user = { ...me, pass };
  audit(ctx.db, { type: 'password_changed', userId: me.id, ip: ctx.ip, detail: viaSms ? 'sms' : '' });
  return { ok: true, ended, data: bootstrap(ctx.db, ctx.user, ctx.session) };
}, { auth: true });

// Удаление аккаунта самим пользователем: подтверждение паролем (5 неверных — блокировка на 5 минут, неверные входят в общий
// с входом часовой счётчик неверных паролей номера), затем одной транзакцией стираются все его данные (lib/retention.js).
on('POST', '/api/me/delete', async ctx => {
  const me = ctx.user, key = 'delete:' + me.id;
  const lock = lockLeft(key);
  if (lock) fail(429, 'locked', `Слишком много неверных попыток. Подождите ${minutes(lock / 1000)} мин.`, `Too many wrong attempts. Wait ${minutes(lock / 1000)} min.`, wait(Math.ceil(lock / 1000)));
  passLimit(ctx, me.phone_idx, 'delete');
  const pass = ctx.body.password;
  if (!(typeof pass === 'string' && pass.length <= 128 && await verifyPassword(pass, me.pass))) {
    passFailed(me.phone_idx);
    const left = failAttempt(key);
    audit(ctx.db, { type: left ? 'delete_fail' : 'delete_locked', userId: me.id, ip: ctx.ip });
    fail(401, left ? 'bad_password' : 'locked', left ? `Неверный пароль. Осталось попыток: ${left}.` : 'Неверный пароль 5 раз подряд. Удаление аккаунта заблокировано на 5 минут.',
      left ? `Wrong password. Attempts left: ${left}.` : 'Wrong password 5 times in a row. Account deletion is locked for 5 minutes.', { left });
  }
  clearFails(key);
  const masked = maskedOf(me);
  // Одной транзакцией: все данные, а гостям его предстоящих сборов — уведомление об отмене без автора (lib/retention.js).
  // null — аккаунт уже удалён параллельным запросом.
  const done = deleteAccount(ctx.db, me) !== null;
  ctx.setCookie('', 0);
  ctx.user = ctx.session = null;
  if (done) audit(ctx.db, { type: 'account_deleted', ip: ctx.ip, detail: masked });
  return { ok: true, data: bootstrap(ctx.db, null, null) };
}, { auth: true });
// Друзья: кнопка меняет только свою сторону. Взаимные друзья — когда добавили оба; только им открывается полный номер
// (PHONE_VISIBLE), так что добавить человека в друзья, чтобы узнать его номер, нельзя. Уведомление «добавляет вас в друзья» —
// один раз на пару, сколько ни нажимай.
on('POST', '/api/friends/:uid', ctx => {
  const f = ctx.params.uid; if (!isId(f) || f === ctx.user.id || !ctx.db.q('SELECT 1 FROM users WHERE id = ?').get(f)) fail(404, 'not_found', 'Пользователь не найден.', 'User not found.');
  if (ctx.db.q('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(ctx.user.id, f).changes) return;
  ctx.db.q('INSERT OR IGNORE INTO friends VALUES (?, ?)').run(ctx.user.id, f);
  if (!ctx.db.q("SELECT 1 FROM notifications WHERE user_id = ? AND actor_id = ? AND type = 'friend'").get(f, ctx.user.id)) notify(ctx.db, f, 'friend', ctx.user.id);
}, { auth: true, data: true });

// ---------- Сборы ----------
function eventQuota(db, me, action) {
  const n = db.q('SELECT COUNT(*) AS n FROM event_log WHERE user_id = ? AND action = ? AND at > ?').get(me.id, action, Date.now() - 864e5).n;
  if (n >= LIMITS.eventsPerDay) {
    audit(db, { type: 'rate_limited', userId: me.id, detail: 'event ' + action });
    fail(429, 'events_limit', action === 'create' ? `За сутки можно создать не больше ${LIMITS.eventsPerDay} сборов.` : `За сутки можно отменить не больше ${LIMITS.eventsPerDay} сборов.`,
      action === 'create' ? `You can create at most ${LIMITS.eventsPerDay} events per day.` : `You can cancel at most ${LIMITS.eventsPerDay} events per day.`);
  }
}
on('POST', '/api/events', ctx => {
  // Один активный сбор на организатора: новый — после завершения текущего или после его отмены.
  const active = ctx.db.q('SELECT id, title FROM events WHERE host_id = ? AND at > ?').get(ctx.user.id, new Date(Date.now() - 4 * 3600e3).toISOString());
  if (active) fail(409, 'active_exists', `У вас уже есть активный сбор «${active.title}». Новый можно создать после его завершения или отменив этот.`, `You already have an active event “${active.title}”. Create a new one after it ends or cancel it.`, { eventId: active.id });
  eventQuota(ctx.db, ctx.user, 'create');
  const f = eventFields(ctx.body), eid = id('e');
  ctx.db.tx(() => {
    ctx.db.q('INSERT INTO events (id, title, venue, venue_id, address, map_url, at, host_id, descr, hookahs, price, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(eid, f.title, f.venue, f.venue_id, f.address, f.map_url, f.at, ctx.user.id, f.descr, f.hookahs, f.price, nowIso());
    addInvites(ctx.db, getEvent(ctx.db, eid), ctx.user, ctx.body.invites);
    ctx.db.q("INSERT INTO event_log VALUES (?, 'create', ?)").run(ctx.user.id, Date.now());
  });
  return { id: eid, data: bootstrap(ctx.db, ctx.user, ctx.session) };
}, { auth: true });
on('PATCH', '/api/events/:id', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user); needUpcoming(e);
  const f = eventFields(ctx.body, true), cols = Object.keys(f);
  if (cols.length) ctx.db.q(`UPDATE events SET ${cols.map(c => c + ' = ?').join(', ')} WHERE id = ?`).run(...cols.map(c => f[c]), e.id);
}, { auth: true, data: true });
on('DELETE', '/api/events/:id', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user);
  eventQuota(ctx.db, ctx.user, 'delete');
  // Отменённый сбор удаляется целиком (сообщения, голоса, приглашения — каскадом), остаётся только счётчик для лимита.
  ctx.db.tx(() => {
    for (const u of goingIds(ctx.db, e)) notify(ctx.db, u, 'cancelled', ctx.user.id, null, e.title.slice(0, 60));
    ctx.db.q('DELETE FROM events WHERE id = ?').run(e.id);
    ctx.db.q("INSERT INTO event_log VALUES (?, 'delete', ?)").run(ctx.user.id, Date.now());
  });
  audit(ctx.db, { type: 'event_cancelled', userId: ctx.user.id, ip: ctx.ip, detail: e.id });
}, { auth: true, data: true });
on('POST', '/api/events/:id/invites', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user)) fail(403, 'forbidden', 'Приглашать могут организатор и те, кто идёт.', 'Only the host and guests who are going can invite.');
  ctx.db.tx(() => addInvites(ctx.db, e, ctx.user, ctx.body.invites));
}, { auth: true, data: true });
// Организатор убирает человека из сбора — например, чужого, пришедшего по пересланной ссылке. Его ответ, голоса, чаша и отметка
// об оплате удаляются, сбор и обсуждение он больше не видит, по ссылке не вернётся (event_bans), ему — уведомление «removed».
// Вернуть может только организатор, позвав снова. Приглашение «по номеру» убирается по номеру ({ phone }): целиком его видит организатор.
on('DELETE', '/api/events/:id/invites', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user);
  const b = ctx.body, title = e.title.slice(0, 60), gone = () => fail(404, 'not_found', 'Этого человека нет среди приглашённых.', 'This person is not on the guest list.');
  if (b.userId != null) {
    const inv = (isId(b.userId) && b.userId !== e.host_id && ctx.db.q('SELECT id, user_id FROM invites WHERE event_id = ? AND user_id = ?').get(e.id, b.userId)) || gone();
    ctx.db.tx(() => {
      ctx.db.q('DELETE FROM invites WHERE id = ?').run(inv.id);
      for (const t of ['picks', 'bowls', 'paid']) ctx.db.q(`DELETE FROM ${t} WHERE event_id = ? AND user_id = ?`).run(e.id, inv.user_id);
      ctx.db.q('INSERT OR REPLACE INTO event_bans (event_id, user_id, at) VALUES (?, ?, ?)').run(e.id, inv.user_id, nowIso());
      notify(ctx.db, inv.user_id, 'removed', ctx.user.id, null, title);
    });
  } else {
    const p = normPhone(b.phone), idx = validPhone(p) && phoneIndex(p);
    const inv = (idx && ctx.db.q('SELECT id FROM invites WHERE event_id = ? AND phone_idx = ? AND user_id IS NULL').get(e.id, idx)) || gone();
    const owner = ctx.db.q('SELECT id FROM users WHERE phone_idx = ?').get(idx);
    ctx.db.tx(() => {
      ctx.db.q('DELETE FROM invites WHERE id = ?').run(inv.id);
      // Владелец номера видел приглашение — сообщаем, что его отозвали (если он не приглашён в этот сбор ещё и по аккаунту).
      if (owner && !ctx.db.q('SELECT 1 FROM invites WHERE event_id = ? AND user_id = ?').get(e.id, owner.id)) notify(ctx.db, owner.id, 'removed', ctx.user.id, null, title);
    });
  }
}, { auth: true, data: true });
// ---------- Приглашение по ссылке ----------
// Ссылку на сбор отправляют в Telegram или WhatsApp. По ней видно только название, место, время и имя организатора;
// ответить можно после входа — тогда человек появляется среди приглашённых. Ссылку получают организатор и идущие гости.
// Ссылка работает, пока сбор не прошёл; организатор может сменить её (POST /link/reset) — старая сразу перестаёт работать.
const joinEvent = (db, token) => {
  const e = /^[\w-]{20,40}$/.test(token) && db.q('SELECT * FROM events WHERE join_token = ?').get(token);
  return e && !isPast(e.at) ? e : fail(404, 'not_found', 'Ссылка устарела или сбор отменили.', 'The link has expired or the event was cancelled.');
};
const newJoinToken = (db, e) => { const token = crypto.randomBytes(18).toString('base64url'); db.q('UPDATE events SET join_token = ? WHERE id = ?').run(token, e.id); return { token }; };
on('POST', '/api/events/:id/link', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user)) fail(403, 'forbidden', 'Приглашать могут организатор и те, кто идёт.', 'Only the host and guests who are going can invite.');
  return e.join_token ? { token: e.join_token } : newJoinToken(ctx.db, e);
}, { auth: true });
on('POST', '/api/events/:id/link/reset', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user); needUpcoming(e);
  return newJoinToken(ctx.db, e);
}, { auth: true });
on('GET', '/api/join/:token', ctx => {
  const e = joinEvent(ctx.db, ctx.params.token), host = ctx.db.q('SELECT name FROM users WHERE id = ?').get(e.host_id);
  const inv = ctx.user && myInvite(ctx.db, e.id, ctx.user);
  return {
    event: { id: e.id, title: e.title, venue: e.venue, venueId: e.venue_id, address: e.address, at: e.at, host: host?.name || '', going: goingIds(ctx.db, e).length, past: isPast(e.at) },
    status: !ctx.user ? null : e.host_id === ctx.user.id ? 'host' : isBanned(ctx.db, e.id, ctx.user.id) ? 'removed' : inv?.status || null
  };
});
on('POST', '/api/join/:token', ctx => {
  const e = joinEvent(ctx.db, ctx.params.token);
  if (e.host_id === ctx.user.id) return;
  if (isBanned(ctx.db, e.id, ctx.user.id)) fail(403, 'removed', 'Организатор убрал вас из этого сбора.', 'The host removed you from this event.');
  if (!myInvite(ctx.db, e.id, ctx.user) && ctx.db.q('SELECT COUNT(*) AS n FROM invites WHERE event_id = ?').get(e.id).n >= LIMITS.invitesPerEvent)
    fail(409, 'event_full', 'В этом сборе уже слишком много приглашённых.', 'This event already has too many guests.');
  ctx.db.tx(() => answer(ctx.db, e, ctx.user, ctx.body.status === 'going' ? 'going' : 'declined'));
  return { ok: true, eventId: e.id, data: bootstrap(ctx.db, ctx.user, ctx.session) };
}, { auth: true });

on('POST', '/api/events/:id/rsvp', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!myInvite(ctx.db, e.id, ctx.user)) fail(403, 'forbidden', 'Вас не приглашали на этот сбор.', 'You are not invited to this event.');
  ctx.db.tx(() => answer(ctx.db, e, ctx.user, ctx.body.status === 'going' ? 'going' : 'declined'));
}, { auth: true, data: true });
on('PUT', '/api/events/:id/picks', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user)) fail(403, 'forbidden', 'Голосовать могут те, кто идёт.', 'Only guests who are going can vote.');
  const ids = [...new Set(Array.isArray(ctx.body.ids) ? ctx.body.ids : [])].filter(t => TOBACCOS.has(t));
  if (ids.length > 5) fail(400, 'too_many', 'Можно выбрать до 5 вкусов.', 'You can pick up to 5 flavours.');
  ctx.db.tx(() => { ctx.db.q('DELETE FROM picks WHERE event_id = ? AND user_id = ?').run(e.id, ctx.user.id); for (const t of ids) ctx.db.q('INSERT INTO picks VALUES (?, ?, ?)').run(e.id, ctx.user.id, t); });
}, { auth: true, data: true });
on('PUT', '/api/events/:id/bowl', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user)) fail(403, 'forbidden', 'Голосовать могут те, кто идёт.', 'Only guests who are going can vote.');
  if (ctx.body.bowlId == null) ctx.db.q('DELETE FROM bowls WHERE event_id = ? AND user_id = ?').run(e.id, ctx.user.id);
  else if (BOWLS.has(ctx.body.bowlId)) ctx.db.q('INSERT OR REPLACE INTO bowls VALUES (?, ?, ?)').run(e.id, ctx.user.id, ctx.body.bowlId);
  else fail(400, 'bad_bowl', 'Такой чаши нет.', 'No such bowl.');
}, { auth: true, data: true });
on('PUT', '/api/events/:id/bill', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user); needUpcoming(e);
  ctx.db.q('UPDATE events SET hookahs = ?, price = ? WHERE id = ?').run(Math.max(0, Math.min(20, parseInt(ctx.body.hookahs, 10) || 0)), Math.max(0, Math.min(100000, parseInt(ctx.body.price, 10) || 0)), e.id);
}, { auth: true, data: true });
on('POST', '/api/events/:id/paid/:uid', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user); needUpcoming(e);
  if (!goingIds(ctx.db, e).includes(ctx.params.uid)) fail(400, 'not_going', 'Этот человек не идёт на сбор.', 'This person is not going.');
  if (!ctx.db.q('DELETE FROM paid WHERE event_id = ? AND user_id = ?').run(e.id, ctx.params.uid).changes) ctx.db.q('INSERT INTO paid VALUES (?, ?)').run(e.id, ctx.params.uid);
}, { auth: true, data: true });

// ---------- Обсуждение, реакции, история ----------
on('POST', '/api/events/:id/comments', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needMember(ctx.db, e, ctx.user);
  const text = clean(ctx.body.text, 500, true) || fail(400, 'empty', 'Напишите сообщение.', 'Write a message.');
  chatAllowed(ctx.db, ctx.user, e.id);
  const cid = id('c');
  ctx.db.tx(() => {
    ctx.db.q("INSERT INTO comments VALUES (?, ?, ?, 'ev', ?, ?)").run(cid, e.id, ctx.user.id, text, nowIso());
    // Организатору и всем, кто не отказался, — и тем, кого позвали «по номеру» и кто уже есть в сервисе.
    const to = ctx.db.q(`SELECT user_id AS id FROM invites WHERE event_id = ?1 AND status != 'declined' AND user_id IS NOT NULL
      UNION SELECT u.id FROM invites i JOIN users u ON u.phone_idx = i.phone_idx WHERE i.event_id = ?1 AND i.user_id IS NULL
        AND u.id NOT IN (SELECT user_id FROM event_bans WHERE event_id = ?1)`).all(e.id).map(r => r.id);
    for (const u of new Set([e.host_id, ...to])) notify(ctx.db, u, 'comment', ctx.user.id, e.id, cid);
  });
}, { auth: true, data: true });
on('DELETE', '/api/comments/:cid', ctx => {
  const c = isId(ctx.params.cid) && ctx.db.q('SELECT * FROM comments WHERE id = ?').get(ctx.params.cid) || fail(404, 'not_found', 'Сообщение не найдено.', 'Message not found.');
  const e = getEvent(ctx.db, c.event_id);
  if (c.user_id !== ctx.user.id && !(c.kind === 'ev' && e.host_id === ctx.user.id)) fail(403, 'forbidden', 'Удалить можно только своё сообщение.', 'You can only delete your own message.');
  ctx.db.q('DELETE FROM comments WHERE id = ?').run(c.id);
}, { auth: true, data: true });
on('PUT', '/api/comments/:cid/reaction', ctx => {
  const c = isId(ctx.params.cid) && ctx.db.q('SELECT * FROM comments WHERE id = ?').get(ctx.params.cid) || fail(404, 'not_found', 'Сообщение не найдено.', 'Message not found.');
  if (c.kind === 'ev') needMember(ctx.db, getEvent(ctx.db, c.event_id), ctx.user);
  const em = ctx.body.emoji;
  if (!EMOJI.has(em)) fail(400, 'bad_emoji', 'Такой реакции нет.', 'No such reaction.');
  const cur = ctx.db.q('SELECT emoji FROM reactions WHERE comment_id = ? AND user_id = ?').get(c.id, ctx.user.id);
  if (cur?.emoji === em) ctx.db.q('DELETE FROM reactions WHERE comment_id = ? AND user_id = ?').run(c.id, ctx.user.id);
  else { ctx.db.q('INSERT OR REPLACE INTO reactions VALUES (?, ?, ?, ?)').run(c.id, ctx.user.id, em, nowIso()); notify(ctx.db, c.user_id, 'reaction', ctx.user.id, c.event_id, `${c.id}:${em}`); }
}, { auth: true, data: true });
on('POST', '/api/events/:id/story', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needHost(e, ctx.user);
  if (!isPast(e.at)) fail(409, 'not_past', 'Рассказать можно после сбора.', 'You can share the story after the event.');
  if (ctx.db.q('SELECT 1 FROM stories WHERE event_id = ?').get(e.id)) fail(409, 'exists', 'Рассказ уже опубликован.', 'The story is already published.');
  const rating = parseInt(ctx.body.rating, 10), text = clean(ctx.body.text, 600, true);
  if (!(rating >= 1 && rating <= 5)) fail(400, 'bad_rating', 'Оцените вечер от 1 до 5.', 'Rate the evening from 1 to 5.');
  if (text.length < 20) fail(400, 'short', 'Напишите хотя бы пару предложений.', 'Write at least a couple of sentences.');
  const hl = (Array.isArray(ctx.body.highlights) ? ctx.body.highlights : []).map(h => clean(h, 80)).filter(Boolean).slice(0, 3);
  ctx.db.q('INSERT INTO stories VALUES (?, ?, ?, ?, ?)').run(e.id, rating, text, JSON.stringify(hl), nowIso());
}, { auth: true, data: true });
on('POST', '/api/events/:id/story/fire', ctx => {
  const e = getEvent(ctx.db, ctx.params.id);
  if (!ctx.db.q('SELECT 1 FROM stories WHERE event_id = ?').get(e.id)) fail(404, 'not_found', 'Рассказа нет.', 'No story.');
  if (!ctx.db.q('DELETE FROM story_fire WHERE event_id = ? AND user_id = ?').run(e.id, ctx.user.id).changes) { ctx.db.q('INSERT INTO story_fire VALUES (?, ?)').run(e.id, ctx.user.id); notify(ctx.db, e.host_id, 'fire', ctx.user.id, e.id); }
}, { auth: true, data: true });
on('POST', '/api/events/:id/story/comments', ctx => {
  const e = getEvent(ctx.db, ctx.params.id);
  if (!ctx.db.q('SELECT 1 FROM stories WHERE event_id = ?').get(e.id)) fail(404, 'not_found', 'Рассказа нет.', 'No story.');
  const text = clean(ctx.body.text, 300, true) || fail(400, 'empty', 'Напишите комментарий.', 'Write a comment.');
  const today = new Date(); today.setHours(0, 0, 0, 0);
  if (ctx.db.q("SELECT 1 FROM comments WHERE event_id = ? AND user_id = ? AND kind = 'story' AND at >= ?").get(e.id, ctx.user.id, today.toISOString()))
    fail(429, 'story_daily', 'Этот вечер можно комментировать раз в день.', 'You can comment on this evening once a day.');
  chatAllowed(ctx.db, ctx.user, null);
  const cid = id('sc');
  ctx.db.q("INSERT INTO comments VALUES (?, ?, ?, 'story', ?, ?)").run(cid, e.id, ctx.user.id, text, nowIso());
  notify(ctx.db, e.host_id, 'story_comment', ctx.user.id, e.id, cid);
}, { auth: true, data: true });

// ---------- Каталог ----------
on('PUT', '/api/reviews/:tid', ctx => {
  const t = ctx.params.tid; if (!TOBACCOS.has(t)) fail(404, 'not_found', 'Такого табака нет.', 'No such tobacco.');
  const rating = parseInt(ctx.body.rating, 10); if (!(rating >= 1 && rating <= 5)) fail(400, 'bad_rating', 'Поставьте оценку от 1 до 5.', 'Give a rating from 1 to 5.');
  const text = clean(ctx.body.text, 400, true), cur = ctx.db.q('SELECT id FROM reviews WHERE tobacco_id = ? AND user_id = ?').get(t, ctx.user.id);
  if (cur) ctx.db.q('UPDATE reviews SET rating = ?, text = ?, at = ? WHERE id = ?').run(rating, text, nowIso(), cur.id);
  else ctx.db.q('INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)').run(id('r'), t, ctx.user.id, rating, text, nowIso());
}, { auth: true, data: true });
on('POST', '/api/mixes', ctx => {
  const name = clean(ctx.body.name, 40) || fail(400, 'bad_name', 'Придумайте название микса.', 'Give the mix a name.');
  const parts = (Array.isArray(ctx.body.parts) ? ctx.body.parts : []).map(p => ({ id: p?.id, pct: parseInt(p?.pct, 10) || 0 })).filter(p => TOBACCOS.has(p.id) && p.pct > 0 && p.pct <= 100);
  if (parts.length < 2 || parts.length > 3 || new Set(parts.map(p => p.id)).size !== parts.length || parts.reduce((s, p) => s + p.pct, 0) !== 100)
    fail(400, 'bad_parts', 'Нужны 2–3 разных табака, доли в сумме 100%.', 'You need 2–3 different tobaccos adding up to 100%.');
  if (ctx.db.q('SELECT COUNT(*) AS n FROM mixes WHERE author_id = ? AND at > ?').get(ctx.user.id, new Date(Date.now() - 864e5).toISOString()).n >= 10) fail(429, 'too_many', 'Не больше 10 миксов в сутки.', 'At most 10 mixes per day.');
  ctx.db.q('INSERT INTO mixes VALUES (?, ?, ?, ?, ?)').run(id('m'), name, ctx.user.id, JSON.stringify(parts.sort((a, b) => b.pct - a.pct)), nowIso());
}, { auth: true, data: true });
on('POST', '/api/mixes/:id/like', ctx => {
  const m = isId(ctx.params.id) && ctx.db.q('SELECT * FROM mixes WHERE id = ?').get(ctx.params.id) || fail(404, 'not_found', 'Микс не найден.', 'Mix not found.');
  if (!ctx.db.q('DELETE FROM mix_likes WHERE mix_id = ? AND user_id = ?').run(m.id, ctx.user.id).changes) ctx.db.q('INSERT INTO mix_likes VALUES (?, ?)').run(m.id, ctx.user.id);
}, { auth: true, data: true });

// ---------- Администратор ----------
// Администратор — роль из консоли сервера (server/admin.js) плюс номер в ADMIN_PHONES (см. lib/panel.js). Панель открывается на 15 минут
// паролем и кодом из приложения-аутентификатора (TOTP, lib/totp.js), каждое действие записывается в журнал.
// Пока приложение не подключено, пароль открывает только экран подключения (admin_mfa = 0): действия панели недоступны.
// Неверный пароль и неверный код считаются вместе: 5 ошибок — блокировка на 5 минут.
const needAdmin = ctx => {
  if (isAdminUser(ctx.user)) return;
  audit(ctx.db, { type: 'admin_denied', userId: ctx.user?.id, ip: ctx.ip, detail: ctx.req.url });
  // Панель ищут повторно (3 раза за 10 минут с одного аккаунта или адреса) — сигнал владельцу. Считаем оба ключа.
  const probes = [burst('probe:u:' + (ctx.user?.id || '-'), ALERTS.probe), burst('probe:ip:' + ctx.net, ALERTS.probe)];
  if (probes.some(Boolean)) alertAdmins(ctx.db, 'admin_probe', `${ctx.user ? maskedOf(ctx.user) : '?'} · ${maskIp(ctx.ip)}`);
  fail(404, 'not_found', 'Неизвестный адрес API.', 'Unknown API endpoint.');
};
const needUnlocked = ctx => {
  needAdmin(ctx);
  if (!(ctx.session.admin_until > Date.now())) fail(403, 'step_up', 'Подтвердите пароль, чтобы открыть панель администратора.', 'Confirm your password to open the admin panel.');
};
const needStepUp = ctx => {
  needUnlocked(ctx);
  if (ctx.session.admin_mfa && ctx.user.totp_secret_enc) return;
  // Приложение уже подключено (например, в другой вкладке) — нужен полный вход с кодом; иначе — сначала подключить.
  if (ctx.user.totp_secret_enc) fail(403, 'step_up', 'Подтвердите вход паролем и кодом из приложения.', 'Confirm with your password and the code from your app.');
  fail(403, 'totp_setup_required', 'Сначала подключите приложение для кодов: без него панель не открывается.', 'Set up an authenticator app first: the panel does not open without it.');
};
const adminKey = ctx => 'admin:' + ctx.user.id;
// Сверх блокировок на 5 минут — не больше 10 неверных паролей и кодов за час: подбор кода из 6 цифр растягивается на годы.
const ADMIN_FAILS_PER_HOUR = [10, 3600e3];
const needNotLocked = ctx => {
  const lock = lockLeft(adminKey(ctx));
  if (lock) fail(429, 'locked', `Слишком много неверных попыток. Подождите ${minutes(lock / 1000)} мин.`, `Too many wrong attempts. Wait ${minutes(lock / 1000)} min.`, wait(Math.ceil(lock / 1000)));
  const h = hit('admin:h:' + ctx.user.id, ADMIN_FAILS_PER_HOUR, false);
  if (!h.ok) fail(429, 'rate_limited', `Слишком много неверных попыток за час. Попробуйте через ${minutes(h.retryAfter)} мин.`, `Too many wrong attempts this hour. Try again in ${minutes(h.retryAfter)} min.`, wait(h.retryAfter));
};
function adminFail(ctx, code, [ru, en], detail) {
  hit('admin:h:' + ctx.user.id, ADMIN_FAILS_PER_HOUR);
  const left = failAttempt(adminKey(ctx));
  audit(ctx.db, { type: 'admin_unlock_fail', userId: ctx.user.id, ip: ctx.ip, detail });
  if (!left) {
    alertAdmins(ctx.db, 'admin_lock', maskIp(ctx.ip));
    fail(401, 'locked', 'Неверный ввод 5 раз подряд. Панель заблокирована на 5 минут.', 'Wrong input 5 times in a row. The panel is locked for 5 minutes.', { left: 0 });
  }
  fail(401, code, `${ru} Осталось попыток: ${left}.`, `${en} Attempts left: ${left}.`, { left });
}
// Открыть панель в этой сессии на 15 минут; mfa — вход был с кодом из приложения.
function openAdmin(ctx, mfa) {
  const until = Date.now() + LIMITS.adminStepUpMs;
  ctx.db.q('UPDATE sessions SET admin_until = ?, admin_mfa = ? WHERE token_hash = ?').run(until, mfa ? 1 : 0, ctx.session.token_hash);
  Object.assign(ctx.session, { admin_until: until, admin_mfa: mfa ? 1 : 0 });
  return { ok: true, adminUntil: until, adminMfa: mfa, adminTotp: mfa };
}
const WRONG_CODE = ['Код не подходит. Проверьте, что время на телефоне устанавливается автоматически.', 'Wrong code. Make sure the time on your phone is set automatically.'];
const USED_CODE = ['Этот код уже использован — дождитесь следующего в приложении.', 'This code has already been used — wait for the next one in the app.'];

on('POST', '/api/admin/unlock', async ctx => {
  needAdmin(ctx);
  needNotLocked(ctx);
  const me = ctx.user, { password, code } = ctx.body;
  const secret = me.totp_secret_enc ? decrypt(me.totp_secret_enc) : null;
  // Приложение подключено — без кода не открываем и пароль даже не проверяем: ответ не подсказывает, верен ли он.
  if (secret && !String(code ?? '').trim()) fail(401, 'totp_required', 'Введите код из приложения-аутентификатора.', 'Enter the code from your authenticator app.');
  if (!(typeof password === 'string' && password.length <= 128 && await verifyPassword(password, me.pass))) adminFail(ctx, 'bad_password', ['Неверный пароль.', 'Wrong password.'], 'password');
  if (secret) {
    const step = totp.verify(secret, code, { lastCounter: me.totp_last });
    // Шаг кода записывается условием в самом UPDATE: даже два одновременных запроса с одним кодом пройдут только один раз.
    if (step === null || !ctx.db.q('UPDATE users SET totp_last = ? WHERE id = ? AND totp_last < ?').run(step, me.id, step).changes) {
      const used = totp.verify(secret, code) !== null;
      adminFail(ctx, 'totp_invalid', used ? USED_CODE : WRONG_CODE, used ? 'totp reused' : 'totp');
    }
  }
  clearFails(adminKey(ctx));
  // Панель открыта с адреса, с которого этот администратор её ещё не открывал (по журналу за 90 дней), — сигнал для сведения.
  // Самый первый вход сигнала не даёт. Ограничение частоты — по адресу: каждый новый адрес сообщается отдельно.
  const UNLOCKS = "SELECT 1 FROM audit WHERE user_id = ? AND type IN ('admin_unlock', 'admin_totp_enabled')";
  const newIp = !ctx.db.q(UNLOCKS + ' AND ip = ? LIMIT 1').get(me.id, ctx.ip) && !!ctx.db.q(UNLOCKS + ' LIMIT 1').get(me.id);
  audit(ctx.db, { type: 'admin_unlock', userId: me.id, ip: ctx.ip, detail: secret ? '2FA' : '2FA setup' });
  if (newIp) alertAdmins(ctx.db, 'admin_new_ip', maskIp(ctx.ip), { key: 'admin_new_ip:' + ctx.ip });
  return openAdmin(ctx, !!secret);
}, { auth: true });
on('POST', '/api/admin/lock', ctx => {
  needAdmin(ctx);
  ctx.db.q('UPDATE sessions SET admin_until = 0, admin_mfa = 0 WHERE token_hash = ?').run(ctx.session.token_hash);
  return { ok: true };
}, { auth: true });
// Подключение приложения: новый секрет (в базе — зашифрованным, до подтверждения кодом — «ожидающим»), QR и ключ для ручного ввода.
on('POST', '/api/admin/totp/setup', ctx => {
  needUnlocked(ctx);
  if (ctx.user.totp_secret_enc) fail(409, 'totp_enabled', 'Приложение уже подключено. Подключить заново можно после сброса в консоли сервера: node server/admin.js totp-reset <номер>.',
    'The app is already set up. To set it up again, reset it in the server console: node server/admin.js totp-reset <number>.');
  const secret = totp.generateSecret();
  ctx.db.q('UPDATE users SET totp_pending_enc = ? WHERE id = ?').run(encrypt(secret), ctx.user.id);
  // В приложении будет «Hookah Party» и номер с последними тремя цифрами — полный номер туда не попадает.
  const uri = totp.otpauthUri({ secret, label: maskPhone(decrypt(ctx.user.phone_enc)).replace(/•/g, '*') });
  audit(ctx.db, { type: 'admin_totp_setup', userId: ctx.user.id, ip: ctx.ip });
  return { ok: true, secret: totp.groupKey(secret), uri, qr: qr.encode(uri) };
}, { auth: true });
// Подтверждение: код по «ожидающему» секрету — секрет становится рабочим, а эта сессия получает полный доступ.
on('POST', '/api/admin/totp/enable', ctx => {
  needUnlocked(ctx);
  needNotLocked(ctx);
  const me = ctx.user;
  if (me.totp_secret_enc) fail(409, 'totp_enabled', 'Приложение уже подключено.', 'The app is already set up.');
  if (!me.totp_pending_enc) fail(409, 'totp_no_setup', 'Сначала получите QR-код для приложения.', 'Get the QR code for the app first.');
  const step = totp.verify(decrypt(me.totp_pending_enc), ctx.body.code);
  if (step === null) adminFail(ctx, 'totp_invalid', ['Код не подходит. Проверьте время на телефоне; если страница обновлялась — удалите запись в приложении и добавьте ключ заново.',
    'Wrong code. Check the time on your phone; if the page was reloaded, delete the entry in the app and add the key again.'], 'totp setup');
  const res = ctx.db.tx(() => {
    // Подключаем ровно тот секрет, которым проверен код: если тем временем выдан новый QR, ничего не меняем.
    if (!ctx.db.q('UPDATE users SET totp_secret_enc = totp_pending_enc, totp_pending_enc = NULL, totp_last = ? WHERE id = ? AND totp_pending_enc = ? AND totp_secret_enc IS NULL').run(step, me.id, me.totp_pending_enc).changes)
      fail(409, 'totp_changed', 'QR-код успел смениться. Обновите страницу и отсканируйте новый.', 'The QR code has changed. Reload the page and scan the new one.');
    return openAdmin(ctx, true);
  });
  clearFails(adminKey(ctx));
  audit(ctx.db, { type: 'admin_totp_enabled', userId: me.id, ip: ctx.ip });
  return res;
}, { auth: true });
on('GET', '/api/admin/overview', ctx => {
  needStepUp(ctx);
  const names = Object.fromEntries(ctx.db.q('SELECT id, name FROM users').all().map(u => [u.id, u.name]));
  const titles = Object.fromEntries(ctx.db.q('SELECT id, title FROM events').all().map(e => [e.id, e.title]));
  return {
    adminUntil: ctx.session.admin_until,
    comments: ctx.db.q('SELECT * FROM comments ORDER BY at DESC LIMIT 500').all().map(c => ({ id: c.id, kind: c.kind, text: c.text, at: c.at, userId: c.user_id, author: names[c.user_id] || '—', eventId: c.event_id, eventTitle: titles[c.event_id] || '—' })),
    events: ctx.db.q('SELECT e.*, (SELECT COUNT(*) FROM invites i WHERE i.event_id = e.id) AS guests, (SELECT COUNT(*) FROM comments c WHERE c.event_id = e.id) AS msgs FROM events e ORDER BY at DESC LIMIT 500').all()
      .map(e => ({ id: e.id, title: e.title, venue: e.venue, at: e.at, hostId: e.host_id, host: names[e.host_id] || '—', guests: e.guests, msgs: e.msgs, past: isPast(e.at) })),
    audit: ctx.db.q('SELECT a.at, a.type, a.detail, a.ip, u.name FROM audit a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 100').all()
      .map(r => ({ ...r, ip: r.ip ? maskIp(r.ip) : null })),
    stats: { users: ctx.db.q('SELECT COUNT(*) AS n FROM users').get().n, events: ctx.db.q('SELECT COUNT(*) AS n FROM events').get().n, comments: ctx.db.q('SELECT COUNT(*) AS n FROM comments').get().n }
  };
}, { auth: true });
on('DELETE', '/api/admin/comments/:cid', ctx => {
  needStepUp(ctx);
  const c = isId(ctx.params.cid) && ctx.db.q('SELECT * FROM comments WHERE id = ?').get(ctx.params.cid) || fail(404, 'not_found', 'Сообщение не найдено.', 'Message not found.');
  ctx.db.q('DELETE FROM comments WHERE id = ?').run(c.id);
  notify(ctx.db, c.user_id, 'admin_removed_comment', ctx.user.id, c.event_id, c.text.slice(0, 60));
  audit(ctx.db, { type: 'admin_delete_comment', userId: ctx.user.id, ip: ctx.ip, detail: `${c.id} (${c.user_id})` });
  return { ok: true };
}, { auth: true });
on('DELETE', '/api/admin/events/:id', ctx => {
  needStepUp(ctx);
  const e = getEvent(ctx.db, ctx.params.id);
  ctx.db.tx(() => {
    for (const u of goingIds(ctx.db, e)) notify(ctx.db, u, 'admin_removed_event', ctx.user.id, null, e.title.slice(0, 60));
    ctx.db.q('DELETE FROM events WHERE id = ?').run(e.id);
  });
  audit(ctx.db, { type: 'admin_delete_event', userId: ctx.user.id, ip: ctx.ip, detail: `${e.id} (${e.host_id})` });
  return { ok: true };
}, { auth: true });

// Ошибки со страниц пользователей попадают в журнал сервера — так поломки видно до того, как о них напишут.
on('POST', '/api/client-errors', ctx => {
  if (!hit('cerr:' + ctx.net, LIMITS.clientErrors).ok) return { ok: true };
  const b = ctx.body || {}, str = (v, n) => String(v ?? '').replace(/[\u0000-\u001f]/g, ' ').slice(0, n);
  log('warn', 'Ошибка на странице', { msg: str(b.msg, 300), src: str(b.src, 120), line: +b.line || 0, page: str(b.page, 60), ua: str(ctx.req.headers['user-agent'], 120), user: ctx.user?.id || null });
  return { ok: true };
});

// Браузер заблокировал код по политике безопасности (CSP или Trusted Types) — страница сама присылает короткий отчёт (app.js).
// Вход не нужен, но лимит с одного адреса. Никаким полям не верим: только слова, адрес сайта без пути, обрезанный образец кода.
// Отдельного report-uri в заголовке CSP нет: браузер слал бы application/csp-report, а сервер принимает только JSON.
const cspWord = (v, n = 40) => (/^[a-z][a-z0-9-]*$/i.exec(clean(v, n)) || [''])[0].toLowerCase();
function cspBlocked(v) {
  const s = clean(v, 300), word = cspWord(s);
  if (!s || word) return word || '?'; // inline, eval, trusted-types-sink, data, blob…
  try { const u = new URL(s); return /^(https?|wss?):$/.test(u.protocol) ? u.origin.slice(0, 100) : cspWord(u.protocol.slice(0, -1)) || 'other'; } catch (e) { return 'other'; }
}
on('POST', '/api/csp-report', ctx => {
  const r = hit('csp:' + ctx.net, LIMITS.cspReports);
  if (!r.ok) fail(429, 'rate_limited', 'Слишком много отчётов.', 'Too many reports.', wait(r.retryAfter));
  // Со всех адресов вместе в журнал — не больше LIMITS.cspGlobal в час: множество адресов не раздует базу (ответ тот же).
  if (!hit('csp:all', LIMITS.cspGlobal).ok) return { ok: true };
  const b = ctx.body || {};
  const directive = cspWord(b.directive) || '?', blocked = cspBlocked(b.blocked), sample = clean(b.sample, 60);
  const src = clean(String(b.src ?? '').split(/[?#]/)[0].split(/[/\\]/).pop(), 60), line = Math.max(0, Math.min(1e7, parseInt(b.line, 10) || 0));
  const page = (/^[\w-]{1,30}$/.exec(String(b.page ?? '')) || ['?'])[0];
  const detail = [directive, blocked, src && `${src}:${line}`, '#/' + page, sample && `«${sample}»`].filter(Boolean).join(' · ');
  audit(ctx.db, { type: 'csp_violation', userId: ctx.user?.id, ip: ctx.ip, detail });
  // Всплеск отчётов (5 за 10 минут со всех адресов) — сигнал владельцу: возможно, кто-то пробует внедрить код.
  if (burst('csp', ALERTS.cspBurst)) alertAdmins(ctx.db, 'csp_burst', `${directive} · ${blocked}`);
  return { ok: true };
});

function match(method, path) {
  for (const r of routes) { if (r.method !== method) continue; const m = r.re.exec(path); if (m) return { route: r, params: m.groups || {} }; }
  return null;
}

module.exports = { match, bootstrap, routes };
