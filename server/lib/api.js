'use strict';
// API Hookah Party. Каждая точка: проверка входа, прав, лимитов и данных; все SQL-запросы подготовленные.
const { crypto, encrypt, decrypt, phoneIndex, hashPassword, verifyPassword, burnTime, sha256, sameHash, smsCode } = require('./secure');
const { normPhone, validPhone, maskPhone, clean, validName, safeUrl, safeAvatar, isId, passIssue, fail, uid, nowIso } = require('./util');
const { LIMITS, hit, lockLeft, failAttempt, clearFails, audit } = require('./guard');
const { TOBACCOS, BOWLS, EMOJI, venueById } = require('./catalog');
const { sendSms, exposeCode } = require('./sms');

const id = p => uid(p, crypto);
const isPast = at => new Date(at).getTime() < Date.now() - 4 * 3600e3;
const wait = s => ({ retryAfter: s });
const minutes = s => Math.max(1, Math.ceil(s / 60));

// ---------- Данные для пользователя ----------
// Отдаём только то, что ему положено видеть: свои сборы целиком, чужие — только прошедшие с рассказом,
// полные номера — только свои, друзей и участников общих сборов.
function bootstrap(db, me, session) {
  const meId = me?.id || null;
  const mine = new Set(meId ? db.q('SELECT id FROM events WHERE host_id = ? UNION SELECT event_id FROM invites WHERE user_id = ?').all(meId, meId).map(r => r.id) : []);
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
  const friends = group(db.q('SELECT * FROM friends').all(), 'user_id');
  const favs = group(db.q('SELECT * FROM favs').all(), 'user_id');

  // Кому можно показать полный номер.
  const visible = new Set(meId ? [meId, ...(friends[meId] || []).map(f => f.friend_id)] : []);
  for (const e of evRows) if (mine.has(e.id)) { visible.add(e.host_id); for (const i of invites[e.id] || []) if (i.user_id) visible.add(i.user_id); }

  const users = db.q('SELECT id, name, avatar, fav_venue, created_at, verified, phone_enc, phone_tail FROM users').all().map(u => ({
    id: u.id, name: u.name, avatar: u.avatar, favVenue: u.fav_venue, createdAt: u.created_at, verified: !!u.verified,
    phone: visible.has(u.id) ? decrypt(u.phone_enc) : null, phoneMasked: `+996 ••• ••• ${u.phone_tail}`,
    favs: (favs[u.id] || []).map(f => f.tobacco_id), friends: (friends[u.id] || []).map(f => f.friend_id)
  }));
  const comment = c => ({ id: c.id, userId: c.user_id, text: c.text, at: c.at, reactions: Object.fromEntries((reacts[c.id] || []).map(r => [r.user_id, r.emoji])) });
  const events = evRows.map(e => {
    const member = mine.has(e.id), st = stories.get(e.id);
    const inv = (invites[e.id] || []).filter(i => member || i.status === 'going');
    return {
      id: e.id, title: e.title, venue: e.venue, venueId: e.venue_id, address: e.address, mapUrl: e.map_url, at: e.at, hostId: e.host_id,
      createdAt: e.created_at, desc: e.descr, hookahs: e.hookahs, price: e.price, member,
      paid: Object.fromEntries((paid[e.id] || []).map(p => [p.user_id, true])),
      invites: inv.map(i => i.user_id ? { userId: i.user_id, status: i.status, at: i.at } : { phone: member ? decrypt(i.phone_enc) : null, phoneMasked: `+996 ••• ••• ${i.phone_tail}`, status: i.status }),
      picks: (picks[e.id] || []).reduce((m, p) => ((m[p.user_id] ||= []).push(p.tobacco_id), m), {}),
      bowls: Object.fromEntries((bowls[e.id] || []).map(b => [b.user_id, b.bowl_id])),
      comments: member ? (comments[e.id] || []).filter(c => c.kind === 'ev').map(comment) : [],
      remind: {}, notified: {},
      story: st ? { rating: st.rating, text: st.text, highlights: JSON.parse(st.highlights), at: st.at, fire: (fire[e.id] || []).map(f => f.user_id), comments: (comments[e.id] || []).filter(c => c.kind === 'story').map(comment) } : undefined
    };
  });
  const reviews = db.q('SELECT * FROM reviews ORDER BY at DESC').all().map(r => ({ id: r.id, tobaccoId: r.tobacco_id, userId: r.user_id, rating: r.rating, text: r.text, at: r.at }));
  const likes = group(db.q('SELECT * FROM mix_likes').all(), 'mix_id');
  const mixes = db.q('SELECT * FROM mixes ORDER BY at DESC').all().map(m => ({ id: m.id, name: m.name, authorId: m.author_id, parts: JSON.parse(m.parts), likes: (likes[m.id] || []).map(l => l.user_id), at: m.at }));
  const notifications = meId ? db.q('SELECT * FROM notifications WHERE user_id = ? ORDER BY at DESC LIMIT 100').all(meId)
    .map(n => ({ id: n.id, type: n.type, actorId: n.actor_id, eventId: n.event_id, ref: n.ref, at: n.at, read: !!n.read })) : [];
  return {
    session: meId, sessionAt: session?.created_at || null, sessionExp: session?.expires_at || null, csrf: session?.csrf || null,
    users, events, reviews, mixes, notifications, storiesSeeded: true
  };
}

// ---------- Помощники прав ----------
const getEvent = (db, eid) => { if (!isId(eid)) fail(404, 'not_found', 'Сбор не найден.', 'Event not found.'); return db.q('SELECT * FROM events WHERE id = ?').get(eid) || fail(404, 'not_found', 'Сбор не найден.', 'Event not found.'); };
const myInvite = (db, eid, uid2) => db.q('SELECT * FROM invites WHERE event_id = ? AND user_id = ?').get(eid, uid2);
const isMember = (db, e, uid2) => e.host_id === uid2 || !!myInvite(db, e.id, uid2);
const canVote = (db, e, uid2) => e.host_id === uid2 || myInvite(db, e.id, uid2)?.status === 'going';
const needHost = (e, me) => { if (e.host_id !== me.id) fail(403, 'forbidden', 'Это может сделать только организатор.', 'Only the host can do this.'); };
const needMember = (db, e, me) => { if (!isMember(db, e, me.id)) fail(403, 'forbidden', 'Это закрытый сбор.', 'This is a private event.'); };
const needUpcoming = e => { if (isPast(e.at)) fail(409, 'past', 'Сбор уже прошёл.', 'The event has already passed.'); };
const goingIds = (db, e) => [e.host_id, ...db.q("SELECT user_id FROM invites WHERE event_id = ? AND status = 'going' AND user_id IS NOT NULL").all(e.id).map(r => r.user_id)];

function notify(db, userId, type, actorId, eventId = null, ref = null) {
  if (!userId || userId === actorId) return;
  db.q('INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id('n'), userId, type, actorId, eventId, ref, nowIso());
}

// ---------- Сессии ----------
function startSession(db, ctx, user) {
  const token = require('./secure').token(), csrf = require('./secure').token(), now = Date.now();
  db.q('INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(sha256(token), user.id, csrf, now, now + LIMITS.sessionMs, now, ctx.ip, String(ctx.req.headers['user-agent'] || '').slice(0, 160));
  ctx.setCookie(token, LIMITS.sessionMs);
  ctx.session = db.q('SELECT * FROM sessions WHERE token_hash = ?').get(sha256(token));
  ctx.user = user;
}

// ---------- Коды из SMS ----------
const codeHash = (code, idx) => sha256(`${idx}:${code}`);
function checkCode(db, idx, purpose, code) {
  const row = db.q('SELECT * FROM sms_codes WHERE phone_idx = ?').get(idx);
  if (!row || row.purpose !== purpose) fail(400, 'code_missing', 'Сначала запросите код.', 'Request a code first.');
  if (Date.now() > row.expires_at) fail(400, 'code_expired', 'Код устарел. Запросите новый.', 'The code has expired. Request a new one.');
  if (row.attempts >= LIMITS.codeAttempts) fail(429, 'code_attempts', 'Слишком много неверных попыток. Запросите новый код.', 'Too many wrong attempts. Request a new code.');
  if (!sameHash(codeHash(String(code || ''), idx), row.code_hash)) {
    db.q('UPDATE sms_codes SET attempts = attempts + 1 WHERE phone_idx = ?').run(idx);
    const left = LIMITS.codeAttempts - row.attempts - 1;
    fail(400, 'code_wrong', `Код не подходит. Осталось попыток: ${left}.`, `Wrong code. Attempts left: ${left}.`, { left });
  }
  db.q('DELETE FROM sms_codes WHERE phone_idx = ?').run(idx);
}
function authLimits(ctx, idx) {
  for (const [key, lim] of [['auth:ip:' + ctx.ip, LIMITS.authPerIp], ['auth:ph:' + idx, LIMITS.authPerPhone]]) {
    const r = hit(key, lim);
    if (!r.ok) { audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: key.split(':')[1] }); fail(429, 'rate_limited', `Слишком много попыток. Попробуйте через ${minutes(r.retryAfter)} мин.`, `Too many attempts. Try again in ${minutes(r.retryAfter)} min.`, wait(r.retryAfter)); }
  }
}
function phoneOf(body) {
  const phone = normPhone(body.phone);
  if (!validPhone(phone)) fail(400, 'bad_phone', 'Введите номер полностью, вместе с кодом страны.', 'Enter the full number including the country code.');
  return { phone, idx: phoneIndex(phone) };
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
function addInvites(db, e, me, list) {
  if (!Array.isArray(list)) return 0;
  if (list.length > 30) fail(400, 'too_many', 'За раз можно пригласить до 30 человек.', 'You can invite up to 30 people at once.');
  let n = 0;
  for (const it of list) {
    if (it?.userId && isId(it.userId) && it.userId !== e.host_id && db.q('SELECT 1 FROM users WHERE id = ?').get(it.userId)) {
      const r = db.q("INSERT OR IGNORE INTO invites (event_id, user_id, status) VALUES (?, ?, 'pending')").run(e.id, it.userId);
      if (r.changes) { n++; notify(db, it.userId, 'invite', me.id, e.id); }
    } else if (it?.phone) {
      const p = normPhone(it.phone); if (!validPhone(p)) continue;
      const idx = phoneIndex(p), u = db.q('SELECT id FROM users WHERE phone_idx = ?').get(idx);
      if (u) { if (u.id === e.host_id) continue; const r = db.q("INSERT OR IGNORE INTO invites (event_id, user_id, status) VALUES (?, ?, 'pending')").run(e.id, u.id); if (r.changes) { n++; notify(db, u.id, 'invite', me.id, e.id); } }
      else { const r = db.q("INSERT OR IGNORE INTO invites (event_id, phone_idx, phone_enc, phone_tail, status) VALUES (?, ?, ?, ?, 'pending')").run(e.id, idx, encrypt(p), p.slice(-3)); if (r.changes) n++; }
    }
  }
  return n;
}

// ---------- Маршруты ----------
// [метод, путь, обработчик, параметры]. auth: нужен вход; data: ответ — свежие данные пользователя.
const routes = [];
const on = (method, path, fn, opt = {}) => routes.push({ method, re: new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, opt });

on('GET', '/api/health', ctx => ({ ok: true, mode: 'server', sms: require('./sms').providerName(), version: 1 }));
on('GET', '/api/bootstrap', ctx => bootstrap(ctx.db, ctx.user, ctx.session));

on('POST', '/api/auth/sms', async ctx => {
  const { phone, idx } = phoneOf(ctx.body), purpose = ctx.body.purpose === 'login' ? 'login' : 'register';
  authLimits(ctx, idx);
  const sms = hit('sms:' + idx, LIMITS.smsPerPhone);
  if (!sms.ok) { audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'sms ' + maskPhone(phone) }); fail(429, 'sms_limit', `Новый код можно запросить через ${minutes(sms.retryAfter)} мин.`, `You can request a new code in ${minutes(sms.retryAfter)} min.`, wait(sms.retryAfter)); }
  const user = ctx.db.q('SELECT id FROM users WHERE phone_idx = ?').get(idx);
  if (purpose === 'register') {
    if (user) fail(409, 'phone_taken', 'Этот номер уже зарегистрирован. Войдите или войдите по SMS.', 'This number is already registered. Sign in instead.');
    if (ctx.db.q('SELECT COUNT(*) AS n FROM users WHERE created_ip = ?').get(ctx.ip).n >= LIMITS.accountsPerIp) {
      audit(ctx.db, { type: 'rate_limited', ip: ctx.ip, detail: 'accounts per ip' });
      fail(429, 'ip_accounts', `С одного адреса можно создать не больше ${LIMITS.accountsPerIp} аккаунтов.`, `At most ${LIMITS.accountsPerIp} accounts can be created from one address.`);
    }
  }
  // Для входа по SMS не сообщаем, есть ли номер в базе: ответ одинаковый.
  if (purpose === 'login' && !user) return { ok: true, ttl: LIMITS.codeTtlMs / 1000 };
  const code = smsCode();
  ctx.db.q('INSERT OR REPLACE INTO sms_codes VALUES (?, ?, ?, ?, 0, ?)').run(idx, codeHash(code, idx), purpose, Date.now() + LIMITS.codeTtlMs, Date.now());
  try { await sendSms(phone, `Hookah Party: код ${code}. Никому его не сообщайте.`); }
  catch (e) { ctx.db.q('DELETE FROM sms_codes WHERE phone_idx = ?').run(idx); require('./guard').log('error', 'SMS не отправлено', { err: e.message }); fail(502, 'sms_failed', 'Не удалось отправить SMS. Попробуйте позже.', 'Could not send the SMS. Try again later.'); }
  audit(ctx.db, { type: 'sms_sent', ip: ctx.ip, detail: maskPhone(phone) });
  return { ok: true, ttl: LIMITS.codeTtlMs / 1000, ...(exposeCode() ? { devCode: code } : {}) };
});

on('POST', '/api/auth/register', async ctx => {
  const b = ctx.body, { phone, idx } = phoneOf(b);
  const name = clean(b.name, 40);
  if (!validName(name)) fail(400, 'bad_name', 'Укажите имя буквами: от 2 до 40 символов.', 'Enter a name using letters: 2 to 40 characters.');
  const issue = passIssue(b.password, phone);
  if (issue) fail(400, issue, 'Пароль слишком простой: от 8 символов, буквы и цифры, без очевидных сочетаний.', 'The password is too weak: 8+ characters, letters and digits, nothing obvious.');
  if (b.adult !== true) fail(400, 'not_adult', 'Сервис доступен только совершеннолетним.', 'The service is for adults only.');
  authLimits(ctx, idx);
  if (ctx.db.q('SELECT 1 FROM users WHERE phone_idx = ?').get(idx)) fail(409, 'phone_taken', 'Этот номер уже зарегистрирован.', 'This number is already registered.');
  checkCode(ctx.db, idx, 'register', b.code);
  const pass = await hashPassword(b.password), uid2 = id('u');
  ctx.db.tx(() => {
    ctx.db.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(uid2, name, encrypt(phone), idx, phone.slice(-3), pass, nowIso(), ctx.ip);
    // Приглашения «по номеру», отправленные до регистрации, переходят к новому пользователю.
    for (const inv of ctx.db.q('SELECT * FROM invites WHERE phone_idx = ?').all(idx)) {
      ctx.db.q('UPDATE OR IGNORE invites SET user_id = ?, phone_idx = NULL, phone_enc = NULL, phone_tail = NULL WHERE id = ?').run(uid2, inv.id);
      const e = ctx.db.q('SELECT host_id FROM events WHERE id = ?').get(inv.event_id);
      if (e) notify(ctx.db, uid2, 'invite', e.host_id, inv.event_id);
    }
  });
  const user = ctx.db.q('SELECT * FROM users WHERE id = ?').get(uid2);
  startSession(ctx.db, ctx, user);
  audit(ctx.db, { type: 'register', userId: uid2, ip: ctx.ip, detail: maskPhone(phone) });
  return { data: bootstrap(ctx.db, ctx.user, ctx.session) };
});

on('POST', '/api/auth/login', async ctx => {
  const { phone, idx } = phoneOf(ctx.body);
  const lock = lockLeft('login:' + idx);
  if (lock) fail(429, 'locked', `Слишком много неверных попыток. Вход заблокирован ещё на ${minutes(lock / 1000)} мин.`, `Too many wrong attempts. Sign-in is locked for ${minutes(lock / 1000)} min.`, wait(Math.ceil(lock / 1000)));
  authLimits(ctx, idx);
  const user = ctx.db.q('SELECT * FROM users WHERE phone_idx = ?').get(idx);
  const ok = user ? await verifyPassword(ctx.body.password, user.pass) : await burnTime(ctx.body.password);
  if (!ok || !user) {
    const left = failAttempt('login:' + idx);
    audit(ctx.db, { type: left ? 'login_fail' : 'lockout', userId: user?.id, ip: ctx.ip, detail: maskPhone(phone) });
    fail(401, left ? 'bad_credentials' : 'locked', left ? `Неверный номер или пароль. Осталось попыток: ${left}.` : 'Неверный пароль 5 раз подряд. Вход заблокирован на 5 минут.',
      left ? `Wrong number or password. Attempts left: ${left}.` : 'Wrong password 5 times in a row. Sign-in is locked for 5 minutes.', { left });
  }
  clearFails('login:' + idx);
  startSession(ctx.db, ctx, user);
  audit(ctx.db, { type: 'login_ok', userId: user.id, ip: ctx.ip });
  return { data: bootstrap(ctx.db, ctx.user, ctx.session) };
});

on('POST', '/api/auth/login-sms', async ctx => {
  const { phone, idx } = phoneOf(ctx.body);
  authLimits(ctx, idx);
  checkCode(ctx.db, idx, 'login', ctx.body.code);
  const user = ctx.db.q('SELECT * FROM users WHERE phone_idx = ?').get(idx) || fail(400, 'code_missing', 'Сначала запросите код.', 'Request a code first.');
  clearFails('login:' + idx);
  startSession(ctx.db, ctx, user);
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
  ctx.setCookie('', 0);
  audit(ctx.db, { type: 'logout_all', userId: ctx.user.id, ip: ctx.ip });
  return { data: bootstrap(ctx.db, null, null) };
}, { auth: true });

on('GET', '/api/security/log', ctx => ({
  log: ctx.db.q('SELECT at, type, ip, detail FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT 30').all(ctx.user.id).map(r => ({ ...r, ip: r.ip ? r.ip.replace(/(\d+)\.(\d+)$/, '•.•') : null })),
  sessions: ctx.db.q('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?').get(ctx.user.id, Date.now()).n
}), { auth: true });

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
on('PUT', '/api/me/avatar', ctx => {
  const a = safeAvatar(ctx.body.dataUrl) || fail(400, 'bad_avatar', 'Нужна картинка JPG, PNG или WebP до 300 КБ.', 'An image (JPG, PNG or WebP) up to 300 KB is required.');
  ctx.db.q('UPDATE users SET avatar = ? WHERE id = ?').run(a, ctx.user.id);
}, { auth: true, data: true });
on('DELETE', '/api/me/avatar', ctx => { ctx.db.q('UPDATE users SET avatar = NULL WHERE id = ?').run(ctx.user.id); }, { auth: true, data: true });
on('POST', '/api/me/favs/:tid', ctx => {
  const t = ctx.params.tid; if (!TOBACCOS.has(t)) fail(404, 'not_found', 'Такого табака нет.', 'No such tobacco.');
  if (!ctx.db.q('DELETE FROM favs WHERE user_id = ? AND tobacco_id = ?').run(ctx.user.id, t).changes) ctx.db.q('INSERT INTO favs VALUES (?, ?)').run(ctx.user.id, t);
}, { auth: true, data: true });
on('POST', '/api/friends/:uid', ctx => {
  const f = ctx.params.uid; if (!isId(f) || f === ctx.user.id || !ctx.db.q('SELECT 1 FROM users WHERE id = ?').get(f)) fail(404, 'not_found', 'Пользователь не найден.', 'User not found.');
  // В этой версии дружба взаимная сразу; позже здесь будет заявка с подтверждением.
  if (ctx.db.q('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(ctx.user.id, f).changes) ctx.db.q('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(f, ctx.user.id);
  else { ctx.db.q('INSERT OR IGNORE INTO friends VALUES (?, ?)').run(ctx.user.id, f); ctx.db.q('INSERT OR IGNORE INTO friends VALUES (?, ?)').run(f, ctx.user.id); notify(ctx.db, f, 'friend', ctx.user.id); }
}, { auth: true, data: true });

// ---------- Сборы ----------
on('POST', '/api/events', ctx => {
  const f = eventFields(ctx.body), eid = id('e');
  ctx.db.tx(() => {
    ctx.db.q('INSERT INTO events (id, title, venue, venue_id, address, map_url, at, host_id, descr, hookahs, price, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(eid, f.title, f.venue, f.venue_id, f.address, f.map_url, f.at, ctx.user.id, f.descr, f.hookahs, f.price, nowIso());
    addInvites(ctx.db, getEvent(ctx.db, eid), ctx.user, ctx.body.invites);
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
  for (const u of goingIds(ctx.db, e)) notify(ctx.db, u, 'cancelled', ctx.user.id, null, e.title.slice(0, 60));
  ctx.db.q('DELETE FROM events WHERE id = ?').run(e.id);
}, { auth: true, data: true });
on('POST', '/api/events/:id/invites', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user.id)) fail(403, 'forbidden', 'Приглашать могут организатор и те, кто идёт.', 'Only the host and guests who are going can invite.');
  ctx.db.tx(() => addInvites(ctx.db, e, ctx.user, ctx.body.invites));
}, { auth: true, data: true });
on('POST', '/api/events/:id/rsvp', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  const inv = myInvite(ctx.db, e.id, ctx.user.id) || fail(403, 'forbidden', 'Вас не приглашали на этот сбор.', 'You are not invited to this event.');
  const status = ctx.body.status === 'going' ? 'going' : 'declined';
  ctx.db.tx(() => {
    ctx.db.q('UPDATE invites SET status = ?, at = ? WHERE id = ?').run(status, nowIso(), inv.id);
    if (status !== 'going') for (const t of ['picks', 'bowls', 'paid']) ctx.db.q(`DELETE FROM ${t} WHERE event_id = ? AND user_id = ?`).run(e.id, ctx.user.id);
    notify(ctx.db, e.host_id, status === 'going' ? 'rsvp_going' : 'rsvp_declined', ctx.user.id, e.id);
  });
}, { auth: true, data: true });
on('PUT', '/api/events/:id/picks', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user.id)) fail(403, 'forbidden', 'Голосовать могут те, кто идёт.', 'Only guests who are going can vote.');
  const ids = [...new Set(Array.isArray(ctx.body.ids) ? ctx.body.ids : [])].filter(t => TOBACCOS.has(t));
  if (ids.length > 5) fail(400, 'too_many', 'Можно выбрать до 5 вкусов.', 'You can pick up to 5 flavours.');
  ctx.db.tx(() => { ctx.db.q('DELETE FROM picks WHERE event_id = ? AND user_id = ?').run(e.id, ctx.user.id); for (const t of ids) ctx.db.q('INSERT INTO picks VALUES (?, ?, ?)').run(e.id, ctx.user.id, t); });
}, { auth: true, data: true });
on('PUT', '/api/events/:id/bowl', ctx => {
  const e = getEvent(ctx.db, ctx.params.id); needUpcoming(e);
  if (!canVote(ctx.db, e, ctx.user.id)) fail(403, 'forbidden', 'Голосовать могут те, кто идёт.', 'Only guests who are going can vote.');
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
    for (const u of new Set([e.host_id, ...ctx.db.q("SELECT user_id FROM invites WHERE event_id = ? AND status != 'declined' AND user_id IS NOT NULL").all(e.id).map(r => r.user_id)])) notify(ctx.db, u, 'comment', ctx.user.id, e.id, cid);
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

function match(method, path) {
  for (const r of routes) { if (r.method !== method) continue; const m = r.re.exec(path); if (m) return { route: r, params: m.groups || {} }; }
  return null;
}

module.exports = { match, bootstrap };
