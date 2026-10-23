/* Тесты сервера: вход, права, CSRF, лимиты, регистрация, заголовки безопасности.
   Сервер поднимается в памяти на случайном порту. Запуск: npm test */
process.env.NODE_ENV = 'test';
process.env.SMS_PROVIDER = 'dev';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { open } = require('../server/lib/db');
const { seed } = require('../server/lib/seed');
const { createServer } = require('../server/index');

let server, base;
before(async () => {
  const db = open(':memory:');
  await seed(db);
  server = createServer(db);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

// Небольшой клиент с cookie и CSRF-токеном, как у браузера.
function client() {
  let cookie = '', csrf = '';
  const call = async (method, path, body, headers = {}) => {
    const r = await fetch(base + '/api' + path, {
      method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    const set = r.headers.get('set-cookie'); if (set) cookie = set.split(';')[0];
    const data = await r.json().catch(() => null);
    if (data?.data?.csrf !== undefined) csrf = data.data.csrf || '';
    return { status: r.status, data };
  };
  return { call, login: async (phone = '0700000001', password = 'hookah') => call('POST', '/auth/login', { phone, password }) };
}

test('страница отдаётся с заголовками безопасности', async () => {
  const r = await fetch(base + '/');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

test('файлы сервера и базы снаружи недоступны', async () => {
  for (const p of ['/server/index.js', '/server/data/hookah.db', '/../package.json', '/.env']) assert.equal((await fetch(base + p)).status, 404, p);
});

test('гость не видит чужие номера и закрытые сборы', async () => {
  const { data } = await client().call('GET', '/bootstrap');
  assert.equal(data.session, null);
  assert.ok(data.users.every(u => u.phone === null));
  assert.ok(data.events.every(e => e.story), 'гостю видны только вечера из Истории');
});

test('неверный пароль, блокировка после 5 попыток', async () => {
  const c = client();
  const r = await c.login('0700000004', 'wrong-pass1');
  assert.equal(r.status, 401);
  assert.equal(r.data.left, 4);
  for (let i = 0; i < 4; i++) await c.login('0700000004', 'wrong-pass1');
  const locked = await c.login('0700000004', 'hookah');
  assert.equal(locked.status, 429);
  assert.equal(locked.data.error, 'locked');
});

test('вход, CSRF и чужой Origin', async () => {
  const c = client();
  const r = await c.login();
  assert.equal(r.status, 200);
  assert.equal(r.data.data.session, 'u1');
  const noCsrf = await fetch(base + '/api/events/e1/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: 'hp_sid=bad' }, body: '{"text":"x"}' });
  assert.equal(noCsrf.status, 401);
  const evil = await c.call('POST', '/events/e1/comments', { text: 'x' }, { Origin: 'https://evil.example' });
  assert.equal(evil.status, 403);
});

test('права: не участник и не организатор', async () => {
  const c = client(); await c.login();
  assert.equal((await c.call('POST', '/events/e6/comments', { text: 'привет' })).status, 403);
  assert.equal((await c.call('PUT', '/events/e2/bill', { hookahs: 9, price: 1 })).status, 403);
  assert.equal((await c.call('POST', "/events/e1' OR 1=1--/rsvp", { status: 'going' })).status, 404);
});

test('сообщения: текст сохраняется как есть, пауза 3 минуты', async () => {
  const c = client(); await c.login('0700000002');
  const ok = await c.call('POST', '/events/e1/comments', { text: '<img src=x onerror=alert(1)> Привет' });
  assert.equal(ok.status, 200);
  const e1 = ok.data.data.events.find(e => e.id === 'e1');
  assert.equal(e1.comments.at(-1).text, '<img src=x onerror=alert(1)> Привет', 'экранирует интерфейс при показе');
  const again = await c.call('POST', '/events/e1/comments', { text: 'ещё' });
  assert.equal(again.status, 429);
  assert.equal(again.data.error, 'chat_cooldown');
});

test('реакция: одна от человека, повтор снимает', async () => {
  const c = client(); await c.login('0700000005');
  let r = await c.call('PUT', '/comments/c1/reaction', { emoji: '🔥' });
  assert.equal(r.data.data.events.find(e => e.id === 'e1').comments.find(x => x.id === 'c1').reactions.u5, '🔥');
  r = await c.call('PUT', '/comments/c1/reaction', { emoji: '🔥' });
  assert.equal(r.data.data.events.find(e => e.id === 'e1').comments.find(x => x.id === 'c1').reactions.u5, undefined);
  assert.equal((await c.call('PUT', '/comments/c1/reaction', { emoji: '💩' })).status, 400);
});

test('регистрация: код из SMS, слабый пароль, приглашение по номеру', async () => {
  const c = client();
  const sms = await c.call('POST', '/auth/sms', { phone: '0555123456', purpose: 'register' });
  assert.equal(sms.status, 200);
  assert.match(sms.data.devCode, /^\d{4}$/);
  const weak = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: '12345678', code: sms.data.devCode, adult: true });
  assert.equal(weak.status, 400);
  const wrong = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: 'Kalyan-Night-2026', code: '0000', adult: true });
  assert.equal(wrong.data.error, 'code_wrong');
  const ok = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: 'Kalyan-Night-2026', code: sms.data.devCode, adult: true });
  assert.equal(ok.status, 200);
  const e1 = ok.data.data.events.find(e => e.id === 'e1');
  assert.ok(e1 && e1.invites.some(i => i.userId === ok.data.data.session), 'приглашение «по номеру» перешло к новому пользователю');
});

test('коды SMS: не больше 3 на номер за 10 минут', async () => {
  const c = client();
  for (let i = 0; i < 3; i++) assert.equal((await c.call('POST', '/auth/sms', { phone: '0555000111', purpose: 'register' })).status, 200);
  const r = await c.call('POST', '/auth/sms', { phone: '0555000111', purpose: 'register' });
  assert.equal(r.status, 429);
});

test('выход завершает сессию', async () => {
  const c = client(); await c.login('0700000006');
  assert.equal((await c.call('POST', '/auth/logout', {})).status, 200);
  assert.equal((await c.call('GET', '/security/log')).status, 401);
});

test('один активный сбор на организатора', async () => {
  const c = client(); await c.login('0700000001');
  const at = new Date(Date.now() + 3 * 864e5).toISOString();
  const r = await c.call('POST', '/events', { title: 'Ещё один', venue: 'Hookah', at });
  assert.equal(r.status, 409);
  assert.equal(r.data.error, 'active_exists');
  assert.equal(r.data.eventId, 'e1');
});

test('отменить сбор может только организатор, отменённый сбор удаляется', async () => {
  const guest = client(); await guest.login('0700000002');
  assert.equal((await guest.call('DELETE', '/events/e1')).status, 403);
  const host = client(); await host.login('0700000006');
  const at = new Date(Date.now() + 2 * 864e5).toISOString();
  const r = await host.call('POST', '/events', { title: 'Тест', venue: 'Hookah', at });
  assert.equal(r.status, 200);
  const del = await host.call('DELETE', `/events/${r.data.id}`);
  assert.equal(del.status, 200);
  assert.ok(!del.data.data.events.some(e => e.id === r.data.id), 'сбора больше нет');
});

test('не больше 12 созданий и отмен в сутки', async () => {
  const c = client(); await c.login('0700000005');
  const at = new Date(Date.now() + 2 * 864e5).toISOString();
  for (let i = 0; i < 12; i++) {
    const r = await c.call('POST', '/events', { title: 'Сбор ' + i, venue: 'Hookah', at });
    assert.equal(r.status, 200, 'создание ' + i);
    assert.equal((await c.call('DELETE', `/events/${r.data.id}`)).status, 200, 'отмена ' + i);
  }
  const over = await c.call('POST', '/events', { title: 'Тринадцатый', venue: 'Hookah', at });
  assert.equal(over.status, 429);
  assert.equal(over.data.error, 'events_limit');
});

test('администратор: скрыт от обычных, требует пароль, удаляет комментарии и сборы', async () => {
  const user = client(); await user.login('0700000003');
  assert.equal((await user.call('GET', '/admin/overview')).status, 404, 'обычный пользователь даже не видит адрес');
  assert.equal((await fetch(base + '/admin.js', { headers: { Cookie: '' } })).status, 404, 'код панели не отдаётся гостю');

  const admin = client(); const login = await admin.login('0700000001');
  assert.equal(login.data.data.role, 'admin');
  assert.equal((await admin.call('GET', '/admin/overview')).data.error, 'step_up', 'без подтверждения пароля нельзя');
  assert.equal((await admin.call('POST', '/admin/unlock', { password: 'wrong' })).status, 401);
  assert.equal((await admin.call('POST', '/admin/unlock', { password: 'hookah' })).status, 200);
  const ov = await admin.call('GET', '/admin/overview');
  assert.equal(ov.status, 200);
  assert.ok(ov.data.comments.length > 0 && ov.data.events.length > 0);
  assert.equal((await admin.call('DELETE', '/admin/comments/c4')).status, 200, 'чужой комментарий в чужом сборе');
  assert.equal((await admin.call('DELETE', '/admin/events/e2')).status, 200, 'чужой сбор');
  const after = await admin.call('GET', '/admin/overview');
  assert.ok(!after.data.comments.some(x => x.id === 'c4') && !after.data.events.some(x => x.id === 'e2'));
  assert.ok(after.data.audit.some(x => x.type === 'admin_delete_event'), 'действие в журнале');
  assert.equal((await user.call('DELETE', '/admin/comments/c1')).status, 404, 'обычный пользователь не может удалять');
});
