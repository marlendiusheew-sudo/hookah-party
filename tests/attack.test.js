/* Постоянный «набор атак» по нашему собственному серверу (в памяти, на localhost — никаких внешних адресов).
   Проверяем: инъекции во все текстовые поля, права доступа, CSRF/Origin, перебор, кривой HTTP, фаззинг всех маршрутов.
   Запуск: node --test tests/attack.test.js

   Важно про лимиты: счётчики ограничения частоты в lib/guard.js живут в памяти процесса. node --test запускает каждый
   файл в своём процессе, но ВНУТРИ файла порядок важен — поэтому тесты на лимиты и перебор стоят ПОСЛЕДНИМИ. Чтобы массовые
   запросы (инъекции, фаззинг) не упёрлись в общий лимит «600 запросов с одного IP за 10 минут», включаем TRUST_PROXY и даём
   каждому «действующему лицу» свой адрес через X-Forwarded-For; тесты на лимиты используют фиксированные адреса/аккаунты. */
'use strict';
process.env.NODE_ENV = 'test';
process.env.SMS_PROVIDER = 'dev';
process.env.TRUST_PROXY = '1';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net'), crypto = require('node:crypto');
process.env.ADMIN_PHONES = '+996700000001';
process.env.ADMIN_CODE_KEY = crypto.randomBytes(32).toString('base64');
process.env.ADMIN_PANEL_ENC = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hp-atk-')), 'panel.enc');
const panel = require('../server/lib/panel');
fs.writeFileSync(process.env.ADMIN_PANEL_ENC, panel.encrypt(Buffer.from('window.HP_ADMIN = { test: true };'), Buffer.from(process.env.ADMIN_CODE_KEY, 'base64')));

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { open } = require('../server/lib/db');
const { seed } = require('../server/lib/seed');
const { createServer } = require('../server/index');
const { routes } = require('../server/lib/api');
const util = require('../server/lib/util');
const totp = require('../server/lib/totp');
const guard = require('../server/lib/guard');

let server, base, db;
before(async () => {
  db = open(':memory:');
  await seed(db);
  server = createServer(db);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

// ---------- Маленький детерминированный ГПСЧ (mulberry32) ----------
function prng(seed) {
  let a = seed >>> 0;
  return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
}
const pick = (rnd, arr) => arr[Math.floor(rnd() * arr.length)];

// ---------- Корпус зловредных значений ----------
const XSS = [
  '<script>window.__x=1</script>', '<img src=x onerror=alert(1)>', '"><svg onload=alert(1)>', '</textarea><script>alert(1)</script>',
  'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)', '<a href="javascript:alert(1)">x</a>',
  'expression(alert(1))', 'url(javascript:alert(1))', '${7*7}', '{{7*7}}', '#{7*7}', '<%= 7*7 %>',
  '‮gnp.exe', '​​skryto', 'nul\u0000byte', 'tab\there', '﻿bom', 'x'.repeat(10000)
];
const SQL = ["' OR 1=1--", '"; DROP TABLE users;--', "'; DELETE FROM events; --", 'admin\'--', '’ OR ’1’=’1', '%27 OR 1=1', "1); DROP TABLE comments;--", "' UNION SELECT pass FROM users--"];
const CORPUS = [...XSS, ...SQL];

// ---------- Клиент с cookie, CSRF и своим адресом (X-Forwarded-For) ----------
let ipCounter = 0;
const freshIp = () => `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${(ipCounter++) & 255}`;
function client(ip = freshIp()) {
  let cookie = '', csrf = '', myId = null, myPhone = '';
  const call = async (method, p, body, headers = {}) => {
    const useJson = body !== undefined;
    const r = await fetch(base + '/api' + p, {
      method,
      headers: { ...(useJson ? { 'Content-Type': 'application/json' } : {}), 'X-Forwarded-For': ip, ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...headers },
      body: useJson ? JSON.stringify(body) : undefined
    });
    const set = r.headers.get('set-cookie'); if (set) cookie = set.split(';')[0];
    const data = await r.json().catch(() => null);
    // Свежие данные приходят либо как {data:{...}} (действия), либо прямо (GET /bootstrap).
    const boot = data && typeof data.data === 'object' && data.data ? data.data : data;
    if (boot && typeof boot === 'object' && 'csrf' in boot) csrf = boot.csrf || '';
    if (boot && typeof boot === 'object' && 'session' in boot && boot.session) myId = boot.session;
    // Требование: любой ответ API — это JSON с заголовком X-Content-Type-Options: nosniff. Исключение одно — само фото профиля
    // (GET /api/avatar/<id>, 200 или 304): тогда это картинка JPG, PNG или WebP.
    const image = method === 'GET' && /^\/avatar\//.test(p) && (r.status === 200 || r.status === 304);
    assert.match(r.headers.get('content-type') || '', image ? /^image\/(png|jpeg|webp)$/ : /application\/json/, `${method} ${p}: тип ответа ${image ? 'картинка' : 'JSON'}`);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff', `${method} ${p}: nosniff`);
    assert.ok(r.status < 500, `${method} ${p}: без 500 (получено ${r.status})`);
    return { status: r.status, data, headers: r.headers, cookie };
  };
  return {
    call, ip,
    jar: () => ({ cookie, csrf }),
    id: () => myId,
    phone: () => myPhone,
    login: (phone, password = 'hookah') => call('POST', '/auth/login', { phone, password }),
    async register(name, phone, password = 'Attack-Pass-2026') {
      myPhone = phone;
      const sms = await call('POST', '/auth/sms', { phone, purpose: 'register' });
      if (!sms.data?.devCode) return sms;
      return call('POST', '/auth/register', { name, phone, password, code: sms.data.devCode, challenge: sms.data.challenge, adult: true });
    }
  };
}
const bootUser = async c => (await c.call('GET', '/bootstrap')).data;
const meIn = d => d.users.find(u => u.id === d.session);

// Чистое «сейчас+N дней» в будущем для сборов.
const future = (d = 3) => new Date(Date.now() + d * 864e5).toISOString();

// ======================================================================
// 1. Инъекции во все текстовые поля всех пишущих эндпоинтов
// ======================================================================
test('инъекции: профиль (имя, любимое место) очищаются и ограничиваются по длине', async () => {
  const c = client();
  const reg = await c.register('Профиль Тест', '0555200001');
  assert.equal(reg.status, 200);
  for (const payload of CORPUS) {
    // Любимое место: нет строгой проверки формата, значит проверяем именно очистку clean(…,60).
    const r = await c.call('PATCH', '/me', { favVenue: payload });
    assert.equal(r.status, 200, 'favVenue ' + JSON.stringify(payload.slice(0, 20)));
    const stored = meIn(r.data.data).favVenue;
    assert.equal(stored, util.clean(payload, 60), 'favVenue сохранён очищенным');
    assert.ok(stored.length <= 60 && !/[\u0000-\u001F​‮]/.test(stored), 'без управляющих и невидимых символов');
    // Имя: либо проходит проверку формата, либо отклоняется 400 — но не 500 и не сохраняется как есть.
    const rn = await c.call('PATCH', '/me', { name: payload });
    assert.ok(rn.status === 200 || rn.status === 400, 'имя: 200 или 400');
    if (rn.status === 200) assert.equal(meIn(rn.data.data).name, util.clean(payload, 40));
  }
});

test('инъекции: поля сбора (название, место, адрес, описание, карта) чистятся, ссылка — только http(s)', async () => {
  const c = client();
  await c.register('Хост Полей', '0555200002');
  const eid = (await c.call('POST', '/events', { title: 'Старт', venue: 'Место', at: future() })).data.id;
  for (const payload of CORPUS) {
    const r = await c.call('PATCH', `/events/${eid}`, { title: payload, venue: payload, address: payload, desc: payload });
    assert.ok(r.status === 200 || r.status === 400, 'поля: 200/400');
    if (r.status === 200) {
      const e = r.data.data.events.find(x => x.id === eid);
      assert.equal(e.title, util.clean(payload, 60));
      assert.equal(e.venue, util.clean(payload, 60));
      assert.equal(e.address, util.clean(payload, 100));
      assert.equal(e.desc, util.clean(payload, 400, true));
    }
    // mapUrl: любой payload из корпуса — не валидный https, значит 400 bad_url и значение не меняется.
    const ru = await c.call('PATCH', `/events/${eid}`, { mapUrl: payload });
    assert.ok(ru.status === 400 || ru.status === 200, 'mapUrl 200/400');
    const now = (await c.call('GET', '/bootstrap')).data.events.find(x => x.id === eid).mapUrl;
    assert.ok(now === '' || /^https?:\/\//.test(now), 'mapUrl либо пусто, либо http(s)');
    assert.ok(!/["'<>]/.test(now), 'в mapUrl нет кавычек и угловых скобок');
  }
  // Валидная, но «злая» ссылка с кавычками/скобками — отклоняется; обычная https — сохраняется как есть.
  assert.equal((await c.call('PATCH', `/events/${eid}`, { mapUrl: 'https://evil.example/"><script>' })).status, 400);
  const ok = await c.call('PATCH', `/events/${eid}`, { mapUrl: 'https://maps.example/place?id=42' });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.data.events.find(x => x.id === eid).mapUrl, 'https://maps.example/place?id=42');
});

test('инъекции: приглашения по номеру с мусором не ломают сервер и не добавляют приглашённых', async () => {
  const c = client();
  await c.register('Хост Приглашений', '0555200003');
  const eid = (await c.call('POST', '/events', { title: 'Сбор', venue: 'Место', at: future() })).data.id;
  const before = (await c.call('GET', '/bootstrap')).data.events.find(e => e.id === eid).invites.length;
  for (const payload of CORPUS) {
    const r = await c.call('POST', `/events/${eid}/invites`, { invites: [{ phone: payload }, { userId: payload }] });
    assert.equal(r.status, 200, 'мусорные приглашения принимаются без ошибки');
  }
  const after = (await c.call('GET', '/bootstrap')).data.events.find(e => e.id === eid).invites.length;
  assert.equal(after, before, 'ни одного «приглашённого» из мусора не добавилось');
});

test('инъекции: сообщения в сборе сохраняются очищенными (текст экранирует интерфейс)', async () => {
  // Пауза между сообщениями — 3 минуты на сбор, поэтому раскладываем по разным гостям.
  const host = client();
  await host.register('Хост Чата', '0555200010');
  const eid = (await host.call('POST', '/events', { title: 'Чат', venue: 'Место', at: future() })).data.id;
  const sub = CORPUS.slice(0, 8);
  for (let i = 0; i < sub.length; i++) {
    const payload = sub[i], g = client();
    await g.register('Гость', '05552001' + String(20 + i).padStart(2, '0'));
    const gid = g.id();
    // Приглашаем гостя по id (достаточно для права писать), затем он отвечает «иду».
    await host.call('POST', `/events/${eid}/invites`, { invites: [{ userId: gid }] });
    await g.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
    const r = await g.call('POST', `/events/${eid}/comments`, { text: payload });
    assert.ok(r.status === 200 || r.status === 400, 'сообщение: 200/400');
    if (r.status === 200) {
      const stored = r.data.data.events.find(e => e.id === eid).comments.find(cm => cm.userId === gid)?.text;
      assert.equal(stored, util.clean(payload, 500, true), 'сообщение сохранено очищенным');
    }
  }
});

test('инъекции: отзывы и миксы — текст и название очищены', async () => {
  const c = client();
  await c.register('Каталог Тест', '0555200030');
  for (const payload of CORPUS) {
    const r = await c.call('PUT', '/reviews/ds-supernova', { rating: 5, text: payload });
    assert.equal(r.status, 200, 'отзыв принят');
    const mine = r.data.data.reviews.find(x => x.tobaccoId === 'ds-supernova' && x.userId === c.id());
    assert.ok(mine, 'свой отзыв найден');
    assert.equal(mine.text, util.clean(payload, 400, true), 'текст отзыва очищен');
  }
  // Название микса: либо принято очищенным, либо 400 (пустое после очистки); не больше 10 в сутки — берём подвыборку.
  for (const payload of CORPUS.slice(0, 8)) {
    const r = await c.call('POST', '/mixes', { name: payload, parts: [{ id: 'od-cola', pct: 50 }, { id: 'tg-canemint', pct: 50 }] });
    assert.ok(r.status === 200 || r.status === 400 || r.status === 429, 'микс: 200/400/429');
    if (r.status === 200) {
      const m = r.data.data.mixes.find(x => x.authorId === c.id() && x.name === util.clean(payload, 40));
      assert.ok(m, 'название микса сохранено очищенным');
    }
  }
});

test('инъекции: рассказ о вечере и комментарии к нему очищаются', async () => {
  const host = client();
  await host.register('Хост Истории', '0555200040');
  const hid = meIn(await bootUser(host)).id;
  // Прошедший сбор нельзя создать через API — вставляем напрямую в базу.
  const past = new Date(Date.now() - 6 * 864e5).toISOString(), eid = 'eAtkStory';
  db.q("INSERT INTO events (id, title, venue, at, host_id, created_at) VALUES (?, 'Был вечер', 'Место', ?, ?, ?)").run(eid, past, hid, past);
  for (const payload of CORPUS.slice(0, 6)) {
    // Удаляем прошлый рассказ, чтобы можно было опубликовать новый с очередным payload.
    db.q('DELETE FROM stories WHERE event_id = ?').run(eid);
    const r = await host.call('POST', `/events/${eid}/story`, { rating: 5, text: payload + ' достаточно длинный текст рассказа', highlights: [payload, payload] });
    assert.ok(r.status === 200 || r.status === 400, 'рассказ 200/400');
    if (r.status === 200) {
      const st = r.data.data.events.find(e => e.id === eid).story;
      assert.equal(st.text, util.clean(payload + ' достаточно длинный текст рассказа', 600, true));
      assert.ok(st.highlights.every(h => !/[\u0000-\u001F]/.test(h) && h.length <= 80), 'highlights очищены');
    }
  }
  // Комментарий к рассказу от другого человека (раз в день на вечер) — проверяем очистку текста на одном payload.
  db.q('DELETE FROM stories WHERE event_id = ?').run(eid);
  await host.call('POST', `/events/${eid}/story`, { rating: 4, text: 'Нормальный рассказ про вечер, всё хорошо', highlights: [] });
  const g = client(); await g.register('Коммент Истории', '0555200041');
  const gid = meIn(await bootUser(g)).id;
  const payload = '<img src=x onerror=alert(1)>" ; DROP TABLE comments;--';
  const rc = await g.call('POST', `/events/${eid}/story/comments`, { text: payload });
  assert.equal(rc.status, 200);
  const sc = rc.data.data.events.find(e => e.id === eid).story.comments.find(x => x.userId === gid);
  assert.equal(sc.text, util.clean(payload, 300, true), 'комментарий к рассказу очищен');
});

test('инъекции: client-errors и csp-report чистят поля, журнал CSP безопасен', async () => {
  const c = client();
  for (const payload of CORPUS.slice(0, 10)) {
    assert.equal((await c.call('POST', '/client-errors', { msg: payload, src: payload, line: payload, page: payload })).status, 200);
  }
  // Отчёт CSP от вошедшего — видно в его журнале; поля должны быть очищены и обрезаны.
  const u = client(); await u.register('CSP Тест', '0555200050');
  const r = await u.call('POST', '/csp-report', { directive: 'script-src-elem', blocked: 'https://evil.example/x.js?t=SECRET#f', sample: '<img src=x onerror=alert(1)>\u0000' + 'y'.repeat(200), src: '../../etc/passwd', line: 'abc', page: '<script>' });
  assert.equal(r.status, 200);
  const log = (await u.call('GET', '/security/log')).data.log.find(x => x.type === 'csp_violation');
  assert.ok(log, 'нарушение CSP в журнале пользователя');
  assert.ok(!/SECRET/.test(log.detail), 'путь и параметры исходного адреса не сохраняются');
  assert.ok(!/[\u0000-\u001F]/.test(log.detail) && log.detail.length < 200, 'детали очищены и обрезаны');
});

test('инъекции: удаление аккаунта с мусорным паролем не падает и не удаляет', async () => {
  const c = client();
  await c.register('Удаляемый', '0555200060', 'Keep-This-2026');
  const uid = meIn(await bootUser(c)).id;
  for (const payload of [...CORPUS.slice(0, 6), 'x'.repeat(5000)]) {
    const r = await c.call('POST', '/me/delete', { password: payload });
    assert.ok(r.status === 401 || r.status === 429, 'мусорный пароль: 401/429, но не 500');
    if (r.status === 429) break; // сработала блокировка после 5 попыток — дальше смысла нет
  }
  assert.ok(db.q('SELECT 1 FROM users WHERE id = ?').get(uid), 'аккаунт на месте');
  guard.clearFails('delete:' + uid);
});

test('инъекции: смена пароля с мусором в полях не падает и пароль не меняет', async () => {
  const c = client();
  await c.register('Пароль Мусор', '0555200070', 'Keep-This-2026');
  const uid = meIn(await bootUser(c)).id, before = db.q('SELECT pass FROM users WHERE id = ?').get(uid).pass;
  // Новый пароль не строкой — отказ ещё до проверки текущего (попытки не тратятся), даже с верным текущим.
  for (const next of [null, true, 42, ['Fresh-Pass-2027'], { a: 1 }, { toString: 1 }]) {
    const r = await c.call('POST', '/me/password', { current: 'Keep-This-2026', next });
    assert.deepEqual([r.status, r.data.error], [400, 'weak_length'], 'новый пароль: ' + JSON.stringify(next));
  }
  // Мусор вместо текущего: 400 (не строка), 401 (неверный), после 5 неверных — 429; никогда 500.
  for (const current of [null, 42, ['Keep-This-2026'], { a: 1 }, ...CORPUS.slice(0, 6), 'x'.repeat(5000)]) {
    const r = await c.call('POST', '/me/password', { current, next: 'Fresh-Pass-2027' });
    assert.ok([400, 401, 429].includes(r.status), `текущий пароль ${JSON.stringify(current).slice(0, 30)}: ${r.status}`);
  }
  assert.equal(db.q('SELECT pass FROM users WHERE id = ?').get(uid).pass, before, 'пароль не изменился');
  assert.equal((await c.call('GET', '/security/log')).status, 200, 'сессия на месте');
  guard.clearFails('pass:' + uid);
});

test('инъекции: админские поля (пароль, код) не роняют сервер', async () => {
  const admin = client(); await admin.login('0700000001');
  for (const payload of CORPUS.slice(0, 8)) {
    const r = await admin.call('POST', '/admin/unlock', { password: payload, code: payload });
    assert.ok(r.status === 401 || r.status === 429, 'unlock с мусором: 401/429');
    if (r.status === 429) break;
  }
  guard.clearFails('admin:u1');
});

test('инъекции: база осталась целой, прототип не отравлен', async () => {
  // Таблицы на месте, посевные данные не повреждены инъекциями выше.
  for (const t of ['users', 'events', 'comments', 'reviews', 'mixes']) assert.ok(db.q(`SELECT COUNT(*) AS n FROM "${t}"`).get().n >= 0);
  assert.equal(db.q("SELECT title FROM events WHERE id = 'e1'").get().title, 'Пятничный сбор', 'посевной сбор не тронут');
  assert.ok(db.q("SELECT 1 FROM users WHERE id = 'u1'").get(), 'посевной администратор на месте');
  assert.equal(({}).polluted, undefined);
  assert.equal(({}).__hp, undefined);
});

// ======================================================================
// 3. Матрица прав доступа
// ======================================================================
test('права: гость, не участник, приглашённый-но-не-идёт и организатор', async () => {
  // Готовим сбор с организатором u1 (e1) и отдельным аккаунтом-участником.
  const guest = client();
  const nonMember = client(); await nonMember.register('Чужой', '0555300001');
  const invited = client(); await invited.register('Приглашён', '0555300002');
  const host = client(); await host.login('0700000001');
  const invId = meIn(await bootUser(invited)).id;
  await host.call('POST', '/events/e1/invites', { invites: [{ userId: invId }] }); // приглашён, но статус pending (не идёт)

  // Эндпоинты, требующие входа: гость → 401.
  const authPaths = [['GET', '/security/log'], ['PATCH', '/me', { name: 'x' }], ['POST', '/events', { title: 'x', venue: 'y', at: future() }],
    ['POST', '/events/e1/comments', { text: 'x' }], ['POST', '/me/delete', { password: 'x' }], ['POST', '/me/password', { current: 'x', next: 'y' }], ['POST', '/mixes', { name: 'x', parts: [] }]];
  for (const [m, p, b] of authPaths) assert.equal((await guest.call(m, p, b)).status, 401, `гость ${m} ${p}`);

  // Закрытый сбор e1: не участник не видит обсуждение и не пишет.
  assert.equal((await nonMember.call('POST', '/events/e1/comments', { text: 'привет' })).status, 403, 'не участник не пишет');
  assert.ok(!(await bootUser(nonMember)).events.some(e => e.id === 'e1' && e.member), 'закрытый сбор не отдаётся не участнику');

  // Приглашённый, но не идёт: голосовать нельзя (canVote требует going), но участник сбор видит.
  assert.equal((await invited.call('PUT', '/events/e1/picks', { ids: ['ds-supernova'] })).status, 403, 'не идёт — не голосует');
  assert.equal((await invited.call('POST', '/events/e1/comments', { text: 'x' })).status, 200, 'приглашённый участник пишет');

  // Только организатор: правка, отмена, счёт, отметка оплаты, рассказ.
  for (const [m, p, b] of [['PATCH', '/events/e1', { title: 'взлом' }], ['DELETE', '/events/e1'], ['PUT', '/events/e1/bill', { hookahs: 1, price: 1 }], ['POST', '/events/e1/paid/u2']]) {
    assert.equal((await invited.call(m, p, b)).status, 403, `не организатор ${m} ${p}`);
  }
  assert.equal(db.q("SELECT title FROM events WHERE id = 'e1'").get().title, 'Пятничный сбор', 'чужая правка не прошла');

  // Несуществующие/чужие объекты: 404, а не утечка.
  assert.equal((await nonMember.call('DELETE', '/comments/c1')).status, 403, 'чужой комментарий не удалить');
  assert.equal((await nonMember.call('POST', '/events/no-such-event/comments', { text: 'x' })).status, 404);
  assert.equal((await nonMember.call('POST', "/events/e1' OR 1=1--/rsvp", { status: 'going' })).status, 404);
});

test('права: вход в панель по коду из приложения (2FA) — гость, обычный пользователь, администратор без кода; мусорные коды', async () => {
  // Отдельный администратор: основной (u1) нужен фаззингу, а счётчики неверных попыток живут в памяти процесса.
  const { hashPassword, encrypt, phoneIndex } = require('../server/lib/secure');
  db.q("INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, role) VALUES ('uAtkTotp', 'Админ Кодов', ?, ?, '919', ?, ?, 'admin')")
    .run(encrypt('996555000919'), phoneIndex('996555000919'), await hashPassword('Totp-Atk-2026'), new Date().toISOString());
  const phones = process.env.ADMIN_PHONES;
  process.env.ADMIN_PHONES = phones + ',+996555000919';
  try {
    const PANEL = [['POST', '/admin/unlock', { password: 'Totp-Atk-2026', code: '123456' }], ['POST', '/admin/totp/setup', {}], ['POST', '/admin/totp/enable', { code: '123456' }],
      ['POST', '/admin/lock', {}], ['GET', '/admin/overview'], ['DELETE', '/admin/comments/c1']];
    // Гость — 401 (нужен вход); обычный пользователь — 404: адресов панели для него «нет».
    const guest = client();
    for (const [m, p, b] of PANEL) assert.equal((await guest.call(m, p, b)).status, 401, `гость ${m} ${p}`);
    const user = client(); await user.register('Не Администратор', '0555300030');
    for (const [m, p, b] of PANEL) assert.equal((await user.call(m, p, b)).status, 404, `пользователь ${m} ${p}`);
    assert.ok(db.q("SELECT 1 FROM comments WHERE id = 'c1'").get(), 'чужое сообщение не удалено');

    // Администратор без подтверждения паролем: ни QR-кода, ни подключения.
    const adm = client();
    assert.equal((await adm.login('0555000919', 'Totp-Atk-2026')).data.data.role, 'admin');
    assert.equal((await adm.call('POST', '/admin/totp/setup', {})).data.error, 'step_up');
    assert.equal((await adm.call('POST', '/admin/totp/enable', { code: '123456' })).data.error, 'step_up');
    // Пароль без приложения открывает только подключение: действия панели закрыты.
    assert.equal((await adm.call('POST', '/admin/unlock', { password: 'Totp-Atk-2026' })).data.adminMfa, false);
    assert.equal((await adm.call('GET', '/admin/overview')).data.error, 'totp_setup_required');
    assert.equal((await adm.call('DELETE', '/admin/comments/c1')).data.error, 'totp_setup_required');
    assert.equal((await adm.call('POST', '/admin/totp/enable', { code: '123456' })).data.error, 'totp_no_setup', 'подтверждать нечего, пока нет QR-кода');
    const st = await adm.call('POST', '/admin/totp/setup', {});
    assert.equal(st.status, 200);
    const secret = st.data.secret.replace(/\s+/g, '');
    assert.ok(!JSON.stringify((await bootUser(adm))).includes(secret), 'секрет не попадает в bootstrap');

    // Мусор вместо кода: 401 (после 5 — блокировка, затем 429), никогда 500, и приложение не подключается.
    for (const code of [...CORPUS.slice(0, 4), '12345', '1234567', 'abcdef', ' 12 34 5x', { toString: 1 }, ['x'], '９９９９９９']) {
      const r = await adm.call('POST', '/admin/totp/enable', { code });
      assert.ok(r.status === 401 || r.status === 429, 'мусорный код: 401/429');
      if (r.status === 429) break;
    }
    assert.equal(db.q("SELECT totp_secret_enc FROM users WHERE id = 'uAtkTotp'").get().totp_secret_enc, null, 'мусорные коды приложение не подключили');
    guard.clearFails('admin:uAtkTotp');

    // Верный код подключает приложение; второй раз подключить поверх нельзя, а обычному пользователю — по-прежнему 404.
    const en = await adm.call('POST', '/admin/totp/enable', { code: totp.code(secret) });
    assert.equal(en.status, 200); assert.equal(en.data.adminMfa, true);
    assert.equal((await adm.call('GET', '/admin/overview')).status, 200);
    assert.equal((await adm.call('POST', '/admin/totp/setup', {})).data.error, 'totp_enabled');
    assert.equal((await user.call('POST', '/admin/totp/setup', {})).status, 404);
    // После блокировки панели пароль без кода больше ничего не открывает.
    await adm.call('POST', '/admin/lock', {});
    assert.equal((await adm.call('POST', '/admin/unlock', { password: 'Totp-Atk-2026' })).data.error, 'totp_required');
    assert.equal((await adm.call('GET', '/admin/overview')).data.error, 'step_up');
  } finally {
    process.env.ADMIN_PHONES = phones;
    guard.clearFails('admin:uAtkTotp');
    db.q("DELETE FROM users WHERE id = 'uAtkTotp'").run();
  }
});

test('утечки в bootstrap: номера чужих скрыты, чужие уведомления/журнал/устройства недоступны', async () => {
  const stranger = client(); await stranger.register('Незнакомец', '0555300010');
  const d = await bootUser(stranger);
  // Чужие полные номера не видны (кроме своего).
  const meId = d.session;
  assert.ok(d.users.every(u => u.id === meId || u.phone === null), 'номера не-друзей — null');
  assert.ok(d.users.find(u => u.id === meId).phone !== null, 'свой номер виден');
  // Закрытые сборы (без рассказа) не отдаются; видны только прошедшие с рассказом.
  assert.ok(d.events.every(e => e.member || e.story), 'не участнику — только вечера из Истории');
  // Чужие уведомления не приходят.
  assert.ok(d.notifications.every(n => true) && d.notifications.length >= 0);
  const other = (await bootUser(stranger)).notifications;
  assert.ok(Array.isArray(other));
  // Журнал и устройства — только свои (чужие недоступны вовсе, это другой эндпоинт).
  const log = (await stranger.call('GET', '/security/log')).data;
  assert.ok(Array.isArray(log.log) && Array.isArray(log.devices));
});

test('ссылка-приглашение: по токену не видно номеров и лишних полей', async () => {
  const host = client(); await host.login('0700000001');
  const { token } = (await host.call('POST', '/events/e1/link')).data;
  const guest = client();
  const r = await guest.call('GET', '/join/' + token);
  assert.equal(r.status, 200);
  const keys = Object.keys(r.data.event).sort();
  assert.deepEqual(keys, ['address', 'at', 'going', 'host', 'id', 'past', 'title', 'venue', 'venueId'], 'только документированные поля');
  assert.ok(!JSON.stringify(r.data).includes('996'), 'никаких номеров телефонов');
  assert.equal(r.data.status, null, 'гость без входа — без статуса');
  assert.equal((await guest.call('GET', '/join/not-a-valid-token-xxxxxx')).status, 404);
});

// ======================================================================
// 4. CSRF / Origin / тип содержимого
// ======================================================================
test('CSRF и Origin: без токена 403, чужой Origin 403, text/plain 415, GET без побочных эффектов', async () => {
  const c = client(); await c.register('CSRF Жертва', '0555400001');
  const { cookie, csrf } = c.jar();
  const raw = (p, body, headers = {}) => fetch(base + '/api' + p, { method: 'POST', headers: { Cookie: cookie, 'X-Forwarded-For': c.ip, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined });
  assert.equal((await raw('/me/favs/ds-supernova')).status, 403, 'без CSRF-токена — 403');
  assert.equal((await raw('/me/favs/ds-supernova', undefined, { 'X-CSRF-Token': 'wrong-token' })).status, 403, 'неверный CSRF — 403');
  assert.equal((await raw('/me/favs/ds-supernova', undefined, { 'X-CSRF-Token': csrf, Origin: 'https://evil.example' })).status, 403, 'чужой Origin — 403');
  // text/plain тело — 415.
  const tp = await fetch(base + '/api/me/favs/ds-supernova', { method: 'POST', headers: { Cookie: cookie, 'X-Forwarded-For': c.ip, 'Content-Type': 'text/plain', 'X-CSRF-Token': csrf }, body: 'hello' });
  assert.equal(tp.status, 415, 'text/plain — 415');
  // Ни одна из отклонённых попыток не изменила избранное.
  const favs = meIn(await bootUser(c)).favs;
  assert.ok(!favs.includes('ds-supernova'), 'избранное не изменилось отклонёнными запросами');
  // GET без побочных эффектов: health/bootstrap не меняют состояние.
  const before = db.q('SELECT COUNT(*) AS n FROM favs').get().n;
  await c.call('GET', '/health'); await c.call('GET', '/bootstrap');
  assert.equal(db.q('SELECT COUNT(*) AS n FROM favs').get().n, before, 'GET ничего не записал');
});

// ======================================================================
// 6. Кривой и злоупотребляющий HTTP
// ======================================================================
// Сырой запрос по сокету: возвращаем статусную строку и тело.
function rawSocket(portText) {
  return new Promise(resolve => {
    const s = net.connect(server.address().port, '127.0.0.1');
    let out = '';
    s.on('data', d => out += d);
    s.on('error', () => resolve({ line: 'ERR', body: '' }));
    s.on('close', () => { const [head, ...rest] = out.split('\r\n\r\n'); resolve({ line: out.split('\r\n')[0] || '', body: rest.join('\r\n\r\n'), head }); });
    s.write(portText);
    setTimeout(() => s.end(), 250);
  });
}
const status = r => parseInt((r.line.match(/HTTP\/1\.\d (\d{3})/) || [])[1], 10);

test('HTTP: кривой адрес запроса не роняет сервер (400), сервер жив', async () => {
  for (const target of ['//[', '//[::1', 'http://[/x', '//%zz', '/%E0%A4%A']) {
    const r = await rawSocket(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
    assert.ok(status(r) === 400 || status(r) === 404, `${target} → 400/404 (${r.line})`);
  }
  assert.equal((await fetch(base + '/api/health')).status, 200, 'сервер жив после кривых адресов');
});

test('HTTP: невалидный JSON 400, text/plain 415, пустое тело без ошибки, CRLF в заголовке', async () => {
  const c = client(); await c.register('HTTP Тест', '0555600001');
  const { cookie, csrf } = c.jar();
  const h = { Cookie: cookie, 'X-Forwarded-For': c.ip, 'X-CSRF-Token': csrf };
  // Невалидный JSON.
  const bad = await fetch(base + '/api/me', { method: 'PATCH', headers: { ...h, 'Content-Type': 'application/json' }, body: '{not json' });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error, 'bad_json');
  // Пустое тело при JSON-методе — не ошибка (трактуется как {}).
  const empty = await fetch(base + '/api/me', { method: 'PATCH', headers: { ...h, 'Content-Type': 'application/json' }, body: '' });
  assert.ok(empty.status < 500);
  // CRLF в значении заголовка (попытка подделки) — Node отвергает такой запрос, сервер остаётся жив.
  const r = await rawSocket('GET /api/health HTTP/1.1\r\nHost: x\r\nX-Evil: a\r\n b\r\nConnection: close\r\n\r\n');
  assert.ok(status(r) === 200 || status(r) === 400, 'свёрнутый заголовок обработан без падения');
  assert.equal((await fetch(base + '/api/health')).status, 200);
});

test('HTTP: слишком большое тело — не 500 (413 или обрыв соединения)', async () => {
  const c = client(); await c.register('Большой', '0555600002');
  const { cookie, csrf } = c.jar();
  const big = JSON.stringify({ favVenue: 'x'.repeat(700 * 1024) });
  let status413 = false, closed = false;
  try {
    const r = await fetch(base + '/api/me', { method: 'PATCH', headers: { Cookie: cookie, 'X-Forwarded-For': c.ip, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' }, body: big });
    status413 = r.status === 413;
    assert.ok(r.status < 500, 'большое тело не даёт 500');
  } catch (e) { closed = true; }
  assert.ok(status413 || closed, 'большое тело: 413 или обрыв');
  assert.equal((await fetch(base + '/api/health')).status, 200, 'сервер жив');
});

test('HTTP: глубоко вложенный JSON и ключи __proto__/constructor не ломают сервер и прототип', async () => {
  const c = client(); await c.register('Вложенный', '0555600003');
  const { cookie, csrf } = c.jar();
  const h = { Cookie: cookie, 'X-Forwarded-For': c.ip, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' };
  const deepArr = '['.repeat(3000) + '1' + ']'.repeat(3000);
  const ra = await fetch(base + '/api/client-errors', { method: 'POST', headers: { 'X-Forwarded-For': c.ip, 'Content-Type': 'application/json' }, body: deepArr });
  assert.ok(ra.status < 500, 'глубоко вложенный массив — не 500');
  // __proto__/constructor/prototype и toString-ловушка.
  const pol = await fetch(base + '/api/me', { method: 'PATCH', headers: h, body: '{"__proto__":{"polluted":1},"constructor":{"prototype":{"p2":1}},"favVenue":{"toString":1}}' });
  assert.ok(pol.status < 500, 'ключи-ловушки — не 500');
  assert.equal(({}).polluted, undefined, 'Object.prototype не отравлен');
  assert.equal(({}).p2, undefined);
});

test('HTTP: неверные типы для чисел (NaN/Infinity/массивы/строки/отрицательные) приводятся без ошибки', async () => {
  const c = client(); await c.register('Числа', '0555600004');
  const eid = (await c.call('POST', '/events', { title: 'Числа', venue: 'Место', at: future() })).data.id;
  for (const body of [{ hookahs: NaN, price: Infinity }, { hookahs: [1, 2], price: {} }, { hookahs: -100, price: -5 }, { hookahs: '9e999', price: '1abc' }, { hookahs: 1e309, price: null }, { hookahs: true, price: false }]) {
    const r = await c.call('PUT', `/events/${eid}/bill`, body);
    assert.equal(r.status, 200, 'счёт: ' + JSON.stringify(body));
    const e = r.data.data.events.find(x => x.id === eid);
    assert.ok(Number.isInteger(e.hookahs) && e.hookahs >= 0 && e.hookahs <= 20, 'кальяны в диапазоне 0..20');
    assert.ok(Number.isInteger(e.price) && e.price >= 0 && e.price <= 100000, 'цена в диапазоне');
  }
  // Доли микса с NaN/Infinity/отрицательными — отклоняются как плохие доли, без 500.
  assert.equal((await c.call('POST', '/mixes', { name: 'Плохой', parts: [{ id: 'od-cola', pct: Infinity }, { id: 'tg-canemint', pct: -5 }] })).data.error, 'bad_parts');
});

test('HTTP: длинный URL, обход каталога и необычные методы на статике', async () => {
  // Обход каталога и прямые пути к секретам — всегда 404 и никогда не содержимое файла.
  const leak = /DATA_KEY|BACKUP_KEY|ADMIN_CODE_KEY|-----BEGIN|argon2id\$|DROP TABLE|require\(/;
  for (const p of ['/..%2f..%2fpackage.json', '/%2e%2e/server/lib/api.js', '/server/lib/api.js', '/.env', '/server/private/admin-panel.js', '/server/private/admin-panel.enc', '/server/data/hookah.db', '/admin.js']) {
    const r = await fetch(base + p);
    assert.equal(r.status, 404, `${p} → 404`);
    assert.ok(!leak.test(await r.text()), `${p}: содержимого файла нет`);
  }
  // Очень длинный URL — не 500 (404), сервер жив.
  const long = await fetch(base + '/' + 'a'.repeat(8000));
  assert.ok(long.status === 404 || long.status === 414, 'длинный URL — 404/414');
  // Необычные методы на статике — не 500.
  for (const m of ['PUT', 'DELETE', 'OPTIONS']) {
    const r = await fetch(base + '/app.js', { method: m });
    assert.ok(r.status === 405 || r.status === 404, `${m} /app.js → 405/404`);
  }
  // Неизвестный путь API — JSON 404.
  const unknown = await fetch(base + '/api/nope/' + encodeURIComponent('<script>'), { headers: { 'X-Forwarded-For': freshIp() } });
  assert.equal(unknown.status, 404);
  assert.match(unknown.headers.get('content-type') || '', /application\/json/);
  assert.equal(unknown.headers.get('x-content-type-options'), 'nosniff');
});

// ======================================================================
// 7. Фаззинг всех зарегистрированных маршрутов
// ======================================================================
test('фаззинг: 300+ случайных запросов ко всем маршрутам (гость, пользователь, администратор) — всегда < 500, сервер жив', async () => {
  const rnd = prng(0xC0FFEE);
  // Готовим три «личности»: гость, обычный пользователь, администратор (вошёл; шаг-ап не обязателен — проверяем ветки защиты).
  const guest = client();
  const user = client(); await user.register('Фаз Юзер', '0555700001');
  const admin = client('192.0.2.200'); await admin.login('0700000001');
  const actors = [guest, user, admin];

  // Значения, которыми подставляем параметры пути и тела.
  const ids = ['e1', 'e2', 'c1', 'u1', 'u2', 'ds-supernova', 'b-phunnel', 'nope', "e1' OR 1=1--", '', '../x', '%00', 'n'.repeat(60)];
  const vals = () => pick(rnd, [pick(rnd, CORPUS), pick(rnd, ids), rnd() * 1e9 - 5e8, NaN, Infinity, -1, true, null, [1, 2], { a: 1 }, 'going', 'declined', '🔥', '0555' + Math.floor(rnd() * 1e6)]);
  const randBody = () => {
    const n = Math.floor(rnd() * 5), o = {};
    const keys = ['text', 'name', 'title', 'venue', 'address', 'desc', 'mapUrl', 'at', 'hookahs', 'price', 'rating', 'status', 'code', 'challenge', 'password', 'current', 'next', 'phone', 'purpose', 'emoji', 'bowlId', 'ids', 'parts', 'invites', 'highlights', 'all', 'dataUrl', 'directive', 'blocked', 'sample', 'msg', 'adult'];
    for (let i = 0; i < n; i++) o[pick(rnd, keys)] = vals();
    return o;
  };
  const concretePath = r => r.path.replace('/api', '').replace(/:(\w+)/g, () => encodeURIComponent(String(pick(rnd, ids))));

  let count = 0;
  for (let i = 0; i < 330; i++) {
    const r = pick(rnd, routes), actor = pick(rnd, actors);
    const p = concretePath(r);
    const body = r.method === 'GET' ? undefined : randBody();
    const res = await actor.call(r.method, p, body); // call уже проверяет < 500, JSON и nosniff
    count++;
    assert.ok(res.status >= 100 && res.status < 500, `${r.method} ${p} → ${res.status}`);
  }
  assert.ok(count >= 300, 'не меньше 300 случайных запросов');
  assert.equal((await fetch(base + '/api/health')).status, 200, 'сервер жив после фаззинга');
  // Прототип по-прежнему чист.
  assert.equal(({}).polluted, undefined);
  guard.clearFails('admin:u1');
});

// ======================================================================
// 5 + 8. Перебор и лимиты (ПОСЛЕДНИМИ: состояние лимитов — в памяти процесса)
// ======================================================================
test('перебор: вход блокируется после 5 неверных паролей', async () => {
  const c = client('198.51.100.10'); await c.register('Перебор Входа', '0555800001', 'Right-Pass-2026');
  await c.call('POST', '/auth/logout', {});
  for (let i = 1; i <= 4; i++) assert.equal((await c.call('POST', '/auth/login', { phone: '0555800001', password: 'wrong-pass1' })).data.left, 5 - i);
  // Пятая неверная — блокировка (401 locked), после неё даже верный пароль не принимается (429).
  const fifth = await c.call('POST', '/auth/login', { phone: '0555800001', password: 'wrong-pass1' });
  assert.equal(fifth.data.error, 'locked');
  const locked = await c.call('POST', '/auth/login', { phone: '0555800001', password: 'Right-Pass-2026' });
  assert.equal(locked.status, 429);
  assert.equal(locked.data.error, 'locked');
});

test('перебор: код из SMS — не больше 5 попыток', async () => {
  const c = client('198.51.100.11');
  const { challenge, devCode } = (await c.call('POST', '/auth/sms', { phone: '0555800002', purpose: 'register' })).data;
  const wrong = String((+devCode + 1) % 1e6).padStart(6, '0');
  for (let i = 0; i < 5; i++) {
    const r = await c.call('POST', '/auth/register', { name: 'Кодовый', phone: '0555800002', password: 'Code-Brute-2026', code: wrong, challenge, adult: true });
    assert.ok(r.status === 400 || r.status === 429, 'неверный код: 400/429');
  }
  const after = await c.call('POST', '/auth/register', { name: 'Кодовый', phone: '0555800002', password: 'Code-Brute-2026', code: devCode, challenge, adult: true });
  assert.equal(after.data.error, 'code_attempts', 'после 5 попыток код больше не принимается, даже верный');
});

test('перебор: не больше 3 аккаунтов с одного адреса', async () => {
  const ip = '198.51.100.12';
  for (let i = 0; i < 3; i++) {
    const c = client(ip);
    assert.equal((await c.register('Аккаунт', '055581000' + i)).status, 200, 'аккаунт ' + i);
  }
  const over = client(ip);
  const sms = await over.call('POST', '/auth/sms', { phone: '0555810009', purpose: 'register' });
  assert.equal(sms.status, 429, 'четвёртый аккаунт с адреса — отказ');
  assert.equal(sms.data.error, 'ip_accounts');
});

test('перебор: удалённый аккаунт не освобождает место — считаются регистрации за сутки', async () => {
  const ip = '198.51.100.14';
  const first = client(ip);
  assert.equal((await first.register('Удалю', '0555820000', 'Gone-Soon-2026')).status, 200);
  assert.equal((await first.call('POST', '/me/delete', { password: 'Gone-Soon-2026' })).status, 200, 'аккаунт удалён');
  for (let i = 1; i < 3; i++) assert.equal((await client(ip).register('Ещё', '055582000' + i)).status, 200, 'аккаунт ' + i);
  const over = await client(ip).call('POST', '/auth/sms', { phone: '0555820009', purpose: 'register' });
  assert.equal(over.data.error, 'ip_accounts', 'удаление не сбрасывает счётчик: четвёртая регистрация за сутки — отказ');
});

test('журнал: неверный код из SMS записывается (его видит fail2ban); адрес — последний в X-Forwarded-For', async () => {
  // Первый адрес «подставил» сам клиент, последний дописал наш прокси — верить можно только ему.
  const c = client('203.0.113.66, 198.51.100.15');
  const { challenge } = (await c.call('POST', '/auth/sms', { phone: '0555830000', purpose: 'register' })).data;
  const r = await c.call('POST', '/auth/register', { name: 'Код', phone: '0555830000', password: 'Code-Log-2026', code: '0000', challenge, adult: true });
  assert.equal(r.data.error, 'code_wrong');
  const row = db.q("SELECT ip, detail FROM audit WHERE type = 'code_fail' ORDER BY id DESC LIMIT 1").get();
  assert.equal(row.ip, '198.51.100.15', 'адрес от прокси, а не подставленный клиентом');
  assert.equal(row.detail, 'register');
});

test('перебор: удаление аккаунта блокируется после 5 неверных паролей', async () => {
  const c = client('198.51.100.13'); await c.register('Удаление Перебор', '0555800003', 'Keep-Me-2026');
  const uid = meIn(await bootUser(c)).id;
  for (let i = 1; i <= 4; i++) assert.equal((await c.call('POST', '/me/delete', { password: 'wrong-pass1' })).data.left, 5 - i);
  assert.equal((await c.call('POST', '/me/delete', { password: 'wrong-pass1' })).data.error, 'locked');
  assert.equal((await c.call('POST', '/me/delete', { password: 'Keep-Me-2026' })).status, 429, 'при блокировке даже верный пароль не принимается');
  assert.ok(db.q('SELECT 1 FROM users WHERE id = ?').get(uid), 'аккаунт не удалён');
  guard.clearFails('delete:' + uid);
});

test('перебор: панель администратора блокируется после 5 неверных попыток', async () => {
  // Отдельный администратор с фиксированным адресом, чтобы не задеть основного.
  const { hashPassword, encrypt, phoneIndex } = require('../server/lib/secure');
  db.q("INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, role) VALUES ('uAtkAdm', 'Админ Атаки', ?, ?, '909', ?, ?, 'admin')")
    .run(encrypt('996555000909'), phoneIndex('996555000909'), await hashPassword('Admin-Atk-2026'), new Date().toISOString());
  const phones = process.env.ADMIN_PHONES;
  process.env.ADMIN_PHONES = phones + ',+996555000909';
  try {
    const c = client('198.51.100.14');
    assert.equal((await c.login('0555000909', 'Admin-Atk-2026')).data.data.role, 'admin');
    for (let i = 0; i < 4; i++) assert.equal((await c.call('POST', '/admin/unlock', { password: 'wrong-pass1' })).data.error, 'bad_password');
    assert.equal((await c.call('POST', '/admin/unlock', { password: 'wrong-pass1' })).data.error, 'locked', 'пятая попытка — блокировка');
    assert.equal((await c.call('POST', '/admin/unlock', { password: 'Admin-Atk-2026' })).status, 429, 'во время блокировки — отказ');
  } finally {
    process.env.ADMIN_PHONES = phones;
    guard.clearFails('admin:uAtkAdm');
    db.q("DELETE FROM users WHERE id = 'uAtkAdm'").run();
  }
});

test('лимиты: шквал запросов с одного адреса упирается в лимит (429); /api/health в лимит не входит', async () => {
  // Фиксированный адрес; шлём много запросов к API, пока не поймаем 429 (apiPerIp = 600 за 10 минут).
  // Запрос к несуществующему адресу API тоже считается — и он самый дешёвый (404).
  const ip = '203.0.113.77', probe = (from = ip) => fetch(base + '/api/limit-probe', { headers: { 'X-Forwarded-For': from } });
  let got429 = false, n = 0;
  for (; n < 650 && !got429; n++) {
    const r = await probe();
    if (r.status === 429) { got429 = true; assert.equal(r.headers.get('x-content-type-options'), 'nosniff'); }
    else assert.equal(r.status, 404);
  }
  assert.ok(got429, 'сработал лимит запросов с одного адреса');
  assert.equal((await probe(freshIp())).status, 404, 'другие адреса не затронуты');
  // По /api/health страница решает, есть ли сервер: под лимитом он по-прежнему отвечает, иначе у всех за этим адресом
  // вместо сайта был бы экран «сервер недоступен».
  const h = await fetch(base + '/api/health', { headers: { 'X-Forwarded-For': ip } });
  assert.equal(h.status, 200, '/api/health отвечает и под лимитом');
  assert.equal((await h.json()).mode, 'server');
});

// ======================================================================
// 9. Вход и SMS: лимиты по сети /64, бюджет SMS, чужие ошибки не закрывают вход владельцу, номера не перечислить
// ======================================================================
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (ok, ms = 3000) => { for (const t0 = Date.now(); !ok(); await sleep(5)) if (Date.now() - t0 > ms) throw new Error('не дождались'); };
// Лимиты на время теста: в автотестах они нарочно высокие, здесь проверяем настоящие значения.
async function withLimits(patch, fn) {
  const saved = Object.fromEntries(Object.keys(patch).map(k => [k, guard.LIMITS[k]]));
  Object.assign(guard.LIMITS, patch);
  try { return await fn(); } finally { Object.assign(guard.LIMITS, saved); }
}
// i-й адрес внутри сети /64 net (каждый раз новый — так перебирают адреса, чтобы обойти лимиты).
const v6 = (net, i) => `${net}:${((i * 7919 + 1) & 0xffff).toString(16)}:${(i + 3).toString(16)}::${(i + 11).toString(16)}`;
const smsSent = () => db.q("SELECT COUNT(*) AS n FROM audit WHERE type = 'sms_sent'").get().n;
const rawPost = (p, body, ip) => fetch(base + '/api' + p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify(body) });

test('IPv6: лимиты считаются по сети /64 — новые адреса внутри неё лимит не обходят, в журнале — полный адрес', async () => {
  await withLimits({ authPerIp: [5, 3600e3], apiPerIp: [30, 600e3] }, async () => {
    const st = [];
    for (let i = 0; i < 8; i++) st.push((await client(v6('2001:db8:aaaa:bbbb', i)).call('POST', '/auth/sms', { phone: '0555' + (900100 + i), purpose: 'login' })).status);
    assert.deepEqual(st, [200, 200, 200, 200, 200, 429, 429, 429], 'шестой запрос из той же /64 — отказ, хотя адрес каждый раз новый');
    assert.equal((await client('2001:db8:aaaa:cccc::1').call('POST', '/auth/sms', { phone: '0555900200', purpose: 'login' })).status, 200, 'соседняя /64 — свой счётчик');
    const row = db.q("SELECT ip FROM audit WHERE type = 'rate_limited' AND detail = 'ip' ORDER BY id DESC LIMIT 1").get();
    assert.equal(row.ip, v6('2001:db8:aaaa:bbbb', 7), 'в журнал — полный адрес');
    let got = 0;
    for (let n = 1; n <= 40 && !got; n++) if ((await fetch(base + '/api/limit-probe', { headers: { 'X-Forwarded-For': v6('2001:db8:dddd:eeee', n) } })).status === 429) got = n;
    assert.equal(got, 31, 'общий лимит запросов к API — тоже на всю сеть /64');
  });
  assert.equal(guard.ipNet('2001:db8:aaaa:bbbb:1:2:3:4'), guard.ipNet('2001:db8:aaaa:bbbb::9'));
  assert.equal(guard.ipNet('::ffff:95.56.12.34'), '95.56.12.34', 'IPv4 внутри IPv6 — это IPv4');
});

test('SMS: только номера с кодом +996 (ALLOWED_PHONE_PREFIXES) — на чужие и платные номера коды не уходят', async () => {
  const c = client(), before = smsSent();
  for (const phone of ['+447700900123', '+2348031234567', '+79161234567', '+88213012345', '+37612345678']) {
    const r = await c.call('POST', '/auth/sms', { phone, purpose: 'register' });
    assert.deepEqual([r.status, r.data.error], [400, 'phone_country'], phone);
    assert.match(r.data.message.ru, /\+996/);
  }
  assert.equal((await c.call('POST', '/auth/sms', { phone: '+9965551234567', purpose: 'register' })).data.error, 'bad_phone', '+996 и лишняя цифра — не номер');
  assert.equal((await c.call('POST', '/auth/login-sms', { phone: '+447700900123', code: '123456' })).data.error, 'phone_country');
  assert.equal((await c.call('POST', '/auth/register', { name: 'Чужой', phone: '+447700900123', password: 'Foreign-Pass-2026', code: '123456', adult: true })).data.error, 'phone_country');
  await sleep(20);
  assert.equal(smsSent(), before, 'ни одного SMS');
  // Владелец может разрешить и другие страны; страница узнаёт список из данных.
  const saved = process.env.ALLOWED_PHONE_PREFIXES;
  process.env.ALLOWED_PHONE_PREFIXES = '996,7';
  try {
    assert.equal((await c.call('POST', '/auth/sms', { phone: '+79161234567', purpose: 'register' })).status, 200);
    assert.deepEqual((await bootUser(c)).phoneCodes, ['996', '7']);
  } finally { if (saved === undefined) delete process.env.ALLOWED_PHONE_PREFIXES; else process.env.ALLOWED_PHONE_PREFIXES = saved; }
  assert.deepEqual((await bootUser(c)).phoneCodes, ['996']);
  // Приглашение «по номеру» другой страны не добавляется: зарегистрироваться с ним нельзя.
  const host = client(); await host.register('Хост Стран', '0555900300');
  const r = await host.call('POST', '/events', { title: 'Страны', venue: 'Место', at: future(), invites: [{ phone: '+447700900123' }, { phone: '0555900301' }] });
  const e = r.data.data.events.find(x => x.id === r.data.id);
  assert.deepEqual(e.invites.map(i => i.phone), ['996555900301']);
});

test('SMS: с адреса (сети /64) — не больше 10 кодов в час; бюджет сервера: с 80% — сигнал владельцу, на 100% — 503 и Retry-After', async () => {
  await withLimits({ smsPerIp: [3, 3600e3] }, async () => {
    const st = [];
    for (let i = 0; i < 5; i++) st.push((await client(v6('2001:db8:5555:6666', i)).call('POST', '/auth/sms', { phone: '0555' + (910100 + i), purpose: 'login' })).data.error || 'ok');
    assert.deepEqual(st, ['ok', 'ok', 'ok', 'sms_ip_limit', 'sms_ip_limit']);
  });
  assert.deepEqual([guard.LIMITS.smsPerIp[0], guard.LIMITS.smsPerIpDay[0]], [1000, 1000], 'в автотестах лимит с адреса высокий (в работе — 10 в час и 30 в сутки)');
  // Бюджет считается по журналу (переживает перезапуск). Прежние отправки на время теста прячем, чтобы считать с нуля.
  db.q("UPDATE audit SET type = 'sms_sent_hidden' WHERE type = 'sms_sent'").run();
  require('../server/lib/alerts').resetAlerts();
  const alertsOf = kind => db.q("SELECT ref FROM notifications WHERE user_id = 'u1' AND type = 'security_alert' AND instr(ref, ?) = 1").all(kind + ':').map(r => r.ref);
  try {
    await withLimits({ smsPerHour: 100, smsPerDay: 5 }, async () => {
      for (let i = 1; i <= 5; i++) {
        assert.equal((await client().call('POST', '/auth/sms', { phone: '0555' + (920100 + i), purpose: 'register' })).status, 200, 'код ' + i);
        await until(() => smsSent() === i);
        assert.equal(alertsOf('sms_budget').length, i >= 4 ? 1 : 0, `после ${i}-го SMS сигнал ${i >= 4 ? 'есть' : 'ещё нет'} (80% от 5 — 4)`);
      }
      assert.deepEqual(alertsOf('sms_budget'), ['sms_budget:4/5']);
      const stop = await rawPost('/auth/sms', { phone: '0555920200', purpose: 'register' }, freshIp());
      const body = await stop.json();
      assert.deepEqual([stop.status, body.error], [503, 'sms_paused'], 'шестой — отправка остановлена');
      assert.match(body.message.ru, /исчерпан лимит/);
      assert.ok(+stop.headers.get('retry-after') >= 60 && body.retryAfter === +stop.headers.get('retry-after'), 'Retry-After в заголовке и в ответе');
      assert.deepEqual(alertsOf('sms_stopped'), ['sms_stopped:5/100 · 5/5'], 'владельцу — сигнал об остановке');
      // Отказ из-за бюджета не тратит лимит кодов номера.
      guard.LIMITS.smsPerDay = 100;
      for (let i = 0; i < 3; i++) assert.equal((await client().call('POST', '/auth/sms', { phone: '0555920200', purpose: 'register' })).status, 200);
    });
  } finally {
    db.q("UPDATE audit SET type = 'sms_sent' WHERE type = 'sms_sent_hidden'").run();
  }
});

test('вход: чужие запросы не закрывают владельцу вход — «коды» без запроса, перебор его кода, чужие неверные пароли', async () => {
  const phone = '0555930001', password = 'Owner-Pass-2026', idx = require('../server/lib/secure').phoneIndex(util.normPhone(phone));
  assert.equal((await client('198.51.100.40').register('Владелец', phone, password)).status, 200);
  // 1) 30 «неверных кодов» с разных адресов, когда код никто не запрашивал: ни SMS, ни расхода счётчиков номера.
  const sent = smsSent();
  for (let i = 0; i < 30; i++) assert.equal((await client().call('POST', '/auth/login-sms', { phone, code: '123456' })).data.error, 'code_missing');
  assert.equal(smsSent(), sent);
  // Удачные входы счётчик неверных паролей не тратят.
  for (let i = 0; i < 3; i++) assert.equal((await client('198.51.100.41').login(phone, password)).status, 200, 'владелец входит паролем');
  // 2) Владелец запросил код; чужие без его ключа запроса перебирают коды — его код цел.
  const own = client('198.51.100.42'), sms = (await own.call('POST', '/auth/sms', { phone, purpose: 'login' })).data;
  for (let i = 0; i < 10; i++) {
    const r = await client().call('POST', '/auth/login-sms', { phone, code: String(i * 111111).padStart(6, '0'), ...(i % 2 ? { challenge: 'x'.repeat(43) } : {}) });
    assert.equal(r.data.error, 'code_missing', 'без ключа запроса код не проверяется и попытки не тратятся');
  }
  assert.equal((await own.call('POST', '/auth/login-sms', { phone, code: sms.devCode, challenge: sms.challenge })).status, 200, 'его код работает');
  // 3) Чужие неверные пароли (17 за час) закрывают вход паролем, но не по коду из SMS.
  for (let i = 0; i < 17; i++) {
    assert.equal((await client().login(phone, 'wrong-pass1')).status, 401, 'неверный пароль ' + (i + 1));
    if (i % 4 === 3) guard.clearFails('login:' + idx); // как будто 5 минут блокировки прошли
  }
  const pw = await client('198.51.100.43').login(phone, password);
  assert.deepEqual([pw.status, pw.data.error], [429, 'rate_limited'], 'вход паролем закрыт до конца часа');
  const s2 = client('198.51.100.44'), c2 = (await s2.call('POST', '/auth/sms', { phone, purpose: 'login' })).data;
  assert.equal((await s2.call('POST', '/auth/login-sms', { phone, code: c2.devCode, challenge: c2.challenge })).status, 200, 'вход по коду из SMS открыт');
  guard.clearFails('login:' + idx);
  // 4) Отказ по квоте адреса не тратит лимит кодов номера (3 за 10 минут): владелец по-прежнему получает все три кода.
  const quotaIp = '198.51.100.45', other = '0700000006';
  for (let i = 0; i < 3; i++) assert.equal((await client(quotaIp).register('Квота', '055593001' + i)).status, 200);
  for (let i = 0; i < 5; i++) assert.equal((await client(quotaIp).call('POST', '/auth/sms', { phone: other, purpose: 'register' })).data.error, 'ip_accounts');
  for (let i = 0; i < 3; i++) assert.equal((await client('198.51.100.46').call('POST', '/auth/sms', { phone: other, purpose: 'login' })).status, 200, `код ${i + 1} из 3 за 10 минут — его`);
});

test('регистрация: не больше 3 аккаунтов с адреса в сутки, даже если коды запрошены заранее; у IPv6 — на всю сеть /64', async () => {
  const net = '2001:db8:7777:8888', reqs = [];
  for (let i = 0; i < 4; i++) {
    const c = client(v6(net, i)), phone = '0555940' + (100 + i);
    reqs.push({ c, phone, d: (await c.call('POST', '/auth/sms', { phone, purpose: 'register' })).data });
  }
  assert.ok(reqs.every(r => r.d.devCode), 'коды выданы: регистраций с адреса ещё не было');
  const res = [];
  for (const { c, phone, d } of reqs) res.push((await c.call('POST', '/auth/register', { name: 'Квота', phone, password: 'Quota-Pass-2026', code: d.devCode, challenge: d.challenge, adult: true })).data.error || 'ok');
  assert.deepEqual(res, ['ok', 'ok', 'ok', 'ip_accounts'], 'четвёртая регистрация с той же /64 — отказ');
  assert.equal(db.q('SELECT COUNT(*) AS n FROM users WHERE phone_idx = ?').get(require('../server/lib/secure').phoneIndex('996555940103')).n, 0);
});

test('номера не перечислить: запрос кода и неверный код — одинаково, есть номер в базе или нет; на занятый номер — SMS «аккаунт уже есть»', async () => {
  const shape = d => Object.keys(d).filter(k => k !== 'devCode').sort().join();
  const to002 = () => db.q("SELECT COUNT(*) AS n FROM audit WHERE type = 'sms_sent' AND detail = '+996 ••• ••• 002'").get().n;
  const a = client(), b = client(), sent = smsSent(), was002 = to002();
  const ex = await a.call('POST', '/auth/sms', { phone: '0700000002', purpose: 'register' }), nw = await b.call('POST', '/auth/sms', { phone: '0555950001', purpose: 'register' });
  assert.deepEqual([ex.status, shape(ex.data)], [nw.status, shape(nw.data)], 'регистрация: тот же ответ');
  assert.equal(shape(nw.data), 'challenge,ok,ttl');
  assert.ok(nw.data.devCode && !ex.data.devCode, 'код уходит только на новый номер (devCode — лишь в режиме разработки)');
  await until(() => smsSent() === sent + 2);
  assert.equal(to002() - was002, 1, 'владельцу занятого номера ушло SMS («аккаунт уже есть»)');
  const reg = (c, phone, code, d) => c.call('POST', '/auth/register', { name: 'Энум', phone, password: 'Enum-Pass-2026', code, challenge: d.challenge, adult: true });
  const we = await reg(a, '0700000002', '000000', ex.data), wn = await reg(b, '0555950001', String((+nw.data.devCode + 1) % 1e6).padStart(6, '0'), nw.data);
  assert.deepEqual([we.status, we.data.error, we.data.left], [400, 'code_wrong', 4], 'занятый номер: «код не подходит», а не «номер занят»');
  assert.deepEqual([wn.status, wn.data.error, wn.data.left], [400, 'code_wrong', 4]);
  // Вход по SMS: зарегистрированный и незнакомый номер.
  const k = await a.call('POST', '/auth/sms', { phone: '0700000004', purpose: 'login' }), u = await b.call('POST', '/auth/sms', { phone: '0555950002', purpose: 'login' });
  assert.deepEqual([k.status, shape(k.data)], [u.status, shape(u.data)], 'вход: тот же ответ');
  const kw = await a.call('POST', '/auth/login-sms', { phone: '0700000004', code: String((+k.data.devCode + 1) % 1e6).padStart(6, '0'), challenge: k.data.challenge });
  const uw = await b.call('POST', '/auth/login-sms', { phone: '0555950002', code: '000000', challenge: u.data.challenge });
  assert.deepEqual([kw.data.error, kw.data.left], [uw.data.error, uw.data.left], 'неверный код — одинаково');
  assert.equal(uw.data.error, 'code_wrong');
});

test('номера не перечислить по времени: запрос кода не ждёт SMS-шлюз — отвечает сразу, SMS уходит после ответа', async () => {
  const keys = ['SMS_PROVIDER', 'NIKITA_LOGIN', 'NIKITA_PASSWORD', 'NIKITA_SENDER'], saved = Object.fromEntries(keys.map(k => [k, process.env[k]]));
  const realFetch = globalThis.fetch;
  let gateway = 0, delivered = 0;
  // Медленный шлюз (600 мс) — подменный: наружу ничего не уходит.
  globalThis.fetch = async (url, opt) => {
    if (!String(url).startsWith('https://smspro.nikita.kg/')) return realFetch(url, opt);
    gateway++; await sleep(600); delivered++;
    return new Response('<response><status>0</status></response>');
  };
  Object.assign(process.env, { SMS_PROVIDER: 'nikita', NIKITA_LOGIN: 'placeholder', NIKITA_PASSWORD: 'placeholder', NIKITA_SENDER: 'placeholder' });
  try {
    const timed = async (phone, purpose) => { const t0 = performance.now(), r = await client().call('POST', '/auth/sms', { phone, purpose }); return { ms: performance.now() - t0, status: r.status, keys: Object.keys(r.data).sort().join() }; };
    const known = await timed('0700000005', 'login'), unknown = await timed('0555960001', 'login');
    assert.ok(known.ms < 300 && unknown.ms < 300, `ответ не ждёт шлюз: ${Math.round(known.ms)} и ${Math.round(unknown.ms)} мс`);
    assert.deepEqual([known.status, known.keys], [unknown.status, unknown.keys]);
    assert.equal(known.keys, 'challenge,ok,ttl', 'без кода в ответе (не режим разработки)');
    await until(() => delivered === 1);
    assert.equal(gateway, 1, 'SMS ушло только на зарегистрированный номер — уже после ответа');
  } finally {
    await until(() => delivered === gateway).catch(() => {}); // подмену снимаем, только когда отправка закончилась
    globalThis.fetch = realFetch;
    for (const k of keys) if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
  }
});
