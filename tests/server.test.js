/* Тесты сервера: вход, права, CSRF, лимиты, регистрация, заголовки безопасности.
   Сервер поднимается в памяти на случайном порту. Запуск: npm test */
process.env.NODE_ENV = 'test';
process.env.SMS_PROVIDER = 'dev';
// Администратор в тестовой базе — «Алекс»: его номер — единственный в списке владельцев.
// Панель для теста шифруется своим ключом во временный файл: настоящего ключа в репозитории нет.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
process.env.ADMIN_PHONES = '+996700000001';
process.env.ADMIN_CODE_KEY = require('node:crypto').randomBytes(32).toString('base64');
process.env.ADMIN_PANEL_ENC = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hp-')), 'panel.enc');
const panel = require('../server/lib/panel');
fs.writeFileSync(process.env.ADMIN_PANEL_ENC, panel.encrypt(Buffer.from('window.HP_ADMIN = { test: true };'), Buffer.from(process.env.ADMIN_CODE_KEY, 'base64')));
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { open } = require('../server/lib/db');
const { seed } = require('../server/lib/seed');
const { createServer } = require('../server/index');
const { purgeOld } = require('../server/lib/retention');
const totp = require('../server/lib/totp');
const qr = require('../server/lib/qr');
const { parseUA } = require('../server/lib/ua');
const alerts = require('../server/lib/alerts');

let server, base, db;
before(async () => {
  db = open(':memory:');
  await seed(db);
  server = createServer(db);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

// Заведомо неверный код из 6 цифр — соседний с настоящим.
const otherCode = c => String((+c + 1) % 1e6).padStart(6, '0');

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
  return { call, login: async (phone = '0700000001', password = 'hookah') => call('POST', '/auth/login', { phone, password }), jar: () => ({ cookie, csrf }) };
}

test('страница отдаётся с заголовками безопасности', async () => {
  const r = await fetch(base + '/');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

test('шрифты свои (fonts/), без Google: тип font/woff2, кеш на год; CSP в заголовке — та же, что в index.html, и без сторонних адресов', async () => {
  const root = path.join(__dirname, '..');
  const files = new Set([...fs.readFileSync(path.join(root, 'styles.css'), 'utf8').matchAll(/url\((fonts\/[a-z0-9-]+\.woff2)\)/g)].map(m => m[1]));
  assert.ok(files.size >= 9, 'шрифты подключены в styles.css: ' + files.size);
  for (const f of files) {
    const r = await fetch(base + '/' + f);
    assert.equal(r.status, 200, f);
    assert.equal(r.headers.get('content-type'), 'font/woff2', f);
    assert.match(r.headers.get('cache-control'), /max-age=31536000/, f);
    assert.equal(Buffer.from(await r.arrayBuffer()).subarray(0, 4).toString('latin1'), 'wOF2', f);
  }
  for (const p of ['/fonts/', '/fonts/OFL.txt', '/fonts/../.env', '/fonts/%2e%2e/package.json', '/fonts/nope.woff2', '/fonts/GOLOSTEXT-V7-LATIN.WOFF2', '/fonts//golostext-v7-latin.woff2'])
    assert.equal((await fetch(base + p)).status, 404, p);
  const csp = (await fetch(base + '/')).headers.get('content-security-policy');
  assert.match(csp, /font-src 'self'/);
  assert.match(csp, /trusted-types default hp-sanitize(;|$)/);
  assert.doesNotMatch(csp, /google|gstatic|https:/);
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  assert.doesNotMatch(html, /fonts\.googleapis|fonts\.gstatic|rel="preconnect"/, 'index.html не обращается к Google Fonts');
  // Политика в <meta> — та же (frame-ancestors бывает только в заголовке, upgrade-insecure-requests — только в meta).
  const meta = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  const dirs = s => s.split(';').map(x => x.trim()).filter(x => x && !/^(frame-ancestors|upgrade-insecure-requests)\b/.test(x)).sort();
  assert.deepEqual(dirs(meta), dirs(csp));
});

test('файлы сервера и базы снаружи недоступны', async () => {
  for (const p of ['/server/index.js', '/server/data/hookah.db', '/../package.json', '/.env']) assert.equal((await fetch(base + p)).status, 404, p);
});

test('гость не видит чужие номера и закрытые сборы', async () => {
  const { data } = await client().call('GET', '/bootstrap');
  assert.equal(data.session, null);
  assert.ok(data.users.every(u => !('phone' in u) && !('phoneMasked' in u)), 'ни номеров, ни их последних цифр');
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
  assert.match(sms.data.devCode, /^\d{6}$/, 'код из 6 цифр');
  const { challenge } = sms.data;
  const weak = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: '12345678', code: sms.data.devCode, challenge, adult: true });
  assert.equal(weak.status, 400);
  const wrong = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: 'Kalyan-Night-2026', code: otherCode(sms.data.devCode), challenge, adult: true });
  assert.equal(wrong.data.error, 'code_wrong');
  const ok = await c.call('POST', '/auth/register', { name: 'Айбек', phone: '0555123456', password: 'Kalyan-Night-2026', code: sms.data.devCode, challenge, adult: true });
  assert.equal(ok.status, 200);
  const e1 = ok.data.data.events.find(e => e.id === 'e1');
  assert.ok(e1 && e1.invites.some(i => i.userId === ok.data.data.session), 'приглашение «по номеру» перешло к новому пользователю');
  assert.ok(ok.data.data.notifications.some(n => n.type === 'invite' && n.eventId === 'e1'), 'и пришло уведомление');
  // Организатор не узнаёт, кто зарегистрировался с этим номером, пока тот не ответит: для него это всё ещё приглашение по номеру.
  const host = client(); await host.login();
  const he1 = (await host.call('GET', '/bootstrap')).data.events.find(e => e.id === 'e1');
  assert.ok(!he1.invites.some(i => i.userId === ok.data.data.session) && he1.invites.some(i => !i.userId && i.phone === '996555123456'), 'организатор видит приглашение по номеру');
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

// ---------- Вход в панель по коду из приложения (TOTP) ----------
test('TOTP: коды RFC 6238 (SHA1), base32 RFC 4648, ссылка otpauth без полного номера', () => {
  const rfc = Buffer.from('12345678901234567890');
  for (const [t, want] of [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']])
    assert.equal(totp.code(rfc, t * 1000), want, `T=${t}`);
  for (const [plain, b32] of [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']]) {
    assert.equal(totp.base32Encode(Buffer.from(plain)), b32);
    assert.equal(totp.base32Decode(b32.toLowerCase() + '=').toString(), plain, 'регистр и «=» в конце не важны');
  }
  for (let n = 0; n <= 40; n++) { const b = require('node:crypto').randomBytes(n); assert.deepEqual(totp.base32Decode(totp.base32Encode(b)), b); }
  assert.throws(() => totp.base32Decode('MZ1W'), 'цифры 0, 1, 8, 9 в base32 не бывает');
  const secret = totp.generateSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/, '20 случайных байт');
  assert.equal(totp.base32Decode(totp.groupKey(secret)).toString('hex'), totp.base32Decode(secret).toString('hex'), 'ключ группами по 4 читается так же');
  const now = Date.now(), step = Math.floor(now / 30000), opt = { timeMs: now };
  assert.equal(totp.verify(secret, totp.code(secret, now), opt), step);
  assert.equal(totp.verify(secret, totp.code(secret, now - 30000), opt), step - 1, 'шаг назад — запас на часы телефона');
  assert.equal(totp.verify(secret, totp.code(secret, now - 60000), opt), null, 'два шага назад — уже нет');
  assert.equal(totp.verify(secret, totp.code(secret, now), { ...opt, lastCounter: step }), null, 'тот же шаг второй раз не принимается');
  for (const bad of ['', '12345', '1234567', 'abcdef', null, undefined, {}]) assert.equal(totp.verify(secret, bad, opt), null);
  const uri = totp.otpauthUri({ secret, label: '+996 *** *** 001' });
  assert.equal(uri, `otpauth://totp/Hookah%20Party:%2B996%20***%20***%20001?secret=${secret}&issuer=Hookah%20Party&algorithm=SHA1&digits=6&period=30`);
  assert.throws(() => totp.otpauthUri({ secret, label: '+996700000001' }), 'полный номер в метку не попадает');
});

test('QR-код: версия по длине, поисковые узоры, линии синхронизации, формат уровня M', () => {
  const FINDER = ['1111111', '1000001', '1011101', '1011101', '1011101', '1000001', '1111111'];
  // Ёмкость уровня M в байтах: v1 — 14, v2 — 26, v7 — 122, v8 — 152, v10 — 213.
  for (const [len, ver] of [[1, 1], [14, 1], [15, 2], [26, 2], [122, 7], [123, 8], [152, 8], [153, 9], [213, 10], [214, 11]]) {
    const m = qr.encode('x'.repeat(len)), n = 17 + 4 * ver;
    assert.equal(m.length, n, `${len} байт → версия ${ver}`);
    assert.ok(m.every(r => r.length === n && /^[01]+$/.test(r)), 'квадрат из 0 и 1');
    for (const [x0, y0] of [[0, 0], [n - 7, 0], [0, n - 7]]) for (let y = 0; y < 7; y++) assert.equal(m[y0 + y].slice(x0, x0 + 7), FINDER[y], `поисковый узор ${x0},${y0}`);
    assert.equal(m[7].slice(0, 8) + m[7].slice(n - 8), '0'.repeat(16), 'светлый разделитель');
    for (let i = 8; i < n - 8; i++) assert.equal(m[6][i] + m[i][6], i % 2 ? '00' : '11', 'линии синхронизации');
    assert.equal(m[n - 8][8], '1', 'тёмный модуль');
    // Две копии информации о формате совпадают, уровень M, код БЧХ сходится.
    const f1 = parseInt([0, 1, 2, 3, 4, 5].map(x => m[8][x]).join('') + m[8][7] + m[8][8] + m[7][8] + [5, 4, 3, 2, 1, 0].map(y => m[y][8]).join(''), 2);
    const f2 = parseInt([1, 2, 3, 4, 5, 6, 7].map(k => m[n - k][8]).join('') + [8, 7, 6, 5, 4, 3, 2, 1].map(k => m[8][n - k]).join(''), 2);
    assert.equal(f1, f2, 'две копии формата');
    let raw = f1 ^ 0x5412;
    assert.equal(raw >> 13, 0b00, 'уровень коррекции M');
    for (let i = 14; i >= 10; i--) if (raw >> i & 1) raw ^= 0x537 << (i - 10);
    assert.equal(raw, 0, 'код БЧХ формата');
  }
  assert.deepEqual(qr.encode('otpauth://totp/x'), qr.encode('otpauth://totp/x'), 'одинаковый текст — одинаковый код');
  assert.throws(() => qr.encode('x'.repeat(2332)), 'больше версии 40 не помещается');
});

// Код для ещё не использованного шага: сервер принимает текущий шаг и соседние (±30 секунд), поэтому берём текущий или следующий;
// если оба уже израсходованы — ждём следующего шага.
async function nextCode(secret, userId = 'u1') {
  for (;;) {
    const last = db.q('SELECT totp_last FROM users WHERE id = ?').get(userId).totp_last, now = Math.floor(Date.now() / 30000), c = Math.max(now, last + 1);
    if (c <= now + 1) return totp.hotp(totp.base32Decode(secret), c);
    await new Promise(r => setTimeout(r, 30000 - Date.now() % 30000 + 50));
  }
}
// Заведомо неверный код: не совпадает ни с одним кодом ближайших шагов.
function wrongCode(secret) {
  const key = totp.base32Decode(secret), now = Math.floor(Date.now() / 30000), near = new Set([-2, -1, 0, 1, 2].map(d => totp.hotp(key, now + d)));
  for (let i = 0; ; i++) { const c = String(i * 7919 % 1e6).padStart(6, '0'); if (!near.has(c)) return c; }
}
let adminSecret = '';

test('администратор: скрыт от обычных; пароль открывает только подключение приложения, затем вход с кодом', async () => {
  const user = client(); const ub = await user.login('0700000003');
  assert.ok(!('adminTotp' in ub.data.data) && !('adminMfa' in ub.data.data), 'обычному пользователю поля администратора не отдаются');
  for (const [m, p] of [['GET', '/admin/overview'], ['POST', '/admin/unlock'], ['POST', '/admin/totp/setup'], ['POST', '/admin/totp/enable']])
    assert.equal((await user.call(m, p, m === 'POST' ? { password: 'hookah', code: '123456' } : undefined)).status, 404, 'обычный пользователь даже не видит адрес ' + p);
  assert.equal((await fetch(base + '/admin.js', { headers: { Cookie: '' } })).status, 404, 'код панели не отдаётся гостю');

  const admin = client(); const login = await admin.login('0700000001');
  assert.equal(login.data.data.role, 'admin');
  assert.equal(login.data.data.adminTotp, false, 'приложение ещё не подключено');
  assert.equal(login.data.data.adminMfa, false);
  assert.equal((await admin.call('GET', '/admin/overview')).data.error, 'step_up', 'без подтверждения пароля нельзя');
  assert.equal((await admin.call('POST', '/admin/totp/setup')).data.error, 'step_up', 'QR — только после пароля');
  const wrong = await admin.call('POST', '/admin/unlock', { password: 'wrong' });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.data.error, 'bad_password');

  // Пароль без подключённого приложения открывает только экран подключения.
  const half = await admin.call('POST', '/admin/unlock', { password: 'hookah' });
  assert.equal(half.status, 200);
  assert.equal(half.data.adminMfa, false);
  assert.equal(half.data.adminTotp, false);
  assert.ok(half.data.adminUntil > Date.now());
  for (const [m, p] of [['GET', '/admin/overview'], ['DELETE', '/admin/comments/c4'], ['DELETE', '/admin/events/e2']]) {
    const r = await admin.call(m, p);
    assert.equal(r.status, 403, p);
    assert.equal(r.data.error, 'totp_setup_required', 'действия панели — только после подключения приложения: ' + p);
  }
  assert.equal((await admin.call('POST', '/admin/totp/enable', { code: '123456' })).data.error, 'totp_no_setup');

  // QR и ключ; в базе секрет только зашифрован; новый запрос выдаёт новый секрет, старый перестаёт подходить.
  const first = await admin.call('POST', '/admin/totp/setup');
  assert.equal(first.status, 200);
  const setup = await admin.call('POST', '/admin/totp/setup');
  assert.match(setup.data.secret, /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/, 'ключ для ручного ввода — группами по 4');
  assert.notEqual(setup.data.secret, first.data.secret);
  adminSecret = setup.data.secret.replace(/ /g, '');
  assert.equal(setup.data.uri, `otpauth://totp/Hookah%20Party:%2B996%20***%20***%20001?secret=${adminSecret}&issuer=Hookah%20Party&algorithm=SHA1&digits=6&period=30`);
  assert.ok(!JSON.stringify(setup.data).includes('700000001'), 'полного номера нет ни в ссылке, ни в ответе');
  assert.deepEqual(setup.data.qr, qr.encode(setup.data.uri), 'QR — это ссылка otpauth');
  assert.ok(setup.data.qr.length <= 57, 'QR не больше версии 10');
  const row = db.q("SELECT totp_secret_enc, totp_pending_enc FROM users WHERE id = 'u1'").get();
  assert.equal(row.totp_secret_enc, null, 'до подтверждения кодом приложение не подключено');
  assert.ok(!row.totp_pending_enc.includes(adminSecret), 'секрет в базе не открытым текстом');
  assert.equal(require('../server/lib/secure').decrypt(row.totp_pending_enc), adminSecret);
  const stale = await admin.call('POST', '/admin/totp/enable', { code: totp.code(first.data.secret.replace(/ /g, '')) });
  assert.equal(stale.status, 401, 'код по прежнему QR не подходит');
  assert.equal(stale.data.error, 'totp_invalid');
  assert.equal(stale.data.left, 4, 'неверный код считается вместе с неверным паролем');

  const on = await admin.call('POST', '/admin/totp/enable', { code: await nextCode(adminSecret) });
  assert.equal(on.status, 200);
  assert.equal(on.data.adminMfa, true);
  assert.equal(on.data.adminTotp, true);
  const enabled = db.q("SELECT totp_secret_enc, totp_pending_enc, totp_last FROM users WHERE id = 'u1'").get();
  assert.equal(require('../server/lib/secure').decrypt(enabled.totp_secret_enc), adminSecret);
  assert.equal(enabled.totp_pending_enc, null);
  assert.ok(enabled.totp_last >= Math.floor(Date.now() / 30000) - 1, 'шаг принятого кода запомнен');
  assert.equal((await admin.call('POST', '/admin/totp/setup')).status, 409, 'подключить второй раз нельзя — только сброс из консоли');
  assert.equal((await admin.call('POST', '/admin/totp/enable', { code: '123456' })).status, 409);
  const boot = await admin.call('GET', '/bootstrap');
  assert.equal(boot.data.adminTotp, true);
  assert.equal(boot.data.adminMfa, true);
  const raw = JSON.stringify(boot.data);
  assert.ok(!raw.includes(adminSecret) && !raw.includes('totp_') && !raw.includes(enabled.totp_secret_enc), 'секрет не отдаётся никогда');

  const ov = await admin.call('GET', '/admin/overview');
  assert.equal(ov.status, 200);
  assert.ok(ov.data.comments.length > 0 && ov.data.events.length > 0);
  assert.equal((await admin.call('DELETE', '/admin/comments/c4')).status, 200, 'чужой комментарий в чужом сборе');
  assert.equal((await admin.call('DELETE', '/admin/events/e2')).status, 200, 'чужой сбор');
  const after = await admin.call('GET', '/admin/overview');
  assert.ok(!after.data.comments.some(x => x.id === 'c4') && !after.data.events.some(x => x.id === 'e2'));
  assert.ok(after.data.audit.some(x => x.type === 'admin_delete_event'), 'действие в журнале');
  assert.ok(after.data.audit.some(x => x.type === 'admin_totp_enabled'), 'подключение приложения в журнале');
  assert.equal((await user.call('DELETE', '/admin/comments/c1')).status, 404, 'обычный пользователь не может удалять');
});

test('администратор: вход паролем и кодом, повтор кода не проходит, 5 ошибок — блокировка', async () => {
  const admin = client(); const login = await admin.login('0700000001');
  assert.equal(login.data.data.adminTotp, true);
  assert.equal(login.data.data.adminMfa, false, 'новая сессия — панель закрыта');
  assert.equal((await admin.call('GET', '/admin/overview')).data.error, 'step_up');

  const noCode = await admin.call('POST', '/admin/unlock', { password: 'hookah' });
  assert.equal(noCode.status, 401);
  assert.equal(noCode.data.error, 'totp_required', 'одного пароля мало');
  const badPass = await admin.call('POST', '/admin/unlock', { password: 'wrong-pass1', code: await nextCode(adminSecret) });
  assert.equal(badPass.data.error, 'bad_password', 'и с верным кодом нужен пароль');
  assert.equal(badPass.data.left, 4);
  const badCode = await admin.call('POST', '/admin/unlock', { password: 'hookah', code: wrongCode(adminSecret) });
  assert.equal(badCode.status, 401);
  assert.equal(badCode.data.error, 'totp_invalid');
  assert.equal(badCode.data.left, 3, 'ошибки пароля и кода — в одном счётчике');

  const code = await nextCode(adminSecret);
  const ok = await admin.call('POST', '/admin/unlock', { password: 'hookah', code });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.adminMfa, true);
  assert.equal((await admin.call('GET', '/admin/overview')).status, 200);
  assert.equal((await admin.call('POST', '/admin/lock')).status, 200);
  assert.equal((await admin.call('GET', '/admin/overview')).data.error, 'step_up', 'после «Закрыть доступ» панель закрыта');
  assert.equal((await admin.call('GET', '/bootstrap')).data.adminMfa, false);

  // Тот же код второй раз не принимается — даже с верным паролем.
  const replay = await admin.call('POST', '/admin/unlock', { password: 'hookah', code });
  assert.equal(replay.status, 401);
  assert.equal(replay.data.error, 'totp_invalid');
  assert.match(replay.data.message.ru, /уже использован/);
  assert.equal(replay.data.left, 4, 'счётчик ошибок обнулился после удачного входа');
  for (const left of [3, 2, 1]) assert.equal((await admin.call('POST', '/admin/unlock', { password: 'hookah', code: wrongCode(adminSecret) })).data.left, left);
  const fifth = await admin.call('POST', '/admin/unlock', { password: 'hookah', code: wrongCode(adminSecret) });
  assert.equal(fifth.status, 401);
  assert.equal(fifth.data.error, 'locked');
  const locked = await admin.call('POST', '/admin/unlock', { password: 'hookah', code: totp.code(adminSecret, Date.now() + 30000) });
  assert.equal(locked.status, 429, 'во время блокировки не открыть даже с верным паролем: блокировка проверяется первой');
  assert.equal(locked.data.error, 'locked');
  assert.equal((await admin.call('GET', '/admin/overview')).status, 403);
  const fails = db.q("SELECT detail FROM audit WHERE user_id = 'u1' AND type = 'admin_unlock_fail'").all().map(r => r.detail);
  assert.ok(fails.includes('password') && fails.includes('totp') && fails.includes('totp reused') && fails.includes('totp setup'), 'ошибки в журнале: ' + fails);
  require('../server/lib/guard').clearFails('admin:u1'); // блокировка — в памяти сервера; снимаем, чтобы не мешать следующим тестам
});

test('консоль: totp-reset отключает приложение и завершает сессии, rekey меняет ключ панели', async () => {
  const { totpReset, rekey } = require('../server/admin');
  const before = client(); await before.login('0700000001');
  assert.throws(() => totpReset(db, '0700000003'), /не администратор/);
  assert.throws(() => totpReset(db, '123'), /номер/);
  const r = totpReset(db, '+996 700 000 001');
  assert.deepEqual([r.wasOn, r.sessions > 0], [true, true]);
  assert.deepEqual({ ...db.q("SELECT totp_secret_enc, totp_pending_enc, totp_last FROM users WHERE id = 'u1'").get() }, { totp_secret_enc: null, totp_pending_enc: null, totp_last: 0 });
  assert.equal(db.q("SELECT COUNT(*) AS n FROM sessions WHERE user_id = 'u1'").get().n, 0);
  assert.equal((await before.call('GET', '/bootstrap')).data.session, null, 'старые сессии больше не действуют');
  assert.ok(db.q("SELECT 1 FROM audit WHERE type = 'admin_totp_reset' AND user_id = 'u1' AND detail = '+996 ••• ••• 001'").get(), 'сброс в журнале, номер скрыт');
  const again = client(); const login = await again.login('0700000001');
  assert.equal(login.data.data.adminTotp, false);
  assert.equal((await again.call('POST', '/admin/unlock', { password: 'hookah' })).data.adminMfa, false, 'после сброса — снова экран подключения');
  assert.equal((await again.call('GET', '/admin/overview')).data.error, 'totp_setup_required');

  // rekey: на временных файлах, с тем же ключом, что у тестового сервера.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-rekey-')), envFile = path.join(dir, '.env'), file = path.join(dir, 'panel.enc');
  const oldKey = process.env.ADMIN_CODE_KEY, src = Buffer.from('window.HP_ADMIN = { rekey: true };');
  fs.writeFileSync(envFile, `# настройки\nADMIN_PHONES=+996700000001\nADMIN_CODE_KEY=${oldKey}\nPORT=3000\n`, { mode: 0o600 });
  fs.writeFileSync(file, panel.encrypt(src, Buffer.from(oldKey, 'base64')));
  rekey({ envFile, file });
  const text = fs.readFileSync(envFile, 'utf8'), newKey = /^ADMIN_CODE_KEY=(.+)$/m.exec(text)[1];
  assert.notEqual(newKey, oldKey, 'ключ сменился');
  assert.equal(text, `# настройки\nADMIN_PHONES=+996700000001\nADMIN_CODE_KEY=${newKey}\nPORT=3000\n`, 'заменена только строка ключа');
  assert.equal(fs.statSync(envFile).mode & 0o777, 0o600, 'права на файл настроек прежние');
  assert.deepEqual(panel.decrypt(fs.readFileSync(file), Buffer.from(newKey, 'base64')), src, 'панель расшифровывается новым ключом');
  assert.throws(() => panel.decrypt(fs.readFileSync(file), Buffer.from(oldKey, 'base64')), 'старым ключом — уже нет');
  assert.deepEqual(fs.readdirSync(dir).sort(), ['.env', 'panel.enc'], 'временных файлов не осталось');
  const snapshot = [fs.readFileSync(envFile), fs.readFileSync(file)];
  assert.throws(() => rekey({ envFile, file }), /отличается/, 'ключ в окружении и в файле разные — отказ');
  assert.deepEqual([fs.readFileSync(envFile), fs.readFileSync(file)], snapshot, 'при отказе ничего не изменилось');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('администратор: сверх блокировок — не больше 10 неверных попыток в час', async () => {
  // Второй владелец на время теста: счётчик за час в памяти не сбросить, поэтому — отдельный аккаунт.
  const { hashPassword, encrypt, phoneIndex } = require('../server/lib/secure');
  db.q("INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, role) VALUES ('uAdm2', 'Второй', ?, ?, '333', ?, ?, 'admin')")
    .run(encrypt('996555000333'), phoneIndex('996555000333'), await hashPassword('Admin-Two-2026'), new Date().toISOString());
  const phones = process.env.ADMIN_PHONES;
  process.env.ADMIN_PHONES = phones + ',+996555000333';
  try {
    const c = client();
    assert.equal((await c.login('0555000333', 'Admin-Two-2026')).data.data.role, 'admin');
    for (let i = 1; i <= 10; i++) {
      assert.equal((await c.call('POST', '/admin/unlock', { password: 'wrong-pass1' })).status, 401, 'попытка ' + i);
      if (i % 5 === 0) require('../server/lib/guard').clearFails('admin:uAdm2'); // как будто 5 минут блокировки прошли
    }
    const r = await c.call('POST', '/admin/unlock', { password: 'Admin-Two-2026' });
    assert.equal(r.status, 429, 'одиннадцатая попытка за час не принимается даже с верным паролем');
    assert.equal(r.data.error, 'rate_limited');
    assert.ok(r.data.retryAfter > 3000, 'ждать — почти час');
  } finally {
    process.env.ADMIN_PHONES = phones;
    db.q("DELETE FROM users WHERE id = 'uAdm2'").run();
  }
});

test('администратор только владелец: роли в базе мало, нужен номер из ADMIN_PHONES', async () => {
  // Как будто кто-то выдал себе роль прямо в базе и даже открыл панель в своей сессии.
  db.q("UPDATE users SET role = 'admin' WHERE id = 'u2'").run();
  const intruder = client(); const login = await intruder.login('0700000002');
  assert.equal(login.data.data.role, 'user', 'сайт не считает его администратором');
  assert.ok(!('adminTotp' in login.data.data));
  db.q("UPDATE sessions SET admin_until = ?, admin_mfa = 1 WHERE user_id = 'u2'").run(Date.now() + 600e3);
  for (const [m, p] of [['POST', '/admin/unlock'], ['POST', '/admin/totp/setup'], ['POST', '/admin/totp/enable'], ['POST', '/admin/lock'], ['GET', '/admin/overview'], ['DELETE', '/admin/comments/c1']])
    assert.equal((await intruder.call(m, p, m === 'POST' ? { password: 'hookah', code: '123456' } : undefined)).status, 404, p);
  assert.equal(db.q("SELECT totp_pending_enc FROM users WHERE id = 'u2'").get().totp_pending_enc, null, 'секрет ему не выдан');
  const cookieOf = async phone => { const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone, password: 'hookah' }) }); return r.headers.get('set-cookie').split(';')[0]; };
  assert.equal((await fetch(base + '/admin.js', { headers: { Cookie: await cookieOf('0700000002') } })).status, 404, 'код панели ему не отдаётся');
  db.q("UPDATE users SET role = 'user' WHERE id = 'u2'").run();

  const owner = await fetch(base + '/admin.js', { headers: { Cookie: await cookieOf('0700000001') } });
  assert.equal(owner.status, 200, 'владельцу панель отдаётся');
  assert.match(await owner.text(), /HP_ADMIN/, 'сервер расшифровал панель');
  assert.equal(owner.headers.get('cache-control'), 'private, no-store');
});

test('код панели в репозитории только зашифрован', () => {
  const enc = fs.readFileSync(path.join(__dirname, '..', 'server', 'private', 'admin-panel.enc'));
  assert.equal(enc.subarray(0, 4).toString(), 'HPA1');
  assert.ok(!enc.includes('HP_ADMIN') && !enc.includes('function'), 'в файле нет открытого кода');
  assert.ok(!fs.existsSync(path.join(__dirname, '..', 'admin.js')), 'в открытой папке сайта панели нет');
  assert.throws(() => panel.decrypt(enc, require('node:crypto').randomBytes(32)), 'чужим ключом не расшифровать');
});

test('приглашение по ссылке: гость видит только главное, ответить можно после входа', async () => {
  const host = client(); await host.login('0700000001');
  const { data: { token } } = await host.call('POST', '/events/e1/link');
  assert.match(token, /^[\w-]{24}$/);
  assert.equal((await host.call('POST', '/events/e1/link')).data.token, token, 'ссылка у сбора одна');

  const guest = client();
  const view = await guest.call('GET', '/join/' + token);
  assert.equal(view.status, 200);
  assert.equal(view.data.event.title, 'Пятничный сбор');
  assert.equal(view.data.event.host, 'Алекс');
  assert.equal(view.data.status, null);
  assert.ok(!JSON.stringify(view.data).includes('996'), 'номера телефонов по ссылке не видны');
  assert.equal((await guest.call('POST', '/join/' + token, { status: 'going' })).status, 401);
  assert.equal((await guest.call('GET', '/join/not-a-real-token-123456')).status, 404);

  const friend = client(); await friend.login('0700000006');
  assert.equal((await friend.call('POST', '/events/e1/link')).status, 403, 'чужой человек ссылку не создаёт');
  const r = await friend.call('POST', '/join/' + token, { status: 'going' });
  assert.equal(r.status, 200);
  assert.equal(r.data.eventId, 'e1');
  assert.ok(r.data.data.events.some(e => e.id === 'e1'), 'сбор появился у друга');
  assert.equal((await friend.call('GET', '/join/' + token)).data.status, 'going');
  const notes = (await host.call('GET', '/bootstrap')).data.notifications;
  assert.ok(notes.some(n => n.type === 'rsvp_going' && n.actorId === 'u6'), 'организатор получил уведомление');
});

test('ошибки со страницы принимаются, но не больше лимита', async () => {
  const c = client();
  assert.equal((await c.call('POST', '/client-errors', { msg: 'TypeError: x is undefined', src: 'app.js', line: 10, page: 'event' })).status, 200);
  assert.equal((await c.call('POST', '/client-errors', { msg: 'x' }, { Origin: 'https://evil.example' })).status, 403);
});

test('сроки хранения: журнал старше 90 дней, счётчики лимитов старше 2 дней, истёкшие сессии и коды, устройства без входа год, уведомления старше полугода удаляются', () => {
  const t = open(':memory:'), now = Date.now(), day = 864e5, iso = ms => new Date(ms).toISOString();
  t.q("INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at) VALUES ('ux', 'Икс', 'x', 'idx-x', '000', 'x', ?)").run(iso(now));
  for (const [type, at] of [['old', now - 91 * day], ['almost', now - 89 * day], ['fresh', now - 3600e3]]) t.q('INSERT INTO audit (at, user_id, type) VALUES (?, ?, ?)').run(iso(at), 'ux', type);
  for (const at of [now - 3 * day, now - 3600e3]) t.q("INSERT INTO event_log VALUES ('ux', 'create', ?)").run(at);
  const sess = t.q("INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen) VALUES (?, 'ux', 'c', ?, ?, ?)");
  sess.run('expired', now - 31 * day, now - day, now - 2 * day); sess.run('live', now, now + day, now);
  t.q("INSERT INTO sms_codes (phone_idx, code_hash, purpose, expires_at, attempts, sent_at) VALUES ('i-old', 'h', 'login', ?, 0, ?)").run(now - 60e3, now - 360e3);
  t.q("INSERT INTO sms_codes (phone_idx, code_hash, purpose, expires_at, attempts, sent_at) VALUES ('i-new', 'h', 'login', ?, 0, ?)").run(now + 60e3, now);
  const dev = t.q("INSERT INTO known_devices VALUES ('ux', ?, ?, ?, ?)");
  dev.run('fp-old', 'Chrome · Windows', now - 500 * day, now - 366 * day); dev.run('fp-new', 'Safari · iPhone', now - 500 * day, now - 364 * day);
  const note = t.q("INSERT INTO notifications (id, user_id, type, at) VALUES (?, 'ux', 'friend', ?)");
  note.run('n-old', iso(now - 181 * day)); note.run('n-new', iso(now - 179 * day));

  assert.deepEqual(purgeOld(t, now), { audit: 1, eventLog: 1, sessions: 1, smsCodes: 1, devices: 1, notifications: 1, createdIp: 0, sessionUa: 0 });
  assert.deepEqual(t.q('SELECT id FROM notifications').all().map(r => r.id), ['n-new'], 'уведомление младше полугода на месте');
  assert.deepEqual(t.q('SELECT type FROM audit ORDER BY id').all().map(r => r.type), ['almost', 'fresh'], 'журнал младше 90 дней на месте');
  assert.deepEqual(t.q('SELECT at FROM event_log').all().map(r => r.at), [now - 3600e3], 'счётчик за последние сутки на месте — лимиты работают');
  assert.deepEqual(t.q('SELECT token_hash FROM sessions').all().map(r => r.token_hash), ['live']);
  assert.deepEqual(t.q('SELECT phone_idx FROM sms_codes').all().map(r => r.phone_idx), ['i-new']);
  assert.deepEqual(t.q('SELECT fp FROM known_devices').all().map(r => r.fp), ['fp-new'], 'устройство, с которого входили меньше года назад, на месте');
  assert.deepEqual(purgeOld(t, now), { audit: 0, eventLog: 0, sessions: 0, smsCodes: 0, devices: 0, notifications: 0, createdIp: 0, sessionUa: 0 }, 'повторно удалять нечего');
  const later = purgeOld(t, now + 2 * day);
  assert.equal(later.audit, 1, 'через два дня уходит запись, которой стало больше 90 дней');
  assert.equal(later.devices, 1, 'и устройство, с которого не входили больше года');
  t.close();
});

test('удаление аккаунта: нужен пароль, после 5 неверных — блокировка', async () => {
  const { hashPassword, encrypt, phoneIndex } = require('../server/lib/secure');
  db.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run('uLock', 'Замок', encrypt('996555000222'), phoneIndex('996555000222'), '222', await hashPassword('Lock-Test-2026'), new Date().toISOString());
  const c = client();
  assert.equal((await c.login('0555000222', 'Lock-Test-2026')).status, 200);
  assert.equal((await client().call('POST', '/me/delete', { password: 'Lock-Test-2026' })).status, 401, 'без входа нельзя');
  const noPass = await c.call('POST', '/me/delete', {});
  assert.equal(noPass.status, 401);
  assert.equal(noPass.data.error, 'bad_password');
  assert.equal(noPass.data.left, 4);
  for (let i = 0; i < 3; i++) assert.equal((await c.call('POST', '/me/delete', { password: 'wrong-pass1' })).data.left, 3 - i);
  const fifth = await c.call('POST', '/me/delete', { password: 'wrong-pass1' });
  assert.equal(fifth.status, 401);
  assert.equal(fifth.data.error, 'locked');
  const locked = await c.call('POST', '/me/delete', { password: 'Lock-Test-2026' });
  assert.equal(locked.status, 429, 'даже верный пароль не принимается, пока действует блокировка');
  assert.equal(locked.data.error, 'locked');
  assert.ok(db.q("SELECT 1 FROM users WHERE id = 'uLock'").get(), 'аккаунт на месте');
  assert.equal((await c.call('GET', '/security/log')).status, 200, 'сессия не тронута');
  assert.deepEqual(db.q("SELECT type FROM audit WHERE user_id = 'uLock' AND type LIKE 'delete%' ORDER BY id").all().map(r => r.type),
    ['delete_fail', 'delete_fail', 'delete_fail', 'delete_fail', 'delete_locked'], 'попытки в журнале');
});

test('удаление аккаунта: стираются все данные, сессии и его сборы; гости узнают об отмене', async () => {
  const phone = '0555777888', password = 'Delete-Me-2026';
  const d = client();
  const sms = await d.call('POST', '/auth/sms', { phone, purpose: 'register' });
  const reg = await d.call('POST', '/auth/register', { name: 'Тестовый', phone, password, code: sms.data.devCode, challenge: sms.data.challenge, adult: true });
  assert.equal(reg.status, 200);
  const uid = reg.data.data.session, idx = db.q('SELECT phone_idx FROM users WHERE id = ?').get(uid).phone_idx;
  const host = client(); await host.login('0700000001');
  const dina = client(); await dina.login('0700000002');
  const ok = async p => { const r = await p; assert.equal(r.status, 200, JSON.stringify(r.data)); return r; };

  // Его данные во всех таблицах: избранное, друзья, свой сбор с гостем, участие в чужом сборе, сообщения, реакции, рассказы, отзыв, микс.
  await ok(d.call('POST', '/me/favs/ds-supernova'));
  await ok(d.call('POST', '/friends/u1'));
  await ok(host.call('POST', '/friends/' + uid)); // дружба взаимная, только когда добавили оба
  const at = new Date(Date.now() + 3 * 864e5).toISOString();
  const eid = (await ok(d.call('POST', '/events', { title: 'Прощальный сбор', venue: 'Hookah', at, invites: [{ userId: 'u2' }, { phone: '0555999000' }] }))).data.id;
  await ok(dina.call('POST', `/events/${eid}/rsvp`, { status: 'going' }));
  await ok(dina.call('PUT', `/events/${eid}/picks`, { ids: ['ds-supernova'] }));
  await ok(dina.call('PUT', `/events/${eid}/bowl`, { bowlId: 'b-phunnel' }));
  await ok(d.call('POST', `/events/${eid}/paid/u2`));
  const dinaMsg = (await ok(dina.call('POST', `/events/${eid}/comments`, { text: 'Буду!' }))).data.data.events.find(e => e.id === eid).comments[0].id;
  await ok(d.call('PUT', `/comments/${dinaMsg}/reaction`, { emoji: '🔥' }));
  await ok(host.call('POST', '/events/e1/invites', { invites: [{ userId: uid }] }));
  await ok(d.call('POST', '/events/e1/rsvp', { status: 'going' }));
  await ok(d.call('PUT', '/events/e1/picks', { ids: ['mh-pinkman'] }));
  await ok(d.call('PUT', '/events/e1/bowl', { bowlId: 'b-killer' }));
  await ok(host.call('POST', `/events/e1/paid/${uid}`));
  const myMsg = (await ok(d.call('POST', '/events/e1/comments', { text: 'Тоже приду' }))).data.data.events.find(e => e.id === 'e1').comments.find(c => c.userId === uid).id;
  await ok(host.call('PUT', `/comments/${myMsg}/reaction`, { emoji: '❤️' }));
  await ok(d.call('PUT', '/comments/c1/reaction', { emoji: '👍' }));
  await ok(d.call('POST', '/events/e5/story/fire'));
  const storyMsg = (await ok(d.call('POST', '/events/e4/story/comments', { text: 'Классный был вечер' }))).data.data.events.find(e => e.id === 'e4').story.comments.find(c => c.userId === uid).id;
  await ok(host.call('PUT', `/comments/${storyMsg}/reaction`, { emoji: '😂' }));
  await ok(d.call('PUT', '/reviews/od-cola', { rating: 5, text: 'Отличная кола' }));
  const mixId = (await ok(d.call('POST', '/mixes', { name: 'Прощальный микс', parts: [{ id: 'od-cola', pct: 50 }, { id: 'tg-canemint', pct: 50 }] }))).data.data.mixes.find(m => m.authorId === uid).id;
  await ok(host.call('POST', `/mixes/${mixId}/like`));
  await ok(d.call('POST', '/mixes/m1/like'));
  // Его прошедший вечер с рассказом, чужими комментариями и реакциями (через API прошедший сбор не создать).
  const past = new Date(Date.now() - 10 * 864e5).toISOString();
  db.q("INSERT INTO events (id, title, venue, at, host_id, created_at) VALUES ('eGone', 'Старый вечер', 'Hookah', ?, ?, ?)").run(past, uid, past);
  db.q("INSERT INTO invites (event_id, user_id, status, at) VALUES ('eGone', 'u1', 'going', ?)").run(past);
  db.q("INSERT INTO picks VALUES ('eGone', 'u1', 'od-cola')").run();
  db.q("INSERT INTO stories VALUES ('eGone', 5, 'Хорошо посидели всей компанией.', '[]', ?)").run(past);
  db.q("INSERT INTO story_fire VALUES ('eGone', 'u1')").run();
  db.q("INSERT INTO comments VALUES ('scGone', 'eGone', 'u3', 'story', 'Было здорово', ?)").run(past);
  db.q("INSERT INTO reactions VALUES ('scGone', 'u2', '🔥', ?)").run(past);
  db.q("INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES ('nGone', 'u3', 'reaction', 'u2', 'eGone', 'scGone:🔥', ?)").run(past);
  // Старое приглашение «по номеру», код из SMS на его номер и вторая сессия на другом устройстве.
  db.q("INSERT INTO invites (event_id, phone_idx, phone_enc, phone_tail, status) VALUES ('e3', ?, 'x', '888', 'pending')").run(idx);
  await ok(d.call('POST', '/auth/sms', { phone, purpose: 'login' }));
  const d2 = client(); await ok(d2.login(phone, password));

  const tables = db.q("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map(r => r.name);
  const colsOf = t => db.q(`PRAGMA table_info("${t}")`).all().map(c => c.name);
  // Сколько строк где-либо ссылается на пользователя: id или индекс номера в любом столбце любой таблицы.
  const traces = () => tables.flatMap(t => colsOf(t).map(c => [t, c, db.q(`SELECT COUNT(*) AS n FROM "${t}" WHERE instr(CAST("${c}" AS TEXT), ?) > 0 OR "${c}" = ?`).get(uid, idx).n])).filter(x => x[2] > 0);
  const hostedComments = db.q('SELECT id FROM comments WHERE event_id IN (?, ?)').all(eid, 'eGone').map(r => r.id);
  const linked = Object.fromEntries(traces().map(([t, c, n]) => [`${t}.${c}`, n]));
  for (const k of ['users.id', 'sessions.user_id', 'favs.user_id', 'friends.user_id', 'friends.friend_id', 'events.host_id', 'invites.user_id', 'invites.phone_idx', 'picks.user_id', 'bowls.user_id',
    'paid.user_id', 'comments.user_id', 'reactions.user_id', 'story_fire.user_id', 'reviews.user_id', 'mixes.author_id', 'mix_likes.user_id', 'notifications.user_id', 'notifications.actor_id',
    'audit.user_id', 'event_log.user_id', 'sms_codes.phone_idx', 'known_devices.user_id']) assert.ok(linked[k] > 0, 'до удаления есть данные в ' + k);
  assert.ok(!db.q("SELECT 1 FROM notifications WHERE user_id = ? AND type = 'new_login'").get(uid), 'регистрация и вход с того же устройства — без уведомления «новое устройство»');
  const auditIds = db.q('SELECT id FROM audit WHERE user_id = ?').all(uid).map(r => r.id);

  // CSRF-токен обязателен и здесь.
  const { cookie, csrf } = d.jar();
  const raw = (path, body, headers = {}) => fetch(base + '/api' + path, { method: body === undefined ? 'GET' : 'POST', headers: { Cookie: cookie, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  assert.equal((await raw('/me/delete', { password })).status, 403, 'без CSRF-токена не удалить');
  assert.equal((await raw('/me/delete', { password }, { 'X-CSRF-Token': csrf, Origin: 'https://evil.example' })).status, 403, 'с чужого сайта не удалить');

  const del = await raw('/me/delete', { password }, { 'X-CSRF-Token': csrf });
  assert.equal(del.status, 200);
  assert.match(del.headers.get('set-cookie'), /^hp_sid=;.*Max-Age=0/, 'cookie сессии стёрт');
  const body = await del.json();
  assert.equal(body.ok, true);
  assert.equal(body.data.session, null);
  assert.ok(!body.data.users.some(u => u.id === uid));

  // Та же сессия и вторая сессия больше не работают, войти с этим номером нельзя, номер снова свободен.
  assert.equal((await raw('/security/log')).status, 401);
  assert.equal((await raw('/events/e1/comments', { text: 'я ещё здесь?' }, { 'X-CSRF-Token': csrf })).status, 401);
  assert.equal((await d2.call('GET', '/security/log')).status, 401);
  const relogin = await client().login(phone, password);
  assert.equal(relogin.status, 401);
  assert.equal(relogin.data.error, 'bad_credentials');

  // Ни в одной таблице не осталось ни его id, ни индекса его номера (журнал безопасности — обезличен).
  assert.deepEqual(traces(), []);
  assert.equal((await client().call('POST', '/auth/sms', { phone, purpose: 'register' })).status, 200, 'номер можно зарегистрировать заново');
  for (const t of tables) if (colsOf(t).includes('event_id')) assert.equal(db.q(`SELECT COUNT(*) AS n FROM "${t}" WHERE event_id IN (?, ?)`).get(eid, 'eGone').n, 0, `${t}: его сборы удалены целиком`);
  assert.equal(db.q(`SELECT COUNT(*) AS n FROM reactions WHERE comment_id IN (${hostedComments.map(() => '?').join(', ')})`).get(...hostedComments).n, 0, 'реакции на сообщения в его сборах');
  assert.equal(db.q('SELECT COUNT(*) AS n FROM reactions WHERE comment_id IN (?, ?)').get(myMsg, storyMsg).n, 0, 'чужие реакции на его сообщения');

  // Гость предстоящего сбора получил уведомление об отмене, гости прошедшего — нет.
  const dinaNotes = (await dina.call('GET', '/bootstrap')).data.notifications.filter(n => n.type === 'cancelled');
  assert.deepEqual(dinaNotes.map(n => [n.ref, n.actorId, n.eventId]), [['Прощальный сбор', null, null]]);
  const hostData = (await host.call('GET', '/bootstrap')).data;
  assert.ok(!hostData.notifications.some(n => n.type === 'cancelled' && n.ref === 'Старый вечер'), 'о прошедшем вечере не уведомляем');
  assert.ok(hostData.notifications.every(n => n.actorId !== uid), 'уведомления от него удалены');
  assert.ok(hostData.users.every(u => u.id !== uid && !(u.friends || []).includes(uid)), 'его нет в списках друзей');
  assert.ok(hostData.mixes.every(m => m.authorId !== uid && !m.likes.includes(uid)), 'миксы и лайки');
  const e1 = hostData.events.find(e => e.id === 'e1');
  assert.ok(e1 && !e1.invites.some(i => i.userId === uid) && !(uid in e1.picks) && !(uid in e1.bowls) && !(uid in e1.paid) && !e1.comments.some(c => c.userId === uid), 'чужой сбор на месте, его следов в нём нет');
  assert.ok(hostData.events.find(e => e.id === 'e4').story.comments.every(c => c.userId !== uid), 'комментарий к рассказу удалён');

  // Журнал безопасности: прежние записи остались без привязки к человеку, удаление записано с одними последними цифрами номера.
  assert.ok(auditIds.length >= 2);
  assert.deepEqual(db.q(`SELECT DISTINCT user_id FROM audit WHERE id IN (${auditIds.join(', ')})`).all().map(r => r.user_id), [null]);
  const gone = db.q("SELECT * FROM audit WHERE type = 'account_deleted' ORDER BY id DESC").get();
  assert.equal(gone.user_id, null);
  assert.equal(gone.detail, '+996 ••• ••• 888');
});

// ---------- Сигналы безопасности: устройства, сигналы владельцу, отчёты CSP ----------
const UA = {
  macChrome: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  macChromeNew: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  macSafari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  iphoneSafari: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  androidPhone: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  androidTablet: 'Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  winFirefox: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0'
};
// Сигналы владельцу данного вида (ref начинается с «вид:»), по порядку.
const alertsFor = (kind, userId = 'u1') => db.q("SELECT ref FROM notifications WHERE user_id = ? AND type = 'security_alert' AND instr(ref, ?) = 1 ORDER BY rowid").all(userId, kind + ':').map(r => r.ref);
async function addUser(id, phone, password) {
  const { hashPassword, encrypt, phoneIndex } = require('../server/lib/secure');
  db.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, 'Тест', encrypt(phone), phoneIndex(phone), phone.slice(-3), await hashPassword(password), new Date().toISOString());
}
const restoreEnv = (k, v) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };

test('устройство по User-Agent: браузер, система и тип без версий; адрес без последних цифр', () => {
  const cases = [
    [UA.macChrome, 'Chrome · macOS', 'desktop'], [UA.macSafari, 'Safari · macOS', 'desktop'], [UA.iphoneSafari, 'Safari · iPhone', 'mobile'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1', 'Chrome · iPhone', 'mobile'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) HookahPartyApp/1.0', 'Hookah Party app · iPhone', 'mobile'],
    ['Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1', 'Safari · iPad', 'tablet'],
    [UA.androidPhone, 'Chrome · Android', 'mobile'], [UA.androidTablet, 'Chrome · Android tablet', 'tablet'],
    ['Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36', 'Samsung Internet · Android', 'mobile'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0', 'Edge · Windows', 'desktop'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0', 'Opera · Windows', 'desktop'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 YaBrowser/24.10.0.0 Safari/537.36', 'Yandex Browser · Windows', 'desktop'],
    [UA.winFirefox, 'Firefox · Windows', 'desktop'], ['Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0', 'Firefox · Linux', 'desktop'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15', 'Firefox · iPhone', 'mobile'],
    ['Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Chrome · ChromeOS', 'desktop'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 325.0.0.35.91 (iPhone14,5; iOS 17_4; ru_RU)', 'Instagram · iPhone', 'mobile'],
    ['node', 'Unknown device', 'other'], ['curl/8.7.1', 'Unknown device', 'other'], ['', 'Unknown device', 'other'], [undefined, 'Unknown device', 'other']
  ];
  for (const [ua, label, device] of cases) {
    const d = parseUA(ua);
    assert.deepEqual([d.label, d.device], [label, device], String(ua));
    assert.match(d.fp, /^[0-9a-f]{64}$/);
  }
  const fp = ua => parseUA(ua).fp;
  assert.equal(fp(UA.macChrome), fp(UA.macChromeNew), 'обновление браузера — то же устройство');
  assert.equal(fp(UA.iphoneSafari), fp(UA.iphoneSafari.replace(/17_4/g, '18_1').replace('Version/17.4', 'Version/18.1')), 'обновление iOS — то же устройство');
  assert.notEqual(fp(UA.macChrome), fp(UA.macSafari), 'другой браузер на том же компьютере — другое устройство');
  assert.notEqual(fp(UA.androidPhone), fp(UA.androidTablet), 'телефон и планшет на Android — разные устройства');
  const t0 = Date.now(); parseUA('Mozilla/5.0 (Linux; Android '.repeat(20000));
  assert.ok(Date.now() - t0 < 100, 'длинный заголовок разбирается быстро');
  for (const [ip, masked] of [['95.56.12.34', '95.56.x.x'], ['::ffff:95.56.12.34', '95.56.x.x'], ['2a02:8109:b6c0:1234::1', '2a02:8109:b6c0:…'],
    ['2001:0db8:0000:0042::8a2e', '2001:db8:0:…'], ['::1', '0:0:0:…'], ['fe80::1%en0', 'fe80:0:0:…'], ['unknown', '?'], ['', '?'], [null, '?']])
    assert.equal(alerts.maskIp(ip), masked, String(ip));
});

test('сигналы владельцу: только администраторам из ADMIN_PHONES, один вид — не чаще раза в 30 минут', () => {
  alerts.resetAlerts();
  const t = Date.now();
  db.q("UPDATE users SET role = 'admin' WHERE id = 'u3'").run(); // роль в базе без номера в ADMIN_PHONES — не владелец
  try {
    assert.equal(alerts.alertAdmins(db, 'test_kind', 'первый', { now: t }), 1, 'сигнал получил один владелец');
    assert.equal(alerts.alertAdmins(db, 'test_kind', 'второй', { now: t + 29 * 60e3 }), 0, 'повтор в течение 30 минут не отправляется');
    assert.equal(alerts.alertAdmins(db, 'test_kind', 'третий', { now: t + 31 * 60e3 }), 1, 'через 30 минут — снова');
    assert.equal(alerts.alertAdmins(db, 'test_other', 'x\u0000y', { now: t }), 1, 'у другого вида свой счётчик');
    assert.deepEqual(alertsFor('test_kind'), ['test_kind:первый', 'test_kind:третий']);
    assert.deepEqual(alertsFor('test_other'), ['test_other:x y'], 'управляющие символы вырезаны');
    assert.equal(alertsFor('test_kind', 'u3').length, 0, 'роль admin без номера в ADMIN_PHONES сигналов не получает');
    const empty = open(':memory:');
    assert.equal(alerts.alertAdmins(empty, 'test_kind', 'x', { now: t + 99 * 60e3 }), 0, 'нет владельцев — некому отправить');
    empty.close();
  } finally {
    db.q("UPDATE users SET role = 'user' WHERE id = 'u3'").run();
    db.q("DELETE FROM notifications WHERE instr(ref, 'test_') = 1").run();
    alerts.resetAlerts();
  }
});

test('сигнал: вход заблокирован после 5 неверных паролей; вторая блокировка за 30 минут — только в журнале', async () => {
  alerts.resetAlerts();
  await addUser('uLk', '996555000444', 'Lock-Alert-2026');
  const before = alertsFor('login_locked').length, c = client();
  for (let i = 1; i <= 4; i++) assert.equal((await c.login('0555000444', 'wrong-pass1')).data.left, 5 - i);
  assert.equal(alertsFor('login_locked').length, before, '4 ошибки — ещё не повод');
  assert.equal((await c.login('0555000444', 'wrong-pass1')).data.error, 'locked');
  const refs = alertsFor('login_locked');
  assert.equal(refs.length, before + 1, 'владелец получил сигнал');
  assert.equal(refs.at(-1), 'login_locked:+996 ••• ••• 444 · 127.0.x.x', 'номер и адрес скрыты');
  assert.equal(db.q("SELECT COUNT(*) AS n FROM notifications WHERE type = 'security_alert' AND user_id != 'u1'").get().n, 0, 'обычным пользователям сигналы не приходят');
  for (let i = 0; i < 5; i++) await c.login('0555000445', 'wrong-pass1');
  assert.equal(alertsFor('login_locked').length, before + 1, 'вторая блокировка в течение 30 минут — без нового сигнала');
  assert.ok(db.q("SELECT 1 FROM audit WHERE type = 'lockout' AND detail = '+996 ••• ••• 445'").get(), 'но в журнале она есть');
  const owner = (await client().login('0700000001')).data.data;
  assert.ok(owner.notifications.some(n => n.type === 'security_alert' && n.ref === refs.at(-1) && n.actorId === null), 'сигнал приходит владельцу в уведомления');
});

test('сигнал: скрытую панель ищут 3 раза за 10 минут', async () => {
  alerts.resetAlerts();
  const before = alertsFor('admin_probe').length, c = client(); await c.login('0700000006');
  for (let i = 0; i < 2; i++) assert.equal((await c.call('GET', '/admin/overview')).status, 404);
  assert.equal(alertsFor('admin_probe').length, before, 'две попытки — ещё не повод');
  assert.equal((await c.call('POST', '/admin/unlock', { password: 'hookah' })).status, 404);
  assert.deepEqual(alertsFor('admin_probe').slice(before), ['admin_probe:+996 ••• ••• 006 · 127.0.x.x'], 'третья — сигнал владельцу');
  assert.equal((await c.call('GET', '/admin/overview')).status, 404);
  assert.equal(alertsFor('admin_probe').length, before + 1, 'дальше — не чаще раза в 30 минут');
});

test('сигналы: панель заблокирована после 5 ошибок; панель открыта с нового адреса', async () => {
  alerts.resetAlerts();
  // Второй владелец на время теста: у основного часовой лимит ошибок почти израсходован тестами выше.
  await addUser('uAdm3', '996555000777', 'Admin-Three-2026');
  db.q("UPDATE users SET role = 'admin' WHERE id = 'uAdm3'").run();
  const phones = process.env.ADMIN_PHONES, proxy = process.env.TRUST_PROXY;
  process.env.ADMIN_PHONES = phones + ',+996555000777';
  try {
    const c = client();
    assert.equal((await c.login('0555000777', 'Admin-Three-2026')).data.data.role, 'admin');
    const before = alertsFor('admin_lock').length;
    for (let i = 0; i < 4; i++) assert.equal((await c.call('POST', '/admin/unlock', { password: 'wrong-pass1' })).data.error, 'bad_password');
    assert.equal(alertsFor('admin_lock').length, before);
    assert.equal((await c.call('POST', '/admin/unlock', { password: 'wrong-pass1' })).data.error, 'locked');
    assert.deepEqual(alertsFor('admin_lock').slice(before), ['admin_lock:127.0.x.x'], 'сигнал владельцу');
    assert.deepEqual(alertsFor('admin_lock', 'uAdm3'), ['admin_lock:127.0.x.x'], 'и второму владельцу');
    require('../server/lib/guard').clearFails('admin:uAdm3');

    // Адрес — из X-Forwarded-For (за прокси). Первый вход в панель и знакомый адрес — без сигнала, каждый новый адрес — сигнал.
    process.env.TRUST_PROXY = '1';
    const unlock = ip => c.call('POST', '/admin/unlock', { password: 'Admin-Three-2026' }, { 'X-Forwarded-For': ip });
    assert.equal((await unlock('198.51.100.23')).status, 200);
    assert.deepEqual(alertsFor('admin_new_ip', 'uAdm3'), [], 'самый первый вход в панель — без сигнала');
    assert.equal((await unlock('198.51.100.23')).status, 200);
    assert.deepEqual(alertsFor('admin_new_ip', 'uAdm3'), [], 'знакомый адрес — без сигнала');
    assert.equal((await unlock('203.0.113.9')).status, 200);
    assert.equal((await unlock('192.0.2.44')).status, 200);
    assert.deepEqual(alertsFor('admin_new_ip', 'uAdm3'), ['admin_new_ip:203.0.x.x', 'admin_new_ip:192.0.x.x'], 'каждый новый адрес — свой сигнал, даже подряд');
    assert.equal(alertsFor('admin_new_ip', 'u1').length, 2, 'сигналы видят все владельцы');
  } finally {
    process.env.ADMIN_PHONES = phones;
    restoreEnv('TRUST_PROXY', proxy);
    db.q("DELETE FROM users WHERE id = 'uAdm3'").run();
  }
});

test('отчёты CSP: без входа, поля очищаются и обрезаются, лимит с адреса, всплеск — сигнал владельцу', async () => {
  alerts.resetAlerts();
  const guest = client(), count = () => db.q("SELECT COUNT(*) AS n FROM audit WHERE type = 'csp_violation'").get().n;
  const n0 = count(), burst0 = alertsFor('csp_burst').length;
  const last = () => db.q("SELECT * FROM audit WHERE type = 'csp_violation' ORDER BY id DESC").get();
  const r = await guest.call('POST', '/csp-report', { directive: 'script-src-elem', blocked: 'https://evil.example/steal.js?token=SECRET#x',
    sample: 'alert(document.cookie)\u0000\u001b[31m' + 'x'.repeat(200), src: 'https://hookah.example/app.js?v=12', line: '42', page: 'event' });
  assert.equal(r.status, 200);
  let row = last();
  assert.equal(row.user_id, null, 'вход не нужен');
  assert.equal(row.detail, `script-src-elem · https://evil.example · app.js:42 · #/event · «alert(document.cookie)[31m${'x'.repeat(34)}»`, 'от адреса — только сайт, образец кода — 60 символов без управляющих');
  assert.equal((await guest.call('POST', '/csp-report', { directive: '<img onerror=1>', blocked: 'javascript:alert(1)', sample: 42, src: '../../etc/passwd', line: 'abc', page: '<script>' })).status, 200);
  assert.equal(last().detail, '? · javascript · passwd:0 · #/? · «42»', 'мусор в полях не проходит');

  // От вошедшего — с привязкой к нему: событие видно в его журнале безопасности.
  const u = client(); await u.login('0700000005');
  assert.equal((await u.call('POST', '/csp-report', { directive: 'require-trusted-types-for', blocked: 'trusted-types-sink', sample: 'Element innerHTML|<img src=x>', src: 'app.js', line: 7, page: 'profile' })).status, 200);
  const mine = (await u.call('GET', '/security/log')).data.log[0];
  assert.deepEqual([mine.type, mine.detail, mine.ip], ['csp_violation', 'require-trusted-types-for · trusted-types-sink · app.js:7 · #/profile · «Element innerHTML|<img src=x>»', '127.0.x.x']);

  // С чужого сайта и в формате report-uri (application/csp-report) — нет: такие отчёты сервер не принимает.
  assert.equal((await guest.call('POST', '/csp-report', { directive: 'img-src' }, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await fetch(base + '/api/csp-report', { method: 'POST', headers: { 'Content-Type': 'application/csp-report' }, body: '{"csp-report":{}}' })).status, 415);
  assert.equal(count() - n0, 3);

  // Лимит: 20 отчётов с адреса в час, лишние не пишутся в журнал. Пятый за 10 минут — сигнал владельцу, дальше не чаще раза в 30 минут.
  let accepted = 3, over = null;
  while (!over) { const x = await guest.call('POST', '/csp-report', { directive: 'img-src', blocked: 'https://ads.example/pixel.gif', src: 'index.html', line: 1, page: 'home' }); if (x.status === 200) accepted++; else over = x; assert.ok(accepted <= 20); }
  assert.deepEqual([accepted, over.status, over.data.error], [20, 429, 'rate_limited']);
  assert.ok(over.data.retryAfter > 0);
  assert.equal(count() - n0, 20, 'отклонённые отчёты в журнал не попадают');
  assert.deepEqual(alertsFor('csp_burst').slice(burst0), ['csp_burst:img-src · https://ads.example'], 'один сигнал о всплеске');
});

test('вход с нового устройства: первое запоминается молча, новое — уведомление; «выйти везде» забывает другие', async () => {
  await addUser('uDev', '996555000666', 'Device-Test-2026');
  const proxy = process.env.TRUST_PROXY;
  process.env.TRUST_PROXY = '1';
  const as = (ua, ip) => ({ 'User-Agent': ua, 'X-Forwarded-For': ip });
  const login = (c, ua, ip) => c.call('POST', '/auth/login', { phone: '0555000666', password: 'Device-Test-2026' }, as(ua, ip));
  const notes = () => db.q("SELECT ref FROM notifications WHERE user_id = 'uDev' AND type = 'new_login' ORDER BY rowid").all().map(r => r.ref);
  const devices = () => db.q("SELECT label FROM known_devices WHERE user_id = 'uDev' ORDER BY label").all().map(r => r.label);
  try {
    assert.equal((await login(client(), UA.macChrome, '95.56.12.34')).status, 200);
    assert.deepEqual([devices(), notes()], [['Chrome · macOS'], []], 'первый вход: устройство запомнено без уведомления');
    const first = db.q("SELECT first_at, last_at FROM known_devices WHERE user_id = 'uDev'").get();
    await new Promise(r => setTimeout(r, 5));
    assert.equal((await login(client(), UA.macChromeNew, '95.56.77.1')).status, 200);
    assert.deepEqual([devices(), notes()], [['Chrome · macOS'], []], 'новая версия того же браузера — то же устройство, даже с другого адреса');
    const again = db.q("SELECT first_at, last_at FROM known_devices WHERE user_id = 'uDev'").get();
    assert.ok(again.first_at === first.first_at && again.last_at > first.last_at, 'обновлено только время последнего входа');

    const phone = client(), r = await login(phone, UA.iphoneSafari, '95.56.200.7');
    assert.equal(r.status, 200);
    assert.deepEqual(notes(), ['Safari · iPhone · 95.56.x.x'], 'вход с нового устройства — уведомление, адрес скрыт');
    const n = r.data.data.notifications.find(x => x.type === 'new_login');
    assert.ok(n && n.actorId === null && n.ref === 'Safari · iPhone · 95.56.x.x' && !n.read, 'уведомление сразу в данных пользователя');
    assert.ok(db.q("SELECT 1 FROM audit WHERE user_id = 'uDev' AND type = 'new_device_login' AND detail = 'Safari · iPhone'").get(), 'и в журнале безопасности');

    // Вход по SMS — то же правило; у IPv6-адреса — первые три группы.
    const pc = client(), v6 = as(UA.winFirefox, '2a02:8109:b6c0:1234::1');
    const sms = await pc.call('POST', '/auth/sms', { phone: '0555000666', purpose: 'login' }, v6);
    assert.equal((await pc.call('POST', '/auth/login-sms', { phone: '0555000666', code: sms.data.devCode, challenge: sms.data.challenge }, v6)).status, 200);
    assert.equal(notes().at(-1), 'Firefox · Windows · 2a02:8109:b6c0:…');

    // В настройках — свои устройства: подпись, первый и последний вход, «это устройство». Отпечатки наружу не отдаются.
    const sec = (await phone.call('GET', '/security/log', undefined, as(UA.iphoneSafari, '95.56.200.7'))).data;
    assert.deepEqual(sec.devices.map(d => [d.label, d.current]).sort(), [['Chrome · macOS', false], ['Firefox · Windows', false], ['Safari · iPhone', true]]);
    assert.ok(sec.devices.every(d => d.firstAt > 0 && d.lastAt >= d.firstAt && Object.keys(d).join() === 'label,firstAt,lastAt,current'), 'без отпечатков');
    assert.ok(sec.log.some(x => x.type === 'new_device_login' && x.ip === '95.56.x.x'), 'в журнале адрес скрыт');
    const other = client(); await other.login('0700000002');
    assert.deepEqual((await other.call('GET', '/security/log')).data.devices.map(d => d.label), ['Unknown device'], 'чужие устройства не видны');

    // «Выйти на всех устройствах» с телефона: остальные устройства забыты — вход с компьютера снова пришлёт уведомление.
    assert.equal((await phone.call('POST', '/auth/logout-all', {}, as(UA.iphoneSafari, '95.56.200.7'))).status, 200);
    assert.deepEqual(devices(), ['Safari · iPhone']);
    assert.equal((await login(client(), UA.macChrome, '95.56.12.34')).status, 200);
    assert.deepEqual(notes(), ['Safari · iPhone · 95.56.x.x', 'Firefox · Windows · 2a02:8109:b6c0:…', 'Chrome · macOS · 95.56.x.x']);
  } finally {
    restoreEnv('TRUST_PROXY', proxy);
  }
});

// ---------- Смена пароля и «Забыли пароль?» ----------
const changePass = (c, body, headers) => c.call('POST', '/me/password', body, headers);

test('смена пароля: нужен текущий; слабый и тот же не принимаются; другие сессии и устройства — долой, эта остаётся с новым токеном', async () => {
  await addUser('uPw1', '996555000801', 'Old-Pass-2026');
  const c = client(), other = client();
  assert.equal((await c.login('0555000801', 'Old-Pass-2026')).data.data.passwordResetAllowed, false, 'после входа паролем без текущего не сменить');
  assert.equal((await other.call('POST', '/auth/login', { phone: '0555000801', password: 'Old-Pass-2026' }, { 'User-Agent': UA.winFirefox })).status, 200);
  assert.deepEqual(db.q("SELECT label FROM known_devices WHERE user_id = 'uPw1' ORDER BY label").all().map(r => r.label), ['Firefox · Windows', 'Unknown device']);
  assert.equal((await client().call('POST', '/me/password', { current: 'Old-Pass-2026', next: 'New-Pass-2027' })).status, 401, 'без входа нельзя');

  // Новый пароль и пустой текущий проверяются до текущего: такие ошибки попыток не тратят.
  for (const [body, error] of [
    [{ current: 'Old-Pass-2026', next: 'short1' }, 'weak_length'], [{ current: 'Old-Pass-2026', next: 'onlyletters' }, 'weak_mix'],
    [{ current: 'Old-Pass-2026', next: 'Hookah-2027' }, 'weak_common'], [{ current: 'Old-Pass-2026', next: 'x555000801' }, 'weak_phone'],
    [{ current: 'Old-Pass-2026', next: ['New-Pass-2027'] }, 'weak_length'], [{ current: 'Old-Pass-2026', next: 'Old-Pass-2026' }, 'same_password'],
    [{ next: 'New-Pass-2027' }, 'current_required'], [{ current: '', next: 'New-Pass-2027' }, 'current_required']]) {
    const r = await changePass(c, body);
    assert.deepEqual([r.status, r.data.error], [400, error], JSON.stringify(body));
  }
  const wrong = await changePass(c, { current: 'wrong-pass1', next: 'New-Pass-2027' });
  assert.deepEqual([wrong.status, wrong.data.error, wrong.data.left], [401, 'bad_password', 4], 'первая настоящая ошибка — осталось 4 попытки');
  require('../server/lib/guard').clearFails('pass:uPw1');

  // CSRF-токен и свой Origin обязательны.
  const before = c.jar();
  const raw = headers => fetch(base + '/api/me/password', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: before.cookie, ...headers }, body: JSON.stringify({ current: 'Old-Pass-2026', next: 'New-Pass-2027' }) });
  assert.equal((await raw({})).status, 403, 'без CSRF-токена — нет');
  assert.equal((await raw({ 'X-CSRF-Token': before.csrf, Origin: 'https://evil.example' })).status, 403, 'с чужого сайта — нет');

  const ok = await changePass(c, { current: 'Old-Pass-2026', next: 'New-Pass-2027' });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal(ok.data.ended, 1, 'завершена одна другая сессия');
  assert.equal(ok.data.data.session, 'uPw1', 'эта сессия на месте');
  assert.equal(ok.data.data.passwordResetAllowed, false);
  const after = c.jar();
  assert.ok(after.cookie !== before.cookie && after.csrf && after.csrf !== before.csrf, 'у этой сессии новый токен и новый CSRF-токен');
  const note = ok.data.data.notifications.find(n => n.type === 'password_changed');
  assert.ok(note && note.actorId === null && note.eventId === null && note.ref === 'Unknown device · 127.0.x.x' && !note.read, 'уведомление «Пароль изменён»: устройство и адрес без последних цифр');
  assert.equal((await c.call('GET', '/security/log')).status, 200, 'эта сессия работает дальше');
  assert.equal((await fetch(base + '/api/security/log', { headers: { Cookie: before.cookie } })).status, 401, 'копия прежнего cookie больше не действует');
  assert.equal((await other.call('GET', '/security/log')).status, 401, 'другая сессия завершена');
  assert.equal(db.q("SELECT COUNT(*) AS n FROM sessions WHERE user_id = 'uPw1'").get().n, 1);
  assert.deepEqual(db.q("SELECT label FROM known_devices WHERE user_id = 'uPw1'").all().map(r => r.label), ['Unknown device'], 'другие устройства забыты: вход с них снова пришлёт уведомление');

  assert.equal((await client().login('0555000801', 'Old-Pass-2026')).data.error, 'bad_credentials', 'старый пароль больше не подходит');
  assert.equal((await client().login('0555000801', 'New-Pass-2027')).status, 200, 'новый — подходит');
  const log = (await c.call('GET', '/security/log')).data.log;
  assert.ok(log.some(x => x.type === 'password_changed' && x.ip === '127.0.x.x' && x.detail === ''), 'смена — в журнале безопасности');
  assert.ok(log.some(x => x.type === 'password_change_fail'), 'и неверный текущий пароль тоже');
});

test('смена пароля: 5 неверных текущих — блокировка на 5 минут; неверные — в общем с входом счётчике номера, вход по SMS остаётся', async () => {
  await addUser('uPw2', '996555000802', 'Lock-Pass-2026');
  const guard = require('../server/lib/guard');
  const c = client(); assert.equal((await c.login('0555000802', 'Lock-Pass-2026')).status, 200);
  for (let i = 1; i <= 4; i++) {
    const r = await changePass(c, { current: 'wrong-pass1', next: 'New-Pass-2027' });
    assert.deepEqual([r.status, r.data.error, r.data.left], [401, 'bad_password', 5 - i], 'попытка ' + i);
  }
  const fifth = await changePass(c, { current: 'wrong-pass1', next: 'New-Pass-2027' });
  assert.deepEqual([fifth.status, fifth.data.error, fifth.data.left], [401, 'locked', 0]);
  const locked = await changePass(c, { current: 'Lock-Pass-2026', next: 'New-Pass-2027' });
  assert.deepEqual([locked.status, locked.data.error], [429, 'locked'], 'во время блокировки не принимается даже верный пароль');
  assert.ok(locked.data.retryAfter > 0);
  assert.equal((await c.call('GET', '/security/log')).status, 200, 'сессия не тронута');
  assert.equal((await client().login('0555000802', 'Lock-Pass-2026')).status, 200, 'пароль прежний');
  assert.deepEqual(db.q("SELECT type FROM audit WHERE user_id = 'uPw2' AND type LIKE 'password%' ORDER BY id").all().map(r => r.type),
    ['password_change_fail', 'password_change_fail', 'password_change_fail', 'password_change_fail', 'password_change_locked'], 'попытки в журнале');

  // Счётчик номера — 17 неверных паролей в час на всё вместе: уже 5 (удачные входы и отказ во время блокировки не считаются).
  guard.clearFails('pass:uPw2');
  let tries = 0, r;
  do { r = await changePass(c, { current: 'wrong-pass1', next: 'New-Pass-2027' }); if (++tries % 4 === 0) guard.clearFails('pass:uPw2'); } while (r.status === 401 && tries < 30);
  assert.deepEqual([r.status, r.data.error, tries], [429, 'rate_limited', 13], 'восемнадцатый неверный пароль за час — уже не проверяется');
  const login = await client().login('0555000802', 'Lock-Pass-2026');
  assert.deepEqual([login.status, login.data.error], [429, 'rate_limited'], 'и вход паролем с этим номером упирается в тот же счётчик');
  assert.match(login.data.message.ru, /по коду из SMS/, 'с подсказкой про вход по SMS');
  // А вход по коду из SMS открыт: код доказывает, что телефон у владельца.
  const s = client(), sms = (await s.call('POST', '/auth/sms', { phone: '0555000802', purpose: 'login' })).data;
  const viaSms = await s.call('POST', '/auth/login-sms', { phone: '0555000802', code: sms.devCode, challenge: sms.challenge });
  assert.deepEqual([viaSms.status, viaSms.data.data?.session], [200, 'uPw2'], 'вход по SMS работает');
  guard.clearFails('pass:uPw2');
});

test('«Забыли пароль?»: после входа по SMS 15 минут пароль меняется без текущего, потом — только с ним', async () => {
  await addUser('uPw3', '996555000803', 'Sms-Pass-2026');
  const pw = client(); assert.equal((await pw.login('0555000803', 'Sms-Pass-2026')).status, 200);
  const c = client();
  const sms = await c.call('POST', '/auth/sms', { phone: '0555000803', purpose: 'login' });
  const login = await c.call('POST', '/auth/login-sms', { phone: '0555000803', code: sms.data.devCode, challenge: sms.data.challenge });
  assert.equal(login.status, 200);
  assert.equal(login.data.data.passwordResetAllowed, true, 'после входа по SMS — можно без текущего');
  const smsAt = () => db.q("SELECT via_sms_at FROM sessions WHERE user_id = 'uPw3' ORDER BY created_at, rowid").all().map(r => r.via_sms_at);
  const [atPw, atSms] = smsAt();
  assert.ok(atPw === 0 && atSms > 0 && Date.now() - atSms < 60e3, 'время входа по SMS записано только в его сессии');

  const setAgo = ms => db.q("UPDATE sessions SET via_sms_at = ? WHERE user_id = 'uPw3' AND via_sms_at > 0").run(Date.now() - ms);
  setAgo(16 * 60e3);
  assert.equal((await c.call('GET', '/bootstrap')).data.passwordResetAllowed, false, '16 минут спустя — уже нельзя');
  const late = await changePass(c, { next: 'Fresh-Pass-2027' });
  assert.deepEqual([late.status, late.data.error], [400, 'current_required']);
  setAgo(14 * 60e3);
  assert.equal((await c.call('GET', '/bootstrap')).data.passwordResetAllowed, true, '14 минут спустя — ещё можно');
  // Блокировка за неверные текущие пароли (здесь — из сессии входа паролем) смене после входа по SMS не мешает:
  // текущий пароль тут не проверяется, а «Забыли пароль?» как раз для того, кто его не помнит.
  for (let i = 0; i < 5; i++) await changePass(pw, { current: 'wrong-pass1', next: 'Fresh-Pass-2027' });
  assert.equal((await changePass(pw, { current: 'Sms-Pass-2026', next: 'Fresh-Pass-2027' })).data.error, 'locked', 'сессия входа паролем заблокирована');
  const same = await changePass(c, { next: 'Sms-Pass-2026' });
  assert.deepEqual([same.status, same.data.error], [400, 'same_password'], 'прежний пароль не принимается и без текущего');

  const ok = await changePass(c, { next: 'Fresh-Pass-2027' });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal(ok.data.data.passwordResetAllowed, false, 'после смены — снова только с текущим');
  assert.deepEqual(smsAt(), [0], 'сессия входа паролем завершена, у этой время входа по SMS сброшено');
  assert.equal((await pw.call('GET', '/security/log')).status, 401);
  assert.ok(ok.data.data.notifications.some(n => n.type === 'password_changed'), 'уведомление пришло');
  assert.equal(db.q("SELECT detail FROM audit WHERE user_id = 'uPw3' AND type = 'password_changed'").get().detail, 'sms');
  assert.equal((await changePass(c, { next: 'Other-Pass-2028' })).data.error, 'current_required', 'второй раз без текущего — нельзя');
  assert.equal((await client().login('0555000803', 'Fresh-Pass-2027')).status, 200, 'новый пароль работает');
});

test('консоль: delete без --yes только показывает, что удалится; с --yes удаляет аккаунт как «Удаление аккаунта» в настройках', async () => {
  // Отдельная временная база и одноразовый ключ данных; настоящий .env не читается (--env — пустой временный файл),
  // окружение дочернего процесса собрано с нуля.
  const { spawnSync } = require('node:child_process');
  const { makeKeyring } = require('../server/lib/secure');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-cli-'));
  const key = require('node:crypto').randomBytes(32), kr = makeKeyring(key);
  const file = path.join(dir, 'cli.db'), envFile = path.join(dir, 'test.env');
  fs.writeFileSync(envFile, '# пустой файл настроек для теста\n', { mode: 0o600 });
  const now = Date.now(), iso = ms => new Date(ms).toISOString();
  const t = open(file);
  const user = (id, name, phone) => t.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, name, kr.encrypt(phone), kr.phoneIndex(phone), phone.slice(-3), 'x', iso(now - 864e5));
  user('uGone', 'Уходящий', '996555000901'); user('uStay', 'Остаётся', '996555000902'); user('uMaybe', 'Может', '996555000903');
  const ev = (id, title, at, host) => t.q('INSERT INTO events (id, title, venue, at, host_id, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, title, 'Hookah', iso(at), host, iso(now));
  const inv = (eid, uid, status) => t.q('INSERT INTO invites (event_id, user_id, status) VALUES (?, ?, ?)').run(eid, uid, status);
  ev('eUp', 'Его сбор', now + 2 * 864e5, 'uGone'); inv('eUp', 'uStay', 'going'); inv('eUp', 'uMaybe', 'pending');
  ev('ePast', 'Старый вечер', now - 10 * 864e5, 'uGone'); inv('ePast', 'uStay', 'going');
  ev('eOther', 'Чужой сбор', now + 3 * 864e5, 'uStay'); inv('eOther', 'uGone', 'going');
  t.q("INSERT INTO comments VALUES ('cG1', 'eOther', 'uGone', 'ev', 'Приду', ?)").run(iso(now));
  t.q("INSERT INTO comments VALUES ('cS1', 'eUp', 'uStay', 'ev', 'Жду', ?)").run(iso(now));
  for (const [a, b] of [['uGone', 'uStay'], ['uStay', 'uGone']]) t.q('INSERT INTO friends VALUES (?, ?)').run(a, b);
  t.q("INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen) VALUES ('tG', 'uGone', 'c', ?, ?, ?)").run(now, now + 864e5, now);
  t.q("INSERT INTO audit (at, user_id, ip, type, detail) VALUES (?, 'uGone', '95.56.1.2', 'login_ok', '')").run(iso(now - 60e3));
  const idx = kr.phoneIndex('996555000901');
  const counts = () => Object.fromEntries(t2().q("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map(({ name }) => [name, t2().q(`SELECT COUNT(*) AS n FROM "${name}"`).get().n]));
  t.close();
  let reader = null; const t2 = () => (reader ||= open(file));
  const before = counts(); reader.close(); reader = null;

  const env = { PATH: process.env.PATH, NODE_ENV: 'test', DB_PATH: file, DATA_KEY: key.toString('base64') };
  const cli = (...args) => spawnSync(process.execPath, [path.join(__dirname, '..', 'server', 'admin.js'), ...args, '--env', envFile], { env, encoding: 'utf8', timeout: 60e3 });
  try {
    const usage = cli();
    assert.match(usage.stdout, /delete <номер> \[--yes\]/, 'команда есть в подсказке');
    const dry = cli('delete', '+996 555 000 901');
    assert.equal(dry.status, 2, 'без --yes — ненулевой код выхода: ' + dry.stderr);
    assert.match(dry.stdout, /Будет удалён аккаунт: Уходящий \(\+996 ••• ••• 901\)/);
    assert.match(dry.stdout, /сборы, которые он организует: 2 \(предстоящих: 1; гостей, которым придёт уведомление об отмене: 1\)/);
    assert.match(dry.stdout, /сообщения и комментарии: 1;.*друзья: 1;/);
    assert.match(dry.stdout, /активные сессии: 1/);
    assert.match(dry.stdout, /--yes/);
    assert.ok(!dry.stdout.includes('996555000901') && !dry.stdout.includes('555 000 901'), 'полный номер не выводится');
    assert.deepEqual(counts(), before, 'без --yes в базе ничего не изменилось');
    reader.close(); reader = null;
    const bad = cli('delete', '123', '--yes');
    assert.deepEqual([bad.status, /номер/.test(bad.stderr)], [1, true], 'неверный номер — ошибка');
    const unknown = cli('delete', '+996555000999', '--yes');
    assert.deepEqual([unknown.status, /не найден/.test(unknown.stderr)], [1, true], 'незнакомый номер — ошибка');

    const done = cli('delete', '0555000901', '--yes');
    assert.equal(done.status, 0, done.stderr);
    assert.match(done.stdout, /Аккаунт удалён: Уходящий \(\+996 ••• ••• 901\).*\nСборов удалено: 2; уведомлений об отмене гостям: 1\./);

    const d = t2();
    const tables = d.q("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map(r => r.name);
    const traces = tables.flatMap(tb => d.q(`PRAGMA table_info("${tb}")`).all().map(c => [tb, c.name, d.q(`SELECT COUNT(*) AS n FROM "${tb}" WHERE instr(CAST("${c.name}" AS TEXT), ?) > 0 OR "${c.name}" = ?`).get('uGone', idx).n])).filter(x => x[2] > 0);
    assert.deepEqual(traces, [], 'ни в одной таблице нет ни его id, ни индекса номера');
    assert.deepEqual(d.q("SELECT id FROM events ORDER BY id").all().map(r => r.id), ['eOther'], 'его сборы удалены, чужой на месте');
    assert.deepEqual(d.q("SELECT user_id, type, actor_id, event_id, ref FROM notifications").all().map(r => ({ ...r })),
      [{ user_id: 'uStay', type: 'cancelled', actor_id: null, event_id: null, ref: 'Его сбор' }], 'уведомление об отмене — только гостю, который шёл на предстоящий сбор');
    const gone = d.q("SELECT * FROM audit WHERE type = 'account_deleted'").get();
    assert.deepEqual([gone.user_id, gone.ip, gone.detail], [null, 'console', '+996 ••• ••• 901 · console'], 'удаление в журнале: из консоли, номер скрыт');
    assert.equal(d.q("SELECT user_id FROM audit WHERE type = 'login_ok'").get().user_id, null, 'прежние записи журнала обезличены');
    assert.deepEqual(d.q('SELECT id FROM users ORDER BY id').all().map(r => r.id), ['uMaybe', 'uStay']);
    reader.close(); reader = null;
    assert.equal(cli('delete', '0555000901', '--yes').status, 1, 'повторно — «не найден»');
  } finally {
    reader?.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- Приватность: номера, справочник людей, рассказы, ссылки, фото, сроки хранения ----------
const fut = (d = 2) => new Date(Date.now() + d * 864e5).toISOString();
// Пользователь прямо в базе (лимит регистраций с одного адреса в этом файле уже почти выбран) и вошедший клиент для него.
async function person(id, phone) {
  await addUser(id, phone, 'Privacy-Pass-2026');
  const c = client(), r = await c.login(phone, 'Privacy-Pass-2026');
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return c;
}
const boot = async c => (await c.call('GET', '/bootstrap')).data;
const userIn = (d, id) => d.users.find(u => u.id === id);

test('номер: дружба в одну сторону номера не открывает, только взаимная; уведомление о дружбе — одно', async () => {
  const a = await person('uPrA', '996555010001'), b = await person('uPrB', '996555010002');
  let r = await a.call('POST', '/friends/uPrB');
  assert.equal(r.status, 200);
  assert.deepEqual([userIn(r.data.data, 'uPrB').phone, userIn(r.data.data, 'uPrB').phoneMasked], [null, '+996 ••• ••• 002'], 'добавил сам — видны только последние цифры');
  assert.deepEqual(userIn(r.data.data, 'uPrA').friends, ['uPrB'], 'свой список друзей приходит');
  assert.ok(r.data.data.users.every(u => u.id === 'uPrA' || !('friends' in u)), 'чужие списки друзей — нет');
  for (let i = 0; i < 4; i++) await a.call('POST', '/friends/uPrB'); // туда-обратно: в конце снова «в друзьях»
  assert.equal(db.q("SELECT COUNT(*) AS n FROM notifications WHERE user_id = 'uPrB' AND actor_id = 'uPrA' AND type = 'friend'").get().n, 1, 'уведомление одно, сколько ни нажимай');
  assert.equal(userIn(await boot(b), 'uPrA').phone, null, 'и тот, кого добавили, номера не видит');
  r = await b.call('POST', '/friends/uPrA');
  assert.equal(userIn(r.data.data, 'uPrA').phone, '996555010001', 'добавили друг друга — номер виден');
  assert.equal(userIn(await boot(a), 'uPrB').phone, '996555010002', 'обоим');
  await a.call('POST', '/friends/uPrB');
  assert.equal(userIn(await boot(b), 'uPrA').phone, null, 'один убрал — номера снова скрыты');
  assert.equal(userIn(await boot(a), 'uPrB').phone, null);
});

test('номер: кто не ответил или отказался, номеров не получает; «иду» открывает номера организатора и гостя друг другу', async () => {
  const host = await person('uPrH', '996555010011'), g1 = await person('uPrG1', '996555010012'), g2 = await person('uPrG2', '996555010013');
  // Посторонний зовёт людей к себе, чтобы узнать их номера (атака из аудита), — не выходит.
  const eid = (await host.call('POST', '/events', { title: 'Номера', venue: 'Hookah', at: fut(), invites: [{ userId: 'uPrG1' }, { userId: 'uPrG2' }, { userId: 'u3' }] })).data.id;
  let hb = await boot(host), g1b = await boot(g1);
  assert.deepEqual(['uPrG1', 'uPrG2', 'u3'].map(id => userIn(hb, id).phone), [null, null, null], 'ждём ответа — номеров приглашённых организатор не видит');
  assert.deepEqual(['uPrH', 'uPrG2', 'u3'].map(id => userIn(g1b, id).phone), [null, null, null], 'приглашённый — ни организатора, ни соседей');
  await g1.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  await g2.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  hb = await boot(host); g1b = await boot(g1);
  assert.equal(userIn(hb, 'uPrG1').phone, '996555010012', 'идёт — организатор видит его номер');
  assert.equal(userIn(g1b, 'uPrH').phone, '996555010011', 'а он — номер организатора');
  assert.equal(userIn(g1b, 'uPrG2').phone, null, 'двое гостей номеров друг друга не видят');
  assert.equal(userIn(hb, 'u3').phone, null, 'не ответивший — по-прежнему нет');
  await g1.call('POST', `/events/${eid}/rsvp`, { status: 'declined' });
  assert.equal(userIn(await boot(host), 'uPrG1').phone, null, 'отказался — номер снова скрыт');
  assert.equal(userIn(await boot(g1), 'uPrH').phone, null, 'и номер организатора тоже');
});

test('приглашение по номеру не выдаёт, чей это номер, пока человек не ответит; номер целиком — организатору и позвавшему', async () => {
  const host = await person('uPrPh', '996555010031'), owner = await person('uPrOw', '996555010032'), guest = await person('uPrGu', '996555010033');
  const eid = (await host.call('POST', '/events', { title: 'По номеру', venue: 'Hookah', at: fut(), invites: [{ phone: '0555010032' }, { phone: '0555010099' }, { userId: 'uPrGu' }] })).data.id;
  const view = async c => (await boot(c)).events.find(e => e.id === eid);
  let e = await view(host);
  assert.ok(!e.invites.some(i => i.userId === 'uPrOw'), 'организатор не видит, чей номер');
  assert.deepEqual(e.invites.filter(i => !i.userId).map(i => [i.phone, i.phoneMasked, i.status]).sort(),
    [['996555010032', '+996 ••• ••• 032', 'pending'], ['996555010099', '+996 ••• ••• 099', 'pending']], 'зарегистрирован номер или нет — выглядит одинаково');
  const o = await view(owner);
  assert.ok(o?.member && o.invites.some(i => i.userId === 'uPrOw' && i.status === 'pending'), 'владелец номера видит приглашение как своё');
  assert.ok((await boot(owner)).notifications.some(n => n.type === 'invite' && n.eventId === eid), 'и получил уведомление');
  await guest.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  await guest.call('POST', `/events/${eid}/invites`, { invites: [{ phone: '0555010098' }] });
  const ge = await view(guest);
  assert.deepEqual([ge.invites.filter(i => !i.userId).length, ge.invites.filter(i => !i.userId && i.phone).map(i => i.phone)], [3, ['996555010098']], 'гость видит целиком только номер, который ввёл сам');
  assert.ok((await view(host)).invites.some(i => i.phone === '996555010098'), 'организатор — все');
  await owner.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  e = await view(host);
  assert.deepEqual(e.invites.filter(i => i.userId === 'uPrOw').map(i => i.status), ['going'], 'ответил — теперь видно, кто это');
  assert.ok(!e.invites.some(i => i.phone === '996555010032'), 'строка «по номеру» стала обычной');
  assert.equal(userIn(await boot(host), 'uPrOw').phone, '996555010032', 'и он идёт — номер виден организатору');
});

test('приглашения: не больше 60 в сборе, каким путём ни зови', async () => {
  const host = await person('uPrCap', '996555010021');
  const eid = (await host.call('POST', '/events', { title: 'Много', venue: 'Hookah', at: fut() })).data.id;
  const batch = from => ({ invites: Array.from({ length: 30 }, (_, i) => ({ phone: '996555' + String(500000 + from + i) })) });
  assert.equal((await host.call('POST', `/events/${eid}/invites`, batch(0))).status, 200);
  assert.equal((await host.call('POST', `/events/${eid}/invites`, batch(30))).status, 200);
  const over = await host.call('POST', `/events/${eid}/invites`, { invites: [{ userId: 'u4' }] });
  assert.deepEqual([over.status, over.data.error], [409, 'event_full']);
  assert.equal(db.q('SELECT COUNT(*) AS n FROM invites WHERE event_id = ?').get(eid).n, 60);
});

test('справочник: гостю без входа — только те, кто «на виду», и только имя с фото; вошедшему — люди без чужих списков друзей', async () => {
  const quiet = await person('uPrQ', '996555010051');
  const anon = await boot(client());
  const publicIds = db.q(`SELECT host_id AS id FROM events WHERE id IN (SELECT event_id FROM stories) UNION SELECT user_id FROM comments WHERE kind = 'story'
    UNION SELECT user_id FROM reviews UNION SELECT author_id FROM mixes`).all().map(r => r.id).sort();
  assert.deepEqual(anon.users.map(u => u.id).sort(), publicIds, 'ровно организаторы рассказов и авторы комментариев, отзывов и миксов');
  assert.ok(!anon.users.some(u => u.id === 'uPrQ'), 'новичка без публикаций гость не видит');
  assert.ok(anon.users.every(u => Object.keys(u).sort().join() === 'avatar,id,name'), 'только имя и фото');
  assert.ok(!/createdAt|"friends"|phoneMasked|favVenue|"favs"/.test(JSON.stringify(anon)), 'ни дат регистрации, ни друзей, ни цифр номеров, ни избранного');
  const me = await boot(quiet);
  assert.ok(userIn(me, 'u1') && userIn(me, 'u6'), 'вошедшему — справочник людей');
  assert.ok(me.users.every(u => (u.id === 'uPrQ') === ('friends' in u)), 'список друзей — только свой');
  assert.ok(me.users.every(u => !('createdAt' in u)), 'дат регистрации нет');
});

test('рассказ: чужой вечер из «Истории» — без адреса, описания, гостей, их голосов и оплат; итоги — только числа', async () => {
  const host = await person('uPrSt', '996555010061'), g = await person('uPrSg', '996555010062');
  const eid = (await host.call('POST', '/events', { title: 'Дома у меня', venue: 'Квартира', address: 'ул. Киевская 95, кв. 14', desc: 'Код домофона 14К', mapUrl: 'https://2gis.kg/bishkek/geo/12345',
    at: new Date(Date.now() + 3600e3).toISOString(), hookahs: 2, price: 1000, invites: [{ userId: 'uPrSg' }, { phone: '0555010069' }] })).data.id;
  await g.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  await g.call('PUT', `/events/${eid}/picks`, { ids: ['od-cola', 'tg-canemint'] });
  await host.call('PUT', `/events/${eid}/picks`, { ids: ['od-cola'] });
  await g.call('PUT', `/events/${eid}/bowl`, { bowlId: 'b-killer' });
  await host.call('POST', `/events/${eid}/paid/uPrSg`);
  db.q('UPDATE events SET at = ? WHERE id = ?').run(new Date(Date.now() - 5 * 3600e3).toISOString(), eid);
  assert.equal((await host.call('POST', `/events/${eid}/story`, { rating: 5, text: 'Отличный вечер, все довольны, повторим обязательно.', highlights: [] })).status, 200);
  await g.call('POST', `/events/${eid}/story/fire`);
  for (const [who, c] of [['гость без входа', client()], ['вошедший не участник', await person('uPrSo', '996555010063')]]) {
    const e = (await boot(c)).events.find(x => x.id === eid);
    assert.ok(e, who + ': вечер есть в «Истории»');
    assert.deepEqual(Object.keys(e).sort(), ['at', 'bowls', 'comments', 'hookahs', 'hostId', 'id', 'invites', 'member', 'notified', 'paid', 'picks', 'price', 'remind', 'story', 'summary', 'title', 'venue', 'venueId'], who + ': только нужное рассказу');
    assert.deepEqual([e.invites, e.picks, e.bowls, e.paid, e.comments], [[], {}, {}, {}, []], who + ': ни гостей, ни голосов, ни оплат, ни обсуждения');
    assert.deepEqual(e.summary, { going: 2, tobaccos: { 'od-cola': 2, 'tg-canemint': 1 }, bowls: { 'b-killer': 1 } }, who + ': итоги — числа');
    assert.deepEqual([e.story.fire, e.story.fired], [1, false], who + ': «огонь» — числом');
    assert.ok(!/Киевская|домофон|2gis|996555|uPrSg/.test(JSON.stringify(e)), who + ': ни адреса, ни описания, ни номеров, ни гостей');
  }
  const mine = (await boot(g)).events.find(x => x.id === eid);
  assert.equal(mine.address, 'ул. Киевская 95, кв. 14', 'участник видит свой вечер целиком');
  assert.deepEqual([mine.picks.uPrSg.sort(), mine.story.fire, mine.story.fired], [['od-cola', 'tg-canemint'], 1, true]);
});

test('ссылка и состав: организатор меняет ссылку и убирает гостя; убранный не возвращается по ссылке; ссылка прошедшего сбора не работает', async () => {
  const host = await person('uPrLh', '996555010071'), guest = await person('uPrLg', '996555010072'), stranger = await person('uPrLs', '996555010073');
  const eid = (await host.call('POST', '/events', { title: 'Ссылка', venue: 'Hookah', at: fut(), invites: [{ userId: 'uPrLg' }] })).data.id;
  await guest.call('POST', `/events/${eid}/rsvp`, { status: 'going' });
  const t1 = (await guest.call('POST', `/events/${eid}/link`)).data.token;
  assert.match(t1, /^[\w-]{24}$/, 'идущий гость по-прежнему зовёт ссылкой');
  assert.equal((await guest.call('POST', `/events/${eid}/link/reset`)).status, 403, 'сменить ссылку может только организатор');
  assert.equal((await stranger.call('POST', '/join/' + t1, { status: 'declined' })).status, 200, 'чужой пришёл по пересланной ссылке');
  const t2 = (await host.call('POST', `/events/${eid}/link/reset`)).data.token;
  assert.ok(t2 && t2 !== t1, 'новая ссылка');
  assert.equal((await client().call('GET', '/join/' + t1)).status, 404, 'старая больше не открывается');
  assert.equal((await guest.call('POST', `/events/${eid}/link`)).data.token, t2, 'гости делятся уже новой');
  assert.equal((await guest.call('DELETE', `/events/${eid}/invites`, { userId: 'uPrLs' })).status, 403, 'убрать может только организатор');
  const rm = await host.call('DELETE', `/events/${eid}/invites`, { userId: 'uPrLs' });
  assert.equal(rm.status, 200);
  assert.ok(!rm.data.data.events.find(e => e.id === eid).invites.some(i => i.userId === 'uPrLs'));
  const sb = await boot(stranger);
  assert.ok(!sb.events.some(e => e.id === eid), 'убранный больше не видит сбор');
  assert.ok(sb.notifications.some(n => n.type === 'removed' && n.actorId === 'uPrLh' && n.ref === 'Ссылка'), 'и получил уведомление');
  assert.equal((await stranger.call('POST', `/events/${eid}/comments`, { text: 'я тут' })).status, 403, 'в обсуждение не пишет');
  const back = await stranger.call('POST', '/join/' + t2, { status: 'going' });
  assert.deepEqual([back.status, back.data.error], [403, 'removed'], 'по ссылке не вернуться');
  assert.equal((await stranger.call('GET', '/join/' + t2)).data.status, 'removed');
  await guest.call('POST', `/events/${eid}/invites`, { invites: [{ userId: 'uPrLs' }] });
  assert.ok(!(await boot(stranger)).events.some(e => e.id === eid), 'гость вернуть убранного не может');
  await host.call('POST', `/events/${eid}/invites`, { invites: [{ userId: 'uPrLs' }] });
  assert.ok((await boot(stranger)).events.some(e => e.id === eid), 'организатор позвал снова — человек вернулся');
  await host.call('POST', `/events/${eid}/invites`, { invites: [{ phone: '0555010079' }] });
  assert.equal((await host.call('DELETE', `/events/${eid}/invites`, { phone: '0555010079' })).status, 200, 'приглашение по номеру убирается по номеру');
  assert.equal(db.q('SELECT COUNT(*) AS n FROM invites WHERE event_id = ? AND user_id IS NULL').get(eid).n, 0);
  assert.equal((await host.call('DELETE', `/events/${eid}/invites`, { phone: '0555010079' })).status, 404);
  assert.equal((await host.call('DELETE', `/events/${eid}/invites`, { userId: 'uPrLh' })).status, 404, 'себя не убрать');
  db.q('UPDATE events SET at = ? WHERE id = ?').run(new Date(Date.now() - 5 * 3600e3).toISOString(), eid);
  assert.equal((await client().call('GET', '/join/' + t2)).status, 404, 'сбор прошёл — ссылка не открывается');
  assert.equal((await stranger.call('POST', '/join/' + t2, { status: 'going' })).status, 404, 'и ответов не принимает');
});

test('фото: в bootstrap только версия, картинка — отдельным адресом и только тем, кто видит имя; размер и формат проверяются', async () => {
  const a = await person('uPrAv', '996555010041');
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
  const big = await a.call('PUT', '/me/avatar', { dataUrl: 'data:image/png;base64,' + Buffer.concat([png, Buffer.alloc(110 * 1024)]).toString('base64') });
  assert.deepEqual([big.status, big.data.error], [400, 'bad_avatar'], 'больше 100 КБ — нельзя');
  assert.equal((await a.call('PUT', '/me/avatar', { dataUrl: 'data:image/png;base64,' + Buffer.from('<svg onload=alert(1)></svg>').toString('base64') })).status, 400, 'не картинка под видом PNG');
  const r = await a.call('PUT', '/me/avatar', { dataUrl: 'data:image/png;base64,' + png.toString('base64') });
  assert.equal(r.status, 200);
  const v = userIn(r.data.data, 'uPrAv').avatar;
  assert.match(v, /^[0-9a-f]{16}$/, 'в данных — версия фото');
  assert.ok(!JSON.stringify(r.data).includes('data:image'), 'ни одной картинки в bootstrap');
  const other = client(); assert.equal((await other.login('0700000002')).status, 200);
  const get = (headers = {}) => fetch(`${base}/api/avatar/uPrAv?v=${v}`, { headers });
  const res = await get({ Cookie: other.jar().cookie });
  assert.equal(res.status, 200, 'вошедший видит фото любого');
  assert.deepEqual([res.headers.get('content-type'), res.headers.get('x-content-type-options'), res.headers.get('etag')], ['image/png', 'nosniff', `"${v}"`]);
  assert.match(res.headers.get('cache-control'), /^private, max-age=\d+$/);
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), png);
  assert.equal((await get({ Cookie: other.jar().cookie, 'If-None-Match': `"${v}"` })).status, 304, 'повтор — 304 без картинки');
  assert.equal((await get()).status, 404, 'гость без входа — 404: человек не «на виду»');
  await a.call('PUT', '/reviews/od-cola', { rating: 5, text: 'Хорошо' });
  assert.equal((await get()).status, 200, 'автор отзыва «на виду» — фото видно и гостю');
  assert.ok((await boot(client())).users.some(u => u.id === 'uPrAv' && u.avatar === v));
  await a.call('DELETE', '/me/avatar');
  assert.equal((await get({ Cookie: other.jar().cookie })).status, 404, 'фото удалено');
  assert.equal(userIn(await boot(a), 'uPrAv').avatar, null);
});

test('сроки хранения: IP регистрации — 90 дней; в сессиях — подпись устройства без версий, а не User-Agent', async () => {
  const t = open(':memory:'), now = Date.now(), day = 864e5, iso = ms => new Date(ms).toISOString();
  const add = t.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  add.run('uOld', 'Старый', 'x', 'i1', '001', 'x', iso(now - 91 * day), '95.56.12.34');
  add.run('uNew', 'Новый', 'x', 'i2', '002', 'x', iso(now - 89 * day), '95.56.12.35');
  const sess = t.q("INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen, ua) VALUES (?, 'uNew', 'c', ?, ?, ?, ?)");
  sess.run('raw', now, now + day, now, UA.macChrome); sess.run('label', now, now + day, now, 'Safari · iPhone');
  const n = purgeOld(t, now);
  assert.deepEqual([n.createdIp, n.sessionUa], [1, 1]);
  assert.deepEqual(t.q('SELECT id, created_ip FROM users ORDER BY id').all().map(r => [r.id, r.created_ip]), [['uNew', '95.56.12.35'], ['uOld', null]], 'старше 90 дней — адреса нет');
  assert.deepEqual(t.q('SELECT token_hash, ua FROM sessions ORDER BY token_hash').all().map(r => [r.token_hash, r.ua]), [['label', 'Safari · iPhone'], ['raw', 'Chrome · macOS']], 'сырой User-Agent заменён подписью');
  t.close();
  await client().call('POST', '/auth/login', { phone: '0700000003', password: 'hookah' }, { 'User-Agent': UA.winFirefox });
  assert.equal(db.q("SELECT ua FROM sessions WHERE user_id = 'u3' ORDER BY created_at DESC LIMIT 1").get().ua, 'Firefox · Windows', 'вход пишет в сессию подпись устройства');
  assert.ok(!db.q("SELECT 1 FROM sessions WHERE ua LIKE '%Mozilla%' OR ua LIKE '%/%'").get(), 'сырого User-Agent в сессиях нет');
});

// ---------- Пароли под нагрузкой, коды из SMS, шифрование, удаление без следов ----------
test('Argon2: одновременно — не больше половины пула потоков, короткая очередь; сверх неё — 503 «сервер занят» с Retry-After', async () => {
  const nodeCrypto = require('node:crypto'), secure = require('../server/lib/secure'), orig = nodeCrypto.argon2;
  const stored = await secure.hashPassword('Busy-Pass-2026'), held = [];
  let running = 0, peak = 0;
  // Подменный Argon2: задачи ждут, пока тест их не отпустит, — так видно, сколько их считается одновременно.
  nodeCrypto.argon2 = (alg, params, cb) => { running++; peak = Math.max(peak, running); held.push(() => orig.call(nodeCrypto, alg, params, (e, k) => { running--; cb(e, k); })); };
  try {
    // Пул libuv по умолчанию — 4 потока: считаются 2 проверки (2 потока остаются файлам сайта), 32 ждут, остальным — «занято».
    const runs = Array.from({ length: 40 }, () => secure.verifyPassword('Busy-Pass-2026', stored).then(ok => ok ? 'ok' : 'wrong', e => e.code));
    assert.equal(held.length, 2, 'считаются только две');
    // Пока очередь полна, вход отвечает 503 с Retry-After — и это не считается неверной попыткой.
    const busy = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone: '0555000901', password: 'Wrong-Pass-2026' }), signal: AbortSignal.timeout(3000) })
      .catch(() => ({ status: 'нет ответа', json: async () => ({}), headers: new Headers() }));
    assert.deepEqual([busy.status, (await busy.json()).error, busy.headers.get('retry-after')], [503, 'busy', '5']);
    while (held.length || running) { held.shift()?.(); await new Promise(r => setTimeout(r, 1)); }
    const res = await Promise.all(runs);
    assert.deepEqual([res.filter(r => r === 'ok').length, res.filter(r => r === 'ARGON_BUSY').length], [34, 6], '2 считаются + 32 в очереди, 6 — «занято»');
    assert.equal(peak, 2, 'одновременно — не больше двух');
  } finally { nodeCrypto.argon2 = orig; }
  const after = await client().login('0555000901', 'Wrong-Pass-2026');
  assert.deepEqual([after.status, after.data.left], [401, 4], '«занято» не потратило попытку');
});

test('код из SMS — 6 цифр из криптостойкого генератора, с ведущими нулями', () => {
  const { smsCode } = require('../server/lib/secure'), codes = Array.from({ length: 3000 }, smsCode);
  assert.ok(codes.every(c => /^\d{6}$/.test(c)), 'ровно 6 цифр');
  assert.ok(codes.some(c => c[0] === '0'), 'бывают и с нуля — весь миллион вариантов');
  assert.ok(new Set(codes).size > 2950, 'не повторяются');
});

test('AES-GCM: тег — ровно 16 байт; блоб с обрезанным тегом не расшифровывается (номера, секреты 2FA, панель)', () => {
  const nodeCrypto = require('node:crypto'), { makeKeyring } = require('../server/lib/secure');
  const kr = makeKeyring(nodeCrypto.randomBytes(32)), full = Buffer.from(kr.encrypt(''), 'base64');
  assert.equal(kr.decrypt(full.toString('base64')), '');
  // IV + первые 4, 8, 12 байт настоящего тега: раньше такой блоб принимался (подделка с шансом 2^-32 вместо 2^-128).
  for (const n of [16, 20, 24]) assert.throws(() => kr.decrypt(full.subarray(0, n).toString('base64')), undefined, `тег ${n - 12} байт`);
  const key = nodeCrypto.randomBytes(32), blob = panel.encrypt(Buffer.alloc(0), key);
  assert.equal(panel.decrypt(blob, key).length, 0);
  for (const n of [20, 24, 28]) assert.throws(() => panel.decrypt(blob.subarray(0, n), key), undefined, `панель: тег ${n - 16} байт`);
});

test('удаление без следов: база затирает удалённое (и в WAL), копии — без свободных страниц, старую базу пересобирает один раз', async () => {
  const nodeCrypto = require('node:crypto'), { DatabaseSync } = require('node:sqlite');
  const { makeBackup, decryptTo } = require('../server/backup'), { deleteAccount } = require('../server/lib/retention');
  const { encrypt, phoneIndex } = require('../server/lib/secure');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-wipe-')), file = path.join(dir, 'hookah.db'), key = nodeCrypto.randomBytes(32);
  const MARK = 'WIPE' + nodeCrypto.randomBytes(6).toString('hex');
  const has = f => fs.existsSync(f) && fs.readFileSync(f).includes(MARK);
  const inBackup = async () => { const r = await makeBackup({ src: file, dir: path.join(dir, 'bk'), key, keep: 14 }); const parts = []; decryptTo(r.file, key, c => parts.push(c)); return Buffer.concat(parts).includes(MARK); };
  try {
    // 1) База из прежней версии (без secure_delete и отметки о пересборке): удалённый текст лежит в свободных страницах.
    open(file).close();
    const old = new DatabaseSync(file);
    old.exec('PRAGMA user_version = 0; CREATE TABLE notes (t TEXT)');
    for (let i = 0; i < 40; i++) old.prepare('INSERT INTO notes VALUES (?)').run(MARK + i + '.'.repeat(400));
    old.exec('DELETE FROM notes; PRAGMA wal_checkpoint(TRUNCATE)');
    assert.ok(has(file), 'в старой базе удалённое осталось в файле');
    assert.equal(await inBackup(), false, 'в копию следы не попадают даже из такой базы (копия пересобирается)');
    old.close();
    // 2) Сервер открывает её: один раз VACUUM, дальше удаление затирает.
    const t = open(file);
    assert.deepEqual([t.prepare('PRAGMA secure_delete').get().secure_delete, t.prepare('PRAGMA user_version').get().user_version], [1, 1]);
    assert.ok(!has(file) && !has(file + '-wal'), 'после пересборки следов нет');
    // 3) Аккаунт с отзывом: после удаления текста нет ни в файле базы, ни в WAL, ни в новой копии.
    const now = new Date().toISOString();
    t.q("INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, created_at) VALUES ('uWipe', 'Стёртый', ?, ?, '321', 'x', ?)").run(encrypt('996555000321'), phoneIndex('996555000321'), now);
    t.q("INSERT INTO reviews VALUES ('rWipe', 'od-cola', 'uWipe', 5, ?, ?)").run('отзыв ' + MARK, now);
    t.wipe();
    assert.ok(has(file), 'отзыв в файле базы');
    assert.equal(deleteAccount(t, t.q("SELECT * FROM users WHERE id = 'uWipe'").get()), 0);
    assert.ok(!has(file) && !has(file + '-wal'), 'после удаления аккаунта — ни в файле базы, ни в WAL');
    assert.equal(await inBackup(), false, 'ни в копии, сделанной после удаления');
    t.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
