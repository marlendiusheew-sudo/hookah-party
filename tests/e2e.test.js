/* Сквозной тест в настоящем браузере (Chromium через Playwright) против настоящего сервера.
   Проверяет путь целиком: организатор отправляет ссылку, друг открывает её, входит и отвечает «Иду».
   Плюс офлайн-режим и отсутствие ошибок на странице. Запуск: npm run test:e2e
   (браузер ставится один раз: npx playwright install chromium) */
process.env.NODE_ENV = 'test';
process.env.SMS_PROVIDER = 'dev';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { open } = require('../server/lib/db');
const { seed } = require('../server/lib/seed');
const { createServer } = require('../server/index');

let server, base, browser;
const errors = [];
before(async () => {
  const db = open(':memory:');
  await seed(db);
  server = createServer(db);
  await new Promise(r => server.listen(0, r));
  // Офлайн-режим браузеры разрешают только на https и на localhost.
  base = `http://localhost:${server.address().port}/`;
  browser = await chromium.launch();
});
after(async () => { await browser?.close(); server?.close(); });

async function page(ctxOpts = {}) {
  const ctx = await browser.newContext({ locale: 'ru-RU', ...ctxOpts });
  const p = await ctx.newPage();
  p.on('pageerror', e => errors.push('pageerror: ' + e.message));
  // 401 у гостя — нормальный ответ API, остальное считаем ошибкой.
  p.on('console', m => { if (m.type() === 'error' && !/401|Failed to load resource/.test(m.text())) errors.push('console: ' + m.text()); });
  // Фильтр разметки сообщает о срабатывании предупреждением. На страницах самого сайта их быть не должно: белый список полон.
  p.on('console', m => { if (m.type() === 'warning' && /заблокирован опасный фрагмент/.test(m.text())) errors.push('фильтр: ' + m.text()); });
  return { ctx, p };
}
async function passAge(p) { await p.locator('.age-gate [data-age="yes"]').click(); await p.locator('.age-gate').waitFor({ state: 'detached' }); }
async function login(p, phone) {
  await p.locator('#lg-phone').fill(phone);
  await p.locator('#lg-pass').fill('hookah');
  await p.locator('#login-form button[type="submit"]').click();
}

test('приглашение ссылкой: организатор → Telegram → друг входит и отвечает «Иду»', async () => {
  const host = await page();
  await host.p.goto(base);
  await passAge(host.p);
  await host.p.goto(base + '#/login');
  await login(host.p, '0700000001');
  await host.p.getByText('Рады видеть вас снова, Алекс').waitFor();

  await host.p.goto(base + '#/event/e1');
  await host.p.locator('.share-strip [data-via="tg"]').click();
  const tg = await host.p.locator('.modal a.share-tg').getAttribute('href');
  assert.match(tg, /^https:\/\/t\.me\/share\/url\?url=/);
  const link = new URL(tg).searchParams.get('url');
  assert.ok(link.startsWith(base + '#/join/'), 'ссылка ведёт на этот же сервер: ' + link);

  const friend = await page();
  await friend.p.goto(link);
  await passAge(friend.p);
  await friend.p.getByText('Алекс зовёт вас').waitFor();
  assert.equal(await friend.p.locator('.join-card h1').textContent(), 'Пятничный сбор');
  await friend.p.locator('.join-reply-btns [data-status="going"]').click();
  await friend.p.locator('#login-form').waitFor();
  await login(friend.p, '0700000006');
  // После входа ответ уходит сам, и друг попадает на страницу сбора.
  await friend.p.waitForURL(/#\/event\/e1$/);
  await friend.p.locator('.rsvp [data-status="going"].btn-primary').waitFor();

  await host.p.goto(base + '#/notifications');
  await host.p.reload();
  await host.p.getByText('Карина').first().waitFor();
  await host.ctx.close(); await friend.ctx.close();
  assert.deepEqual(errors, []);
});

test('«Забыли пароль?»: вход по SMS → новый пароль без старого → уведомление «Пароль изменён» → вход с новым паролем', async () => {
  const { ctx, p } = await page();
  await p.goto(base);
  await passAge(p);
  await p.goto(base + '#/login');
  await p.locator('#lg-phone').fill('0700000005');
  await p.locator('#lg-forgot').click();
  // Режим разработки: код из SMS показывается на экране. По цифре в поле (у полей maxlength=1); после последней (шестой) форма уходит сама.
  const code = await p.locator('#sms-hint b').textContent();
  assert.match(code, /^\d{6}$/, 'код из 6 цифр');
  assert.equal(await p.locator('.code-inputs input').count(), 6, 'шесть клеток для кода');
  for (let i = 0; i < code.length; i++) await p.locator('#code-' + i).fill(code[i]);
  await p.locator('#pw-form').waitFor();
  assert.ok(await p.locator('#pw-cur-f').isHidden(), 'текущий пароль не спрашивается');
  assert.ok(await p.locator('.sec-pass.sms').isVisible(), 'в «Безопасности» подсказка про вход по SMS');
  await p.locator('#pw-new').fill('Browser-Pass-2027');
  await p.locator('#pw-rep').fill('Browser-Pass-2027');
  await p.locator('#pw-go').click();
  await p.getByText('Пароль изменён, остальные сеансы завершены').waitFor();
  assert.equal(await p.locator('.sec-pass.sms').count(), 0, 'после смены — снова только с текущим паролем');
  await p.goto(base + '#/notifications');
  await p.locator('.notif-text b', { hasText: 'Пароль изменён' }).waitFor();
  assert.match(await p.locator('.notif', { hasText: 'Пароль изменён' }).first().textContent(), /Если это были не вы — войдите по SMS и смените пароль снова/);
  await p.goto(base + '#/profile');
  await p.locator('.profile-card [data-action="logout"]').click();
  await p.getByText('Вы вышли из аккаунта').waitFor();
  await p.goto(base + '#/login');
  await p.locator('#lg-phone').fill('0700000005');
  await p.locator('#lg-pass').fill('Browser-Pass-2027');
  await p.locator('#login-form button[type="submit"]').click();
  await p.getByText('Рады видеть вас снова, Руслан').waitFor();
  await ctx.close();
  assert.deepEqual(errors, []);
});

test('приватность: «История» без входа — из итогов вечера; фото — отдельным адресом; организатор убирает гостя', async () => {
  // Гость без входа: о чужих вечерах сервер присылает только итоги — карточки всё равно с обложкой, гостями и «огнём».
  const anon = await page();
  await anon.p.goto(base + '#/history');
  await passAge(anon.p);
  await anon.p.locator('#story-e4').waitFor();
  assert.equal(await anon.p.locator('.story').count(), 4, 'четыре вечера с рассказом');
  assert.ok(await anon.p.locator('#story-e4 .story-shot').count() >= 2, 'обложка из самых популярных табаков');
  assert.match(await anon.p.locator('#story-e4 .story-facts').textContent(), /5 гостей/);
  assert.equal((await anon.p.locator('#story-e4 .react-btn b').textContent()).trim(), '5', '«огонь» — числом');
  await anon.ctx.close();

  // Фото профиля: картинка приходит по адресу /api/avatar/<id>?v=<версия>, в данных — только версия.
  const host = await page();
  await host.p.goto(base);
  await passAge(host.p);
  await host.p.goto(base + '#/login');
  await login(host.p, '0700000001');
  await host.p.getByText('Рады видеть вас снова, Алекс').waitFor();
  await host.p.goto(base + '#/profile');
  const chooser = host.p.waitForEvent('filechooser');
  await host.p.locator('.profile-card [data-action="uploadAvatar"]').click();
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
  await (await chooser).setFiles({ name: 'me.png', mimeType: 'image/png', buffer: png });
  await host.p.getByText('Фото обновлено').waitFor();
  assert.match(await host.p.locator('.profile-card img.av').getAttribute('src'), /^\/api\/avatar\/u1\?v=[0-9a-f]{16}$/);
  await host.p.waitForFunction(() => document.querySelector('.profile-card img.av')?.naturalWidth === 256);
  // Под управлением офлайн-скрипта фото снова приходит с сервера, а в кеш офлайн-режима ничего из /api/ не попадает.
  await host.p.evaluate(() => navigator.serviceWorker.ready.then(() => null));
  await host.p.reload();
  await host.p.waitForFunction(() => !!navigator.serviceWorker.controller && document.querySelector('.profile-card img.av')?.naturalWidth === 256);
  const cached = await host.p.evaluate(async () => (await Promise.all((await caches.keys()).map(async k => (await (await caches.open(k)).keys()).map(r => r.url)))).flat());
  assert.ok(cached.length && !cached.some(u => u.includes('/api/')), 'офлайн-кеш без /api/: ' + cached.join(', '));

  // Организатор убирает приглашённую из сбора: «карандаш» в списке участников, «Убрать», подтверждение.
  await host.p.goto(base + '#/event/e1');
  assert.equal(await host.p.locator('[data-action="removeGuest"]').count(), 0, 'по умолчанию список как раньше');
  await host.p.locator('[data-action="guestEdit"]').click();
  await host.p.locator('.people .person:has(a[href="#/user/u4"]) [data-action="removeGuest"]').click();
  await host.p.locator('.modal #rg-ok').click();
  await host.p.getByText('Сабина больше не в сборе').waitFor();
  assert.equal(await host.p.locator('.people a[href="#/user/u4"]').count(), 0, 'Сабины больше нет среди приглашённых');
  await host.ctx.close();
  assert.deepEqual(errors, []);
});

test('офлайн: сайт открывается без сети и честно говорит об этом', async () => {
  const { ctx, p } = await page();
  await p.goto(base);
  await passAge(p);
  await p.evaluate(() => navigator.serviceWorker.ready.then(() => null));
  await p.reload(); // страница под управлением офлайн-скрипта
  await ctx.setOffline(true);
  await p.reload();
  await p.getByText('Нет соединения').waitFor();
  assert.ok(await p.locator('.topbar .brand').isVisible(), 'шапка сайта на месте');
  await ctx.close();
  assert.deepEqual(errors.filter(e => !/ERR_INTERNET_DISCONNECTED|Failed to fetch/.test(e)), []);
});

test('офлайн: переход на картинку или файл сайта не подменяет сохранённую страницу (только сама страница и только HTML)', async () => {
  const { ctx, p } = await page();
  await p.goto(base);
  await passAge(p);
  await p.evaluate(() => navigator.serviceWorker.ready.then(() => null));
  await p.reload(); // страница под управлением офлайн-скрипта
  // Так же, как по ссылке с чужого сайта: переход прямо на файлы сайта.
  for (const f of ['og.png', 'sw.js', 'manifest.webmanifest']) await p.goto(base + f);
  const shell = await p.evaluate(async () => (await caches.match('./'))?.headers.get('content-type'));
  assert.match(shell || '', /^text\/html/, 'в кеше как страница сайта — только HTML: ' + shell);
  await ctx.setOffline(true);
  await p.goto(base).catch(() => {});
  await p.getByText('Нет соединения').waitFor();
  assert.equal(await p.evaluate(() => document.contentType), 'text/html');
  // Шрифты офлайн-скрипт держит заранее: и без сети заголовки — своим шрифтом.
  assert.ok(await p.evaluate(() => document.fonts.ready.then(f => [...f].some(x => x.family.includes('Unbounded') && x.status === 'loaded'))), 'шрифт Unbounded без сети — из кеша');
  await ctx.close();
  assert.deepEqual(errors.filter(e => !/ERR_INTERNET_DISCONNECTED|Failed to fetch/.test(e)), []);
});

test('шрифты: свои, с этого же сайта — кириллица заголовков в Unbounded, ни одного запроса к другим сайтам', async () => {
  const { ctx, p } = await page();
  const outside = [], fonts = [];
  await ctx.route(u => !u.href.startsWith(base), r => { outside.push(r.request().url()); r.abort(); });
  p.on('response', r => { if (r.url().includes('/fonts/')) fonts.push(r.status() + ' ' + r.url().slice(base.length)); });
  await p.goto(base + '#/history');
  await passAge(p);
  await p.locator('h1').first().waitFor();
  const f = await p.evaluate(async () => {
    await document.fonts.ready;
    const loaded = [...document.fonts].filter(x => x.status === 'loaded');
    return { loaded: loaded.map(x => `${x.family.replace(/["']/g, '')} ${x.unicodeRange.slice(0, 13)}`), h1: getComputedStyle(document.querySelector('h1')).fontFamily, text: document.querySelector('h1').textContent };
  });
  assert.match(f.text, /[а-яё]/i, 'заголовок по-русски');
  assert.match(f.h1, /^"?Unbounded/);
  assert.ok(f.loaded.some(x => /^Unbounded U\+0?301, U\+0?400/i.test(x)), 'кириллица Unbounded загружена: ' + f.loaded.join('; '));
  assert.ok(f.loaded.some(x => /^Golos Text U\+0?301, U\+0?400/i.test(x)), 'кириллица Golos Text загружена');
  assert.ok(fonts.length && fonts.every(x => /^200 fonts\/[a-z0-9-]+\.woff2$/.test(x)), 'шрифты — с этого сайта: ' + fonts.join(', '));
  assert.deepEqual(outside, [], 'ни одного запроса к другим сайтам');
  await ctx.close();
  assert.deepEqual(errors, []);
});

test('фильтр разметки в Chromium (Trusted Types): обходные формы — без обработчиков и javascript:, своя разметка — как есть', async () => {
  const { ctx, p } = await page();
  await p.goto(base);
  await passAge(p);
  const r = await p.evaluate(() => {
    const box = document.createElement('div'); document.body.append(box);
    const BAD = ['<img src=x title=">" onerror="window.__X=1">', '<img/onerror="window.__X=1" src=x>', '<img src="x"onerror="window.__X=1">',
      '<img title="a>b" onerror="window.__X=1" src=x>', '<svg/onload="window.__X=1"><path d="M0 0"/></svg>', '<a href=" java\tscript:window.__X=1">x</a>',
      '<math><mtext><table><mglyph><style><img src=x onerror="window.__X=1">', '<noscript><p title="</noscript><img src=x onerror=window.__X=1>"></noscript>',
      '<form><button formaction="javascript:window.__X=1">x</button></form>', '<svg><animate attributeName="href" values="javascript:window.__X=1"/></svg>'];
    const bad = BAD.flatMap(h => {
      box.innerHTML = h;
      return [...box.querySelectorAll('*')].flatMap(el => [...el.attributes].filter(a => /^on|formaction/i.test(a.name) || /javascript:/i.test(a.value)).map(a => `${el.localName}[${a.name}]`))
        .concat([...box.querySelectorAll('math, noscript, style, script, animate')].map(e => e.localName));
    });
    box.innerHTML = '<svg viewBox="0 0 10 10"><defs><linearGradient id="gq"><stop offset="0" stop-color="#fff"/></linearGradient></defs><path d="M0 0L5 5" fill="url(#gq)"/></svg><a href="https://t.me/x" target="_blank" rel="noopener noreferrer">t</a>';
    const svgEl = box.querySelector('svg');
    const good = svgEl.namespaceURI === 'http://www.w3.org/2000/svg' && svgEl.getAttribute('viewBox') === '0 0 10 10' && box.querySelector('path').getAttribute('fill') === 'url(#gq)' && !!box.querySelector('a[href="https://t.me/x"]');
    box.remove();
    return { tt: !!window.trustedTypes?.defaultPolicy, bad, good };
  });
  assert.ok(r.tt, 'включены Trusted Types: фильтр — политика default');
  assert.deepEqual(r.bad, []);
  assert.ok(r.good, 'своя разметка (SVG с градиентом, внешняя ссылка) осталась как есть');
  await p.waitForTimeout(300);
  assert.equal(await p.evaluate(() => window.__X), undefined, 'ни один обработчик не сработал');
  await ctx.close();
  // Предупреждения фильтра здесь нарочные. Chromium ещё и сообщает о нарушении CSP, когда фильтр разбирает такую разметку
  // в отдельном документе (обработчик там не создаётся и не выполняется) — это тоже ожидаемо.
  const rest = errors.filter(e => !/^фильтр:|^console: (Executing inline event handler|Applying inline style) violates/.test(e));
  errors.length = 0;
  assert.deepEqual(rest, []);
});

test('сервер под лимитом: вместо демо — честный экран, меню его не обходит; сервер ответил — страница открылась сама', async () => {
  const { ctx, p } = await page();
  const limited = r => r.fulfill({ status: 429, contentType: 'application/json', body: JSON.stringify({ error: 'rate_limited', message: { ru: 'Слишком много запросов.', en: 'Too many requests.' } }) });
  await ctx.route('**/api/health', limited);
  await p.clock.install();
  await p.goto(base);
  await p.getByText('Сервер ненадолго недоступен').waitFor();
  for (const h of ['#/events', '#/people', '#/profile', '#/register']) { await p.goto(base + h); await p.getByText('Сервер ненадолго недоступен').waitFor(); }
  const text = await p.locator('body').textContent();
  assert.doesNotMatch(text, /Алекс|Пятничный сбор|Дина|Тимур/, 'ни демо-данных, ни чужого входа');
  assert.equal(await p.locator('#reg-form, #login-form').count(), 0, 'регистрация не открывается (ушла бы в демо)');
  await ctx.unroute('**/api/health', limited);
  await p.clock.runFor(21e3); // повторная попытка — раз в 20 секунд
  await p.locator('#reg-form').waitFor();
  assert.equal(await p.evaluate(() => document.documentElement.dataset.mode), 'server');
  await ctx.close();
  assert.deepEqual(errors, []);
});
