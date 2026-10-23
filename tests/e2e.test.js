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
