/* Проверка защиты от XSS на стороне браузера (jsdom, демо-режим). В localStorage заранее кладём данные,
   где в КАЖДОЕ поле, которое заполняет пользователь, подставлены зловредные строки, и открываем все страницы.
   Ни одного обработчика on*, ни одного внедрённого <script>/<iframe>, ни одной ссылки javascript: — и «маячок»
   window.__XSS__, который ставят вредоносные строки, не срабатывает. Запуск: node tests/xss.test.js
   Только локально, никаких внешних адресов. */
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');
const dir = process.argv[2] || path.resolve(__dirname, '..');
const html = fs.readFileSync(dir + '/index.html', 'utf8').replace(/<script src="[^"]+"><\/script>/g, '');
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => { if (!/Not implemented/.test(e.message)) errors.push('jsdomError: ' + e.message); });
// Срабатывания фильтра разметки (он пишет о них в консоль): на страницах с экранированными нагрузками их быть не должно.
const blocked = [];
vc.on('warn', (msg, hit) => { if (/заблокирован опасный фрагмент/.test(msg)) blocked.push(String(hit)); });
const dom = new JSDOM(html, { url: 'https://example.test/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window, d = w.document;
w.scrollTo = () => {}; w.Element.prototype.scrollIntoView = () => {};
// Как на GitHub Pages: сервера нет, /api/health отвечает 404 — демо-режим, никаких внешних адресов.
w.fetch = async () => ({ ok: false, status: 404, json: async () => { throw new SyntaxError('HTML, не JSON'); } });
if (!w.TextEncoder) Object.assign(w, { TextEncoder, TextDecoder });
// Маячок: любая сработавшая полезная нагрузка его поднимет.
w.__XSS__ = 0;
w.addEventListener('error', e => errors.push('window error: ' + e.message));

const $ = s => d.querySelector(s), $$ = s => [...d.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const go = async h => { w.location.hash = h; await sleep(40); };
const click = el => { if (el) el.dispatchEvent(new w.MouseEvent('click', { bubbles: true })); };
const ok = (cond, msg) => { console.log((cond ? 'OK   ' : 'FAIL ') + msg); if (!cond) errors.push('FAIL ' + msg); };

// Набор нагрузок во все поля: каждая пытается поднять маячок через on*-обработчик, <script>, javascript:-ссылку.
const SINK = 'window.__XSS__=1';
const P = `<script>${SINK}<\/script><img src=x onerror="${SINK}"><svg onload="${SINK}"></svg>` +
  `<iframe src="javascript:${SINK}"></iframe><a href="javascript:${SINK}">j</a><b style="x:expression(${SINK})">t</b>` +
  `"><script>${SINK}<\/script> '"‮​\u0000 \${7*7} {{7*7}}`;
const b64u = s => Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const iso = ms => new Date(ms).toISOString();
const now = Date.now();

// Демо-данные с нагрузкой в каждом пользовательском поле.
const demo = {
  session: 'uX',
  users: [
    { id: 'uX', name: 'Я' + P, phone: '996700000001', pass: { alg: 'x' }, verified: true, avatar: 'javascript:' + SINK, favs: ['ds-supernova'], friends: ['u2'], favVenue: 'Люблю' + P, createdAt: iso(now - 1e6) },
    { id: 'u2', name: 'Друг' + P, phone: '996700000002', pass: { alg: 'x' }, verified: true, avatar: null, favs: [], friends: ['uX'], favVenue: 'Место' + P, createdAt: iso(now - 1e6) }
  ],
  events: [{
    id: 'eX', title: 'Сбор' + P, venue: 'Заведение' + P, address: 'Адрес' + P, venueId: '', mapUrl: 'javascript:' + SINK,
    at: iso(now + 2 * 864e5), hostId: 'uX', createdAt: iso(now - 1e5), desc: 'Описание' + P, hookahs: 1, price: 100, paid: {},
    invites: [{ userId: 'u2', status: 'going', at: iso(now - 1e5) }], picks: { uX: ['ds-supernova'] }, bowls: { uX: 'b-phunnel' },
    comments: [{ id: 'cX', userId: 'uX', text: 'Коммент' + P, at: iso(now - 5e4), reactions: { u2: '<img src=x onerror="' + SINK + '">' } }],
    remind: {}, notified: {}
  }, {
    // Прошедший сбор с рассказом — для раздела «История».
    id: 'eY', title: 'Вечер' + P, venue: 'Лаунж' + P, address: 'Адрес2' + P, venueId: '', mapUrl: '',
    at: iso(now - 6 * 864e5), hostId: 'uX', createdAt: iso(now - 7 * 864e5), desc: '', hookahs: 2, price: 500, paid: {},
    invites: [{ userId: 'u2', status: 'going', at: iso(now - 7 * 864e5) }], picks: { uX: ['ds-supernova'] }, bowls: {},
    comments: [], remind: {}, notified: {},
    story: { rating: 5, at: iso(now - 6 * 864e5), fire: ['u2'], text: 'Рассказ' + P, highlights: ['Хайлайт' + P, 'Второй' + P],
      comments: [{ id: 'scX', userId: 'u2', text: 'Отзыв о вечере' + P, at: iso(now - 5 * 864e5), reactions: { uX: '🔥' } }] }
  }],
  storiesSeeded: true,
  reviews: [{ id: 'rX', tobaccoId: 'ds-supernova', userId: 'u2', rating: 5, text: 'Отзыв' + P, at: iso(now - 1e5) }],
  mixes: [{ id: 'mX', name: 'Микс' + P, authorId: 'u2', parts: [{ id: 'od-cola', pct: 50 }, { id: 'tg-canemint', pct: 50 }], likes: ['uX'], at: iso(now - 1e5) }]
};

// Проверка поддерева: обработчики событий, опасные теги и ссылки-скрипты.
function unsafe(root = d.body) {
  const bad = [];
  root.querySelectorAll('*').forEach(el => {
    for (const a of el.attributes) {
      if (/^on/i.test(a.name)) bad.push(`${el.tagName}[${a.name}]`);
      if ((a.name === 'style') && /expression\(|javascript:/i.test(a.value)) bad.push(`${el.tagName} style`);
    }
  });
  root.querySelectorAll('script, iframe, object, embed, frame, frameset').forEach(el => bad.push('tag ' + el.tagName));
  root.querySelectorAll('[href], [src]').forEach(el => {
    for (const a of ['href', 'src']) {
      const v = (el.getAttribute(a) || '').trim().toLowerCase().replace(/[\u0000-\u001f]/g, '');
      if (v.startsWith('javascript:') || v.startsWith('vbscript:') || v.startsWith('data:text')) bad.push(`${a}=${v.slice(0, 24)}`);
    }
  });
  return bad;
}

(async () => {
  try {
    w.localStorage.setItem('hp.age18', 'yes');
    w.localStorage.setItem('hookahparty.v2', JSON.stringify(demo));
    w.eval(fs.readFileSync(dir + '/map-data.js', 'utf8'));
    w.eval(fs.readFileSync(dir + '/art.js', 'utf8'));
    w.eval(fs.readFileSync(dir + '/app.js', 'utf8'));
    await sleep(60);

    // Ссылка-приглашение с нагрузкой в каждом поле.
    const invite = 'd' + b64u(JSON.stringify({ i: 'eX', t: 'Сбор' + P, v: 'Место' + P, a: 'Адрес' + P, at: iso(now + 3 * 864e5), h: 'Хост' + P, vid: '' }));
    const pages = [
      ['#/', 'главная'], ['#/events', 'события'], ['#/event/eX', 'страница сбора'], ['#/history', 'история'],
      ['#/people', 'люди'], ['#/user/u2', 'профиль друга'], ['#/user/uX', 'свой профиль'], ['#/profile', 'профиль'],
      ['#/notifications', 'уведомления'], ['#/catalog', 'каталог'], ['#/join/' + invite, 'приглашение по ссылке']
    ];
    for (const [hash, name] of pages) {
      await go(hash);
      const bad = unsafe();
      ok(bad.length === 0, `${name}: нет on*/опасных тегов/js-ссылок` + (bad.length ? ' — ' + bad.slice(0, 4).join(', ') : ''));
    }

    // Профиль → Настройки.
    await go('#/profile');
    click($('.utabs[data-tabs="profile"] [data-tab="settings"]')); await sleep(30);
    ok(unsafe().length === 0, 'профиль → настройки: безопасно');
    click($('.sec-pass [data-action="changePassword"]')); await sleep(30);
    ok(!!$('#pw-form') && unsafe($('#modal-root')).length === 0, 'профиль → смена пароля: окно безопасно');
    click($('[data-action="closeModal"]')); await sleep(10);

    // Каталог: все вкладки и открытые карточки-детали.
    await go('#/catalog');
    for (const t of ['tobaccos', 'mixes', 'bowls', 'gear']) {
      click($(`.utabs[data-tabs="cat"] [data-tab="${t}"]`)); await sleep(30);
      ok(unsafe().length === 0, `каталог/${t}: безопасно`);
    }
    await go('#/catalog');
    click($('.t-card[data-action="tobacco"][data-id="ds-supernova"]')); await sleep(30);
    ok(unsafe($('#modal-root')).length === 0, 'каталог: модалка табака (с отзывом-нагрузкой) безопасна');
    click($('[data-action="closeModal"]')); await sleep(10);
    await go('#/catalog');
    click($('.utabs[data-tabs="cat"] [data-tab="mixes"]')); await sleep(20);
    click($('.mix-card[data-action="mixInfo"]')); await sleep(30);
    ok(unsafe($('#modal-root')).length === 0, 'каталог: модалка микса (с названием-нагрузкой) безопасна');
    click($('[data-action="closeModal"]')); await sleep(10);

    // Уведомления ещё раз (реакция с нагрузкой в ref).
    await go('#/notifications');
    ok(unsafe().length === 0, 'уведомления: реакция с нагрузкой в ref безопасна');

    // Положительная проверка: нагрузка ДЕЙСТВИТЕЛЬНО отрисовалась, но как текст (экранирована).
    await go('#/event/eX');
    ok(/window\.__XSS__=1/.test($('#view').textContent), 'нагрузка отрисована как текст (экранирована), а не как код');
    ok(!$('#view').querySelector('script, iframe'), 'в тексте сбора нет живых <script>/<iframe>');

    ok(!blocked.length, 'фильтр разметки: экранированные нагрузки до него не доходят как разметка, своя разметка проходит без потерь' + (blocked.length ? ' — ' + blocked.slice(0, 3).join(', ') : ''));

    // Сам фильтр разметки (второй рубеж после esc и CSP; в jsdom он встроен в innerHTML, в Chrome — политика Trusted Types).
    // Формы, которые обходили прежний фильтр на регулярных выражениях: атрибут после «/», вплотную за кавычкой, после «>»
    // внутри кавычек; и известные приёмы: SVG и MathML, noscript, srcdoc, formaction, ссылки с табуляцией и HTML-сущностями.
    const BYPASS = [
      `<img src=x title=">" onerror="${SINK}">`, `<img/onerror="${SINK}" src=x>`, `<img src="x"onerror="${SINK}">`,
      `<img title="a>b" onerror="${SINK}" src=x>`, `<svg/onload="${SINK}"><path d="M0 0"/></svg>`, `<a href=" java\tscript:${SINK}">x</a>`,
      `<a href="jav&#x61;script:${SINK}">x</a>`, `<svg><a xlink:href="javascript:${SINK}"><text>x</text></a></svg>`,
      `<svg><animate attributeName="href" values="javascript:${SINK}"/><set attributeName="onload" to="${SINK}"/></svg>`,
      `<math><mtext><table><mglyph><style><img src=x onerror="${SINK}">`, `<form><button formaction="javascript:${SINK}">x</button></form>`,
      `<iframe srcdoc="<script>${SINK}<\/script>"></iframe>`, `<noscript><p title="</noscript><img src=x onerror=${SINK}>"></noscript>`,
      `<div style="background:url(javascript:${SINK})">x</div>`, `<b style="x:expression(${SINK})">t</b>`, `<img src="data:image/svg+xml,<svg onload=${SINK}>">`,
      `<details open ontoggle="${SINK}">x</details>`, `<input autofocus onfocus="${SINK}">`, `<template><img src=x onerror="${SINK}"></template>`,
      `<object data="javascript:${SINK}"></object><embed src="javascript:${SINK}">`, `<base href="javascript:/"><meta http-equiv="refresh" content="0;javascript:${SINK}">`
    ];
    const lab = d.createElement('div'); d.body.append(lab);
    for (const p of BYPASS) {
      lab.innerHTML = p;
      const bad = unsafe(lab).concat([...lab.querySelectorAll('[style*="url"], [style*="expression"], [srcdoc], [formaction], [xlink\\:href], noscript, template, math, animate, set, style, base, meta')].map(e => e.tagName),
        [...lab.querySelectorAll('img[src]')].filter(i => /^\s*data:(?!image\/(png|jpe?g|webp|gif);)/i.test(i.getAttribute('src'))).map(() => 'img data:'));
      ok(bad.length === 0, 'фильтр разметки: ' + p.slice(0, 48) + (bad.length ? ' — ' + bad.join(', ') : ''));
    }
    // Своя разметка сайта остаётся как есть: SVG с градиентом, ссылки (свои, внешние, otpauth для 2FA), фото data:image.
    lab.innerHTML = '<svg viewBox="0 0 10 10" aria-hidden="true"><defs><linearGradient id="g1"><stop offset="0" stop-color="#fff"/></linearGradient></defs><path d="M0 0L5 5" fill="url(#g1)"/></svg>'
      + '<a href="#/event/e1">a</a><a href="https://t.me/share/url?url=x" target="_blank" rel="noopener noreferrer">b</a><a href="otpauth://totp/Hookah?secret=AB">c</a>'
      + '<img class="av" src="data:image/png;base64,iVBORw0KGgo=" alt=""><button type="button" data-action="go" aria-label="x" style="--pc:#fff;flex:1">d</button>';
    ok(lab.querySelector('svg').getAttribute('viewBox') === '0 0 10 10' && lab.querySelector('path').getAttribute('fill') === 'url(#g1)' && lab.querySelectorAll('a[href]').length === 3
      && !!lab.querySelector('img.av[src^="data:image/png"]') && lab.querySelector('button').getAttribute('style') === '--pc:#fff;flex:1' && lab.querySelector('button').dataset.action === 'go',
      'фильтр разметки: своя разметка (SVG, ссылки, фото, data-*, style) остаётся как есть');
    lab.remove();

    // Главный итог: маячок не сработал ни разу.
    ok(w.__XSS__ === 0, 'маячок window.__XSS__ не сработал ни на одной странице');
  } catch (e) { errors.push('исключение: ' + e.stack); }
  console.log('\nОшибок: ' + errors.length); errors.forEach(e => console.log(e));
  process.exit(errors.length ? 1 : 0);
})();
