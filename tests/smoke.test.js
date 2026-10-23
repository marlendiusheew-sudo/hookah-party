/* Сквозной тест сайта в имитации браузера (jsdom): страницы, сборы, карта, язык, история, лимиты, защита.
   Запуск: npm test */
const fs = require('fs');
const { JSDOM, VirtualConsole } = require('jsdom');
const path = require('path');
const dir = process.argv[2] || path.resolve(__dirname, '..');
const html = fs.readFileSync(dir + '/index.html', 'utf8').replace(/<script src="[^"]+"><\/script>/g, '');
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => { if (!/Not implemented/.test(e.message)) errors.push('jsdomError: ' + e.message); });
vc.on('error', e => errors.push('console.error: ' + e));
// Фильтр разметки сообщает в консоль о каждом срабатывании. На страницах самого сайта их быть не должно: белый список тегов
// и атрибутов покрывает всю его разметку, иначе часть страницы молча пропала бы.
const blocked = [];
vc.on('warn', (msg, hit) => { if (/заблокирован опасный фрагмент/.test(msg)) blocked.push(String(hit)); });
const dom = new JSDOM(html, { url: 'https://example.test/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window, d = w.document;
// Как на GitHub Pages: сервера нет, /api/health отвечает 404 (страница HTML) — сайт работает в демо-режиме.
const pagesFetch = async () => ({ ok: false, status: 404, json: async () => { throw new SyntaxError('HTML, не JSON'); } });
w.fetch = pagesFetch;
w.scrollTo = () => {};
// В jsdom нет TextEncoder/TextDecoder, а в настоящих браузерах они есть всегда.
if (!w.TextEncoder) Object.assign(w, { TextEncoder, TextDecoder });
w.Element.prototype.scrollIntoView = () => {};
w.addEventListener('error', e => errors.push('window error: ' + e.message));
w.eval(fs.readFileSync(dir + '/map-data.js', 'utf8'));
w.eval(fs.readFileSync(dir + '/art.js', 'utf8'));
w.eval(fs.readFileSync(dir + '/app.js', 'utf8'));
const $ = s => d.querySelector(s), $$ = s => [...d.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const go = async h => { w.location.hash = h; await sleep(30); };
const click = el => { if (!el) throw new Error('нет элемента'); el.dispatchEvent(new w.MouseEvent('click', { bubbles: true })); };
const ok = (cond, msg) => { console.log((cond ? 'OK   ' : 'FAIL ') + msg); if (!cond) errors.push('FAIL ' + msg); };
const text = () => d.body.textContent.replace(/\s+/g, ' ');
const setVal = (sel, v) => { const el = $(sel); el.value = v; el.dispatchEvent(new w.Event('input', { bubbles: true })); };
const ptr = (el, type, x = 10, y = 10) => { const e = new w.Event(type, { bubbles: true }); Object.assign(e, { pointerId: 1, pointerType: 'mouse', clientX: x, clientY: y }); el.dispatchEvent(e); };
const tabTo = async (n, k) => { click($(`.utabs[data-tabs="${n}"] [data-tab="${k}"]`)); await sleep(15); };
const until = async (cond, ms = 2000) => { for (let t = 0; t < ms && !cond(); t += 20) await sleep(20); return cond(); };
const store = () => JSON.parse(w.localStorage.getItem('hookahparty.v2'));
const typeCode = code => [...code].forEach((c, i) => { const b = $('#code-' + i); b.value = c; b.dispatchEvent(new w.Event('input', { bubbles: true })); });

(async () => {
  try {
    await sleep(20);
    ok(!!$('.age-gate') && /18/.test($('.age-gate').textContent), 'возраст: при первом визите спрашиваем 18+');
    click($('.age-gate [data-age="no"]')); await sleep(5);
    ok(!$('.age-gate .age-no').hidden && !!$('.age-gate'), 'возраст: «Нет» не пускает дальше');
    click($('.age-gate [data-age="yes"]')); await sleep(5);
    ok(!$('.age-gate') && w.localStorage.getItem('hp.age18') === 'yes', 'возраст: «Да» запоминается');
    ok($$('.tiles .tile').length === 3, 'главная: три плитки');
    const today = new Date(), m = today.getMonth() + 1, dd = today.getDate();
    const expect = (m === 10 && dd >= 23) || (m === 11 && dd <= 3) ? 'halloween' : (m === 12 && dd >= 22) || (m === 1 && dd <= 10) ? 'newyear' : undefined;
    ok(d.documentElement.dataset.season === expect, 'праздник по дате сегодня: ' + (expect || 'нет'));
    if (expect) ok(!$('#season-ribbon').hidden && !!$('.season-fx'), 'праздник: лента и украшения');
    ok(/Заведения/.test($('.tiles').textContent) && /Кальян/.test($('.tiles').textContent) && /События/.test($('.tiles').textContent), 'плитки: подписи');
    ok(!!($('.tile[href="#/venues"] .art-house') && $('.tile[href="#/catalog"] .art-hookah') && $('.tile[href="#/events"] .art-mail')), 'плитки: домик, кальян, конверт');
    ok(/Рады видеть вас снова, Алекс/.test(text()), 'приветствие для вошедшего');
    ok(!!$('.next-strip [data-countdown]'), 'полоска ближайшего сбора');
    ok($$('#home-map .m-pin').length === 12, 'карта: 12 точек');
    ok($$('#home-map .m-pri path').length > 50, 'карта: улицы нарисованы');
    const css = require('fs').readFileSync(dir + '/styles.css', 'utf8');
    ok(!/g:not\(\.m-park\)/.test(css) && $$('#home-map .m-pin-body').every(b => !b.matches('.m-water path, .m-tert path, .m-sec path, .m-pri path')), 'метки: стиль улиц их больше не задевает');
    ok($$('#home-map .m-pin .m-pin-ring').length === 12 && $$('#home-map .map-name').length === 12, 'метки: капля с кольцом и подписью');
    ok(!!$('#home-map .map-legend'), 'карта: легенда');
    ok($$('.stat-big').length === 4 && $('.stat-big b').textContent === '12', 'главная: цифры');
    ok($$('#venue-scroller .vcard').length === 12, 'главная: «Куда пойти сегодня»');
    ok($$('.marquee-track span').length >= 20, 'главная: бегущая строка брендов');
    ok(/Табак недели/.test(text()) && $$('.mix-list li').length === 3, 'главная: табак недели и миксы');
    ok($$('.quote').length === 3, 'главная: отзывы');
    ok($$('.faq details').length === 6, 'главная: частые вопросы');
    ok(!!$('.to-top'), 'кнопка «Наверх»');
    const pin = $('#home-map .m-pin[data-vid="n4270648990"]');
    ptr(pin, 'pointerdown'); ptr(pin, 'pointerup'); await sleep(10);
    const card = $('#home-map .map-card');
    ok(!card.hidden && /Savor Hookah Bar/.test(card.textContent), 'карта: карточка по клику');
    ok(/Чынгыз Айтматов/.test(card.textContent) && /Вт–Вс, 17:00–02:00/.test(card.textContent), 'карточка: адрес и часы');
    ok(!!card.querySelector('a.ml-google[href*="google.com/maps"]') && !!card.querySelector('a.ml-2gis[href*="2gis.kg"]'), 'карточка: ссылки Google Карты и 2ГИС');
    click(card.querySelector('[data-mclose]')); await sleep(5);
    ok(card.hidden, 'карточка закрывается');
    ptr(pin, 'pointermove'); await sleep(5);
    ok(!$('#home-map .map-tip').hidden && /Savor/.test($('#home-map .map-tip').textContent), 'карта: подсказка при наведении');
    pin.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); await sleep(5);
    ok(!card.hidden, 'карта: открытие точки с клавиатуры');
    click($('#home-map [data-mz="in"]')); click($('#home-map [data-mz="fit"]'));

    click($('#venue-scroller .vcard[data-vid="n12870025414"]')); await sleep(40);
    ok(w.location.hash === '#/venues' && /Hydra/.test($('#venues-map .map-card').textContent), 'карточка «Куда пойти» ведёт на карту');
    await go('#/venues');
    ok($$('.venue-item').length === 12, 'заведения: список из 12');
    click($('.venue-item[data-vid="n6360868686"]')); await sleep(10);
    ok(/Holy Cow/.test($('#venues-map .map-card').textContent) && $('.venue-item[data-vid="n6360868686"]').classList.contains('sel'), 'заведения: выбор из списка');
    setVal('#v-q', 'гоголя'); ok($$('.venue-item').length === 1, 'заведения: поиск по улице');
    setVal('#v-q', '');
    click($('[data-action="venueOpen"]')); await sleep(10);
    ok($$('.venue-item').length <= 12, 'заведения: фильтр «открыто сейчас»');
    click($('[data-action="venueOpen"]')); await sleep(10);
    click($('.venue-item[data-vid="n6360868686"]')); await sleep(10);
    click($('#venues-map [data-action="gatherHere"]')); await sleep(10);
    // У Алекса уже есть активный сбор — новый создать нельзя, пока этот не пройдёт или не будет отменён.
    ok(/У вас уже есть активный сбор/.test($('.modal h2').textContent) && !!$('.modal [data-action="deleteEvent"]'), 'один активный сбор: вместо формы — предупреждение');
    click($('[data-action="closeModal"]'));

    click($('[data-action="setLang"][data-lang="en"]')); await sleep(10);
    ok(/Venues/.test($('#nav').textContent) && d.documentElement.lang === 'en', 'язык: меню на английском');
    await go('#/');
    ok(/Good to see you again, Алекс/.test(text()) && /Hookah lounges in Bishkek/.test(text()), 'язык: главная на английском');
    await go('#/event/e1');
    ok(/Tobacco/.test(text()) && /Discussion/.test(text()) && /KGS/.test(text()), 'язык: страница сбора на английском');
    await go('#/catalog');
    ok(/Strength/.test(text()) && /Icy cooling/.test(text()), 'язык: каталог на английском');
    for (const h of ['#/', '#/venues', '#/events', '#/catalog', '#/people', '#/profile', '#/how']) {
      await go(h);
      const ru = [...new Set(($('#view').textContent + $('#footer').textContent + $('#topbar-actions').textContent).match(/[А-Яа-яЁё]{3,}/g) || [])];
      void ru;
    }
    click($('[data-action="setLang"][data-lang="ru"]')); await sleep(10);
    ok(/Заведения/.test($('#nav').textContent), 'язык: обратно на русский');

    await go('#/events');
    ok($$('.utabs[data-tabs="home"] [role=tab]').length === 5, 'события: 5 вкладок');
    ok(!!$('.next-card [data-countdown]'), 'события: ближайший сбор');
    await tabTo('home', 'invites'); ok(/Зовёт Тимур/.test(text()), 'вкладка «Приглашения»');
    await tabTo('home', 'past'); ok(/После работы/.test($('.tab-panel').textContent), 'вкладка «Прошедшие»');
    await tabTo('home', 'feed'); ok($$('.feed-item').length >= 5, 'вкладка «Лента»');
    await tabTo('home', 'upcoming');
    click($('[data-action="homeView"][data-view="cal"]')); await sleep(10);
    ok($$('.cal-cell:not(.pad)').length >= 28, 'календарь');
    click($('[data-action="homeView"][data-view="list"]')); await sleep(10);

    await go('#/event/e1');
    ok(/Savor Hookah Bar/.test(text()) && /1\s200\sсом/.test(text()), 'сбор: реальное заведение и сомы');
    const before = $$('.comment').length;
    $('#comment-text').value = 'Тест'; $('#comment-form').requestSubmit(); await sleep(10);
    ok($$('.comment').length === before + 1, 'сбор: комментарий');
    ok($('#comment-text').disabled && /через/.test($('.quota').textContent) && !!$('[data-until]'), 'сообщения: пауза 3 минуты после отправки');
    click($('.comment .react-add')); await sleep(10);
    click($$('.emoji-pop [data-e]').find(b => b.dataset.e === '🔥')); await sleep(10);
    ok(/🔥/.test($('.comment .reacts').textContent), 'сообщения: реакция смайликом');
    click($('.comment .react-chip.on')); await sleep(10);
    ok(!$('.comment .react-chip.on'), 'сообщения: повторное нажатие снимает реакцию');
    click($('[data-action="togglePaid"][data-user="u3"]')); await sleep(10);
    ok($('[data-action="togglePaid"][data-user="u3"]').classList.contains('on'), 'сбор: складчина');
    // Номера — по тому же правилу, что на сервере: идущий гость виден организатору целиком; приглашённого «по номеру» организатор видит
    // целиком и подписью «По номеру» (кто это в сервисе — не говорим).
    const guestRow = id => $$('.people .person').find(li => li.querySelector(`a[href="#/user/${id}"]`));
    const phoneRow = $$('.people .person').find(li => /По номеру/.test(li.textContent));
    ok(/\+996 700 000 002/.test(guestRow('u2').textContent) && /\+996 555 123 456/.test(phoneRow?.textContent || ''), 'номер: идущий гость и приглашённый по номеру — организатору целиком');
    ok(!$('[data-action="removeGuest"]'), 'участники: по умолчанию без кнопок «Убрать»');
    click($('[data-action="guestEdit"]')); await sleep(10);
    ok($$('[data-action="removeGuest"]').length === 5, 'участники: «карандаш» — «Убрать» у каждого приглашённого');
    click($('[data-action="removeGuest"][data-user="u4"]')); await sleep(10);
    ok(/Убрать из сбора/.test($('.modal h2').textContent), 'убрать из сбора: с подтверждением');
    click($('#rg-ok')); await sleep(10);
    ok(!guestRow('u4') && !JSON.parse(w.localStorage.getItem('hookahparty.v2')).events.find(e => e.id === 'e1').invites.some(i => i.userId === 'u4'), 'убрать из сбора: Сабины в сборе больше нет');
    click($('[data-action="guestEdit"]')); await sleep(10);
    click($('[data-action="showVenue"]')); await sleep(40);
    ok(w.location.hash === '#/venues' && !$('#venues-map .map-card').hidden && /Savor/.test($('#venues-map .map-card').textContent), 'сбор → место на карте');

    await go('#/history');
    ok($$('.story').length === 5 && $$('.story-month').length >= 3, 'история: 5 вечеров по месяцам');
    ok($$('.story .story-shot .pack-art').length >= 10, 'история: обложки из иллюстраций');
    const before5 = +$('[data-action="storyFire"][data-id="e5"] b').textContent;
    click($('[data-action="storyFire"][data-id="e5"]')); await sleep(10);
    ok(Math.abs(+$('[data-action="storyFire"][data-id="e5"] b').textContent - before5) === 1, 'история: «Огонь»');
    const sf = $('.story-form[data-story="e5"]');
    sf.querySelector('textarea').value = 'Тест'; sf.requestSubmit(); await sleep(10);
    ok(!$('.story-form[data-story="e5"]') && /уже комментировали этот вечер сегодня/.test($('#story-e5').textContent), 'история: один комментарий в день');
    ok(!!$('.story-form[data-story="e6"]'), 'история: лимит считается для каждого вечера отдельно');
    click($('[data-action="likeThis"][data-id="e6"]')); await sleep(10);
    ok(/У вас уже есть активный сбор/.test($('.modal h2').textContent), 'история: «Хочу так же» тоже проверяет активный сбор');
    click($('[data-action="closeModal"]'));

    await go('#/catalog');
    ok($$('.t-card').length === 17, 'каталог');
    ok($$('.t-card .pack-art').length === 17 && $$('.t-card .pack-art ellipse, .t-card .pack-art circle').length > 200, 'каталог: иллюстрации вкусов');
    click($('[data-action="catFilter"][data-strength="strong"]')); await sleep(10);
    ok($$('.t-card').length === 6, 'каталог: фильтр');
    await tabTo('cat', 'bowls');
    ok($$('.t-card[data-action="bowlInfo"]').length === 6 && $$('.t-card .pack-art').length === 6, 'каталог: чаши с картинками');
    click($('.t-card[data-action="bowlInfo"][data-id="b-phunnel"]')); await sleep(10);
    ok(!!$('.modal .specs') && /Как забивать/.test($('.modal').textContent) && $$('.modal .pc-list li').length >= 2 && !!$('.modal .fit-chip'), 'чаша: подробности, совет и подходящие табаки');
    click($('.modal-x')); await sleep(5);
    await tabTo('cat', 'gear');
    ok($$('.t-card[data-action="gearInfo"]').length === 8 && $$('.t-card .pack-art').length === 8, 'каталог: аксессуары с картинками');
    click($('.t-card[data-action="gearInfo"]')); await sleep(10);
    ok(!!$('.modal .specs') && !!$('.modal .tip-box'), 'аксессуар: описание, характеристики, совет');
    click($('.modal-x')); await sleep(5);
    await tabTo('cat', 'mixes');
    click($('.mix-card')); await sleep(10);
    ok(!!$('.modal .mix-ring') && $$('.modal .mix-parts li').length >= 2 && /Подойдёт чаша/.test($('.modal').textContent), 'микс: раскрывается с долями, крепостью и чашей');
    click($('.modal-x')); await sleep(5);
    await tabTo('cat', 'tobaccos');
    await go('#/people'); ok($$('.person-card').length === 3, 'люди');
    await go('#/profile'); await tabTo('profile', 'settings');
    click($('[data-action="setAccent"][data-accent="mint"]')); await sleep(10);
    ok(d.documentElement.dataset.accent === 'mint', 'профиль: акцент');
    ok($$('[data-action="setAccent"]').length >= 8 && !!$('[data-accent="blue"]') && !!$('[data-accent="green"]'), 'профиль: синий, зелёный и другие цвета');
    ok(d.documentElement.hasAttribute('data-accent-user'), 'профиль: выбранный цвет сильнее праздничного');
    click($('[data-action="setLamp"][data-lamp="off"]')); await sleep(10);
    ok(d.documentElement.dataset.lamp === 'off', 'профиль: фонарик выключается');
    click($('[data-action="setLamp"][data-lamp="accent"]')); await sleep(10);
    ok(d.documentElement.dataset.lamp === 'accent', 'профиль: фонарик по цвету акцента');
    click($('[data-action="setSeason"][data-season="newyear"]')); await sleep(10);
    ok(d.documentElement.dataset.season === 'newyear' && /Новым годом/.test($('#season-ribbon').textContent), 'праздник: ручной выбор «Новый год»');
    click($('[data-action="closeRibbon"]')); await sleep(5);
    ok($('#season-ribbon').hidden, 'праздник: ленту можно скрыть');
    click($('[data-action="setSeason"][data-season="off"]')); await sleep(10);
    ok(!d.documentElement.dataset.season && !$('.season-fx'), 'праздник: выключение');
    click($('[data-action="setSeason"][data-season="auto"]')); await sleep(10);

    // Защита
    ok(!blocked.length, 'фильтр разметки: все страницы и окна выше проходят его без потерь' + (blocked.length ? ' — ' + blocked.slice(0, 3).join(', ') : ''));
    const probe = d.createElement('div'); d.body.append(probe);
    probe.innerHTML = '<img src="x" onerror="alert(1)"><a href="javascript:alert(1)">a</a><script>alert(1)<\/script><b>ok</b>';
    ok(!probe.querySelector('[onerror], script') && !/^\s*javascript:/i.test(probe.querySelector('a').getAttribute('href') || '') && /ok/.test(probe.textContent), 'защита: фильтр вырезает опасную разметку');
    ok(blocked.length === 1, 'защита: срабатывание фильтра записано'); blocked.length = 0;
    probe.remove();
    await go('#/event/<script>'); ok(/Такой страницы нет/.test(text()), 'защита: неизвестные адреса не открываются');

    // Приглашение ссылкой в Telegram и WhatsApp
    await go('#/event/e1');
    ok(!!$('.share-strip [data-via="tg"]') && !!$('.share-strip [data-via="wa"]'), 'приглашение: кнопки Telegram и WhatsApp на странице сбора');
    click($('.share-strip [data-via="tg"]')); await sleep(30);
    const tgA = $('.modal a.share-tg');
    ok(!!tgA && /^https:\/\/t\.me\/share\/url\?url=/.test(tgA.getAttribute('href')), 'приглашение: ссылка Telegram');
    ok(/^https:\/\/wa\.me\/\?text=/.test($('.modal a.share-wa').getAttribute('href')), 'приглашение: ссылка WhatsApp');
    ok(/Зову на кальян/.test($('.share-preview').textContent), 'приглашение: готовый текст');
    ok(!$('#sh-reset'), 'приглашение: в демо ссылку не сменить — в ней самой данные сбора');
    const inviteUrl = new w.URL(tgA.getAttribute('href')).searchParams.get('url');
    ok(inviteUrl.startsWith('https://marlendiusheew-sudo.github.io/hookah-party/#/join/d'), 'приглашение: ссылка ведёт на настоящий сайт');
    const inviteHash = '#' + inviteUrl.split('#')[1];
    click($('.modal-x')); await sleep(5);
    await go(inviteHash);
    ok(!!$('.join-card') && /Это ваш сбор/.test(text()), 'приглашение: организатор видит свой сбор');
    await go('#/join/dAAAA-bad'); ok(/Приглашение не найдено/.test(text()), 'приглашение: испорченная ссылка');
    click($('[data-action="ics"]') || $('a')); await sleep(5);
    await go('#/event/e1'); click($('[data-action="ics"]')); await sleep(10);
    ok(/calendar\.google\.com/.test($('.modal').innerHTML) && !!$('#cal-ics'), 'календарь: Google и файл .ics');
    click($('.modal-x')); await sleep(5);

    // Правила и конфиденциальность
    await go('#/privacy'); ok(/Политика конфиденциальности/.test(text()) && $$('.legal section').length >= 8, 'страница: конфиденциальность');
    ok(/не обращается ни к Google Fonts/.test(text()) && !/fonts\.(googleapis|gstatic)\.com/.test(fs.readFileSync(dir + '/index.html', 'utf8')), 'политика: шрифты с нашего сервера, сторонних запросов нет — и index.html их не делает');
    await go('#/terms'); ok(/Правила сервиса/.test(text()) && /18 лет/.test(text()), 'страница: правила');
    const sw = fs.readFileSync(dir + '/sw.js', 'utf8'), ver = /VERSION = (\d+)/.exec(sw)[1];
    ok(fs.readFileSync(dir + '/index.html', 'utf8').match(/\?v=(\d+)/g).every(x => x === '?v=' + ver), 'офлайн: версия кеша совпадает с ?v= в index.html');
    await go('#/profile'); click($('.utabs [data-tab="settings"]')); await sleep(10);
    ok(!!$('.sec-panel') && /Журнал безопасности/.test($('.sec-panel').textContent), 'защита: панель безопасности в профиле');
    // Браузер заблокировал код (CSP или Trusted Types): в демо событие попадает в журнал этого браузера; от адреса — только сайт.
    const cspEv = new w.Event('securitypolicyviolation', { bubbles: true });
    Object.assign(cspEv, { effectiveDirective: 'script-src-elem', violatedDirective: 'script-src-elem', blockedURI: 'https://evil.example/steal.js?token=SECRET', sample: 'alert(1)\u0000', sourceFile: 'https://example.test/app.js?v=9', lineNumber: 12 });
    d.body.dispatchEvent(cspEv);
    await go('#/'); await go('#/profile');
    const secText = $('.sec-panel').textContent;
    ok(/Браузер заблокировал запрос \(CSP\)/.test(secText) && secText.includes('script-src-elem https://evil.example «alert(1)»') && !/SECRET|steal\.js/.test(secText), 'защита: нарушение CSP — в журнале безопасности, адрес без пути');
    ok(!$('#srv-devices') && !$('[data-action="logoutAll"]'), 'защита: в демо нет списка устройств с сервера');
    ok(!$('#nav').textContent.includes('Админ') && !$('.admin-entry'), 'админ: в демо нет ни вкладки, ни входа в панель');
    await go('#/admin'); ok(/Такой страницы нет/.test(text()) && !d.querySelector('script[src*="admin.js"]'), 'админ: в демо адрес панели не открывается и код не грузится');
    await go('#/notifications');
    ok(!!$('.utabs[data-tabs="notif"]') && !$('[data-tab="security"]') && !/Безопасность/.test($('.notif-settings').textContent), 'уведомления: в демо нет вкладки «Безопасность» — эти уведомления присылает сервер');
    await go('#/profile');
    click($('[data-action="logout"]')); await sleep(40);
    ok(/Добро пожаловать в Hookah Party!/.test(text()) && $$('.tiles .tile').length === 3, 'гость: главная');
    await go('#/events'); ok(/Войдите, чтобы видеть свои сборы/.test(text()), 'гость: события просят войти');
    w.localStorage.removeItem('hp.sent.e1'); // как будто ссылку открыли на другом устройстве
    await go(inviteHash);
    ok(/Алекс зовёт вас/.test(text()) && $$('.join-reply-btns .btn').length === 2 && !!$('.join-about'), 'приглашение: гость видит сбор и кнопки ответа');
    click($('.join-reply-btns [data-status="going"]')); await sleep(10);
    ok(/Вы ответили: иду/.test(text()) && !!$('#join-reply a.share-tg') && !!$('#join-reply a.share-wa'), 'приглашение: ответ уходит организатору в мессенджер');
    click($('[data-action="joinChange"]')); await sleep(10);
    ok($$('.join-reply-btns .btn').length === 2, 'приглашение: ответ можно изменить');
    await go('#/login');
    for (let i = 0; i < 5; i++) { setVal('#lg-phone', '0700000001'); $('#lg-pass').value = 'wrong'; $('#login-form').requestSubmit(); await sleep(450); }
    ok(/заблокирован/.test($('#lg-err').textContent), 'защита: блокировка после 5 неверных паролей');

    // «Забыли пароль?»: вход по коду из SMS (блокировка пароля его не касается) и сразу окно смены пароля без текущего.
    ok(/Забыли пароль\?/.test($('#lg-forgot').textContent), 'вход: ссылка «Забыли пароль?»');
    setVal('#lg-phone', ''); click($('#lg-forgot')); await sleep(10);
    ok(/номер телефона/.test($('#lg-err').textContent), '«Забыли пароль?»: без номера просит ввести номер');
    setVal('#lg-phone', '0700000001'); click($('#lg-forgot')); await sleep(20);
    ok(/Восстановление доступа/.test($('#auth-card').textContent) && /^\d{6}$/.test($('#sms-hint b')?.textContent || '') && $$('.code-inputs input').length === 6, '«Забыли пароль?»: переход ко входу по коду из SMS (6 цифр)');
    typeCode($('#sms-hint b').textContent);
    ok(await until(() => !!$('#pw-form')), '«Забыли пароль?»: после входа сразу открывается окно смены пароля');
    ok(w.location.hash === '#/profile' && !!$('.sec-panel') && $('.utabs[data-tabs="profile"] [data-tab="settings"]').getAttribute('aria-selected') === 'true', '«Забыли пароль?»: под окном — Профиль → Настройки');
    ok($('#pw-cur-f').hidden && !$('#pw-sms').hidden && /15 минут/.test($('#pw-sms').textContent), 'после входа по SMS текущий пароль не нужен — и сказано почему');
    ok(!!$('.sec-pass.sms .btn-primary[data-action="changePassword"]'), '«Безопасность»: после входа по SMS смена пароля подсвечена');
    setVal('#pw-new', 'Smoke-Night-2027'); setVal('#pw-rep', 'Smoke-Night-2028'); $('#pw-form').requestSubmit(); await sleep(10);
    ok(/не совпадают/.test($('#pw-rep-err').textContent) && $('#pw-rep').getAttribute('aria-invalid') === 'true', 'смена пароля: повтор не совпал — ошибка у своего поля');
    setVal('#pw-new', 'short1'); setVal('#pw-rep', 'short1'); $('#pw-form').requestSubmit(); await sleep(10);
    ok(/не короче 8 символов/.test($('#pw-new-err').textContent) && !$('#pw-rep-err').textContent, 'смена пароля: слабый пароль — ошибка у поля нового');
    setVal('#pw-new', 'Smoke-Night-2027');
    ok($('.modal .pass-meter').dataset.score === '3' && /Надёжный пароль/.test($('#pw-strength').textContent) && !$('#pw-new-err').textContent, 'смена пароля: индикатор надёжности, ошибка уходит при вводе');
    const alexPass = JSON.stringify(store().users.find(x => x.id === 'u1').pass);
    setVal('#pw-rep', 'Smoke-Night-2027'); $('#pw-form').requestSubmit();
    ok(await until(() => !$('#pw-form'), 5000) && /Пароль изменён, остальные сеансы завершены/.test($('#toasts').textContent), 'смена пароля без текущего после входа по SMS');
    ok(JSON.stringify(store().users.find(x => x.id === 'u1').pass) !== alexPass && !store().viaSmsAt && !$('.sec-pass.sms'), 'пароль сменился, «без текущего» больше нельзя');
    ok(/Пароль изменён/.test($('.sec-panel').textContent), 'смена пароля — в журнале безопасности');
    click($('[data-action="changePassword"]')); await sleep(10);
    ok(!$('#pw-cur-f').hidden && $('#pw-sms').hidden, 'второй раз — снова нужен текущий пароль');
    click($('.modal [data-action="closeModal"]')); await sleep(10);
    click($('[data-action="logout"]')); await sleep(40);
    await go('#/login');
    setVal('#lg-phone', '0700000001'); $('#lg-pass').value = 'hookah'; $('#login-form').requestSubmit();
    ok(await until(() => /Неверный номер или пароль/.test($('#lg-err').textContent), 3000), 'старый пароль больше не подходит');
    $('#lg-pass').value = 'Smoke-Night-2027'; $('#login-form').requestSubmit();
    ok(await until(() => /Рады видеть вас снова, Алекс/.test(text()), 3000), 'вход с новым паролем');
    await go('#/profile');
    click($('[data-action="logout"]')); await sleep(40);
    await go('#/register');
    setVal('#rg-name', 'Айбек'); setVal('#rg-phone', '0555123499');
    ok($('#rg-phone').value === '+996 555 123 499', 'маска телефона +996: ' + $('#rg-phone').value);
    $('#rg-pass').value = 'Kalyan-Night-2026'; $('#rg-age').checked = true;
    $('#rg-pass').value = '12345678'; $('#reg-form').requestSubmit(); await sleep(10);
    ok(/буквы, и цифры/.test($('#rg-err').textContent), 'защита: слабый пароль не принимается');
    $('#rg-pass').value = 'Kalyan-Night-2026';
    $('#reg-form').requestSubmit(); await sleep(10);
    const code = $('#sms-hint b').textContent;
    [...code].forEach((c, i) => { const b = $('#code-' + i); b.value = c; b.dispatchEvent(new w.Event('input', { bubbles: true })); });
    await sleep(10);
    click($('#av-done')); await sleep(40);
    ok(/Рады видеть вас снова, Айбек/.test(text()), 'регистрация и вход');

    // Журнал безопасности хранится не дольше 90 дней, удаление аккаунта — в настройках профиля
    const secLogNow = () => JSON.parse(w.localStorage.getItem('hp.sec.log') || '[]');
    w.localStorage.setItem('hp.sec.log', JSON.stringify([...secLogNow(), { type: 'csp', detail: 'старое событие', at: new Date(Date.now() - 100 * 864e5).toISOString() }]));
    // Данные Айбека, которые должны исчезнуть вместе с аккаунтом: друг, «огонь» рассказу, лайк, свой микс, свой сбор с гостем и сообщением.
    await go('#/user/u1'); click($('[data-action="toggleFriend"][data-id="u1"]')); await sleep(10);
    await go('#/history'); click($('[data-action="storyFire"][data-id="e5"]')); await sleep(10);
    await go('#/catalog'); await tabTo('cat', 'mixes'); click($('[data-action="likeMix"][data-id="m1"]')); await sleep(10);
    click($('[data-action="newMix"]')); await sleep(10);
    setVal('#mx-name', 'Прощальный микс'); $('#mx-t0').value = 'od-cola'; $('#mx-t1').value = 'tg-canemint'; $('#mix-form').requestSubmit(); await sleep(10);
    click($('.plus-btn[data-action="newEvent"]')); await sleep(10);
    setVal('#ev-title', 'Прощальный сбор'); setVal('#ev-venue', 'Hookah'); setVal('#inv-q', 'Дина'); click($('.suggest [data-u="u2"]')); $('#ev-form').requestSubmit(); await sleep(30);
    $('#comment-text').value = 'Жду всех'; $('#comment-form').requestSubmit(); await sleep(10);
    const mine = store(), aibekId = mine.session;
    ok(mine.users.find(x => x.id === 'u1').friends.includes(aibekId) && mine.mixes.some(m => m.authorId === aibekId) && mine.mixes.find(m => m.id === 'm1').likes.includes(aibekId)
      && mine.events.find(e => e.id === 'e5').story.fire.includes(aibekId) && mine.events.some(e => e.hostId === aibekId && e.invites.some(i => i.userId === 'u2') && e.comments.length === 1), 'удаление аккаунта: перед удалением у Айбека есть друг, микс, лайк, «огонь» и свой сбор');
    await go('#/profile'); await tabTo('profile', 'settings');
    ok(!/старое событие/.test($('.sec-panel').textContent) && secLogNow().every(x => Date.now() - new Date(x.at) < 90 * 864e5) && secLogNow().length > 0, 'журнал: записи старше 90 дней удаляются');

    // Смена пароля в демо: нужен текущий; ошибки у полей; 5 неверных — блокировка на 5 минут, как при входе.
    click($('.sec-pass [data-action="changePassword"]')); await sleep(10);
    ok(/Смена пароля/.test($('.modal h2').textContent) && !$('#pw-cur-f').hidden && $('#pw-sms').hidden && $('#pw-cur').getAttribute('autocomplete') === 'current-password'
      && $('#pw-new').getAttribute('autocomplete') === 'new-password' && !!$('.modal .pass-meter'), 'смена пароля: окно с текущим, новым и повтором');
    $('#pw-form').requestSubmit(); await sleep(10);
    ok(/Введите текущий пароль/.test($('#pw-cur-err').textContent), 'смена пароля: без текущего — ошибка у его поля');
    setVal('#pw-cur', 'Kalyan-Night-2026'); setVal('#pw-new', 'Kalyan-Night-2026'); setVal('#pw-rep', 'Kalyan-Night-2026'); $('#pw-form').requestSubmit(); await sleep(10);
    ok(/совпадает с текущим/.test($('#pw-new-err').textContent), 'смена пароля: тот же пароль не принимается');
    setVal('#pw-cur', 'wrong-pass1'); setVal('#pw-new', 'Night-Kalyan-2027'); setVal('#pw-rep', 'Night-Kalyan-2027'); $('#pw-form').requestSubmit();
    ok(await until(() => /Неверный текущий пароль. Осталось попыток: 4/.test($('#pw-cur-err').textContent), 3000) && !$('#pw-cur').value, 'смена пароля: неверный текущий — ошибка у поля, попыток осталось 4');
    const fails = JSON.parse(w.localStorage.getItem('hp.sec.fails') || '{}');
    ok(fails['pass:' + aibekId]?.n === 1, 'смена пароля: неверная попытка посчитана');
    w.localStorage.setItem('hp.sec.fails', JSON.stringify({ ...fails, ['pass:' + aibekId]: { n: 4 } })); // как будто ошибок уже четыре
    setVal('#pw-cur', 'wrong-pass1'); $('#pw-form').requestSubmit();
    ok(await until(() => /заблокирована на 5 минут/.test($('#pw-cur-err').textContent), 3000), 'смена пароля: пятая ошибка — блокировка на 5 минут');
    setVal('#pw-cur', 'Kalyan-Night-2026'); $('#pw-form').requestSubmit();
    ok(await until(() => /заблокирована ещё на/.test($('#pw-cur-err').textContent), 3000), 'смена пароля: во время блокировки не принимается даже верный пароль');
    ok(secLogNow().some(x => x.type === 'password_change_locked') && secLogNow().some(x => x.type === 'password_change_fail'), 'смена пароля: ошибки и блокировка — в журнале');
    const unlocked = JSON.parse(w.localStorage.getItem('hp.sec.fails')); delete unlocked['pass:' + aibekId];
    w.localStorage.setItem('hp.sec.fails', JSON.stringify(unlocked)); // как будто 5 минут прошли
    setVal('#pw-cur', 'Kalyan-Night-2026'); $('#pw-form').requestSubmit();
    ok(await until(() => !$('#pw-form'), 5000) && /Пароль изменён, остальные сеансы завершены/.test($('#toasts').textContent), 'смена пароля с текущим: готово');
    ok(!JSON.parse(w.localStorage.getItem('hp.sec.fails'))['pass:' + aibekId] && secLogNow()[0].type === 'password_changed', 'смена пароля: счётчик ошибок сброшен, событие в журнале');
    const dz = $('.danger-zone');
    ok(!!dz && /Удаление аккаунта/.test(dz.textContent) && $$('.danger-zone .dz-list li').length === 6 && /нельзя/.test(dz.textContent), 'удаление аккаунта: отдельная панель, что удалится и что это навсегда');
    click($('[data-action="setLang"][data-lang="en"]')); await sleep(10);
    ok(/Delete account/.test($('.danger-zone').textContent) && /cannot be restored/.test($('.danger-zone').textContent), 'удаление аккаунта: панель на английском');
    click($('[data-action="setLang"][data-lang="ru"]')); await sleep(10);
    const aibek = store().users.find(x => x.name === 'Айбек');
    click($('[data-action="deleteAccount"]')); await sleep(10);
    ok(/Удалить аккаунт/.test($('.modal h2').textContent) && $('#da-pass').type === 'password' && $('#da-pass').getAttribute('autocomplete') === 'current-password', 'удаление аккаунта: окно с паролем');
    ok($('#da-go').disabled && $('#da-go').classList.contains('btn-danger-solid'), 'удаление аккаунта: красная кнопка неактивна, пока нет галочки');
    $('#da-sure').checked = true; $('#da-sure').dispatchEvent(new w.Event('change', { bubbles: true }));
    ok(!$('#da-go').disabled, 'удаление аккаунта: галочка «Понимаю…» включает кнопку');
    $('#da-pass').value = 'wrong-pass1'; $('#del-acc-form').requestSubmit();
    ok(await until(() => /Неверный пароль. Осталось попыток: 4/.test($('#da-err')?.textContent || '')), 'удаление аккаунта: неверный пароль — ошибка, аккаунт на месте');
    ok(store().users.some(x => x.id === aibek.id) && store().session === aibek.id, 'удаление аккаунта: после ошибки ничего не удалено');
    $('#da-pass').value = 'Night-Kalyan-2027'; $('#del-acc-form').requestSubmit(); // пароль уже новый — смена выше
    ok(await until(() => !store().session), 'удаление аккаунта: верный пароль — выход из аккаунта');
    const left = store(), keys = [...Array(w.localStorage.length)].map((_, i) => w.localStorage.key(i));
    ok(!left.users.some(x => x.id === aibek.id) && !left.mixes.some(m => m.name === 'Прощальный микс') && !left.events.some(e => e.title === 'Прощальный сбор'), 'удаление аккаунта: пользователь, его микс и сбор удалены');
    const leaks = keys.filter(k => [aibek.id, aibek.phone].some(s => (k + w.localStorage.getItem(k)).includes(s)));
    ok(!leaks.length, 'удаление аккаунта: в браузере не осталось ни его id, ни номера' + (leaks.length ? ': ' + leaks.join(', ') : ''));
    ok(secLogNow()[0].type === 'account_deleted' && !secLogNow().some(x => x.detail === 'Айбек'), 'удаление аккаунта: в журнале — без имени');
    await sleep(40);
    ok(/Добро пожаловать в Hookah Party!/.test(text()) && /Аккаунт удалён/.test($('#toasts').textContent), 'удаление аккаунта: гостевая главная и сообщение');
    await go('#/privacy'); ok(/Профиль → Настройки → «Удаление аккаунта»/.test(text()) && /90 дней/.test(text()) && !/в течение 30 дней/.test(text()), 'политика: удаление аккаунта самостоятельно, журнал 90 дней');
    ok(!blocked.length, 'фильтр разметки: и остальные страницы проходят его без потерь' + (blocked.length ? ' — ' + blocked.slice(0, 3).join(', ') : ''));

    // ===== Сайт с сервером не показывает демо-данные и чужой вход никогда: ни при лимите запросов, ни при сбое сервера, ни без сети =====
    // Каждый сценарий — отдельная страница на «боевом» адресе, ответы сервера — заглушки. Повторная попытка (раз в 20 секунд) здесь — сразу.
    const src = f => fs.readFileSync(dir + '/' + f, 'utf8'), appSrc = src('app.js'), artSrc = src('art.js'), mapSrc = src('map-data.js');
    const DEMO = /Рады видеть вас снова, Алекс|Пятничный сбор|Дина|Тимур/, DOWN = /Сервер ненадолго недоступен/, OFF = /Нет соединения/;
    const BOOT = { session: null, role: null, csrf: null, phoneCodes: ['996'], users: [{ id: 's1', name: 'Серверный Гость', avatar: null }], events: [], reviews: [], mixes: [], notifications: [], storiesSeeded: true };
    const HEALTH = [200, { ok: true, mode: 'server', sms: 'dev', version: 1 }], LIMIT = [429, { error: 'rate_limited', message: { ru: 'Слишком много запросов.', en: 'Too many requests.' } }];
    async function site({ health, bootstrap = [200, BOOT], mode, demoLeft = false }) {
      const w2 = new JSDOM(html, { url: 'https://hookah.example/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: new VirtualConsole() }).window, d2 = w2.document;
      w2.scrollTo = () => {}; w2.Element.prototype.scrollIntoView = () => {}; if (!w2.TextEncoder) Object.assign(w2, { TextEncoder, TextDecoder });
      const later = w2.setTimeout.bind(w2); w2.setTimeout = (f, ms, ...a) => later(f, ms >= 20e3 ? 30 : ms, ...a);
      const net = { health, bootstrap };
      w2.fetch = async url => {
        const r = url === '/api/health' ? net.health : url === '/api/bootstrap' ? net.bootstrap : [401, { error: 'auth_required' }];
        if (r === 'offline') throw new TypeError('Failed to fetch');
        return { ok: r[0] >= 200 && r[0] < 300, status: r[0], json: async () => { if (r[1] === undefined) throw new SyntaxError('HTML'); return r[1]; } };
      };
      w2.localStorage.setItem('hp.age18', 'yes');
      if (mode) w2.localStorage.setItem('hp.mode', mode);
      // Остатки «регистрации» в демо, когда прежние версии по ошибке показывали его вместо сервера: номер и хэш пароля.
      if (demoLeft) { w2.localStorage.setItem('hookahparty.v2', JSON.stringify({ session: 'uR', users: [{ id: 'uR', name: 'Марат', phone: '996555123987', pass: { alg: 'pbkdf2-sha256', hash: 'x' } }], events: [] })); w2.localStorage.setItem('hp.sec.fails', '{"996555123987":{"n":1}}'); w2.localStorage.setItem('hp.sec.rl', '{"sms:996555123987":[1]}'); }
      w2.eval(mapSrc); w2.eval(artSrc); w2.eval(appSrc);
      const txt = () => d2.body.textContent.replace(/\s+/g, ' ');
      return { w: w2, d: d2, net, txt, nav: async h => { w2.location.hash = h; await sleep(30); }, close: () => w2.close() };
    }
    // Лимит запросов на /api/health (люди за одним адресом): экран «сервер недоступен», меню его не обходит, сервер ответил — страница сама.
    let s = await site({ health: LIMIT });
    ok(await until(() => DOWN.test(s.txt())) && !DEMO.test(s.txt()) && !s.d.querySelector('.me-link') && !s.d.querySelector('#topbar-actions a[href="#/login"]'), 'сервер: лимит на /api/health — честный экран, ни демо-данных, ни чужого входа');
    ok(s.w.localStorage.getItem('hp.mode') === 'server', 'сервер: ответ ошибкой в формате сервера запоминает, что сервер здесь есть');
    for (const h of ['#/events', '#/profile', '#/people', '#/event/e1', '#/history']) await s.nav(h);
    ok(DOWN.test(s.txt()) && !DEMO.test(s.txt()), 'сервер: переходы по меню не открывают демо вместо экрана ожидания');
    click(s.d.querySelector('[data-action="setLang"][data-lang="en"]')); await sleep(20);
    ok(/The server is briefly unavailable/.test(s.txt()) && !DEMO.test(s.txt()), 'сервер: экран ожидания на английском');
    click(s.d.querySelector('[data-action="setLang"][data-lang="ru"]')); await sleep(20);
    s.net.health = HEALTH;
    ok(await until(() => s.d.documentElement.dataset.mode === 'server' && !DOWN.test(s.txt())), 'сервер: ответил — страница открылась сама');
    await s.nav('#/');
    ok(/Добро пожаловать в Hookah Party!/.test(s.txt()) && !DEMO.test(s.txt()), 'сервер: после ожидания — данные сервера (гость), не демо');
    s.close();
    // Сервер ответил на /api/health, но не отдал данные (лимит на /api/bootstrap) — тоже экран ожидания; демо-остатки стёрты.
    s = await site({ health: HEALTH, bootstrap: LIMIT, mode: 'server', demoLeft: true });
    ok(await until(() => DOWN.test(s.txt())) && !DEMO.test(s.txt()) && !/Марат/.test(s.txt()) && s.d.documentElement.dataset.mode === 'server', 'сервер: данные не пришли — экран ожидания, не демо');
    ok(['hookahparty.v2', 'hp.sec.fails', 'hp.sec.rl'].every(k => s.w.localStorage.getItem(k) === null), 'сервер: демо-данные с номером и хэшем пароля стёрты из браузера');
    await s.nav('#/register'); await s.nav('#/login');
    ok(DOWN.test(s.txt()) && !s.d.querySelector('#reg-form, #login-form'), 'сервер: пока данных нет, вход и регистрация не открываются (иначе ушли бы в демо)');
    s.net.bootstrap = [200, BOOT];
    ok(await until(() => !DOWN.test(s.txt()) && !!s.d.querySelector('#login-form')), 'сервер: данные пришли — открылась нужная страница');
    s.close();
    // Перезапуск сервера (5xx без JSON) и 404 там, где сервер уже был, — сбой, а не «сайт без сервера».
    for (const [health, name] of [[[503], '503 от прокси'], [[404], '404 там, где был сервер']]) {
      s = await site({ health, mode: 'server' });
      ok(await until(() => DOWN.test(s.txt())) && !DEMO.test(s.txt()), 'сервер: ' + name + ' — экран ожидания, не демо');
      s.close();
    }
    // Нет сети: где был сервер — «Нет соединения» (и меню его не обходит); где сервера не было — демо работает и без сети.
    s = await site({ health: 'offline', mode: 'server' });
    ok(await until(() => OFF.test(s.txt()), 3000) && !DEMO.test(s.txt()), 'без сети: сайт с сервером честно говорит «Нет соединения»');
    await s.nav('#/events'); await s.nav('#/profile');
    ok(OFF.test(s.txt()) && !DEMO.test(s.txt()), 'без сети: переходы не открывают демо-данные');
    s.close();
    s = await site({ health: 'offline' });
    ok(await until(() => /Рады видеть вас снова, Алекс/.test(s.txt()), 3000), 'без сети: сайт без сервера (демо) работает на данных браузера');
    s.close();
  } catch (e) { errors.push('исключение: ' + e.stack); }
  console.log('\nОшибок: ' + errors.length); errors.forEach(e => console.log(e));
  process.exit(errors.length ? 1 : 0);
})();
