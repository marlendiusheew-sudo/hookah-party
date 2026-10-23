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
const dom = new JSDOM(html, { url: 'https://example.test/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window, d = w.document;
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
    await tabTo('cat', 'bowls'); ok($$('.art-svg').length === 5, 'каталог: чаши');
    await go('#/people'); ok($$('.person-card').length === 3, 'люди');
    await go('#/profile'); await tabTo('profile', 'settings');
    click($('[data-action="setAccent"][data-accent="mint"]')); await sleep(10);
    ok(d.documentElement.dataset.accent === 'mint', 'профиль: акцент');
    click($('[data-action="setSeason"][data-season="newyear"]')); await sleep(10);
    ok(d.documentElement.dataset.season === 'newyear' && /Новым годом/.test($('#season-ribbon').textContent), 'праздник: ручной выбор «Новый год»');
    click($('[data-action="closeRibbon"]')); await sleep(5);
    ok($('#season-ribbon').hidden, 'праздник: ленту можно скрыть');
    click($('[data-action="setSeason"][data-season="off"]')); await sleep(10);
    ok(!d.documentElement.dataset.season && !$('.season-fx'), 'праздник: выключение');
    click($('[data-action="setSeason"][data-season="auto"]')); await sleep(10);

    // Защита
    const probe = d.createElement('div'); d.body.append(probe);
    probe.innerHTML = '<img src="x" onerror="alert(1)"><a href="javascript:alert(1)">a</a><script>alert(1)<\/script><b>ok</b>';
    ok(!probe.querySelector('[onerror], script') && probe.querySelector('a').getAttribute('href') === '#' && /ok/.test(probe.textContent), 'защита: фильтр вырезает опасную разметку');
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
    await go('#/terms'); ok(/Правила сервиса/.test(text()) && /18 лет/.test(text()), 'страница: правила');
    const sw = fs.readFileSync(dir + '/sw.js', 'utf8'), ver = /VERSION = (\d+)/.exec(sw)[1];
    ok(fs.readFileSync(dir + '/index.html', 'utf8').match(/\?v=(\d+)/g).every(x => x === '?v=' + ver), 'офлайн: версия кеша совпадает с ?v= в index.html');
    await go('#/profile'); click($('.utabs [data-tab="settings"]')); await sleep(10);
    ok(!!$('.sec-panel') && /Журнал безопасности/.test($('.sec-panel').textContent), 'защита: панель безопасности в профиле');
    ok(!$('#nav').textContent.includes('Админ') && !$('.admin-entry'), 'админ: в демо нет ни вкладки, ни входа в панель');
    await go('#/admin'); ok(/Такой страницы нет/.test(text()) && !d.querySelector('script[src*="admin.js"]'), 'админ: в демо адрес панели не открывается и код не грузится');
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
  } catch (e) { errors.push('исключение: ' + e.stack); }
  console.log('\nОшибок: ' + errors.length); errors.forEach(e => console.log(e));
  process.exit(errors.length ? 1 : 0);
})();
