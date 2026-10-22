/* Hookah Party — клиентский шаблон.
   Все данные хранятся в localStorage (демо). При переходе на приложение
   слой `api` ниже заменяется запросами к серверу, а отправка SMS — реальным
   провайдером (Firebase Phone Auth, Twilio, SMS.ru и т.п.). */
(() => {
  'use strict';

  // ---------- Утилиты ----------
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = p => p + Math.random().toString(36).slice(2, 9);
  const digits = s => String(s ?? '').replace(/\D/g, '');
  const hashStr = s => { let h = 2166136261; for (const c of String(s)) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; };
  // Только для демо. На сервере пароль хэшируется bcrypt/argon2.
  const hashPass = p => 'h' + hashStr('hp-salt:' + p).toString(36);

  function plural(n, one, few, many) {
    const a = Math.abs(n) % 100, b = a % 10;
    if (a > 10 && a < 20) return many;
    if (b > 1 && b < 5) return few;
    if (b === 1) return one;
    return many;
  }
  function normPhone(s) {
    let d = digits(s);
    if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1);
    if (d.length === 10) d = '7' + d;
    return d;
  }
  const validPhone = d => d.length >= 11 && d.length <= 15;
  function fmtPhone(s) {
    const d = normPhone(s);
    if (d.length === 11 && d[0] === '7') return `+7 (${d.slice(1, 4)}) ${d.slice(4, 7)}-${d.slice(7, 9)}-${d.slice(9)}`;
    return '+' + d;
  }
  function maskPhone(el) {
    el.addEventListener('input', () => {
      let d = digits(el.value);
      if (!d) { el.value = ''; return; }
      if (d[0] === '8') d = '7' + d.slice(1);
      if (d[0] !== '7') { el.value = '+' + d.slice(0, 15); return; }
      d = d.slice(0, 11);
      let o = '+7';
      if (d.length > 1) o += ' (' + d.slice(1, 4);
      if (d.length > 4) o += ') ' + d.slice(4, 7);
      if (d.length > 7) o += '-' + d.slice(7, 9);
      if (d.length > 9) o += '-' + d.slice(9, 11);
      el.value = o;
    });
  }
  const dtDay = new Intl.DateTimeFormat('ru-RU', { day: 'numeric' });
  const dtMon = new Intl.DateTimeFormat('ru-RU', { month: 'short' });
  const dtFull = new Intl.DateTimeFormat('ru-RU', { weekday: 'long', day: 'numeric', month: 'long' });
  const dtTime = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' });
  const isPast = e => new Date(e.at).getTime() < Date.now() - 4 * 3600e3;

  const ICON = {
    pin: '<svg viewBox="0 0 24 24"><path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>',
    plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    heart: '<svg viewBox="0 0 24 24"><path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/></svg>'
  };

  // ---------- Каталог ----------
  const CATALOG = {
    tobaccos: [
      { id: 'ds-supernova', brand: 'Darkside', flavor: 'Supernova', note: 'Ледяной холодок', strength: 7, tags: ['холодок'] },
      { id: 'ds-bananapapa', brand: 'Darkside', flavor: 'Bananapapa', note: 'Спелый банан', strength: 7, tags: ['фрукты'] },
      { id: 'ds-fallingstar', brand: 'Darkside', flavor: 'Falling Star', note: 'Манго и маракуйя', strength: 7, tags: ['тропики'] },
      { id: 'mh-pinkman', brand: 'MustHave', flavor: 'Pinkman', note: 'Грейпфрут и малина', strength: 6, tags: ['ягоды', 'цитрус'] },
      { id: 'mh-raspberry', brand: 'MustHave', flavor: 'Raspberry', note: 'Малина', strength: 6, tags: ['ягоды'] },
      { id: 'bb-cherry', brand: 'Black Burn', flavor: 'Cherry Shock', note: 'Кислая вишня', strength: 8, tags: ['ягоды', 'кислое'] },
      { id: 'el-grapefruit', brand: 'Element', flavor: 'Вода · Грейпфрут', note: 'Свежий грейпфрут', strength: 5, tags: ['цитрус'] },
      { id: 'tg-canemint', brand: 'Tangiers', flavor: 'Cane Mint', note: 'Сладкая мята', strength: 9, tags: ['мята'] },
      { id: 'af-twoapples', brand: 'Al Fakher', flavor: 'Two Apples', note: 'Двойное яблоко с анисом', strength: 3, tags: ['классика'] },
      { id: 'af-mint', brand: 'Al Fakher', flavor: 'Mint', note: 'Мята', strength: 3, tags: ['мята', 'классика'] },
      { id: 'ad-love66', brand: 'Adalya', flavor: 'Love 66', note: 'Арбуз, дыня, маракуйя и мята', strength: 4, tags: ['микс'] },
      { id: 'fu-gummi', brand: 'Fumari', flavor: 'White Gummi Bear', note: 'Мармеладные мишки', strength: 4, tags: ['сладкое'] },
      { id: 'sb-bluemist', brand: 'Starbuzz', flavor: 'Blue Mist', note: 'Черника с мятой', strength: 4, tags: ['ягоды', 'мята'] },
      { id: 'se-watermelon', brand: 'Sebero', flavor: 'Арбуз', note: 'Сочный арбуз', strength: 6, tags: ['фрукты'] },
      { id: 'du-pear', brand: 'Duft', flavor: 'Pear', note: 'Спелая груша', strength: 5, tags: ['фрукты'] },
      { id: 'od-cola', brand: 'Overdose', flavor: 'Cola', note: 'Кола', strength: 7, tags: ['напитки'] },
      { id: 'ch-icemint', brand: 'Chabacco', flavor: 'Ice Mint', note: 'Бестабачная смесь: мята со льдом', strength: 1, tags: ['бестабачное', 'мята'] }
    ],
    bowls: [
      { id: 'b-phunnel', name: 'Oblako Phunnel M', type: 'Фанел', note: 'Табак не проваливается в шахту, жар держится ровно' },
      { id: 'b-turka', name: 'Kong Turkish', type: 'Турка', note: 'Классика с отверстиями на дне' },
      { id: 'b-killer', name: 'Cosmo Bowl Killer', type: 'Киллер', note: 'Глубокая чаша для плотной забивки' },
      { id: 'b-harmony', name: 'HookahJohn Harmony', type: 'Фанел', note: 'Глина, мягкий прогрев' },
      { id: 'b-fruit', name: 'Чаша на грейпфруте', type: 'На фрукте', note: 'Половинка грейпфрута вместо чаши' }
    ],
    gear: [
      { id: 'g-lotus', name: 'Kaloud Lotus I+', type: 'Калауд', note: 'Контроль жара без фольги' },
      { id: 'g-coal', name: 'Кокосовый уголь 25 мм', type: 'Уголь', note: '72 кубика, разжиг 8–10 минут на плитке' },
      { id: 'g-hose', name: 'Силиконовый шланг', type: 'Шланг', note: 'Моется и не впитывает вкус' },
      { id: 'g-mouth', name: 'Личный мундштук', type: 'Мундштук', note: 'Гигиена на общих сборах' },
      { id: 'g-tongs', name: 'Щипцы для угля', type: 'Инструмент', note: 'Длина 20 см' },
      { id: 'g-stove', name: 'Плитка для угля', type: 'Розжиг', note: 'Электрическая, 800 Вт' }
    ]
  };
  const tobacco = id => CATALOG.tobaccos.find(t => t.id === id);
  const bowl = id => CATALOG.bowls.find(b => b.id === id);

  // ---------- Хранилище (демо) ----------
  const KEY = 'hookahparty.v1';
  function seed() {
    const day = 864e5, at = (d, h, m = 0) => { const x = new Date(Date.now() + d * day); x.setHours(h, m, 0, 0); return x.toISOString(); };
    const u = (id, name, phone) => ({ id, name, phone, pass: hashPass('hookah'), verified: true, avatar: null, favs: [], createdAt: new Date().toISOString() });
    return {
      session: 'u1',
      users: [
        { ...u('u1', 'Алекс', '79000000001'), favs: ['ds-supernova', 'mh-pinkman'] },
        u('u2', 'Дина', '79000000002'),
        u('u3', 'Тимур', '79000000003'),
        u('u4', 'Сабина', '79000000004'),
        u('u5', 'Руслан', '79000000005'),
        u('u6', 'Карина', '79000000006')
      ],
      events: [
        {
          id: 'e1', title: 'Пятничный сбор', venue: 'Smoke Lab Lounge', address: 'ул. Пушкина, 12, 2 этаж',
          at: at(2, 20, 30), hostId: 'u1', desc: 'Забронирован диван у окна на 6 человек. Берём два кальяна, второй — на фанеле.',
          invites: [
            { userId: 'u2', status: 'going' }, { userId: 'u3', status: 'going' }, { userId: 'u4', status: 'pending' },
            { userId: 'u5', status: 'going' }, { phone: '79001234567', status: 'pending' }
          ],
          picks: { u1: ['ds-supernova', 'mh-pinkman'], u2: ['ds-supernova', 'ad-love66'], u3: ['ds-supernova', 'mh-pinkman', 'tg-canemint'], u5: ['ds-bananapapa'] },
          bowls: { u1: 'b-phunnel', u2: 'b-phunnel', u3: 'b-killer' }
        },
        {
          id: 'e2', title: 'День рождения Тимура', venue: 'Северный дым', address: 'пр. Мира, 48',
          at: at(6, 19), hostId: 'u3', desc: 'Отмечаем 25 лет. Подарок собираем вскладчину, детали у Сабины.',
          invites: [{ userId: 'u1', status: 'pending' }, { userId: 'u4', status: 'going' }, { userId: 'u6', status: 'going' }],
          picks: { u3: ['af-twoapples', 'sb-bluemist'], u4: ['af-twoapples'], u6: ['fu-gummi', 'sb-bluemist', 'af-twoapples'] },
          bowls: { u3: 'b-turka' }
        },
        {
          id: 'e3', title: 'После работы', venue: 'Чайхана «Восток»', address: 'ул. Гоголя, 7',
          at: at(-9, 21), hostId: 'u2', desc: '',
          invites: [{ userId: 'u1', status: 'going' }, { userId: 'u6', status: 'going' }],
          picks: { u1: ['bb-cherry'], u2: ['bb-cherry', 'el-grapefruit'], u6: ['el-grapefruit'] },
          bowls: { u2: 'b-fruit' }
        }
      ]
    };
  }
  function load() { try { const raw = localStorage.getItem(KEY); if (raw) return JSON.parse(raw); } catch (e) { /* хранилище недоступно */ } return null; }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) { /* хранилище недоступно */ } }
  let db = load() || seed();

  const me = () => db.users.find(u => u.id === db.session) || null;
  const userById = id => db.users.find(u => u.id === id);
  const userByPhone = p => db.users.find(u => u.phone === normPhone(p));
  const eventById = id => db.events.find(e => e.id === id);
  const myInvite = (e, u) => e.invites.find(i => i.userId === u.id);
  const isMember = (e, u) => !!u && (e.hostId === u.id || !!myInvite(e, u));
  const canVote = (e, u) => !!u && (e.hostId === u.id || myInvite(e, u)?.status === 'going');
  const goingIds = e => [e.hostId, ...e.invites.filter(i => i.status === 'going' && i.userId).map(i => i.userId)];

  // Подсчёт голосов: чем больше участников выбрали позицию, тем выше она в списке.
  function ranking(map, nameOf) {
    const c = {};
    for (const [userId, ids] of Object.entries(map || {})) for (const id of [].concat(ids)) (c[id] ||= []).push(userId);
    return Object.entries(c).map(([id, users]) => ({ id, users }))
      .sort((a, b) => b.users.length - a.users.length || nameOf(a.id).localeCompare(nameOf(b.id), 'ru'));
  }
  const tobaccoName = id => { const t = tobacco(id); return t ? `${t.brand} ${t.flavor}` : id; };
  const bowlName = id => bowl(id)?.name || id;

  // Привязать приглашения «по номеру» к только что зарегистрированному пользователю.
  function claimPhoneInvites(user) {
    for (const e of db.events) for (const i of e.invites) if (!i.userId && i.phone === user.phone) { i.userId = user.id; delete i.phone; }
  }

  // ---------- Аватары ----------
  const initials = n => String(n || '?').trim().split(/\s+/).slice(0, 2).map(w => w[0]).join('').toUpperCase();
  function avatar(u, size = '') {
    const cls = `av ${size ? 'av-' + size : ''}`;
    if (!u) return `<span class="${cls} av-ghost">?</span>`;
    if (u.avatar) return `<img class="${cls}" src="${u.avatar}" alt="${esc(u.name)}">`;
    return `<span class="${cls}" style="--h:${hashStr(u.id) % 360}" title="${esc(u.name)}">${esc(initials(u.name))}</span>`;
  }
  function avatarStack(ids, max = 5, size = 'sm') {
    const list = ids.map(userById).filter(Boolean);
    const extra = list.length - max;
    return `<span class="av-stack">${list.slice(0, max).map(u => avatar(u, size)).join('')}${extra > 0 ? `<span class="av av-${size} av-more">+${extra}</span>` : ''}</span>`;
  }
  function readAvatar(file) {
    return new Promise((resolve, reject) => {
      if (!file || !file.type.startsWith('image/')) return reject(new Error('Выберите файл изображения: JPG, PNG или WebP.'));
      const r = new FileReader();
      r.onerror = () => reject(new Error('Не удалось прочитать файл.'));
      r.onload = () => {
        const img = new Image();
        img.onerror = () => reject(new Error('Файл повреждён или это не изображение.'));
        img.onload = () => {
          const s = 256, c = document.createElement('canvas'), k = Math.min(img.width, img.height);
          c.width = c.height = s;
          c.getContext('2d').drawImage(img, (img.width - k) / 2, (img.height - k) / 2, k, k, 0, 0, s, s);
          resolve(c.toDataURL('image/jpeg', .86));
        };
        img.src = r.result;
      };
      r.readAsDataURL(file);
    });
  }
  function pickAvatarFile(onDone) {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = 'image/*';
    inp.onchange = async () => {
      try { onDone(await readAvatar(inp.files[0])); } catch (err) { toast(err.message, 'err'); }
    };
    inp.click();
  }

  // ---------- Модальные окна и уведомления ----------
  const modalRoot = $('#modal-root');
  function openModal(title, body, onMount) {
    modalRoot.innerHTML = `<div class="modal-backdrop"><div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}">
      <div class="modal-head"><h2>${esc(title)}</h2><button class="modal-x" type="button" data-action="closeModal" aria-label="Закрыть">×</button></div>
      ${body}</div></div>`;
    modalRoot.hidden = false;
    document.body.classList.add('locked');
    const m = $('.modal', modalRoot);
    onMount && onMount(m);
    const f = m.querySelector('input:not([type=checkbox]):not([type=radio]), textarea');
    f && f.focus();
  }
  function closeModal() { modalRoot.innerHTML = ''; modalRoot.hidden = true; document.body.classList.remove('locked'); }
  modalRoot.addEventListener('mousedown', e => { if (e.target.classList.contains('modal-backdrop')) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modalRoot.hidden) closeModal(); });

  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind; t.textContent = msg;
    $('#toasts').append(t);
    setTimeout(() => t.classList.add('out'), 3600);
    setTimeout(() => t.remove(), 4100);
  }

  // ---------- Шапка ----------
  function renderChrome(page) {
    const u = me();
    $('#topbar-actions').innerHTML = u
      ? `<button class="plus-btn" type="button" data-action="newEvent" title="Создать сбор и пригласить друзей" aria-label="Создать сбор">${ICON.plus}</button>
         <a class="me-link" href="#/profile" title="Профиль">${avatar(u, 'sm')}</a>`
      : `<a class="btn btn-ghost btn-sm hide-sm" href="#/register">Регистрация</a><a class="btn btn-primary btn-sm" href="#/login">Войти</a>`;
    $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === page));
  }

  // ---------- Страницы ----------
  const view = $('#view');

  function eventCard(e, u) {
    const d = new Date(e.at);
    const ids = goingIds(e);
    const top = ranking(e.picks, tobaccoName)[0];
    const inv = u && myInvite(e, u);
    const status = e.hostId === u?.id ? '<span class="pill pill-host">Организатор</span>'
      : inv ? `<span class="pill pill-${inv.status}">${{ going: 'Иду', pending: 'Ждёт ответа', declined: 'Не иду' }[inv.status]}</span>` : '';
    return `<a class="ev-card ${isPast(e) ? 'ev-past' : ''}" href="#/event/${e.id}">
      <div class="ev-date"><b>${dtDay.format(d)}</b><span>${dtMon.format(d).replace('.', '')}</span><span class="mono">${dtTime.format(d)}</span></div>
      <div class="ev-body">
        <h3>${esc(e.title)}</h3>
        <div class="ev-venue">${ICON.pin}<span>${esc(e.venue)}</span></div>
        ${top ? `<div><span class="chip chip-accent">Лидирует: ${esc(tobaccoName(top.id))} · ${top.users.length}</span></div>` : ''}
        <div class="ev-foot">${avatarStack(ids)}${status}</div>
      </div>
    </a>`;
  }

  function pageHome() {
    const u = me();
    if (!u) return pageLanding();
    const mine = db.events.filter(e => isMember(e, u)).sort((a, b) => new Date(a.at) - new Date(b.at));
    const invites = mine.filter(e => !isPast(e) && myInvite(e, u)?.status === 'pending');
    const upcoming = mine.filter(e => !isPast(e) && !invites.includes(e));
    const past = mine.filter(isPast).reverse();
    view.innerHTML = `
      <section class="greet">
        <div><span class="eyebrow">Мои сборы</span><h1>Привет, ${esc(u.name)}</h1>
          <p>${upcoming.length ? `Впереди ${upcoming.length} ${plural(upcoming.length, 'сбор', 'сбора', 'сборов')}` : 'Пока нет запланированных сборов'}${invites.length ? ` и ${invites.length} ${plural(invites.length, 'новое приглашение', 'новых приглашения', 'новых приглашений')}` : ''}.</p></div>
        <button class="btn btn-primary" type="button" data-action="newEvent">${'+'} Новый сбор</button>
      </section>
      ${invites.length ? `<section class="section"><div class="section-head"><h2>Приглашения</h2></div><div class="ev-grid">
        ${invites.map(e => {
          const host = userById(e.hostId), d = new Date(e.at);
          return `<div class="ev-card invite-card">
            <div class="ev-date"><b>${dtDay.format(d)}</b><span>${dtMon.format(d).replace('.', '')}</span><span class="mono">${dtTime.format(d)}</span></div>
            <div class="ev-body"><h3><a href="#/event/${e.id}">${esc(e.title)}</a></h3>
              <div class="ev-venue">${ICON.pin}<span>${esc(e.venue)}</span></div>
              <div class="ev-venue">${avatar(host, 'xs')}<span>Зовёт ${esc(host?.name)}</span></div>
              <div class="invite-actions"><button class="btn btn-primary btn-sm" data-action="rsvp" data-id="${e.id}" data-status="going">Иду</button>
              <button class="btn btn-sm" data-action="rsvp" data-id="${e.id}" data-status="declined">Не смогу</button></div></div></div>`;
        }).join('')}</div></section>` : ''}
      <section class="section"><div class="section-head"><h2>Ближайшие</h2></div>
        ${upcoming.length ? `<div class="ev-grid">${upcoming.map(e => eventCard(e, u)).join('')}</div>`
          : `<div class="empty"><p>Создайте сбор, выберите заведение и пригласите друзей по номеру телефона.</p><button class="btn btn-primary" data-action="newEvent">Создать сбор</button></div>`}
      </section>
      ${past.length ? `<section class="section"><div class="section-head"><h2>Прошедшие</h2></div><div class="ev-grid">${past.map(e => eventCard(e, u)).join('')}</div></section>` : ''}`;
  }

  function stepsHtml() {
    return `<div class="steps">
      <div class="step"><h3>Создайте сбор</h3><p>Нажмите «+», укажите заведение, адрес, дату и время.</p></div>
      <div class="step"><h3>Пригласите друзей</h3><p>Найдите друзей по имени или номеру телефона. Тех, кого ещё нет в сервисе, пригласите по номеру: сбор появится у них после регистрации.</p></div>
      <div class="step"><h3>Выберите табаки</h3><p>Каждый участник отмечает любимые вкусы и чашу. Самые популярные поднимаются наверх списка.</p></div>
    </div>`;
  }

  function pageLanding() {
    const sample = db.events.find(e => e.id === 'e1') || db.events[0];
    view.innerHTML = `
      <section class="hero">
        <div><span class="eyebrow">Hookah Party</span>
          <h1>Собирайте друзей на&nbsp;<span>кальян</span> в&nbsp;пару касаний</h1>
          <p>Выберите заведение, отправьте приглашения и проголосуйте за табаки. Кальянщик получит готовый список: что забивать первым и на какой чаше.</p>
          <div class="hero-cta"><a class="btn btn-primary" href="#/register">Зарегистрироваться</a><a class="btn" href="#/login">У меня есть аккаунт</a></div>
        </div>
        <div class="hero-preview">${sample ? `<span class="eyebrow">Пример сбора</span><div style="height:10px"></div>${eventCard(sample, null).replace(/href="[^"]*"/, 'href="#/login"')}` : ''}</div>
      </section>
      <section class="section"><div class="section-head"><h2>Как это работает</h2></div>${stepsHtml()}</section>`;
  }

  function pageHow() {
    view.innerHTML = `<section class="section"><span class="eyebrow">Помощь</span><h1>Как это работает</h1></section>
      ${stepsHtml()}
      <section class="panel"><h2>Подтверждение телефона</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      При регистрации мы отправляем на номер четырёхзначный код. Пока номер не подтверждён, войти в сервис и получать приглашения нельзя.
      Так друзья могут найти вас по номеру, а приглашения не уходят чужим людям.</p></section>`;
  }

  function pageEvent(id) {
    const u = me();
    if (!u) return go('login');
    const e = eventById(id);
    if (!e) { view.innerHTML = `<div class="empty"><p>Сбор не найден или удалён.</p><a class="btn" href="#/">К моим сборам</a></div>`; return; }
    if (!isMember(e, u)) { view.innerHTML = `<div class="empty"><p>Это закрытый сбор. Попросите организатора прислать приглашение.</p><a class="btn" href="#/">К моим сборам</a></div>`; return; }
    const d = new Date(e.at), host = userById(e.hostId), inv = myInvite(e, u), isHost = e.hostId === u.id, past = isPast(e);
    const going = goingIds(e);
    const tRank = ranking(e.picks, tobaccoName), bRank = ranking(e.bowls, bowlName);
    const myPicks = e.picks[u.id] || [];

    const rankHtml = (rank, kind) => {
      if (!rank.length) return `<div class="empty"><p>${kind === 't' ? 'Пока никто не выбрал табак.' : 'Чашу ещё не выбрали.'}</p></div>`;
      const max = rank[0].users.length;
      return `<ol class="rank">${rank.map((r, i) => {
        const n = r.users.length;
        const lead = i === 0 && (rank.length === 1 || rank[1].users.length < n);
        let name, sub;
        if (kind === 't') { const t = tobacco(r.id); name = `<b>${esc(t?.brand)}</b> ${esc(t?.flavor)}`; sub = `${esc(t?.note)} · крепость ${t?.strength}/10`; }
        else { const b = bowl(r.id); name = `<b>${esc(b?.name)}</b><small>${esc(b?.type)}</small>`; sub = esc(b?.note); }
        return `<li class="rank-row ${lead ? 'is-top' : ''}">
          <div class="rank-pos">${i + 1}</div>
          <div class="rank-body">
            <div class="rank-name">${name} ${lead ? '<span class="lead-badge">лидер</span>' : ''}</div>
            <div class="rank-bar"><span style="width:${Math.round(n / max * 100)}%"></span></div>
            <div class="rank-meta">${avatarStack(r.users, 6, 'xs')}<span>${sub}</span></div>
          </div>
          <div class="rank-count">${n}<small>${plural(n, 'голос', 'голоса', 'голосов')}</small></div>
        </li>`;
      }).join('')}</ol>`;
    };

    const statusLabel = { going: 'Идёт', pending: 'Ждём ответа', declined: 'Не придёт' };
    const people = [
      `<li class="person">${avatar(host, 'sm')}<div class="person-name"><b>${esc(host?.name)}</b><small class="mono">${fmtPhone(host?.phone)}</small></div><span class="pill pill-host">Организатор</span></li>`,
      ...e.invites.map(i => {
        const p = i.userId ? userById(i.userId) : null;
        return `<li class="person">${avatar(p, 'sm')}<div class="person-name"><b>${p ? esc(p.name) : 'Ещё не в сервисе'}</b><small class="mono">${fmtPhone(p ? p.phone : i.phone)}</small></div><span class="pill pill-${i.status}">${statusLabel[i.status]}</span></li>`;
      })
    ].join('');

    view.innerHTML = `
      <a class="back" href="#/">← Мои сборы</a>
      <section class="ev-hero">
        <div class="section-head"><div><span class="eyebrow">${past ? 'Сбор прошёл' : 'Сбор'}</span><h1 style="margin-top:8px">${esc(e.title)}</h1></div>
          ${isHost && !past ? `<button class="btn btn-danger btn-sm" data-action="deleteEvent" data-id="${e.id}">Отменить сбор</button>` : ''}</div>
        <div class="ev-facts">
          <div class="fact"><small>Заведение</small><b>${esc(e.venue)}</b></div>
          <div class="fact"><small>Адрес</small><b>${esc(e.address || 'Не указан')}</b></div>
          <div class="fact"><small>Когда</small><b>${dtFull.format(d)}, ${dtTime.format(d)}</b></div>
          <div class="fact"><small>Участники</small><b>${going.length} ${plural(going.length, 'идёт', 'идут', 'идут')} · ${e.invites.length + 1} ${plural(e.invites.length + 1, 'приглашён', 'приглашены', 'приглашены')}</b></div>
        </div>
        ${e.desc ? `<p style="max-width:65ch">${esc(e.desc)}</p>` : ''}
        ${inv && !past ? `<div class="rsvp"><span>Ваш ответ:</span>
          <button class="btn btn-sm ${inv.status === 'going' ? 'btn-primary' : ''}" data-action="rsvp" data-id="${e.id}" data-status="going">Иду</button>
          <button class="btn btn-sm ${inv.status === 'declined' ? 'btn-primary' : ''}" data-action="rsvp" data-id="${e.id}" data-status="declined">Не смогу</button></div>` : ''}
      </section>
      <div class="ev-layout">
        <div class="ev-main">
          <section class="panel">
            <div class="panel-head"><div><h2>Табаки</h2><p class="muted" style="font-size:13.5px;margin-top:4px">Чем больше голосов, тем выше позиция</p></div>
              ${canVote(e, u) && !past ? `<button class="btn btn-sm ${myPicks.length ? '' : 'btn-primary'}" data-action="pickTobacco" data-id="${e.id}">${myPicks.length ? `Мой выбор · ${myPicks.length}` : 'Выбрать табаки'}</button>` : ''}</div>
            ${rankHtml(tRank, 't')}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Чаша</h2>
              ${canVote(e, u) && !past ? `<button class="btn btn-sm" data-action="pickBowl" data-id="${e.id}">${e.bowls?.[u.id] ? 'Изменить' : 'Выбрать чашу'}</button>` : ''}</div>
            ${rankHtml(bRank, 'b')}
          </section>
        </div>
        <aside class="panel">
          <div class="panel-head"><h2>Участники</h2>
            ${(isHost || inv?.status === 'going') && !past ? `<button class="plus-btn sm" data-action="invite" data-id="${e.id}" title="Пригласить" aria-label="Пригласить участников">${ICON.plus}</button>` : ''}</div>
          <ul class="people">${people}</ul>
        </aside>
      </div>`;
  }

  let catTab = 'tobaccos', catQuery = '';
  function pageCatalog() {
    const u = me();
    const tabs = { tobaccos: 'Табаки', bowls: 'Чаши', gear: 'Аксессуары' };
    view.innerHTML = `
      <section class="section"><span class="eyebrow">Каталог</span><h1>Табаки, чаши и всё для кальяна</h1></section>
      <div class="toolbar">
        <div class="tabs" role="tablist">${Object.entries(tabs).map(([k, v]) => `<button role="tab" class="${k === catTab ? 'active' : ''}" data-action="catTab" data-tab="${k}">${v}</button>`).join('')}</div>
        <input class="input" id="cat-q" type="search" placeholder="Поиск по бренду или вкусу" value="${esc(catQuery)}" style="max-width:320px">
      </div>
      <div class="cat-grid" id="cat-grid"></div>`;
    const grid = $('#cat-grid');
    const draw = () => {
      const q = catQuery.trim().toLowerCase();
      const items = CATALOG[catTab].filter(x => !q || JSON.stringify(x).toLowerCase().includes(q));
      if (!items.length) { grid.innerHTML = `<div class="empty" style="grid-column:1/-1"><p>Ничего не нашлось по запросу «${esc(catQuery)}».</p></div>`; return; }
      grid.innerHTML = items.map(x => catTab === 'tobaccos' ? `
        <article class="cat-card">
          <div class="cat-top"><span class="cat-brand">${esc(x.brand)}</span>
            ${u ? `<button class="fav-btn ${u.favs.includes(x.id) ? 'on' : ''}" data-action="fav" data-id="${x.id}" aria-label="В избранное">${ICON.heart}</button>` : ''}</div>
          <h3>${esc(x.flavor)}</h3><p>${esc(x.note)}</p>
          <div class="strength"><div class="strength-bar">${Array.from({ length: 10 }, (_, i) => `<i class="${i < x.strength ? 'on' : ''} ${i < x.strength && i >= 7 ? 'hot' : ''}"></i>`).join('')}</div>
            <small>Крепость ${x.strength}/10</small></div>
          <div class="cat-tags">${x.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div>
        </article>` : `
        <article class="cat-card"><span class="cat-brand">${esc(x.type)}</span><h3>${esc(x.name)}</h3><p>${esc(x.note)}</p></article>`).join('');
    };
    draw();
    $('#cat-q').addEventListener('input', ev => { catQuery = ev.target.value; draw(); });
  }

  function pageProfile() {
    const u = me();
    if (!u) return go('login');
    const hosted = db.events.filter(e => e.hostId === u.id).length;
    const attended = db.events.filter(e => isPast(e) && goingIds(e).includes(u.id)).length;
    const favs = u.favs.map(tobacco).filter(Boolean);
    view.innerHTML = `
      <section class="section"><span class="eyebrow">Профиль</span><h1>Мой аккаунт</h1></section>
      <div class="profile">
        <section class="panel profile-card">
          ${avatar(u, 'lg')}
          <div class="avatar-actions"><button class="btn btn-sm" data-action="uploadAvatar">${u.avatar ? 'Сменить фото' : 'Загрузить фото'}</button>
            ${u.avatar ? '<button class="btn btn-ghost btn-sm" data-action="removeAvatar">Удалить</button>' : ''}</div>
          <div><h2>${esc(u.name)}</h2>
            <div style="margin-top:6px" class="mono">${fmtPhone(u.phone)}</div>
            ${u.verified ? `<div class="verified" style="margin-top:6px">${ICON.check}Номер подтверждён</div>` : ''}</div>
          <div class="stats">
            <div class="stat"><b>${hosted}</b><small>создал</small></div>
            <div class="stat"><b>${attended}</b><small>посетил</small></div>
            <div class="stat"><b>${favs.length}</b><small>в избранном</small></div>
          </div>
          <button class="btn btn-ghost btn-sm" data-action="logout">Выйти из аккаунта</button>
        </section>
        <div class="ev-main">
          <section class="panel">
            <div class="panel-head"><h2>Личные данные</h2></div>
            <form class="form" id="profile-form">
              <div class="field"><label for="pf-name">Имя</label><input id="pf-name" required minlength="2" maxlength="40" value="${esc(u.name)}"></div>
              <div class="field"><span class="label">Телефон</span><div class="input mono" style="opacity:.8">${fmtPhone(u.phone)}</div></div>
              <div class="error" id="pf-err"></div>
              <div><button class="btn btn-primary" type="submit">Сохранить</button></div>
            </form>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Любимые табаки</h2><a class="btn btn-sm" href="#/catalog">Открыть каталог</a></div>
            ${favs.length ? `<div class="cat-tags">${favs.map(t => `<span class="chip chip-accent">${esc(t.brand)} ${esc(t.flavor)}</span>`).join('')}</div>`
              : '<p class="muted">Отмечайте вкусы сердечком в каталоге, и они появятся здесь.</p>'}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Демо-данные</h2></div>
            <p class="muted" style="margin-bottom:14px">Все данные этого шаблона хранятся в вашем браузере. Сброс вернёт тестовых пользователей и сборы.</p>
            <button class="btn btn-danger btn-sm" data-action="reset">Сбросить демо-данные</button>
          </section>
        </div>
      </div>`;
    $('#profile-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const name = $('#pf-name').value.trim();
      if (name.length < 2) { $('#pf-err').textContent = 'Имя должно быть не короче двух букв.'; return; }
      u.name = name; save(); toast('Профиль сохранён'); route();
    });
  }

  // ---------- Вход и регистрация ----------
  function pageAuth(mode) {
    if (me()) return go('');
    view.innerHTML = `<section class="auth"><div class="panel auth-card" id="auth-card"></div></section>`;
    const card = $('#auth-card');
    mode === 'register' ? renderRegister(card) : renderLogin(card);
  }

  function renderLogin(card) {
    card.innerHTML = `
      <div><span class="eyebrow">Вход</span><h1 style="margin-top:8px">С возвращением</h1></div>
      <form class="form" id="login-form" novalidate>
        <div class="field"><label for="lg-phone">Номер телефона</label><input id="lg-phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+7 (900) 000-00-00"></div>
        <div class="field"><label for="lg-pass">Пароль</label><input id="lg-pass" type="password" autocomplete="current-password"></div>
        <div class="error" id="lg-err"></div>
        <button class="btn btn-primary" type="submit">Войти</button>
        <button class="btn" type="button" id="lg-sms">Войти по SMS-коду</button>
      </form>
      <div class="hint">Демо-аккаунт: <span class="mono">+7 (900) 000-00-01</span>, пароль <b>hookah</b></div>
      <p class="muted" style="text-align:center">Нет аккаунта? <a href="#/register" style="color:var(--accent)">Зарегистрируйтесь</a></p>`;
    maskPhone($('#lg-phone'));
    const err = $('#lg-err');
    $('#login-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const phone = normPhone($('#lg-phone').value), user = userByPhone(phone);
      if (!validPhone(phone)) { err.textContent = 'Введите номер полностью, вместе с кодом страны.'; return; }
      if (!user || user.pass !== hashPass($('#lg-pass').value)) { err.textContent = 'Неверный номер или пароль.'; return; }
      if (!user.verified) { renderVerify(card, phone, () => { user.verified = true; signIn(user); }); return; }
      signIn(user);
    });
    $('#lg-sms').addEventListener('click', () => {
      const phone = normPhone($('#lg-phone').value), user = userByPhone(phone);
      if (!validPhone(phone)) { err.textContent = 'Сначала введите номер телефона.'; return; }
      if (!user) { err.textContent = 'Этот номер ещё не зарегистрирован.'; return; }
      renderVerify(card, phone, () => { user.verified = true; signIn(user); });
    });
  }

  function renderRegister(card) {
    card.innerHTML = `
      <div><span class="eyebrow">Регистрация · шаг 1 из 3</span><h1 style="margin-top:8px">Создайте аккаунт</h1></div>
      <form class="form" id="reg-form" novalidate>
        <div class="field"><label for="rg-name">Имя</label><input id="rg-name" autocomplete="given-name" maxlength="40" placeholder="Как вас называть друзьям"></div>
        <div class="field"><label for="rg-phone">Номер телефона</label><input id="rg-phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+7 (900) 000-00-00"></div>
        <div class="field"><label for="rg-pass">Пароль</label><input id="rg-pass" type="password" autocomplete="new-password" placeholder="Минимум 6 символов"></div>
        <label class="check"><input type="checkbox" id="rg-age"> Мне исполнилось 18 лет, я принимаю правила сервиса</label>
        <div class="error" id="rg-err"></div>
        <button class="btn btn-primary" type="submit">Получить код по SMS</button>
      </form>
      <p class="muted" style="text-align:center">Уже есть аккаунт? <a href="#/login" style="color:var(--accent)">Войти</a></p>`;
    maskPhone($('#rg-phone'));
    $('#reg-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const err = $('#rg-err');
      const name = $('#rg-name').value.trim(), phone = normPhone($('#rg-phone').value), pass = $('#rg-pass').value;
      if (name.length < 2) return void (err.textContent = 'Укажите имя: минимум две буквы.');
      if (!validPhone(phone)) return void (err.textContent = 'Введите номер полностью, вместе с кодом страны.');
      if (userByPhone(phone)?.verified) return void (err.textContent = 'Этот номер уже зарегистрирован. Войдите или восстановите доступ по SMS.');
      if (pass.length < 6) return void (err.textContent = 'Пароль должен быть не короче 6 символов.');
      if (!$('#rg-age').checked) return void (err.textContent = 'Сервис доступен только совершеннолетним.');
      renderVerify(card, phone, () => {
        let user = userByPhone(phone);
        if (user) Object.assign(user, { name, pass: hashPass(pass), verified: true });
        else { user = { id: uid('u'), name, phone, pass: hashPass(pass), verified: true, avatar: null, favs: [], createdAt: new Date().toISOString() }; db.users.push(user); }
        claimPhoneInvites(user);
        db.session = user.id; save();
        renderAvatarStep(card, user);
      }, 'Регистрация · шаг 2 из 3');
    });
  }

  // Подтверждение номера. В демо код показывается на экране вместо настоящего SMS.
  function renderVerify(card, phone, onSuccess, eyebrow = 'Подтверждение номера') {
    let code = String(1000 + Math.floor(Math.random() * 9000)), timer = null, left = 0;
    card.innerHTML = `
      <div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">Введите код из SMS</h1>
        <p class="muted" style="margin-top:8px">Отправили 4 цифры на <span class="mono">${fmtPhone(phone)}</span></p></div>
      <form class="form" id="code-form">
        <div class="code-inputs">${[0, 1, 2, 3].map(i => `<input id="code-${i}" inputmode="numeric" autocomplete="${i === 0 ? 'one-time-code' : 'off'}" maxlength="1" aria-label="Цифра ${i + 1}">`).join('')}</div>
        <div class="hint" id="sms-hint"></div>
        <div class="error" id="code-err" style="text-align:center"></div>
        <button class="btn btn-primary" type="submit">Подтвердить</button>
        <div class="resend" id="resend"></div>
        <button class="link-btn" type="button" id="code-back">Изменить номер</button>
      </form>`;
    const boxes = $$('.code-inputs input', card);
    const showHint = () => { $('#sms-hint').innerHTML = `Демо-режим, SMS не отправляется. Ваш код: <b>${code}</b>`; };
    const tick = () => {
      const r = $('#resend'); if (!r) return clearInterval(timer);
      r.innerHTML = left > 0 ? `Отправить код повторно через <span class="mono">0:${String(left).padStart(2, '0')}</span>` : '<button class="link-btn" type="button" id="resend-btn">Отправить код ещё раз</button>';
      if (left-- <= 0) {
        clearInterval(timer);
        $('#resend-btn').onclick = () => { code = String(1000 + Math.floor(Math.random() * 9000)); showHint(); toast('Новый код отправлен'); start(); };
      }
    };
    const start = () => { left = 30; clearInterval(timer); tick(); timer = setInterval(tick, 1000); };
    showHint(); start();
    boxes.forEach((b, i) => {
      b.addEventListener('input', () => {
        const v = digits(b.value);
        if (v.length > 1) { v.split('').slice(0, 4 - i).forEach((c, k) => boxes[i + k].value = c); boxes[Math.min(i + v.length, 3)].focus(); }
        else { b.value = v; if (v && i < 3) boxes[i + 1].focus(); }
        if (boxes.every(x => x.value)) $('#code-form').requestSubmit();
      });
      b.addEventListener('keydown', e => { if (e.key === 'Backspace' && !b.value && i > 0) boxes[i - 1].focus(); });
    });
    boxes[0].focus();
    $('#code-form').addEventListener('submit', ev => {
      ev.preventDefault();
      if (boxes.map(b => b.value).join('') !== code) {
        $('#code-err').textContent = 'Код не подходит. Проверьте цифры или запросите новый.';
        boxes.forEach(b => b.value = ''); boxes[0].focus(); return;
      }
      clearInterval(timer); onSuccess();
    });
    $('#code-back').addEventListener('click', () => { clearInterval(timer); route(); });
  }

  function renderAvatarStep(card, user) {
    const draw = () => {
      card.innerHTML = `
        <div><span class="eyebrow">Регистрация · шаг 3 из 3</span><h1 style="margin-top:8px">Добавьте фото</h1>
          <p class="muted" style="margin-top:8px">По аватару друзья узнают вас в списке участников.</p></div>
        <div class="avatar-upload">${avatar(user, 'lg')}
          <div class="verified">${ICON.check}Номер ${fmtPhone(user.phone)} подтверждён</div>
          <div class="avatar-actions"><button class="btn" type="button" id="av-up">${user.avatar ? 'Выбрать другое' : 'Загрузить фото'}</button></div></div>
        <button class="btn btn-primary" type="button" id="av-done">${user.avatar ? 'Готово' : 'Пропустить'}</button>`;
      $('#av-up').onclick = () => pickAvatarFile(url => { user.avatar = url; save(); draw(); });
      $('#av-done').onclick = () => { toast(`Добро пожаловать, ${user.name}!`); go(''); };
    };
    draw();
  }

  function signIn(user) { db.session = user.id; save(); toast(`Вы вошли как ${user.name}`); go(''); }

  // ---------- Пикер приглашений ----------
  function invitePicker(root, exclude) {
    const sel = [];
    root.innerHTML = `<div class="picker"><div class="picker-chips"></div>
      <input class="input" id="inv-q" placeholder="Имя или номер телефона" autocomplete="off"><div class="suggest"></div></div>`;
    const chips = $('.picker-chips', root), sug = $('.suggest', root), q = $('#inv-q', root);
    const taken = () => new Set([...exclude, ...sel.map(s => s.userId || s.phone)]);
    const draw = () => {
      chips.innerHTML = sel.map((s, i) => {
        const u = s.userId && userById(s.userId);
        return `<span class="chip">${u ? avatar(u, 'xs') + esc(u.name) : `<span class="mono">${fmtPhone(s.phone)}</span>`}<button type="button" data-i="${i}" aria-label="Убрать">×</button></span>`;
      }).join('');
      const text = q.value.trim().toLowerCase(), qd = digits(text), t = taken();
      const found = db.users.filter(u => !t.has(u.id) && (!text || u.name.toLowerCase().includes(text) || (qd.length >= 3 && u.phone.includes(qd)))).slice(0, 6);
      let html = found.map(u => `<button type="button" data-u="${u.id}">${avatar(u, 'sm')}<span>${esc(u.name)}</span><small>${fmtPhone(u.phone)}</small></button>`).join('');
      const np = normPhone(qd);
      if (validPhone(np) && !userByPhone(np) && !t.has(np)) html += `<button type="button" data-p="${np}"><span class="av av-sm av-ghost">+</span><span>Пригласить по номеру</span><small>${fmtPhone(np)}</small></button>`;
      sug.innerHTML = html || `<p class="muted" style="padding:8px;font-size:13.5px">${text ? 'Никого не нашли. Введите номер полностью, чтобы пригласить по SMS.' : 'Все ваши знакомые уже приглашены.'}</p>`;
    };
    q.addEventListener('input', draw);
    root.addEventListener('click', e => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.u) sel.push({ userId: b.dataset.u });
      else if (b.dataset.p) { sel.push({ phone: b.dataset.p }); q.value = ''; }
      else if (b.dataset.i != null) sel.splice(+b.dataset.i, 1);
      else return;
      draw(); q.focus();
    });
    draw();
    return { get: () => sel.slice() };
  }
  const toInvites = sel => sel.map(s => {
    const u = s.phone && userByPhone(s.phone);
    return u ? { userId: u.id, status: 'pending' } : { ...s, status: 'pending' };
  });

  // ---------- Действия ----------
  function go(path) { const h = '#/' + path; if (location.hash === h) route(); else location.hash = h; }
  function requireUser() { if (me()) return true; toast('Войдите, чтобы продолжить'); go('login'); return false; }

  const actions = {
    closeModal,
    newEvent() {
      if (!requireUser()) return;
      const u = me(), t = new Date(Date.now() + 864e5);
      const dVal = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`;
      let picker;
      openModal('Новый сбор', `
        <form class="form" id="ev-form" novalidate>
          <div class="field"><label for="ev-title">Название</label><input id="ev-title" maxlength="60" placeholder="Например, пятничный сбор"></div>
          <div class="field"><label for="ev-venue">Заведение</label><input id="ev-venue" maxlength="60" placeholder="Название кальянной"></div>
          <div class="field"><label for="ev-address">Адрес</label><input id="ev-address" maxlength="100" placeholder="Улица, дом"></div>
          <div class="row-2"><div class="field"><label for="ev-date">Дата</label><input id="ev-date" type="date" value="${dVal}"></div>
            <div class="field"><label for="ev-time">Время</label><input id="ev-time" type="time" value="20:00"></div></div>
          <div class="field"><label for="ev-desc">Комментарий</label><textarea id="ev-desc" maxlength="400" placeholder="Бронь, сколько кальянов, кто что приносит"></textarea></div>
          <div class="field"><span class="label">Пригласить</span><div id="ev-picker"></div></div>
          <div class="error" id="ev-err"></div>
          <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="submit">Создать и пригласить</button></div>
        </form>`, m => {
        picker = invitePicker($('#ev-picker', m), [u.id]);
        $('#ev-form', m).addEventListener('submit', ev => {
          ev.preventDefault();
          const err = $('#ev-err', m), title = $('#ev-title', m).value.trim(), venue = $('#ev-venue', m).value.trim();
          const date = $('#ev-date', m).value, time = $('#ev-time', m).value;
          if (!title) return void (err.textContent = 'Придумайте название сбора.');
          if (!venue) return void (err.textContent = 'Укажите заведение.');
          const at = new Date(`${date}T${time || '20:00'}`);
          if (isNaN(at)) return void (err.textContent = 'Укажите дату и время.');
          if (at < Date.now()) return void (err.textContent = 'Дата сбора уже прошла. Выберите время в будущем.');
          const e = { id: uid('e'), title, venue, address: $('#ev-address', m).value.trim(), at: at.toISOString(), hostId: u.id,
            desc: $('#ev-desc', m).value.trim(), invites: toInvites(picker.get()), picks: {}, bowls: {} };
          db.events.push(e); save(); closeModal();
          toast(e.invites.length ? `Сбор создан, приглашения отправлены: ${e.invites.length}` : 'Сбор создан');
          go('event/' + e.id);
        });
      });
    },
    invite({ id }) {
      const e = eventById(id); if (!e) return;
      let picker;
      openModal('Пригласить на сбор', `<div id="inv-picker"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="button" id="inv-send">Отправить приглашения</button></div>`, m => {
        picker = invitePicker($('#inv-picker', m), [e.hostId, ...e.invites.map(i => i.userId || i.phone)]);
        $('#inv-send', m).onclick = () => {
          const list = toInvites(picker.get());
          if (!list.length) return toast('Выберите хотя бы одного человека', 'err');
          e.invites.push(...list); save(); closeModal(); toast(`Приглашения отправлены: ${list.length}`); route();
        };
      });
    },
    rsvp({ id, status }) {
      const e = eventById(id), inv = e && myInvite(e, me()); if (!inv) return;
      inv.status = status;
      if (status !== 'going') { delete e.picks[me().id]; delete e.bowls[me().id]; }
      save(); toast(status === 'going' ? 'Отлично, ждём вас! Выберите табаки.' : 'Организатор узнает, что вы не придёте'); route();
    },
    pickTobacco({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      const MAX = 5, cur = new Set(e.picks[u.id] || []);
      openModal('Мои табаки', `
        <p class="muted">Отметьте до ${MAX} вкусов. Позиции, которые выбрало больше участников, будут выше в общем списке.</p>
        <input class="input" id="pk-q" type="search" placeholder="Поиск по бренду или вкусу">
        <div class="pick-list" id="pk-list">${CATALOG.tobaccos.map(t => `<label class="pick-item" data-s="${esc((t.brand + ' ' + t.flavor + ' ' + t.note).toLowerCase())}">
          <input type="checkbox" value="${t.id}" ${cur.has(t.id) ? 'checked' : ''}><span><b>${esc(t.brand)}</b> ${esc(t.flavor)}<small>${esc(t.note)}</small></span><em>${t.strength}/10</em></label>`).join('')}</div>
        <div class="modal-foot"><span class="muted" id="pk-count" style="margin-right:auto;align-self:center"></span>
          <button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="button" id="pk-save">Сохранить</button></div>`, m => {
        const boxes = $$('input[type=checkbox]', m);
        const upd = () => {
          const n = boxes.filter(b => b.checked).length;
          $('#pk-count', m).textContent = `Выбрано ${n} из ${MAX}`;
          boxes.forEach(b => { b.disabled = !b.checked && n >= MAX; });
        };
        boxes.forEach(b => b.addEventListener('change', upd)); upd();
        $('#pk-q', m).addEventListener('input', ev => {
          const q = ev.target.value.trim().toLowerCase();
          $$('.pick-item', m).forEach(l => { l.hidden = !!q && !l.dataset.s.includes(q); });
        });
        $('#pk-save', m).onclick = () => {
          const ids = boxes.filter(b => b.checked).map(b => b.value);
          if (ids.length) e.picks[u.id] = ids; else delete e.picks[u.id];
          save(); closeModal(); toast('Ваш выбор учтён'); route();
        };
      });
    },
    pickBowl({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      e.bowls ||= {};
      const cur = e.bowls[u.id];
      openModal('Чаша', `<div class="pick-list">${CATALOG.bowls.map(b => `<label class="pick-item"><input type="radio" name="bowl" value="${b.id}" ${cur === b.id ? 'checked' : ''}>
          <span><b>${esc(b.name)}</b><small>${esc(b.type)} · ${esc(b.note)}</small></span></label>`).join('')}</div>
        <div class="modal-foot">${cur ? '<button class="btn btn-ghost" type="button" id="bw-clear" style="margin-right:auto">Снять голос</button>' : ''}
          <button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="button" id="bw-save">Сохранить</button></div>`, m => {
        $('#bw-save', m).onclick = () => {
          const v = $('input[name=bowl]:checked', m)?.value;
          if (!v) return toast('Выберите чашу', 'err');
          e.bowls[u.id] = v; save(); closeModal(); route();
        };
        const c = $('#bw-clear', m); if (c) c.onclick = () => { delete e.bowls[u.id]; save(); closeModal(); route(); };
      });
    },
    deleteEvent({ id }) {
      const e = eventById(id); if (!e) return;
      openModal('Отменить сбор?', `<p class="muted">Сбор «${esc(e.title)}» исчезнет у всех приглашённых. Это действие нельзя отменить.</p>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Оставить</button><button class="btn btn-danger" type="button" id="del-ok">Отменить сбор</button></div>`, m => {
        $('#del-ok', m).onclick = () => { db.events = db.events.filter(x => x.id !== id); save(); closeModal(); toast('Сбор отменён'); go(''); };
      });
    },
    fav({ id }) {
      const u = me(); if (!u) return;
      u.favs = u.favs.includes(id) ? u.favs.filter(x => x !== id) : [...u.favs, id];
      save(); pageCatalog();
    },
    catTab({ tab }) { catTab = tab; catQuery = ''; pageCatalog(); },
    uploadAvatar() { const u = me(); pickAvatarFile(url => { u.avatar = url; save(); toast('Фото обновлено'); route(); }); },
    removeAvatar() { const u = me(); u.avatar = null; save(); route(); },
    logout() { db.session = null; save(); toast('Вы вышли из аккаунта'); go(''); },
    reset() { db = seed(); save(); toast('Демо-данные восстановлены'); go(''); },
    info({ key }) {
      const texts = {
        rules: ['Правила сервиса', 'Сервис предназначен для лиц старше 18 лет. Организатор отвечает за бронь в заведении. Запрещено приглашать людей без их согласия и рассылать рекламу.'],
        privacy: ['Конфиденциальность', 'Номер телефона нужен для входа и чтобы друзья могли пригласить вас. Номер видят только участники ваших сборов. Мы не передаём данные третьим лицам.'],
        venues: ['Заведениям', 'Хотите, чтобы гости находили вас в Hookah Party и бронировали столы? Напишите на hello@hookahparty.app, расскажем об условиях.'],
        faq: ['Вопросы и ответы', 'Как пригласить друга без аккаунта? Введите его номер в поле приглашения. Сбор появится у него сразу после регистрации с этим номером.']
      };
      const [t, body] = texts[key] || texts.faq;
      openModal(t, `<p class="muted" style="max-width:60ch">${esc(body)}</p><div class="modal-foot"><button class="btn btn-primary" type="button" data-action="closeModal">Понятно</button></div>`);
    }
  };

  document.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (!el || !actions[el.dataset.action]) return;
    e.preventDefault();
    actions[el.dataset.action]({ ...el.dataset }, el);
  });

  // ---------- Роутер ----------
  function route() {
    const [page = '', arg] = location.hash.replace(/^#\/?/, '').split('/');
    const nav = { '': 'home', catalog: 'catalog', how: 'how', profile: 'profile', login: 'profile', register: 'profile' }[page] || '';
    closeModal();
    renderChrome(nav);
    switch (page) {
      case 'event': pageEvent(arg); break;
      case 'catalog': pageCatalog(); break;
      case 'how': pageHow(); break;
      case 'profile': pageProfile(); break;
      case 'login': pageAuth('login'); break;
      case 'register': pageAuth('register'); break;
      default: pageHome();
    }
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);
  route();
})();
