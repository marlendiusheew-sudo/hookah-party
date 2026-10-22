/* Hookah Party — клиентский шаблон.
   Все данные хранятся в localStorage (демо). При переходе на приложение
   функции load/save заменяются запросами к серверу, а отправка SMS — реальным
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
  const pad = n => String(n).padStart(2, '0');
  const ymd = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const hm = d => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const money = n => new Intl.NumberFormat('ru-RU').format(Math.round(n)) + ' ₽';

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
  // Номер целиком видят только друзья и участники общих сборов.
  const maskedPhone = s => { const f = fmtPhone(s); return f.slice(0, -9) + '•••-••-' + f.slice(-2); };
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
  const dtShort = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long' });
  const dtTime = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' });
  const isPast = e => new Date(e.at).getTime() < Date.now() - 4 * 3600e3;
  function timeAgo(iso) {
    const m = (Date.now() - new Date(iso)) / 60000;
    if (m < 1) return 'только что';
    if (m < 60) return `${Math.floor(m)} мин назад`;
    if (m < 1440) return `${Math.floor(m / 60)} ч назад`;
    const d = Math.floor(m / 1440);
    return d < 7 ? `${d} ${plural(d, 'день', 'дня', 'дней')} назад` : dtShort.format(new Date(iso));
  }
  function whenLabel(e) {
    const d = new Date(e.at), today = new Date(); today.setHours(0, 0, 0, 0);
    const diff = Math.round((new Date(d).setHours(0, 0, 0, 0) - today) / 864e5);
    const day = diff === 0 ? 'Сегодня' : diff === 1 ? 'Завтра' : dtFull.format(d);
    return `${day}, ${dtTime.format(d)}`;
  }

  // Настройки вида живут только в этом браузере.
  const prefs = {
    get(k, d) { try { return localStorage.getItem('hp.' + k) ?? d; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('hp.' + k, v); } catch (e) { /* хранилище недоступно */ } }
  };

  const svg = (d, extra = '') => `<svg viewBox="0 0 24 24" aria-hidden="true" ${extra}>${d}</svg>`;
  const ICON = {
    pin: svg('<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>'),
    plus: svg('<path d="M12 5v14M5 12h14"/>'),
    check: svg('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),
    heart: svg('<path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/>'),
    chat: svg('<path d="M5 5h14v10H10l-4 4v-4H5z"/>'),
    bell: svg('<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20.5h4"/>'),
    cal: svg('<rect x="4" y="5" width="16" height="15" rx="2"/><path d="M4 10h16M9 3v4M15 3v4"/>'),
    repeat: svg('<path d="M17 3l3 3-3 3M4 12V9a3 3 0 0 1 3-3h13M7 21l-3-3 3-3M20 12v3a3 3 0 0 1-3 3H4"/>'),
    edit: svg('<path d="M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4"/>'),
    wallet: svg('<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M16 12.5h2M3 9h18"/>'),
    trash: svg('<path d="M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13"/>'),
    users: svg('<circle cx="9" cy="9" r="3.5"/><path d="M2.5 20c.8-3.5 3.4-5 6.5-5s5.7 1.5 6.5 5M16 5.5a3.5 3.5 0 0 1 0 7M18 15c2 .6 3.2 2.2 3.5 5"/>'),
    sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
    moon: svg('<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>'),
    auto: svg('<circle cx="12" cy="12" r="8"/><path d="M12 4v16a8 8 0 0 0 0-16z" fill="currentColor"/>'),
    smoke: svg('<path d="M8 20c-3-3 2-5-1-8s2-5 0-8M14 20c-3-3 2-5-1-8s2-5 0-8"/>'),
    star: svg('<path d="M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 16.8l-5.2 2.8 1-5.8-4.3-4.1 5.9-.8z"/>'),
    ext: svg('<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>')
  };

  // ---------- Каталог ----------
  const CATALOG = {
    tobaccos: [
      { id: 'ds-supernova', brand: 'Darkside', flavor: 'Supernova', note: 'Ледяной холодок', strength: 7, tags: ['холодок'], color: '#4fa9cf' },
      { id: 'ds-bananapapa', brand: 'Darkside', flavor: 'Bananapapa', note: 'Спелый банан', strength: 7, tags: ['фрукты'], color: '#d8a92a' },
      { id: 'ds-fallingstar', brand: 'Darkside', flavor: 'Falling Star', note: 'Манго и маракуйя', strength: 7, tags: ['тропики', 'фрукты'], color: '#e8892c' },
      { id: 'mh-pinkman', brand: 'MustHave', flavor: 'Pinkman', note: 'Грейпфрут и малина', strength: 6, tags: ['ягоды', 'цитрус'], color: '#d84a74' },
      { id: 'mh-raspberry', brand: 'MustHave', flavor: 'Raspberry', note: 'Малина', strength: 6, tags: ['ягоды'], color: '#b52a52' },
      { id: 'bb-cherry', brand: 'Black Burn', flavor: 'Cherry Shock', note: 'Кислая вишня', strength: 8, tags: ['ягоды', 'кислое'], color: '#8a1d30' },
      { id: 'el-grapefruit', brand: 'Element', flavor: 'Вода · Грейпфрут', note: 'Свежий грейпфрут', strength: 5, tags: ['цитрус'], color: '#e4694b' },
      { id: 'tg-canemint', brand: 'Tangiers', flavor: 'Cane Mint', note: 'Сладкая мята', strength: 9, tags: ['мята'], color: '#2f8f68' },
      { id: 'af-twoapples', brand: 'Al Fakher', flavor: 'Two Apples', note: 'Двойное яблоко с анисом', strength: 3, tags: ['классика', 'фрукты'], color: '#78a832' },
      { id: 'af-mint', brand: 'Al Fakher', flavor: 'Mint', note: 'Мята', strength: 3, tags: ['мята', 'классика'], color: '#3ea87b' },
      { id: 'ad-love66', brand: 'Adalya', flavor: 'Love 66', note: 'Арбуз, дыня, маракуйя и мята', strength: 4, tags: ['микс', 'фрукты'], color: '#c43e62' },
      { id: 'fu-gummi', brand: 'Fumari', flavor: 'White Gummi Bear', note: 'Мармеладные мишки', strength: 4, tags: ['сладкое'], color: '#9d82cf' },
      { id: 'sb-bluemist', brand: 'Starbuzz', flavor: 'Blue Mist', note: 'Черника с мятой', strength: 4, tags: ['ягоды', 'мята'], color: '#4560c4' },
      { id: 'se-watermelon', brand: 'Sebero', flavor: 'Арбуз', note: 'Сочный арбуз', strength: 6, tags: ['фрукты'], color: '#d63c4f' },
      { id: 'du-pear', brand: 'Duft', flavor: 'Pear', note: 'Спелая груша', strength: 5, tags: ['фрукты'], color: '#9fae38' },
      { id: 'od-cola', brand: 'Overdose', flavor: 'Cola', note: 'Кола', strength: 7, tags: ['напитки'], color: '#6b3420' },
      { id: 'ch-icemint', brand: 'Chabacco', flavor: 'Ice Mint', note: 'Бестабачная смесь: мята со льдом', strength: 1, tags: ['бестабачное', 'мята'], color: '#4bb8b0' }
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
  const ALL_TAGS = [...new Set(CATALOG.tobaccos.flatMap(t => t.tags))];
  const STRENGTH = { all: ['Любая', 0, 10], light: ['Лёгкие · 1–4', 1, 4], mid: ['Средние · 5–6', 5, 6], strong: ['Крепкие · 7–10', 7, 10] };

  // ---------- Хранилище (демо) ----------
  const KEY = 'hookahparty.v1';
  function seed() {
    const day = 864e5, at = (d, h, m = 0) => { const x = new Date(Date.now() + d * day); x.setHours(h, m, 0, 0); return x.toISOString(); };
    const ago = mins => new Date(Date.now() - mins * 60000).toISOString();
    const u = (id, name, phone, extra = {}) => ({ id, name, phone, pass: hashPass('hookah'), verified: true, avatar: null, favs: [], friends: [], favVenue: '', createdAt: ago(60 * 24 * 40), ...extra });
    return {
      session: 'u1',
      users: [
        u('u1', 'Алекс', '79000000001', { favs: ['ds-supernova', 'mh-pinkman'], friends: ['u2', 'u3', 'u5'], favVenue: 'Smoke Lab Lounge' }),
        u('u2', 'Дина', '79000000002', { friends: ['u1', 'u3', 'u6'], favVenue: 'Чайхана «Восток»', favs: ['ad-love66'] }),
        u('u3', 'Тимур', '79000000003', { friends: ['u1', 'u2', 'u4'], favVenue: 'Северный дым', favs: ['tg-canemint', 'af-twoapples'] }),
        u('u4', 'Сабина', '79000000004', { friends: ['u3'], favs: ['fu-gummi'] }),
        u('u5', 'Руслан', '79000000005', { friends: ['u1'], favVenue: 'Smoke Lab Lounge', favs: ['od-cola'] }),
        u('u6', 'Карина', '79000000006', { friends: ['u2'], favs: ['sb-bluemist'] })
      ],
      events: [
        {
          id: 'e1', title: 'Пятничный сбор', venue: 'Smoke Lab Lounge', address: 'ул. Пушкина, 12, 2 этаж', mapUrl: '',
          at: at(2, 20, 30), hostId: 'u1', desc: 'Забронирован диван у окна на 6 человек. Берём два кальяна, второй — на фанеле.',
          hookahs: 2, price: 1800, paid: { u1: true, u2: true },
          invites: [
            { userId: 'u2', status: 'going' }, { userId: 'u3', status: 'going' }, { userId: 'u4', status: 'pending' },
            { userId: 'u5', status: 'going' }, { phone: '79001234567', status: 'pending' }
          ],
          picks: { u1: ['ds-supernova', 'mh-pinkman'], u2: ['ds-supernova', 'ad-love66'], u3: ['ds-supernova', 'mh-pinkman', 'tg-canemint'], u5: ['ds-bananapapa'] },
          bowls: { u1: 'b-phunnel', u2: 'b-phunnel', u3: 'b-killer' },
          comments: [
            { id: 'c1', userId: 'u3', text: 'Бронь на 20:30 подтвердили?', at: ago(180) },
            { id: 'c2', userId: 'u1', text: 'Да, диван у окна наш до часу ночи.', at: ago(150) },
            { id: 'c3', userId: 'u2', text: 'Возьму свой мундштук и калауд.', at: ago(40) }
          ],
          remind: {}, notified: {}
        },
        {
          id: 'e2', title: 'День рождения Тимура', venue: 'Северный дым', address: 'пр. Мира, 48', mapUrl: '',
          at: at(6, 19), hostId: 'u3', desc: 'Отмечаем 25 лет. Подарок собираем вскладчину, детали у Сабины.',
          hookahs: 3, price: 2200, paid: { u3: true },
          invites: [{ userId: 'u1', status: 'pending' }, { userId: 'u4', status: 'going' }, { userId: 'u6', status: 'going' }],
          picks: { u3: ['af-twoapples', 'sb-bluemist'], u4: ['af-twoapples'], u6: ['fu-gummi', 'sb-bluemist', 'af-twoapples'] },
          bowls: { u3: 'b-turka' },
          comments: [{ id: 'c4', userId: 'u4', text: 'Торт беру на себя.', at: ago(300) }],
          remind: {}, notified: {}
        },
        {
          id: 'e3', title: 'После работы', venue: 'Чайхана «Восток»', address: 'ул. Гоголя, 7', mapUrl: '',
          at: at(-9, 21), hostId: 'u2', desc: '',
          hookahs: 1, price: 1500, paid: { u1: true, u2: true, u6: true },
          invites: [{ userId: 'u1', status: 'going' }, { userId: 'u6', status: 'going' }],
          picks: { u1: ['bb-cherry'], u2: ['bb-cherry', 'el-grapefruit'], u6: ['el-grapefruit'] },
          bowls: { u2: 'b-fruit' }, comments: [], remind: {}, notified: {}
        }
      ],
      reviews: [
        { id: 'r1', tobaccoId: 'ds-supernova', userId: 'u3', rating: 5, text: 'Лучший холодок, добавляю в каждый микс по чуть-чуть.', at: ago(60 * 24 * 3) },
        { id: 'r2', tobaccoId: 'ds-supernova', userId: 'u2', rating: 4, text: 'Сильно холодит, больше 20% не кладу.', at: ago(60 * 24 * 8) },
        { id: 'r3', tobaccoId: 'mh-pinkman', userId: 'u1', rating: 5, text: 'Яркий и не приторный, держит вкус весь сеанс.', at: ago(60 * 24 * 5) },
        { id: 'r4', tobaccoId: 'af-twoapples', userId: 'u3', rating: 4, text: 'Классика. Лёгкий, подходит новичкам.', at: ago(60 * 24 * 12) },
        { id: 'r5', tobaccoId: 'tg-canemint', userId: 'u5', rating: 5, text: 'Крепкий, на любителя. Мята честная.', at: ago(60 * 24 * 2) },
        { id: 'r6', tobaccoId: 'od-cola', userId: 'u5', rating: 4, text: 'Похоже на колу, хорошо с мятой.', at: ago(60 * 24 * 6) },
        { id: 'r7', tobaccoId: 'fu-gummi', userId: 'u4', rating: 5, text: 'Сладкий, как мармелад. Девушкам заходит.', at: ago(60 * 24 * 9) },
        { id: 'r8', tobaccoId: 'bb-cherry', userId: 'u2', rating: 3, text: 'Слишком кислый в чистом виде.', at: ago(60 * 24 * 10) }
      ],
      mixes: [
        { id: 'm1', name: 'Ледяной грейпфрут', authorId: 'u3', parts: [{ id: 'mh-pinkman', pct: 50 }, { id: 'el-grapefruit', pct: 30 }, { id: 'ds-supernova', pct: 20 }], likes: ['u1', 'u2', 'u5'], at: ago(60 * 24 * 4) },
        { id: 'm2', name: 'Тропики', authorId: 'u2', parts: [{ id: 'ds-fallingstar', pct: 60 }, { id: 'ds-bananapapa', pct: 40 }], likes: ['u4'], at: ago(60 * 24 * 7) },
        { id: 'm3', name: 'Мятная кола', authorId: 'u5', parts: [{ id: 'od-cola', pct: 70 }, { id: 'tg-canemint', pct: 30 }], likes: ['u1', 'u3', 'u6', 'u2'], at: ago(60 * 24 * 2) },
        { id: 'm4', name: 'Ягодный лёд', authorId: 'u6', parts: [{ id: 'sb-bluemist', pct: 50 }, { id: 'mh-raspberry', pct: 35 }, { id: 'ch-icemint', pct: 15 }], likes: ['u2'], at: ago(60 * 24 * 1) }
      ]
    };
  }
  // Дополняет данные старой версии шаблона новыми полями.
  function migrate(d) {
    const s = seed();
    d.users.forEach(u => { u.favs ||= []; u.friends ||= []; u.favVenue ??= ''; });
    d.events.forEach(e => {
      e.picks ||= {}; e.bowls ||= {}; e.comments ||= []; e.paid ||= {}; e.remind ||= {}; e.notified ||= {};
      e.hookahs ??= 1; e.price ??= 0; e.mapUrl ??= '';
    });
    d.reviews ||= s.reviews;
    d.mixes ||= s.mixes;
    return d;
  }
  function load() { try { const raw = localStorage.getItem(KEY); if (raw) return migrate(JSON.parse(raw)); } catch (e) { /* хранилище недоступно */ } return null; }
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
  const isFriend = (a, b) => !!a && !!b && a.friends.includes(b.id);
  const sharedEvents = (a, b) => db.events.filter(e => isMember(e, a) && isMember(e, b));
  const canSeePhone = (viewer, u) => viewer && (viewer.id === u.id || isFriend(viewer, u) || sharedEvents(viewer, u).length > 0);

  // Подсчёт голосов: чем больше участников выбрали позицию, тем выше она в списке.
  function ranking(map, nameOf) {
    const c = {};
    for (const [userId, ids] of Object.entries(map || {})) for (const id of [].concat(ids)) (c[id] ||= []).push(userId);
    return Object.entries(c).map(([id, users]) => ({ id, users }))
      .sort((a, b) => b.users.length - a.users.length || nameOf(a.id).localeCompare(nameOf(b.id), 'ru'));
  }
  const tobaccoName = id => { const t = tobacco(id); return t ? `${t.brand} ${t.flavor}` : id; };
  const bowlName = id => bowl(id)?.name || id;
  const reviewsFor = id => db.reviews.filter(r => r.tobaccoId === id).sort((a, b) => new Date(b.at) - new Date(a.at));
  function ratingOf(id) {
    const r = reviewsFor(id);
    return r.length ? { avg: r.reduce((s, x) => s + x.rating, 0) / r.length, n: r.length } : { avg: 0, n: 0 };
  }
  function bill(e) {
    const going = goingIds(e), total = (e.hookahs || 0) * (e.price || 0);
    const per = going.length ? total / going.length : 0;
    const paidCount = going.filter(id => e.paid[id]).length;
    return { going, total, per, paidCount, collected: paidCount * per };
  }

  // Привязать приглашения «по номеру» к только что зарегистрированному пользователю.
  function claimPhoneInvites(user) {
    for (const e of db.events) for (const i of e.invites) if (!i.userId && i.phone === user.phone) { i.userId = user.id; delete i.phone; }
  }

  // ---------- Картинки ----------
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
  // Иллюстрация пачки: цвет вкуса вместо фотографии. Свою картинку можно задать полем `img` в каталоге.
  function packArt(t, size = '') {
    if (t.img) return `<img class="pack ${size}" src="${esc(t.img)}" alt="${esc(t.brand + ' ' + t.flavor)}">`;
    return `<div class="pack ${size}" style="--pc:${t.color}" aria-hidden="true">
      <span class="pack-smoke">${ICON.smoke}</span>
      <span class="pack-brand">${esc(t.brand)}</span><span class="pack-flavor">${esc(t.flavor)}</span></div>`;
  }
  function bowlArt(type) {
    const shapes = {
      'Фанел': '<path d="M14 26h36l-6 16H20z"/><path d="M28 26v-6h8v6" class="a2"/><rect x="29" y="42" width="6" height="10"/>',
      'Турка': '<path d="M12 24h40l-8 18H20z"/><circle cx="26" cy="33" r="1.6" class="a2"/><circle cx="32" cy="33" r="1.6" class="a2"/><circle cx="38" cy="33" r="1.6" class="a2"/><rect x="29" y="42" width="6" height="10"/>',
      'Киллер': '<path d="M16 14h32l-5 30H21z"/><rect x="29" y="44" width="6" height="8"/>',
      'На фрукте': '<path d="M10 28h44a22 18 0 0 1-44 0z"/><path d="M14 28h36" class="a2" stroke-width="3"/><rect x="29" y="44" width="6" height="8"/>'
    };
    return `<svg class="art-svg" viewBox="0 0 64 60" aria-hidden="true">${shapes[type] || shapes['Турка']}</svg>`;
  }
  function stars(v, cls = '') {
    const full = Math.round(v);
    return `<span class="stars ${cls}" aria-label="Оценка ${v ? v.toFixed(1) : 'нет'} из 5">${[1, 2, 3, 4, 5].map(i => `<i class="${i <= full ? 'on' : ''}">★</i>`).join('')}</span>`;
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
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !modalRoot.hidden) closeModal();
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[role=button][data-action]')) { e.preventDefault(); e.target.click(); }
  });

  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind; t.textContent = msg;
    $('#toasts').append(t);
    setTimeout(() => t.classList.add('out'), 3600);
    setTimeout(() => t.remove(), 4100);
  }

  // ---------- Оформление ----------
  const THEMES = { auto: ['Как в системе', ICON.auto], light: ['Светлая', ICON.sun], dark: ['Тёмная', ICON.moon] };
  const ACCENTS = { copper: 'Медь', mint: 'Мята', plum: 'Слива', ember: 'Уголь' };
  function applyLook() {
    const root = document.documentElement, theme = prefs.get('theme', 'auto'), accent = prefs.get('accent', 'copper');
    if (theme === 'auto') delete root.dataset.theme; else root.dataset.theme = theme;
    root.dataset.accent = ACCENTS[accent] ? accent : 'copper';
  }
  applyLook();

  // ---------- Шапка ----------
  function renderChrome(page) {
    const u = me(), theme = prefs.get('theme', 'auto');
    const themeBtn = `<button class="icon-btn" type="button" data-action="cycleTheme" title="Тема: ${THEMES[theme][0]}" aria-label="Тема: ${THEMES[theme][0]}">${THEMES[theme][1]}</button>`;
    $('#topbar-actions').innerHTML = themeBtn + (u
      ? `<button class="plus-btn" type="button" data-action="newEvent" title="Создать сбор и пригласить друзей" aria-label="Создать сбор">${ICON.plus}</button>
         <a class="me-link" href="#/profile" title="Профиль">${avatar(u, 'sm')}</a>`
      : `<a class="btn btn-ghost btn-sm hide-sm" href="#/register">Регистрация</a><a class="btn btn-primary btn-sm" href="#/login">Войти</a>`);
    $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === page));
  }

  // ---------- Страницы ----------
  const view = $('#view');

  function dateBlock(e) {
    const d = new Date(e.at);
    return `<div class="ev-date"><b>${dtDay.format(d)}</b><span>${dtMon.format(d).replace('.', '')}</span><span class="mono">${dtTime.format(d)}</span></div>`;
  }
  function eventCard(e, u, href = `#/event/${e.id}`) {
    const ids = goingIds(e), b = bill(e);
    const top = ranking(e.picks, tobaccoName)[0];
    const inv = u && myInvite(e, u);
    const status = e.hostId === u?.id ? '<span class="pill pill-host">Организатор</span>'
      : inv ? `<span class="pill pill-${inv.status}">${{ going: 'Иду', pending: 'Ждёт ответа', declined: 'Не иду' }[inv.status]}</span>` : '';
    return `<a class="ev-card ${isPast(e) ? 'ev-past' : ''}" href="${href}">
      ${dateBlock(e)}
      <div class="ev-body">
        <h3>${esc(e.title)}</h3>
        <div class="ev-venue">${ICON.pin}<span>${esc(e.venue)}</span></div>
        ${top ? `<div><span class="chip chip-accent">Лидирует: ${esc(tobaccoName(top.id))} · ${top.users.length}</span></div>` : ''}
        <div class="ev-meta">
          ${b.total ? `<span>${ICON.wallet}${money(b.per)} с человека</span>` : ''}
          ${e.comments.length ? `<span>${ICON.chat}${e.comments.length}</span>` : ''}
        </div>
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
    const soon = upcoming.filter(e => goingIds(e).includes(u.id) && new Date(e.at) - Date.now() < 864e5 && new Date(e.at) > Date.now() - 3 * 3600e3);
    view.innerHTML = `
      <section class="greet">
        <div><span class="eyebrow">Мои сборы</span><h1>Привет, ${esc(u.name)}</h1>
          <p>${upcoming.length ? `Впереди ${upcoming.length} ${plural(upcoming.length, 'сбор', 'сбора', 'сборов')}` : 'Пока нет запланированных сборов'}${invites.length ? ` и ${invites.length} ${plural(invites.length, 'новое приглашение', 'новых приглашения', 'новых приглашений')}` : ''}.</p></div>
        <button class="btn btn-primary" type="button" data-action="newEvent">+ Новый сбор</button>
      </section>
      ${soon.map(e => `<a class="soon" href="#/event/${e.id}"><span class="soon-dot"></span><span><b>${whenLabel(e)}</b> · ${esc(e.title)} · ${esc(e.venue)}</span><span class="soon-go">Открыть →</span></a>`).join('')}
      ${invites.length ? `<section class="section"><div class="section-head"><h2>Приглашения</h2></div><div class="ev-grid">
        ${invites.map(e => {
          const host = userById(e.hostId);
          return `<div class="ev-card invite-card">
            ${dateBlock(e)}
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
      ${past.length ? `<section class="section"><div class="section-head"><h2>Прошедшие</h2><span class="muted" style="font-size:13.5px">Сбор можно повторить с теми же людьми</span></div><div class="ev-grid">${past.map(e => eventCard(e, u)).join('')}</div></section>` : ''}`;
  }

  function stepsHtml() {
    return `<div class="steps">
      <div class="step"><h3>Создайте сбор</h3><p>Нажмите «+», укажите заведение, время, сколько кальянов и почём.</p></div>
      <div class="step"><h3>Пригласите друзей</h3><p>Найдите друзей по имени или номеру. Тех, кого ещё нет в сервисе, пригласите по номеру: сбор появится у них после регистрации.</p></div>
      <div class="step"><h3>Выберите табаки</h3><p>Участники отмечают вкусы и чашу, самые популярные поднимаются наверх. Сумма делится поровну.</p></div>
    </div>`;
  }

  function mixCard(m, u) {
    const author = userById(m.authorId), liked = !!u && m.likes.includes(u.id);
    return `<article class="cat-card mix-card">
      <div class="cat-top"><span class="cat-brand">Микс · ${m.parts.length} ${plural(m.parts.length, 'вкус', 'вкуса', 'вкусов')}</span>
        <button class="like-btn ${liked ? 'on' : ''}" type="button" data-action="likeMix" data-id="${m.id}" aria-pressed="${liked}" aria-label="Нравится">${ICON.heart}<span>${m.likes.length}</span></button></div>
      <h3>${esc(m.name)}</h3>
      <div class="mix-bar">${m.parts.map(p => `<span style="flex:${p.pct};--pc:${tobacco(p.id)?.color || 'gray'}" title="${esc(tobaccoName(p.id))} ${p.pct}%"></span>`).join('')}</div>
      <ul class="mix-legend">${m.parts.map(p => `<li><i style="--pc:${tobacco(p.id)?.color || 'gray'}"></i><span>${esc(tobaccoName(p.id))}</span><b class="mono">${p.pct}%</b></li>`).join('')}</ul>
      <div class="ev-venue">${avatar(author, 'xs')}<span>${esc(author?.name || 'Гость')}</span></div>
    </article>`;
  }

  function pageLanding() {
    const sample = eventById('e1') || db.events[0];
    const topMixes = [...db.mixes].sort((a, b) => b.likes.length - a.likes.length).slice(0, 3);
    const topT = [...CATALOG.tobaccos].sort((a, b) => ratingOf(b.id).avg - ratingOf(a.id).avg || ratingOf(b.id).n - ratingOf(a.id).n).slice(0, 4);
    const feat = (icon, h, p) => `<div class="feature"><span class="feature-ic">${icon}</span><h3>${h}</h3><p>${p}</p></div>`;
    view.innerHTML = `
      <section class="hero">
        <div><span class="eyebrow">Hookah Party</span>
          <h1>Собирайте друзей на&nbsp;<span>кальян</span> в&nbsp;пару касаний</h1>
          <p>Выберите заведение, отправьте приглашения и проголосуйте за табаки. Кальянщик получит готовый список, а счёт поделится сам.</p>
          <div class="hero-cta"><a class="btn btn-primary" href="#/register">Зарегистрироваться</a><a class="btn" href="#/login">У меня есть аккаунт</a></div>
        </div>
        <div class="hero-preview">${sample ? `<span class="eyebrow">Пример сбора</span><div style="height:10px"></div>${eventCard(sample, null, '#/login')}` : ''}</div>
      </section>
      <section class="features">
        ${feat(ICON.users, 'Приглашения по номеру', 'Зовите друзей из контактов. Кого нет в сервисе, получит сбор после регистрации.')}
        ${feat(ICON.star, 'Голосование за табаки', 'Каждый отмечает вкусы и чашу. Популярное поднимается наверх списка.')}
        ${feat(ICON.wallet, 'Складчина', 'Укажите число кальянов и цену. Сервис посчитает, сколько с каждого, и отметит, кто скинулся.')}
        ${feat(ICON.chat, 'Обсуждение и напоминания', 'Чат внутри сбора, напоминание за час и выгрузка в календарь телефона.')}
      </section>
      <section class="section"><div class="section-head"><h2>Популярные миксы</h2><a class="btn btn-sm" href="#/catalog" data-action="catTab" data-tab="mixes">Все миксы</a></div>
        <div class="cat-grid">${topMixes.map(m => mixCard(m, null)).join('')}</div></section>
      <section class="section"><div class="section-head"><h2>Лучшие по отзывам</h2><a class="btn btn-sm" href="#/catalog">Каталог</a></div>
        <div class="cat-grid">${topT.map(t => tobaccoCard(t, null)).join('')}</div></section>
      <section class="section"><div class="section-head"><h2>Как это работает</h2></div>${stepsHtml()}</section>
      <section class="cta-band"><div><h2>Пятница уже скоро</h2><p>Регистрация занимает минуту: имя, номер и код из SMS.</p></div><a class="btn btn-primary" href="#/register">Создать аккаунт</a></section>`;
  }

  function pageHow() {
    view.innerHTML = `<section class="section"><span class="eyebrow">Помощь</span><h1>Как это работает</h1></section>
      ${stepsHtml()}
      <section class="panel"><h2>Подтверждение телефона</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      При регистрации мы отправляем на номер четырёхзначный код. Пока номер не подтверждён, войти в сервис и получать приглашения нельзя.
      Так друзья могут найти вас по номеру, а приглашения не уходят чужим людям. Полный номер видят только друзья и участники общих сборов.</p></section>
      <section class="panel"><h2>Складчина</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      Организатор указывает, сколько кальянов заказать и сколько стоит один. Сумма делится поровну между теми, кто идёт.
      Организатор отмечает, кто уже перевёл деньги, и все видят, сколько собрано.</p></section>
      <section class="panel"><h2>Напоминания</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      Включите колокольчик на странице сбора, и сайт напомнит за час, если он открыт. Чтобы напоминание пришло наверняка,
      нажмите «В календарь»: сбор добавится в календарь телефона с напоминанием за час.</p></section>`;
  }

  function pageEvent(id) {
    const u = me();
    if (!u) return go('login');
    const e = eventById(id);
    if (!e) { view.innerHTML = `<div class="empty"><p>Сбор не найден или удалён.</p><a class="btn" href="#/">К моим сборам</a></div>`; return; }
    if (!isMember(e, u)) { view.innerHTML = `<div class="empty"><p>Это закрытый сбор. Попросите организатора прислать приглашение.</p><a class="btn" href="#/">К моим сборам</a></div>`; return; }
    const d = new Date(e.at), host = userById(e.hostId), inv = myInvite(e, u), isHost = e.hostId === u.id, past = isPast(e);
    const going = goingIds(e), b = bill(e);
    const tRank = ranking(e.picks, tobaccoName), bRank = ranking(e.bowls, bowlName);
    const myPicks = e.picks[u.id] || [];
    const reminded = !!e.remind[u.id];
    const place = [e.venue, e.address].filter(Boolean).join(', ');

    const rankHtml = (rank, kind) => {
      if (!rank.length) return `<div class="empty"><p>${kind === 't' ? 'Пока никто не выбрал табак.' : 'Чашу ещё не выбрали.'}</p></div>`;
      const max = rank[0].users.length;
      return `<ol class="rank">${rank.map((r, i) => {
        const n = r.users.length;
        const lead = i === 0 && (rank.length === 1 || rank[1].users.length < n);
        let name, sub, art;
        if (kind === 't') { const t = tobacco(r.id); art = `<span class="swatch" style="--pc:${t?.color}"></span>`; name = `<b>${esc(t?.brand)}</b> ${esc(t?.flavor)}`; sub = `${esc(t?.note)} · крепость ${t?.strength}/10`; }
        else { const bw = bowl(r.id); art = ''; name = `<b>${esc(bw?.name)}</b><small>${esc(bw?.type)}</small>`; sub = esc(bw?.note); }
        return `<li class="rank-row ${lead ? 'is-top' : ''}">
          <div class="rank-pos">${i + 1}</div>
          <div class="rank-body">
            <div class="rank-name">${art}${name} ${lead ? '<span class="lead-badge">лидер</span>' : ''}</div>
            <div class="rank-bar"><span style="width:${Math.round(n / max * 100)}%"></span></div>
            <div class="rank-meta">${avatarStack(r.users, 6, 'xs')}<span>${sub}</span></div>
          </div>
          <div class="rank-count">${n}<small>${plural(n, 'голос', 'голоса', 'голосов')}</small></div>
        </li>`;
      }).join('')}</ol>`;
    };

    const statusLabel = { going: 'Идёт', pending: 'Ждём ответа', declined: 'Не придёт' };
    const personRow = (p, phone, pill) => `<li class="person">${avatar(p, 'sm')}<div class="person-name">
      ${p ? `<a href="#/user/${p.id}"><b>${esc(p.name)}</b></a>` : '<b>Ещё не в сервисе</b>'}<small class="mono">${fmtPhone(phone)}</small></div>${pill}</li>`;
    const people = [
      personRow(host, host?.phone, '<span class="pill pill-host">Организатор</span>'),
      ...e.invites.map(i => { const p = i.userId ? userById(i.userId) : null; return personRow(p, p ? p.phone : i.phone, `<span class="pill pill-${i.status}">${statusLabel[i.status]}</span>`); })
    ].join('');

    const billHtml = b.total ? `
      <div class="bill-sum"><div><small>${e.hookahs} ${plural(e.hookahs, 'кальян', 'кальяна', 'кальянов')} × ${money(e.price)}</small><b>${money(b.total)}</b></div>
        <div><small>С каждого из ${going.length}</small><b>${money(b.per)}</b></div></div>
      <div class="progress" role="img" aria-label="Собрано ${money(b.collected)} из ${money(b.total)}"><span style="width:${Math.round(b.collected / b.total * 100)}%"></span></div>
      <p class="muted" style="font-size:13px">Собрано ${money(b.collected)} из ${money(b.total)}</p>
      <ul class="people">${going.map(uid => {
        const p = userById(uid), paid = !!e.paid[uid];
        const ctl = isHost && !past ? `<button class="pay-btn ${paid ? 'on' : ''}" data-action="togglePaid" data-id="${e.id}" data-user="${uid}" aria-pressed="${paid}">${paid ? 'Скинул' : 'Не скинул'}</button>`
          : `<span class="pill ${paid ? 'pill-going' : 'pill-pending'}">${paid ? 'Скинул' : 'Не скинул'}</span>`;
        return `<li class="person">${avatar(p, 'xs')}<div class="person-name"><b>${esc(p?.name)}</b></div>${ctl}</li>`;
      }).join('')}</ul>`
      : `<div class="empty"><p>${isHost ? 'Укажите, сколько кальянов заказываете и почём, и сервис поделит счёт.' : 'Организатор ещё не указал цену.'}</p></div>`;

    view.innerHTML = `
      <a class="back" href="#/">← Мои сборы</a>
      <section class="ev-hero">
        <div class="section-head"><div><span class="eyebrow">${past ? 'Сбор прошёл' : 'Сбор'}</span><h1 style="margin-top:8px">${esc(e.title)}</h1></div>
          <div class="btn-row">
            <button class="btn btn-sm" data-action="repeatEvent" data-id="${e.id}">${ICON.repeat}Повторить</button>
            ${isHost && !past ? `<button class="btn btn-sm" data-action="editEvent" data-id="${e.id}">${ICON.edit}Изменить</button>
              <button class="btn btn-danger btn-sm" data-action="deleteEvent" data-id="${e.id}">Отменить сбор</button>` : ''}
          </div></div>
        <div class="ev-facts">
          <div class="fact"><small>Заведение</small><b>${esc(e.venue)}</b></div>
          <div class="fact"><small>Адрес</small><b>${esc(e.address || 'Не указан')}</b></div>
          <div class="fact"><small>Когда</small><b>${dtFull.format(d)}, ${dtTime.format(d)}</b></div>
          <div class="fact"><small>Участники</small><b>${going.length} ${plural(going.length, 'идёт', 'идут', 'идут')} · ${e.invites.length + 1} ${plural(e.invites.length + 1, 'приглашён', 'приглашены', 'приглашены')}</b></div>
        </div>
        <div class="btn-row">
          <a class="btn btn-sm" href="https://yandex.ru/maps/?text=${encodeURIComponent(place)}" target="_blank" rel="noopener">${ICON.pin}Яндекс Карты</a>
          <a class="btn btn-sm" href="https://2gis.ru/search/${encodeURIComponent(place)}" target="_blank" rel="noopener">${ICON.pin}2ГИС</a>
          ${e.mapUrl ? `<a class="btn btn-sm" href="${esc(e.mapUrl)}" target="_blank" rel="noopener">${ICON.ext}Сайт заведения</a>` : ''}
          ${!past ? `<button class="btn btn-sm ${reminded ? 'btn-on' : ''}" data-action="toggleRemind" data-id="${e.id}" aria-pressed="${reminded}">${ICON.bell}${reminded ? 'Напомним за час' : 'Напомнить за час'}</button>
          <button class="btn btn-sm" data-action="ics" data-id="${e.id}">${ICON.cal}В календарь</button>` : ''}
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
              ${canVote(e, u) && !past ? `<button class="btn btn-sm" data-action="pickBowl" data-id="${e.id}">${e.bowls[u.id] ? 'Изменить' : 'Выбрать чашу'}</button>` : ''}</div>
            ${rankHtml(bRank, 'b')}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Обсуждение</h2><span class="muted" style="font-size:13.5px">${e.comments.length} ${plural(e.comments.length, 'сообщение', 'сообщения', 'сообщений')}</span></div>
            <ul class="comments">${e.comments.length ? e.comments.map(c => {
              const p = userById(c.userId);
              return `<li class="comment">${avatar(p, 'sm')}<div class="comment-body"><div class="comment-head"><b>${esc(p?.name || 'Участник')}</b><small>${timeAgo(c.at)}</small>
                ${c.userId === u.id || isHost ? `<button class="link-btn danger" data-action="deleteComment" data-id="${e.id}" data-comment="${c.id}">Удалить</button>` : ''}</div><p>${esc(c.text)}</p></div></li>`;
            }).join('') : '<li class="muted">Пока тихо. Напишите первым: кто что берёт, во сколько встречаемся.</li>'}</ul>
            <form class="comment-form" id="comment-form">
              <textarea id="comment-text" rows="2" maxlength="500" placeholder="Сообщение участникам" aria-label="Сообщение"></textarea>
              <button class="btn btn-primary" type="submit">Отправить</button>
            </form>
          </section>
        </div>
        <div class="ev-main">
          <aside class="panel">
            <div class="panel-head"><h2>Участники</h2>
              ${(isHost || inv?.status === 'going') && !past ? `<button class="plus-btn sm" data-action="invite" data-id="${e.id}" title="Пригласить" aria-label="Пригласить участников">${ICON.plus}</button>` : ''}</div>
            <ul class="people">${people}</ul>
          </aside>
          <aside class="panel">
            <div class="panel-head"><h2>Складчина</h2>
              ${isHost && !past ? `<button class="btn btn-sm" data-action="editBill" data-id="${e.id}">${b.total ? 'Изменить' : 'Указать'}</button>` : ''}</div>
            ${billHtml}
          </aside>
        </div>
      </div>`;

    const form = $('#comment-form'), ta = $('#comment-text');
    form.addEventListener('submit', ev => {
      ev.preventDefault();
      const text = ta.value.trim();
      if (!text) return;
      e.comments.push({ id: uid('c'), userId: u.id, text, at: new Date().toISOString() });
      save(); render();
      $('#comment-text')?.focus();
    });
    ta.addEventListener('keydown', ev => { if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) form.requestSubmit(); });
  }

  // ---------- Каталог ----------
  const cat = { tab: 'tobaccos', q: '', strength: 'all', tag: '', sort: 'rating' };
  function tobaccoCard(t, u) {
    const r = ratingOf(t.id), fav = !!u && u.favs.includes(t.id);
    return `<article class="cat-card t-card" data-action="tobacco" data-id="${t.id}" role="button" tabindex="0" aria-label="${esc(t.brand + ' ' + t.flavor)}: подробнее и отзывы">
      ${packArt(t)}
      <div class="cat-top"><span class="cat-brand">${esc(t.brand)}</span>
        ${u ? `<button class="fav-btn ${fav ? 'on' : ''}" type="button" data-action="fav" data-id="${t.id}" aria-pressed="${fav}" aria-label="В избранное">${ICON.heart}</button>` : ''}</div>
      <h3>${esc(t.flavor)}</h3><p>${esc(t.note)}</p>
      <div class="rating-line">${stars(r.avg)}<small>${r.n ? `${r.avg.toFixed(1)} · ${r.n} ${plural(r.n, 'отзыв', 'отзыва', 'отзывов')}` : 'Нет отзывов'}</small></div>
      ${strengthBar(t.strength)}
      <div class="cat-tags">${t.tags.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div>
    </article>`;
  }
  const strengthBar = s => `<div class="strength"><div class="strength-bar">${Array.from({ length: 10 }, (_, i) => `<i class="${i < s ? 'on' : ''} ${i < s && i >= 7 ? 'hot' : ''}"></i>`).join('')}</div><small>Крепость ${s}/10</small></div>`;

  function pageCatalog() {
    const u = me();
    const tabs = { tobaccos: 'Табаки', mixes: 'Миксы', bowls: 'Чаши', gear: 'Аксессуары' };
    view.innerHTML = `
      <section class="section"><span class="eyebrow">Каталог</span><h1>Табаки, миксы и всё для кальяна</h1></section>
      <div class="toolbar">
        <div class="tabs" role="tablist">${Object.entries(tabs).map(([k, v]) => `<button role="tab" aria-selected="${k === cat.tab}" class="${k === cat.tab ? 'active' : ''}" data-action="catTab" data-tab="${k}">${v}</button>`).join('')}</div>
        <div class="btn-row">
          ${cat.tab === 'mixes' ? '<button class="btn btn-primary btn-sm" data-action="newMix">+ Свой микс</button>' : ''}
          <input class="input" id="cat-q" type="search" placeholder="${cat.tab === 'mixes' ? 'Поиск по названию или табаку' : 'Поиск по бренду или вкусу'}" value="${esc(cat.q)}" style="max-width:300px" aria-label="Поиск">
        </div>
      </div>
      ${cat.tab === 'tobaccos' ? `<div class="filters">
        <div class="chip-row" role="group" aria-label="Крепость">${Object.entries(STRENGTH).map(([k, [label]]) => `<button class="chip-btn ${cat.strength === k ? 'on' : ''}" data-action="catFilter" data-strength="${k}">${label}</button>`).join('')}</div>
        <div class="chip-row" role="group" aria-label="Вкус"><button class="chip-btn ${!cat.tag ? 'on' : ''}" data-action="catFilter" data-tag="">Все вкусы</button>${ALL_TAGS.map(x => `<button class="chip-btn ${cat.tag === x ? 'on' : ''}" data-action="catFilter" data-tag="${esc(x)}">${esc(x)}</button>`).join('')}</div>
        <label class="sort">Сортировка <select id="cat-sort" class="input">
          <option value="rating" ${cat.sort === 'rating' ? 'selected' : ''}>По рейтингу</option>
          <option value="name" ${cat.sort === 'name' ? 'selected' : ''}>По названию</option>
          <option value="strong" ${cat.sort === 'strong' ? 'selected' : ''}>Сначала крепкие</option>
          <option value="light" ${cat.sort === 'light' ? 'selected' : ''}>Сначала лёгкие</option></select></label>
      </div>` : ''}
      <div class="cat-grid" id="cat-grid"></div>`;
    const grid = $('#cat-grid');
    const draw = () => {
      const q = cat.q.trim().toLowerCase();
      let html = '';
      if (cat.tab === 'tobaccos') {
        const [, lo, hi] = STRENGTH[cat.strength];
        const list = CATALOG.tobaccos
          .filter(t => (!q || `${t.brand} ${t.flavor} ${t.note} ${t.tags.join(' ')}`.toLowerCase().includes(q)) && t.strength >= lo && t.strength <= hi && (!cat.tag || t.tags.includes(cat.tag)))
          .sort({
            rating: (a, b) => ratingOf(b.id).avg - ratingOf(a.id).avg || ratingOf(b.id).n - ratingOf(a.id).n,
            name: (a, b) => tobaccoName(a.id).localeCompare(tobaccoName(b.id), 'ru'),
            strong: (a, b) => b.strength - a.strength, light: (a, b) => a.strength - b.strength
          }[cat.sort]);
        html = list.map(t => tobaccoCard(t, u)).join('');
      } else if (cat.tab === 'mixes') {
        html = [...db.mixes].filter(m => !q || (m.name + ' ' + m.parts.map(p => tobaccoName(p.id)).join(' ')).toLowerCase().includes(q))
          .sort((a, b) => b.likes.length - a.likes.length).map(m => mixCard(m, u)).join('');
      } else {
        html = CATALOG[cat.tab].filter(x => !q || `${x.name} ${x.type} ${x.note}`.toLowerCase().includes(q)).map(x => `
          <article class="cat-card"><div class="art-tile">${cat.tab === 'bowls' ? bowlArt(x.type) : `<span class="art-word">${esc(x.type)}</span>`}</div>
            <span class="cat-brand">${esc(x.type)}</span><h3>${esc(x.name)}</h3><p>${esc(x.note)}</p></article>`).join('');
      }
      grid.innerHTML = html || `<div class="empty" style="grid-column:1/-1"><p>Ничего не нашлось. Измените поиск или фильтры.</p></div>`;
    };
    draw();
    $('#cat-q').addEventListener('input', ev => { cat.q = ev.target.value; draw(); });
    $('#cat-sort')?.addEventListener('change', ev => { cat.sort = ev.target.value; draw(); });
  }

  function openTobacco(id) {
    const t = tobacco(id), u = me(); if (!t) return;
    const r = ratingOf(id), list = reviewsFor(id), mine = u && list.find(x => x.userId === u.id), fav = !!u && u.favs.includes(id);
    const inMixes = db.mixes.filter(m => m.parts.some(p => p.id === id));
    openModal(`${t.brand} ${t.flavor}`, `
      <div class="t-detail">${packArt(t, 'lg')}
        <div class="t-info"><p>${esc(t.note)}</p>${strengthBar(t.strength)}
          <div class="rating-line">${stars(r.avg, 'lg')}<small>${r.n ? `${r.avg.toFixed(1)} из 5 · ${r.n} ${plural(r.n, 'отзыв', 'отзыва', 'отзывов')}` : 'Отзывов пока нет'}</small></div>
          <div class="cat-tags">${t.tags.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div>
          ${u ? `<div><button class="btn btn-sm ${fav ? 'btn-on' : ''}" data-action="fav" data-id="${t.id}" aria-pressed="${fav}">${ICON.heart}${fav ? 'В избранном' : 'В избранное'}</button></div>` : ''}
        </div></div>
      ${inMixes.length ? `<div><span class="label">Встречается в миксах</span><div class="cat-tags" style="margin-top:6px">${inMixes.map(m => `<span class="chip chip-accent">${esc(m.name)}</span>`).join('')}</div></div>` : ''}
      ${u ? `<form class="form review-form" id="rv-form">
        <span class="label">${mine ? 'Ваш отзыв' : 'Оставить отзыв'}</span>
        <div class="star-input" role="radiogroup" aria-label="Оценка">${[5, 4, 3, 2, 1].map(n => `<input type="radio" name="rv-star" id="rv-s${n}" value="${n}" ${mine?.rating === n ? 'checked' : ''}><label for="rv-s${n}" title="${n} из 5">★</label>`).join('')}</div>
        <div class="field"><textarea id="rv-text" maxlength="400" placeholder="Как раскрывается, с чем мешать, на какой чаше лучше">${esc(mine?.text || '')}</textarea></div>
        <div class="error" id="rv-err"></div>
        <div><button class="btn btn-primary btn-sm" type="submit">${mine ? 'Обновить отзыв' : 'Опубликовать'}</button></div>
      </form>` : '<p class="muted"><a href="#/login" style="color:var(--accent)">Войдите</a>, чтобы оставить отзыв.</p>'}
      <ul class="comments">${list.map(x => {
        const p = userById(x.userId);
        return `<li class="comment">${avatar(p, 'sm')}<div class="comment-body"><div class="comment-head"><b>${esc(p?.name || 'Гость')}</b>${stars(x.rating)}<small>${timeAgo(x.at)}</small></div>${x.text ? `<p>${esc(x.text)}</p>` : ''}</div></li>`;
      }).join('')}</ul>`, m => {
      const f = $('#rv-form', m);
      f && f.addEventListener('submit', ev => {
        ev.preventDefault();
        const rating = +($('input[name=rv-star]:checked', m)?.value || 0);
        if (!rating) { $('#rv-err', m).textContent = 'Поставьте оценку от 1 до 5 звёзд.'; return; }
        const text = $('#rv-text', m).value.trim();
        if (mine) Object.assign(mine, { rating, text, at: new Date().toISOString() });
        else db.reviews.push({ id: uid('r'), tobaccoId: id, userId: u.id, rating, text, at: new Date().toISOString() });
        save(); toast('Спасибо за отзыв'); render(); openTobacco(id);
      });
    });
  }

  // ---------- Люди ----------
  function personCard(p, u) {
    const friend = isFriend(u, p), shared = sharedEvents(u, p).length;
    return `<article class="person-card">
      <a class="person-link" href="#/user/${p.id}">${avatar(p)}<div class="person-name"><b>${esc(p.name)}</b>
        <small>${p.favVenue ? `Любит ${esc(p.favVenue)}` : 'Любимое место не указано'}</small>
        <small>${shared ? `${shared} ${plural(shared, 'общий сбор', 'общих сбора', 'общих сборов')}` : 'Общих сборов нет'}</small></div></a>
      <button class="btn btn-sm ${friend ? 'btn-on' : 'btn-primary'}" data-action="toggleFriend" data-id="${p.id}" aria-pressed="${friend}">${friend ? `${ICON.check}В друзьях` : '+ В друзья'}</button>
    </article>`;
  }
  let peopleTab = 'friends', peopleQ = '';
  function pagePeople() {
    const u = me();
    if (!u) return go('login');
    const others = db.users.filter(p => p.id !== u.id);
    const friends = others.filter(p => isFriend(u, p));
    view.innerHTML = `
      <section class="section"><span class="eyebrow">Люди</span><h1>Друзья и знакомые</h1>
        <p class="muted">Друзья первыми появляются в списке приглашений и видят ваш номер целиком.</p></section>
      <div class="toolbar">
        <div class="tabs" role="tablist">
          <button role="tab" class="${peopleTab === 'friends' ? 'active' : ''}" data-action="peopleTab" data-tab="friends">Друзья · ${friends.length}</button>
          <button role="tab" class="${peopleTab === 'all' ? 'active' : ''}" data-action="peopleTab" data-tab="all">Все люди</button></div>
        <input class="input" id="pp-q" type="search" placeholder="Имя или номер" value="${esc(peopleQ)}" style="max-width:300px" aria-label="Поиск людей">
      </div>
      <div class="people-grid" id="pp-grid"></div>`;
    const draw = () => {
      const q = peopleQ.trim().toLowerCase(), qd = digits(q);
      const list = (peopleTab === 'friends' ? friends : others).filter(p => !q || p.name.toLowerCase().includes(q) || (qd.length >= 4 && p.phone.includes(qd)));
      $('#pp-grid').innerHTML = list.map(p => personCard(p, u)).join('') ||
        `<div class="empty" style="grid-column:1/-1"><p>${peopleTab === 'friends' && !q ? 'Друзей пока нет. Откройте «Все люди» и добавьте тех, с кем ходите на кальян.' : 'Никого не нашли.'}</p></div>`;
    };
    draw();
    $('#pp-q').addEventListener('input', ev => { peopleQ = ev.target.value; draw(); });
  }

  function pageUser(id) {
    const u = me();
    if (!u) return go('login');
    if (id === u.id) return go('profile');
    const p = userById(id);
    if (!p) { view.innerHTML = `<div class="empty"><p>Пользователь не найден.</p><a class="btn" href="#/people">К людям</a></div>`; return; }
    const friend = isFriend(u, p), shared = sharedEvents(u, p).sort((a, b) => new Date(b.at) - new Date(a.at));
    const favs = p.favs.map(tobacco).filter(Boolean), mixes = db.mixes.filter(m => m.authorId === p.id);
    view.innerHTML = `
      <a class="back" href="#/people">← Люди</a>
      <div class="profile">
        <section class="panel profile-card">
          ${avatar(p, 'lg')}
          <div><h2>${esc(p.name)}</h2><div class="mono" style="margin-top:6px">${canSeePhone(u, p) ? fmtPhone(p.phone) : maskedPhone(p.phone)}</div>
            ${p.verified ? `<div class="verified" style="margin-top:6px">${ICON.check}Номер подтверждён</div>` : ''}</div>
          ${p.favVenue ? `<div class="fact" style="width:100%"><small>Любимое место</small><b>${esc(p.favVenue)}</b></div>` : ''}
          <div class="btn-row" style="justify-content:center">
            <button class="btn btn-sm ${friend ? 'btn-on' : 'btn-primary'}" data-action="toggleFriend" data-id="${p.id}" aria-pressed="${friend}">${friend ? `${ICON.check}В друзьях` : '+ В друзья'}</button>
            <button class="btn btn-sm" data-action="inviteUser" data-id="${p.id}">Позвать на сбор</button></div>
        </section>
        <div class="ev-main">
          <section class="panel"><div class="panel-head"><h2>Любимые табаки</h2></div>
            ${favs.length ? `<div class="cat-tags">${favs.map(t => `<button class="chip chip-accent" data-action="tobacco" data-id="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</button>`).join('')}</div>` : '<p class="muted">Пока ничего не отмечено.</p>'}</section>
          ${mixes.length ? `<section class="panel"><div class="panel-head"><h2>Миксы</h2></div><div class="cat-grid">${mixes.map(m => mixCard(m, u)).join('')}</div></section>` : ''}
          <section class="panel"><div class="panel-head"><h2>Общие сборы</h2></div>
            ${shared.length ? `<div class="ev-grid">${shared.map(e => eventCard(e, u)).join('')}</div>` : '<p class="muted">Вы ещё не были на одном сборе.</p>'}</section>
        </div>
      </div>`;
  }

  function pageProfile() {
    const u = me();
    if (!u) return go('login');
    const hosted = db.events.filter(e => e.hostId === u.id).length;
    const history = db.events.filter(e => isPast(e) && goingIds(e).includes(u.id)).sort((a, b) => new Date(b.at) - new Date(a.at));
    const favs = u.favs.map(tobacco).filter(Boolean);
    const friends = u.friends.map(userById).filter(Boolean);
    const venues = [...new Set(db.events.map(e => e.venue))];
    const theme = prefs.get('theme', 'auto'), accent = prefs.get('accent', 'copper');
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
            <div class="stat"><b>${history.length}</b><small>посетил</small></div>
            <div class="stat"><b>${friends.length}</b><small>${plural(friends.length, 'друг', 'друга', 'друзей')}</small></div>
          </div>
          <button class="btn btn-ghost btn-sm" data-action="logout">Выйти из аккаунта</button>
        </section>
        <div class="ev-main">
          <section class="panel">
            <div class="panel-head"><h2>Личные данные</h2></div>
            <form class="form" id="profile-form">
              <div class="field"><label for="pf-name">Имя</label><input id="pf-name" required minlength="2" maxlength="40" value="${esc(u.name)}"></div>
              <div class="field"><label for="pf-venue">Любимое заведение</label><input id="pf-venue" maxlength="60" list="pf-venues" placeholder="Где чаще всего собираетесь" value="${esc(u.favVenue)}">
                <datalist id="pf-venues">${venues.map(v => `<option value="${esc(v)}">`).join('')}</datalist></div>
              <div class="field"><span class="label">Телефон</span><div class="input mono" style="opacity:.8">${fmtPhone(u.phone)}</div></div>
              <div class="error" id="pf-err"></div>
              <div><button class="btn btn-primary" type="submit">Сохранить</button></div>
            </form>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Оформление</h2></div>
            <div class="form">
              <div class="field"><span class="label">Тема</span><div class="segmented" role="radiogroup" aria-label="Тема">${Object.entries(THEMES).map(([k, [label, ic]]) => `<button role="radio" aria-checked="${theme === k}" class="${theme === k ? 'on' : ''}" data-action="setTheme" data-theme="${k}">${ic}${label}</button>`).join('')}</div></div>
              <div class="field"><span class="label">Цвет акцента</span><div class="swatches" role="radiogroup" aria-label="Цвет акцента">${Object.entries(ACCENTS).map(([k, label]) => `<button role="radio" aria-checked="${accent === k}" class="sw sw-${k} ${accent === k ? 'on' : ''}" data-action="setAccent" data-accent="${k}"><i></i>${label}</button>`).join('')}</div></div>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Друзья</h2><a class="btn btn-sm" href="#/people">Найти друзей</a></div>
            ${friends.length ? `<div class="friend-row">${friends.map(f => `<a href="#/user/${f.id}" class="friend">${avatar(f)}<span>${esc(f.name)}</span></a>`).join('')}</div>` : '<p class="muted">Добавьте друзей, чтобы быстрее звать их на сборы.</p>'}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Любимые табаки</h2><a class="btn btn-sm" href="#/catalog">Открыть каталог</a></div>
            ${favs.length ? `<div class="cat-tags">${favs.map(t => `<button class="chip chip-accent" data-action="tobacco" data-id="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</button>`).join('')}</div>`
              : '<p class="muted">Отмечайте вкусы сердечком в каталоге, и они появятся здесь.</p>'}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>История</h2></div>
            ${history.length ? `<ul class="history">${history.map(e => {
              const mine = (e.picks[u.id] || []).map(tobaccoName), top = ranking(e.picks, tobaccoName).slice(0, 2).map(r => tobaccoName(r.id));
              return `<li><a href="#/event/${e.id}"><span class="history-date mono">${dtShort.format(new Date(e.at))}</span><span class="history-main"><b>${esc(e.title)}</b><small>${esc(e.venue)}</small></span>
                <span class="history-t">${mine.length ? `Мой выбор: ${esc(mine.join(', '))}` : top.length ? `Курили: ${esc(top.join(', '))}` : ''}</span></a></li>`;
            }).join('')}</ul>` : '<p class="muted">Здесь появятся прошедшие сборы: где были и что курили.</p>'}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Демо-данные</h2></div>
            <p class="muted" style="margin-bottom:14px">Все данные этого шаблона хранятся в вашем браузере. Сброс вернёт тестовых пользователей, сборы, отзывы и миксы.</p>
            <button class="btn btn-danger btn-sm" data-action="reset">Сбросить демо-данные</button>
          </section>
        </div>
      </div>`;
    $('#profile-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const name = $('#pf-name').value.trim();
      if (name.length < 2) { $('#pf-err').textContent = 'Имя должно быть не короче двух букв.'; return; }
      u.name = name; u.favVenue = $('#pf-venue').value.trim(); save(); toast('Профиль сохранён'); render();
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
        else { user = { id: uid('u'), name, phone, pass: hashPass(pass), verified: true, avatar: null, favs: [], friends: [], favVenue: '', createdAt: new Date().toISOString() }; db.users.push(user); }
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
      r.innerHTML = left > 0 ? `Отправить код повторно через <span class="mono">0:${pad(left)}</span>` : '<button class="link-btn" type="button" id="resend-btn">Отправить код ещё раз</button>';
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
  function invitePicker(root, exclude, preset = []) {
    const u = me(), sel = preset.slice();
    root.innerHTML = `<div class="picker"><div class="picker-chips"></div>
      <input class="input" id="inv-q" placeholder="Имя или номер телефона" autocomplete="off" aria-label="Кого пригласить"><div class="suggest"></div></div>`;
    const chips = $('.picker-chips', root), sug = $('.suggest', root), q = $('#inv-q', root);
    const taken = () => new Set([...exclude, ...sel.map(s => s.userId || s.phone)]);
    const draw = () => {
      chips.innerHTML = sel.map((s, i) => {
        const p = s.userId && userById(s.userId);
        return `<span class="chip">${p ? avatar(p, 'xs') + esc(p.name) : `<span class="mono">${fmtPhone(s.phone)}</span>`}<button type="button" data-i="${i}" aria-label="Убрать">×</button></span>`;
      }).join('');
      const text = q.value.trim().toLowerCase(), qd = digits(text), t = taken();
      const found = db.users
        .filter(p => !t.has(p.id) && (!text || p.name.toLowerCase().includes(text) || (qd.length >= 3 && p.phone.includes(qd))))
        .sort((a, b) => isFriend(u, b) - isFriend(u, a) || a.name.localeCompare(b.name, 'ru')).slice(0, 6);
      let html = found.map(p => `<button type="button" data-u="${p.id}">${avatar(p, 'sm')}<span>${esc(p.name)}${isFriend(u, p) ? ' <em class="tag-friend">друг</em>' : ''}</span><small>${canSeePhone(u, p) ? fmtPhone(p.phone) : maskedPhone(p.phone)}</small></button>`).join('');
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
    const p = s.phone && userByPhone(s.phone);
    return p ? { userId: p.id, status: 'pending' } : { ...s, status: 'pending' };
  });

  // Форма сбора: создание, повтор и редактирование.
  function eventForm({ heading, submitLabel, data = {}, preset = [], withPicker = true, onSave }) {
    const u = me();
    const at = data.at ? new Date(data.at) : (() => { const t = new Date(Date.now() + 864e5); t.setHours(20, 0, 0, 0); return t; })();
    let picker;
    openModal(heading, `
      <form class="form" id="ev-form" novalidate>
        <div class="field"><label for="ev-title">Название</label><input id="ev-title" maxlength="60" placeholder="Например, пятничный сбор" value="${esc(data.title || '')}"></div>
        <div class="row-2"><div class="field"><label for="ev-venue">Заведение</label><input id="ev-venue" maxlength="60" list="ev-venues" placeholder="Название кальянной" value="${esc(data.venue || u.favVenue || '')}">
            <datalist id="ev-venues">${[...new Set([u.favVenue, ...db.events.map(e => e.venue)].filter(Boolean))].map(v => `<option value="${esc(v)}">`).join('')}</datalist></div>
          <div class="field"><label for="ev-address">Адрес</label><input id="ev-address" maxlength="100" placeholder="Улица, дом" value="${esc(data.address || '')}"></div></div>
        <div class="field"><label for="ev-map">Ссылка на заведение <span class="muted">(необязательно)</span></label><input id="ev-map" type="url" maxlength="300" placeholder="https://… сайт, Instagram или карточка на картах" value="${esc(data.mapUrl || '')}"></div>
        <div class="row-2"><div class="field"><label for="ev-date">Дата</label><input id="ev-date" type="date" value="${ymd(at)}"></div>
          <div class="field"><label for="ev-time">Время</label><input id="ev-time" type="time" value="${hm(at)}"></div></div>
        <div class="row-2"><div class="field"><label for="ev-hookahs">Кальянов</label><input id="ev-hookahs" type="number" min="0" max="20" value="${data.hookahs ?? 2}"></div>
          <div class="field"><label for="ev-price">Цена одного, ₽</label><input id="ev-price" type="number" min="0" max="100000" step="50" value="${data.price ?? 1800}"></div></div>
        <div class="field"><label for="ev-desc">Комментарий</label><textarea id="ev-desc" maxlength="400" placeholder="Бронь, кто что приносит">${esc(data.desc || '')}</textarea></div>
        ${withPicker ? '<div class="field"><span class="label">Пригласить</span><div id="ev-picker"></div></div>' : ''}
        <div class="error" id="ev-err"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="submit">${submitLabel}</button></div>
      </form>`, m => {
      if (withPicker) picker = invitePicker($('#ev-picker', m), [u.id], preset);
      $('#ev-form', m).addEventListener('submit', ev => {
        ev.preventDefault();
        const err = $('#ev-err', m), val = s => $(s, m).value.trim();
        const title = val('#ev-title'), venue = val('#ev-venue'), mapUrl = val('#ev-map');
        if (!title) return void (err.textContent = 'Придумайте название сбора.');
        if (!venue) return void (err.textContent = 'Укажите заведение.');
        if (mapUrl && !/^https?:\/\/\S+\.\S+/.test(mapUrl)) return void (err.textContent = 'Ссылка должна начинаться с https://');
        const when = new Date(`${val('#ev-date')}T${val('#ev-time') || '20:00'}`);
        if (isNaN(when)) return void (err.textContent = 'Укажите дату и время.');
        if (when < Date.now()) return void (err.textContent = 'Это время уже прошло. Выберите время в будущем.');
        const hookahs = Math.max(0, Math.min(20, parseInt(val('#ev-hookahs'), 10) || 0));
        const price = Math.max(0, parseInt(val('#ev-price'), 10) || 0);
        onSave({ title, venue, address: val('#ev-address'), mapUrl, at: when.toISOString(), hookahs, price, desc: val('#ev-desc') }, picker ? toInvites(picker.get()) : []);
      });
    });
  }
  function createEvent(fields, invites) {
    const e = { id: uid('e'), hostId: me().id, ...fields, invites, picks: {}, bowls: {}, comments: [], paid: {}, remind: {}, notified: {} };
    db.events.push(e); save(); closeModal();
    toast(invites.length ? `Сбор создан, приглашения отправлены: ${invites.length}` : 'Сбор создан');
    go('event/' + e.id);
  }

  // Напоминания работают, пока сайт открыт. Надёжный вариант — файл .ics с будильником.
  function checkReminders() {
    const u = me(); if (!u) return;
    for (const e of db.events) {
      if (!e.remind[u.id] || e.notified[u.id]) continue;
      const left = new Date(e.at) - Date.now();
      if (left > 0 && left <= 3600e3) {
        e.notified[u.id] = true; save();
        const msg = `Через ${Math.ceil(left / 60000)} мин: ${e.title}, ${e.venue}`;
        toast(msg);
        try { if ('Notification' in window && Notification.permission === 'granted') new Notification('Hookah Party', { body: msg }); } catch (err) { /* уведомления недоступны */ }
      }
    }
  }
  setInterval(checkReminders, 30000);

  function downloadIcs(e) {
    const f = d => `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}00Z`;
    const x = t => String(t || '').replace(/[\\,;]/g, m => '\\' + m).replace(/\n/g, '\\n');
    const s = new Date(e.at), end = new Date(s.getTime() + 3 * 3600e3);
    const ics = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Hookah Party//RU', 'BEGIN:VEVENT',
      `UID:${e.id}@hookahparty`, `DTSTAMP:${f(new Date())}`, `DTSTART:${f(s)}`, `DTEND:${f(end)}`,
      `SUMMARY:${x(e.title)}`, `LOCATION:${x([e.venue, e.address].filter(Boolean).join(', '))}`, `DESCRIPTION:${x(e.desc)}`,
      'BEGIN:VALARM', 'TRIGGER:-PT60M', 'ACTION:DISPLAY', 'DESCRIPTION:Через час кальянный сбор', 'END:VALARM',
      'END:VEVENT', 'END:VCALENDAR'].join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([ics], { type: 'text/calendar' }));
    a.download = `hookah-party-${e.id}.ics`;
    document.body.append(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ---------- Действия ----------
  function go(path) { const h = '#/' + path; if (location.hash === h) route(); else location.hash = h; }
  function requireUser() { if (me()) return true; toast('Войдите, чтобы продолжить'); go('login'); return false; }

  const actions = {
    closeModal,
    newEvent() {
      if (!requireUser()) return;
      eventForm({ heading: 'Новый сбор', submitLabel: 'Создать и пригласить', onSave: createEvent });
    },
    inviteUser({ id }) {
      if (!requireUser()) return;
      eventForm({ heading: 'Новый сбор', submitLabel: 'Создать и пригласить', preset: [{ userId: id }], onSave: createEvent });
    },
    repeatEvent({ id }) {
      const e = eventById(id), u = me(); if (!e || !u) return;
      const next = new Date(e.at);
      do next.setDate(next.getDate() + 7); while (next < Date.now());
      const preset = [...(e.hostId !== u.id ? [{ userId: e.hostId }] : []),
        ...e.invites.filter(i => i.userId !== u.id && i.status !== 'declined').map(i => i.userId ? { userId: i.userId } : { phone: i.phone })];
      eventForm({ heading: 'Повторить сбор', submitLabel: 'Создать и пригласить', data: { ...e, at: next.toISOString() }, preset, onSave: createEvent });
    },
    editEvent({ id }) {
      const e = eventById(id); if (!e) return;
      eventForm({
        heading: 'Изменить сбор', submitLabel: 'Сохранить', data: e, withPicker: false,
        onSave(fields) {
          if (fields.at !== e.at) e.notified = {};
          Object.assign(e, fields); save(); closeModal(); toast('Сбор обновлён'); render();
        }
      });
    },
    editBill({ id }) {
      const e = eventById(id); if (!e) return;
      openModal('Складчина', `<form class="form" id="bill-form">
        <div class="row-2"><div class="field"><label for="bl-h">Кальянов</label><input id="bl-h" type="number" min="0" max="20" value="${e.hookahs}"></div>
          <div class="field"><label for="bl-p">Цена одного, ₽</label><input id="bl-p" type="number" min="0" step="50" value="${e.price}"></div></div>
        <p class="muted" id="bl-sum"></p>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="submit">Сохранить</button></div></form>`, m => {
        const n = goingIds(e).length, upd = () => {
          const t = (+$('#bl-h', m).value || 0) * (+$('#bl-p', m).value || 0);
          $('#bl-sum', m).textContent = `Итого ${money(t)}, с каждого из ${n}: ${money(n ? t / n : 0)}`;
        };
        $$('input', m).forEach(i => i.addEventListener('input', upd)); upd();
        $('#bill-form', m).addEventListener('submit', ev => {
          ev.preventDefault();
          e.hookahs = Math.max(0, Math.min(20, parseInt($('#bl-h', m).value, 10) || 0));
          e.price = Math.max(0, parseInt($('#bl-p', m).value, 10) || 0);
          save(); closeModal(); render();
        });
      });
    },
    togglePaid({ id, user }) {
      const e = eventById(id); if (!e || e.hostId !== me()?.id) return;
      if (e.paid[user]) delete e.paid[user]; else e.paid[user] = true;
      save(); render();
    },
    toggleRemind({ id }) {
      const e = eventById(id), u = me(); if (!e || !u) return;
      if (e.remind[u.id]) { delete e.remind[u.id]; save(); toast('Напоминание выключено'); render(); return; }
      e.remind[u.id] = true; delete e.notified[u.id]; save(); render();
      toast('Напомним за час, пока сайт открыт. Надёжнее добавить сбор в календарь.');
      try { if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {}); } catch (err) { /* уведомления недоступны */ }
      checkReminders();
    },
    ics({ id }) { const e = eventById(id); if (e) { downloadIcs(e); toast('Файл календаря скачан. Откройте его, чтобы добавить сбор.'); } },
    deleteComment({ id, comment }) {
      const e = eventById(id); if (!e) return;
      e.comments = e.comments.filter(c => c.id !== comment); save(); render();
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
          e.invites.push(...list); save(); closeModal(); toast(`Приглашения отправлены: ${list.length}`); render();
        };
      });
    },
    rsvp({ id, status }) {
      const e = eventById(id), u = me(), inv = e && u && myInvite(e, u); if (!inv) return;
      inv.status = status;
      if (status !== 'going') { delete e.picks[u.id]; delete e.bowls[u.id]; delete e.paid[u.id]; }
      save(); toast(status === 'going' ? 'Отлично, ждём вас! Выберите табаки.' : 'Организатор узнает, что вы не придёте'); render();
    },
    pickTobacco({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      const MAX = 5, cur = new Set(e.picks[u.id] || []);
      const list = [...CATALOG.tobaccos].sort((a, b) => u.favs.includes(b.id) - u.favs.includes(a.id));
      openModal('Мои табаки', `
        <p class="muted">Отметьте до ${MAX} вкусов. Избранные стоят первыми. Позиции, которые выбрало больше участников, будут выше в общем списке.</p>
        <input class="input" id="pk-q" type="search" placeholder="Поиск по бренду или вкусу" aria-label="Поиск табака">
        <div class="pick-list" id="pk-list">${list.map(t => `<label class="pick-item" data-s="${esc((t.brand + ' ' + t.flavor + ' ' + t.note).toLowerCase())}">
          <input type="checkbox" value="${t.id}" ${cur.has(t.id) ? 'checked' : ''}><span class="swatch" style="--pc:${t.color}"></span><span><b>${esc(t.brand)}</b> ${esc(t.flavor)}${u.favs.includes(t.id) ? ' <em class="tag-friend">избранное</em>' : ''}<small>${esc(t.note)}</small></span><em>${t.strength}/10</em></label>`).join('')}</div>
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
          save(); closeModal(); toast('Ваш выбор учтён'); render();
        };
      });
    },
    pickBowl({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      const cur = e.bowls[u.id];
      openModal('Чаша', `<div class="pick-list">${CATALOG.bowls.map(b => `<label class="pick-item"><input type="radio" name="bowl" value="${b.id}" ${cur === b.id ? 'checked' : ''}>
          <span><b>${esc(b.name)}</b><small>${esc(b.type)} · ${esc(b.note)}</small></span></label>`).join('')}</div>
        <div class="modal-foot">${cur ? '<button class="btn btn-ghost" type="button" id="bw-clear" style="margin-right:auto">Снять голос</button>' : ''}
          <button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="button" id="bw-save">Сохранить</button></div>`, m => {
        $('#bw-save', m).onclick = () => {
          const v = $('input[name=bowl]:checked', m)?.value;
          if (!v) return toast('Выберите чашу', 'err');
          e.bowls[u.id] = v; save(); closeModal(); render();
        };
        const c = $('#bw-clear', m); if (c) c.onclick = () => { delete e.bowls[u.id]; save(); closeModal(); render(); };
      });
    },
    deleteEvent({ id }) {
      const e = eventById(id); if (!e) return;
      openModal('Отменить сбор?', `<p class="muted">Сбор «${esc(e.title)}» исчезнет у всех приглашённых. Это действие нельзя отменить.</p>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Оставить</button><button class="btn btn-danger" type="button" id="del-ok">Отменить сбор</button></div>`, m => {
        $('#del-ok', m).onclick = () => { db.events = db.events.filter(x => x.id !== id); save(); closeModal(); toast('Сбор отменён'); go(''); };
      });
    },
    tobacco({ id }) { openTobacco(id); },
    fav({ id }, el) {
      const u = me(); if (!u) return;
      u.favs = u.favs.includes(id) ? u.favs.filter(x => x !== id) : [...u.favs, id];
      save();
      const inModal = el.closest('.modal');
      render();
      if (inModal) openTobacco(id);
    },
    newMix() {
      if (!requireUser()) return;
      const opts = `<option value="">— не выбран —</option>` + CATALOG.tobaccos.map(t => `<option value="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</option>`).join('');
      openModal('Свой микс', `<form class="form" id="mix-form">
        <div class="field"><label for="mx-name">Название</label><input id="mx-name" maxlength="40" placeholder="Например, Ягодный лёд"></div>
        ${[0, 1, 2].map(i => `<div class="mix-row"><div class="field"><label for="mx-t${i}">Табак ${i + 1}${i === 2 ? ' <span class="muted">(необязательно)</span>' : ''}</label><select id="mx-t${i}" class="input">${opts}</select></div>
          <div class="field"><label for="mx-p${i}">Доля, %</label><input id="mx-p${i}" type="number" min="0" max="100" step="5" value="${[60, 40, 0][i]}"></div></div>`).join('')}
        <div class="mix-bar" id="mx-bar"></div>
        <p class="muted" id="mx-sum"></p>
        <div class="error" id="mx-err"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">Отмена</button><button class="btn btn-primary" type="submit">Опубликовать</button></div></form>`, m => {
        const parts = () => [0, 1, 2].map(i => ({ id: $(`#mx-t${i}`, m).value, pct: parseInt($(`#mx-p${i}`, m).value, 10) || 0 })).filter(p => p.id && p.pct > 0);
        const upd = () => {
          const p = parts(), sum = p.reduce((s, x) => s + x.pct, 0);
          $('#mx-sum', m).textContent = `Сумма долей: ${sum}%${sum !== 100 ? ' · должно быть 100%' : ''}`;
          $('#mx-bar', m).innerHTML = p.map(x => `<span style="flex:${x.pct};--pc:${tobacco(x.id).color}"></span>`).join('');
        };
        $$('input, select', m).forEach(i => i.addEventListener('input', upd)); upd();
        $('#mix-form', m).addEventListener('submit', ev => {
          ev.preventDefault();
          const err = $('#mx-err', m), name = $('#mx-name', m).value.trim(), p = parts();
          if (!name) return void (err.textContent = 'Придумайте название микса.');
          if (p.length < 2) return void (err.textContent = 'Выберите хотя бы два табака с долей больше нуля.');
          if (new Set(p.map(x => x.id)).size !== p.length) return void (err.textContent = 'Табаки в миксе не должны повторяться.');
          if (p.reduce((s, x) => s + x.pct, 0) !== 100) return void (err.textContent = 'Доли должны давать в сумме 100%.');
          db.mixes.push({ id: uid('m'), name, authorId: me().id, parts: p.sort((a, b) => b.pct - a.pct), likes: [], at: new Date().toISOString() });
          save(); closeModal(); toast('Микс опубликован'); cat.tab = 'mixes'; render();
        });
      });
    },
    likeMix({ id }) {
      const u = me(); if (!requireUser()) return;
      const m = db.mixes.find(x => x.id === id); if (!m) return;
      m.likes = m.likes.includes(u.id) ? m.likes.filter(x => x !== u.id) : [...m.likes, u.id];
      save(); render();
    },
    catTab({ tab }) { cat.tab = tab; cat.q = ''; if (location.hash !== '#/catalog') go('catalog'); else render(); },
    catFilter(ds) {
      if ('strength' in ds) cat.strength = ds.strength;
      if ('tag' in ds) cat.tag = ds.tag;
      render();
    },
    peopleTab({ tab }) { peopleTab = tab; render(); },
    toggleFriend({ id }) {
      const u = me(), p = userById(id); if (!u || !p) return;
      // В демо дружба взаимная сразу; на сервере здесь будет заявка в друзья.
      if (isFriend(u, p)) { u.friends = u.friends.filter(x => x !== id); p.friends = p.friends.filter(x => x !== u.id); toast(`${p.name} удалён из друзей`); }
      else { u.friends.push(id); if (!p.friends.includes(u.id)) p.friends.push(u.id); toast(`${p.name} теперь в друзьях`); }
      save(); render();
    },
    cycleTheme() {
      const order = ['auto', 'light', 'dark'], cur = prefs.get('theme', 'auto');
      const next = order[(order.indexOf(cur) + 1) % order.length];
      prefs.set('theme', next); applyLook(); render(); toast(`Тема: ${THEMES[next][0].toLowerCase()}`);
    },
    setTheme({ theme }) { prefs.set('theme', theme); applyLook(); render(); },
    setAccent({ accent }) { prefs.set('accent', accent); applyLook(); render(); },
    uploadAvatar() { const u = me(); pickAvatarFile(url => { u.avatar = url; save(); toast('Фото обновлено'); render(); }); },
    removeAvatar() { const u = me(); u.avatar = null; save(); render(); },
    logout() { db.session = null; save(); toast('Вы вышли из аккаунта'); go(''); },
    reset() { db = seed(); save(); toast('Демо-данные восстановлены'); go(''); },
    info({ key }) {
      const texts = {
        rules: ['Правила сервиса', 'Сервис предназначен для лиц старше 18 лет. Организатор отвечает за бронь в заведении. Запрещено приглашать людей без их согласия и рассылать рекламу.'],
        privacy: ['Конфиденциальность', 'Номер телефона нужен для входа и чтобы друзья могли пригласить вас. Полный номер видят только друзья и участники общих сборов. Мы не передаём данные третьим лицам.'],
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
  // render() перерисовывает текущую страницу без прокрутки наверх; route() — полный переход.
  function render() {
    const [page = '', arg] = location.hash.replace(/^#\/?/, '').split('/');
    const nav = { '': 'home', event: 'home', catalog: 'catalog', people: 'people', user: 'people', how: 'how', profile: 'profile', login: 'profile', register: 'profile' }[page] || '';
    renderChrome(nav);
    switch (page) {
      case 'event': pageEvent(arg); break;
      case 'catalog': pageCatalog(); break;
      case 'people': pagePeople(); break;
      case 'user': pageUser(arg); break;
      case 'how': pageHow(); break;
      case 'profile': pageProfile(); break;
      case 'login': pageAuth('login'); break;
      case 'register': pageAuth('register'); break;
      default: pageHome();
    }
  }
  function route() { closeModal(); render(); window.scrollTo(0, 0); checkReminders(); }
  window.addEventListener('hashchange', route);
  route();
})();
