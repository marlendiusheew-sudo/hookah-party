/* Hookah Party — клиентский шаблон.
   Все данные хранятся в localStorage (демо). При переходе на приложение
   функции load/save заменяются запросами к серверу, а отправка SMS — реальным
   провайдером (Firebase Phone Auth, Twilio, Nikita SMS и т.п.).
   Тексты интерфейса на двух языках: L('русский', 'English'). */
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

  // Режим: SERVER = true, если сайт открыт с нашего сервера (тогда данные и вход идут через API).
  let SERVER = false, CSRF = null;
  // Открыт ли сайт внутри iOS-приложения (оно добавляет метку HookahPartyApp к User-Agent).
  const IN_APP = location.protocol === 'hookah:' || /HookahPartyApp/.test(navigator.userAgent);

  // Настройки вида и языка живут только в этом браузере.
  const prefs = {
    get(k, d) { try { return localStorage.getItem('hp.' + k) ?? d; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('hp.' + k, v); } catch (e) { /* хранилище недоступно */ } }
  };

  // ================= Безопасность (клиентская часть) =================
  // Всё здесь — защита на стороне браузера. Когда появится сервер, те же правила нужно повторить на нём:
  // браузерные проверки можно обойти, серверные — нет.

  // Журнал событий безопасности (последние 100), виден в профиле → Настройки → Безопасность.
  const SEC_LOG = 'hp.sec.log';
  function secRead(key, d) { try { return JSON.parse(localStorage.getItem(key)) ?? d; } catch (e) { return d; } }
  function secWrite(key, v) { try { localStorage.setItem(key, JSON.stringify(v)); } catch (e) { /* хранилище недоступно */ } }
  function secLog(type, detail = '') {
    const log = secRead(SEC_LOG, []);
    log.unshift({ type, detail: String(detail).slice(0, 160), at: new Date().toISOString() });
    secWrite(SEC_LOG, log.slice(0, 100));
  }

  // Фильтр разметки: вырезает опасные теги, обработчики событий и ссылки javascript:.
  // Пользовательский текст до сюда доходит уже экранированным (esc), поэтому фильтр — второй рубеж защиты.
  const BAD_BLOCKS = /<\s*(script|iframe|object|embed|template|noscript|style)\b[\s\S]*?<\s*\/\s*\1\s*>/gi;
  const BAD_TAGS = /<\s*\/?\s*(script|iframe|object|embed|base|meta|link|frame|frameset|template|noscript|style)\b[^>]*>/gi;
  const BAD_ATTR = /\s(on[a-z]+|formaction|srcdoc)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;
  const BAD_URL = /(\s(?:href|src|action|xlink:href)\s*=\s*)(["'])\s*(?:javascript|vbscript|data:(?!image\/(?:png|jpe?g|webp|gif);))[^"']*\2/gi;
  let blockedCount = 0;
  function sanitizeHTML(html) {
    const src = String(html);
    if (!/[<]/.test(src)) return src;
    let hit = '';
    const cut = m => { hit ||= m.slice(0, 40); return ''; };
    const out = src.replace(BAD_BLOCKS, cut).replace(BAD_TAGS, cut)
      .replace(/<[a-zA-Z][^>]*>/g, tag => tag
        .replace(BAD_ATTR, m => { hit ||= m.trim().slice(0, 40); return ''; })
        .replace(BAD_URL, (m, a, q) => { hit ||= m.trim().slice(0, 40); return `${a}${q}#${q}`; }));
    if (hit && blockedCount++ < 20) { secLog('html_blocked', hit); console.warn('Hookah Party: заблокирован опасный фрагмент разметки', hit); }
    return out;
  }
  // Trusted Types (Chrome, Edge): браузер пропускает в разметку только то, что прошло через фильтр.
  // В остальных браузерах тот же фильтр встроен в установку innerHTML.
  (() => {
    try {
      if (window.trustedTypes?.createPolicy) {
        window.trustedTypes.createPolicy('default', {
          createHTML: sanitizeHTML,
          // Скрипт можно подключить только один: панель администратора с нашего сайта.
          createScriptURL: u => { if (/^admin\.js\?v=\d+$/.test(u) || u === 'sw.js') return u; secLog('html_blocked', 'script ' + String(u).slice(0, 40)); throw new TypeError('Скрипт запрещён'); }
        });
        return;
      }
      const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (d?.set) Object.defineProperty(Element.prototype, 'innerHTML', { ...d, set(v) { d.set.call(this, sanitizeHTML(v)); } });
    } catch (e) { /* политика уже создана или браузер не позволяет */ }
  })();
  document.addEventListener('securitypolicyviolation', e => secLog('csp', `${e.violatedDirective} ${e.blockedURI || ''}`.trim()));

  // Очистка ввода: невидимые и управляющие символы, «переворот» текста, лишние пробелы, длина.
  function clean(s, max = 500, multiline = false) {
    let t = String(s ?? '').normalize('NFC')
      .replace(/[​-‏‪-‮⁦-⁩﻿]/g, '')
      .replace(multiline ? /[\u0000-\u0009\u000B-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g, '');
    t = multiline ? t.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n') : t.replace(/\s+/g, ' ');
    return t.trim().slice(0, max);
  }
  const validName = s => /^[\p{L}\p{M}][\p{L}\p{M}\s'’.-]{1,39}$/u.test(s);
  const safeUrl = u => /^https?:\/\/[^\s"'<>]+\.[^\s"'<>]+$/i.test(String(u || '')) ? String(u) : '';
  const safeAvatar = u => /^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/.test(String(u || '')) && String(u).length < 400000 ? u : null;

  // Ограничение частоты для чувствительных действий (вход, SMS, регистрация) — хранится в браузере.
  function rateHit(key, max, windowMs, consume = true) {
    const all = secRead('hp.sec.rl', {}), now = Date.now();
    const list = (all[key] || []).filter(t => now - t < windowMs);
    if (list.length >= max) { all[key] = list; secWrite('hp.sec.rl', all); return { ok: false, wait: list[0] + windowMs - now }; }
    if (consume) list.push(now);
    all[key] = list; secWrite('hp.sec.rl', all);
    return { ok: true, left: max - list.length };
  }
  const SEC = {
    authPerHour: 17,          // попытки входа и отправки SMS с этого устройства за час
    failsBeforeLock: 5,       // неверных паролей подряд до блокировки номера
    lockMs: 5 * 60e3,         // блокировка на 5 минут
    smsPer10Min: 3,           // кодов на один номер за 10 минут
    codeTtlMs: 5 * 60e3,      // код из SMS действует 5 минут
    codeAttempts: 5,          // попыток ввести код
    accountsPerDevice: 3,     // аккаунтов, созданных с одного устройства (аналог «3 с одного IP»)
    sessionDays: 30           // сессия истекает через 30 дней
  };
  const waitText = ms => { const m = Math.ceil(ms / 60000); return m >= 60 ? L(`${Math.ceil(m / 60)} ч`, `${Math.ceil(m / 60)} h`) : L(`${m} мин`, `${m} min`); };

  // Пароли: PBKDF2-SHA256, 150 000 итераций, своя соль у каждого пользователя (Web Crypto).
  // На сервере вместо этого будет Argon2id.
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hasSubtle = () => !!(window.crypto?.subtle && window.isSecureContext !== false);
  async function pbkdf2(pass, salt) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
    return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 }, key, 256));
  }
  async function makePass(pass) {
    if (!hasSubtle()) return hashPass(pass);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return { alg: 'pbkdf2-sha256', it: 150000, salt: b64(salt), hash: await pbkdf2(pass, salt) };
  }
  // Сравнение без раннего выхода, чтобы время проверки не подсказывало совпадения.
  const sameStr = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
  async function checkPass(user, pass) {
    const rec = user.pass;
    if (typeof rec === 'string') {
      // Старый демо-хэш: при успешном входе сразу переводим на PBKDF2.
      if (!sameStr(rec, hashPass(pass))) return false;
      if (hasSubtle()) { user.pass = await makePass(pass); save(); }
      return true;
    }
    if (!rec?.salt || !hasSubtle()) return false;
    return sameStr(await pbkdf2(pass, unb64(rec.salt)), rec.hash);
  }
  // Надёжность пароля: 0 — слабый, 3 — надёжный.
  const COMMON = ['password', 'qwerty', '123456', '12345678', '123456789', 'qwerty123', '11111111', 'hookah', 'hookah123', 'parol', 'bishkek'];
  function passIssues(pass, phone = '') {
    const p = String(pass), low = p.toLowerCase();
    if (p.length < 8) return L('Пароль должен быть не короче 8 символов.', 'The password must be at least 8 characters.');
    if (!/\p{L}/u.test(p) || !/\d/.test(p)) return L('Добавьте в пароль и буквы, и цифры.', 'Use both letters and digits.');
    if (COMMON.some(c => low.includes(c))) return L('Этот пароль слишком простой, его легко подобрать.', 'This password is too common and easy to guess.');
    if (phone && digits(p).length >= 6 && digits(phone).includes(digits(p))) return L('Не используйте номер телефона как пароль.', 'Do not use your phone number as a password.');
    return '';
  }
  function passScore(p) {
    let s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[a-zа-яё]/.test(p) && /[A-ZА-ЯЁ]/.test(p)) s++;
    if (/\d/.test(p) && /[^\p{L}\d]/u.test(p)) s++;
    return Math.min(3, s);
  }

  // Защита от встраивания сайта в чужие страницы (на GitHub Pages нельзя задать заголовок frame-ancestors).
  if (window.top !== window.self && /(^|\.)github\.io$/.test(location.hostname)) {
    try { window.top.location = window.self.location.href; } catch (e) { document.documentElement.style.display = 'none'; }
  }

  // ---------- Язык ----------
  let lang = prefs.get('lang', 'ru') === 'en' ? 'en' : 'ru';
  const L = (ru, en) => lang === 'en' ? en : ru;
  const locale = () => lang === 'en' ? 'en-GB' : 'ru-RU';
  function plural(n, one, few, many) {
    const a = Math.abs(n) % 100, b = a % 10;
    if (a > 10 && a < 20) return many;
    if (b > 1 && b < 5) return few;
    if (b === 1) return one;
    return many;
  }
  // pl(3, ['сбор', 'сбора', 'сборов'], ['event', 'events'])
  const pl = (n, ru, en) => lang === 'en' ? (n === 1 ? en[0] : en[1]) : plural(n, ...ru);
  const DF = {};
  const df = (key, opts) => (DF[lang + key] ||= new Intl.DateTimeFormat(locale(), opts));
  const fDay = d => df('d', { day: 'numeric' }).format(d);
  const fMon = d => df('m', { month: 'short' }).format(d).replace('.', '');
  const fFull = d => df('f', { weekday: 'long', day: 'numeric', month: 'long' }).format(d);
  const fShort = d => df('s', { day: 'numeric', month: 'long' }).format(d);
  const fTime = d => df('t', { hour: '2-digit', minute: '2-digit', hour12: false }).format(d);
  const fMonthYear = d => { const s = df('my', { month: 'long', year: 'numeric' }).format(d).replace(' г.', ''); return s[0].toUpperCase() + s.slice(1); };
  const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;
  const money = n => new Intl.NumberFormat(locale()).format(Math.round(n)) + L(' сом', ' KGS');

  // ---------- Телефоны: Кыргызстан (+996) и Россия/Казахстан (+7) ----------
  function normPhone(s) {
    let d = digits(s);
    if (d.length === 10 && d[0] === '0') d = '996' + d.slice(1);
    else if (d.length === 9) d = '996' + d;
    else if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1);
    return d;
  }
  const validPhone = d => d.length >= 11 && d.length <= 15;
  function fmtPhone(s) {
    const d = normPhone(s);
    if (d.length === 12 && d.startsWith('996')) return `+996 ${d.slice(3, 6)} ${d.slice(6, 9)} ${d.slice(9)}`;
    if (d.length === 11 && d[0] === '7') return `+7 (${d.slice(1, 4)}) ${d.slice(4, 7)}-${d.slice(7, 9)}-${d.slice(9)}`;
    return '+' + d;
  }
  // Номер целиком видят только друзья и участники общих сборов.
  const maskedPhone = s => { const d = normPhone(s); return `+${d.startsWith('996') ? '996' : d[0]} ••• ••• ${d.slice(-3)}`; };
  function maskPhone(el) {
    el.addEventListener('input', () => {
      let d = digits(el.value);
      if (!d) { el.value = ''; return; }
      if (d[0] === '0') d = '996' + d.slice(1);
      if (d[0] === '8' && d.length > 1) d = '7' + d.slice(1);
      if (d.startsWith('996')) {
        const r = d.slice(3, 12);
        el.value = '+996' + (r ? ' ' + [r.slice(0, 3), r.slice(3, 6), r.slice(6, 9)].filter(Boolean).join(' ') : '');
        return;
      }
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

  const isPast = e => new Date(e.at).getTime() < Date.now() - 4 * 3600e3;
  function timeAgo(iso) {
    const m = (Date.now() - new Date(iso)) / 60000;
    if (m < 1) return L('только что', 'just now');
    if (m < 60) return L(`${Math.floor(m)} мин назад`, `${Math.floor(m)} min ago`);
    if (m < 1440) return L(`${Math.floor(m / 60)} ч назад`, `${Math.floor(m / 60)} h ago`);
    const d = Math.floor(m / 1440);
    return d < 7 ? L(`${d} ${plural(d, 'день', 'дня', 'дней')} назад`, `${d} ${d === 1 ? 'day' : 'days'} ago`) : fShort(new Date(iso));
  }
  function whenLabel(e) {
    const d = new Date(e.at), today = new Date(); today.setHours(0, 0, 0, 0);
    const diff = Math.round((new Date(d).setHours(0, 0, 0, 0) - today) / 864e5);
    const day = diff === 0 ? L('Сегодня', 'Today') : diff === 1 ? L('Завтра', 'Tomorrow') : cap(fFull(d));
    return `${day}, ${fTime(d)}`;
  }
  function countdown(iso) {
    const ms = new Date(iso) - Date.now();
    if (ms <= 0) return ms > -4 * 3600e3 ? L('идёт сейчас', 'happening now') : L('прошёл', 'finished');
    const m = Math.floor(ms / 60000), d = Math.floor(m / 1440), h = Math.floor(m % 1440 / 60), mm = m % 60;
    const H = n => pl(n, ['час', 'часа', 'часов'], ['hour', 'hours']), D = n => pl(n, ['день', 'дня', 'дней'], ['day', 'days']);
    if (d) return L('через ', 'in ') + `${d} ${D(d)}${h ? ` ${h} ${H(h)}` : ''}`;
    if (h) return L('через ', 'in ') + `${h} ${H(h)}${mm ? ` ${mm} ${L('мин', 'min')}` : ''}`;
    return L('через ', 'in ') + `${mm || 1} ${L('мин', 'min')}`;
  }

  const svg = (d, extra = '') => `<svg viewBox="0 0 24 24" aria-hidden="true" ${extra}>${d}</svg>`;
  const ICON = {
    pin: svg('<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>'),
    plus: svg('<path d="M12 5v14M5 12h14"/>'),
    check: svg('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),
    x: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
    heart: svg('<path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/>'),
    chat: svg('<path d="M5 5h14v10H10l-4 4v-4H5z"/>'),
    bell: svg('<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20.5h4"/>'),
    cal: svg('<rect x="4" y="5" width="16" height="15" rx="2"/><path d="M4 10h16M9 3v4M15 3v4"/>'),
    clock: svg('<circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 2"/>'),
    phone: svg('<path d="M6 3.5h3l1.5 4.5-2 1.5a11 11 0 0 0 6 6l1.5-2 4.5 1.5v3a2 2 0 0 1-2 2A16 16 0 0 1 4 5.5a2 2 0 0 1 2-2z"/>'),
    repeat: svg('<path d="M17 3l3 3-3 3M4 12V9a3 3 0 0 1 3-3h13M7 21l-3-3 3-3M20 12v3a3 3 0 0 1-3 3H4"/>'),
    edit: svg('<path d="M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4"/>'),
    wallet: svg('<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M16 12.5h2M3 9h18"/>'),
    users: svg('<circle cx="9" cy="9" r="3.5"/><path d="M2.5 20c.8-3.5 3.4-5 6.5-5s5.7 1.5 6.5 5M16 5.5a3.5 3.5 0 0 1 0 7M18 15c2 .6 3.2 2.2 3.5 5"/>'),
    sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
    moon: svg('<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>'),
    auto: svg('<circle cx="12" cy="12" r="8"/><path d="M12 4v16a8 8 0 0 0 0-16z" fill="currentColor"/>'),
    smoke: svg('<path d="M8 20c-3-3 2-5-1-8s2-5 0-8M14 20c-3-3 2-5-1-8s2-5 0-8"/>'),
    star: svg('<path d="M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 16.8l-5.2 2.8 1-5.8-4.3-4.1 5.9-.8z"/>'),
    ext: svg('<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>'),
    home: svg('<path d="M4 11l8-7 8 7M6 9.5V20h12V9.5M10 20v-5h4v5"/>'),
    hookah: svg('<path d="M9 4h6l-1.2 3h-3.6zM12 7v6M9.5 9.5h5M12 13c-3.2 0-5 2.2-5 4.4C7 19.4 9 20.5 12 20.5s5-1.1 5-3.1c0-2.2-1.8-4.4-5-4.4zM14.5 11c3 0 5.5 1.4 6 4.5"/>'),
    mail: svg('<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 8l9 6 9-6"/>'),
    list: svg('<path d="M4 6h16M4 12h16M4 18h10"/>'),
    shield: svg('<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/><path d="M9 12l2 2 4-4"/>'),
    tg: svg('<path d="M21 4.5L2.8 11.4c-.8.3-.8 1.4 0 1.7l4.6 1.6 1.8 5.4c.2.7 1.1.9 1.6.4l2.6-2.5 4.6 3.4c.6.4 1.4.1 1.6-.6L22.3 5.8c.2-.9-.6-1.6-1.3-1.3z"/><path d="M7.4 14.7L18 7.5l-8.2 8.8"/>'),
    wa: svg('<path d="M3.5 20.5l1.3-4.3A8.6 8.6 0 1 1 8 19.3z"/><path d="M9 8.3c-.4 2.6 3.5 6.6 6.4 6.3.6 0 1.2-.6 1.3-1.3l-1.9-1-1 .9c-1.1-.4-2.4-1.6-2.8-2.8l.9-1-1-1.9c-.7 0-1.4.4-1.9.8z"/>'),
    share: svg('<path d="M12 15V3.5M8 7l4-4 4 4M6 11H5v9.5h14V11h-1"/>'),
    link: svg('<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/>')
  };

  // ---------- Каталог ----------
  const TAGS = { холодок: 'cooling', фрукты: 'fruit', тропики: 'tropical', ягоды: 'berries', цитрус: 'citrus', кислое: 'sour', мята: 'mint', классика: 'classic', микс: 'mix', сладкое: 'sweet', напитки: 'drinks', бестабачное: 'tobacco-free' };
  const tagName = t => L(t, TAGS[t] || t);
  const CATALOG = {
    tobaccos: [
      { id: 'ds-supernova', brand: 'Darkside', flavor: 'Supernova', note: ['Ледяной холодок', 'Icy cooling'], strength: 7, tags: ['холодок'], color: '#4fa9cf', art: ['ice'] },
      { id: 'ds-bananapapa', brand: 'Darkside', flavor: 'Bananapapa', note: ['Спелый банан', 'Ripe banana'], strength: 7, tags: ['фрукты'], color: '#d8a92a', art: ['banana'] },
      { id: 'ds-fallingstar', brand: 'Darkside', flavor: 'Falling Star', note: ['Манго и маракуйя', 'Mango and passion fruit'], strength: 7, tags: ['тропики', 'фрукты'], color: '#e8892c', art: ['mango', 'passion'] },
      { id: 'mh-pinkman', brand: 'MustHave', flavor: 'Pinkman', note: ['Грейпфрут и малина', 'Grapefruit and raspberry'], strength: 6, tags: ['ягоды', 'цитрус'], color: '#d84a74', art: ['citrus', 'raspberry'] },
      { id: 'mh-raspberry', brand: 'MustHave', flavor: 'Raspberry', note: ['Малина', 'Raspberry'], strength: 6, tags: ['ягоды'], color: '#b52a52', art: ['raspberry'] },
      { id: 'bb-cherry', brand: 'Black Burn', flavor: 'Cherry Shock', note: ['Кислая вишня', 'Sour cherry'], strength: 8, tags: ['ягоды', 'кислое'], color: '#8a1d30', art: ['cherry'] },
      { id: 'el-grapefruit', brand: 'Element', flavor: 'Water · Grapefruit', note: ['Свежий грейпфрут', 'Fresh grapefruit'], strength: 5, tags: ['цитрус'], color: '#e4694b', art: ['citrus'] },
      { id: 'tg-canemint', brand: 'Tangiers', flavor: 'Cane Mint', note: ['Сладкая мята', 'Sweet mint'], strength: 9, tags: ['мята'], color: '#2f8f68', art: ['mint'] },
      { id: 'af-twoapples', brand: 'Al Fakher', flavor: 'Two Apples', note: ['Двойное яблоко с анисом', 'Double apple with anise'], strength: 3, tags: ['классика', 'фрукты'], color: '#78a832', art: ['apple', 'apple:green'] },
      { id: 'af-mint', brand: 'Al Fakher', flavor: 'Mint', note: ['Мята', 'Mint'], strength: 3, tags: ['мята', 'классика'], color: '#3ea87b', art: ['mint:2'] },
      { id: 'ad-love66', brand: 'Adalya', flavor: 'Love 66', note: ['Арбуз, дыня, маракуйя и мята', 'Watermelon, melon, passion fruit and mint'], strength: 4, tags: ['микс', 'фрукты'], color: '#c43e62', art: ['watermelon', 'mint:2'] },
      { id: 'fu-gummi', brand: 'Fumari', flavor: 'White Gummi Bear', note: ['Мармеладные мишки', 'Gummy bears'], strength: 4, tags: ['сладкое'], color: '#9d82cf', art: ['gummy', 'gummy:pink'] },
      { id: 'sb-bluemist', brand: 'Starbuzz', flavor: 'Blue Mist', note: ['Черника с мятой', 'Blueberry with mint'], strength: 4, tags: ['ягоды', 'мята'], color: '#4560c4', art: ['blueberry', 'mint:2'] },
      { id: 'se-watermelon', brand: 'Sebero', flavor: 'Watermelon', note: ['Сочный арбуз', 'Juicy watermelon'], strength: 6, tags: ['фрукты'], color: '#d63c4f', art: ['watermelon'] },
      { id: 'du-pear', brand: 'Duft', flavor: 'Pear', note: ['Спелая груша', 'Ripe pear'], strength: 5, tags: ['фрукты'], color: '#9fae38', art: ['pear'] },
      { id: 'od-cola', brand: 'Overdose', flavor: 'Cola', note: ['Кола', 'Cola'], strength: 7, tags: ['напитки'], color: '#6b3420', art: ['cola'] },
      { id: 'ch-icemint', brand: 'Chabacco', flavor: 'Ice Mint', note: ['Бестабачная смесь: мята со льдом', 'Tobacco-free blend: iced mint'], strength: 1, tags: ['бестабачное', 'мята'], color: '#4bb8b0', art: ['mint', 'ice'] }
    ],
    bowls: [
      { id: 'b-phunnel', name: 'Oblako Phunnel M', type: 'phunnel', note: ['Табак не проваливается в шахту, жар держится ровно', 'Tobacco stays out of the stem, heat stays even'] },
      { id: 'b-turka', name: 'Kong Turkish', type: 'turka', note: ['Классика с отверстиями на дне', 'Classic bowl with holes in the base'] },
      { id: 'b-killer', name: 'Cosmo Bowl Killer', type: 'killer', note: ['Глубокая чаша для плотной забивки', 'Deep bowl for dense packing'] },
      { id: 'b-harmony', name: 'HookahJohn Harmony', type: 'phunnel', note: ['Глина, мягкий прогрев', 'Clay, gentle heat-up'] },
      { id: 'b-fruit', name: ['Чаша на грейпфруте', 'Grapefruit bowl'], type: 'fruit', note: ['Половинка грейпфрута вместо чаши', 'Half a grapefruit instead of a bowl'] }
    ],
    gear: [
      { id: 'g-lotus', name: 'Kaloud Lotus I+', type: ['Калауд', 'Heat manager'], note: ['Контроль жара без фольги', 'Heat control without foil'] },
      { id: 'g-coal', name: ['Кокосовый уголь 25 мм', 'Coconut coals 25 mm'], type: ['Уголь', 'Coals'], note: ['72 кубика, разжиг 8–10 минут на плитке', '72 cubes, 8–10 minutes on a heater'] },
      { id: 'g-hose', name: ['Силиконовый шланг', 'Silicone hose'], type: ['Шланг', 'Hose'], note: ['Моется и не впитывает вкус', 'Washable, keeps no flavour'] },
      { id: 'g-mouth', name: ['Личный мундштук', 'Personal mouthpiece'], type: ['Мундштук', 'Mouthpiece'], note: ['Гигиена на общих сборах', 'Hygiene at group sessions'] },
      { id: 'g-tongs', name: ['Щипцы для угля', 'Coal tongs'], type: ['Инструмент', 'Tool'], note: ['Длина 20 см', '20 cm long'] },
      { id: 'g-stove', name: ['Плитка для угля', 'Coal heater'], type: ['Розжиг', 'Heater'], note: ['Электрическая, 800 Вт', 'Electric, 800 W'] }
    ]
  };
  const tr = v => Array.isArray(v) ? L(v[0], v[1]) : v;
  const BOWL_TYPE = { phunnel: ['Фанел', 'Phunnel'], turka: ['Турка', 'Turkish'], killer: ['Киллер', 'Killer'], fruit: ['На фрукте', 'Fruit bowl'] };
  const tobacco = id => CATALOG.tobaccos.find(t => t.id === id);
  const bowl = id => CATALOG.bowls.find(b => b.id === id);
  const ALL_TAGS = [...new Set(CATALOG.tobaccos.flatMap(t => t.tags))];
  const STRENGTH = { all: [['Любая', 'Any'], 0, 10], light: [['Лёгкие · 1–4', 'Light · 1–4'], 1, 4], mid: [['Средние · 5–6', 'Medium · 5–6'], 5, 6], strong: [['Крепкие · 7–10', 'Strong · 7–10'], 7, 10] };

  // ---------- Заведения на карте (данные OpenStreetMap, файл map-data.js) ----------
  const MAP = window.HP_MAP || { w: 1000, h: 600, layers: {}, labels: [], venues: [] };
  const VENUES = MAP.venues;
  const venueById = id => VENUES.find(v => v.id === id);
  const venueName = v => (lang === 'en' && v.nameEn) || v.name;
  const VTYPE = { lounge: ['Кальянная', 'Hookah lounge'], bar: ['Бар', 'Bar'], cafe: ['Кафе', 'Café'], restaurant: ['Ресторан', 'Restaurant'], shop: ['Магазин и прокат', 'Shop & rental'] };
  const DAYS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'];
  const DAY_NAMES = { ru: ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'], en: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] };
  // Разбор часов работы из OpenStreetMap: «Mo-Su 12:00-02:00», «Tu-Su 17:00-02:00», «17:00-06:00», «24/7».
  function parseHours(s) {
    s = String(s || '').trim();
    if (!s) return null;
    if (s === '24/7') return { always: true };
    const m = s.match(/^(?:([A-Z][a-z](?:-[A-Z][a-z])?(?:,[A-Z][a-z](?:-[A-Z][a-z])?)*)\s+)?(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/);
    if (!m) return { raw: s };
    let days = [0, 1, 2, 3, 4, 5, 6];
    if (m[1]) {
      days = [];
      for (const part of m[1].split(',')) {
        const [a, b] = part.split('-').map(x => DAYS.indexOf(x));
        if (b === undefined) days.push(a); else for (let i = a; ; i = (i + 1) % 7) { days.push(i); if (i === b) break; }
      }
    }
    return { days, from: +m[2] * 60 + +m[3], to: +m[4] * 60 + +m[5], daysGiven: !!m[1] };
  }
  function venueStatus(v, now = new Date()) {
    const h = parseHours(v.hours);
    if (!h) return { known: false, text: L('Часы работы не указаны', 'Opening hours unknown') };
    if (h.always) return { known: true, open: true, text: L('Круглосуточно', 'Open 24/7'), hours: L('Круглосуточно', '24/7') };
    if (h.raw) return { known: false, text: h.raw, hours: h.raw };
    const t = x => `${pad(Math.floor(x / 60) % 24)}:${pad(x % 60)}`;
    const dn = DAY_NAMES[lang];
    let daysText = L('Ежедневно', 'Daily');
    if (h.days.length < 7) daysText = h.days.length > 2 && h.days.every((d, i) => i === 0 || d === (h.days[i - 1] + 1) % 7) ? `${dn[h.days[0]]}–${dn[h.days[h.days.length - 1]]}` : h.days.map(d => dn[d]).join(', ');
    const hours = `${daysText}, ${t(h.from)}–${t(h.to)}`;
    const d = (now.getDay() + 6) % 7, prev = (d + 6) % 7, mins = now.getHours() * 60 + now.getMinutes();
    const overnight = h.to <= h.from;
    const open = overnight ? (h.days.includes(d) && mins >= h.from) || (h.days.includes(prev) && mins < h.to)
      : h.days.includes(d) && mins >= h.from && mins < h.to;
    return { known: true, open, hours, text: open ? L(`Открыто до ${t(h.to)}`, `Open until ${t(h.to)}`) : (h.days.includes(d) && mins < h.from ? L(`Закрыто, откроется в ${t(h.from)}`, `Closed, opens at ${t(h.from)}`) : L('Сейчас закрыто', 'Closed now')) };
  }
  const gmapsUrl = v => `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(`${v.name}, ${v.addr ? v.addr + ', ' : ''}Бишкек`)}`;
  const gisUrl = v => `https://2gis.kg/bishkek/search/${encodeURIComponent(v.name)}?m=${v.lon},${v.lat}/18`;
  const placeQuery = (venue, address) => [venue, address, 'Бишкек'].filter(Boolean).join(', ');

  // ---------- Хранилище (демо) ----------
  const KEY = 'hookahparty.v2';
  // PBKDF2-SHA256 от демо-пароля «hookah» (соль общая только у тестовых пользователей).
  const DEMO_PASS = { alg: 'pbkdf2-sha256', it: 150000, salt: 'aG9va2FoLXBhcnR5LWRlbW8tc2FsdC12MQ==', hash: 'ZwP6viAssMvtj69J3eu80BsrY0tOpQfbwK/XW8Zu6S8=' };
  function seed() {
    const day = 864e5, at = (d, h, m = 0) => { const x = new Date(Date.now() + d * day); x.setHours(h, m, 0, 0); return x.toISOString(); };
    const ago = mins => new Date(Date.now() - mins * 60000).toISOString();
    const u = (id, name, phone, extra = {}) => ({ id, name, phone, pass: { ...DEMO_PASS }, verified: true, avatar: null, favs: [], friends: [], favVenue: '', createdAt: ago(60 * 24 * 40), ...extra });
    const V = id => venueById(id) || { name: 'Hookah', addr: '' };
    const savor = V('n4270648990'), holy = V('n6360868686'), hydra = V('n12870025414');
    return {
      session: 'u1',
      users: [
        u('u1', 'Алекс', '996700000001', { favs: ['ds-supernova', 'mh-pinkman'], friends: ['u2', 'u3', 'u5'], favVenue: savor.name, role: 'admin' }),
        u('u2', 'Дина', '996700000002', { friends: ['u1', 'u3', 'u6'], favVenue: hydra.name, favs: ['ad-love66'] }),
        u('u3', 'Тимур', '996700000003', { friends: ['u1', 'u2', 'u4'], favVenue: holy.name, favs: ['tg-canemint', 'af-twoapples'] }),
        u('u4', 'Сабина', '996700000004', { friends: ['u3'], favs: ['fu-gummi'] }),
        u('u5', 'Руслан', '996700000005', { friends: ['u1'], favVenue: savor.name, favs: ['od-cola'] }),
        u('u6', 'Карина', '996700000006', { friends: ['u2'], favs: ['sb-bluemist'] })
      ],
      events: [
        {
          id: 'e1', title: 'Пятничный сбор', venue: savor.name, address: savor.addr, venueId: 'n4270648990', mapUrl: '',
          at: at(2, 20, 30), hostId: 'u1', createdAt: ago(60 * 26), desc: 'Забронирован диван у окна на 6 человек. Берём два кальяна, второй — на фанеле.',
          hookahs: 2, price: 1200, paid: { u1: true, u2: true },
          invites: [
            { userId: 'u2', status: 'going', at: ago(600) }, { userId: 'u3', status: 'going', at: ago(420) }, { userId: 'u4', status: 'pending' },
            { userId: 'u5', status: 'going', at: ago(95) }, { phone: '996555123456', status: 'pending' }
          ],
          picks: { u1: ['ds-supernova', 'mh-pinkman'], u2: ['ds-supernova', 'ad-love66'], u3: ['ds-supernova', 'mh-pinkman', 'tg-canemint'], u5: ['ds-bananapapa'] },
          bowls: { u1: 'b-phunnel', u2: 'b-phunnel', u3: 'b-killer' },
          comments: [
            { id: 'c1', userId: 'u3', text: 'Бронь на 20:30 подтвердили?', at: ago(180), reactions: { u1: '👍' } },
            { id: 'c2', userId: 'u1', text: 'Да, диван у окна наш до двух ночи. 🔥', at: ago(150), reactions: { u2: '🔥', u3: '👍', u5: '👍' } },
            { id: 'c3', userId: 'u2', text: 'Возьму свой мундштук и калауд 💨', at: ago(40), reactions: { u3: '❤️', u5: '😂' } }
          ],
          remind: {}, notified: {}
        },
        {
          id: 'e2', title: 'День рождения Тимура', venue: holy.name, address: holy.addr, venueId: 'n6360868686', mapUrl: '',
          at: at(6, 19), hostId: 'u3', createdAt: ago(60 * 20), desc: 'Отмечаем 25 лет. Подарок собираем вскладчину, детали у Сабины.',
          hookahs: 3, price: 1500, paid: { u3: true },
          invites: [{ userId: 'u1', status: 'pending' }, { userId: 'u4', status: 'going', at: ago(500) }, { userId: 'u6', status: 'going', at: ago(210) }],
          picks: { u3: ['af-twoapples', 'sb-bluemist'], u4: ['af-twoapples'], u6: ['fu-gummi', 'sb-bluemist', 'af-twoapples'] },
          bowls: { u3: 'b-turka' },
          comments: [{ id: 'c4', userId: 'u4', text: 'Торт беру на себя.', at: ago(300) }],
          remind: {}, notified: {}
        },
        {
          id: 'e3', title: 'После работы', venue: hydra.name, address: hydra.addr, venueId: 'n12870025414', mapUrl: '',
          at: at(-9, 21), hostId: 'u2', createdAt: ago(60 * 24 * 11), desc: '',
          hookahs: 1, price: 900, paid: { u1: true, u2: true, u6: true },
          invites: [{ userId: 'u1', status: 'going' }, { userId: 'u6', status: 'going' }],
          picks: { u1: ['bb-cherry'], u2: ['bb-cherry', 'el-grapefruit'], u6: ['el-grapefruit'] },
          bowls: { u2: 'b-fruit' }, comments: [], remind: {}, notified: {}
        }
      ],
      storiesSeeded: true,
      reviews: [
        { id: 'r1', tobaccoId: 'ds-supernova', userId: 'u3', rating: 5, text: 'Лучший холодок, добавляю в каждый микс по чуть-чуть.', at: ago(60 * 24 * 3) },
        { id: 'r2', tobaccoId: 'ds-supernova', userId: 'u2', rating: 4, text: 'Сильно холодит, больше 20% не кладу.', at: ago(60 * 24 * 8) },
        { id: 'r3', tobaccoId: 'mh-pinkman', userId: 'u1', rating: 5, text: 'Яркий и не приторный, держит вкус весь сеанс.', at: ago(60 * 24 * 5) },
        { id: 'r4', tobaccoId: 'af-twoapples', userId: 'u3', rating: 4, text: 'Классика. Лёгкий, подходит новичкам.', at: ago(60 * 24 * 12) },
        { id: 'r5', tobaccoId: 'tg-canemint', userId: 'u5', rating: 5, text: 'Крепкий, на любителя. Мята честная.', at: ago(60 * 24 * 2) },
        { id: 'r6', tobaccoId: 'od-cola', userId: 'u5', rating: 4, text: 'Похоже на колу, хорошо с мятой.', at: ago(60 * 24 * 6) },
        { id: 'r7', tobaccoId: 'fu-gummi', userId: 'u4', rating: 5, text: 'Сладкий, как мармелад.', at: ago(60 * 24 * 9) },
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
  // Примеры для «Истории»: прошедшие вечера в настоящих заведениях с рассказом организатора.
  function seedStories() {
    const day = 864e5, past = (d, h) => { const x = new Date(Date.now() - d * day); x.setHours(h, 0, 0, 0); return x.toISOString(); };
    const ago = mins => new Date(Date.now() - mins * 60000).toISOString();
    const V = id => venueById(id) || { name: 'Hookah', addr: '' };
    const ev = (id, title, vid, at, hostId, guests, picks, bowls, hookahs, price, story) => ({
      id, title, venue: V(vid).name, address: V(vid).addr, venueId: vid, mapUrl: '', at, hostId, createdAt: at, desc: '',
      hookahs, price, paid: Object.fromEntries([hostId, ...guests].map(g => [g, true])),
      invites: guests.map(g => ({ userId: g, status: 'going', at })), picks, bowls, comments: [], remind: {}, notified: {}, story
    });
    const nyAt = (() => { const y = new Date().getMonth() >= 11 ? new Date().getFullYear() : new Date().getFullYear() - 1; return new Date(y, 11, 30, 21).toISOString(); })();
    return {
      e3: {
        rating: 4, at: ago(60 * 24 * 8), fire: ['u1', 'u6'],
        text: 'Заскочили после работы на пару часов. Кислая вишня в чистом виде оказалась слишком резкой, кальянщик подмешал грейпфрут, и стало то что нужно.',
        highlights: ['Вишня + грейпфрут 50/50: забираем в миксы', 'Кальянщик Эрлан, просите его'],
        comments: [{ id: 'sc1', userId: 'u6', text: 'Тот самый грейпфрут спас вечер 😄', at: ago(60 * 24 * 8 - 30) }]
      },
      events: [
        ev('e4', 'Проводы лета', 'n4270648990', past(55, 20), 'u3', ['u1', 'u2', 'u5', 'u6'],
          { u3: ['mh-pinkman', 'el-grapefruit'], u1: ['mh-pinkman', 'ds-supernova'], u2: ['mh-pinkman'], u5: ['ds-supernova'], u6: ['el-grapefruit'] }, { u3: 'b-phunnel', u1: 'b-phunnel' }, 2, 1200,
          { rating: 5, at: past(54, 12), fire: ['u1', 'u2', 'u5', 'u6', 'u4'],
            text: 'Последний тёплый вечер на веранде. Взяли два кальяна на фанеле и просидели до двух ночи. «Ледяной грейпфрут» по нашему миксу зашёл всем, второй забили так же.',
            highlights: ['Pinkman + грейпфрут + капля Supernova — лучший микс лета', 'Веранда с видом на проспект, бронируйте заранее', 'Вышло по 480 сом с человека'],
            comments: [
              { id: 'sc2', userId: 'u1', text: 'Лучший вечер этого лета, без вариантов.', at: past(54, 13), reactions: { u2: '❤️', u3: '🔥', u6: '❤️' } },
              { id: 'sc3', userId: 'u5', text: 'Повторим в сентябре, пока не похолодало?', at: past(53, 18) },
              { id: 'sc4', userId: 'u6', text: 'Микс записала себе в избранное.', at: past(52, 10) }
            ] }),
        ev('e5', 'Футбол и кальян', 'n4724156811', past(30, 19), 'u5', ['u1', 'u3'],
          { u5: ['od-cola', 'tg-canemint'], u1: ['od-cola'], u3: ['tg-canemint'] }, { u5: 'b-killer' }, 1, 1400,
          { rating: 4, at: past(29, 11), fire: ['u1', 'u3'],
            text: 'Смотрели матч на большом экране. Попросили собрать «Мятную колу» 70/30, кальянщик сделал на киллере, держал почти два часа. Наши выиграли 2:1.',
            highlights: ['Cola 70% + Cane Mint 30%', 'Экран видно с любого дивана', 'Шумно во время матча, на разговоры лучше в другой день'],
            comments: [{ id: 'sc5', userId: 'u3', text: 'Cane Mint крепкий, с колой как раз смягчается.', at: past(29, 15) }] }),
        ev('e6', 'Девичник Сабины', 'n6360868686', past(20, 19), 'u4', ['u2', 'u6'],
          { u4: ['fu-gummi', 'ad-love66'], u2: ['ad-love66', 'sb-bluemist'], u6: ['sb-bluemist', 'fu-gummi'] }, { u4: 'b-fruit', u2: 'b-fruit' }, 2, 1500,
          { rating: 5, at: past(19, 13), fire: ['u2', 'u6', 'u3', 'u1'],
            text: 'Отмечали втроём. Первый кальян на грейпфруте с мармеладными мишками, второй — Blue Mist. Музыка не громкая, можно спокойно поговорить.',
            highlights: ['Чаша на грейпфруте — must have для праздника', 'Gummi Bear + Love 66 — сладко, но не приторно', 'Попросите столик у окна'],
            comments: [
              { id: 'sc6', userId: 'u2', text: 'Мишки на грейпфруте — это любовь 🍊🐻', at: past(19, 14), reactions: { u4: '❤️', u6: '😂' } },
              { id: 'sc7', userId: 'u3', text: 'Надо будет сводить туда парней.', at: past(18, 20) }
            ] }),
        ev('e7', 'Новогодний сбор', 'n5620015285', nyAt, 'u1', ['u2', 'u3', 'u4', 'u5', 'u6'],
          { u1: ['ds-supernova', 'mh-pinkman'], u2: ['ds-fallingstar'], u3: ['ds-supernova'], u4: ['fu-gummi'], u5: ['ds-supernova', 'od-cola'], u6: ['ds-fallingstar'] }, { u1: 'b-phunnel', u3: 'b-phunnel', u5: 'b-killer' }, 3, 1300,
          { rating: 5, at: new Date(new Date(nyAt).getTime() + 15 * 3600e3).toISOString(), fire: ['u2', 'u3', 'u4', 'u5', 'u6'],
            text: 'Собрались всей компанией за день до Нового года. Три кальяна, тайный Санта и бенгальские огни на улице. Supernova выбрали почти все — зимой холодок особенно в тему.',
            highlights: ['Тайный Санта: лимит 1000 сом', 'Supernova — фаворит вечера', 'Divan Lounge закрывает зал под компании от 6 человек'],
            comments: [
              { id: 'sc8', userId: 'u4', text: 'Мой подарок до сих пор стоит на полке!', at: new Date(new Date(nyAt).getTime() + 20 * 3600e3).toISOString() },
              { id: 'sc9', userId: 'u6', text: 'Делаем традицией.', at: new Date(new Date(nyAt).getTime() + 26 * 3600e3).toISOString() }
            ] })
      ]
    };
  }

  // Дополняет сохранённые данные полями, которых не было в прошлых версиях.
  function withStories(d) {
    const st = seedStories();
    const e3 = d.events.find(e => e.id === 'e3');
    if (e3 && !e3.story) e3.story = st.e3;
    for (const e of st.events) if (!d.events.some(x => x.id === e.id)) d.events.push(e);
    d.storiesSeeded = true;
    return d;
  }
  function migrate(d) {
    const s = seed();
    if (!d.storiesSeeded) withStories(d);
    d.users.forEach(u => { u.favs ||= []; u.friends ||= []; u.favVenue ??= ''; u.role ??= u.id === 'u1' ? 'admin' : 'user'; });
    d.events.forEach(e => {
      e.picks ||= {}; e.bowls ||= {}; e.comments ||= []; e.paid ||= {}; e.remind ||= {}; e.notified ||= {};
      e.hookahs ??= 1; e.price ??= 0; e.mapUrl ??= '';
    });
    d.reviews ||= s.reviews;
    d.mixes ||= s.mixes;
    return d;
  }
  // Загрузка с проверкой: отбрасываем опасные ключи (__proto__), чиним формат, проверяем аватары и ссылки.
  function load() {
    let raw = null;
    try { raw = localStorage.getItem(KEY); } catch (e) { return null; }
    if (!raw) return null;
    try {
      const d = JSON.parse(raw, (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v);
      if (!d || !Array.isArray(d.users) || !Array.isArray(d.events)) throw new Error('bad shape');
      d.users = d.users.filter(u => u && typeof u.id === 'string' && typeof u.phone === 'string');
      d.users.forEach(u => { u.avatar = safeAvatar(u.avatar); u.name = clean(u.name, 40) || '—'; });
      d.events = d.events.filter(e => e && typeof e.id === 'string' && Array.isArray(e.invites));
      d.events.forEach(e => { e.mapUrl = safeUrl(e.mapUrl); });
      if (d.session && d.sessionExp && Date.now() > d.sessionExp) { d.session = null; secLog('session_expired'); }
      if (d.session && !d.sessionExp) d.sessionExp = Date.now() + 30 * 864e5;
      return migrate(d);
    } catch (e) {
      secLog('storage_repaired', String(e.message || e));
      return null;
    }
  }
  function save() { if (SERVER) return; try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) { /* хранилище недоступно */ } }
  let db = load() || withStories(seed());

  // ---------- Сервер ----------
  // На GitHub Pages и с диска сайт работает в демо-режиме (данные в браузере).
  // Если рядом есть наш сервер (/api/health), вход, данные и все проверки идут через API.
  async function api(method, path, body) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (CSRF) headers['X-CSRF-Token'] = CSRF;
    const r = await fetch('/api' + path, { method, credentials: 'same-origin', headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    let data = null;
    try { data = await r.json(); } catch (e) { /* пустой ответ */ }
    if (!r.ok) { const err = new Error(data?.error || 'http_' + r.status); err.status = r.status; err.info = data; throw err; }
    return data;
  }
  const apiMsg = err => err?.info?.message ? L(err.info.message.ru, err.info.message.en)
    : navigator.onLine === false ? L('Нет соединения с интернетом.', 'No internet connection.') : L('Не удалось связаться с сервером. Попробуйте ещё раз.', 'Could not reach the server. Try again.');
  function applyData(d) { if (d && Array.isArray(d.users)) { db = d; CSRF = d.csrf || null; } }
  async function refresh() { try { applyData(await api('GET', '/bootstrap')); } catch (e) { /* покажем то, что есть */ } }
  // 'server' — есть сервер; 'static' — сайт без сервера (демо); 'offline' — сеть недоступна.
  async function detectServer() {
    if (location.protocol === 'file:') return 'static';
    try { const r = await fetch('/api/health', { cache: 'no-store' }); return r.ok && (await r.json())?.mode === 'server' ? 'server' : 'static'; } catch (e) { return 'offline'; }
  }
  // Одно действие пользователя: в демо меняем данные в браузере, на сервере — запрос и свежие данные в ответ.
  async function act(local, method, path, body) {
    if (!SERVER) { const r = local && local(); save(); return r; }
    try { const r = await api(method, path, body); if (r?.data) applyData(r.data); return r; }
    catch (e) {
      toast(apiMsg(e), 'err');
      if (e.status === 401 || e.info?.error === 'bad_csrf') { await refresh(); render(); }
      throw e;
    }
  }
  const quiet = () => {};
  // Номер для показа: полный — себе, друзьям и участникам общих сборов, иначе скрытый.
  const phoneShown = (viewer, p) => p?.phone ? (canSeePhone(viewer, p) ? fmtPhone(p.phone) : maskedPhone(p.phone)) : (p?.phoneMasked || '');

  // Напоминания хранятся в этом браузере в обоих режимах.
  const REM = 'hp.remind';
  const remindOn = (e, u) => !!secRead(REM, {})[u.id + ':' + e.id]?.on;
  const remindSet = (e, u, patch) => { const all = secRead(REM, {}), k = u.id + ':' + e.id; all[k] = { ...all[k], ...patch }; secWrite(REM, all); };

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
  const eventVenue = e => (e.venueId && venueById(e.venueId)) || VENUES.find(v => v.name === e.venue);

  // Подсчёт голосов: чем больше участников выбрали позицию, тем выше она в списке.
  function ranking(map, nameOf) {
    const c = {};
    for (const [userId, ids] of Object.entries(map || {})) for (const id of [].concat(ids)) (c[id] ||= []).push(userId);
    return Object.entries(c).map(([id, users]) => ({ id, users }))
      .sort((a, b) => b.users.length - a.users.length || nameOf(a.id).localeCompare(nameOf(b.id), 'ru'));
  }
  const tobaccoName = id => { const t = tobacco(id); return t ? `${t.brand} ${t.flavor}` : id; };
  const bowlName = id => tr(bowl(id)?.name) || id;
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
  function claimPhoneInvites(user) {
    for (const e of db.events) for (const i of e.invites) if (!i.userId && i.phone === user.phone) { i.userId = user.id; delete i.phone; }
  }

  // ---------- Картинки ----------
  const initials = n => String(n || '?').trim().split(/\s+/).slice(0, 2).map(w => w[0]).join('').toUpperCase();
  function avatar(u, size = '') {
    const cls = `av ${size ? 'av-' + size : ''}`;
    if (!u) return `<span class="${cls} av-ghost">?</span>`;
    if (safeAvatar(u.avatar)) return `<img class="${cls}" src="${u.avatar}" alt="${esc(u.name)}">`;
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
      ${window.HP_ART ? HP_ART.flavor(t) : `<span class="pack-smoke">${ICON.smoke}</span>`}
      <span class="pack-brand">${esc(t.brand)}</span><span class="pack-flavor">${esc(t.flavor)}</span></div>`;
  }
  // Миниатюра вкуса для списков: тот же рисунок, крупным планом.
  const flavorThumb = t => window.HP_ART && t ? `<span class="flavor-thumb" aria-hidden="true">${HP_ART.flavor(t, { thumb: true })}</span>` : `<span class="swatch" style="--pc:${t?.color}"></span>`;
  function bowlArt(type) {
    const shapes = {
      phunnel: '<path d="M14 26h36l-6 16H20z"/><path d="M28 26v-6h8v6" class="a2"/><rect x="29" y="42" width="6" height="10"/>',
      turka: '<path d="M12 24h40l-8 18H20z"/><circle cx="26" cy="33" r="1.6" class="a2"/><circle cx="32" cy="33" r="1.6" class="a2"/><circle cx="38" cy="33" r="1.6" class="a2"/><rect x="29" y="42" width="6" height="10"/>',
      killer: '<path d="M16 14h32l-5 30H21z"/><rect x="29" y="44" width="6" height="8"/>',
      fruit: '<path d="M10 28h44a22 18 0 0 1-44 0z"/><path d="M14 28h36" class="a2" stroke-width="3"/><rect x="29" y="44" width="6" height="8"/>'
    };
    return `<svg class="art-svg" viewBox="0 0 64 60" aria-hidden="true">${shapes[type] || shapes.turka}</svg>`;
  }
  function stars(v, cls = '') {
    const full = Math.round(v);
    return `<span class="stars ${cls}" aria-label="${L('Оценка', 'Rating')} ${v ? v.toFixed(1) : '—'} / 5">${[1, 2, 3, 4, 5].map(i => `<i class="${i <= full ? 'on' : ''}">★</i>`).join('')}</span>`;
  }
  function readAvatar(file) {
    return new Promise((resolve, reject) => {
      if (!file || !file.type.startsWith('image/')) return reject(new Error(L('Выберите файл изображения: JPG, PNG или WebP.', 'Choose an image file: JPG, PNG or WebP.')));
      const r = new FileReader();
      r.onerror = () => reject(new Error(L('Не удалось прочитать файл.', 'Could not read the file.')));
      r.onload = () => {
        const img = new Image();
        img.onerror = () => reject(new Error(L('Файл повреждён или это не изображение.', 'The file is damaged or not an image.')));
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
  let closeTimer = null;
  const reduceMotion = () => !window.matchMedia || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function openModal(title, body, onMount) {
    clearTimeout(closeTimer);
    modalRoot.innerHTML = `<div class="modal-backdrop"><div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}">
      <div class="modal-head"><h2>${esc(title)}</h2><button class="modal-x" type="button" data-action="closeModal" aria-label="${L('Закрыть', 'Close')}">×</button></div>
      ${body}</div></div>`;
    modalRoot.hidden = false;
    document.body.classList.add('locked');
    const m = $('.modal', modalRoot);
    onMount && onMount(m);
    const f = m.querySelector('input:not([type=checkbox]):not([type=radio]), textarea');
    f && f.focus();
  }
  // Закрытие с анимацией; если сразу открывается новое окно, оно просто заменит закрывающееся.
  function closeModal() {
    const node = modalRoot.firstElementChild;
    document.body.classList.remove('locked');
    if (!node || reduceMotion()) { modalRoot.innerHTML = ''; modalRoot.hidden = true; return; }
    node.classList.add('closing');
    clearTimeout(closeTimer);
    closeTimer = setTimeout(() => { if (node.parentNode === modalRoot) { modalRoot.innerHTML = ''; modalRoot.hidden = true; } }, 200);
  }
  modalRoot.addEventListener('mousedown', e => { if (e.target.classList.contains('modal-backdrop')) closeModal(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !modalRoot.hidden) closeModal();
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('[role=button][data-action]')) { e.preventDefault(); e.target.click(); }
  });
  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind; t.textContent = msg;
    $('#toasts').append(t);
    setTimeout(() => t.classList.add('out'), 3600);
    setTimeout(() => t.remove(), 4000);
  }

  // ---------- Оформление ----------
  const THEMES = { auto: [['Как в системе', 'System'], ICON.auto], light: [['Светлая', 'Light'], ICON.sun], dark: [['Тёмная', 'Dark'], ICON.moon] };
  const ACCENTS = { copper: ['Медь', 'Copper'], mint: ['Мята', 'Mint'], plum: ['Слива', 'Plum'], ember: ['Уголь', 'Ember'] };
  // Праздничное оформление включается само по датам: Хэллоуин 23.10–03.11, Новый год 22.12–10.01.
  const SEASONS = { auto: ['По датам', 'By date'], halloween: ['Хэллоуин', 'Halloween'], newyear: ['Новый год', 'New Year'], off: ['Выключить', 'Off'] };
  function seasonByDate(d = new Date()) {
    const m = d.getMonth() + 1, day = d.getDate();
    if ((m === 10 && day >= 23) || (m === 11 && day <= 3)) return 'halloween';
    if ((m === 12 && day >= 22) || (m === 1 && day <= 10)) return 'newyear';
    return '';
  }
  function activeSeason() {
    const p = prefs.get('season', 'auto');
    return p === 'auto' ? seasonByDate() : p === 'off' ? '' : (SEASONS[p] ? p : '');
  }
  function applyLook() {
    const root = document.documentElement, theme = prefs.get('theme', 'auto'), accent = prefs.get('accent', 'copper');
    if (theme === 'auto') delete root.dataset.theme; else root.dataset.theme = theme;
    root.dataset.accent = ACCENTS[accent] ? accent : 'copper';
    const season = activeSeason();
    if (season) root.dataset.season = season; else delete root.dataset.season;
    root.lang = lang;
    seasonFx(season);
    window.requestAnimationFrame?.(() => typeof syncScroll === 'function' && syncScroll());
  }

  // Летучие мыши на Хэллоуин и снег на Новый год. Слой не ловит клики и выключается при «уменьшить движение».
  let fxSeason = null, snow = null;
  const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  function seasonFx(season) {
    snow?.recolor();
    if (season === fxSeason) return;
    fxSeason = season;
    $('.season-fx')?.remove();
    snow?.stop();
    if (!season) return;
    const fx = document.createElement('div');
    fx.className = 'season-fx'; fx.setAttribute('aria-hidden', 'true');
    if (season === 'halloween') fx.innerHTML = [1, 2, 3].map(i => `<span class="bat bat-${i}"><i></i></span>`).join('');
    document.body.append(fx);
    if (season === 'newyear' && !reducedMotion()) startSnow();
  }
  function startSnow() {
    const c = document.createElement('canvas'), ctx = c.getContext && c.getContext('2d');
    if (!ctx) return;
    c.className = 'snow-canvas'; c.setAttribute('aria-hidden', 'true');
    document.body.append(c);
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let W = 0, H = 0, color = '#fff', raf = 0, flakes = [];
    const make = anywhere => ({ x: Math.random() * W, y: anywhere ? Math.random() * H : -8, r: .8 + Math.random() * 2.2, vy: .25 + Math.random() * .65, vx: -.15 + Math.random() * .3, ph: Math.random() * 6.3, o: .3 + Math.random() * .5 });
    const size = () => {
      W = window.innerWidth; H = window.innerHeight; c.width = W * dpr; c.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      color = getComputedStyle(document.documentElement).getPropertyValue('--snow').trim() || '#fff';
      const n = Math.round(Math.min(90, W * H / 15000));
      while (flakes.length < n) flakes.push(make(true));
      flakes.length = n;
    };
    const tick = () => {
      ctx.clearRect(0, 0, W, H); ctx.fillStyle = color;
      for (const f of flakes) {
        f.ph += .012; f.y += f.vy; f.x += f.vx + Math.sin(f.ph) * .3;
        if (f.y > H + 6 || f.x < -6 || f.x > W + 6) Object.assign(f, make(false));
        ctx.globalAlpha = f.o; ctx.beginPath(); ctx.arc(f.x, f.y, f.r, 0, 6.283); ctx.fill();
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(tick);
    };
    size(); window.addEventListener('resize', size); tick();
    snow = { stop() { cancelAnimationFrame(raf); window.removeEventListener('resize', size); c.remove(); snow = null; }, recolor() { setTimeout(size, 0); } };
  }
  function seasonRibbon() {
    const season = activeSeason(), el = $('#season-ribbon');
    if (!el) return;
    const key = season + new Date().getFullYear();
    if (!season || prefs.get('ribbonClosed', '') === key) { el.hidden = true; el.innerHTML = ''; return; }
    const icon = season === 'halloween'
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 7c-1-2.5 0-4 2-4.5"/><path d="M12 7c-4.5-1-8 2-8 6.5S7 21 12 21s8-3 8-7.5S16.5 6 12 7z"/><path d="M8.5 12l1.5 1.5L11.5 12M12.5 12l1.5 1.5 1.5-1.5M9 16.5c1 .8 2 1 3 1s2-.2 3-1"/></svg>'
      : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v20M3.3 7l17.4 10M3.3 17L20.7 7M9.5 3.5L12 6l2.5-2.5M9.5 20.5L12 18l2.5 2.5M2.7 9.6l3.4.9-.9 3.4M21.3 14.4l-3.4-.9.9-3.4M2.7 14.4l3.4-.9-.9-3.4M21.3 9.6l-3.4.9.9 3.4"/></svg>';
    const text = season === 'halloween'
      ? L('Хэллоуин в Hookah Party · тыквенное настроение до 3 ноября', 'Halloween at Hookah Party · pumpkin mood until 3 November')
      : L('С наступающим Новым годом! Праздничное оформление до 10 января', 'Happy New Year! Festive look until 10 January');
    el.hidden = false;
    el.innerHTML = `<div class="wrap ribbon-in"><span class="ribbon-ic">${icon}</span><span>${text}</span>
      <button class="ribbon-x" type="button" data-action="closeRibbon" data-key="${key}" aria-label="${L('Скрыть', 'Hide')}">×</button></div>`;
  }
  applyLook();

  // Живой фон: световые пятна сдвигаются при прокрутке, цвет меняется от верха страницы к низу.
  const ambient = document.createElement('div');
  ambient.className = 'ambient'; ambient.setAttribute('aria-hidden', 'true');
  ambient.innerHTML = '<i class="amb amb-1"></i><i class="amb amb-2"></i><i class="amb amb-3"></i><i class="amb amb-4"></i>';
  document.body.prepend(ambient);
  let scrollQueued = false;
  function syncScroll() {
    scrollQueued = false;
    const root = document.documentElement, max = Math.max(1, root.scrollHeight - window.innerHeight);
    root.style.setProperty('--sy', Math.round(window.scrollY));
    root.style.setProperty('--sp', Math.min(1, window.scrollY / max).toFixed(3));
  }
  window.addEventListener('scroll', () => { if (!scrollQueued) { scrollQueued = true; requestAnimationFrame(syncScroll); } }, { passive: true });
  window.addEventListener('resize', syncScroll);
  syncScroll();
  // Свечение под курсором: координаты мыши внутри карточки.
  const GLOW = '.tile-box, .ev-card, .cat-card, .vcard, .quote, .spot, .feature, .person-card, .step, .story-card, .venue-item, .next-card, .next-strip, .ev-hero, .stats-band, .cta-band, .history-stats > div, .notif, .feed-item, .map-card, .panel';
  let glowEl = null;
  document.addEventListener('pointermove', e => {
    if (e.pointerType !== 'mouse') return;
    const el = e.target.closest?.(GLOW);
    if (glowEl && glowEl !== el) { glowEl.style.removeProperty('--mx'); glowEl.style.removeProperty('--my'); }
    glowEl = el;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', (e.clientX - r.left) + 'px'); el.style.setProperty('--my', (e.clientY - r.top) + 'px');
  }, { passive: true });

  // ---------- Шапка, меню и подвал ----------
  function renderChrome(page) {
    const u = me(), theme = prefs.get('theme', 'auto'), themeName = tr(THEMES[theme][0]);
    const navItems = [['venues', L('Заведения', 'Venues')], ['catalog', L('Кальян', 'Hookah')], ['events', L('События', 'Events')], ['history', L('История', 'History')], ['people', L('Люди', 'People')]];
    if (isAdmin()) navItems.push(['admin', L('Админ', 'Admin')]);
    $('#nav').innerHTML = navItems.map(([k, t]) => `<a href="#/${k}" data-nav="${k}">${t}</a>`).join('');
    $('#nav').setAttribute('aria-label', L('Основное меню', 'Main menu'));
    $('#topbar-actions').innerHTML = `
      <div class="lang-switch" role="radiogroup" aria-label="${L('Язык', 'Language')}">
        <button role="radio" aria-checked="${lang === 'ru'}" class="${lang === 'ru' ? 'on' : ''}" data-action="setLang" data-lang="ru">RU</button>
        <button role="radio" aria-checked="${lang === 'en'}" class="${lang === 'en' ? 'on' : ''}" data-action="setLang" data-lang="en">EN</button></div>
      ${u ? bellHtml() : ''}
      <button class="icon-btn" type="button" data-action="cycleTheme" title="${L('Тема', 'Theme')}: ${themeName}" aria-label="${L('Тема', 'Theme')}: ${themeName}">${THEMES[theme][1]}</button>
      ${u ? `<button class="plus-btn" type="button" data-action="newEvent" title="${L('Создать сбор и пригласить друзей', 'Create an event and invite friends')}" aria-label="${L('Создать сбор', 'Create event')}">${ICON.plus}</button>
         <a class="me-link" href="#/profile" title="${L('Профиль', 'Profile')}">${avatar(u, 'sm')}</a>`
        : `<a class="btn btn-primary btn-sm" href="#/login">${L('Войти', 'Sign in')}</a>`}`;
    const tab = (k, icon, t) => `<a href="#/${k}" data-nav="${k}">${icon}${t}</a>`;
    $('#tabbar').innerHTML = tab('venues', ICON.home, L('Места', 'Places')) + tab('catalog', ICON.hookah, L('Кальян', 'Hookah'))
      + `<button type="button" class="tab-plus" data-action="newEvent" aria-label="${L('Создать сбор', 'Create event')}">${ICON.plus}</button>`
      + tab('events', ICON.mail, L('События', 'Events')) + tab('profile', svg('<circle cx="12" cy="9" r="4"/><path d="M5 20c1-4 4-5 7-5s6 1 7 5"/>'), L('Профиль', 'Profile'));
    $('#tabbar').setAttribute('aria-label', L('Нижнее меню', 'Bottom menu'));
    $('#footer').innerHTML = `
      <div class="wrap footer-in">
        <div class="footer-brand">
          <a class="brand" href="#/"><span class="brand-word">HOOKAH<span>PARTY</span></span></a>
          <p>${L('Кальянные Бишкека на одной карте, приглашения друзьям и общий выбор табака.', 'Bishkek hookah lounges on one map, invitations for friends and a shared tobacco pick.')}</p>
        </div>
        <div class="footer-col"><h4>${L('Сервис', 'Service')}</h4>
          <a href="#/venues">${L('Заведения', 'Venues')}</a><a href="#/catalog">${L('Каталог табаков', 'Tobacco catalogue')}</a>
          <a href="#/catalog" data-action="catTab" data-tab="mixes">${L('Миксы', 'Mixes')}</a><a href="#/events">${L('События', 'Events')}</a><a href="#/history">${L('История', 'History')}</a><a href="#/notifications">${L('Уведомления', 'Notifications')}</a>
          <a href="#/people">${L('Люди', 'People')}</a><a href="#/how">${L('Как это работает', 'How it works')}</a></div>
        <div class="footer-col"><h4>${L('Помощь', 'Help')}</h4>
          <a href="#/terms">${L('Правила сервиса', 'Terms of use')}</a>
          <a href="#/privacy">${L('Конфиденциальность', 'Privacy')}</a>
          <a href="#/" data-action="info" data-key="venues">${L('Заведениям', 'For venues')}</a>
          <a href="#/" data-action="info" data-key="faq">${L('Вопросы и ответы', 'FAQ')}</a>
          ${IN_APP ? '' : `<a href="#/" data-action="installApp">${L('Установить приложение', 'Install the app')}</a>`}</div>
        <div class="footer-col"><h4>${L('Контакты', 'Contacts')}</h4>
          <span class="mono">hello@hookahparty.app</span><span class="mono">+996 700 000 000</span>
          <span>Telegram: <span class="mono">@hookahparty</span></span><span class="muted">${L('Ежедневно 12:00–02:00', 'Daily 12:00–02:00')}</span></div>
      </div>
      <div class="wrap footer-bottom">
        <span>© 2026 Hookah Party</span><span class="age">18+</span>
        <span>${L('Курение вредит вашему здоровью. Сервис предназначен только для совершеннолетних.', 'Smoking harms your health. This service is for adults only.')}</span>
        <span>${L('Карта', 'Map')}: <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">© OpenStreetMap</a></span>
      </div>`;
    $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === page));
    seasonRibbon();
  }

  // ---------- Вкладки ----------
  // Одни и те же вкладки в событиях, каталоге, у людей и в профиле. Последняя открытая запоминается.
  const tab = {
    home: prefs.get('tab.home', 'upcoming'), cat: prefs.get('tab.cat', 'tobaccos'),
    people: prefs.get('tab.people', 'friends'), profile: prefs.get('tab.profile', 'about'), history: prefs.get('tab.history', 'all'), notif: 'all'
  };
  const tabKeys = {};
  let tabDir = null;
  function uTabs(name, items) {
    tabKeys[name] = items.map(t => t.key);
    if (!tabKeys[name].includes(tab[name])) tab[name] = tabKeys[name][0];
    return `<div class="utabs-wrap"><div class="utabs" role="tablist" data-tabs="${name}">${items.map(t => {
      const on = t.key === tab[name];
      return `<button role="tab" type="button" id="tab-${name}-${t.key}" aria-selected="${on}" tabindex="${on ? 0 : -1}" class="${on ? 'active' : ''}" data-action="switchTab" data-tabs="${name}" data-tab="${t.key}">${t.label}${t.count ? `<span class="cnt ${t.alert ? 'alert' : ''}">${t.count}</span>` : ''}</button>`;
    }).join('')}<span class="utabs-ink" aria-hidden="true"></span></div></div>`;
  }
  function tabPanel(name, html) {
    const anim = tabDir && tabDir.name === name ? `in-${tabDir.dir}` : '';
    if (anim) tabDir = null;
    return `<div class="tab-panel ${anim}" role="tabpanel" aria-labelledby="tab-${name}-${tab[name]}" data-swipe="${name}">${html}</div>`;
  }
  function inkTo(bar, from) {
    const ink = bar.querySelector('.utabs-ink'), a = bar.querySelector('[role=tab].active');
    if (!ink || !a) return;
    const set = b => { ink.style.transform = `translateX(${b.l}px)`; ink.style.width = b.w + 'px'; ink.dataset.l = b.l; };
    ink.style.transition = 'none';
    set(from || { l: a.offsetLeft, w: a.offsetWidth });
    void ink.offsetWidth;
    ink.style.transition = '';
    if (from) set({ l: a.offsetLeft, w: a.offsetWidth });
    const left = a.offsetLeft - 24, right = a.offsetLeft + a.offsetWidth + 24;
    if (left < bar.scrollLeft) bar.scrollLeft = left; else if (right > bar.scrollLeft + bar.clientWidth) bar.scrollLeft = right - bar.clientWidth;
  }
  const inkAll = () => $$('.utabs').forEach(b => inkTo(b));
  window.addEventListener('resize', inkAll);
  document.fonts?.ready.then(inkAll);
  function switchTo(name, key) {
    if (!key || tab[name] === key) return;
    const keys = tabKeys[name] || [], ink = $(`.utabs[data-tabs="${name}"] .utabs-ink`);
    const from = ink ? { l: +ink.dataset.l || 0, w: ink.offsetWidth } : null;
    tabDir = { name, dir: keys.indexOf(key) > keys.indexOf(tab[name]) ? 'next' : 'prev' };
    tab[name] = key; prefs.set('tab.' + name, key);
    if (name === 'cat') cat.q = '';
    if (name === 'home') homeQ = '';
    render();
    const nb = $(`.utabs[data-tabs="${name}"]`);
    if (nb && from) inkTo(nb, from);
    // Если вкладки прилипли к шапке, показываем новую вкладку с начала.
    const wrap = nb?.parentElement;
    if (wrap) {
      const top = wrap.getBoundingClientRect().top + window.scrollY - $('.topbar').offsetHeight - 1;
      if (window.scrollY > top) window.scrollTo(0, top);
    }
  }
  // Свайп влево-вправо по содержимому переключает вкладки на телефоне.
  let swipe = null;
  document.addEventListener('touchstart', e => {
    const p = e.target.closest?.('[data-swipe]');
    if (!p || e.touches.length > 1 || e.target.closest('input, textarea, select, .utabs, .cal, .map')) { swipe = null; return; }
    swipe = { name: p.dataset.swipe, x: e.touches[0].clientX, y: e.touches[0].clientY, t: Date.now() };
  }, { passive: true });
  document.addEventListener('touchend', e => {
    if (!swipe) return;
    const t = e.changedTouches[0], dx = t.clientX - swipe.x, dy = t.clientY - swipe.y, s = swipe;
    swipe = null;
    if (Math.abs(dx) < 60 || Math.abs(dx) < Math.abs(dy) * 1.6 || Date.now() - s.t > 700) return;
    const keys = tabKeys[s.name] || [], i = keys.indexOf(tab[s.name]);
    switchTo(s.name, keys[i + (dx < 0 ? 1 : -1)]);
  }, { passive: true });
  document.addEventListener('keydown', e => {
    const b = e.target.closest?.('.utabs [role=tab]');
    if (!b || !['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
    const name = b.dataset.tabs, keys = tabKeys[name], i = keys.indexOf(tab[name]);
    switchTo(name, keys[i + (e.key === 'ArrowRight' ? 1 : -1)]);
    $(`.utabs[data-tabs="${name}"] [role=tab].active`)?.focus();
  });

  function emptyState(title, text, action = '') {
    return `<div class="empty-state">
      <svg class="empty-art" viewBox="0 0 120 96" aria-hidden="true">
        <path class="es-smoke" d="M66 6c6 4-3 9 3 13s-3 9 2 13" /><path class="es-smoke" d="M54 10c5 3-2 7 2 10" />
        <path d="M44 34h32l-5 10H49z" /><path d="M58 44h4v18h-4z" /><path d="M50 50h20" />
        <path d="M60 62c-14 0-21 8-21 15 0 6 6 10 21 10s21-4 21-10c0-7-7-15-21-15z" /><path d="M64 54c10 0 18 3 22 10l6 4" />
      </svg><h3>${title}</h3><p>${text}</p>${action}</div>`;
  }

  // ---------- Карта ----------
  // Своя минималистичная карта: подложка из OpenStreetMap в SVG, точки заведений, масштаб и перетаскивание.
  function mapHtml(id, cls = '') {
    const lay = MAP.layers, g = (c, k) => `<g class="${c}">${(lay[k] || []).map(d => `<path d="${d}"/>`).join('')}</g>`;
    return `<div class="map ${cls}" id="${id}" data-map>
      <svg class="map-svg" viewBox="0 0 ${MAP.w} ${MAP.h}" role="img" aria-label="${L('Карта кальянных Бишкека', 'Map of Bishkek hookah lounges')}">
        <defs>${['main', 'dim', 'sel'].map(k => `<linearGradient id="pg-${k}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="pg-${k}-a"/><stop offset="1" class="pg-${k}-b"/></linearGradient>`).join('')}</defs>
        <rect class="m-bg" x="-3000" y="-3000" width="${MAP.w + 6000}" height="${MAP.h + 6000}"/>
        ${g('m-park', 'park')}${g('m-water', 'water')}${g('m-tert', 'tertiary')}${g('m-sec', 'secondary')}${g('m-pri', 'primary')}
        <g class="m-labels">${MAP.labels.map(l => `<text data-x="${l.x}" data-y="${l.y}" data-a="${l.a}" text-anchor="middle">${esc(l.t)}</text>`).join('')}</g>
        <g class="m-pins">${VENUES.map(v => {
          const st = venueStatus(v);
          return `<g class="m-pin ${st.known ? (st.open ? 'is-open' : 'is-closed') : 'is-unknown'}" data-vid="${v.id}" data-x="${v.x}" data-y="${v.y}" tabindex="0" role="button" aria-label="${esc(venueName(v))}. ${esc(st.text)}">
            <circle class="m-pin-hit" cy="-24" r="22"/>
            <ellipse class="m-pin-shadow" rx="8" ry="3"/>
            ${st.open ? '<circle class="m-pin-pulse" cy="-27" r="17"/>' : ''}
            <g class="m-pin-shape">
              <path class="m-pin-body" d="M0 0C-2.5-6.5-17-15-17-27a17 17 0 0 1 34 0C17-15 2.5-6.5 0 0z"/>
              <circle class="m-pin-ring" cy="-27" r="11.5"/>
              <path class="m-pin-glyph" transform="translate(-8.64 -35.64) scale(.72)" d="M9 4h6l-1.2 3h-3.6zM12 7v6M9.5 9.5h5M12 13c-3.2 0-5 2.2-5 4.4C7 19.4 9 20.5 12 20.5s5-1.1 5-3.1c0-2.2-1.8-4.4-5-4.4zM14.5 11c3 0 5.5 1.4 6 4.5"/>
              <circle class="m-pin-status" cx="12" cy="-39" r="4.8"/>
            </g>
          </g>`;
        }).join('')}</g>
      </svg>
      <div class="map-ctl">
        <button type="button" data-mz="in" aria-label="${L('Приблизить', 'Zoom in')}">+</button>
        <button type="button" data-mz="out" aria-label="${L('Отдалить', 'Zoom out')}">−</button>
        <button type="button" data-mz="fit" aria-label="${L('Показать все места', 'Show all places')}" title="${L('Показать все места', 'Show all places')}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg></button>
      </div>
      <div class="map-names" aria-hidden="true">${VENUES.map(v => {
        const st = venueStatus(v);
        return `<span class="map-name" data-vid="${v.id}"><i class="${st.known ? (st.open ? 'v-open' : 'v-closed') : ''}"></i>${esc(venueName(v))}</span>`;
      }).join('')}</div>
      <div class="map-tip" hidden></div>
      <div class="map-card" hidden></div>
      <div class="map-hint" hidden>${L('Чтобы приблизить, зажмите Ctrl (⌘) и крутите колесо', 'Hold Ctrl (⌘) and scroll to zoom')}</div>
      <div class="map-legend" aria-hidden="true"><span><i class="lg-open"></i>${L('Открыто', 'Open')}</span><span><i class="lg-closed"></i>${L('Закрыто', 'Closed')}</span><span><i class="lg-unknown"></i>${L('Часы не указаны', 'Hours unknown')}</span></div>
      <a class="map-attr" href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">© OpenStreetMap</a>
    </div>`;
  }
  const maps = {};
  let mapSel = null;
  function venueCardHtml(v) {
    const st = venueStatus(v);
    return `<button class="map-card-x" type="button" data-mclose aria-label="${L('Закрыть', 'Close')}">×</button>
      <span class="cat-brand">${tr(VTYPE[v.type] || VTYPE.bar)}</span>
      <h3>${esc(venueName(v))}</h3>
      <ul class="vinfo">
        <li class="${st.known ? (st.open ? 'v-open' : 'v-closed') : ''}">${ICON.clock}<span><b>${esc(st.text)}</b>${st.hours && st.hours !== st.text ? `<small>${esc(st.hours)}</small>` : ''}</span></li>
        <li>${ICON.pin}<span>${v.addr ? esc(v.addr) : L('Адрес не указан', 'Address not listed')}</span></li>
        ${v.phone ? `<li>${ICON.phone}<span class="mono">${esc(fmtPhone(v.phone))}</span></li>` : ''}
      </ul>
      <div class="map-links">
        <a class="maplink ml-google" href="${gmapsUrl(v)}" target="_blank" rel="noopener noreferrer"><span class="ml-ic" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 22s-7-6.6-7-12a7 7 0 0 1 14 0c0 5.4-7 12-7 12z"/><circle cx="12" cy="10" r="2.6"/></svg></span>Google ${L('Карты', 'Maps')}</a>
        <a class="maplink ml-2gis" href="${gisUrl(v)}" target="_blank" rel="noopener noreferrer"><span class="ml-ic" aria-hidden="true">2</span>2ГИС</a>
      </div>
      <button class="btn btn-primary btn-sm" type="button" data-action="gatherHere" data-vid="${v.id}">${ICON.plus}${L('Собрать друзей здесь', 'Gather friends here')}</button>`;
  }
  function initMap(id, { onSelect } = {}) {
    const el = $('#' + id); if (!el) return;
    const sv = $('svg', el), tip = $('.map-tip', el), card = $('.map-card', el), hint = $('.map-hint', el);
    const pins = $$('.m-pin', el), labels = $$('.m-labels text', el);
    const xs = VENUES.map(v => v.x), ys = VENUES.map(v => v.y);
    const box = VENUES.length ? { x0: Math.min(...xs), x1: Math.max(...xs), y0: Math.min(...ys), y1: Math.max(...ys) } : { x0: 0, x1: MAP.w, y0: 0, y1: MAP.h };
    const st = { vb: { x: 0, y: 0, w: MAP.w, h: MAP.h }, sel: null };
    const aspect = () => el.clientHeight / Math.max(el.clientWidth, 1);
    const unit = () => st.vb.w / Math.max(el.clientWidth, 1); // единиц карты на пиксель
    function clamp() {
      const v = st.vb, a = aspect(), cx = v.x + v.w / 2, cy = v.y + v.h / 2;
      v.w = Math.max(60, Math.min(v.w, MAP.w * 2.2)); v.h = v.w * a;
      v.x = cx - v.w / 2; v.y = cy - v.h / 2;
      const mx = MAP.w * .6, my = MAP.h * .6;
      v.x = Math.max(-mx, Math.min(v.x, MAP.w + mx - v.w)); v.y = Math.max(-my, Math.min(v.y, MAP.h + my - v.h));
    }
    function apply() {
      if (el.clientWidth < 10 || el.clientHeight < 10) return; // карта ещё не на экране
      clamp();
      const v = st.vb, s = unit();
      sv.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`);
      pins.forEach(p => p.setAttribute('transform', `translate(${p.dataset.x} ${p.dataset.y}) scale(${s})`));
      labels.forEach(t => t.setAttribute('transform', `translate(${t.dataset.x} ${t.dataset.y}) rotate(${t.dataset.a}) scale(${s})`));
      el.classList.toggle('show-labels', s < 1.1);
      layoutNames();
      place();
    }
    // Подписи у меток: справа или слева от точки, без наложений друг на друга и на метки.
    const names = $$('.map-name', el);
    function layoutNames() {
      const W = el.clientWidth, H = el.clientHeight, taken = [];
      const pts = VENUES.map(v => ({ v, p: toScreen(v.x, v.y) })).filter(o => o.p[0] > -20 && o.p[0] < W + 20 && o.p[1] > -10 && o.p[1] < H + 50);
      pts.forEach(o => taken.push([o.p[0] - 17, o.p[1] - 46, 34, 46]));
      const hit = r => taken.some(t => r[0] < t[0] + t[2] && r[0] + r[2] > t[0] && r[1] < t[1] + t[3] && r[1] + r[3] > t[1]);
      const order = [...pts].sort((a, b) => (b.v.id === st.sel) - (a.v.id === st.sel) || (venueStatus(b.v).open ? 1 : 0) - (venueStatus(a.v).open ? 1 : 0));
      const shown = new Set();
      for (const o of order) {
        const n = names.find(x => x.dataset.vid === o.v.id);
        const nw = n.offsetWidth || 100, nh = n.offsetHeight || 24, [x, y] = o.p;
        const cands = [[x + 20, y - 38], [x - 20 - nw, y - 38], [x - nw / 2, y + 6], [x - nw / 2, y - 76]];
        const spot = cands.find(([cx, cy]) => cx > 4 && cy > 4 && cx + nw < W - 52 && cy + nh < H - 40 && !hit([cx - 3, cy - 3, nw + 6, nh + 6]));
        if (spot && o.v.id !== st.sel) { n.style.transform = `translate(${spot[0]}px, ${spot[1]}px)`; taken.push([spot[0] - 3, spot[1] - 3, nw + 6, nh + 6]); shown.add(o.v.id); }
      }
      names.forEach(n => n.classList.toggle('on', shown.has(n.dataset.vid)));
    }
    el.addEventListener('click', e => { const n = e.target.closest('.map-name'); if (n) select(n.dataset.vid); });
    function fit() {
      if (el.clientWidth < 10 || el.clientHeight < 10) return;
      // Сначала примерный масштаб, затем запас под высоту меток и подписи справа.
      const a = aspect(), cw = Math.max(el.clientWidth, 1);
      let w = Math.max(box.x1 - box.x0, (box.y1 - box.y0) / a, 200) * 1.25;
      for (let i = 0; i < 2; i++) {
        const u = w / cw, x0 = box.x0 - 40 * u, x1 = box.x1 + 150 * u, y0 = box.y0 - 70 * u, y1 = box.y1 + 46 * u;
        w = Math.max(x1 - x0, (y1 - y0) / a);
        st.vb.w = w; st.vb.h = w * a; st.vb.x = (x0 + x1) / 2 - w / 2; st.vb.y = (y0 + y1) / 2 - st.vb.h / 2;
      }
      apply();
    }
    const toScreen = (x, y) => [(x - st.vb.x) / st.vb.w * el.clientWidth, (y - st.vb.y) / st.vb.h * el.clientHeight];
    function zoomAt(f, sx = el.clientWidth / 2, sy = el.clientHeight / 2) {
      st.touched = true;
      const v = st.vb, mx = v.x + sx / el.clientWidth * v.w, my = v.y + sy / el.clientHeight * v.h;
      v.w /= f; v.h = v.w * aspect();
      v.x = mx - sx / el.clientWidth * v.w; v.y = my - sy / el.clientHeight * v.h;
      apply();
    }
    function place() {
      if (!st.sel) return;
      const v = venueById(st.sel); if (!v) return;
      const [x, y] = toScreen(v.x, v.y);
      if (el.clientWidth < 560) { card.style.left = card.style.top = ''; return; }
      const cw = card.offsetWidth, ch = card.offsetHeight;
      let left = x - cw / 2, top = y - ch - 34;
      if (top < 10) top = y + 14;
      left = Math.max(10, Math.min(left, el.clientWidth - cw - 10)); top = Math.max(10, Math.min(top, el.clientHeight - ch - 10));
      card.style.left = left + 'px'; card.style.top = top + 'px';
    }
    function select(vid, { center = false } = {}) {
      st.sel = vid; mapSel = vid;
      pins.forEach(p => p.classList.toggle('sel', p.dataset.vid === vid));
      if (!vid) { card.hidden = true; onSelect && onSelect(null); return; }
      const v = venueById(vid);
      card.innerHTML = venueCardHtml(v); card.hidden = false;
      $(`.m-pin[data-vid="${vid}"]`, el)?.parentNode.appendChild($(`.m-pin[data-vid="${vid}"]`, el));
      if (center) {
        if (st.vb.w > 320) st.vb.w = 320;
        st.vb.h = st.vb.w * aspect(); st.vb.x = v.x - st.vb.w / 2; st.vb.y = v.y - st.vb.h * .62;
      }
      apply();
      onSelect && onSelect(vid);
    }
    // Мышь и пальцы: перетаскивание одним указателем, масштаб двумя.
    const ptrs = new Map();
    let drag = null, moved = 0, pinch = null;
    el.addEventListener('pointerdown', e => {
      if (e.target.closest('.map-card, .map-ctl, .map-attr')) return;
      el.setPointerCapture?.(e.pointerId);
      ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      moved = 0;
      if (ptrs.size === 1) drag = { x: e.clientX, y: e.clientY, vx: st.vb.x, vy: st.vb.y, target: e.target };
      if (ptrs.size === 2) { const [a, b] = [...ptrs.values()]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), w: st.vb.w }; drag = null; }
    });
    el.addEventListener('pointermove', e => {
      if (!ptrs.has(e.pointerId)) {
        const pin = e.target.closest?.('.m-pin');
        if (pin && e.pointerType === 'mouse') showTip(pin); else tip.hidden = true;
        return;
      }
      ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pinch && ptrs.size === 2) {
        const [a, b] = [...ptrs.values()], r = el.getBoundingClientRect();
        const f = Math.hypot(a.x - b.x, a.y - b.y) / pinch.d, target = pinch.w / f;
        zoomAt(st.vb.w / target, (a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top);
        moved = 99; return;
      }
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      moved = Math.max(moved, Math.hypot(dx, dy));
      if (moved > 4) { el.classList.add('dragging'); tip.hidden = true; st.touched = true; }
      st.vb.x = drag.vx - dx * unit(); st.vb.y = drag.vy - dy * unit(); apply();
    });
    const up = e => {
      if (!ptrs.has(e.pointerId)) return;
      ptrs.delete(e.pointerId);
      if (ptrs.size < 2) pinch = null;
      if (drag && moved <= 4 && e.type === 'pointerup') {
        const pin = drag.target.closest?.('.m-pin');
        if (pin) select(pin.dataset.vid); else if (st.sel) select(null);
      }
      if (!ptrs.size) { drag = null; el.classList.remove('dragging'); }
    };
    el.addEventListener('pointerup', up); el.addEventListener('pointercancel', up);
    el.addEventListener('pointerleave', e => { if (e.pointerType === 'mouse' && !ptrs.size) tip.hidden = true; });
    let hintT;
    el.addEventListener('wheel', e => {
      if (!(e.ctrlKey || e.metaKey)) { hint.hidden = false; clearTimeout(hintT); hintT = setTimeout(() => { hint.hidden = true; }, 1400); return; }
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * .0025), e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });
    el.addEventListener('click', e => {
      const b = e.target.closest('[data-mz]');
      if (b) { if (b.dataset.mz === 'fit') { st.touched = false; fit(); } else zoomAt(b.dataset.mz === 'in' ? 1.6 : 1 / 1.6); return; }
      if (e.target.closest('[data-mclose]')) select(null);
    });
    el.addEventListener('keydown', e => {
      const pin = e.target.closest?.('.m-pin');
      if (pin && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); select(pin.dataset.vid, { center: true }); }
      if (e.key === 'Escape' && st.sel) select(null);
    });
    el.addEventListener('focusin', e => { const pin = e.target.closest?.('.m-pin'); if (pin) showTip(pin); });
    function showTip(pin) {
      const v = venueById(pin.dataset.vid), s = venueStatus(v);
      tip.innerHTML = `<b>${esc(venueName(v))}</b><span class="${s.known ? (s.open ? 'v-open' : 'v-closed') : ''}">${esc(s.text)}</span>`;
      tip.hidden = false;
      const [x, y] = toScreen(v.x, v.y);
      tip.style.left = Math.max(8, Math.min(x - tip.offsetWidth / 2, el.clientWidth - tip.offsetWidth - 8)) + 'px';
      tip.style.top = Math.max(8, y - 34 - tip.offsetHeight - 6) + 'px';
    }
    // Пока карту не двигали, при смене размера вписываем все места заново.
    const onResize = () => { if (!st.touched) fit(); else { const cy = st.vb.y + st.vb.h / 2; st.vb.h = st.vb.w * aspect(); st.vb.y = cy - st.vb.h / 2; apply(); } };
    if (window.ResizeObserver) new ResizeObserver(onResize).observe(el); else window.addEventListener('resize', onResize);
    fit();
    maps[id] = { select, fit };
    return maps[id];
  }

  // ---------- Плитки и главная ----------
  const tileArt = {
    venues: `<svg class="tile-art art-house" viewBox="0 0 64 64" aria-hidden="true">
      <path class="t-smoke" d="M45 9c2 1.5-1 3 1 4.5s-1 3 .5 4.5"/><path d="M42 21v-7h5v11"/>
      <path d="M9 31 32 12l23 19"/><path d="M15 26.5V54h34V26.5"/>
      <rect class="t-win" x="20" y="32" width="8" height="7" rx="1.5"/><rect class="t-win" x="36" y="32" width="8" height="7" rx="1.5"/>
      <path d="M28 54V44h8v10"/></svg>`,
    hookah: `<svg class="tile-art art-hookah" viewBox="0 0 64 64" aria-hidden="true">
      <path class="t-smoke" d="M34 3c3 2-1 4 1 6s-1 4 1 6"/><path class="t-smoke t-smoke2" d="M29 6c2 1.5-1 3 .8 4.5"/>
      <circle class="t-coal" cx="32" cy="16.5" r="2"/>
      <path d="M24 19h16l-3 6H27z"/><path d="M32 25v14"/><path d="M26 30h12"/>
      <path d="M32 39c-8.5 0-13 6-13 11.5C19 55 24 58 32 58s13-3 13-7.5C45 45 40.5 39 32 39z"/>
      <path d="M38 34c7 0 12.5 3 15 10l1.5 6"/><path d="M53 50.5l3 1.5"/></svg>`,
    events: `<svg class="tile-art art-mail" viewBox="0 0 64 64" aria-hidden="true">
      <g class="t-letter"><rect x="16" y="14" width="32" height="30" rx="2"/><path d="M22 22h20M22 28h14"/></g>
      <path class="t-env" d="M8 26l24 15 24-15v26a3 3 0 0 1-3 3H11a3 3 0 0 1-3-3z"/>
      <path d="M8 26l24 15 24-15"/><path d="M8 52l18-13M56 52 38 39"/></svg>`
  };
  function tilesHtml() {
    const t = (k, href, label, sub) => `<a class="tile" href="${href}" aria-label="${label}. ${sub}">
      <span class="tile-box">${tileArt[k]}<span class="tile-text"><span class="tile-label">${label}</span><span class="tile-sub">${sub}</span></span></span></a>`;
    return `<nav class="tiles" aria-label="${L('Разделы', 'Sections')}">
      ${t('venues', '#/venues', L('Заведения', 'Venues'), L(`${VENUES.length} мест в Бишкеке`, `${VENUES.length} places in Bishkek`))}
      ${t('hookah', '#/catalog', L('Кальян', 'Hookah'), L('Табаки, миксы, чаши', 'Tobacco, mixes, bowls'))}
      ${t('events', '#/events', L('События', 'Events'), L('Сборы и приглашения', 'Meet-ups and invitations'))}
    </nav>`;
  }

  // Нижняя часть главной: цифры, куда пойти, бренды, табак недели, шаги, отзывы, вопросы.
  function homeExtras(u) {
    const openNow = VENUES.filter(v => venueStatus(v).open);
    const ranked = [...VENUES].sort((a, b) => {
      const sa = venueStatus(a), sb = venueStatus(b);
      return (sb.open ? 2 : sb.known ? 1 : 0) - (sa.open ? 2 : sa.known ? 1 : 0) || venueName(a).localeCompare(venueName(b));
    });
    const top = [...CATALOG.tobaccos].sort((a, b) => ratingOf(b.id).avg - ratingOf(a.id).avg || ratingOf(b.id).n - ratingOf(a.id).n)[0];
    const topR = ratingOf(top.id), topQuote = reviewsFor(top.id).find(r => r.text);
    const mixes = [...db.mixes].sort((a, b) => b.likes.length - a.likes.length).slice(0, 3);
    const quotes = [...db.reviews].filter(r => r.text && r.rating >= 4).sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 3);
    const brands = [...new Set(CATALOG.tobaccos.map(t => t.brand))];
    const stat = (n, label) => `<div class="stat-big"><b>${n}</b><span>${label}</span></div>`;
    const faq = [
      [['Это платно?', 'Is it free?'], ['Нет. Создавать сборы, приглашать друзей и пользоваться картой можно бесплатно.', 'Yes. Creating events, inviting friends and using the map are free.']],
      [['Нужно ли скачивать приложение?', 'Do I need to install an app?'], ['Нет, сайт работает в браузере телефона. Мобильное приложение сейчас в разработке.', 'No, the site works in your phone’s browser. A mobile app is in development.']],
      [['Как позвать друга, которого нет в сервисе?', 'How do I invite a friend who is not on the service?'], ['Введите его номер в поле приглашения. Сбор появится у него сразу после регистрации с этим номером.', 'Enter their number in the invite field. The event appears for them as soon as they sign up with that number.']],
      [['Откуда данные о заведениях?', 'Where does the venue data come from?'], ['Из OpenStreetMap, открытой карты, которую заполняют сами пользователи. Часы работы могут устареть, поэтому перед походом проверьте их в 2ГИС или Google Картах.', 'From OpenStreetMap, an open map filled in by its users. Opening hours may be out of date, so check them in 2GIS or Google Maps before you go.']],
      [['Есть ли что-то без никотина?', 'Is there anything nicotine-free?'], ['Да, в каталоге есть бестабачные смеси. Включите фильтр «бестабачное».', 'Yes, the catalogue has tobacco-free blends. Use the “tobacco-free” filter.']],
      [['Кто видит мой номер телефона?', 'Who can see my phone number?'], ['Полностью — только друзья и участники общих сборов. Остальные видят последние три цифры.', 'Only friends and people from shared events see it in full. Everyone else sees the last three digits.']]
    ];
    return `
      <section class="stats-band" aria-label="${L('Hookah Party в цифрах', 'Hookah Party in numbers')}">
        ${stat(VENUES.length, L('заведений на карте', 'venues on the map'))}
        ${stat(openNow.length, L('открыто прямо сейчас', 'open right now'))}
        ${stat(CATALOG.tobaccos.length, L('табаков в каталоге', 'tobaccos in the catalogue'))}
        ${stat(db.mixes.length, L('миксов от сообщества', 'community mixes'))}
      </section>

      <section class="section">
        <div class="section-head"><div><h2>${L('Куда пойти сегодня', 'Where to go tonight')}</h2><p class="muted">${L('Сначала открытые, затем остальные', 'Open places first, then the rest')}</p></div>
          <div class="scroller-ctl"><button class="icon-btn" type="button" data-scroll="-1" aria-label="${L('Назад', 'Back')}">‹</button><button class="icon-btn" type="button" data-scroll="1" aria-label="${L('Вперёд', 'Forward')}">›</button></div></div>
        <div class="scroller" id="venue-scroller">${ranked.map(v => {
          const st = venueStatus(v);
          return `<button type="button" class="vcard" data-action="showVenue" data-vid="${v.id}">
            <span class="vcard-top"><span class="vcard-ic">${ICON.pin}</span><span class="pill ${st.known ? (st.open ? 'pill-going' : 'pill-declined') : 'pill-pending'}">${st.known ? (st.open ? L('Открыто', 'Open') : L('Закрыто', 'Closed')) : L('Нет часов', 'No hours')}</span></span>
            <b>${esc(venueName(v))}</b>
            <small>${tr(VTYPE[v.type] || VTYPE.bar)}</small>
            <small class="vcard-addr">${v.addr ? esc(v.addr) : L('Адрес не указан', 'Address not listed')}</small>
            <small class="vcard-hours">${esc(st.hours || st.text)}</small>
          </button>`;
        }).join('')}</div>
      </section>

      <section class="marquee" aria-label="${L('Бренды в каталоге', 'Brands in the catalogue')}"><div class="marquee-track">
        ${[...brands, ...brands].map((b, i) => `<span ${i >= brands.length ? 'aria-hidden="true"' : ''}>${esc(b)}</span>`).join('')}
      </div></section>

      <section class="duo">
        <article class="spot">
          <span class="eyebrow">${L('Табак недели', 'Tobacco of the week')}</span>
          <div class="spot-body">${packArt(top, 'lg')}
            <div class="spot-text"><h2>${esc(top.brand)} ${esc(top.flavor)}</h2><p class="muted">${esc(tr(top.note))}</p>
              <div class="rating-line">${stars(topR.avg, 'lg')}<small>${topR.avg.toFixed(1)} · ${topR.n} ${pl(topR.n, ['отзыв', 'отзыва', 'отзывов'], ['review', 'reviews'])}</small></div>
              ${topQuote ? `<blockquote>«${esc(topQuote.text)}»<cite>${esc(userById(topQuote.userId)?.name || '')}</cite></blockquote>` : ''}
              <div><button class="btn btn-sm" type="button" data-action="tobacco" data-id="${top.id}">${L('Подробнее и отзывы', 'Details and reviews')}</button></div></div></div>
        </article>
        <article class="spot">
          <div class="section-head"><span class="eyebrow">${L('Популярные миксы', 'Popular mixes')}</span><a class="link-btn" href="#/catalog" data-action="catTab" data-tab="mixes">${L('Все миксы', 'All mixes')} →</a></div>
          <ul class="mix-list">${mixes.map((m, i) => `<li>
            <span class="mix-rank mono">${i + 1}</span>
            <div><b>${esc(m.name)}</b><div class="mix-bar">${m.parts.map(p => `<span style="flex:${p.pct};--pc:${tobacco(p.id)?.color || 'gray'}"></span>`).join('')}</div>
              <small class="muted">${m.parts.map(p => `${esc(tobacco(p.id)?.flavor || '')} ${p.pct}%`).join(' · ')}</small></div>
            <span class="mix-likes">${ICON.heart}${m.likes.length}</span></li>`).join('')}</ul>
        </article>
      </section>

      <section class="section">
        <div class="section-head"><h2>${L('Как это работает', 'How it works')}</h2></div>
        ${stepsHtml()}
      </section>

      ${quotes.length ? `<section class="section">
        <div class="section-head"><h2>${L('Что говорят о табаках', 'What people say about tobacco')}</h2><a class="link-btn" href="#/catalog">${L('Каталог', 'Catalogue')} →</a></div>
        <div class="quotes">${quotes.map(r => {
          const p = userById(r.userId), t = tobacco(r.tobaccoId);
          return `<figure class="quote"><span class="quote-mark" aria-hidden="true">“</span><blockquote>${esc(r.text)}</blockquote>
            <figcaption>${avatar(p, 'sm')}<span><b>${esc(p?.name || '—')}</b><small>${esc(t.brand)} ${esc(t.flavor)} · ${stars(r.rating)}</small></span></figcaption></figure>`;
        }).join('')}</div>
      </section>` : ''}

      <section class="faq-wrap">
        <div><span class="eyebrow">FAQ</span><h2>${L('Частые вопросы', 'Frequently asked questions')}</h2>
          <p class="muted">${L('Не нашли ответ? Напишите нам в Telegram', 'Didn’t find an answer? Message us on Telegram')} <span class="mono">@hookahparty</span>.</p></div>
        <div class="faq">${faq.map(([q, a]) => `<details><summary>${tr(q)}<span class="faq-ic" aria-hidden="true"></span></summary><p>${tr(a)}</p></details>`).join('')}</div>
      </section>

      <section class="cta-band"><div><h2>${u ? L('Пятница уже скоро', 'Friday is coming') : L('Готовы к первому сбору?', 'Ready for your first meet-up?')}</h2>
        <p>${u ? L('Выберите место на карте и позовите друзей за минуту.', 'Pick a place on the map and invite friends in a minute.') : L('Регистрация занимает минуту: имя, номер и код из SMS.', 'Signing up takes a minute: name, number and an SMS code.')}</p></div>
        ${u ? `<button class="btn btn-primary" type="button" data-action="newEvent">${ICON.plus}${L('Создать сбор', 'Create event')}</button>` : `<a class="btn btn-primary" href="#/register">${L('Создать аккаунт', 'Create account')}</a>`}
      </section>`;
  }

  function pageHome() {
    const u = me();
    const next = u && db.events.filter(e => !isPast(e) && goingIds(e).includes(u.id)).sort((a, b) => new Date(a.at) - new Date(b.at))[0];
    const invites = u ? db.events.filter(e => !isPast(e) && myInvite(e, u)?.status === 'pending').length : 0;
    const openNow = VENUES.filter(v => venueStatus(v).open).length;
    const tips = INTRO_TIPS();
    view.innerHTML = `
      ${tilesHtml()}
      ${next ? `<a class="next-strip" href="#/event/${next.id}"><span class="soon-dot"></span><span><b>${esc(next.title)}</b> · <span data-countdown="${next.at}">${countdown(next.at)}</span> · ${esc(next.venue)}</span><span class="next-go">${L('Открыть', 'Open')} →</span></a>`
        : invites ? `<a class="next-strip" href="#/events" data-action="openInvites"><span class="soon-dot"></span><span>${L(`Вас зовут на ${invites} ${plural(invites, 'сбор', 'сбора', 'сборов')}`, `You have ${invites} new ${invites === 1 ? 'invitation' : 'invitations'}`)}</span><span class="next-go">${L('Посмотреть', 'View')} →</span></a>` : ''}
      <section class="intro">
        <div class="intro-text">
          <span class="eyebrow">Hookah Party</span>
          <h1>${u ? L(`Рады видеть вас снова, ${esc(u.name)}!`, `Good to see you again, ${esc(u.name)}!`) : L('Добро пожаловать в Hookah Party!', 'Welcome to Hookah Party!')}</h1>
          <p class="lead">${L('Здесь собираются те, кто любит кальян и хорошую компанию. Найдите место в Бишкеке, позовите друзей и решите вместе, что курить, без переписки в десяти чатах.',
            'A place for people who love hookah and good company. Find a lounge in Bishkek, invite your friends and decide together what to smoke, without juggling ten group chats.')}</p>
          ${u ? `<div class="hero-cta"><button class="btn btn-primary" type="button" data-action="newEvent">${ICON.plus}${L('Собрать друзей', 'Gather friends')}</button><a class="btn" href="#/venues">${L('Выбрать место', 'Pick a place')}</a></div>`
            : `<div class="hero-cta"><a class="btn btn-primary" href="#/register">${L('Зарегистрироваться', 'Sign up')}</a><a class="btn" href="#/login">${L('У меня есть аккаунт', 'I have an account')}</a></div>`}
        </div>
        <div class="intro-icons">
          <div class="ii-row" role="tablist" aria-label="${L('Что умеет Hookah Party', 'What Hookah Party does')}">
            ${tips.map((t, i) => `<button class="ii-btn" type="button" role="tab" id="ii-tab-${i}" aria-selected="false" aria-controls="ii-panel" data-ii="${i}" title="${t.h}">${t.icon}<span class="ii-label">${t.short}</span></button>`).join('')}
          </div>
          <div class="ii-panel" id="ii-panel" role="tabpanel" aria-live="polite"><p class="ii-hint">${L('Нажмите на значок, чтобы узнать подробнее', 'Tap an icon to learn more')}</p></div>
        </div>
      </section>
      <section class="section map-section">
        <div class="section-head"><div><h2>${L('Кальянные Бишкека', 'Hookah lounges in Bishkek')}</h2>
          <p class="muted">${L(`${VENUES.length} ${plural(VENUES.length, 'место', 'места', 'мест')} на карте · сейчас открыто ${openNow}`, `${VENUES.length} places on the map · ${openNow} open now`)}</p></div>
          <a class="btn btn-sm" href="#/venues">${ICON.list}${L('Все заведения списком', 'All venues as a list')}</a></div>
        ${mapHtml('home-map')}
        <p class="map-note">${L('Данные о заведениях взяты из OpenStreetMap и могут устареть. Перед походом проверьте часы работы в 2ГИС или Google Картах.', 'Venue data comes from OpenStreetMap and may be out of date. Check opening hours in 2GIS or Google Maps before you go.')}</p>
      </section>
      ${homeExtras(u)}`;
    initMap('home-map');
    initIntroIcons();
    const sc = $('#venue-scroller');
    $$('[data-scroll]').forEach(b => b.addEventListener('click', () => sc.scrollBy({ left: +b.dataset.scroll * sc.clientWidth * .8, behavior: 'smooth' })));
  }

  // Значки рядом с приветствием: описание открывается по нажатию, без лишнего текста на экране.
  const INTRO_TIPS = () => [
    { icon: ICON.home, short: L('Места', 'Places'), h: L('Кальянные на карте', 'Lounges on the map'), p: L('Адреса, часы работы и что открыто прямо сейчас. Один клик, и место открыто в Google Картах или 2ГИС.', 'Addresses, opening hours and what is open right now. One click opens the place in Google Maps or 2GIS.'), go: '#/venues' },
    { icon: ICON.mail, short: L('Приглашения', 'Invites'), h: L('Приглашения по номеру', 'Invitations by phone'), p: L('Позовите друзей по номеру телефона. Они ответят «Иду» или «Не смогу» в одно касание.', 'Invite friends by phone number. They reply “Going” or “Can’t make it” in one tap.'), go: '#/events' },
    { icon: ICON.hookah, short: L('Табак', 'Tobacco'), h: L('Общий выбор табака', 'A shared tobacco pick'), p: L('Каждый отмечает любимые вкусы и чашу. Популярное поднимается наверх, кальянщик получает готовый список.', 'Everyone marks their favourite flavours and bowl. Popular picks rise to the top, and the hookah master gets a ready list.'), go: '#/catalog' },
    { icon: ICON.wallet, short: L('Счёт', 'Bill'), h: L('Счёт поровну', 'Split the bill'), p: L('Сервис сам посчитает, сколько с каждого, и напомнит о встрече за час.', 'The service works out each person’s share and reminds you an hour before.'), go: '#/how' }
  ];
  function initIntroIcons() {
    const box = $('.intro-icons'); if (!box) return;
    const tips = INTRO_TIPS(), panel = $('#ii-panel', box), btns = $$('.ii-btn', box);
    let open = -1;
    const show = i => {
      open = open === i ? -1 : i;
      btns.forEach((b, k) => { b.classList.toggle('on', k === open); b.setAttribute('aria-selected', String(k === open)); });
      const t = tips[open];
      panel.innerHTML = t ? `<div class="ii-card" aria-labelledby="ii-tab-${open}"><span class="ii-card-ic">${t.icon}</span><div><b>${t.h}</b><p>${t.p}</p><a class="link-btn" href="${t.go}">${L('Подробнее', 'Learn more')} →</a></div></div>`
        : `<p class="ii-hint">${L('Нажмите на значок, чтобы узнать подробнее', 'Tap an icon to learn more')}</p>`;
    };
    btns.forEach((b, i) => {
      b.addEventListener('click', () => show(i));
      b.addEventListener('keydown', e => { if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); const j = (i + (e.key === 'ArrowRight' ? 1 : btns.length - 1)) % btns.length; btns[j].focus(); show(j); } });
    });
  }

  function pageVenues() {
    view.innerHTML = `
      <section class="section"><span class="eyebrow">${L('Заведения', 'Venues')}</span><h1>${L('Кальянные Бишкека', 'Hookah lounges in Bishkek')}</h1>
        <p class="muted">${L('Нажмите на точку или на место в списке, чтобы увидеть адрес, часы работы и ссылки на карты.', 'Tap a pin or a place in the list to see its address, opening hours and map links.')}</p></section>
      <div class="venues-layout">
        ${mapHtml('venues-map', 'map-tall')}
        <aside class="venue-side">
          <div class="panel-tools"><input class="input" id="v-q" type="search" placeholder="${L('Название или улица', 'Name or street')}" aria-label="${L('Поиск заведений', 'Search venues')}" value="${esc(venueQ)}">
            <button class="chip-btn ${venueOpenOnly ? 'on' : ''}" type="button" data-action="venueOpen" aria-pressed="${venueOpenOnly}">${L('Открыто сейчас', 'Open now')}</button></div>
          <ul class="venue-list" id="v-list"></ul>
          <p class="map-note">${L('Данные: OpenStreetMap. Нашли ошибку или нет вашего заведения? Напишите нам, добавим.', 'Data: OpenStreetMap. Spotted a mistake or missing a venue? Write to us and we will add it.')}</p>
        </aside>
      </div>`;
    const drawList = () => {
      const q = venueQ.trim().toLowerCase();
      const list = VENUES.filter(v => (!q || `${v.name} ${v.nameEn || ''} ${v.addr}`.toLowerCase().includes(q)) && (!venueOpenOnly || venueStatus(v).open));
      $('#v-list').innerHTML = list.map(v => {
        const s = venueStatus(v);
        return `<li><button type="button" class="venue-item ${mapSel === v.id ? 'sel' : ''}" data-vid="${v.id}">
          <span class="vi-top"><b>${esc(venueName(v))}</b><span class="vi-dot ${s.known ? (s.open ? 'v-open' : 'v-closed') : ''}"></span></span>
          <small>${tr(VTYPE[v.type] || VTYPE.bar)} · ${v.addr ? esc(v.addr) : L('адрес не указан', 'no address')}</small>
          <small class="${s.known ? (s.open ? 'v-open' : 'v-closed') : ''}">${esc(s.text)}</small></button></li>`;
      }).join('') || `<li class="muted">${L('Ничего не нашлось.', 'Nothing found.')}</li>`;
    };
    drawList();
    const m = initMap('venues-map', { onSelect: vid => { $$('.venue-item').forEach(b => b.classList.toggle('sel', b.dataset.vid === vid)); } });
    $('#v-q').addEventListener('input', e => { venueQ = e.target.value; drawList(); });
    $('#v-list').addEventListener('click', e => {
      const b = e.target.closest('.venue-item'); if (!b) return;
      m.select(b.dataset.vid, { center: true });
      if (window.innerWidth < 900) $('#venues-map').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
    if (pendingVenue) { const vid = pendingVenue; pendingVenue = null; m.select(vid, { center: true }); }
  }
  let venueQ = '', venueOpenOnly = false, pendingVenue = null;

  // ---------- События ----------
  function dateBlock(e) {
    const d = new Date(e.at);
    return `<div class="ev-date"><b>${fDay(d)}</b><span>${fMon(d)}</span><span class="mono">${fTime(d)}</span></div>`;
  }
  function statusPill(e, u) {
    const inv = u && myInvite(e, u);
    if (e.hostId === u?.id) return `<span class="pill pill-host">${L('Организатор', 'Host')}</span>`;
    if (!inv) return '';
    return `<span class="pill pill-${inv.status}">${{ going: L('Иду', 'Going'), pending: L('Ждёт ответа', 'Awaiting reply'), declined: L('Не иду', 'Not going') }[inv.status]}</span>`;
  }
  function eventCard(e, u, href = `#/event/${e.id}`) {
    const ids = goingIds(e), b = bill(e);
    const top = ranking(e.picks, tobaccoName)[0];
    return `<a class="ev-card ${isPast(e) ? 'ev-past' : ''}" href="${href}">
      ${dateBlock(e)}
      <div class="ev-body">
        <h3>${esc(e.title)}</h3>
        <div class="ev-venue">${ICON.pin}<span>${esc(e.venue)}</span></div>
        ${top ? `<div><span class="chip chip-accent">${L('Лидирует', 'Leading')}: ${esc(tobaccoName(top.id))} · ${top.users.length}</span></div>` : ''}
        <div class="ev-meta">
          ${b.total ? `<span>${ICON.wallet}${money(b.per)} ${L('с человека', 'per person')}</span>` : ''}
          ${e.comments.length ? `<span>${ICON.chat}${e.comments.length}</span>` : ''}
        </div>
        <div class="ev-foot">${avatarStack(ids)}${statusPill(e, u)}</div>
      </div>
    </a>`;
  }

  // Лента: что происходит у друзей и в ваших сборах.
  function feedItems(u) {
    const items = [], friends = new Set(u.friends), nm = id => `<a href="#/user/${id}"><b>${esc(userById(id)?.name || '—')}</b></a>`;
    const ev = e => `«<a href="#/event/${e.id}">${esc(e.title)}</a>»`;
    for (const e of db.events) {
      if (!isMember(e, u)) continue;
      for (const c of e.comments) if (c.userId !== u.id) items.push({ at: c.at, who: c.userId, icon: 'chat', html: `${nm(c.userId)} ${L('в', 'in')} ${ev(e)}: ${esc(c.text.length > 90 ? c.text.slice(0, 90) + '…' : c.text)}` });
      for (const i of e.invites) if (i.at && i.userId && i.userId !== u.id && i.status !== 'pending') items.push({ at: i.at, who: i.userId, icon: i.status === 'going' ? 'check' : 'x', html: `${nm(i.userId)} ${i.status === 'going' ? L('идёт на', 'is going to') : L('не сможет прийти на', 'can’t make it to')} ${ev(e)}` });
      if (e.createdAt && e.hostId !== u.id && myInvite(e, u)) items.push({ at: e.createdAt, who: e.hostId, icon: 'plus', html: `${nm(e.hostId)} ${L('зовёт вас на', 'invites you to')} ${ev(e)}` });
    }
    for (const m of db.mixes) if (friends.has(m.authorId)) items.push({ at: m.at, who: m.authorId, icon: 'smoke', html: `${nm(m.authorId)} ${L('делится миксом', 'shares a mix')} <button class="link-btn" data-action="catTab" data-tab="mixes">«${esc(m.name)}»</button>` });
    for (const r of db.reviews) if (friends.has(r.userId)) items.push({ at: r.at, who: r.userId, icon: 'star', html: `${nm(r.userId)} ${L('оценивает', 'rates')} <button class="link-btn" data-action="tobacco" data-id="${r.tobaccoId}">${esc(tobaccoName(r.tobaccoId))}</button> ${L('на', '')} ${r.rating} ${L('из 5', 'out of 5')}` });
    return items.filter(x => x.at).sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 40);
  }
  function feedHtml(items) {
    if (!items.length) return emptyState(L('В ленте пока тихо', 'Nothing in the feed yet'), L('Здесь появятся новые сообщения в ваших сборах, ответы на приглашения и миксы друзей.', 'New messages in your events, replies to invitations and friends’ mixes will show up here.'), `<a class="btn btn-primary btn-sm" href="#/people">${L('Найти друзей', 'Find friends')}</a>`);
    const dayKey = iso => { const d = new Date(iso); d.setHours(0, 0, 0, 0); return d.getTime(); };
    const today = dayKey(Date.now()), label = k => k === today ? L('Сегодня', 'Today') : k === today - 864e5 ? L('Вчера', 'Yesterday') : fShort(new Date(k));
    let out = '', last = null;
    for (const it of items) {
      const k = dayKey(it.at);
      if (k !== last) { out += `${last === null ? '' : '</ul>'}<h4 class="feed-day">${label(k)}</h4><ul class="feed">`; last = k; }
      out += `<li class="feed-item"><span class="feed-av">${avatar(userById(it.who), 'sm')}<span class="feed-ic ic-${it.icon}">${ICON[it.icon]}</span></span>
        <p>${it.html}</p><time class="mono">${fTime(new Date(it.at))}</time></li>`;
    }
    return out + '</ul>';
  }

  // Календарь сборов на месяц.
  const cal = { y: new Date().getFullYear(), m: new Date().getMonth(), day: null };
  function calendarHtml(list, u) {
    const first = new Date(cal.y, cal.m, 1), startPad = (first.getDay() + 6) % 7, days = new Date(cal.y, cal.m + 1, 0).getDate();
    const todayYmd = ymd(new Date()), byDay = {};
    for (const e of list) { const k = ymd(new Date(e.at)); (byDay[k] ||= []).push(e); }
    let cells = '';
    for (let i = 0; i < startPad; i++) cells += '<span class="cal-cell pad"></span>';
    for (let d = 1; d <= days; d++) {
      const k = ymd(new Date(cal.y, cal.m, d)), evs = byDay[k] || [];
      cells += `<button type="button" class="cal-cell ${k === todayYmd ? 'today' : ''} ${cal.day === k ? 'sel' : ''} ${evs.length ? 'has' : ''}" data-action="calDay" data-day="${k}" aria-label="${d}${evs.length ? `, ${evs.length} ${pl(evs.length, ['сбор', 'сбора', 'сборов'], ['event', 'events'])}` : ''}">
        <span class="cal-n">${d}</span>${evs.slice(0, 3).map(e => `<i class="cal-dot ${isPast(e) ? 'past' : e.hostId === u.id ? 'host' : ''}"></i>`).join('')}</button>`;
    }
    const sel = cal.day ? (byDay[cal.day] || []) : [];
    return `<div class="cal">
      <div class="cal-head"><button class="icon-btn" type="button" data-action="calNav" data-step="-1" aria-label="${L('Предыдущий месяц', 'Previous month')}">‹</button>
        <b>${fMonthYear(first)}</b><button class="icon-btn" type="button" data-action="calNav" data-step="1" aria-label="${L('Следующий месяц', 'Next month')}">›</button></div>
      <div class="cal-grid">${DAY_NAMES[lang].map(w => `<span class="cal-w">${w}</span>`).join('')}${cells}</div>
      <div class="cal-legend"><span><i class="cal-dot"></i>${L('Иду', 'Going')}</span><span><i class="cal-dot host"></i>${L('Организую', 'Hosting')}</span><span><i class="cal-dot past"></i>${L('Прошёл', 'Past')}</span></div>
    </div>
    ${cal.day ? `<h4 class="feed-day">${cap(fFull(new Date(cal.day + 'T12:00')))}</h4>${sel.length ? `<div class="ev-grid">${sel.map(e => eventCard(e, u)).join('')}</div>` : `<p class="muted">${L('В этот день сборов нет.', 'No events on this day.')}</p>`}` : `<p class="muted">${L('Нажмите на день, чтобы увидеть сборы.', 'Tap a day to see its events.')}</p>`}`;
  }

  let homeQ = '';
  function pageEvents() {
    const u = me();
    if (!u) {
      view.innerHTML = `<section class="section"><span class="eyebrow">${L('События', 'Events')}</span><h1>${L('Сборы и приглашения', 'Meet-ups and invitations')}</h1></section>
        ${emptyState(L('Войдите, чтобы видеть свои сборы', 'Sign in to see your events'), L('Создавайте сборы, принимайте приглашения друзей и выбирайте табак вместе.', 'Create events, accept invitations from friends and pick tobacco together.'),
          `<div class="btn-row"><a class="btn btn-primary btn-sm" href="#/register">${L('Зарегистрироваться', 'Sign up')}</a><a class="btn btn-sm" href="#/login">${L('Войти', 'Sign in')}</a></div>`)}`;
      return;
    }
    const mine = db.events.filter(e => isMember(e, u)).sort((a, b) => new Date(a.at) - new Date(b.at));
    const invites = mine.filter(e => !isPast(e) && myInvite(e, u)?.status === 'pending');
    const upcoming = mine.filter(e => !isPast(e) && !invites.includes(e));
    const hosting = upcoming.filter(e => e.hostId === u.id);
    const past = mine.filter(isPast).reverse();
    const feed = feedItems(u), seen = +prefs.get('feedSeen', 0);
    const unseen = tab.home === 'feed' ? 0 : feed.filter(f => new Date(f.at) > seen && f.who !== u.id).length;
    const next = upcoming.find(e => goingIds(e).includes(u.id));
    const homeView = prefs.get('homeView', 'list');

    const nextCard = next ? (() => {
      const b = bill(next), picked = (next.picks[u.id] || []).length;
      return `<section class="next-card">
        <div class="next-main">
          <span class="next-when"><span class="soon-dot"></span><span data-countdown="${next.at}">${countdown(next.at)}</span></span>
          <h2><a href="#/event/${next.id}">${esc(next.title)}</a></h2>
          <div class="next-facts"><span>${ICON.pin}${esc(next.venue)}</span><span>${ICON.cal}${whenLabel(next)}</span>${b.total ? `<span>${ICON.wallet}${money(b.per)} ${L('с человека', 'per person')}</span>` : ''}</div>
        </div>
        <div class="next-side">${avatarStack(goingIds(next), 5)}
          <div class="btn-row">${canVote(next, u) && !picked ? `<button class="btn btn-sm" data-action="pickTobacco" data-id="${next.id}">${L('Выбрать табаки', 'Pick tobacco')}</button>` : ''}<a class="btn btn-primary btn-sm" href="#/event/${next.id}">${L('Открыть', 'Open')}</a></div></div>
      </section>`;
    })() : '';

    const grid = list => list.length ? `<div class="ev-grid">${list.map(e => eventCard(e, u)).join('')}</div>` : '';
    const filterQ = list => { const q = homeQ.trim().toLowerCase(); return q ? list.filter(e => `${e.title} ${e.venue} ${e.address}`.toLowerCase().includes(q)) : list; };
    const nothing = `<p class="muted">${L('Ничего не нашлось.', 'Nothing found.')}</p>`;
    const search = (extra = '') => `<div class="panel-tools"><input class="input" id="home-q" type="search" placeholder="${L('Поиск по названию или заведению', 'Search by name or venue')}" value="${esc(homeQ)}" aria-label="${L('Поиск сборов', 'Search events')}">${extra}</div>`;
    const newBtn = `<button class="btn btn-primary btn-sm" data-action="newEvent">${L('Создать сбор', 'Create event')}</button>`;
    const lists = { upcoming, hosting, past };
    const empties = {
      upcoming: emptyState(L('Ближайших сборов нет', 'No upcoming events'), L('Создайте сбор, выберите заведение и позовите друзей по номеру телефона.', 'Create an event, pick a venue and invite friends by phone number.'), newBtn),
      hosting: emptyState(L('Вы пока ничего не организуете', 'You are not hosting anything yet'), L('Соберите друзей сами: это займёт меньше минуты.', 'Gather your friends yourself: it takes under a minute.'), newBtn),
      past: emptyState(L('Здесь будет история', 'Your history will appear here'), L('После первого сбора тут появится, где вы были и что курили.', 'After your first event you will see where you went and what you smoked.'))
    };
    let body;
    if (tab.home === 'invites') {
      body = invites.length ? `<div class="ev-grid">${invites.map(e => {
        const host = userById(e.hostId);
        return `<div class="ev-card invite-card">${dateBlock(e)}
          <div class="ev-body"><h3><a href="#/event/${e.id}">${esc(e.title)}</a></h3>
            <div class="ev-venue">${ICON.pin}<span>${esc(e.venue)}</span></div>
            <div class="ev-venue">${avatar(host, 'xs')}<span>${L('Зовёт', 'Invited by')} ${esc(host?.name)}</span></div>
            <div class="invite-actions"><button class="btn btn-primary btn-sm" data-action="rsvp" data-id="${e.id}" data-status="going">${L('Иду', 'Going')}</button>
            <button class="btn btn-sm" data-action="rsvp" data-id="${e.id}" data-status="declined">${L('Не смогу', 'Can’t make it')}</button></div></div></div>`;
      }).join('')}</div>` : emptyState(L('Новых приглашений нет', 'No new invitations'), L('Когда друзья позовут вас на сбор, приглашение появится здесь.', 'When friends invite you, the invitation will appear here.'), `<a class="btn btn-sm" href="#/people">${L('Найти друзей', 'Find friends')}</a>`);
    } else if (tab.home === 'feed') {
      body = feedHtml(feed);
    } else {
      const k = tab.home, toggle = k === 'upcoming' ? `<div class="segmented sm" role="radiogroup" aria-label="${L('Вид', 'View')}">
          <button role="radio" aria-checked="${homeView === 'list'}" class="${homeView === 'list' ? 'on' : ''}" data-action="homeView" data-view="list">${L('Список', 'List')}</button>
          <button role="radio" aria-checked="${homeView === 'cal'}" class="${homeView === 'cal' ? 'on' : ''}" data-action="homeView" data-view="cal">${L('Календарь', 'Calendar')}</button></div>` : '';
      if (k === 'upcoming' && homeView === 'cal') body = `<div class="panel-tools">${toggle}</div>${calendarHtml(mine.filter(e => myInvite(e, u)?.status !== 'declined'), u)}`;
      else body = lists[k].length ? `${search(toggle)}<div id="home-grid">${grid(filterQ(lists[k])) || nothing}</div>` : (toggle ? `<div class="panel-tools">${toggle}</div>` : '') + empties[k];
    }

    view.innerHTML = `
      <section class="greet-line"><div><span class="eyebrow">${L('События', 'Events')}</span><h1>${L('Мои сборы', 'My events')}</h1></div>
        <div class="btn-row"><a class="btn btn-sm" href="#/history">${ICON.clock}${L('История вечеров', 'Evening stories')}</a><button class="btn btn-primary btn-sm" type="button" data-action="newEvent">${ICON.plus}${L('Новый сбор', 'New event')}</button></div></section>
      ${nextCard}
      ${uTabs('home', [
        { key: 'upcoming', label: L('Ближайшие', 'Upcoming'), count: upcoming.length },
        { key: 'invites', label: L('Приглашения', 'Invitations'), count: invites.length, alert: invites.length > 0 },
        { key: 'hosting', label: L('Организую', 'Hosting'), count: hosting.length },
        { key: 'past', label: L('Прошедшие', 'Past') },
        { key: 'feed', label: L('Лента', 'Feed'), count: unseen, alert: unseen > 0 }
      ])}
      ${tabPanel('home', body)}`;
    if (tab.home === 'feed') prefs.set('feedSeen', Date.now());
    $('#home-q')?.addEventListener('input', ev => {
      homeQ = ev.target.value;
      $('#home-grid').innerHTML = grid(filterQ(lists[tab.home])) || nothing;
    });
  }

  function stepsHtml() {
    return `<div class="steps">
      <div class="step"><h3>${L('Выберите место', 'Pick a place')}</h3><p>${L('Откройте карту заведений: адреса, часы работы и что открыто сейчас.', 'Open the venue map: addresses, opening hours and what is open now.')}</p></div>
      <div class="step"><h3>${L('Пригласите друзей', 'Invite friends')}</h3><p>${L('Нажмите «+», укажите время и позовите друзей по имени или номеру. Тех, кого ещё нет в сервисе, сбор дождётся после регистрации.', 'Tap “+”, set the time and invite friends by name or number. People not yet on the service get the event once they sign up.')}</p></div>
      <div class="step"><h3>${L('Выберите табаки', 'Pick tobacco')}</h3><p>${L('Участники отмечают вкусы и чашу, самые популярные поднимаются наверх. Сумма делится поровну.', 'Guests mark flavours and a bowl, the most popular rise to the top. The bill is split evenly.')}</p></div>
    </div>`;
  }

  function pageHow() {
    view.innerHTML = `<section class="section"><span class="eyebrow">${L('Помощь', 'Help')}</span><h1>${L('Как это работает', 'How it works')}</h1></section>
      ${stepsHtml()}
      <section class="panel"><h2>${L('Подтверждение телефона', 'Phone verification')}</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      ${L('При регистрации мы отправляем на номер четырёхзначный код. Пока номер не подтверждён, войти в сервис и получать приглашения нельзя. Полный номер видят только друзья и участники общих сборов.',
        'When you sign up we text a four-digit code to your number. Until it is confirmed you cannot sign in or receive invitations. Only friends and people from shared events see your full number.')}</p></section>
      <section class="panel"><h2>${L('Складчина', 'Splitting the bill')}</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      ${L('Организатор указывает, сколько кальянов заказать и сколько стоит один. Сумма делится поровну между теми, кто идёт. Организатор отмечает, кто уже перевёл деньги.',
        'The host sets how many hookahs to order and the price of one. The total is split evenly between everyone going. The host marks who has already paid.')}</p></section>
      <section class="panel"><h2>${L('Напоминания', 'Reminders')}</h2><p class="muted" style="margin-top:8px;max-width:65ch">
      ${L('Включите колокольчик на странице сбора, и сайт напомнит за час, если он открыт. Чтобы напоминание пришло наверняка, нажмите «В календарь».',
        'Turn on the bell on the event page and the site reminds you an hour before while it is open. For a guaranteed reminder, tap “Add to calendar”.')}</p></section>`;
  }

  function pageEvent(id) {
    const u = me();
    if (!u) return go('login');
    const e = eventById(id);
    if (!e) { view.innerHTML = emptyState(L('Сбор не найден', 'Event not found'), L('Возможно, его отменили.', 'It may have been cancelled.'), `<a class="btn btn-sm" href="#/events">${L('К моим сборам', 'To my events')}</a>`); return; }
    if (!isMember(e, u)) { view.innerHTML = emptyState(L('Это закрытый сбор', 'This is a private event'), L('Попросите организатора прислать приглашение.', 'Ask the host to send you an invitation.'), `<a class="btn btn-sm" href="#/events">${L('К моим сборам', 'To my events')}</a>`); return; }
    const d = new Date(e.at), host = userById(e.hostId), inv = myInvite(e, u), isHost = e.hostId === u.id, past = isPast(e);
    const going = goingIds(e), b = bill(e);
    const tRank = ranking(e.picks, tobaccoName), bRank = ranking(e.bowls, bowlName);
    const myPicks = e.picks[u.id] || [];
    const reminded = remindOn(e, u);
    const v = eventVenue(e);
    const q = placeQuery(e.venue, e.address);
    const votes = n => pl(n, ['голос', 'голоса', 'голосов'], ['vote', 'votes']);
    const quota = chatQuota(e, u);

    const rankHtml = (rank, kind) => {
      if (!rank.length) return emptyState(kind === 't' ? L('Пока никто не выбрал табак', 'No tobacco picked yet') : L('Чашу ещё не выбрали', 'No bowl picked yet'), kind === 't' ? L('Отметьте свои вкусы, и список начнёт складываться.', 'Mark your flavours and the list will start to form.') : L('Проголосуйте за чашу, на которой хотите курить.', 'Vote for the bowl you want.'));
      const max = rank[0].users.length;
      return `<ol class="rank">${rank.map((r, i) => {
        const n = r.users.length;
        const lead = i === 0 && (rank.length === 1 || rank[1].users.length < n);
        let name, sub, art = '';
        if (kind === 't') { const t = tobacco(r.id); art = flavorThumb(t); name = `<b>${esc(t?.brand)}</b> ${esc(t?.flavor)}`; sub = `${esc(tr(t?.note))} · ${L('крепость', 'strength')} ${t?.strength}/10`; }
        else { const bw = bowl(r.id); name = `<b>${esc(tr(bw?.name))}</b><small>${tr(BOWL_TYPE[bw?.type] || ['', ''])}</small>`; sub = esc(tr(bw?.note)); }
        return `<li class="rank-row ${lead ? 'is-top' : ''}">
          <div class="rank-pos">${i + 1}</div>
          <div class="rank-body">
            <div class="rank-name">${art}${name} ${lead ? `<span class="lead-badge">${L('лидер', 'top')}</span>` : ''}</div>
            <div class="rank-bar"><span style="width:${Math.round(n / max * 100)}%"></span></div>
            <div class="rank-meta">${avatarStack(r.users, 6, 'xs')}<span>${sub}</span></div>
          </div>
          <div class="rank-count">${n}<small>${votes(n)}</small></div>
        </li>`;
      }).join('')}</ol>`;
    };

    const statusLabel = { going: L('Идёт', 'Going'), pending: L('Ждём ответа', 'Awaiting'), declined: L('Не придёт', 'Not going') };
    const waTo = phone => /^996\d{9}$/.test(normPhone(phone)) && canVote(e, u) && !past
      ? `<button class="icon-btn wa-mini" data-action="shareEvent" data-id="${e.id}" data-via="wa" data-phone="${normPhone(phone)}" title="${L('Написать в WhatsApp', 'Message on WhatsApp')}" aria-label="${L('Отправить приглашение в WhatsApp', 'Send the invitation on WhatsApp')}">${ICON.wa}</button>` : '';
    const personRow = (p, phone, pill) => `<li class="person">${avatar(p, 'sm')}<div class="person-name">
      ${p ? `<a href="#/user/${p.id}"><b>${esc(p.name)}</b></a>` : `<b>${L('Ещё не в сервисе', 'Not on the service yet')}</b>`}<small class="mono">${fmtPhone(phone)}</small></div>${p ? '' : waTo(phone)}${pill}</li>`;
    const people = [
      personRow(host, host?.phone, `<span class="pill pill-host">${L('Организатор', 'Host')}</span>`),
      ...e.invites.map(i => { const p = i.userId ? userById(i.userId) : null; return personRow(p, p ? p.phone : i.phone, `<span class="pill pill-${i.status}">${statusLabel[i.status]}</span>`); })
    ].join('');
    const paidLabel = paid => paid ? L('Скинул', 'Paid') : L('Не скинул', 'Not paid');
    const billHtml = b.total ? `
      <div class="bill-sum"><div><small>${e.hookahs} × ${money(e.price)}</small><b>${money(b.total)}</b></div>
        <div><small>${L(`С каждого из ${going.length}`, `Each of ${going.length}`)}</small><b>${money(b.per)}</b></div></div>
      <div class="progress" role="img" aria-label="${L('Собрано', 'Collected')} ${money(b.collected)} / ${money(b.total)}"><span style="width:${Math.round(b.collected / b.total * 100)}%"></span></div>
      <p class="muted" style="font-size:13px">${L('Собрано', 'Collected')} ${money(b.collected)} ${L('из', 'of')} ${money(b.total)}</p>
      <ul class="people">${going.map(pid => {
        const p = userById(pid), paid = !!e.paid[pid];
        const ctl = isHost && !past ? `<button class="pay-btn ${paid ? 'on' : ''}" data-action="togglePaid" data-id="${e.id}" data-user="${pid}" aria-pressed="${paid}">${paidLabel(paid)}</button>`
          : `<span class="pill ${paid ? 'pill-going' : 'pill-pending'}">${paidLabel(paid)}</span>`;
        return `<li class="person">${avatar(p, 'xs')}<div class="person-name"><b>${esc(p?.name)}</b></div>${ctl}</li>`;
      }).join('')}</ul>`
      : `<p class="muted">${isHost ? L('Укажите, сколько кальянов заказываете и почём, и сервис поделит счёт.', 'Set how many hookahs you order and the price, and the bill will be split.') : L('Организатор ещё не указал цену.', 'The host has not set a price yet.')}</p>`;

    view.innerHTML = `
      <a class="back" href="#/events">← ${L('Мои сборы', 'My events')}</a>
      <section class="ev-hero">
        <div class="section-head"><div><span class="eyebrow">${past ? L('Сбор прошёл', 'Past event') : L('Сбор', 'Event')}</span><h1 style="margin-top:8px">${esc(e.title)}</h1></div>
          <div class="btn-row">
            <button class="btn btn-sm" data-action="repeatEvent" data-id="${e.id}">${ICON.repeat}${L('Повторить', 'Repeat')}</button>
            ${isHost && !past ? `<button class="btn btn-sm" data-action="editEvent" data-id="${e.id}">${ICON.edit}${L('Изменить', 'Edit')}</button>
              <button class="btn btn-danger btn-sm" data-action="deleteEvent" data-id="${e.id}">${L('Отменить сбор', 'Cancel event')}</button>` : ''}
          </div></div>
        <div class="ev-facts">
          <div class="fact"><small>${L('Заведение', 'Venue')}</small><b>${esc(e.venue)}</b></div>
          <div class="fact"><small>${L('Адрес', 'Address')}</small><b>${esc(e.address || L('Не указан', 'Not set'))}</b></div>
          <div class="fact"><small>${L('Когда', 'When')}</small><b>${cap(fFull(d))}, ${fTime(d)}</b></div>
          <div class="fact"><small>${L('Участники', 'Guests')}</small><b>${going.length} ${pl(going.length, ['идёт', 'идут', 'идут'], ['going', 'going'])} · ${e.invites.length + 1} ${pl(e.invites.length + 1, ['приглашён', 'приглашены', 'приглашены'], ['invited', 'invited'])}</b></div>
        </div>
        ${canVote(e, u) && !past ? `<div class="share-strip"><div><b>${L('Позовите друзей ссылкой', 'Invite friends with a link')}</b><small>${L('Отправьте сбор в чат, а друзья ответят «Иду» в одно касание', 'Send the event to a chat and friends reply “Going” in one tap')}</small></div>
          <div class="btn-row"><button class="btn btn-sm share-tg" data-action="shareEvent" data-id="${e.id}" data-via="tg">${ICON.tg}Telegram</button>
          <button class="btn btn-sm share-wa" data-action="shareEvent" data-id="${e.id}" data-via="wa">${ICON.wa}WhatsApp</button>
          <button class="btn btn-sm" data-action="shareEvent" data-id="${e.id}">${ICON.link}${L('Ссылка', 'Link')}</button></div></div>` : ''}
        <div class="btn-row">
          ${v ? `<button class="btn btn-sm" data-action="showVenue" data-vid="${v.id}">${ICON.home}${L('На нашей карте', 'On our map')}</button>` : ''}
          <a class="btn btn-sm" href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}" target="_blank" rel="noopener noreferrer">${ICON.pin}Google ${L('Карты', 'Maps')}</a>
          <a class="btn btn-sm" href="https://2gis.kg/bishkek/search/${encodeURIComponent(e.venue)}${v ? `?m=${v.lon},${v.lat}/18` : ''}" target="_blank" rel="noopener noreferrer">${ICON.pin}2ГИС</a>
          ${safeUrl(e.mapUrl) ? `<a class="btn btn-sm" href="${esc(safeUrl(e.mapUrl))}" target="_blank" rel="noopener noreferrer">${ICON.ext}${L('Сайт заведения', 'Venue website')}</a>` : ''}
          ${!past ? `<button class="btn btn-sm ${reminded ? 'btn-on' : ''}" data-action="toggleRemind" data-id="${e.id}" aria-pressed="${reminded}">${ICON.bell}${reminded ? L('Напомним за час', 'Reminder on') : L('Напомнить за час', 'Remind me 1 h before')}</button>
          <button class="btn btn-sm" data-action="ics" data-id="${e.id}">${ICON.cal}${L('В календарь', 'Add to calendar')}</button>` : ''}
        </div>
        ${e.desc ? `<p style="max-width:65ch">${esc(e.desc)}</p>` : ''}
        ${inv && !past ? `<div class="rsvp"><span>${L('Ваш ответ:', 'Your reply:')}</span>
          <button class="btn btn-sm ${inv.status === 'going' ? 'btn-primary' : ''}" data-action="rsvp" data-id="${e.id}" data-status="going">${L('Иду', 'Going')}</button>
          <button class="btn btn-sm ${inv.status === 'declined' ? 'btn-primary' : ''}" data-action="rsvp" data-id="${e.id}" data-status="declined">${L('Не смогу', 'Can’t make it')}</button></div>` : ''}
      </section>
      <div class="ev-layout">
        <div class="ev-main">
          ${past && isHost && !e.story ? storyFormHtml(e) : ''}
          ${past && e.story ? `<a class="story-link" href="#/history" data-action="openStory" data-id="${e.id}">${ICON.clock}<span><b>${L('Рассказ об этом вечере в Истории', 'This evening’s story in History')}</b><small>${stars(e.story.rating)} · ${e.story.comments.length} ${pl(e.story.comments.length, ['комментарий', 'комментария', 'комментариев'], ['comment', 'comments'])}</small></span><span class="next-go">→</span></a>` : ''}
          <section class="panel">
            <div class="panel-head"><div><h2>${L('Табаки', 'Tobacco')}</h2><p class="muted" style="font-size:13.5px;margin-top:4px">${L('Чем больше голосов, тем выше позиция', 'More votes, higher position')}</p></div>
              ${canVote(e, u) && !past ? `<button class="btn btn-sm ${myPicks.length ? '' : 'btn-primary'}" data-action="pickTobacco" data-id="${e.id}">${myPicks.length ? `${L('Мой выбор', 'My pick')} · ${myPicks.length}` : L('Выбрать табаки', 'Pick tobacco')}</button>` : ''}</div>
            ${rankHtml(tRank, 't')}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>${L('Чаша', 'Bowl')}</h2>
              ${canVote(e, u) && !past ? `<button class="btn btn-sm" data-action="pickBowl" data-id="${e.id}">${e.bowls[u.id] ? L('Изменить', 'Change') : L('Выбрать чашу', 'Pick a bowl')}</button>` : ''}</div>
            ${rankHtml(bRank, 'b')}
          </section>
          <section class="panel">
            <div class="panel-head"><h2>${L('Обсуждение', 'Discussion')}</h2><span class="muted" style="font-size:13.5px">${e.comments.length} ${pl(e.comments.length, ['сообщение', 'сообщения', 'сообщений'], ['message', 'messages'])}</span></div>
            <ul class="comments">${e.comments.length ? e.comments.map(c => commentItem(c, { scope: 'ev', eventId: e.id, u, canDelete: c.userId === u.id || isHost, delAction: 'deleteComment' })).join('')
              : `<li class="muted">${L('Пока тихо. Напишите первым: кто что берёт, во сколько встречаемся.', 'Quiet so far. Be the first: who brings what, what time to meet.')}</li>`}</ul>
            <form class="comment-form" id="comment-form">
              <div class="cf-box"><textarea id="comment-text" rows="2" maxlength="500" placeholder="${L('Сообщение участникам', 'Message to guests')}" aria-label="${L('Сообщение', 'Message')}" ${quota.ok ? '' : 'disabled'}></textarea>
                <button type="button" class="emoji-btn" data-action="emoji" data-target="comment-text" data-pop-anchor aria-label="${L('Смайлики', 'Emoji')}" ${quota.ok ? '' : 'disabled'}>${SMILE}</button></div>
              <button class="btn btn-primary" type="submit" ${quota.ok ? '' : 'disabled'}>${L('Отправить', 'Send')}</button>
            </form>
            <p class="quota ${quota.ok ? '' : 'blocked'}">${ICON.clock}<span>${quotaText(quota)}</span></p>
          </section>
        </div>
        <div class="ev-main">
          <aside class="panel">
            <div class="panel-head"><h2>${L('Участники', 'Guests')}</h2>
              ${(isHost || inv?.status === 'going') && !past ? `<button class="plus-btn sm" data-action="invite" data-id="${e.id}" title="${L('Пригласить', 'Invite')}" aria-label="${L('Пригласить участников', 'Invite guests')}">${ICON.plus}</button>` : ''}</div>
            <ul class="people">${people}</ul>
          </aside>
          <aside class="panel">
            <div class="panel-head"><h2>${L('Складчина', 'Bill')}</h2>
              ${isHost && !past ? `<button class="btn btn-sm" data-action="editBill" data-id="${e.id}">${b.total ? L('Изменить', 'Edit') : L('Указать', 'Set')}</button>` : ''}</div>
            ${billHtml}
          </aside>
        </div>
      </div>`;

    $('#story-form')?.addEventListener('submit', ev => {
      ev.preventDefault();
      const rating = +($('input[name=st-star]:checked')?.value || 0), text = clean($('#st-text').value, 600, true);
      const highlights = $('#st-hl').value.split('\n').map(x => clean(x, 80)).filter(Boolean).slice(0, 3);
      if (!rating) return void ($('#st-err').textContent = L('Оцените вечер от 1 до 5 звёзд.', 'Rate the evening from 1 to 5 stars.'));
      if (text.length < 20) return void ($('#st-err').textContent = L('Напишите хотя бы пару предложений: что курили и как было.', 'Write at least a couple of sentences: what you smoked and how it was.'));
      act(() => { e.story = { rating, text, highlights, at: new Date().toISOString(), fire: [], comments: [] }; }, 'POST', `/events/${e.id}/story`, { rating, text, highlights })
        .then(() => { toast(L('Рассказ опубликован в Истории', 'Story published to History')); pendingStory = e.id; go('history'); }, quiet);
    });
    const form = $('#comment-form'), ta = $('#comment-text');
    form.addEventListener('submit', ev => {
      ev.preventDefault();
      const text = clean(ta.value, 500, true);
      if (!text) return;
      const q = chatQuota(e, u);
      if (!q.ok) { toast(L('Сейчас отправить нельзя: сработало ограничение на сообщения', 'You can’t send right now: message limit reached'), 'err'); render(); return; }
      act(() => { e.comments.push({ id: uid('c'), userId: u.id, text, at: new Date().toISOString(), reactions: {} }); }, 'POST', `/events/${e.id}/comments`, { text })
        .then(() => render(), quiet);
    });
    if (!quota.ok) startQuotaTimer();
    ta.addEventListener('keydown', ev => { if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) form.requestSubmit(); });
  }

  // ---------- Сообщения: защита от спама, реакции, смайлики ----------
  // Ограничения на одного человека. Это удобство для честных пользователей: настоящую защиту от DDoS и спама
  // даёт сервер (те же правила в API плюс ограничение запросов на уровне nginx/Cloudflare).
  const LIMITS = {
    cooldownMs: 3 * 60e3,          // одно сообщение раз в 3 минуты в обсуждении сбора
    perEvent: 10,                  // не больше 10 сообщений в одном сборе…
    perEventWindowMs: 24 * 3600e3, // …за сутки
    global: 144,                   // не больше 144 сообщений на всём сайте…
    globalWindowMs: 7 * 3600e3     // …за 7 часов (считаются и комментарии в «Истории»)
  };
  const msgTime = c => new Date(c.at).getTime();
  function myRecentMessages(u) {
    const now = Date.now(), out = [];
    for (const e of db.events) for (const c of [...e.comments, ...(e.story?.comments || [])]) if (c.userId === u.id && now - msgTime(c) < LIMITS.globalWindowMs) out.push(msgTime(c));
    return out.sort((a, b) => a - b);
  }
  function chatQuota(e, u) {
    const now = Date.now(), global = myRecentMessages(u);
    const mine = e.comments.filter(c => c.userId === u.id).map(msgTime).sort((a, b) => a - b);
    const inEvent = mine.filter(t => now - t < LIMITS.perEventWindowMs), last = mine[mine.length - 1] || 0;
    const q = { leftEvent: LIMITS.perEvent - inEvent.length, leftGlobal: LIMITS.global - global.length };
    if (q.leftGlobal <= 0) return { ...q, ok: false, reason: 'global', until: global[0] + LIMITS.globalWindowMs };
    if (q.leftEvent <= 0) return { ...q, ok: false, reason: 'event', until: inEvent[0] + LIMITS.perEventWindowMs };
    if (last && now - last < LIMITS.cooldownMs) return { ...q, ok: false, reason: 'cooldown', until: last + LIMITS.cooldownMs };
    return { ...q, ok: true };
  }
  function fmtWait(ms) {
    const s = Math.max(0, Math.ceil(ms / 1000));
    if (s < 3600) return `${Math.floor(s / 60)}:${pad(s % 60)}`;
    const h = Math.floor(s / 3600), m = Math.ceil((s % 3600) / 60);
    return L(`${h} ч ${m} мин`, `${h} h ${m} min`);
  }
  function quotaText(q) {
    if (q.ok) return L(`Можно написать ещё ${q.leftEvent} ${plural(q.leftEvent, 'сообщение', 'сообщения', 'сообщений')} в этом сборе сегодня · одно сообщение раз в 3 минуты`,
      `${q.leftEvent} more ${q.leftEvent === 1 ? 'message' : 'messages'} in this event today · one message every 3 minutes`);
    const w = `<b class="mono" data-until="${q.until}">${fmtWait(q.until - Date.now())}</b>`;
    return {
      cooldown: L(`Следующее сообщение можно отправить через ${w}. Так обсуждение остаётся читаемым.`, `You can send the next message in ${w}. This keeps the discussion readable.`),
      event: L(`Вы уже отправили ${LIMITS.perEvent} сообщений в этом сборе за сутки. Следующее — через ${w}.`, `You have sent ${LIMITS.perEvent} messages in this event today. Next one in ${w}.`),
      global: L(`Лимит: ${LIMITS.global} ${plural(LIMITS.global, 'сообщение', 'сообщения', 'сообщений')} за 7 часов. Следующее — через ${w}.`, `Limit: ${LIMITS.global} messages per 7 hours. Next one in ${w}.`)
    }[q.reason];
  }
  // Обратный отсчёт: когда ожидание закончилось, форма снова становится доступной.
  let quotaTimer = null;
  function startQuotaTimer() {
    clearInterval(quotaTimer);
    quotaTimer = setInterval(() => {
      const els = $$('[data-until]');
      if (!els.length) { clearInterval(quotaTimer); return; }
      let done = false;
      els.forEach(el => { const left = +el.dataset.until - Date.now(); if (left <= 0) done = true; else el.textContent = fmtWait(left); });
      if (done) { clearInterval(quotaTimer); render(); }
    }, 1000);
  }

  const SMILE = svg('<circle cx="12" cy="12" r="8.5"/><path d="M8.5 14c.9 1.3 2.1 2 3.5 2s2.6-.7 3.5-2"/><circle cx="9.3" cy="10" r=".7" fill="currentColor"/><circle cx="14.7" cy="10" r=".7" fill="currentColor"/>');
  const QUICK = '👍 ❤️ 😂 🔥 😮 😢 💨 🎉';
  const EMOJI = [
    [['Эмоции', 'Feelings'], '😀 😂 🥲 😍 😎 🤩 🥳 😏 😴 🤔 😮 😢 😡 🤯 🥶 🤤'],
    [['Жесты', 'Gestures'], '👍 👎 👏 🙌 🙏 🤝 💪 ✌️ 👌 🤙 👀 💯'],
    [['Вкусы и кальян', 'Flavours & hookah'], '💨 🔥 🧊 ❄️ 🍉 🍒 🍋 🍏 🍎 🍌 🥭 🍇 🫐 🍓 🍐 🥥 🍹 ☕'],
    [['Праздник', 'Party'], '🎉 🎂 🎁 🎃 🎄 ✨ ❤️ 🖤 🌙 ⭐']
  ];
  // Реакции: один смайлик от человека на сообщение. Тот же смайлик ещё раз — реакция снимается.
  function reactionsHtml(c, scope, eventId, u) {
    const by = {};
    Object.entries(c.reactions || {}).forEach(([who, em]) => (by[em] ||= []).push(who));
    const chips = Object.entries(by).sort((a, b) => b[1].length - a[1].length).map(([em, ids]) => {
      const mine = !!u && ids.includes(u.id), names = ids.map(i => userById(i)?.name).filter(Boolean).join(', ');
      return `<button type="button" class="react-chip ${mine ? 'on' : ''}" data-action="react" data-scope="${scope}" data-id="${eventId}" data-comment="${c.id}" data-emoji="${em}" title="${esc(names)}" aria-pressed="${mine}"><span>${em}</span><b>${ids.length}</b></button>`;
    }).join('');
    if (!chips && !u) return '';
    return `<div class="reacts">${chips}${u ? `<button type="button" class="react-add" data-action="reactPick" data-scope="${scope}" data-id="${eventId}" data-comment="${c.id}" data-pop-anchor aria-label="${L('Поставить реакцию', 'Add a reaction')}" title="${L('Реакция', 'Reaction')}">${SMILE}<span>+</span></button>` : ''}</div>`;
  }
  function commentItem(c, { scope, eventId, u, canDelete, delAction }) {
    const p = userById(c.userId);
    return `<li class="comment">${avatar(p, 'sm')}<div class="comment-body"><div class="comment-head"><b>${esc(p?.name || '—')}</b><small>${timeAgo(c.at)}</small>
      ${canDelete ? `<button class="link-btn danger" type="button" data-action="${delAction}" data-id="${eventId}" data-comment="${c.id}">${L('Удалить', 'Delete')}</button>` : ''}</div>
      <p>${esc(c.text)}</p>${reactionsHtml(c, scope, eventId, u)}</div></li>`;
  }
  function setReaction(scope, eventId, commentId, em) {
    const u = me(), e = eventById(eventId); if (!u || !e) return;
    const c = (scope === 'story' ? e.story?.comments : e.comments)?.find(x => x.id === commentId); if (!c) return;
    act(() => { c.reactions ||= {}; if (c.reactions[u.id] === em) delete c.reactions[u.id]; else c.reactions[u.id] = em; }, 'PUT', `/comments/${commentId}/reaction`, { emoji: em })
      .then(() => render(), quiet);
  }
  // Панель смайликов: для реакции и для вставки в текст сообщения.
  let pop = null;
  function closePop() { pop?.remove(); pop = null; }
  function openEmojiPop(anchor, groups, onPick, key) {
    if (pop && pop.dataset.key === key) { closePop(); return; }
    closePop();
    pop = document.createElement('div');
    pop.className = 'emoji-pop'; pop.dataset.key = key; pop.setAttribute('role', 'dialog'); pop.setAttribute('aria-label', L('Смайлики', 'Emoji'));
    pop.innerHTML = groups.map(([title, list]) => `${title ? `<div class="ep-title">${tr(title)}</div>` : ''}<div class="ep-grid">${list.split(' ').map(em => `<button type="button" data-e="${em}" aria-label="${em}">${em}</button>`).join('')}</div>`).join('');
    document.body.append(pop);
    const r = anchor.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
    const left = Math.max(8, Math.min(r.left + r.width / 2 - pw / 2, window.innerWidth - pw - 8));
    let top = r.top - ph - 8;
    if (top < 70) top = r.bottom + 8;
    pop.style.left = left + window.scrollX + 'px'; pop.style.top = top + window.scrollY + 'px';
    pop.addEventListener('click', ev => { const b = ev.target.closest('[data-e]'); if (b) { const em = b.dataset.e; closePop(); onPick(em); } });
  }
  document.addEventListener('mousedown', ev => { if (pop && !pop.contains(ev.target) && !ev.target.closest('[data-pop-anchor]')) closePop(); });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closePop(); });
  window.addEventListener('hashchange', closePop);
  function insertAtCursor(ta, text) {
    if (!ta || ta.disabled) return;
    const s = ta.selectionStart ?? ta.value.length, en = ta.selectionEnd ?? s;
    ta.value = ta.value.slice(0, s) + text + ta.value.slice(en);
    ta.focus(); ta.selectionStart = ta.selectionEnd = s + text.length;
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  }

  // ---------- История ----------
  // Прошедшие вечера с рассказом организатора. Комментировать вечер можно раз в день.
  const sameDay = (a, b) => ymd(new Date(a)) === ymd(new Date(b));
  const myStoryCommentToday = (e, u) => !!u && (e.story?.comments || []).some(c => c.userId === u.id && sameDay(c.at, Date.now()));
  function untilTomorrow() {
    const t = new Date(); t.setHours(24, 0, 0, 0);
    const m = Math.ceil((t - Date.now()) / 60000), h = Math.floor(m / 60);
    return h ? L(`${h} ч ${m % 60} мин`, `${h} h ${m % 60} min`) : L(`${m} мин`, `${m} min`);
  }
  const storyEvents = () => db.events.filter(e => e.story && isPast(e)).sort((a, b) => new Date(b.at) - new Date(a.at));

  function storyCard(e, u) {
    const st = e.story, host = userById(e.hostId), going = goingIds(e), b = bill(e), v = eventVenue(e);
    const top = ranking(e.picks, tobaccoName).slice(0, 3).map(r => ({ t: tobacco(r.id), n: r.users.length })).filter(x => x.t);
    const bw = ranking(e.bowls, bowlName)[0], fired = !!u && st.fire.includes(u.id), d = new Date(e.at);
    const commented = myStoryCommentToday(e, u);
    return `<article class="story" id="story-${e.id}">
      <div class="story-rail"><span class="story-dot"></span></div>
      <div class="story-card">
        <div class="story-cover cols-${top.length || 1}">
          ${top.map((x, i) => `<div class="story-shot">${window.HP_ART ? HP_ART.flavor(x.t) : ''}<span class="story-shot-tag">${i === 0 ? `<b>${L('Лидер вечера', 'Top pick')}</b>` : ''}${esc(x.t.brand)} ${esc(x.t.flavor)}</span></div>`).join('')}
          <div class="story-date"><b>${fDay(d)}</b><span>${fMon(d)}</span></div>
        </div>
        <div class="story-main">
          <div class="story-head">
            <div><h3>${esc(e.title)}</h3>
              <div class="story-meta">
                ${v ? `<button class="link-btn" type="button" data-action="showVenue" data-vid="${v.id}">${ICON.pin}${esc(e.venue)}</button>` : `<span>${ICON.pin}${esc(e.venue)}</span>`}
                <span>${avatar(host, 'xs')}${L('организатор', 'host')} ${esc(host?.name || '')}</span>
              </div></div>
            <div class="story-score" aria-label="${L('Оценка вечера', 'Evening rating')} ${st.rating} / 5">${stars(st.rating)}<small>${L('вечер', 'evening')} ${st.rating}/5</small></div>
          </div>
          <p class="story-text">${esc(st.text)}</p>
          ${st.highlights?.length ? `<ul class="story-highlights">${st.highlights.map(h => `<li>${esc(h)}</li>`).join('')}</ul>` : ''}
          <div class="story-facts">
            <span>${avatarStack(going, 6, 'xs')}${going.length} ${pl(going.length, ['гость', 'гостя', 'гостей'], ['guest', 'guests'])}</span>
            ${e.hookahs ? `<span>${ICON.hookah}${e.hookahs} ${pl(e.hookahs, ['кальян', 'кальяна', 'кальянов'], ['hookah', 'hookahs'])}</span>` : ''}
            ${bw ? `<span>${tr(BOWL_TYPE[bowl(bw.id)?.type] || ['', ''])}: ${esc(bowlName(bw.id))}</span>` : ''}
            ${b.total ? `<span>${ICON.wallet}${money(b.per)} ${L('с человека', 'per person')}</span>` : ''}
          </div>
          <div class="story-actions">
            <button class="react-btn ${fired ? 'on' : ''}" type="button" data-action="storyFire" data-id="${e.id}" aria-pressed="${fired}">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22c4.4 0 7-2.8 7-6.6 0-3.4-2.2-5.6-3.6-7.2-.3 1.8-1.3 3-2.4 3.4.6-3.6-1-6.8-4-9.1.2 3-1.5 5-3 6.8C4.7 11 5 12.5 5 15.4 5 19.2 7.6 22 12 22z"/></svg>
              <span>${L('Огонь', 'Fire')}</span><b>${st.fire.length}</b></button>
            <button class="btn btn-sm" type="button" data-action="likeThis" data-id="${e.id}">${ICON.repeat}${L('Хочу так же', 'I want this too')}</button>
            <span class="muted story-count">${ICON.chat}${st.comments.length}</span>
          </div>
          <section class="story-comments">
            ${st.comments.length ? `<ul class="comments">${st.comments.map(c => commentItem(c, { scope: 'story', eventId: e.id, u, canDelete: !!u && c.userId === u.id, delAction: 'deleteStoryComment' })).join('')}</ul>` : ''}
            ${!u ? `<p class="muted story-limit"><a href="#/login" style="color:var(--accent)">${L('Войдите', 'Sign in')}</a>${L(', чтобы оставить комментарий.', ' to leave a comment.')}</p>`
              : commented ? `<p class="story-limit">${ICON.clock}${L(`Вы уже комментировали этот вечер сегодня. Следующий комментарий можно оставить через ${untilTomorrow()}.`, `You have already commented on this evening today. You can comment again in ${untilTomorrow()}.`)}</p>`
              : `<form class="comment-form story-form" data-story="${e.id}">
                  ${avatar(u, 'sm')}<div class="cf-box"><textarea rows="1" maxlength="300" placeholder="${L('Как вам вечер? Один комментарий в день', 'How was it? One comment per day')}" aria-label="${L('Комментарий', 'Comment')}"></textarea>
                  <button type="button" class="emoji-btn" data-action="emoji" data-pop-anchor aria-label="${L('Смайлики', 'Emoji')}">${SMILE}</button></div>
                  <button class="btn btn-primary btn-sm" type="submit">${L('Отправить', 'Send')}</button></form>`}
          </section>
        </div>
      </div>
    </article>`;
  }

  function pageHistory() {
    const u = me(), all = storyEvents();
    const items = [{ key: 'all', label: L('Все вечера', 'All evenings'), count: all.length }];
    if (u) items.push({ key: 'mine', label: L('Мои', 'Mine'), count: all.filter(e => isMember(e, u)).length }, { key: 'friends', label: L('Друзей', 'Friends'), count: all.filter(e => goingIds(e).some(id => u.friends.includes(id))).length });
    const key = tab.history = items.some(i => i.key === tab.history) ? tab.history : 'all';
    const list = key === 'mine' ? all.filter(e => isMember(e, u)) : key === 'friends' ? all.filter(e => goingIds(e).some(id => u.friends.includes(id))) : all;
    const guests = all.reduce((s, e) => s + goingIds(e).length, 0), hookahs = all.reduce((s, e) => s + (e.hookahs || 0), 0);
    const favCount = {};
    all.forEach(e => ranking(e.picks, tobaccoName).forEach(r => { favCount[r.id] = (favCount[r.id] || 0) + r.users.length; }));
    const fav = Object.entries(favCount).sort((a, b) => b[1] - a[1])[0];
    let body = '', month = '';
    for (const e of list) {
      const m = fMonthYear(new Date(e.at));
      if (m !== month) { body += `<h3 class="story-month">${m}</h3>`; month = m; }
      body += storyCard(e, u);
    }
    view.innerHTML = `
      <section class="history-hero">
        <div><span class="eyebrow">${L('История', 'History')}</span><h1>${L('Как проходили наши вечера', 'How our evenings went')}</h1>
          <p class="lead">${L('Рассказы организаторов о прошедших сборах: где были, что курили и что запомнилось. Ставьте огонь любимым вечерам и делитесь впечатлениями.', 'Hosts’ stories about past meet-ups: where they went, what they smoked and what they remember. Give your favourite evenings some fire and share your thoughts.')}</p></div>
        <div class="history-stats">
          <div><b>${all.length}</b><span>${pl(all.length, ['вечер', 'вечера', 'вечеров'], ['evening', 'evenings'])}</span></div>
          <div><b>${guests}</b><span>${pl(guests, ['гость', 'гостя', 'гостей'], ['guest', 'guests'])}</span></div>
          <div><b>${hookahs}</b><span>${pl(hookahs, ['кальян', 'кальяна', 'кальянов'], ['hookah', 'hookahs'])}</span></div>
          ${fav ? `<div class="hs-fav">${window.HP_ART ? `<span class="flavor-thumb">${HP_ART.flavor(tobacco(fav[0]), { thumb: true })}</span>` : ''}<span>${L('Любимый табак', 'Favourite tobacco')}<b>${esc(tobaccoName(fav[0]))}</b></span></div>` : ''}
        </div>
      </section>
      ${uTabs('history', items)}
      ${tabPanel('history', list.length ? `<div class="timeline">${body}</div>` : emptyState(L('Здесь пока пусто', 'Nothing here yet'), key === 'mine' ? L('После сбора расскажите, как всё прошло: кнопка появится на странице прошедшего сбора.', 'After an event, tell everyone how it went: the button appears on the past event page.') : L('Когда друзья поделятся рассказами о вечерах, они появятся здесь.', 'When friends share stories about their evenings, they will appear here.')))}`;
    $$('.story-form').forEach(f => {
      const ta = $('textarea', f);
      ta.addEventListener('input', () => { ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; });
      f.addEventListener('submit', ev => {
        ev.preventDefault();
        const e = eventById(f.dataset.story), text = clean(ta.value, 300, true);
        if (!e || !text) return;
        if (myStoryCommentToday(e, u)) { toast(L('Сегодня вы уже комментировали этот вечер', 'You have already commented on this evening today'), 'err'); return; }
        if (myRecentMessages(u).length >= LIMITS.global) { toast(L(`Лимит: ${LIMITS.global} ${plural(LIMITS.global, 'сообщение', 'сообщения', 'сообщений')} за 7 часов. Попробуйте позже.`, `Limit: ${LIMITS.global} messages per 7 hours. Try again later.`), 'err'); return; }
        act(() => { e.story.comments.push({ id: uid('sc'), userId: u.id, text, at: new Date().toISOString(), reactions: {} }); }, 'POST', `/events/${e.id}/story/comments`, { text })
          .then(() => { toast(L('Комментарий опубликован', 'Comment published')); render(); }, quiet);
      });
    });
  }

  // Форма рассказа о прошедшем сборе — для организатора.
  function storyFormHtml(e) {
    return `<section class="panel story-compose">
      <div class="panel-head"><div><h2>${L('Расскажите, как прошло', 'Tell everyone how it went')}</h2>
        <p class="muted" style="font-size:13.5px;margin-top:4px">${L('Рассказ появится в «Истории», его смогут прочитать и прокомментировать.', 'The story will appear in History where people can read and comment on it.')}</p></div></div>
      <form class="form" id="story-form">
        <div class="field"><span class="label">${L('Оценка вечера', 'Evening rating')}</span>
          <div class="star-input" role="radiogroup" aria-label="${L('Оценка вечера', 'Evening rating')}">${[5, 4, 3, 2, 1].map(n => `<input type="radio" name="st-star" id="st-s${n}" value="${n}"><label for="st-s${n}" title="${n} / 5">★</label>`).join('')}</div></div>
        <div class="field"><label for="st-text">${L('Рассказ', 'Story')}</label><textarea id="st-text" maxlength="600" placeholder="${L('Что курили, как было в заведении, что запомнилось', 'What you smoked, how the place was, what you remember')}"></textarea></div>
        <div class="field"><label for="st-hl">${L('Яркие моменты', 'Highlights')} <span class="muted">(${L('каждый с новой строки, до 3', 'one per line, up to 3')})</span></label><textarea id="st-hl" maxlength="300" rows="3" placeholder="${L('Например: лучший микс вечера', 'For example: best mix of the night')}"></textarea></div>
        <div class="error" id="st-err"></div>
        <div><button class="btn btn-primary" type="submit">${L('Опубликовать в Истории', 'Publish to History')}</button></div>
      </form>
    </section>`;
  }

  // ---------- Уведомления ----------
  // На сервере уведомления создаёт сам сервер. В демо-режиме они собираются из данных в браузере.
  const NOTIF_GROUPS = {
    invites: { types: ['invite', 'cancelled', 'admin_removed_event'], label: ['Приглашения', 'Invitations'] },
    replies: { types: ['rsvp_going', 'rsvp_declined'], label: ['Ответы', 'Replies'] },
    messages: { types: ['comment', 'story_comment', 'admin_removed_comment'], label: ['Сообщения', 'Messages'] },
    reactions: { types: ['reaction', 'fire', 'friend'], label: ['Реакции и друзья', 'Reactions & friends'] }
  };
  const groupOf = type => Object.keys(NOTIF_GROUPS).find(g => NOTIF_GROUPS[g].types.includes(type));
  const notifOff = () => secRead('hp.notifOff', []);
  function findComment(ref) {
    const cid = String(ref || '').split(':')[0];
    for (const e of db.events) for (const c of [...(e.comments || []), ...(e.story?.comments || [])]) if (c.id === cid) return c;
    return null;
  }
  function demoNotifs(u) {
    const out = [], push = (id, type, actorId, eventId, ref, at) => at && actorId !== u.id && out.push({ id, type, actorId, eventId, ref, at });
    for (const e of db.events) {
      const inv = myInvite(e, u);
      if (inv && inv.status === 'pending' && !isPast(e)) push('inv:' + e.id, 'invite', e.hostId, e.id, null, e.createdAt || e.at);
      if (e.hostId === u.id) for (const i of e.invites) if (i.userId && i.at && i.status !== 'pending') push(`rsvp:${e.id}:${i.userId}:${i.status}`, i.status === 'going' ? 'rsvp_going' : 'rsvp_declined', i.userId, e.id, null, i.at);
      if (isMember(e, u)) for (const c of e.comments) push('c:' + c.id, 'comment', c.userId, e.id, c.id, c.at);
      for (const c of [...e.comments, ...(e.story?.comments || [])]) if (c.userId === u.id) for (const [who, em] of Object.entries(c.reactions || {})) push(`r:${c.id}:${who}`, 'reaction', who, e.id, `${c.id}:${em}`, c.at);
      if (e.story && e.hostId === u.id) {
        for (const c of e.story.comments) push('sc:' + c.id, 'story_comment', c.userId, e.id, c.id, c.at);
        for (const who of e.story.fire) push(`f:${e.id}:${who}`, 'fire', who, e.id, null, e.story.at);
      }
    }
    const read = new Set(secRead('hp.notifRead', []));
    // Всё старше недели в демо считаем прочитанным, чтобы счётчик не пугал.
    return out.map(n => ({ ...n, read: read.has(n.id) || Date.now() - new Date(n.at) > 7 * 864e5 }));
  }
  function notifications(u = me()) {
    if (!u) return [];
    const list = SERVER ? (db.notifications || []) : demoNotifs(u), off = new Set(notifOff());
    return list.filter(n => !off.has(groupOf(n.type))).sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 100);
  }
  const unreadCount = () => notifications().filter(n => !n.read).length;
  function notifText(n) {
    const who = `<b>${esc(userById(n.actorId)?.name || L('Кто-то', 'Someone'))}</b>`, e = eventById(n.eventId);
    const ev = e ? `«${esc(e.title)}»` : n.ref && n.type === 'cancelled' ? `«${esc(n.ref)}»` : L('сбор', 'an event');
    const c = ['comment', 'story_comment', 'reaction'].includes(n.type) ? findComment(n.ref) : null;
    const snip = c ? `<span class="nt-quote">${esc(c.text.length > 70 ? c.text.slice(0, 70) + '…' : c.text)}</span>` : '';
    return {
      invite: L(`${who} зовёт вас на ${ev}`, `${who} invites you to ${ev}`),
      cancelled: L(`${who} отменяет сбор ${ev}`, `${who} cancelled ${ev}`),
      rsvp_going: L(`${who} идёт на ${ev}`, `${who} is going to ${ev}`),
      rsvp_declined: L(`${who} не сможет прийти на ${ev}`, `${who} can’t make it to ${ev}`),
      comment: L(`${who} в ${ev}: `, `${who} in ${ev}: `) + snip,
      story_comment: L(`${who} комментирует ваш вечер ${ev}: `, `${who} commented on your evening ${ev}: `) + snip,
      reaction: L(`${who} реагирует ${String(n.ref || '').split(':')[1] || ''} на ваше сообщение `, `${who} reacted ${String(n.ref || '').split(':')[1] || ''} to your message `) + snip,
      fire: L(`${who} ставит огонь вашему вечеру ${ev}`, `${who} gave your evening ${ev} some fire`),
      friend: L(`${who} добавляет вас в друзья`, `${who} added you as a friend`),
      admin_removed_event: L(`Администратор удалил сбор «${esc(n.ref || '')}»`, `An administrator removed the event “${esc(n.ref || '')}”`),
      admin_removed_comment: L(`Администратор удалил ваше сообщение «${esc(n.ref || '')}»`, `An administrator removed your message “${esc(n.ref || '')}”`)
    }[n.type] || esc(n.type);
  }
  const notifHref = n => n.type === 'friend' ? `#/user/${n.actorId}` : n.type === 'story_comment' || n.type === 'fire' ? '#/history' : n.eventId && eventById(n.eventId) ? `#/event/${n.eventId}` : '#/events';
  const NOTIF_ICON = { admin_removed_event: 'shield', admin_removed_comment: 'shield', invite: 'mail', cancelled: 'x', rsvp_going: 'check', rsvp_declined: 'x', comment: 'chat', story_comment: 'chat', reaction: 'heart', fire: 'smoke', friend: 'users' };
  function notifItem(n) {
    return `<li><button type="button" class="notif ${n.read ? '' : 'unread'}" data-action="openNotif" data-id="${esc(n.id)}" data-href="${esc(notifHref(n))}" data-story="${n.type === 'story_comment' || n.type === 'fire' ? esc(n.eventId || '') : ''}">
      <span class="feed-av">${avatar(userById(n.actorId), 'sm')}<span class="feed-ic ic-${NOTIF_ICON[n.type] || 'chat'} nt-${groupOf(n.type)}">${ICON[NOTIF_ICON[n.type]] || ICON.chat}</span></span>
      <span class="notif-text">${notifText(n)}<time>${timeAgo(n.at)}</time></span>${n.read ? '' : '<i class="notif-dot" aria-label="' + L('Новое', 'New') + '"></i>'}</button></li>`;
  }
  async function markRead(ids) {
    if (!ids.length) return;
    if (SERVER) { await act(null, 'POST', '/notifications/read', ids === 'all' ? { all: true } : { ids }).catch(() => {}); return; }
    const all = ids === 'all' ? notifications().map(n => n.id) : ids;
    secWrite('hp.notifRead', [...new Set([...secRead('hp.notifRead', []), ...all])].slice(-500));
  }

  function pageNotifications() {
    const u = me();
    if (!u) return go('login');
    const all = notifications(u), off = new Set(notifOff());
    const items = [{ key: 'all', label: L('Все', 'All'), count: all.filter(n => !n.read).length, alert: all.some(n => !n.read) }]
      .concat(Object.entries(NOTIF_GROUPS).filter(([g]) => !off.has(g)).map(([g, d]) => ({ key: g, label: tr(d.label), count: all.filter(n => groupOf(n.type) === g && !n.read).length })));
    tab.notif = items.some(i => i.key === tab.notif) ? tab.notif : 'all';
    const list = tab.notif === 'all' ? all : all.filter(n => groupOf(n.type) === tab.notif);
    const dayKey = iso => { const d = new Date(iso); d.setHours(0, 0, 0, 0); return d.getTime(); };
    const today = dayKey(Date.now()), dayLabel = k => k === today ? L('Сегодня', 'Today') : k === today - 864e5 ? L('Вчера', 'Yesterday') : fShort(new Date(k));
    let body = '', last = null;
    for (const n of list) {
      const k = dayKey(n.at);
      if (k !== last) { body += `${last === null ? '' : '</ul>'}<h4 class="feed-day">${dayLabel(k)}</h4><ul class="notif-list">`; last = k; }
      body += notifItem(n);
    }
    if (body) body += '</ul>';
    const unread = all.filter(n => !n.read).length;
    view.innerHTML = `
      <section class="greet-line"><div><span class="eyebrow">${L('Уведомления', 'Notifications')}</span><h1>${unread ? L(`${unread} ${plural(unread, 'новое', 'новых', 'новых')}`, `${unread} new`) : L('Всё прочитано', 'All caught up')}</h1></div>
        ${unread ? `<button class="btn btn-sm" type="button" data-action="readAll">${ICON.check}${L('Отметить всё прочитанным', 'Mark all as read')}</button>` : ''}</section>
      ${uTabs('notif', items)}
      ${tabPanel('notif', `${body || emptyState(L('Здесь пока пусто', 'Nothing here yet'), L('Сюда придут приглашения, ответы друзей, сообщения в ваших сборах и реакции на них.', 'Invitations, replies, messages in your events and reactions will show up here.'), `<a class="btn btn-sm" href="#/events">${L('К сборам', 'To events')}</a>`)}
        <section class="panel notif-settings"><div class="panel-head"><div><h2>${L('Что показывать', 'What to show')}</h2>
          <p class="muted" style="font-size:13.5px;margin-top:4px">${L('Выключенные типы не попадают в список и счётчик на колокольчике.', 'Hidden types are left out of the list and the bell counter.')}</p></div></div>
          <div class="switches">${Object.entries(NOTIF_GROUPS).map(([g, d]) => `<label class="switch"><input type="checkbox" data-notif-group="${g}" ${off.has(g) ? '' : 'checked'}><span class="sw-track"><span></span></span>${tr(d.label)}</label>`).join('')}</div>
        </section>`)}`;
    $$('[data-notif-group]').forEach(cb => cb.addEventListener('change', () => {
      const set = new Set(notifOff()); cb.checked ? set.delete(cb.dataset.notifGroup) : set.add(cb.dataset.notifGroup);
      secWrite('hp.notifOff', [...set]); render();
    }));
  }

  // Колокольчик в шапке: быстрый список последних уведомлений.
  function bellHtml() {
    const n = unreadCount();
    return `<button class="icon-btn bell ${n ? 'has' : ''}" type="button" data-action="bell" data-pop-anchor aria-label="${L('Уведомления', 'Notifications')}${n ? ': ' + n : ''}" aria-haspopup="dialog">
      ${svg('<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20.5h4"/>')}${n ? `<span class="bell-badge">${n > 99 ? '99+' : n}</span>` : ''}</button>`;
  }
  function openBell(anchor) {
    if (pop && pop.dataset.key === 'bell') { closePop(); return; }
    closePop();
    const list = notifications().slice(0, 6);
    pop = document.createElement('div');
    pop.className = 'bell-pop'; pop.dataset.key = 'bell'; pop.setAttribute('role', 'dialog'); pop.setAttribute('aria-label', L('Уведомления', 'Notifications'));
    pop.innerHTML = `<div class="bell-head"><b>${L('Уведомления', 'Notifications')}</b>${unreadCount() ? `<button class="link-btn" type="button" data-action="readAll">${L('Прочитать всё', 'Mark all read')}</button>` : ''}</div>
      ${list.length ? `<ul class="notif-list">${list.map(notifItem).join('')}</ul>` : `<p class="muted" style="padding:10px 4px">${L('Новых уведомлений нет.', 'No new notifications.')}</p>`}
      <a class="btn btn-sm bell-all" href="#/notifications">${L('Все уведомления', 'All notifications')} →</a>`;
    document.body.append(pop);
    const r = anchor.getBoundingClientRect();
    pop.style.left = Math.max(8, Math.min(r.right - pop.offsetWidth, window.innerWidth - pop.offsetWidth - 8)) + window.scrollX + 'px';
    pop.style.top = r.bottom + 8 + window.scrollY + 'px';
  }
  function updateTitle() { const n = me() ? unreadCount() : 0; document.title = n ? `(${n}) Hookah Party` : 'Hookah Party'; }

  // ---------- Администратор ----------
  // Код панели лежит в отдельном файле admin.js. На сервере его получает только вошедший администратор,
  // а каждое действие сервер ещё раз проверяет (роль + подтверждение паролем).
  const isAdmin = () => !!me() && (SERVER ? db.role === 'admin' : me().role === 'admin');
  const ADMIN_V = 23;
  let adminLoading = null;
  function loadAdmin() {
    if (window.HP_ADMIN) return Promise.resolve(window.HP_ADMIN);
    return adminLoading ||= new Promise((resolve, reject) => {
      const sc = document.createElement('script');
      sc.src = `admin.js?v=${ADMIN_V}`;
      sc.onload = () => window.HP_ADMIN ? resolve(window.HP_ADMIN) : reject(new Error('admin'));
      sc.onerror = () => { adminLoading = null; reject(new Error('admin')); };
      document.body.append(sc);
    });
  }
  function pageAdmin() {
    if (!isAdmin()) { view.innerHTML = emptyState(L('Такой страницы нет', 'Page not found'), L('Возможно, ссылка устарела или в ней опечатка.', 'The link may be outdated or contain a typo.'), `<a class="btn btn-primary btn-sm" href="#/">${L('На главную', 'Go home')}</a>`); return; }
    view.innerHTML = `<p class="muted">${L('Загружаем панель…', 'Loading the panel…')}</p>`;
    loadAdmin().then(A => {
      if (location.hash !== '#/admin') return;
      A.render({ view, L, esc, api, apiMsg, act, SERVER, getDb: () => db, setDb: applyData, save, me, userById, eventById, toast, openModal, closeModal, uTabs, tabPanel, tab, emptyState, avatar, fShort, fTime, timeAgo, plural, pl, ICON, secRead, secLog, checkPass, render, isPast, SEC_EVENTS });
      inkAll();
    }).catch(() => { view.innerHTML = emptyState(L('Панель недоступна', 'Panel unavailable'), L('Не удалось загрузить панель администратора. Обновите страницу.', 'Could not load the admin panel. Reload the page.')); });
  }

  // ---------- Каталог ----------
  const cat = { q: '', strength: 'all', tag: '', sort: 'rating' };
  let favPop = null; // только что добавленный в избранное — для анимации сердечка
  const strengthBar = s => `<div class="strength"><div class="strength-bar">${Array.from({ length: 10 }, (_, i) => `<i class="${i < s ? 'on' : ''} ${i < s && i >= 7 ? 'hot' : ''}"></i>`).join('')}</div><small>${L('Крепость', 'Strength')} ${s}/10</small></div>`;
  const reviewsWord = n => pl(n, ['отзыв', 'отзыва', 'отзывов'], ['review', 'reviews']);
  function tobaccoCard(t, u) {
    const r = ratingOf(t.id), fav = !!u && u.favs.includes(t.id);
    return `<article class="cat-card t-card" data-action="tobacco" data-id="${t.id}" role="button" tabindex="0" aria-label="${esc(t.brand + ' ' + t.flavor)}">
      ${packArt(t)}
      <div class="cat-top"><span class="cat-brand">${esc(t.brand)}</span>
        ${u ? `<button class="fav-btn ${fav ? 'on' : ''} ${favPop === t.id ? 'pop' : ''}" type="button" data-action="fav" data-id="${t.id}" aria-pressed="${fav}">${ICON.heart}<span>${fav ? L('В избранном', 'Favourite') : L('В избранное', 'Add to favourites')}</span></button>` : ''}</div>
      <h3>${esc(t.flavor)}</h3><p>${esc(tr(t.note))}</p>
      <div class="rating-line">${stars(r.avg)}<small>${r.n ? `${r.avg.toFixed(1)} · ${r.n} ${reviewsWord(r.n)}` : L('Нет отзывов', 'No reviews')}</small></div>
      ${strengthBar(t.strength)}
      <div class="cat-tags">${t.tags.map(x => `<span class="chip">${esc(tagName(x))}</span>`).join('')}</div>
    </article>`;
  }
  function mixCard(m, u) {
    const author = userById(m.authorId), liked = !!u && m.likes.includes(u.id);
    return `<article class="cat-card mix-card">
      <div class="cat-top"><span class="cat-brand">${L('Микс', 'Mix')} · ${m.parts.length} ${pl(m.parts.length, ['вкус', 'вкуса', 'вкусов'], ['flavour', 'flavours'])}</span>
        <button class="like-btn ${liked ? 'on' : ''}" type="button" data-action="likeMix" data-id="${m.id}" aria-pressed="${liked}" aria-label="${L('Нравится', 'Like')}">${ICON.heart}<span>${m.likes.length}</span></button></div>
      <h3>${esc(m.name)}</h3>
      <div class="mix-bar">${m.parts.map(p => `<span style="flex:${p.pct};--pc:${tobacco(p.id)?.color || 'gray'}" title="${esc(tobaccoName(p.id))} ${p.pct}%"></span>`).join('')}</div>
      <ul class="mix-legend">${m.parts.map(p => `<li><i style="--pc:${tobacco(p.id)?.color || 'gray'}"></i><span>${esc(tobaccoName(p.id))}</span><b class="mono">${p.pct}%</b></li>`).join('')}</ul>
      <div class="ev-venue">${avatar(author, 'xs')}<span>${esc(author?.name || '—')}</span></div>
    </article>`;
  }

  function pageCatalog() {
    const u = me();
    view.innerHTML = `
      <section class="section"><span class="eyebrow">${L('Кальян', 'Hookah')}</span><h1>${L('Табаки, миксы и всё для кальяна', 'Tobacco, mixes and hookah gear')}</h1></section>
      ${uTabs('cat', [
        { key: 'tobaccos', label: L('Табаки', 'Tobacco'), count: CATALOG.tobaccos.length }, { key: 'mixes', label: L('Миксы', 'Mixes'), count: db.mixes.length },
        { key: 'bowls', label: L('Чаши', 'Bowls'), count: CATALOG.bowls.length }, { key: 'gear', label: L('Аксессуары', 'Accessories'), count: CATALOG.gear.length }
      ])}
      ${tabPanel('cat', `<div class="panel-tools">
        <input class="input" id="cat-q" type="search" placeholder="${tab.cat === 'mixes' ? L('Поиск по названию или табаку', 'Search by name or tobacco') : L('Поиск по бренду или вкусу', 'Search by brand or flavour')}" value="${esc(cat.q)}" aria-label="${L('Поиск', 'Search')}">
        ${tab.cat === 'mixes' ? `<button class="btn btn-primary btn-sm" data-action="newMix">+ ${L('Свой микс', 'Your mix')}</button>` : ''}
      </div>
      ${tab.cat === 'tobaccos' ? `<div class="filters">
        <div class="chip-row" role="group" aria-label="${L('Крепость', 'Strength')}">${Object.entries(STRENGTH).map(([k, [label]]) => `<button class="chip-btn ${cat.strength === k ? 'on' : ''}" data-action="catFilter" data-strength="${k}">${tr(label)}</button>`).join('')}</div>
        <div class="chip-row" role="group" aria-label="${L('Вкус', 'Flavour')}"><button class="chip-btn ${!cat.tag ? 'on' : ''}" data-action="catFilter" data-tag="">${L('Все вкусы', 'All flavours')}</button>${ALL_TAGS.map(x => `<button class="chip-btn ${cat.tag === x ? 'on' : ''}" data-action="catFilter" data-tag="${esc(x)}">${esc(tagName(x))}</button>`).join('')}</div>
        <label class="sort">${L('Сортировка', 'Sort')} <select id="cat-sort" class="input">
          <option value="rating" ${cat.sort === 'rating' ? 'selected' : ''}>${L('По рейтингу', 'By rating')}</option>
          <option value="name" ${cat.sort === 'name' ? 'selected' : ''}>${L('По названию', 'By name')}</option>
          <option value="strong" ${cat.sort === 'strong' ? 'selected' : ''}>${L('Сначала крепкие', 'Strongest first')}</option>
          <option value="light" ${cat.sort === 'light' ? 'selected' : ''}>${L('Сначала лёгкие', 'Lightest first')}</option></select></label>
      </div>` : ''}
      <div class="cat-grid" id="cat-grid"></div>`)}`;
    const grid = $('#cat-grid');
    const draw = () => {
      const q = cat.q.trim().toLowerCase();
      let html = '';
      if (tab.cat === 'tobaccos') {
        const [, lo, hi] = STRENGTH[cat.strength];
        const list = CATALOG.tobaccos
          .filter(t => (!q || `${t.brand} ${t.flavor} ${t.note.join(' ')} ${t.tags.map(x => x + ' ' + TAGS[x]).join(' ')}`.toLowerCase().includes(q)) && t.strength >= lo && t.strength <= hi && (!cat.tag || t.tags.includes(cat.tag)))
          .sort({
            rating: (a, b) => ratingOf(b.id).avg - ratingOf(a.id).avg || ratingOf(b.id).n - ratingOf(a.id).n,
            name: (a, b) => tobaccoName(a.id).localeCompare(tobaccoName(b.id), 'ru'),
            strong: (a, b) => b.strength - a.strength, light: (a, b) => a.strength - b.strength
          }[cat.sort]);
        html = list.map(t => tobaccoCard(t, u)).join('');
      } else if (tab.cat === 'mixes') {
        html = [...db.mixes].filter(m => !q || (m.name + ' ' + m.parts.map(p => tobaccoName(p.id)).join(' ')).toLowerCase().includes(q))
          .sort((a, b) => b.likes.length - a.likes.length).map(m => mixCard(m, u)).join('');
      } else if (tab.cat === 'bowls') {
        html = CATALOG.bowls.filter(x => !q || `${tr(x.name)} ${BOWL_TYPE[x.type].join(' ')} ${x.note.join(' ')}`.toLowerCase().includes(q)).map(x => `
          <article class="cat-card"><div class="art-tile">${bowlArt(x.type)}</div>
            <span class="cat-brand">${tr(BOWL_TYPE[x.type])}</span><h3>${esc(tr(x.name))}</h3><p>${esc(tr(x.note))}</p></article>`).join('');
      } else {
        html = CATALOG.gear.filter(x => !q || `${[].concat(x.name).join(' ')} ${x.type.join(' ')} ${x.note.join(' ')}`.toLowerCase().includes(q)).map(x => `
          <article class="cat-card"><div class="art-tile"><span class="art-word">${esc(tr(x.type))}</span></div>
            <span class="cat-brand">${esc(tr(x.type))}</span><h3>${esc(tr(x.name))}</h3><p>${esc(tr(x.note))}</p></article>`).join('');
      }
      grid.innerHTML = html || `<div style="grid-column:1/-1"><p class="muted">${L('Ничего не нашлось. Измените поиск или фильтры.', 'Nothing found. Change the search or filters.')}</p></div>`;
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
        <div class="t-info"><p>${esc(tr(t.note))}</p>${strengthBar(t.strength)}
          <div class="rating-line">${stars(r.avg, 'lg')}<small>${r.n ? `${r.avg.toFixed(1)} ${L('из 5', 'of 5')} · ${r.n} ${reviewsWord(r.n)}` : L('Отзывов пока нет', 'No reviews yet')}</small></div>
          <div class="cat-tags">${t.tags.map(x => `<span class="chip">${esc(tagName(x))}</span>`).join('')}</div>
          ${u ? `<div><button class="btn btn-sm fav-big ${fav ? 'btn-on on' : ''} ${favPop === t.id ? 'pop' : ''}" data-action="fav" data-id="${t.id}" aria-pressed="${fav}">${ICON.heart}${fav ? L('В избранном', 'In favourites') : L('В избранное', 'Add to favourites')}</button></div>` : ''}
        </div></div>
      ${inMixes.length ? `<div><span class="label">${L('Встречается в миксах', 'Used in mixes')}</span><div class="cat-tags" style="margin-top:6px">${inMixes.map(m => `<span class="chip chip-accent">${esc(m.name)}</span>`).join('')}</div></div>` : ''}
      ${u ? `<form class="form review-form" id="rv-form">
        <span class="label">${mine ? L('Ваш отзыв', 'Your review') : L('Оставить отзыв', 'Leave a review')}</span>
        <div class="star-input" role="radiogroup" aria-label="${L('Оценка', 'Rating')}">${[5, 4, 3, 2, 1].map(n => `<input type="radio" name="rv-star" id="rv-s${n}" value="${n}" ${mine?.rating === n ? 'checked' : ''}><label for="rv-s${n}" title="${n} / 5">★</label>`).join('')}</div>
        <div class="field"><textarea id="rv-text" maxlength="400" placeholder="${L('Как раскрывается, с чем мешать, на какой чаше лучше', 'How it smokes, what to mix it with, which bowl suits it')}">${esc(mine?.text || '')}</textarea></div>
        <div class="error" id="rv-err"></div>
        <div><button class="btn btn-primary btn-sm" type="submit">${mine ? L('Обновить отзыв', 'Update review') : L('Опубликовать', 'Publish')}</button></div>
      </form>` : `<p class="muted"><a href="#/login" style="color:var(--accent)">${L('Войдите', 'Sign in')}</a>${L(', чтобы оставить отзыв.', ' to leave a review.')}</p>`}
      <ul class="comments">${list.map(x => {
        const p = userById(x.userId);
        return `<li class="comment">${avatar(p, 'sm')}<div class="comment-body"><div class="comment-head"><b>${esc(p?.name || '—')}</b>${stars(x.rating)}<small>${timeAgo(x.at)}</small></div>${x.text ? `<p>${esc(x.text)}</p>` : ''}</div></li>`;
      }).join('')}</ul>`, m => {
      const f = $('#rv-form', m);
      f && f.addEventListener('submit', ev => {
        ev.preventDefault();
        const rating = +($('input[name=rv-star]:checked', m)?.value || 0);
        if (!rating) { $('#rv-err', m).textContent = L('Поставьте оценку от 1 до 5 звёзд.', 'Give a rating from 1 to 5 stars.'); return; }
        const text = clean($('#rv-text', m).value, 400, true);
        act(() => {
          if (mine) Object.assign(mine, { rating, text, at: new Date().toISOString() });
          else db.reviews.push({ id: uid('r'), tobaccoId: id, userId: u.id, rating, text, at: new Date().toISOString() });
        }, 'PUT', `/reviews/${id}`, { rating, text }).then(() => { toast(L('Спасибо за отзыв', 'Thanks for the review')); render(); openTobacco(id); }, quiet);
      });
    });
  }

  // ---------- Люди ----------
  const friendBtn = (p, friend) => `<button class="btn btn-sm ${friend ? 'btn-on' : 'btn-primary'}" data-action="toggleFriend" data-id="${p.id}" aria-pressed="${friend}">${friend ? `${ICON.check}${L('В друзьях', 'Friends')}` : `+ ${L('В друзья', 'Add friend')}`}</button>`;
  function personCard(p, u) {
    const shared = sharedEvents(u, p).length;
    return `<article class="person-card">
      <a class="person-link" href="#/user/${p.id}">${avatar(p)}<div class="person-name"><b>${esc(p.name)}</b>
        <small>${p.favVenue ? `${L('Любит', 'Likes')} ${esc(p.favVenue)}` : L('Любимое место не указано', 'No favourite place')}</small>
        <small>${shared ? `${shared} ${pl(shared, ['общий сбор', 'общих сбора', 'общих сборов'], ['shared event', 'shared events'])}` : L('Общих сборов нет', 'No shared events')}</small></div></a>
      ${friendBtn(p, isFriend(u, p))}
    </article>`;
  }
  let peopleQ = '';
  function pagePeople() {
    const u = me();
    if (!u) return go('login');
    const others = db.users.filter(p => p.id !== u.id);
    const friends = others.filter(p => isFriend(u, p));
    view.innerHTML = `
      <section class="section"><span class="eyebrow">${L('Люди', 'People')}</span><h1>${L('Друзья и знакомые', 'Friends and contacts')}</h1>
        <p class="muted">${L('Друзья первыми появляются в списке приглашений и видят ваш номер целиком.', 'Friends come first in the invite list and see your full number.')}</p></section>
      ${uTabs('people', [{ key: 'friends', label: L('Друзья', 'Friends'), count: friends.length }, { key: 'all', label: L('Все люди', 'Everyone'), count: others.length }])}
      ${tabPanel('people', `<div class="panel-tools"><input class="input" id="pp-q" type="search" placeholder="${L('Имя или номер', 'Name or number')}" value="${esc(peopleQ)}" aria-label="${L('Поиск людей', 'Search people')}"></div>
      <div class="people-grid" id="pp-grid"></div>`)}`;
    const draw = () => {
      const q = peopleQ.trim().toLowerCase(), qd = digits(q);
      const list = (tab.people === 'friends' ? friends : others).filter(p => !q || p.name.toLowerCase().includes(q) || (qd.length >= 4 && (p.phone || '').includes(qd)));
      $('#pp-grid').innerHTML = list.map(p => personCard(p, u)).join('') ||
        `<div style="grid-column:1/-1">${tab.people === 'friends' && !q ? emptyState(L('Друзей пока нет', 'No friends yet'), L('Откройте вкладку «Все люди» и добавьте тех, с кем ходите на кальян.', 'Open “Everyone” and add the people you go out with.'), `<button class="btn btn-primary btn-sm" data-action="switchTab" data-tabs="people" data-tab="all">${L('Все люди', 'Everyone')}</button>`) : `<p class="muted">${L('Никого не нашли.', 'Nobody found.')}</p>`}</div>`;
    };
    draw();
    $('#pp-q').addEventListener('input', ev => { peopleQ = ev.target.value; draw(); });
  }

  function pageUser(id) {
    const u = me();
    if (!u) return go('login');
    if (id === u.id) return go('profile');
    const p = userById(id);
    if (!p) { view.innerHTML = emptyState(L('Пользователь не найден', 'User not found'), '', `<a class="btn btn-sm" href="#/people">${L('К людям', 'To people')}</a>`); return; }
    const shared = sharedEvents(u, p).sort((a, b) => new Date(b.at) - new Date(a.at));
    const favs = p.favs.map(tobacco).filter(Boolean), mixes = db.mixes.filter(m => m.authorId === p.id);
    view.innerHTML = `
      <a class="back" href="#/people">← ${L('Люди', 'People')}</a>
      <div class="profile">
        <section class="panel profile-card">
          ${avatar(p, 'lg')}
          <div><h2>${esc(p.name)}</h2><div class="mono" style="margin-top:6px">${phoneShown(u, p)}</div>
            ${p.verified ? `<div class="verified" style="margin-top:6px">${ICON.check}${L('Номер подтверждён', 'Number verified')}</div>` : ''}</div>
          ${p.favVenue ? `<div class="fact" style="width:100%"><small>${L('Любимое место', 'Favourite place')}</small><b>${esc(p.favVenue)}</b></div>` : ''}
          <div class="btn-row" style="justify-content:center">${friendBtn(p, isFriend(u, p))}
            <button class="btn btn-sm" data-action="inviteUser" data-id="${p.id}">${L('Позвать на сбор', 'Invite to an event')}</button></div>
        </section>
        <div class="ev-main">
          <section class="panel"><div class="panel-head"><h2>${L('Любимые табаки', 'Favourite tobacco')}</h2></div>
            ${favs.length ? `<div class="cat-tags">${favs.map(t => `<button class="chip chip-accent" data-action="tobacco" data-id="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</button>`).join('')}</div>` : `<p class="muted">${L('Пока ничего не отмечено.', 'Nothing marked yet.')}</p>`}</section>
          ${mixes.length ? `<section class="panel"><div class="panel-head"><h2>${L('Миксы', 'Mixes')}</h2></div><div class="cat-grid">${mixes.map(m => mixCard(m, u)).join('')}</div></section>` : ''}
          <section class="panel"><div class="panel-head"><h2>${L('Общие сборы', 'Shared events')}</h2></div>
            ${shared.length ? `<div class="ev-grid">${shared.map(e => eventCard(e, u)).join('')}</div>` : `<p class="muted">${L('Вы ещё не были на одном сборе.', 'You have not been to the same event yet.')}</p>`}</section>
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
    const venues = [...new Set([...VENUES.map(v => v.name), ...db.events.map(e => e.venue)])];
    const theme = prefs.get('theme', 'auto'), accent = prefs.get('accent', 'copper'), seasonPref = prefs.get('season', 'auto');
    const panels = {
      about: `<section class="panel">
          <div class="panel-head"><h2>${L('Личные данные', 'Personal details')}</h2></div>
          <form class="form" id="profile-form">
            <div class="field"><label for="pf-name">${L('Имя', 'Name')}</label><input id="pf-name" required minlength="2" maxlength="40" value="${esc(u.name)}"></div>
            <div class="field"><label for="pf-venue">${L('Любимое заведение', 'Favourite venue')}</label><input id="pf-venue" maxlength="60" list="pf-venues" placeholder="${L('Где чаще всего собираетесь', 'Where you meet most often')}" value="${esc(u.favVenue)}">
              <datalist id="pf-venues">${venues.map(v => `<option value="${esc(v)}">`).join('')}</datalist></div>
            <div class="field"><span class="label">${L('Телефон', 'Phone')}</span><div class="input mono" style="opacity:.8">${fmtPhone(u.phone)}</div></div>
            <div class="error" id="pf-err"></div>
            <div><button class="btn btn-primary" type="submit">${L('Сохранить', 'Save')}</button></div>
          </form>
        </section>
        <section class="panel">
          <div class="panel-head"><h2>${L('Любимые табаки', 'Favourite tobacco')}</h2><a class="btn btn-sm" href="#/catalog">${L('Открыть каталог', 'Open catalogue')}</a></div>
          ${favs.length ? `<div class="cat-tags">${favs.map(t => `<button class="chip chip-accent" data-action="tobacco" data-id="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</button>`).join('')}</div>`
            : `<p class="muted">${L('Отмечайте вкусы сердечком в каталоге, и они появятся здесь.', 'Heart flavours in the catalogue and they will appear here.')}</p>`}
        </section>`,
      friends: `<section class="panel">
          <div class="panel-head"><h2>${L('Друзья', 'Friends')}</h2><a class="btn btn-sm" href="#/people">${L('Найти друзей', 'Find friends')}</a></div>
          ${friends.length ? `<div class="friend-row">${friends.map(f => `<a href="#/user/${f.id}" class="friend">${avatar(f)}<span>${esc(f.name)}</span></a>`).join('')}</div>` : `<p class="muted">${L('Добавьте друзей, чтобы быстрее звать их на сборы.', 'Add friends to invite them faster.')}</p>`}
        </section>`,
      history: `<section class="panel">
          <div class="panel-head"><h2>${L('История', 'History')}</h2></div>
          ${history.length ? `<ul class="history">${history.map(e => {
            const mine = (e.picks[u.id] || []).map(tobaccoName), top = ranking(e.picks, tobaccoName).slice(0, 2).map(r => tobaccoName(r.id));
            return `<li><a href="#/event/${e.id}"><span class="history-date mono">${fShort(new Date(e.at))}</span><span class="history-main"><b>${esc(e.title)}</b><small>${esc(e.venue)}</small></span>
              <span class="history-t">${mine.length ? `${L('Мой выбор', 'My pick')}: ${esc(mine.join(', '))}` : top.length ? `${L('Курили', 'Smoked')}: ${esc(top.join(', '))}` : ''}</span></a></li>`;
          }).join('')}</ul>` : `<p class="muted">${L('Здесь появятся прошедшие сборы: где были и что курили.', 'Past events will appear here: where you went and what you smoked.')}</p>`}
        </section>`,
      settings: `<section class="panel">
          <div class="panel-head"><h2>${L('Оформление', 'Appearance')}</h2></div>
          <div class="form">
            <div class="field"><span class="label">${L('Язык', 'Language')}</span><div class="segmented" role="radiogroup" aria-label="${L('Язык', 'Language')}">
              <button role="radio" aria-checked="${lang === 'ru'}" class="${lang === 'ru' ? 'on' : ''}" data-action="setLang" data-lang="ru">Русский</button>
              <button role="radio" aria-checked="${lang === 'en'}" class="${lang === 'en' ? 'on' : ''}" data-action="setLang" data-lang="en">English</button></div></div>
            <div class="field"><span class="label">${L('Тема', 'Theme')}</span><div class="segmented" role="radiogroup" aria-label="${L('Тема', 'Theme')}">${Object.entries(THEMES).map(([k, [label, ic]]) => `<button role="radio" aria-checked="${theme === k}" class="${theme === k ? 'on' : ''}" data-action="setTheme" data-theme="${k}">${ic}${tr(label)}</button>`).join('')}</div></div>
            <div class="field"><span class="label">${L('Праздничное оформление', 'Holiday look')}</span><div class="segmented" role="radiogroup" aria-label="${L('Праздничное оформление', 'Holiday look')}">${Object.entries(SEASONS).map(([k, label]) => `<button role="radio" aria-checked="${seasonPref === k}" class="${seasonPref === k ? 'on' : ''}" data-action="setSeason" data-season="${k}">${tr(label)}</button>`).join('')}</div>
              <small class="muted">${L('По датам: Хэллоуин с 23 октября по 3 ноября, Новый год с 22 декабря по 10 января. На время праздника цвет акцента меняется.', 'By date: Halloween from 23 October to 3 November, New Year from 22 December to 10 January. The accent colour changes during the holiday.')}</small></div>
            <div class="field"><span class="label">${L('Цвет акцента', 'Accent colour')}</span><div class="swatches" role="radiogroup" aria-label="${L('Цвет акцента', 'Accent colour')}">${Object.entries(ACCENTS).map(([k, label]) => `<button role="radio" aria-checked="${accent === k}" class="sw sw-${k} ${accent === k ? 'on' : ''}" data-action="setAccent" data-accent="${k}"><i></i>${tr(label)}</button>`).join('')}</div></div>
          </div>
        </section>
        <section class="panel" ${IN_APP ? 'hidden' : ''}>
          <div class="panel-head"><div><h2>${L('Приложение', 'App')}</h2><p class="muted" style="font-size:13.5px;margin-top:4px">${L('Hookah Party можно поставить на экран «Домой»: откроется на весь экран, со своей иконкой.', 'Add Hookah Party to your Home Screen: it opens full screen with its own icon.')}</p></div>
            <button class="btn btn-sm" type="button" data-action="installApp">${L('Установить', 'Install')}</button></div>
        </section>
        ${securityPanel(u)}
        <section class="panel" ${SERVER ? 'hidden' : ''}>
          <div class="panel-head"><h2>${L('Демо-данные', 'Demo data')}</h2></div>
          <p class="muted" style="margin-bottom:14px">${L('Все данные этого шаблона хранятся в вашем браузере. Сброс вернёт тестовых пользователей, сборы, отзывы и миксы.', 'All template data lives in your browser. Resetting restores the test users, events, reviews and mixes.')}</p>
          <button class="btn btn-danger btn-sm" data-action="reset">${L('Сбросить демо-данные', 'Reset demo data')}</button>
        </section>`
    };
    view.innerHTML = `
      <section class="section"><span class="eyebrow">${L('Профиль', 'Profile')}</span><h1>${L('Мой аккаунт', 'My account')}</h1></section>
      <div class="profile">
        <section class="panel profile-card">
          ${avatar(u, 'lg')}
          <div class="avatar-actions"><button class="btn btn-sm" data-action="uploadAvatar">${u.avatar ? L('Сменить фото', 'Change photo') : L('Загрузить фото', 'Upload photo')}</button>
            ${u.avatar ? `<button class="btn btn-ghost btn-sm" data-action="removeAvatar">${L('Удалить', 'Remove')}</button>` : ''}</div>
          <div><h2>${esc(u.name)}</h2>
            <div style="margin-top:6px" class="mono">${fmtPhone(u.phone)}</div>
            ${u.verified ? `<div class="verified" style="margin-top:6px">${ICON.check}${L('Номер подтверждён', 'Number verified')}</div>` : ''}</div>
          <div class="stats">
            <div class="stat"><b>${hosted}</b><small>${L('создал', 'hosted')}</small></div>
            <div class="stat"><b>${history.length}</b><small>${L('посетил', 'attended')}</small></div>
            <div class="stat"><b>${friends.length}</b><small>${pl(friends.length, ['друг', 'друга', 'друзей'], ['friend', 'friends'])}</small></div>
          </div>
          <button class="btn btn-ghost btn-sm" data-action="logout">${L('Выйти из аккаунта', 'Sign out')}</button>
        </section>
        <div class="ev-main">
          ${uTabs('profile', [{ key: 'about', label: L('Обо мне', 'About') }, { key: 'friends', label: L('Друзья', 'Friends'), count: friends.length }, { key: 'history', label: L('Мои вечера', 'My evenings'), count: history.length }, { key: 'settings', label: L('Настройки', 'Settings') }])}
          ${tabPanel('profile', panels[tab.profile])}
        </div>
      </div>`;
    if (SERVER && $('#srv-log')) api('GET', '/security/log').then(r => {
      const dt = t => `${fShort(new Date(t))}, ${fTime(new Date(t))}`, el = $('#srv-log'); if (!el) return;
      $('#srv-sessions').textContent = L(`активных сессий: ${r.sessions}`, `active sessions: ${r.sessions}`);
      el.innerHTML = r.log.length ? r.log.map(x => { const ev = SEC_EVENTS[x.type] || [x.type, x.type, '']; return `<li class="${ev[2]}"><i></i><span><b>${L(ev[0], ev[1])}</b><small>${esc([x.detail, x.ip].filter(Boolean).join(' · '))}</small></span><time class="mono">${dt(x.at)}</time></li>`; }).join('') : `<li class="muted">${L('Событий пока нет.', 'No events yet.')}</li>`;
    }).catch(() => { const el = $('#srv-log'); if (el) el.innerHTML = `<li class="muted">${L('Не удалось загрузить журнал.', 'Could not load the log.')}</li>`; });
    $('#profile-form')?.addEventListener('submit', ev => {
      ev.preventDefault();
      const name = clean($('#pf-name').value, 40);
      if (!validName(name)) { $('#pf-err').textContent = L('Укажите имя буквами: от 2 до 40 символов.', 'Enter a name using letters: 2 to 40 characters.'); return; }
      const favVenue = clean($('#pf-venue').value, 60);
      act(() => { u.name = name; u.favVenue = favVenue; }, 'PATCH', '/me', { name, favVenue }).then(() => { toast(L('Профиль сохранён', 'Profile saved')); render(); }, quiet);
    });
  }

  // Панель «Безопасность»: сессия, правила защиты, журнал событий.
  const SEC_EVENTS = {
    login_ok: ['Вход в аккаунт', 'Signed in', 'ok'], login_fail: ['Неверный пароль', 'Wrong password', 'warn'], lockout: ['Номер временно заблокирован', 'Number temporarily locked', 'bad'],
    logout: ['Выход из аккаунта', 'Signed out', ''], register: ['Создан аккаунт', 'Account created', 'ok'], sms_sent: ['Отправлен код', 'Code sent', ''],
    sms_fail: ['Неверный код', 'Wrong code', 'warn'], rate_limited: ['Сработало ограничение частоты', 'Rate limit hit', 'warn'], html_blocked: ['Заблокирован опасный фрагмент', 'Dangerous markup blocked', 'bad'],
    csp: ['Браузер заблокировал запрос (CSP)', 'Browser blocked a request (CSP)', 'bad'], bad_url: ['Подозрительная ссылка', 'Suspicious link', 'bad'],
    session_expired: ['Сессия истекла', 'Session expired', ''], storage_repaired: ['Данные восстановлены после ошибки', 'Data repaired after an error', 'warn'],
    logout_all: ['Выход на всех устройствах', 'Signed out everywhere', 'warn'], csrf_blocked: ['Отклонён запрос с чужого сайта', 'Cross-site request blocked', 'bad'],
    event_cancelled: ['Сбор отменён', 'Event cancelled', ''], admin_unlock: ['Вход в панель администратора', 'Admin panel unlocked', 'warn'],
    admin_unlock_fail: ['Неверный пароль в панели администратора', 'Wrong admin password', 'bad'], admin_denied: ['Попытка открыть панель без прав', 'Admin access denied', 'bad'],
    admin_delete_comment: ['Администратор удалил сообщение', 'Admin removed a message', 'warn'], admin_delete_event: ['Администратор удалил сбор', 'Admin removed an event', 'warn'],
    admin_granted: ['Выданы права администратора', 'Admin rights granted', 'warn'], admin_revoked: ['Сняты права администратора', 'Admin rights revoked', 'warn']
  };
  function securityPanel(u) {
    const log = secRead(SEC_LOG, []).slice(0, 12), dt = t => `${fShort(new Date(t))}, ${fTime(new Date(t))}`;
    const rules = [
      L(`Политика безопасности браузера (CSP): скрипты только с этого сайта, без встроенного кода`, `Browser security policy (CSP): scripts only from this site, no inline code`),
      L('Фильтр разметки и экранирование всего, что вводят пользователи', 'Markup filter and escaping of everything users type'),
      SERVER ? L('Пароли хранятся хэшем Argon2id, номера телефонов зашифрованы (AES-256-GCM)', 'Passwords are stored as Argon2id hashes, phone numbers are encrypted (AES-256-GCM)') : L(`Пароли хранятся хэшем PBKDF2 (150 000 итераций)`, `Passwords are stored as PBKDF2 hashes (150,000 iterations)`),
      L(`${SEC.failsBeforeLock} неверных паролей — блокировка номера на 5 минут`, `${SEC.failsBeforeLock} wrong passwords lock the number for 5 minutes`),
      L(`Не больше ${SEC.authPerHour} попыток входа и SMS в час, ${SEC.smsPer10Min} кодов на номер за 10 минут`, `At most ${SEC.authPerHour} sign-in and SMS attempts per hour, ${SEC.smsPer10Min} codes per number per 10 minutes`),
      L(`Не больше ${SEC.accountsPerDevice} аккаунтов с одного устройства`, `At most ${SEC.accountsPerDevice} accounts per device`),
      L('Лимиты сообщений: раз в 3 минуты, 10 в сборе за сутки, 144 за 7 часов', 'Message limits: one per 3 minutes, 10 per event per day, 144 per 7 hours')
    ];
    return `<section class="panel sec-panel">
      <div class="panel-head"><div><h2>${L('Безопасность', 'Security')}</h2>
        <p class="muted" style="font-size:13.5px;margin-top:4px">${L('Сессия', 'Session')}: ${db.sessionAt ? `${L('вход', 'since')} ${dt(db.sessionAt)} · ` : ''}${L('действует до', 'valid until')} ${dt(db.sessionExp || Date.now())}</p></div>
        <div class="btn-row"><button class="btn btn-sm" data-action="logout">${L('Завершить сессию', 'End session')}</button>${SERVER ? `<button class="btn btn-danger btn-sm" data-action="logoutAll">${L('Выйти на всех устройствах', 'Sign out everywhere')}</button>` : ''}</div></div>
      <ul class="sec-rules">${rules.map(r => `<li>${ICON.shield}<span>${r}</span></li>`).join('')}</ul>
      ${SERVER ? `<div class="sec-log-head"><b>${L('Журнал безопасности на сервере', 'Server security log')}</b><span class="muted" id="srv-sessions"></span></div><ul class="sec-log" id="srv-log"><li class="muted">${L('Загружаем…', 'Loading…')}</li></ul>` : ''}
      <div class="sec-log-head"><b>${SERVER ? L('События в этом браузере', 'Events in this browser') : L('Журнал безопасности', 'Security log')}</b>${log.length ? `<button class="link-btn" type="button" data-action="clearSecLog">${L('Очистить', 'Clear')}</button>` : ''}</div>
      ${log.length ? `<ul class="sec-log">${log.map(x => { const ev = SEC_EVENTS[x.type] || [x.type, x.type, '']; return `<li class="${ev[2]}"><i></i><span><b>${L(ev[0], ev[1])}</b>${x.detail ? `<small>${esc(x.detail)}</small>` : ''}</span><time class="mono">${dt(x.at)}</time></li>`; }).join('')}</ul>`
        : `<p class="muted">${L('Событий пока нет.', 'No events yet.')}</p>`}
    </section>`;
  }

  // ---------- Вход и регистрация ----------
  function pageAuth(mode) {
    if (me()) return go('');
    view.innerHTML = `<section class="auth"><div class="panel auth-card" id="auth-card"></div></section>`;
    const card = $('#auth-card');
    mode === 'register' ? renderRegister(card) : renderLogin(card);
  }
  const phonePh = '+996 700 123 456';
  // Блокировка номера после серии неверных паролей.
  function lockLeft(phone) { const f = secRead('hp.sec.fails', {})[phone]; return f?.until > Date.now() ? f.until - Date.now() : 0; }
  function failLogin(phone) {
    const all = secRead('hp.sec.fails', {}), now = Date.now();
    const f = all[phone] && !(all[phone].until && all[phone].until <= now) ? all[phone] : { n: 0 };
    f.n = (f.n || 0) + 1;
    if (f.n >= SEC.failsBeforeLock) { all[phone] = { n: 0, until: now + SEC.lockMs }; secWrite('hp.sec.fails', all); secLog('lockout', maskedPhone(phone)); return 0; }
    all[phone] = f; secWrite('hp.sec.fails', all);
    return SEC.failsBeforeLock - f.n;
  }
  function clearFails(phone) { const all = secRead('hp.sec.fails', {}); delete all[phone]; secWrite('hp.sec.fails', all); }
  const secureCode = () => String(1000 + (crypto.getRandomValues ? crypto.getRandomValues(new Uint32Array(1))[0] % 9000 : Math.floor(Math.random() * 9000)));

  function renderLogin(card) {
    card.innerHTML = `
      <div><span class="eyebrow">${L('Вход', 'Sign in')}</span><h1 style="margin-top:8px">${L('С возвращением', 'Welcome back')}</h1></div>
      <form class="form" id="login-form" novalidate>
        <div class="field"><label for="lg-phone">${L('Номер телефона', 'Phone number')}</label><input id="lg-phone" type="tel" inputmode="tel" autocomplete="tel" maxlength="20" placeholder="${phonePh}"></div>
        <div class="field"><label for="lg-pass">${L('Пароль', 'Password')}</label><input id="lg-pass" type="password" autocomplete="current-password" maxlength="128"></div>
        <div class="error" id="lg-err" role="alert"></div>
        <button class="btn btn-primary" type="submit" id="lg-go">${L('Войти', 'Sign in')}</button>
        <button class="btn" type="button" id="lg-sms">${L('Войти по SMS-коду', 'Sign in with an SMS code')}</button>
      </form>
      <div class="hint">${L('Тестовый аккаунт', 'Test account')}: <span class="mono">+996 700 000 001</span>, ${L('пароль', 'password')} <b>hookah</b></div>
      <p class="sec-note">${ICON.shield}${L(`Защита входа: ${SEC.failsBeforeLock} неверных попыток — блокировка на 5 минут, не больше ${SEC.authPerHour} попыток в час с устройства.`, `Sign-in protection: ${SEC.failsBeforeLock} wrong attempts lock the number for 5 minutes, at most ${SEC.authPerHour} attempts per hour from a device.`)}</p>
      <p class="muted" style="text-align:center">${L('Нет аккаунта?', 'No account?')} <a href="#/register" style="color:var(--accent)">${L('Зарегистрируйтесь', 'Sign up')}</a></p>`;
    maskPhone($('#lg-phone'));
    const err = $('#lg-err'), go1 = $('#lg-go');
    $('#login-form').addEventListener('submit', async ev => {
      ev.preventDefault();
      err.textContent = '';
      const phone = normPhone($('#lg-phone').value), pass = $('#lg-pass').value;
      if (!validPhone(phone)) { err.textContent = L('Введите номер полностью, вместе с кодом страны.', 'Enter the full number including the country code.'); return; }
      if (SERVER) {
        go1.disabled = true; go1.textContent = L('Проверяем…', 'Checking…');
        try { applyData((await api('POST', '/auth/login', { phone, password: pass })).data); toast(L(`Вы вошли как ${me().name}`, `Signed in as ${me().name}`)); afterAuth(); }
        catch (e) { err.textContent = apiMsg(e); }
        finally { go1.disabled = false; go1.textContent = L('Войти', 'Sign in'); }
        return;
      }
      const lock = lockLeft(phone);
      if (lock) { err.textContent = L(`Слишком много неверных попыток. Вход для этого номера заблокирован ещё на ${waitText(lock)}.`, `Too many wrong attempts. Sign-in for this number is locked for ${waitText(lock)}.`); return; }
      const r = rateHit('auth', SEC.authPerHour, 3600e3);
      if (!r.ok) { secLog('rate_limited', 'login'); err.textContent = L(`Слишком много попыток входа с этого устройства. Попробуйте через ${waitText(r.wait)}.`, `Too many sign-in attempts from this device. Try again in ${waitText(r.wait)}.`); return; }
      go1.disabled = true; go1.textContent = L('Проверяем…', 'Checking…');
      const user = userByPhone(phone);
      // Одинаковое сообщение и для неизвестного номера, и для неверного пароля: так не узнать, кто зарегистрирован.
      const ok = user ? await checkPass(user, pass) : (await new Promise(r2 => setTimeout(r2, 300)), false);
      go1.disabled = false; go1.textContent = L('Войти', 'Sign in');
      if (!ok) {
        const left = failLogin(phone);
        secLog('login_fail', maskedPhone(phone));
        err.textContent = left > 0 ? L(`Неверный номер или пароль. Осталось попыток: ${left}.`, `Wrong number or password. Attempts left: ${left}.`)
          : L(`Неверный пароль ${SEC.failsBeforeLock} раз подряд. Вход для номера заблокирован на 5 минут.`, `Wrong password ${SEC.failsBeforeLock} times in a row. Sign-in for this number is locked for 5 minutes.`);
        return;
      }
      clearFails(phone);
      if (!user.verified) { renderVerify(card, phone, () => { user.verified = true; signIn(user); }); return; }
      signIn(user);
    });
    $('#lg-sms').addEventListener('click', () => {
      const phone = normPhone($('#lg-phone').value), user = userByPhone(phone);
      if (!validPhone(phone)) { err.textContent = L('Сначала введите номер телефона.', 'Enter your phone number first.'); return; }
      if (SERVER) return void renderVerifyServer(card, phone, 'login', async code => {
        applyData((await api('POST', '/auth/login-sms', { phone, code })).data);
        toast(L(`Вы вошли как ${me().name}`, `Signed in as ${me().name}`)); afterAuth();
      });
      if (!user) { err.textContent = L('Этот номер ещё не зарегистрирован.', 'This number is not registered yet.'); return; }
      renderVerify(card, phone, () => { user.verified = true; clearFails(phone); signIn(user); });
    });
  }

  function renderRegister(card) {
    const regs = secRead('hp.sec.regs', []);
    card.innerHTML = `
      <div><span class="eyebrow">${L('Регистрация · шаг 1 из 3', 'Sign up · step 1 of 3')}</span><h1 style="margin-top:8px">${L('Создайте аккаунт', 'Create an account')}</h1></div>
      <form class="form" id="reg-form" novalidate>
        <div class="field"><label for="rg-name">${L('Имя', 'Name')}</label><input id="rg-name" autocomplete="given-name" maxlength="40" placeholder="${L('Как вас называть друзьям', 'What friends call you')}"></div>
        <div class="field"><label for="rg-phone">${L('Номер телефона', 'Phone number')}</label><input id="rg-phone" type="tel" inputmode="tel" autocomplete="tel" maxlength="20" placeholder="${phonePh}"></div>
        <div class="field"><label for="rg-pass">${L('Пароль', 'Password')}</label><input id="rg-pass" type="password" autocomplete="new-password" maxlength="128" placeholder="${L('Минимум 8 символов, буквы и цифры', 'At least 8 characters, letters and digits')}">
          <div class="pass-meter" aria-hidden="true"><i></i><i></i><i></i></div><small class="muted" id="rg-strength"></small></div>
        <label class="check"><input type="checkbox" id="rg-age"> ${L('Мне исполнилось 18 лет, я принимаю <a href="#/terms">правила сервиса</a> и согласен на обработку номера телефона по <a href="#/privacy">политике конфиденциальности</a>', 'I am 18 or older, accept the <a href="#/terms">terms of use</a> and agree to the processing of my phone number under the <a href="#/privacy">privacy policy</a>')}</label>
        <div class="error" id="rg-err" role="alert"></div>
        <button class="btn btn-primary" type="submit">${L('Получить код по SMS', 'Get an SMS code')}</button>
      </form>
      <p class="sec-note">${ICON.shield}${SERVER ? L('Номер подтверждается кодом из SMS. С одного адреса можно создать не больше 3 аккаунтов.', 'The number is confirmed by an SMS code. At most 3 accounts per address.') : L(`С одного устройства можно создать не больше ${SEC.accountsPerDevice} аккаунтов. Создано: ${regs.length}.`, `Up to ${SEC.accountsPerDevice} accounts can be created from one device. Created: ${regs.length}.`)}</p>
      <p class="muted" style="text-align:center">${L('Уже есть аккаунт?', 'Already have an account?')} <a href="#/login" style="color:var(--accent)">${L('Войти', 'Sign in')}</a></p>`;
    maskPhone($('#rg-phone'));
    const meter = $('.pass-meter'), strength = $('#rg-strength');
    $('#rg-pass').addEventListener('input', e => {
      const p = e.target.value, sc = p ? passScore(p) : -1, issue = p ? passIssues(p, $('#rg-phone').value) : '';
      $('#rg-err').textContent = '';
      meter.dataset.score = issue ? 0 : sc;
      strength.textContent = !p ? '' : issue || [L('Слабый пароль', 'Weak password'), L('Неплохой пароль', 'Fair password'), L('Хороший пароль', 'Good password'), L('Надёжный пароль', 'Strong password')][sc];
    });
    $('#reg-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const err = $('#rg-err');
      const name = clean($('#rg-name').value, 40), phone = normPhone($('#rg-phone').value), pass = $('#rg-pass').value;
      if (!validName(name)) return void (err.textContent = L('Укажите имя буквами: от 2 до 40 символов.', 'Enter a name using letters: 2 to 40 characters.'));
      if (!validPhone(phone)) return void (err.textContent = L('Введите номер полностью, вместе с кодом страны.', 'Enter the full number including the country code.'));
      if (userByPhone(phone)?.verified) return void (err.textContent = L('Этот номер уже зарегистрирован. Войдите или восстановите доступ по SMS.', 'This number is already registered. Sign in or recover access by SMS.'));
      const issue = passIssues(pass, phone);
      if (issue) return void (err.textContent = issue);
      if (!$('#rg-age').checked) return void (err.textContent = L('Сервис доступен только совершеннолетним.', 'The service is for adults only.'));
      if (SERVER) return void renderVerifyServer(card, phone, 'register', async code => {
        applyData((await api('POST', '/auth/register', { name, phone, password: pass, code, adult: true })).data);
        renderAvatarStep(card, me());
      }, L('Регистрация · шаг 2 из 3', 'Sign up · step 2 of 3'));
      if (secRead('hp.sec.regs', []).length >= SEC.accountsPerDevice) {
        secLog('rate_limited', 'register');
        return void (err.textContent = L(`С этого устройства уже создано ${SEC.accountsPerDevice} аккаунта. Это ограничение защищает от массовой регистрации.`, `${SEC.accountsPerDevice} accounts have already been created on this device. This limit prevents mass sign-ups.`));
      }
      renderVerify(card, phone, async () => {
        const passRec = await makePass(pass);
        let user = userByPhone(phone);
        if (user) Object.assign(user, { name, pass: passRec, verified: true });
        else { user = { id: uid('u'), name, phone, pass: passRec, verified: true, avatar: null, favs: [], friends: [], favVenue: '', createdAt: new Date().toISOString() }; db.users.push(user); }
        secWrite('hp.sec.regs', [...secRead('hp.sec.regs', []), Date.now()]);
        secLog('register', maskedPhone(phone));
        claimPhoneInvites(user);
        startSession(user);
        renderAvatarStep(card, user);
      }, L('Регистрация · шаг 2 из 3', 'Sign up · step 2 of 3'));
    });
  }

  // Подтверждение номера. В демо код показывается на экране вместо настоящего SMS.
  // Защита: не больше 3 кодов на номер за 10 минут и 17 попыток в час с устройства, код живёт 5 минут, 5 попыток ввода.
  function renderVerify(card, phone, onSuccess, eyebrow = L('Подтверждение номера', 'Number verification')) {
    let code = '', codeAt = 0, attempts = 0, timer = null, left = 0;
    const blocked = wait => {
      clearInterval(timer);
      card.innerHTML = `<div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">${L('Слишком много запросов кода', 'Too many code requests')}</h1>
        <p class="muted" style="margin-top:8px">${L(`Для защиты от злоупотреблений новый код можно запросить через ${waitText(wait)}.`, `To prevent abuse you can request a new code in ${waitText(wait)}.`)}</p></div>
        <button class="btn" type="button" id="code-back">${L('Назад', 'Back')}</button>`;
      $('#code-back').onclick = () => route();
    };
    const send = () => {
      const perPhone = rateHit('sms:' + phone, SEC.smsPer10Min, 10 * 60e3, false);
      if (!perPhone.ok) { secLog('rate_limited', 'sms ' + maskedPhone(phone)); blocked(perPhone.wait); return false; }
      const total = rateHit('auth', SEC.authPerHour, 3600e3);
      if (!total.ok) { secLog('rate_limited', 'sms'); blocked(total.wait); return false; }
      rateHit('sms:' + phone, SEC.smsPer10Min, 10 * 60e3);
      code = secureCode(); codeAt = Date.now(); attempts = 0;
      secLog('sms_sent', maskedPhone(phone));
      return true;
    };
    if (!send()) return;
    card.innerHTML = `
      <div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">${L('Введите код из SMS', 'Enter the SMS code')}</h1>
        <p class="muted" style="margin-top:8px">${L('Отправили 4 цифры на', 'We sent 4 digits to')} <span class="mono">${fmtPhone(phone)}</span>. ${L('Код действует 5 минут.', 'The code is valid for 5 minutes.')}</p></div>
      <form class="form" id="code-form">
        <div class="code-inputs">${[0, 1, 2, 3].map(i => `<input id="code-${i}" inputmode="numeric" autocomplete="${i === 0 ? 'one-time-code' : 'off'}" maxlength="1" aria-label="${L('Цифра', 'Digit')} ${i + 1}">`).join('')}</div>
        <div class="hint" id="sms-hint"></div>
        <div class="error" id="code-err" style="text-align:center" role="alert"></div>
        <button class="btn btn-primary" type="submit">${L('Подтвердить', 'Confirm')}</button>
        <div class="resend" id="resend"></div>
        <button class="link-btn" type="button" id="code-back">${L('Изменить номер', 'Change number')}</button>
      </form>`;
    const boxes = $$('.code-inputs input', card);
    const showHint = () => { $('#sms-hint').innerHTML = `${L('Демо-режим, SMS не отправляется. Ваш код:', 'Demo mode, no SMS is sent. Your code:')} <b>${code}</b>`; };
    const tick = () => {
      const r = $('#resend'); if (!r) return clearInterval(timer);
      r.innerHTML = left > 0 ? `${L('Отправить код повторно через', 'Resend the code in')} <span class="mono">0:${pad(left)}</span>` : `<button class="link-btn" type="button" id="resend-btn">${L('Отправить код ещё раз', 'Send the code again')}</button>`;
      if (left-- <= 0) {
        clearInterval(timer);
        $('#resend-btn').onclick = () => { if (!send()) return; showHint(); $('#code-err').textContent = ''; toast(L('Новый код отправлен', 'A new code has been sent')); start(); };
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
    $('#code-form').addEventListener('submit', async ev => {
      ev.preventDefault();
      const errEl = $('#code-err'), reset = () => { boxes.forEach(b => b.value = ''); boxes[0].focus(); };
      if (Date.now() - codeAt > SEC.codeTtlMs) { errEl.textContent = L('Код устарел. Запросите новый.', 'The code has expired. Request a new one.'); reset(); return; }
      if (attempts >= SEC.codeAttempts) { errEl.textContent = L('Слишком много неверных попыток. Запросите новый код.', 'Too many wrong attempts. Request a new code.'); reset(); return; }
      if (!sameStr(boxes.map(b => b.value).join(''), code)) {
        attempts++;
        secLog('sms_fail', maskedPhone(phone));
        errEl.textContent = attempts >= SEC.codeAttempts ? L('Слишком много неверных попыток. Запросите новый код.', 'Too many wrong attempts. Request a new code.')
          : L(`Код не подходит. Осталось попыток: ${SEC.codeAttempts - attempts}.`, `Wrong code. Attempts left: ${SEC.codeAttempts - attempts}.`);
        reset(); return;
      }
      clearInterval(timer); code = '';
      await onSuccess();
    });
    $('#code-back').addEventListener('click', () => { clearInterval(timer); route(); });
  }
  // Подтверждение номера на сервере: код приходит в SMS (в режиме разработки сервер показывает его здесь).
  async function renderVerifyServer(card, phone, purpose, onCode, eyebrow = L('Подтверждение номера', 'Number verification')) {
    let timer = null, left = 0;
    const blocked = msg => {
      clearInterval(timer);
      card.innerHTML = `<div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">${L('Код не отправлен', 'Code not sent')}</h1>
        <p class="muted" style="margin-top:8px">${esc(msg)}</p></div><button class="btn" type="button" id="code-back">${L('Назад', 'Back')}</button>`;
      $('#code-back').onclick = () => route();
    };
    const request = async () => {
      try { const r = await api('POST', '/auth/sms', { phone, purpose }); return r.devCode || ''; }
      catch (e) { blocked(apiMsg(e)); return null; }
    };
    card.innerHTML = `<div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">${L('Отправляем код…', 'Sending the code…')}</h1></div>`;
    let devCode = await request();
    if (devCode === null) return;
    card.innerHTML = `
      <div><span class="eyebrow">${eyebrow}</span><h1 style="margin-top:8px">${L('Введите код из SMS', 'Enter the SMS code')}</h1>
        <p class="muted" style="margin-top:8px">${L('Отправили 4 цифры на', 'We sent 4 digits to')} <span class="mono">${fmtPhone(phone)}</span>. ${L('Код действует 5 минут.', 'The code is valid for 5 minutes.')}</p></div>
      <form class="form" id="code-form">
        <div class="code-inputs">${[0, 1, 2, 3].map(i => `<input id="code-${i}" inputmode="numeric" autocomplete="${i === 0 ? 'one-time-code' : 'off'}" maxlength="1" aria-label="${L('Цифра', 'Digit')} ${i + 1}">`).join('')}</div>
        <div class="hint" id="sms-hint"></div>
        <div class="error" id="code-err" style="text-align:center" role="alert"></div>
        <button class="btn btn-primary" type="submit" id="code-go">${L('Подтвердить', 'Confirm')}</button>
        <div class="resend" id="resend"></div>
        <button class="link-btn" type="button" id="code-back">${L('Изменить номер', 'Change number')}</button>
      </form>`;
    const boxes = $$('.code-inputs input', card);
    const showHint = () => {
      const h = $('#sms-hint');
      h.innerHTML = devCode ? `${L('Режим разработки: SMS не отправляется. Ваш код:', 'Development mode: no SMS is sent. Your code:')} <b>${devCode}</b>`
        : L('Если SMS не пришло за минуту, проверьте номер или запросите код ещё раз.', 'If the SMS does not arrive within a minute, check the number or request the code again.');
    };
    const tick = () => {
      const r = $('#resend'); if (!r) return clearInterval(timer);
      r.innerHTML = left > 0 ? `${L('Отправить код повторно через', 'Resend the code in')} <span class="mono">0:${pad(left)}</span>` : `<button class="link-btn" type="button" id="resend-btn">${L('Отправить код ещё раз', 'Send the code again')}</button>`;
      if (left-- <= 0) {
        clearInterval(timer);
        $('#resend-btn').onclick = async () => { const c = await request(); if (c === null) return; devCode = c; showHint(); $('#code-err').textContent = ''; toast(L('Новый код отправлен', 'A new code has been sent')); start(); };
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
    let busy = false;
    $('#code-form').addEventListener('submit', async ev => {
      ev.preventDefault();
      if (busy) return;
      busy = true; $('#code-go').disabled = true;
      try { await onCode(boxes.map(b => b.value).join('')); clearInterval(timer); }
      catch (e) { $('#code-err').textContent = apiMsg(e); boxes.forEach(b => b.value = ''); boxes[0].focus(); }
      finally { busy = false; const g = $('#code-go'); if (g) g.disabled = false; }
    });
    $('#code-back').addEventListener('click', () => { clearInterval(timer); route(); });
  }

  function renderAvatarStep(card, user) {
    const draw = () => {
      card.innerHTML = `
        <div><span class="eyebrow">${L('Регистрация · шаг 3 из 3', 'Sign up · step 3 of 3')}</span><h1 style="margin-top:8px">${L('Добавьте фото', 'Add a photo')}</h1>
          <p class="muted" style="margin-top:8px">${L('По аватару друзья узнают вас в списке участников.', 'Friends will recognise you in the guest list.')}</p></div>
        <div class="avatar-upload">${avatar(user, 'lg')}
          <div class="verified">${ICON.check}${L('Номер', 'Number')} ${fmtPhone(user.phone)} ${L('подтверждён', 'verified')}</div>
          <div class="avatar-actions"><button class="btn" type="button" id="av-up">${user.avatar ? L('Выбрать другое', 'Choose another') : L('Загрузить фото', 'Upload photo')}</button></div></div>
        <button class="btn btn-primary" type="button" id="av-done">${user.avatar ? L('Готово', 'Done') : L('Пропустить', 'Skip')}</button>`;
      $('#av-up').onclick = () => pickAvatarFile(url => act(() => { user.avatar = url; }, 'PUT', '/me/avatar', { dataUrl: url }).then(() => { user = me() || user; draw(); }, quiet));
      $('#av-done').onclick = () => { toast(L(`Добро пожаловать, ${user.name}!`, `Welcome, ${user.name}!`)); afterAuth(); };
    };
    draw();
  }
  function startSession(user) {
    db.session = user.id; db.sessionAt = Date.now(); db.sessionExp = Date.now() + SEC.sessionDays * 864e5;
    save(); secLog('login_ok', user.name);
  }
  function signIn(user) { startSession(user); toast(L(`Вы вошли как ${user.name}`, `Signed in as ${user.name}`)); afterAuth(); }

  // ---------- Пикер приглашений ----------
  function invitePicker(root, exclude, preset = []) {
    const u = me(), sel = preset.slice();
    root.innerHTML = `<div class="picker"><div class="picker-chips"></div>
      <input class="input" id="inv-q" placeholder="${L('Имя или номер телефона', 'Name or phone number')}" autocomplete="off" aria-label="${L('Кого пригласить', 'Who to invite')}"><div class="suggest"></div></div>`;
    const chips = $('.picker-chips', root), sug = $('.suggest', root), q = $('#inv-q', root);
    const taken = () => new Set([...exclude, ...sel.map(s => s.userId || s.phone)]);
    const draw = () => {
      chips.innerHTML = sel.map((s, i) => {
        const p = s.userId && userById(s.userId);
        return `<span class="chip">${p ? avatar(p, 'xs') + esc(p.name) : `<span class="mono">${fmtPhone(s.phone)}</span>`}<button type="button" data-i="${i}" aria-label="${L('Убрать', 'Remove')}">×</button></span>`;
      }).join('');
      const text = q.value.trim().toLowerCase(), qd = digits(text), t = taken();
      const found = db.users
        .filter(p => !t.has(p.id) && (!text || p.name.toLowerCase().includes(text) || (qd.length >= 3 && (p.phone || '').includes(qd))))
        .sort((a, b) => isFriend(u, b) - isFriend(u, a) || a.name.localeCompare(b.name, 'ru')).slice(0, 6);
      let html = found.map(p => `<button type="button" data-u="${p.id}">${avatar(p, 'sm')}<span>${esc(p.name)}${isFriend(u, p) ? ` <em class="tag-friend">${L('друг', 'friend')}</em>` : ''}</span><small>${phoneShown(u, p)}</small></button>`).join('');
      const np = normPhone(qd);
      if (validPhone(np) && !userByPhone(np) && !t.has(np)) html += `<button type="button" data-p="${np}"><span class="av av-sm av-ghost">+</span><span>${L('Пригласить по номеру', 'Invite by number')}</span><small>${fmtPhone(np)}</small></button>`;
      sug.innerHTML = html || `<p class="muted" style="padding:8px;font-size:13.5px">${text ? L('Никого не нашли. Введите номер полностью, чтобы пригласить по SMS.', 'Nobody found. Enter the full number to invite by SMS.') : L('Все ваши знакомые уже приглашены.', 'Everyone you know is already invited.')}</p>`;
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

  // Форма сбора: создание, повтор и редактирование. Заведение можно выбрать из карты.
  function eventForm({ heading, submitLabel, data = {}, preset = [], withPicker = true, onSave }) {
    const u = me();
    const at = data.at ? new Date(data.at) : (() => { const t = new Date(Date.now() + 864e5); t.setHours(20, 0, 0, 0); return t; })();
    const names = [...new Set([...VENUES.map(v => v.name), u.favVenue, ...db.events.map(e => e.venue)].filter(Boolean))];
    let picker;
    openModal(heading, `
      <form class="form" id="ev-form" novalidate>
        <div class="field"><label for="ev-title">${L('Название', 'Title')}</label><input id="ev-title" maxlength="60" placeholder="${L('Например, пятничный сбор', 'For example, Friday night')}" value="${esc(data.title || '')}"></div>
        <div class="row-2"><div class="field"><label for="ev-venue">${L('Заведение', 'Venue')}</label><input id="ev-venue" maxlength="60" list="ev-venues" placeholder="${L('Начните вводить название', 'Start typing a name')}" value="${esc(data.venue || u.favVenue || '')}">
            <datalist id="ev-venues">${names.map(v => `<option value="${esc(v)}">`).join('')}</datalist></div>
          <div class="field"><label for="ev-address">${L('Адрес', 'Address')}</label><input id="ev-address" maxlength="100" placeholder="${L('Подставится сам для мест с карты', 'Filled in automatically for places on the map')}" value="${esc(data.address || '')}"></div></div>
        <div class="field"><label for="ev-map">${L('Ссылка на заведение', 'Venue link')} <span class="muted">(${L('необязательно', 'optional')})</span></label><input id="ev-map" type="url" maxlength="300" placeholder="https://…" value="${esc(data.mapUrl || '')}"></div>
        <div class="row-2"><div class="field"><label for="ev-date">${L('Дата', 'Date')}</label><input id="ev-date" type="date" value="${ymd(at)}"></div>
          <div class="field"><label for="ev-time">${L('Время', 'Time')}</label><input id="ev-time" type="time" value="${hm(at)}"></div></div>
        <div class="row-2"><div class="field"><label for="ev-hookahs">${L('Кальянов', 'Hookahs')}</label><input id="ev-hookahs" type="number" min="0" max="20" value="${data.hookahs ?? 2}"></div>
          <div class="field"><label for="ev-price">${L('Цена одного, сом', 'Price each, KGS')}</label><input id="ev-price" type="number" min="0" max="100000" step="50" value="${data.price ?? 1200}"></div></div>
        <div class="field"><label for="ev-desc">${L('Комментарий', 'Notes')}</label><textarea id="ev-desc" maxlength="400" placeholder="${L('Бронь, кто что приносит', 'Booking, who brings what')}">${esc(data.desc || '')}</textarea></div>
        ${withPicker ? `<div class="field"><span class="label">${L('Пригласить', 'Invite')}</span><div id="ev-picker"></div></div>` : ''}
        <div class="error" id="ev-err"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="submit">${submitLabel}</button></div>
      </form>`, m => {
      if (withPicker) picker = invitePicker($('#ev-picker', m), [u.id], preset);
      const vIn = $('#ev-venue', m), aIn = $('#ev-address', m);
      vIn.addEventListener('change', () => { const v = VENUES.find(x => x.name === vIn.value.trim()); if (v && v.addr && !aIn.value.trim()) aIn.value = v.addr; });
      $('#ev-form', m).addEventListener('submit', ev => {
        ev.preventDefault();
        const err = $('#ev-err', m), val = s => clean($(s, m).value, 100);
        const title = val('#ev-title'), venue = val('#ev-venue'), mapUrl = clean($('#ev-map', m).value, 300);
        if (!title) return void (err.textContent = L('Придумайте название сбора.', 'Give the event a title.'));
        if (!venue) return void (err.textContent = L('Укажите заведение.', 'Choose a venue.'));
        if (mapUrl && !/^https?:\/\/\S+\.\S+/.test(mapUrl)) return void (err.textContent = L('Ссылка должна начинаться с https://', 'The link must start with https://'));
        const when = new Date(`${val('#ev-date')}T${val('#ev-time') || '20:00'}`);
        if (isNaN(when)) return void (err.textContent = L('Укажите дату и время.', 'Set a date and time.'));
        if (when < Date.now()) return void (err.textContent = L('Это время уже прошло. Выберите время в будущем.', 'That time has passed. Pick a time in the future.'));
        const hookahs = Math.max(0, Math.min(20, parseInt(val('#ev-hookahs'), 10) || 0));
        const price = Math.max(0, parseInt(val('#ev-price'), 10) || 0);
        const v = VENUES.find(x => x.name === venue);
        onSave({ title: title.slice(0, 60), venue: venue.slice(0, 60), venueId: v ? v.id : null, address: val('#ev-address') || v?.addr || '', mapUrl: safeUrl(mapUrl), at: when.toISOString(), hookahs, price, desc: clean($('#ev-desc', m).value, 400, true) }, picker ? toInvites(picker.get()) : [], picker ? picker.get() : []);
      });
    });
  }
  async function createEvent(fields, invites, raw = invites) {
    let newId;
    if (SERVER) {
      const r = await act(null, 'POST', '/events', { ...fields, invites: raw }).catch(() => null);
      if (!r) return;
      newId = r.id;
    } else {
      const e = { id: uid('e'), hostId: me().id, createdAt: new Date().toISOString(), ...fields, invites, picks: {}, bowls: {}, comments: [], paid: {}, remind: {}, notified: {} };
      db.events.push(e); save(); evLog(me(), 'create'); newId = e.id;
    }
    closeModal();
    toast(invites.length ? L(`Сбор создан, приглашения отправлены: ${invites.length}`, `Event created, invitations sent: ${invites.length}`) : L('Сбор создан', 'Event created'));
    go('event/' + newId);
  }

  // Напоминания работают, пока сайт открыт. Надёжный вариант — файл .ics с будильником.
  function checkReminders() {
    const u = me(); if (!u) return;
    for (const e of db.events) {
      if (!remindOn(e, u) || secRead(REM, {})[u.id + ':' + e.id]?.done === e.at) continue;
      const left = new Date(e.at) - Date.now();
      if (left > 0 && left <= 3600e3) {
        remindSet(e, u, { done: e.at });
        const msg = L(`Через ${Math.ceil(left / 60000)} мин: ${e.title}, ${e.venue}`, `In ${Math.ceil(left / 60000)} min: ${e.title}, ${e.venue}`);
        toast(msg);
        try { if ('Notification' in window && Notification.permission === 'granted') new Notification('Hookah Party', { body: msg }); } catch (err) { /* уведомления недоступны */ }
      }
    }
  }
  setInterval(() => { checkReminders(); $$('[data-countdown]').forEach(el => { el.textContent = countdown(el.dataset.countdown); }); }, 30000);
  const calTimes = e => { const s = new Date(e.at); return [s, new Date(s.getTime() + 3 * 3600e3)]; };
  const icsStamp = d => `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}00Z`;
  const googleCal = e => { const [s, end] = calTimes(e);
    return `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(e.title)}&dates=${icsStamp(s)}/${icsStamp(end)}&location=${encodeURIComponent([e.venue, e.address].filter(Boolean).join(', '))}&details=${encodeURIComponent(e.desc || 'Hookah Party')}`; };
  function calendarModal(e) {
    openModal(L('Добавить в календарь', 'Add to calendar'), `<p class="muted">${L('Календарь сам напомнит о сборе за день и за час, даже если сайт закрыт.', 'Your calendar will remind you a day and an hour before, even when the site is closed.')}</p>
      <div class="share-grid">
        <button class="share-btn" type="button" id="cal-ics">${ICON.cal}<span>${L('Apple, Outlook и другие', 'Apple, Outlook and others')}<small>${L('файл .ics', '.ics file')}</small></span></button>
        <a class="share-btn" href="${esc(googleCal(e))}" target="_blank" rel="noopener noreferrer">${ICON.cal}<span>Google ${L('Календарь', 'Calendar')}<small>${L('в браузере или на Android', 'in the browser or on Android')}</small></span></a>
      </div>`, m => {
      $('#cal-ics', m).onclick = () => { downloadIcs(e); closeModal(); toast(L('Файл календаря скачан. Откройте его, чтобы добавить сбор.', 'Calendar file downloaded. Open it to add the event.')); };
    });
  }
  function downloadIcs(e) {
    const f = d => `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}00Z`;
    const x = t => String(t || '').replace(/[\\,;]/g, m => '\\' + m).replace(/\n/g, '\\n');
    const s = new Date(e.at), end = new Date(s.getTime() + 3 * 3600e3);
    const ics = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Hookah Party//RU', 'BEGIN:VEVENT',
      `UID:${e.id}@hookahparty`, `DTSTAMP:${f(new Date())}`, `DTSTART:${f(s)}`, `DTEND:${f(end)}`,
      `SUMMARY:${x(e.title)}`, `LOCATION:${x([e.venue, e.address].filter(Boolean).join(', '))}`, `DESCRIPTION:${x(e.desc)}`,
      'BEGIN:VALARM', 'TRIGGER:-P1D', 'ACTION:DISPLAY', `DESCRIPTION:${x(L('Завтра кальянный сбор', 'Hookah meet-up tomorrow'))}`, 'END:VALARM',
      'BEGIN:VALARM', 'TRIGGER:-PT60M', 'ACTION:DISPLAY', `DESCRIPTION:${x(L('Через час кальянный сбор', 'Hookah meet-up in one hour'))}`, 'END:VALARM',
      'END:VEVENT', 'END:VCALENDAR'].join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([ics], { type: 'text/calendar' }));
    a.download = `hookah-party-${e.id || 'event'}.ics`;
    document.body.append(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ---------- Правила и конфиденциальность ----------
  // Отдельные страницы со своими адресами: на них ссылаются регистрация, App Store и магазины приложений.
  const LEGAL = {
    privacy: () => ({
      title: L('Политика конфиденциальности', 'Privacy policy'),
      parts: [
        [L('Коротко', 'In short'), L('Мы собираем только то, без чего сервис не работает: номер телефона, имя и то, что вы сами публикуете. Номер хранится зашифрованным, пароль — только в виде необратимого хэша. Мы не продаём данные и не показываем рекламу.', 'We collect only what the service needs to work: your phone number, name and what you publish yourself. The number is stored encrypted and the password only as an irreversible hash. We do not sell data or show ads.')],
        [L('Какие данные мы храним', 'What we store'), L('Номер телефона — для входа и чтобы друзья могли вас пригласить. Имя и фото профиля, если вы его загрузили. Сборы, ответы на приглашения, выбор табака, сообщения, оценки и отзывы. Для защиты от взлома — время входов, IP-адрес и тип устройства в журнале безопасности.', 'Your phone number, to sign in and so friends can invite you. Your name and profile photo if you upload one. Events, replies to invitations, tobacco picks, messages, ratings and reviews. For protection against break-ins: sign-in times, IP address and device type in the security log.')],
        [L('Кто видит ваши данные', 'Who sees your data'), L('Имя и фото видят другие пользователи. Полный номер видят только ваши друзья и участники общих сборов, остальные — последние цифры. Сообщения в обсуждении сбора видят только его участники. Рассказы в «Истории» видят все.', 'Other users see your name and photo. Only your friends and people from shared events see your full number; others see the last digits. Event discussion messages are visible only to its guests. Stories in History are public.')],
        [L('Как мы защищаем данные', 'How we protect data'), L('Соединение с сайтом шифруется (HTTPS). Номера в базе зашифрованы, пароли хранятся как хэш Argon2. Вход защищён кодом из SMS и ограничением числа попыток. Сессия хранится в защищённом cookie, недоступном скриптам.', 'The connection is encrypted (HTTPS). Numbers in the database are encrypted and passwords stored as an Argon2 hash. Sign-in is protected by an SMS code and attempt limits. The session lives in a protected cookie that scripts cannot read.')],
        [L('Сколько храним', 'How long we keep it'), L('Пока у вас есть аккаунт. Отменённые сборы удаляются сразу вместе с сообщениями. Журнал безопасности хранится до 90 дней. По запросу удалим аккаунт и все связанные данные в течение 30 дней.', 'As long as you have an account. Cancelled events are deleted immediately together with their messages. The security log is kept for up to 90 days. On request we delete the account and all related data within 30 days.')],
        [L('Cookie и хранилище браузера', 'Cookies and browser storage'), L('Один cookie нужен, чтобы вы оставались в аккаунте. В хранилище браузера сохраняются настройки: язык, тема, открытые вкладки. Сторонних счётчиков и рекламных cookie нет.', 'One cookie keeps you signed in. Browser storage keeps your settings: language, theme, open tabs. There are no third-party trackers or advertising cookies.')],
        [L('Ваши права', 'Your rights'), L('Вы можете узнать, какие данные о вас хранятся, исправить их или попросить удалить. Обработка ведётся в соответствии с Законом Кыргызской Республики «Об информации персонального характера».', 'You can find out what data we hold about you, correct it or ask us to delete it. Processing follows the Law of the Kyrgyz Republic “On Personal Information”.')],
        [L('Сторонние сервисы', 'Third-party services'), L('Коды подтверждения отправляет SMS-провайдер: ему передаётся только номер и текст сообщения. Ссылки на Google Карты, 2ГИС, Telegram и WhatsApp открывают эти сервисы, у них свои правила.', 'Confirmation codes are sent by an SMS provider, which receives only the number and the message text. Links to Google Maps, 2GIS, Telegram and WhatsApp open those services, which have their own policies.')],
        [L('Контакты', 'Contact'), L('Вопросы и запросы на удаление данных: hello@hookahparty.app.', 'Questions and data deletion requests: hello@hookahparty.app.')]
      ]
    }),
    terms: () => ({
      title: L('Правила сервиса', 'Terms of use'),
      parts: [
        [L('Только 18+', '18+ only'), L('Hookah Party предназначен только для совершеннолетних. Регистрируясь, вы подтверждаете, что вам исполнилось 18 лет. Курение вредит вашему здоровью.', 'Hookah Party is for adults only. By signing up you confirm that you are 18 or older. Smoking harms your health.')],
        [L('Что делает сервис', 'What the service does'), L('Помогает собрать друзей в кальянной: выбрать место, позвать людей, договориться о табаке и поделить счёт. Мы не продаём табак, не принимаем оплату и не бронируем столы.', 'It helps you get friends together at a hookah lounge: pick a place, invite people, agree on tobacco and split the bill. We do not sell tobacco, take payments or book tables.')],
        [L('Организатор сбора', 'The event host'), L('Организатор сам бронирует стол и договаривается с заведением. Один человек может вести один активный сбор; за сутки можно создать и отменить не больше 12 сборов.', 'The host books the table and deals with the venue. One person can run one active event at a time; at most 12 events can be created and 12 cancelled per day.')],
        [L('Что запрещено', 'What is not allowed'), L('Приглашать людей без их согласия, рассылать рекламу и спам, оскорблять других, публиковать чужие личные данные, выдавать себя за другого человека, пытаться обойти ограничения и защиту сервиса.', 'Inviting people without their consent, sending ads and spam, insulting others, posting other people’s personal data, impersonating someone, trying to bypass limits and protection.')],
        [L('Сообщения и модерация', 'Messages and moderation'), L('Чтобы обсуждения не превращались в поток, действуют ограничения: одно сообщение в 3 минуты, до 10 в одном сборе за сутки. Администраторы могут удалять сообщения и сборы, нарушающие правила.', 'To keep discussions readable there are limits: one message every 3 minutes, up to 10 per event per day. Administrators may remove messages and events that break the rules.')],
        [L('Данные о заведениях', 'Venue information'), L('Адреса и часы работы взяты из открытых источников (OpenStreetMap) и могут устареть. Перед походом уточняйте их у заведения.', 'Addresses and opening hours come from open sources (OpenStreetMap) and may be out of date. Check with the venue before you go.')],
        [L('Ответственность', 'Liability'), L('Сервис предоставляется «как есть». Мы стараемся, чтобы всё работало, но не отвечаем за действия заведений и других пользователей.', 'The service is provided “as is”. We do our best to keep it working but are not responsible for the actions of venues or other users.')],
        [L('Изменения правил', 'Changes'), L('О важных изменениях мы предупредим на сайте заранее.', 'We will announce important changes on the site in advance.')]
      ]
    })
  };
  function pageLegal(kind) {
    const doc = LEGAL[kind]();
    view.innerHTML = `<article class="legal">
      <div class="legal-switch"><a href="#/privacy" class="${kind === 'privacy' ? 'on' : ''}">${L('Конфиденциальность', 'Privacy')}</a><a href="#/terms" class="${kind === 'terms' ? 'on' : ''}">${L('Правила', 'Terms')}</a></div>
      <h1>${doc.title}</h1><p class="muted">${L('Редакция от 23 октября 2026 года', 'Version of 23 October 2026')}</p>
      ${doc.parts.map(([h, t]) => `<section><h2>${h}</h2><p>${t}</p></section>`).join('')}
    </article>`;
  }

  // Сервис о табаке: при первом визите спрашиваем возраст.
  function ageGate() {
    if (prefs.get('age18') === 'yes') return;
    const g = document.createElement('div');
    g.className = 'age-gate'; g.setAttribute('role', 'dialog'); g.setAttribute('aria-modal', 'true'); g.setAttribute('aria-labelledby', 'age-h');
    g.innerHTML = `<div class="age-card"><span class="age-badge">18+</span><h2 id="age-h">${L('Вам уже исполнилось 18 лет?', 'Are you 18 or older?')}</h2>
      <p class="muted">${L('Hookah Party — сервис о кальянах, он только для совершеннолетних. Курение вредит вашему здоровью.', 'Hookah Party is about hookah and is for adults only. Smoking harms your health.')}</p>
      <div class="btn-row"><button class="btn btn-primary" type="button" data-age="yes">${L('Да, мне есть 18', 'Yes, I’m 18+')}</button><button class="btn" type="button" data-age="no">${L('Нет', 'No')}</button></div>
      <p class="age-no" hidden>${L('Извините, сайт доступен только с 18 лет.', 'Sorry, this site is for adults only.')}</p>
      <p class="age-links"><a href="#/terms">${L('Правила', 'Terms')}</a> · <a href="#/privacy">${L('Конфиденциальность', 'Privacy')}</a></p></div>`;
    document.body.append(g); document.body.classList.add('locked');
    g.addEventListener('click', ev => {
      const b = ev.target.closest('[data-age]'); if (!b) return;
      if (b.dataset.age === 'no') { $('.age-no', g).hidden = false; return; }
      prefs.set('age18', 'yes'); document.body.classList.remove('locked');
      g.classList.add('out'); setTimeout(() => g.remove(), reduceMotion() ? 0 : 320);
    });
    $('[data-age="yes"]', g).focus();
  }

  // ---------- Приглашение ссылкой: Telegram, WhatsApp ----------
  // Ссылки ведут на настоящий сайт, даже если их создали в приложении или в превью.
  const PUBLIC_URL = 'https://marlendiusheew-sudo.github.io/hookah-party/';
  const siteBase = () => SERVER ? location.origin + location.pathname : PUBLIC_URL;
  const b64u = {
    enc: str => btoa(String.fromCharCode(...new TextEncoder().encode(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    dec: str => new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)))
  };
  // В демо сервера нет, поэтому всё нужное о сборе лежит в самой ссылке: название, место, время, имя организатора.
  function demoInviteCode(e) {
    return 'd' + b64u.enc(JSON.stringify({ i: e.id, t: e.title, v: e.venue, a: e.address || '', at: e.at, h: userById(e.hostId)?.name || '', vid: eventVenue(e)?.id || '' }));
  }
  function readDemoInvite(code) {
    try {
      const o = JSON.parse(b64u.dec(code.slice(1))), at = new Date(o?.at);
      if (!o || typeof o !== 'object' || isNaN(at)) return null;
      return { id: /^[\w-]{1,40}$/.test(o.i) ? o.i : '', title: clean(o.t, 80) || L('Кальянный сбор', 'Hookah meet-up'), venue: clean(o.v, 80), address: clean(o.a, 120),
        at: at.toISOString(), host: clean(o.h, 40), venueId: VENUES.some(v => v.id === o.vid) ? o.vid : '', past: isPast({ at: at.toISOString() }) };
    } catch (err) { return null; }
  }
  async function inviteLink(e) {
    if (!SERVER) { prefs.set('sent.' + e.id, '1'); return siteBase() + '#/join/' + demoInviteCode(e); }
    return siteBase() + '#/join/' + (await api('POST', `/events/${e.id}/link`)).token;
  }
  const whenText = at => { const d = new Date(at); return `${fFull(d)}, ${fTime(d)}`; };
  const inviteText = e => L(`Зову на кальян: «${e.title}»\n📍 ${[e.venue, e.address].filter(Boolean).join(', ')}\n🕗 ${whenText(e.at)}\nОтветь по ссылке, придёшь или нет:`,
    `Join me for hookah: “${e.title}”\n📍 ${[e.venue, e.address].filter(Boolean).join(', ')}\n🕗 ${whenText(e.at)}\nLet me know if you’re coming:`);
  const tgShare = (url, text) => `https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`;
  const waShare = (text, phone = '') => `https://wa.me/${phone}?text=${encodeURIComponent(text)}`;
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (err) {
      const t = document.createElement('textarea'); t.value = text; t.setAttribute('readonly', ''); t.style.cssText = 'position:fixed;opacity:0';
      document.body.append(t); t.select(); try { document.execCommand('copy'); } catch (e2) { /* копирование недоступно */ } t.remove();
    }
    toast(L('Скопировано', 'Copied'));
  }
  function shareModal(e, url, phone = '') {
    const text = inviteText(e), full = text + '\n' + url;
    openModal(L('Позвать на сбор', 'Invite to the event'), `
      <p class="muted">${SERVER ? L('Друг откроет ссылку, войдёт по номеру и ответит «Иду» или «Не смогу». Вам придёт уведомление.', 'Your friend opens the link, signs in with their number and replies “Going” or “Can’t make it”. You get a notification.')
        : L('Друг откроет ссылку и увидит место, время и карту. Ответ он пришлёт вам в мессенджер.', 'Your friend opens the link and sees the place, time and map. They send their reply to you in the messenger.')}</p>
      <div class="share-preview">${esc(text)}<span class="mono">${esc(url)}</span></div>
      <div class="share-grid">
        ${phone ? '' : `<a class="share-btn share-tg" href="${esc(tgShare(url, text))}" target="_blank" rel="noopener noreferrer">${ICON.tg}<span>Telegram<small>${L('выбрать чат', 'pick a chat')}</small></span></a>`}
        <a class="share-btn share-wa" href="${esc(waShare(full, phone))}" target="_blank" rel="noopener noreferrer">${ICON.wa}<span>WhatsApp<small>${phone ? fmtPhone(phone) : L('выбрать чат', 'pick a chat')}</small></span></a>
        ${navigator.share ? `<button class="share-btn" type="button" id="sh-more">${ICON.share}<span>${L('Другое', 'More')}<small>${L('SMS, почта…', 'SMS, email…')}</small></span></button>` : ''}
        <button class="share-btn" type="button" id="sh-copy">${ICON.link}<span>${L('Скопировать', 'Copy')}<small>${L('текст и ссылку', 'text and link')}</small></span></button>
      </div>`, m => {
      $('#sh-copy', m).onclick = () => copyText(full);
      const more = $('#sh-more', m); if (more) more.onclick = () => navigator.share({ title: e.title, text, url }).catch(() => {});
    });
  }

  // Страница, которую видит друг, открыв ссылку-приглашение. Вход не обязателен, чтобы посмотреть.
  const JOIN_ANSWER = 'hp.joinAnswer', BACK = 'hp.back';
  const sess = { get: k => { try { return sessionStorage.getItem(k); } catch (e) { return null; } }, set: (k, v) => { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) { /* недоступно */ } } };
  function afterAuth() {
    const back = sess.get(BACK); sess.set(BACK, null);
    if (back && /^#\/join\/[\w-]{1,900}$/.test(back)) location.hash = back; else go('');
  }
  async function pageJoin(code) {
    const hash = location.hash, u = me();
    let ev = null, status = null;
    if (code[0] === 'd' && code.length > 20) {
      ev = readDemoInvite(code);
      // В демо у всех одни и те же примерные данные, поэтому «ваш сбор» — только там, где ссылку создали.
      if (ev?.id && prefs.get('sent.' + ev.id) && eventById(ev.id)) status = 'host';
      if (!status && ev) status = prefs.get('join.' + (ev.id || code.slice(1, 40))) || null;
    } else if (SERVER) {
      view.innerHTML = `<p class="muted" style="padding:40px 0;text-align:center">${L('Загружаем приглашение…', 'Loading the invitation…')}</p>`;
      try { const r = await api('GET', '/join/' + code); ev = r.event; status = r.status; } catch (err) { ev = null; }
      if (location.hash !== hash) return;
    }
    if (!ev) { view.innerHTML = emptyState(L('Приглашение не найдено', 'Invitation not found'), L('Ссылка устарела или сбор отменили. Попросите организатора прислать новую.', 'The link has expired or the event was cancelled. Ask the host to send a new one.'), `<a class="btn btn-primary btn-sm" href="#/">${L('На главную', 'Go home')}</a>`); return; }
    // Ответ, выбранный до входа, отправляем сразу после возвращения.
    const pending = sess.get(JOIN_ANSWER);
    if (SERVER && u && pending && pending.startsWith(code + ':') && !status) { sess.set(JOIN_ANSWER, null); return actions.joinAnswer({ code, status: pending.split(':').pop() }); }
    const v = ev.venueId ? venueById(ev.venueId) : VENUES.find(x => x.name === ev.venue);
    const q = placeQuery(ev.venue, ev.address);
    const answered = { going: L('Вы ответили: иду', 'You replied: going'), declined: L('Вы ответили: не смогу', 'You replied: can’t make it'), pending: L('Вы ещё не ответили', 'You haven’t replied yet'), host: L('Это ваш сбор', 'This is your event') };
    const memberLink = SERVER ? (status ? ev.id : '') : (status === 'host' ? ev.id : '');
    const replyBtns = `<button class="btn btn-primary" data-action="joinAnswer" data-code="${code}" data-status="going">${ICON.check}${L('Иду', 'Going')}</button>
      <button class="btn" data-action="joinAnswer" data-code="${code}" data-status="declined">${L('Не смогу', 'Can’t make it')}</button>`;
    view.innerHTML = `
      <section class="join ${u ? 'solo' : ''}">
        <div class="join-card">
          <span class="eyebrow">${ev.host ? L(`${esc(ev.host)} зовёт вас`, `${esc(ev.host)} invites you`) : L('Вас зовут на кальян', 'You’re invited for hookah')}</span>
          <h1>${esc(ev.title)}</h1>
          ${ev.past ? '' : `<p class="join-count"><span class="soon-dot"></span><span data-countdown="${ev.at}">${countdown(ev.at)}</span>${ev.going ? ` · ${L(`уже идут: ${ev.going}`, `${ev.going} going`)}` : ''}</p>`}
          <div class="ev-facts">
            <div class="fact"><small>${L('Заведение', 'Venue')}</small><b>${esc(ev.venue)}</b></div>
            ${ev.address ? `<div class="fact"><small>${L('Адрес', 'Address')}</small><b>${esc(ev.address)}</b></div>` : ''}
            <div class="fact"><small>${L('Когда', 'When')}</small><b>${cap(whenText(ev.at))}</b></div>
            ${v ? `<div class="fact"><small>${L('Часы работы', 'Opening hours')}</small><b>${esc(venueStatus(v).hours || '—')}</b></div>` : ''}
          </div>
          ${ev.past ? `<p class="muted">${L('Этот сбор уже прошёл.', 'This event has already passed.')}</p>`
            : status && status !== 'pending' ? `<div class="join-status"><b>${answered[status] || ''}</b>${memberLink ? `<a class="btn btn-sm" href="#/event/${memberLink}">${L('Открыть сбор', 'Open the event')} →</a>` : ''}
                ${status !== 'host' ? `<button class="link-btn" data-action="joinChange" data-code="${code}" data-key="${esc(ev.id || code.slice(1, 40))}">${L('Изменить ответ', 'Change reply')}</button>` : ''}</div>
                ${!SERVER && status !== 'host' ? `<div id="join-reply"></div>` : ''}`
            : `<div class="join-reply-btns">${replyBtns}</div>
               ${SERVER && !u ? `<p class="muted join-note">${L('Чтобы ответить, войдите или зарегистрируйтесь по номеру. Это займёт минуту, ответ сохранится.', 'To reply, sign in or sign up with your number. It takes a minute and your reply is kept.')}</p>` : ''}
               ${!SERVER ? `<p class="muted join-note">${L('Ответ уйдёт организатору сообщением в Telegram или WhatsApp.', 'Your reply goes to the host as a Telegram or WhatsApp message.')}</p>` : ''}`}
          <div class="btn-row">
            ${v ? `<button class="btn btn-sm" data-action="showVenue" data-vid="${v.id}">${ICON.home}${L('На нашей карте', 'On our map')}</button>` : ''}
            <a class="btn btn-sm" href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}" target="_blank" rel="noopener noreferrer">${ICON.pin}Google ${L('Карты', 'Maps')}</a>
            <a class="btn btn-sm" href="https://2gis.kg/bishkek/search/${encodeURIComponent(ev.venue)}${v ? `?m=${v.lon},${v.lat}/18` : ''}" target="_blank" rel="noopener noreferrer">${ICON.pin}2ГИС</a>
            ${ev.past ? '' : `<button class="btn btn-sm" data-action="joinCalendar">${ICON.cal}${L('В календарь', 'Add to calendar')}</button>`}
          </div>
        </div>
        ${u ? '' : `<aside class="join-about"><h2>${L('Что такое Hookah Party', 'What is Hookah Party')}</h2>
          <ul><li>${ICON.home}<span>${L('Кальянные Бишкека на одной карте: адреса, часы, что открыто сейчас', 'Bishkek hookah lounges on one map: addresses, hours, what’s open now')}</span></li>
          <li>${ICON.hookah}<span>${L('Общий выбор табака: каждый отмечает вкусы, популярное поднимается наверх', 'A shared tobacco pick: everyone marks flavours, popular ones rise to the top')}</span></li>
          <li>${ICON.wallet}<span>${L('Счёт поровну и напоминание о встрече', 'An even bill split and a reminder before you meet')}</span></li></ul>
          <a class="btn btn-sm" href="#/register">${L('Создать аккаунт', 'Create account')}</a></aside>`}
      </section>`;
    view._join = ev;
    if (!SERVER && status && status !== 'host' && status !== 'pending') replyToHost($('#join-reply'), ev, status);
  }
  // В демо ответ организатору — готовое сообщение в мессенджер.
  function replyToHost(box, ev, status) {
    if (!box) return;
    const text = status === 'going' ? L(`Иду на «${ev.title}» (${whenText(ev.at)}) 🙌`, `I’m coming to “${ev.title}” (${whenText(ev.at)}) 🙌`)
      : L(`Не смогу прийти на «${ev.title}», в другой раз!`, `Can’t make it to “${ev.title}”, next time!`);
    box.innerHTML = `<p class="muted" style="margin:10px 0 8px">${L('Сообщите организатору:', 'Let the host know:')}</p><div class="btn-row">
      <a class="btn btn-sm share-tg" href="${esc(tgShare(location.href, text))}" target="_blank" rel="noopener noreferrer">${ICON.tg}Telegram</a>
      <a class="btn btn-sm share-wa" href="${esc(waShare(text))}" target="_blank" rel="noopener noreferrer">${ICON.wa}WhatsApp</a></div>`;
  }

  // ---------- Действия ----------
  function go(path) { const h = '#/' + path; if (location.hash === h) route(); else location.hash = h; }
  function requireUser() { if (me()) return true; toast(L('Войдите, чтобы продолжить', 'Sign in to continue')); go('login'); return false; }
  // Один активный сбор на организатора, не больше 12 созданий и 12 отмен в сутки (на сервере — то же самое, обязательно).
  const EV_LIMIT = 12;
  const evCount = (u, a) => secRead('hp.evlog', []).filter(x => x.u === u.id && x.a === a && Date.now() - x.at < 864e5).length;
  const evLog = (u, a) => secWrite('hp.evlog', [...secRead('hp.evlog', []).filter(x => Date.now() - x.at < 864e5), { u: u.id, a, at: Date.now() }]);
  function createBlocked() {
    const u = me(), active = u && db.events.find(e => e.hostId === u.id && !isPast(e));
    if (active) {
      openModal(L('У вас уже есть активный сбор', 'You already have an active event'), `
        <p class="muted" style="max-width:52ch">${L(`«${esc(active.title)}» — ${esc(whenLabel(active))}. Новый сбор можно создать после того, как этот пройдёт, или отменив его.`, `“${esc(active.title)}” — ${esc(whenLabel(active))}. You can create a new one after this event ends, or by cancelling it.`)}</p>
        <div class="modal-foot"><button class="btn btn-danger" type="button" data-action="deleteEvent" data-id="${active.id}">${L('Отменить этот сбор', 'Cancel this event')}</button>
          <a class="btn btn-primary" href="#/event/${active.id}">${L('Открыть сбор', 'Open event')}</a></div>`);
      return true;
    }
    if (!SERVER && u && evCount(u, 'create') >= EV_LIMIT) { toast(L(`За сутки можно создать не больше ${EV_LIMIT} сборов.`, `You can create at most ${EV_LIMIT} events per day.`), 'err'); return true; }
    return false;
  }
  const newEventForm = (extra = {}) => createBlocked() || eventForm({ heading: L('Новый сбор', 'New event'), submitLabel: L('Создать и пригласить', 'Create and invite'), onSave: createEvent, ...extra });

  const actions = {
    closeModal,
    newEvent() { if (requireUser()) newEventForm(); },
    inviteUser({ id }) { if (requireUser()) newEventForm({ preset: [{ userId: id }] }); },
    gatherHere({ vid }) {
      if (!requireUser()) return;
      const v = venueById(vid);
      newEventForm({ data: { venue: v.name, address: v.addr } });
    },
    showVenue({ vid }) { pendingVenue = vid; go('venues'); },
    venueOpen() { venueOpenOnly = !venueOpenOnly; render(); },
    openInvites() { tab.home = 'invites'; prefs.set('tab.home', 'invites'); go('events'); },
    repeatEvent({ id }) {
      const e = eventById(id), u = me(); if (!e || !u || createBlocked()) return;
      const next = new Date(e.at);
      do next.setDate(next.getDate() + 7); while (next < Date.now());
      const preset = [...(e.hostId !== u.id ? [{ userId: e.hostId }] : []),
        ...e.invites.filter(i => i.userId !== u.id && i.status !== 'declined').map(i => i.userId ? { userId: i.userId } : { phone: i.phone })];
      eventForm({ heading: L('Повторить сбор', 'Repeat event'), submitLabel: L('Создать и пригласить', 'Create and invite'), data: { ...e, at: next.toISOString() }, preset, onSave: createEvent });
    },
    editEvent({ id }) {
      const e = eventById(id); if (!e) return;
      eventForm({
        heading: L('Изменить сбор', 'Edit event'), submitLabel: L('Сохранить', 'Save'), data: e, withPicker: false,
        onSave(fields) {
          act(() => Object.assign(e, fields), 'PATCH', `/events/${e.id}`, fields).then(() => { closeModal(); toast(L('Сбор обновлён', 'Event updated')); render(); }, quiet);
        }
      });
    },
    editBill({ id }) {
      const e = eventById(id); if (!e) return;
      openModal(L('Складчина', 'Bill'), `<form class="form" id="bill-form">
        <div class="row-2"><div class="field"><label for="bl-h">${L('Кальянов', 'Hookahs')}</label><input id="bl-h" type="number" min="0" max="20" value="${e.hookahs}"></div>
          <div class="field"><label for="bl-p">${L('Цена одного, сом', 'Price each, KGS')}</label><input id="bl-p" type="number" min="0" step="50" value="${e.price}"></div></div>
        <p class="muted" id="bl-sum"></p>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="submit">${L('Сохранить', 'Save')}</button></div></form>`, m => {
        const n = goingIds(e).length, upd = () => {
          const t = (+$('#bl-h', m).value || 0) * (+$('#bl-p', m).value || 0);
          $('#bl-sum', m).textContent = L(`Итого ${money(t)}, с каждого из ${n}: ${money(n ? t / n : 0)}`, `Total ${money(t)}, each of ${n}: ${money(n ? t / n : 0)}`);
        };
        $$('input', m).forEach(i => i.addEventListener('input', upd)); upd();
        $('#bill-form', m).addEventListener('submit', ev => {
          ev.preventDefault();
          const hookahs = Math.max(0, Math.min(20, parseInt($('#bl-h', m).value, 10) || 0)), price = Math.max(0, parseInt($('#bl-p', m).value, 10) || 0);
          act(() => { e.hookahs = hookahs; e.price = price; }, 'PUT', `/events/${e.id}/bill`, { hookahs, price }).then(() => { closeModal(); render(); }, quiet);
        });
      });
    },
    togglePaid({ id, user }) {
      const e = eventById(id); if (!e || e.hostId !== me()?.id) return;
      act(() => { if (e.paid[user]) delete e.paid[user]; else e.paid[user] = true; }, 'POST', `/events/${id}/paid/${user}`).then(() => render(), quiet);
    },
    toggleRemind({ id }) {
      const e = eventById(id), u = me(); if (!e || !u) return;
      if (remindOn(e, u)) { remindSet(e, u, { on: false }); toast(L('Напоминание выключено', 'Reminder off')); render(); return; }
      remindSet(e, u, { on: true, done: null }); render();
      toast(L('Напомним за час, пока сайт открыт. Надёжнее добавить сбор в календарь.', 'We will remind you an hour before while the site is open. Adding it to your calendar is more reliable.'));
      try { if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {}); } catch (err) { /* уведомления недоступны */ }
      checkReminders();
    },
    ics({ id }) { const e = eventById(id); if (e) calendarModal(e); },
    async shareEvent({ id, via, phone }) {
      const e = eventById(id); if (!e) return;
      let url; try { url = await inviteLink(e); } catch (err) { return toast(apiMsg(err), 'err'); }
      shareModal(e, url, /^996\d{9}$/.test(phone || '') ? phone : '');
      if (via) $(`.modal .share-${via}`)?.focus();
    },
    joinCalendar() { const ev = view._join; if (ev) calendarModal({ id: ev.id, title: ev.title, venue: ev.venue, address: ev.address, at: ev.at, desc: ev.host ? L(`Зовёт ${ev.host}`, `Invited by ${ev.host}`) : '' }); },
    joinChange({ code, key }) {
      if (SERVER) { $('.join-status')?.replaceWith(Object.assign(document.createElement('div'), { className: 'join-reply-btns' })); $('.join-reply-btns').innerHTML = `<button class="btn btn-primary" data-action="joinAnswer" data-code="${code}" data-status="going">${ICON.check}${L('Иду', 'Going')}</button><button class="btn" data-action="joinAnswer" data-code="${code}" data-status="declined">${L('Не смогу', 'Can’t make it')}</button>`; return; }
      prefs.set('join.' + key, ''); render();
    },
    async joinAnswer({ code, status }) {
      status = status === 'going' ? 'going' : 'declined';
      if (!SERVER) {
        const ev = view._join || readDemoInvite(code); if (!ev) return;
        prefs.set('join.' + (ev.id || code.slice(1, 40)), status);
        render(); return;
      }
      if (!me()) { sess.set(BACK, '#/join/' + code); sess.set(JOIN_ANSWER, code + ':' + status); toast(L('Войдите — и ответ сразу уйдёт организатору', 'Sign in and your reply goes straight to the host')); return go('login'); }
      try {
        const r = await api('POST', '/join/' + code, { status });
        applyData(r.data);
        toast(status === 'going' ? L('Отлично, ждём вас! Выберите табаки.', 'Great, see you there! Pick your tobacco.') : L('Организатор узнает, что вы не придёте', 'The host will know you can’t make it'));
        go('event/' + r.eventId);
      } catch (err) { toast(apiMsg(err), 'err'); render(); }
    },
    deleteComment({ id, comment }) {
      const e = eventById(id); if (!e) return;
      act(() => { e.comments = e.comments.filter(c => c.id !== comment); }, 'DELETE', `/comments/${comment}`).then(() => render(), quiet);
    },
    invite({ id }) {
      const e = eventById(id); if (!e) return;
      let picker;
      openModal(L('Пригласить на сбор', 'Invite to the event'), `<div id="inv-picker"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="button" id="inv-send">${L('Отправить приглашения', 'Send invitations')}</button></div>`, m => {
        picker = invitePicker($('#inv-picker', m), [e.hostId, ...e.invites.map(i => i.userId || i.phone)]);
        $('#inv-send', m).onclick = () => {
          const list = toInvites(picker.get());
          if (!list.length) return toast(L('Выберите хотя бы одного человека', 'Choose at least one person'), 'err');
          act(() => { e.invites.push(...list); }, 'POST', `/events/${e.id}/invites`, { invites: picker.get() })
            .then(() => { closeModal(); toast(L(`Приглашения отправлены: ${list.length}`, `Invitations sent: ${list.length}`)); render(); }, quiet);
        };
      });
    },
    rsvp({ id, status }) {
      const e = eventById(id), u = me(), inv = e && u && myInvite(e, u); if (!inv) return;
      act(() => {
        inv.status = status; inv.at = new Date().toISOString();
        if (status !== 'going') { delete e.picks[u.id]; delete e.bowls[u.id]; delete e.paid[u.id]; }
      }, 'POST', `/events/${id}/rsvp`, { status }).then(() => { toast(status === 'going' ? L('Отлично, ждём вас! Выберите табаки.', 'Great, see you there! Pick your tobacco.') : L('Организатор узнает, что вы не придёте', 'The host will know you can’t make it')); render(); }, quiet);
    },
    pickTobacco({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      const MAX = 5, cur = new Set(e.picks[u.id] || []);
      const list = [...CATALOG.tobaccos].sort((a, b) => u.favs.includes(b.id) - u.favs.includes(a.id));
      openModal(L('Мои табаки', 'My tobacco'), `
        <p class="muted">${L(`Отметьте до ${MAX} вкусов. Избранные стоят первыми.`, `Mark up to ${MAX} flavours. Favourites come first.`)}</p>
        <input class="input" id="pk-q" type="search" placeholder="${L('Поиск по бренду или вкусу', 'Search by brand or flavour')}" aria-label="${L('Поиск табака', 'Search tobacco')}">
        <div class="pick-list" id="pk-list">${list.map(t => `<label class="pick-item" data-s="${esc((t.brand + ' ' + t.flavor + ' ' + t.note.join(' ')).toLowerCase())}">
          <input type="checkbox" value="${t.id}" ${cur.has(t.id) ? 'checked' : ''}>${flavorThumb(t)}<span><b>${esc(t.brand)}</b> ${esc(t.flavor)}${u.favs.includes(t.id) ? ` <em class="tag-friend">${L('избранное', 'favourite')}</em>` : ''}<small>${esc(tr(t.note))}</small></span><em>${t.strength}/10</em></label>`).join('')}</div>
        <div class="modal-foot"><span class="muted" id="pk-count" style="margin-right:auto;align-self:center"></span>
          <button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="button" id="pk-save">${L('Сохранить', 'Save')}</button></div>`, m => {
        const boxes = $$('input[type=checkbox]', m);
        const upd = () => {
          const n = boxes.filter(b => b.checked).length;
          $('#pk-count', m).textContent = L(`Выбрано ${n} из ${MAX}`, `${n} of ${MAX} selected`);
          boxes.forEach(b => { b.disabled = !b.checked && n >= MAX; });
        };
        boxes.forEach(b => b.addEventListener('change', upd)); upd();
        $('#pk-q', m).addEventListener('input', ev => {
          const q = ev.target.value.trim().toLowerCase();
          $$('.pick-item', m).forEach(l => { l.hidden = !!q && !l.dataset.s.includes(q); });
        });
        $('#pk-save', m).onclick = () => {
          const ids = boxes.filter(b => b.checked).map(b => b.value);
          act(() => { if (ids.length) e.picks[u.id] = ids; else delete e.picks[u.id]; }, 'PUT', `/events/${e.id}/picks`, { ids })
            .then(() => { closeModal(); toast(L('Ваш выбор учтён', 'Your pick is saved')); render(); }, quiet);
        };
      });
    },
    pickBowl({ id }) {
      const e = eventById(id), u = me(); if (!e || !canVote(e, u)) return;
      const cur = e.bowls[u.id];
      openModal(L('Чаша', 'Bowl'), `<div class="pick-list">${CATALOG.bowls.map(b => `<label class="pick-item"><input type="radio" name="bowl" value="${b.id}" ${cur === b.id ? 'checked' : ''}>
          <span><b>${esc(tr(b.name))}</b><small>${tr(BOWL_TYPE[b.type])} · ${esc(tr(b.note))}</small></span></label>`).join('')}</div>
        <div class="modal-foot">${cur ? `<button class="btn btn-ghost" type="button" id="bw-clear" style="margin-right:auto">${L('Снять голос', 'Remove vote')}</button>` : ''}
          <button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="button" id="bw-save">${L('Сохранить', 'Save')}</button></div>`, m => {
        $('#bw-save', m).onclick = () => {
          const v = $('input[name=bowl]:checked', m)?.value;
          if (!v) return toast(L('Выберите чашу', 'Choose a bowl'), 'err');
          act(() => { e.bowls[u.id] = v; }, 'PUT', `/events/${e.id}/bowl`, { bowlId: v }).then(() => { closeModal(); render(); }, quiet);
        };
        const c = $('#bw-clear', m); if (c) c.onclick = () => act(() => { delete e.bowls[u.id]; }, 'PUT', `/events/${e.id}/bowl`, { bowlId: null }).then(() => { closeModal(); render(); }, quiet);
      });
    },
    deleteEvent({ id }) {
      const e = eventById(id), u = me();
      // Отменить сбор может только его организатор (сервер проверяет это ещё раз).
      if (!e || !u || e.hostId !== u.id) return;
      if (!SERVER && evCount(u, 'delete') >= EV_LIMIT) return toast(L(`За сутки можно отменить не больше ${EV_LIMIT} сборов.`, `You can cancel at most ${EV_LIMIT} events per day.`), 'err');
      openModal(L('Отменить сбор?', 'Cancel the event?'), `<p class="muted">${L(`Сбор «${esc(e.title)}» исчезнет у всех приглашённых. Это действие нельзя отменить.`, `“${esc(e.title)}” will disappear for everyone invited. This cannot be undone.`)}</p>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Оставить', 'Keep it')}</button><button class="btn btn-danger" type="button" id="del-ok">${L('Отменить сбор', 'Cancel event')}</button></div>`, m => {
        $('#del-ok', m).onclick = () => act(() => { db.events = db.events.filter(x => x.id !== id); evLog(u, 'delete'); }, 'DELETE', `/events/${id}`).then(() => { closeModal(); toast(L('Сбор отменён', 'Event cancelled')); go('events'); }, quiet);
      });
    },
    tobacco({ id }) { openTobacco(id); },
    async fav({ id }, el) {
      const u = me(); if (!u) return;
      const adding = !u.favs.includes(id), t = tobacco(id);
      try { await act(() => { u.favs = adding ? [...u.favs, id] : u.favs.filter(x => x !== id); }, 'POST', `/me/favs/${id}`); } catch (e) { return; }
      favPop = adding ? id : null;
      const inModal = el.closest('.modal');
      render();
      if (inModal) openTobacco(id);
      favPop = null;
      toast(adding ? L(`${t.brand} ${t.flavor} добавлен в избранное`, `${t.brand} ${t.flavor} added to favourites`) : L(`${t.brand} ${t.flavor} убран из избранного`, `${t.brand} ${t.flavor} removed from favourites`));
    },
    newMix() {
      if (!requireUser()) return;
      const opts = `<option value="">— ${L('не выбран', 'none')} —</option>` + CATALOG.tobaccos.map(t => `<option value="${t.id}">${esc(t.brand)} ${esc(t.flavor)}</option>`).join('');
      openModal(L('Свой микс', 'Your mix'), `<form class="form" id="mix-form">
        <div class="field"><label for="mx-name">${L('Название', 'Name')}</label><input id="mx-name" maxlength="40" placeholder="${L('Например, Ягодный лёд', 'For example, Berry Ice')}"></div>
        ${[0, 1, 2].map(i => `<div class="mix-row"><div class="field"><label for="mx-t${i}">${L('Табак', 'Tobacco')} ${i + 1}${i === 2 ? ` <span class="muted">(${L('необязательно', 'optional')})</span>` : ''}</label><select id="mx-t${i}" class="input">${opts}</select></div>
          <div class="field"><label for="mx-p${i}">${L('Доля, %', 'Share, %')}</label><input id="mx-p${i}" type="number" min="0" max="100" step="5" value="${[60, 40, 0][i]}"></div></div>`).join('')}
        <div class="mix-bar" id="mx-bar"></div>
        <p class="muted" id="mx-sum"></p>
        <div class="error" id="mx-err"></div>
        <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-primary" type="submit">${L('Опубликовать', 'Publish')}</button></div></form>`, m => {
        const parts = () => [0, 1, 2].map(i => ({ id: $(`#mx-t${i}`, m).value, pct: parseInt($(`#mx-p${i}`, m).value, 10) || 0 })).filter(p => p.id && p.pct > 0);
        const upd = () => {
          const p = parts(), sum = p.reduce((s, x) => s + x.pct, 0);
          $('#mx-sum', m).textContent = L(`Сумма долей: ${sum}%`, `Total: ${sum}%`) + (sum !== 100 ? L(' · должно быть 100%', ' · must be 100%') : '');
          $('#mx-bar', m).innerHTML = p.map(x => `<span style="flex:${x.pct};--pc:${tobacco(x.id).color}"></span>`).join('');
        };
        $$('input, select', m).forEach(i => i.addEventListener('input', upd)); upd();
        $('#mix-form', m).addEventListener('submit', ev => {
          ev.preventDefault();
          const err = $('#mx-err', m), name = clean($('#mx-name', m).value, 40), p = parts();
          if (!name) return void (err.textContent = L('Придумайте название микса.', 'Give the mix a name.'));
          if (p.length < 2) return void (err.textContent = L('Выберите хотя бы два табака с долей больше нуля.', 'Choose at least two tobaccos with a share above zero.'));
          if (new Set(p.map(x => x.id)).size !== p.length) return void (err.textContent = L('Табаки в миксе не должны повторяться.', 'Each tobacco can appear only once.'));
          if (p.reduce((s, x) => s + x.pct, 0) !== 100) return void (err.textContent = L('Доли должны давать в сумме 100%.', 'Shares must add up to 100%.'));
          act(() => { db.mixes.push({ id: uid('m'), name, authorId: me().id, parts: p.sort((a, b) => b.pct - a.pct), likes: [], at: new Date().toISOString() }); }, 'POST', '/mixes', { name, parts: p })
            .then(() => { closeModal(); toast(L('Микс опубликован', 'Mix published')); tab.cat = 'mixes'; prefs.set('tab.cat', 'mixes'); if (location.hash !== '#/catalog') go('catalog'); else render(); }, quiet);
        });
      });
    },
    likeMix({ id }) {
      if (!requireUser()) return;
      const u = me(), m = db.mixes.find(x => x.id === id); if (!m) return;
      act(() => { m.likes = m.likes.includes(u.id) ? m.likes.filter(x => x !== u.id) : [...m.likes, u.id]; }, 'POST', `/mixes/${id}/like`).then(() => render(), quiet);
    },
    catTab({ tab: t }) { tab.cat = t; prefs.set('tab.cat', t); cat.q = ''; if (location.hash !== '#/catalog') go('catalog'); else { closeModal(); render(); } },
    catFilter(ds) {
      if ('strength' in ds) cat.strength = ds.strength;
      if ('tag' in ds) cat.tag = ds.tag;
      render();
    },
    switchTab({ tabs, tab: t }) { switchTo(tabs, t); },
    bell(_, el) { openBell(el); },
    async readAll() { closePop(); await markRead('all'); render(); },
    async openNotif({ id, href, story }) {
      closePop();
      await markRead([id]);
      if (story) { pendingStory = story; tab.history = 'all'; }
      if (location.hash === href) route(); else location.hash = href;
    },
    reactPick({ scope, id, comment }, el) { openEmojiPop(el, [[null, QUICK]], em => setReaction(scope, id, comment, em), 'r' + comment); },
    react({ scope, id, comment, emoji }) { if (requireUser()) setReaction(scope, id, comment, emoji); },
    emoji({ target }, el) {
      const ta = (target && $('#' + target)) || el.closest('form')?.querySelector('textarea');
      openEmojiPop(el, EMOJI, em => insertAtCursor(ta, em), 'e' + (target || 'story'));
    },
    storyFire({ id }) {
      if (!requireUser()) return;
      const e = eventById(id), u = me(); if (!e?.story) return;
      act(() => { e.story.fire = e.story.fire.includes(u.id) ? e.story.fire.filter(x => x !== u.id) : [...e.story.fire, u.id]; }, 'POST', `/events/${id}/story/fire`).then(() => render(), quiet);
    },
    deleteStoryComment({ id, comment }) {
      const e = eventById(id), u = me(); if (!e?.story || !u) return;
      act(() => { e.story.comments = e.story.comments.filter(c => !(c.id === comment && c.userId === u.id)); }, 'DELETE', `/comments/${comment}`).then(() => render(), quiet);
    },
    likeThis({ id }) {
      if (!requireUser()) return;
      const e = eventById(id);
      newEventForm({ data: { title: L(`Как «${e.title}»`, `Like “${e.title}”`), venue: e.venue, address: e.address, hookahs: e.hookahs, price: e.price } });
    },
    openStory({ id }) { pendingStory = id; tab.history = 'all'; go('history'); },
    homeView({ view: v }) { prefs.set('homeView', v); render(); },
    calNav({ step }) { cal.m += +step; if (cal.m < 0) { cal.m = 11; cal.y--; } if (cal.m > 11) { cal.m = 0; cal.y++; } cal.day = null; render(); },
    calDay({ day }) { cal.day = cal.day === day ? null : day; render(); },
    toggleFriend({ id }) {
      const u = me(), p = userById(id); if (!u || !p) return;
      // В демо дружба взаимная сразу; на сервере здесь будет заявка в друзья.
      const was = isFriend(u, p);
      act(() => {
        if (was) { u.friends = u.friends.filter(x => x !== id); p.friends = p.friends.filter(x => x !== u.id); }
        else { u.friends.push(id); if (!p.friends.includes(u.id)) p.friends.push(u.id); }
      }, 'POST', `/friends/${id}`).then(() => { toast(was ? L(`${p.name} удалён из друзей`, `${p.name} removed from friends`) : L(`${p.name} теперь в друзьях`, `${p.name} is now your friend`)); render(); }, quiet);
    },
    setLang({ lang: l }) { if (l === lang) return; lang = l; prefs.set('lang', l); applyLook(); render(); },
    cycleTheme() {
      const order = ['auto', 'light', 'dark'], cur = prefs.get('theme', 'auto');
      const next = order[(order.indexOf(cur) + 1) % order.length];
      prefs.set('theme', next); applyLook(); render(); toast(`${L('Тема', 'Theme')}: ${tr(THEMES[next][0]).toLowerCase()}`);
    },
    setTheme({ theme }) { prefs.set('theme', theme); applyLook(); render(); },
    setAccent({ accent }) { prefs.set('accent', accent); applyLook(); render(); },
    setSeason({ season }) { prefs.set('season', season); prefs.set('ribbonClosed', ''); applyLook(); render(); },
    closeRibbon({ key }) { prefs.set('ribbonClosed', key); seasonRibbon(); },
    uploadAvatar() { const u = me(); pickAvatarFile(url => act(() => { u.avatar = url; }, 'PUT', '/me/avatar', { dataUrl: url }).then(() => { toast(L('Фото обновлено', 'Photo updated')); render(); }, quiet)); },
    removeAvatar() { const u = me(); act(() => { u.avatar = null; }, 'DELETE', '/me/avatar').then(() => render(), quiet); },
    logout() {
      act(() => { secLog('logout'); db.session = null; db.sessionExp = null; }, 'POST', '/auth/logout', {})
        .then(() => { toast(L('Вы вышли из аккаунта', 'You have signed out')); go(''); }, quiet);
    },
    logoutAll() {
      act(null, 'POST', '/auth/logout-all', {}).then(() => { toast(L('Все сессии завершены', 'All sessions ended')); go(''); }, quiet);
    },
    async installApp() {
      // Android и компьютеры: системное окно установки. iPhone: инструкция «Поделиться → На экран „Домой“».
      if (installPrompt) { installPrompt.prompt(); try { await installPrompt.userChoice; } catch (e) { /* закрыли окно */ } installPrompt = null; return; }
      const standalone = window.matchMedia?.('(display-mode: standalone)').matches || navigator.standalone;
      if (standalone) return toast(L('Приложение уже установлено и открыто', 'The app is already installed and open'));
      const step = (n, t) => `<li><b class="mono">${n}</b><span>${t}</span></li>`;
      openModal(L('Установить на iPhone', 'Install on iPhone'), `<ol class="install-steps">
          ${step(1, L('Откройте этот сайт в Safari.', 'Open this site in Safari.'))}
          ${step(2, L('Нажмите «Поделиться» — квадрат со стрелкой вверх внизу экрана.', 'Tap Share — the square with an arrow at the bottom of the screen.'))}
          ${step(3, L('Выберите «На экран „Домой“» и нажмите «Добавить».', 'Choose “Add to Home Screen” and tap Add.'))}
        </ol>
        <p class="muted">${L('На Android: меню Chrome (⋮) → «Установить приложение».', 'On Android: Chrome menu (⋮) → “Install app”.')}</p>
        <div class="modal-foot"><button class="btn btn-primary" type="button" data-action="closeModal">${L('Понятно', 'Got it')}</button></div>`);
    },
    clearSecLog() { secWrite(SEC_LOG, []); render(); },
    reset() { db = withStories(seed()); save(); toast(L('Демо-данные восстановлены', 'Demo data restored')); go(''); },
    reload() { location.reload(); },
    info({ key }) {
      const texts = {
        rules: [['Правила сервиса', 'Terms of use'], ['Сервис предназначен для лиц старше 18 лет. Организатор отвечает за бронь в заведении. Запрещено приглашать людей без их согласия и рассылать рекламу.', 'The service is for people aged 18 and over. The host is responsible for the booking. Inviting people without consent and sending ads is not allowed.']],
        privacy: [['Конфиденциальность', 'Privacy'], ['Номер телефона нужен для входа и чтобы друзья могли пригласить вас. Полный номер видят только друзья и участники общих сборов. Мы не передаём данные третьим лицам.', 'Your phone number is used to sign in and so friends can invite you. Only friends and people from shared events see the full number. We do not share data with third parties.']],
        venues: [['Заведениям', 'For venues'], ['Хотите оказаться на карте Hookah Party или поправить данные о своём заведении? Напишите на hello@hookahparty.app.', 'Want to appear on the Hookah Party map or correct your venue details? Write to hello@hookahparty.app.']],
        faq: [['Вопросы и ответы', 'FAQ'], ['Как пригласить друга без аккаунта? Введите его номер в поле приглашения. Сбор появится у него сразу после регистрации с этим номером.', 'How do I invite a friend without an account? Enter their number in the invite field. The event appears for them as soon as they sign up with that number.']]
      };
      const [t, body] = texts[key] || texts.faq;
      openModal(tr(t), `<p class="muted" style="max-width:60ch">${esc(tr(body))}</p><div class="modal-foot"><button class="btn btn-primary" type="button" data-action="closeModal">${L('Понятно', 'Got it')}</button></div>`);
    }
  };

  document.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (!el || !actions[el.dataset.action]) return;
    e.preventDefault();
    Promise.resolve(actions[el.dataset.action]({ ...el.dataset }, el)).catch(() => {});
  });

  // ---------- Роутер ----------
  const view = $('#view');
  // render() перерисовывает текущую страницу без прокрутки наверх; route() — полный переход.
  const navFor = () => ({ join: 'events', admin: 'admin', notifications: 'notifications', history: 'history', venues: 'venues', catalog: 'catalog', events: 'events', event: 'events', people: 'people', user: 'people', profile: 'profile', login: 'profile', register: 'profile' })[location.hash.replace(/^#\/?/, '').split('/')[0]] || '';
  const PAGES = new Set(['', 'venues', 'events', 'event', 'catalog', 'people', 'user', 'how', 'profile', 'login', 'register', 'history', 'notifications', 'admin', 'join', 'privacy', 'terms']);
  const NEEDS_ARG = new Set(['event', 'user', 'join']);
  function render() {
    const hash = location.hash.replace(/^#\/?/, '');
    let [page = '', arg, extra] = hash.split('/');
    // Ссылка-приглашение в демо длиннее обычных адресов: в ней лежат данные сбора.
    const long = page === 'join';
    const badArg = arg !== undefined && !(long ? /^[\w-]{1,900}$/ : /^[\w-]{1,40}$/).test(arg);
    if (!PAGES.has(page) || badArg || extra !== undefined || hash.length > (long ? 960 : 120) || (NEEDS_ARG.has(page) && !arg)) {
      if (/[<>"'`]|script|%3c/i.test(hash)) secLog('bad_url', hash.slice(0, 60));
      page = 'notfound';
    }
    if (!SERVER && db.session && db.sessionExp && Date.now() > db.sessionExp) { secLog('session_expired'); db.session = null; save(); toast(L('Сессия истекла, войдите снова', 'Your session has expired, please sign in again')); }
    const nav = navFor();
    renderChrome(nav);
    updateTitle();
    switch (page) {
      case 'venues': pageVenues(); break;
      case 'events': pageEvents(); break;
      case 'event': pageEvent(arg); break;
      case 'catalog': pageCatalog(); break;
      case 'people': pagePeople(); break;
      case 'user': pageUser(arg); break;
      case 'how': pageHow(); break;
      case 'history': pageHistory(); break;
      case 'notifications': pageNotifications(); break;
      case 'admin': pageAdmin(); break;
      case 'join': pageJoin(arg); break;
      case 'privacy': case 'terms': pageLegal(page); break;
      case 'notfound': view.innerHTML = emptyState(L('Такой страницы нет', 'Page not found'), L('Возможно, ссылка устарела или в ней опечатка.', 'The link may be outdated or contain a typo.'), `<a class="btn btn-primary btn-sm" href="#/">${L('На главную', 'Go home')}</a>`); break;
      case 'profile': pageProfile(); break;
      case 'login': pageAuth('login'); break;
      case 'register': pageAuth('register'); break;
      default: pageHome();
    }
    inkAll();
  }
  let pendingStory = null;
  function route() {
    closeModal(); render(); window.scrollTo(0, 0); checkReminders();
    if (!reduceMotion()) { view.classList.remove('view-enter'); void view.offsetWidth; view.classList.add('view-enter'); }
    if (pendingStory) { const el = $('#story-' + pendingStory); pendingStory = null; if (el) { el.scrollIntoView({ block: 'start' }); window.scrollBy(0, -90); el.classList.add('flash'); } }
  }
  // Кнопка «Наверх» появляется после прокрутки.
  const toTop = document.createElement('button');
  toTop.className = 'to-top'; toTop.type = 'button'; toTop.hidden = true;
  toTop.innerHTML = svg('<path d="M12 19V5M5 12l7-7 7 7"/>');
  toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  document.body.append(toTop);
  window.addEventListener('scroll', () => { toTop.hidden = window.scrollY < 700; toTop.setAttribute('aria-label', L('Наверх', 'Back to top')); }, { passive: true });
  let installPrompt = null;
  window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); installPrompt = e; });
  window.addEventListener('hashchange', route);
  // На сервере раз в минуту подтягиваем новые уведомления, пока вкладка на экране.
  setInterval(async () => {
    if (!SERVER || !me() || document.visibilityState !== 'visible') return;
    const before = (db.notifications || []).map(n => n.id + n.read).join();
    try {
      const d = await api('GET', '/bootstrap');
      if ((d.notifications || []).map(n => n.id + n.read).join() !== before) { applyData(d); renderChrome(navFor()); updateTitle(); if (location.hash === '#/notifications') render(); }
    } catch (e) { /* сеть недоступна — попробуем позже */ }
  }, 60e3);
  // Ошибки на странице отправляем на сервер (не больше 5 за визит), чтобы видеть поломки раньше пользователей.
  let errSent = 0;
  const reportError = (msg, src = '', line = 0) => {
    if (!SERVER || errSent++ >= 5) return;
    api('POST', '/client-errors', { msg: String(msg).slice(0, 300), src: String(src).split('/').pop().slice(0, 120), line: line | 0, page: location.hash.split('/')[1] || 'home' }).catch(() => {});
  };
  window.addEventListener('error', ev => reportError(ev.message, ev.filename, ev.lineno));
  window.addEventListener('unhandledrejection', ev => reportError('promise: ' + (ev.reason?.message || ev.reason)));
  // Офлайн-режим: сайт открывается без сети и мгновенно. Не в приложении и не внутри чужой страницы.
  if ('serviceWorker' in navigator && !IN_APP && window.top === window && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
  }
  (async () => {
    const mode = await detectServer();
    if (mode === 'server') { SERVER = true; prefs.set('mode', 'server'); document.documentElement.dataset.mode = 'server'; await refresh(); }
    // Сайт с сервером открылся из офлайн-кеша: показываем честный экран, а не демо-данные вместо ваших.
    if (mode === 'offline' && prefs.get('mode') === 'server') {
      renderChrome('');
      view.innerHTML = emptyState(L('Нет соединения', 'No connection'), L('Сайт открылся без интернета. Ваши сборы и сообщения появятся, как только сеть вернётся.', 'The site opened without internet. Your events and messages will appear as soon as you are back online.'),
        `<button class="btn btn-primary btn-sm" type="button" data-action="reload">${L('Обновить', 'Reload')}</button>`);
      window.addEventListener('online', () => location.reload(), { once: true });
      return;
    }
    route();
    ageGate();
  })();
})();
