'use strict';
// Общие проверки и очистка данных. Те же правила, что в браузере, но здесь они обязательные.

const digits = s => String(s ?? '').replace(/\D/g, '');

function normPhone(s) {
  let d = digits(s);
  if (d.length === 10 && d[0] === '0') d = '996' + d.slice(1);
  else if (d.length === 9) d = '996' + d;
  else if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1);
  return d;
}
const validPhone = d => /^\d{11,15}$/.test(d);
// Какие номера принимаем для регистрации, входа по SMS и приглашений: коды стран через запятую в ALLOWED_PHONE_PREFIXES,
// по умолчанию только 996 (Кыргызстан). SMS на номера других стран (в том числе платные) не уходят: иначе перебором чужих
// номеров легко потратить бюджет SMS. Длина номера для известных кодов проверяется точно.
const PHONE_LEN = { 996: 12, 7: 11 };
const phonePrefixes = () => String(process.env.ALLOWED_PHONE_PREFIXES || '996').split(',').map(s => s.replace(/\D/g, '')).filter(Boolean);
const phoneAllowed = d => validPhone(d) && phonePrefixes().some(p => d.startsWith(p) && (!PHONE_LEN[p] || d.length === PHONE_LEN[p]));
const maskPhone = d => `+${d.startsWith('996') ? '996' : d[0]} ••• ••• ${d.slice(-3)}`;

// Невидимые и управляющие символы, «переворот» текста, лишние пробелы, длина.
function clean(s, max = 500, multiline = false) {
  let t = String(s ?? '').normalize('NFC')
    .replace(/[​-‏‪-‮⁦-⁩﻿]/g, '')
    .replace(multiline ? /[\u0000-\u0009\u000B-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g, '');
  t = multiline ? t.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n') : t.replace(/\s+/g, ' ');
  return t.trim().slice(0, max);
}
const validName = s => /^[\p{L}\p{M}][\p{L}\p{M}\s'’.-]{1,39}$/u.test(s);
const safeUrl = u => /^https?:\/\/[^\s"'<>]+\.[^\s"'<>]+$/i.test(String(u || '')) && String(u).length <= 300 ? String(u) : '';
// Фото профиля: data:-адрес JPG, PNG или WebP не больше AVATAR_MAX байт (страница присылает квадрат 256 px в JPEG — обычно 20–60 КБ),
// и по первым байтам это действительно картинка заявленного формата.
const AVATAR_MAX = 100 * 1024;
const IMG_MAGIC = { png: b => b[0] === 0x89 && b.toString('latin1', 1, 4) === 'PNG', jpeg: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  webp: b => b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP' };
function safeAvatar(u) {
  const m = /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(String(u ?? ''));
  if (!m || m[2].length > Math.ceil(AVATAR_MAX / 3) * 4) return null;
  const b = Buffer.from(m[2], 'base64'), kind = m[1].startsWith('jp') ? 'jpeg' : m[1];
  return b.length >= 12 && b.length <= AVATAR_MAX && IMG_MAGIC[kind](b) ? String(u) : null;
}
const isId = s => typeof s === 'string' && /^[\w-]{1,40}$/.test(s);

const COMMON = ['password', 'qwerty', '123456', '12345678', '123456789', 'qwerty123', '11111111', 'hookah', 'hookah123', 'parol', 'bishkek'];
function passIssue(pass, phone = '') {
  const p = String(pass ?? ''), low = p.toLowerCase();
  if (p.length < 8 || p.length > 128) return 'weak_length';
  if (!/\p{L}/u.test(p) || !/\d/.test(p)) return 'weak_mix';
  if (COMMON.some(c => low.includes(c))) return 'weak_common';
  if (phone && digits(p).length >= 6 && phone.includes(digits(p))) return 'weak_phone';
  return '';
}

// Ошибка API: код, понятный текст на двух языках и HTTP-статус.
class ApiError extends Error {
  constructor(status, code, ru, en, extra = {}) {
    super(code);
    Object.assign(this, { status, code, ru, en, extra });
  }
}
const fail = (status, code, ru, en, extra) => { throw new ApiError(status, code, ru, en, extra); };

const uid = (p, crypto) => p + crypto.randomBytes(6).toString('base64url').replace(/[^\w]/g, '').slice(0, 8);
const nowIso = () => new Date().toISOString();

module.exports = { digits, normPhone, validPhone, phonePrefixes, phoneAllowed, maskPhone, clean, validName, safeUrl, safeAvatar, AVATAR_MAX, isId, passIssue, ApiError, fail, uid, nowIso };
