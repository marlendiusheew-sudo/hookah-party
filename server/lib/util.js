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
const safeAvatar = u => /^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/.test(String(u || '')) && String(u).length < 400000 ? String(u) : null;
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

module.exports = { digits, normPhone, validPhone, maskPhone, clean, validName, safeUrl, safeAvatar, isId, passIssue, ApiError, fail, uid, nowIso };
