'use strict';
// Одноразовые коды из приложения для входа в панель администратора: TOTP (RFC 6238) поверх HOTP (RFC 4226),
// HMAC-SHA1, 6 цифр, новый код каждые 30 секунд. Подходит Google Authenticator, «Пароли» на iPhone, 1Password и др.
// Только встроенный crypto. Секрет — 20 случайных байт (160 бит, как советует RFC 4226), в базе — только зашифрованным.
const crypto = require('node:crypto');

const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ISSUER = 'Hookah Party';

// Base32 (RFC 4648) без «=» в конце: в таком виде ключ вводят в приложение вручную и передают в otpauth://.
function base32Encode(buf) {
  let out = '', bits = 0, acc = 0;
  for (const byte of buf) {
    acc = (acc << 8 | byte) & 0xfff; bits += 8;
    while (bits >= 5) { bits -= 5; out += ABC[acc >>> bits & 31]; }
  }
  if (bits) out += ABC[acc << (5 - bits) & 31];
  return out;
}
// Обратно в байты: регистр не важен, пробелы и «=» в конце пропускаются, другие знаки — ошибка.
function base32Decode(str) {
  const s = String(str ?? '').replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (!/^[A-Z2-7]*$/.test(s)) throw new Error('Ключ не в формате base32');
  const out = [];
  let bits = 0, acc = 0;
  for (const ch of s) {
    acc = (acc << 5 | ABC.indexOf(ch)) & 0xfff; bits += 5;
    if (bits >= 8) { bits -= 8; out.push(acc >>> bits & 255); }
  }
  return Buffer.from(out);
}

const generateSecret = () => base32Encode(crypto.randomBytes(20));
const keyOf = secret => Buffer.isBuffer(secret) ? secret : base32Decode(secret);
const counterAt = (timeMs, step) => Math.floor(timeMs / (step * 1000));

// HOTP: HMAC-SHA1 от номера шага (8 байт), «динамическое усечение» до 31 бита, последние digits цифр.
function hotp(key, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const bin = h.readUInt32BE(h[h.length - 1] & 0xf) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, '0');
}
// Код на момент timeMs. secret — строка base32 или байты.
const code = (secret, timeMs = Date.now(), { step = 30, digits = 6 } = {}) => hotp(keyOf(secret), counterAt(timeMs, step), digits);

// Проверка кода: подходят текущий шаг и соседние (window — запас на расхождение часов телефона и сервера).
// Возвращает номер шага, которому подошёл код, или null. Шаги не новее lastCounter не принимаются:
// однажды введённый код повторно не сработает. Сравнение — за постоянное время, по всему окну без досрочного выхода.
function verify(secret, input, { window = 1, lastCounter = 0, timeMs = Date.now(), step = 30, digits = 6 } = {}) {
  const given = String(input ?? '').replace(/\s+/g, '');
  if (given.length !== digits || !/^\d+$/.test(given)) return null;
  const key = keyOf(secret), now = counterAt(timeMs, step), want = Buffer.from(given);
  let found = null;
  for (let c = now - window; c <= now + window; c++) {
    const same = crypto.timingSafeEqual(Buffer.from(hotp(key, c, digits)), want);
    if (same && c > lastCounter && found === null) found = c;
  }
  return found;
}

// Ссылка для приложения (её же кодируем в QR). Метка — «Hookah Party:<скрытый номер>»: полный номер в приложение не попадает.
function otpauthUri({ secret, label, issuer = ISSUER }) {
  if (String(label ?? '').replace(/\D/g, '').length > 6) throw new Error('В метке не должно быть полного номера');
  const e = encodeURIComponent;
  return `otpauth://totp/${e(issuer)}:${e(label)}?secret=${base32Encode(keyOf(secret))}&issuer=${e(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
// Ключ для ручного ввода — группами по 4 знака.
const groupKey = secret => base32Encode(keyOf(secret)).match(/.{1,4}/g).join(' ');

module.exports = { base32Encode, base32Decode, generateSecret, hotp, code, verify, otpauthUri, groupKey, ISSUER };
