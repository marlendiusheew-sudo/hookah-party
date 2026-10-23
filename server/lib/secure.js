'use strict';
// Пароли (Argon2id), шифрование номеров (AES-256-GCM), поисковый индекс номера (HMAC), токены.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Ключ данных: из переменной DATA_KEY. В режиме разработки, если ключа нет, создаётся локальный файл.
function loadKey() {
  if (process.env.DATA_KEY) {
    const k = Buffer.from(process.env.DATA_KEY, 'base64');
    if (k.length !== 32) throw new Error('DATA_KEY должен быть 32 байта в base64');
    return k;
  }
  if (process.env.NODE_ENV === 'production') throw new Error('В production нужен DATA_KEY');
  const file = path.join(__dirname, '..', 'data', '.dev-key');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
}
const KEY = loadKey();
// Отдельные подключи для шифрования и для индекса, чтобы один ключ не использовался для двух задач.
const ENC_KEY = crypto.createHmac('sha256', KEY).update('hp:enc').digest();
const IDX_KEY = crypto.createHmac('sha256', KEY).update('hp:idx').digest();

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decrypt(b64) {
  const buf = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
const phoneIndex = phone => crypto.createHmac('sha256', IDX_KEY).update('phone:' + phone).digest('hex');

// Argon2id: 19 МиБ памяти, 2 прохода — рекомендация OWASP.
const A2 = { parallelism: 1, tagLength: 32, memory: 19456, passes: 2 };
const argon = (message, nonce) => new Promise((res, rej) => crypto.argon2('argon2id', { message, nonce, ...A2 }, (e, k) => e ? rej(e) : res(k)));
async function hashPassword(pass) {
  const salt = crypto.randomBytes(16);
  const h = await argon(String(pass), salt);
  return `$argon2id$v=19$m=${A2.memory},t=${A2.passes},p=${A2.parallelism}$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyPassword(pass, stored) {
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/.exec(String(stored || ''));
  if (!m) return false;
  const h = await argon(String(pass), Buffer.from(m[4], 'base64'));
  const expected = Buffer.from(m[5], 'base64');
  return h.length === expected.length && crypto.timingSafeEqual(h, expected);
}
// Пустая проверка той же длительности, чтобы по времени ответа нельзя было понять, есть ли такой номер.
const DUMMY = '$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const burnTime = pass => verifyPassword(pass, DUMMY).catch(() => false);

const token = () => crypto.randomBytes(32).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const sameHash = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const smsCode = () => String(1000 + crypto.randomInt(9000));

module.exports = { crypto, encrypt, decrypt, phoneIndex, hashPassword, verifyPassword, burnTime, token, sha256, sameHash, smsCode };
