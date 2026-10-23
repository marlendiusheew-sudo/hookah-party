'use strict';
// Пароли (Argon2id), шифрование номеров (AES-256-GCM), поисковый индекс номера (HMAC), токены.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Ключ данных: из переменной DATA_KEY. В режиме разработки, если ключа нет, создаётся локальный файл.
const DEV_KEY_FILE = path.join(__dirname, '..', 'data', '.dev-key');
function loadKey() {
  if (process.env.DATA_KEY) {
    const k = Buffer.from(process.env.DATA_KEY, 'base64');
    if (k.length !== 32) throw new Error('DATA_KEY должен быть 32 байта в base64');
    return k;
  }
  if (process.env.NODE_ENV === 'production') throw new Error('В production нужен DATA_KEY');
  const file = DEV_KEY_FILE;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Создаём атомарно: ключ пишется во временный файл и появляется под своим именем сразу целиком (link не перезапишет
  // ключ, созданный другим процессом). Иначе два процесса, запущенные одновременно (node --test с несколькими файлами),
  // могли прочитать пустой или недописанный ключ.
  if (!fs.existsSync(file)) {
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
    try { fs.linkSync(tmp, file); }
    catch (e) { if (e.code !== 'EEXIST') fs.renameSync(tmp, file); } // нет жёстких ссылок в этой файловой системе — переименование
    finally { fs.rmSync(tmp, { force: true }); }
  }
  return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
}

// Шифрование и индекс для одного ключа данных. Фабрикой — чтобы при смене ключа (server/rotate-key.js)
// держать в руках старый и новый ключ одновременно. Сам модуль пользуется ею же с ключом из loadKey().
function makeKeyring(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Ключ данных должен быть 32 байта');
  // Отдельные подключи для шифрования и для индекса, чтобы один ключ не использовался для двух задач.
  const ENC_KEY = crypto.createHmac('sha256', key).update('hp:enc').digest();
  const IDX_KEY = crypto.createHmac('sha256', key).update('hp:idx').digest();
  function encrypt(text) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
    const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
  }
  // Тег GCM — ровно 16 байт: короче (обрезанный блоб) не принимаем, иначе подделка стала бы в миллиарды раз проще.
  function decrypt(b64) {
    const buf = Buffer.from(b64, 'base64');
    if (buf.length < 28) throw new Error('Шифротекст короче IV и тега');
    const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, buf.subarray(0, 12), { authTagLength: 16 });
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
  }
  const phoneIndex = phone => crypto.createHmac('sha256', IDX_KEY).update('phone:' + phone).digest('hex');
  return { encrypt, decrypt, phoneIndex };
}
const { encrypt, decrypt, phoneIndex } = makeKeyring(loadKey());

// Argon2id: 19 МиБ памяти, 2 прохода — рекомендация OWASP.
const A2 = { parallelism: 1, tagLength: 32, memory: 19456, passes: 2 };
// Argon2 считается в общем пуле потоков libuv (по умолчанию 4 потока, UV_THREADPOOL_SIZE), на нём же чтение файлов сайта.
// Одновременно считаем не больше половины пула, остальные ждут в короткой очереди; сверх очереди — ошибка ARGON_BUSY
// (сервер отвечает 503 и Retry-After). Так шквал попыток входа с разных адресов не забирает все потоки и всю память.
const A2_SLOTS = { active: Math.max(1, Math.floor((parseInt(process.env.UV_THREADPOOL_SIZE, 10) || 4) / 2)), queue: 32 };
let a2Running = 0;
const a2Waiting = [];
const busy = () => Object.assign(new Error('Слишком много проверок пароля одновременно'), { code: 'ARGON_BUSY' });
function argon(message, nonce) {
  if (a2Running >= A2_SLOTS.active && a2Waiting.length >= A2_SLOTS.queue) return Promise.reject(busy());
  return new Promise((res, rej) => {
    const done = (e, k) => { a2Running--; a2Waiting.shift()?.(); e ? rej(e) : res(k); };
    const run = () => {
      a2Running++;
      try { crypto.argon2('argon2id', { message, nonce, ...A2 }, done); } catch (e) { done(e); } // кривые параметры (битая соль в базе)
    };
    if (a2Running < A2_SLOTS.active) run(); else a2Waiting.push(run);
  });
}
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
// «Сервер занят» пробрасываем: иначе неизвестный номер под нагрузкой отвечал бы иначе, чем известный.
const burnTime = pass => verifyPassword(pass, DUMMY).catch(e => { if (e.code === 'ARGON_BUSY') throw e; return false; });

const token = () => crypto.randomBytes(32).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const sameHash = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
// Код из SMS — 6 цифр (миллион вариантов, как у кодов 2FA), с ведущими нулями.
const smsCode = () => String(crypto.randomInt(1e6)).padStart(6, '0');

module.exports = { crypto, encrypt, decrypt, phoneIndex, makeKeyring, loadKey, DEV_KEY_FILE, hashPassword, verifyPassword, burnTime, token, sha256, sameHash, smsCode, A2_SLOTS };
