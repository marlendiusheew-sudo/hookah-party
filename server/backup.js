'use strict';
// Зашифрованная резервная копия базы — без остановки сервера.
//   node server/backup.js [папка]                             сделать копию (папка по умолчанию: BACKUP_DIR или server/data/backups)
//   node server/backup.js key                                 создать ключ BACKUP_KEY в .env — один раз, на экран он не выводится
//   node server/backup.js restore <копия.db.enc> <база.db>    расшифровать копию в новый файл, проверить и показать, что внутри
//   --env <файл>                                              взять настройки из этого файла вместо .env в корне проекта
// Копию делает сама SQLite (целостная даже во время записи), копия пересобирается без свободных страниц (VACUUM: в ней нет
// следов удалённых данных), проверяется (integrity_check), шифруется AES-256-GCM
// ключом BACKUP_KEY в файл hookah-<время>.db.enc, а открытая копия сразу удаляется. Хранятся последние BACKUP_KEEP
// копий (по умолчанию 14); незашифрованные копии hookah-*.db от прежней версии удаляются.
// Формат файла: 'HPB1' + IV (12 байт) + тег (16 байт) + шифротекст; дополнительные данные (AAD) — 'hookah-party/backup'.
// Без BACKUP_KEY копию не открыть: храните .env (BACKUP_KEY и DATA_KEY) ещё и вне сервера, например в менеджере паролей.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { DatabaseSync, backup } = require('node:sqlite');
const { DEFAULT_ENV, loadEnv, envValues, setEnvValue } = require('./lib/envfile');

const ROOT = path.join(__dirname, '..');
const MAGIC = Buffer.from('HPB1'), AAD = Buffer.from('hookah-party/backup'), HEAD = 32, CHUNK = 1 << 20;
const COPY = /^hookah-[\dTZ-]+\.db\.enc$/, LEGACY = /^hookah-[\dT-]+\.db$/;
const TEMP = /^\.hookah-.+\.db\.part(-wal|-shm|-journal)?$|^hookah-.+\.db\.enc\.part$/;

// Пути из настроек считаются от корня проекта — как у сервиса systemd (WorkingDirectory) и у npm-скриптов.
const dbPath = () => path.resolve(ROOT, process.env.DB_PATH || path.join('server', 'data', 'hookah.db'));
const backupDir = () => path.resolve(ROOT, process.env.BACKUP_DIR || path.join('server', 'data', 'backups'));
const keepCount = () => Math.max(1, parseInt(process.env.BACKUP_KEEP, 10) || 14);

function backupKey() {
  if (!process.env.BACKUP_KEY) throw new Error('Нет BACKUP_KEY — без шифрования копию не делаю. Создайте ключ (один раз): node server/backup.js key');
  const k = Buffer.from(process.env.BACKUP_KEY, 'base64');
  if (k.length !== 32) throw new Error('BACKUP_KEY должен быть 32 байта в base64');
  return k;
}

// Под root служебные файлы базы (-wal, -shm) и копии получили бы владельца root, и сервис потом не открыл бы базу.
function notAsRoot(file, cmd) {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0 || !fs.existsSync(file) || fs.statSync(file).uid === 0) return;
  throw new Error(`Не запускайте от root: база принадлежит другому пользователю. Запустите от его имени: sudo -u hookah node ${cmd}`);
}

const writeAll = (fd, buf, pos = null) => { for (let off = 0; off < buf.length;) off += fs.writeSync(fd, buf, off, buf.length - off, pos === null ? null : pos + off); };

// Шифрование файла по частям (база может быть большой): заголовок, шифротекст, затем тег — на своё место в заголовке.
function encryptFile(src, out, key) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(AAD);
  const fin = fs.openSync(src, 'r'), fout = fs.openSync(out, 'wx', 0o600);
  try {
    writeAll(fout, Buffer.concat([MAGIC, iv, Buffer.alloc(16)]));
    const buf = Buffer.allocUnsafe(CHUNK);
    for (let n; (n = fs.readSync(fin, buf, 0, CHUNK, null)) > 0;) writeAll(fout, c.update(buf.subarray(0, n)));
    writeAll(fout, c.final());
    writeAll(fout, c.getAuthTag(), 16);
    fs.fsyncSync(fout);
  } finally { fs.closeSync(fin); fs.closeSync(fout); }
}

// Расшифровка по частям в sink(кусок). Подлинность проверяется в самом конце (final), поэтому пишем только во временный
// файл и считаем результат годным, лишь когда функция вернулась без ошибки.
function decryptTo(file, key, sink) {
  const fin = fs.openSync(file, 'r');
  try {
    const head = Buffer.alloc(HEAD);
    if (fs.readSync(fin, head, 0, HEAD, 0) !== HEAD || !head.subarray(0, 4).equals(MAGIC)) throw new Error('Это не зашифрованная копия Hookah Party (нет заголовка HPB1): ' + file);
    const d = crypto.createDecipheriv('aes-256-gcm', key, head.subarray(4, 16), { authTagLength: 16 });
    d.setAAD(AAD); d.setAuthTag(head.subarray(16, HEAD));
    const buf = Buffer.allocUnsafe(CHUNK);
    for (let pos = HEAD, n; (n = fs.readSync(fin, buf, 0, CHUNK, pos)) > 0; pos += n) sink(d.update(buf.subarray(0, n)));
    try { sink(d.final()); } catch (e) { throw new Error('Копия не расшифровалась: BACKUP_KEY не тот, или файл повреждён либо изменён'); }
  } finally { fs.closeSync(fin); }
}
const verifyFile = (file, key) => decryptTo(file, key, () => {});

// Целостность базы и число строк в каждой таблице.
function inspect(file) {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const ic = db.prepare('PRAGMA integrity_check').get()?.integrity_check;
    if (ic !== 'ok') throw new Error('проверка целостности: ' + ic);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(t => t.name);
    return Object.fromEntries(tables.map(t => [t, db.prepare(`SELECT COUNT(*) AS n FROM "${t.replace(/"/g, '""')}"`).get().n]));
  } finally { db.close(); }
}

// Остатки прерванных запусков (в них могла остаться открытая копия) — удаляем, если им больше часа.
function cleanTemp(dir) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (TEMP.test(f) && Date.now() - fs.statSync(p).mtimeMs > 3600e3) fs.rmSync(p, { force: true });
  }
}

async function makeBackup({ src = dbPath(), dir = backupDir(), key = backupKey(), keep = keepCount() } = {}) {
  if (!fs.existsSync(src)) throw new Error('База не найдена: ' + src);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  cleanTemp(dir);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const out = path.join(dir, `hookah-${stamp}.db.enc`), part = out + '.part', plain = path.join(dir, `.hookah-${stamp}.db.part`);
  let users;
  try {
    const db = new DatabaseSync(src, { readOnly: true });
    try { await backup(db, plain); } finally { db.close(); }
    fs.chmodSync(plain, 0o600);
    // Копия — один самостоятельный файл (без -wal/-shm); заодно проверяем, что она цела и в ней есть данные.
    // VACUUM пересобирает копию без свободных страниц: даже если в базе остались следы удалённого (база создана до secure_delete
    // и ещё не пересобрана), в копию они не попадут.
    const check = new DatabaseSync(plain);
    try {
      check.exec('PRAGMA journal_mode = DELETE');
      check.exec('VACUUM');
      const ic = check.prepare('PRAGMA integrity_check').get()?.integrity_check;
      if (ic !== 'ok') throw new Error('Копия повреждена: ' + ic);
      users = check.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    } finally { check.close(); }
    encryptFile(plain, part, key);
    verifyFile(part, key); // перечитываем с диска: файл действительно расшифровывается
    fs.renameSync(part, out);
  } finally {
    for (const f of [plain, plain + '-journal', plain + '-wal', plain + '-shm', part]) fs.rmSync(f, { force: true });
  }
  const files = fs.readdirSync(dir);
  const old = files.filter(f => COPY.test(f)).sort().slice(0, -keep), legacy = files.filter(f => LEGACY.test(f));
  for (const f of [...old, ...legacy]) fs.rmSync(path.join(dir, f), { force: true });
  return { file: out, bytes: fs.statSync(out).size, users, removed: old.length, legacy: legacy.length };
}

// Восстановление — только в новый файл: существующую базу (и её -wal/-shm) не трогаем.
function restore(file, out, key = backupKey()) {
  if (!fs.existsSync(file)) throw new Error('Файл копии не найден: ' + file);
  for (const f of [out, out + '-wal', out + '-shm', out + '-journal']) if (fs.existsSync(f)) throw new Error(`${f} уже существует — укажите новый путь (существующую базу не перезаписываю)`);
  fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
  const tmp = `${out}.${crypto.randomBytes(4).toString('hex')}.part`;
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try { decryptTo(file, key, chunk => writeAll(fd, chunk)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    let counts;
    try { counts = inspect(tmp); } catch (e) { throw new Error('Расшифрованный файл не прошёл проверку базы: ' + e.message); }
    fs.linkSync(tmp, out);
    return counts;
  } finally { fs.rmSync(tmp, { force: true }); }
}

const size = n => n < 1 << 20 ? `${Math.ceil(n / 1024)} КБ` : `${(n / (1 << 20)).toFixed(1)} МБ`;
const USAGE = 'Использование: node server/backup.js [папка] | key | restore <копия.db.enc> <новый-файл.db>   (+ --env <файл>)';

async function main(argv) {
  process.umask(0o077); // всё, что создаём (копии, временные файлы), доступно только владельцу
  let envFile = DEFAULT_ENV; const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--env' || a.startsWith('--env=')) {
      const v = a === '--env' ? argv[++i] : a.slice(6);
      if (!v || !fs.existsSync(v)) throw new Error('Файл настроек не найден: ' + (v || '(не указан)'));
      envFile = path.resolve(v);
    } else args.push(a);
  }
  loadEnv(envFile);
  const [cmd, a, b] = args;
  if (['help', '-h', '--help'].includes(cmd)) return console.log(USAGE);
  if (cmd === 'key') {
    if (process.env.BACKUP_KEY || envValues(envFile, 'BACKUP_KEY').some(Boolean)) return console.log('BACKUP_KEY уже задан — новый не создаю (иначе прежние копии не расшифровать).');
    setEnvValue(envFile, 'BACKUP_KEY', crypto.randomBytes(32).toString('base64'));
    return console.log(`Ключ BACKUP_KEY записан в ${envFile} (на экран не выводится).\nСохраните копию этого файла вне сервера, например в менеджере паролей: без ключа копии не расшифровать.`);
  }
  if (cmd === 'restore') {
    if (!a || !b) throw new Error(USAGE);
    const out = path.resolve(b), counts = restore(path.resolve(a), out);
    console.log(`Копия расшифрована и проверена: ${out}`);
    for (const [t, n] of Object.entries(counts)) console.log(`  ${t}: ${n}`);
    return console.log('Номера в копии зашифрованы тем DATA_KEY, который действовал в день копии. Как вернуть базу на место — deploy/SERVER-SETUP.md.');
  }
  if (args.length > 1) throw new Error(USAGE);
  const src = dbPath();
  notAsRoot(src, 'server/backup.js');
  const r = await makeBackup({ src, dir: cmd ? path.resolve(cmd) : backupDir() });
  console.log(`Копия готова: ${r.file} (зашифрована, ${size(r.bytes)}; пользователей: ${r.users}; удалено старых копий: ${r.removed}` +
    (r.legacy ? `; удалено незашифрованных копий прежнего формата: ${r.legacy}` : '') + ')');
}

if (require.main === module) main(process.argv.slice(2)).catch(e => { console.error('Не сделано:', e.message); process.exit(1); });
module.exports = { makeBackup, restore, inspect, encryptFile, decryptTo, verifyFile, backupKey, dbPath, backupDir, keepCount, notAsRoot };
