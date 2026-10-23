'use strict';
// Смена ключа данных DATA_KEY. Номера телефонов и все другие поля *_enc перешифровываются новым ключом,
// индексы номеров (phone_idx) пересчитываются, коды из SMS удаляются (они всё равно живут 5 минут).
// Когда нужно: ключ мог утечь (вместе с .env или копией сервера), ушёл человек с доступом к серверу, плановая смена.
//
//   sudo systemctl stop hookah-party
//   sudo -u hookah node server/rotate-key.js       сменить ключ; перед этим делается зашифрованная копия базы
//   sudo systemctl start hookah-party
//   node server/rotate-key.js --check              только проверить, что все данные читаются текущим ключом (ничего не меняет)
//   --env <файл>                                   файл, откуда сервис берёт DATA_KEY (по умолчанию .env в корне проекта)
//
// Всё перешифрование — одна транзакция: при любой ошибке база остаётся как была. Ключи на экран не выводятся.
// Новый ключ записывается на место старого (строка DATA_KEY в .env; в разработке без DATA_KEY — server/data/.dev-key).
// Старый ключ сохраняется рядом с базой: он нужен только чтобы открыть копии, сделанные до смены.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const { DEFAULT_ENV, loadEnv, envValues, setEnvValue } = require('./lib/envfile');

const q = s => '"' + String(s).replace(/"/g, '""') + '"';
const stop = msg => { throw new Error(msg + '\nНичего не изменено.'); };
const LOOKS_ENCRYPTED = /^[A-Za-z0-9+/]{40,4000}={0,2}$/; // IV 12 + тег 16 + хотя бы 1 байт, в base64

function parseArgs(argv) {
  const o = { envFile: DEFAULT_ENV, check: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--check') o.check = true;
    else if (a === '--env' || a.startsWith('--env=')) {
      const v = a === '--env' ? argv[++i] : a.slice(6);
      if (!v || !fs.existsSync(v)) stop('Файл настроек не найден: ' + (v || '(не указан)'));
      o.envFile = path.resolve(v);
    } else stop('Неизвестный параметр: ' + a + '\nИспользование: node server/rotate-key.js [--check] [--env <файл>]');
  }
  return o;
}

// Сервер со старым ключом в памяти продолжил бы писать им, поэтому менять ключ можно только у остановленного.
function serverAnswers(port) {
  return new Promise(resolve => {
    const req = http.get({ host: '127.0.0.1', port, path: '/api/health', timeout: 1500 }, res => {
      let body = ''; res.setEncoding('utf8');
      res.on('data', c => { body += c; if (body.length > 4096) req.destroy(); });
      res.on('end', () => { try { resolve(JSON.parse(body)?.mode === 'server'); } catch (e) { resolve(false); } });
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}
const serviceActive = () => { try { return spawnSync('systemctl', ['is-active', '--quiet', 'hookah-party'], { timeout: 5000 }).status === 0; } catch (e) { return false; } };

// Какие таблицы трогаем: колонки *_enc перешифровываем, phone_idx пересчитываем из phone_enc, sms_codes очищаем.
// Список берётся из самой базы, поэтому новые колонки *_enc (например, секреты 2FA) попадут сюда без правок.
function discover(db) {
  const plan = [];
  for (const t of db.prepare("SELECT name, wr FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()) {
    const cols = db.prepare('SELECT name, pk FROM pragma_table_info(?)').all(t.name);
    const enc = cols.filter(c => /_enc$/.test(c.name)).map(c => c.name), idx = cols.filter(c => /_idx$/.test(c.name)).map(c => c.name);
    const other = cols.map(c => c.name).filter(c => !enc.includes(c) && !idx.includes(c));
    if (t.name === 'sms_codes') { plan.push({ table: t.name, clear: true, enc: [], other: [] }); continue; }
    for (const c of idx) if (c !== 'phone_idx' || !enc.includes('phone_enc'))
      stop(`Таблица ${t.name}: колонка ${c} похожа на индекс, зависящий от ключа, но как её пересчитать — неизвестно. Допишите это в server/rotate-key.js.`);
    const key = t.wr ? cols.filter(c => c.pk > 0).sort((a, b) => a.pk - b.pk).map(c => c.name) : ['rowid'];
    plan.push({ table: t.name, enc, phoneIdx: idx.includes('phone_idx'), other, key, rows: [] });
  }
  return plan;
}

// Чтение и проверка текущим ключом: каждое значение *_enc расшифровывается, индекс совпадает с номером,
// и нигде больше нет значений, зашифрованных этим ключом (иначе они остались бы под старым ключом).
function readAll(db, plan, kr) {
  const stats = { values: 0, columns: new Set() };
  for (const t of plan.filter(p => !p.clear)) {
    if (t.enc.length) {
      const sel = [...t.key.map((k, i) => `${q(k)} AS "__k${i}"`), ...t.enc.map(q), ...(t.phoneIdx ? ['"phone_idx"'] : [])].join(', ');
      for (const r of db.prepare(`SELECT ${sel} FROM ${q(t.table)}`).all()) {
        const key = t.key.map((k, i) => r[`__k${i}`]), where = `${t.key.join(', ')} = ${key.join(', ')}`, plain = {};
        for (const c of t.enc) {
          if (r[c] == null) continue;
          if (typeof r[c] !== 'string') stop(`${t.table}.${c} (${where}): значение не строка — так наши данные не хранятся.`);
          try { plain[c] = kr.decrypt(r[c]); } catch (e) { stop(`${t.table}.${c} (${where}): значение не расшифровывается текущим ключом. Ключ в настройках не тот, что у базы, или данные повреждены.`); }
          stats.values++; stats.columns.add(`${t.table}.${c}`);
        }
        if (t.phoneIdx && r.phone_idx != null) {
          if (plain.phone_enc == null) stop(`${t.table} (${where}): есть phone_idx, но нет phone_enc — индекс не из чего пересчитать.`);
          if (kr.phoneIndex(plain.phone_enc) !== r.phone_idx) stop(`${t.table} (${where}): phone_idx не совпадает с номером — данные несогласованы, разберитесь до смены ключа.`);
        }
        t.rows.push({ key, plain, idx: r.phone_idx ?? null });
      }
    }
    for (const c of t.other) {
      for (const r of db.prepare(`SELECT ${q(c)} AS v FROM ${q(t.table)} WHERE typeof(${q(c)}) = 'text' AND length(${q(c)}) BETWEEN 40 AND 4000`).iterate()) {
        if (!LOOKS_ENCRYPTED.test(r.v)) continue;
        let opened = false; try { kr.decrypt(r.v); opened = true; } catch (e) { /* обычный текст */ }
        if (opened) stop(`${t.table}.${c}: в колонке есть значения, зашифрованные ключом данных, но её имя не оканчивается на _enc. Переименуйте колонку (…_enc) или допишите её в server/rotate-key.js.`);
      }
    }
  }
  return stats;
}

// Перешифровка внутри уже открытой транзакции и проверка результата новым ключом (до COMMIT).
function reencrypt(db, plan, oldKr, newKr) {
  const done = { enc: {}, idx: {}, sms: 0 };
  for (const t of plan) {
    if (t.clear) { done.sms = Number(db.prepare(`DELETE FROM ${q(t.table)}`).run().changes); continue; }
    if (!t.enc.length) continue;
    const cols = [...t.enc, ...(t.phoneIdx ? ['phone_idx'] : [])];
    const upd = db.prepare(`UPDATE ${q(t.table)} SET ${cols.map(c => `${q(c)} = ?`).join(', ')} WHERE ${t.key.map(k => `${q(k)} = ?`).join(' AND ')}`);
    for (const row of t.rows) {
      const vals = t.enc.map(c => row.plain[c] == null ? null : newKr.encrypt(row.plain[c]));
      if (t.phoneIdx) vals.push(row.idx == null ? null : newKr.phoneIndex(row.plain.phone_enc));
      if (Number(upd.run(...vals, ...row.key).changes) !== 1) throw new Error(`${t.table}: строка ${row.key.join(', ')} не обновилась`);
      for (const c of t.enc) if (row.plain[c] != null) done.enc[`${t.table}.${c}`] = (done.enc[`${t.table}.${c}`] || 0) + 1;
      if (t.phoneIdx && row.idx != null) done.idx[t.table] = (done.idx[t.table] || 0) + 1;
    }
  }
  verify(db, plan, newKr, oldKr);
  return done;
}

// Проверка: каждое значение читается ключом kr и совпадает с исходным, индексы номеров совпадают, старый ключ уже не читает.
function verify(db, plan, kr, oldKr = null) {
  for (const t of plan) {
    if (t.clear) { if (db.prepare(`SELECT COUNT(*) AS n FROM ${q(t.table)}`).get().n) throw new Error(`${t.table} не очищена`); continue; }
    if (!t.enc.length) continue;
    const sel = [...t.key.map((k, i) => `${q(k)} AS "__k${i}"`), ...t.enc.map(q), ...(t.phoneIdx ? ['"phone_idx"'] : [])].join(', ');
    const rows = db.prepare(`SELECT ${sel} FROM ${q(t.table)}`).all();
    if (rows.length !== t.rows.length) throw new Error(`${t.table}: было строк ${t.rows.length}, стало ${rows.length}`);
    const byKey = new Map(t.rows.map(r => [JSON.stringify(r.key), r]));
    for (const r of rows) {
      const before = byKey.get(JSON.stringify(t.key.map((k, i) => r[`__k${i}`])));
      if (!before) throw new Error(`${t.table}: появилась незнакомая строка`);
      for (const c of t.enc) {
        if (before.plain[c] == null) { if (r[c] != null) throw new Error(`${t.table}.${c}: пустое значение стало непустым`); continue; }
        if (kr.decrypt(r[c]) !== before.plain[c]) throw new Error(`${t.table}.${c}: значение после перешифровки не совпадает`);
        if (oldKr) { let stale = true; try { oldKr.decrypt(r[c]); } catch (e) { stale = false; } if (stale) throw new Error(`${t.table}.${c}: значение всё ещё читается старым ключом`); }
      }
      if (t.phoneIdx && (before.idx == null ? r.phone_idx != null : r.phone_idx !== kr.phoneIndex(before.plain.phone_enc))) throw new Error(`${t.table}: phone_idx не совпадает с номером`);
    }
  }
}

const writeSecret = (file, text) => { const fd = fs.openSync(file, 'w', 0o600); try { fs.writeFileSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };

async function main() {
  process.umask(0o077);
  const { envFile, check } = parseArgs(process.argv.slice(2));
  const keyFromProcess = !!process.env.DATA_KEY;
  loadEnv(envFile);
  const { loadKey, makeKeyring, DEV_KEY_FILE } = require('./lib/secure');
  const prod = process.env.NODE_ENV === 'production';

  // 1. Где сейчас ключ и куда записать новый.
  const fileVals = envValues(envFile, 'DATA_KEY').filter(Boolean);
  let target;
  if (process.env.DATA_KEY) {
    if (new Set(fileVals).size > 1) stop(`В ${envFile} несколько разных строк DATA_KEY — оставьте одну (ту, с которой работает сервер) и повторите.`);
    if (fileVals.length && fileVals[0] !== process.env.DATA_KEY) stop(`DATA_KEY в окружении отличается от строки в ${envFile} — непонятно, какой настоящий. Выполните unset DATA_KEY и повторите.`);
    if (!fileVals.length) stop(`DATA_KEY задан в окружении, а не в ${envFile}, — некуда записать новый ключ.\n` +
      'Запустите без DATA_KEY в окружении или укажите файл, откуда сервис берёт ключ (EnvironmentFile в systemd): node server/rotate-key.js --env <файл>');
    target = { kind: 'env', file: envFile };
  } else {
    if (prod) stop(`В production нужен DATA_KEY в ${envFile}.`);
    if (!fs.existsSync(DEV_KEY_FILE)) stop(`Ключа данных ещё нет (ни DATA_KEY, ни ${DEV_KEY_FILE}) — менять нечего.`);
    target = { kind: 'dev', file: DEV_KEY_FILE };
  }
  const oldKey = loadKey(), oldKr = makeKeyring(oldKey);
  const dbFile = path.resolve(path.join(__dirname, '..'), process.env.DB_PATH || path.join('server', 'data', 'hookah.db'));
  if (!fs.existsSync(dbFile)) stop('База не найдена: ' + dbFile);
  console.log(`База: ${dbFile}\nКлюч сейчас берётся из: ${target.file}`);

  if (!check) {
    if (typeof process.getuid === 'function' && process.getuid() !== fs.statSync(dbFile).uid) stop('Запустите от имени владельца базы, на сервере это hookah: sudo -u hookah node server/rotate-key.js');
    for (const f of [target.file, path.dirname(dbFile)]) { try { fs.accessSync(f, fs.constants.W_OK); } catch (e) { stop(`Нет прав на запись: ${f}. Запустите от имени владельца: sudo -u hookah node server/rotate-key.js`); } }
    const port = +process.env.PORT || 3000;
    if (serviceActive() || await serverAnswers(port)) stop(`Сервер работает (порт ${port}) и держит старый ключ в памяти. Сначала остановите его: sudo systemctl stop hookah-party`);
    require('./backup').backupKey(); // без ключа копий — отказ до любых действий
  }

  // 2. Чтение и проверка текущим ключом — внутри транзакции записи, чтобы никто не изменил данные между шагами.
  const db = new DatabaseSync(dbFile, check ? { readOnly: true } : {});
  db.exec('PRAGMA busy_timeout = 5000');
  // Затираем старые значения нулями, чтобы прежний шифротекст не остался в свободных страницах базы.
  if (!check) db.exec('PRAGMA secure_delete = ON');
  let committed = false, pending = null, oldFile = null;
  try {
    if (!check) db.exec('BEGIN IMMEDIATE');
    const plan = discover(db), stats = readAll(db, plan, oldKr);
    console.log(`Проверка текущим ключом: ${stats.values} зашифрованных значений в колонках ${[...stats.columns].join(', ') || '—'} — всё читается.`);
    if (check) return console.log('Режим --check: ничего не изменено.');

    // 3. Копия базы до смены (её откроет только старый ключ).
    const bk = await require('./backup').makeBackup({ src: dbFile });
    console.log(`Копия до смены: ${bk.file}`);

    // 4. Перешифровка и проверка новым ключом — в той же транзакции.
    const newKey = crypto.randomBytes(32), newB64 = newKey.toString('base64'), newKr = makeKeyring(newKey);
    const done = reencrypt(db, plan, oldKr, newKr);
    try { db.prepare("INSERT INTO audit (at, user_id, ip, type, detail) VALUES (?, NULL, 'console', 'data_key_rotated', ?)").run(new Date().toISOString(), `${Object.values(done.enc).reduce((a, b) => a + b, 0)} значений`); } catch (e) { /* журнала может не быть */ }

    // 5. Оба ключа — в файлы рядом с базой (только владельцу) до COMMIT: если дальше что-то сорвётся, ключ не потеряется.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-'), dir = path.dirname(dbFile);
    oldFile = path.join(dir, `old-data-key-${stamp}.env`); pending = path.join(dir, `new-data-key-${stamp}.env`);
    writeSecret(oldFile, `# Прежний DATA_KEY: заменён ${new Date().toISOString()} командой server/rotate-key.js.\n# Нужен только чтобы открыть копии базы, сделанные до этой даты. Когда они больше не нужны — удалите файл: shred -u ${oldFile}\nDATA_KEY=${oldKey.toString('base64')}\n`);
    writeSecret(pending, `# Новый DATA_KEY (${new Date().toISOString()}). Если он не попал в ${target.file} — перенесите строку ниже туда вручную.\nDATA_KEY=${newB64}\n`);
    db.exec('COMMIT'); committed = true;
    // Пересобираем базу и обнуляем WAL: там могли остаться страницы со значениями, зашифрованными старым ключом.
    try { db.exec('VACUUM'); db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch (e) { console.log('Предупреждение: не удалось пересобрать базу (VACUUM) — сделайте это позже при остановленном сервере.'); }

    // 6. Новый ключ — на место старого, затем проверка: ключ, который теперь лежит в файле, читает всю базу.
    if (target.kind === 'env') setEnvValue(target.file, 'DATA_KEY', newB64); else writeSecret(target.file, newB64);
    const onDisk = target.kind === 'env' ? envValues(target.file, 'DATA_KEY').filter(Boolean) : [fs.readFileSync(target.file, 'utf8').trim()];
    if (!onDisk.length || onDisk.some(v => v !== newB64)) throw new Error(`новый ключ не записался в ${target.file}`);
    const ro = new DatabaseSync(dbFile, { readOnly: true });
    try { verify(ro, plan, makeKeyring(Buffer.from(onDisk[0], 'base64'))); } finally { ro.close(); }
    fs.rmSync(pending, { force: true }); pending = null;

    console.log('Перешифровано: ' + (Object.entries(done.enc).map(([c, n]) => `${c} — ${n}`).join(', ') || 'нечего') +
      `; индексов номеров пересчитано: ${Object.values(done.idx).reduce((a, b) => a + b, 0)}; удалено кодов из SMS: ${done.sms}.`);
    console.log(`Проверка: ключ из ${target.file} расшифровывает всё, индексы номеров совпадают, старый ключ эти данные уже не читает.`);
    console.log(`Новый ключ записан в ${target.file}${target.kind === 'env' ? ' (строка DATA_KEY)' : ''}; на экран он не выводился.`);
    console.log(`Старый ключ сохранён в ${oldFile} — только для копий, сделанных до смены. Когда они станут не нужны (через ${require('./backup').keepCount()} дн.), удалите: shred -u ${oldFile}`);
    if (keyFromProcess) console.log('В окружении этой оболочки тоже был DATA_KEY — он устарел: выполните unset DATA_KEY.');
    console.log(target.kind === 'env' ? `Сохраните новый ${path.basename(target.file)} в менеджере паролей вместо прежнего.\nТеперь запустите сервер: sudo systemctl start hookah-party` : 'Теперь запустите сервер заново (npm start).');
  } catch (e) {
    if (!committed) { try { db.exec('ROLLBACK'); } catch (x) { /* транзакции не было */ } for (const f of [pending, oldFile]) if (f) fs.rmSync(f, { force: true }); }
    else Object.assign(e, { afterCommit: true, message: `База уже перешифрована новым ключом, но дальше случилась ошибка: ${e.message}.\nНовый ключ лежит в ${pending || target.file} — DATA_KEY в ${target.file} должен совпадать с ним. Сервер не запускайте, пока не исправите.` });
    throw e;
  } finally { db.close(); }
}

if (require.main === module) main().catch(e => { console.error(e.afterCommit ? 'ВНИМАНИЕ:' : 'Ключ не сменён:', e.message); process.exit(1); });
module.exports = { discover, readAll, reencrypt, verify };
