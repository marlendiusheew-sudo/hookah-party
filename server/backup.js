'use strict';
// Резервная копия базы без остановки сервера: node server/backup.js [папка]
// Копия делается средствами SQLite (целостная даже во время записи), хранятся последние KEEP копий.
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync, backup } = require('node:sqlite');

const KEEP = +(process.env.BACKUP_KEEP || 14);
const src = process.env.DB_PATH || path.join(__dirname, 'data', 'hookah.db');
const dir = path.resolve(process.argv[2] || process.env.BACKUP_DIR || path.join(__dirname, 'data', 'backups'));

async function main() {
  if (!fs.existsSync(src)) throw new Error('База не найдена: ' + src);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const out = path.join(dir, `hookah-${stamp}.db`);
  const db = new DatabaseSync(src, { readOnly: true });
  try { await backup(db, out); } finally { db.close(); }
  fs.chmodSync(out, 0o600);
  // Копия — один самостоятельный файл (без -wal/-shm); заодно проверяем, что она цела и в ней есть данные.
  const check = new DatabaseSync(out);
  check.exec('PRAGMA journal_mode = DELETE');
  if (check.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw new Error('Копия повреждена: ' + out);
  const users = check.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  check.close();
  const old = fs.readdirSync(dir).filter(f => /^hookah-.*\.db$/.test(f)).sort().slice(0, -KEEP);
  for (const f of old) fs.unlinkSync(path.join(dir, f));
  console.log(`Копия готова: ${out} (пользователей: ${users}, удалено старых копий: ${old.length})`);
}

main().catch(e => { console.error('Резервная копия не сделана:', e.message); process.exit(1); });
