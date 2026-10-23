'use strict';
// Файл настроек .env без сторонних библиотек: строки KEY=VALUE, строки с # — комментарии.
// Читается так же, как в server/index.js и server/admin.js: уже заданные переменные окружения не перезаписываются.
// Нужен консольным командам (server/backup.js, server/rotate-key.js): прочитать, найти значение, заменить строку на месте.
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_ENV = path.join(__dirname, '..', '..', '.env');
const LINE = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/;
const parse = line => { const m = !line.trim().startsWith('#') && LINE.exec(line); return m ? [m[1], m[2].replace(/^["']|["']$/g, '')] : null; };

function loadEnv(file = DEFAULT_ENV) {
  if (!fs.existsSync(file)) return false;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) { const kv = parse(line); if (kv && process.env[kv[0]] === undefined) process.env[kv[0]] = kv[1]; }
  return true;
}

// Все значения переменной в файле по порядку (обычно одно; пустые тоже попадают в список).
const envValues = (file, name) => !fs.existsSync(file) ? [] : fs.readFileSync(file, 'utf8').split('\n').map(parse).filter(kv => kv && kv[0] === name).map(kv => kv[1]);

// Записать NAME=value: все строки NAME=... заменяются, а если их нет — строка дописывается в конец.
// Файл переписывается на месте, поэтому владелец и права остаются прежними (на сервере в папку проекта писать нельзя,
// а сам .env принадлежит пользователю сервиса); новый файл создаётся с правами 0600.
function setEnvValue(file, name, value) {
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  let found = false;
  let out = text.split('\n').map(line => { if (parse(line)?.[0] !== name) return line; found = true; return `${name}=${value}`; }).join('\n');
  if (!found) out += (out && !out.endsWith('\n') ? '\n' : '') + `${name}=${value}\n`;
  const fd = fs.openSync(file, 'w', 0o600);
  try { fs.writeFileSync(fd, out); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

module.exports = { DEFAULT_ENV, loadEnv, envValues, setEnvValue };
