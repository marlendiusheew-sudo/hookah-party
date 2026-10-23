'use strict';
// Управление администраторами — только из консоли сервера, не через сайт.
//   node server/admin.js grant +996700123456    выдать права
//   node server/admin.js revoke +996700123456   забрать права
//   node server/admin.js list                   кто администратор
//   node server/admin.js key                    создать ключ шифрования панели в .env (один раз)
//   node server/admin.js pack                   зашифровать панель после правок (admin-panel.js → admin-panel.enc)
//   node server/admin.js unpack                 восстановить исходник панели из зашифрованного файла
// Пользователь должен быть зарегистрирован, а его номер — записан в ADMIN_PHONES в .env.
// После изменения роли все его сессии завершаются.
const path = require('node:path');
process.env.NODE_ENV ||= 'development';
(function loadEnv() {
  const fs = require('node:fs'), file = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();
const { open } = require('./lib/db');
const { phoneIndex, decrypt } = require('./lib/secure');
const { normPhone, validPhone, maskPhone } = require('./lib/util');
const { audit } = require('./lib/guard');

const [cmd, phoneArg] = process.argv.slice(2);
const panel = require('./lib/panel');
if (['key', 'pack', 'unpack'].includes(cmd)) {
  const fs = require('node:fs'), envFile = path.join(__dirname, '..', '.env');
  try {
    if (cmd === 'key') {
      if (process.env.ADMIN_CODE_KEY) { console.log('Ключ уже есть в .env — новый не создаю (иначе старая панель не расшифруется).'); process.exit(0); }
      fs.appendFileSync(envFile, `\nADMIN_CODE_KEY=${panel.newKey()}\n`, { mode: 0o600 });
      console.log('Ключ записан в .env. Сохраните копию .env в надёжном месте и перенесите ключ на сервер.');
    } else console.log((cmd === 'pack' ? 'Зашифровано: ' : 'Восстановлено: ') + panel[cmd]());
  } catch (e) { console.error(e.message); process.exit(1); }
  process.exit(0);
}
const db = open(process.env.DB_PATH || path.join(__dirname, 'data', 'hookah.db'));

if (cmd === 'list') {
  const rows = db.q("SELECT id, name, phone_enc FROM users WHERE role = 'admin'").all();
  console.log(rows.length ? rows.map(r => { const p = decrypt(r.phone_enc); return `${r.name} (${maskPhone(p)})${panel.phoneAllowed(p) ? '' : ' — номера нет в ADMIN_PHONES, панель недоступна'}`; }).join('\n') : 'Администраторов нет.');
} else if (cmd === 'grant' || cmd === 'revoke') {
  const phone = normPhone(phoneArg);
  if (!validPhone(phone)) { console.error('Укажите номер полностью, например +996700123456'); process.exit(1); }
  if (cmd === 'grant' && !panel.phoneAllowed(phone)) { console.error('Этого номера нет в ADMIN_PHONES в .env — права не выданы. Администратором может быть только владелец.'); process.exit(1); }
  const user = db.q('SELECT id, name FROM users WHERE phone_idx = ?').get(phoneIndex(phone));
  if (!user) { console.error('Пользователь с таким номером не найден. Сначала зарегистрируйтесь на сайте.'); process.exit(1); }
  db.q('UPDATE users SET role = ? WHERE id = ?').run(cmd === 'grant' ? 'admin' : 'user', user.id);
  db.q('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  audit(db, { type: cmd === 'grant' ? 'admin_granted' : 'admin_revoked', userId: user.id, ip: 'console', detail: maskPhone(phone) });
  console.log(`${user.name}: ${cmd === 'grant' ? 'права администратора выданы' : 'права администратора сняты'}. Войдите на сайт заново.`);
} else {
  console.log('Использование: node server/admin.js grant|revoke <номер> | list | key | pack | unpack');
}
db.close();
