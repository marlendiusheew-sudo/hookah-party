'use strict';
// Управление администраторами и удаление аккаунта по просьбе — только из консоли сервера, не через сайт.
//   node server/admin.js grant +996700123456        выдать права
//   node server/admin.js revoke +996700123456       забрать права
//   node server/admin.js list                       кто администратор и подключено ли приложение для кодов
//   node server/admin.js totp-reset +996700123456   сбросить вход по коду из приложения (телефон потерян или заменён)
//   node server/admin.js delete +996700123456       показать, что удалится вместе с аккаунтом (ничего не удаляет, код выхода 2)
//   node server/admin.js delete +996700123456 --yes удалить аккаунт по просьбе человека, который сам войти не может
//                                                   (нет ни пароля, ни доступа к номеру): то же, что «Удаление аккаунта» в настройках
//   node server/admin.js key                        создать ключ шифрования панели в .env (один раз)
//   node server/admin.js rekey                      сменить ключ шифрования панели: панель перешифровывается, строка ADMIN_CODE_KEY в .env заменяется
//   node server/admin.js pack                       зашифровать панель после правок (admin-panel.js → admin-panel.enc)
//   node server/admin.js unpack                     восстановить исходник панели из зашифрованного файла
//   --env <файл>                                    другой файл настроек вместо .env в корне проекта (например, EnvironmentFile сервиса)
// Для grant: пользователь должен быть зарегистрирован, а его номер — записан в ADMIN_PHONES в .env.
// После изменения роли и после сброса кода все его сессии завершаются. Ключи на экран не выводятся никогда.
// Панель открывается паролем и кодом из приложения-аутентификатора; подключается приложение в самой панели при первом входе.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { DEFAULT_ENV, loadEnv, envValues, setEnvValue } = require('./lib/envfile');

const USAGE = 'Использование: node server/admin.js grant|revoke|totp-reset <номер> | delete <номер> [--yes] | list | key | rekey | pack | unpack [--env <файл>]';
const encFile = () => process.env.ADMIN_PANEL_ENC || path.join(__dirname, 'private', 'admin-panel.enc');
const writeSync = (file, data) => { const fd = fs.openSync(file, 'w'); try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };

// Сброс входа по коду: рабочий и «ожидающий» секреты и шаг последнего кода стираются, все сессии завершаются.
// Дальше владелец входит на сайт, открывает панель паролем и подключает приложение заново.
function totpReset(db, phoneArg) {
  const { normPhone, validPhone, maskPhone } = require('./lib/util');
  const { phoneIndex } = require('./lib/secure');
  const { audit } = require('./lib/guard');
  const phone = normPhone(phoneArg);
  if (!validPhone(phone)) throw new Error('Укажите номер полностью, например +996700123456');
  const user = db.q('SELECT id, name, role, totp_secret_enc, totp_pending_enc FROM users WHERE phone_idx = ?').get(phoneIndex(phone));
  if (!user) throw new Error('Пользователь с таким номером не найден.');
  if (user.role !== 'admin' && !user.totp_secret_enc && !user.totp_pending_enc) throw new Error('Это не администратор — сбрасывать нечего.');
  const sessions = db.tx(() => {
    db.q('UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_last = 0 WHERE id = ?').run(user.id);
    return Number(db.q('DELETE FROM sessions WHERE user_id = ?').run(user.id).changes);
  });
  audit(db, { type: 'admin_totp_reset', userId: user.id, ip: 'console', detail: maskPhone(phone) });
  return { name: user.name, wasOn: !!user.totp_secret_enc, sessions };
}

// Удаление аккаунта из консоли — по просьбе человека, который сам войти не может (ни пароля, ни доступа к номеру; кто просит,
// владелец сайта проверяет сам). Без yes — только сводка: что удалится; с yes — то же, что POST /api/me/delete
// (lib/retention.js deleteAccount): одной транзакцией стираются все данные, гостям его предстоящих сборов — уведомление
// об отмене, журнал безопасности обезличивается, а удаление записывается в него с последними цифрами номера.
function deleteUser(db, phoneArg, { yes = false, now = Date.now() } = {}) {
  const { normPhone, validPhone, maskPhone } = require('./lib/util');
  const { phoneIndex } = require('./lib/secure');
  const { audit } = require('./lib/guard');
  const { deleteAccount, upcomingGuests } = require('./lib/retention');
  const phone = normPhone(phoneArg);
  if (!validPhone(phone)) throw new Error('Укажите номер полностью, например +996700123456');
  const user = db.q('SELECT * FROM users WHERE phone_idx = ?').get(phoneIndex(phone));
  if (!user) throw new Error('Пользователь с таким номером не найден.');
  const n = (sql, ...args) => db.q(sql).get(...args).n;
  const hosted = db.q('SELECT at FROM events WHERE host_id = ?').all(user.id);
  const r = {
    name: String(user.name).replace(/[\u0000-\u001f\u007f-\u009f]/g, ''), masked: maskPhone(phone), admin: user.role === 'admin', createdAt: String(user.created_at || '').slice(0, 10),
    events: hosted.length, upcoming: hosted.filter(e => !(new Date(e.at).getTime() < now - 4 * 3600e3)).length, guests: upcomingGuests(db, user.id, now).length,
    messages: n('SELECT COUNT(*) AS n FROM comments WHERE user_id = ?', user.id), reviews: n('SELECT COUNT(*) AS n FROM reviews WHERE user_id = ?', user.id),
    mixes: n('SELECT COUNT(*) AS n FROM mixes WHERE author_id = ?', user.id), friends: n('SELECT COUNT(*) AS n FROM friends WHERE user_id = ?', user.id),
    sessions: n('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?', user.id, now), deleted: false, notified: 0
  };
  if (!yes) return r;
  const notified = deleteAccount(db, user, now);
  if (notified === null) throw new Error('Аккаунт уже удалён.');
  audit(db, { type: 'account_deleted', ip: 'console', detail: `${r.masked} · console` });
  return { ...r, deleted: true, notified };
}

// Смена ключа ADMIN_CODE_KEY (ключ мог утечь вместе с .env, ушёл человек с доступом, плановая смена).
// Панель расшифровывается текущим ключом из файла настроек и шифруется новым; строка ADMIN_CODE_KEY заменяется на месте.
// Прежний файл панели лежит рядом (.old), пока новый файл и новый ключ не прошли проверку с диска; при ошибке всё возвращается как было.
function rekey({ envFile = DEFAULT_ENV, file = encFile() } = {}) {
  const panel = require('./lib/panel');
  const current = [...new Set(envValues(envFile, 'ADMIN_CODE_KEY').filter(Boolean))];
  if (!current.length) throw new Error(`В ${envFile} нет ADMIN_CODE_KEY — менять нечего. Создать ключ: node server/admin.js key`);
  if (current.length > 1) throw new Error(`В ${envFile} несколько разных строк ADMIN_CODE_KEY — оставьте одну (ту, которой зашифрована панель) и повторите.`);
  if (process.env.ADMIN_CODE_KEY && process.env.ADMIN_CODE_KEY !== current[0]) throw new Error(`ADMIN_CODE_KEY задан в окружении и отличается от ${envFile} — непонятно, какой настоящий. Выполните unset ADMIN_CODE_KEY и повторите.`);
  const oldKey = Buffer.from(current[0], 'base64');
  if (oldKey.length !== 32) throw new Error(`ADMIN_CODE_KEY в ${envFile} — не 32 байта в base64.`);
  if (!fs.existsSync(file)) throw new Error('Нет файла панели: ' + file);
  for (const f of [envFile, path.dirname(file)]) { try { fs.accessSync(f, fs.constants.W_OK); } catch (e) { throw new Error('Нет прав на запись: ' + f); } }
  let plain;
  try { plain = panel.decrypt(fs.readFileSync(file), oldKey); } catch (e) { throw new Error(`Текущий ключ не расшифровывает ${file}: ключ не тот или файл повреждён.`); }
  const newKey = crypto.randomBytes(32), newB64 = newKey.toString('base64'), next = panel.encrypt(plain, newKey);
  if (!panel.decrypt(next, newKey).equals(plain)) throw new Error('Проверка нового шифрования не прошла.');

  const old = file + '.old', tmp = file + '.new', envBefore = fs.readFileSync(envFile);
  fs.copyFileSync(file, old);
  let envTouched = false;
  try {
    writeSync(tmp, next);
    fs.renameSync(tmp, file);
    envTouched = true;
    setEnvValue(envFile, 'ADMIN_CODE_KEY', newB64);
    // Проверка с диска: в файле настроек ровно новый ключ, и он расшифровывает новый файл панели в прежний исходник.
    const onDisk = envValues(envFile, 'ADMIN_CODE_KEY').filter(Boolean);
    if (onDisk.length !== 1 || onDisk[0] !== newB64) throw new Error(`новый ключ не записался в ${envFile}`);
    if (!panel.decrypt(fs.readFileSync(file), Buffer.from(onDisk[0], 'base64')).equals(plain)) throw new Error('новый файл панели не расшифровывается новым ключом');
  } catch (e) {
    try {
      if (envTouched) writeSync(envFile, envBefore); // файл настроек — байт в байт как был, на месте
      fs.renameSync(old, file);
      fs.rmSync(tmp, { force: true });
    } catch (x) { throw new Error(`Ключ не сменён (${e.message}), и вернуть всё назад не удалось (${x.message}). Прежний файл панели — ${old}; проверьте ADMIN_CODE_KEY в ${envFile}.`); }
    throw new Error(`Ключ не сменён: ${e.message}. Всё возвращено как было.`);
  }
  fs.rmSync(old, { force: true });
  return { file, envFile };
}

function main(cmd, arg, envFile, { yes = false } = {}) {
  const panel = require('./lib/panel');
  if (cmd === 'key') {
    if (process.env.ADMIN_CODE_KEY) return console.log('Ключ уже есть — новый не создаю (иначе панель не расшифруется). Сменить ключ: node server/admin.js rekey');
    setEnvValue(envFile, 'ADMIN_CODE_KEY', panel.newKey());
    return console.log(`Ключ записан в ${envFile}. Сохраните копию файла в надёжном месте и перенесите ключ на сервер.`);
  }
  if (cmd === 'pack' || cmd === 'unpack') return console.log((cmd === 'pack' ? 'Зашифровано: ' : 'Восстановлено: ') + panel[cmd]());
  if (cmd === 'rekey') {
    const r = rekey({ envFile });
    return console.log([`Ключ панели сменён: ${r.file} перешифрован, новый ADMIN_CODE_KEY записан в ${r.envFile} (на экран не выводился).`,
      'Дальше:', '  1) закоммитьте и отправьте новый admin-panel.enc;',
      '  2) на сервере замените ADMIN_CODE_KEY на новый и перезапустите сервис — пока ключ и файл не совпадут, панель не откроется;',
      '  3) сохраните новый .env в менеджере паролей вместо прежнего.'].join('\n'));
  }
  if (!['list', 'grant', 'revoke', 'totp-reset', 'delete'].includes(cmd)) return console.log(USAGE);

  const { open } = require('./lib/db');
  const { phoneIndex, decrypt } = require('./lib/secure');
  const { normPhone, validPhone, maskPhone } = require('./lib/util');
  const { audit } = require('./lib/guard');
  const db = open(process.env.DB_PATH || path.join(__dirname, 'data', 'hookah.db'));
  try {
    if (cmd === 'list') {
      const rows = db.q("SELECT id, name, phone_enc, totp_secret_enc FROM users WHERE role = 'admin'").all();
      console.log(rows.length ? rows.map(r => {
        const p = decrypt(r.phone_enc);
        return `${r.name} (${maskPhone(p)})${panel.phoneAllowed(p) ? '' : ' — номера нет в ADMIN_PHONES, панель недоступна'} — приложение для кодов: ${r.totp_secret_enc ? 'подключено' : 'не подключено'}`;
      }).join('\n') : 'Администраторов нет.');
    } else if (cmd === 'totp-reset') {
      const r = totpReset(db, arg);
      console.log(`${r.name}: вход по коду из приложения сброшен${r.wasOn ? '' : ' (приложение и не было подключено)'}, завершено сессий: ${r.sessions}.\n` +
        'Войдите на сайт, откройте панель паролем и подключите приложение заново. Старую запись «Hookah Party» в приложении удалите.');
    } else if (cmd === 'delete') {
      const r = deleteUser(db, arg, { yes });
      const who = `${r.name} (${r.masked})${r.admin ? ', администратор' : ''}, зарегистрирован ${r.createdAt}`;
      if (r.deleted) {
        console.log(`Аккаунт удалён: ${who}.\nСборов удалено: ${r.events}; уведомлений об отмене гостям: ${r.notified}. Журнал безопасности обезличен, удаление записано в него.`);
      } else {
        console.log([`Будет удалён аккаунт: ${who}.`, 'Сразу и навсегда удалятся:',
          `  · сборы, которые он организует: ${r.events} (предстоящих: ${r.upcoming}; гостей, которым придёт уведомление об отмене: ${r.guests});`,
          `  · сообщения и комментарии: ${r.messages}; отзывы: ${r.reviews}; миксы: ${r.mixes}; друзья: ${r.friends};`,
          `  · профиль, номер, ответы на приглашения, голоса, лайки, уведомления; активные сессии: ${r.sessions}.`,
          'Журнал безопасности останется без привязки к человеку (до 90 дней).',
          'Ничего не удалено. Чтобы удалить, повторите с --yes: node server/admin.js delete <номер> --yes'].join('\n'));
        process.exitCode = 2;
      }
    } else {
      const phone = normPhone(arg);
      if (!validPhone(phone)) throw new Error('Укажите номер полностью, например +996700123456');
      if (cmd === 'grant' && !panel.phoneAllowed(phone)) throw new Error('Этого номера нет в ADMIN_PHONES в .env — права не выданы. Администратором может быть только владелец.');
      const user = db.q('SELECT id, name FROM users WHERE phone_idx = ?').get(phoneIndex(phone));
      if (!user) throw new Error('Пользователь с таким номером не найден. Сначала зарегистрируйтесь на сайте.');
      db.q('UPDATE users SET role = ? WHERE id = ?').run(cmd === 'grant' ? 'admin' : 'user', user.id);
      db.q('DELETE FROM sessions WHERE user_id = ?').run(user.id);
      audit(db, { type: cmd === 'grant' ? 'admin_granted' : 'admin_revoked', userId: user.id, ip: 'console', detail: maskPhone(phone) });
      console.log(`${user.name}: ${cmd === 'grant' ? 'права администратора выданы' : 'права администратора сняты'}. Войдите на сайт заново.`);
    }
  } finally { db.close(); }
}

if (require.main === module) {
  const argv = process.argv.slice(2), rest = [];
  let envFile = DEFAULT_ENV, yes = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--env') envFile = path.resolve(argv[++i] || '.env');
    else if (argv[i].startsWith('--env=')) envFile = path.resolve(argv[i].slice(6));
    else if (argv[i] === '--yes' || argv[i] === '-y') yes = true;
    else rest.push(argv[i]);
  }
  // Настройки — до подключения модулей с ключами: secure.js берёт DATA_KEY при загрузке.
  process.env.NODE_ENV ||= 'development';
  loadEnv(envFile);
  try { main(rest[0], rest[1], envFile, { yes }); } catch (e) { console.error(e.message); process.exit(1); }
}
module.exports = { totpReset, rekey, deleteUser };
