'use strict';
// База SQLite (встроена в Node 24). Все запросы — подготовленные: данные передаются отдельно от SQL,
// поэтому SQL-инъекция невозможна.
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

function open(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  // secure_delete: удалённое затирается нулями, в свободных страницах файла и в WAL не остаётся текста сообщений, имён и номеров
  // удалённых аккаунтов (а значит, и в копиях, сделанных после удаления).
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 3000;
    PRAGMA secure_delete = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      phone_enc TEXT NOT NULL, phone_idx TEXT NOT NULL UNIQUE, phone_tail TEXT NOT NULL,
      pass TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 1, avatar TEXT,
      fav_venue TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_ip TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, ua TEXT
    );
    CREATE TABLE IF NOT EXISTS sms_codes (
      phone_idx TEXT PRIMARY KEY, code_hash TEXT NOT NULL, purpose TEXT NOT NULL,
      expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS favs (user_id TEXT REFERENCES users(id) ON DELETE CASCADE, tobacco_id TEXT, PRIMARY KEY (user_id, tobacco_id));
    CREATE TABLE IF NOT EXISTS friends (user_id TEXT REFERENCES users(id) ON DELETE CASCADE, friend_id TEXT REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (user_id, friend_id));
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, venue TEXT NOT NULL, venue_id TEXT, address TEXT NOT NULL DEFAULT '',
      map_url TEXT NOT NULL DEFAULT '', at TEXT NOT NULL, host_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      descr TEXT NOT NULL DEFAULT '', hookahs INTEGER NOT NULL DEFAULT 0, price INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE, phone_idx TEXT, phone_enc TEXT, phone_tail TEXT,
      status TEXT NOT NULL DEFAULT 'pending', at TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS invites_user ON invites(event_id, user_id) WHERE user_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS invites_phone ON invites(event_id, phone_idx) WHERE phone_idx IS NOT NULL;
    CREATE TABLE IF NOT EXISTS picks (event_id TEXT REFERENCES events(id) ON DELETE CASCADE, user_id TEXT, tobacco_id TEXT, PRIMARY KEY (event_id, user_id, tobacco_id));
    CREATE TABLE IF NOT EXISTS bowls (event_id TEXT REFERENCES events(id) ON DELETE CASCADE, user_id TEXT, bowl_id TEXT, PRIMARY KEY (event_id, user_id));
    CREATE TABLE IF NOT EXISTS paid (event_id TEXT REFERENCES events(id) ON DELETE CASCADE, user_id TEXT, PRIMARY KEY (event_id, user_id));
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, text TEXT NOT NULL, at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS comments_user_at ON comments(user_id, at);
    CREATE TABLE IF NOT EXISTS reactions (comment_id TEXT REFERENCES comments(id) ON DELETE CASCADE, user_id TEXT, emoji TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (comment_id, user_id));
    CREATE TABLE IF NOT EXISTS stories (event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, rating INTEGER NOT NULL, text TEXT NOT NULL, highlights TEXT NOT NULL, at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS story_fire (event_id TEXT REFERENCES events(id) ON DELETE CASCADE, user_id TEXT, PRIMARY KEY (event_id, user_id));
    CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, tobacco_id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, rating INTEGER NOT NULL, text TEXT NOT NULL, at TEXT NOT NULL, UNIQUE (tobacco_id, user_id));
    CREATE TABLE IF NOT EXISTS mixes (id TEXT PRIMARY KEY, name TEXT NOT NULL, author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, parts TEXT NOT NULL, at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS mix_likes (mix_id TEXT REFERENCES mixes(id) ON DELETE CASCADE, user_id TEXT, PRIMARY KEY (mix_id, user_id));
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL,
      actor_id TEXT, event_id TEXT, ref TEXT, at TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS notifications_user ON notifications(user_id, at);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, user_id TEXT, ip TEXT, type TEXT NOT NULL, detail TEXT
    );
    CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, at);
    CREATE INDEX IF NOT EXISTS audit_type_at ON audit(type, at);
  `);
  // Журнал созданий и отмен сборов: сами отменённые сборы удаляются, а счётчик для лимита остаётся.
  db.exec(`CREATE TABLE IF NOT EXISTS event_log (user_id TEXT NOT NULL, action TEXT NOT NULL, at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS event_log_user ON event_log(user_id, action, at);`);
  // Устройства, с которых входил пользователь (lib/ua.js): fp — отпечаток «браузер + система + тип устройства» без версий,
  // label — подпись для людей («Chrome · macOS»). Вход с нового устройства — уведомление; не виденные год — удаляются (lib/retention.js).
  db.exec(`CREATE TABLE IF NOT EXISTS known_devices (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, fp TEXT NOT NULL, label TEXT NOT NULL,
      first_at INTEGER NOT NULL, last_at INTEGER NOT NULL, PRIMARY KEY (user_id, fp)
    );
    CREATE INDEX IF NOT EXISTS known_devices_seen ON known_devices(last_at);`);
  // sessions.ua — подпись устройства без версий («Chrome · macOS», lib/ua.js), а не сырой User-Agent; ip живёт, пока жива сессия (≤ 30 дней).
  // Миграции старых баз: роль пользователя и время подтверждения прав администратора в сессии.
  // Вход в панель по коду из приложения (lib/totp.js): секрет и секрет на этапе подключения — только зашифрованными (secure.encrypt),
  // totp_last — шаг последнего принятого кода (повторно тот же код не сработает); admin_mfa — сессия открыта паролем и кодом.
  // via_sms_at — когда сессия создана входом по коду из SMS (0 — вход паролем): первые 15 минут в такой сессии пароль
  // можно сменить без текущего («Забыли пароль?», POST /api/me/password).
  // avatar_v — версия фото: в bootstrap уходит только она, сама картинка — по адресу /api/avatar/<id>?v=<версия>.
  // invited_by — кто позвал (организатор или идущий гость): номер приглашённого «по номеру» целиком видят только они.
  // sms_codes.challenge — хэш ключа запроса кода: проверить код может только тот, кто его запросил (POST /api/auth/sms).
  for (const sql of ["ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'", 'ALTER TABLE sessions ADD COLUMN admin_until INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE events ADD COLUMN join_token TEXT',
    'ALTER TABLE users ADD COLUMN totp_secret_enc TEXT', 'ALTER TABLE users ADD COLUMN totp_pending_enc TEXT',
    'ALTER TABLE users ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0', 'ALTER TABLE sessions ADD COLUMN admin_mfa INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE sessions ADD COLUMN via_sms_at INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN avatar_v TEXT', 'ALTER TABLE invites ADD COLUMN invited_by TEXT', 'ALTER TABLE sms_codes ADD COLUMN challenge TEXT']) {
    try { db.exec(sql); } catch (e) { /* колонка уже есть */ }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS events_join ON events(join_token) WHERE join_token IS NOT NULL');
  // Фото, загруженные до появления версии, получают случайную версию один раз.
  db.exec('UPDATE users SET avatar_v = lower(hex(randomblob(8))) WHERE avatar IS NOT NULL AND avatar_v IS NULL');
  // Кого организатор убрал из сбора: по ссылке такой человек не вернётся, пока организатор сам не позовёт его снова.
  db.exec(`CREATE TABLE IF NOT EXISTS event_bans (
      event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      at TEXT NOT NULL, PRIMARY KEY (event_id, user_id)
    );`);
  // Короткие помощники: q(sql).all(...)/get/run. Кешируем подготовленные запросы.
  const cache = new Map();
  db.q = sql => { let st = cache.get(sql); if (!st) { st = db.prepare(sql); cache.set(sql, st); } return st; };
  db.tx = fn => { db.exec('BEGIN'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  // Перенести WAL в файл базы и обнулить WAL (там остаются прежние версии страниц, в том числе удалённый текст).
  // Не ждём: если базу сейчас читает другой процесс (ночная копия), откладываем до следующей чистки (раз в час) — иначе
  // синхронный вызов на 3 секунды остановил бы весь сервер. true — получилось.
  db.wipe = () => {
    db.exec('PRAGMA busy_timeout = 0');
    try { return db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get()?.busy === 0; } catch (e) { return false; } finally { db.exec('PRAGMA busy_timeout = 3000'); }
  };
  // База, созданная до secure_delete, могла сохранить удалённое в свободных страницах — один раз пересобираем её (VACUUM).
  // Отметка — user_version = 1; не вышло (база занята) — попробуем при следующем запуске.
  if (db.prepare('PRAGMA user_version').get().user_version < 1) {
    try { db.exec('VACUUM'); db.exec('PRAGMA user_version = 1'); db.wipe(); } catch (e) { /* в следующий раз */ }
  }
  return db;
}

module.exports = { open };
