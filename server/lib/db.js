'use strict';
// База SQLite (встроена в Node 24). Все запросы — подготовленные: данные передаются отдельно от SQL,
// поэтому SQL-инъекция невозможна.
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

function open(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 3000;

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
  `);
  // Короткие помощники: q(sql).all(...)/get/run. Кешируем подготовленные запросы.
  const cache = new Map();
  db.q = sql => { let st = cache.get(sql); if (!st) { st = db.prepare(sql); cache.set(sql, st); } return st; };
  db.tx = fn => { db.exec('BEGIN'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  return db;
}

module.exports = { open };
