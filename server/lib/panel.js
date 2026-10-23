'use strict';
// Панель администратора и кто имеет к ней доступ.
//
// 1) Код панели хранится в репозитории только зашифрованным (AES-256-GCM): server/private/admin-panel.enc.
//    Ключ ADMIN_CODE_KEY есть только в .env у владельца и на сервере. Сервер расшифровывает панель в памяти
//    и отдаёт её лишь администратору. Исходник server/private/admin-panel.js в git не попадает.
// 2) Администратор — только тот, у кого роль admin в базе И номер записан в ADMIN_PHONES на сервере.
//    Одной записи в базе недостаточно: даже с доступом к базе права администратора не получить.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { phoneIndex } = require('./secure');
const { normPhone, validPhone } = require('./util');

const DIR = path.join(__dirname, '..', 'private');
const SRC = path.join(DIR, 'admin-panel.js');
const encPath = () => process.env.ADMIN_PANEL_ENC || path.join(DIR, 'admin-panel.enc');
const MAGIC = Buffer.from('HPA1'), AAD = Buffer.from('hookah-party/admin-panel');

function codeKey() {
  const k = Buffer.from(process.env.ADMIN_CODE_KEY || '', 'base64');
  return k.length === 32 ? k : null;
}
const newKey = () => crypto.randomBytes(32).toString('base64');

function encrypt(plain, key) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(AAD);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), body]);
}
// Тег GCM — ровно 16 байт (authTagLength): обрезанный файл не принимаем.
function decrypt(blob, key) {
  if (blob.length < 32 || !blob.subarray(0, 4).equals(MAGIC)) throw new Error('не тот формат файла');
  const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(4, 16), { authTagLength: 16 });
  d.setAAD(AAD); d.setAuthTag(blob.subarray(16, 32));
  return Buffer.concat([d.update(blob.subarray(32)), d.final()]);
}

// Зашифровать исходник панели (после правок в admin-panel.js).
function pack(src = SRC, out = encPath(), key = codeKey()) {
  if (!key) throw new Error('Нет ключа ADMIN_CODE_KEY в .env');
  fs.writeFileSync(out, encrypt(fs.readFileSync(src), key));
  return out;
}
// Восстановить исходник из зашифрованного файла (например, на новом компьютере).
function unpack(out = SRC, file = encPath(), key = codeKey()) {
  if (!key) throw new Error('Нет ключа ADMIN_CODE_KEY в .env');
  fs.writeFileSync(out, decrypt(fs.readFileSync(file), key), { mode: 0o600 });
  return out;
}

// Расшифрованная панель для отдачи администратору; null — ключа нет или файл не тот.
let cached = null;
function panelCode() {
  const key = codeKey(); if (!key) return null;
  try {
    const st = fs.statSync(encPath());
    if (!cached || cached.mtime !== st.mtimeMs) cached = { mtime: st.mtimeMs, code: decrypt(fs.readFileSync(encPath()), key) };
    return cached.code;
  } catch (e) { return null; }
}

// Номера владельцев из ADMIN_PHONES (через запятую). Сравниваем по индексу номера, как в базе.
function allowedIdx() {
  return new Set(String(process.env.ADMIN_PHONES || '').split(',').map(normPhone).filter(validPhone).map(phoneIndex));
}
const phoneAllowed = phone => validPhone(normPhone(phone)) && allowedIdx().has(phoneIndex(normPhone(phone)));
const isAdminUser = user => !!user && user.role === 'admin' && allowedIdx().has(user.phone_idx);

module.exports = { pack, unpack, panelCode, newKey, isAdminUser, phoneAllowed, encrypt, decrypt };
