'use strict';
// QR-код (ISO/IEC 18004) без сторонних библиотек — для ссылки otpauth:// при подключении приложения-аутентификатора.
// Байтовый режим (UTF-8), уровень коррекции M (восстанавливает ~15% повреждений), версия 1–40 подбирается по длине,
// маска — та из восьми, у которой меньше всего штрафных очков по правилам стандарта.
// encode(text) → массив строк из '0' и '1' (1 — тёмный модуль), строка — ряд сверху вниз. Белую рамку (4 модуля) добавляет тот, кто рисует.

// Уровень M по версиям 1–40 (таблица 9 стандарта): кодовых слов коррекции в каждом блоке и число блоков.
const EC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
const LEVEL_M = 0b00; // код уровня M в служебной информации о формате (L = 01, M = 00, Q = 11, H = 10)

// Сколько модулей под данные и коррекцию: всё поле минус служебные узоры (формула из стандарта, в битах).
function rawModules(ver) {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}
const totalCodewords = ver => Math.floor(rawModules(ver) / 8);
const dataCodewords = ver => totalCodewords(ver) - EC_PER_BLOCK[ver] * BLOCKS[ver];
const countBits = ver => ver <= 9 ? 8 : 16; // длина поля «сколько байт» в байтовом режиме

// Центры выравнивающих узоров по каждой оси.
function alignPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2, step = Math.floor((ver * 8 + n * 3 + 5) / (n * 4 - 4)) * 2, out = [6];
  for (let pos = ver * 4 + 10; out.length < n; pos -= step) out.splice(1, 0, pos);
  return out;
}

// ---------- Рид — Соломон над GF(256), многочлен поля x^8 + x^4 + x^3 + x^2 + 1 (0x11D) ----------
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => a && b ? EXP[LOG[a] + LOG[b]] : 0;

// Порождающий многочлен (x − α^0)(x − α^1)…(x − α^(n−1)), коэффициенты от старшей степени.
function generator(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) { next[j] ^= g[j]; next[j + 1] ^= mul(g[j], EXP[i]); }
    g = next;
  }
  return g;
}
// Остаток от деления данных (умноженных на x^n) на порождающий многочлен — это и есть кодовые слова коррекции.
function remainder(data, gen) {
  const rem = new Array(gen.length - 1).fill(0);
  for (const b of data) {
    const f = b ^ rem.shift();
    rem.push(0);
    for (let i = 0; i < rem.length; i++) rem[i] ^= mul(gen[i + 1], f);
  }
  return rem;
}

// ---------- Данные ----------
// Режим «байты» (0100), длина, сами байты, терминатор, добивка до байта и чередование 0xEC / 0x11 до заполнения версии.
function packData(bytes, ver) {
  const bits = [], cap = dataCodewords(ver) * 8;
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push(val >>> i & 1); };
  put(0b0100, 4);
  put(bytes.length, countBits(ver));
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - bits.length % 8) % 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((v, bit) => v << 1 | bit, 0));
  for (let pad = 0xec; out.length < dataCodewords(ver); pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}
// Делим на блоки (сначала короткие, затем на одно слово длиннее), к каждому — коррекция; затем перемежаем по словам.
function withEcc(data, ver) {
  const nb = BLOCKS[ver], ec = EC_PER_BLOCK[ver], total = totalCodewords(ver);
  const shortLen = Math.floor(total / nb), nShort = nb - total % nb, gen = generator(ec), blocks = [];
  for (let i = 0, k = 0; i < nb; i++) {
    const len = shortLen - ec + (i < nShort ? 0 : 1), d = data.slice(k, k + len);
    k += len;
    blocks.push({ d, e: remainder(d, gen) });
  }
  const out = [];
  for (let i = 0; i <= shortLen - ec; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i]);
  for (let i = 0; i < ec; i++) for (const b of blocks) out.push(b.e[i]);
  return out;
}

// ---------- Поле ----------
// m[y][x]: 1 — тёмный модуль; fn[y][x]: 1 — служебный модуль (узоры, формат, версия), маска его не трогает.
function functionPatterns(ver) {
  const size = ver * 4 + 17;
  const m = Array.from({ length: size }, () => new Uint8Array(size)), fn = Array.from({ length: size }, () => new Uint8Array(size));
  const set = (x, y, dark) => { m[y][x] = dark ? 1 : 0; fn[y][x] = 1; };
  // Линии синхронизации: шестой ряд и шестой столбец, через один.
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  // Три поисковых узора 7×7 с белой каймой-разделителем.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
      if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
    }
  }
  // Выравнивающие узоры 5×5 — везде на сетке, кроме трёх углов с поисковыми.
  const pos = alignPositions(ver), last = pos.length - 1;
  for (let i = 0; i <= last; i++) for (let j = 0; j <= last; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  drawFormat(m, fn, 0); // место под формат занимаем сразу, сами биты — после выбора маски
  // Версия (с 7-й): 6 бит номера + 12 бит кода Боуза — Чоудхури — Хоквингема, два блока 3×6.
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = ver << 12 | rem;
    for (let i = 0; i < 18; i++) {
      const dark = bits >>> i & 1, a = size - 11 + i % 3, b = Math.floor(i / 3);
      set(a, b, dark); set(b, a, dark);
    }
  }
  return { m, fn, size };
}

// Формат: уровень коррекции и номер маски, 10 бит кода БЧХ, XOR 101010000010010. Две копии и всегда тёмный модуль.
function drawFormat(m, fn, mask) {
  const size = m.length, data = LEVEL_M << 3 | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = (data << 10 | rem) ^ 0x5412, bit = i => bits >>> i & 1;
  const set = (x, y, dark) => { m[y][x] = dark; fn[y][x] = 1; };
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, 1);
}

// Кодовые слова — змейкой по парам столбцов справа налево, снизу вверх и обратно; столбец 6 (синхронизация) пропускается.
function placeData(m, fn, codewords) {
  const size = m.length, total = codewords.length * 8;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const up = ((right + 1) & 2) === 0;
    for (let k = 0; k < size; k++) for (let j = 0; j < 2; j++) {
      const x = right - j, y = up ? size - 1 - k : k;
      if (!fn[y][x] && i < total) { m[y][x] = codewords[i >>> 3] >>> (7 - (i & 7)) & 1; i++; }
    }
  }
}

// Восемь масок стандарта; x — столбец, y — ряд.
const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => x * y % 2 + x * y % 3 === 0,
  (x, y) => (x * y % 2 + x * y % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0
];

// Штрафные очки (раздел 7.8.3): 1) ряды из 5+ одинаковых модулей; 2) квадраты 2×2 одного цвета;
// 3) узор 1:1:3:1:1, как у поискового, с 4 светлыми модулями с одной из сторон (за краем поля — светлая рамка);
// 4) отклонение доли тёмных модулей от 50%.
function penalty(m) {
  const n = m.length, CORE = [1, 0, 1, 1, 1, 0, 1];
  let p = 0, dark = 0;
  for (let a = 0; a < n; a++) {
    for (const get of [i => m[a][i], i => m[i][a]]) {
      for (let i = 1, run = 1; i <= n; i++) {
        if (i < n && get(i) === get(i - 1)) run++;
        else { if (run >= 5) p += 3 + run - 5; run = 1; }
      }
      const light = (from, to) => { for (let i = from; i <= to; i++) if (i >= 0 && i < n && get(i)) return false; return true; };
      for (let c = 0; c + 7 <= n; c++) {
        if (!CORE.every((v, k) => get(c + k) === v)) continue;
        if (light(c - 4, c - 1)) p += 40;
        if (light(c + 7, c + 10)) p += 40;
      }
    }
  }
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
    const v = m[y][x];
    if (v === m[y][x + 1] && v === m[y + 1][x] && v === m[y + 1][x + 1]) p += 3;
  }
  for (const row of m) for (const v of row) dark += v;
  return p + (Math.ceil(Math.abs(dark * 20 - n * n * 10) / (n * n)) - 1) * 10;
}

function encode(text) {
  const bytes = Buffer.from(String(text ?? ''), 'utf8');
  let ver = 1;
  while (ver <= 40 && 4 + countBits(ver) + bytes.length * 8 > dataCodewords(ver) * 8) ver++;
  if (ver > 40) throw new Error('Слишком длинный текст для QR-кода');
  const { m, fn, size } = functionPatterns(ver);
  placeData(m, fn, withEcc(packData(bytes, ver), ver));
  let best = null;
  for (let k = 0; k < 8; k++) {
    const t = m.map(r => r.slice()), f = fn.map(r => r.slice());
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[k](x, y)) t[y][x] ^= 1;
    drawFormat(t, f, k);
    const score = penalty(t);
    if (!best || score < best.score) best = { t, score };
  }
  return best.t.map(row => row.join(''));
}

module.exports = { encode };
