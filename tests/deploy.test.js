'use strict';
// Настройки сервера (deploy/): пределы ресурсов systemd и лимиты nginx — IPv6 считается по сети /64, а не по адресу.
// nginx на машине разработчика нет, поэтому проверяем файл разбором: структура, ключи зон и то, как map
// превращает адрес в ключ лимита (те же регулярные выражения, что прочтёт nginx).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DIR = process.env.DEPLOY_DIR || path.join(__dirname, '..', 'deploy');
const read = f => fs.readFileSync(path.join(DIR, f), 'utf8');

// systemd: { Unit: { Key: value }, Service: {...} } — последнее значение ключа.
function unit(text) {
  const out = {}; let sec = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const s = /^\[(\w+)\]$/.exec(line);
    if (s) { sec = out[s[1]] = {}; continue; }
    const kv = /^(\w+)=(.*)$/.exec(line);
    if (kv && sec) sec[kv[1]] = kv[2];
  }
  return out;
}
const bytes = v => { const m = /^(\d+)([KMG]?)$/.exec(v || ''); assert.ok(m, `размер памяти: ${v}`); return +m[1] * { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3 }[m[2]]; };

test('systemd: у сервиса есть пределы памяти, потоков и файлов, перезапуск с разумным пределом частоты', () => {
  const u = unit(read('hookah-party.service'));
  const s = u.Service;
  assert.equal(s.Restart, 'on-failure');
  const high = bytes(s.MemoryHigh), max = bytes(s.MemoryMax);
  assert.ok(high < max, 'MemoryHigh ниже MemoryMax: сначала притормаживание, потом остановка');
  // 4 одновременных Argon2 по 19 МиБ + сам Node; и не больше половины небольшого VPS.
  assert.ok(max >= 256 * 1024 ** 2 && max <= 1024 ** 3, `MemoryMax ${s.MemoryMax}`);
  assert.ok(+s.TasksMax >= 32 && +s.TasksMax <= 512, `TasksMax ${s.TasksMax}`);
  assert.ok(+s.LimitNOFILE >= 1024 && +s.LimitNOFILE <= 65536, `LimitNOFILE ${s.LimitNOFILE}`);
  // StartLimit* — в [Unit] (в [Service] systemd их не понимает и молча игнорирует).
  assert.ok(u.Unit.StartLimitIntervalSec && +u.Unit.StartLimitBurst > 0, 'StartLimitIntervalSec и StartLimitBurst в [Unit]');
  assert.ok(!('StartLimitIntervalSec' in s) && !('StartLimitBurst' in s));
  // Падение при каждом запуске (раз в RestartSec + ~1 с) упирается в предел, а падения раз в минуту и реже — нет.
  const sec = v => { const m = /^(\d+)(min|s)?$/.exec(v); assert.ok(m, `время: ${v}`); return +m[1] * (m[2] === 'min' ? 60 : 1); };
  const interval = sec(u.Unit.StartLimitIntervalSec), burst = +u.Unit.StartLimitBurst;
  assert.ok(burst * (sec(s.RestartSec) + 1) <= interval, 'цикл падений при запуске останавливается');
  assert.ok(interval / burst <= 60, 'редкие падения не останавливают сервис');
});

// nginx: разбор как в ngx_conf_read_token — кавычки, \, комментарии, { } ;.
function nginx(text) {
  const toks = []; let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if ('{};'.includes(c)) { toks.push(c); i++; continue; }
    let v = '';
    if (c === '"' || c === "'") {
      i++;
      while (text[i] !== c) { assert.ok(i < text.length, 'незакрытая кавычка'); if (text[i] === '\\' && (text[i + 1] === c || text[i + 1] === '\\')) i++; v += text[i++]; }
      i++;
    } else while (i < text.length && !/[\s{};]/.test(text[i])) v += text[i++];
    toks.push({ v });
  }
  let p = 0;
  const block = () => {
    const items = [];
    while (p < toks.length && toks[p] !== '}') {
      const words = [];
      while (typeof toks[p] === 'object') words.push(toks[p++].v);
      const end = toks[p++];
      assert.ok(end === ';' || end === '{', `после «${words.join(' ')}» нет ; или {`);
      const d = { name: words[0], args: words.slice(1) };
      if (end === '{') { d.children = block(); assert.equal(toks[p++], '}', `не закрыт блок ${d.name}`); }
      items.push(d);
    }
    return items;
  };
  const tree = block();
  assert.equal(p, toks.length, 'лишняя }');
  return tree;
}
const all = (items, name) => items.filter(d => d.name === name);
const one = (items, name) => { const f = all(items, name); assert.equal(f.length, 1, `одна директива ${name}`); return f[0]; };

// Адрес → байты, как $binary_remote_addr (IPv4 — 4 байта, IPv6 — 16).
function addrBytes(a) {
  if (!a.includes(':')) return Buffer.from(a.split('.').map(Number));
  let tail = [];
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (v4) { const b = addrBytes(v4[1]); tail = [b.readUInt16BE(0).toString(16), b.readUInt16BE(2).toString(16)]; a = a.slice(0, -v4[1].length) + 'x'; }
  const [head, rest] = a.split('::');
  const part = s => (s ? s.split(':') : []).flatMap(g => g === 'x' ? tail : [g]);
  const h = part(head), r = rest === undefined ? [] : part(rest);
  const groups = rest === undefined ? h : [...h, ...Array(8 - h.length - r.length).fill('0'), ...r];
  assert.equal(groups.length, 8, a);
  return Buffer.from(groups.flatMap(g => { const n = parseInt(g, 16); return [n >> 8, n & 255]; }));
}

test('nginx: лимиты считают IPv6 по сети /64, IPv4 — по адресу; есть пределы одновременных запросов', () => {
  const tree = nginx(read('nginx.conf'));
  const map = all(tree, 'map').find(m => m.args[0] === '$binary_remote_addr');
  assert.ok(map, 'map $binary_remote_addr $… — ключ посетителя');
  const key = map.args[1];
  // Все зоны частоты и одновременных запросов — по этому ключу. Общей зоны на весь сайт нет намеренно: несколько адресов
  // с медленными запросами заняли бы её и закрыли сайт для всех.
  const zones = [...all(tree, 'limit_req_zone'), ...all(tree, 'limit_conn_zone')];
  assert.ok(zones.length >= 3);
  for (const z of zones) assert.ok(z.args[0] === key, `${z.name} ${z.args.join(' ')}: ключ ${key}`);
  const zoneName = z => z.args.find(a => a.startsWith('zone=')).slice(5).split(':')[0];
  const perClient = zoneName(all(tree, 'limit_conn_zone').find(z => z.args[0] === key));

  // map так, как его выполнит nginx: регулярные выражения по порядку, потом default. (?s) PCRE = флаг s в JS.
  const rules = map.children.map(d => ({ re: d.name, val: d.args[0] }));
  const ev = buf => {
    const s = buf.toString('latin1');
    for (const r of rules) {
      if (r.re === 'default' || !r.re.startsWith('~')) continue;
      let src = r.re.slice(1), flags = '';
      if (src.startsWith('(?s)')) { src = src.slice(4); flags = 's'; }
      const m = new RegExp(src, flags).exec(s);
      if (m) return r.val === '$1' ? m[1] : r.val === '$binary_remote_addr' ? s : assert.fail(`неожиданное значение ${r.val}`);
    }
    const d = rules.find(r => r.re === 'default');
    assert.equal(d?.val, '$binary_remote_addr');
    return s;
  };
  const k = a => Buffer.from(ev(addrBytes(a)), 'latin1').toString('hex');
  // Одна сеть /64 — один посетитель, в любой записи адреса (в том числе с байтами 0x0a — «перевод строки» для регулярки).
  assert.equal(k('2001:db8:1234:5678::1'), k('2001:db8:1234:5678:ffff:ffff:ffff:fffe'));
  assert.equal(k('2001:db8:a0a:a0a:a0a:a0a:a0a:a0a'), k('2001:db8:a0a:a0a::'));
  assert.equal(k('2001:db8::1'), k('2001:db8:0:0:1::1'));
  assert.equal(k('2001:db8:1234:5678::1'), '20010db812345678');
  // Соседняя сеть — другой посетитель; IPv4 — каждый адрес отдельно, в том числе внутри IPv6 (::ffff:a.b.c.d).
  assert.notEqual(k('2001:db8:1234:5678::1'), k('2001:db8:1234:5679::1'));
  assert.notEqual(k('203.0.113.7'), k('203.0.113.8'));
  assert.equal(k('203.0.113.7'), 'cb007107');
  assert.notEqual(k('::ffff:203.0.113.7'), k('::ffff:203.0.113.8'));

  // Сам сайт (443 с именем): оба предела одновременных запросов, ответ 429 (как у лимита частоты) — сайт покажет его как
  // «слишком много запросов», а не как «сервер недоступен» (503).
  const servers = all(tree, 'server');
  const site = servers.find(s => all(s.children, 'listen').some(l => l.args[0] === '443' && !l.args.includes('default_server')));
  assert.ok(site, 'server на 443');
  const lc = all(site.children, 'limit_conn');
  const n = zone => +(lc.find(d => d.args[0] === zone) || assert.fail(`limit_conn ${zone}`)).args[1];
  assert.ok(n(perClient) > 0, 'есть предел одновременных запросов от одного посетителя');
  assert.equal(lc.length, 1, 'общего потолка на весь сайт нет');
  assert.ok(n(perClient) >= 30, 'страница при первом открытии грузит ~15 файлов сразу, с запасом на общий IP оператора');
  assert.equal(one(site.children, 'limit_conn_status').args[0], '429');
  assert.equal(one(site.children, 'limit_req_status').args[0], '429');
  for (const loc of all(site.children, 'location').filter(l => l.args[0].startsWith('/api/'))) {
    const pages = all(loc.children, 'error_page').map(d => d.args.join(' '));
    assert.ok(pages.includes('429 = @api_429') && pages.includes('502 503 504 = @api_down'), `ошибки nginx в JSON: ${loc.args[0]}`);
  }
  const down = all(site.children, 'location').find(l => l.args[0] === '@api_down');
  assert.match(one(down.children, 'return').args.join(' '), /^503 \{"error":"server_down"/);

  // Серверы по умолчанию принимают каждое соединение первыми: их client_header_timeout действует до конца заголовков
  // первого запроса (и рукопожатия TLS). Без него — 60 секунд по умолчанию.
  const defaults = servers.filter(s => all(s.children, 'listen').some(l => l.args.includes('default_server')));
  assert.equal(defaults.length, 2);
  for (const s of defaults) assert.ok(parseInt(one(s.children, 'client_header_timeout').args[0], 10) <= 15, 'короткий client_header_timeout у сервера по умолчанию');
});
