#!/usr/bin/env node
'use strict';
// Поиск секретов в git: ключей, токенов, паролей и файлов, которым не место в репозитории.
//   node scripts/check-secrets.js --staged    подготовленное к коммиту (git add); так его вызывает .githooks/pre-commit
//   node scripts/check-secrets.js --all       все файлы под контролем git; так его вызывает CI
//   node scripts/check-secrets.js --history   все коммиты всех веток (git log -p --all)
// Правила только надёжные, почти без ложных срабатываний. Найденное значение не печатается никогда:
// в отчёте — только первые символы и ***. Ложное срабатывание подавляется пометкой «check-secrets: allow»
// в той же строке (пометку увидят при проверке кода). Только встроенные модули Node.
// Код выхода: 0 — секретов нет, 1 — найдены, 2 — проверку выполнить не удалось.
const { spawn, spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

// ---------- Правила ----------
// Токены и ключи с узнаваемым форматом. Заголовок закрытого ключа считается находкой, только если за ним
// конец строки (файл .pem) или сам ключ (\n и base64 в строке кода), а не, например, проверка заголовка в коде.
const TOKEN_RULES = [
  ['private-key', 'закрытый ключ (PEM, OpenSSH, PGP, PuTTY)', /-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?=[ \t]*$|\\[rn]|[A-Za-z0-9+/]{16})|^PuTTY-User-Key-File-\d+: /g],
  ['aws-access-key', 'ключ доступа AWS', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['github-token', 'токен GitHub', /\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{36,})/g],
  ['gitlab-token', 'токен GitLab', /\bglpat-[0-9A-Za-z_-]{20,}/g],
  ['slack-token', 'токен Slack', /\bxox[abpr]-[0-9A-Za-z-]{10,}/g],
  ['stripe-live-key', 'боевой ключ Stripe', /\b[rs]k_live_[0-9A-Za-z]{20,}/g],
  ['google-api-key', 'ключ Google API', /\bAIza[0-9A-Za-z_-]{35}/g],
].map(([id, title, re]) => ({ id, title, re }));
// Токен Twilio — 32 шестнадцатеричных знака; надёжен, только если рядом в строке есть TWILIO_.
const TWILIO = { id: 'twilio-token', title: 'токен Twilio', re: /(?<![0-9A-Za-z])[0-9a-fA-F]{32}(?![0-9A-Za-z])/g };
// Переменные с секретами проекта: значение им задаётся только в .env (он вне git), в .env.example — пустое.
const ENV_SECRETS = ['DATA_KEY', 'ADMIN_CODE_KEY', 'BACKUP_KEY', 'NEW_DATA_KEY', 'TWILIO_TOKEN', 'NIKITA_PASSWORD'];
const ENV_RULE = { id: 'env-secret', title: 'значение секретной переменной' };
// Имя переменной (в JSON/YAML — возможно, в кавычках), затем = := или : и значение.
// «^» перед именем — это шаблон поиска строки (grep '^DATA_KEY=' .env, sed '/^DATA_KEY=/d'), а не присваивание.
const ENV_RE = new RegExp(`(?<![A-Za-z0-9_^])(${ENV_SECRETS.join('|')})["']?[ \\t]*(:=|=(?![=>~])|:(?!:))[ \\t]*`, 'g');
const ALLOW_RE = /check-secrets:\s*allow/;
const CODE_EXT = /\.(?:[cm]?[jt]sx?|swift|py|rb|go|java|kts?|c|cc|cpp|h|hpp|m|mm|rs|php|cs|scala|dart|lua|pl)$/i;
const YAML_EXT = /\.ya?ml$/i;

// Файлы, которых не должно быть в git вовсе (то же самое перечислено в .gitignore).
function forbiddenPath(p) {
  const base = p.slice(p.lastIndexOf('/') + 1);
  if (base === '.env' || (base.startsWith('.env.') && base !== '.env.example')) return 'файл .env с настоящими ключами';
  if (/\.(?:pem|key|p12|pfx|p8)$/i.test(base)) return 'файл ключа или сертификата';
  if (/^id_(?:rsa|dsa|ecdsa|ed25519)/.test(base)) return 'ключ SSH';
  if (p.startsWith('server/data/')) return 'данные сервера (база, копии, ключ разработки)';
  if (p === 'server/private/admin-panel.js') return 'исходник панели администратора (в git — только admin-panel.enc)';
  return null;
}

// Заглушки из документации и примеров: ghp_xxxx…, AKIA…EXAMPLE и т. п.
const looksFake = s => /example|x{8}|0{8}/i.test(s) || new Set(s).size < 6;
// Значение — не литерал, а ссылка на переменную, подстановка или заглушка вида <ключ>, ..., changeme.
const isReference = v => /^(?:\$|%|\{\{|<|process\.env|os\.environ|env\.|ENV\[|secrets\.)/.test(v);
const isPlaceholder = v => /^(?:\.{2,}|…+|\*+|x+|-+|_+|changeme|change[-_]?me|placeholder|example|your[-_ ].*|todo|tbd|none|null|nil|undefined|empty|<.*>|\[.*\]|\{.*\})$/i.test(v) || /[^\x00-\x7f]/.test(v);

// Присваивания секретных переменных в строке. kind: code | yaml | other — от него зависит,
// считать ли значением слово без кавычек (в коде это имя переменной, в .env/YAML/shell — сам секрет).
function envAssignments(line, kind) {
  const out = [];
  ENV_RE.lastIndex = 0;
  for (let m; (m = ENV_RE.exec(line));) {
    const [, name, op] = m, rest = line.slice(ENV_RE.lastIndex), q = rest[0];
    let value;
    if (q === '"' || q === "'" || q === '`') {
      let i = 1;
      value = '';
      for (; i < rest.length && rest[i] !== q; i++) value += rest[i] === '\\' ? (rest[++i] ?? '') : rest[i];
      if (i >= rest.length || (q === '`' && value.includes('${'))) continue; // не закрыта или с подстановкой
    } else {
      const envLine = new RegExp(`^\\s*(?:export\\s+)?${name}=\\S`).test(line);
      if (kind === 'code' ? !envLine : kind === 'other' && op === ':') continue;
      value = (/^[^\s"'`,;)}\]]+/.exec(rest) || [''])[0];
      if (value.startsWith('#')) continue; // комментарий: значение пустое
    }
    if (value.trim() && !isReference(value) && !isPlaceholder(value)) out.push({ rule: ENV_RULE, secret: value, name });
  }
  return out;
}

function scanLine(line, kind, envRule) {
  if (ALLOW_RE.test(line)) return [];
  const out = [];
  for (const r of TOKEN_RULES) for (const m of line.matchAll(r.re)) if (r.id === 'private-key' || !looksFake(m[0])) out.push({ rule: r, secret: m[0] });
  if (/TWILIO_/i.test(line)) for (const m of line.matchAll(TWILIO.re)) if (!looksFake(m[0])) out.push({ rule: TWILIO, secret: m[0] });
  if (envRule) out.push(...envAssignments(line, kind));
  return out.filter((h, i) => out.findIndex(o => o.secret === h.secret) === i); // одно значение — одна находка
}

const fileKind = p => (CODE_EXT.test(p) ? 'code' : YAML_EXT.test(p) ? 'yaml' : 'other');
const envRuleFor = p => p.slice(p.lastIndexOf('/') + 1) !== '.env.example';
const isBinary = buf => buf.subarray(0, 8000).includes(0);

// ---------- Отчёт ----------
const findings = [];
// Из значения показываем не больше 4 первых знаков (у коротких — меньше), остальное скрыто.
const mask = s => s.slice(0, Math.min(4, Math.floor(s.length / 4))) + '***';
function report(where, hit) {
  const preview = hit.name ? `${hit.name}=${mask(hit.secret)}` : mask(hit.secret);
  findings.push(`  ${where}  ${hit.rule.title} [${hit.rule.id}]  ${preview}`);
}
const reportPath = (where, why) => findings.push(`  ${where}  запрещённый файл: ${why} [forbidden-path]`);

function scanText(file, buf, where = file) {
  if (isBinary(buf)) return;
  const kind = fileKind(file), envRule = envRuleFor(file), lines = buf.toString('utf8').split('\n');
  lines.forEach((line, i) => { for (const hit of scanLine(line.replace(/\r$/, ''), kind, envRule)) report(`${where}:${i + 1}`, hit); });
}

// ---------- git ----------
// Единый вид вывода git независимо от личных настроек: без цвета, внешних diff, подписей и т. п.
const GIT_CFG = ['-c', 'core.quotePath=false', '-c', 'color.ui=never', '-c', 'diff.noprefix=false', '-c', 'diff.mnemonicPrefix=false',
  '-c', 'diff.suppressBlankEmpty=false', '-c', 'log.showSignature=false'];
let ROOT = process.cwd();
function git(args) {
  const r = spawnSync('git', [...GIT_CFG, ...args], { cwd: ROOT, maxBuffer: 1 << 30 });
  if (r.error) throw new Error('не удалось запустить git: ' + r.error.message);
  if (r.status !== 0) throw new Error(`команда git ${args[0]} завершилась с ошибкой: ${String(r.stderr).trim().split('\n')[0]}`);
  return r.stdout;
}
const splitZ = buf => buf.toString('utf8').split('\0').filter(Boolean);
// Имя файла в выводе git в кавычках C ("a\tb", "\320\277…") → обычная строка.
function unquote(s) {
  if (!s.startsWith('"') || !s.endsWith('"') || s.length < 2) return s;
  const ch = Array.from(s.slice(1, -1)), bytes = [], esc = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13 };
  for (let i = 0; i < ch.length; i++) {
    if (ch[i] !== '\\') { bytes.push(...Buffer.from(ch[i], 'utf8')); continue; }
    const d = ch[++i] ?? '';
    if (/[0-7]/.test(d)) { bytes.push(parseInt(ch.slice(i, i + 3).join(''), 8)); i += 2; } else if (d in esc) bytes.push(esc[d]); else bytes.push(...Buffer.from(d, 'utf8'));
  }
  return Buffer.from(bytes).toString('utf8');
}

// --staged: то, что войдёт в коммит, читается из индекса (git show :0:<путь>), а не из рабочей копии.
function scanStaged() {
  const files = splitZ(git(['diff', '--cached', '--name-only', '--diff-filter=ACMRT', '-z']));
  const modes = new Map(splitZ(git(['ls-files', '-s', '-z'])).map(e => { const t = e.indexOf('\t'); return [e.slice(t + 1), e.slice(0, 6)]; }));
  for (const f of files) {
    const why = forbiddenPath(f);
    if (why) { reportPath(f, why); continue; }
    if (modes.get(f) === '160000') continue; // подмодуль
    scanText(f, git(['show', `:0:${f}`]));
  }
  return `${files.length} файл(ов), подготовленных к коммиту`;
}

// --all: все файлы под контролем git в рабочей копии.
function scanAll() {
  const files = [...new Set(splitZ(git(['ls-files', '-z'])))];
  for (const f of files) {
    const why = forbiddenPath(f);
    if (why) { reportPath(f, why); continue; }
    let st;
    try { st = fs.lstatSync(path.join(ROOT, f)); } catch { continue; } // удалён в рабочей копии
    if (st.isFile()) scanText(f, fs.readFileSync(path.join(ROOT, f)));
  }
  return `${files.length} файл(ов) под контролем git`;
}

// --history: 1) запрещённые файлы, когда-либо добавленные в любой коммит; 2) добавленные строки всех коммитов.
// Слияния проверяются в виде --cc: видно только то, чего не было ни в одном из родителей.
async function scanHistory() {
  let commit = '';
  const out = git(['log', '--all', '--cc', '--no-renames', '--diff-filter=d', '--name-only', '--format=%x00%H']).toString('utf8');
  const seen = new Set();
  for (const line of out.split('\n')) {
    if (line.startsWith('\0')) { commit = line.slice(1, 13); continue; }
    if (!line) continue;
    const f = unquote(line), why = forbiddenPath(f);
    if (why && !seen.has(commit + f)) { seen.add(commit + f); reportPath(`${commit} ${f}`, why); }
  }
  let commits = 0, file = null, kind = 'other', envRule = true, inHunk = false, ncol = 1, lineNo = 0;
  const onLine = line => {
    if (line.charCodeAt(0) === 0) { commit = line.slice(1, 13); commits++; file = null; inHunk = false; return; }
    if (line.startsWith('diff --git ') || line.startsWith('diff --cc ') || line.startsWith('diff --combined ')) { file = null; inHunk = false; return; }
    if (line.startsWith('@@')) {
      const m = /^(@{2,}) .*?\+(\d+)/.exec(line);
      inHunk = !!(m && file);
      if (inHunk) { ncol = m[1].length - 1; lineNo = +m[2]; }
      return;
    }
    if (!inHunk) {
      if (line.startsWith('+++ ')) {
        let p = line.slice(4).replace(/\t$/, ''); // git добавляет табуляцию, если в имени есть пробел
        p = p === '/dev/null' ? null : unquote(p).replace(/^b\//, '');
        file = p && !forbiddenPath(p) ? p : null; // запрещённые файлы уже в отчёте целиком
        if (file) { kind = fileKind(file); envRule = envRuleFor(file); }
      }
      return;
    }
    if (line.startsWith('\\')) return; // «\ No newline at end of file»
    const mark = line.slice(0, ncol);
    if (mark.includes('-')) return; // строки нет в новой версии файла
    if (mark.includes('+')) for (const hit of scanLine(line.slice(ncol).replace(/\r$/, ''), kind, envRule)) report(`${commit} ${file}:${lineNo}`, hit);
    lineNo++;
  };
  await new Promise((resolve, reject) => {
    const child = spawn('git', [...GIT_CFG, 'log', '-p', '--all', '--cc', '--format=%x00%H', '--no-color', '--no-ext-diff', '--no-textconv',
      '--src-prefix=a/', '--dst-prefix=b/'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let rest = Buffer.alloc(0), err = '';
    child.stdout.on('data', chunk => {
      let buf = rest.length ? Buffer.concat([rest, chunk]) : chunk, start = 0;
      for (let i; (i = buf.indexOf(10, start)) !== -1; start = i + 1) onLine(buf.toString('utf8', start, i));
      rest = buf.subarray(start);
    });
    child.stderr.on('data', d => { err += d; });
    child.on('error', e => reject(new Error('не удалось запустить git: ' + e.message)));
    child.on('close', code => {
      if (rest.length) onLine(rest.toString('utf8'));
      code === 0 ? resolve() : reject(new Error(`git log завершился с ошибкой: ${err.trim().split('\n')[0]}`));
    });
  });
  return `${commits} коммит(ов) во всех ветках`;
}

// ---------- Запуск ----------
const HELP = `Поиск секретов в git.
  node scripts/check-secrets.js --staged    подготовленное к коммиту (для pre-commit)
  node scripts/check-secrets.js --all       все файлы под контролем git (для CI)
  node scripts/check-secrets.js --history   вся история всех веток`;
const ADVICE = {
  '--staged': `Коммит остановлен. Уберите секрет из файла: ключи и пароли хранятся только в .env (он не попадает в git).
Убрать файл из коммита: git restore --staged <файл>. Если ключ уже был где-то опубликован — замените его на новый.`,
  '--all': `Уберите секреты из файлов и закоммитьте исправление. Запрещённый файл уберите из git: git rm --cached <файл>
(на диске он останется). Ключ, который уже попал в git, считайте раскрытым: замените его на новый.`,
  '--history': `Эти значения уже лежат в истории git и могли быть скопированы вместе с репозиторием. Главное — замените
каждый такой ключ или пароль на новый. Переписать историю (git filter-repo + принудительная отправка) — отдельное решение.`,
};

async function main() {
  const mode = process.argv[2];
  if (!['--staged', '--all', '--history'].includes(mode) || process.argv.length > 3) {
    console.log(HELP);
    return mode === '--help' || mode === '-h' ? 0 : 2;
  }
  ROOT = git(['rev-parse', '--show-toplevel']).toString('utf8').trim();
  const scope = mode === '--staged' ? scanStaged() : mode === '--all' ? scanAll() : await scanHistory();
  if (!findings.length) { console.log(`check-secrets: секретов не найдено (проверено: ${scope}).`); return 0; }
  console.log(`check-secrets: найдены возможные секреты — ${findings.length} (проверено: ${scope}).\n${findings.join('\n')}\n`);
  console.log(`${ADVICE[mode]}\nЕсли это ложное срабатывание, добавьте в ту же строку комментарий «check-secrets: allow».`);
  return 1;
}

main().then(code => { process.exitCode = code; }, e => { console.error('check-secrets: проверка не выполнена — ' + e.message); process.exitCode = 2; });
