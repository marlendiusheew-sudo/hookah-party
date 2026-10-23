'use strict';
// Демо-данные для пустой базы: те же люди, сборы, отзывы, миксы и истории, что в демо-режиме сайта.
// Пароль у всех тестовых пользователей — hookah. Отключается переменной SEED=0.
const { encrypt, phoneIndex, hashPassword } = require('./secure');
const { venueById } = require('./catalog');

async function seed(db) {
  if (db.q('SELECT COUNT(*) AS n FROM users').get().n > 0) return false;
  const day = 864e5, iso = t => new Date(t).toISOString();
  const at = (d, h, m = 0) => { const x = new Date(Date.now() + d * day); x.setHours(h, m, 0, 0); return iso(x); };
  const ago = mins => iso(Date.now() - mins * 60000);
  const V = id => venueById(id) || { name: 'Hookah', addr: '' };
  const pass = await hashPassword('hookah');

  const users = [
    ['u1', 'Алекс', '996700000001', 'n4270648990', ['ds-supernova', 'mh-pinkman'], ['u2', 'u3', 'u5']],
    ['u2', 'Дина', '996700000002', 'n12870025414', ['ad-love66'], ['u1', 'u3', 'u6']],
    ['u3', 'Тимур', '996700000003', 'n6360868686', ['tg-canemint', 'af-twoapples'], ['u1', 'u2', 'u4']],
    ['u4', 'Сабина', '996700000004', null, ['fu-gummi'], ['u3']],
    ['u5', 'Руслан', '996700000005', 'n4270648990', ['od-cola'], ['u1']],
    ['u6', 'Карина', '996700000006', null, ['sb-bluemist'], ['u2']]
  ];
  const ev = (id, title, vid, when, host, desc, hookahs, price, created, guests, picks, bowls, paid) => ({ id, title, vid, when, host, desc, hookahs, price, created, guests, picks, bowls, paid });
  const events = [
    ev('e1', 'Пятничный сбор', 'n4270648990', at(2, 20, 30), 'u1', 'Забронирован диван у окна на 6 человек. Берём два кальяна, второй — на фанеле.', 2, 1200, ago(60 * 26),
      [['u2', 'going', ago(600)], ['u3', 'going', ago(420)], ['u4', 'pending'], ['u5', 'going', ago(95)], ['phone:996555123456', 'pending']],
      { u1: ['ds-supernova', 'mh-pinkman'], u2: ['ds-supernova', 'ad-love66'], u3: ['ds-supernova', 'mh-pinkman', 'tg-canemint'], u5: ['ds-bananapapa'] },
      { u1: 'b-phunnel', u2: 'b-phunnel', u3: 'b-killer' }, ['u1', 'u2']),
    ev('e2', 'День рождения Тимура', 'n6360868686', at(6, 19), 'u3', 'Отмечаем 25 лет. Подарок собираем вскладчину, детали у Сабины.', 3, 1500, ago(60 * 20),
      [['u1', 'pending'], ['u4', 'going', ago(500)], ['u6', 'going', ago(210)]],
      { u3: ['af-twoapples', 'sb-bluemist'], u4: ['af-twoapples'], u6: ['fu-gummi', 'sb-bluemist', 'af-twoapples'] }, { u3: 'b-turka' }, ['u3']),
    ev('e3', 'После работы', 'n12870025414', at(-9, 21), 'u2', '', 1, 900, ago(60 * 24 * 11),
      [['u1', 'going'], ['u6', 'going']], { u1: ['bb-cherry'], u2: ['bb-cherry', 'el-grapefruit'], u6: ['el-grapefruit'] }, { u2: 'b-fruit' }, ['u1', 'u2', 'u6']),
    ev('e4', 'Проводы лета', 'n4270648990', at(-55, 20), 'u3', '', 2, 1200, at(-60, 12),
      [['u1', 'going'], ['u2', 'going'], ['u5', 'going'], ['u6', 'going']],
      { u3: ['mh-pinkman', 'el-grapefruit'], u1: ['mh-pinkman', 'ds-supernova'], u2: ['mh-pinkman'], u5: ['ds-supernova'], u6: ['el-grapefruit'] }, { u3: 'b-phunnel', u1: 'b-phunnel' }, ['u3', 'u1', 'u2', 'u5', 'u6']),
    ev('e5', 'Футбол и кальян', 'n4724156811', at(-30, 19), 'u5', '', 1, 1400, at(-33, 12),
      [['u1', 'going'], ['u3', 'going']], { u5: ['od-cola', 'tg-canemint'], u1: ['od-cola'], u3: ['tg-canemint'] }, { u5: 'b-killer' }, ['u5', 'u1', 'u3']),
    ev('e6', 'Девичник Сабины', 'n6360868686', at(-20, 19), 'u4', '', 2, 1500, at(-25, 12),
      [['u2', 'going'], ['u6', 'going']], { u4: ['fu-gummi', 'ad-love66'], u2: ['ad-love66', 'sb-bluemist'], u6: ['sb-bluemist', 'fu-gummi'] }, { u4: 'b-fruit', u2: 'b-fruit' }, ['u4', 'u2', 'u6'])
  ];
  const comments = [
    ['c1', 'e1', 'u3', 'ev', 'Бронь на 20:30 подтвердили?', ago(180), { u1: '👍' }],
    ['c2', 'e1', 'u1', 'ev', 'Да, диван у окна наш до двух ночи. 🔥', ago(150), { u2: '🔥', u3: '👍', u5: '👍' }],
    ['c3', 'e1', 'u2', 'ev', 'Возьму свой мундштук и калауд 💨', ago(40), { u3: '❤️', u5: '😂' }],
    ['c4', 'e2', 'u4', 'ev', 'Торт беру на себя.', ago(300), {}],
    ['sc1', 'e3', 'u6', 'story', 'Тот самый грейпфрут спас вечер 😄', ago(60 * 24 * 8 - 30), {}],
    ['sc2', 'e4', 'u1', 'story', 'Лучший вечер этого лета, без вариантов.', at(-54, 13), { u2: '❤️', u3: '🔥', u6: '❤️' }],
    ['sc3', 'e4', 'u5', 'story', 'Повторим в сентябре, пока не похолодало?', at(-53, 18), {}],
    ['sc5', 'e5', 'u3', 'story', 'Cane Mint крепкий, с колой как раз смягчается.', at(-29, 15), {}],
    ['sc6', 'e6', 'u2', 'story', 'Мишки на грейпфруте — это любовь 🍊🐻', at(-19, 14), { u4: '❤️', u6: '😂' }]
  ];
  const stories = [
    ['e3', 4, 'Заскочили после работы на пару часов. Кислая вишня в чистом виде оказалась слишком резкой, кальянщик подмешал грейпфрут, и стало то что нужно.', ['Вишня + грейпфрут 50/50: забираем в миксы', 'Кальянщик Эрлан, просите его'], ago(60 * 24 * 8), ['u1', 'u6']],
    ['e4', 5, 'Последний тёплый вечер на веранде. Взяли два кальяна на фанеле и просидели до двух ночи. «Ледяной грейпфрут» по нашему миксу зашёл всем, второй забили так же.', ['Pinkman + грейпфрут + капля Supernova — лучший микс лета', 'Веранда с видом на проспект, бронируйте заранее', 'Вышло по 480 сом с человека'], at(-54, 12), ['u1', 'u2', 'u5', 'u6', 'u4']],
    ['e5', 4, 'Смотрели матч на большом экране. Попросили собрать «Мятную колу» 70/30, кальянщик сделал на киллере, держал почти два часа. Наши выиграли 2:1.', ['Cola 70% + Cane Mint 30%', 'Экран видно с любого дивана', 'Шумно во время матча, на разговоры лучше в другой день'], at(-29, 11), ['u1', 'u3']],
    ['e6', 5, 'Отмечали втроём. Первый кальян на грейпфруте с мармеладными мишками, второй — Blue Mist. Музыка не громкая, можно спокойно поговорить.', ['Чаша на грейпфруте — must have для праздника', 'Gummi Bear + Love 66 — сладко, но не приторно', 'Попросите столик у окна'], at(-19, 13), ['u2', 'u6', 'u3', 'u1']]
  ];
  const reviews = [
    ['r1', 'ds-supernova', 'u3', 5, 'Лучший холодок, добавляю в каждый микс по чуть-чуть.', 3], ['r2', 'ds-supernova', 'u2', 4, 'Сильно холодит, больше 20% не кладу.', 8],
    ['r3', 'mh-pinkman', 'u1', 5, 'Яркий и не приторный, держит вкус весь сеанс.', 5], ['r4', 'af-twoapples', 'u3', 4, 'Классика. Лёгкий, подходит новичкам.', 12],
    ['r5', 'tg-canemint', 'u5', 5, 'Крепкий, на любителя. Мята честная.', 2], ['r6', 'od-cola', 'u5', 4, 'Похоже на колу, хорошо с мятой.', 6],
    ['r7', 'fu-gummi', 'u4', 5, 'Сладкий, как мармелад.', 9], ['r8', 'bb-cherry', 'u2', 3, 'Слишком кислый в чистом виде.', 10]
  ];
  const mixes = [
    ['m1', 'Ледяной грейпфрут', 'u3', [['mh-pinkman', 50], ['el-grapefruit', 30], ['ds-supernova', 20]], ['u1', 'u2', 'u5'], 4],
    ['m2', 'Тропики', 'u2', [['ds-fallingstar', 60], ['ds-bananapapa', 40]], ['u4'], 7],
    ['m3', 'Мятная кола', 'u5', [['od-cola', 70], ['tg-canemint', 30]], ['u1', 'u3', 'u6', 'u2'], 2],
    ['m4', 'Ягодный лёд', 'u6', [['sb-bluemist', 50], ['mh-raspberry', 35], ['ch-icemint', 15]], ['u2'], 1]
  ];

  db.tx(() => {
    for (const [id, name, phone, fv, favs] of users) {
      db.q('INSERT INTO users (id, name, phone_enc, phone_idx, phone_tail, pass, fav_venue, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(id, name, encrypt(phone), phoneIndex(phone), phone.slice(-3), pass, fv ? V(fv).name : '', ago(60 * 24 * 40));
      for (const t of favs) db.q('INSERT INTO favs VALUES (?, ?)').run(id, t);
    }
    for (const [id, , , , , friends] of users) for (const f of friends) db.q('INSERT OR IGNORE INTO friends VALUES (?, ?)').run(id, f);
    for (const e of events) {
      const v = V(e.vid);
      db.q('INSERT INTO events (id, title, venue, venue_id, address, at, host_id, descr, hookahs, price, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(e.id, e.title, v.name, e.vid, v.addr || '', e.when, e.host, e.desc, e.hookahs, e.price, e.created);
      for (const [who, status, when] of e.guests) {
        if (who.startsWith('phone:')) { const p = who.slice(6); db.q('INSERT INTO invites (event_id, phone_idx, phone_enc, phone_tail, status) VALUES (?, ?, ?, ?, ?)').run(e.id, phoneIndex(p), encrypt(p), p.slice(-3), status); }
        else db.q('INSERT INTO invites (event_id, user_id, status, at) VALUES (?, ?, ?, ?)').run(e.id, who, status, when || null);
      }
      for (const [u, ids] of Object.entries(e.picks)) for (const t of ids) db.q('INSERT INTO picks VALUES (?, ?, ?)').run(e.id, u, t);
      for (const [u, b] of Object.entries(e.bowls)) db.q('INSERT INTO bowls VALUES (?, ?, ?)').run(e.id, u, b);
      for (const u of e.paid) db.q('INSERT INTO paid VALUES (?, ?)').run(e.id, u);
    }
    for (const [id, eid, u, kind, text, when, reacts] of comments) {
      db.q('INSERT INTO comments VALUES (?, ?, ?, ?, ?, ?)').run(id, eid, u, kind, text, when);
      for (const [ru, em] of Object.entries(reacts)) db.q('INSERT INTO reactions VALUES (?, ?, ?, ?)').run(id, ru, em, when);
    }
    for (const [eid, rating, text, hl, when, fire] of stories) {
      db.q('INSERT INTO stories VALUES (?, ?, ?, ?, ?)').run(eid, rating, text, JSON.stringify(hl), when);
      for (const u of fire) db.q('INSERT INTO story_fire VALUES (?, ?)').run(eid, u);
    }
    for (const [id, t, u, rating, text, d] of reviews) db.q('INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)').run(id, t, u, rating, text, ago(60 * 24 * d));
    for (const [id, name, a, parts, likes, d] of mixes) {
      db.q('INSERT INTO mixes VALUES (?, ?, ?, ?, ?)').run(id, name, a, JSON.stringify(parts.map(([pid, pct]) => ({ id: pid, pct }))), ago(60 * 24 * d));
      for (const u of likes) db.q('INSERT INTO mix_likes VALUES (?, ?)').run(id, u);
    }
    // Несколько уведомлений, чтобы раздел не был пустым.
    const n = (id, user, type, actor, eid, ref, when) => db.q('INSERT INTO notifications (id, user_id, type, actor_id, event_id, ref, at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, user, type, actor, eid, ref, when);
    n('n1', 'u1', 'invite', 'u3', 'e2', null, ago(60 * 20));
    n('n2', 'u1', 'rsvp_going', 'u2', 'e1', null, ago(600));
    n('n3', 'u1', 'rsvp_going', 'u3', 'e1', null, ago(420));
    n('n4', 'u1', 'comment', 'u3', 'e1', 'c1', ago(180));
    n('n5', 'u1', 'reaction', 'u2', 'e1', 'c2:🔥', ago(140));
    n('n6', 'u1', 'rsvp_going', 'u5', 'e1', null, ago(95));
    n('n7', 'u1', 'comment', 'u2', 'e1', 'c3', ago(40));
  });
  return true;
}

module.exports = { seed };
