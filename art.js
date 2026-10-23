/* Иллюстрации вкусов для каталога Hookah Party.
   Каждая картинка — SVG, нарисованный кодом: фрукты, лёд, мята на фоне цвета вкуса.
   HP_ART.flavor(tobacco, { thumb }) возвращает строку <svg>. Набор предметов задаётся полем `art` у табака. */
(() => {
  'use strict';
  let seq = 0;

  // Смешивание цветов #rrggbb: mix('#ff0000', '#ffffff', .3) — на 30% ближе к белому.
  const full = c => c.length === 4 ? '#' + [...c.slice(1)].map(x => x + x).join('') : c; // #fff → #ffffff
  const hex = c => [1, 3, 5].map(i => parseInt(full(c).slice(i, i + 2), 16));
  const mix = (a, b, t) => '#' + hex(a).map((v, i) => Math.round(v + (hex(b)[i] - v) * t).toString(16).padStart(2, '0')).join('');

  // Общие кисти: градиенты (с уникальными id на каждую картинку), блики и звёздочки.
  function kit() {
    const k = 'fa' + (++seq), defs = [];
    const lin = (stops, x2 = 0, y2 = 1) => {
      const id = `${k}-${defs.length}`;
      defs.push(`<linearGradient id="${id}" x1="0" y1="0" x2="${x2}" y2="${y2}">${stops.map((c, i) => `<stop offset="${i / (stops.length - 1)}" stop-color="${c}"/>`).join('')}</linearGradient>`);
      return `url(#${id})`;
    };
    const rad = (c1, c2, fx = .35, fy = .3) => {
      const id = `${k}-${defs.length}`;
      defs.push(`<radialGradient id="${id}" cx=".5" cy=".5" r=".6" fx="${fx}" fy="${fy}"><stop offset="0" stop-color="${c1}"/><stop offset="1" stop-color="${c2}"/></radialGradient>`);
      return `url(#${id})`;
    };
    const shine = (x, y, rx, ry, rot = -30, o = .55) => `<ellipse cx="${x}" cy="${y}" rx="${rx}" ry="${ry}" transform="rotate(${rot} ${x} ${y})" fill="#fff" opacity="${o}"/>`;
    const sparkle = (x, y, s, o = .9) => `<path d="M${x} ${y - s}C${x + s * .15} ${y - s * .15} ${x + s * .15} ${y - s * .15} ${x + s} ${y}C${x + s * .15} ${y + s * .15} ${x + s * .15} ${y + s * .15} ${x} ${y + s}C${x - s * .15} ${y + s * .15} ${x - s * .15} ${y + s * .15} ${x - s} ${y}C${x - s * .15} ${y - s * .15} ${x - s * .15} ${y - s * .15} ${x} ${y - s}Z" fill="#fff" opacity="${o}"/>`;
    return { defs, lin, rad, shine, sparkle };
  }

  function flavor(t, { thumb = false } = {}) {
    const { defs, lin, rad, shine, sparkle } = kit();
    const leaf = (x, y, rot, s = 1, c1 = '#8be08f', c2 = '#2f8f4c') => `<g transform="translate(${x} ${y}) rotate(${rot}) scale(${s})">
      <path d="M0 0C10-8 26-10 34-4C26 4 10 6 0 0Z" fill="${lin([c1, c2], 1, 1)}"/><path d="M2 0L30-4" stroke="${c2}" stroke-width="1.2" opacity=".6" fill="none"/></g>`;

    // Предметы рисуются вокруг точки (0, 0) в квадрате примерно 100×100.
    const P = {
      citrus(rind = '#f5a13a', flesh = '#ef5d4f') {
        let s = `<circle r="46" fill="${rad(mix(rind, '#fff', .35), rind)}"/><circle r="41" fill="#fff4e6"/><circle r="37.5" fill="${rad(mix(flesh, '#fff', .35), flesh, .5, .5)}"/>`;
        for (let i = 0; i < 10; i++) s += `<path d="M0 0L0-37" transform="rotate(${i * 36})" stroke="#fff4e6" stroke-width="2.6" stroke-linecap="round"/>`;
        s += `<circle r="4.5" fill="#fff4e6"/>`;
        [[-14, -18], [12, -22], [20, 8], [-6, 22], [-22, 6], [6, -8]].forEach(([x, y]) => { s += `<ellipse cx="${x}" cy="${y}" rx="3.4" ry="1.6" transform="rotate(${Math.atan2(y, x) * 57.3} ${x} ${y})" fill="#fff" opacity=".45"/>`; });
        return s + `<path d="M-33-20A38 38 0 0 1-8-37" stroke="#fff" stroke-opacity=".7" stroke-width="3.5" fill="none" stroke-linecap="round"/>`;
      },
      raspberry() {
        let s = '', rows = [[3, 18], [4, 26], [5, 30], [4, 26], [3, 18], [2, 9]];
        rows.forEach(([n, w], r) => {
          for (let i = 0; i < n; i++) {
            const x = n === 1 ? 0 : -w + (2 * w * i) / (n - 1), y = -24 + r * 10.5;
            s += `<circle cx="${x}" cy="${y}" r="8" fill="${rad('#ff7b97', '#a8123c')}"/><circle cx="${x - 2.4}" cy="${y - 2.6}" r="2.2" fill="#fff" opacity=".6"/>`;
          }
        });
        return s + leaf(-4, -32, 200, .7) + leaf(4, -32, -20, .7) + leaf(0, -33, 260, .55);
      },
      cherry() {
        return `<path d="M-18 4C-12-22 -2-40 10-52M20 8C18-16 14-36 10-52" stroke="#6b7f2a" stroke-width="3.5" fill="none" stroke-linecap="round"/>
          ${leaf(10, -52, -25, 1.1)}
          <circle cx="-18" cy="22" r="21" fill="${rad('#ff6b7d', '#6e0a1f')}"/>${shine(-25, 13, 6, 3.5)}
          <circle cx="21" cy="26" r="21" fill="${rad('#ff6b7d', '#6e0a1f')}"/>${shine(14, 17, 6, 3.5)}`;
      },
      banana() {
        return `<path d="M-46-6Q-4 46 48-18" stroke="#b8860f" stroke-width="27" fill="none" stroke-linecap="round"/>
          <path d="M-46-11Q-4 39 48-23" stroke="${lin(['#fff09a', '#f7c623'])}" stroke-width="22" fill="none" stroke-linecap="round"/>
          <path d="M-32 0Q-2 28 34-12" stroke="#fff" stroke-opacity=".5" stroke-width="4" fill="none" stroke-linecap="round"/>
          <circle cx="-48" cy="-10" r="5" fill="#5a3d0e"/><path d="M48-23l9-12" stroke="#7a5a1a" stroke-width="7" stroke-linecap="round"/>`;
      },
      mango() {
        return `<g transform="rotate(-28)"><ellipse rx="34" ry="43" fill="${rad('#ffe36b', '#ee5a2b', .4, .25)}"/>${shine(-12, -20, 9, 5, -60)}</g>
          <path d="M14-38l4-10" stroke="#6b4a1a" stroke-width="4" stroke-linecap="round"/>${leaf(18, -46, -30, 1.3)}`;
      },
      passion() {
        let s = `<circle r="31" fill="${rad('#a868cf', '#3f1157')}"/><circle r="25" fill="#fff1b8"/><circle r="23.5" fill="${rad('#ffe680', '#f0a01c', .5, .5)}"/>`;
        [[-10, -10], [6, -14], [14, 2], [2, 12], [-12, 8], [-2, -2], [10, 14], [-16, -2], [16, -10]].forEach(([x, y]) => { s += `<circle cx="${x}" cy="${y}" r="4.6" fill="#ffd34f" opacity=".7"/><ellipse cx="${x}" cy="${y}" rx="2" ry="2.6" fill="#2a1408"/>`; });
        return s + shine(-20, -20, 5, 2.5, -45, .5);
      },
      mint(n = 3) {
        let s = '';
        const rots = n === 2 ? [-28, 26] : [-42, 0, 40];
        rots.forEach((r, i) => {
          s += `<g transform="translate(0 34) rotate(${r})"><path d="M0 0C18-14 24-46 0-66C-24-46-18-14 0 0Z" fill="${lin(['#9df0ae', '#2f9c5a'], .3, 1)}"/>
            <path d="M0-4V-58M0-18L12-28M0-30L13-40M0-42L10-50M0-18L-12-28M0-30L-13-40M0-42L-10-50" stroke="#1f7a42" stroke-width="1.6" opacity=".55" fill="none" stroke-linecap="round"/>
            ${i === 1 || n === 2 ? shine(-7, -40, 4, 10, 10, .3) : ''}</g>`;
        });
        return s;
      },
      apple(red = true) {
        const [c1, c2] = red ? ['#ff8f7a', '#c01f2c'] : ['#e2f58a', '#5fa52e'];
        return `<path d="M0-26C18-40 44-26 40 4C36 32 16 44 0 36C-16 44-36 32-40 4C-44-26-18-40 0-26Z" fill="${rad(c1, c2, .38, .3)}"/>
          <path d="M0-26C-2-34 0-42 4-48" stroke="#5a3d1a" stroke-width="3.5" fill="none" stroke-linecap="round"/>${leaf(3, -42, -35, .9)}
          ${shine(-20, -10, 7, 12, 20, .45)}`;
      },
      watermelon() {
        let s = `<g transform="rotate(-14)"><path d="M-50-14A50 50 0 0 0 50-14Z" fill="#2c8a3c"/><path d="M-50-14A50 50 0 0 0 50-14" stroke="#1d6a2c" stroke-width="2" stroke-dasharray="6 7" fill="none"/>
          <path d="M-45-14A45 45 0 0 0 45-14Z" fill="#dff5cf"/><path d="M-41-14A41 41 0 0 0 41-14Z" fill="${rad('#ff8a96', '#e2303f', .5, .05)}"/>`;
        [[-24, -2], [-8, 8], [10, 6], [26, -3], [-14, 18], [4, 20], [18, 14]].forEach(([x, y]) => { s += `<ellipse cx="${x}" cy="${y}" rx="2.4" ry="3.8" fill="#2a1a12" transform="rotate(${x / 2} ${x} ${y})"/>`; });
        return s + `<path d="M-36-12H36" stroke="#fff" stroke-opacity=".35" stroke-width="3" stroke-linecap="round"/></g>`;
      },
      gummy(c = '#ffffff', c2 = '#d9ccff') {
        const f = lin([c, c2], .4, 1);
        return `<g opacity=".95"><circle cx="-12" cy="-44" r="8" fill="${f}"/><circle cx="12" cy="-44" r="8" fill="${f}"/><circle cy="-30" r="17" fill="${f}"/>
          <ellipse cy="6" rx="23" ry="27" fill="${f}"/><ellipse cx="-24" cy="-4" rx="8" ry="12" transform="rotate(30 -24 -4)" fill="${f}"/><ellipse cx="24" cy="-4" rx="8" ry="12" transform="rotate(-30 24 -4)" fill="${f}"/>
          <circle cx="-13" cy="30" r="11" fill="${f}"/><circle cx="13" cy="30" r="11" fill="${f}"/></g>
          <circle cx="-6" cy="-32" r="2" fill="#8a6fb8" opacity=".5"/><circle cx="6" cy="-32" r="2" fill="#8a6fb8" opacity=".5"/>
          ${shine(-8, -38, 5, 3, -20, .8)}${shine(-10, -2, 4, 10, 10, .55)}`;
      },
      blueberry() {
        let s = '';
        [[-20, 8, 17], [16, 12, 16], [-2, -14, 17], [22, -18, 13]].forEach(([x, y, r]) => {
          s += `<circle cx="${x}" cy="${y}" r="${r}" fill="${rad('#8aa6ff', '#24307f')}"/><circle cx="${x}" cy="${y}" r="${r}" fill="#fff" opacity=".08"/>
            <path d="M${x} ${y - r * .55}l1.6 2.4 2.8.4-2 2 .5 2.8-2.9-1.4-2.9 1.4.5-2.8-2-2 2.8-.4z" fill="#141a4d"/>${shine(x - r * .45, y - r * .4, r * .22, r * .12, -40, .5)}`;
        });
        return s;
      },
      pear() {
        return `<path d="M0-46C10-46 14-30 16-18C34-4 40 22 26 38C14 50-14 50-26 38C-40 22-34-4-16-18C-14-30-10-46 0-46Z" fill="${rad('#f6f7a0', '#9db02a', .4, .3)}"/>
          <path d="M0-46C0-52 2-56 6-60" stroke="#5a3d1a" stroke-width="3.5" fill="none" stroke-linecap="round"/>${leaf(5, -56, -30, .9)}
          ${shine(-16, 4, 6, 14, 15, .45)}`;
      },
      cola() {
        let s = `<path d="M-31-46H31L25 46Q0 54-25 46Z" fill="#fff" opacity=".22"/>
          <path d="M-29-24H29L25 44Q0 51-25 44Z" fill="${lin(['#8a3b1a', '#2c0d05'])}"/>
          <path d="M-29-24Q-15-32 0-26Q15-32 29-24V-17H-29Z" fill="#f5dcb8"/>
          <path d="M8-26L22-66" stroke="#e8433a" stroke-width="6" stroke-linecap="round"/><path d="M11-34L14-43M17-50L20-59" stroke="#fff" stroke-width="6"/>`;
        [[-12, -6, 13, 12], [6, 4, 12, -8]].forEach(([x, y, w, r]) => { s += `<rect x="${x - w / 2}" y="${y - w / 2}" width="${w}" height="${w}" rx="3" transform="rotate(${r} ${x} ${y})" fill="#fff" opacity=".35"/>`; });
        [[-14, 20, 2.2], [-4, 30, 1.6], [10, 22, 2], [16, 34, 1.4], [0, 12, 1.4]].forEach(([x, y, r]) => { s += `<circle cx="${x}" cy="${y}" r="${r}" fill="#fff" opacity=".5"/>`; });
        return s + `<path d="M-24-40L-19 38" stroke="#fff" stroke-opacity=".45" stroke-width="4" stroke-linecap="round"/>`;
      },
      ice() {
        let s = '';
        [[-14, 6, 40, -12], [22, -14, 32, 16], [18, 26, 26, 30]].forEach(([x, y, w, r]) => {
          s += `<g transform="translate(${x} ${y}) rotate(${r})"><rect x="${-w / 2}" y="${-w / 2}" width="${w}" height="${w}" rx="${w * .22}" fill="${lin(['#f2fbff', '#9fd4f0'], 1, 1)}" opacity=".85"/>
            <rect x="${-w / 2}" y="${-w / 2}" width="${w}" height="${w}" rx="${w * .22}" fill="none" stroke="#fff" stroke-width="1.6" opacity=".9"/>
            <path d="M${-w * .3} ${-w * .3}h${w * .35}" stroke="#fff" stroke-width="3" stroke-linecap="round" opacity=".9"/><path d="M${-w * .3} ${-w * .3}v${w * .3}" stroke="#fff" stroke-width="3" stroke-linecap="round" opacity=".6"/></g>`;
        });
        return s + sparkle(-36, -30, 7) + sparkle(42, 10, 5) + sparkle(-30, 36, 4, .7);
      }
    };
    const draw = (name, x, y, s) => {
      const [fn, arg] = name.split(':');
      const out = fn === 'apple' ? P.apple(arg !== 'green') : fn === 'gummy' && arg ? P.gummy('#ffd1dc', '#ff7a9c') : fn === 'mint' && arg ? P.mint(+arg) : P[fn]();
      return `<ellipse cx="${x}" cy="${y + 50 * s}" rx="${44 * s}" ry="${7 * s}" fill="#000" opacity=".16"/><g transform="translate(${x} ${y}) scale(${s})">${out}</g>`;
    };

    const c = t.color || '#c47a4a', items = t.art || [];
    const spots = items.length > 1 ? [[198, 104, .92], [266, 66, .72]] : [[226, 88, 1.08]];
    let scene = '';
    // второй предмет рисуется позади первого
    for (let i = items.length - 1; i >= 0; i--) { const [x, y, s] = spots[Math.min(i, spots.length - 1)]; scene += draw(items[i], x, y, s); }
    const bg = lin([mix(c, '#fff', .28), c, mix(c, '#140a0c', .45)], 1, 1);
    const glow = rad('rgba(255,255,255,.42)', 'rgba(255,255,255,0)', .5, .5);
    const box = thumb ? 'viewBox="150 10 160 160" preserveAspectRatio="xMidYMid slice"' : 'viewBox="0 0 320 180" preserveAspectRatio="xMidYMid slice"';
    return `<svg class="${thumb ? 'thumb-art' : 'pack-art'}" ${box} aria-hidden="true">
      <defs>${''}</defs>
      <rect x="-10" y="-10" width="340" height="200" fill="${bg}"/>
      <circle cx="226" cy="84" r="118" fill="${glow}"/>
      <path d="M40 170C20 130 70 120 46 84S70 40 52 8M96 176C80 140 122 128 100 96" stroke="#fff" stroke-opacity=".13" stroke-width="7" fill="none" stroke-linecap="round"/>
      ${scene}
      ${sparkle(150, 30, 4, .55)}${sparkle(300, 150, 3, .5)}
    </svg>`.replace('<defs></defs>', `<defs>${defs.join('')}</defs>`);
  }

  // ---------- Чаши и аксессуары ----------
  // HP_ART.item(kind, color, { thumb }) — те же рамка и свет, что у табаков, но с предметом для кальяна.
  function item(kind, c = '#8a6a5a', { thumb = false } = {}) {
    const { defs, lin, rad, shine, sparkle } = kit();
    const metal = (a = '#e6e9ee', b = '#6f7680') => lin([a, mix(a, b, .5), b], 1, 0);
    const coal = (x, y, sc = 1, r = 0) => `<g transform="translate(${x} ${y}) rotate(${r}) scale(${sc})">
      <rect x="-9" y="-9" width="18" height="18" rx="3.5" fill="${lin(['#4d4446', '#1b1514'], 1, 1)}"/>
      <rect x="-9" y="-9" width="18" height="18" rx="3.5" fill="none" stroke="#ff8a3d" stroke-width="1.7" opacity=".9"/>
      <path d="M-5 5L5-5M-6-1L-1-6" stroke="#ffc07a" stroke-width="1.5" stroke-linecap="round" opacity=".95"/></g>`;
    const heat = (x, y, r) => `<circle cx="${x}" cy="${y}" r="${r}" fill="${rad('rgba(255,150,70,.8)', 'rgba(255,120,40,0)', .5, .5)}"/>`;
    const coalsOn = y => heat(2, y - 6, 46) + coal(-17, y, .9, -8) + coal(3, y - 3, .92, 7) + coal(22, y + 1, .85, -4);
    const stem = (y = 20) => `<rect x="-6" y="${y}" width="12" height="20" rx="3" fill="${metal()}"/><rect x="-10" y="${y + 16}" width="20" height="6" rx="2" fill="#575c64"/>`;

    // Чаша: тело с глазурью, табак сверху, угли и жар.
    const bowl = ({ top = 40, bottom = 25, depth = 32, holes = 0, spire = false, ribs = false, clay = false }) => {
      const y0 = -12, y1 = y0 + depth;
      let b = stem(y1 - 2);
      b += `<path d="M${-top} ${y0}L${top} ${y0}L${bottom} ${y1}Q0 ${y1 + 7} ${-bottom} ${y1}Z" fill="${lin([mix(c, '#fff', .3), c, mix(c, '#000', .45)], 1, 0)}"/>`;
      if (clay) b += `<path d="M${-top + 6} ${y0 + 8}Q0 ${y0 + 13} ${top - 6} ${y0 + 8}" stroke="${mix(c, '#000', .25)}" stroke-width="1.4" fill="none" opacity=".6"/>`;
      if (ribs) for (let i = -2; i <= 2; i++) b += `<path d="M${i * 14} ${y0 + 3}Q${i * 12} ${y0 + depth / 2} ${i * 9} ${y1 - 1}" stroke="${mix(c, '#fff', .35)}" stroke-width="2.4" fill="none" opacity=".55" stroke-linecap="round"/>`;
      for (let i = 0; i < holes; i++) b += `<circle cx="${(i - (holes - 1) / 2) * 11}" cy="${y0 + depth * .58}" r="2.4" fill="${mix(c, '#000', .6)}"/>`;
      b += shine(-top * .55, y0 + depth * .45, 4, depth * .3, 10, .35);
      b += `<ellipse cy="${y0}" rx="${top}" ry="8.5" fill="${mix(c, '#fff', .38)}"/><ellipse cy="${y0 + .5}" rx="${top - 5}" ry="6.2" fill="${lin(['#7a4428', '#2c160c'])}"/>`;
      if (spire) b += `<path d="M-5 ${y0 + 1}L0 ${y0 - 7}L5 ${y0 + 1}Z" fill="${mix(c, '#fff', .2)}"/>`;
      return b + coalsOn(y0 - 9);
    };
    const D = {
      phunnel: () => bowl({ spire: true }),
      harmony: () => bowl({ spire: true, clay: true, top: 38, bottom: 27 }),
      turka: () => bowl({ holes: 3, top: 42, bottom: 24, depth: 28 }),
      killer: () => bowl({ holes: 1, top: 34, bottom: 22, depth: 42 }),
      silicone: () => bowl({ spire: true, ribs: true, top: 39, bottom: 27 }),
      fruit: () => {
        let f = stem(26);
        f += `<path d="M-46-4A46 36 0 0 0 46-4Z" fill="${rad(mix('#f6b24a', '#fff', .2), '#e0702d', .4, .2)}"/>`;
        f += `<ellipse cy="-4" rx="46" ry="11" fill="#fff1dc"/><ellipse cy="-4" rx="42" ry="9" fill="${rad('#ff9a86', '#e2504a', .5, .5)}"/>`;
        for (let i = 0; i < 12; i++) f += `<path d="M0-4L${Math.cos(i * Math.PI / 6) * 41} ${-4 + Math.sin(i * Math.PI / 6) * 8.6}" stroke="#ffe3d6" stroke-width="1.4" opacity=".8"/>`;
        f += `<ellipse cy="-6" rx="17" ry="5" fill="${mix(c, '#000', .2)}"/><ellipse cy="-6" rx="13" ry="3.6" fill="#3a1d10"/>`;
        return f + shine(-28, 10, 5, 12, 30, .3) + heat(0, -16, 34) + coal(-8, -14, .8, -6) + coal(9, -16, .8, 8);
      },
      kaloud: () => {
        let s2 = heat(0, -6, 48);
        s2 += `<rect x="38" y="-2" width="14" height="6" rx="3" fill="${metal('#cfd3d9', '#5e646d')}"/>`;
        s2 += `<path d="M-38-8H38V14Q0 24-38 14Z" fill="${metal()}"/>`;
        for (let i = -3; i <= 3; i++) s2 += `<rect x="${i * 10 - 2}" y="-2" width="4" height="13" rx="2" fill="#ff8a3d"/><rect x="${i * 10 - 1}" y="0" width="2" height="9" rx="1" fill="#ffd08a"/>`;
        s2 += `<ellipse cy="-8" rx="38" ry="9" fill="${metal('#f4f6f9', '#9aa1aa')}"/><ellipse cy="-9" rx="20" ry="5" fill="${metal('#dfe3e8', '#7c838c')}"/>`;
        return s2 + `<rect x="-4" y="-22" width="8" height="12" rx="3" fill="${lin([mix(c, '#fff', .2), mix(c, '#000', .3)])}"/><ellipse cy="-22" rx="7" ry="3" fill="${mix(c, '#fff', .3)}"/>` + shine(-24, 4, 3, 8, 0, .5);
      },
      coal: () => heat(0, 4, 52) + coal(-22, 18, 1.15, -6) + coal(4, 20, 1.15, 4) + coal(28, 16, 1.1, -10) + coal(-10, -2, 1.1, 12) + coal(16, -4, 1.05, -4) + sparkle(-30, -24, 5) + sparkle(30, -22, 4, .7),
      hose: () => {
        const path = 'M-44 34C-44-6 6 24 6-6S36-36 38-26';
        return `<path d="${path}" stroke="${mix(c, '#000', .35)}" stroke-width="12" fill="none" stroke-linecap="round"/><path d="${path}" stroke="${c}" stroke-width="9" fill="none" stroke-linecap="round"/>
          <path d="${path}" stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round" opacity=".35" transform="translate(-2 -2)"/>
          <g transform="translate(38 -26) rotate(-55)"><rect x="-5" y="-4" width="34" height="9" rx="4" fill="${metal()}"/><rect x="22" y="-3" width="10" height="7" rx="3" fill="${metal('#f2f4f7', '#8b929b')}"/></g>
          <rect x="-50" y="30" width="12" height="16" rx="3" fill="${metal()}"/>`;
      },
      mouth: () => `<g transform="rotate(-22)"><path d="M-44 4L26-3H40Q44 3 40 9H26L-44 14Z" fill="${lin([mix(c, '#fff', .45), c, mix(c, '#000', .35)])}"/>
          <rect x="14" y="-5" width="6" height="16" rx="2" fill="${mix(c, '#000', .3)}"/><path d="M-40 6L24 1" stroke="#fff" stroke-width="2" opacity=".55" stroke-linecap="round"/></g>`,
      tongs: () => `<path d="M-46 34L28-12" stroke="${mix(c, '#000', .2)}" stroke-width="5" stroke-linecap="round"/><path d="M-46 38L32-4" stroke="${c}" stroke-width="5" stroke-linecap="round"/>
          <path d="M-46 34L28-12M-46 38L32-4" stroke="#fff" stroke-width="1.2" opacity=".45"/>${heat(36, -12, 26)}${coal(36, -12, .95, 18)}
          <rect x="-50" y="31" width="10" height="10" rx="3" fill="${mix(c, '#000', .35)}"/>`,
      stove: () => {
        let s2 = `<rect x="-44" y="-2" width="88" height="34" rx="8" fill="${lin([mix(c, '#fff', .15), mix(c, '#000', .35)])}"/><circle cx="32" cy="18" r="5" fill="#2a2a2e"/><circle cx="32" cy="18" r="2" fill="#ffb066"/>`;
        s2 += `<ellipse cy="-2" rx="40" ry="9" fill="#2b2b30"/>`;
        for (let r = 6; r <= 30; r += 6) s2 += `<ellipse cy="-2" rx="${r}" ry="${r * .22}" stroke="#ff7a2e" stroke-width="1.8" fill="none" opacity="${.5 + r / 60}"/>`;
        return s2 + heat(0, -10, 44) + coal(-14, -12, .9, -8) + coal(10, -14, .9, 8) + shine(-30, 14, 3, 8, 0, .3);
      },
      brush: () => {
        let s2 = `<g transform="rotate(-28)"><rect x="-46" y="-4" width="60" height="8" rx="4" fill="${lin([mix(c, '#fff', .3), mix(c, '#000', .3)])}"/><path d="M14 0H48" stroke="#9aa1aa" stroke-width="2"/>`;
        for (let x = 18; x <= 46; x += 2.6) s2 += `<path d="M${x} -9L${x} 9" stroke="#e8e4dc" stroke-width="1.3" opacity=".9"/>`;
        return s2 + '</g>';
      },
      flask: () => `<path d="M-8-40H8V-20C30-12 38 4 34 20 30 36 14 42 0 42S-30 36-34 20C-38 4-30-12-8-20Z" fill="#fff" opacity=".22"/>
          <path d="M-35 10C-30 28-14 40 0 40S30 28 35 10Z" fill="${lin([mix(c, '#fff', .35), c])}" opacity=".85"/>
          ${[[-14, 24, 3], [6, 30, 2.4], [16, 18, 2], [-4, 14, 1.8]].map(([x, y, r]) => `<circle cx="${x}" cy="${y}" r="${r}" fill="#fff" opacity=".7"/>`).join('')}
          <path d="M-8-40H8V-20C30-12 38 4 34 20 30 36 14 42 0 42S-30 36-34 20C-38 4-30-12-8-20Z" fill="none" stroke="#fff" stroke-width="2" opacity=".8"/>
          <rect x="-11" y="-46" width="22" height="7" rx="2" fill="${metal()}"/>${shine(-22, 2, 4, 14, 15, .55)}`
    };
    const draw = D[kind] || D.turka;
    const [x, y, sc] = [226, 90, 1.12];
    const bg = lin([mix(c, '#fff', .28), c, mix(c, '#140a0c', .45)], 1, 1);
    const glow = rad('rgba(255,255,255,.4)', 'rgba(255,255,255,0)', .5, .5);
    const box = thumb ? 'viewBox="150 10 160 160" preserveAspectRatio="xMidYMid slice"' : 'viewBox="0 0 320 180" preserveAspectRatio="xMidYMid slice"';
    const scene = `<ellipse cx="${x}" cy="${y + 50 * sc}" rx="${46 * sc}" ry="${7 * sc}" fill="#000" opacity=".2"/><g transform="translate(${x} ${y}) scale(${sc})">${draw()}</g>`;
    return `<svg class="${thumb ? 'thumb-art' : 'pack-art'}" ${box} aria-hidden="true">
      <rect x="-10" y="-10" width="340" height="200" fill="${bg}"/>
      <circle cx="226" cy="84" r="118" fill="${glow}"/>
      <path d="M40 170C20 130 70 120 46 84S70 40 52 8M96 176C80 140 122 128 100 96" stroke="#fff" stroke-opacity=".13" stroke-width="7" fill="none" stroke-linecap="round"/>
      ${scene}${sparkle(150, 30, 4, .55)}${sparkle(300, 150, 3, .5)}
    </svg>`.replace('<svg ', `<svg `).replace(/^/, '').replace('aria-hidden="true">', `aria-hidden="true"><defs>${defs.join('')}</defs>`);
  }

  window.HP_ART = { flavor, item };
})();
