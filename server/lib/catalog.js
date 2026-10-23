'use strict';
// Справочник для проверок на сервере: какие табаки, чаши и заведения существуют.
// Табаки и чаши совпадают с каталогом в app.js; заведения читаются из map-data.js.
const fs = require('node:fs');
const path = require('node:path');

const TOBACCOS = new Set(['ds-supernova', 'ds-bananapapa', 'ds-fallingstar', 'mh-pinkman', 'mh-raspberry', 'bb-cherry', 'el-grapefruit', 'tg-canemint',
  'af-twoapples', 'af-mint', 'ad-love66', 'fu-gummi', 'sb-bluemist', 'se-watermelon', 'du-pear', 'od-cola', 'ch-icemint']);
const BOWLS = new Set(['b-phunnel', 'b-turka', 'b-killer', 'b-harmony', 'b-fruit']);
const EMOJI = new Set('👍 ❤️ 😂 🔥 😮 😢 💨 🎉'.split(' '));

let VENUES = [];
try {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'map-data.js'), 'utf8');
  VENUES = JSON.parse(src.slice(src.indexOf('{'), src.lastIndexOf('}') + 1)).venues;
} catch (e) { /* без карты сервер работает, просто не проверяет заведения */ }
const venueById = id => VENUES.find(v => v.id === id);

module.exports = { TOBACCOS, BOWLS, EMOJI, VENUES, venueById };
