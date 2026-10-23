'use strict';
// Устройство по заголовку User-Agent: семейство браузера, система и тип (телефон, планшет, компьютер) — без версий,
// чтобы обновление браузера или системы не считалось «новым устройством». Нужно для уведомления «Вход с нового устройства».
// Подделать User-Agent легко, поэтому это сигнал, а не защита: защищают пароль, код из SMS и лимиты.
const crypto = require('node:crypto');

// Порядок важен: встроенные браузеры и браузеры на Chromium называют себя ещё и «Chrome», «Safari».
const BROWSERS = [
  [/HookahPartyApp/, 'Hookah Party app'], [/Instagram/, 'Instagram'], [/FBAN|FBAV|FB_IAB/, 'Facebook'],
  [/YaBrowser|YaSearchBrowser/, 'Yandex Browser'], [/SamsungBrowser/, 'Samsung Internet'], [/OPR\/|OPT\/|OPiOS|Opera/, 'Opera'],
  [/Edg(?:e|A|iOS)?\//, 'Edge'], [/Firefox\/|FxiOS/, 'Firefox'], [/CriOS|Chrome\/|Chromium\//, 'Chrome'], [/Safari\//, 'Safari']
];
// [признак, система, тип устройства]; Android без слова Mobile — планшет.
const SYSTEMS = [
  [/iPhone|iPod/, 'iPhone', 'mobile'], [/iPad/, 'iPad', 'tablet'], [/Android.*Mobile/, 'Android', 'mobile'], [/Android/, 'Android tablet', 'tablet'],
  [/Windows/, 'Windows', 'desktop'], [/CrOS/, 'ChromeOS', 'desktop'], [/Macintosh|Mac OS X/, 'macOS', 'desktop'], [/Linux|X11/, 'Linux', 'desktop']
];

// { browser, os, device, label, fp }: label — для людей («Chrome · macOS»), fp — отпечаток для таблицы known_devices.
function parseUA(header) {
  const ua = String(header ?? '').slice(0, 512);
  const browser = (BROWSERS.find(([re]) => re.test(ua)) || [])[1] || '';
  const [, os = '', device = 'other'] = SYSTEMS.find(([re]) => re.test(ua)) || [];
  const label = browser || os ? [browser || 'Browser', os].filter(Boolean).join(' · ') : 'Unknown device';
  const fp = crypto.createHash('sha256').update(`ua:${browser || '?'}|${os || '?'}|${device}`).digest('hex');
  return { browser, os, device, label, fp };
}

module.exports = { parseUA };
