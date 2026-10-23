'use strict';
// Отправка SMS. Провайдер выбирается переменной SMS_PROVIDER.
// dev — код не отправляется, а пишется в журнал сервера и возвращается в ответе (только не в production).
const { log } = require('./guard');

const providers = {
  async dev(phone, text) { log('info', 'SMS (dev)', { to: phone.slice(0, 4) + '…' + phone.slice(-3), text }); },
  // Nikita (smspro.nikita.kg) — кыргызский шлюз. Формат запроса по их документации XML API.
  async nikita(phone, text) {
    const { NIKITA_LOGIN: login, NIKITA_PASSWORD: pass, NIKITA_SENDER: sender } = process.env;
    if (!login || !pass || !sender) throw new Error('Не заданы NIKITA_LOGIN / NIKITA_PASSWORD / NIKITA_SENDER');
    const esc = s => String(s).replace(/[<>&'"]/g, c => `&#${c.charCodeAt(0)};`);
    const xml = `<?xml version="1.0" encoding="UTF-8"?><message><login>${esc(login)}</login><pwd>${esc(pass)}</pwd><id>${Date.now()}</id><sender>${esc(sender)}</sender><text>${esc(text)}</text><phones><phone>${esc(phone)}</phone></phones></message>`;
    const r = await fetch('https://smspro.nikita.kg/api/message', { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: xml, signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error('Nikita ответил ' + r.status);
  },
  async twilio(phone, text) {
    const { TWILIO_SID: sid, TWILIO_TOKEN: tok, TWILIO_FROM: from } = process.env;
    if (!sid || !tok || !from) throw new Error('Не заданы TWILIO_SID / TWILIO_TOKEN / TWILIO_FROM');
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
      method: 'POST', signal: AbortSignal.timeout(8000),
      headers: { Authorization: 'Basic ' + Buffer.from(`${sid}:${tok}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ To: '+' + phone, From: from, Body: text })
    });
    if (!r.ok) throw new Error('Twilio ответил ' + r.status);
  }
};

const name = () => process.env.SMS_PROVIDER || 'dev';
async function sendSms(phone, text) {
  const p = providers[name()];
  if (!p) throw new Error('Неизвестный SMS_PROVIDER: ' + name());
  await p(phone, text);
}
// Показывать код в ответе можно только с dev-провайдером и не в production.
const exposeCode = () => name() === 'dev' && process.env.NODE_ENV !== 'production';

module.exports = { sendSms, exposeCode, providerName: name };
