/* Панель администратора Hookah Party.
   На сервере этот файл отдаётся только вошедшему администратору, а каждое действие сервер проверяет сам:
   роль администратора + свежее подтверждение паролем (15 минут) + запись в журнал.
   В демо-режиме (GitHub Pages) панель работает с данными в браузере. */
(() => {
  'use strict';
  let unlockedUntil = 0, query = '', timer = null;

  function render(c) {
    const { L, esc, view } = c;
    clearInterval(timer);
    const until = c.SERVER ? (c.getDb().adminUntil || 0) : unlockedUntil;
    if (until < Date.now()) return renderUnlock(c);

    view.innerHTML = `<section class="greet-line"><div><span class="eyebrow">${L('Администратор', 'Administrator')}</span><h1>${L('Панель управления', 'Control panel')}</h1></div>
      <div class="btn-row"><span class="adm-timer">${c.ICON.shield}<span>${L('Доступ открыт ещё', 'Access open for')} <b class="mono" id="adm-left"></b></span></span>
      <button class="btn btn-sm" type="button" id="adm-lock">${L('Закрыть доступ', 'Lock')}</button></div></section>
      <div id="adm-body"><p class="muted">${L('Загружаем данные…', 'Loading data…')}</p></div>`;
    const tick = () => {
      const left = until - Date.now(), el = document.getElementById('adm-left');
      if (!el) return clearInterval(timer);
      if (left <= 0) { clearInterval(timer); return render(c); }
      el.textContent = `${Math.floor(left / 60000)}:${String(Math.floor(left % 60000 / 1000)).padStart(2, '0')}`;
    };
    tick(); timer = setInterval(tick, 1000);
    document.getElementById('adm-lock').onclick = async () => {
      if (c.SERVER) await c.api('POST', '/admin/lock', {}).catch(() => {});
      unlockedUntil = 0; const d = c.getDb(); d.adminUntil = 0; render(c);
    };
    load(c).then(data => draw(c, data)).catch(e => {
      if (e?.info?.error === 'step_up') { unlockedUntil = 0; c.getDb().adminUntil = 0; return render(c); }
      document.getElementById('adm-body').innerHTML = c.emptyState(L('Не удалось загрузить данные', 'Could not load data'), esc(c.apiMsg(e)));
    });
  }

  // Подтверждение паролем перед доступом.
  function renderUnlock(c) {
    const { L, view } = c;
    view.innerHTML = `<section class="auth"><div class="panel auth-card">
      <div><span class="eyebrow">${L('Администратор', 'Administrator')}</span><h1 style="margin-top:8px">${L('Подтвердите пароль', 'Confirm your password')}</h1>
        <p class="muted" style="margin-top:8px">${L('Панель управления открывается на 15 минут. Все действия записываются в журнал.', 'The control panel opens for 15 minutes. Every action is logged.')}</p></div>
      <form class="form" id="adm-form" novalidate>
        <div class="field"><label for="adm-pass">${L('Пароль от аккаунта', 'Account password')}</label><input id="adm-pass" type="password" autocomplete="current-password" maxlength="128"></div>
        <div class="error" id="adm-err" role="alert"></div>
        <button class="btn btn-primary" type="submit" id="adm-go">${c.ICON.shield}${L('Открыть панель', 'Open panel')}</button>
      </form></div></section>`;
    const err = document.getElementById('adm-err'), go = document.getElementById('adm-go');
    document.getElementById('adm-pass').focus();
    document.getElementById('adm-form').addEventListener('submit', async ev => {
      ev.preventDefault(); err.textContent = ''; go.disabled = true;
      const pass = document.getElementById('adm-pass').value;
      try {
        if (c.SERVER) { const r = await c.api('POST', '/admin/unlock', { password: pass }); c.getDb().adminUntil = r.adminUntil; }
        else {
          if (!(await c.checkPass(c.me(), pass))) { c.secLog('admin_unlock_fail'); throw new Error(L('Неверный пароль.', 'Wrong password.')); }
          unlockedUntil = Date.now() + 15 * 60e3; c.secLog('admin_unlock');
        }
        render(c);
      } catch (e) { err.textContent = e.info ? c.apiMsg(e) : e.message; go.disabled = false; }
    });
  }

  // Данные: с сервера или из браузера (демо).
  async function load(c) {
    if (c.SERVER) return c.api('GET', '/admin/overview');
    const d = c.getDb(), name = id => c.userById(id)?.name || '—', comments = [];
    for (const e of d.events) {
      for (const m of e.comments || []) comments.push({ id: m.id, kind: 'ev', text: m.text, at: m.at, userId: m.userId, author: name(m.userId), eventId: e.id, eventTitle: e.title });
      for (const m of e.story?.comments || []) comments.push({ id: m.id, kind: 'story', text: m.text, at: m.at, userId: m.userId, author: name(m.userId), eventId: e.id, eventTitle: e.title });
    }
    comments.sort((a, b) => new Date(b.at) - new Date(a.at));
    const events = [...d.events].sort((a, b) => new Date(b.at) - new Date(a.at)).map(e => ({ id: e.id, title: e.title, venue: e.venue, at: e.at, hostId: e.hostId, host: name(e.hostId), guests: e.invites.length, msgs: (e.comments || []).length + (e.story?.comments || []).length, past: c.isPast(e) }));
    const audit = c.secRead('hp.sec.log', []).slice(0, 100).map(x => ({ at: x.at, type: x.type, detail: x.detail, name: c.me()?.name }));
    return { comments, events, audit, stats: { users: d.users.length, events: d.events.length, comments: comments.length } };
  }

  function draw(c, data) {
    const { L, esc } = c, body = document.getElementById('adm-body'); if (!body) return;
    const dt = t => `${c.fShort(new Date(t))}, ${c.fTime(new Date(t))}`, q = query.trim().toLowerCase();
    const comments = data.comments.filter(x => !q || `${x.text} ${x.author} ${x.eventTitle}`.toLowerCase().includes(q));
    const events = data.events.filter(x => !q || `${x.title} ${x.venue} ${x.host}`.toLowerCase().includes(q));
    const audit = data.audit.filter(x => !q || `${x.type} ${x.detail} ${x.name}`.toLowerCase().includes(q));
    const tabKey = c.tab.admin || 'comments';
    let list = '';
    if (tabKey === 'comments') list = comments.length ? `<ul class="adm-list">${comments.map(x => `<li class="adm-row">
        <div class="adm-main"><div class="adm-meta"><b>${esc(x.author)}</b><span class="pill ${x.kind === 'story' ? 'pill-host' : 'pill-going'}">${x.kind === 'story' ? L('История', 'History') : L('Обсуждение', 'Discussion')}</span>
          <a href="#/event/${esc(x.eventId)}">${esc(x.eventTitle)}</a><time class="mono">${dt(x.at)}</time></div>
          <p>${esc(x.text)}</p></div>
        <button class="btn btn-danger btn-sm" type="button" data-adm="comment" data-id="${esc(x.id)}" data-label="${esc(x.text.slice(0, 60))}">${L('Удалить', 'Delete')}</button></li>`).join('')}</ul>`
      : `<p class="muted">${L('Ничего не нашлось.', 'Nothing found.')}</p>`;
    else if (tabKey === 'events') list = events.length ? `<ul class="adm-list">${events.map(x => `<li class="adm-row">
        <div class="adm-main"><div class="adm-meta"><b>${esc(x.title)}</b><span class="pill ${x.past ? 'pill-pending' : 'pill-going'}">${x.past ? L('Прошёл', 'Past') : L('Активный', 'Active')}</span><time class="mono">${dt(x.at)}</time></div>
          <p class="muted">${esc(x.venue)} · ${L('организатор', 'host')} ${esc(x.host)} · ${x.guests} ${c.pl(x.guests, ['гость', 'гостя', 'гостей'], ['guest', 'guests'])} · ${x.msgs} ${c.pl(x.msgs, ['сообщение', 'сообщения', 'сообщений'], ['message', 'messages'])}</p></div>
        <div class="btn-row"><a class="btn btn-sm" href="#/event/${esc(x.id)}">${L('Открыть', 'Open')}</a>
          <button class="btn btn-danger btn-sm" type="button" data-adm="event" data-id="${esc(x.id)}" data-label="${esc(x.title)}">${L('Удалить', 'Delete')}</button></div></li>`).join('')}</ul>`
      : `<p class="muted">${L('Ничего не нашлось.', 'Nothing found.')}</p>`;
    else list = audit.length ? `<ul class="sec-log">${audit.map(x => { const ev = c.SEC_EVENTS[x.type] || [x.type, x.type, '']; return `<li class="${ev[2]}"><i></i><span><b>${L(ev[0], ev[1])}</b><small>${esc([x.name, x.detail, x.ip].filter(Boolean).join(' · '))}</small></span><time class="mono">${dt(x.at)}</time></li>`; }).join('')}</ul>`
      : `<p class="muted">${L('Событий нет.', 'No events.')}</p>`;

    body.innerHTML = `
      <div class="adm-stats"><span>${L('Пользователей', 'Users')} <b>${data.stats.users}</b></span><span>${L('Сборов', 'Events')} <b>${data.stats.events}</b></span><span>${L('Сообщений', 'Messages')} <b>${data.stats.comments}</b></span></div>
      ${c.uTabs('admin', [{ key: 'comments', label: L('Комментарии', 'Comments'), count: data.comments.length }, { key: 'events', label: L('События', 'Events'), count: data.events.length }, { key: 'audit', label: L('Журнал', 'Log') }])}
      ${c.tabPanel('admin', `<div class="panel-tools"><input class="input" id="adm-q" type="search" value="${esc(query)}" placeholder="${L('Поиск по тексту, автору или сбору', 'Search by text, author or event')}" aria-label="${L('Поиск', 'Search')}"></div><div class="panel adm-panel">${list}</div>`)}`;
    const qi = document.getElementById('adm-q');
    qi.addEventListener('input', () => { query = qi.value; const pos = qi.selectionStart; draw(c, data); const n = document.getElementById('adm-q'); n.focus(); n.setSelectionRange(pos, pos); });
    body.querySelectorAll('[data-adm]').forEach(b => b.addEventListener('click', () => confirmDelete(c, b.dataset.adm, b.dataset.id, b.dataset.label)));
  }

  function confirmDelete(c, kind, id, label) {
    const { L, esc } = c;
    c.openModal(kind === 'event' ? L('Удалить сбор?', 'Delete the event?') : L('Удалить сообщение?', 'Delete the message?'), `
      <p class="muted" style="max-width:52ch">«${esc(label)}». ${kind === 'event' ? L('Сбор исчезнет у всех участников вместе с сообщениями и голосами. Участники получат уведомление.', 'The event disappears for all guests along with messages and votes. Guests will be notified.') : L('Автор получит уведомление. Действие попадёт в журнал.', 'The author will be notified. The action is logged.')}</p>
      <div class="modal-foot"><button class="btn btn-ghost" type="button" data-action="closeModal">${L('Отмена', 'Cancel')}</button><button class="btn btn-danger" type="button" id="adm-del">${L('Удалить', 'Delete')}</button></div>`, m => {
      m.querySelector('#adm-del').onclick = async () => {
        try {
          if (c.SERVER) await c.api('DELETE', `/admin/${kind === 'event' ? 'events' : 'comments'}/${encodeURIComponent(id)}`);
          else {
            const d = c.getDb();
            if (kind === 'event') d.events = d.events.filter(e => e.id !== id);
            else for (const e of d.events) { e.comments = (e.comments || []).filter(x => x.id !== id); if (e.story) e.story.comments = e.story.comments.filter(x => x.id !== id); }
            c.save(); c.secLog(kind === 'event' ? 'admin_delete_event' : 'admin_delete_comment', id);
          }
          c.closeModal(); c.toast(kind === 'event' ? L('Сбор удалён', 'Event deleted') : L('Сообщение удалено', 'Message deleted'));
          if (c.SERVER) { const fresh = await c.api('GET', '/bootstrap').catch(() => null); if (fresh) { const until = c.getDb().adminUntil; c.setDb(fresh); c.getDb().adminUntil = fresh.adminUntil || until; } }
          render(c);
        } catch (e) { c.toast(c.apiMsg(e), 'err'); if (e?.info?.error === 'step_up') { c.closeModal(); c.getDb().adminUntil = 0; render(c); } }
      };
    });
  }

  window.HP_ADMIN = { render };
})();
