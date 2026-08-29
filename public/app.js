import { api, ApiError } from './lib/api.js';
import { renderBarcode } from './lib/render.js';
import { setupSso, showSsoError, finishLogout } from './lib/sso.js';

const el = (id) => document.getElementById(id);
const views = { auth: el('view-auth'), cabinet: el('view-cabinet') };

const state = {
  user: null,
  pass: null,
  format: localStorage.getItem('pass.format') === 'pdf417' ? 'pdf417' : 'qr',
  token: null, // { token, issuedAt, expiresAt, ttl, receivedAt }
  refreshTimer: null,
  tickTimer: null,
  refreshing: false,
};

/* ------------------------------- view plumbing ------------------------------- */

function showView(name) {
  for (const [key, node] of Object.entries(views)) node.hidden = key !== name;
}

function setError(form, message) {
  const node = form.querySelector('[data-error]');
  node.textContent = message || '';
  node.hidden = !message;
}

function overlay(text, { retry = false } = {}) {
  const wrap = el('barcode-overlay');
  if (!text) {
    wrap.hidden = true;
    el('barcode').classList.remove('is-stale');
    return;
  }
  el('barcode-overlay-text').textContent = text;
  el('btn-retry').hidden = !retry;
  wrap.hidden = false;
  el('barcode').classList.add('is-stale');
}

const dateFormat = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short' });

/* --------------------------------- auth flow -------------------------------- */

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((other) => other.classList.toggle('is-active', other === tab));
    el('form-login').hidden = tab.dataset.tab !== 'login';
    el('form-register').hidden = tab.dataset.tab !== 'register';
  });
});

el('form-login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setError(form, '');
  form.querySelector('button').disabled = true;
  try {
    const result = await api.login(String(data.get('email')), String(data.get('password')));
    await enterCabinet(result.user, result.pass);
  } catch (error) {
    setError(form, error instanceof ApiError ? error.message : 'не удалось войти');
  } finally {
    form.querySelector('button').disabled = false;
  }
});

el('form-register').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setError(form, '');
  form.querySelector('button').disabled = true;
  try {
    const result = await api.register({
      fullName: String(data.get('fullName')),
      email: String(data.get('email')),
      password: String(data.get('password')),
    });
    await enterCabinet(result.user, result.pass);
  } catch (error) {
    setError(form, error instanceof ApiError ? error.message : 'не удалось зарегистрироваться');
  } finally {
    form.querySelector('button').disabled = false;
  }
});

// Email is checked (syntax, MX, disposable domains) while the field is filled in.
let emailCheckTimer = null;
el('form-register').elements.email.addEventListener('input', (event) => {
  const hint = document.querySelector('[data-email-hint]');
  const value = event.target.value.trim();
  clearTimeout(emailCheckTimer);
  hint.textContent = '';
  hint.className = 'hint';
  if (value.length < 5 || !value.includes('@')) return;
  emailCheckTimer = setTimeout(async () => {
    try {
      const result = await api.checkEmail(value);
      hint.textContent = result.valid ? 'адрес выглядит рабочим' : result.message;
      hint.className = `hint ${result.valid ? 'is-good' : 'is-bad'}`;
    } catch {
      hint.textContent = '';
    }
  }, 600);
});

el('btn-logout').addEventListener('click', async () => {
  stopTokenLoop();
  const result = await api.logout().catch(() => null);
  state.user = null;
  state.pass = null;
  state.token = null;
  // With single sign-on the provider session outlives the local one; let it end too.
  if (finishLogout(result)) return;
  showView('auth');
});

/* ------------------------------- pass rendering ------------------------------ */

function statusBadge(pass) {
  const badge = el('pass-status');
  const labels = { active: 'активен', suspended: 'приостановлен', revoked: 'аннулирован' };
  badge.textContent = labels[pass.status] || pass.status;
  badge.className = 'badge' + (pass.status === 'active' ? '' : pass.status === 'suspended' ? ' is-warn' : ' is-danger');
}

function drawToken() {
  if (!state.token) return;
  const info = renderBarcode(el('barcode'), state.token.token, state.format);
  el('token-hint').textContent =
    state.format === 'qr'
      ? `QR ${info.version} · покажите код сотруднику`
      : `PDF417 ${info.version} · для сканеров на турникете`;
}

function tick() {
  if (!state.token) return;
  const secondsLeft = Math.max(0, state.token.expiresAt - Math.floor(Date.now() / 1000) + state.token.skew);
  const ratio = Math.max(0, Math.min(1, secondsLeft / state.token.ttl));
  const ring = el('ring-progress');
  ring.style.strokeDashoffset = String(100.5 * (1 - ratio));
  ring.classList.toggle('is-low', ratio < 0.34);
  el('countdown-value').textContent = String(secondsLeft);
  if (secondsLeft === 0 && !state.refreshing) overlay('Код устарел', { retry: true });
}

async function refreshToken({ silent = false } = {}) {
  if (state.refreshing) return;
  state.refreshing = true;
  if (!silent) overlay('Обновляем код…');
  try {
    const issued = await api.passToken();
    // Trust the server clock: phones drift, and a drifted phone would show a
    // countdown that disagrees with what the scanner sees.
    const skew = issued.serverTime - Math.floor(Date.now() / 1000);
    state.token = { ...issued, skew };
    drawToken();
    overlay('');
    el('token-status').textContent = 'Код действителен';
    tick();
    scheduleRefresh(issued.refreshEvery);
  } catch (error) {
    const message =
      error instanceof ApiError && error.code === 'network_error'
        ? 'Нет сети — код не обновлён'
        : error.message || 'Не удалось обновить код';
    el('token-status').textContent = message;
    overlay(message, { retry: true });
    if (error instanceof ApiError && error.status === 401) {
      stopTokenLoop();
      showView('auth');
    } else {
      scheduleRefresh(5);
    }
  } finally {
    state.refreshing = false;
  }
}

function scheduleRefresh(seconds) {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(() => refreshToken({ silent: true }), Math.max(2, seconds) * 1000);
}

function startTokenLoop() {
  stopTokenLoop();
  state.tickTimer = setInterval(tick, 250);
  refreshToken();
}

function stopTokenLoop() {
  clearTimeout(state.refreshTimer);
  clearInterval(state.tickTimer);
  state.refreshTimer = null;
  state.tickTimer = null;
}

document.querySelectorAll('.switch-btn').forEach((button) => {
  button.addEventListener('click', () => {
    state.format = button.dataset.format;
    localStorage.setItem('pass.format', state.format);
    document.querySelectorAll('.switch-btn').forEach((other) => other.classList.toggle('is-active', other === button));
    drawToken();
  });
});

el('btn-refresh').addEventListener('click', () => refreshToken());
el('btn-retry').addEventListener('click', () => refreshToken());
el('btn-bright').addEventListener('click', () => {
  document.body.classList.toggle('is-bright');
  el('btn-bright').textContent = document.body.classList.contains('is-bright') ? 'Обычно' : 'Ярче';
});

/* --------------------------------- history ---------------------------------- */

function renderScans(scans) {
  const list = el('scan-list');
  if (!scans.length) {
    list.innerHTML = '<li class="muted">Пока нет ни одного прохода</li>';
    return;
  }
  list.replaceChildren(
    ...scans.map((scan) => {
      const item = document.createElement('li');
      const left = document.createElement('div');
      const granted = scan.result === 'granted';
      const result = document.createElement('p');
      result.className = `scan-result ${granted ? 'is-granted' : 'is-denied'}`;
      result.textContent = granted ? 'Проход разрешён' : describeDenial(scan.result);
      const meta = document.createElement('p');
      meta.className = 'muted small';
      meta.textContent = [scan.gate || 'вход', scan.staffName].filter(Boolean).join(' · ');
      left.append(result, meta);
      const time = document.createElement('p');
      time.className = 'muted small';
      time.textContent = dateFormat.format(new Date(scan.scannedAt));
      item.append(left, time);
      return item;
    }),
  );
}

function describeDenial(result) {
  const reason = String(result).replace(/^denied_/, '');
  const labels = {
    expired: 'Код просрочен',
    bad_signature: 'Подпись не совпала',
    already_used: 'Код уже использован',
    pass_suspended: 'Пропуск приостановлен',
    pass_revoked: 'Пропуск аннулирован',
    pass_expired: 'Срок пропуска истёк',
    holder_suspended: 'Владелец заблокирован',
    malformed: 'Нечитаемый код',
  };
  return labels[reason] || 'Отказано';
}

/* ---------------------------------- start ----------------------------------- */

async function enterCabinet(user, pass) {
  state.user = user;
  state.pass = pass;
  el('holder-name').textContent = user.fullName;
  el('holder-role').textContent = user.role === 'user' ? 'Личный кабинет' : `Личный кабинет · ${user.role}`;
  showView('cabinet');

  document.querySelectorAll('.switch-btn').forEach((button) =>
    button.classList.toggle('is-active', button.dataset.format === state.format),
  );

  try {
    const details = await api.pass();
    state.pass = details.pass;
    el('pass-serial').textContent = details.pass.serial;
    statusBadge(details.pass);
    renderScans(details.recentScans);
    if (details.pass.status === 'active') {
      startTokenLoop();
    } else {
      overlay('Пропуск неактивен — обратитесь в администрацию');
      el('token-status').textContent = 'Код не выдаётся';
    }
  } catch (error) {
    overlay(error.message || 'Не удалось загрузить пропуск', { retry: true });
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || !state.user) return;
  // Coming back to the app with a stale code is the common case: refresh at once.
  const secondsLeft = state.token ? state.token.expiresAt - Math.floor(Date.now() / 1000) + state.token.skew : 0;
  if (secondsLeft < 5) refreshToken({ silent: true });
  api.pass().then((details) => renderScans(details.recentScans)).catch(() => {});
});

window.addEventListener('online', () => {
  el('offline-banner').hidden = true;
  if (state.user) refreshToken({ silent: true });
});
window.addEventListener('offline', () => {
  el('offline-banner').hidden = false;
});

const CONFIG_WARNINGS = {
  ephemeral_storage: 'база данных не подключена — аккаунты и проходы живут только до перезапуска сервера',
  ephemeral_signing_key: 'ключ подписи не задан — коды перестанут проверяться после перезапуска',
};

/** Shows or hides the password form and the single sign-on button. */
function applyAuthMethods(auth) {
  if (!auth) return;
  setupSso({
    auth,
    next: '/',
    elements: {
      block: el('sso-block'),
      button: el('btn-sso'),
      name: el('sso-name'),
      divider: el('sso-divider'),
      error: el('sso-error'),
    },
  });
  document.querySelector('.tabs').hidden = !auth.local;
  el('form-login').hidden = !auth.local;
  if (!auth.local) el('form-register').hidden = true;
  document.querySelector('.tab[data-tab="register"]').hidden = !auth.registration;
}

function showConfigWarnings(server) {
  const messages = (server?.warnings || []).map((code) => CONFIG_WARNINGS[code]).filter(Boolean);
  const banner = el('config-banner');
  banner.hidden = messages.length === 0;
  banner.textContent = messages.length ? `Демо-режим: ${messages.join('; ')}` : '';
}

(async function boot() {
  el('offline-banner').hidden = navigator.onLine;
  try {
    const session = await api.me();
    showConfigWarnings(session.server);
    applyAuthMethods(session.server?.auth);
    showSsoError(el('sso-error'));
    if (session.user) {
      await enterCabinet(session.user, session.pass);
    } else {
      showView('auth');
    }
  } catch {
    showView('auth');
  }
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
})();
