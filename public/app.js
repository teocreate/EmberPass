import { api, ApiError } from './lib/api.js';
import { renderBarcode, loadFormat } from './lib/render.js';
import { setupSso, showSsoError, finishLogout } from './lib/sso.js';

const el = (id) => document.getElementById(id);
const views = { auth: el('view-auth'), cabinet: el('view-cabinet') };

const state = {
  user: null,
  pass: null,
  format: localStorage.getItem('pass.format') === 'pdf417' ? 'pdf417' : 'qr',
  formats: ['qr'],
  token: null, // { token, issuedAt, expiresAt, ttl, receivedAt }
  refreshTimer: null,
  frame: null,
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

/** Today shows as a time, anything older gets a short date - a full timestamp
 * wraps onto two lines on a phone and pulls the row out of alignment. */
function formatScanTime(value) {
  const date = new Date(value);
  const today = new Date();
  const sameDay = date.toDateString() === today.toDateString();
  return sameDay
    ? date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}


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
      ? `QR ${info.version} · нажмите на код, чтобы увеличить`
      : `PDF417 ${info.version} · нажмите на код, чтобы увеличить`;
}

/*
 * The countdown ring. Its geometry is written in the button's own pixels every time
 * the button changes size, so the stroke keeps an even width and the erasing head an
 * even speed all the way round.
 */
const ring = { box: null, path: null, w: 0, h: 0 };

function layoutRing() {
  if (!ring.box) return;
  const button = el('btn-refresh');
  const rect = button.getBoundingClientRect();
  const w = Math.round(rect.width);
  const h = Math.round(rect.height);
  // Zero while the view is hidden; keep the last good geometry until it has a size.
  if (!w || !h || (w === ring.w && h === ring.h)) return;
  ring.w = w;
  ring.h = h;
  const stroke = 2;
  const radius = parseFloat(getComputedStyle(button).borderTopLeftRadius) || 12;
  ring.box.setAttribute('viewBox', `0 0 ${w} ${h}`);
  ring.path.setAttribute('x', String(stroke / 2));
  ring.path.setAttribute('y', String(stroke / 2));
  ring.path.setAttribute('width', String(w - stroke));
  ring.path.setAttribute('height', String(h - stroke));
  ring.path.setAttribute('rx', String(Math.max(0, radius - stroke / 2)));
}

function setStatus(text) {
  const node = el('token-status');
  if (node.textContent !== text) node.textContent = text;
}

/**
 * The code on screen is replaced well before its token expires, so counting down to
 * the expiry would show the code changing with a third of the ring still to go. The
 * ring counts to the replacement instead - an empty ring is the moment the code
 * changes.
 *
 * If a refresh is late (no network, say), the ring switches to the token's real
 * lifetime: the code stays valid and scannable until then, and that is what the
 * holder needs to know at that point.
 */
let lastSecond = -1;

function tick() {
  if (!state.token) return;
  const now = Date.now() / 1000;
  const untilRefresh = state.token.refreshDueAt - now;
  const untilExpiry = state.token.expiresAt - now + state.token.skew;
  const late = untilRefresh <= 0;

  const total = late ? state.token.ttl : state.token.cycle;
  const left = Math.max(0, late ? untilExpiry : untilRefresh);
  const secondsLeft = Math.ceil(left);

  // 0 leaves the ring whole, 1 erases it completely. The rect path starts at the
  // top-left corner and runs clockwise, so this is where the head goes.
  const gone = total > 0 ? Math.min(1, Math.max(0, 1 - left / total)) : 1;
  ring.path.style.strokeDashoffset = String(-gone);

  // Announcing sixty times a second would flood a screen reader; the value only
  // ever changes once.
  if (secondsLeft !== lastSecond) {
    lastSecond = secondsLeft;
    ring.box.setAttribute('aria-valuemax', String(Math.round(total)));
    ring.box.setAttribute('aria-valuenow', String(secondsLeft));
    ring.box.setAttribute('aria-valuetext', `${secondsLeft} с до обновления кода`);
  }

  if (late && !state.refreshing) {
    setStatus(secondsLeft ? `Обновление задерживается — код годен ещё ${secondsLeft} с` : 'Код устарел');
    if (!secondsLeft) overlay('Код устарел', { retry: true });
  }
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
    // refreshDueAt runs on the browser's clock, the same one the timer below uses, so
    // the ring and the actual replacement cannot drift apart.
    const cycle = Math.max(2, Math.min(issued.refreshEvery, issued.ttl));
    // One deadline drives both the ring and the replacement, taken at one instant,
    // so the ring cannot empty early or late.
    const dueAt = Date.now() + cycle * 1000;
    state.token = { ...issued, skew, cycle, refreshDueAt: dueAt / 1000 };
    drawToken();
    overlay('');
    setStatus('Код действителен');
    layoutRing();
    tick();
    scheduleRefreshAt(dueAt);
  } catch (error) {
    const message =
      error instanceof ApiError && error.code === 'network_error'
        ? 'Нет сети — код не обновлён'
        : error.message || 'Не удалось обновить код';
    setStatus(message);
    overlay(message, { retry: true });
    // A refresh that did not happen means the ring should show the real lifetime left.
    if (state.token) state.token.refreshDueAt = Date.now() / 1000;
    if (error instanceof ApiError && error.status === 401) {
      stopTokenLoop();
      showView('auth');
    } else {
      scheduleRefreshAt(Date.now() + 5000);
    }
  } finally {
    state.refreshing = false;
  }
}

const ringResize = new ResizeObserver(() => layoutRing());

function scheduleRefreshAt(dueAt) {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(() => refreshToken({ silent: true }), Math.max(0, dueAt - Date.now()));
}

/* The ring is redrawn every frame from the clock rather than stepped on a timer:
 * anything coarser shows as a stutter on a stroke this long. */
function frameLoop() {
  state.frame = requestAnimationFrame(frameLoop);
  tick();
}

function startTokenLoop() {
  stopTokenLoop();
  ring.box = el('ring');
  ring.path = el('ring-path');
  layoutRing();
  ringResize.observe(el('btn-refresh'));
  state.frame = requestAnimationFrame(frameLoop);
  refreshToken();
}

function stopTokenLoop() {
  clearTimeout(state.refreshTimer);
  cancelAnimationFrame(state.frame);
  ringResize.disconnect();
  state.refreshTimer = null;
  state.frame = null;
}


document.querySelectorAll('.switch-btn').forEach((button) => {
  button.addEventListener('click', async () => {
    await loadFormat(button.dataset.format);
    state.format = button.dataset.format;
    localStorage.setItem('pass.format', state.format);
    document.querySelectorAll('.switch-btn').forEach((other) => other.classList.toggle('is-active', other === button));
    drawToken();
  });
});

el('btn-refresh').addEventListener('click', () => refreshToken());
el('btn-retry').addEventListener('click', () => refreshToken());
/**
 * Screen brightness is not something a web page can set - that needs a native app.
 * What helps a scanner is a big, maximally contrasty code that the screen will not
 * dim away from under it, so this mode enlarges the code, drops everything else, and
 * holds a wake lock where the browser supports one.
 */
let wakeLock = null;

async function enterCodeFullscreen() {
  document.body.classList.add('is-code-fullscreen');

  const hint = document.createElement('p');
  hint.className = 'fullscreen-hint';
  hint.id = 'fullscreen-hint';
  hint.textContent = 'Нажмите, чтобы выйти';
  document.body.appendChild(hint);
  document.body.addEventListener('click', exitOnTap, true);

  // Both are best-effort: iOS Safari refuses fullscreen for anything but video, and
  // older browsers have no wake lock at all. Neither failure matters here.
  document.documentElement.requestFullscreen?.().catch(() => {});
  try {
    wakeLock = (await navigator.wakeLock?.request('screen')) ?? null;
  } catch {
    wakeLock = null;
  }
}

function exitCodeFullscreen() {
  document.body.classList.remove('is-code-fullscreen');
  el('fullscreen-hint')?.remove();
  document.body.removeEventListener('click', exitOnTap, true);
  if (document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
  wakeLock?.release?.().catch(() => {});
  wakeLock = null;
}

function exitOnTap(event) {
  event.preventDefault();
  event.stopPropagation();
  exitCodeFullscreen();
}

/* The code is the control. Tapping it opens the full-screen view; the capture
 * listener installed above closes it again on the next tap anywhere. */
el('barcode-wrap').addEventListener('click', (event) => {
  // The retry button lives inside the window and means something else.
  if (event.target.closest('#btn-retry')) return;
  enterCodeFullscreen();
});
el('barcode-wrap').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  enterCodeFullscreen();
});

// A wake lock is dropped when the page is hidden; take it again on return.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && document.body.classList.contains('is-code-fullscreen') && !wakeLock) {
    navigator.wakeLock?.request('screen').then((lock) => { wakeLock = lock; }).catch(() => {});
  }
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
      time.textContent = formatScanTime(scan.scannedAt);
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
  const roles = { staff: 'сотрудник', admin: 'администратор' };
  el('holder-role').textContent = roles[user.role] ? `Личный кабинет · ${roles[user.role]}` : 'Личный кабинет';
  showView('cabinet');

  try {
    const details = await api.pass();
    state.pass = details.pass;
    state.formats = details.formats || ['qr'];
    await applyFormats();
    el('pass-serial').textContent = details.pass.serial;
    statusBadge(details.pass);
    renderScans(details.recentScans);
    if (details.pass.status === 'active') {
      startTokenLoop();
    } else {
      overlay('Пропуск неактивен — обратитесь в администрацию');
      setStatus('Код не выдаётся');
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

/**
 * Which code formats this deployment offers. PDF417 is switched off unless a
 * turnstile with a laser scanner is in play, and then the switch is not shown at all:
 * one format needs no chooser.
 */
async function applyFormats() {
  const formats = state.formats;
  if (!formats.includes(state.format)) state.format = formats[0];
  await loadFormat(state.format);
  el('format-switch').hidden = formats.length < 2;
  document.querySelectorAll('.switch-btn').forEach((button) => {
    button.hidden = !formats.includes(button.dataset.format);
    button.classList.toggle('is-active', button.dataset.format === state.format);
  });
}

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
