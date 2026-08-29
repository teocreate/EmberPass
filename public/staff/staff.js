import { api, ApiError } from '/lib/api.js';
import { setupSso, showSsoError, finishLogout } from '/lib/sso.js';
import { parseToken, verifyOffline, importVerifyKey, offlineVerificationSupported } from '/staff/lib/passtoken.js';
import { createScanner, describeScanner, loadVendorDecoder } from '/staff/lib/scanner.js';

const el = (id) => document.getElementById(id);
const views = { auth: el('view-auth'), scanner: el('view-scanner') };

const QUEUE_KEY = 'staff.queue';
const GATE_KEY = 'staff.gate';
const JWK_KEY = 'staff.verifyKey';

const state = {
  staff: null,
  detector: null,
  stream: null,
  scanning: false,
  verifyKey: null,
  keyMeta: null,
  lastToken: null,
  lastAt: 0,
  busy: false,
  resultTimer: null,
  formats: ['qr'],
  torchTrack: null,
  torchOn: false,
};

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


function showView(name) {
  for (const [key, node] of Object.entries(views)) node.hidden = key !== name;
}

/* --------------------------------- offline queue -------------------------------- */

const queue = {
  read() {
    try {
      return JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]');
    } catch {
      return [];
    }
  },
  write(items) {
    localStorage.setItem(QUEUE_KEY, JSON.stringify(items.slice(0, 500)));
    el('queue-count').textContent = String(items.length);
    el('queue-pill').hidden = items.length === 0;
  },
  add(entry) {
    const items = queue.read();
    items.push(entry);
    queue.write(items);
  },
  async flush() {
    const items = queue.read();
    if (!items.length || !navigator.onLine) return;
    const remaining = [];
    for (const item of items) {
      try {
        await api.verify(item.token, item.gate, true);
      } catch (error) {
        if (error instanceof ApiError && error.status === 0) remaining.push(item);
        // A 4xx means the server has judged this scan; keeping it would loop forever.
      }
    }
    queue.write(remaining);
    if (items.length !== remaining.length) await loadScans();
  },
};

/* ----------------------------------- verifying ---------------------------------- */

async function loadVerifyKey() {
  try {
    const result = await api.verifyKey();
    localStorage.setItem(JWK_KEY, JSON.stringify(result));
    state.keyMeta = result;
  } catch {
    const cached = localStorage.getItem(JWK_KEY);
    if (!cached) return;
    state.keyMeta = JSON.parse(cached);
  }
  if (!state.keyMeta || !(await offlineVerificationSupported())) return;
  try {
    state.verifyKey = await importVerifyKey(state.keyMeta.keys[0]);
  } catch {
    state.verifyKey = null;
  }
}

function feedback(kind) {
  if (!navigator.vibrate) return;
  navigator.vibrate(kind === 'granted' ? 60 : [50, 60, 50]);
}

/**
 * The verdict takes the whole screen. At a gate it has to be readable at arm's
 * length in bad light, and covering the camera for a moment is a feature: it stops
 * the next person's code being read before this one has been acted on.
 *
 * A grant clears itself - the queue moves on. A refusal stays until it is dismissed,
 * because someone has to read why.
 */
function showResult(kind, title, name, meta, serial) {
  const node = el('result');
  clearTimeout(state.resultTimer);
  node.hidden = false;
  node.className = `result is-${kind}`;
  el('result-title').textContent = title;
  el('result-name').textContent = name || '';
  el('result-serial').textContent = serial || '';
  el('result-meta').textContent = meta || '';
  feedback(kind);

  if (kind === 'granted') state.resultTimer = setTimeout(hideResult, 2500);
}

function hideResult() {
  clearTimeout(state.resultTimer);
  el('result').hidden = true;
}

const DENIAL_LABELS = {
  expired: 'Код просрочен',
  not_yet_valid: 'Код ещё не действителен',
  bad_signature: 'Подпись не совпала',
  unknown_key: 'Неизвестный ключ подписи',
  unsupported_version: 'Неподдерживаемый формат',
  malformed: 'Это не пропуск',
  already_used: 'Код уже использован',
  pass_suspended: 'Пропуск приостановлен',
  pass_revoked: 'Пропуск аннулирован',
  pass_expired: 'Срок пропуска истёк',
  holder_suspended: 'Владелец заблокирован',
  unknown_pass: 'Пропуск не найден',
  unknown_holder: 'Владелец не найден',
  pass_mismatch: 'Пропуск не принадлежит владельцу',
};

async function handleToken(token, { force = false } = {}) {
  const now = Date.now();
  // The camera fires many times a second; ignore the same code for a moment. A code
  // typed in by hand is always an explicit request, so it skips that suppression.
  if (!force && (state.busy || (token === state.lastToken && now - state.lastAt < 2500))) return;
  // A typed-in code waits its turn rather than being dropped.
  for (let i = 0; state.busy && i < 30; i++) await new Promise((resolve) => setTimeout(resolve, 100));
  if (state.busy) return;
  state.busy = true;
  state.lastToken = token;
  state.lastAt = now;

  const gate = el('gate-input').value.trim() || null;
  try {
    if (navigator.onLine) {
      const result = await api.verify(token, gate, false);
      renderVerdict(result);
      await loadScans();
      return;
    }
    await verifyWhileOffline(token, gate);
  } catch (error) {
    if (error instanceof ApiError && error.status === 0) {
      await verifyWhileOffline(token, gate);
    } else if (error instanceof ApiError && error.status === 401) {
      showView('auth');
    } else {
      showResult('denied', 'Ошибка', '', error.message);
    }
  } finally {
    setTimeout(() => {
      state.busy = false;
    }, 700);
  }
}

function renderVerdict(result) {
  if (result.status === 'granted') {
    showResult(
      'granted',
      'Проход разрешён',
      result.holder?.fullName,
      [result.scan?.gate, `код выдан ${result.tokenAge} с назад`].filter(Boolean).join(' · '),
      result.pass?.serial,
    );
    return;
  }
  const label = DENIAL_LABELS[result.reason] || result.message || 'Отказано';
  const details = [];
  if (result.holder?.fullName) details.push(result.holder.fullName);
  if (result.previousScan) {
    details.push(`прошёл в ${formatScanTime(result.previousScan.scannedAt)}`);
    if (result.previousScan.gate) details.push(result.previousScan.gate);
  }
  showResult('denied', 'Отказано', label, details.join(' · '), result.pass?.serial);
}

/** No connectivity: check the signature locally and queue the scan for the server. */
async function verifyWhileOffline(token, gate) {
  if (!state.verifyKey) {
    const parsed = parseToken(token);
    if (!parsed) return showResult('denied', 'Отказано', 'Это не пропуск', '');
    queue.add({ token, gate, at: Date.now() });
    return showResult('pending', 'Нет сети', 'Проверка отложена', 'Код будет проверен сервером позже');
  }

  const result = await verifyOffline(token, state.verifyKey, state.keyMeta?.keys?.[0]?.kid ? Number(state.keyMeta.keys[0].kid) : undefined, {
    clockSkew: state.keyMeta?.clockSkew ?? 5,
  });
  if (!result.ok) {
    showResult('denied', 'Отказано', DENIAL_LABELS[result.reason] || 'Код не прошёл проверку', 'офлайн-проверка');
    return;
  }
  queue.add({ token, gate, at: Date.now() });
  showResult(
    'pending',
    'Подпись верна',
    'Офлайн-проверка',
    'Повторное использование здесь не видно — скан уйдёт на сервер',
    `Пропуск #${result.parsed.passId}`,
  );
}

/* ----------------------------------- camera ------------------------------------- */

async function startCamera() {
  el('btn-camera').disabled = true;
  try {
    // Ask for the camera first: it is the step that needs the user's gesture, and
    // loading the fallback decoder can take a moment on a slow connection.
    state.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 } },
      audio: false,
    });
    el('scanner-note').textContent = 'Готовим сканер…';
    state.detector = await createScanner(state.formats);
  } catch (error) {
    const denied = error.name === 'NotAllowedError';
    el('scanner-note').textContent = denied
      ? 'Доступ к камере запрещён. Разрешите его в настройках сайта и попробуйте снова.'
      : `Не удалось включить камеру: ${error.message}. Используйте ручной ввод кода.`;
    el('manual-card').hidden = false;
    stopCamera();
    return;
  } finally {
    el('btn-camera').disabled = false;
  }

  const video = el('video');
  video.srcObject = state.stream;
  try {
    await video.play();
  } catch (error) {
    el('scanner-note').textContent = `Видео не запустилось: ${error.message}`;
    stopCamera();
    return;
  }
  el('camera-card').hidden = false;
  el('scanner-note').textContent = describeScanner(state.detector);
  setupTorch();
  state.scanning = true;
  scanLoop();
}

/*
 * The lamp is a property of the video track, not of the page, and only some devices
 * expose it: Chrome on Android does, Safari on iOS does not expose it at all. So the
 * button appears only where it can actually turn something on, rather than sitting
 * there dead on half the phones that reach the gate.
 */
function setupTorch() {
  const btn = el('btn-torch');
  state.torchTrack = null;
  state.torchOn = false;
  btn.hidden = true;
  btn.classList.remove('is-on');
  btn.setAttribute('aria-pressed', 'false');

  const track = state.stream?.getVideoTracks?.()[0];
  if (!track || typeof track.getCapabilities !== 'function') return;
  let capabilities;
  try {
    capabilities = track.getCapabilities();
  } catch {
    return;
  }
  if (capabilities.torch !== true) return;
  state.torchTrack = track;
  btn.hidden = false;
}

async function toggleTorch() {
  if (!state.torchTrack) return;
  const next = !state.torchOn;
  const btn = el('btn-torch');
  try {
    await state.torchTrack.applyConstraints({ advanced: [{ torch: next }] });
  } catch (error) {
    // The lamp can be refused while another app holds it, or on a device that
    // advertises the capability but not the constraint.
    state.torchTrack = null;
    btn.hidden = true;
    el('scanner-note').textContent = `Фонарик недоступен: ${error.message}`;
    return;
  }
  state.torchOn = next;
  btn.classList.toggle('is-on', next);
  btn.setAttribute('aria-pressed', String(next));
}

function stopCamera() {
  state.scanning = false;
  state.detector = null;
  state.torchTrack = null;
  state.torchOn = false;
  el('btn-torch').hidden = true;
  el('btn-torch').classList.remove('is-on');
  el('btn-torch').setAttribute('aria-pressed', 'false');
  // Stopping the track puts the lamp out with it.
  if (state.stream) state.stream.getTracks().forEach((track) => track.stop());
  state.stream = null;
  el('video').srcObject = null;
  el('camera-card').hidden = true;
}

async function scanLoop() {
  const video = el('video');
  while (state.scanning) {
    try {
      for (const value of await state.detector.detect(video)) {
        if (parseToken(value)) {
          await handleToken(value.trim());
          break;
        }
      }
    } catch {
      // A transient detect() failure (video not ready yet) is not worth reporting.
    }
    // Decoding in JavaScript is heavier than the native path, so it gets more room.
    await new Promise((resolve) => setTimeout(resolve, state.detector.kind === 'native' ? 180 : 320));
  }
}

/* ------------------------------------ scans ------------------------------------- */

async function loadScans() {
  try {
    const { scans } = await api.recentScans(25);
    const list = el('scan-list');
    if (!scans.length) {
      list.innerHTML = '<li class="muted">Пока пусто</li>';
      return;
    }
    list.replaceChildren(
      ...scans.map((scan) => {
        const item = document.createElement('li');
        const left = document.createElement('div');
        const title = document.createElement('p');
        const granted = scan.result === 'granted';
        title.className = `scan-result ${granted ? 'is-granted' : 'is-denied'}`;
        title.textContent = granted
          ? scan.holderName || 'Проход разрешён'
          : DENIAL_LABELS[String(scan.result).replace(/^denied_/, '')] || 'Отказано';
        const meta = document.createElement('p');
        meta.className = 'muted small';
        meta.textContent = [scan.passSerial, scan.gate, scan.offline ? 'офлайн' : null].filter(Boolean).join(' · ');
        left.append(title, meta);
        const time = document.createElement('p');
        time.className = 'muted small';
        time.textContent = formatScanTime(scan.scannedAt);
        item.append(left, time);
        return item;
      }),
    );
  } catch {
    /* the list is a convenience; failing to refresh it must not break scanning */
  }
}

/* ------------------------------------- wiring ----------------------------------- */

el('form-login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const error = form.querySelector('[data-error]');
  error.hidden = true;
  try {
    const result = await api.login(String(data.get('email')), String(data.get('password')));
    if (result.user.role !== 'staff' && result.user.role !== 'admin') {
      await api.logout().catch(() => {});
      throw new ApiError(403, 'forbidden', 'у этого аккаунта нет доступа сотрудника');
    }
    await enterScanner(result.user);
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
  }
});

el('btn-logout').addEventListener('click', async () => {
  stopCamera();
  const result = await api.logout().catch(() => null);
  state.staff = null;
  if (finishLogout(result)) return;
  showView('auth');
});

el('result').addEventListener('click', hideResult);
el('btn-camera').addEventListener('click', startCamera);
el('btn-stop-camera').addEventListener('click', stopCamera);
el('btn-torch').addEventListener('click', toggleTorch);
el('btn-manual').addEventListener('click', () => {
  el('manual-card').hidden = !el('manual-card').hidden;
  if (!el('manual-card').hidden) el('manual-token').focus();
});
el('btn-reload-scans').addEventListener('click', loadScans);

el('form-manual').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = el('manual-token');
  const token = input.value.trim();
  if (!token) return;
  await handleToken(token, { force: true });
  input.value = '';
});

el('gate-input').addEventListener('change', (event) => localStorage.setItem(GATE_KEY, event.target.value.trim()));

window.addEventListener('online', () => {
  el('offline-banner').hidden = true;
  queue.flush();
});
window.addEventListener('offline', () => {
  el('offline-banner').hidden = false;
});

async function enterScanner(staff) {
  state.staff = staff;
  el('staff-name').textContent = staff.fullName;
  el('gate-input').value = localStorage.getItem(GATE_KEY) || '';
  showView('scanner');
  queue.write(queue.read());
  await loadVerifyKey();
  el('scanner-note').textContent = state.verifyKey
    ? 'Офлайн-проверка подписи доступна'
    : 'Офлайн-проверка подписи недоступна в этом браузере';

  // Where the browser has no BarcodeDetector the decoder is a 1.1 MB download.
  // Fetching it now, while the gate is being typed in, keeps the first scan quick.
  if (!('BarcodeDetector' in window)) loadVendorDecoder().catch(() => {});
  await Promise.all([loadScans(), queue.flush()]);
}

function applyAuthMethods(auth) {
  if (!auth) return;
  setupSso({
    auth,
    next: '/staff/',
    elements: {
      block: el('sso-block'),
      button: el('btn-sso'),
      name: el('sso-name'),
      divider: el('sso-divider'),
      error: el('sso-error'),
    },
  });
  el('form-login').hidden = !auth.local;
}

(async function boot() {
  el('offline-banner').hidden = navigator.onLine;
  try {
    const session = await api.me();
    state.formats = session.server?.formats || ['qr'];
    applyAuthMethods(session.server?.auth);
    showSsoError(el('sso-error'));
    if (session.user && (session.user.role === 'staff' || session.user.role === 'admin')) {
      await enterScanner(session.user);
    } else {
      if (session.user) {
        const error = el('sso-error');
        error.textContent = 'у этого аккаунта нет доступа сотрудника';
        error.hidden = false;
      }
      showView('auth');
    }
  } catch {
    showView('auth');
  }
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/staff/sw.js').catch(() => {});
})();
