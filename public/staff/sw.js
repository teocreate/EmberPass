/*
 * Service worker for the staff app.
 *
 * Network first, cache as the fallback - see the holder app's worker for why. The
 * vendored decoder is the exception: it is 1.1 MB and changes only when it is
 * re-vendored, so it comes from the cache and is never re-downloaded.
 */
const CACHE = 'staff-shell-v7';
const SHELL = [
  '/staff/',
  '/staff/index.html',
  '/styles.css',
  '/staff/staff.css',
  '/staff/staff.js',
  '/lib/api.js',
  '/staff/lib/passtoken.js',
  '/staff/lib/scanner.js',
  // The module and its shared chunk are small; the 1.1 MB .wasm is left to the
  // runtime cache, filled by the warm-up fetch right after sign-in.
  '/staff/lib/vendor/zxing/index.js',
  '/staff/lib/vendor/share.js',
  '/lib/sso.js',
  '/staff/manifest.webmanifest',
  '/icons/icon-staff.svg',
];

const CACHE_FIRST = /\/lib\/vendor\//;
const NETWORK_TIMEOUT = 2500;

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      // 'reload' keeps the snapshot out of the browser's own HTTP cache, which would
      // otherwise let a stale copy into a fresh install.
      .then((cache) => cache.addAll(SHELL.map((url) => new Request(url, { cache: 'reload' }))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

async function fromNetwork(request, timeout) {
  const controller = new AbortController();
  const timer = timeout ? setTimeout(() => controller.abort(), timeout) : null;
  try {
    const response = await fetch(request, { signal: controller.signal });
    if (response.ok) {
      const copy = response.clone();
      caches.open(CACHE).then((cache) => cache.put(request, copy));
    }
    return response;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  // A verification result must never be answered from a cache.
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    (async () => {
      const cached = await caches.match(event.request);
      if (cached && CACHE_FIRST.test(url.pathname)) return cached;
      try {
        // With nothing cached there is nothing to fall back to, so wait it out.
        return await fromNetwork(event.request, cached ? NETWORK_TIMEOUT : 0);
      } catch {
        return cached || (await caches.match('/staff/index.html')) || Response.error();
      }
    })(),
  );
});
