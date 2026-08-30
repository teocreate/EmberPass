/*
 * Service worker for the holder app.
 *
 * Network first, cache as the fallback. Cache first is the usual advice and it is
 * wrong for this app: it hands the browser whatever it stored last, so a deploy
 * reaches a phone one resource at a time and the page runs new markup against old
 * styles until every entry happens to refresh. Correctness here is worth a round
 * trip; the cache exists so the app still opens with no signal at all.
 */
const CACHE = 'pass-shell-v4';
const SHELL = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/lib/api.js',
  '/lib/render.js',
  '/lib/sso.js',
  '/lib/qrcode.js',
  '/manifest.webmanifest',
  '/icons/icon.svg',
];

/* Vendored code changes only when it is re-vendored, and that changes CACHE, so it
   is served from the cache and never re-downloaded. */
const CACHE_FIRST = /\/lib\/vendor\//;

/* Long enough for a slow gate connection, short enough not to strand the holder in
   front of a scanner. Only ever applied when there is a cached copy to fall back to. */
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
  // Pass tokens and verification results must always come from the server.
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    (async () => {
      const cached = await caches.match(event.request);
      if (cached && CACHE_FIRST.test(url.pathname)) return cached;
      try {
        // With nothing cached there is nothing to fall back to, so wait it out.
        return await fromNetwork(event.request, cached ? NETWORK_TIMEOUT : 0);
      } catch {
        return cached || (await caches.match('/index.html')) || Response.error();
      }
    })(),
  );
});
