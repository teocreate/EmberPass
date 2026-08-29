/* Service worker for the staff app: cache the shell, never cache the API. */
const CACHE = 'staff-shell-v3';
const SHELL = [
  '/staff/',
  '/staff/index.html',
  '/styles.css',
  '/staff/staff.css',
  '/staff/staff.js',
  '/lib/api.js',
  '/staff/lib/passtoken.js',
  '/staff/lib/scanner.js',
  '/lib/sso.js',
  '/staff/manifest.webmanifest',
  '/icons/icon-staff.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  // Pass tokens and verification results must always come from the server.
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE).then((cache) => cache.put(event.request, copy));
          }
          return response;
        })
        .catch(() => cached || caches.match('/staff/index.html'));
      return cached || network;
    }),
  );
});
