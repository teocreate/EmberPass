import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { config, loadSigningKey } from './config.js';
import { getStore, closeStore } from './db/index.js';
import { PassSigner } from './lib/token.js';
import { RateLimiter } from './lib/ratelimit.js';
import { HttpError, sendJson, sendError, serveStatic } from './lib/http.js';
import {
  handleRegister, handleLogin, handleLogout, handleMe, handleCheckEmail,
} from './routes/auth.js';
import {
  handleGetPass, handleIssueToken, handleHistory, handlePublicKey,
} from './routes/pass.js';
import { handleVerify, handleRecentScans } from './routes/staff.js';

const publicDir = resolve(dirname(fileURLToPath(import.meta.url)), '../public');

const ROUTES = [
  ['POST', '/api/auth/register', handleRegister],
  ['POST', '/api/auth/login', handleLogin],
  ['POST', '/api/auth/logout', handleLogout],
  ['POST', '/api/auth/check-email', handleCheckEmail],
  ['GET', '/api/auth/me', handleMe],
  ['GET', '/api/pass', handleGetPass],
  ['POST', '/api/pass/token', handleIssueToken],
  ['GET', '/api/pass/history', handleHistory],
  ['GET', '/api/verify/key', handlePublicKey],
  ['POST', '/api/staff/verify', handleVerify],
  ['GET', '/api/staff/scans', handleRecentScans],
];

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'same-origin',
  'content-security-policy':
    "default-src 'self'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; " +
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
};

export async function createApp() {
  const store = await getStore();
  const signer = new PassSigner(loadSigningKey());
  const limiters = {
    login: new RateLimiter({ limit: 10, windowMs: 5 * 60 * 1000 }),
    register: new RateLimiter({ limit: 5, windowMs: 60 * 60 * 1000 }),
    emailCheck: new RateLimiter({ limit: 30, windowMs: 10 * 60 * 1000 }),
    token: new RateLimiter({ limit: 120, windowMs: 60 * 1000 }),
    verify: new RateLimiter({ limit: 600, windowMs: 60 * 1000 }),
  };

  const ctx = {
    store,
    signer,
    limiters,
    log: (message, fields = {}) => console.log(`[app] ${message}`, JSON.stringify(fields)),
  };

  const server = createServer(async (req, res) => {
    for (const [header, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(header, value);
    const { pathname } = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    try {
      const route = ROUTES.find(([method, path]) => path === pathname && method === req.method);
      if (route) return await route[2](ctx, req, res);

      if (pathname.startsWith('/api/')) {
        const methodMismatch = ROUTES.some(([, path]) => path === pathname);
        throw methodMismatch
          ? new HttpError(405, 'method_not_allowed', 'method not allowed')
          : new HttpError(404, 'not_found', 'no such endpoint');
      }

      if (req.method === 'GET' || req.method === 'HEAD') {
        if (await serveStatic(req, res, publicDir, pathname)) return;
        // Unknown paths fall back to the matching app shell.
        const shell = pathname.startsWith('/staff') ? '/staff/index.html' : '/index.html';
        if (await serveStatic(req, res, publicDir, shell)) return;
      }
      throw new HttpError(404, 'not_found', 'not found');
    } catch (error) {
      sendError(res, error);
    }
  });

  const sweeper = setInterval(() => {
    Object.values(limiters).forEach((limiter) => limiter.sweep());
    store.deleteExpiredSessions().catch((error) => console.error('[sweep]', error));
  }, 60_000);
  sweeper.unref();

  return { server, ctx, close: async () => { clearInterval(sweeper); await closeStore(); } };
}

const isMain = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`;
if (isMain) {
  const app = await createApp();
  app.server.listen(config.port, config.host, () => {
    console.log(`[app] storage=${app.ctx.store.kind} listening on http://${config.host}:${config.port}`);
    console.log(`[app] holder PWA: /   staff PWA: /staff   pass token TTL: ${config.passTokenTtl}s`);
    if (app.ctx.store.kind === 'memory') {
      console.log('[app] DATABASE_URL is not set - using the in-memory store, data will not persist');
    }
  });

  const shutdown = async (signal) => {
    console.log(`[app] ${signal} received, shutting down`);
    app.server.close();
    await app.close();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

export { sendJson };
