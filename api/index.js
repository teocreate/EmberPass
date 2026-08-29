/**
 * Serverless entry point (Vercel and anything else with the same Node signature).
 *
 * `public/` is served by the platform's CDN, so this function only answers /api/*
 * routes; vercel.json rewrites them all here. The context is built once per warm
 * instance and reused across invocations.
 */
import { createContext, createRequestHandler } from '../server/index.js';

let handlerPromise = null;

async function getHandler() {
  if (!handlerPromise) {
    handlerPromise = createContext()
      .then((ctx) => {
        if (ctx.store.kind === 'memory') {
          console.warn(
            '[app] DATABASE_URL is not set. On a serverless platform the in-memory store ' +
              'is per-instance and disappears between cold starts - accounts and sessions will not survive.',
          );
        }
        return createRequestHandler(ctx, { serveFiles: false });
      })
      .catch((error) => {
        handlerPromise = null; // let the next invocation retry a failed cold start
        throw error;
      });
  }
  return handlerPromise;
}

export default async function handler(req, res) {
  try {
    const handle = await getHandler();
    await handle(req, res);
  } catch (error) {
    console.error('[app] startup failed', error);
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'startup_failed', message: 'server is not configured correctly' }));
  }
}
