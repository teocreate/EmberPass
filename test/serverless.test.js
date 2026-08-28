import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.CHECK_EMAIL_MX = 'false';
process.env.DATABASE_URL = '';
process.env.VERCEL = '1'; // pretend we are on a serverless platform
process.env.SIGNING_KEY_FILE = join(mkdtempSync(join(tmpdir(), 'pass-fn-')), 'signing-key.json');

const { default: handler } = await import('../api/index.js');
const { hashPassword } = await import('../server/lib/crypto.js');
const { getStore } = await import('../server/db/index.js');

/**
 * Vercel hands the function a request whose body is already read and parsed, and
 * serves `public/` from its CDN rather than through the function. This mirrors both.
 */
function startFunction() {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    if (raw) req.body = JSON.parse(raw);
    await handler(req, res);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const base = `http://127.0.0.1:${server.address().port}`;
      let cookie = '';
      const call = async (method, path, body) => {
        const response = await fetch(base + path, {
          method,
          headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
          body: body ? JSON.stringify(body) : undefined,
        });
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) cookie = setCookie.split(';')[0];
        const text = await response.text();
        return { status: response.status, type: response.headers.get('content-type'), body: text ? JSON.parse(text) : null };
      };
      resolve({ base, call, close: () => new Promise((done) => server.close(done)) });
    });
  });
}

test('the serverless entry point serves the whole pass flow', async (t) => {
  const fn = await startFunction();
  t.after(() => fn.close());

  const store = await getStore();
  await store.createUser({
    email: 'staff@fn.local',
    passwordHash: await hashPassword('staff-password-1'),
    fullName: 'Контролёр',
    role: 'staff',
  });

  const registered = await fn.call('POST', '/api/auth/register', {
    email: 'holder@fn.local', password: 'holder-password-1', fullName: 'Держатель Пропуска',
  });
  assert.equal(registered.status, 201, 'a pre-parsed JSON body is accepted');

  const issued = await fn.call('POST', '/api/pass/token', {});
  assert.equal(issued.body.token.length, 118);

  const staffCookie = await startFunction();
  await staffCookie.call('POST', '/api/auth/login', { email: 'staff@fn.local', password: 'staff-password-1' });
  const verdict = await staffCookie.call('POST', '/api/staff/verify', { token: issued.body.token, gate: 'Вход' });
  assert.equal(verdict.body.status, 'granted');
  await staffCookie.close();
});

test('unknown routes answer with JSON, never with the app shell', async (t) => {
  const fn = await startFunction();
  t.after(() => fn.close());

  for (const path of ['/api/nope', '/', '/staff/']) {
    const response = await fn.call('GET', path);
    assert.equal(response.status, 404, `${path} must 404 from the function`);
    assert.match(response.type, /application\/json/, `${path} must not return HTML`);
    assert.equal(response.body.error, 'not_found');
  }
});

test('a deployment without a database says so instead of failing silently', async (t) => {
  const fn = await startFunction();
  t.after(() => fn.close());

  const session = await fn.call('GET', '/api/auth/me');
  assert.equal(session.body.server.storage, 'memory');
  assert.deepEqual(session.body.server.warnings, ['ephemeral_storage', 'ephemeral_signing_key']);
});

test('session cookies are marked Secure on a serverless deployment', async (t) => {
  const fn = await startFunction();
  t.after(() => fn.close());

  const raw = await fetch(fn.base + '/api/auth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'cookie@fn.local', password: 'holder-password-1', fullName: 'Куки Тест' }),
  });
  const cookie = raw.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
});
