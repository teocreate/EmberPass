import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Configure the app before it is imported: no DNS lookups, no shared signing key,
// and the in-memory store (no DATABASE_URL) so the suite needs no database.
process.env.CHECK_EMAIL_MX = 'false';
process.env.DATABASE_URL = '';
process.env.SIGNING_KEY_FILE = join(mkdtempSync(join(tmpdir(), 'pass-test-')), 'signing-key.json');

const { createApp } = await import('../server/index.js');
const { hashPassword } = await import('../server/lib/crypto.js');

/** Starts the app on an ephemeral port with a cookie-aware client. */
async function startApp() {
  const app = await createApp();
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;

  const makeClient = () => {
    let cookie = '';
    return async (method, path, body) => {
      const response = await fetch(base + path, {
        method,
        headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(cookie ? { cookie } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const setCookie = response.headers.get('set-cookie');
      if (setCookie) cookie = setCookie.split(';')[0];
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : null };
    };
  };

  return {
    base,
    ctx: app.ctx,
    client: makeClient,
    async close() {
      await new Promise((resolve) => app.server.close(resolve));
      await app.close();
    },
  };
}

async function makeStaff(ctx, email = 'staff@test.local') {
  await ctx.store.createUser({
    email,
    passwordHash: await hashPassword('staff-password-1'),
    fullName: 'Контролёр',
    role: 'staff',
  });
}

test('register, get a pass token, and pass a gate', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  await makeStaff(app.ctx);

  const holder = app.client();
  const registered = await holder('POST', '/api/auth/register', {
    email: 'holder@test.local',
    password: 'holder-password-1',
    fullName: 'Держатель Пропуска',
  });
  assert.equal(registered.status, 201);
  assert.match(registered.body.pass.serial, /^PS-\d{5}-/);

  const me = await holder('GET', '/api/auth/me');
  assert.equal(me.body.user.email, 'holder@test.local');

  const issued = await holder('POST', '/api/pass/token', {});
  assert.equal(issued.status, 200);
  assert.equal(issued.body.token.length, 118);
  assert.equal(issued.body.expiresAt - issued.body.issuedAt, issued.body.ttl);

  const staff = app.client();
  await staff('POST', '/api/auth/login', { email: 'staff@test.local', password: 'staff-password-1' });
  const verdict = await staff('POST', '/api/staff/verify', { token: issued.body.token, gate: 'Главный вход' });
  assert.equal(verdict.body.status, 'granted');
  assert.equal(verdict.body.holder.fullName, 'Держатель Пропуска');
  assert.equal(verdict.body.scan.gate, 'Главный вход');

  const history = await holder('GET', '/api/pass/history');
  assert.equal(history.body.scans[0].result, 'granted');
});

test('a token can only be used once', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  await makeStaff(app.ctx);

  const holder = app.client();
  await holder('POST', '/api/auth/register', {
    email: 'replay@test.local', password: 'holder-password-1', fullName: 'Повтор Повторов',
  });
  const { body: issued } = await holder('POST', '/api/pass/token', {});

  const staff = app.client();
  await staff('POST', '/api/auth/login', { email: 'staff@test.local', password: 'staff-password-1' });
  const first = await staff('POST', '/api/staff/verify', { token: issued.token, gate: 'A' });
  const second = await staff('POST', '/api/staff/verify', { token: issued.token, gate: 'B' });

  assert.equal(first.body.status, 'granted');
  assert.equal(second.body.status, 'denied');
  assert.equal(second.body.reason, 'already_used');
  assert.equal(second.body.previousScan.gate, 'A');
});

test('forged and stale codes are refused', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  await makeStaff(app.ctx);

  const holder = app.client();
  await holder('POST', '/api/auth/register', {
    email: 'forge@test.local', password: 'holder-password-1', fullName: 'Тест Подписи',
  });
  const { body: issued } = await holder('POST', '/api/pass/token', {});

  const staff = app.client();
  await staff('POST', '/api/auth/login', { email: 'staff@test.local', password: 'staff-password-1' });

  const raw = Buffer.from(issued.token, 'base64url');
  raw[40] ^= 0x08; // flip a bit inside the signature
  const forged = await staff('POST', '/api/staff/verify', { token: raw.toString('base64url') });
  assert.equal(forged.body.status, 'denied');
  assert.equal(forged.body.reason, 'bad_signature');

  const garbage = await staff('POST', '/api/staff/verify', { token: 'definitely-not-a-pass' });
  assert.equal(garbage.body.reason, 'malformed');

  const expired = app.ctx.signer.issue({
    passId: 1, userId: 1, ttl: 30, now: Math.floor(Date.now() / 1000) - 600,
  });
  const stale = await staff('POST', '/api/staff/verify', { token: expired.token });
  assert.equal(stale.body.reason, 'expired');
});

test('a suspended pass stops being usable', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  await makeStaff(app.ctx);

  const holder = app.client();
  const registered = await holder('POST', '/api/auth/register', {
    email: 'suspended@test.local', password: 'holder-password-1', fullName: 'Заблокированный',
  });
  const { body: issued } = await holder('POST', '/api/pass/token', {});
  await app.ctx.store.setPassStatus(registered.body.pass.id, 'suspended');

  const staff = app.client();
  await staff('POST', '/api/auth/login', { email: 'staff@test.local', password: 'staff-password-1' });
  const verdict = await staff('POST', '/api/staff/verify', { token: issued.token });
  assert.equal(verdict.body.status, 'denied');
  assert.equal(verdict.body.reason, 'pass_suspended');

  const refused = await holder('POST', '/api/pass/token', {});
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, 'pass_suspended');
});

test('endpoints require the right session and role', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  await makeStaff(app.ctx);

  const anonymous = app.client();
  assert.equal((await anonymous('GET', '/api/pass')).status, 401);
  assert.equal((await anonymous('POST', '/api/pass/token', {})).status, 401);
  assert.equal((await anonymous('POST', '/api/staff/verify', { token: 'x' })).status, 401);

  const holder = app.client();
  await holder('POST', '/api/auth/register', {
    email: 'roles@test.local', password: 'holder-password-1', fullName: 'Обычный Пользователь',
  });
  const forbidden = await holder('POST', '/api/staff/verify', { token: 'x' });
  assert.equal(forbidden.status, 403, 'a plain holder cannot verify passes');

  await holder('POST', '/api/auth/logout', {});
  assert.equal((await holder('GET', '/api/pass')).status, 401, 'logout ends the session');
});

test('login is rejected for wrong credentials and rate limited', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const client = app.client();
  await client('POST', '/api/auth/register', {
    email: 'brute@test.local', password: 'holder-password-1', fullName: 'Цель Перебора',
  });

  const wrong = await client('POST', '/api/auth/login', { email: 'brute@test.local', password: 'nope-nope-nope' });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.body.error, 'invalid_credentials');

  let limited = null;
  for (let i = 0; i < 15 && !limited; i++) {
    const attempt = await client('POST', '/api/auth/login', { email: 'brute@test.local', password: `wrong-${i}` });
    if (attempt.status === 429) limited = attempt;
  }
  assert.ok(limited, 'repeated failures are rate limited');
  assert.equal(limited.body.error, 'rate_limited');
});

test('duplicate registrations are refused', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  const client = app.client();
  const first = await client('POST', '/api/auth/register', {
    email: 'dupe@test.local', password: 'holder-password-1', fullName: 'Первый',
  });
  assert.equal(first.status, 201);
  const second = await client('POST', '/api/auth/register', {
    email: 'dupe@test.local', password: 'holder-password-2', fullName: 'Второй',
  });
  assert.equal(second.status, 409);
  assert.equal(second.body.error, 'email_taken');
});

test('the verification key is public and contains no secret material', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  const response = await app.client()('GET', '/api/verify/key');
  assert.equal(response.status, 200);
  assert.equal(response.body.keys[0].crv, 'Ed25519');
  assert.ok(!('d' in response.body.keys[0]));
  assert.equal(typeof response.body.tokenTtl, 'number');
});

test('static files and app shells are served', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  for (const path of ['/', '/staff/', '/lib/qrcode.js', '/manifest.webmanifest', '/some/unknown/path']) {
    const response = await fetch(app.base + path);
    assert.equal(response.status, 200, `${path} must be served`);
  }
  const missingApi = await fetch(app.base + '/api/nope');
  assert.equal(missingApi.status, 404);
});
