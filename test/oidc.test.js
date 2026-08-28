import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.CHECK_EMAIL_MX = 'false';
process.env.DATABASE_URL = '';
process.env.SIGNING_KEY_FILE = join(mkdtempSync(join(tmpdir(), 'pass-oidc-')), 'signing-key.json');

const { startStubProvider } = await import('./helpers/oidc-provider.js');
const { createApp } = await import('../server/index.js');
const { config } = await import('../server/config.js');
const { resetOidcCaches } = await import('../server/lib/oidc.js');
const { hashPassword } = await import('../server/lib/crypto.js');

/**
 * Brings up the app against a stub provider. Endpoints are read from config at call
 * time, so the two can learn each other's ports after both are listening.
 */
async function startEnvironment() {
  const provider = await startStubProvider();
  const app = await createApp();
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;

  config.oidc.issuer = provider.issuer;
  config.oidc.clientId = provider.clientId;
  config.oidc.clientSecret = provider.clientSecret;
  config.oidc.redirectUri = `${base}/api/auth/oidc/callback`;
  config.oidc.staffGroups = ['pass-staff'];
  config.oidc.adminGroups = ['pass-admins'];
  config.oidc.linkByEmail = true;
  config.oidc.rpLogout = true;
  config.oidcEnabled = true;
  config.localAuthEnabled = true;
  resetOidcCaches();

  const client = () => {
    const jar = new Map();
    const cookieHeader = () => [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    const remember = (response) => {
      for (const raw of response.headers.getSetCookie?.() ?? []) {
        const [pair] = raw.split(';');
        const index = pair.indexOf('=');
        const name = pair.slice(0, index).trim();
        const value = pair.slice(index + 1).trim();
        if (value === '' || /Max-Age=0/i.test(raw)) jar.delete(name);
        else jar.set(name, value);
      }
    };
    const request = async (method, url, body) => {
      const response = await fetch(url.startsWith('http') ? url : base + url, {
        method,
        redirect: 'manual',
        headers: {
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...(jar.size ? { cookie: cookieHeader() } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      remember(response);
      return response;
    };
    return {
      jar,
      request,
      async json(method, url, body) {
        const response = await request(method, url, body);
        const text = await response.text();
        return { status: response.status, body: text ? JSON.parse(text) : null };
      },
      /** Walks the whole single sign-on round trip and returns the final redirect. */
      async signIn(next = '/') {
        const start = await request('GET', `/api/auth/oidc/start?next=${encodeURIComponent(next)}`);
        assert.equal(start.status, 302, 'start must redirect to the provider');
        const atProvider = await request('GET', start.headers.get('location'));
        assert.equal(atProvider.status, 302, 'provider must redirect back');
        return request('GET', atProvider.headers.get('location'));
      },
    };
  };

  return {
    base,
    provider,
    ctx: app.ctx,
    client,
    async close() {
      await new Promise((resolve) => app.server.close(resolve));
      await app.close();
      await provider.close();
    },
  };
}

const errorOf = (response) => new URL(response.headers.get('location'), 'http://x').searchParams.get('sso_error');

test('single sign-on creates the account, its pass, and a local session', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  const user = env.client();

  const done = await user.signIn('/');
  assert.equal(done.status, 302);
  assert.equal(done.headers.get('location'), '/');

  const me = await user.json('GET', '/api/auth/me');
  assert.equal(me.body.user.email, 'holder@example.com');
  assert.equal(me.body.user.fullName, 'Иван Держатель');
  assert.equal(me.body.user.role, 'user', 'no staff group, no scanner access');
  assert.match(me.body.pass.serial, /^PS-\d{5}-/, 'a pass is issued on first sign-in');

  // The session is a normal one: the pass flow works without another provider hop.
  const token = await user.json('POST', '/api/pass/token', {});
  assert.equal(token.body.token.length, 118);
});

test('the authorization request uses PKCE, state and nonce', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());

  await env.client().signIn('/');
  const request = env.provider.lastAuthRequest;
  assert.equal(request.response_type, 'code');
  assert.equal(request.code_challenge_method, 'S256');
  assert.ok(request.code_challenge?.length >= 43);
  assert.ok(request.state?.length >= 16);
  assert.ok(request.nonce?.length >= 16);
  assert.equal(request.scope, 'openid profile email groups');
});

test('group membership decides the role, on every sign-in', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());

  env.provider.user.groups = ['everyone', 'pass-staff'];
  const staff = env.client();
  await staff.signIn('/staff/');
  let me = await staff.json('GET', '/api/auth/me');
  assert.equal(me.body.user.role, 'staff');

  // A staff member can actually use the scanner endpoints.
  const scans = await staff.json('GET', '/api/staff/scans');
  assert.equal(scans.status, 200);

  // Taking the group away at the provider takes the access away here.
  env.provider.user.groups = ['everyone'];
  const again = env.client();
  await again.signIn('/staff/');
  me = await again.json('GET', '/api/auth/me');
  assert.equal(me.body.user.role, 'user');
  assert.equal((await again.json('GET', '/api/staff/scans')).status, 403);

  env.provider.user.groups = ['pass-admins'];
  const admin = env.client();
  await admin.signIn('/');
  assert.equal((await admin.json('GET', '/api/auth/me')).body.user.role, 'admin');
});

test('a verified provider address links to an existing local account', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());

  const local = await env.ctx.store.createUser({
    email: 'holder@example.com',
    passwordHash: await hashPassword('local-password-1'),
    fullName: 'Локальный Аккаунт',
    role: 'user',
  });
  await env.ctx.store.createPass({ userId: local.id, serial: 'PS-00001-AAAA' });

  const user = env.client();
  await user.signIn('/');
  const me = await user.json('GET', '/api/auth/me');
  assert.equal(me.body.user.id, local.id, 'the same account, not a second one');
  assert.equal(me.body.pass.serial, 'PS-00001-AAAA', 'the existing pass is kept');

  const linked = await env.ctx.store.findUserById(local.id);
  assert.equal(linked.oidcSub, 'void-user-1');
  assert.equal(linked.authSource, 'oidc');
});

test('an unverified provider address may not take over a local account', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());

  await env.ctx.store.createUser({
    email: 'holder@example.com',
    passwordHash: await hashPassword('local-password-1'),
    fullName: 'Локальный Аккаунт',
    role: 'admin',
  });
  env.provider.user.email_verified = false;

  const attacker = env.client();
  const done = await attacker.signIn('/');
  assert.equal(errorOf(done), 'email_conflict');
  assert.equal((await attacker.json('GET', '/api/auth/me')).body.user, null, 'no session was issued');
});

test('a tampered or mis-issued ID token is refused', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  const now = Math.floor(Date.now() / 1000);
  const base = {
    iss: env.provider.issuer,
    aud: env.provider.clientId,
    sub: 'void-user-1',
    iat: now,
    exp: now + 300,
    email: 'holder@example.com',
    email_verified: true,
    groups: [],
  };

  const cases = [
    ['wrong signing key', { signWithWrongKey: true }, 'invalid_signature'],
    ['wrong audience', { claimsOverride: { ...base, aud: 'someone-else' } }, 'invalid_token'],
    ['wrong issuer', { claimsOverride: { ...base, iss: 'https://evil.example.com/oidc' } }, 'invalid_token'],
    ['expired', { claimsOverride: { ...base, exp: now - 60 } }, 'invalid_token'],
    ['replayed nonce', { claimsOverride: { ...base, nonce: 'not-the-one-we-sent' } }, 'invalid_token'],
  ];

  for (const [label, knobs, expected] of cases) {
    Object.assign(env.provider, { claimsOverride: null, signWithWrongKey: false }, knobs);
    const user = env.client();
    const done = await user.signIn('/');
    assert.equal(errorOf(done), expected, label);
    assert.equal((await user.json('GET', '/api/auth/me')).body.user, null, `${label}: no session`);
  }
});

test('the callback refuses a redirect this browser did not start', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  const user = env.client();

  // No transaction cookie at all.
  const cold = await user.request('GET', '/api/auth/oidc/callback?code=abc&state=whatever');
  assert.equal(errorOf(cold), 'expired');

  // A real login, but the state coming back has been swapped.
  const start = await user.request('GET', '/api/auth/oidc/start?next=/');
  const atProvider = await user.request('GET', start.headers.get('location'));
  const back = new URL(atProvider.headers.get('location'));
  back.searchParams.set('state', 'attacker-chosen-state');
  assert.equal(errorOf(await user.request('GET', back.pathname + back.search)), 'state_mismatch');

  // The provider itself reporting a refusal is passed through, not swallowed.
  const denied = await user.request('GET', '/api/auth/oidc/callback?error=access_denied&state=x');
  assert.equal(errorOf(denied), 'access_denied');
});

test('an authorization code cannot be replayed', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  const user = env.client();

  const start = await user.request('GET', '/api/auth/oidc/start?next=/');
  const atProvider = await user.request('GET', start.headers.get('location'));
  const callback = new URL(atProvider.headers.get('location'));

  const first = await user.request('GET', callback.pathname + callback.search);
  assert.equal(first.headers.get('location'), '/');

  const replay = env.client();
  const startAgain = await replay.request('GET', '/api/auth/oidc/start?next=/');
  await replay.request('GET', startAgain.headers.get('location'));
  const stolen = await replay.request('GET', callback.pathname + callback.search);
  assert.equal(errorOf(stolen), 'state_mismatch');
});

test('signing out ends the provider session too', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  const user = env.client();
  await user.signIn('/');

  const out = await user.json('POST', '/api/auth/logout', {});
  assert.equal(out.body.ok, true);
  assert.ok(out.body.redirectTo.startsWith(`${env.provider.base}/oidc/session/end`), 'RP-initiated logout URL');
  const url = new URL(out.body.redirectTo);
  assert.ok(url.searchParams.get('id_token_hint'), 'the provider is told which session to end');
  assert.equal(url.searchParams.get('client_id'), env.provider.clientId);

  assert.equal((await user.json('GET', '/api/auth/me')).body.user, null, 'the local session is gone');
});

test('provider-managed accounts have no password to guess', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  await env.client().signIn('/');

  for (const password of ['', 'password', 'null', 'undefined']) {
    const attempt = await env.client().json('POST', '/api/auth/login', { email: 'holder@example.com', password });
    assert.equal(attempt.status, 401, `password "${password}" must not sign in an SSO account`);
  }
});

test('AUTH_MODE=oidc closes the local password forms', async (t) => {
  const env = await startEnvironment();
  t.after(() => env.close());
  config.localAuthEnabled = false;
  t.after(() => {
    config.localAuthEnabled = true;
  });

  const client = env.client();
  const login = await client.json('POST', '/api/auth/login', { email: 'a@b.co', password: 'whatever-123' });
  assert.equal(login.status, 403);
  assert.equal(login.body.error, 'local_login_disabled');

  const register = await client.json('POST', '/api/auth/register', {
    email: 'new@example.com', password: 'whatever-1234', fullName: 'Кто-то',
  });
  assert.equal(register.status, 403);

  const me = await client.json('GET', '/api/auth/me');
  assert.equal(me.body.server.auth.local, false);
  assert.equal(me.body.server.auth.oidc.startUrl, '/api/auth/oidc/start');

  // Single sign-on still works while the password form is closed.
  const done = await client.signIn('/');
  assert.equal(done.headers.get('location'), '/');
});
