import test from 'node:test';
import assert from 'node:assert/strict';

process.env.DATABASE_URL = '';
const { resolveSsl } = await import('../server/db/pg.js');

/**
 * node-postgres connects in the clear unless told otherwise, and reads `require`
 * from a URL as `verify-full`. Hosted databases fail on the first, private CAs on
 * the second, so the setting is resolved here rather than left to the URL.
 */
test('TLS is on for hosted databases and off for a local one', () => {
  const local = ['postgres://pass:pass@localhost:5432/pass', 'postgres://pass:pass@127.0.0.1:5432/pass'];
  for (const url of local) assert.equal(resolveSsl(url, 'auto', ''), false, url);

  const hosted = [
    'postgres://postgres.ref:pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres',
    'postgres://postgres:pw@db.ref.supabase.co:5432/postgres',
    'postgres://user:pw@some-db.render.com:5432/app',
  ];
  for (const url of hosted) {
    assert.deepEqual(resolveSsl(url, 'auto', ''), { rejectUnauthorized: true }, url);
  }
});

test('explicit modes override the guess', () => {
  const url = 'postgres://postgres:pw@db.ref.supabase.co:5432/postgres';
  assert.equal(resolveSsl(url, 'disable', ''), false);
  assert.deepEqual(resolveSsl(url, 'no-verify', ''), { rejectUnauthorized: false });
  assert.deepEqual(resolveSsl(url, 'verify-full', ''), { rejectUnauthorized: true });
  assert.equal(resolveSsl('postgres://pass:pass@localhost:5432/pass', 'require', '').rejectUnauthorized, true);
});

test('a supplied CA keeps verification on instead of switching it off', () => {
  const ca = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
  const ssl = resolveSsl('postgres://postgres:pw@db.ref.supabase.co:5432/postgres', 'auto', ca);
  assert.equal(ssl.ca, ca);
  assert.equal(ssl.rejectUnauthorized, true);
});

test('an unusable mode is rejected loudly', () => {
  assert.throws(() => resolveSsl('postgres://x@host/db', 'sometimes', ''), /DATABASE_SSL must be/);
});

test('a connection string that is not a URL is treated as a local socket', () => {
  // libpq keyword strings and socket paths are the usual reason a URL fails to
  // parse, and those are local by nature. DATABASE_SSL overrides if it is not.
  assert.equal(resolveSsl('host=/var/run/postgresql dbname=pass', 'auto', ''), false);
  assert.deepEqual(resolveSsl('host=/var/run/postgresql dbname=pass', 'require', ''), { rejectUnauthorized: true });
  assert.deepEqual(resolveSsl('postgres://user:pw@example.com/db', 'auto', ''), { rejectUnauthorized: true });
});
