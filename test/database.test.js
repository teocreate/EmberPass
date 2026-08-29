import test from 'node:test';
import assert from 'node:assert/strict';

process.env.DATABASE_URL = '';
const { resolveSsl, parseDatabaseUrl, describeConnectionError, redactUrl, describeTls } =
  await import('../server/db/pg.js');

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

/**
 * node-postgres accepts a connection string it cannot parse and silently falls back
 * to localhost, so a wrong DATABASE_URL surfaces much later as ECONNREFUSED
 * 127.0.0.1 with no mention of the variable at fault.
 */
test('a connection string that is not a URL is refused by name', () => {
  const psql = 'psql -h db.abcdef.supabase.co -p 5432 -d postgres -U postgres';
  assert.throws(() => parseDatabaseUrl(psql), /DATABASE_URL is not a connection URL/);
  assert.throws(() => parseDatabaseUrl(psql), /psql -h db\.abcdef\.supab/, 'shows what was actually set');
  assert.throws(() => parseDatabaseUrl(''), /DATABASE_URL is not a connection URL/);
  assert.throws(() => parseDatabaseUrl('mysql://user:pw@host/db'), /must start with postgres/);
});

test('an unreplaced password placeholder is caught before connecting', () => {
  assert.throws(
    () => parseDatabaseUrl('postgres://postgres.ref:[YOUR-PASSWORD]@aws-0-eu.pooler.supabase.com:5432/postgres'),
    /\[YOUR-PASSWORD\] placeholder/,
  );
});

test('a valid connection string yields the target for diagnostics', () => {
  const target = parseDatabaseUrl('postgres://postgres.ref:s3cret@aws-0-eu-central-1.pooler.supabase.com:5432/postgres');
  assert.deepEqual(target, {
    host: 'aws-0-eu-central-1.pooler.supabase.com',
    port: '5432',
    database: 'postgres',
    user: 'postgres.ref',
  });
  // Defaults match libpq: port 5432, database postgres.
  assert.equal(parseDatabaseUrl('postgres://user@host/').port, '5432');
  assert.equal(parseDatabaseUrl('postgres://user@host/').database, 'postgres');
  assert.equal(parseDatabaseUrl('postgresql://user@host/app').database, 'app');
});

test('connection failures name the likely cause', () => {
  const supabase = { host: 'aws-0-eu.pooler.supabase.com', port: '5432', database: 'postgres', user: 'postgres.ref' };
  const local = { host: '127.0.0.1', port: '5432', database: 'pass', user: 'pass' };

  assert.match(describeConnectionError({ code: 'ECONNREFUSED' }, local), /points at this machine/);
  assert.match(describeConnectionError({ code: 'ECONNREFUSED' }, supabase), /refused/);
  assert.match(describeConnectionError({ code: 'ENETUNREACH' }, supabase), /IPv6-only/);
  assert.match(describeConnectionError({ code: 'ENOTFOUND' }, supabase), /does not resolve/);
  assert.match(describeConnectionError({ code: '28P01' }, supabase), /password for user "postgres.ref"/);
  assert.match(describeConnectionError({ code: '3D000' }, supabase), /database "postgres" does not exist/);
  assert.match(describeConnectionError({ code: 'SELF_SIGNED_CERT_IN_CHAIN' }, supabase), /DATABASE_CA_CERT/);
});

test('a connection string is never logged with its password', () => {
  const url = 'postgres://postgres.ref:sup3r-s3cret@aws-0-eu.pooler.supabase.com:5432/postgres';
  const redacted = redactUrl(url);
  assert.ok(!redacted.includes('sup3r-s3cret'));
  assert.match(redacted, /postgres\.ref:\*\*\*@aws-0-eu\.pooler\.supabase\.com/);
});

test('the CA certificate may be given as PEM or as base64', async () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n';
  const original = process.env.DATABASE_CA_CERT;
  const load = async () => {
    // config is read once per process, so exercise the reader directly
    const { readCaCertForTest } = await import('../server/config.js');
    return readCaCertForTest(process.env.DATABASE_CA_CERT);
  };
  try {
    process.env.DATABASE_CA_CERT = pem;
    assert.equal(await load(), pem.trim(), 'surrounding whitespace is stripped');

    // A one-line value survives a hosting dashboard where a multi-line one may not.
    process.env.DATABASE_CA_CERT = Buffer.from(pem).toString('base64');
    assert.equal(await load(), pem.trim());

    process.env.DATABASE_CA_CERT = '';
    assert.equal(await load(), '');

    process.env.DATABASE_CA_CERT = 'not-a-certificate';
    await assert.rejects(async () => load(), /must be a PEM certificate/);
  } finally {
    if (original === undefined) delete process.env.DATABASE_CA_CERT;
    else process.env.DATABASE_CA_CERT = original;
  }
});

test('the startup line says which trust anchor is in use', async () => {
  const { generateKeyPairSync, X509Certificate } = await import('node:crypto');
  void generateKeyPairSync;
  void X509Certificate;

  assert.equal(describeTls(false), 'off');
  assert.equal(describeTls({ rejectUnauthorized: false }), 'on, chain not verified');
  assert.equal(describeTls({ rejectUnauthorized: true }), 'on, verified against system roots');
  // A CA that cannot be read must say so rather than claim verification is set up.
  assert.match(describeTls({ ca: 'not a certificate', rejectUnauthorized: true }), /could not be read/);
});

test('a chain error distinguishes a missing CA from a wrong one', () => {
  const target = { host: 'db.example.com', port: '5432', database: 'postgres', user: 'u' };
  const withoutCa = describeConnectionError({ code: 'SELF_SIGNED_CERT_IN_CHAIN' }, target);
  const withCa = describeConnectionError({ code: 'SELF_SIGNED_CERT_IN_CHAIN' }, { ...target, hasCa: true });

  assert.match(withoutCa, /against the system roots/);
  assert.match(withoutCa, /Supply the provider's CA/);
  assert.match(withCa, /does not sign this server's chain/);
});
