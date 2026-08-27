import test from 'node:test';
import assert from 'node:assert/strict';

import { checkEmail, normalizeEmail } from '../server/lib/email.js';

const offline = { checkMx: false }; // keep the suite independent of DNS

test('addresses are normalised before anything else', () => {
  assert.equal(normalizeEmail('  User.Name+Tag@Example.COM '), 'user.name+tag@example.com');
});

test('obvious syntax problems are rejected', async () => {
  const bad = ['', 'plainaddress', 'no-at-sign.com', '@no-local.com', 'two@@at.com', 'trailing@dot.', 'a b@spaces.com'];
  for (const value of bad) {
    const result = await checkEmail(value, offline);
    assert.equal(result.valid, false, `${value} must be rejected`);
    assert.equal(result.reason, 'invalid_syntax');
  }
});

test('plausible addresses pass the syntax stage', async () => {
  for (const value of ['user@example.com', 'first.last+tag@sub.example.co.uk', "o'brien@example.org"]) {
    const result = await checkEmail(value, offline);
    assert.equal(result.valid, true, `${value} must be accepted`);
    assert.equal(result.checks.syntax, true);
  }
});

test('disposable domains are flagged, and rejected when configured', async () => {
  const rejected = await checkEmail('someone@mailinator.com', { ...offline, rejectDisposable: true });
  assert.equal(rejected.valid, false);
  assert.equal(rejected.reason, 'disposable_domain');

  const allowed = await checkEmail('someone@mailinator.com', { ...offline, rejectDisposable: false });
  assert.equal(allowed.valid, true);
  assert.equal(allowed.checks.disposable, true, 'still reported to the caller');
});

test('role accounts are reported but not blocked', async () => {
  const result = await checkEmail('support@example.com', offline);
  assert.equal(result.valid, true);
  assert.equal(result.checks.role, true);
});

test('over-long addresses are rejected', async () => {
  const result = await checkEmail(`${'a'.repeat(250)}@example.com`, offline);
  assert.equal(result.valid, false);
});

test('a domain with no mail exchanger is rejected', { timeout: 10_000 }, async (t) => {
  const result = await checkEmail('user@invalid-domain-that-cannot-exist-9f2a.example', { checkMx: true });
  if (result.checks.mx === null) return t.skip('no DNS resolver available in this environment');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'no_mx_record');
});
