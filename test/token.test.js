import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { PassSigner, verifyPassToken, TOKEN_BYTES } from '../server/lib/token.js';

function makeSigner(kid = 1) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return new PassSigner({
    kid,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  });
}

const signer = makeSigner();
const options = () => ({ publicKey: signer.publicKey, kid: signer.kid, clockSkew: 5 });

test('a freshly issued token verifies and carries its claims', () => {
  const issued = signer.issue({ passId: 7, userId: 42, ttl: 30 });
  assert.equal(Buffer.from(issued.token, 'base64url').length, TOKEN_BYTES);
  assert.equal(issued.token.length, 118, 'stays short enough for a low QR version');

  const result = verifyPassToken(issued.token, options());
  assert.equal(result.ok, true);
  assert.equal(result.payload.passId, 7);
  assert.equal(result.payload.userId, 42);
  assert.equal(result.payload.expiresAt - result.payload.issuedAt, 30);
});

test('every token gets a different jti', () => {
  const jtis = new Set();
  for (let i = 0; i < 100; i++) jtis.add(signer.issue({ passId: 1, userId: 1, ttl: 30 }).jti);
  assert.equal(jtis.size, 100);
});

test('tokens expire and are not accepted before they are issued', () => {
  const now = Math.floor(Date.now() / 1000);
  const issued = signer.issue({ passId: 1, userId: 1, ttl: 30, now });
  assert.equal(verifyPassToken(issued.token, { ...options(), now: now + 20 }).ok, true);
  assert.equal(verifyPassToken(issued.token, { ...options(), now: now + 40 }).reason, 'expired');
  assert.equal(verifyPassToken(issued.token, { ...options(), now: now - 40 }).reason, 'not_yet_valid');
  // A little clock drift on the gate device is tolerated.
  assert.equal(verifyPassToken(issued.token, { ...options(), now: now + 33 }).ok, true);
});

test('tampering with any byte breaks the signature', () => {
  const issued = signer.issue({ passId: 7, userId: 42, ttl: 30 });
  const raw = Buffer.from(issued.token, 'base64url');
  for (const index of [2, 5, 9, 13, 17, 30, 60, 87]) {
    const copy = Buffer.from(raw);
    copy[index] ^= 0x01;
    const result = verifyPassToken(copy.toString('base64url'), options());
    assert.equal(result.ok, false, `byte ${index} must not verify`);
    assert.ok(['bad_signature', 'expired', 'not_yet_valid', 'unsupported_version', 'unknown_key'].includes(result.reason));
  }
});

test('a token signed by another key is rejected', () => {
  const other = makeSigner(1);
  const forged = other.issue({ passId: 7, userId: 42, ttl: 30 });
  assert.equal(verifyPassToken(forged.token, options()).reason, 'bad_signature');
});

test('an unknown key id is rejected before the signature is checked', () => {
  const other = makeSigner(2);
  assert.equal(verifyPassToken(other.issue({ passId: 1, userId: 1, ttl: 30 }).token, options()).reason, 'unknown_key');
});

test('garbage input is rejected as malformed', () => {
  for (const value of ['', 'not-a-token', 'x'.repeat(500), 'a'.repeat(118), null, 42, {}]) {
    const result = verifyPassToken(value, options());
    assert.equal(result.ok, false);
  }
});

test('the published JWK matches the signing key', () => {
  const jwk = signer.publicJwk();
  assert.equal(jwk.kty, 'OKP');
  assert.equal(jwk.crv, 'Ed25519');
  assert.equal(jwk.kid, String(signer.kid));
  assert.ok(!('d' in jwk), 'the private scalar must never be published');
});
