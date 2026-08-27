import { createPrivateKey, createPublicKey, sign, verify, randomBytes } from 'node:crypto';
import { base64url, fromBase64url } from './crypto.js';

/**
 * Dynamic pass tokens.
 *
 * A token is a compact binary payload plus an Ed25519 signature, base64url encoded:
 *
 *   byte  0      format version (1)
 *   byte  1      signing key id
 *   bytes 2-5    pass id      (uint32 BE)
 *   bytes 6-9    user id      (uint32 BE)
 *   bytes 10-13  issued at    (uint32 BE, unix seconds)
 *   bytes 14-15  lifetime     (uint16 BE, seconds)
 *   bytes 16-23  jti          (8 random bytes, used for replay detection)
 *   bytes 24-87  Ed25519 signature over bytes 0-23
 *
 * 88 bytes total, 118 base64url characters: small enough for a low QR version and a
 * short PDF417 symbol, which matters when the code is scanned off a phone screen.
 */

export const TOKEN_VERSION = 1;
const PAYLOAD_BYTES = 24;
const SIGNATURE_BYTES = 64;
export const TOKEN_BYTES = PAYLOAD_BYTES + SIGNATURE_BYTES;

export class PassSigner {
  constructor({ kid, privateKeyPem, publicKeyPem }) {
    this.kid = kid;
    this.privateKey = createPrivateKey(privateKeyPem);
    this.publicKey = createPublicKey(publicKeyPem);
  }

  /** Issues a short-lived token for a pass. */
  issue({ passId, userId, ttl, now = Math.floor(Date.now() / 1000) }) {
    if (ttl < 1 || ttl > 0xffff) throw new RangeError('ttl out of range');
    const payload = Buffer.alloc(PAYLOAD_BYTES);
    const jti = randomBytes(8);
    payload.writeUInt8(TOKEN_VERSION, 0);
    payload.writeUInt8(this.kid, 1);
    payload.writeUInt32BE(passId, 2);
    payload.writeUInt32BE(userId, 6);
    payload.writeUInt32BE(now, 10);
    payload.writeUInt16BE(ttl, 14);
    jti.copy(payload, 16);

    const signature = sign(null, payload, this.privateKey);
    return {
      token: base64url(Buffer.concat([payload, signature])),
      jti: base64url(jti),
      passId,
      userId,
      issuedAt: now,
      expiresAt: now + ttl,
    };
  }

  /** Public key as a JWK, so staff devices can verify signatures offline via WebCrypto. */
  publicJwk() {
    const jwk = this.publicKey.export({ format: 'jwk' });
    return { ...jwk, kid: String(this.kid), alg: 'EdDSA', use: 'sig' };
  }
}

/** Parses a token and checks its signature and lifetime. Does not touch the database. */
export function verifyPassToken(token, { publicKey, kid, now = Math.floor(Date.now() / 1000), clockSkew = 5 }) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{80,200}$/.test(token)) {
    return { ok: false, reason: 'malformed' };
  }
  const raw = fromBase64url(token);
  if (raw.length !== TOKEN_BYTES) return { ok: false, reason: 'malformed' };

  const payload = raw.subarray(0, PAYLOAD_BYTES);
  const signature = raw.subarray(PAYLOAD_BYTES);
  if (payload.readUInt8(0) !== TOKEN_VERSION) return { ok: false, reason: 'unsupported_version' };
  if (payload.readUInt8(1) !== kid) return { ok: false, reason: 'unknown_key' };
  if (!verify(null, payload, publicKey, signature)) return { ok: false, reason: 'bad_signature' };

  const issuedAt = payload.readUInt32BE(10);
  const ttl = payload.readUInt16BE(14);
  const expiresAt = issuedAt + ttl;
  const parsed = {
    version: payload.readUInt8(0),
    kid: payload.readUInt8(1),
    passId: payload.readUInt32BE(2),
    userId: payload.readUInt32BE(6),
    issuedAt,
    ttl,
    expiresAt,
    jti: base64url(payload.subarray(16, 24)),
  };

  if (now + clockSkew < issuedAt) return { ok: false, reason: 'not_yet_valid', payload: parsed };
  if (now - clockSkew > expiresAt) return { ok: false, reason: 'expired', payload: parsed };
  return { ok: true, payload: parsed };
}
