/**
 * Client-side pass token parsing and offline signature verification.
 *
 * The server is always the authority - it is the only side that can detect a replayed
 * token. When the gate has no connectivity, a staff device can still check that the
 * token is well-formed, unexpired and signed by the known key, and queue the scan for
 * the server to settle later.
 */

const TOKEN_BYTES = 88;
const PAYLOAD_BYTES = 24;
const TOKEN_VERSION = 1;

export function fromBase64url(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Structural parse only - no signature check. Returns null if this is not a pass token. */
export function parseToken(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{110,130}$/.test(token.trim())) return null;
  let raw;
  try {
    raw = fromBase64url(token.trim());
  } catch {
    return null;
  }
  if (raw.length !== TOKEN_BYTES) return null;
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (view.getUint8(0) !== TOKEN_VERSION) return null;
  const issuedAt = view.getUint32(10);
  const ttl = view.getUint16(14);
  return {
    raw,
    payload: raw.subarray(0, PAYLOAD_BYTES),
    signature: raw.subarray(PAYLOAD_BYTES),
    version: view.getUint8(0),
    kid: view.getUint8(1),
    passId: view.getUint32(2),
    userId: view.getUint32(6),
    issuedAt,
    ttl,
    expiresAt: issuedAt + ttl,
    jti: base64url(raw.subarray(16, 24)),
  };
}

/** True when this browser can verify Ed25519 signatures locally. */
export async function offlineVerificationSupported() {
  try {
    await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
    return true;
  } catch {
    return false;
  }
}

export async function importVerifyKey(jwk) {
  return crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, { name: 'Ed25519' }, false, [
    'verify',
  ]);
}

/**
 * Offline check: signature, key id and lifetime. Cannot detect replays, so the caller
 * must queue the scan and let the server settle it.
 */
export async function verifyOffline(token, key, kid, { clockSkew = 5, now = Math.floor(Date.now() / 1000) } = {}) {
  const parsed = parseToken(token);
  if (!parsed) return { ok: false, reason: 'malformed' };
  if (kid !== undefined && parsed.kid !== kid) return { ok: false, reason: 'unknown_key', parsed };
  const valid = await crypto.subtle.verify({ name: 'Ed25519' }, key, parsed.signature, parsed.payload);
  if (!valid) return { ok: false, reason: 'bad_signature', parsed };
  if (now + clockSkew < parsed.issuedAt) return { ok: false, reason: 'not_yet_valid', parsed };
  if (now - clockSkew > parsed.expiresAt) return { ok: false, reason: 'expired', parsed };
  return { ok: true, reason: null, parsed };
}
