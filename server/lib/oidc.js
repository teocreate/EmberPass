import { createHash, createPublicKey, randomBytes, verify as verifySignature } from 'node:crypto';
import { base64url, fromBase64url } from './crypto.js';
import { config } from '../config.js';

/**
 * Minimal OpenID Connect relying party: authorization code flow with PKCE, against
 * VoidAuth or any other standards-compliant provider. No dependencies - discovery,
 * JWKS handling and JWT verification are done here.
 *
 * The provider authenticates people; this app still issues its own session cookie
 * afterwards. Access and refresh tokens are deliberately not kept: nothing here
 * calls the provider's API on the user's behalf.
 */

const DISCOVERY_TTL_MS = 10 * 60 * 1000;
const JWKS_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;

let discoveryCache = null;
let jwksCache = null;

export class OidcError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.code = code;
    this.cause = cause;
  }
}

async function fetchJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, { ...options, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (error) {
    throw new OidcError('provider_unreachable', `provider request failed: ${url}`, error);
  }
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (error) {
    throw new OidcError('provider_bad_response', `provider returned non-JSON from ${url}`, error);
  }
  if (!response.ok) {
    const detail = payload.error_description || payload.error || `HTTP ${response.status}`;
    throw new OidcError('provider_error', `provider rejected the request: ${detail}`);
  }
  return payload;
}

/** Reads (and caches) the provider's discovery document. */
export async function discover({ force = false } = {}) {
  if (!force && discoveryCache && Date.now() < discoveryCache.expiresAt) return discoveryCache.document;
  if (!config.oidcEnabled) throw new OidcError('not_configured', 'OIDC is not configured');

  const url = `${config.oidc.issuer}/.well-known/openid-configuration`;
  const document = await fetchJson(url);
  // A provider whose issuer disagrees with where the document was found can be used
  // to point tokens at the wrong party; refuse rather than guess.
  if (document.issuer !== config.oidc.issuer) {
    throw new OidcError('issuer_mismatch', `discovery issuer ${document.issuer} != ${config.oidc.issuer}`);
  }
  for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    if (!document[field]) throw new OidcError('discovery_incomplete', `discovery document has no ${field}`);
  }
  discoveryCache = { document, expiresAt: Date.now() + DISCOVERY_TTL_MS };
  return document;
}

async function getSigningKey(kid, alg) {
  const load = async () => {
    const { jwks_uri: jwksUri } = await discover();
    const { keys } = await fetchJson(jwksUri);
    jwksCache = { keys: keys || [], expiresAt: Date.now() + JWKS_TTL_MS };
    return jwksCache.keys;
  };

  let keys = jwksCache && Date.now() < jwksCache.expiresAt ? jwksCache.keys : await load();
  let match = keys.find((key) => (kid ? key.kid === kid : true) && (!key.alg || key.alg === alg));
  if (!match) {
    // Unknown key id usually means the provider rotated keys; refetch once.
    keys = await load();
    match = keys.find((key) => (kid ? key.kid === kid : true) && (!key.alg || key.alg === alg));
  }
  if (!match) throw new OidcError('unknown_key', `no JWKS entry for kid=${kid} alg=${alg}`);
  return createPublicKey({ key: match, format: 'jwk' });
}

const ALGORITHMS = {
  RS256: { hash: 'RSA-SHA256' },
  RS384: { hash: 'RSA-SHA384' },
  RS512: { hash: 'RSA-SHA512' },
  PS256: { hash: 'RSA-SHA256', padding: 'pss' },
  ES256: { hash: 'SHA256', dsaEncoding: 'ieee-p1363' },
  ES384: { hash: 'SHA384', dsaEncoding: 'ieee-p1363' },
  EdDSA: { hash: null },
};

function verifyJwsSignature(alg, signingInput, signature, key) {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new OidcError('unsupported_alg', `unsupported id_token algorithm: ${alg}`);
  const options = { key };
  if (spec.padding === 'pss') {
    options.padding = 1 << 6; // RSA_PKCS1_PSS_PADDING
    options.saltLength = -1; // RSA_PSS_SALTLEN_DIGEST
  }
  if (spec.dsaEncoding) options.dsaEncoding = spec.dsaEncoding;
  return verifySignature(spec.hash, Buffer.from(signingInput), options, signature);
}

/** PKCE pair: the verifier stays with the browser session, the challenge goes out. */
export function createPkce() {
  const verifier = base64url(randomBytes(32));
  return { verifier, challenge: base64url(createHash('sha256').update(verifier).digest()), method: 'S256' };
}

export async function buildAuthorizationUrl({ state, nonce, challenge, prompt }) {
  const { authorization_endpoint: endpoint } = await discover();
  const url = new URL(endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.oidc.clientId);
  url.searchParams.set('redirect_uri', config.oidc.redirectUri);
  url.searchParams.set('scope', config.oidc.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (prompt) url.searchParams.set('prompt', prompt);
  return url.toString();
}

/** Trades the authorization code for tokens. */
export async function exchangeCode({ code, verifier }) {
  const { token_endpoint: endpoint } = await discover();
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.oidc.redirectUri,
    client_id: config.oidc.clientId,
    code_verifier: verifier,
  });
  const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };

  if (config.oidc.authMethod === 'client_secret_basic') {
    const credentials = `${encodeURIComponent(config.oidc.clientId)}:${encodeURIComponent(config.oidc.clientSecret)}`;
    headers.authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
  } else if (config.oidc.authMethod === 'client_secret_post') {
    body.set('client_secret', config.oidc.clientSecret);
  }

  return fetchJson(endpoint, { method: 'POST', headers, body: body.toString() });
}

/**
 * Verifies an ID token: signature against the provider's JWKS, then issuer,
 * audience, lifetime and the nonce this login started with.
 */
export async function verifyIdToken(idToken, { nonce, now = Math.floor(Date.now() / 1000) } = {}) {
  if (typeof idToken !== 'string' || idToken.split('.').length !== 3) {
    throw new OidcError('invalid_token', 'id_token is not a JWS');
  }
  const [headerPart, payloadPart, signaturePart] = idToken.split('.');
  let header;
  let claims;
  try {
    header = JSON.parse(fromBase64url(headerPart).toString('utf8'));
    claims = JSON.parse(fromBase64url(payloadPart).toString('utf8'));
  } catch (error) {
    throw new OidcError('invalid_token', 'id_token is not valid JSON', error);
  }
  if (header.alg === 'none') throw new OidcError('invalid_token', 'unsigned id_token');

  const key = await getSigningKey(header.kid, header.alg);
  if (!verifyJwsSignature(header.alg, `${headerPart}.${payloadPart}`, fromBase64url(signaturePart), key)) {
    throw new OidcError('invalid_signature', 'id_token signature does not verify');
  }

  const skew = config.clockSkew;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== config.oidc.issuer) throw new OidcError('invalid_token', 'id_token issuer mismatch');
  if (!audiences.includes(config.oidc.clientId)) throw new OidcError('invalid_token', 'id_token audience mismatch');
  if (audiences.length > 1 && claims.azp !== config.oidc.clientId) {
    throw new OidcError('invalid_token', 'id_token azp mismatch');
  }
  if (typeof claims.exp !== 'number' || claims.exp + skew < now) throw new OidcError('invalid_token', 'id_token expired');
  if (typeof claims.iat === 'number' && claims.iat - skew > now) {
    throw new OidcError('invalid_token', 'id_token issued in the future');
  }
  if (nonce && claims.nonce !== nonce) throw new OidcError('invalid_token', 'id_token nonce mismatch');
  if (!claims.sub) throw new OidcError('invalid_token', 'id_token has no subject');

  return claims;
}

/** Claims the provider keeps out of the ID token (VoidAuth returns them all, but not every provider does). */
export async function fetchUserInfo(accessToken) {
  const { userinfo_endpoint: endpoint } = await discover();
  if (!endpoint || !accessToken) return {};
  try {
    return await fetchJson(endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
  } catch (error) {
    // Userinfo is a supplement here; the ID token already carries what is required.
    console.warn('[oidc] userinfo request failed:', error.message);
    return {};
  }
}

/** RP-initiated logout URL, so signing out here also ends the session at the provider. */
export async function buildLogoutUrl({ idToken, redirectTo }) {
  const { end_session_endpoint: endpoint } = await discover();
  if (!endpoint) return null;
  const url = new URL(endpoint);
  if (idToken) url.searchParams.set('id_token_hint', idToken);
  if (redirectTo) url.searchParams.set('post_logout_redirect_uri', redirectTo);
  url.searchParams.set('client_id', config.oidc.clientId);
  return url.toString();
}

/** Maps the provider's `groups` claim onto this app's roles. */
export function roleFromGroups(groups) {
  const names = (Array.isArray(groups) ? groups : []).map((group) => String(group));
  if (names.some((name) => config.oidc.adminGroups.includes(name))) return 'admin';
  if (names.some((name) => config.oidc.staffGroups.includes(name))) return 'staff';
  return 'user';
}

/** Clears cached discovery and keys. Used by tests. */
export function resetOidcCaches() {
  discoveryCache = null;
  jwksCache = null;
}
