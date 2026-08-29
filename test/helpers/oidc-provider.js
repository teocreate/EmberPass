import { createServer } from 'node:http';
import { generateKeyPairSync, createHash, randomBytes, sign as signData } from 'node:crypto';

const b64 = (input) => Buffer.from(input).toString('base64url');

/**
 * A stand-in OpenID Connect provider that mirrors the parts of VoidAuth this app
 * relies on: an issuer at <base>/oidc, RS256 ID tokens, a JWKS endpoint, PKCE, and
 * `groups` as an array of names. Handy knobs let a test bend one thing at a time.
 */
export async function startStubProvider() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'stub-key-1';
  const codes = new Map();

  const state = {
    user: {
      sub: 'void-user-1',
      email: 'holder@example.com',
      email_verified: true,
      name: 'Иван Держатель',
      preferred_username: 'ivan',
      groups: ['everyone'],
    },
    // Test hooks: tamper with the issued token or claims.
    claimsOverride: null,
    signWithWrongKey: false,
    expiresIn: 300,
    lastAuthRequest: null,
  };

  function signIdToken(claims) {
    const header = b64(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
    const payload = b64(JSON.stringify(claims));
    const key = state.signWithWrongKey ? generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey : privateKey;
    const signature = signData('RSA-SHA256', Buffer.from(`${header}.${payload}`), key);
    return `${header}.${payload}.${signature.toString('base64url')}`;
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const json = (status, body) => {
      const text = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
      res.end(text);
    };

    if (url.pathname === '/oidc/.well-known/openid-configuration') {
      return json(200, {
        issuer: `${state.base}/oidc`,
        authorization_endpoint: `${state.base}/oidc/auth`,
        token_endpoint: `${state.base}/oidc/token`,
        userinfo_endpoint: `${state.base}/oidc/me`,
        jwks_uri: `${state.base}/oidc/jwks`,
        end_session_endpoint: `${state.base}/oidc/session/end`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        scopes_supported: ['openid', 'profile', 'email', 'groups', 'offline_access'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      });
    }

    if (url.pathname === '/oidc/jwks') {
      const jwk = publicKey.export({ format: 'jwk' });
      return json(200, { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
    }

    if (url.pathname === '/oidc/auth') {
      const params = Object.fromEntries(url.searchParams);
      state.lastAuthRequest = params;
      if (params.response_type !== 'code') return json(400, { error: 'unsupported_response_type' });
      if (params.client_id !== state.clientId) return json(400, { error: 'invalid_client' });
      if (params.code_challenge_method !== 'S256' || !params.code_challenge) {
        return json(400, { error: 'invalid_request', error_description: 'PKCE required' });
      }
      const code = randomBytes(16).toString('hex');
      codes.set(code, { challenge: params.code_challenge, nonce: params.nonce, scope: params.scope });
      const back = new URL(params.redirect_uri);
      back.searchParams.set('code', code);
      if (params.state) back.searchParams.set('state', params.state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }

    if (url.pathname === '/oidc/token') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));

      const header = String(req.headers.authorization || '');
      const basic = header.startsWith('Basic ') ? Buffer.from(header.slice(6), 'base64').toString('utf8') : '';
      const [basicId, basicSecret] = basic.split(':').map((part) => decodeURIComponent(part || ''));
      const clientId = basicId || body.client_id;
      const clientSecret = basicSecret || body.client_secret;
      if (clientId !== state.clientId || clientSecret !== state.clientSecret) {
        return json(401, { error: 'invalid_client', error_description: 'client authentication failed' });
      }

      const pending = codes.get(body.code);
      if (!pending) return json(400, { error: 'invalid_grant', error_description: 'unknown code' });
      codes.delete(body.code); // authorization codes are single use
      const verifierHash = b64(createHash('sha256').update(String(body.code_verifier || '')).digest());
      if (verifierHash !== pending.challenge) {
        return json(400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }

      const now = Math.floor(Date.now() / 1000);
      const claims = state.claimsOverride || {
        iss: `${state.base}/oidc`,
        aud: state.clientId,
        sub: state.user.sub,
        iat: now,
        exp: now + state.expiresIn,
        nonce: pending.nonce,
        email: state.user.email,
        email_verified: state.user.email_verified,
        name: state.user.name,
        preferred_username: state.user.preferred_username,
        groups: state.user.groups,
      };
      return json(200, {
        access_token: `stub-access-${randomBytes(8).toString('hex')}`,
        token_type: 'Bearer',
        expires_in: state.expiresIn,
        id_token: signIdToken(claims),
        scope: pending.scope,
      });
    }

    if (url.pathname === '/oidc/me') {
      return json(200, { sub: state.user.sub, ...state.user });
    }

    if (url.pathname === '/oidc/session/end') {
      return json(200, { ended: true, id_token_hint: url.searchParams.get('id_token_hint') ? 'present' : 'absent' });
    }

    return json(404, { error: 'not_found' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  state.base = `http://127.0.0.1:${server.address().port}`;
  state.clientId = 'pass-app';
  state.clientSecret = 'pass-app-secret';
  state.issuer = `${state.base}/oidc`;
  state.close = () => new Promise((resolve) => server.close(resolve));
  return state;
}
