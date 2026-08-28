import { HttpError, parseCookies, serializeCookie, clientIp } from '../lib/http.js';
import { startSession, passSerial } from './auth.js';
import {
  buildAuthorizationUrl, createPkce, exchangeCode, fetchUserInfo, roleFromGroups, verifyIdToken, OidcError,
} from '../lib/oidc.js';
import { normalizeEmail } from '../lib/email.js';
import { config } from '../config.js';
import { randomToken } from '../lib/crypto.js';

const TX_COOKIE = 'oidc_tx';
const TX_TTL_SECONDS = 600;

/** Only same-origin paths may be used as a post-login destination. */
function safeNext(value) {
  const next = typeof value === 'string' ? value : '';
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '/';
  return next;
}

function redirect(res, location, cookies = []) {
  const headers = { location, 'cache-control': 'no-store' };
  if (cookies.length) headers['set-cookie'] = cookies;
  res.writeHead(302, headers);
  res.end();
}

function txCookie(value, maxAge) {
  return serializeCookie(TX_COOKIE, value, { maxAge, secure: config.secureCookies, sameSite: 'Lax' });
}

/**
 * Starts single sign-on: remembers state, nonce and the PKCE verifier in a
 * short-lived cookie, then sends the browser to the provider.
 */
export async function handleOidcStart(ctx, req, res) {
  if (!config.oidcEnabled) throw new HttpError(404, 'oidc_disabled', 'единый вход не настроен');

  const url = new URL(req.url, 'http://localhost');
  const transaction = {
    state: randomToken(16),
    nonce: randomToken(16),
    pkce: createPkce(),
    next: safeNext(url.searchParams.get('next')),
    createdAt: Math.floor(Date.now() / 1000),
  };

  const authorizationUrl = await buildAuthorizationUrl({
    state: transaction.state,
    nonce: transaction.nonce,
    challenge: transaction.pkce.challenge,
    prompt: url.searchParams.get('prompt') || undefined,
  });

  ctx.log('oidc start', { ip: clientIp(req), next: transaction.next });
  redirect(res, authorizationUrl, [txCookie(Buffer.from(JSON.stringify(transaction)).toString('base64url'), TX_TTL_SECONDS)]);
}

/**
 * Handles the provider's redirect back: validates state, trades the code for an ID
 * token, resolves the local account and issues this app's own session cookie.
 */
export async function handleOidcCallback(ctx, req, res) {
  if (!config.oidcEnabled) throw new HttpError(404, 'oidc_disabled', 'единый вход не настроен');

  const url = new URL(req.url, 'http://localhost');
  const clear = txCookie('', 0);
  const transaction = readTransaction(req);
  const back = (reason, next = transaction?.next || '/') =>
    redirect(res, `${next}${next.includes('?') ? '&' : '?'}sso_error=${encodeURIComponent(reason)}`, [clear]);

  const providerError = url.searchParams.get('error');
  if (providerError) {
    ctx.log('oidc denied by provider', { error: providerError });
    return back(providerError === 'access_denied' ? 'access_denied' : 'provider_error');
  }
  if (!transaction) return back('expired');
  if (Math.floor(Date.now() / 1000) - transaction.createdAt > TX_TTL_SECONDS) return back('expired');

  const state = url.searchParams.get('state');
  const code = url.searchParams.get('code');
  // The state cookie is what ties this redirect to a login this browser started.
  if (!state || state !== transaction.state) return back('state_mismatch');
  if (!code) return back('no_code');

  let claims;
  let tokens;
  try {
    tokens = await exchangeCode({ code, verifier: transaction.pkce.verifier });
    claims = await verifyIdToken(tokens.id_token, { nonce: transaction.nonce });
    if (!claims.email || claims.groups === undefined) {
      claims = { ...(await fetchUserInfo(tokens.access_token)), ...claims };
    }
  } catch (error) {
    if (error instanceof OidcError) {
      ctx.log('oidc exchange failed', { code: error.code, message: error.message });
      return back(error.code);
    }
    throw error;
  }

  let user;
  try {
    user = await resolveUser(ctx, claims);
  } catch (error) {
    if (error instanceof HttpError) {
      ctx.log('oidc login refused', { code: error.code });
      return back(error.code);
    }
    throw error;
  }

  await ctx.store.touchLogin(user.id);
  await startSession(ctx, res, user, req, { idToken: tokens.id_token });
  res.setHeader('set-cookie', [...[].concat(res.getHeader('set-cookie') || []), clear]);
  ctx.log('oidc login', { userId: user.id, role: user.role, sub: claims.sub });

  redirect(res, transaction.next);
}

function readTransaction(req) {
  const raw = parseCookies(req)[TX_COOKIE];
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    return parsed?.state && parsed?.nonce && parsed?.pkce?.verifier ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Finds or creates the local account behind a set of provider claims, and keeps the
 * name and role in step with the provider on every sign-in - so removing someone
 * from the staff group there takes their scanner access away here.
 */
async function resolveUser(ctx, claims) {
  const role = roleFromGroups(claims.groups);
  const fullName = String(claims.name || claims.preferred_username || claims.email || 'Пользователь').slice(0, 120);
  const email = normalizeEmail(claims.email || '');

  let user = await ctx.store.findUserByOidcSub(claims.sub);

  if (!user && email) {
    const existing = await ctx.store.findUserByEmail(email);
    if (existing) {
      // Linking by address is only safe when the provider vouches for the address;
      // otherwise anyone able to set an email at the provider could take an account.
      if (!config.oidc.linkByEmail || claims.email_verified !== true) {
        throw new HttpError(409, 'email_conflict', 'этот email уже занят локальным аккаунтом');
      }
      // An existing password is left in place: with AUTH_MODE=both the holder may
      // keep using it. Switching AUTH_MODE to oidc is what closes that door.
      user = await ctx.store.updateUserFromProvider(existing.id, {
        oidcSub: claims.sub,
        fullName,
        role,
        authSource: 'oidc',
      });
      ctx.log('oidc linked existing account', { userId: user.id });
    }
  }

  if (!user) {
    if (!email) throw new HttpError(400, 'no_email', 'провайдер не передал email');
    user = await ctx.store.createUser({
      email,
      passwordHash: null,
      fullName,
      role,
      authSource: 'oidc',
      oidcSub: claims.sub,
    });
    await ctx.store.createPass({ userId: user.id, serial: passSerial(user.id) });
    ctx.log('oidc created account', { userId: user.id, role });
  } else if (user.fullName !== fullName || user.role !== role) {
    user = await ctx.store.updateUserFromProvider(user.id, { fullName, role });
  }

  if (user.status !== 'active') throw new HttpError(403, 'account_suspended', 'аккаунт заблокирован');
  return user;
}
