import { HttpError, readJson, sendJson, parseCookies, serializeCookie, clientIp } from '../lib/http.js';
import { hashPassword, verifyPassword, randomToken, sha256 } from '../lib/crypto.js';
import { checkEmail } from '../lib/email.js';
import { buildLogoutUrl } from '../lib/oidc.js';
import { config } from '../config.js';

export const SESSION_COOKIE = 'sid';
const MIN_PASSWORD_LENGTH = 10;

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: user.role,
    status: user.status,
    lastLoginAt: user.lastLoginAt,
  };
}

export function publicPass(pass) {
  return (
    pass && {
      id: pass.id,
      serial: pass.serial,
      tier: pass.tier,
      status: pass.status,
      validFrom: pass.validFrom,
      validUntil: pass.validUntil,
    }
  );
}

export function passSerial(userId) {
  return `PS-${String(userId).padStart(5, '0')}-${randomToken(3).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 4)}`;
}

export async function startSession(ctx, res, user, req, { idToken = null } = {}) {
  const token = randomToken(32);
  await ctx.store.createSession({
    tokenHash: sha256(token),
    userId: user.id,
    expiresAt: new Date(Date.now() + config.sessionTtl * 1000),
    userAgent: String(req.headers['user-agent'] || '').slice(0, 200),
    ip: clientIp(req),
    idToken,
  });
  res.setHeader(
    'set-cookie',
    serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtl, secure: config.secureCookies }),
  );
}

/** Resolves the signed-in user, or null. */
export async function currentUser(ctx, req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const session = await ctx.store.findSession(sha256(token));
  if (!session) return null;
  const user = await ctx.store.findUserById(session.userId);
  if (!user || user.status !== 'active') return null;
  return user;
}

export async function requireUser(ctx, req) {
  const user = await currentUser(ctx, req);
  if (!user) throw new HttpError(401, 'unauthenticated', 'нужно войти в систему');
  return user;
}

export async function requireStaff(ctx, req) {
  const user = await requireUser(ctx, req);
  if (user.role !== 'staff' && user.role !== 'admin') {
    throw new HttpError(403, 'forbidden', 'нужен доступ сотрудника');
  }
  return user;
}

export async function handleRegister(ctx, req, res) {
  if (!config.localAuthEnabled) {
    throw new HttpError(403, 'local_login_disabled', 'аккаунты заводятся в системе единого входа');
  }
  if (!config.registrationOpen) throw new HttpError(403, 'registration_closed', 'регистрация закрыта');
  const ip = clientIp(req);
  const limit = ctx.limiters.register.check(ip);
  if (!limit.allowed) throw new HttpError(429, 'rate_limited', `слишком много попыток, повторите через ${limit.retryAfter} с`);

  const body = await readJson(req);
  const fullName = String(body.fullName || '').trim();
  const password = String(body.password || '');
  if (fullName.length < 2 || fullName.length > 120) {
    throw new HttpError(400, 'invalid_name', 'имя должно быть от 2 до 120 символов');
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new HttpError(400, 'weak_password', `пароль должен быть не короче ${MIN_PASSWORD_LENGTH} символов`);
  }

  const email = await checkEmail(body.email, {
    checkMx: config.checkEmailMx,
    rejectDisposable: config.rejectDisposableEmail,
  });
  if (!email.valid) throw new HttpError(400, email.reason, describeEmailReason(email.reason));

  const passwordHash = await hashPassword(password);
  let user;
  try {
    user = await ctx.store.createUser({ email: email.email, passwordHash, fullName });
  } catch (error) {
    if (error.code === '23505') throw new HttpError(409, 'email_taken', 'этот email уже зарегистрирован');
    throw error;
  }
  const pass = await ctx.store.createPass({ userId: user.id, serial: passSerial(user.id) });

  await startSession(ctx, res, user, req);
  sendJson(res, 201, { user: publicUser(user), pass: publicPass(pass), emailChecks: email.checks });
}

export async function handleLogin(ctx, req, res) {
  if (!config.localAuthEnabled) {
    throw new HttpError(403, 'local_login_disabled', 'вход по паролю отключён, используйте единый вход');
  }
  const body = await readJson(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const key = `${clientIp(req)}|${email}`;
  const limit = ctx.limiters.login.check(key);
  if (!limit.allowed) throw new HttpError(429, 'rate_limited', `слишком много попыток, повторите через ${limit.retryAfter} с`);

  const user = email ? await ctx.store.findUserByEmail(email) : null;
  const ok = user && user.passwordHash ? await verifyPassword(password, user.passwordHash) : false;
  if (!user || !ok) throw new HttpError(401, 'invalid_credentials', 'неверный email или пароль');
  if (user.status !== 'active') throw new HttpError(403, 'account_suspended', 'аккаунт заблокирован');

  ctx.limiters.login.reset(key);
  await ctx.store.touchLogin(user.id);
  await startSession(ctx, res, user, req);
  const pass = await ctx.store.findPassByUserId(user.id);
  sendJson(res, 200, { user: publicUser({ ...user, lastLoginAt: new Date() }), pass: publicPass(pass) });
}

export async function handleLogout(ctx, req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  let idToken = null;
  if (token) {
    const session = await ctx.store.findSession(sha256(token));
    idToken = session?.idToken ?? null;
    await ctx.store.deleteSession(sha256(token));
  }
  res.setHeader('set-cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0, secure: config.secureCookies }));

  // Ending the local session leaves the provider session alive, so the next sign-in
  // would go straight through. Hand the app a URL that ends it there as well.
  let redirectTo = null;
  if (idToken && config.oidcEnabled && config.oidc.rpLogout) {
    const origin = requestOrigin(req);
    redirectTo = await buildLogoutUrl({ idToken, redirectTo: origin }).catch(() => null);
  }
  sendJson(res, 200, { ok: true, redirectTo });
}

/** Best-effort public origin of this deployment, for provider redirects. */
export function requestOrigin(req) {
  const proto = String(req.headers['x-forwarded-proto'] || (config.secureCookies ? 'https' : 'http')).split(',')[0];
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  return `${proto}://${host}`;
}

export async function handleMe(ctx, req, res) {
  // `server` lets the apps tell the user when a deployment is only good for a demo,
  // and which sign-in methods to offer.
  const server = {
    storage: ctx.store.kind,
    warnings: ctx.warnings ?? [],
    auth: {
      local: config.localAuthEnabled,
      registration: config.localAuthEnabled && config.registrationOpen,
      oidc: config.oidcEnabled ? { displayName: config.oidc.displayName, startUrl: '/api/auth/oidc/start' } : null,
    },
  };
  const user = await currentUser(ctx, req);
  if (!user) return sendJson(res, 200, { user: null, pass: null, server });
  const pass = await ctx.store.findPassByUserId(user.id);
  sendJson(res, 200, { user: publicUser(user), pass: publicPass(pass), server });
}

/** Lets the signup form show email problems before the account is created. */
export async function handleCheckEmail(ctx, req, res) {
  const limit = ctx.limiters.emailCheck.check(clientIp(req));
  if (!limit.allowed) throw new HttpError(429, 'rate_limited', `слишком много попыток, повторите через ${limit.retryAfter} с`);
  const body = await readJson(req);
  const result = await checkEmail(body.email, {
    checkMx: config.checkEmailMx,
    rejectDisposable: config.rejectDisposableEmail,
  });
  sendJson(res, 200, {
    email: result.email,
    valid: result.valid,
    reason: result.reason,
    message: result.reason ? describeEmailReason(result.reason) : null,
    checks: result.checks,
  });
}

function describeEmailReason(reason) {
  switch (reason) {
    case 'invalid_syntax':
      return 'это не похоже на адрес электронной почты';
    case 'disposable_domain':
      return 'одноразовые адреса не принимаются';
    case 'reserved_domain':
      return 'этот домен зарезервирован для примеров и не принимает почту';
    case 'no_mx_record':
      return 'этот домен не принимает почту';
    default:
      return 'адрес отклонён';
  }
}

export { publicUser };
