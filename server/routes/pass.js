import { HttpError, sendJson, clientIp } from '../lib/http.js';
import { requireUser, publicPass } from './auth.js';
import { config } from '../config.js';

const PASS_STATUS = { suspended: 'пропуск приостановлен', revoked: 'пропуск аннулирован' };

/** The holder's own pass, plus where it was last used. */
export async function handleGetPass(ctx, req, res) {
  const user = await requireUser(ctx, req);
  const pass = await ctx.store.findPassByUserId(user.id);
  if (!pass) throw new HttpError(404, 'no_pass', 'к аккаунту не привязан пропуск');
  const scans = await ctx.store.listScansForPass(pass.id, 10);
  sendJson(res, 200, {
    pass: publicPass(pass),
    holder: { id: user.id, fullName: user.fullName, email: user.email },
    recentScans: scans.map(publicScan),
    tokenTtl: config.passTokenTtl,
    refreshEvery: config.passTokenRefresh,
  });
}

/**
 * Issues a fresh short-lived pass token. The PWA calls this every few seconds; the
 * token is what gets rendered as a QR and PDF417 symbol.
 */
export async function handleIssueToken(ctx, req, res) {
  const user = await requireUser(ctx, req);
  const limit = ctx.limiters.token.check(`${user.id}`);
  if (!limit.allowed) throw new HttpError(429, 'rate_limited', `слишком часто, повторите через ${limit.retryAfter} с`);

  const pass = await ctx.store.findPassByUserId(user.id);
  if (!pass) throw new HttpError(404, 'no_pass', 'к аккаунту не привязан пропуск');
  if (pass.status !== 'active') throw new HttpError(403, 'pass_' + pass.status, PASS_STATUS[pass.status] || `пропуск: ${pass.status}`);

  const now = Date.now();
  if (pass.validUntil && new Date(pass.validUntil).getTime() < now) {
    throw new HttpError(403, 'pass_expired', 'срок действия пропуска истёк');
  }
  if (pass.validFrom && new Date(pass.validFrom).getTime() > now) {
    throw new HttpError(403, 'pass_not_active_yet', 'пропуск ещё не активен');
  }

  const issued = ctx.signer.issue({ passId: pass.id, userId: user.id, ttl: config.passTokenTtl });
  ctx.log('token issued', { userId: user.id, passId: pass.id, ip: clientIp(req) });
  sendJson(res, 200, {
    token: issued.token,
    issuedAt: issued.issuedAt,
    expiresAt: issued.expiresAt,
    ttl: config.passTokenTtl,
    refreshEvery: config.passTokenRefresh,
    serverTime: Math.floor(now / 1000),
  });
}

export async function handleHistory(ctx, req, res) {
  const user = await requireUser(ctx, req);
  const pass = await ctx.store.findPassByUserId(user.id);
  if (!pass) throw new HttpError(404, 'no_pass', 'к аккаунту не привязан пропуск');
  const scans = await ctx.store.listScansForPass(pass.id, 50);
  sendJson(res, 200, { scans: scans.map(publicScan) });
}

/** The Ed25519 public key, so staff devices can verify tokens while offline. */
export function handlePublicKey(ctx, req, res) {
  sendJson(
    res,
    200,
    { keys: [ctx.signer.publicJwk()], tokenTtl: config.passTokenTtl, clockSkew: config.clockSkew },
    { 'cache-control': 'public, max-age=300' },
  );
}

export function publicScan(scan) {
  return {
    id: scan.id,
    result: scan.result,
    gate: scan.gate,
    offline: scan.offline,
    scannedAt: scan.scannedAt,
    staffName: scan.staffName ?? null,
    holderName: scan.holderName ?? null,
    passSerial: scan.passSerial ?? null,
  };
}
