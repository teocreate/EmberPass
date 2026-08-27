import { HttpError, readJson, sendJson } from '../lib/http.js';
import { requireStaff } from './auth.js';
import { publicScan } from './pass.js';
import { verifyPassToken } from '../lib/token.js';
import { config } from '../config.js';

/**
 * Verifies a scanned pass token.
 *
 * Signature and lifetime are checked first, then the pass and holder are looked up,
 * and finally the token's jti is claimed in PostgreSQL. The unique index on jti is
 * what makes the token single-use: a replay collides with the original scan's row.
 */
export async function handleVerify(ctx, req, res) {
  const staff = await requireStaff(ctx, req);
  const limit = ctx.limiters.verify.check(`${staff.id}`);
  if (!limit.allowed) throw new HttpError(429, 'rate_limited', `too many scans, retry in ${limit.retryAfter}s`);

  const body = await readJson(req);
  const gate = body.gate ? String(body.gate).slice(0, 64) : null;
  const offline = Boolean(body.offline);
  const token = String(body.token || '').trim();

  const parsed = verifyPassToken(token, {
    publicKey: ctx.signer.publicKey,
    kid: ctx.signer.kid,
    clockSkew: config.clockSkew,
  });

  if (!parsed.ok && !parsed.payload) {
    // Nothing trustworthy to log against a pass; record the attempt only.
    await ctx.store.recordScan({ jti: null, staffId: staff.id, gate, result: `denied_${parsed.reason}`, offline });
    return sendJson(res, 200, deny(parsed.reason, 'This code is not a valid pass'));
  }

  const payload = parsed.payload;
  const pass = await ctx.store.findPassById(payload.passId);
  const holder = await ctx.store.findUserById(payload.userId);

  const problem = evaluate(parsed, pass, holder, payload);
  const result = problem ? `denied_${problem.reason}` : 'granted';

  const recorded = await ctx.store.recordScan({
    jti: payload.jti,
    passId: pass?.id ?? null,
    userId: holder?.id ?? null,
    staffId: staff.id,
    gate,
    result,
    offline,
    issuedAt: payload.issuedAt,
  });

  if (!recorded) {
    const original = await ctx.store.findScanByJti(payload.jti);
    return sendJson(res, 200, {
      status: 'denied',
      reason: 'already_used',
      message: 'This pass code was already scanned',
      previousScan: original ? publicScan(original) : null,
      holder: holder ? { fullName: holder.fullName } : null,
      pass: pass ? { serial: pass.serial, tier: pass.tier } : null,
    });
  }

  if (problem) {
    ctx.log('scan denied', { staffId: staff.id, reason: problem.reason, passId: payload.passId });
    return sendJson(res, 200, {
      ...deny(problem.reason, problem.message),
      holder: holder ? { fullName: holder.fullName } : null,
      pass: pass ? { serial: pass.serial, tier: pass.tier, status: pass.status } : null,
      scan: publicScan(recorded),
    });
  }

  ctx.log('scan granted', { staffId: staff.id, passId: pass.id, gate });
  sendJson(res, 200, {
    status: 'granted',
    reason: null,
    message: 'Access granted',
    holder: { fullName: holder.fullName, email: holder.email },
    pass: { serial: pass.serial, tier: pass.tier, status: pass.status, validUntil: pass.validUntil },
    scan: publicScan(recorded),
    tokenAge: Math.floor(Date.now() / 1000) - payload.issuedAt,
  });
}

function evaluate(parsed, pass, holder, payload) {
  if (!parsed.ok) return { reason: parsed.reason, message: messageFor(parsed.reason) };
  if (!pass) return { reason: 'unknown_pass', message: 'This pass no longer exists' };
  if (!holder) return { reason: 'unknown_holder', message: 'The pass holder no longer exists' };
  if (pass.userId !== payload.userId) return { reason: 'pass_mismatch', message: 'Pass does not belong to this holder' };
  if (pass.status !== 'active') return { reason: `pass_${pass.status}`, message: `Pass is ${pass.status}` };
  if (holder.status !== 'active') return { reason: 'holder_suspended', message: 'Pass holder is suspended' };

  const now = Date.now();
  if (pass.validUntil && new Date(pass.validUntil).getTime() < now) {
    return { reason: 'pass_expired', message: 'Pass validity period has ended' };
  }
  if (pass.validFrom && new Date(pass.validFrom).getTime() > now) {
    return { reason: 'pass_not_active_yet', message: 'Pass is not valid yet' };
  }
  return null;
}

function messageFor(reason) {
  switch (reason) {
    case 'expired':
      return 'This code has expired - ask for a fresh one';
    case 'not_yet_valid':
      return 'This code is not valid yet (device clock out of sync?)';
    case 'bad_signature':
      return 'Signature does not match - possible forgery';
    case 'unknown_key':
      return 'Signed with an unknown key';
    case 'unsupported_version':
      return 'Unsupported pass format';
    default:
      return 'This code is not a valid pass';
  }
}

function deny(reason, message) {
  return { status: 'denied', reason, message };
}

export async function handleRecentScans(ctx, req, res) {
  await requireStaff(ctx, req);
  const url = new URL(req.url, 'http://localhost');
  const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get('limit') || '50', 10) || 50));
  const scans = await ctx.store.listRecentScans(limit);
  sendJson(res, 200, { scans: scans.map(publicScan) });
}
