import { resolveMx } from 'node:dns/promises';

/**
 * Email checks in the spirit of reacherhq/check-if-email-exists: syntax, disposable
 * domains, role accounts and a real MX lookup. SMTP mailbox probing is deliberately
 * left out - it is unreliable from most networks and gets the sender blocklisted.
 */

// RFC 5322 in full is not worth it here; this covers the addresses people actually type.
const SYNTAX = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

const DISPOSABLE_DOMAINS = new Set([
  '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.com', 'temp-mail.org',
  'yopmail.com', 'throwawaymail.com', 'trashmail.com', 'getnada.com', 'sharklasers.com',
  'dispostable.com', 'fakeinbox.com', 'maildrop.cc', 'mintemail.com', 'spamgourmet.com',
  'mailnesia.com', 'tempinbox.com', 'emailondeck.com', 'burnermail.io', 'moakt.com',
]);

const ROLE_ACCOUNTS = new Set([
  'admin', 'administrator', 'billing', 'contact', 'info', 'help', 'hostmaster', 'mail',
  'marketing', 'noreply', 'no-reply', 'postmaster', 'root', 'sales', 'security', 'support',
  'sysadmin', 'webmaster', 'abuse',
]);

export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

const withTimeout = (promise, ms) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error('dns timeout')), ms))]);

/**
 * @returns {Promise<{valid: boolean, reason: string|null, checks: object, email: string}>}
 */
export async function checkEmail(rawEmail, { checkMx = true, rejectDisposable = true, timeoutMs = 3000 } = {}) {
  const email = normalizeEmail(rawEmail);
  const checks = { syntax: false, disposable: false, role: false, mx: null };

  if (!SYNTAX.test(email) || email.length > 254) {
    return { valid: false, reason: 'invalid_syntax', checks, email };
  }
  checks.syntax = true;

  const [local, domain] = email.split('@');
  checks.disposable = DISPOSABLE_DOMAINS.has(domain);
  checks.role = ROLE_ACCOUNTS.has(local.split('+')[0]);

  if (rejectDisposable && checks.disposable) {
    return { valid: false, reason: 'disposable_domain', checks, email };
  }

  if (checkMx) {
    try {
      const records = await withTimeout(resolveMx(domain), timeoutMs);
      checks.mx = records.length > 0;
      if (!checks.mx) return { valid: false, reason: 'no_mx_record', checks, email };
    } catch (error) {
      // ENOTFOUND/ENODATA mean the domain cannot receive mail; anything else (timeout,
      // no resolver in the sandbox) is inconclusive and must not block a signup.
      if (['ENOTFOUND', 'ENODATA', 'NXDOMAIN'].includes(error.code)) {
        checks.mx = false;
        return { valid: false, reason: 'no_mx_record', checks, email };
      }
      checks.mx = null;
    }
  }

  return { valid: true, reason: null, checks, email };
}
