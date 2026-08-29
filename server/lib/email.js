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

// RFC 2606 / RFC 6761 keep these for documentation and testing: mail to them can
// never be delivered, whatever DNS happens to answer. example.com in particular does
// publish an MX record, so an MX check alone lets it through.
const RESERVED_DOMAINS = new Set(['example.com', 'example.net', 'example.org', 'example.edu']);
// .local is deliberately absent: it is mDNS scope, but self-hosted installations do
// use it for internal addresses, and this product gets deployed inside organisations.
const RESERVED_SUFFIXES = ['.example', '.invalid', '.test', '.localhost'];

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
  const checks = { syntax: false, disposable: false, role: false, reserved: false, mx: null };

  if (!SYNTAX.test(email) || email.length > 254) {
    return { valid: false, reason: 'invalid_syntax', checks, email };
  }
  checks.syntax = true;

  const [local, domain] = email.split('@');
  checks.disposable = DISPOSABLE_DOMAINS.has(domain);
  checks.role = ROLE_ACCOUNTS.has(local.split('+')[0]);
  checks.reserved = RESERVED_DOMAINS.has(domain) || RESERVED_SUFFIXES.some((suffix) => domain.endsWith(suffix));

  if (checks.reserved) {
    return { valid: false, reason: 'reserved_domain', checks, email };
  }
  if (rejectDisposable && checks.disposable) {
    return { valid: false, reason: 'disposable_domain', checks, email };
  }

  if (checkMx) {
    try {
      const records = await withTimeout(resolveMx(domain), timeoutMs);
      // RFC 7505: a single MX with an empty exchange is a "null MX" - the domain says
      // outright that it accepts no mail. example.com publishes exactly that, which is
      // why counting records alone let it through.
      checks.mx = records.some((record) => record.exchange && record.exchange !== '.');
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
