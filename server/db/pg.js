import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate } from 'node:crypto';

import { config } from '../config.js';

const here = dirname(fileURLToPath(import.meta.url));

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '']);

/** Names the trust anchor in use, so the log says whether DATABASE_CA_CERT arrived. */
export function describeTls(ssl) {
  if (!ssl) return 'off';
  const verified = ssl.rejectUnauthorized !== false;
  if (!verified) return 'on, chain not verified';
  if (!ssl.ca) return 'on, verified against system roots';
  try {
    const subject = new X509Certificate(ssl.ca).subject;
    const cn = /CN=(.+)/.exec(subject)?.[1]?.trim() || subject.replace(/\n/g, ' ');
    return `on, verified against DATABASE_CA_CERT (${cn})`;
  } catch {
    return 'on, but DATABASE_CA_CERT could not be read as a certificate';
  }
}

/** A connection string with the password replaced, safe to print in a log. */
export function redactUrl(databaseUrl) {
  return String(databaseUrl).replace(/^(\w+:\/\/[^:@/]*):[^@]*@/, '$1:***@');
}

/**
 * Validates DATABASE_URL before anything tries to use it.
 *
 * node-postgres accepts a string it cannot parse and quietly falls back to its
 * defaults - which means localhost. On a hosted platform that surfaces much later
 * as ECONNREFUSED 127.0.0.1:5432, with nothing in the message about the variable
 * that is actually wrong.
 */
export function parseDatabaseUrl(databaseUrl) {
  const expected = 'postgres://user:password@host:5432/database';
  let url;
  try {
    url = new URL(databaseUrl);
  } catch {
    const value = String(databaseUrl).trim();
    // A string that already looks like a connection URL but will not parse is
    // almost always a password with a character that needs percent-encoding.
    if (/^postgres(ql)?:\/\//i.test(value)) {
      throw new Error(
        'DATABASE_URL could not be parsed. A password containing @ : / ? # or a space breaks it - ' +
          'percent-encode those characters (@ as %40, : as %3A, / as %2F, ? as %3F, # as %23, space as %20).',
      );
    }
    // The whole shell command pasted into the value, variable name and all.
    const assignment = /^([A-Z_][A-Z0-9_]*)\s*=/i.exec(value);
    if (assignment) {
      throw new Error(
        `DATABASE_URL contains the assignment "${assignment[1]}=..." rather than a value. Set only the URL ` +
          `itself: ${expected} - no variable name, no quotes, no trailing command.`,
      );
    }
    throw new Error(
      `DATABASE_URL is not a connection URL (starts with "${value.slice(0, 24)}"). Expected ${expected} - ` +
        'not a psql command line and not the example from .env.example.',
    );
  }
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) {
    throw new Error(`DATABASE_URL must start with postgres:// or postgresql:// (got ${url.protocol}//). Expected ${expected}`);
  }
  if (!url.hostname) throw new Error(`DATABASE_URL has no host. Expected ${expected}`);
  if (/[[\]]/.test(decodeURIComponent(url.password || ''))) {
    throw new Error('DATABASE_URL still contains the [YOUR-PASSWORD] placeholder - put the real database password there.');
  }
  if (!url.password) throw new Error(`DATABASE_URL has no password. Expected ${expected}`);

  // An unencoded "@" does not fail to parse: the URL splits at the *last* one, so the
  // user and password silently become something else and the server answers with a
  // plain "password authentication failed". Catch it here instead.
  const authority = String(databaseUrl).trim().split('://')[1]?.split('/')[0] ?? '';
  const userinfo = authority.slice(0, authority.lastIndexOf('@'));
  if (userinfo.includes('@')) {
    throw new Error(
      'DATABASE_URL has an unescaped "@" in the user or password, so the string splits in the wrong place. ' +
        'Percent-encode it as %40.',
    );
  }
  if (/\s/.test(String(databaseUrl).trim())) {
    throw new Error('DATABASE_URL contains a space. Percent-encode it as %20, or remove it if it was a stray one.');
  }
  if (url.hash) {
    // Everything after an unescaped '#' is a URL fragment, so the password was cut
    // short there and the rest of the string was silently dropped.
    throw new Error(
      'DATABASE_URL contains an unescaped "#", so the password was cut off at it. ' +
        'Percent-encode it as %23 (and @ as %40, : as %3A, / as %2F, ? as %3F).',
    );
  }

  return {
    host: url.hostname,
    port: url.port || '5432',
    database: url.pathname.replace(/^\//, '') || 'postgres',
    user: decodeURIComponent(url.username || ''),
    passwordLength: decodeURIComponent(url.password).length,
  };
}

/** Turns a driver-level failure into something that names the likely cause. */
export function describeConnectionError(error, target) {
  const where = `${target.host}:${target.port}`;
  const local = LOCAL_HOSTS.has(target.host);
  switch (error.code) {
    case 'ECONNREFUSED':
      return local
        ? `no database is listening on ${where}. DATABASE_URL points at this machine - on a hosted platform ` +
            'it must point at the database provider (for Supabase: Connect -> Connection String -> Session pooler).'
        : `connection to ${where} was refused - check the host and port in DATABASE_URL.`;
    case 'ENETUNREACH':
      return `${where} is unreachable. Supabase's direct endpoint (db.<ref>.supabase.co) is IPv6-only unless the ` +
        'IPv4 add-on is enabled; use the pooler host instead.';
    case 'ENOTFOUND':
      return `host ${target.host} does not resolve - check it for typos.`;
    case 'ETIMEDOUT':
      return `${where} did not answer in time - a firewall or the wrong port.`;
    case '28P01':
      // Supavisor strips the project suffix, so its own message names plain
      // "postgres" - that mismatch is normal and not the problem.
      return `the password for user "${target.user}" was rejected by ${where} ` +
        `(${target.passwordLength} characters were sent). It must be the database password, not the account ` +
        'password; reset it in the provider dashboard if unsure. Percent-encode @ : / ? # and spaces in it.';
    case '3D000':
      return `database "${target.database}" does not exist on ${where}.`;
    case 'SELF_SIGNED_CERT_IN_CHAIN':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
      return target.hasCa
        ? `TLS to ${where} could not be verified: the certificate in DATABASE_CA_CERT does not sign this ` +
            "server's chain. Download the provider's current CA, or set DATABASE_SSL=no-verify to keep " +
            'encryption without checking the chain.'
        : `TLS to ${where} could not be verified against the system roots. Supply the provider's CA in ` +
            'DATABASE_CA_CERT, or set DATABASE_SSL=no-verify to keep encryption without checking the chain.';
    default:
      return `could not connect to ${where} (${error.code || error.message}).`;
  }
}

/**
 * Decides the TLS settings for the connection.
 *
 * Left to itself, node-postgres connects in the clear unless the URL carries an
 * sslmode, which hosted providers refuse - and where an sslmode is given, pg 8
 * treats `require` as `verify-full`, which fails against a private CA such as the
 * one on Supabase's direct connections. Being explicit avoids both traps.
 */
export function resolveSsl(databaseUrl, mode = config.databaseSsl, caCert = config.databaseCaCert) {
  let host = '';
  try {
    host = new URL(databaseUrl).hostname;
  } catch {
    // A libpq keyword string or a socket path, which means a local server.
    host = '';
  }
  const local = LOCAL_HOSTS.has(host) || host.endsWith('.local');
  const effective = mode === 'auto' ? (local ? 'disable' : 'require') : mode;

  switch (effective) {
    case 'disable':
      return false;
    case 'no-verify':
      // Encrypted, but the certificate chain is not checked. For a private CA
      // prefer DATABASE_CA_CERT, which keeps verification on.
      return { rejectUnauthorized: false };
    case 'require':
    case 'verify-full':
      return caCert ? { ca: caCert, rejectUnauthorized: true } : { rejectUnauthorized: true };
    default:
      throw new Error(`DATABASE_SSL must be auto, disable, no-verify, require or verify-full (got ${mode})`);
  }
}

/** PostgreSQL-backed repository. Requires the `pg` package and DATABASE_URL. */
export async function createPostgresStore(databaseUrl) {
  const target = parseDatabaseUrl(databaseUrl);
  const { default: pg } = await import('pg');
  const ssl = resolveSsl(databaseUrl);
  target.hasCa = Boolean(ssl && ssl.ca);
  console.log(
    `[db] connecting to ${target.host}:${target.port}/${target.database} as ${target.user}` +
      ` (TLS: ${describeTls(ssl)})`,
  );

  const pool = new pg.Pool({
    connectionString: databaseUrl,
    max: config.databasePoolMax,
    ssl,
    application_name: 'dynamic-pass',
  });

  try {
    await pool.query(readFileSync(join(here, 'schema.sql'), 'utf8'));
  } catch (error) {
    await pool.end().catch(() => {});
    throw new Error(`[db] ${describeConnectionError(error, target)}`, { cause: error });
  }

  const one = async (text, params) => (await pool.query(text, params)).rows[0] || null;
  const many = async (text, params) => (await pool.query(text, params)).rows;

  const mapUser = (row) =>
    row && {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      fullName: row.full_name,
      role: row.role,
      status: row.status,
      authSource: row.auth_source,
      oidcSub: row.oidc_sub,
      createdAt: row.created_at,
      lastLoginAt: row.last_login_at,
    };

  const mapPass = (row) =>
    row && {
      id: row.id,
      userId: row.user_id,
      serial: row.serial,
      tier: row.tier,
      status: row.status,
      validFrom: row.valid_from,
      validUntil: row.valid_until,
    };

  const mapScan = (row) =>
    row && {
      id: Number(row.id),
      jti: row.jti,
      passId: row.pass_id,
      userId: row.user_id,
      staffId: row.staff_id,
      gate: row.gate,
      result: row.result,
      offline: row.offline,
      issuedAt: row.issued_at,
      scannedAt: row.scanned_at,
      holderName: row.holder_name,
      staffName: row.staff_name,
      passSerial: row.pass_serial,
    };

  return {
    kind: 'postgres',

    async close() {
      await pool.end();
    },

    async createUser({ email, passwordHash = null, fullName, role = 'user', authSource = 'local', oidcSub = null }) {
      return mapUser(
        await one(
          `INSERT INTO users (email, password_hash, full_name, role, auth_source, oidc_sub)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
          [email, passwordHash, fullName, role, authSource, oidcSub],
        ),
      );
    },

    async findUserByOidcSub(sub) {
      return mapUser(await one('SELECT * FROM users WHERE oidc_sub = $1', [sub]));
    },

    /** Links a local account to a provider subject, or refreshes name and role from it. */
    async updateUserFromProvider(userId, { oidcSub, fullName, role, authSource }) {
      return mapUser(
        await one(
          `UPDATE users SET
             oidc_sub    = COALESCE($2, oidc_sub),
             full_name   = COALESCE($3, full_name),
             role        = COALESCE($4, role),
             auth_source = COALESCE($5, auth_source)
           WHERE id = $1 RETURNING *`,
          [userId, oidcSub ?? null, fullName ?? null, role ?? null, authSource ?? null],
        ),
      );
    },

    async findUserByEmail(email) {
      return mapUser(await one('SELECT * FROM users WHERE email = $1', [email]));
    },

    async findUserById(id) {
      return mapUser(await one('SELECT * FROM users WHERE id = $1', [id]));
    },

    async touchLogin(userId) {
      await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [userId]);
    },

    async createPass({ userId, serial, tier = 'standard', validUntil = null }) {
      return mapPass(
        await one(
          `INSERT INTO passes (user_id, serial, tier, valid_until)
           VALUES ($1, $2, $3, $4) RETURNING *`,
          [userId, serial, tier, validUntil],
        ),
      );
    },

    async findPassByUserId(userId) {
      return mapPass(await one('SELECT * FROM passes WHERE user_id = $1', [userId]));
    },

    async findPassById(id) {
      return mapPass(await one('SELECT * FROM passes WHERE id = $1', [id]));
    },

    async setPassStatus(passId, status) {
      return mapPass(await one('UPDATE passes SET status = $2 WHERE id = $1 RETURNING *', [passId, status]));
    },

    async createSession({ tokenHash, userId, expiresAt, userAgent, ip, idToken = null }) {
      await pool.query(
        `INSERT INTO sessions (token_hash, user_id, expires_at, user_agent, ip, id_token)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [tokenHash, userId, expiresAt, userAgent, ip, idToken],
      );
    },

    async findSession(tokenHash) {
      const row = await one(
        `SELECT s.token_hash, s.user_id, s.expires_at, s.id_token FROM sessions s
         WHERE s.token_hash = $1 AND s.expires_at > now()`,
        [tokenHash],
      );
      return row && { userId: row.user_id, expiresAt: row.expires_at, idToken: row.id_token };
    },

    async deleteSession(tokenHash) {
      await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
    },

    async deleteExpiredSessions() {
      const result = await pool.query('DELETE FROM sessions WHERE expires_at <= now()');
      return result.rowCount;
    },

    /**
     * Records a scan. Returns null when the jti was already used, which is how a
     * replayed token is detected.
     */
    async recordScan(scan) {
      const row = await one(
        `INSERT INTO pass_scans (jti, pass_id, user_id, staff_id, gate, result, offline, issued_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (jti) DO NOTHING
         RETURNING *`,
        [
          scan.jti,
          scan.passId ?? null,
          scan.userId ?? null,
          scan.staffId ?? null,
          scan.gate ?? null,
          scan.result,
          scan.offline ?? false,
          scan.issuedAt ? new Date(scan.issuedAt * 1000) : null,
        ],
      );
      return mapScan(row);
    },

    async findScanByJti(jti) {
      return mapScan(await one('SELECT * FROM pass_scans WHERE jti = $1', [jti]));
    },

    async listScansForPass(passId, limit = 20) {
      return (
        await many(
          `SELECT s.*, u.full_name AS staff_name FROM pass_scans s
           LEFT JOIN users u ON u.id = s.staff_id
           WHERE s.pass_id = $1 ORDER BY s.scanned_at DESC LIMIT $2`,
          [passId, limit],
        )
      ).map(mapScan);
    },

    async listRecentScans(limit = 50) {
      return (
        await many(
          `SELECT s.*, h.full_name AS holder_name, p.serial AS pass_serial, st.full_name AS staff_name
           FROM pass_scans s
           LEFT JOIN users h ON h.id = s.user_id
           LEFT JOIN users st ON st.id = s.staff_id
           LEFT JOIN passes p ON p.id = s.pass_id
           ORDER BY s.scanned_at DESC LIMIT $1`,
          [limit],
        )
      ).map(mapScan);
    },
  };
}
