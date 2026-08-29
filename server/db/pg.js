import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { config } from '../config.js';

const here = dirname(fileURLToPath(import.meta.url));

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '']);

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
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    max: config.databasePoolMax,
    ssl: resolveSsl(databaseUrl),
    application_name: 'dynamic-pass',
  });
  await pool.query(readFileSync(join(here, 'schema.sql'), 'utf8'));

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
