import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';

/** Reads a .env file into process.env without overwriting real environment variables. */
export function loadDotEnv(path = resolve(process.cwd(), '.env')) {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i.exec(line);
    if (!match) continue;
    const value = match[2].replace(/^["']|["']$/g, '');
    if (process.env[match[1]] === undefined) process.env[match[1]] = value;
  }
}

loadDotEnv();

/**
 * Reads an environment variable, tolerating what copy-paste into a hosting
 * dashboard adds: surrounding whitespace and a pair of matching quotes.
 */
const env = (name) => {
  const raw = (process.env[name] ?? '').trim();
  const quoted = /^(['"])([\s\S]*)\1$/.exec(raw);
  return quoted ? quoted[2].trim() : raw;
};

const int = (name, fallback) => {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) throw new Error(`${name} must be an integer`);
  return value;
};
const list = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return raw.split(',').map((item) => item.trim()).filter(Boolean);
};
const bool = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
};

export { readCaCert as readCaCertForTest };

function readCaCert(raw) {
  const value = (raw || '').trim();
  if (!value) return '';
  if (value.includes('-----BEGIN CERTIFICATE-----')) return value;
  const decoded = Buffer.from(value, 'base64').toString('utf8').trim();
  if (decoded.includes('-----BEGIN CERTIFICATE-----')) return decoded;
  throw new Error('DATABASE_CA_CERT must be a PEM certificate, or that certificate encoded as base64');
}

// Vercel and similar platforms run the app on a read-only filesystem behind HTTPS.
const serverless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);

export const config = {
  serverless,
  port: int('PORT', 3000),
  host: process.env.HOST || '0.0.0.0',
  databaseUrl: env('DATABASE_URL'),
  // Falls back to an in-memory store so the app can be demoed without PostgreSQL.
  storage: env('DATABASE_URL') ? 'postgres' : 'memory',
  // TLS for the database connection: auto (on for every host but localhost),
  // require, no-verify (accept a self-signed chain), verify-full, or disable.
  databaseSsl: (process.env.DATABASE_SSL || 'auto').toLowerCase(),
  // The provider's CA, so verification can stay on with a private chain. Accepts a
  // PEM or that PEM in base64, because a one-line value survives copy-paste into a
  // hosting dashboard where a multi-line one often does not.
  databaseCaCert: readCaCert(env('DATABASE_CA_CERT')),
  // Serverless instances each hold their own pool, so they must stay small.
  databasePoolMax: int('DATABASE_POOL_MAX', serverless ? 2 : 10),
  keyFile: process.env.SIGNING_KEY_FILE || resolve(process.cwd(), 'data/signing-key.json'),
  passTokenTtl: int('PASS_TOKEN_TTL', 30), // seconds a QR/PDF417 pass stays valid
  passTokenRefresh: int('PASS_TOKEN_REFRESH', 12), // client refresh interval, seconds
  sessionTtl: int('SESSION_TTL', 60 * 60 * 12), // seconds
  secureCookies: bool('SECURE_COOKIES', serverless),
  checkEmailMx: bool('CHECK_EMAIL_MX', true),
  rejectDisposableEmail: bool('REJECT_DISPOSABLE_EMAIL', true),
  clockSkew: int('CLOCK_SKEW', 5), // seconds of tolerance when verifying tokens
  registrationOpen: bool('REGISTRATION_OPEN', true),

  oidc: {
    // Discovery document of the provider. For VoidAuth the issuer is APP_URL + /oidc,
    // e.g. https://auth.example.com/oidc/.well-known/openid-configuration
    issuer: (process.env.OIDC_ISSUER || '').replace(/\/+$/, ''),
    clientId: process.env.OIDC_CLIENT_ID || '',
    clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    // Must match the Redirect URL configured in the provider.
    redirectUri: process.env.OIDC_REDIRECT_URI || '',
    scope: process.env.OIDC_SCOPE || 'openid profile email groups',
    // client_secret_basic is VoidAuth's default; client_secret_post also works.
    authMethod: process.env.OIDC_AUTH_METHOD || 'client_secret_basic',
    // Group names from the `groups` claim that grant elevated roles.
    staffGroups: list('OIDC_STAFF_GROUPS', ['pass-staff']),
    adminGroups: list('OIDC_ADMIN_GROUPS', ['pass-admins']),
    // Link a provider account to an existing local account with the same address.
    // Only ever done for addresses the provider reports as verified.
    linkByEmail: bool('OIDC_LINK_BY_EMAIL', true),
    // Also end the session at the provider on logout (RP-initiated logout).
    rpLogout: bool('OIDC_RP_LOGOUT', true),
    displayName: process.env.OIDC_DISPLAY_NAME || 'VoidAuth',
  },
};

/**
 * Which sign-in methods this deployment offers. Configuring a provider makes OIDC
 * available; AUTH_MODE decides whether the local password form stays alongside it.
 */
config.oidcEnabled = Boolean(config.oidc.issuer && config.oidc.clientId && config.oidc.redirectUri);
config.authMode = (process.env.AUTH_MODE || (config.oidcEnabled ? 'both' : 'local')).toLowerCase();
if (!['local', 'oidc', 'both'].includes(config.authMode)) throw new Error('AUTH_MODE must be local, oidc or both');
if (config.authMode !== 'local' && !config.oidcEnabled) {
  throw new Error('AUTH_MODE requires OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_REDIRECT_URI');
}
config.localAuthEnabled = config.authMode !== 'oidc';

/** Builds a fresh Ed25519 key record. Exported so scripts/genkey.js can print one. */
export function generateSigningKey(kid = 1) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    kid,
    createdAt: new Date().toISOString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

const shape = (record, source) => ({
  kid: record.kid,
  privateKeyPem: record.privateKey,
  publicKeyPem: record.publicKey,
  source,
});

/**
 * Loads the Ed25519 signing key pair. Passes are signed asymmetrically so staff
 * devices can verify them offline with the public key alone.
 *
 * Sources, in order: the SIGNING_KEY environment variable (the only option on a
 * read-only filesystem, and the only way several instances agree on one key), then
 * the key file, then a freshly generated key which is persisted when possible.
 */
export function loadSigningKey() {
  if (process.env.SIGNING_KEY) {
    const raw = env('SIGNING_KEY');
    // The value is what `npm run genkey` prints, not the command itself - a mistake
    // that otherwise surfaces as a JSON parse error full of binary noise.
    const hint = 'SIGNING_KEY must be the output of `npm run genkey` (a base64 string), not the command itself';
    let stored;
    try {
      stored = JSON.parse(raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8'));
    } catch {
      throw new Error(`${hint}. Got ${raw.length} characters starting with "${raw.slice(0, 16)}".`);
    }
    if (!stored?.privateKey || !stored?.publicKey) {
      throw new Error(`${hint}. The value parsed, but has no privateKey/publicKey PEM fields.`);
    }
    return shape({ kid: stored.kid ?? 1, ...stored }, 'env');
  }

  if (existsSync(config.keyFile)) {
    return shape(JSON.parse(readFileSync(config.keyFile, 'utf8')), 'file');
  }

  const record = generateSigningKey();
  try {
    mkdirSync(dirname(config.keyFile), { recursive: true });
    writeFileSync(config.keyFile, JSON.stringify(record, null, 2), { mode: 0o600 });
  } catch (error) {
    // A read-only filesystem is expected on serverless platforms. Every instance then
    // signs with its own key, so passes issued by one are rejected by another.
    console.warn(
      `[config] could not persist the signing key (${error.code}) - using an ephemeral one. ` +
        'Set SIGNING_KEY (see: npm run genkey) to keep passes verifiable across restarts.',
    );
  }
  return shape(record, 'generated');
}
