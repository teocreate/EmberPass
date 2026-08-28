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

const int = (name, fallback) => {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) throw new Error(`${name} must be an integer`);
  return value;
};
const bool = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
};

// Vercel and similar platforms run the app on a read-only filesystem behind HTTPS.
const serverless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);

export const config = {
  serverless,
  port: int('PORT', 3000),
  host: process.env.HOST || '0.0.0.0',
  databaseUrl: process.env.DATABASE_URL || '',
  // Falls back to an in-memory store so the app can be demoed without PostgreSQL.
  storage: process.env.DATABASE_URL ? 'postgres' : 'memory',
  keyFile: process.env.SIGNING_KEY_FILE || resolve(process.cwd(), 'data/signing-key.json'),
  passTokenTtl: int('PASS_TOKEN_TTL', 30), // seconds a QR/PDF417 pass stays valid
  passTokenRefresh: int('PASS_TOKEN_REFRESH', 12), // client refresh interval, seconds
  sessionTtl: int('SESSION_TTL', 60 * 60 * 12), // seconds
  secureCookies: bool('SECURE_COOKIES', serverless),
  checkEmailMx: bool('CHECK_EMAIL_MX', true),
  rejectDisposableEmail: bool('REJECT_DISPOSABLE_EMAIL', true),
  clockSkew: int('CLOCK_SKEW', 5), // seconds of tolerance when verifying tokens
  registrationOpen: bool('REGISTRATION_OPEN', true),
};

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

const shape = (record) => ({ kid: record.kid, privateKeyPem: record.privateKey, publicKeyPem: record.publicKey });

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
    const raw = process.env.SIGNING_KEY.trim();
    const json = raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
    const stored = JSON.parse(json);
    if (!stored.privateKey || !stored.publicKey) {
      throw new Error('SIGNING_KEY must contain privateKey and publicKey PEM values');
    }
    return shape({ kid: stored.kid ?? 1, ...stored });
  }

  if (existsSync(config.keyFile)) {
    return shape(JSON.parse(readFileSync(config.keyFile, 'utf8')));
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
  return shape(record);
}
