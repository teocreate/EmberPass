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

export const config = {
  port: int('PORT', 3000),
  host: process.env.HOST || '0.0.0.0',
  databaseUrl: process.env.DATABASE_URL || '',
  // Falls back to an in-memory store so the app can be demoed without PostgreSQL.
  storage: process.env.DATABASE_URL ? 'postgres' : 'memory',
  keyFile: process.env.SIGNING_KEY_FILE || resolve(process.cwd(), 'data/signing-key.json'),
  passTokenTtl: int('PASS_TOKEN_TTL', 30), // seconds a QR/PDF417 pass stays valid
  passTokenRefresh: int('PASS_TOKEN_REFRESH', 12), // client refresh interval, seconds
  sessionTtl: int('SESSION_TTL', 60 * 60 * 12), // seconds
  secureCookies: bool('SECURE_COOKIES', false),
  checkEmailMx: bool('CHECK_EMAIL_MX', true),
  rejectDisposableEmail: bool('REJECT_DISPOSABLE_EMAIL', true),
  clockSkew: int('CLOCK_SKEW', 5), // seconds of tolerance when verifying tokens
  registrationOpen: bool('REGISTRATION_OPEN', true),
};

/**
 * Loads the Ed25519 signing key pair, generating and persisting one on first run.
 * Passes are signed asymmetrically so staff devices can verify them offline with
 * the public key alone.
 */
export function loadSigningKey() {
  if (existsSync(config.keyFile)) {
    const stored = JSON.parse(readFileSync(config.keyFile, 'utf8'));
    return { kid: stored.kid, privateKeyPem: stored.privateKey, publicKeyPem: stored.publicKey };
  }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const record = {
    kid: 1,
    createdAt: new Date().toISOString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  };
  mkdirSync(dirname(config.keyFile), { recursive: true });
  writeFileSync(config.keyFile, JSON.stringify(record, null, 2), { mode: 0o600 });
  return { kid: record.kid, privateKeyPem: record.privateKey, publicKeyPem: record.publicKey };
}
