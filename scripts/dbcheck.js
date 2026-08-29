#!/usr/bin/env node
/**
 * Checks a database connection and says what is wrong if it fails, without starting
 * the application. Faster than a deploy when working out a connection string.
 *
 *   DATABASE_URL="postgres://..." npm run dbcheck
 */
import { config } from '../server/config.js';
import { parseDatabaseUrl, resolveSsl, describeConnectionError, describeTls, redactUrl } from '../server/db/pg.js';

if (!config.databaseUrl) {
  console.error('DATABASE_URL is not set. Pass it in the environment:\n  DATABASE_URL="postgres://..." npm run dbcheck');
  process.exit(2);
}

let target;
try {
  target = parseDatabaseUrl(config.databaseUrl);
} catch (error) {
  console.error(`✗ ${error.message}`);
  process.exit(1);
}

const ssl = resolveSsl(config.databaseUrl);
target.hasCa = Boolean(ssl && ssl.ca);
console.log(`url      ${redactUrl(config.databaseUrl)}`);
console.log(`host     ${target.host}:${target.port}`);
console.log(`database ${target.database}`);
console.log(`user     ${target.user} (password: ${target.passwordLength} characters)`);
console.log(`tls      ${describeTls(ssl)}`);
console.log('');

const { default: pg } = await import('pg');
const client = new pg.Client({ connectionString: config.databaseUrl, ssl, application_name: 'dynamic-pass-check' });

try {
  await client.connect();
  const { rows } = await client.query('SELECT current_user, current_database(), version()');
  console.log(`✓ connected as ${rows[0].current_user} to ${rows[0].current_database}`);
  console.log(`  ${rows[0].version.split(' on ')[0]}`);

  const { rows: tables } = await client.query(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name IN ('users', 'passes', 'sessions', 'pass_scans')
     ORDER BY table_name`,
  );
  console.log(
    tables.length
      ? `  schema present: ${tables.map((row) => row.table_name).join(', ')}`
      : '  schema not created yet - it is applied on the first application start',
  );
  await client.end();
  process.exit(0);
} catch (error) {
  console.error(`✗ ${describeConnectionError(error, target)}`);
  await client.end().catch(() => {});
  process.exit(1);
}
