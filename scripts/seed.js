#!/usr/bin/env node
/**
 * Creates demo accounts: one pass holder and one staff member.
 * Usage: node scripts/seed.js [--password <pw>]
 */
import { getStore, closeStore } from '../server/db/index.js';
import { hashPassword, randomToken } from '../server/lib/crypto.js';
import { config } from '../server/config.js';

const args = process.argv.slice(2);
const password = args.includes('--password') ? args[args.indexOf('--password') + 1] : 'demo-password-123';

const DEMO = [
  { email: 'holder@example.com', fullName: 'Иван Держатель', role: 'user', withPass: true },
  { email: 'staff@example.com', fullName: 'Ольга Контролёр', role: 'staff', withPass: false },
  { email: 'admin@example.com', fullName: 'Админ Системы', role: 'admin', withPass: false },
];

const store = await getStore();
if (store.kind === 'memory') {
  console.warn('DATABASE_URL is not set: seeding the in-memory store has no lasting effect.');
}

for (const person of DEMO) {
  const existing = await store.findUserByEmail(person.email);
  if (existing) {
    console.log(`- ${person.email} already exists (id ${existing.id}, role ${existing.role})`);
    continue;
  }
  const user = await store.createUser({
    email: person.email,
    passwordHash: await hashPassword(password),
    fullName: person.fullName,
    role: person.role,
  });
  let pass = null;
  if (person.withPass) {
    pass = await store.createPass({
      userId: user.id,
      serial: `PS-${String(user.id).padStart(5, '0')}-${randomToken(3).replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 4)}`,
      tier: 'standard',
    });
  }
  console.log(`+ ${person.email} (${person.role})${pass ? ` pass ${pass.serial}` : ''}`);
}

console.log(`\nStorage: ${store.kind}`);
console.log(`Password for all demo accounts: ${password}`);
console.log(`Pass token TTL: ${config.passTokenTtl}s`);
await closeStore();
