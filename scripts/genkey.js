#!/usr/bin/env node
/**
 * Prints a signing key for deployments with a read-only filesystem (Vercel, Lambda,
 * containers). Store the output in the SIGNING_KEY environment variable.
 *
 *   node scripts/genkey.js            # base64, ready to paste into a secret
 *   node scripts/genkey.js --json     # the same key as readable JSON
 */
import { generateSigningKey } from '../server/config.js';

const record = generateSigningKey();
const json = JSON.stringify(record);
console.log(process.argv.includes('--json') ? JSON.stringify(record, null, 2) : Buffer.from(json).toString('base64'));
