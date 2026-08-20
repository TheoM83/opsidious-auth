#!/usr/bin/env node
// Each suite runs in its own process: lib/config.js and lib/database.js both
// hold module-level state that must not leak between suites.
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const testDir = dirname(fileURLToPath(import.meta.url));
const files = readdirSync(testDir)
  .filter((f) => f.endsWith('.test.js'))
  .sort();

let failed = 0;
const failedFiles = [];

for (const file of files) {
  const res = spawnSync(process.execPath, [join(testDir, file)], {
    stdio: 'inherit',
    cwd: dirname(testDir),
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PUBLIC_URL: process.env.PUBLIC_URL || 'http://localhost:4570',
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || 'test-google-client',
      GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || 'test-google-secret'
    }
  });
  if (res.status !== 0) {
    failed += 1;
    failedFiles.push(file);
  }
}

console.log('\n' + '='.repeat(60));
console.log(`Suites: ${files.length - failed} passed, ${failed} failed, ${files.length} total`);
if (failedFiles.length) console.log('Failed suites:\n  - ' + failedFiles.join('\n  - '));
console.log('='.repeat(60));
process.exit(failed ? 1 : 0);
