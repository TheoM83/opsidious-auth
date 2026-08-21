#!/usr/bin/env node
// Registers an application and prints its secret exactly once. There is no way
// to recover it afterwards - only its hash is stored.
//
// THIS WRITES DIRECTLY TO WHATEVER DATABASE THE ENVIRONMENT POINTS AT. There
// is no dry-run mode and no confirmation prompt - it is a single INSERT, run
// with the same DB_PATH / environment as the server itself. Run it against a
// production database only when you mean to register a production client;
// running it by habit, or against the wrong .env, silently creates a real
// client with a real secret in a real database.
//
//   npm run register-client -- defnote "Defnote" https://defnote.opsidious.com/auth/callback
//
// Inside the running container:
//
//   docker exec -it opsidious-auth node scripts/register-client.mjs defnote "Defnote" https://defnote.opsidious.com/auth/callback
import { initDatabase, closeDatabase } from '../lib/database.js';
import { createClient } from '../lib/clients.js';
import { DB_PATH } from '../lib/config.js';

const [id, name, ...redirectUris] = process.argv.slice(2);

if (!id || !name || redirectUris.length === 0) {
  console.error('usage: npm run register-client -- <client_id> <name> <redirect_uri> [redirect_uri...]');
  process.exit(1);
}

// Named plainly, before anything is written, so it is never ambiguous which
// database is about to get a new row - DB_PATH is what decides that, and an
// empty value here means the process-default path under ./data.
console.error(`target database: ${DB_PATH || '(default: ./data/opsidious-auth.db)'}`);

await initDatabase();
try {
  const { secret } = await createClient({ id, name, redirectUris });
  console.log('');
  console.log(`  client_id      ${id}`);
  console.log(`  client_secret  ${secret}`);
  console.log('');
  console.log('  This secret is shown ONCE, right now, and never again. Only its hash is');
  console.log('  stored - there is no "forgot secret" recovery. Copy it into the client');
  console.log("  application's configuration before closing this terminal.");
  console.log(`  Redirect URIs are matched EXACTLY - a trailing slash is a different URI:`);
  for (const uri of redirectUris) console.log(`    ${uri}`);
  console.log('');
} catch (err) {
  console.error(`registration failed: ${err.message}`);
  process.exitCode = 1;
} finally {
  await closeDatabase();
}
