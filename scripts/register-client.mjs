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

// `--secret-only` prints the secret and nothing else on stdout, so a caller can
// capture it without the surrounding explanation. It exists for the
// registration workflow, which masks what it captures and writes it straight
// into the consuming repository's secrets - a secret that is never rendered is
// a secret nobody has to remember not to paste somewhere.
const argv = process.argv.slice(2);
const secretOnly = argv.includes('--secret-only');
// A public client cannot hold a secret: an installed application would carry
// it in its binary on every user's machine. It proves itself with PKCE.
const isPublic = argv.includes('--public');
const [id, name, ...redirectUris] = argv.filter((a) => a !== '--secret-only' && a !== '--public');

if (!id || !name || redirectUris.length === 0) {
  console.error(
    'usage: npm run register-client -- [--secret-only] [--public] <client_id> <name> <redirect_uri> [redirect_uri...]'
  );
  process.exit(1);
}

if (isPublic && secretOnly) {
  console.error('--public and --secret-only are contradictory: a public client has no secret');
  process.exit(1);
}

// Named plainly, before anything is written, so it is never ambiguous which
// database is about to get a new row - DB_PATH is what decides that, and an
// empty value here means the process-default path under ./data.
console.error(`target database: ${DB_PATH || '(default: ./data/opsidious-auth.db)'}`);

await initDatabase();
try {
  const { secret } = await createClient({ id, name, redirectUris, isPublic });

  if (isPublic) {
    console.log('');
    console.log(`  client_id      ${id}`);
    console.log('  client_secret  (none - this is a public client)');
    console.log('');
    console.log('  It authenticates with PKCE instead: /authorize will REQUIRE a');
    console.log('  code_challenge with code_challenge_method=S256, and /token will require');
    console.log('  the matching code_verifier. A request without one is refused.');
    console.log(`  Redirect URIs are matched EXACTLY - a trailing slash is a different URI:`);
    for (const uri of redirectUris) console.log(`    ${uri}`);
    console.log('');
    await closeDatabase();
    process.exit(0);
  }

  if (secretOnly) {
    // Everything explanatory goes to stderr; stdout carries the secret alone.
    console.error(`registered ${id} with ${redirectUris.length} redirect URI(s)`);
    process.stdout.write(secret);
    await closeDatabase();
    process.exit(0);
  }

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
