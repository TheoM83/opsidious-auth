// Every side effect lives here: database init, one-time bootstrap, schedulers,
// listen, signals. Guarded by a main-module check so importing app.js (or this
// file itself) from a test starts nothing.
import { pathToFileURL } from 'node:url';
import { app } from './app.js';
import { initDatabase, closeDatabase, dbRun } from './lib/database.js';
import { ensurePepper } from './lib/accounts.js';
import { currentSigner, rotateIfNeeded, sweepExpiredKeys } from './lib/keys.js';
import { sweepSessions } from './lib/sessions.js';
import { sweepCodes } from './lib/codes.js';
import { backupNow, pruneBackups } from './lib/backup.js';
import {
  PORT,
  PUBLIC_URL,
  BACKUP_DIR,
  BACKUP_RETENTION_DAYS,
  BACKUP_INTERVAL_MS,
  SWEEP_INTERVAL_MS
} from './lib/config.js';

// Re-entrancy guard for a periodic job. `setInterval` does not wait for a
// promise to settle before scheduling the next tick, so a job that ever
// outlasts its interval (a large database, a slow disk, a stalled write)
// could otherwise run twice at once. For the sweep specifically, two
// concurrent `rotateIfNeeded` calls could each decide a new signing key is
// due and each mint one (flagged in Task 4's review, fixed here). The check
// and the flag-set below run synchronously, before either call's first
// `await`, so two ticks racing into this function can never both see
// `running === false`.
//
// Returns `{ ran }` so a tick that was skipped is distinguishable from one
// that actually did the work - this is what makes the guard testable without
// reaching into the job's internals.
function withOverlapGuard(fn, label) {
  let running = false;
  return async (...args) => {
    if (running) {
      console.warn(`${label} already running, skipping this tick`);
      return { ran: false };
    }
    running = true;
    try {
      await fn(...args);
      return { ran: true };
    } finally {
      running = false;
    }
  };
}

async function sweepOnce() {
  try {
    const now = Date.now();
    await dbRun('DELETE FROM auth_requests WHERE expires_at <= ?', [now]);
    await sweepCodes(now);
    await sweepSessions(now);
    await sweepExpiredKeys(now);
    await rotateIfNeeded(now);
  } catch (err) {
    console.error('sweep failed:', err.message);
  }
}

async function backupOnce() {
  // Mirrors sweep()'s try/catch. Neither backupNow nor pruneBackups throws
  // today - both swallow internally - but this function is handed straight
  // to setInterval, and an async interval callback that rejects produces an
  // unhandled rejection, which crashes the process under Node's default
  // behaviour. A scheduled job must never take the process down with it.
  try {
    await backupNow(BACKUP_DIR);
    await pruneBackups(BACKUP_DIR, BACKUP_RETENTION_DAYS);
  } catch (err) {
    console.error('backup failed:', err.message);
  }
}

// Exported (not just used locally) so tests can invoke them directly without
// starting the server - see test/server.test.js. Importing this module never
// runs either of them; only start(), below, does, and only when this file is
// the process entry point.
export const sweep = withOverlapGuard(sweepOnce, 'sweep');
export const backup = withOverlapGuard(backupOnce, 'backup');

// Factory rather than a bare function so the re-entrancy behaviour is
// testable without a real HTTP server or a real process.exit: a second
// signal (SIGTERM then SIGINT, or a repeated one) must not call
// `server.close` twice or race two `process.exit` paths, and a rejection
// from `closeDatabase` inside the close callback must not become an
// unhandled rejection.
export function makeShutdown({ server, closeDatabase: close, exit = process.exit, timeoutMs = 10000 }) {
  let shuttingDown = false;
  return function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received, shutting down`);
    server.close(async () => {
      try {
        await close();
      } catch (err) {
        console.error('shutdown error:', err.message);
      }
      exit(0);
    });
    setTimeout(() => exit(1), timeoutMs).unref();
  };
}

async function start() {
  await initDatabase();
  console.log('database ready');

  // Idempotent: both are created on the first boot and only re-read afterwards.
  // Minting a second pepper would orphan every account that exists.
  await ensurePepper();
  await currentSigner();
  console.log('pepper and signing key ready');

  await sweep();
  const sweepTimer = setInterval(sweep, SWEEP_INTERVAL_MS);
  sweepTimer.unref();

  if (BACKUP_DIR) {
    await backup();
    const backupTimer = setInterval(backup, BACKUP_INTERVAL_MS);
    backupTimer.unref();
  } else {
    console.warn('BACKUP_DIR is not set - this deployment has no backups');
  }

  const server = app.listen(PORT, () => console.log(`opsidious-auth listening on :${PORT} as ${PUBLIC_URL}`));

  const shutdown = makeShutdown({ server, closeDatabase });
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  start().catch((err) => {
    console.error('fatal startup error:', err.message);
    process.exit(1);
  });
}
