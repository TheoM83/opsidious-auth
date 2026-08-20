// This database is the identity of every Opsidious application. Losing it
// loses every per-account salt, and therefore every user of every application,
// permanently and with no recovery path. Backups are part of the service, not
// an operational afterthought (spec §8).
import { mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { dbRun } from './database.js';

const DAY_MS = 86400000;

function fileFor(dir, now) {
  const stamp = new Date(now).toISOString().slice(0, 10);
  return join(dir, `opsidious-auth-${stamp}.db`);
}

// VACUUM INTO, not a file copy: copying a live WAL database can capture a torn
// state that will not open.
export async function backupNow(dir, now = Date.now()) {
  if (!dir) {
    console.error('backup skipped: BACKUP_DIR is not set');
    return null;
  }
  try {
    mkdirSync(dir, { recursive: true });
    const target = fileFor(dir, now);
    try {
      unlinkSync(target); // VACUUM INTO refuses to overwrite
    } catch {
      /* not there yet */
    }
    // Unparameterised, by necessity rather than oversight: VACUUM INTO's
    // grammar takes its target as a string literal in the SQL text itself -
    // SQLite has no bind-parameter form of this statement, so there is no
    // `?` to give it. `target` is never attacker-influenced: it is built by
    // fileFor() above from BACKUP_DIR (an operator-set env var, not request
    // input) and an ISO date derived from the server's own clock, then
    // single-quote-escaped here. Nothing a request handler touches reaches
    // this string.
    await dbRun(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
    console.info(`backup written: ${target}`);
    return target;
  } catch (err) {
    console.error('backup failed:', err.message);
    return null;
  }
}

export async function pruneBackups(dir, retentionDays, now = Date.now()) {
  if (!dir) return 0;
  let removed = 0;
  try {
    const cutoff = now - retentionDays * DAY_MS;
    for (const name of readdirSync(dir)) {
      if (!name.startsWith('opsidious-auth-') || !name.endsWith('.db')) continue;
      const path = join(dir, name);
      if (statSync(path).mtimeMs < cutoff) {
        unlinkSync(path);
        removed += 1;
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('backup pruning failed:', err.message);
  }
  return removed;
}
