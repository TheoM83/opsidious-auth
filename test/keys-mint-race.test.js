// Reproduces the Task 14 audit finding: `currentSigner` used to do a plain
// SELECT and, finding nothing, INSERT a freshly minted key with no locking
// in between. A single Node process cannot reproduce that race no matter how
// many promises it fires concurrently, because they all share one
// module-level `db` connection and one JS call stack - the race is between
// independent OS processes, each with its own connection, each booting
// against one shared, freshly created database file. So this test spawns
// real child processes (test/fixtures/mint-race-child.mjs) rather than
// simulating concurrency in-process.
//
// Before the fix (a plain SELECT, then an unguarded INSERT) this reliably
// produced four rows, not zero or one: every process's SELECT ran before any
// of their INSERTs landed. After the fix (BEGIN IMMEDIATE around the
// check-then-mint, serialised further by lib/database.js's busy_timeout so
// the losers wait for the lock instead of failing with SQLITE_BUSY) exactly
// one row survives and every process reports the same kid.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import sqlite3 from 'sqlite3';

const here = dirname(fileURLToPath(import.meta.url));
const CHILD = join(here, 'fixtures', 'mint-race-child.mjs');
const PROCESS_COUNT = 4;

function spawnChild(dbPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, dbPath], { env: process.env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`mint-race child exited ${code}: ${stderr}`));
      else resolve(stdout.trim());
    });
  });
}

function readSigningKeyRows(dbPath) {
  return new Promise((resolve, reject) => {
    const copy = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (openErr) => {
      if (openErr) return reject(openErr);
      copy.all('SELECT kid FROM signing_keys', (queryErr, rows) => {
        copy.close((closeErr) => {
          if (queryErr) reject(queryErr);
          else if (closeErr) reject(closeErr);
          else resolve(rows);
        });
      });
    });
  });
}

test('four real processes racing to boot against one fresh database mint exactly one signing key', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'opsid-keys-race-'));
  const dbPath = join(dir, 'race.db');
  try {
    const kids = await Promise.all(
      Array.from({ length: PROCESS_COUNT }, () => spawnChild(dbPath))
    );
    const rows = await readSigningKeyRows(dbPath);
    assert.equal(rows.length, 1, `expected exactly one signing key, found ${rows.length}`);
    assert.ok(
      kids.every((kid) => kid === rows[0].kid),
      'every process must converge on the one winning key, not sign with a key of its own that then lost the race'
    );
  } finally {
    // Best effort: on Windows a child's WAL/SHM sidecar file can still be
    // settling its close for a moment after the child process has exited,
    // which turns a bare rmSync into a flaky EBUSY unrelated to the actual
    // assertions above. Retry a few times rather than let that mask a real
    // pass/fail result.
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
