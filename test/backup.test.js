import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readdirSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import sqlite3 from 'sqlite3';
import { initDatabase, closeDatabase, dbRun } from '../lib/database.js';
import { backupNow, pruneBackups } from '../lib/backup.js';

let dir;
let dbFile;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'opsid-backup-'));
  dbFile = join(dir, 'live.db');
  await initDatabase(dbFile);
  await dbRun(
    'INSERT INTO accounts (id, google_sub_hash, kdf_salt, sealed_salt, created_at) VALUES (?,?,?,?,?)',
    ['a1', 'h1', Buffer.alloc(16), Buffer.alloc(60), 0]
  );
});
after(async () => {
  await closeDatabase();
  rmSync(dir, { recursive: true, force: true });
});

test('a backup is written and actually opens', async () => {
  const out = join(dir, 'out');
  const file = await backupNow(out);
  assert.ok(file);

  const rows = await new Promise((resolve, reject) => {
    const copy = new sqlite3.Database(file, sqlite3.OPEN_READONLY, (err) => {
      if (err) reject(err);
      else copy.all('SELECT id FROM accounts', (e, r) => (e ? reject(e) : resolve(r)));
    });
  });
  assert.equal(rows.length, 1, 'the copy contains the accounts');
});

test('a second backup on the same day overwrites rather than piling up', async () => {
  const out = join(dir, 'out');
  await backupNow(out);
  await backupNow(out);
  assert.equal(readdirSync(out).filter((f) => f.endsWith('.db')).length, 1);
});

test('an unwritable directory logs and returns null rather than crashing', async () => {
  // A failing backup must never take the service down with it.
  assert.equal(await backupNow(''), null);
});

test('pruning removes files past the retention window and keeps the rest', async () => {
  const out = join(dir, 'prune');
  await backupNow(out);
  const old = join(out, 'opsidious-auth-2000-01-01.db');
  writeFileSync(old, 'x');
  const ancient = new Date('2000-01-01').getTime() / 1000;
  utimesSync(old, ancient, ancient);

  const removed = await pruneBackups(out, 14);
  assert.equal(removed, 1);
  assert.ok(!readdirSync(out).includes('opsidious-auth-2000-01-01.db'));
  assert.equal(readdirSync(out).filter((f) => f.endsWith('.db')).length, 1);
});

test('pruning a missing directory is a no-op', async () => {
  assert.equal(await pruneBackups(join(dir, 'nope'), 14), 0);
});
