import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readdirSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import sqlite3 from 'sqlite3';
import { initDatabase, closeDatabase, dbRun, setSettingOnce } from '../lib/database.js';
import { backupNow, pruneBackups } from '../lib/backup.js';

let dir;
let dbFile;

// Opens a read-only handle just long enough to read a table, then closes it
// before resolving. On Windows an open sqlite3 handle holds a file lock;
// leaving it open past the assertion would make the temp-dir cleanup in
// after() throw EBUSY. The assertion needed is that the backup file opens
// and is a valid database - not that the handle outlives the check.
function readBackedUpTable(file, sql) {
  return new Promise((resolve, reject) => {
    const copy = new sqlite3.Database(file, sqlite3.OPEN_READONLY, (openErr) => {
      if (openErr) return reject(openErr);
      copy.all(sql, (queryErr, rows) => {
        copy.close((closeErr) => {
          if (queryErr) reject(queryErr);
          else if (closeErr) reject(closeErr);
          else resolve(rows);
        });
      });
    });
  });
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'opsid-backup-'));
  dbFile = join(dir, 'live.db');
  await initDatabase(dbFile);
  await dbRun(
    'INSERT INTO accounts (id, google_sub_hash, kdf_salt, sealed_salt, created_at) VALUES (?,?,?,?,?)',
    ['a1', 'h1', Buffer.alloc(16), Buffer.alloc(60), 0]
  );
  // Not a real credential - a fixture pepper for a throwaway temp-dir test
  // database that is deleted in after().
  await setSettingOnce('lookup_pepper', 'test-fixture-pepper-not-a-real-secret');
  await dbRun(
    'INSERT INTO signing_keys (kid, private_pem, public_jwk, created_at, retires_at, expires_at) VALUES (?,?,?,?,?,?)',
    ['test-kid', 'test-fixture-private-pem-not-a-real-key', '{"kty":"RSA","kid":"test-kid"}', 0, 1, 2]
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

  const accounts = await readBackedUpTable(file, 'SELECT id FROM accounts');
  assert.equal(accounts.length, 1, 'the copy contains the accounts');
});

test('a backup carries the pepper and the signing keys, not just accounts', async () => {
  // A backup missing the pepper orphans every account it contains - restoring
  // accounts without the pepper that hashed their google_sub_hash values
  // makes every one of them unrecoverable. This is the worst possible silent
  // backup failure, so it is asserted on its own, not folded into the
  // generic "a backup opens" check above.
  const out = join(dir, 'out');
  const file = await backupNow(out);
  assert.ok(file);

  const settings = await readBackedUpTable(file, "SELECT value FROM settings WHERE key = 'lookup_pepper'");
  assert.equal(settings.length, 1, 'the pepper setting must survive the backup');
  assert.equal(settings[0].value, 'test-fixture-pepper-not-a-real-secret');

  const keys = await readBackedUpTable(file, 'SELECT kid FROM signing_keys');
  assert.equal(keys.length, 1, 'the signing key must survive the backup');
  assert.equal(keys[0].kid, 'test-kid');
});

test('a second backup on the same day overwrites rather than piling up', async () => {
  const out = join(dir, 'out');
  const first = await backupNow(out);
  assert.ok(first, 'the first backup must succeed');

  await dbRun(
    'INSERT INTO accounts (id, google_sub_hash, kdf_salt, sealed_salt, created_at) VALUES (?,?,?,?,?)',
    ['a2', 'h2', Buffer.alloc(16), Buffer.alloc(60), 0]
  );

  const second = await backupNow(out);
  // A previous version of this test only asserted one .db file existed,
  // which is equally true whether the second call actually rewrote it or
  // silently failed on "output file already exists" and left the first
  // backup in place untouched. Assert the second call reported success and
  // that its content is the newer content, not just that the filename count
  // didn't change.
  assert.ok(
    second,
    'the second backup must also succeed, not silently fail because the target already exists'
  );
  assert.equal(second, first, 'the same day must produce the same target filename');

  const rows = await readBackedUpTable(second, 'SELECT id FROM accounts');
  assert.equal(
    rows.length,
    2,
    'the file must contain the account inserted after the first backup - proof the second write actually won, not that it merely left a stale copy of the first behind'
  );
  assert.equal(readdirSync(out).filter((f) => f.endsWith('.db')).length, 1);
});

test('an empty BACKUP_DIR argument is refused before touching the filesystem', async () => {
  // The falsy-argument early return, kept separate from the genuine
  // filesystem-failure case below: this path never reaches mkdirSync or
  // VACUUM INTO at all, so it proves nothing about the try/catch around them.
  assert.equal(await backupNow(''), null);
});

test('a target that cannot be created on disk logs and returns null rather than crashing', async () => {
  // A genuine filesystem failure, not the falsy-argument short-circuit above:
  // `blocker` exists as a plain file, so asking mkdirSync to create a
  // directory *inside* it (recursive: true included) fails with ENOTDIR, the
  // same shape of error an unwritable or read-only directory would produce.
  // This is what actually exercises the try/catch around mkdirSync/VACUUM
  // INTO - a failing backup must never take the service down with it.
  const blocker = join(dir, 'not-a-directory');
  writeFileSync(blocker, 'x');
  const target = join(blocker, 'nested', 'out');

  assert.equal(await backupNow(target), null);
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
