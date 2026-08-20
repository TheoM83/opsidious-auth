import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  initDatabase,
  closeDatabase,
  dbRun,
  dbGet,
  dbAll,
  getSetting,
  setSettingOnce
} from '../lib/database.js';
import { DB_BUSY_TIMEOUT_MS } from '../lib/config.js';

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

test('every expected table exists', async () => {
  const rows = await dbAll("SELECT name FROM sqlite_master WHERE type = 'table'");
  const names = rows.map((r) => r.name);
  for (const t of [
    'accounts',
    'clients',
    'auth_requests',
    'codes',
    'sso_sessions',
    'signing_keys',
    'settings'
  ]) {
    assert.ok(names.includes(t), `missing table ${t}`);
  }
});

test('no table stores a pairwise salt in the clear', async () => {
  // Spec §4.3. A plaintext salt column would silently undo the entire
  // anonymity guarantee while every other test still passed.
  const tables = (await dbAll("SELECT name FROM sqlite_master WHERE type = 'table'")).map(
    (r) => r.name
  );
  for (const table of tables) {
    // SQLite cannot bind identifiers, so we must interpolate. The table name
    // comes from sqlite_master, so the source is not exploitable. This
    // assertion guarantees it is a plain SQL identifier before interpolation.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new Error(`unexpected table name: ${table}`);
    const columns = await dbAll(`PRAGMA table_info(${table})`);
    for (const column of columns) {
      assert.notEqual(
        column.name,
        'pairwise_salt',
        `${table}.pairwise_salt must not exist - see spec §4.3`
      );
    }
  }
});

test('no table links an account to a client', async () => {
  // Spec §4. No single table carries both account_id and client_id, which would
  // record which client a specific account signs in to. The `codes` table
  // carries derived app_sub, never account_id.
  const tables = (await dbAll("SELECT name FROM sqlite_master WHERE type = 'table'")).map(
    (r) => r.name
  );
  for (const table of tables) {
    // SQLite cannot bind identifiers, so we must interpolate. The table name
    // comes from sqlite_master, so the source is not exploitable. This
    // assertion guarantees it is a plain SQL identifier before interpolation.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new Error(`unexpected table name: ${table}`);
    const columns = (await dbAll(`PRAGMA table_info(${table})`)).map((c) => c.name);
    const hasAccountId = columns.includes('account_id');
    const hasClientId = columns.includes('client_id');
    assert.ok(
      !(hasAccountId && hasClientId),
      `${table} carries both account_id and client_id - would record which client a user signs in to`
    );
  }
  // Explicit assertion that codes has app_sub and not account_id.
  const codesColumns = (await dbAll('PRAGMA table_info(codes)')).map((c) => c.name);
  assert.ok(codesColumns.includes('app_sub'), 'codes must have app_sub');
  assert.ok(!codesColumns.includes('account_id'), 'codes.account_id would record which app a person uses');
});

test('foreign keys are enforced', async () => {
  const row = await dbGet('PRAGMA foreign_keys');
  assert.equal(row.foreign_keys, 1);
});

test('a busy_timeout is set so a colliding writer waits instead of failing immediately', async () => {
  // Without this, a write that collides with another write (a sign-in
  // landing during a sweep, or during the backup's VACUUM INTO) throws
  // SQLITE_BUSY straight away instead of retrying, which is the classic
  // SQLite production failure - it would surface as a 500 on a real user's
  // sign-in.
  const row = await dbGet('PRAGMA busy_timeout');
  assert.equal(row.timeout, DB_BUSY_TIMEOUT_MS);
  assert.ok(row.timeout > 0, 'a zero timeout would fail fast exactly like having none at all');
});

test('setSettingOnce writes once and never overwrites', async () => {
  assert.equal(await setSettingOnce('lookup_pepper', 'first'), 'first');
  // A second call must return the stored value, not replace it. Replacing the
  // pepper would orphan every account in every application, permanently.
  assert.equal(await setSettingOnce('lookup_pepper', 'second'), 'first');
  assert.equal(await getSetting('lookup_pepper'), 'first');
});

test('getSetting returns undefined for an unknown key', async () => {
  assert.equal(await getSetting('nope'), undefined);
});

test('a Google subject hash is unique across accounts', async () => {
  const insert = (id, hash) =>
    dbRun(
      'INSERT INTO accounts (id, google_sub_hash, kdf_salt, sealed_salt, created_at) VALUES (?,?,?,?,?)',
      [id, hash, Buffer.alloc(16), Buffer.alloc(60), 1]
    );
  await insert('a1', 'hash-1');
  await assert.rejects(() => insert('a2', 'hash-1'));
});

test('deleting an account cascades to its sessions', async () => {
  await dbRun(
    'INSERT INTO sso_sessions (id, token_hash, account_id, kdf_salt, sealed_salt, expires_at, created_at) VALUES (?,?,?,?,?,?,?)',
    ['s1', 'th1', 'a1', Buffer.alloc(16), Buffer.alloc(60), 2, 1]
  );
  await dbRun('DELETE FROM accounts WHERE id = ?', ['a1']);
  assert.equal((await dbAll('SELECT id FROM sso_sessions WHERE account_id = ?', ['a1'])).length, 0);
});

test('a code can only be marked used once', async () => {
  // The atomic consume of §7.4 depends on this being a real UPDATE guard.
  await dbRun(
    'INSERT INTO codes (code_hash, app_sub, client_id, redirect_uri, used, expires_at, created_at) VALUES (?,?,?,?,0,?,?)',
    ['ch1', 'sub1', 'defnote', 'https://x.test/cb', Date.now() + 60000, Date.now()]
  );
  const first = await dbRun('UPDATE codes SET used = 1 WHERE code_hash = ? AND used = 0', ['ch1']);
  const second = await dbRun('UPDATE codes SET used = 1 WHERE code_hash = ? AND used = 0', ['ch1']);
  assert.equal(first.changes, 1);
  assert.equal(second.changes, 0);
});
