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
  // Spec §4. `codes` carries the derived app_sub, never account_id.
  const columns = (await dbAll('PRAGMA table_info(codes)')).map((c) => c.name);
  assert.ok(columns.includes('app_sub'));
  assert.ok(!columns.includes('account_id'), 'codes.account_id would record which app a person uses');
});

test('foreign keys are enforced', async () => {
  const row = await dbGet('PRAGMA foreign_keys');
  assert.equal(row.foreign_keys, 1);
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
