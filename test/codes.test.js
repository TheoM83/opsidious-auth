import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbRun, dbGet, dbAll } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession, resolveSession } from '../lib/sessions.js';
import { issueCode, consumeCode, sweepCodes } from '../lib/codes.js';

const NOW = 1_800_000_000_000;
const CLIENT = 'defnote';
const CALLBACK = 'https://defnote.test/auth/callback';

const issue = (over = {}, now = NOW) =>
  issueCode(
    { appSub: 'sub-abc', clientId: CLIENT, redirectUri: CALLBACK, nonce: 'n1', ...over },
    now
  );

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});
beforeEach(async () => {
  await dbRun('DELETE FROM codes');
});

test('a code is opaque and only its hash is stored', async () => {
  const code = await issue();
  assert.ok(code.length >= 32);
  const rows = await dbAll('SELECT code_hash FROM codes');
  assert.equal(rows.length, 1);
  assert.ok(!rows[0].code_hash.includes(code));
});

test('a fresh code is consumed once and yields its row', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, true);
  assert.equal(result.row.app_sub, 'sub-abc');
  assert.equal(result.row.nonce, 'n1');
});

test('the same code cannot be consumed twice', async () => {
  const code = await issue();
  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  const second = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'replayed');
});

test('two concurrent exchanges: exactly one wins', async () => {
  // The reason consumption is a guarded UPDATE and not SELECT-then-DELETE.
  const code = await issue();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW))
  );
  assert.equal(results.filter((r) => r.ok).length, 1);
  assert.equal(results.filter((r) => !r.ok && r.reason === 'replayed').length, 7);
});

test('a replay kills the SSO session the code came from', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.ok(await resolveSession(cookieValue, NOW), 'still valid after a legitimate exchange');

  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(await resolveSession(cookieValue, NOW), null, 'a replay means the code leaked');
});

test('an expired code is refused', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW + 61_000);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired');
});

test('a code presented by another client is refused', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: 'otherapp', redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'client_mismatch');
});

test('a code presented with a different redirect URI is refused', async () => {
  const code = await issue();
  const result = await consumeCode(
    code,
    { clientId: CLIENT, redirectUri: CALLBACK + '?x=1' },
    NOW
  );
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'redirect_mismatch');
});

test('a mismatched code is still spent, not left reusable', async () => {
  // Otherwise an attacker could probe with a wrong client id and then use the
  // code properly.
  const code = await issue();
  await consumeCode(code, { clientId: 'otherapp', redirectUri: CALLBACK }, NOW);
  const row = await dbGet('SELECT used FROM codes WHERE code_hash IS NOT NULL');
  assert.equal(row.used, 1);
});

test('an unknown code is refused without an error', async () => {
  const result = await consumeCode('never-issued', { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unknown');
});

test('the sweep removes expired codes', async () => {
  await issue();
  assert.equal(await sweepCodes(NOW), 0);
  assert.equal(await sweepCodes(NOW + 61_000), 1);
});
