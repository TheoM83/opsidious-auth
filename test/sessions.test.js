import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbRun, dbGet, dbAll } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import {
  createSession,
  resolveSession,
  deleteSessionByCookie,
  deleteSessionById,
  sweepSessions
} from '../lib/sessions.js';

const SUB = '109384756102938475610';
const NOW = 1_800_000_000_000;

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

test('a session recovers the salt without the Google subject', async () => {
  // This is what makes silent SSO possible: the second visit never touches
  // Google, yet still derives the same subjects.
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue } = await createSession(account.id, pairwiseSalt, NOW);

  const resolved = await resolveSession(cookieValue, NOW + 1000);
  assert.ok(resolved);
  assert.deepEqual(resolved.pairwiseSalt, pairwiseSalt);
  assert.equal(resolved.session.account_id, account.id);
});

test('the cookie value is never stored', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const row = await dbGet('SELECT * FROM sso_sessions WHERE id = ?', [session.id]);
  const dump = JSON.stringify(row, (k, v) => (Buffer.isBuffer(v) ? v.toString('hex') : v));
  assert.ok(!dump.includes(cookieValue));
  assert.ok(!dump.includes(pairwiseSalt.toString('hex')));
});

test('an unknown cookie resolves to null', async () => {
  assert.equal(await resolveSession('not-a-real-cookie', NOW), null);
  assert.equal(await resolveSession('', NOW), null);
  assert.equal(await resolveSession(undefined, NOW), null);
});

test('an expired session resolves to null', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  await dbRun('UPDATE sso_sessions SET expires_at = ? WHERE id = ?', [NOW - 1, session.id]);
  assert.equal(await resolveSession(cookieValue, NOW), null);
});

test('a tampered sealed salt resolves to null rather than throwing', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  await dbRun('UPDATE sso_sessions SET sealed_salt = ? WHERE id = ?', [Buffer.alloc(60), session.id]);
  assert.equal(await resolveSession(cookieValue, NOW), null);
});

test('deleting by cookie ends the session', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue } = await createSession(account.id, pairwiseSalt, NOW);
  await deleteSessionByCookie(cookieValue);
  assert.equal(await resolveSession(cookieValue, NOW), null);
});

test('deleting by id ends the session', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  await deleteSessionById(session.id);
  assert.equal(await resolveSession(cookieValue, NOW), null);
});

test('two sessions for one account are independent', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const a = await createSession(account.id, pairwiseSalt, NOW);
  const b = await createSession(account.id, pairwiseSalt, NOW);
  assert.notEqual(a.cookieValue, b.cookieValue);
  await deleteSessionByCookie(a.cookieValue);
  assert.equal(await resolveSession(a.cookieValue, NOW), null);
  assert.ok(await resolveSession(b.cookieValue, NOW));
});

test('the sweep removes only expired sessions', async () => {
  await dbRun('DELETE FROM sso_sessions');
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB, NOW);
  const live = await createSession(account.id, pairwiseSalt, NOW);
  const dead = await createSession(account.id, pairwiseSalt, NOW);
  await dbRun('UPDATE sso_sessions SET expires_at = ? WHERE id = ?', [NOW - 1, dead.session.id]);

  assert.equal(await sweepSessions(NOW), 1);
  assert.equal((await dbAll('SELECT id FROM sso_sessions')).length, 1);
  assert.ok(await resolveSession(live.cookieValue, NOW));
});
