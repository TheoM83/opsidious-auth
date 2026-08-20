import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbAll, dbGet } from '../lib/database.js';
import { pairwiseSubject } from '../lib/crypto.js';
import { ensurePepper, signInWithGoogleSub, getAccount, deleteAccount } from '../lib/accounts.js';

const SUB = '109384756102938475610';
const OTHER = '210293847561029384756';

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

test('the pepper is created once and never replaced', async () => {
  const first = await ensurePepper();
  assert.ok(first && first.length >= 32);
  assert.equal(await ensurePepper(), first);
});

test('a first sign-in creates the account', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub(SUB);
  assert.ok(account.id);
  assert.equal(pairwiseSalt.length, 32);
  assert.equal((await dbAll('SELECT id FROM accounts')).length, 1);
});

test('a later sign-in finds the same account and the same salt', async () => {
  const first = await signInWithGoogleSub(SUB);
  const second = await signInWithGoogleSub(SUB);
  assert.equal(second.account.id, first.account.id);
  assert.deepEqual(second.pairwiseSalt, first.pairwiseSalt);
  assert.equal((await dbAll('SELECT id FROM accounts')).length, 1);
});

test('a different Google account gets a different salt', async () => {
  const a = await signInWithGoogleSub(SUB);
  const b = await signInWithGoogleSub(OTHER);
  assert.notEqual(b.account.id, a.account.id);
  assert.notDeepEqual(b.pairwiseSalt, a.pairwiseSalt);
});

test('the same person gets a different subject in each application', async () => {
  // The anonymity guarantee, end to end through the account layer.
  const { pairwiseSalt } = await signInWithGoogleSub(SUB);
  assert.notEqual(pairwiseSubject(pairwiseSalt, 'defnote'), pairwiseSubject(pairwiseSalt, 'other'));
});

test('creation time is rounded to the day', async () => {
  // A millisecond-precision timestamp is a fingerprint that can be matched
  // against an application's own first-seen record. Spec §4.2.
  const { account } = await signInWithGoogleSub('333333333333333333333');
  assert.equal(account.created_at % 86400000, 0);
});

test('the stored row contains neither the Google subject nor the salt', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub('444444444444444444444');
  const row = await dbGet('SELECT * FROM accounts WHERE id = ?', [account.id]);
  const dump = JSON.stringify(row, (k, v) => (Buffer.isBuffer(v) ? v.toString('hex') : v));
  assert.ok(!dump.includes('444444444444444444444'));
  assert.ok(!dump.includes(pairwiseSalt.toString('hex')));
});

test('deleting an account removes it', async () => {
  const { account } = await signInWithGoogleSub('555555555555555555555');
  await deleteAccount(account.id);
  assert.equal(await getAccount(account.id), undefined);
});
