import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  INFO_ACCOUNT,
  INFO_SESSION,
  deriveKey,
  seal,
  openSealed,
  newSalt,
  newKdfSalt,
  pairwiseSubject,
  lookupHash,
  sha256,
  randomToken,
  safeEqual
} from '../lib/crypto.js';

const GOOGLE_SUB = '109384756102938475610'; // the shape of a real Google sub

test('a derived key is 32 bytes and deterministic', () => {
  const kdfSalt = newKdfSalt();
  const a = deriveKey(GOOGLE_SUB, kdfSalt, INFO_ACCOUNT);
  const b = deriveKey(GOOGLE_SUB, kdfSalt, INFO_ACCOUNT);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
});

test('the same input under a different purpose yields a different key', () => {
  // Distinct info strings are what stop an account key from opening a session
  // row and vice versa.
  const kdfSalt = newKdfSalt();
  assert.notDeepEqual(
    deriveKey(GOOGLE_SUB, kdfSalt, INFO_ACCOUNT),
    deriveKey(GOOGLE_SUB, kdfSalt, INFO_SESSION)
  );
});

test('the same input under a different salt yields a different key', () => {
  assert.notDeepEqual(
    deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT),
    deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT)
  );
});

test('seal then open round-trips', () => {
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  const salt = newSalt();
  assert.deepEqual(openSealed(key, seal(key, salt)), salt);
});

test('sealing the same value twice gives different bytes', () => {
  // A fresh IV each time. Identical ciphertext would reveal that two accounts
  // hold the same salt.
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  const salt = newSalt();
  assert.notDeepEqual(seal(key, salt), seal(key, salt));
});

test('a sealed 32-byte salt is 60 bytes', () => {
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  assert.equal(seal(key, newSalt()).length, 12 + 16 + 32);
});

test('the sealed blob never contains the plaintext', () => {
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  const salt = newSalt();
  assert.ok(!seal(key, salt).includes(salt));
});

test('a wrong key throws rather than returning plausible bytes', () => {
  const kdfSalt = newKdfSalt();
  const blob = seal(deriveKey(GOOGLE_SUB, kdfSalt, INFO_ACCOUNT), newSalt());
  assert.throws(() => openSealed(deriveKey('999999999999999999999', kdfSalt, INFO_ACCOUNT), blob));
});

test('a key derived for the other purpose cannot open the blob', () => {
  const kdfSalt = newKdfSalt();
  const blob = seal(deriveKey(GOOGLE_SUB, kdfSalt, INFO_ACCOUNT), newSalt());
  assert.throws(() => openSealed(deriveKey(GOOGLE_SUB, kdfSalt, INFO_SESSION), blob));
});

test('a tampered blob fails its authentication tag', () => {
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  const blob = seal(key, newSalt());
  blob[blob.length - 1] ^= 0x01;
  assert.throws(() => openSealed(key, blob));
});

test('a truncated blob is rejected', () => {
  const key = deriveKey(GOOGLE_SUB, newKdfSalt(), INFO_ACCOUNT);
  assert.throws(() => openSealed(key, seal(key, newSalt()).subarray(0, 20)));
});

test('two clients get different subjects from one salt', () => {
  // The anonymity guarantee of §4, as a single assertion.
  const salt = newSalt();
  assert.notEqual(pairwiseSubject(salt, 'defnote'), pairwiseSubject(salt, 'futureapp'));
});

test('a subject is stable for one client', () => {
  const salt = newSalt();
  assert.equal(pairwiseSubject(salt, 'defnote'), pairwiseSubject(salt, 'defnote'));
});

test('two accounts never share a subject for the same client', () => {
  assert.notEqual(pairwiseSubject(newSalt(), 'defnote'), pairwiseSubject(newSalt(), 'defnote'));
});

test('a subject is URL-safe and reveals neither the salt nor the client', () => {
  const salt = newSalt();
  const sub = pairwiseSubject(salt, 'defnote');
  assert.match(sub, /^[A-Za-z0-9_-]+$/);
  assert.ok(!sub.includes('defnote'));
  assert.ok(!sub.includes(salt.toString('base64url')));
});

test('lookupHash is deterministic and peppered', () => {
  const pepperA = randomToken();
  const pepperB = randomToken();
  assert.equal(lookupHash(pepperA, GOOGLE_SUB), lookupHash(pepperA, GOOGLE_SUB));
  assert.notEqual(lookupHash(pepperA, GOOGLE_SUB), lookupHash(pepperB, GOOGLE_SUB));
  assert.ok(!lookupHash(pepperA, GOOGLE_SUB).includes(GOOGLE_SUB));
});

test('randomToken is URL-safe and unique', () => {
  const tokens = new Set(Array.from({ length: 500 }, () => randomToken()));
  assert.equal(tokens.size, 500);
  assert.match([...tokens][0], /^[A-Za-z0-9_-]+$/);
});

test('safeEqual compares without throwing on a length mismatch', () => {
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'much longer string'), false);
  assert.equal(safeEqual('', ''), true);
});

test('sha256 is hex and stable', () => {
  assert.match(sha256('x'), /^[0-9a-f]{64}$/);
  assert.equal(sha256('x'), sha256('x'));
});

test('the whole envelope keeps every secret out of a serialised row', () => {
  // What a database dump would actually contain, asserted directly.
  const googleSub = GOOGLE_SUB;
  const pairwiseSalt = newSalt();
  const kdfSalt = newKdfSalt();
  const row = {
    google_sub_hash: lookupHash('pepper', googleSub),
    kdf_salt: kdfSalt.toString('hex'),
    sealed_salt: seal(deriveKey(googleSub, kdfSalt, INFO_ACCOUNT), pairwiseSalt).toString('hex')
  };
  const dump = JSON.stringify(row);

  assert.ok(!dump.includes(googleSub), 'the Google subject must not appear');
  assert.ok(!dump.includes(pairwiseSalt.toString('hex')), 'the salt must not appear');
  assert.ok(!dump.includes(pairwiseSubject(pairwiseSalt, 'defnote')), 'no app subject may appear');
});
