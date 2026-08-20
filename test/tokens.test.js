import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { jwtVerify, createLocalJWKSet, decodeProtectedHeader, decodeJwt } from 'jose';
import { initDatabase, closeDatabase } from '../lib/database.js';
import { publishedJwks } from '../lib/keys.js';
import { signIdToken } from '../lib/tokens.js';
import { ISSUER } from '../lib/config.js';

const NOW = 1_800_000_000_000;

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

async function verify(token, options = {}) {
  return jwtVerify(token, createLocalJWKSet(await publishedJwks(NOW)), {
    issuer: ISSUER,
    algorithms: ['RS256'],
    currentDate: new Date(NOW),
    ...options
  });
}

test('a signed token verifies with the expected claims', async () => {
  const token = await signIdToken({ sub: 'pairwise-abc', clientId: 'defnote', nonce: 'n1' }, NOW);
  const { payload } = await verify(token, { audience: 'defnote' });
  assert.equal(payload.sub, 'pairwise-abc');
  assert.equal(payload.aud, 'defnote');
  assert.equal(payload.iss, ISSUER);
  assert.equal(payload.nonce, 'n1');
  assert.ok(payload.jti);
  assert.equal(payload.exp - payload.iat, 120);
  assert.equal(decodeProtectedHeader(token).alg, 'RS256');
  assert.ok(decodeProtectedHeader(token).kid);
});

test('the token carries nothing beyond those claims', async () => {
  // There is no email, name or picture to put in it, and nothing else may
  // creep in later.
  const token = await signIdToken({ sub: 'pairwise-abc', clientId: 'defnote', nonce: 'n1' }, NOW);
  assert.deepEqual(
    Object.keys(decodeJwt(token)).sort(),
    ['aud', 'exp', 'iat', 'iss', 'jti', 'nonce', 'sub'].sort()
  );
});

test('two tokens issued in the same millisecond differ', async () => {
  const a = await signIdToken({ sub: 's', clientId: 'defnote', nonce: 'n' }, NOW);
  const b = await signIdToken({ sub: 's', clientId: 'defnote', nonce: 'n' }, NOW);
  assert.notEqual(a, b, 'the random jti must make each token unique');
});

test('a token minted for one client fails another client audience check', async () => {
  const token = await signIdToken({ sub: 'pairwise-abc', clientId: 'defnote', nonce: 'n' }, NOW);
  await assert.rejects(() => verify(token, { audience: 'otherapp' }));
});

test('a token is refused once it has expired', async () => {
  const token = await signIdToken({ sub: 'pairwise-abc', clientId: 'defnote', nonce: 'n' }, NOW);
  await assert.rejects(async () =>
    jwtVerify(token, createLocalJWKSet(await publishedJwks(NOW)), {
      issuer: ISSUER,
      algorithms: ['RS256'],
      currentDate: new Date(NOW + 121_000)
    })
  );
});

test('a token omits the nonce claim when none was requested', async () => {
  const token = await signIdToken({ sub: 'pairwise-abc', clientId: 'defnote' }, NOW);
  assert.equal(decodeJwt(token).nonce, undefined);
});
