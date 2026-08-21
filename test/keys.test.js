import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, jwtVerify, createLocalJWKSet, decodeProtectedHeader } from 'jose';
import { initDatabase, closeDatabase, dbRun, dbAll } from '../lib/database.js';
import { currentSigner, publishedJwks, rotateIfNeeded, sweepExpiredKeys } from '../lib/keys.js';
import { KEY_ROTATION_MS, KEY_GRACE_MS } from '../lib/config.js';

const HOUR = 3600000;
const DAY = 24 * HOUR;
const NOW = 1_800_000_000_000;

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});
beforeEach(async () => {
  await dbRun('DELETE FROM signing_keys');
});

async function sign(signer, now) {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: signer.kid })
    .setIssuer('https://auth.test')
    .setAudience('defnote')
    .setIssuedAt(Math.floor(now / 1000))
    .setExpirationTime(Math.floor(now / 1000) + 120)
    .sign(signer.privateKey);
}

test('the first call mints a key', async () => {
  const signer = await currentSigner(NOW);
  assert.ok(signer.kid);
  assert.equal((await dbAll('SELECT kid FROM signing_keys')).length, 1);
});

test('a second call reuses the same key', async () => {
  const first = await currentSigner(NOW);
  const second = await currentSigner(NOW + 1000);
  assert.equal(first.kid, second.kid);
});

test('a token signed by the current key verifies against the published set', async () => {
  const signer = await currentSigner(NOW);
  const token = await sign(signer, NOW);
  const { payload } = await jwtVerify(token, createLocalJWKSet(await publishedJwks(NOW)), {
    issuer: 'https://auth.test',
    audience: 'defnote',
    algorithms: ['RS256'],
    currentDate: new Date(NOW)
  });
  assert.equal(payload.aud, 'defnote');
  assert.equal(decodeProtectedHeader(token).kid, signer.kid);
});

test('the published JWKS carries no private material', async () => {
  await currentSigner(NOW);
  const jwks = await publishedJwks(NOW);
  const dump = JSON.stringify(jwks);
  for (const secret of ['"d"', '"p"', '"q"', 'PRIVATE KEY']) {
    assert.ok(!dump.includes(secret), `${secret} must not be published`);
  }
  assert.equal(jwks.keys[0].alg, 'RS256');
  assert.equal(jwks.keys[0].use, 'sig');
});

test('rotation does nothing before the key is due', async () => {
  await currentSigner(NOW);
  assert.equal(await rotateIfNeeded(NOW + DAY), null);
  assert.equal((await dbAll('SELECT kid FROM signing_keys')).length, 1);
});

test('rotation mints a new key during the lookahead window', async () => {
  // The lookahead window is (retires_at - KEY_GRACE_MS, retires_at).
  // At this point, the old key is still non-retired, so newestSigningKey returns it
  // and the lookahead check (row.retires_at > now + KEY_GRACE_MS) fails, triggering a mint.
  const first = await currentSigner(NOW);
  const retiresAt = NOW + KEY_ROTATION_MS;
  const inLookahead = retiresAt - KEY_GRACE_MS / 2; // Strictly inside the lookahead window
  const minted = await rotateIfNeeded(inLookahead);
  assert.ok(minted && minted !== first.kid, 'should mint a successor during lookahead');
  // After lookahead rotation, the new key signs.
  assert.equal((await currentSigner(inLookahead)).kid, minted, 'the new key signs once minted');
});

test('rotation mints a new key once the current one has retired', async () => {
  // After retires_at, newestSigningKey returns null (no non-retired key exists).
  // rotateIfNeeded mints a successor through the !row fallthrough.
  const first = await currentSigner(NOW);
  const atRetires = NOW + KEY_ROTATION_MS;
  const minted = await rotateIfNeeded(atRetires);
  assert.ok(minted && minted !== first.kid, 'should mint a successor after retires_at');
  assert.equal((await currentSigner(atRetires)).kid, minted, 'the new key signs once minted');
});

test('a token signed before rotation still verifies after it', async () => {
  // The reason a key has two boundaries rather than one.
  const first = await currentSigner(NOW);
  const token = await sign(first, NOW);
  const later = NOW + 30 * DAY;
  await rotateIfNeeded(later);

  const { payload } = await jwtVerify(token, createLocalJWKSet(await publishedJwks(later)), {
    issuer: 'https://auth.test',
    algorithms: ['RS256'],
    currentDate: new Date(NOW + 60000)
  });
  assert.ok(payload);
});

test('a retired key stops being published once its grace has passed', async () => {
  const first = await currentSigner(NOW);
  const later = NOW + 30 * DAY;
  await rotateIfNeeded(later);

  const published = await publishedJwks(later + 2 * HOUR);
  assert.ok(!published.keys.some((k) => k.kid === first.kid));
});

test('the sweep deletes only keys past expiry', async () => {
  const first = await currentSigner(NOW);
  const later = NOW + 30 * DAY;
  await rotateIfNeeded(later);

  assert.equal(await sweepExpiredKeys(later), 0, 'still inside the grace window');
  assert.equal(await sweepExpiredKeys(later + 2 * HOUR), 1);
  const remaining = await dbAll('SELECT kid FROM signing_keys');
  assert.equal(remaining.length, 1);
  assert.notEqual(remaining[0].kid, first.kid);
});

test('a signer is minted again if every key was swept', async () => {
  await currentSigner(NOW);
  await dbRun('DELETE FROM signing_keys');
  assert.ok((await currentSigner(NOW)).kid);
});

test('concurrent same-process rotateIfNeeded calls at the rotation boundary mint exactly one successor', async () => {
  // rotateIfNeeded used to call mint() directly, bypassing the same
  // withMintLock/BEGIN IMMEDIATE machinery currentSigner uses - harmless
  // in-process only because server.js's withOverlapGuard already stops one
  // process's own sweep ticks from overlapping. This proves the lock itself
  // now covers rotateIfNeeded too, the same way the test above proves it for
  // currentSigner's first-mint path.
  const first = await currentSigner(NOW);
  const atRetires = NOW + KEY_ROTATION_MS;

  const minted = await Promise.all(Array.from({ length: 8 }, () => rotateIfNeeded(atRetires)));
  const kids = new Set(minted.filter(Boolean));
  assert.equal(kids.size, 1, 'every concurrent rotation must converge on one successor key');
  assert.notEqual([...kids][0], first.kid);

  const rows = await dbAll('SELECT kid FROM signing_keys');
  assert.equal(rows.length, 2, 'exactly one successor minted, alongside the original key');
});

test('concurrent same-process calls with no key yet mint exactly one', async () => {
  // A single SQLite connection cannot have two BEGIN IMMEDIATE transactions
  // open at once (a second throws "cannot start a transaction within a
  // transaction" rather than queueing), and this process holds exactly one
  // connection - so concurrent in-process callers have to be serialised
  // ahead of that transaction, not just across it. This is the in-process
  // half of the guarantee; test/keys-mint-race.test.js proves the
  // cross-process half with real OS processes.
  await dbRun('DELETE FROM signing_keys');
  const signers = await Promise.all(Array.from({ length: 8 }, () => currentSigner(NOW)));
  const kids = new Set(signers.map((s) => s.kid));
  assert.equal(kids.size, 1, 'every concurrent caller must converge on one key');
  assert.equal((await dbAll('SELECT kid FROM signing_keys')).length, 1);
});
