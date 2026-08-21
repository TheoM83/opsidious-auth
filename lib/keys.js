// RS256 signing keys, their rotation, and the set we publish.
//
// A key has two boundaries. At `retires_at` it stops signing. It keeps being
// published until `expires_at`, so tokens issued just before a rotation still
// verify afterwards. One boundary would force a choice between never rotating
// and breaking tokens in flight.
import { generateKeyPair, exportJWK, exportPKCS8, importPKCS8 } from 'jose';
import { randomUUID } from 'node:crypto';
import { dbAll, dbGet, dbRun } from './database.js';
import { KEY_ROTATION_MS, KEY_GRACE_MS } from './config.js';

async function mint(now) {
  const kid = randomUUID();
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  const retiresAt = now + KEY_ROTATION_MS;
  await dbRun(
    'INSERT INTO signing_keys (kid, private_pem, public_jwk, created_at, retires_at, expires_at) VALUES (?,?,?,?,?,?)',
    [kid, await exportPKCS8(privateKey), JSON.stringify(jwk), now, retiresAt, retiresAt + KEY_GRACE_MS]
  );
  return kid;
}

async function newestSigningKey(now) {
  return dbGet('SELECT * FROM signing_keys WHERE retires_at > ? ORDER BY created_at DESC LIMIT 1', [now]);
}

async function toSigner(row) {
  return { kid: row.kid, privateKey: await importPKCS8(row.private_pem, 'RS256') };
}

// Same-process serialisation. sqlite3 keeps one connection per process
// (lib/database.js's module-level `db`), and a single SQLite connection
// cannot have two BEGIN IMMEDIATE transactions open at once - a second one
// throws "cannot start a transaction within a transaction" rather than
// queueing. So two calls to currentSigner() racing inside the same process
// (e.g. two /token requests arriving together with no key yet minted) have
// to be serialised here, before either ever reaches BEGIN IMMEDIATE below.
let mintChain = Promise.resolve();
function withMintLock(fn) {
  const turn = mintChain.then(fn, fn);
  mintChain = turn.then(
    () => undefined,
    () => undefined
  );
  return turn;
}

// Shared by currentSigner ("no live key exists yet") and rotateIfNeeded
// ("the live key is due to retire soon"): both are a check-then-mint that
// has to be re-checked once the write lock is actually held, in case another
// caller minted while this one was waiting for it. `shouldMint(row)` is that
// check, run once before the lock (so a caller that clearly has nothing to
// do never even attempts one) and once again inside it.
async function mintUnderLockIf(now, shouldMint) {
  // A caller queued behind another one on the same process may find the
  // queued-ahead-of-us caller already did what was needed - nothing left to do.
  let row = await newestSigningKey(now);
  if (!shouldMint(row)) return row;

  // BEGIN IMMEDIATE takes SQLite's write lock up front, before this
  // transaction's own SELECT runs, which is what serialises "check, then
  // mint" *across processes* - a plain SELECT followed by an unguarded
  // INSERT (the previous implementation) let every racing process see no
  // row and mint its own; reproduced with four real OS processes booting
  // against one fresh database, every process minted a key, every round
  // (test/keys-mint-race.test.js). The loser here waits for the lock instead
  // of failing outright only because lib/database.js sets a busy_timeout -
  // without it this would surface as SQLITE_BUSY instead of waiting.
  await dbRun('BEGIN IMMEDIATE');
  try {
    row = await newestSigningKey(now);
    if (shouldMint(row)) {
      const kid = await mint(now);
      row = await dbGet('SELECT * FROM signing_keys WHERE kid = ?', [kid]);
    }
    await dbRun('COMMIT');
  } catch (err) {
    // Release the write lock on every path, including a failed mint, so a
    // dead transaction never wedges every future signer lookup.
    try {
      await dbRun('ROLLBACK');
    } catch {
      /* connection may already have rolled back the failed transaction itself */
    }
    throw err;
  }
  return row;
}

export async function currentSigner(now = Date.now()) {
  const row = await newestSigningKey(now);
  if (row) return toSigner(row);
  return toSigner(await withMintLock(() => mintUnderLockIf(now, (r) => !r)));
}

// Everything still inside its publication window, newest first. Only public
// material: `private_pem` is never read here.
export async function publishedJwks(now = Date.now()) {
  const rows = await dbAll(
    'SELECT public_jwk FROM signing_keys WHERE expires_at > ? ORDER BY created_at DESC',
    [now]
  );
  return { keys: rows.map((r) => JSON.parse(r.public_jwk)) };
}

// Mints a successor once the current key is within one grace window of
// retirement, so there is always an overlap rather than a cliff.
//
// Routed through the same withMintLock/BEGIN IMMEDIATE machinery
// currentSigner uses, rather than calling mint() directly as this used to:
// unguarded, two concurrent callers each deciding a new key is due each
// mint one. Harmless with a single container - server.js's withOverlapGuard
// already stops one process's own sweep ticks from overlapping - but two
// replicas hitting the rotation boundary at the same moment, each running
// their own sweep, would otherwise still double-mint.
export async function rotateIfNeeded(now = Date.now()) {
  const dueSoon = (row) => !row || row.retires_at <= now + KEY_GRACE_MS;

  const before = await newestSigningKey(now);
  if (!dueSoon(before)) return null;

  const after = await withMintLock(() => mintUnderLockIf(now, dueSoon));
  return after && after.kid !== before?.kid ? after.kid : null;
}

export async function sweepExpiredKeys(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM signing_keys WHERE expires_at <= ?', [now]);
  return changes;
}
