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
  return dbGet(
    'SELECT * FROM signing_keys WHERE retires_at > ? ORDER BY created_at DESC LIMIT 1',
    [now]
  );
}

export async function currentSigner(now = Date.now()) {
  let row = await newestSigningKey(now);
  if (!row) {
    const kid = await mint(now);
    row = await dbGet('SELECT * FROM signing_keys WHERE kid = ?', [kid]);
  }
  return { kid: row.kid, privateKey: await importPKCS8(row.private_pem, 'RS256') };
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
export async function rotateIfNeeded(now = Date.now()) {
  const row = await newestSigningKey(now);
  if (row && row.retires_at > now + KEY_GRACE_MS) return null;
  return mint(now);
}

export async function sweepExpiredKeys(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM signing_keys WHERE expires_at <= ?', [now]);
  return changes;
}
