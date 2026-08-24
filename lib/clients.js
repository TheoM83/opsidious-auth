// Registered applications. There is no self-service registration: a client is
// added by an operator running scripts/register-client.mjs.
import { dbGet, dbRun } from './database.js';
import { sha256, safeEqual, randomToken } from './crypto.js';

export async function createClient({ id, name, redirectUris, isPublic = false }) {
  if (!id || !name) throw new Error('a client needs an id and a name');
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    throw new Error('a client needs at least one redirect URI');
  }
  if (await getClient(id)) throw new Error(`client ${id} already exists`);

  // A public client has no secret: an installed application would carry it in
  // its binary on every user's machine, where anyone can read it, and a secret
  // everyone can read authenticates nothing. Its proof is PKCE instead.
  //
  // `secret_hash` is NOT NULL, so the row still holds a hash - of a random
  // value generated here and immediately discarded. Nobody, including the
  // operator running this, ever sees its preimage. That way a future bug that
  // sent a public client down the confidential path would be comparing a
  // presented secret against something no one can produce, rather than against
  // an empty string or a fixed sentinel that an attacker could guess.
  const secret = isPublic ? null : randomToken(32);
  const secretHash = sha256(secret ?? randomToken(32));

  await dbRun(
    'INSERT INTO clients (id, name, secret_hash, redirect_uris, is_public, created_at) VALUES (?,?,?,?,?,?)',
    [id, name, secretHash, JSON.stringify(redirectUris), isPublic ? 1 : 0, Date.now()]
  );
  // The secret is returned exactly once. Only its hash is kept.
  return { client: await getClient(id), secret };
}

export function getClient(id) {
  return dbGet('SELECT * FROM clients WHERE id = ?', [String(id)]);
}

// SHA-256 rather than bcrypt: a 32-byte random secret has nothing to
// dictionary-attack, and a deliberately slow hash on the token endpoint is a
// denial-of-service lever rather than a defence (spec §7.7).
export function verifyClientSecret(client, secret) {
  if (!client || !secret) return false;
  return safeEqual(sha256(secret), client.secret_hash);
}

// A client that authenticates with nothing at /token, because it cannot hold a
// credential. Read from the column rather than inferred from an absent secret:
// "has no secret" and "is allowed to present none" must be one explicit
// decision made at registration, not something derived at request time.
export function isPublicClient(client) {
  return Boolean(client && client.is_public);
}

// Exact string equality, nothing else. No prefix match, no normalisation, no
// parsing: every one of those has been someone's open redirect (spec §7.1).
export function redirectAllowed(client, uri) {
  if (!client || typeof uri !== 'string' || !uri) return false;
  let registered;
  try {
    registered = JSON.parse(client.redirect_uris);
  } catch {
    return false;
  }
  return Array.isArray(registered) && registered.includes(uri);
}
