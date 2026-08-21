// Registered applications. There is no self-service registration: a client is
// added by an operator running scripts/register-client.mjs.
import { dbGet, dbRun } from './database.js';
import { sha256, safeEqual, randomToken } from './crypto.js';

export async function createClient({ id, name, redirectUris }) {
  if (!id || !name) throw new Error('a client needs an id and a name');
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    throw new Error('a client needs at least one redirect URI');
  }
  if (await getClient(id)) throw new Error(`client ${id} already exists`);

  const secret = randomToken(32);
  await dbRun('INSERT INTO clients (id, name, secret_hash, redirect_uris, created_at) VALUES (?,?,?,?,?)', [
    id,
    name,
    sha256(secret),
    JSON.stringify(redirectUris),
    Date.now()
  ]);
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
