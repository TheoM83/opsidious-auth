// The identity-provider session. It holds its own copy of the pairwise salt,
// sealed under the cookie value, so the silent path never needs the Google
// subject again (spec §4.3).
import { randomUUID } from 'node:crypto';
import { dbGet, dbRun } from './database.js';
import { INFO_SESSION, deriveKey, seal, openSealed, newKdfSalt, sha256, randomToken } from './crypto.js';
import { SSO_TTL_MS } from './config.js';

export async function createSession(accountId, pairwiseSalt, now = Date.now()) {
  const id = randomUUID();
  const cookieValue = randomToken(32);
  const kdfSalt = newKdfSalt();

  await dbRun(
    `INSERT INTO sso_sessions (id, token_hash, account_id, kdf_salt, sealed_salt, expires_at, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [
      id,
      sha256(cookieValue),
      accountId,
      kdfSalt,
      seal(deriveKey(cookieValue, kdfSalt, INFO_SESSION), pairwiseSalt),
      now + SSO_TTL_MS, // absolute, never extended on use
      now
    ]
  );

  return { cookieValue, session: await dbGet('SELECT * FROM sso_sessions WHERE id = ?', [id]) };
}

// Null for anything that does not resolve cleanly: unknown, expired, or
// tampered. A caller only ever has to check for null.
export async function resolveSession(cookieValue, now = Date.now()) {
  if (!cookieValue) return null;
  const session = await dbGet('SELECT * FROM sso_sessions WHERE token_hash = ? AND expires_at > ?', [
    sha256(cookieValue),
    now
  ]);
  if (!session) return null;

  try {
    const key = deriveKey(cookieValue, session.kdf_salt, INFO_SESSION);
    return { session, pairwiseSalt: openSealed(key, session.sealed_salt) };
  } catch {
    // The row exists but does not open: corrupted or tampered with. Refuse.
    return null;
  }
}

export function deleteSessionByCookie(cookieValue) {
  if (!cookieValue) return Promise.resolve({ changes: 0 });
  return dbRun('DELETE FROM sso_sessions WHERE token_hash = ?', [sha256(cookieValue)]);
}

export function deleteSessionById(id) {
  return dbRun('DELETE FROM sso_sessions WHERE id = ?', [String(id)]);
}

export async function sweepSessions(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM sso_sessions WHERE expires_at <= ?', [now]);
  return changes;
}
