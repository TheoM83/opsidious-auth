// An account is a Google subject we have seen before, and nothing else. No
// email, no name: we never requested them (spec §4).
import { randomUUID } from 'node:crypto';
import { dbGet, dbRun, getSetting, setSettingOnce } from './database.js';
import {
  INFO_ACCOUNT,
  deriveKey,
  seal,
  openSealed,
  newSalt,
  newKdfSalt,
  lookupHash,
  randomToken
} from './crypto.js';

const DAY_MS = 86400000;

// The one service-wide secret. It only enables the *lookup* of an account from
// a Google subject; it cannot unwrap anything. Stored in the database rather
// than the environment so it is backed up with the data it belongs to, and so
// nobody can "fix" it later - replacing it would orphan every account in every
// application, permanently.
export async function ensurePepper() {
  const existing = await getSetting('lookup_pepper');
  if (existing) return existing;
  return setSettingOnce('lookup_pepper', randomToken(32));
}

export function getAccount(id) {
  return dbGet('SELECT * FROM accounts WHERE id = ?', [String(id)]);
}

// Finds or creates the account for a Google subject and returns the plaintext
// pairwise salt. The caller must already hold the Google subject - that is the
// only key that opens the account row.
export async function signInWithGoogleSub(googleSub, now = Date.now()) {
  const pepper = await ensurePepper();
  const hash = lookupHash(pepper, googleSub);
  const existing = await dbGet('SELECT * FROM accounts WHERE google_sub_hash = ?', [hash]);

  if (existing) {
    const key = deriveKey(googleSub, existing.kdf_salt, INFO_ACCOUNT);
    return { account: existing, pairwiseSalt: openSealed(key, existing.sealed_salt) };
  }

  const id = randomUUID();
  const pairwiseSalt = newSalt();
  const kdfSalt = newKdfSalt();
  await dbRun(
    'INSERT INTO accounts (id, google_sub_hash, kdf_salt, sealed_salt, created_at) VALUES (?,?,?,?,?)',
    [
      id,
      hash,
      kdfSalt,
      seal(deriveKey(googleSub, kdfSalt, INFO_ACCOUNT), pairwiseSalt),
      // Rounded to the day: a precise creation time is a correlation handle.
      Math.floor(now / DAY_MS) * DAY_MS
    ]
  );
  return { account: await getAccount(id), pairwiseSalt };
}

export function deleteAccount(id) {
  // sso_sessions cascade via the foreign key.
  return dbRun('DELETE FROM accounts WHERE id = ?', [String(id)]);
}
