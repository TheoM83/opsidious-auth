// Authorization codes: one shot, sixty seconds, bound to the client and the
// redirect URI they were issued for.
//
// The row carries `app_sub`, already derived - never `account_id`. A code row
// must not record which application a person is signing in to (spec §4.2).
//
// The `used` column encodes the outcome, not just a boolean:
// 0 = not yet presented
// 1 = in-flight (currently being claimed by a concurrent presentation)
// 2 = successfully consumed and validated
// 3 = rejected (expired, client mismatch, or redirect mismatch)
//
// This distinction matters: a code rejected for mismatch is not a leak, so we
// do not delete the user's session if it is presented again correctly. Only a
// successful consumption followed by replay (used=2→2) proves a leak (spec §7.5).
// A concurrent presentation (used=1→2) is also a leak of the code itself.
const OUTCOME = { UNUSED: 0, IN_FLIGHT: 1, SUCCESS: 2, REJECTED: 3 };

import { dbGet, dbRun } from './database.js';
import { sha256, randomToken } from './crypto.js';
import { CODE_TTL_MS } from './config.js';
import { deleteSessionById } from './sessions.js';

export async function issueCode(
  { appSub, clientId, redirectUri, nonce = null, ssoSessionId = null },
  now = Date.now()
) {
  const code = randomToken(32);
  await dbRun(
    `INSERT INTO codes (code_hash, app_sub, client_id, redirect_uri, nonce, sso_session_id, used, expires_at, created_at)
     VALUES (?,?,?,?,?,?,0,?,?)`,
    [sha256(code), appSub, clientId, redirectUri, nonce, ssoSessionId, now + CODE_TTL_MS, now]
  );
  return code;
}

export async function consumeCode(code, { clientId, redirectUri } = {}, now = Date.now()) {
  if (!code) return { ok: false, reason: 'unknown' };
  const hash = sha256(code);

  // A single guarded UPDATE is the whole concurrency defence. SELECT followed
  // by DELETE leaves a window in which two exchanges both succeed (spec §7.4).
  const { changes } = await dbRun('UPDATE codes SET used = ? WHERE code_hash = ? AND used = 0', [
    OUTCOME.IN_FLIGHT,
    hash,
  ]);

  if (changes !== 1) {
    const spent = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
    if (!spent) return { ok: false, reason: 'unknown' };

    // Distinguish between a genuine replay (successful consumption) and a rejected code.
    if (spent.used === OUTCOME.SUCCESS) {
      // Presented twice after successful consumption. The code leaked (spec §7.5).
      if (spent.sso_session_id) await deleteSessionById(spent.sso_session_id);
      return { ok: false, reason: 'replayed' };
    } else if (spent.used === OUTCOME.REJECTED) {
      // Previously rejected on validation (expired, client mismatch, redirect mismatch).
      // A mismatch does not prove a leak, so don't delete the session.
      return { ok: false, reason: 'replayed' };
    } else if (spent.used === OUTCOME.IN_FLIGHT) {
      // Concurrent presentation: two simultaneous exchanges of one code is a leak (spec §7.5).
      if (spent.sso_session_id) await deleteSessionById(spent.sso_session_id);
      return { ok: false, reason: 'replayed' };
    }
    return { ok: false, reason: 'unknown' };
  }

  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
  if (row.expires_at <= now) {
    await dbRun('UPDATE codes SET used = ? WHERE code_hash = ?', [OUTCOME.REJECTED, hash]);
    return { ok: false, reason: 'expired' };
  }
  if (row.client_id !== clientId) {
    await dbRun('UPDATE codes SET used = ? WHERE code_hash = ?', [OUTCOME.REJECTED, hash]);
    return { ok: false, reason: 'client_mismatch' };
  }
  if (row.redirect_uri !== redirectUri) {
    await dbRun('UPDATE codes SET used = ? WHERE code_hash = ?', [OUTCOME.REJECTED, hash]);
    return { ok: false, reason: 'redirect_mismatch' };
  }

  // Validation passed: mark as successfully consumed.
  await dbRun('UPDATE codes SET used = ? WHERE code_hash = ?', [OUTCOME.SUCCESS, hash]);
  return { ok: true, row };
}

export async function sweepCodes(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM codes WHERE expires_at <= ?', [now]);
  return changes;
}
