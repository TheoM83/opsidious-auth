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
// A concurrent presentation (used=1→2) is also a leak of the code itself - but
// only within CODE_RECOVERY_GRACE_MS of the code's creation, and only when the
// presenting client is the code's own owner (see consumeCode below: a client
// that does not own the row never transitions it at all, so it can never
// produce this state in the first place). Past the grace period, a row still
// sitting at 1 cannot be a live race (a real resolution finishes in
// milliseconds); it is read as a wedge left by a process death between an
// earlier claim and that claim's own resolution, and is recovered rather
// than treated as a leak.
const OUTCOME = Object.freeze({ UNUSED: 0, IN_FLIGHT: 1, SUCCESS: 2, REJECTED: 3 });

import { dbGet, dbRun } from './database.js';
import { sha256, randomToken } from './crypto.js';
import { CODE_TTL_MS, CODE_RECOVERY_GRACE_MS } from './config.js';
import { deleteSessionById } from './sessions.js';

export async function issueCode(
  { appSub, clientId, redirectUri, nonce = null, ssoSessionId = null },
  now = Date.now()
) {
  // app_sub, client_id and redirect_uri are nullable in the schema now - they
  // get nulled out on successful consumption, for the tombstone (see the
  // schema comment in lib/database.js). That relaxation was for
  // consumeCode's UPDATE, not for issueCode's INSERT: a caller bug that used
  // to fail loudly with SQLITE_CONSTRAINT would otherwise now be silently
  // accepted and only surface later, as a code that can never legitimately
  // validate. Enforce here what the schema can no longer enforce for us.
  if (!appSub) throw new Error('issueCode: appSub is required');
  if (!clientId) throw new Error('issueCode: clientId is required');
  if (!redirectUri) throw new Error('issueCode: redirectUri is required');

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
  const staleBefore = now - CODE_RECOVERY_GRACE_MS;

  // The single guarded UPDATE is still the whole concurrency defence (spec
  // §7.4) - SELECT followed by DELETE leaves a window in which two exchanges
  // both succeed - but it now carries every predicate that decides whether
  // THIS caller may claim the row at all, not just whether the row is free:
  //
  //  - client_id / redirect_uri / expires_at: only the code's own owner,
  //    presenting it correctly and before it expires, can transition it. Any
  //    other registered client, even with its own perfectly valid
  //    credentials, cannot burn someone else's code just by holding it - the
  //    review's own framing is right that this presupposes already holding
  //    the 32-byte code, but there is no reason to let that attacker move
  //    the row at all when the check is this cheap to fold in.
  //  - used = 0, or used = 1 and old enough (see CODE_RECOVERY_GRACE_MS
  //    above): a fresh code, or one wedged by a crash between an earlier
  //    claim and that claim's own resolution, reclaimed here rather than
  //    left to rot - but only for the code's own owner, and only once it is
  //    clearly too old to still be a live race.
  const { changes } = await dbRun(
    `UPDATE codes SET used = ?
      WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND expires_at > ?
        AND (used = 0 OR (used = 1 AND created_at <= ?))`,
    [OUTCOME.IN_FLIGHT, hash, clientId, redirectUri, now, staleBefore]
  );

  if (changes !== 1) {
    const spent = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
    if (!spent) return { ok: false, reason: 'unknown' };

    if (spent.used === OUTCOME.SUCCESS) {
      // Presented twice after successful consumption. The code leaked (spec §7.5).
      if (spent.sso_session_id) await deleteSessionById(spent.sso_session_id);
      return { ok: false, reason: 'replayed' };
    }
    if (spent.used === OUTCOME.REJECTED) {
      // Previously rejected on validation (expired, client mismatch, redirect mismatch).
      // A mismatch does not prove a leak, so don't delete the session.
      return { ok: false, reason: 'replayed' };
    }
    if (spent.used === OUTCOME.IN_FLIGHT && spent.created_at > staleBefore) {
      // Still within the grace period: two simultaneous exchanges of one
      // code is a leak of the code itself (spec §7.5). Past the grace
      // period, the guarded UPDATE above would already have reclaimed this
      // row if the caller's own client_id/redirect_uri/expiry matched it -
      // so falling through here (below) is what happens for the code's own
      // owner presenting a genuinely stale wedge with the wrong redirect URI
      // or after it has expired, exactly like a fresh row.
      if (spent.sso_session_id) await deleteSessionById(spent.sso_session_id);
      return { ok: false, reason: 'replayed' };
    }

    // used = 0, or a stale IN_FLIGHT wedge this caller's own predicates did
    // not match above: the guarded UPDATE's predicates are why it didn't
    // match, not a race. Never transition a row on behalf of a client that
    // does not own it - classify only, so a third party's presentation can
    // never burn someone else's code (unlike every other rejection here,
    // which does tombstone it - see the review).
    if (spent.client_id !== clientId) {
      return { ok: false, reason: 'client_mismatch' };
    }

    // This client owns the code: an expired or wrong-redirect presentation
    // is its own misuse, which still burns the code (otherwise this
    // endpoint would let a client probe its own code risk-free) and is
    // tombstoned exactly like a success (spec §4.2). Guarded on `used` so a
    // race with another resolution of the same row is never blindly
    // overwritten.
    const reason = spent.expires_at <= now ? 'expired' : 'redirect_mismatch';
    await dbRun(
      `UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL, redirect_uri = NULL
        WHERE code_hash = ? AND used IN (?, ?)`,
      [OUTCOME.REJECTED, hash, OUTCOME.UNUSED, OUTCOME.IN_FLIGHT]
    );
    return { ok: false, reason };
  }

  // Claimed IN_FLIGHT - a fresh code, or a stale wedge just reclaimed above -
  // and client_id, redirect_uri and expiry were already validated by the
  // WHERE clause, so this is a straightforward success. Tombstone in the
  // same UPDATE that marks it spent: null every field that could otherwise
  // go on linking an account to a named application for the rest of this
  // row's tombstone lifetime (spec §4.2). `row` was read before this UPDATE
  // runs, so the caller (routes/token.js) still gets live values. Replay
  // detection above only ever branches on `used` and `sso_session_id`, both
  // of which survive (spec §7.5).
  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
  await dbRun(
    'UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL, redirect_uri = NULL WHERE code_hash = ?',
    [OUTCOME.SUCCESS, hash]
  );
  return { ok: true, row };
}

export async function sweepCodes(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM codes WHERE expires_at <= ?', [now]);
  return changes;
}
