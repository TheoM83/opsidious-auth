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
const OUTCOME = Object.freeze({ UNUSED: 0, IN_FLIGHT: 1, SUCCESS: 2, REJECTED: 3 });

import { dbGet, dbRun } from './database.js';
import { sha256, randomToken } from './crypto.js';
import { CODE_TTL_MS } from './config.js';
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

  // A single guarded UPDATE is the whole concurrency defence. SELECT followed
  // by DELETE leaves a window in which two exchanges both succeed (spec §7.4).
  const { changes } = await dbRun('UPDATE codes SET used = ? WHERE code_hash = ? AND used = 0', [
    OUTCOME.IN_FLIGHT,
    hash
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

  // Every terminal state - success below, or a rejection here - nulls the
  // same four fields in the same UPDATE that records the outcome. Before
  // this, only the success path tombstoned the row: an abandoned or rejected
  // code kept `app_sub`/`client_id` live for the rest of its tombstone
  // lifetime, which is exactly the account-to-application link the schema
  // comment (lib/database.js) says must not survive (spec §4.2). `row`,
  // above, was already read before any of these UPDATEs run, so the caller
  // still gets live values where it needs them (routes/token.js does not
  // read a rejected row's fields, but tests and future callers might).
  // Replay detection below only ever branches on `used` and
  // `sso_session_id`, both of which survive every one of these UPDATEs
  // (spec §4.2, §7.5).
  const tombstone = (outcome) =>
    dbRun(
      'UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL, redirect_uri = NULL WHERE code_hash = ?',
      [outcome, hash]
    );

  if (row.expires_at <= now) {
    await tombstone(OUTCOME.REJECTED);
    return { ok: false, reason: 'expired' };
  }
  if (row.client_id !== clientId) {
    await tombstone(OUTCOME.REJECTED);
    return { ok: false, reason: 'client_mismatch' };
  }
  if (row.redirect_uri !== redirectUri) {
    await tombstone(OUTCOME.REJECTED);
    return { ok: false, reason: 'redirect_mismatch' };
  }

  await tombstone(OUTCOME.SUCCESS);
  return { ok: true, row };
}

export async function sweepCodes(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM codes WHERE expires_at <= ?', [now]);
  return changes;
}
