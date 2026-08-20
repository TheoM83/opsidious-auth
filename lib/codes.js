// Authorization codes: one shot, sixty seconds, bound to the client and the
// redirect URI they were issued for.
//
// The row carries `app_sub`, already derived - never `account_id`. A code row
// must not record which application a person is signing in to (spec §4.2).
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

export async function consumeCode(code, { clientId, redirectUri }, now = Date.now()) {
  if (!code) return { ok: false, reason: 'unknown' };
  const hash = sha256(code);

  // A single guarded UPDATE is the whole concurrency defence. SELECT followed
  // by DELETE leaves a window in which two exchanges both succeed (spec §7.4).
  const { changes } = await dbRun('UPDATE codes SET used = 1 WHERE code_hash = ? AND used = 0', [hash]);

  if (changes !== 1) {
    const spent = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
    if (!spent) return { ok: false, reason: 'unknown' };
    // Presented twice. The only way that happens is a leak, so the session it
    // was issued from is no longer trustworthy (spec §7.5).
    if (spent.sso_session_id) await deleteSessionById(spent.sso_session_id);
    await dbRun('DELETE FROM codes WHERE code_hash = ?', [hash]);
    return { ok: false, reason: 'replayed' };
  }

  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);
  if (row.expires_at <= now) return { ok: false, reason: 'expired' };
  if (row.client_id !== clientId) return { ok: false, reason: 'client_mismatch' };
  if (row.redirect_uri !== redirectUri) return { ok: false, reason: 'redirect_mismatch' };
  return { ok: true, row };
}

export async function sweepCodes(now = Date.now()) {
  const { changes } = await dbRun('DELETE FROM codes WHERE expires_at <= ?', [now]);
  return changes;
}
