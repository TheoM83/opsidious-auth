import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbRun, dbGet, dbAll } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession, resolveSession } from '../lib/sessions.js';
import { issueCode, consumeCode, sweepCodes } from '../lib/codes.js';
import { CODE_RECOVERY_GRACE_MS } from '../lib/config.js';
import { sha256 } from '../lib/crypto.js';

const NOW = 1_800_000_000_000;
const CLIENT = 'defnote';
const CALLBACK = 'https://defnote.test/auth/callback';
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const issue = (over = {}, now = NOW) =>
  issueCode({ appSub: 'sub-abc', clientId: CLIENT, redirectUri: CALLBACK, nonce: 'n1', ...over }, now);

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});
beforeEach(async () => {
  await dbRun('DELETE FROM codes');
});

test('issueCode rejects a missing appSub instead of silently accepting it', async () => {
  // app_sub, client_id and redirect_uri were loosened to nullable in the
  // schema for the post-consumption tombstone (spec §4.2). That must not
  // let a caller bug through at issuance, where a used-to-be-NOT-NULL column
  // used to catch it loudly with SQLITE_CONSTRAINT.
  await assert.rejects(
    () => issueCode({ appSub: '', clientId: CLIENT, redirectUri: CALLBACK }, NOW),
    /appSub/
  );
});

test('issueCode rejects a missing clientId instead of silently accepting it', async () => {
  await assert.rejects(
    () => issueCode({ appSub: 'sub-abc', clientId: undefined, redirectUri: CALLBACK }, NOW),
    /clientId/
  );
});

test('issueCode rejects a missing redirectUri instead of silently accepting it', async () => {
  await assert.rejects(
    () => issueCode({ appSub: 'sub-abc', clientId: CLIENT, redirectUri: null }, NOW),
    /redirectUri/
  );
});

test('a code is opaque and only its hash is stored', async () => {
  const code = await issue();
  assert.ok(code.length >= 32);
  const rows = await dbAll('SELECT code_hash FROM codes');
  assert.equal(rows.length, 1);
  assert.ok(!rows[0].code_hash.includes(code));
});

test('a fresh code is consumed once and yields its row', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, true);
  assert.equal(result.row.app_sub, 'sub-abc');
  assert.equal(result.row.nonce, 'n1');
});

test('the same code cannot be consumed twice', async () => {
  const code = await issue();
  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  const second = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'replayed');
});

test('two concurrent exchanges: exactly one wins', async () => {
  // The reason consumption is a guarded UPDATE and not SELECT-then-DELETE.
  const code = await issue();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW))
  );
  assert.equal(results.filter((r) => r.ok).length, 1);
  assert.equal(results.filter((r) => !r.ok && r.reason === 'replayed').length, 7);
});

test('a replay kills the SSO session the code came from', async () => {
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.ok(await resolveSession(cookieValue, NOW), 'still valid after a legitimate exchange');

  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(await resolveSession(cookieValue, NOW), null, 'a replay means the code leaked');
});

test('an expired code is refused', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW + 61_000);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired');
});

test('a code presented by another client is refused', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: 'otherapp', redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'client_mismatch');
});

test('a code presented with a different redirect URI is refused', async () => {
  const code = await issue();
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK + '?x=1' }, NOW);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'redirect_mismatch');
});

test('a third party never transitions a code it does not own: the rightful client can still redeem it', async () => {
  // Previously any registered client presenting someone else's code, with
  // its own valid credentials, burned the row to REJECTED - the rightful
  // owner's later, legitimate exchange then failed too. The guarded UPDATE
  // now carries the ownership predicates, so a caller that does not own the
  // row can never move it out of UNUSED, only classify why it didn't match.
  const code = await issue();
  const foreign = await consumeCode(code, { clientId: 'otherapp', redirectUri: CALLBACK }, NOW);
  assert.equal(foreign.ok, false);
  assert.equal(foreign.reason, 'client_mismatch');

  const row = await dbGet('SELECT used, client_id FROM codes WHERE code_hash IS NOT NULL');
  assert.equal(row.used, 0, 'a party that does not own the code must never transition it');
  assert.equal(row.client_id, CLIENT, 'not tombstoned - the row was never touched');

  const owner = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(owner.ok, true, 'the rightful owner can still redeem the code afterward');
});

test('an unknown code is refused without an error', async () => {
  const result = await consumeCode('never-issued', { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unknown');
});

test('the sweep removes expired codes', async () => {
  await issue();
  assert.equal(await sweepCodes(NOW), 0);
  assert.equal(await sweepCodes(NOW + 61_000), 1);
});

test('a code rejected for its own wrong redirect URI, then presented legitimately: no session deletion', async () => {
  // A mismatch proves nothing — the code should not be deleted, and the SSO session
  // should not be terminated. The code is marked spent (rejected), but a later
  // legitimate presentation is still a replay and does not kill the user's session.
  //
  // Uses the owning client presenting its own wrong redirect URI, not a
  // third party: a third party's presentation no longer burns the code at
  // all (see the test above), so it can no longer produce a REJECTED row to
  // replay against.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  // First presentation: own client, wrong redirect URI
  const wrongRedirect = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK + '?x=1' }, NOW);
  assert.equal(wrongRedirect.ok, false);
  assert.equal(wrongRedirect.reason, 'redirect_mismatch');
  assert.ok(await resolveSession(cookieValue, NOW), 'session still alive after mismatch');

  // Second presentation: correct client and redirect - still a replay, but session survives
  const replay = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replayed');
  assert.ok(await resolveSession(cookieValue, NOW), 'session still alive after rejected-then-replayed');
});

test('a successful consumption followed by replay kills the session', async () => {
  // This is the real leak detection: if a code is consumed successfully and then
  // presented again, the session it was issued from is deleted.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  // First presentation: success
  const success = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(success.ok, true);
  assert.ok(await resolveSession(cookieValue, NOW), 'session still alive after success');

  // Second presentation: replay kills the session
  const replay = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replayed');
  assert.equal(await resolveSession(cookieValue, NOW), null, 'session deleted on genuine replay');
});

test('a successful consumption tombstones the row: no app, no pairwise subject, but replay still revokes', async () => {
  // While app_sub, client_id and sso_session_id sit together in one row, and
  // sso_session_id joins on to accounts via sso_sessions, the auth database
  // alone can link an account to a named application for as long as that row
  // survives. consumeCode must null the correlating fields in the same
  // UPDATE that marks the code spent, not wait for sweepCodes (spec §4.2).
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  const success = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(success.ok, true);
  // The in-memory row returned to the caller (routes/token.js) still has live
  // values - it was read before the nulling UPDATE ran.
  assert.equal(success.row.app_sub, 'sub-abc');
  assert.equal(success.row.client_id, CLIENT);

  const persisted = await dbGet('SELECT * FROM codes WHERE sso_session_id = ?', [session.id]);
  assert.equal(persisted.app_sub, null, 'no pairwise subject survives consumption');
  assert.equal(persisted.client_id, null, 'no application name survives consumption');
  assert.equal(persisted.nonce, null);
  assert.equal(persisted.redirect_uri, null);
  // What replay detection and session revocation need is exactly this: kept.
  assert.equal(persisted.used, 2);
  assert.ok(persisted.sso_session_id);
  assert.ok(persisted.code_hash);
  assert.ok(persisted.expires_at);

  // A replay of the same (now-tombstoned) code must still revoke the session.
  const replay = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replayed');
  assert.equal(await resolveSession(cookieValue, NOW), null, 'replay still revokes the session');
});

test('an IN_FLIGHT row still within the grace period is a genuine leak, not a wedge', async () => {
  // What consumeCode's normal guarded UPDATE would produce for a real
  // concurrent presentation: the row is claimed (used=1) and nothing has
  // resolved it yet.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });
  await dbRun('UPDATE codes SET used = 1 WHERE sso_session_id = ?', [session.id]);

  const result = await consumeCode(
    code,
    { clientId: CLIENT, redirectUri: CALLBACK },
    NOW + CODE_RECOVERY_GRACE_MS - 1
  );
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'replayed');
  assert.equal(
    await resolveSession(cookieValue, NOW),
    null,
    'still within grace: read as a leak, session killed'
  );
});

test('an IN_FLIGHT row past the grace period is recovered, not treated as a leak', async () => {
  // Exactly what a process death between the guarded UPDATE and its own
  // resolution leaves behind: a row wedged at used=1 forever, with nothing
  // else ever moving it out.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { cookieValue, session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });
  await dbRun('UPDATE codes SET used = 1 WHERE sso_session_id = ?', [session.id]);

  const retryAt = NOW + CODE_RECOVERY_GRACE_MS + 1;
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, retryAt);
  assert.equal(result.ok, true, 'a legitimate retry past the grace period must succeed, not 400');
  assert.equal(result.row.app_sub, 'sub-abc');
  assert.ok(
    await resolveSession(cookieValue, NOW),
    'recovery is a real resolution, not a replay - the session must survive'
  );

  // And the row is now genuinely spent: presenting it again is a real replay.
  const again = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, retryAt);
  assert.equal(again.ok, false);
  assert.equal(again.reason, 'replayed');
});

test('the recovery path still refuses a wedged code that would not have validated anyway', async () => {
  // Recovery reruns the same validation, not a bypass of it: a wedge whose
  // owning client presents the wrong redirect URI is still rejected.
  const code = await issue();
  await dbRun('UPDATE codes SET used = 1 WHERE code_hash IS NOT NULL');

  const retryAt = NOW + CODE_RECOVERY_GRACE_MS + 1;
  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK + '?x=1' }, retryAt);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'redirect_mismatch');
});

test('a rejected code is tombstoned too, not just a successfully consumed one', async () => {
  // Before this, only the success path nulled app_sub/client_id/nonce/
  // redirect_uri. An abandoned or rejected code kept every field live for
  // the rest of its tombstone lifetime, which is exactly the account-to-
  // application link the schema comment (lib/database.js) says must not
  // survive (spec §4.2). Exercised here via an expired code, since it's the
  // simplest rejection to reach without another client's credentials.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610', NOW);
  const { session } = await createSession(account.id, pairwiseSalt, NOW);
  const code = await issue({ ssoSessionId: session.id });

  const result = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW + 61_000);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired');

  const persisted = await dbGet('SELECT * FROM codes WHERE sso_session_id = ?', [session.id]);
  assert.equal(persisted.used, 3, 'rejected');
  assert.equal(persisted.app_sub, null, 'no pairwise subject survives a rejection either');
  assert.equal(persisted.client_id, null, 'no application name survives a rejection either');
  assert.equal(persisted.nonce, null);
  assert.equal(persisted.redirect_uri, null);
  // What replay detection needs is exactly this: kept.
  assert.ok(persisted.sso_session_id);
  assert.ok(persisted.code_hash);
});

test('a third presentation of a rejected-then-replayed code still returns replayed', async () => {
  // The code row persists until sweep, so a third presentation should still
  // return 'replayed', not 'unknown'. Own-client wrong redirect, not a third
  // party, is what still produces a REJECTED row to replay against.
  const code = await issue();
  await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK + '?x=1' }, NOW);
  const second = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(second.reason, 'replayed');
  const third = await consumeCode(code, { clientId: CLIENT, redirectUri: CALLBACK }, NOW);
  assert.equal(third.ok, false);
  assert.equal(third.reason, 'replayed');
});

test('a code issued with a challenge needs the matching verifier', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

  const result = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(result.ok, true);
  assert.equal(result.row.app_sub, 'pairwise-abc');
});

test('a wrong verifier is refused AND burns the code', async () => {
  // Burning it is the point. If a failed verification left the code usable,
  // whoever intercepted it could brute-force the verifier one request at a
  // time - which is precisely the attack PKCE exists to stop.
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

  const first = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: 'E'.repeat(43)
  });
  assert.equal(first.ok, false);
  assert.equal(first.reason, 'pkce_mismatch');

  const second = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(second.ok, false, 'the correct verifier must not rescue a burnt code');
});

test('a missing verifier on a challenged code is refused', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  const result = await consumeCode(code, { clientId: 'defnote', redirectUri: CALLBACK });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'pkce_mismatch');
});

test('a code issued without a challenge still consumes with no verifier', async () => {
  // The confidential path, unchanged. This is the regression guard for every
  // client already deployed.
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    nonce: 'n1'
  });
  const result = await consumeCode(code, { clientId: 'defnote', redirectUri: CALLBACK });
  assert.equal(result.ok, true);
});

test('the tombstone clears the challenge along with everything else', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [sha256(code)]);
  assert.equal(row.code_challenge, null);
  assert.equal(row.code_challenge_method, null);
  assert.equal(row.client_id, null);
});

test('a PKCE mismatch tombstones the challenge method along with the challenge', async () => {
  // The pkce_mismatch path has its own tombstoning UPDATE, separate from the
  // success path above and from the plain rejection path below - each of the
  // three needs its own read-back, since a review found the third
  // (code_challenge_method) missing from all three despite a passing test
  // that only ever checked the success path and never read the full column
  // set back.
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  const result = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: 'E'.repeat(43)
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'pkce_mismatch');

  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [sha256(code)]);
  assert.equal(row.app_sub, null);
  assert.equal(row.client_id, null);
  assert.equal(row.nonce, null);
  assert.equal(row.redirect_uri, null);
  assert.equal(row.code_challenge, null);
  assert.equal(row.code_challenge_method, null);
});

test('a plain rejection tombstones the challenge method along with everything else', async () => {
  // Same read-back gap as above, but for the ordinary rejection path (an
  // expired or wrong-redirect presentation by the code's own owner).
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  const result = await consumeCode(code, { clientId: 'defnote', redirectUri: CALLBACK }, NOW + 61_000);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired');

  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [sha256(code)]);
  assert.equal(row.app_sub, null);
  assert.equal(row.client_id, null);
  assert.equal(row.nonce, null);
  assert.equal(row.redirect_uri, null);
  assert.equal(row.code_challenge, null);
  assert.equal(row.code_challenge_method, null);
});
