import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase, dbAll, dbGet } from '../lib/database.js';
import { __setTransport } from '../lib/google.js';
import { SSO_COOKIE_NAME } from '../lib/config.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession, resolveSession } from '../lib/sessions.js';
import { registerTestClient, CALLBACK } from './helpers.js';

const GOOGLE_SUB = '109384756102938475610';

before(async () => {
  await initForTest();
  await registerTestClient({ id: 'defnote' });
});
after(async () => {
  await closeDatabase();
});

// Google always succeeds unless a test says otherwise. The nonce echoed back
// is whichever one we parked, which is what the real Google does.
beforeEach(async () => {
  const parked = await dbAll('SELECT google_nonce FROM auth_requests ORDER BY expires_at DESC');
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({
      payload: { sub: GOOGLE_SUB, nonce: parked[0] ? parked[0].google_nonce : 'none' }
    })
  });
});

async function startFlow(over = {}) {
  const res = await request(app)
    .get('/authorize')
    .query({ client_id: 'defnote', redirect_uri: CALLBACK, state: 's1', nonce: 'n1', ...over });
  return new URL(res.headers.location).searchParams.get('state'); // the parked request id
}

async function completeFlow(requestId) {
  const parked = await dbGet('SELECT google_nonce FROM auth_requests WHERE id = ?', [requestId]);
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({
      payload: { sub: GOOGLE_SUB, nonce: parked ? parked.google_nonce : 'wrong' }
    })
  });
  return request(app).get('/callback/google').query({ code: 'google-code', state: requestId });
}

test('a completed Google round trip redirects back with a code', async () => {
  const res = await completeFlow(await startFlow());
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, CALLBACK);
  assert.ok(url.searchParams.get('code'));
  assert.equal(url.searchParams.get('state'), 's1', 'the application state is returned untouched');
});

test('the SSO cookie is set with every hardening attribute', async () => {
  const res = await completeFlow(await startFlow());
  const cookie = res.headers['set-cookie'].find((c) => c.startsWith(SSO_COOKIE_NAME));
  assert.ok(cookie, 'the session cookie must be set');
  assert.match(cookie, /^__Host-/, 'the __Host- prefix forbids a Domain attribute');
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Lax/i);
  assert.match(cookie, /Path=\//i);
  assert.match(cookie, /;\s*Secure/i, '__Host- cookies are rejected by every browser without Secure');
  assert.doesNotMatch(cookie, /Domain=/i, 'a Domain would expose it to sibling subdomains');
});

test('the account is created once across repeated sign-ins', async () => {
  const before = (await dbAll('SELECT id FROM accounts')).length;
  await completeFlow(await startFlow());
  await completeFlow(await startFlow());
  const after = (await dbAll('SELECT id FROM accounts')).length;
  assert.equal(
    after,
    before,
    'no new account row was created across two sign-ins with the same Google subject'
  );
});

test('the parked request is consumed and cannot be reused', async () => {
  const id = await startFlow();
  await completeFlow(id);
  assert.equal(await dbGet('SELECT id FROM auth_requests WHERE id = ?', [id]), undefined);

  const replay = await request(app).get('/callback/google').query({ code: 'x', state: id });
  assert.equal(replay.status, 400);
});

test('an unknown state renders an error and never redirects', async () => {
  // There is no verified redirect URI to send them to.
  const res = await request(app).get('/callback/google').query({ code: 'x', state: 'never-parked' });
  assert.equal(res.status, 400);
  assert.equal(res.headers.location, undefined);
});

test('a wrong Google nonce is refused and touches no account', async () => {
  const id = await startFlow();
  const before = (await dbAll('SELECT id FROM accounts')).length;
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({ payload: { sub: '99999', nonce: 'not-the-parked-one' } })
  });
  const res = await request(app).get('/callback/google').query({ code: 'x', state: id });

  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'access_denied');
  assert.equal((await dbAll('SELECT id FROM accounts')).length, before, 'no account was written');
});

test('a failed Google exchange redirects back with an error', async () => {
  const id = await startFlow();
  __setTransport({
    fetchImpl: async () => ({ ok: false, status: 400, json: async () => ({}) })
  });
  const res = await request(app).get('/callback/google').query({ code: 'x', state: id });
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.searchParams.get('error'), 'access_denied');
  assert.equal(url.searchParams.get('state'), 's1');
});

test('a user who cancels at Google is sent back cleanly', async () => {
  const id = await startFlow();
  // Prove the cancel path returns before ever contacting Google. A thrown
  // fetchImpl alone would not distinguish this from a broken implementation
  // that falls through to a failed exchange - both end in the same
  // access_denied redirect - so also assert the exchange was never attempted.
  let contacted = false;
  __setTransport({
    fetchImpl: async () => {
      contacted = true;
      throw new Error('Google must not be contacted on the cancel path');
    }
  });
  const res = await request(app).get('/callback/google').query({ error: 'access_denied', state: id });
  assert.equal(contacted, false, 'the cancel path must not attempt the Google exchange');
  assert.equal(res.status, 302);
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'access_denied');
});

test('re-authenticating (prompt=login) revokes the session named by the cookie the browser still holds', async () => {
  // A live session never reaches Google at all except via prompt=login
  // forcing it past one (routes/authorize.js) - so the browser completing a
  // round trip through Google while still presenting an old SSO cookie only
  // happens on exactly this path. Left unrevoked, that old session would
  // keep working under a cookie the browser itself has already replaced,
  // for the rest of its own 14-day life.
  const { account, pairwiseSalt } = await signInWithGoogleSub('old-google-sub');
  const { cookieValue: oldCookie } = await createSession(account.id, pairwiseSalt);
  assert.ok(await resolveSession(oldCookie), 'the pre-existing session is live before re-authentication');

  const started = await request(app)
    .get('/authorize')
    .query({ client_id: 'defnote', redirect_uri: CALLBACK, state: 's1', nonce: 'n1', prompt: 'login' })
    .set('Cookie', `${SSO_COOKIE_NAME}=${oldCookie}`);
  const requestId = new URL(started.headers.location).searchParams.get('state');

  const parked = await dbGet('SELECT google_nonce FROM auth_requests WHERE id = ?', [requestId]);
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({ payload: { sub: GOOGLE_SUB, nonce: parked.google_nonce } })
  });
  const res = await request(app)
    .get('/callback/google')
    .query({ code: 'google-code', state: requestId })
    .set('Cookie', `${SSO_COOKIE_NAME}=${oldCookie}`); // the browser still holds its old cookie mid-flow

  const newCookie = res.headers['set-cookie']
    .find((c) => c.startsWith(SSO_COOKIE_NAME))
    .split(';')[0]
    .split('=')[1];
  assert.notEqual(newCookie, oldCookie, 'a fresh cookie is issued');
  assert.equal(await resolveSession(oldCookie), null, 'the old session is revoked, not orphaned');
  assert.ok(await resolveSession(newCookie), 'the new session is live');
});

test('the second sign-in is silent and never contacts Google again', async () => {
  const res = await completeFlow(await startFlow());
  const cookie = res.headers['set-cookie'].find((c) => c.startsWith(SSO_COOKIE_NAME)).split(';')[0];

  __setTransport({
    fetchImpl: async () => {
      throw new Error('Google must not be contacted on the silent path');
    }
  });
  const silent = await request(app)
    .get('/authorize')
    .query({ client_id: 'defnote', redirect_uri: CALLBACK, state: 's2', nonce: 'n2' })
    .set('Cookie', cookie);

  assert.equal(silent.status, 302);
  assert.ok(new URL(silent.headers.location).searchParams.get('code'));
});
