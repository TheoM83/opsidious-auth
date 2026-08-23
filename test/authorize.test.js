import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase, dbAll, dbRun } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession } from '../lib/sessions.js';
import { SSO_COOKIE_NAME, SEEN_COOKIE_NAME } from '../lib/config.js';
import { __setTransport } from '../lib/google.js';
import { registerTestClient, CALLBACK } from './helpers.js';

before(async () => {
  await initForTest();
  await registerTestClient({ id: 'defnote' });
});
after(async () => {
  await closeDatabase();
});

// Tests that assert a path never reaches Google install a transport that
// throws on any fetch. Reset it after every test so that stub cannot leak
// into a later test in this file (see test/google.test.js for the pattern).
afterEach(() => {
  __setTransport({ fetchImpl: (...args) => fetch(...args) });
});

const authorize = (over = {}) =>
  request(app)
    .get('/authorize')
    // L'écran d'introduction ne s'affiche qu'à la toute première visite d'un
    // navigateur. Ces tests portent sur le flux, pas sur lui : il a le sien.
    .set('Cookie', `${SEEN_COOKIE_NAME}=1`)
    .query({
      client_id: 'defnote',
      redirect_uri: CALLBACK,
      response_type: 'code',
      scope: 'openid',
      state: 's1',
      nonce: 'n1',
      ...over
    });

// Les deux cookies ensemble : supertest REMPLACE l'en-tête Cookie, il ne le
// complète pas — poser le sien écrasait donc celui du helper, et le test
// tombait sur l'écran d'introduction.
async function sessionCookie() {
  const { account, pairwiseSalt } = await signInWithGoogleSub(`sub-${Math.random()}`);
  const { cookieValue } = await createSession(account.id, pairwiseSalt);
  return `${SSO_COOKIE_NAME}=${cookieValue}; ${SEEN_COOKIE_NAME}=1`;
}

test('with no session it redirects straight to Google', async () => {
  // Spec §6. There is no interstitial page: Google is the only method, so a
  // page offering one choice is friction and an extra surface.
  const res = await authorize();
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
  assert.equal(new URL(res.headers.location).searchParams.get('scope'), 'openid');
  assert.equal(res.text.includes('<html'), false, 'nothing is rendered');
});

test('the response is not cacheable, whether it redirects with a code or asks Google', async () => {
  // /authorize's redirect carries a fresh code in Location - a cache
  // replaying it later would be handing out someone else's code.
  const withSession = await authorize().set('Cookie', await sessionCookie());
  assert.match(withSession.headers['cache-control'], /no-store/);

  const toGoogle = await authorize();
  assert.match(toGoogle.headers['cache-control'], /no-store/);
});

test('the request is parked so the Google round trip can resume it', async () => {
  await authorize({ state: 'parked-state' });
  const rows = await dbAll('SELECT * FROM auth_requests ORDER BY expires_at DESC');
  const parked = rows.find((r) => r.state === 'parked-state');
  assert.ok(parked);
  assert.equal(parked.client_id, 'defnote');
  assert.equal(parked.redirect_uri, CALLBACK);
  assert.ok(parked.google_nonce, 'a nonce binds the Google token to this request');
});

test('an unknown client renders an error and never redirects', async () => {
  // Redirecting to an unverified URI is precisely the open-redirect bug.
  const res = await authorize({ client_id: 'nobody' });
  assert.equal(res.status, 400);
  assert.match(res.headers['content-type'], /text\/html/);
  assert.equal(res.headers.location, undefined);
});

test('an unregistered redirect URI renders an error and never redirects', async () => {
  const res = await authorize({ redirect_uri: 'https://evil.test/steal' });
  assert.equal(res.status, 400);
  assert.equal(res.headers.location, undefined);
  assert.ok(!res.text.includes('evil.test'), 'the error page must not echo it');
});

test('a near-miss redirect URI is refused', async () => {
  const res = await authorize({ redirect_uri: CALLBACK + '/' });
  assert.equal(res.status, 400);
});

test('a missing state redirects back with an error', async () => {
  // The client is valid here, so an error redirect is safe and more useful.
  const res = await authorize({ state: '' });
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, CALLBACK);
  assert.equal(url.searchParams.get('error'), 'invalid_request');
});

test('with a session it issues a code without contacting Google', async () => {
  // Prove it, don't just assert the shape of the redirect: any stray call
  // into lib/google.js fails this test loudly.
  __setTransport({
    fetchImpl: async () => {
      throw new Error('Google must not be contacted on this path');
    }
  });
  const res = await authorize().set('Cookie', await sessionCookie());
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, CALLBACK);
  assert.ok(url.searchParams.get('code'));
  assert.equal(url.searchParams.get('state'), 's1');
});

test('prompt=none with no session returns login_required and never reaches Google', async () => {
  __setTransport({
    fetchImpl: async () => {
      throw new Error('Google must not be contacted on this path');
    }
  });
  const res = await authorize({ prompt: 'none' });
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, CALLBACK);
  assert.equal(url.searchParams.get('error'), 'login_required');
  assert.equal(url.searchParams.get('state'), 's1');
  assert.ok(!res.headers.location.includes('accounts.google.com'));
});

test('prompt=none with a session signs in silently', async () => {
  const res = await authorize({ prompt: 'none' }).set('Cookie', await sessionCookie());
  assert.equal(res.status, 302);
  assert.ok(new URL(res.headers.location).searchParams.get('code'));
});

test('prompt=login ignores the session and asks Google for the chooser', async () => {
  const res = await authorize({ prompt: 'login' }).set('Cookie', await sessionCookie());
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /accounts\.google\.com/);
  assert.equal(new URL(res.headers.location).searchParams.get('prompt'), 'select_account');
});

test('a session cookie that resolves to nothing is treated as anonymous', async () => {
  // Genuine TTL expiry is covered at the unit level in test/sessions.test.js;
  // this only proves the endpoint falls back to the no-session path for a
  // cookie value with no matching row at all.
  const res = await authorize().set('Cookie', `${SSO_COOKIE_NAME}=not-a-real-session; ${SEEN_COOKIE_NAME}=1`);
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /accounts\.google\.com/);
});

test('two applications get different subjects for one person', async () => {
  // The guarantee of §4, observed through the endpoint rather than the unit.
  //
  // Deletes from `codes` first: without this, a row left behind by an earlier
  // test in this file could be one of the two rows compared below, and the
  // assertion would pass while proving nothing about pairwise subjects. This
  // binds over the brief's own text; see task-10-brief.md.
  await dbRun('DELETE FROM codes');

  await registerTestClient({ id: 'otherapp', redirectUris: ['https://other.test/cb'] });
  const cookie = await sessionCookie();

  const one = await authorize().set('Cookie', cookie);
  const two = await request(app)
    .get('/authorize')
    .query({
      client_id: 'otherapp',
      redirect_uri: 'https://other.test/cb',
      response_type: 'code',
      scope: 'openid',
      state: 's',
      nonce: 'n'
    })
    .set('Cookie', cookie);

  const codes = await dbAll('SELECT app_sub, client_id FROM codes');
  const a = codes.find((c) => c.client_id === 'defnote');
  const b = codes.find((c) => c.client_id === 'otherapp');
  assert.ok(one.headers.location && two.headers.location);
  assert.notEqual(a.app_sub, b.app_sub);
});

// The discovery document promises exactly one response type and one scope.
// Before these checks existed the promise was decorative: a client attempting
// the implicit flow with `response_type=token` was handed an authorization
// code, with no error and no way to find out why. Found by pointing the
// reference client at the service rather than by re-reading our own tests.
test('a client attempting the implicit flow is refused, not handed a code', async () => {
  for (const responseType of ['token', 'id_token', 'code token']) {
    const res = await authorize({ response_type: responseType });
    const url = new URL(res.headers.location);
    assert.equal(
      url.searchParams.get('error'),
      'unsupported_response_type',
      `${responseType} must be refused`
    );
    assert.equal(url.searchParams.get('code'), null, 'no code may be issued');
    assert.equal(url.searchParams.get('state'), 's1', 'the error must carry state back');
  }
});

test('a missing response_type is a bad request, not a silent success', async () => {
  const res = await authorize({ response_type: undefined });
  const url = new URL(res.headers.location);
  assert.equal(url.searchParams.get('error'), 'invalid_request');
  assert.equal(url.searchParams.get('code'), null);
});

test('a scope that omits openid is refused rather than half-answered', async () => {
  // This service issues an ID token and nothing else, so `email` or `profile`
  // would be answered with a token carrying neither. Failing loudly beats
  // returning a token that silently lacks what was asked for.
  for (const scope of ['email', 'profile email']) {
    const res = await authorize({ scope });
    assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_scope');
  }
});

test('unrecognised OIDC parameters are ignored, not rejected', async () => {
  // OIDC Core 3.1.2.1: a server ignores request parameters it does not
  // understand. A real client library sends several as a matter of course, so
  // rejecting them would break exactly the integrations this service wants.
  const res = await authorize({
    max_age: '3600',
    display: 'page',
    ui_locales: 'fr',
    login_hint: 'someone@example.test',
    acr_values: '1'
  }).set('Cookie', await sessionCookie());
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.ok(url.searchParams.get('code'), 'the flow must still complete');
  assert.equal(url.searchParams.get('error'), null);
});
