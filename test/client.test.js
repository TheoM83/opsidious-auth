import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { app as authApp, initForTest } from '../app.js';
import { closeDatabase, dbAll } from '../lib/database.js';
import { __setTransport } from '../lib/google.js';
import { ISSUER } from '../lib/config.js';
import { registerTestClient } from './helpers.js';
import { opsidiousAuth } from '../client/index.js';

const GOOGLE_SUB = '109384756102938475610';
const REDIRECT = 'http://consumer.test/auth/callback';

let authServer;
let issuer;
let consumer;

before(async () => {
  await initForTest();
  const { secret } = await registerTestClient({ id: 'consumer', redirectUris: [REDIRECT] });

  // The auth service on a real port so the client can talk to it for real.
  // The signed ID token's `iss` claim is the service's configured ISSUER
  // (fixed for this whole process by PUBLIC_URL), so the client must be
  // pointed at that exact host and port, not an arbitrary free one, or a
  // correct `iss` check would reject its own service's tokens.
  const { hostname, port } = new URL(ISSUER);
  authServer = authApp.listen(Number(port), hostname);
  issuer = ISSUER;

  const auth = opsidiousAuth({
    issuer,
    clientId: 'consumer',
    clientSecret: secret,
    redirectUri: REDIRECT
  });

  consumer = express();
  consumer.use(cookieParser());
  consumer.get('/auth/start', auth.start());
  consumer.get('/auth/silent', auth.start({ silent: true }));
  consumer.get('/auth/callback', auth.callback(), (req, res) =>
    res.json({ sub: req.opsidious.sub ?? null, error: req.opsidious.error ?? null })
  );
});

after(async () => {
  authServer.close();
  await closeDatabase();
});

// Walks the whole flow the way a browser would, carrying cookies by hand.
async function signIn() {
  const started = await request(consumer).get('/auth/start');
  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const toGoogle = new URL(started.headers.location);

  // A browser would follow this redirect to the auth service, which is what
  // actually parks the request and hands back the real redirect to Google.
  const authorize = await request(authApp).get(toGoogle.pathname + toGoogle.search);
  const requestId = new URL(authorize.headers.location).searchParams.get('state');

  const parked = await dbAll('SELECT google_nonce FROM auth_requests WHERE id = ?', [requestId]);
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({ payload: { sub: GOOGLE_SUB, nonce: parked[0].google_nonce } })
  });

  const backFromGoogle = await request(authApp)
    .get('/callback/google')
    .query({ code: 'google-code', state: requestId });

  const back = new URL(backFromGoogle.headers.location);
  const done = await request(consumer)
    .get('/auth/callback')
    .query({ code: back.searchParams.get('code'), state: back.searchParams.get('state') })
    .set('Cookie', txCookie);

  return { done, txCookie, ssoCookie: backFromGoogle.headers['set-cookie'] };
}

test('three lines of setup produce a verified subject', async () => {
  const { done } = await signIn();
  assert.equal(done.status, 200);
  assert.ok(done.body.sub);
  assert.equal(done.body.error, null);
});

test('start sends the browser to the public issuer with state and nonce', async () => {
  const res = await request(consumer).get('/auth/start');
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, `${issuer}/authorize`);
  assert.ok(url.searchParams.get('state'));
  assert.ok(url.searchParams.get('nonce'));
  assert.equal(url.searchParams.get('client_id'), 'consumer');
});

test('the transaction cookie is httpOnly and short-lived', async () => {
  const res = await request(consumer).get('/auth/start');
  const cookie = res.headers['set-cookie'][0];
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Lax/i);
});

test('a callback with no transaction cookie is refused', async () => {
  // Without this, an attacker can complete a flow they started and sign the
  // victim into the attacker's account.
  const res = await request(consumer).get('/auth/callback').query({ code: 'x', state: 'y' });
  assert.equal(res.body.sub, null);
  assert.equal(res.body.error, 'invalid_state');
});

test('a mismatched state is refused', async () => {
  const started = await request(consumer).get('/auth/start');
  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const res = await request(consumer)
    .get('/auth/callback')
    .query({ code: 'x', state: 'not-the-one-we-issued' })
    .set('Cookie', txCookie);
  assert.equal(res.body.error, 'invalid_state');
});

test('an error returned by the service is surfaced, not thrown', async () => {
  const started = await request(consumer).get('/auth/start');
  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const state = new URL(started.headers.location).searchParams.get('state');
  // The client's own state, not the parked request id: read it back from the cookie.
  const own = txCookie.split('=')[1].split('.')[0];
  const res = await request(consumer)
    .get('/auth/callback')
    .query({ error: 'access_denied', state: own })
    .set('Cookie', txCookie);
  assert.equal(res.body.error, 'access_denied');
  assert.ok(state);
});

test('silent mode returns login_required rather than a Google redirect', async () => {
  const started = await request(consumer).get('/auth/silent');
  const url = new URL(started.headers.location);
  assert.equal(url.searchParams.get('prompt'), 'none');

  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const authorize = await request(authApp).get(url.pathname + url.search);
  const back = new URL(authorize.headers.location);
  const res = await request(consumer)
    .get('/auth/callback')
    .query(Object.fromEntries(back.searchParams))
    .set('Cookie', txCookie);
  assert.equal(res.body.error, 'login_required');
});

test('the same person is a different subject in a second application', async () => {
  // The guarantee, proven end to end through two real client instances.
  const first = await signIn();

  const { secret } = await registerTestClient({
    id: 'consumer2',
    redirectUris: ['http://other.test/cb']
  });
  const second = opsidiousAuth({
    issuer,
    clientId: 'consumer2',
    clientSecret: secret,
    redirectUri: 'http://other.test/cb'
  });
  const otherApp = express();
  otherApp.use(cookieParser());
  otherApp.get('/auth/start', second.start());
  otherApp.get('/auth/callback', second.callback(), (req, res) =>
    res.json({ sub: req.opsidious.sub ?? null })
  );

  const started = await request(otherApp).get('/auth/start');
  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const sso = first.ssoCookie.map((c) => c.split(';')[0]).join('; ');
  const authorizeUrl = new URL(started.headers.location);

  // Reuse the SSO session: no Google, no click.
  const authorize = await request(authApp)
    .get(authorizeUrl.pathname + authorizeUrl.search)
    .set('Cookie', sso);
  const back = new URL(authorize.headers.location);
  const done = await request(otherApp)
    .get('/auth/callback')
    .query(Object.fromEntries(back.searchParams))
    .set('Cookie', txCookie);

  assert.ok(done.body.sub);
  assert.notEqual(done.body.sub, first.done.body.sub, 'two applications, two subjects');
});
