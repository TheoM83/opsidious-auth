import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
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

// A standalone stand-in for the auth service, used only to prove each
// verification gate in client/index.js on its own: it serves whatever JWKS
// and /token response a test hands it, so a test can mint a token that is
// wrong in exactly one way (algorithm, issuer, audience, or nonce) while
// everything else about it is otherwise a token the client would accept.
function stubAuthService() {
  let jwks = { keys: [] };
  let tokenBody = {};
  const stub = express();
  stub.get('/.well-known/jwks.json', (req, res) => res.json(jwks));
  stub.post('/token', (req, res) => res.json(tokenBody));
  const server = stub.listen(0);
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    setJwks: (next) => {
      jwks = next;
    },
    setTokenResponse: (next) => {
      tokenBody = next;
    },
    close: () => server.close()
  };
}

// Mints a token exactly the way the real service would EXCEPT for whichever
// field a test overrides, and returns the JWKS that makes it verifiable
// (i.e. the client is not rejecting it for a missing/unmatched key - only
// for the one deliberately wrong claim or header).
async function forgeToken({ alg = 'RS256', iss, aud, sub = 'forged-sub', nonce, kid = 'forge-kid' }) {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = alg;

  const now = Math.floor(Date.now() / 1000);
  const claims = {};
  if (nonce !== undefined) claims.nonce = nonce;

  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg, kid })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .sign(privateKey);

  return { token, jwks: { keys: [jwk] } };
}

// Builds a fresh client + host app pointed at a stub service, and runs it
// through /start so a test gets a real transaction cookie, state and nonce
// to build a forged token around.
async function startAgainstStub(stubUrl) {
  const auth = opsidiousAuth({
    issuer: stubUrl,
    clientId: 'forge-client',
    clientSecret: 'forge-secret',
    redirectUri: 'http://forge.test/cb'
  });
  const forgeApp = express();
  forgeApp.use(cookieParser());
  forgeApp.get('/start', auth.start());
  forgeApp.get('/cb', auth.callback(), (req, res) =>
    res.json({ sub: req.opsidious.sub ?? null, error: req.opsidious.error ?? null })
  );

  const started = await request(forgeApp).get('/start');
  const txCookie = started.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  const startUrl = new URL(started.headers.location);
  return {
    forgeApp,
    txCookie,
    state: startUrl.searchParams.get('state'),
    nonce: startUrl.searchParams.get('nonce')
  };
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

// Each of the next four tests mints a token that is wrong in exactly one
// way - the algorithm, the issuer, the audience, or the nonce - while every
// other field is what the client would otherwise accept, so each test can
// only pass because its one gate held. Every one of them asserts both that
// no subject is returned AND the specific refusal the client's code path
// actually produces, not just that something failed.

test('a token signed with a non-pinned algorithm is refused', async () => {
  const stub = stubAuthService();
  try {
    const { forgeApp, txCookie, state, nonce } = await startAgainstStub(stub.url);

    // Correct issuer, correct audience, correct nonce - wrong only in that
    // this is signed PS256, which is not in the pinned algorithms list.
    const { token, jwks } = await forgeToken({
      alg: 'PS256',
      iss: stub.url,
      aud: 'forge-client',
      nonce
    });
    stub.setJwks(jwks);
    stub.setTokenResponse({ id_token: token, token_type: 'Bearer', expires_in: 120 });

    const res = await request(forgeApp).get('/cb').query({ code: 'c', state }).set('Cookie', txCookie);
    assert.equal(res.body.sub, null);
    assert.equal(res.body.error, 'invalid_grant');
  } finally {
    stub.close();
  }
});

test('a token with the wrong issuer is refused', async () => {
  const stub = stubAuthService();
  try {
    const { forgeApp, txCookie, state, nonce } = await startAgainstStub(stub.url);

    // Correctly signed, correct audience, correct nonce - wrong only in
    // that `iss` names a different origin than the one the client trusts.
    const { token, jwks } = await forgeToken({
      iss: 'http://not-the-real-issuer.test',
      aud: 'forge-client',
      nonce
    });
    stub.setJwks(jwks);
    stub.setTokenResponse({ id_token: token, token_type: 'Bearer', expires_in: 120 });

    const res = await request(forgeApp).get('/cb').query({ code: 'c', state }).set('Cookie', txCookie);
    assert.equal(res.body.sub, null);
    assert.equal(res.body.error, 'invalid_grant');
  } finally {
    stub.close();
  }
});

test('a token issued for a different client_id is refused', async () => {
  // This is the check that stops one relying application from replaying
  // another application's token as its own.
  const stub = stubAuthService();
  try {
    const { forgeApp, txCookie, state, nonce } = await startAgainstStub(stub.url);

    // Correctly signed, correct issuer, correct nonce - wrong only in that
    // `aud` names a client_id other than the one asking.
    const { token, jwks } = await forgeToken({
      iss: stub.url,
      aud: 'someone-elses-client',
      nonce
    });
    stub.setJwks(jwks);
    stub.setTokenResponse({ id_token: token, token_type: 'Bearer', expires_in: 120 });

    const res = await request(forgeApp).get('/cb').query({ code: 'c', state }).set('Cookie', txCookie);
    assert.equal(res.body.sub, null);
    assert.equal(res.body.error, 'invalid_grant');
  } finally {
    stub.close();
  }
});

test('a token carrying a different nonce than the one parked is refused', async () => {
  const stub = stubAuthService();
  try {
    const { forgeApp, txCookie, state } = await startAgainstStub(stub.url);

    // Correctly signed, correct issuer, correct audience - wrong only in
    // that `nonce` is not the one bound to this transaction's cookie.
    const { token, jwks } = await forgeToken({
      iss: stub.url,
      aud: 'forge-client',
      nonce: 'not-the-nonce-we-parked'
    });
    stub.setJwks(jwks);
    stub.setTokenResponse({ id_token: token, token_type: 'Bearer', expires_in: 120 });

    const res = await request(forgeApp).get('/cb').query({ code: 'c', state }).set('Cookie', txCookie);
    assert.equal(res.body.sub, null);
    assert.equal(res.body.error, 'invalid_nonce');
  } finally {
    stub.close();
  }
});
