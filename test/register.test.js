// Open registration (RFC 7591).
//
// The interesting assertions here are not "the happy path returns 201". They
// are the ones that pin down WHY an unauthenticated write endpoint is safe on
// this particular service: a registered client cannot reach anyone, cannot name
// itself something a person will read, and cannot store anything.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

// Set BEFORE app.js is loaded, because lib/config.js reads the environment once
// at module load. Every suite runs in its own process (test/run-tests.mjs), so
// this changes nothing for anyone else.
//
// The default is 10 registrations an hour from one address, and this file makes
// far more than that: the first version of it failed four tests on the limiter
// rather than on anything it meant to check. Raised here, and then pinned by
// its own test at the bottom - a limiter nobody exercises is a limiter nobody
// notices breaking.
process.env.REGISTER_RATE_LIMIT_MAX = '40';

const { app, initForTest } = await import('../app.js');
const { closeDatabase } = await import('../lib/database.js');
const { getClient, verifyClientSecret, isPublicClient } = await import('../lib/clients.js');
const { validateRedirectUri } = await import('../lib/registration.js');
const { REGISTER_RATE_LIMIT_MAX } = await import('../lib/config.js');

before(async () => {
  await initForTest();
});
after(async () => {
  await closeDatabase();
});

const register = (body) => request(app).post('/register').send(body);

const VALID = {
  client_name: 'Test application',
  redirect_uris: ['https://app.example/auth/callback']
};

test('an application registers itself, with nobody in the loop', async () => {
  const res = await register(VALID);

  assert.equal(res.status, 201);
  assert.ok(res.body.client_id, 'a client_id comes back');
  assert.ok(res.body.client_secret, 'a confidential client gets a secret');
  assert.equal(res.body.client_secret_expires_at, 0, 'the secret does not expire');
  assert.equal(res.body.token_endpoint_auth_method, 'client_secret_post');
  assert.deepEqual(res.body.grant_types, ['authorization_code']);
  // Stated in the response, so an integrator cannot fail to have been told what
  // the subject they receive actually is.
  assert.equal(res.body.subject_type, 'pairwise');

  const client = await getClient(res.body.client_id);
  assert.ok(client, 'the row exists');
  assert.ok(verifyClientSecret(client, res.body.client_secret), 'the secret is the real one');
  assert.ok(!isPublicClient(client));
});

test('the response is never cached: it carries a secret exactly once', async () => {
  const res = await register(VALID);
  assert.match(res.headers['cache-control'], /no-store/);
});

test('a public client gets no secret at all, rather than an empty one', async () => {
  const res = await register({ ...VALID, token_endpoint_auth_method: 'none' });

  assert.equal(res.status, 201);
  assert.equal(res.body.client_secret, undefined, 'the field is absent, not null or ""');
  assert.ok(!('client_secret_expires_at' in res.body));
  assert.ok(isPublicClient(await getClient(res.body.client_id)));
});

test('a self-registered client can actually sign someone in', async () => {
  // The proof that registration is real rather than a row in a table nobody
  // reads: the resulting client_id passes /authorize's own validation.
  const redirect = 'https://real.example/auth/callback';
  const { body } = await register({ client_name: 'Real', redirect_uris: [redirect] });

  const res = await request(app).get('/authorize').query({
    client_id: body.client_id,
    redirect_uri: redirect,
    response_type: 'code',
    scope: 'openid',
    state: 'abc'
  });

  // No session, so it is either the introduction screen or a redirect to
  // Google. Both mean the client was accepted; a rejected one renders a 400.
  assert.ok([200, 302].includes(res.status), `expected the flow to start, got ${res.status}`);
});

test('the caller does not choose its own client_id', async () => {
  // `defnote` is a real client id on the live deployment. An id that looks like
  // somebody else's is the one part of this exchange that could mislead a human
  // reading a URL, so the caller does not get to pick.
  const res = await register({ ...VALID, client_id: 'defnote' });
  assert.equal(res.status, 201);
  assert.notEqual(res.body.client_id, 'defnote');
});

// ── The phishing guard ───────────────────────────────────────────────────

test('a name an unauthenticated caller chose never reaches a page', async () => {
  const phishy = 'Opsidious Official Login';
  const redirect = 'https://phish.example/cb';
  const { body } = await register({ client_name: phishy, redirect_uris: [redirect] });

  const screen = await request(app).get('/authorize').query({
    client_id: body.client_id,
    redirect_uri: redirect,
    response_type: 'code',
    scope: 'openid',
    state: 'abc'
  });

  // If this ever fails, open registration has become a way to put chosen words
  // next to a trust decision. The sign-in screen is about Opsidious and Google;
  // it says nothing about the application, deliberately.
  assert.ok(!screen.text.includes(phishy), 'the sign-in screen must not display a client-supplied name');

  const home = await request(app).get('/');
  assert.ok(!home.text.includes(phishy));
});

// ── Redirect URIs ────────────────────────────────────────────────────────

test('https anywhere, http only on the loopback IP literal', () => {
  assert.ok(validateRedirectUri('https://app.example/cb').ok);
  assert.ok(validateRedirectUri('http://127.0.0.1:47821/callback').ok);
  assert.ok(validateRedirectUri('http://[::1]:47821/callback').ok);
  // RFC 8252 §7.1: a private-use scheme must be reverse-DNS.
  assert.ok(validateRedirectUri('com.example.app:/callback').ok);

  assert.ok(!validateRedirectUri('http://app.example/cb').ok, 'plain http is refused');
  assert.ok(!validateRedirectUri('myapp:/cb').ok, 'a scheme without a dot is claimable by anyone');
  assert.ok(!validateRedirectUri('ftp://app.example/cb').ok);
  assert.ok(!validateRedirectUri('/relative/cb').ok);
  assert.ok(!validateRedirectUri('https://app.example/cb#frag').ok, 'RFC 6749 §3.1.2');
  assert.ok(!validateRedirectUri('https://user:pw@app.example/cb').ok, 'no userinfo');
  assert.ok(!validateRedirectUri('https://*.example/cb').ok, 'matching is exact; a wildcard is a lie');
  assert.ok(!validateRedirectUri(' https://app.example/cb').ok, 'whitespace would never match');
});

test('localhost is refused, and the message says what to use instead', () => {
  const result = validateRedirectUri('http://localhost:47821/cb');
  assert.ok(!result.ok);
  // A name is resolved; a resolver an attacker influences turns a native
  // application's redirect into somebody else's.
  assert.match(result.description, /127\.0\.0\.1/);
});

test('a bad redirect URI is refused as invalid_redirect_uri, per RFC 7591 §3.2.2', async () => {
  const res = await register({ ...VALID, redirect_uris: ['http://app.example/cb'] });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_redirect_uri');
  assert.ok(res.body.error_description, 'an integrator gets told what to fix');
});

test('redirect_uris is required and bounded', async () => {
  assert.equal((await register({ client_name: 'x' })).status, 400);
  assert.equal((await register({ ...VALID, redirect_uris: [] })).status, 400);

  const many = Array.from({ length: 6 }, (_, i) => `https://app.example/cb${i}`);
  const res = await register({ ...VALID, redirect_uris: many });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_redirect_uri');
});

test('a duplicate redirect URI is refused rather than silently deduplicated', async () => {
  const res = await register({
    ...VALID,
    redirect_uris: ['https://app.example/cb', 'https://app.example/cb']
  });
  assert.equal(res.status, 400);
});

// ── Metadata ─────────────────────────────────────────────────────────────

test('metadata this service does not implement is refused, not ignored', async () => {
  // Same reasoning as /authorize checking response_type: advertising exactly
  // one grant type and then accepting a declaration of another one makes the
  // discovery document decorative.
  for (const body of [
    { ...VALID, token_endpoint_auth_method: 'client_secret_basic' },
    { ...VALID, grant_types: ['refresh_token'] },
    { ...VALID, response_types: ['token'] }
  ]) {
    const res = await register(body);
    assert.equal(res.status, 400, JSON.stringify(body));
    assert.equal(res.body.error, 'invalid_client_metadata');
  }
});

test('the name is optional, bounded, and cannot forge a log line', async () => {
  const anonymous = await register({ redirect_uris: ['https://app.example/cb'] });
  assert.equal(anonymous.status, 201, 'a name is not required: there is nobody to identify');

  const long = await register({ ...VALID, client_name: 'x'.repeat(200) });
  assert.equal(long.status, 400);

  const injected = await register({ ...VALID, client_name: 'ok\ninfo: forged line' });
  assert.equal(injected.status, 400);
});

test('a body that is not an object is a 400, not a 500', async () => {
  const res = await request(app).post('/register').type('json').send('"just a string"');
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_client_metadata');
});

// ── The limiter ──────────────────────────────────────────────────────────

test('registration is rate limited: it is the only unauthenticated write', async () => {
  // Everything above has already spent part of the budget, so this walks until
  // it is refused rather than assuming a starting point.
  let refused = null;
  for (let i = 0; i <= REGISTER_RATE_LIMIT_MAX + 1 && !refused; i += 1) {
    const res = await register({ redirect_uris: [`https://flood.example/cb${i}`] });
    if (res.status === 429) refused = res;
  }

  assert.ok(refused, 'an unbounded open endpoint is a table someone decides to fill');
  assert.equal(refused.body.error, 'too_many_requests');
});
