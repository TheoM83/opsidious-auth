import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { publishedJwks } from '../lib/keys.js';
import { issueCode } from '../lib/codes.js';
import { tokenRateLimitKey } from '../lib/middleware.js';
import { ISSUER, ID_TOKEN_TTL_S, CODE_TTL_MS } from '../lib/config.js';
import { registerTestClient, CALLBACK } from './helpers.js';

let secret;

before(async () => {
  await initForTest();
  ({ secret } = await registerTestClient({ id: 'defnote' }));
});
after(async () => {
  await closeDatabase();
});

const exchange = (over = {}) =>
  request(app)
    .post('/token')
    .type('form')
    .send({
      grant_type: 'authorization_code',
      client_id: 'defnote',
      client_secret: secret,
      redirect_uri: CALLBACK,
      ...over
    });

const freshCode = (over = {}) =>
  issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    nonce: 'n1',
    ...over
  });

test('a valid exchange returns a verifiable ID token', async () => {
  const res = await exchange({ code: await freshCode() });
  assert.equal(res.status, 200);
  assert.equal(res.body.token_type, 'Bearer');
  // ID_TOKEN_TTL_S is configurable via env, so assert against the constant
  // rather than a hardcoded number that would go stale silently.
  assert.equal(res.body.expires_in, ID_TOKEN_TTL_S);

  const { payload } = await jwtVerify(res.body.id_token, createLocalJWKSet(await publishedJwks()), {
    issuer: ISSUER,
    audience: 'defnote',
    algorithms: ['RS256']
  });
  assert.equal(payload.sub, 'pairwise-abc');
  assert.equal(payload.nonce, 'n1');
});

test('the response carries an access token, and it grants nothing', async () => {
  // RFC 6749 section 5.1 and OIDC Core 3.1.3.3 make access_token REQUIRED.
  // Omitting it was the original design decision - there is no Opsidious API
  // to call on a user's behalf - and it broke every conformant client:
  // openid-client refused the exchange with `"response" body "access_token"
  // property must be a string`. Conformance costs one field; a response no
  // standard library can parse costs the integration.
  const res = await exchange({ code: await freshCode() });
  assert.equal(typeof res.body.access_token, 'string');
  assert.ok(res.body.access_token.length >= 32, 'must be opaque, not a placeholder');

  // But it must stay inert. Two exchanges give two different values because
  // nothing stores or looks at them, and no endpoint here accepts one as a
  // credential - "there is no resource server" is the property that matters.
  const second = await exchange({ code: await freshCode() });
  assert.notEqual(second.body.access_token, res.body.access_token);

  const asBearer = await request(app).get('/account').set('Authorization', `Bearer ${res.body.access_token}`);
  assert.notEqual(asBearer.status, 200, 'the access token must not authenticate anything');

  // refresh_token is optional, so it stays absent: there is no long-lived
  // grant to refresh.
  assert.equal(res.body.refresh_token, undefined);
});
test('the response is not cacheable', async () => {
  const res = await exchange({ code: await freshCode() });
  assert.match(res.headers['cache-control'], /no-store/);
});

test('a wrong client secret is refused', async () => {
  const res = await exchange({ code: await freshCode(), client_secret: 'wrong' });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_client');
});

test('a missing client secret is refused', async () => {
  const res = await exchange({ code: await freshCode(), client_secret: '' });
  assert.equal(res.status, 401);
});

test('an unknown client is refused', async () => {
  const res = await exchange({ code: await freshCode(), client_id: 'nobody' });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_client');
});

test('a replayed code is refused', async () => {
  const code = await freshCode();
  assert.equal((await exchange({ code })).status, 200);
  const second = await exchange({ code });
  assert.equal(second.status, 400);
  assert.equal(second.body.error, 'invalid_grant');
});

test('a code issued for another client cannot be redeemed', async () => {
  // Even with valid credentials for the presenting client.
  const { secret: otherSecret } = await registerTestClient({
    id: 'otherapp',
    redirectUris: ['https://other.test/cb']
  });
  const code = await freshCode(); // issued for defnote
  const res = await exchange({
    code,
    client_id: 'otherapp',
    client_secret: otherSecret,
    redirect_uri: 'https://other.test/cb'
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
});

test('a mismatched redirect URI is refused', async () => {
  const res = await exchange({ code: await freshCode(), redirect_uri: CALLBACK + '?x=1' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
});

test('an unknown code is refused', async () => {
  const res = await exchange({ code: 'never-issued' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
});

test('an unsupported grant type is refused', async () => {
  const res = await exchange({ code: await freshCode(), grant_type: 'password' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'unsupported_grant_type');
});

test('failures reveal nothing about which check failed', async () => {
  // invalid_grant for every grant problem: an attacker must not be able to
  // tell "expired" from "wrong client" from "never existed".
  const bodies = await Promise.all([
    exchange({ code: 'never-issued' }).then((r) => r.body),
    exchange({ code: await freshCode(), redirect_uri: CALLBACK + '?x=1' }).then((r) => r.body)
  ]);
  assert.deepEqual(bodies[0], bodies[1]);
});

test('an expired code is refused', async () => {
  const code = await issueCode(
    { appSub: 'pairwise-abc', clientId: 'defnote', redirectUri: CALLBACK, nonce: 'n1' },
    Date.now() - CODE_TTL_MS - 1000
  );
  const res = await exchange({ code });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: 'invalid_grant' });
});

test('tokenLimiter keys on the normalised IPv6 subnet and the client id', () => {
  // Exercises our own wiring, not the third-party library in isolation: this
  // is the exact function tokenLimiter's keyGenerator option is built from
  // (lib/middleware.js), called here with a stub request. Task 9 fixed a
  // raw req.ip crashing express-rate-limit's IPv6 validation; a test that
  // only calls ipKeyGenerator directly would never notice a regression that
  // stopped tokenRateLimitKey from using it at all.
  const key = tokenRateLimitKey({ ip: '2001:db8::1', body: { client_id: 'defnote' } });
  assert.equal(typeof key, 'string');
  // Subnet-normalised, not the literal address.
  assert.ok(!key.includes('2001:db8::1'), `expected a normalised subnet, got ${key}`);
  // The client id is still part of the key, so one client cannot exhaust
  // another's budget.
  assert.ok(key.includes('defnote'), `expected the client id in the key, got ${key}`);
});

test('exactly one concurrent exchange of a freshly issued code succeeds, over HTTP', async () => {
  // The central safety property of this endpoint - consumeCode's guarded
  // UPDATE gives exactly one winner - proven through the real rate-limited
  // route rather than at the library level (test/codes.test.js covers the
  // library alone, bypassing the route and tokenLimiter entirely).
  //
  // A dedicated client keeps this test's rate-limit bucket isolated from the
  // rest of this file's requests, so the "zero 429s" assertion below reflects
  // only this test's own budget (6 rounds x 8 = 48, comfortably under
  // TOKEN_RATE_LIMIT_MAX=60) and doesn't depend on how many requests the
  // other tests in this file happened to make first.
  const { secret: concurrentSecret } = await registerTestClient({ id: 'concurrent-app' });
  const exchangeConcurrent = (over = {}) =>
    request(app)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        client_id: 'concurrent-app',
        client_secret: concurrentSecret,
        redirect_uri: CALLBACK,
        ...over
      });

  const ROUNDS = 6;
  const CONCURRENCY = 8;

  for (let round = 0; round < ROUNDS; round += 1) {
    const code = await issueCode({
      appSub: 'pairwise-abc',
      clientId: 'concurrent-app',
      redirectUri: CALLBACK,
      nonce: 'n1'
    });

    const responses = await Promise.all(
      Array.from({ length: CONCURRENCY }, () => exchangeConcurrent({ code }))
    );

    assert.ok(
      responses.every((r) => r.status !== 429),
      `round ${round}: hit the rate limiter - lower CONCURRENCY/ROUNDS or check TOKEN_RATE_LIMIT_MAX`
    );

    const successes = responses.filter((r) => r.status === 200);
    assert.equal(successes.length, 1, `round ${round}: expected exactly one 200, got ${successes.length}`);

    for (const r of responses) {
      if (r.status === 200) continue;
      assert.equal(r.status, 400);
      assert.deepEqual(r.body, { error: 'invalid_grant' });
    }
  }
});
