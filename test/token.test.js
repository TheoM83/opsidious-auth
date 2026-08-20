import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { ipKeyGenerator } from 'express-rate-limit';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { publishedJwks } from '../lib/keys.js';
import { issueCode } from '../lib/codes.js';
import { ISSUER, ID_TOKEN_TTL_S } from '../lib/config.js';
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

test('no access token is issued', async () => {
  // There is no Opsidious API to call on a user's behalf. Returning an unused
  // access_token would be cargo cult.
  const res = await exchange({ code: await freshCode() });
  assert.equal(res.body.access_token, undefined);
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

test('the token rate limiter normalises an IPv6 address', () => {
  // Every request in this file goes through tokenLimiter, but whether its
  // IPv6 branch actually runs depends on which loopback family supertest
  // happens to bind - not something this suite controls. Exercise the branch
  // directly: this is exactly the call lib/middleware.js's keyGenerator makes,
  // and it is what Task 9 fixed (a raw req.ip fails express-rate-limit's IPv6
  // validation and throws).
  const key = ipKeyGenerator('2001:db8::1');
  assert.equal(typeof key, 'string');
  // Subnet-normalised (a /56 by default), not the literal address.
  assert.notEqual(key, '2001:db8::1');
});
