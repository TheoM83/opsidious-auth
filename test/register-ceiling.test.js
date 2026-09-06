// The ceiling on open registration.
//
// Its own file because it needs the two limits set against each other before
// lib/config.js is read, and every suite runs in its own process
// (test/run-tests.mjs) — so the numbers below change nothing for anyone else.
//
// What this pins is the reason the ceiling exists at all. The per-address
// limiter is the obvious one and the weaker one: an IPv6 allocation is a /64,
// eighteen quintillion addresses, each of which the limiter counts separately.
// Ten rows per address is then not a bound on the table, it is a bound on
// nothing. The ceiling is keyed on no part of the request, so a flood spread
// across as many addresses as an attacker likes still meets it.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

// Deliberately lopsided: one address is allowed a thousand registrations and
// the service as a whole is allowed three. Anything refused below is therefore
// refused BY THE CEILING, and the test cannot pass by accident because the
// per-address rule happened to fire first.
process.env.REGISTER_RATE_LIMIT_MAX = '1000';
process.env.REGISTER_GLOBAL_MAX = '3';

const { app, initForTest } = await import('../app.js');
const { closeDatabase } = await import('../lib/database.js');
const { REGISTER_GLOBAL_MAX } = await import('../lib/config.js');

before(async () => {
  await initForTest();
});

after(async () => {
  await closeDatabase();
});

const register = (n) =>
  request(app)
    .post('/register')
    .send({ client_name: `Ceiling ${n}`, redirect_uris: ['https://app.example/auth/callback'] });

test('registration has a ceiling that is not keyed on the caller', async () => {
  assert.equal(REGISTER_GLOBAL_MAX, 3, 'the environment override was not read');

  for (let n = 0; n < REGISTER_GLOBAL_MAX; n += 1) {
    const res = await register(n);
    assert.equal(res.status, 201, `registration ${n} should have been allowed`);
  }

  const refused = await register('over');
  assert.equal(refused.status, 429);
  assert.equal(refused.body.error, 'too_many_requests');
});

// The ceiling is a blunt instrument and it is allowed to be, because nothing
// anybody depends on passes through it. A client that already exists signs
// people in exactly as before while registration is closed.
test('a full ceiling does not touch anything already registered', async () => {
  const res = await request(app).get('/.well-known/openid-configuration');
  assert.equal(res.status, 200);
  assert.ok(res.body.authorization_endpoint, 'sign-in must still be advertised');

  const home = await request(app).get('/');
  assert.equal(home.status, 200);
});
