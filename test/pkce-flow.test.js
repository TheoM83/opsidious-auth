import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { publishedJwks } from '../lib/keys.js';
import { issueCode } from '../lib/codes.js';
import { ISSUER } from '../lib/config.js';
import { registerTestPublicClient, registerTestClient, LOOPBACK, CALLBACK } from './helpers.js';

const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

let confidentialSecret;

before(async () => {
  await initForTest();
  await registerTestPublicClient({ id: 'sediment', redirectUris: [LOOPBACK] });
  ({ secret: confidentialSecret } = await registerTestClient({ id: 'defnote' }));
});
after(async () => {
  await closeDatabase();
});

const publicCode = () =>
  issueCode({
    appSub: 'pairwise-sediment',
    clientId: 'sediment',
    redirectUri: LOOPBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

const exchange = (body) =>
  request(app)
    .post('/token')
    .type('form')
    .send({
      grant_type: 'authorization_code',
      client_id: 'sediment',
      redirect_uri: LOOPBACK,
      ...body
    });

test('a public client exchanges with a verifier and no secret', async () => {
  const res = await exchange({ code: await publicCode(), code_verifier: RFC_VERIFIER });
  assert.equal(res.status, 200);

  const { payload } = await jwtVerify(res.body.id_token, createLocalJWKSet(await publishedJwks()), {
    issuer: ISSUER,
    audience: 'sediment',
    algorithms: ['RS256']
  });
  assert.equal(payload.sub, 'pairwise-sediment');
});

test('a public client without a verifier is refused', async () => {
  const res = await exchange({ code: await publicCode() });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: 'invalid_grant' });
});

test('a public client with a wrong verifier is refused', async () => {
  const res = await exchange({ code: await publicCode(), code_verifier: 'E'.repeat(43) });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: 'invalid_grant' });
});

test('a failed verifier does not leave the code reusable', async () => {
  const code = await publicCode();
  await exchange({ code, code_verifier: 'E'.repeat(43) });
  const retry = await exchange({ code, code_verifier: RFC_VERIFIER });
  assert.equal(retry.status, 400, 'the correct verifier must not rescue a burnt code');
});

test('an unknown client is still refused the same way as before', async () => {
  const res = await exchange({
    code: await publicCode(),
    client_id: 'nobody',
    code_verifier: RFC_VERIFIER
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_client');
});

test('a secret sent by a public client changes nothing', async () => {
  // There is no secret on record to compare against. Answering differently
  // for a present and an absent secret would tell a caller which kind of
  // client an id names, which is not theirs to learn.
  const res = await exchange({
    code: await publicCode(),
    code_verifier: RFC_VERIFIER,
    client_secret: 'anything-at-all'
  });
  assert.equal(res.status, 200);
});

test('a confidential client still requires its secret', async () => {
  // The regression guard for everything already deployed.
  const code = await issueCode({
    appSub: 'pairwise-defnote',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    nonce: 'n1'
  });
  const withoutSecret = await request(app).post('/token').type('form').send({
    grant_type: 'authorization_code',
    client_id: 'defnote',
    redirect_uri: CALLBACK,
    code
  });
  assert.equal(withoutSecret.status, 401);
  assert.equal(withoutSecret.body.error, 'invalid_client');

  const withSecret = await request(app).post('/token').type('form').send({
    grant_type: 'authorization_code',
    client_id: 'defnote',
    client_secret: confidentialSecret,
    redirect_uri: CALLBACK,
    code
  });
  assert.equal(withSecret.status, 200);
});
