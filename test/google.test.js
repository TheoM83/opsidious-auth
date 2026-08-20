import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import {
  authorizeUrl,
  exchangeCode,
  verifyGoogleIdToken,
  __setTransport,
  __verifyGoogleJwt
} from '../lib/google.js';
import { GOOGLE_CLIENT_ID } from '../lib/config.js';

const GOOGLE_ISSUER = 'https://accounts.google.com';

async function localSubjectFixture(alg) {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(publicKey);
  jwk.kid = `test-${alg}`;
  jwk.alg = alg;
  jwk.use = 'sig';
  return { privateKey, kid: jwk.kid, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

function signToken(privateKey, alg, kid, { nonce = 'n1', sub = '109384756102938475610' } = {}) {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg, kid })
    .setIssuer(GOOGLE_ISSUER)
    .setAudience(GOOGLE_CLIENT_ID)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

beforeEach(() => {
  __setTransport({
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ id_token: 'stub' }) }),
    verifyImpl: async () => ({ payload: { sub: '109384756102938475610', nonce: 'n1' } })
  });
});

test('the authorize URL asks for openid and nothing else', () => {
  // Spec §7.11. Requesting `email` or `profile` would hand us data we then
  // have to promise not to keep. Not asking is the stronger guarantee.
  const url = new URL(authorizeUrl({ state: 's1', nonce: 'n1' }));
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(url.searchParams.get('scope'), 'openid');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('state'), 's1');
  assert.equal(url.searchParams.get('nonce'), 'n1');
  assert.ok(url.searchParams.get('redirect_uri').endsWith('/callback/google'));
});

test('the account chooser is requested only when asked for', () => {
  assert.equal(new URL(authorizeUrl({ state: 's', nonce: 'n' })).searchParams.get('prompt'), null);
  const forced = new URL(authorizeUrl({ state: 's', nonce: 'n', forceChooser: true }));
  assert.equal(forced.searchParams.get('prompt'), 'select_account');
});

test('the code exchange returns the id token', async () => {
  assert.equal(await exchangeCode('google-code'), 'stub');
});

test('the exchange posts the secret in the body, never in the URL', async () => {
  let seen = null;
  __setTransport({
    fetchImpl: async (url, options) => {
      seen = { url, options };
      return { ok: true, status: 200, json: async () => ({ id_token: 'stub' }) };
    }
  });
  await exchangeCode('google-code');
  assert.ok(!seen.url.includes('client_secret'), 'a secret in a URL lands in logs');
  assert.equal(seen.options.method, 'POST');
  assert.match(String(seen.options.body), /client_secret=/);
});

test('a failed exchange raises rather than returning undefined', async () => {
  __setTransport({
    fetchImpl: async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) })
  });
  await assert.rejects(() => exchangeCode('bad'), /Google/);
});

test('a response with no id token raises', async () => {
  __setTransport({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({}) }) });
  await assert.rejects(() => exchangeCode('weird'), /id_token/);
});

test('verification returns the subject when the nonce matches', async () => {
  assert.equal(await verifyGoogleIdToken('token', 'n1'), '109384756102938475610');
});

test('a mismatched nonce is refused', async () => {
  // Without this bind, a token obtained elsewhere could be replayed here.
  assert.equal(await verifyGoogleIdToken('token', 'someone-elses-nonce'), null);
});

test('a token with no subject is refused', async () => {
  __setTransport({ verifyImpl: async () => ({ payload: { nonce: 'n1' } }) });
  assert.equal(await verifyGoogleIdToken('token', 'n1'), null);
});

test('a verification failure returns null rather than throwing', async () => {
  __setTransport({
    verifyImpl: async () => {
      throw new Error('bad signature');
    }
  });
  assert.equal(await verifyGoogleIdToken('token', 'n1'), null);
});

// The two tests below use __verifyGoogleJwt - production's real jwtVerify
// call - against a local JWKS instead of stubbing verification away
// entirely, so they exercise the actual `algorithms: ['RS256']` pin rather
// than a re-implementation of it that could silently drift from production.

test('a correctly signed RS256 token verifies through the real check', async () => {
  // A positive control: proves the harness (local JWKS, matching issuer,
  // audience, nonce and kid) genuinely allows a valid token through, so the
  // rejection asserted below is because of the algorithm and nothing else.
  const { privateKey, kid, jwks } = await localSubjectFixture('RS256');
  __setTransport({ jwks, verifyImpl: __verifyGoogleJwt });
  const token = await signToken(privateKey, 'RS256', kid);
  assert.equal(await verifyGoogleIdToken(token, 'n1'), '109384756102938475610');
});

test('an id token signed with an algorithm outside the pinned list is rejected', async () => {
  // Same issuer, audience, nonce, subject and kid as the positive control
  // above - only the algorithm differs (ES256, not in the RS256-only pin).
  // Without `algorithms: ['RS256']` on the production jwtVerify call, jose
  // would happily verify this.
  const { privateKey, kid, jwks } = await localSubjectFixture('ES256');
  __setTransport({ jwks, verifyImpl: __verifyGoogleJwt });
  const token = await signToken(privateKey, 'ES256', kid);
  assert.equal(await verifyGoogleIdToken(token, 'n1'), null);
});
