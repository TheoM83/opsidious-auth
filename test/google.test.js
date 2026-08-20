import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { authorizeUrl, exchangeCode, verifyGoogleIdToken, __setTransport } from '../lib/google.js';

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
