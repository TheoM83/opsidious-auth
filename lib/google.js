// The only module that talks to Google. Both calls are a fetch and a jose
// call, which is why there is no Google SDK in the dependency list (§3.1).
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI } from './config.js';

const AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN = 'https://oauth2.googleapis.com/token';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

// jose caches the key set and refetches on an unknown kid, which is exactly
// the behaviour we would otherwise have to write and get subtly wrong.
const googleJwks = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

// The real verification call, exported under a test-only name (matching the
// `__setTransport` convention) so a test can point `jwks` at a local key set
// and exercise this exact function - including its `algorithms` pin - without
// a network call, rather than re-implementing it in the test and risking the
// test drifting from what production actually does.
export function __verifyGoogleJwt(token) {
  return jwtVerify(token, transport.jwks, {
    issuer: ISSUERS,
    audience: GOOGLE_CLIENT_ID,
    // This is the production verification of Google's ID token - the front
    // door of every identity in this system - so the algorithm is pinned
    // rather than left to whatever the token's own header claims. Without
    // this, jose will happily verify a token signed with any algorithm the
    // supplied JWKS material can be coerced into, which is exactly the class
    // of bug behind the "alg confusion" family of JWT attacks.
    algorithms: ['RS256']
  });
}

// Injected so tests never reach the network. `jwks` is injected separately
// from `verifyImpl` (rather than folded into one stub, as most tests here
// do) so a test can swap in a local JWKS and call `__verifyGoogleJwt` for
// real.
let transport = {
  fetchImpl: (...args) => fetch(...args),
  jwks: googleJwks,
  verifyImpl: __verifyGoogleJwt
};
export function __setTransport(next) {
  transport = { ...transport, ...next };
}

export function authorizeUrl({ state, nonce, forceChooser = false }) {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    // Nothing but `openid`. We never receive an email or a name, so there is
    // none to store, log, or promise to discard (spec §7.11).
    scope: 'openid',
    state,
    nonce
  });
  if (forceChooser) params.set('prompt', 'select_account');
  return `${AUTHORIZE}?${params.toString()}`;
}

export async function exchangeCode(code) {
  const body = new URLSearchParams({
    code,
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    redirect_uri: GOOGLE_REDIRECT_URI,
    grant_type: 'authorization_code'
  });

  const res = await transport.fetchImpl(TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!res.ok) throw new Error(`Google token exchange failed with ${res.status}`);
  const payload = await res.json();
  if (!payload || !payload.id_token) throw new Error('Google returned no id_token');
  return payload.id_token;
}

// Returns the subject, or null. Never throws: a caller only has to check for
// null, and a thrown error here would leak detail into a log.
export async function verifyGoogleIdToken(idToken, expectedNonce) {
  try {
    const { payload } = await transport.verifyImpl(idToken);
    if (!payload || !payload.sub) return null;
    if (!expectedNonce || payload.nonce !== expectedNonce) return null;
    return String(payload.sub);
  } catch {
    return null;
  }
}
