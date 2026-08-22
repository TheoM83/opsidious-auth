import { Router } from 'express';
import { join } from 'node:path';
import { publishedJwks } from '../lib/keys.js';
import { ISSUER, PUBLIC_URL, ID_TOKEN_TTL_S } from '../lib/config.js';

const router = Router();

// The discovery document. §1 lists "full OIDC discovery, userinfo, dynamic
// registration" as a non-goal and notes that growing into it later is additive
// - this is that addition, and only that one. It is a static, read-only
// description of endpoints that already exist. No userinfo, no registration
// endpoint, no client management.
//
// Every field below advertises something this service actually does. A
// discovery document that promises a capability the server lacks is worse than
// no document at all: a standard library would configure itself against the
// promise and fail at the call. So `scopes_supported` is `openid` alone,
// `response_types_supported` is `code` alone, and there is no
// `code_challenge_methods_supported` because PKCE is deliberately absent (§1 -
// every client is a confidential server-side client with a secret).
//
// `subject_types_supported: ["pairwise"]` is the one line that states the whole
// product in the vocabulary of the standard: each application receives a
// different, stable subject for the same person.
const DISCOVERY = Object.freeze({
  issuer: ISSUER,
  authorization_endpoint: `${PUBLIC_URL}/authorize`,
  token_endpoint: `${PUBLIC_URL}/token`,
  jwks_uri: `${PUBLIC_URL}/.well-known/jwks.json`,
  response_types_supported: ['code'],
  response_modes_supported: ['query'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['pairwise'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_post'],
  scopes_supported: ['openid'],
  // No email, no profile, no name: the service never receives them, so it
  // could not put them in a token even if a client asked.
  claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'],
  id_token_lifetime_seconds: ID_TOKEN_TTL_S
});

router.get('/.well-known/openid-configuration', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json(DISCOVERY);
});

router.get('/.well-known/jwks.json', async (req, res, next) => {
  try {
    // Only rows' `public_jwk` is read; private material never leaves the DB.
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(await publishedJwks());
  } catch (err) {
    next(err);
  }
});

// The service's own front door. It answered 404 before: someone typing the
// bare hostname - which is what a curious person does after seeing it in a
// redirect bar - was met with an error page for a service whose entire subject
// is being trustworthy about what it does.
router.get('/', (req, res, next) => {
  res.render(
    join(res.app.get('views'), 'home.ejs'),
    {},
    (err, body) => {
      if (err) return next(err);
      res.render(
        join(res.app.get('views'), 'layout.ejs'),
        { title: 'Opsidious', body },
        (e, html) => (e ? next(e) : res.send(html))
      );
    }
  );
});

export default router;
