import { Router } from 'express';
import { publishedJwks } from '../lib/keys.js';
import { renderPage } from '../lib/render.js';
import { LOCALES } from '../lib/i18n.js';
import { ISSUER, PUBLIC_URL, ID_TOKEN_TTL_S, REGISTRATION_ENABLED } from '../lib/config.js';

const router = Router();

// The discovery document. §1 lists "full OIDC discovery, userinfo, dynamic
// registration" as a non-goal and notes that growing into it later is additive
// - this is that addition, and only that one. It is a static, read-only
// description of endpoints that already exist. No userinfo, no registration
// endpoint, no client management.
//
// `registration_endpoint` and `ui_locales_supported` are the two later
// additions, and both follow the same rule as everything else here: the field
// appears only when the capability does. A deployment with
// REGISTRATION_ENABLED=false omits the endpoint rather than advertising one
// that answers 403.
//
// Every field below advertises something this service actually does. A
// discovery document that promises a capability the server lacks is worse than
// no document at all: a standard library would configure itself against the
// promise and fail at the call. So `scopes_supported` is `openid` alone,
// `response_types_supported` is `code` alone, and `code_challenge_methods_supported`
// lists S256 and only S256. §1 called PKCE out of scope because every client was a
// confidential server-side one, and §14 recorded the condition that would end that:
// "needed the day a public client (mobile, SPA) appears". A desktop application is
// that day - it cannot hold a secret, because the secret would ship inside a binary
// on every user's machine. `plain` stays absent: it sends the verifier through the
// same channel that may already be leaking the code.
//
// `subject_types_supported: ["pairwise"]` is the one line that states the whole
// product in the vocabulary of the standard: each application receives a
// different, stable subject for the same person.
const DISCOVERY = Object.freeze({
  issuer: ISSUER,
  authorization_endpoint: `${PUBLIC_URL}/authorize`,
  token_endpoint: `${PUBLIC_URL}/token`,
  jwks_uri: `${PUBLIC_URL}/.well-known/jwks.json`,
  // RFC 7591 §4. Open: no initial access token, no software statement, no
  // operator. See routes/register.js for why that is not a hole.
  ...(REGISTRATION_ENABLED ? { registration_endpoint: `${PUBLIC_URL}/register` } : {}),
  response_types_supported: ['code'],
  response_modes_supported: ['query'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['pairwise'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
  code_challenge_methods_supported: ['S256'],
  scopes_supported: ['openid'],
  // No email, no profile, no name: the service never receives them, so it
  // could not put them in a token even if a client asked.
  claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'],
  // OIDC Core §3.1.2.1. This service used to accept `ui_locales` and ignore it,
  // which the spec permits - but a parameter that is accepted and ignored is
  // indistinguishable from one that is honoured until someone checks. It is
  // honoured now, so it is advertised now, and test/wellknown.test.js pins the
  // two lists to each other.
  ui_locales_supported: [...LOCALES],
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
  const t = res.locals.t;
  renderPage(res, 'home', {
    ...res.locals,
    title: t('home.title'),
    // The only page here that a search engine should ever hold. Everything
    // else - the sign-in step, the account page - is somebody's session, and
    // the layout keeps it out of the index by default.
    noindex: false,
    canonical: `${PUBLIC_URL}/`,
    shareImage: `${PUBLIC_URL}/${res.locals.locale === 'fr' ? 'og-fr.png' : 'og.png'}`,
    registrationOpen: REGISTRATION_ENABLED,
    publicUrl: PUBLIC_URL
  }).catch(next);
});

// One page, so one entry. It exists because the front door became indexable and
// is the entry point for open registration: an open door nobody can find is
// open only to whoever was already told about it. Everything else this service
// serves is somebody's session and carries `noindex`, which is why nothing else
// is listed here.
//
// No `hreflang` alternates: this service has one URL per page and negotiates
// the language behind it (cookie, then `ui_locales`, then `Accept-Language`).
// Declaring a French address that does not exist would be a lie told to a robot.
router.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${PUBLIC_URL}/</loc></url>
</urlset>
`
  );
});

export default router;
