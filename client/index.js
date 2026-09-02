// Express client for Opsidious Auth.
//
// Everything in §7.2 of the design lives here so that an application does not
// have to remember it: state, nonce, issuer and audience checks, a pinned
// algorithm, and a code exchanged server-side then redirected away from.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const TRANSACTION_TTL_MS = 10 * 60 * 1000;

// A short allowance for clock drift between this host and the auth service,
// so a few seconds of skew never turns into a spurious `invalid_grant`.
const CLOCK_TOLERANCE_S = 30;

// An explicit ceiling on both outbound calls: an unreachable or hanging auth
// service must fail this request, not hang the caller's forever.
const FETCH_TIMEOUT_MS = 5000;

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ''));
  const bufB = Buffer.from(String(b ?? ''));
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return timingSafeEqual(bufA, bufB);
}

function timedFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

// OIDC Core §3.1.2.1. A string, an array, or a function of the request - the
// third because an application whose interface language is per-request (a
// locale in the URL, a cookie, a header) has no single answer to give at
// startup, and asking it to call `start()` differently per language would be a
// worse API than just letting it answer per request.
//
// Whatever comes back is space-joined and sent as `ui_locales`. The service
// treats it as a hint: someone who has explicitly chosen a language ON the
// service keeps it. See its lib/i18n.js.
function resolveUiLocales(value, req) {
  const raw = typeof value === 'function' ? value(req) : value;
  if (!raw) return null;
  const list = Array.isArray(raw) ? raw : [raw];
  const cleaned = list
    .filter((tag) => typeof tag === 'string')
    .map((tag) => tag.trim())
    // A language tag, and nothing that could carry a space or a control
    // character into a URL this library builds.
    .filter((tag) => /^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/.test(tag));
  return cleaned.length ? cleaned.join(' ') : null;
}

export function opsidiousAuth({
  issuer,
  clientId,
  clientSecret,
  redirectUri,
  internalUrl,
  uiLocales,
  cookieName = 'opsid_tx'
}) {
  for (const [name, value] of Object.entries({ issuer, clientId, clientSecret, redirectUri })) {
    if (!value) throw new Error(`opsidiousAuth: ${name} is required`);
  }

  // Browser redirects and the `iss`/`aud` check always use the public
  // issuer. `internalUrl`, if given, is used ONLY for the two server-to-
  // server calls (token exchange, JWKS fetch) - never for anything a
  // redirect or a token claim is checked against - so a misconfigured
  // internalUrl cannot silently send browser traffic to an internal
  // hostname, and cannot widen what issuer a token is accepted from either.
  const publicBase = issuer.replace(/\/+$/, '');
  const apiBase = (internalUrl || issuer).replace(/\/+$/, '');
  const jwks = createRemoteJWKSet(new URL(`${apiBase}/.well-known/jwks.json`), {
    timeoutDuration: FETCH_TIMEOUT_MS
  });
  const secureCookie = true;

  function start({ silent = false, uiLocales: perCall } = {}) {
    return (req, res) => {
      const state = randomBytes(32).toString('base64url');
      const nonce = randomBytes(32).toString('base64url');

      // Both halves in one httpOnly cookie: the callback needs to compare
      // them and nothing else ever needs to read them. `Secure` is set
      // unconditionally - browsers treat http://localhost as a trustworthy
      // origin, so local development is unaffected, and gating this on an
      // environment variable is exactly the bug that was found twice in this
      // service's own cookies.
      res.cookie(cookieName, `${state}.${nonce}`, {
        httpOnly: true,
        sameSite: 'lax',
        secure: secureCookie,
        path: '/',
        maxAge: TRANSACTION_TTL_MS
      });

      const url = new URL(`${publicBase}/authorize`);
      // `response_type` and `scope` are REQUIRED by RFC 6749 §4.1.1 and OIDC
      // Core §3.1.2.1. This package omitted both and worked anyway, because
      // the service did not check either - two halves of the same repository
      // agreeing on a mistake. The service checks now, and anyone reading this
      // file as a reference implementation gets a conformant request.
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'openid');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', state);
      url.searchParams.set('nonce', nonce);
      if (silent) url.searchParams.set('prompt', 'none');

      // The sign-in screen then speaks the language of the application the
      // person came from, with nothing to configure on either side. Omitted
      // entirely when there is nothing to say - an empty parameter is a
      // parameter the server has to have an opinion about.
      const locales = resolveUiLocales(perCall ?? uiLocales, req);
      if (locales) url.searchParams.set('ui_locales', locales);

      res.redirect(302, url.toString());
    };
  }

  function callback() {
    return async (req, res, next) => {
      const fail = (error) => {
        // Fail closed: this is the only way `req.opsidious` is populated, and
        // it never carries a sub or claims unless every check below passed.
        req.opsidious = { error };
        next();
      };

      const transaction = req.cookies?.[cookieName];
      res.clearCookie(cookieName, { path: '/', sameSite: 'lax', secure: secureCookie });

      if (!transaction || !transaction.includes('.')) return fail('invalid_state');
      const [state, nonce] = transaction.split('.');

      // Compared before anything else is trusted. Without it, an attacker
      // can finish a flow they started and sign the victim into their
      // account.
      if (!safeEqual(String(req.query.state ?? ''), state)) return fail('invalid_state');
      if (req.query.error) return fail(String(req.query.error));

      const code = String(req.query.code ?? '');
      if (!code) return fail('invalid_request');

      try {
        const response = await timedFetch(`${apiBase}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri
          }).toString()
        });
        if (!response.ok) return fail('invalid_grant');

        const { id_token: idToken } = await response.json();
        if (!idToken) return fail('invalid_grant');

        const { payload } = await jwtVerify(idToken, jwks, {
          issuer: publicBase,
          audience: clientId,
          // Pinned. Accepting the token's own `alg` is algorithm confusion:
          // against this service's own JWKS material, a token signed with
          // PS256 verifies successfully without this pin.
          algorithms: ['RS256'],
          clockTolerance: CLOCK_TOLERANCE_S
        });

        if (payload.nonce !== nonce) return fail('invalid_nonce');

        req.opsidious = { sub: payload.sub, claims: payload };
        next();
      } catch {
        // Never log the token, the code, or any claim - just refuse.
        fail('invalid_grant');
      }
    };
  }

  return { start, callback };
}

// Exported for applications that want the transaction cookie name.
export const defaults = { cookieName: 'opsid_tx' };
