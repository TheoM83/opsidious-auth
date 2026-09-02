// Validation for open client registration (RFC 7591 §2, §3.1).
//
// Kept out of the route so every rule below is a unit test rather than an HTTP
// round trip, and so the reasoning sits next to the rule it justifies.
//
// ── Why this endpoint can be open at all ─────────────────────────────────
//
// Because a registered client gains nothing worth having. The subject it
// receives for a person is derived from that person's salt AND its own
// client_id, so it is meaningless in every other application — including the
// other applications the same author might register. There is no shared
// identifier to accumulate, so accumulating them is not an attack, it is a
// waste of an afternoon.
//
// What that argument does NOT cover is written down in the README under "What
// is not defended": a hostile application still gets a working sign-in for its
// own users, and this service still has to not be a lever for anything else.
// That is what the rules below are for — every one of them either stops this
// endpoint being used to reach somebody else, or stops it being used to store
// something.

import { MAX_CLIENT_NAME_LENGTH, MAX_REDIRECT_URIS, MAX_REDIRECT_URI_LENGTH } from './config.js';

// RFC 7591 §3.2.2 names exactly two error codes for this endpoint. Anything
// this file refuses maps onto one of them.
export const INVALID_REDIRECT_URI = 'invalid_redirect_uri';
export const INVALID_CLIENT_METADATA = 'invalid_client_metadata';

const AUTH_METHODS = new Set(['client_secret_post', 'none']);

// RFC 8252 §7.3: the loopback redirect for a native application. The IP
// literal, and not `localhost` — `localhost` is a name, names are resolved, and
// a resolver an attacker influences turns a native app's redirect into someone
// else's. The port is deliberately unconstrained: §7.3 requires the client to
// pick an ephemeral one at runtime, which means it cannot be registered ahead
// of time. Everything ELSE about the URI is still matched exactly.
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]']);

// RFC 8252 §7.1: a private-use scheme must be a reverse-DNS name the
// application controls, so it carries a dot. `myapp:/cb` is refused; a scheme
// that short is one any other application on the device can claim too.
const PRIVATE_SCHEME = /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/i;

function bad(error, description) {
  return { ok: false, error, description };
}

export function validateRedirectUri(raw) {
  if (typeof raw !== 'string' || !raw) {
    return bad(INVALID_REDIRECT_URI, 'each redirect_uri must be a non-empty string');
  }
  if (raw.length > MAX_REDIRECT_URI_LENGTH) {
    return bad(INVALID_REDIRECT_URI, `a redirect_uri may be at most ${MAX_REDIRECT_URI_LENGTH} characters`);
  }
  if (raw !== raw.trim()) {
    return bad(INVALID_REDIRECT_URI, 'a redirect_uri may not have leading or trailing whitespace');
  }
  // Matching is exact string equality at /authorize, so a wildcard would never
  // match anything. Refusing it here says so, instead of letting someone
  // discover it at their first sign-in.
  if (raw.includes('*')) {
    return bad(INVALID_REDIRECT_URI, 'redirect URIs are matched exactly; wildcards never match');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    return bad(INVALID_REDIRECT_URI, 'a redirect_uri must be an absolute URI');
  }

  // RFC 6749 §3.1.2: the redirect endpoint URI MUST NOT include a fragment.
  // The authorization response is appended as a query, and a fragment would
  // make the resulting URI mean something different from the one registered.
  if (url.hash) return bad(INVALID_REDIRECT_URI, 'a redirect_uri may not contain a fragment');
  if (url.username || url.password) {
    return bad(INVALID_REDIRECT_URI, 'a redirect_uri may not contain userinfo');
  }

  if (PRIVATE_SCHEME.test(url.protocol)) return { ok: true, uri: raw };

  if (url.protocol === 'https:') {
    if (!url.hostname) return bad(INVALID_REDIRECT_URI, 'a redirect_uri needs a host');
    return { ok: true, uri: raw };
  }

  if (url.protocol === 'http:') {
    if (LOOPBACK_HOSTS.has(url.hostname)) return { ok: true, uri: raw };
    if (url.hostname === 'localhost') {
      return bad(
        INVALID_REDIRECT_URI,
        'use http://127.0.0.1 or http://[::1] rather than localhost: a name is resolved, and a resolver an attacker influences would redirect elsewhere (RFC 8252 §7.3)'
      );
    }
    return bad(INVALID_REDIRECT_URI, 'http is accepted only on the loopback interface');
  }

  return bad(
    INVALID_REDIRECT_URI,
    'a redirect_uri must be https, http on loopback, or a reverse-DNS private-use scheme'
  );
}

// Returns either `{ ok: true, metadata }` or `{ ok: false, error, description }`.
// Nothing here throws: the caller is an unauthenticated endpoint, and a thrown
// error there is a 500 where a 400 was the honest answer.
export function validateRegistration(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return bad(INVALID_CLIENT_METADATA, 'the request body must be a JSON object');
  }

  const uris = body.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0) {
    return bad(INVALID_REDIRECT_URI, 'redirect_uris is required and must be a non-empty array');
  }
  if (uris.length > MAX_REDIRECT_URIS) {
    return bad(INVALID_REDIRECT_URI, `at most ${MAX_REDIRECT_URIS} redirect URIs`);
  }

  const checked = [];
  for (const candidate of uris) {
    const result = validateRedirectUri(candidate);
    if (!result.ok) return result;
    checked.push(result.uri);
  }
  if (new Set(checked).size !== checked.length) {
    return bad(INVALID_REDIRECT_URI, 'redirect_uris contains a duplicate');
  }

  // Optional, and only ever read by the operator in a log line. It is NOT shown
  // to the person signing in — a name an unauthenticated caller chose is a
  // phishing surface the moment it appears next to a trust decision, so no
  // template renders it and test/register.test.js pins that.
  let name = '(unnamed)';
  if (body.client_name !== undefined && body.client_name !== null) {
    if (typeof body.client_name !== 'string') {
      return bad(INVALID_CLIENT_METADATA, 'client_name must be a string');
    }
    const trimmed = body.client_name.trim();
    if (trimmed.length > MAX_CLIENT_NAME_LENGTH) {
      return bad(INVALID_CLIENT_METADATA, `client_name may be at most ${MAX_CLIENT_NAME_LENGTH} characters`);
    }
    // Control characters would ride into a log line and could forge a second
    // line in it. The name is only ever read in logs, so that is exactly the
    // place it must not be able to lie.
    const hasControl = [...trimmed].some((ch) => {
      const point = ch.codePointAt(0);
      return point < 0x20 || point === 0x7f;
    });
    if (hasControl) {
      return bad(INVALID_CLIENT_METADATA, 'client_name may not contain control characters');
    }
    if (trimmed) name = trimmed;
  }

  const method = body.token_endpoint_auth_method ?? 'client_secret_post';
  if (!AUTH_METHODS.has(method)) {
    return bad(
      INVALID_CLIENT_METADATA,
      `token_endpoint_auth_method must be one of ${[...AUTH_METHODS].join(', ')}`
    );
  }

  // The discovery document advertises exactly one grant type and one response
  // type. A client that declares something else has misread the document, and
  // saying so now is cheaper than a failed sign-in later — the same reasoning
  // that made /authorize check `response_type` instead of quietly proceeding.
  const declared = [
    ['grant_types', body.grant_types, 'authorization_code'],
    ['response_types', body.response_types, 'code']
  ];
  for (const [field, value, only] of declared) {
    if (value === undefined) continue;
    if (!Array.isArray(value) || value.length !== 1 || value[0] !== only) {
      return bad(INVALID_CLIENT_METADATA, `${field} must be exactly ["${only}"]`);
    }
  }

  return {
    ok: true,
    metadata: { name, redirectUris: checked, isPublic: method === 'none', authMethod: method }
  };
}
