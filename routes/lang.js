// Choosing a language, and remembering it.
//
// A link, not a form: it has to work on the sign-in screen, which runs no
// script at all. The choice is stored in a cookie because it belongs to the
// person and not to the application that sent them — see lib/i18n.js for why
// that cookie outranks `ui_locales`.

import { Router } from 'express';
import { isSupported } from '../lib/i18n.js';
import { LOCALE_COOKIE_NAME, LOCALE_COOKIE_MAX_AGE_MS } from '../lib/config.js';
import { renderError } from '../lib/middleware.js';

const router = Router();

// `next` comes from the query, so it is attacker-controlled and could be an
// absolute URL to anywhere. Only a same-origin PATH is ever followed.
//
// THE CHECK RUNS AFTER NORMALISATION, AND THAT IS THE WHOLE FUNCTION.
//
// The first version rejected a leading `//` on the RAW string and then handed
// the parsed path back. But `new URL()` resolves `..` segments, and resolving
// them can CREATE a leading `//` that was not in the input:
//
//   new URL('/..//evil.example', base).pathname === '//evil.example'
//
// A browser reads `Location: //evil.example` as scheme-relative and goes to
// https://evil.example — sent there by the identity provider's own origin,
// which is the phishing primitive an OIDC provider least needs to have. The
// guard was right and ran one step too early.
function safeNext(raw) {
  const value = String(raw ?? '');
  if (!value.startsWith('/')) return '/';

  let path;
  try {
    // Resolved against a throwaway origin purely to normalise it; nothing about
    // that origin is ever used.
    const url = new URL(value, 'https://opsidious.invalid');
    path = `${url.pathname}${url.search}`;
  } catch {
    return '/';
  }

  return path.startsWith('//') ? '/' : path;
}

router.get('/lang/:code', (req, res) => {
  const code = String(req.params.code ?? '').toLowerCase();
  if (!isSupported(code)) return renderError(res, 404, 'errors.notFound');

  res.cookie(LOCALE_COOKIE_NAME, code, {
    httpOnly: true,
    // Unconditional, like every other cookie here: a `__Host-` cookie without
    // Secure is rejected outright, and browsers treat http://localhost as a
    // trustworthy origin, so local development is unaffected.
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: LOCALE_COOKIE_MAX_AGE_MS
  });

  // 303, not 302: the browser must GET the destination, and this is the only
  // route here that exists to change state and then send you somewhere else.
  res.redirect(303, safeNext(req.query.next));
});

export default router;
