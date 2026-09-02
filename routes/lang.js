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
// absolute URL to anywhere. Only a same-origin PATH is ever followed, and
// `//evil.example` is refused explicitly: a browser reads a leading `//` as a
// scheme-relative URL, which is an open redirect wearing a path's clothes.
function safeNext(raw) {
  const value = String(raw ?? '');
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  try {
    // Resolved against a throwaway origin purely to reject anything that
    // parses as absolute despite the checks above.
    const url = new URL(value, 'https://opsidious.invalid');
    return `${url.pathname}${url.search}`;
  } catch {
    return '/';
  }
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
