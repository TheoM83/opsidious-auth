import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { join } from 'node:path';
import { localeFor, translator, LOCALES, CATALOGUES } from './i18n.js';
import {
  GLOBAL_RATE_LIMIT_WINDOW_MS,
  GLOBAL_RATE_LIMIT_MAX,
  TOKEN_RATE_LIMIT_WINDOW_MS,
  TOKEN_RATE_LIMIT_MAX
} from './config.js';

// /authorize now redirects straight to Google, so an unbounded rate here makes
// this service an amplifier pointed at Google (spec §7.17).
export const globalLimiter = rateLimit({
  windowMs: GLOBAL_RATE_LIMIT_WINDOW_MS,
  limit: GLOBAL_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});

// Per client as well as per IP: one misbehaving client must not exhaust the
// budget for the others. ipKeyGenerator normalises the IP (and collapses an
// IPv6 /64) so the library's own validation does not reject the key.
//
// client_id is read from the body before the client is authenticated -
// authentication is a database round trip that cannot run ahead of the
// limiter - so it is unauthenticated input. A caller sharing an egress IP
// with a victim application's backend could aim at that application's
// budget. Accepted trade, not a bug: do not attempt to fix it here.
export function tokenRateLimitKey(req) {
  return `${ipKeyGenerator(req.ip)}:${(req.body && req.body.client_id) || '-'}`;
}

export const tokenLimiter = rateLimit({
  windowMs: TOKEN_RATE_LIMIT_WINDOW_MS,
  limit: TOKEN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: tokenRateLimitKey,
  message: { error: 'too_many_requests' }
});

// Runs on every request. Decides the language once, and hangs a `t` on the
// response so no template and no route ever names a locale.
//
// `res.locals.locale` is also what tells `renderError` which language to use —
// which is why this runs ahead of everything that can fail.
export function attachLocale(req, res, next) {
  const { locale, from } = localeFor(req);
  res.locals.locale = locale;
  res.locals.localeFrom = from;
  res.locals.t = translator(locale);
  // Endonyms for the switcher: each language labelled in itself, never
  // translated, and never a flag — a language is not a country.
  res.locals.locales = LOCALES.map((code) => ({ code, endonym: CATALOGUES[code].endonym }));
  // Where the language switch sends you back to. THE PATH ONLY, deliberately:
  // a page that renders this renders it into an href, and spec §7.3 says the
  // error page names the failure and nothing else - no client id, no redirect
  // URI, no query value of any kind. A first version of this carried the query
  // too, and test/app.test.js caught /404?secret=hunter2 coming back out in a
  // link. Safe everywhere by default; the one page that genuinely cannot lose
  // its query opts in explicitly (routes/authorize.js).
  res.locals.currentPath = req.path;
  // Content-Language is what a cache keys on. Without it, a shared cache can
  // hand a French page to the next person who asks in English.
  res.setHeader('Content-Language', locale);
  res.setHeader('Vary', 'Accept-Language, Cookie');
  next();
}

// Replaces `attachLocale`'s answer for one request, when a language was decided
// earlier in a flow and has to survive a round trip through Google.
export function useLocale(res, locale) {
  res.locals.locale = locale;
  res.locals.t = translator(locale);
  res.setHeader('Content-Language', res.locals.t.locale);
}

// The only page besides /account. It names the failure and nothing else - no
// client id, no redirect URI, no query value of any kind (spec §7.3).
//
// Takes a translation KEY, never a sentence: a route that could pass a string
// through here is a route that could pass a query value through here.
export function renderError(res, status, key, vars = {}) {
  const t = res.locals.t ?? translator(undefined);
  const message = t(key, vars);
  res.status(status);
  return new Promise((resolve) => {
    res.render(join(res.app.get('views'), 'error.ejs'), { ...res.locals, status, message }, (err, body) => {
      if (err) {
        res.type('text/plain').send(message);
        return resolve();
      }
      res.render(
        join(res.app.get('views'), 'layout.ejs'),
        { ...res.locals, title: t('errors.title'), body },
        (e, html) => {
          res.send(e ? message : html);
          resolve();
        }
      );
    });
  });
}
