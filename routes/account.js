import { Router } from 'express';
import { join } from 'node:path';
import { resolveSession, deleteSessionByCookie } from '../lib/sessions.js';
import { deleteAccount } from '../lib/accounts.js';
import { sha256, safeEqual } from '../lib/crypto.js';
import { renderError } from '../lib/middleware.js';
import { SSO_COOKIE_NAME } from '../lib/config.js';

const router = Router();

// Derived from the session cookie, which an attacker on another origin cannot
// read. No extra table, no extra cookie.
const csrfFor = (cookieValue) => sha256(`csrf:${cookieValue}`);

// The cookie is `__Host-` prefixed. A browser rejects any Set-Cookie carrying
// that prefix without `Secure`, clearing directive included - so `secure`
// here must be unconditional, never gated on IS_PRODUCTION. Getting this
// wrong on the clear side is worse than on the set side: outside production
// the browser would silently keep a live, valid SSO cookie after "logout".
function clearSsoCookie(res) {
  res.clearCookie(SSO_COOKIE_NAME, { path: '/', secure: true, sameSite: 'lax' });
}

async function requireSession(req, res) {
  const cookieValue = req.cookies?.[SSO_COOKIE_NAME];
  const resolved = await resolveSession(cookieValue);
  if (!resolved) {
    await renderError(res, 401, 'Vous n’êtes pas connecté à Opsidious.');
    return null;
  }
  return { ...resolved, cookieValue };
}

function checkCsrf(req, cookieValue) {
  return safeEqual(String(req.body?.csrf ?? ''), csrfFor(cookieValue));
}

router.get('/account', async (req, res, next) => {
  try {
    // The page embeds this session's CSRF token (derived from the cookie
    // value - see csrfFor above). A cache serving a stale copy of this page
    // to a different visitor is not something to allow, even though nothing
    // here is currently observed leaking through one.
    res.setHeader('Cache-Control', 'no-store');

    const current = await requireSession(req, res);
    if (!current) return undefined;

    // Nothing identifying is rendered - there is nothing worth rendering.
    res.render(
      join(res.app.get('views'), 'account.ejs'),
      { csrf: csrfFor(current.cookieValue) },
      (err, body) => {
        if (err) return next(err);
        res.render(
          join(res.app.get('views'), 'layout.ejs'),
          { title: 'Compte Opsidious', body },
          (e, html) => (e ? next(e) : res.send(html))
        );
      }
    );
  } catch (err) {
    next(err);
  }
});

router.post('/logout', async (req, res, next) => {
  try {
    const current = await requireSession(req, res);
    if (!current) return undefined;
    if (!checkCsrf(req, current.cookieValue)) return renderError(res, 403, 'Requête invalide.');

    await deleteSessionByCookie(current.cookieValue);
    clearSsoCookie(res);
    res.redirect(302, '/account');
  } catch (err) {
    next(err);
  }
});

router.post('/account/delete', async (req, res, next) => {
  try {
    const current = await requireSession(req, res);
    if (!current) return undefined;
    if (!checkCsrf(req, current.cookieValue)) return renderError(res, 403, 'Requête invalide.');

    // The CSRF token above is the actual security control. SUPPRIMER is
    // fixed and public, so it stops nothing an attacker who can pass the
    // CSRF check couldn't also supply - its job is deliberate friction
    // against an authenticated user's own misclick on an irreversible action.
    if (String(req.body?.confirm ?? '').trim() !== 'SUPPRIMER') {
      return renderError(res, 400, 'Saisissez SUPPRIMER pour confirmer.');
    }

    await deleteAccount(current.session.account_id); // sessions cascade
    clearSsoCookie(res);
    console.info('account deleted');
    res.redirect(302, '/account');
  } catch (err) {
    next(err);
  }
});

export default router;
