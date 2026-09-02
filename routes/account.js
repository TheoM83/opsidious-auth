import { Router } from 'express';
import { resolveSession, deleteSessionByCookie } from '../lib/sessions.js';
import { deleteAccount, getAccount } from '../lib/accounts.js';
import { dbAll } from '../lib/database.js';
import { sha256, safeEqual } from '../lib/crypto.js';
import { renderError } from '../lib/middleware.js';
import { renderPage } from '../lib/render.js';
import { LOCALES, CATALOGUES } from '../lib/i18n.js';
import { SSO_COOKIE_NAME } from '../lib/config.js';

const router = Router();

// The page's argument is the row itself. It shows every FIELD NAME - that is
// what transparency requires - but not the opaque values.
//
// Showing the raw bytes was the first shape of this page, and it was wrong on
// both counts. It gains the reader nothing: a random hex string cannot be
// checked against anything, so it asks for the same trust as the sentence
// beside it. And it costs something real: a screenshot shared publicly, plus a
// future leak of this database, would let someone confirm "that screenshot is
// this row". The shape - what the field is, how many bytes, what it can and
// cannot say - is strictly more informative and carries no such handle.
//
// `created_at` and the session count are different: they are meaningful to the
// person reading, and they are the two things this row genuinely discloses. So
// they are shown in full, and marked.
// Sizes are stated as the thing they actually are, not as the length of their
// text encoding. `google_sub_hash` is 64 hex CHARACTERS but a 32-byte digest,
// and `id` is a 36-character UUID carrying 122 bits of entropy - quoting the
// text lengths would overstate both. On a page whose whole claim is
// truthfulness, a technically-derived but misleading number costs more than it
// would anywhere else.

function describeRow(t, account, sessionCount) {
  const f = (name) => `account.fields.${name}`;
  return [
    { field: 'id', shape: t(`${f('id')}.shape`), kind: t(`${f('id')}.kind`), reveals: null },
    {
      field: 'google_sub_hash',
      shape: t(`${f('googleSubHash')}.shape`),
      kind: t(`${f('googleSubHash')}.kind`),
      reveals: null
    },
    { field: 'kdf_salt', shape: t(`${f('kdfSalt')}.shape`), kind: t(`${f('kdfSalt')}.kind`), reveals: null },
    {
      field: 'sealed_salt',
      shape: t(`${f('sealedSalt')}.shape`),
      kind: t(`${f('sealedSalt')}.kind`),
      reveals: null
    },
    {
      field: 'created_at',
      // The stored value, not a localised rendering of it. This page shows the
      // row as it IS - a date formatted for the reader's locale would be the
      // one line on the page that had been dressed up.
      shape: new Date(account.created_at).toISOString().slice(0, 10),
      kind: t(`${f('createdAt')}.kind`),
      // The one field that discloses something. The page says so out loud
      // instead of burying it among the reassuring ones.
      reveals: t(`${f('createdAt')}.reveals`)
    },
    {
      field: 'sso_sessions',
      shape: String(sessionCount),
      kind: t(`${f('ssoSessions')}.kind`),
      reveals: sessionCount > 1 ? t(`${f('ssoSessions')}.reveals`, { count: sessionCount }) : null
    }
  ];
}

// Every locale's confirmation word is accepted, whichever language the page was
// rendered in. The CSRF token above is the actual control; this word is
// deliberate friction against a misclick, and friction that fails because
// someone's browser switched language between the page and the submit is not
// friction, it is a bug. See the note on the CSRF check below.

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
    await renderError(res, 401, 'errors.notSignedIn');
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

    const account = await getAccount(current.session.account_id);
    const sessions = await dbAll('SELECT id FROM sso_sessions WHERE account_id = ?', [
      current.session.account_id
    ]);

    const t = res.locals.t;
    await renderPage(res, 'account', {
      ...res.locals,
      title: t('account.title'),
      csrf: csrfFor(current.cookieValue),
      row: describeRow(t, account, sessions.length)
    });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', async (req, res, next) => {
  try {
    const current = await requireSession(req, res);
    if (!current) return undefined;
    if (!checkCsrf(req, current.cookieValue)) return renderError(res, 403, 'errors.invalidRequest');

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
    if (!checkCsrf(req, current.cookieValue)) return renderError(res, 403, 'errors.invalidRequest');

    // The CSRF token above is the actual security control. The confirmation
    // word is fixed and public, so it stops nothing an attacker who can pass
    // the CSRF check couldn't also supply - its job is deliberate friction
    // against an authenticated user's own misclick on an irreversible action.
    //
    // Every language's word is accepted, not just the one this page was
    // rendered in. Someone who switched language between loading the form and
    // submitting it typed a real confirmation word; refusing it would be an
    // error message about nothing.
    const words = LOCALES.map((code) => CATALOGUES[code].account.deleteWord);
    if (!words.includes(String(req.body?.confirm ?? '').trim())) {
      return renderError(res, 400, 'errors.confirmDelete', {
        word: res.locals.t('account.deleteWord')
      });
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
