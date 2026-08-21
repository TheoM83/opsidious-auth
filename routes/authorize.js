import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { dbRun } from '../lib/database.js';
import { getClient, redirectAllowed } from '../lib/clients.js';
import { resolveSession } from '../lib/sessions.js';
import { issueCode } from '../lib/codes.js';
import { pairwiseSubject, randomToken } from '../lib/crypto.js';
import { authorizeUrl } from '../lib/google.js';
import { renderError } from '../lib/middleware.js';
import { AUTH_REQUEST_TTL_MS, SSO_COOKIE_NAME } from '../lib/config.js';

const router = Router();

// Only ever called with a redirect_uri that has already been matched exactly
// against the client's registered list.
export function redirectBack(res, redirectUri, params) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) url.searchParams.set(key, value);
  }
  return res.redirect(302, url.toString());
}

router.get('/authorize', async (req, res, next) => {
  try {
    // Every response this handler can produce is either a redirect carrying
    // a fresh code in `Location` or an error page - a cache (browser or
    // intermediary) replaying either one later is not something to allow,
    // even though nothing here is currently observed leaking through one.
    res.setHeader('Cache-Control', 'no-store');

    const clientId = String(req.query.client_id ?? '');
    const redirectUri = String(req.query.redirect_uri ?? '');

    // Validate the client and the URI BEFORE anything else. Until both are
    // known good, a redirect is an open redirect (spec §7.2).
    const client = await getClient(clientId);
    if (!client || !redirectAllowed(client, redirectUri)) {
      console.warn('authorize rejected: unknown client or redirect_uri');
      return renderError(res, 400, "Cette application n'est pas autorisée à utiliser Opsidious.");
    }

    const state = String(req.query.state ?? '');
    const nonce = req.query.nonce ? String(req.query.nonce) : null;
    const prompt = String(req.query.prompt ?? '');

    if (!state) return redirectBack(res, redirectUri, { error: 'invalid_request' });

    // A live session, unless the application explicitly asked to re-authenticate.
    const existing = prompt === 'login' ? null : await resolveSession(req.cookies?.[SSO_COOKIE_NAME]);

    if (existing) {
      const code = await issueCode({
        appSub: pairwiseSubject(existing.pairwiseSalt, clientId),
        clientId,
        redirectUri,
        nonce,
        ssoSessionId: existing.session.id
      });
      return redirectBack(res, redirectUri, { code, state });
    }

    // No session. `prompt=none` means "silently or not at all", so we answer
    // rather than sending the browser to Google.
    if (prompt === 'none') {
      return redirectBack(res, redirectUri, { error: 'login_required', state });
    }

    // Park the request so /callback/google can resume it, then go straight to
    // Google. There is no sign-in page (spec §6).
    const id = randomUUID();
    const googleNonce = randomToken(24);
    await dbRun(
      `INSERT INTO auth_requests (id, client_id, redirect_uri, state, nonce, google_nonce, expires_at)
       VALUES (?,?,?,?,?,?,?)`,
      [id, clientId, redirectUri, state, nonce, googleNonce, Date.now() + AUTH_REQUEST_TTL_MS]
    );

    res.redirect(302, authorizeUrl({ state: id, nonce: googleNonce, forceChooser: prompt === 'login' }));
  } catch (err) {
    next(err);
  }
});

export default router;
