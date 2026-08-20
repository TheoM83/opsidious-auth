import { Router } from 'express';
import { dbGet, dbRun } from '../lib/database.js';
import { exchangeCode, verifyGoogleIdToken } from '../lib/google.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession } from '../lib/sessions.js';
import { issueCode } from '../lib/codes.js';
import { pairwiseSubject } from '../lib/crypto.js';
import { renderError } from '../lib/middleware.js';
import { redirectBack } from './authorize.js';
import { SSO_COOKIE_NAME, SSO_TTL_MS } from '../lib/config.js';

const router = Router();

router.get('/callback/google', async (req, res, next) => {
  try {
    const requestId = String(req.query.state ?? '');
    const parked = await dbGet('SELECT * FROM auth_requests WHERE id = ? AND expires_at > ?', [
      requestId,
      Date.now()
    ]);

    // Without the parked request there is no verified redirect URI to answer
    // on, so this can only be a page, never a redirect.
    if (!parked) {
      console.warn('callback rejected: unknown or expired request');
      return renderError(res, 400, 'Cette demande de connexion a expiré. Recommencez.');
    }

    // One shot, whatever happens next.
    await dbRun('DELETE FROM auth_requests WHERE id = ?', [requestId]);

    if (req.query.error) {
      return redirectBack(res, parked.redirect_uri, {
        error: 'access_denied',
        state: parked.state
      });
    }

    let googleSub = null;
    try {
      const idToken = await exchangeCode(String(req.query.code ?? ''));
      // Signature, issuer, audience, expiry and the nonce we parked - all of
      // it before a single account row is read or written (spec §7.10).
      googleSub = await verifyGoogleIdToken(idToken, parked.google_nonce);
    } catch (err) {
      console.warn('callback: google exchange failed:', err.message);
    }

    if (!googleSub) {
      return redirectBack(res, parked.redirect_uri, {
        error: 'access_denied',
        state: parked.state
      });
    }

    const { account, pairwiseSalt } = await signInWithGoogleSub(googleSub);
    const { cookieValue, session } = await createSession(account.id, pairwiseSalt);

    res.cookie(SSO_COOKIE_NAME, cookieValue, {
      httpOnly: true,
      // Unconditional: a `__Host-` cookie without Secure is rejected outright
      // by every browser. Browsers treat http://localhost as a trustworthy
      // origin, so local development is unaffected.
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: SSO_TTL_MS
      // Deliberately no `domain`: __Host- forbids it, and a parent-domain
      // cookie would be readable by every sibling subdomain (spec §2).
    });

    const code = await issueCode({
      appSub: pairwiseSubject(pairwiseSalt, parked.client_id),
      clientId: parked.client_id,
      redirectUri: parked.redirect_uri,
      nonce: parked.nonce,
      ssoSessionId: session.id
    });

    console.info(`sign-in completed for client ${parked.client_id}`);
    redirectBack(res, parked.redirect_uri, { code, state: parked.state });
  } catch (err) {
    next(err);
  }
});

export default router;
