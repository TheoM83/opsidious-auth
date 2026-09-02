import { Router } from 'express';
import { dbGet, dbRun } from '../lib/database.js';
import { exchangeCode, verifyGoogleIdToken } from '../lib/google.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession, deleteSessionByCookie } from '../lib/sessions.js';
import { issueCode } from '../lib/codes.js';
import { pairwiseSubject } from '../lib/crypto.js';
import { renderError, useLocale } from '../lib/middleware.js';
import { redirectBack } from './authorize.js';
import { SSO_COOKIE_NAME, SSO_TTL_MS } from '../lib/config.js';

const router = Router();

router.get('/callback/google', async (req, res, next) => {
  try {
    const requestId = String(req.query.state ?? '');
    const now = Date.now();

    // Read the row's contents, but let the guarded DELETE below - not this
    // SELECT - decide who owns it. lib/codes.js uses the same guarded-mutation
    // pattern (a single UPDATE ... WHERE used = 0) to avoid a SELECT-then-DELETE
    // window in which two racing requests could both pass the "is this parked?"
    // gate.
    const parked = await dbGet('SELECT * FROM auth_requests WHERE id = ? AND expires_at > ?', [
      requestId,
      now
    ]);

    // One shot, whatever happens next: the DELETE itself is the gate. Only the
    // caller whose predicates still match a live row wins the race.
    const { changes } = await dbRun('DELETE FROM auth_requests WHERE id = ? AND expires_at > ?', [
      requestId,
      now
    ]);

    // Without a parked request there is no verified redirect URI to answer
    // on, so this can only be a page, never a redirect.
    if (!parked || changes !== 1) {
      console.warn('callback rejected: unknown or expired request');
      return renderError(res, 400, 'errors.requestExpired');
    }

    // The language the sign-in was STARTED in, replayed here. Google is a
    // detour, and a detour must not change the language of the page you come
    // back to — the browser's Accept-Language may well disagree with the
    // `ui_locales` the application asked for, and the application asked first.
    if (parked.ui_locale) useLocale(res, parked.ui_locale);

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

    // A completed round trip through Google only ever lands here when there
    // was no existing session (nothing to revoke below) or prompt=login
    // forced re-authentication past one (routes/authorize.js) - a live
    // session never reaches Google at all otherwise. In the second case, the
    // cookie this browser still presents names a session that is about to be
    // replaced by a fresh one. Left alone, that old session - and the old
    // cookie value hashed into `token_hash` - would keep working for the
    // rest of its own 14-day life even though the browser itself has already
    // moved on to a new cookie.
    await deleteSessionByCookie(req.cookies?.[SSO_COOKIE_NAME]);
    const { cookieValue, session } = await createSession(account.id, pairwiseSalt);

    const code = await issueCode({
      appSub: pairwiseSubject(pairwiseSalt, parked.client_id),
      clientId: parked.client_id,
      redirectUri: parked.redirect_uri,
      nonce: parked.nonce,
      ssoSessionId: session.id,
      codeChallenge: parked.code_challenge,
      codeChallengeMethod: parked.code_challenge_method
    });

    // Staged only once nothing else can fail: if issueCode had thrown after the
    // cookie was staged, Express would still flush the Set-Cookie header on the
    // 500 page, leaving the browser signed in while the client app never gets
    // a code.
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

    console.info(`sign-in completed for client ${parked.client_id}`);
    redirectBack(res, parked.redirect_uri, { code, state: parked.state });
  } catch (err) {
    next(err);
  }
});

export default router;
