import { Router } from 'express';
import { getClient, verifyClientSecret } from '../lib/clients.js';
import { consumeCode } from '../lib/codes.js';
import { signIdToken } from '../lib/tokens.js';
import { tokenLimiter } from '../lib/middleware.js';
import { ID_TOKEN_TTL_S } from '../lib/config.js';

const router = Router();

// One shape for every grant failure. Distinguishing "expired" from "wrong
// client" from "never existed" hands an attacker a probing oracle.
const INVALID_GRANT = { error: 'invalid_grant' };

router.post('/token', tokenLimiter, async (req, res, next) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    const body = req.body || {};
    const clientId = String(body.client_id ?? '');
    const redirectUri = String(body.redirect_uri ?? '');

    if (String(body.grant_type ?? '') !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    // Client id is public by design in this system - it rides in every
    // sign-in redirect URL and in the client package's own configuration, so
    // there is no secret in it to protect by hiding whether it exists. What
    // must not leak is the secret. A wrong secret, a missing secret, and an
    // unknown client id all answer with this one uniform shape, so a caller
    // gains nothing by probing.
    const client = await getClient(clientId);
    if (!verifyClientSecret(client, String(body.client_secret ?? ''))) {
      console.warn(`token rejected: bad client credentials for ${clientId || '(none)'}`);
      return res.status(401).json({ error: 'invalid_client' });
    }

    const result = await consumeCode(String(body.code ?? ''), { clientId, redirectUri });
    if (!result.ok) {
      console.warn(`token rejected for ${clientId}: ${result.reason}`);
      return res.status(400).json(INVALID_GRANT);
    }

    const idToken = await signIdToken({
      sub: result.row.app_sub,
      clientId,
      nonce: result.row.nonce
    });

    // No access_token, no refresh_token: there is no resource server behind
    // this and no long-lived grant to refresh (spec §1, §6).
    res.json({ id_token: idToken, token_type: 'Bearer', expires_in: ID_TOKEN_TTL_S });
  } catch (err) {
    next(err);
  }
});

export default router;
