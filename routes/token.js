import { Router } from 'express';
import { getClient, verifyClientSecret, isPublicClient } from '../lib/clients.js';
import { consumeCode } from '../lib/codes.js';
import { randomToken } from '../lib/crypto.js';
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
    if (!client) {
      console.warn(`token rejected: unknown client ${clientId || '(none)'}`);
      return res.status(401).json({ error: 'invalid_client' });
    }

    // A public client authenticates with nothing - that is what public means.
    // Its proof is the code_verifier, checked inside consumeCode against the
    // challenge the authorization request carried.
    //
    // A secret sent by a public client is ignored rather than rejected: there
    // is no secret on record to compare it to, and answering differently for a
    // present and an absent one would tell a caller which kind of client an id
    // names. That is the same reasoning as the uniform invalid_client shape
    // above, applied one level in.
    if (!isPublicClient(client) && !verifyClientSecret(client, String(body.client_secret ?? ''))) {
      console.warn(`token rejected: bad client credentials for ${clientId || '(none)'}`);
      return res.status(401).json({ error: 'invalid_client' });
    }

    const result = await consumeCode(String(body.code ?? ''), {
      clientId,
      redirectUri,
      // Absent is a value here: consumeCode refuses a challenged code with no
      // verifier, and that must stay a grant failure rather than becoming a
      // separate, distinguishable error.
      codeVerifier: body.code_verifier == null ? null : String(body.code_verifier)
    });
    if (!result.ok) {
      console.warn(`token rejected for ${clientId}: ${result.reason}`);
      return res.status(400).json(INVALID_GRANT);
    }

    const idToken = await signIdToken({
      sub: result.row.app_sub,
      clientId,
      nonce: result.row.nonce
    });

    // `access_token` is REQUIRED by RFC 6749 §5.1 and OIDC Core §3.1.3.3, so it
    // is present even though nothing behind this service accepts one.
    //
    // The spec's §1 called omitting it the honest choice - there is no
    // Opsidious API to call on a user's behalf, so an unused access token
    // looked like cargo cult. That reasoning was right about the purpose and
    // wrong about the cost, and the cost was only measured later: pointing the
    // reference client (`openid-client`, on `oauth4webapi`) at this issuer
    // failed the exchange outright with `"response" body "access_token"
    // property must be a string`. Adding this one field turned that into a
    // completed flow - discovery, exchange, signature and nonce all verified by
    // the library itself. A response no conformant client can parse is a worse
    // kind of cargo cult than an unused field.
    //
    // It is deliberately inert: a fresh random string, never stored, never
    // examined, accepted by no endpoint here. Nothing can be done with it,
    // which is exactly what "there is no resource server" means in practice.
    // `refresh_token` stays absent - it is optional, so omitting it costs
    // nothing and there is no long-lived grant to refresh.
    res.json({
      access_token: randomToken(32),
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: ID_TOKEN_TTL_S
    });
  } catch (err) {
    next(err);
  }
});

export default router;
