// Our own ID token. Seven claims, and there is deliberately nothing else to
// put in it.
import { SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';
import { currentSigner } from './keys.js';
import { ISSUER, ID_TOKEN_TTL_S } from './config.js';

export async function signIdToken({ sub, clientId, nonce }, now = Date.now()) {
  const { kid, privateKey } = await currentSigner(now);
  const issuedAt = Math.floor(now / 1000);

  const claims = { jti: randomUUID() };
  if (nonce) claims.nonce = nonce;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(ISSUER)
    .setAudience(clientId)
    .setSubject(sub)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ID_TOKEN_TTL_S)
    .sign(privateKey);
}
