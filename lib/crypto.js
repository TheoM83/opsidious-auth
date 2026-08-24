// The envelope of spec §4.3, and the small primitives around it.
//
// The pairwise salt is what turns one account into a different opaque subject
// per application. It is never stored in the clear: it is sealed under a key
// derived from a secret the service does not keep - the Google subject on the
// account row, the SSO cookie value on the session row. The plaintext exists
// only in memory, only during a request that already carries that secret.
//
// Pure. No database, no clock, no I/O.
import {
  hkdfSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  createHash,
  timingSafeEqual
} from 'node:crypto';

const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SALT_BYTES = 32;
const KDF_SALT_BYTES = 16;

// Distinct purposes must never derive the same key from the same input, so a
// key that opens an account row cannot open a session row.
export const INFO_ACCOUNT = 'opsidious-pairwise-v1';
export const INFO_SESSION = 'opsidious-session-v1';
// Deux usages distincts de la MÊME clé maîtresse. Les `info` séparés font que
// la clé qui ouvre le pepper n'ouvre pas les clés de signature : compromettre
// un usage ne donne pas l'autre.
export const INFO_KEYSTORE = 'opsidious-keystore-v1';
export const INFO_PEPPER = 'opsidious-pepper-v1';

// Scelle sous la clé maîtresse, qui vit dans l'environnement et jamais dans la
// base. Le sel de dérivation accompagne le chiffré : il n'est pas secret, il
// sert à ce que deux valeurs scellées sous la même clé ne partagent pas la
// leur.
export function sealUnderMaster(masterKey, info, plaintext) {
  const kdfSalt = newKdfSalt();
  return { kdfSalt, blob: seal(deriveKey(masterKey, kdfSalt, info), plaintext) };
}

export function openUnderMaster(masterKey, info, kdfSalt, blob) {
  return openSealed(deriveKey(masterKey, kdfSalt, info), blob);
}

export function deriveKey(ikm, kdfSalt, info) {
  return Buffer.from(hkdfSync('sha256', Buffer.from(ikm), kdfSalt, Buffer.from(info), KEY_BYTES));
}

export function newSalt() {
  return randomBytes(SALT_BYTES);
}

export function newKdfSalt() {
  return randomBytes(KDF_SALT_BYTES);
}

export function seal(key, plaintext) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

// Throws on a wrong key, a wrong purpose, tampering, or truncation. It must
// never return bytes it is not sure about.
export function openSealed(key, blob) {
  const buffer = Buffer.from(blob);
  if (buffer.length < IV_BYTES + TAG_BYTES) throw new Error('sealed value is truncated');
  const decipher = createDecipheriv('aes-256-gcm', key, buffer.subarray(0, IV_BYTES));
  decipher.setAuthTag(buffer.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
  return Buffer.concat([decipher.update(buffer.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]);
}

// The subject an application sees. Derived on every issue, never stored.
export function pairwiseSubject(pairwiseSalt, clientId) {
  return createHmac('sha256', pairwiseSalt).update(String(clientId)).digest('base64url');
}

// The one deterministic index we need: finding an existing account from a
// Google subject at sign-in.
export function lookupHash(pepper, value) {
  return createHmac('sha256', Buffer.from(pepper)).update(String(value)).digest('hex');
}

export function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

// PKCE (RFC 7636), S256 only.
//
// `plain` is deliberately absent, here and at the route: it sends the verifier
// itself through the same channel that may already be leaking the code, which
// is the interception the mechanism exists to prevent. Supporting it would be
// advertising a defence that is not one.
const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/;

// RFC 7636 §4.1: 43 to 128 characters of unreserved ASCII. Enforced rather
// than assumed - a short verifier is a guessable one, and the whole mechanism
// rests on the verifier being unguessable to whoever intercepted the code.
export function isValidCodeVerifier(verifier) {
  return typeof verifier === 'string' && VERIFIER_PATTERN.test(verifier);
}

// The S256 output is always 43 base64url characters. Anything else was not
// produced by the transformation we are about to compare against.
export function isValidCodeChallenge(challenge) {
  return typeof challenge === 'string' && CHALLENGE_PATTERN.test(challenge);
}

// RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))). The `ascii` encoding is
// the spec's, not an approximation of it.
export function s256Challenge(verifier) {
  return createHash('sha256').update(String(verifier), 'ascii').digest('base64url');
}

// Never throws: /token hands this whatever arrived in the request body, and a
// throw would be a 500 that separates malformed input from a wrong verifier -
// an oracle for exactly the value this is meant to protect.
export function verifyCodeVerifier(challenge, verifier) {
  if (!isValidCodeChallenge(challenge) || !isValidCodeVerifier(verifier)) return false;
  return safeEqual(s256Challenge(verifier), challenge);
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  // timingSafeEqual throws on a length mismatch, which would itself leak.
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
