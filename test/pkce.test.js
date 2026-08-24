import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  s256Challenge,
  verifyCodeVerifier,
  isValidCodeVerifier,
  isValidCodeChallenge
} from '../lib/crypto.js';

// RFC 7636 Appendix B. Testing against the published vector rather than
// against our own output is the difference between "consistent with itself"
// and "interoperable with every client library that exists".
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

test('s256Challenge matches the RFC 7636 test vector', () => {
  assert.equal(s256Challenge(RFC_VERIFIER), RFC_CHALLENGE);
});

test('the matching verifier verifies', () => {
  assert.equal(verifyCodeVerifier(RFC_CHALLENGE, RFC_VERIFIER), true);
});

test('a different verifier does not', () => {
  const other = 'E'.repeat(43);
  assert.equal(verifyCodeVerifier(RFC_CHALLENGE, other), false);
});

test('a missing or malformed verifier is refused, never thrown on', () => {
  // /token passes whatever arrived in the body. A throw here would be a 500
  // that distinguishes malformed input from a wrong verifier - an oracle.
  for (const bad of [undefined, null, '', 'short', 42, {}, 'a'.repeat(129), 'a'.repeat(42)]) {
    assert.equal(verifyCodeVerifier(RFC_CHALLENGE, bad), false);
  }
});

test('a missing challenge never verifies', () => {
  for (const bad of [undefined, null, '']) {
    assert.equal(verifyCodeVerifier(bad, RFC_VERIFIER), false);
  }
});

test('isValidCodeVerifier enforces the RFC 7636 length and alphabet', () => {
  assert.equal(isValidCodeVerifier('a'.repeat(43)), true);
  assert.equal(isValidCodeVerifier('a'.repeat(128)), true);
  assert.equal(isValidCodeVerifier('a'.repeat(42)), false);
  assert.equal(isValidCodeVerifier('a'.repeat(129)), false);
  assert.equal(isValidCodeVerifier('-._~' + 'a'.repeat(39)), true);
  // Not in the unreserved set.
  assert.equal(isValidCodeVerifier('+' + 'a'.repeat(42)), false);
  assert.equal(isValidCodeVerifier('/' + 'a'.repeat(42)), false);
  assert.equal(isValidCodeVerifier('=' + 'a'.repeat(42)), false);
});

test('isValidCodeChallenge accepts exactly a 43-char base64url string', () => {
  assert.equal(isValidCodeChallenge(RFC_CHALLENGE), true);
  assert.equal(isValidCodeChallenge('a'.repeat(43)), true);
  assert.equal(isValidCodeChallenge('a'.repeat(42)), false);
  assert.equal(isValidCodeChallenge('a'.repeat(44)), false);
  // base64url has no padding and no + or /
  assert.equal(isValidCodeChallenge('a'.repeat(42) + '='), false);
  assert.equal(isValidCodeChallenge('a'.repeat(42) + '+'), false);
  assert.equal(isValidCodeChallenge(undefined), false);
});
