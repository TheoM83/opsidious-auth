import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase, dbAll } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession, resolveSession } from '../lib/sessions.js';
import { SSO_COOKIE_NAME } from '../lib/config.js';

before(async () => {
  await initForTest();
});
after(async () => {
  await closeDatabase();
});

// Well-formed (64 hex chars, the shape of a real sha256 hex digest) so a
// comparison against it exercises safeEqual's equal-length path rather than
// the length-mismatch shortcut - but it is not the session's actual token.
const WRONG_CSRF = '0'.repeat(64);

async function signedIn() {
  const { account, pairwiseSalt } = await signInWithGoogleSub(`sub-${Math.random()}`);
  const { cookieValue } = await createSession(account.id, pairwiseSalt);
  const page = await request(app).get('/account').set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`);
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)[1];
  return { account, cookieValue, csrf, page };
}

// A `__Host-` cookie without `Secure` is rejected outright by every browser -
// clearing it without `Secure` is silently a no-op, not a partial success.
// `NODE_ENV` is 'test' here (never 'production'), so this also proves the
// clearing directive is not gated on IS_PRODUCTION.
function assertCookieCleared(res) {
  const setCookies = res.headers['set-cookie'] || [];
  const clearing = setCookies.find((c) => c.startsWith(`${SSO_COOKIE_NAME}=`));
  assert.ok(clearing, 'response must clear the SSO cookie');
  assert.match(clearing, /Secure/);
}

test('the account page requires a session', async () => {
  const res = await request(app).get('/account');
  assert.equal(res.status, 401);
});

test('the page says what deleting here does not reach', async () => {
  // Spec §11. Pairwise subjects mean this service cannot tell applications
  // whom to erase, so the order matters and the page has to say so.
  const { page } = await signedIn();
  assert.equal(page.status, 200);
  assert.match(page.text, /applications/i);
  // Pins the explanation itself, not just decorative heading/button text
  // that also happens to contain "supprim" (e.g. "Supprimer ce compte").
  assert.match(page.text, /ne seront pas effacées/i);
});

test('the page never displays the Google account or any identifier', async () => {
  const { page, account } = await signedIn();
  assert.ok(!page.text.includes(account.id));
  assert.ok(!page.text.includes('google_sub'));
});

test('logout ends the session and clears the __Host- cookie with Secure set', async () => {
  const { cookieValue, csrf } = await signedIn();
  const res = await request(app)
    .post('/logout')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ csrf });
  assert.equal(res.status, 302);
  assert.equal(await resolveSession(cookieValue), null);
  assertCookieCleared(res);
});

test('logout without the CSRF token is refused', async () => {
  const { cookieValue } = await signedIn();
  const res = await request(app)
    .post('/logout')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({});
  assert.equal(res.status, 403);
  assert.ok(await resolveSession(cookieValue));
});

test('logout with a present but incorrect CSRF token is refused', async () => {
  // A presence-only check (`Boolean(req.body?.csrf)`) would pass this. The
  // token must be compared against the value derived from the cookie.
  const { cookieValue } = await signedIn();
  const res = await request(app)
    .post('/logout')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ csrf: WRONG_CSRF });
  assert.equal(res.status, 403);
  assert.ok(await resolveSession(cookieValue));
});

test('deleting the account erases it, every session, and clears the cookie with Secure set', async () => {
  const { account, cookieValue, csrf } = await signedIn();
  const res = await request(app)
    .post('/account/delete')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ csrf, confirm: 'SUPPRIMER' });

  assert.equal(res.status, 302);
  assert.equal((await dbAll('SELECT id FROM accounts WHERE id = ?', [account.id])).length, 0);
  assert.equal((await dbAll('SELECT id FROM sso_sessions WHERE account_id = ?', [account.id])).length, 0);
  assert.equal(await resolveSession(cookieValue), null);
  assertCookieCleared(res);
});

test('deletion without the confirmation word does nothing', async () => {
  const { account, cookieValue, csrf } = await signedIn();
  const res = await request(app)
    .post('/account/delete')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ csrf, confirm: 'oui' });

  assert.equal(res.status, 400);
  assert.equal((await dbAll('SELECT id FROM accounts WHERE id = ?', [account.id])).length, 1);
});

test('deletion without the CSRF token does nothing', async () => {
  const { account, cookieValue } = await signedIn();
  const res = await request(app)
    .post('/account/delete')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ confirm: 'SUPPRIMER' });

  assert.equal(res.status, 403);
  assert.equal((await dbAll('SELECT id FROM accounts WHERE id = ?', [account.id])).length, 1);
});

test('deletion with a present but incorrect CSRF token does nothing', async () => {
  // Same regression this guards against as the logout case above: a
  // presence-only check would let a forged-but-wrong token through.
  const { account, cookieValue } = await signedIn();
  const res = await request(app)
    .post('/account/delete')
    .type('form')
    .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`)
    .send({ csrf: WRONG_CSRF, confirm: 'SUPPRIMER' });

  assert.equal(res.status, 403);
  assert.equal((await dbAll('SELECT id FROM accounts WHERE id = ?', [account.id])).length, 1);
});
