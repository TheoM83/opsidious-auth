import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { ISSUER, PUBLIC_URL } from '../lib/config.js';

before(async () => {
  await initForTest();
});
after(async () => {
  await closeDatabase();
});

const get = () => request(app).get('/.well-known/openid-configuration');

test('the discovery document points at endpoints that actually exist', async () => {
  const res = await get();
  assert.equal(res.status, 200);
  const d = res.body;
  assert.equal(d.issuer, ISSUER);

  // Every advertised endpoint must answer. A discovery document that names a
  // route the server does not serve is worse than none: a standard library
  // configures itself against the promise and fails at the call.
  // Probed with the method the endpoint actually accepts: /token is POST-only,
  // so a GET there correctly falls through to 404 and would make this check
  // fail for the wrong reason.
  for (const [key, expectedPath, method] of [
    ['authorization_endpoint', '/authorize', 'get'],
    ['token_endpoint', '/token', 'post'],
    ['jwks_uri', '/.well-known/jwks.json', 'get']
  ]) {
    assert.equal(d[key], `${PUBLIC_URL}${expectedPath}`, `${key} must be ${expectedPath}`);
    const probe = await request(app)[method](expectedPath);
    assert.notEqual(probe.status, 404, `${expectedPath} is advertised but answers 404`);
  }
});

test('it advertises pairwise subjects, which is the whole product', async () => {
  const { body } = await get();
  assert.deepEqual(body.subject_types_supported, ['pairwise']);
});

test('it promises no capability this service lacks', async () => {
  const { body } = await get();

  // openid only: the service never asks Google for email or profile, so it
  // could not populate those claims even if a client requested them.
  assert.deepEqual(body.scopes_supported, ['openid']);
  assert.ok(!body.claims_supported.includes('email'));
  assert.ok(!body.claims_supported.includes('name'));

  // Deliberate absences (spec section 1). Advertising any of these would make a
  // standard client attempt a flow this server does not implement.
  assert.equal(body.userinfo_endpoint, undefined, 'there is no userinfo endpoint');
  // `registration_endpoint` used to be asserted absent here, with the note
  // "dynamic registration is a non-goal". It stopped being a non-goal: an
  // identity service whose subjects are pairwise has nothing to protect by
  // gate-keeping registration, because a client that registers gains a value
  // that is worthless everywhere else. The endpoint exists, so it is
  // advertised - see routes/register.js.
  assert.equal(
    body.registration_endpoint,
    `${PUBLIC_URL}/register`,
    'registration is open, so it must be discoverable'
  );
  assert.ok(!(body.grant_types_supported || []).includes('refresh_token'));
  assert.deepEqual(body.response_types_supported, ['code']);
  assert.deepEqual(body.id_token_signing_alg_values_supported, ['RS256']);
});

test('the front door is a page, not a 404', async () => {
  const res = await request(app).get('/');
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /html/);
  // It must route a curious visitor onward rather than dead-end them.
  assert.match(res.text, /\/account/);
});

// The front door is the ONE page here a search engine should hold: the whole
// design is that any application may register without asking anyone, and an
// open door nobody can find is open only to those who were told about it. Every
// other page is somebody's session, and the layout excludes those by default -
// which is why this test also checks the negative.
test('the front door is the only indexable page', async () => {
  const home = await request(app).get('/');
  assert.ok(!/name="robots"[^>]*noindex/.test(home.text), 'the home page excludes itself');
  assert.match(home.text, /<meta name="description" content="[^"]{40,}"/);
  assert.match(home.text, /rel="canonical"/);
  assert.match(home.text, /property="og:image" content="[^"]+og\.png"/);
  assert.match(home.text, /name="twitter:card" content="summary_large_image"/);
  // A title that is only the brand says nothing in a tab strip or a result.
  const title = home.text.match(/<title>([^<]*)<\/title>/);
  assert.ok(title && title[1].length > 'Opsidious'.length + 8, `weak title: ${title && title[1]}`);

  const intro = await request(app).get('/intro');
  assert.match(intro.text, /name="robots" content="noindex"/, 'sign-in must stay out');
});

test('discovery advertises S256 and none', async () => {
  const res = await request(app).get('/.well-known/openid-configuration');
  assert.deepEqual(res.body.code_challenge_methods_supported, ['S256']);
  // `none` is the standard name for "this client presents no credential",
  // which is exactly what a public client does at /token.
  assert.deepEqual(res.body.token_endpoint_auth_methods_supported, ['client_secret_post', 'none']);
});

test('discovery never advertises plain', async () => {
  // A discovery document that promises a capability the server lacks is worse
  // than no document: a standard library configures itself against the promise
  // and fails at the call. The inverse holds too - this service refuses plain,
  // so it must never appear here.
  const res = await request(app).get('/.well-known/openid-configuration');
  assert.ok(!res.body.code_challenge_methods_supported.includes('plain'));
});
