// A half-translated identity service is worse than a monolingual one: the pages
// a person reads before deciding to trust something are exactly the pages that
// must not be half in a language they do not speak.
//
// So completeness is not a habit here, it is a failing test.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession } from '../lib/sessions.js';
import { createClient } from '../lib/clients.js';
import { SSO_COOKIE_NAME, LOCALE_COOKIE_NAME } from '../lib/config.js';
import {
  CATALOGUES,
  LOCALES,
  DEFAULT_LOCALE,
  negotiate,
  parseAcceptLanguage,
  parseUiLocales,
  translator
} from '../lib/i18n.js';

before(async () => {
  await initForTest();
});
after(async () => {
  await closeDatabase();
});

function flatten(value, prefix = '', out = new Map()) {
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  } else {
    out.set(prefix, value);
  }
  return out;
}

const placeholders = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

const reference = flatten(CATALOGUES[DEFAULT_LOCALE]);
const others = LOCALES.filter((code) => code !== DEFAULT_LOCALE);

// ── The catalogues agree with each other ─────────────────────────────────

test('every locale carries exactly the reference key set', () => {
  for (const code of others) {
    const flat = flatten(CATALOGUES[code]);
    assert.deepEqual(
      [...reference.keys()].filter((k) => !flat.has(k)),
      [],
      `${code}: missing keys`
    );
    assert.deepEqual(
      [...flat.keys()].filter((k) => !reference.has(k)),
      [],
      `${code}: keys that exist in no other locale`
    );
  }
});

test('placeholders match across locales', () => {
  for (const code of others) {
    const flat = flatten(CATALOGUES[code]);
    for (const [key, value] of reference) {
      assert.deepEqual(
        placeholders(flat.get(key)),
        placeholders(value),
        `${code}: ${key} does not interpolate the same values`
      );
    }
  }
});

test('no locale ships an empty string, and none ships markup', () => {
  for (const code of LOCALES) {
    for (const [key, value] of flatten(CATALOGUES[code])) {
      assert.equal(typeof value, 'string', `${code}: ${key} is not a string`);
      assert.notEqual(value.trim(), '', `${code}: ${key} is empty`);
      // Templates escape everything. A translation containing a tag would show
      // the tag spelled out, which is a bug nobody notices in a language they
      // do not read.
      assert.ok(!/[<>]/.test(value), `${code}: ${key} contains markup`);
    }
  }
});

// ── Negotiation ──────────────────────────────────────────────────────────

test('a person beats the application that sent them', () => {
  // The whole ordering decision in one assertion: someone who picked French on
  // this service keeps French even when an English application says `en`.
  const chosen = negotiate({ cookie: 'fr', uiLocales: 'en', acceptLanguage: 'en-GB,en' });
  assert.deepEqual(chosen, { locale: 'fr', from: 'cookie' });
});

test('ui_locales beats the browser, because the application asked first', () => {
  const chosen = negotiate({ uiLocales: 'en de', acceptLanguage: 'fr-FR,fr;q=0.9' });
  assert.deepEqual(chosen, { locale: 'en', from: 'ui_locales' });
});

test('an unsupported ui_locales falls through rather than failing', () => {
  const chosen = negotiate({ uiLocales: 'de ja', acceptLanguage: 'fr-FR,fr;q=0.9' });
  assert.deepEqual(chosen, { locale: 'fr', from: 'accept-language' });
});

test('a region tag matches its language', () => {
  assert.equal(negotiate({ acceptLanguage: 'fr-CA' }).locale, 'fr');
  assert.equal(negotiate({ uiLocales: 'en-AU' }).locale, 'en');
});

test('nothing at all is the default, and a junk header cannot fail a request', () => {
  assert.deepEqual(negotiate({}), { locale: DEFAULT_LOCALE, from: 'default' });
  assert.deepEqual(negotiate({ acceptLanguage: ';;;q=' }), {
    locale: DEFAULT_LOCALE,
    from: 'default'
  });
});

test('Accept-Language is read in q order, not in written order', () => {
  assert.deepEqual(parseAcceptLanguage('de;q=0.2, fr;q=0.9, en;q=0.5'), ['fr', 'en', 'de']);
  // q=0 means "not acceptable" and must not be offered.
  assert.deepEqual(parseAcceptLanguage('fr;q=0, en'), ['en']);
});

test('ui_locales is bounded: it is unauthenticated query input', () => {
  const many = Array.from({ length: 50 }, (_, i) => `x${i}`).join(' ');
  assert.equal(parseUiLocales(many).length, 10);
});

// ── The translator ───────────────────────────────────────────────────────

test('placeholders are filled, and an unknown one is left visible', () => {
  const t = translator('en');
  assert.match(t('common.langAria', { lang: 'Français' }), /Français/);
  assert.match(t('common.langAria', {}), /\{lang\}/);
});

test('plurals go through Intl, not through a === 1 guess', () => {
  const t = translator('en');
  assert.match(t('account.fields.ssoSessions.reveals', { count: 3 }), /3/);
});

test('a missing key throws outside production rather than reaching a reader', () => {
  const t = translator('en');
  assert.throws(() => t('nope.not.a.key'), /does not exist/);
});

// ── The pages ────────────────────────────────────────────────────────────

// The strongest of these, and the cheapest: render every page the service has,
// in every language, and look for every string the catalogue defines. A key
// nobody renders fails here, and so does a template slot with nothing behind it.
test('every string in every catalogue reaches a real page', async () => {
  // `errors.serverError` needs an unhandled exception, which this suite has no
  // honest way to provoke; `code` is an identifier, not prose.
  const NOT_ON_A_PAGE = new Set(['code', 'errors.serverError']);

  for (const locale of LOCALES) {
    const lang = (path) => request(app).get(path).set('Cookie', `${LOCALE_COOKIE_NAME}=${locale}`);

    const { account, pairwiseSalt } = await signInWithGoogleSub(`i18n-${locale}-${Math.random()}`);
    const { cookieValue } = await createSession(account.id, pairwiseSalt);
    // A SECOND browser, so the one plural string on the whole service actually
    // renders. Without it the sweep silently skips the only key that goes
    // through Intl.PluralRules - which is exactly the key most likely to be
    // wrong in a language nobody on the team reads.
    await createSession(account.id, pairwiseSalt);
    const clientId = `i18n-${locale}`;
    await createClient({
      id: clientId,
      name: 'i18n fixture',
      redirectUris: ['https://app.example/cb']
    });

    const pages = await Promise.all([
      lang('/'),
      lang('/definitely-not-a-page'),
      lang('/account'),
      lang(
        `/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent('https://app.example/cb')}` +
          '&response_type=code&scope=openid&state=abc'
      ),
      lang('/authorize?client_id=nope&redirect_uri=https%3A%2F%2Fnope.example%2Fcb'),
      lang('/callback/google?state=gone'),
      // Signed in, so the ledger itself renders and not the 401 page.
      request(app)
        .get('/account')
        .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}; ${LOCALE_COOKIE_NAME}=${locale}`),
      request(app)
        .post('/account/delete')
        .type('form')
        .send({ csrf: 'wrong', confirm: 'nope' })
        .set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}; ${LOCALE_COOKIE_NAME}=${locale}`)
    ]);

    const html = pages.map((r) => r.text).join('\n');

    for (const [key, value] of flatten(CATALOGUES[locale])) {
      if (NOT_ON_A_PAGE.has(key)) continue;
      // A string with a placeholder is rendered filled in, so only the part
      // before the first `{` survives verbatim.
      const literal = value.split('{')[0].trim();
      if (literal.length < 4) continue;
      const escaped = literal.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
      assert.ok(
        html.includes(literal) || html.includes(escaped),
        `${locale}: "${key}" is defined but never rendered`
      );
    }
  }
});

test('ui_locales alone changes the sign-in screen, with no cookie involved', async () => {
  await createClient({
    id: 'ui-locales-probe',
    name: 'probe',
    redirectUris: ['https://app.example/cb']
  });

  const authorize = (uiLocales) =>
    request(app)
      .get('/authorize')
      .query({
        client_id: 'ui-locales-probe',
        redirect_uri: 'https://app.example/cb',
        response_type: 'code',
        scope: 'openid',
        state: 'abc',
        ui_locales: uiLocales
      })
      // The browser says French. The application will say otherwise.
      .set('Accept-Language', 'fr-FR,fr;q=0.9');

  const french = await authorize('fr');
  const english = await authorize('en');

  assert.equal(french.headers['content-language'], 'fr');
  assert.equal(english.headers['content-language'], 'en');
  assert.match(french.text, /Connexion anonyme/);
  assert.match(english.text, /Anonymous sign-in/);
});

test('the language switch keeps the sign-in request it was clicked from', async () => {
  await createClient({
    id: 'switch-probe',
    name: 'probe',
    redirectUris: ['https://app.example/cb']
  });

  const page = await request(app).get('/authorize').query({
    client_id: 'switch-probe',
    redirect_uri: 'https://app.example/cb',
    response_type: 'code',
    scope: 'openid',
    state: 'abc'
  });

  // Losing the query here would drop the person out of a sign-in they were
  // halfway through, which is why this one page opts out of the path-only rule.
  const href = /href="(\/lang\/[^"]+)"/.exec(page.text);
  assert.ok(href, 'the sign-in screen must offer the other language');
  assert.match(decodeURIComponent(href[1]), /client_id=switch-probe/);
});

test('the language cookie is host-only and Secure, like every other cookie here', async () => {
  const res = await request(app).get('/lang/fr?next=/');
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/');
  const cookie = (res.headers['set-cookie'] || []).find((c) => c.startsWith(LOCALE_COOKIE_NAME));
  assert.ok(cookie, 'the choice must be remembered');
  assert.match(cookie, /Secure/);
  assert.match(cookie, /HttpOnly/);
  assert.ok(!/Domain=/i.test(cookie), '__Host- forbids a Domain attribute');
});

test('the language switch is not an open redirect', async () => {
  for (const next of ['//evil.example/', 'https://evil.example/', 'javascript:alert(1)']) {
    const res = await request(app).get(`/lang/fr`).query({ next });
    assert.equal(res.headers.location, '/', `${next} must not be followed`);
  }
});

test('an unknown language is a 404, not a silent default', async () => {
  const res = await request(app).get('/lang/de?next=/');
  assert.equal(res.status, 404);
});

test('a localised page tells caches what it varied on', async () => {
  const res = await request(app).get('/').set('Accept-Language', 'fr');
  assert.equal(res.headers['content-language'], 'fr');
  assert.match(res.headers.vary, /Accept-Language/);
  assert.match(res.headers.vary, /Cookie/);
});
