// Language for the pages this service renders.
//
// Four sources, in this order, and the order is the whole design:
//
//   1. `__Host-opsid_lang` — a choice the person made ON THIS SERVICE.
//   2. `ui_locales` — OIDC Core §3.1.2.1: the application's hint about the
//      language its own interface is in.
//   3. `Accept-Language` — the browser's standing preference.
//   4. DEFAULT_LOCALE.
//
// The human beats the application, deliberately. An application knows what
// language IT is in; only the person knows what language THEY read. Someone who
// clicked "Français" here once should not be handed an English sign-in screen
// because the application that sent them happens to be English.
//
// routes/authorize.js used to carry a comment saying `ui_locales` was among the
// parameters "deliberately NOT rejected" — accepted and ignored, because the
// spec says a server ignores what it does not understand. It understands it now.

import { LOCALE_COOKIE_NAME, DEFAULT_LOCALE as CONFIGURED_DEFAULT } from './config.js';
import en from '../locales/en.js';
import fr from '../locales/fr.js';

export const CATALOGUES = Object.freeze({ en, fr });

// Advertised verbatim in the discovery document, so this array is the contract.
export const LOCALES = Object.freeze(Object.keys(CATALOGUES));

export const DEFAULT_LOCALE = LOCALES.includes(CONFIGURED_DEFAULT) ? CONFIGURED_DEFAULT : 'en';

export const isSupported = (code) => LOCALES.includes(code);

// ── Flattening ───────────────────────────────────────────────────────────
// `{ home: { title: 'x' } }` becomes `{ 'home.title': 'x' }` once, at load,
// so a lookup is a Map hit rather than a walk down an object per call.
function flatten(value, prefix, out) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  } else {
    out.set(prefix, value);
  }
  return out;
}

const FLAT = Object.fromEntries(
  Object.entries(CATALOGUES).map(([code, catalogue]) => [code, flatten(catalogue, '', new Map())])
);

// ── Lookup ───────────────────────────────────────────────────────────────
// A missing key is a bug, and it is loud in the two places bugs get found:
// the test suite and a developer's terminal. In production it falls back to the
// default locale rather than showing a reader `account.title` where a sentence
// should be — a half-translated page is bad, a page displaying its own internals
// is worse.
const STRICT = process.env.NODE_ENV !== 'production';

function lookup(locale, key) {
  const hit = FLAT[locale]?.get(key);
  if (hit !== undefined) return hit;

  const fallback = FLAT[DEFAULT_LOCALE]?.get(key);
  if (fallback !== undefined) {
    if (STRICT) throw new Error(`i18n: "${key}" is missing from locale "${locale}"`);
    console.warn(`i18n: "${key}" missing from "${locale}", used "${DEFAULT_LOCALE}"`);
    return fallback;
  }

  if (STRICT) throw new Error(`i18n: "${key}" does not exist in any locale`);
  console.warn(`i18n: "${key}" does not exist in any locale`);
  return key;
}

const interpolate = (template, vars) =>
  String(template).replace(/\{(\w+)\}/g, (whole, name) =>
    Object.hasOwn(vars, name) ? String(vars[name]) : whole
  );

// One `t` per request, closed over the negotiated locale. Templates call
// `t('key')`; nothing in a template ever names a language.
export function translator(locale) {
  const code = isSupported(locale) ? locale : DEFAULT_LOCALE;

  // Intl decides the plural category, not a `n === 1` guess: a catalogue that
  // one day needs `few` or `many` gets them without this file changing.
  const plurals = new Intl.PluralRules(code);

  function t(key, vars = {}) {
    if (Object.hasOwn(vars, 'count')) {
      const category = plurals.select(Number(vars.count));
      const exact = FLAT[code]?.get(`${key}.${category}`);
      const chosen = exact !== undefined ? `${key}.${category}` : `${key}.other`;
      return interpolate(lookup(code, chosen), vars);
    }
    return interpolate(lookup(code, key), vars);
  }

  t.locale = code;
  t.number = (n) => new Intl.NumberFormat(code).format(n);
  t.date = (value) =>
    new Intl.DateTimeFormat(code, { dateStyle: 'long', timeZone: 'UTC' }).format(new Date(value));
  return t;
}

// ── Negotiation ──────────────────────────────────────────────────────────

// `fr-CA` matches `fr`. Nothing here matches across languages: a request for
// `de` gets the default, not "whatever is closest alphabetically".
function bestMatch(tags) {
  for (const tag of tags) {
    const lower = String(tag).toLowerCase();
    if (isSupported(lower)) return lower;
    const primary = lower.split('-')[0];
    if (isSupported(primary)) return primary;
  }
  return null;
}

// RFC 9110 §12.5.4. Malformed input yields no preference rather than an error:
// a header this service does not control must never be able to fail a request.
export function parseAcceptLanguage(header) {
  if (!header) return [];
  return String(header)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
      const weight = q ? Number.parseFloat(q.slice(2)) : 1;
      return { tag: tag.trim(), q: Number.isFinite(weight) ? weight : 0 };
    })
    .filter((entry) => entry.tag && entry.q > 0)
    .sort((a, b) => b.q - a.q)
    .map((entry) => entry.tag);
}

// OIDC Core §3.1.2.1: space-separated BCP-47 tags, most preferred first.
export const parseUiLocales = (value) =>
  String(value ?? '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 10); // a bounded list: this is unauthenticated query input

export function negotiate({ cookie, uiLocales, acceptLanguage } = {}) {
  if (isSupported(cookie)) return { locale: cookie, from: 'cookie' };

  const fromApp = bestMatch(parseUiLocales(uiLocales));
  if (fromApp) return { locale: fromApp, from: 'ui_locales' };

  const fromBrowser = bestMatch(parseAcceptLanguage(acceptLanguage));
  if (fromBrowser) return { locale: fromBrowser, from: 'accept-language' };

  return { locale: DEFAULT_LOCALE, from: 'default' };
}

// Reads only what the request carries. `parkedLocale` is the language an
// /authorize request was made in, replayed on the way back from Google so the
// round trip does not change language halfway through.
export function localeFor(req, parkedLocale) {
  return negotiate({
    cookie: req.cookies?.[LOCALE_COOKIE_NAME],
    uiLocales: parkedLocale ?? req.query?.ui_locales,
    acceptLanguage: req.headers?.['accept-language']
  });
}
