// Centralised configuration, validated at import time so a misconfigured
// deployment fails at boot rather than at the first sign-in.

export const NODE_ENV = process.env.NODE_ENV || 'development';
export const IS_PRODUCTION = NODE_ENV === 'production';

// 0-safe numeric env reader: an explicitly configured `0` is honoured, unlike
// the `Number(x) || default` idiom which treats it as falsy.
export function numEnv(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  return Number.isNaN(n) ? def : n;
}

function required(name) {
  const value = (process.env[name] || '').trim();
  if (!value) throw new Error(`${name} must be set`);
  return value;
}

export const PORT = numEnv('PORT', 4570);

// No default. This service is published openly and someone else self-hosting
// it must not inherit our domain (spec §13).
export const PUBLIC_URL = required('PUBLIC_URL').replace(/\/+$/, '');
export const ISSUER = (process.env.ISSUER || PUBLIC_URL).replace(/\/+$/, '');
export const GOOGLE_REDIRECT_URI = `${PUBLIC_URL}/callback/google`;

export const GOOGLE_CLIENT_ID = required('GOOGLE_CLIENT_ID');
export const GOOGLE_CLIENT_SECRET = required('GOOGLE_CLIENT_SECRET');

// La clé qui protège tout ce qui, dans la base, permettrait d'usurper une
// identité : la clé privée de signature et le pepper. Elle ne figure NULLE PART
// dans la base — c'est tout son intérêt.
//
// Mesuré avant de l'introduire : avec le seul fichier de base, un jeton portant
// n'importe quel `sub` se forgeait et passait la vérification contre le JWKS
// publié. Une sauvegarde égarée, un disque revendu ou un dump suffisaient.
//
// Hors production, une valeur de développement fixe est utilisée : une clé
// éphémère invaliderait les jetons à chaque redémarrage, et l'avertissement
// vaut mieux qu'un service qui ne démarre pas en local.
export const MASTER_KEY = (() => {
  const value = process.env.MASTER_KEY || '';
  if (value) return value;
  if (IS_PRODUCTION) {
    throw new Error('MASTER_KEY must be set in production. Générez-en une : openssl rand -base64 32');
  }
  console.warn(
    'MASTER_KEY not set - using a development value. La clé de signature et le ' +
      'pepper ne sont PAS protégés dans cette base.'
  );
  return 'development-only-master-key-not-for-production';
})();

export const DB_PATH = process.env.DB_PATH || '';

// SQLite serialises writers even in WAL mode: a write that collides with
// another write (a sign-in landing during a sweep, or during the backup's
// VACUUM INTO) throws SQLITE_BUSY immediately unless the connection is told
// to wait. This is comfortably longer than any single write should take, and
// comfortably under a user's patience for a sign-in request.
export const DB_BUSY_TIMEOUT_MS = numEnv('DB_BUSY_TIMEOUT_MS', 5000);
export const BACKUP_DIR = process.env.BACKUP_DIR || '';
export const BACKUP_RETENTION_DAYS = numEnv('BACKUP_RETENTION_DAYS', 14);
export const BACKUP_INTERVAL_MS = numEnv('BACKUP_INTERVAL_MS', 24 * 3600 * 1000);

// __Host- forbids a Domain attribute, which is exactly what we want: the
// cookie must never be readable by a sibling subdomain (spec §2).
export const SSO_COOKIE_NAME = '__Host-opsid_sso';
// Dit seulement que l'écran d'introduction a déjà été vu. Il ne porte aucune
// identité, ne survit pas à un changement de navigateur, et son absence ne
// coûte qu'un écran de plus — jamais un échec de connexion.
export const SEEN_COOKIE_NAME = '__Host-opsid_seen';
export const SSO_TTL_MS = numEnv('SSO_TTL_MS', 14 * 24 * 3600 * 1000);
export const CODE_TTL_MS = numEnv('CODE_TTL_MS', 60 * 1000);

// How long a code may sit IN_FLIGHT before a later presentation stops
// reading that as "someone else is presenting this right now, so the code
// leaked" and starts reading it as "whatever process claimed this one died
// before it could resolve the row". A genuine resolution completes in
// milliseconds (a couple of local database round trips), so this only needs
// to be comfortably longer than that - not anywhere near CODE_TTL_MS - to
// keep telling the two apart correctly.
export const CODE_RECOVERY_GRACE_MS = numEnv('CODE_RECOVERY_GRACE_MS', 5 * 1000);
export const AUTH_REQUEST_TTL_MS = numEnv('AUTH_REQUEST_TTL_MS', 10 * 60 * 1000);
export const ID_TOKEN_TTL_S = numEnv('ID_TOKEN_TTL_S', 120);

export const KEY_ROTATION_MS = numEnv('KEY_ROTATION_MS', 30 * 24 * 3600 * 1000);
export const KEY_GRACE_MS = numEnv('KEY_GRACE_MS', 3600 * 1000);

if (KEY_ROTATION_MS <= KEY_GRACE_MS) {
  throw new Error(
    `KEY_ROTATION_MS (${KEY_ROTATION_MS}ms) must be larger than KEY_GRACE_MS (${KEY_GRACE_MS}ms)`
  );
}

export const SWEEP_INTERVAL_MS = numEnv('SWEEP_INTERVAL_MS', 10 * 60 * 1000);

// Codes get their own, much shorter sweep cadence. SWEEP_INTERVAL_MS (10
// minutes) is sized for auth_requests, sessions and signing keys - things
// that live for minutes to weeks. A code that is abandoned (browser closed,
// app backend down, user hits back) rather than consumed has no tombstoning
// UPDATE to null its fields early, so it sits there naming an application
// for an account until this sweep deletes the row outright. Riding the
// general sweep's cadence would let that abandoned row outlive its own
// CODE_TTL_MS (60s) by up to ten minutes; this keeps it close to the TTL
// instead.
export const CODE_SWEEP_INTERVAL_MS = numEnv('CODE_SWEEP_INTERVAL_MS', 30 * 1000);

export const GLOBAL_RATE_LIMIT_WINDOW_MS = numEnv('GLOBAL_RATE_LIMIT_WINDOW_MS', 60 * 1000);
export const GLOBAL_RATE_LIMIT_MAX = numEnv('GLOBAL_RATE_LIMIT_MAX', 120);
export const TOKEN_RATE_LIMIT_WINDOW_MS = numEnv('TOKEN_RATE_LIMIT_WINDOW_MS', 60 * 1000);
export const TOKEN_RATE_LIMIT_MAX = numEnv('TOKEN_RATE_LIMIT_MAX', 60);

// ── Language ─────────────────────────────────────────────────────────────
// Set ONLY when someone picks a language on this service. Absent otherwise, so
// a person who never chose keeps following their browser rather than a decision
// made for them once and remembered forever. __Host- for the same reason as the
// two cookies above: no Domain attribute, no sibling subdomain can read it.
export const LOCALE_COOKIE_NAME = '__Host-opsid_lang';
export const LOCALE_COOKIE_MAX_AGE_MS = numEnv('LOCALE_COOKIE_MAX_AGE_MS', 365 * 24 * 3600 * 1000);

// The language served when the request carries no preference at all: no cookie,
// no `ui_locales`, no Accept-Language. That is a robot or a bare `curl`, and the
// service is open to applications anywhere, so English is the useful answer.
// lib/i18n.js falls back to 'en' if this names a locale that does not exist.
export const DEFAULT_LOCALE = process.env.DEFAULT_LOCALE || 'en';

// ── Open client registration (RFC 7591) ──────────────────────────────────
// On by default. This is the point of the service, not a feature flag someone
// forgot to turn off: registration can be open precisely BECAUSE a registered
// client learns a subject that is worthless in every other application. A
// self-hosted deployment that wants a closed instance sets this to `false` and
// keeps scripts/register-client.mjs.
export const REGISTRATION_ENABLED = process.env.REGISTRATION_ENABLED !== 'false';

// Deliberately mean. Registration is unauthenticated and writes a row, so the
// limiter is the only thing standing between an open endpoint and a table
// someone decided to fill. Ten applications an hour from one address is far
// more than an honest developer needs and far less than a script wants.
export const REGISTER_RATE_LIMIT_WINDOW_MS = numEnv('REGISTER_RATE_LIMIT_WINDOW_MS', 3600 * 1000);
export const REGISTER_RATE_LIMIT_MAX = numEnv('REGISTER_RATE_LIMIT_MAX', 10);

// And a second bound that is not keyed on anything at all.
//
// The per-address limiter above is worth nothing on its own against IPv6: a
// residential allocation is a /64, which is 18 quintillion addresses, and the
// limiter sees each one as a new caller. Ten rows per address becomes as many
// rows as the attacker has patience for, and the table is the only thing this
// service cannot rebuild from nothing.
//
// So the endpoint has a ceiling as well as a fence. Two hundred registrations
// an hour ACROSS EVERYONE is far beyond anything this service has ever seen in
// a day, and the failure mode when it is reached is that new applications wait
// - sign-in, tokens and every existing client are untouched, because they do
// not pass through here.
export const REGISTER_GLOBAL_WINDOW_MS = numEnv('REGISTER_GLOBAL_WINDOW_MS', 3600 * 1000);
export const REGISTER_GLOBAL_MAX = numEnv('REGISTER_GLOBAL_MAX', 200);

// Every one of these bounds a row written by an unauthenticated caller. They
// are small on purpose: an application that genuinely needs six redirect URIs
// can register twice, and nothing here should be a place to store data.
export const MAX_CLIENT_NAME_LENGTH = numEnv('MAX_CLIENT_NAME_LENGTH', 64);
export const MAX_REDIRECT_URIS = numEnv('MAX_REDIRECT_URIS', 5);
export const MAX_REDIRECT_URI_LENGTH = numEnv('MAX_REDIRECT_URI_LENGTH', 512);
