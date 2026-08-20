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

export const DB_PATH = process.env.DB_PATH || '';
export const BACKUP_DIR = process.env.BACKUP_DIR || '';
export const BACKUP_RETENTION_DAYS = numEnv('BACKUP_RETENTION_DAYS', 14);
export const BACKUP_INTERVAL_MS = numEnv('BACKUP_INTERVAL_MS', 24 * 3600 * 1000);

// __Host- forbids a Domain attribute, which is exactly what we want: the
// cookie must never be readable by a sibling subdomain (spec §2).
export const SSO_COOKIE_NAME = '__Host-opsid_sso';
export const SSO_TTL_MS = numEnv('SSO_TTL_MS', 14 * 24 * 3600 * 1000);
export const CODE_TTL_MS = numEnv('CODE_TTL_MS', 60 * 1000);
export const AUTH_REQUEST_TTL_MS = numEnv('AUTH_REQUEST_TTL_MS', 10 * 60 * 1000);
export const ID_TOKEN_TTL_S = numEnv('ID_TOKEN_TTL_S', 120);

export const KEY_ROTATION_MS = numEnv('KEY_ROTATION_MS', 30 * 24 * 3600 * 1000);
export const KEY_GRACE_MS = numEnv('KEY_GRACE_MS', 3600 * 1000);
export const SWEEP_INTERVAL_MS = numEnv('SWEEP_INTERVAL_MS', 10 * 60 * 1000);

export const GLOBAL_RATE_LIMIT_WINDOW_MS = numEnv('GLOBAL_RATE_LIMIT_WINDOW_MS', 60 * 1000);
export const GLOBAL_RATE_LIMIT_MAX = numEnv('GLOBAL_RATE_LIMIT_MAX', 120);
export const TOKEN_RATE_LIMIT_WINDOW_MS = numEnv('TOKEN_RATE_LIMIT_WINDOW_MS', 60 * 1000);
export const TOKEN_RATE_LIMIT_MAX = numEnv('TOKEN_RATE_LIMIT_MAX', 60);
