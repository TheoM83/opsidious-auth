// SQLite access layer: one connection per process, promise wrappers, schema.
// Schema creation is idempotent, so a restart against an existing volume is a
// no-op.
import sqlite3 from 'sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_PATH } from './config.js';

const here = dirname(fileURLToPath(import.meta.url));
let db = null;

export function getDatabase() {
  return db;
}

const SCHEMA = [
  // NOTE: there is deliberately no `pairwise_salt` column. The salt is
  // envelope-encrypted into `sealed_salt` under a key derived from the Google
  // subject, which this service never stores. See spec §4.3.
  `CREATE TABLE IF NOT EXISTS accounts (
     id              TEXT PRIMARY KEY,
     google_sub_hash TEXT NOT NULL UNIQUE,
     kdf_salt        BLOB NOT NULL,
     sealed_salt     BLOB NOT NULL,
     created_at      INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS clients (
     id            TEXT PRIMARY KEY,
     name          TEXT NOT NULL,
     secret_hash   TEXT NOT NULL,
     redirect_uris TEXT NOT NULL,
     created_at    INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS auth_requests (
     id           TEXT PRIMARY KEY,
     client_id    TEXT NOT NULL,
     redirect_uri TEXT NOT NULL,
     state        TEXT NOT NULL,
     nonce        TEXT,
     google_nonce TEXT NOT NULL,
     expires_at   INTEGER NOT NULL
   )`,
  // `app_sub`, never `account_id`: this row must not record which application
  // a person is signing in to. See spec §4.2.
  //
  // `app_sub`, `client_id`, `redirect_uri` and `nonce` are nullable, not just
  // NOT-NULL-at-insert: once a code is successfully consumed, `consumeCode`
  // nulls all four in the same UPDATE that marks it spent, so this row cannot
  // go on linking an account (via `sso_session_id` -> `sso_sessions` ->
  // `accounts`) to a named application for the rest of its tombstone
  // lifetime. Only `sso_session_id`, `code_hash`, `used` and `expires_at`
  // need to survive - replay detection and session revocation use exactly
  // those (spec §4.2, §7.5).
  `CREATE TABLE IF NOT EXISTS codes (
     code_hash      TEXT PRIMARY KEY,
     app_sub        TEXT,
     client_id      TEXT,
     redirect_uri   TEXT,
     nonce          TEXT,
     sso_session_id TEXT,
     used           INTEGER NOT NULL DEFAULT 0,
     expires_at     INTEGER NOT NULL,
     created_at     INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS sso_sessions (
     id          TEXT PRIMARY KEY,
     token_hash  TEXT NOT NULL UNIQUE,
     account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
     kdf_salt    BLOB NOT NULL,
     sealed_salt BLOB NOT NULL,
     expires_at  INTEGER NOT NULL,
     created_at  INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS signing_keys (
     kid         TEXT PRIMARY KEY,
     private_pem TEXT NOT NULL,
     public_jwk  TEXT NOT NULL,
     created_at  INTEGER NOT NULL,
     retires_at  INTEGER NOT NULL,
     expires_at  INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS settings (
     key   TEXT PRIMARY KEY,
     value TEXT NOT NULL
   )`,
  'CREATE INDEX IF NOT EXISTS idx_codes_expiry ON codes(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_requests_expiry ON auth_requests(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sso_sessions(expires_at)'
];

export async function initDatabase(path) {
  const dbPath = path || DB_PATH || join(here, '..', 'data', 'opsidious-auth.db');
  if (dbPath !== ':memory:') {
    try {
      mkdirSync(dirname(dbPath), { recursive: true });
    } catch {
      /* already there */
    }
  }

  await new Promise((resolve, reject) => {
    db = new sqlite3.Database(dbPath, (err) => (err ? reject(err) : resolve()));
  });

  await dbRun('PRAGMA foreign_keys = ON');
  if (dbPath !== ':memory:') await dbRun('PRAGMA journal_mode = WAL');
  for (const statement of SCHEMA) await dbRun(statement);
  return db;
}

export async function closeDatabase() {
  if (!db) return;
  const handle = db;
  db = null;
  await new Promise((resolve) => handle.close(() => resolve()));
}

export function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function runCallback(err) {
      if (err) reject(err);
      else resolve({ changes: this.changes, lastID: this.lastID });
    });
  });
}

export function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

export function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows || [])));
  });
}

export async function getSetting(key) {
  const row = await dbGet('SELECT value FROM settings WHERE key = ?', [key]);
  return row ? row.value : undefined;
}

// Write-once. Replacing the lookup pepper would orphan every account in every
// application with no way back, so this never overwrites: it inserts if absent
// and returns whatever is actually stored.
export async function setSettingOnce(key, value) {
  await dbRun('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', [key, value]);
  return getSetting(key);
}
