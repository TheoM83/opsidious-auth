// SQLite access layer: one connection per process, promise wrappers, schema.
// Schema creation is idempotent, so a restart against an existing volume is a
// no-op.
import sqlite3 from 'sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_PATH, DB_BUSY_TIMEOUT_MS } from './config.js';

const here = dirname(fileURLToPath(import.meta.url));
let db = null;

export function getDatabase() {
  return db;
}

// SQLite's busy_timeout does not reliably cover one specific operation:
// switching a brand-new database file into WAL mode for the first time, which
// itself needs a lock to create the `-wal` file. Reproduced directly:
// several processes racing to boot against one fresh database can each get
// an immediate SQLITE_BUSY on `PRAGMA journal_mode = WAL` even with
// busy_timeout already set, rather than the busy handler retrying it the way
// it retries an ordinary write-lock wait. This is a documented SQLite quirk,
// not a bug in this driver, so it needs its own bounded retry rather than
// relying on busy_timeout alone. This only runs once, at boot.
async function withBusyRetry(fn, { attempts = 50, delayMs = 50 } = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (err.code !== 'SQLITE_BUSY' || attempt === attempts) throw err;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  return undefined;
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
     -- Scellée sous la clé maîtresse, qui vit dans l'environnement et jamais
     -- ici. En clair, ce champ suffisait à forger un jeton portant n'importe
     -- quel sujet : mesuré, pas supposé.
     private_pem BLOB NOT NULL,
     pem_kdf_salt BLOB NOT NULL,
     public_jwk  TEXT NOT NULL,
     created_at  INTEGER NOT NULL,
     retires_at  INTEGER NOT NULL,
     expires_at  INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS settings (
     key   TEXT PRIMARY KEY,
     -- Scellé quand la valeur est sensible (le pepper). Le sel de dérivation
     -- accompagne le chiffré ; il n'est pas secret.
     value BLOB NOT NULL,
     kdf_salt BLOB
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

  // Set before anything else touches the connection, deliberately ahead of
  // `PRAGMA journal_mode = WAL` below: switching a brand-new file into WAL
  // mode itself needs a lock to create the `-wal` file, and several
  // processes booting against one fresh database race for exactly that
  // (test/keys-mint-race.test.js reproduced this directly - without the
  // reorder, a losing process's very first PRAGMA could throw SQLITE_BUSY
  // before busy_timeout was ever in effect for it).
  //
  // PRAGMA statements cannot take a bound parameter - `PRAGMA busy_timeout = ?`
  // is a SQLite syntax error, not merely unsupported by this driver - so this
  // is a second, narrow exception to "every SQL statement is parameterised"
  // alongside lib/backup.js's VACUUM INTO. DB_BUSY_TIMEOUT_MS is a validated
  // internal config constant (see lib/config.js's numEnv), never derived from
  // request input, and coerced to an integer here before interpolation, so
  // there is nothing an attacker could put in this string.
  const busyTimeoutMs = Math.max(0, Math.trunc(DB_BUSY_TIMEOUT_MS) || 0);
  await dbRun(`PRAGMA busy_timeout = ${busyTimeoutMs}`);

  await dbRun('PRAGMA foreign_keys = ON');
  if (dbPath !== ':memory:') {
    await withBusyRetry(() => dbRun('PRAGMA journal_mode = WAL'));
  }
  for (const statement of SCHEMA) await dbRun(statement);
  await sealExistingSecrets();
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

// Migration des bases antérieures au scellement.
//
// `CREATE TABLE IF NOT EXISTS` ne touche pas une table déjà là : une base créée
// avant que la clé de signature et le pepper ne soient scellés garde ses
// colonnes d'origine et ses valeurs en clair. Sans cette migration, le service
// démarrerait sans rien dire et échouerait à la PREMIÈRE connexion, quand
// openUnderMaster tenterait d'ouvrir un PEM qui n'a jamais été scellé.
//
// Elle est idempotente : sur une base déjà scellée, elle ne trouve rien à
// faire. Elle est aussi la seule occasion où ces valeurs transitent en clair,
// et c'est inévitable — elles y sont déjà.
async function sealExistingSecrets() {
  const { MASTER_KEY } = await import('./config.js');
  const { INFO_KEYSTORE, INFO_PEPPER, sealUnderMaster } = await import('./crypto.js');

  const hasColumn = async (table, column) => {
    const cols = await dbAll(`PRAGMA table_info(${table})`);
    return cols.some((c) => c.name === column);
  };

  // Les colonnes d'abord : ALTER TABLE ne sait pas ajouter une colonne NOT NULL
  // sans défaut, donc elles sont nullables ici et remplies juste après.
  if (!(await hasColumn('signing_keys', 'pem_kdf_salt'))) {
    await dbRun('ALTER TABLE signing_keys ADD COLUMN pem_kdf_salt BLOB');
  }
  if (!(await hasColumn('settings', 'kdf_salt'))) {
    await dbRun('ALTER TABLE settings ADD COLUMN kdf_salt BLOB');
  }

  const asText = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : String(v ?? ''));

  for (const row of await dbAll('SELECT kid, private_pem FROM signing_keys')) {
    if (!asText(row.private_pem).includes('PRIVATE KEY')) continue;
    const { kdfSalt, blob } = sealUnderMaster(MASTER_KEY, INFO_KEYSTORE, asText(row.private_pem));
    await dbRun('UPDATE signing_keys SET private_pem = ?, pem_kdf_salt = ? WHERE kid = ?', [
      blob,
      kdfSalt,
      row.kid
    ]);
    console.info('migration : clé de signature scellée');
  }

  const pepper = await dbGet('SELECT value, kdf_salt FROM settings WHERE key = ?', [
    'lookup_pepper'
  ]);
  if (pepper && pepper.kdf_salt == null) {
    const { kdfSalt, blob } = sealUnderMaster(MASTER_KEY, INFO_PEPPER, asText(pepper.value));
    await dbRun('UPDATE settings SET value = ?, kdf_salt = ? WHERE key = ?', [
      blob,
      kdfSalt,
      'lookup_pepper'
    ]);
    console.info('migration : pepper scellé');
  }
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
