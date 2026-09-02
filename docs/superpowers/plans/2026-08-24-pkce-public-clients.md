# PKCE / Public Clients Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let opsidious-auth serve public clients — installed desktop, mobile and SPA applications that cannot hold a secret — by adding PKCE (S256) alongside the existing confidential-client flow, changing nothing for clients that exist today.

**Architecture:** Three additive schema columns, one new crypto primitive, and a branch at two route handlers. `/authorize` accepts and parks a `code_challenge`; the code row carries it; `/token` skips secret verification for a client marked public and instead requires a `code_verifier` that `consumeCode` checks against the parked challenge. Confidential clients keep their current path exactly, and may supply PKCE optionally.

**Tech Stack:** Node ≥22, ESM, Express 4, sqlite3, `node:crypto`, `node:test` + supertest.

**Spec:** `C:\Users\theom\Documents\GitHub\sediment\docs\superpowers\specs\2026-08-24-sediment-design.md` §8.2

## Global Constraints

- Node `>=22`, ESM only (`"type": "module"`). No CommonJS, no `require`.
- **No new npm dependencies.** PKCE needs `node:crypto` and nothing else.
- Every SQL statement is parameterised. The only existing exceptions are `PRAGMA busy_timeout` and `VACUUM INTO`; add none.
- Redirect URIs stay matched by **exact string equality**. No prefix matching, no normalisation, no port wildcards — `lib/clients.js:39` states why.
- `plain` as a `code_challenge_method` is **refused**. S256 only.
- Existing confidential clients must keep working unchanged: `is_public` defaults to `0`, challenge columns default to `NULL`.
- Comments match the language already used in the file being edited — this repo mixes English and French per file. Follow the file, not a global rule.
- Tests: `npm test` runs every suite, each in its own process. A single suite runs with `node --test test/<file>.test.js`.
- Run `npm run lint` and `npm run format` before each commit.

---

## File Structure

| File                          | Responsibility                 | Change                                                 |
| ----------------------------- | ------------------------------ | ------------------------------------------------------ |
| `lib/database.js`             | Schema and migration           | Modify — 5 columns, 1 migration                        |
| `lib/crypto.js`               | Pure primitives                | Modify — 3 exported functions                          |
| `lib/clients.js`              | Client records                 | Modify — `isPublic` on create, `isPublicClient` reader |
| `lib/codes.js`                | Authorization codes            | Modify — carry and verify the challenge                |
| `routes/authorize.js`         | Authorization request          | Modify — accept, validate, park the challenge          |
| `routes/callback.js`          | Google return leg              | Modify — carry parked challenge into the code          |
| `routes/token.js`             | Token exchange                 | Modify — public-client branch                          |
| `routes/wellknown.js`         | Discovery document             | Modify — advertise S256 and `none`                     |
| `scripts/register-client.mjs` | Operator registration          | Modify — `--public` flag                               |
| `test/pkce.test.js`           | Primitive tests                | Create                                                 |
| `test/pkce-flow.test.js`      | End-to-end public client tests | Create                                                 |
| `test/helpers.js`             | Test fixtures                  | Modify — public client helper                          |
| `README.md`, `docs/design.md` | Documentation                  | Modify — PKCE is no longer deferred                    |

---

### Task 1: Schema columns and migration

**Files:**

- Modify: `lib/database.js:49-55` (clients table), `lib/database.js:56-64` (auth_requests table), `lib/database.js:76-86` (codes table), `lib/database.js:188-231` (`sealExistingSecrets`)
- Test: `test/pkce-migration.test.js`

**Interfaces:**

- Consumes: nothing.
- Produces: columns `clients.is_public INTEGER NOT NULL DEFAULT 0`, `auth_requests.code_challenge TEXT`, `auth_requests.code_challenge_method TEXT`, `codes.code_challenge TEXT`, `codes.code_challenge_method TEXT`. Exported function `migrateSchema(): Promise<void>`, called from `initDatabase` before `sealExistingSecrets()`.

- [ ] **Step 1: Write the failing test**

Create `test/pkce-migration.test.js`. It builds a database at the pre-PKCE schema, the way `test/migration.test.js` does, and asserts the migration adds the columns without disturbing the rows already there.

```js
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import sqlite3 from 'sqlite3';
import { initDatabase, closeDatabase, dbAll, dbGet } from '../lib/database.js';

let dir;
let file;

// Une base à l'ANCIEN schéma : pas de colonne is_public, pas de challenge.
// C'est la forme exacte de la production d'aujourd'hui, et le seul point de
// départ honnête pour vérifier une migration.
before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'opsid-pkce-'));
  file = join(dir, 'ancienne.db');

  const db = new sqlite3.Database(file);
  const run = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, (e) => (e ? rej(e) : res())));

  await run(`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL,
    secret_hash TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL)`);
  await run(`CREATE TABLE auth_requests (id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL, state TEXT NOT NULL, nonce TEXT, google_nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL)`);
  await run(`CREATE TABLE codes (code_hash TEXT PRIMARY KEY, app_sub TEXT, client_id TEXT,
    redirect_uri TEXT, nonce TEXT, sso_session_id TEXT, used INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`);

  await run('INSERT INTO clients VALUES (?,?,?,?,?)', [
    'defnote',
    'Defnote',
    'un-hash-existant',
    JSON.stringify(['https://defnote.test/auth/callback']),
    Date.now()
  ]);
  await new Promise((r) => db.close(r));
});

after(async () => {
  await closeDatabase();
  rmSync(dir, { recursive: true, force: true });
});

const columns = async (table) => (await dbAll(`PRAGMA table_info(${table})`)).map((c) => c.name);

test('la migration ajoute les colonnes PKCE', async () => {
  await initDatabase(file);

  assert.ok((await columns('clients')).includes('is_public'));
  assert.ok((await columns('auth_requests')).includes('code_challenge'));
  assert.ok((await columns('auth_requests')).includes('code_challenge_method'));
  assert.ok((await columns('codes')).includes('code_challenge'));
  assert.ok((await columns('codes')).includes('code_challenge_method'));
});

test('un client existant reste confidentiel et intact', async () => {
  // Le point qui compte : une base migrée ne doit pas transformer un client
  // confidentiel en client public. Ce serait ouvrir /token sans secret sur une
  // application déjà déployée.
  const row = await dbGet('SELECT * FROM clients WHERE id = ?', ['defnote']);
  assert.equal(row.is_public, 0);
  assert.equal(row.secret_hash, 'un-hash-existant');
  assert.deepEqual(JSON.parse(row.redirect_uris), ['https://defnote.test/auth/callback']);
});

test('relancer la migration ne fait rien', async () => {
  await closeDatabase();
  await initDatabase(file);
  const row = await dbGet('SELECT * FROM clients WHERE id = ?', ['defnote']);
  assert.equal(row.is_public, 0);
  assert.equal((await columns('clients')).filter((c) => c === 'is_public').length, 1);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/pkce-migration.test.js`
Expected: FAIL — `columns('clients')` does not include `is_public`.

- [ ] **Step 3: Add the columns to the schema**

In `lib/database.js`, the `clients` statement becomes:

```js
  `CREATE TABLE IF NOT EXISTS clients (
     id            TEXT PRIMARY KEY,
     name          TEXT NOT NULL,
     secret_hash   TEXT NOT NULL,
     redirect_uris TEXT NOT NULL,
     -- 0 = confidential (a secret, verified at /token), 1 = public (no secret,
     -- PKCE instead). Defaults to 0 so that an existing database migrated by
     -- migrateSchema() below cannot turn a deployed confidential client into
     -- one that /token will accept without credentials.
     is_public     INTEGER NOT NULL DEFAULT 0,
     created_at    INTEGER NOT NULL
   )`,
```

`auth_requests` gains two columns:

```js
  `CREATE TABLE IF NOT EXISTS auth_requests (
     id                    TEXT PRIMARY KEY,
     client_id             TEXT NOT NULL,
     redirect_uri          TEXT NOT NULL,
     state                 TEXT NOT NULL,
     nonce                 TEXT,
     google_nonce          TEXT NOT NULL,
     code_challenge        TEXT,
     code_challenge_method TEXT,
     expires_at            INTEGER NOT NULL
   )`,
```

And `codes` gains the same two, added after `nonce`:

```js
     nonce          TEXT,
     code_challenge TEXT,
     code_challenge_method TEXT,
     sso_session_id TEXT,
```

- [ ] **Step 4: Hoist `hasColumn` and add the migration**

`hasColumn` currently lives inside `sealExistingSecrets` (`lib/database.js:192-195`). Move it to module scope, just above `sealExistingSecrets`, and delete the inner copy:

```js
const hasColumn = async (table, column) => {
  const cols = await dbAll(`PRAGMA table_info(${table})`);
  return cols.some((c) => c.name === column);
};
```

Then add, directly below it:

```js
// `CREATE TABLE IF NOT EXISTS` ne touche pas une table déjà là : une base créée
// avant PKCE garde ses colonnes d'origine. Sans cette migration, /authorize
// échouerait au premier INSERT portant un code_challenge — sur une base de
// production, donc, et seulement à la première connexion d'un client public.
//
// Idempotente : sur une base déjà migrée, elle ne trouve rien à faire.
export async function migrateSchema() {
  // NOT NULL avec DEFAULT est accepté par ALTER TABLE ADD COLUMN sous SQLite ;
  // NOT NULL sans défaut ne l'est pas. Le défaut à 0 est aussi la propriété de
  // sûreté : une base migrée n'a aucun client public tant qu'on n'en crée pas.
  if (!(await hasColumn('clients', 'is_public'))) {
    await dbRun('ALTER TABLE clients ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0');
    console.info('migration : colonne clients.is_public ajoutée');
  }
  for (const table of ['auth_requests', 'codes']) {
    if (!(await hasColumn(table, 'code_challenge'))) {
      await dbRun(`ALTER TABLE ${table} ADD COLUMN code_challenge TEXT`);
    }
    if (!(await hasColumn(table, 'code_challenge_method'))) {
      await dbRun(`ALTER TABLE ${table} ADD COLUMN code_challenge_method TEXT`);
    }
  }
}
```

The table name is interpolated because `ALTER TABLE ?` is a SQLite syntax error, exactly like `PRAGMA busy_timeout = ?`. The value comes from a literal array in this file and never from request input — the same justification `lib/database.js:142-148` already records for the busy-timeout PRAGMA. Note it in a comment.

In `initDatabase`, call it after the schema loop and before sealing (`lib/database.js:156-157`):

```js
for (const statement of SCHEMA) await dbRun(statement);
await migrateSchema();
await sealExistingSecrets();
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test test/pkce-migration.test.js`
Expected: PASS, 3 tests.

- [ ] **Step 6: Run the whole suite to check nothing regressed**

Run: `npm test`
Expected: every suite passes. `test/database.test.js` and `test/migration.test.js` in particular must stay green — they exercise `initDatabase` on both fresh and legacy databases.

- [ ] **Step 7: Commit**

```bash
git add lib/database.js test/pkce-migration.test.js
git commit -m "feat(db): add is_public and code_challenge columns with migration"
```

---

### Task 2: The PKCE primitive

**Files:**

- Modify: `lib/crypto.js` (append after `sha256`, around line 91)
- Test: `test/pkce.test.js`

**Interfaces:**

- Consumes: `safeEqual` from `lib/crypto.js`.
- Produces:
  - `isValidCodeVerifier(verifier: unknown): boolean`
  - `isValidCodeChallenge(challenge: unknown): boolean`
  - `s256Challenge(verifier: string): string` — base64url, 43 chars
  - `verifyCodeVerifier(challenge: string, verifier: unknown): boolean`

- [ ] **Step 1: Write the failing test**

Create `test/pkce.test.js`. The first test is the published RFC 7636 Appendix B vector, which is what makes this implementation verifiably interoperable rather than merely self-consistent.

```js
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/pkce.test.js`
Expected: FAIL — `s256Challenge is not a function`.

- [ ] **Step 3: Implement the primitives**

Append to `lib/crypto.js`, after `sha256`:

```js
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test test/pkce.test.js`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add lib/crypto.js test/pkce.test.js
git commit -m "feat(crypto): add S256 PKCE verifier and challenge primitives"
```

---

### Task 3: Public clients in the client record

**Files:**

- Modify: `lib/clients.js:6-23` (`createClient`), append `isPublicClient`
- Modify: `test/helpers.js:14-21`
- Test: `test/clients.test.js` (append)

**Interfaces:**

- Consumes: `sha256`, `randomToken` from `lib/crypto.js`; `dbRun`, `dbGet` from `lib/database.js`.
- Produces:
  - `createClient({ id, name, redirectUris, isPublic? }): Promise<{ client, secret: string | null }>` — `secret` is `null` when `isPublic` is true.
  - `isPublicClient(client): boolean`
  - `registerTestPublicClient(over?): Promise<{ client, secret: null }>` in `test/helpers.js`

- [ ] **Step 1: Write the failing test**

Append to `test/clients.test.js`:

```js
test('a public client is stored with no usable secret', async () => {
  const { client, secret } = await createClient({
    id: 'sediment',
    name: 'Sediment',
    redirectUris: ['http://127.0.0.1:47821/callback'],
    isPublic: true
  });

  assert.equal(secret, null, 'a public client has no secret to hand back');
  assert.equal(client.is_public, 1);
  assert.equal(isPublicClient(client), true);

  // secret_hash is NOT NULL in the schema, so the row holds something. The
  // property that matters is that no secret anyone could present matches it -
  // including the empty string, which is what a caller sending no secret at
  // all produces at /token.
  assert.ok(client.secret_hash, 'the column is NOT NULL, so it must hold something');
  assert.equal(verifyClientSecret(client, ''), false);
  assert.equal(verifyClientSecret(client, client.secret_hash), false);
});

test('a confidential client is unchanged and is not public', async () => {
  const { client, secret } = await createClient({
    id: 'still-confidential',
    name: 'Confidential',
    redirectUris: ['https://conf.test/cb']
  });
  assert.equal(typeof secret, 'string');
  assert.equal(client.is_public, 0);
  assert.equal(isPublicClient(client), false);
  assert.equal(verifyClientSecret(client, secret), true);
});
```

Add `isPublicClient` and `verifyClientSecret` to that file's existing import from `../lib/clients.js`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/clients.test.js`
Expected: FAIL — `isPublicClient is not a function`.

- [ ] **Step 3: Implement**

Replace `createClient` in `lib/clients.js`:

```js
export async function createClient({ id, name, redirectUris, isPublic = false }) {
  if (!id || !name) throw new Error('a client needs an id and a name');
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    throw new Error('a client needs at least one redirect URI');
  }
  if (await getClient(id)) throw new Error(`client ${id} already exists`);

  // A public client has no secret: an installed application would carry it in
  // its binary on every user's machine, where anyone can read it, and a secret
  // everyone can read authenticates nothing. Its proof is PKCE instead.
  //
  // `secret_hash` is NOT NULL, so the row still holds a hash - of a random
  // value generated here and immediately discarded. Nobody, including the
  // operator running this, ever sees its preimage. That way a future bug that
  // sent a public client down the confidential path would be comparing a
  // presented secret against something no one can produce, rather than against
  // an empty string or a fixed sentinel that an attacker could guess.
  const secret = isPublic ? null : randomToken(32);
  const secretHash = sha256(secret ?? randomToken(32));

  await dbRun(
    'INSERT INTO clients (id, name, secret_hash, redirect_uris, is_public, created_at) VALUES (?,?,?,?,?,?)',
    [id, name, secretHash, JSON.stringify(redirectUris), isPublic ? 1 : 0, Date.now()]
  );
  // The secret is returned exactly once. Only its hash is kept.
  return { client: await getClient(id), secret };
}

// A client that authenticates with nothing at /token, because it cannot hold a
// credential. Read from the column rather than inferred from an absent secret:
// "has no secret" and "is allowed to present none" must be one explicit
// decision made at registration, not something derived at request time.
export function isPublicClient(client) {
  return Boolean(client && client.is_public);
}
```

- [ ] **Step 4: Add the test helper**

Append to `test/helpers.js`:

```js
// A public client: no secret, PKCE instead. Returns the same shape as
// registerTestClient, with `secret` null.
export async function registerTestPublicClient(over = {}) {
  const id = over.id || `public-${Math.random().toString(36).slice(2, 8)}`;
  return createClient({
    id,
    name: over.name || 'Test public client',
    redirectUris: over.redirectUris || [LOOPBACK],
    isPublic: true
  });
}
```

And add the loopback constant next to `CALLBACK`:

```js
// The desktop shape: a loopback URI on a fixed pre-registered port, matched
// exactly like every other redirect URI. 127.0.0.1 rather than localhost,
// which can resolve to ::1 and would then not match this string.
export const LOOPBACK = 'http://127.0.0.1:47821/callback';
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test test/clients.test.js`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/clients.js test/clients.test.js test/helpers.js
git commit -m "feat(clients): register public clients without a secret"
```

---

### Task 4: Codes carry and verify the challenge

**Files:**

- Modify: `lib/codes.js:32-54` (`issueCode`), `lib/codes.js:56-151` (`consumeCode`)
- Test: `test/codes.test.js` (append)

**Interfaces:**

- Consumes: `verifyCodeVerifier` from `lib/crypto.js`.
- Produces:
  - `issueCode({ appSub, clientId, redirectUri, nonce?, ssoSessionId?, codeChallenge?, codeChallengeMethod? }, now?): Promise<string>`
  - `consumeCode(code, { clientId, redirectUri, codeVerifier? }, now?): Promise<{ ok: true, row } | { ok: false, reason: string }>` — new reason value `'pkce_mismatch'`.

- [ ] **Step 1: Write the failing test**

Append to `test/codes.test.js`, following that file's existing import and setup style:

```js
test('a code issued with a challenge needs the matching verifier', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

  const result = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(result.ok, true);
  assert.equal(result.row.app_sub, 'pairwise-abc');
});

test('a wrong verifier is refused AND burns the code', async () => {
  // Burning it is the point. If a failed verification left the code usable,
  // whoever intercepted it could brute-force the verifier one request at a
  // time - which is precisely the attack PKCE exists to stop.
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

  const first = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: 'E'.repeat(43)
  });
  assert.equal(first.ok, false);
  assert.equal(first.reason, 'pkce_mismatch');

  const second = await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  assert.equal(second.ok, false, 'the correct verifier must not rescue a burnt code');
});

test('a missing verifier on a challenged code is refused', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  const result = await consumeCode(code, { clientId: 'defnote', redirectUri: CALLBACK });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'pkce_mismatch');
});

test('a code issued without a challenge still consumes with no verifier', async () => {
  // The confidential path, unchanged. This is the regression guard for every
  // client already deployed.
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    nonce: 'n1'
  });
  const result = await consumeCode(code, { clientId: 'defnote', redirectUri: CALLBACK });
  assert.equal(result.ok, true);
});

test('the tombstone clears the challenge along with everything else', async () => {
  const code = await issueCode({
    appSub: 'pairwise-abc',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });
  await consumeCode(code, {
    clientId: 'defnote',
    redirectUri: CALLBACK,
    codeVerifier: RFC_VERIFIER
  });
  const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [sha256(code)]);
  assert.equal(row.code_challenge, null);
  assert.equal(row.client_id, null);
});
```

Add to that file's imports: `dbGet` from `../lib/database.js`, `sha256` from `../lib/crypto.js`, and the two RFC constants:

```js
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/codes.test.js`
Expected: FAIL — the challenged code consumes successfully with a wrong verifier, because nothing checks it yet.

- [ ] **Step 3: Extend `issueCode`**

In `lib/codes.js`, add the import and change the signature and INSERT:

```js
import { sha256, randomToken, verifyCodeVerifier } from './crypto.js';
```

```js
export async function issueCode(
  {
    appSub,
    clientId,
    redirectUri,
    nonce = null,
    ssoSessionId = null,
    codeChallenge = null,
    codeChallengeMethod = null
  },
  now = Date.now()
) {
  if (!appSub) throw new Error('issueCode: appSub is required');
  if (!clientId) throw new Error('issueCode: clientId is required');
  if (!redirectUri) throw new Error('issueCode: redirectUri is required');

  // No requirement that a challenge be present: a confidential client without
  // PKCE is still the normal case. Whether a challenge is MANDATORY is a
  // property of the client, decided at /authorize where the client record is
  // in hand - not here.
  const code = randomToken(32);
  await dbRun(
    `INSERT INTO codes (code_hash, app_sub, client_id, redirect_uri, nonce, code_challenge,
                        code_challenge_method, sso_session_id, used, expires_at, created_at)
     VALUES (?,?,?,?,?,?,?,?,0,?,?)`,
    [
      sha256(code),
      appSub,
      clientId,
      redirectUri,
      nonce,
      codeChallenge,
      codeChallengeMethod,
      ssoSessionId,
      now + CODE_TTL_MS,
      now
    ]
  );
  return code;
}
```

- [ ] **Step 4: Verify in `consumeCode`**

Change the signature at `lib/codes.js:56`:

```js
export async function consumeCode(code, { clientId, redirectUri, codeVerifier } = {}, now = Date.now()) {
```

Add `code_challenge = NULL` to the existing rejection tombstone (currently `lib/codes.js:128-132`):

```js
await dbRun(
  `UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL,
                        redirect_uri = NULL, code_challenge = NULL
        WHERE code_hash = ? AND used IN (?, ?)`,
  [OUTCOME.REJECTED, hash, OUTCOME.UNUSED, OUTCOME.IN_FLIGHT]
);
```

Then, in the success path, between the `SELECT` at `lib/codes.js:145` and the success `UPDATE` at `146-149`:

```js
const row = await dbGet('SELECT * FROM codes WHERE code_hash = ?', [hash]);

// PKCE, when this code was issued with a challenge.
//
// Checked here, AFTER the guarded UPDATE has already claimed the row, so a
// wrong verifier burns the code exactly like any other misuse by its owner.
// Verifying before claiming would leave the row reusable, and whoever
// intercepted the code could then brute-force the verifier one request at a
// time - the precise attack this mechanism exists to stop.
if (row.code_challenge) {
  if (!verifyCodeVerifier(row.code_challenge, codeVerifier)) {
    await dbRun(
      `UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL,
                          redirect_uri = NULL, code_challenge = NULL
          WHERE code_hash = ? AND used = ?`,
      [OUTCOME.REJECTED, hash, OUTCOME.IN_FLIGHT]
    );
    return { ok: false, reason: 'pkce_mismatch' };
  }
}

await dbRun(
  `UPDATE codes SET used = ?, app_sub = NULL, client_id = NULL, nonce = NULL,
                      redirect_uri = NULL, code_challenge = NULL
      WHERE code_hash = ?`,
  [OUTCOME.SUCCESS, hash]
);
return { ok: true, row };
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node --test test/codes.test.js`
Expected: PASS, including the pre-existing concurrency and replay tests.

- [ ] **Step 6: Commit**

```bash
git add lib/codes.js test/codes.test.js
git commit -m "feat(codes): carry a PKCE challenge and verify the verifier on exchange"
```

---

### Task 5: `/authorize` accepts and parks the challenge

**Files:**

- Modify: `routes/authorize.js:4` (import), `routes/authorize.js:90-107` (validation and the existing-session branch), `routes/authorize.js:116-122` (the parked request)
- Test: `test/authorize.test.js` (append)

**Interfaces:**

- Consumes: `isPublicClient` from `lib/clients.js`; `isValidCodeChallenge` from `lib/crypto.js`; `issueCode` from Task 4.
- Produces: `/authorize` accepts `code_challenge` and `code_challenge_method=S256`, stores both on `auth_requests`, and passes both to `issueCode` on the live-session path.

- [ ] **Step 1: Write the failing test**

Append to `test/authorize.test.js`. It already provides everything needed:
`authorize(over)` at line 27 builds the request with `SEEN_COOKIE_NAME=1` set
and sensible defaults that `over` overrides, and `sessionCookie()` at line 46
returns a `Cookie` header value carrying both the SSO and the seen cookie.

```js
// A public client registered once for this file's PKCE tests.
before(async () => {
  await registerTestPublicClient({ id: 'sediment', redirectUris: [LOOPBACK] });
});

const authorizePublic = (over = {}) => authorize({ client_id: 'sediment', redirect_uri: LOOPBACK, ...over });

const errorOf = (res) => new URL(res.headers.location).searchParams.get('error');

test('a public client must send a code_challenge', async () => {
  const res = await authorizePublic();
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.searchParams.get('error'), 'invalid_request');
  assert.equal(url.searchParams.get('state'), 's1', 'state must ride back with the error');
});

test('plain is refused, even though RFC 7636 allows it', async () => {
  // Supporting `plain` would send the verifier through the same channel that
  // may already be leaking the code. Refusing it is the whole point.
  const res = await authorizePublic({
    code_challenge: RFC_CHALLENGE,
    code_challenge_method: 'plain'
  });
  assert.equal(errorOf(res), 'invalid_request');
});

test('a malformed challenge is refused', async () => {
  const res = await authorizePublic({
    code_challenge: 'too-short',
    code_challenge_method: 'S256'
  });
  assert.equal(errorOf(res), 'invalid_request');
});

test('a challenge without its method is refused', async () => {
  // RFC 7636 defaults a missing method to `plain`, which this service refuses.
  // Guessing S256 on the client's behalf would accept a request whose author
  // may genuinely have meant plain.
  const res = await authorizePublic({ code_challenge: RFC_CHALLENGE });
  assert.equal(errorOf(res), 'invalid_request');
});

test('a confidential client may still omit PKCE entirely', async () => {
  // The regression guard for every client already deployed: no challenge, no
  // error, straight on to Google.
  const res = await authorize();
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /^https:\/\/accounts\.google\.com\//);
});

test('a live session issues a code carrying the challenge', async () => {
  const res = await authorizePublic({
    code_challenge: RFC_CHALLENGE,
    code_challenge_method: 'S256'
  }).set('Cookie', await sessionCookie());

  const code = new URL(res.headers.location).searchParams.get('code');
  assert.ok(code, 'a live session must return a code directly, without going to Google');

  const row = await dbGet('SELECT code_challenge, code_challenge_method FROM codes WHERE code_hash = ?', [
    sha256(code)
  ]);
  assert.equal(row.code_challenge, RFC_CHALLENGE);
  assert.equal(row.code_challenge_method, 'S256');
});
```

Extend this file's existing imports: add `registerTestPublicClient` and
`LOOPBACK` to the `./helpers.js` import at line 10, add `dbGet` to the
`../lib/database.js` import at line 5, add `import { sha256 } from '../lib/crypto.js'`,
and declare the two RFC constants near the top:

```js
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
```

The file already has a `before` hook at line 12; add the public client
registration to it rather than declaring a second one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/authorize.test.js`
Expected: FAIL — the public client without a challenge is accepted.

- [ ] **Step 3: Implement the validation**

In `routes/authorize.js`, extend the import at line 4 and add one for the crypto helper:

```js
import { getClient, redirectAllowed, isPublicClient } from '../lib/clients.js';
import { pairwiseSubject, randomToken, isValidCodeChallenge } from '../lib/crypto.js';
```

Insert this block after the `scope` check (currently ending at line 93), before the session is resolved:

```js
// PKCE (RFC 7636). S256 only - see lib/crypto.js for why `plain` is absent.
const codeChallenge = req.query.code_challenge ? String(req.query.code_challenge) : null;
const codeChallengeMethod = req.query.code_challenge_method ? String(req.query.code_challenge_method) : null;

if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
  return redirectBack(res, redirectUri, { error: 'invalid_request', state });
}
// RFC 7636 §4.3 defaults a missing method to `plain`, which this service
// refuses. Guessing S256 on the client's behalf would silently accept a
// request whose author may genuinely have meant plain, and hand them a
// code their verifier will never open.
if (codeChallenge && !codeChallengeMethod) {
  return redirectBack(res, redirectUri, { error: 'invalid_request', state });
}
if (codeChallenge && !isValidCodeChallenge(codeChallenge)) {
  return redirectBack(res, redirectUri, { error: 'invalid_request', state });
}
// A public client presents no secret at /token, so the challenge is the
// only thing standing between a stolen code and a token. Not optional.
if (isPublicClient(client) && !codeChallenge) {
  console.warn(`authorize rejected: public client ${clientId} sent no code_challenge`);
  return redirectBack(res, redirectUri, { error: 'invalid_request', state });
}
```

- [ ] **Step 4: Carry it into both code paths**

The live-session branch (currently `routes/authorize.js:98-107`):

```js
if (existing) {
  const code = await issueCode({
    appSub: pairwiseSubject(existing.pairwiseSalt, clientId),
    clientId,
    redirectUri,
    nonce,
    ssoSessionId: existing.session.id,
    codeChallenge,
    codeChallengeMethod
  });
  return redirectBack(res, redirectUri, { code, state });
}
```

And the parked request (currently `routes/authorize.js:118-122`):

```js
await dbRun(
  `INSERT INTO auth_requests (id, client_id, redirect_uri, state, nonce, google_nonce,
                                  code_challenge, code_challenge_method, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
  [
    id,
    clientId,
    redirectUri,
    state,
    nonce,
    googleNonce,
    codeChallenge,
    codeChallengeMethod,
    Date.now() + AUTH_REQUEST_TTL_MS
  ]
);
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node --test test/authorize.test.js`
Expected: PASS, existing tests included.

- [ ] **Step 6: Commit**

```bash
git add routes/authorize.js test/authorize.test.js
git commit -m "feat(authorize): accept and park an S256 code challenge"
```

---

### Task 6: The Google return leg carries the challenge

**Files:**

- Modify: `routes/callback.js:81-87`
- Test: `test/callback.test.js` (append)

**Interfaces:**

- Consumes: the `auth_requests` columns from Task 1; `issueCode` from Task 4.
- Produces: a code issued after a full Google round trip carries the challenge that was parked at `/authorize`.

- [ ] **Step 1: Write the failing test**

Append to `test/callback.test.js`. It already has exactly the two helpers this
needs: `startFlow(over)` at line 34 drives `/authorize` and returns the parked
request id, and `completeFlow(requestId)` at line 50 stubs Google's response
and drives `/callback/google`. `over` spreads into the query string, so the
public client and its challenge go straight through.

```js
test('a code minted after the Google round trip keeps the parked challenge', async () => {
  // Without this, PKCE would work only for a user who already had a session -
  // that is, never on a first sign-in, which is the only path a freshly
  // installed desktop application ever takes. The live-session path is covered
  // in test/authorize.test.js; this is the other half.
  const requestId = await startFlow({
    client_id: 'sediment',
    redirect_uri: LOOPBACK,
    code_challenge: RFC_CHALLENGE,
    code_challenge_method: 'S256'
  });

  const res = await completeFlow(requestId);
  const code = new URL(res.headers.location).searchParams.get('code');
  assert.ok(code, 'the round trip must come back with a code');

  const row = await dbGet('SELECT code_challenge, code_challenge_method FROM codes WHERE code_hash = ?', [
    sha256(code)
  ]);
  assert.equal(row.code_challenge, RFC_CHALLENGE);
  assert.equal(row.code_challenge_method, 'S256');
});
```

Extend this file's existing imports: add `registerTestPublicClient` and
`LOOPBACK` to the `./helpers.js` import at line 10, add
`import { sha256 } from '../lib/crypto.js'`, and declare `RFC_CHALLENGE` near
the top. `dbGet` is already imported at line 5. Register the public client in
the existing `before` hook at line 14:

```js
await registerTestPublicClient({ id: 'sediment', redirectUris: [LOOPBACK] });
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/callback.test.js`
Expected: FAIL — `row.code_challenge` is `null`.

- [ ] **Step 3: Implement**

In `routes/callback.js`, the `issueCode` call becomes:

```js
const code = await issueCode({
  appSub: pairwiseSubject(pairwiseSalt, parked.client_id),
  clientId: parked.client_id,
  redirectUri: parked.redirect_uri,
  nonce: parked.nonce,
  ssoSessionId: session.id,
  codeChallenge: parked.code_challenge,
  codeChallengeMethod: parked.code_challenge_method
});
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test test/callback.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add routes/callback.js test/callback.test.js
git commit -m "feat(callback): carry the parked code challenge into the issued code"
```

---

### Task 7: `/token` serves public clients

**Files:**

- Modify: `routes/token.js:2` (import), `routes/token.js:34-40`
- Test: `test/pkce-flow.test.js` (create)

**Interfaces:**

- Consumes: `isPublicClient` from Task 3; `consumeCode` with `codeVerifier` from Task 4.
- Produces: `/token` accepts an exchange from a public client with no `client_secret`, requiring `code_verifier`.

- [ ] **Step 1: Write the failing test**

Create `test/pkce-flow.test.js`:

```js
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { publishedJwks } from '../lib/keys.js';
import { issueCode } from '../lib/codes.js';
import { ISSUER } from '../lib/config.js';
import { registerTestPublicClient, registerTestClient, LOOPBACK, CALLBACK } from './helpers.js';

const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

let confidentialSecret;

before(async () => {
  await initForTest();
  await registerTestPublicClient({ id: 'sediment', redirectUris: [LOOPBACK] });
  ({ secret: confidentialSecret } = await registerTestClient({ id: 'defnote' }));
});
after(async () => {
  await closeDatabase();
});

const publicCode = () =>
  issueCode({
    appSub: 'pairwise-sediment',
    clientId: 'sediment',
    redirectUri: LOOPBACK,
    codeChallenge: RFC_CHALLENGE,
    codeChallengeMethod: 'S256'
  });

const exchange = (body) =>
  request(app)
    .post('/token')
    .type('form')
    .send({
      grant_type: 'authorization_code',
      client_id: 'sediment',
      redirect_uri: LOOPBACK,
      ...body
    });

test('a public client exchanges with a verifier and no secret', async () => {
  const res = await exchange({ code: await publicCode(), code_verifier: RFC_VERIFIER });
  assert.equal(res.status, 200);

  const { payload } = await jwtVerify(res.body.id_token, createLocalJWKSet(await publishedJwks()), {
    issuer: ISSUER,
    audience: 'sediment',
    algorithms: ['RS256']
  });
  assert.equal(payload.sub, 'pairwise-sediment');
});

test('a public client without a verifier is refused', async () => {
  const res = await exchange({ code: await publicCode() });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: 'invalid_grant' });
});

test('a public client with a wrong verifier is refused', async () => {
  const res = await exchange({ code: await publicCode(), code_verifier: 'E'.repeat(43) });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: 'invalid_grant' });
});

test('a failed verifier does not leave the code reusable', async () => {
  const code = await publicCode();
  await exchange({ code, code_verifier: 'E'.repeat(43) });
  const retry = await exchange({ code, code_verifier: RFC_VERIFIER });
  assert.equal(retry.status, 400, 'the correct verifier must not rescue a burnt code');
});

test('an unknown client is still refused the same way as before', async () => {
  const res = await exchange({
    code: await publicCode(),
    client_id: 'nobody',
    code_verifier: RFC_VERIFIER
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_client');
});

test('a secret sent by a public client changes nothing', async () => {
  // There is no secret on record to compare against. Answering differently
  // for a present and an absent secret would tell a caller which kind of
  // client an id names, which is not theirs to learn.
  const res = await exchange({
    code: await publicCode(),
    code_verifier: RFC_VERIFIER,
    client_secret: 'anything-at-all'
  });
  assert.equal(res.status, 200);
});

test('a confidential client still requires its secret', async () => {
  // The regression guard for everything already deployed.
  const code = await issueCode({
    appSub: 'pairwise-defnote',
    clientId: 'defnote',
    redirectUri: CALLBACK,
    nonce: 'n1'
  });
  const withoutSecret = await request(app).post('/token').type('form').send({
    grant_type: 'authorization_code',
    client_id: 'defnote',
    redirect_uri: CALLBACK,
    code
  });
  assert.equal(withoutSecret.status, 401);
  assert.equal(withoutSecret.body.error, 'invalid_client');

  const withSecret = await request(app).post('/token').type('form').send({
    grant_type: 'authorization_code',
    client_id: 'defnote',
    client_secret: confidentialSecret,
    redirect_uri: CALLBACK,
    code
  });
  assert.equal(withSecret.status, 200);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/pkce-flow.test.js`
Expected: FAIL — the public exchange answers 401, because `verifyClientSecret` is still unconditional.

- [ ] **Step 3: Implement**

In `routes/token.js`, extend the import at line 2:

```js
import { getClient, verifyClientSecret, isPublicClient } from '../lib/clients.js';
```

Replace the credential block (`routes/token.js:34-40`):

```js
const client = await getClient(clientId);
if (!client) {
  console.warn(`token rejected: unknown client ${clientId || '(none)'}`);
  return res.status(401).json({ error: 'invalid_client' });
}

// A public client authenticates with nothing - that is what public means.
// Its proof is the code_verifier, checked inside consumeCode against the
// challenge the authorization request carried.
//
// A secret sent by a public client is ignored rather than rejected: there
// is no secret on record to compare it to, and answering differently for a
// present and an absent one would tell a caller which kind of client an id
// names. That is the same reasoning as the uniform invalid_client shape
// above, applied one level in.
if (!isPublicClient(client) && !verifyClientSecret(client, String(body.client_secret ?? ''))) {
  console.warn(`token rejected: bad client credentials for ${clientId || '(none)'}`);
  return res.status(401).json({ error: 'invalid_client' });
}

const result = await consumeCode(String(body.code ?? ''), {
  clientId,
  redirectUri,
  // Absent is a value here: consumeCode refuses a challenged code with no
  // verifier, and that must stay a grant failure rather than becoming a
  // separate, distinguishable error.
  codeVerifier: body.code_verifier == null ? null : String(body.code_verifier)
});
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test test/pkce-flow.test.js && node --test test/token.test.js`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add routes/token.js test/pkce-flow.test.js
git commit -m "feat(token): exchange without a secret for public clients"
```

---

### Task 8: Discovery advertises what the service now does

**Files:**

- Modify: `routes/wellknown.js:8-41`
- Test: `test/wellknown-discovery.test.js` (append)

**Interfaces:**

- Consumes: nothing.
- Produces: `code_challenge_methods_supported: ["S256"]` and `token_endpoint_auth_methods_supported: ["client_secret_post", "none"]` in the discovery document.

- [ ] **Step 1: Write the failing test**

Append to `test/wellknown-discovery.test.js`:

```js
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/wellknown-discovery.test.js`
Expected: FAIL — `code_challenge_methods_supported` is `undefined`.

- [ ] **Step 3: Implement**

In `routes/wellknown.js`, replace the paragraph of the comment block that explains PKCE's absence (lines 18-20) with:

```js
// `code_challenge_methods_supported` lists S256 and only S256. §1 called PKCE
// out of scope because every client was a confidential server-side one, and
// §14 recorded the condition that would end that: "needed the day a public
// client (mobile, SPA) appears". A desktop application is that day - it cannot
// hold a secret, because the secret would ship inside a binary on every user's
// machine. `plain` stays absent: it sends the verifier through the same
// channel that may already be leaking the code.
```

Add both fields to `DISCOVERY`:

```js
  token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
  code_challenge_methods_supported: ['S256'],
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test test/wellknown-discovery.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add routes/wellknown.js test/wellknown-discovery.test.js
git commit -m "feat(discovery): advertise S256 and none"
```

---

### Task 9: Registering a public client

**Files:**

- Modify: `scripts/register-client.mjs:21-63`

**Interfaces:**

- Consumes: `createClient({ isPublic })` from Task 3.
- Produces: `npm run register-client -- --public <id> <name> <redirect_uri...>` registers a client with no secret.

- [ ] **Step 1: Add the flag**

Replace the argument parsing (`scripts/register-client.mjs:26-35`):

```js
const argv = process.argv.slice(2);
const secretOnly = argv.includes('--secret-only');
// A public client cannot hold a secret: an installed application would carry
// it in its binary on every user's machine. It proves itself with PKCE.
const isPublic = argv.includes('--public');
const [id, name, ...redirectUris] = argv.filter((a) => a !== '--secret-only' && a !== '--public');

if (!id || !name || redirectUris.length === 0) {
  console.error(
    'usage: npm run register-client -- [--secret-only] [--public] <client_id> <name> <redirect_uri> [redirect_uri...]'
  );
  process.exit(1);
}

if (isPublic && secretOnly) {
  console.error('--public and --secret-only are contradictory: a public client has no secret');
  process.exit(1);
}
```

- [ ] **Step 2: Branch the output**

Replace the body of the `try` block after `createClient`:

```js
const { secret } = await createClient({ id, name, redirectUris, isPublic });

if (isPublic) {
  console.log('');
  console.log(`  client_id      ${id}`);
  console.log('  client_secret  (none - this is a public client)');
  console.log('');
  console.log('  It authenticates with PKCE instead: /authorize will REQUIRE a');
  console.log('  code_challenge with code_challenge_method=S256, and /token will require');
  console.log('  the matching code_verifier. A request without one is refused.');
  console.log(`  Redirect URIs are matched EXACTLY - a trailing slash is a different URI:`);
  for (const uri of redirectUris) console.log(`    ${uri}`);
  console.log('');
  await closeDatabase();
  process.exit(0);
}

if (secretOnly) {
  console.error(`registered ${id} with ${redirectUris.length} redirect URI(s)`);
  process.stdout.write(secret);
  await closeDatabase();
  process.exit(0);
}
```

Leave the existing confidential-client output below unchanged.

- [ ] **Step 3: Verify by hand against a scratch database**

This repository is developed on Windows, where `VAR=value cmd` is not valid
shell syntax — PowerShell has no inline environment-variable prefix. Set it
first:

```powershell
$env:DB_PATH = './data/scratch.db'
node scripts/register-client.mjs --public sediment "Sediment" http://127.0.0.1:47821/callback http://127.0.0.1:47822/callback http://127.0.0.1:47823/callback
```

Expected: the three URIs are echoed, and the output says `(none - this is a
public client)` where a secret would be. Then confirm the row:

```powershell
node -e "import('./lib/database.js').then(async d=>{await d.initDatabase('./data/scratch.db');console.log(await d.dbGet('SELECT id,is_public,redirect_uris FROM clients WHERE id=?',['sediment']));await d.closeDatabase()})"
```

Expected: `is_public: 1` and all three URIs present. Then clean up, so a scratch
database never becomes a real one by being left where the next command looks:

```powershell
Remove-Item ./data/scratch.db, ./data/scratch.db-wal, ./data/scratch.db-shm -ErrorAction SilentlyContinue
$env:DB_PATH = $null
```

- [ ] **Step 4: Commit**

```bash
git add scripts/register-client.mjs
git commit -m "feat(register): --public registers a client with no secret"
```

---

### Task 10: Documentation catches up with the code

**Files:**

- Modify: `docs/design.md:56-63` (the "out of scope" entry), `docs/design.md:1152` (the deferred list), `README.md`

**Interfaces:** none.

- [ ] **Step 1: Correct the out-of-scope entry**

`docs/design.md:58-63` currently states PKCE is out of scope. It is now in. Replace that bullet with:

```markdown
- **PKCE.** ~~Out of scope~~ — implemented for public clients on 2026-08-24. The
  original reasoning held while every Opsidious app was a confidential
  server-side client exchanging the code from its own backend with a secret.
  An installed desktop application cannot do that: the secret would ship inside
  a binary on every user's machine. Public clients now register with
  `--public`, are REQUIRED to send a `code_challenge` with
  `code_challenge_method=S256` at `/authorize`, and present a `code_verifier`
  instead of a secret at `/token`. `plain` is refused. Confidential clients are
  unchanged and may use PKCE optionally. The addition was additive, exactly as
  this section predicted.
```

- [ ] **Step 2: Correct the deferred list**

`docs/design.md:1152` reads _"**PKCE** — needed the day a public client (mobile, SPA) appears."_ Replace with:

```markdown
- ~~**PKCE**~~ — that day came: Sediment, an installed desktop application.
  Implemented 2026-08-24, S256 only. See §1.
```

- [ ] **Step 3: Document it in the README**

Add a section after the existing integration example:

````markdown
### Public clients

A desktop, mobile or single-page application cannot hold a `clientSecret` — it
would ship inside something every user can read, and a secret everyone can read
authenticates nothing. Those register as **public clients** and prove
themselves with PKCE instead:

```bash
npm run register-client -- --public sediment "Sediment" http://127.0.0.1:47821/callback
```
````

A public client MUST send `code_challenge` with `code_challenge_method=S256` to
`/authorize`, and the matching `code_verifier` to `/token`. It sends no
`client_secret`. `plain` is refused: it would send the verifier through the same
channel that may already be leaking the code.

Native applications must use the **system browser**, never an embedded web view
— RFC 8252 §8.12. An application that owns the control the password is typed
into can read it, which defeats the entire delegation. Register a loopback
redirect URI on a fixed port; URIs are matched by exact string equality, so
`127.0.0.1` and `localhost` are different URIs and every port must be
registered.

`opsidious-auth/client` remains a confidential-client library and is unchanged.
A public client implements the flow directly against `/authorize` and `/token`,
using the discovery document at `/.well-known/openid-configuration`.

````

- [ ] **Step 4: Run everything**

Run: `npm run lint && npm run format && npm test`
Expected: lint clean, no formatting diff left uncommitted, every suite green.

- [ ] **Step 5: Commit**

```bash
git add docs/design.md README.md
git commit -m "docs: PKCE is implemented, not deferred"
````

---

## Verification

After Task 10, the following must all hold. Check them rather than assuming.

1. `npm test` — every suite green, including the ten pre-existing ones that never mention PKCE.
2. A database created before this change opens, migrates, and its clients still authenticate with their secrets (`test/pkce-migration.test.js`).
3. `s256Challenge` reproduces the RFC 7636 Appendix B vector (`test/pkce.test.js`).
4. A public client cannot obtain a token without a verifier, and a wrong verifier burns the code (`test/pkce-flow.test.js`).
5. A confidential client cannot obtain a token without its secret (`test/pkce-flow.test.js`).
6. The discovery document advertises `S256` and never `plain`.

## Out of scope for this plan

- Any change to `client/index.js`. It is a confidential-client library; a public client implements the flow directly.
- Relaxing exact redirect-URI matching, including RFC 8252 §7.3's suggestion that loopback ports be treated as variable. Ports are pre-registered instead. Revisit only with its own design note.
- Refresh tokens, `access_token` with meaning, `userinfo`, back-channel logout.
- Everything in the Sediment client itself — that is M1 onward.
