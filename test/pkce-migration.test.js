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
