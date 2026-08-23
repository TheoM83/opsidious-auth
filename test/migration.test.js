import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import sqlite3 from 'sqlite3';
import { generateKeyPair, exportPKCS8, exportJWK } from 'jose';
import { initDatabase, closeDatabase, dbAll } from '../lib/database.js';
import { currentSigner } from '../lib/keys.js';
import { ensurePepper } from '../lib/accounts.js';

let dir;
let file;
const PEPPER = 'pepper-de-production-en-clair';

// Fabrique une base à l'ANCIEN schéma : colonnes d'origine, valeurs en clair.
// C'est exactement ce que contenait la production avant le scellement, et le
// seul moyen honnête de vérifier une migration est de lui donner la vraie
// forme de départ.
before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'opsid-mig-'));
  file = join(dir, 'ancienne.db');

  const db = new sqlite3.Database(file);
  const run = (sql, p = []) =>
    new Promise((res, rej) => db.run(sql, p, (e) => (e ? rej(e) : res())));

  await run(`CREATE TABLE signing_keys (kid TEXT PRIMARY KEY, private_pem TEXT NOT NULL,
    public_jwk TEXT NOT NULL, created_at INTEGER NOT NULL, retires_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL)`);
  await run('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');

  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  jwk.kid = 'kid-ancien';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const now = Date.now();
  await run('INSERT INTO signing_keys VALUES (?,?,?,?,?,?)', [
    'kid-ancien',
    await exportPKCS8(privateKey),
    JSON.stringify(jwk),
    now,
    now + 30 * 86400000,
    now + 31 * 86400000
  ]);
  await run('INSERT INTO settings VALUES (?,?)', ['lookup_pepper', PEPPER]);
  await new Promise((r) => db.close(r));
});

after(async () => {
  await closeDatabase();
  rmSync(dir, { recursive: true, force: true });
});

const asText = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : String(v));

test('ouvrir une base d’avant le scellement la scelle, sans rien perdre', async () => {
  await initDatabase(file);

  const [key] = await dbAll('SELECT kid, private_pem FROM signing_keys');
  assert.ok(!asText(key.private_pem).includes('PRIVATE KEY'), 'la clé doit être scellée');

  // Le point qui compte : la clé d'ORIGINE est conservée, pas remplacée. Une
  // migration qui en frapperait une nouvelle invaliderait tous les jetons déjà
  // émis, et le ferait sans rien dire.
  assert.equal(key.kid, 'kid-ancien');
  const signer = await currentSigner();
  assert.equal(signer.kid, 'kid-ancien');
  assert.ok(signer.privateKey, 'la clé scellée doit se rouvrir et servir à signer');

  // Le pepper aussi : une valeur différente orphelinerait tous les comptes,
  // puisque google_sub_hash est calculé avec.
  assert.equal(await ensurePepper(), PEPPER, 'le pepper doit rendre exactement la même valeur');
});

test('relancer sur une base déjà scellée ne fait rien', async () => {
  // Une migration qui rescellerait à chaque démarrage produirait un chiffré
  // différent à chaque fois — inoffensif ici, mais le signe qu'elle ne sait pas
  // reconnaître son propre travail.
  const [avant] = await dbAll('SELECT private_pem, pem_kdf_salt FROM signing_keys');
  await closeDatabase();
  await initDatabase(file);
  const [apres] = await dbAll('SELECT private_pem, pem_kdf_salt FROM signing_keys');

  assert.deepEqual(Buffer.from(apres.private_pem), Buffer.from(avant.private_pem));
  assert.deepEqual(Buffer.from(apres.pem_kdf_salt), Buffer.from(avant.pem_kdf_salt));
  assert.equal(await ensurePepper(), PEPPER);
});
