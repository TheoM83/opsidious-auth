import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { importPKCS8 } from 'jose';
import { initDatabase, closeDatabase, dbAll } from '../lib/database.js';
import { currentSigner } from '../lib/keys.js';
import { ensurePepper } from '../lib/accounts.js';
import { INFO_KEYSTORE, INFO_PEPPER, openUnderMaster } from '../lib/crypto.js';
import { MASTER_KEY } from '../lib/config.js';

before(async () => {
  await initDatabase(':memory:');
  await ensurePepper();
  await currentSigner();
});
after(async () => {
  await closeDatabase();
});

const asText = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : String(v));

test('un dump de la base ne contient aucune clé utilisable', async () => {
  // Ce test existe parce que le contraire a été DÉMONTRÉ : avec le seul
  // fichier de base, un jeton portant `sub: "JE-SUIS-QUI-JE-VEUX"` a été forgé
  // et accepté contre le JWKS publié. Une sauvegarde égarée suffisait.
  const [key] = await dbAll('SELECT private_pem FROM signing_keys');
  const pem = asText(key.private_pem);

  assert.ok(!pem.includes('PRIVATE KEY'), 'la clé ne doit pas être un PEM en clair');
  await assert.rejects(
    () => importPKCS8(pem, 'RS256'),
    'la valeur stockée ne doit pas être importable telle quelle'
  );
});

test('le pepper non plus', async () => {
  // En clair, il permettait de tester un sujet Google connu contre
  // google_sub_hash — et, le pepper en main, de balayer un corpus entier de
  // sujets d'un coup.
  const [row] = await dbAll("SELECT value FROM settings WHERE key = 'lookup_pepper'");
  assert.doesNotMatch(asText(row.value), /^[A-Za-z0-9_-]{40,}$/);
});

test('la clé maîtresse ouvre, et chaque usage a la sienne', async () => {
  const [key] = await dbAll('SELECT private_pem, pem_kdf_salt FROM signing_keys');

  // Avec la bonne clé et le bon usage : un PEM.
  const pem = openUnderMaster(MASTER_KEY, INFO_KEYSTORE, key.pem_kdf_salt, key.private_pem);
  assert.ok(pem.toString('utf8').includes('PRIVATE KEY'));
  await importPKCS8(pem.toString('utf8'), 'RS256');

  // Avec le mauvais USAGE, la même clé maîtresse n'ouvre rien : compromettre
  // l'accès au pepper ne donne pas les clés de signature.
  assert.throws(
    () => openUnderMaster(MASTER_KEY, INFO_PEPPER, key.pem_kdf_salt, key.private_pem),
    'un info différent ne doit jamais ouvrir'
  );

  // Avec une mauvaise clé maîtresse, rien non plus.
  assert.throws(
    () => openUnderMaster('pas-la-bonne-cle-du-tout', INFO_KEYSTORE, key.pem_kdf_salt, key.private_pem)
  );
});

test('la clé maîtresse n’apparaît nulle part dans la base', async () => {
  // Elle vit dans l'environnement. Si elle atterrissait en base, tout ce
  // travail serait annulé — et ce serait invisible.
  const tables = await dbAll("SELECT name FROM sqlite_master WHERE type = 'table'");
  for (const { name } of tables) {
    const rows = await dbAll(`SELECT * FROM "${name.replace(/"/g, '""')}"`);
    const dump = JSON.stringify(rows, (k, v) => (Buffer.isBuffer(v) ? v.toString('hex') : v));
    assert.ok(!dump.includes(MASTER_KEY), `la clé maîtresse ne doit pas être dans ${name}`);
  }
});
