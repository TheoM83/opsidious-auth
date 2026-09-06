// Ce que ce service publie sur son usage, et ce qu'il ne peut pas publier.
//
// Le point délicat n'est pas le comptage : c'est qu'il reste un COMPTE. Ces
// tests épinglent les deux moitiés — le nombre est juste, et il n'est
// attribuable à personne.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

const { app, initForTest } = await import('../app.js');
const { closeDatabase, dbRun, dbAll } = await import('../lib/database.js');
const { flushTraffic, pruneTraffic, requestsLastDay, requestsByHour, hourOf } = await import(
  '../lib/traffic.js'
);

before(async () => {
  await initForTest();
});

after(async () => {
  await closeDatabase();
});

test('une requête est comptée, une fois écrite', async () => {
  await dbRun('DELETE FROM traffic');

  const avant = await requestsLastDay();
  assert.equal(avant, 0, 'la table vient d’être vidée');

  // Rien n'est écrit avant la vidange : le compteur vit en mémoire pour que le
  // chemin de la requête ne touche pas la base.
  await request(app).get('/.well-known/openid-configuration');
  await request(app).get('/.well-known/openid-configuration');
  assert.equal(await requestsLastDay(), 0, 'une requête ne doit pas écrire elle-même');

  const written = await flushTraffic();
  assert.equal(written, 2);
  assert.equal(await requestsLastDay(), 2);
});

test('la sonde et la page de chiffres ne se comptent pas elles-mêmes', async () => {
  await dbRun('DELETE FROM traffic');
  await flushTraffic(); // vide ce qui traînait

  await request(app).get('/healthz');
  await request(app).get('/stats');
  await request(app).get('/healthz');

  assert.equal(await flushTraffic(), 0, 'la supervision se mesurerait elle-même');
});

test('la table ne retient qu’un compteur par heure, et rien d’autre', async () => {
  const colonnes = await dbAll('PRAGMA table_info(traffic)');
  assert.deepEqual(
    colonnes.map((c) => c.name).sort(),
    ['hour', 'requests'],
    'une colonne de plus ici et le compte devient un journal'
  );
});

test('les chiffres publiés sont des agrégats, et le disent', async () => {
  const res = await request(app).get('/stats');
  assert.equal(res.status, 200);
  assert.match(res.headers['cache-control'], /max-age=\d+/);

  assert.equal(typeof res.body.accounts, 'number');
  assert.equal(typeof res.body.clients, 'number');
  assert.equal(typeof res.body.requests24h, 'number');
  assert.equal(res.body.byHour.length, 24, 'vingt-quatre heures, trous compris');

  // Ce service ne PEUT pas dire qui utilise quoi : rien dans la réponse ne doit
  // laisser croire le contraire.
  const brut = JSON.stringify(res.body);
  for (const interdit of ['defnote', 'tarkov', 'perUser', 'byClient', 'ip']) {
    assert.ok(!brut.toLowerCase().includes(interdit.toLowerCase()), `${interdit} n’a rien à faire ici`);
  }
});

test('les vieilles heures sont purgées', async () => {
  const vieille = hourOf(Date.now()) - 24 * 30;
  await dbRun('INSERT OR REPLACE INTO traffic (hour, requests) VALUES (?, ?)', [vieille, 99]);
  await pruneTraffic();

  const restant = await dbAll('SELECT hour FROM traffic WHERE hour = ?', [vieille]);
  assert.equal(restant.length, 0, 'un mois de compteurs horaires reste un journal');
});

test('une heure sans trafic est un zéro, pas un trou', async () => {
  await dbRun('DELETE FROM traffic');
  await dbRun('INSERT INTO traffic (hour, requests) VALUES (?, ?)', [hourOf(Date.now()), 7]);

  const heures = await requestsByHour();
  assert.equal(heures.length, 24);
  assert.equal(heures[23], 7, 'l’heure courante est la dernière');
  assert.ok(
    heures.slice(0, 23).every((n) => n === 0),
    'un graphique troué se lit comme une donnée manquante'
  );
});
