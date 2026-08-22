import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';

before(async () => {
  await initForTest();
});
after(async () => {
  await closeDatabase();
});

// Le bouton de marque est destiné à être chargé PAR d'autres origines. Deux
// en-têtes doivent le permettre, et le second est facile à oublier : helmet
// pose Cross-Origin-Resource-Policy: same-origin sur tout le service, et CORP
// prime sur CORS pour le chargement d'une ressource — sans lui, le navigateur
// bloque malgré l'Access-Control-Allow-Origin.
for (const path of ['/button.css', '/emblem.svg']) {
  test(`${path} est chargeable depuis une autre origine`, async () => {
    const res = await request(app).get(path);
    assert.equal(res.status, 200);
    assert.equal(res.headers['access-control-allow-origin'], '*');
    assert.equal(res.headers['cross-origin-resource-policy'], 'cross-origin');
    assert.match(res.headers['cache-control'], /max-age=\d{4,}/);
  });
}

test('rien d’autre n’est relâché', async () => {
  // Le CORS est une exception nommée, pas un réglage global. Une page du
  // service ne doit pas devenir lisible par n'importe quelle origine.
  for (const path of ['/styles.css', '/healthz', '/.well-known/jwks.json']) {
    const res = await request(app).get(path);
    assert.equal(
      res.headers['cross-origin-resource-policy'],
      'same-origin',
      `${path} ne doit pas être relâché`
    );
  }
});
