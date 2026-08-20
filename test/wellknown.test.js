import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { currentSigner } from '../lib/keys.js';

before(async () => {
  await initForTest();
  await currentSigner();
});
after(async () => {
  await closeDatabase();
});

test('the JWKS is served and cacheable', async () => {
  const res = await request(app).get('/.well-known/jwks.json');
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /application\/json/);
  assert.match(res.headers['cache-control'], /max-age=3600/);
  assert.ok(Array.isArray(res.body.keys) && res.body.keys.length >= 1);
});

test('the JWKS carries only public material', async () => {
  const res = await request(app).get('/.well-known/jwks.json');
  const dump = JSON.stringify(res.body);
  for (const field of ['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', 'PRIVATE KEY']) {
    assert.ok(!dump.includes(field), `${field} must never be published`);
  }
  assert.equal(res.body.keys[0].kty, 'RSA');
  assert.equal(res.body.keys[0].alg, 'RS256');
  assert.ok(res.body.keys[0].kid);
});
