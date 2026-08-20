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

test('healthz is cheap and always ok', async () => {
  const res = await request(app).get('/healthz');
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'ok');
});

test('the CSP allows no external origin whatsoever', async () => {
  // Spec §7.15. There is no third-party script, style, font or image in this
  // service, and nothing should be able to introduce one unnoticed.
  const csp = (await request(app).get('/healthz')).headers['content-security-policy'];
  assert.match(csp, /default-src 'self'/);
  assert.doesNotMatch(csp, /https?:\/\//, 'no external origin may appear in the policy');
  assert.doesNotMatch(csp, /unsafe-eval/);
});

test('the service can never be framed', async () => {
  // A framed authorization endpoint is the clickjacking primitive.
  const res = await request(app).get('/healthz');
  assert.match(res.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(res.headers['x-frame-options'], 'DENY');
});

test('no referrer ever leaves', async () => {
  const res = await request(app).get('/healthz');
  assert.equal(res.headers['referrer-policy'], 'no-referrer');
});

test('HSTS is set for a year across subdomains', async () => {
  const res = await request(app).get('/healthz');
  assert.match(res.headers['strict-transport-security'], /max-age=31536000/);
  assert.match(res.headers['strict-transport-security'], /includeSubDomains/);
});

test('nosniff is set', async () => {
  assert.equal((await request(app).get('/healthz')).headers['x-content-type-options'], 'nosniff');
});

test('an unknown path renders the error page, not a stack trace', async () => {
  const res = await request(app).get('/definitely-not-a-route');
  assert.equal(res.status, 404);
  assert.match(res.headers['content-type'], /text\/html/);
  assert.doesNotMatch(res.text, /at Object\.|node_modules/);
});

test('the error page never echoes the query string', async () => {
  // Spec §7.3. With no sign-in page left, this is the only reflection risk.
  const res = await request(app).get('/nope?client_id=<script>alert(1)</script>&secret=hunter2');
  assert.ok(!res.text.includes('<script>alert(1)</script>'));
  assert.ok(!res.text.includes('hunter2'));
  assert.ok(!res.text.includes('client_id'));
});
