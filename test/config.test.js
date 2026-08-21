import { test } from 'node:test';
import assert from 'node:assert/strict';

// config.js validates at import time, so each scenario needs a fresh module
// registry. A cache-busting query string gives us that without a subprocess.
async function loadConfig(env) {
  const previous = { ...process.env };
  Object.assign(process.env, env);
  try {
    return await import(`../lib/config.js?t=${Math.random()}`);
  } finally {
    for (const key of Object.keys(process.env)) delete process.env[key];
    Object.assign(process.env, previous);
  }
}

const MINIMUM = {
  NODE_ENV: 'test',
  PUBLIC_URL: 'http://localhost:4570',
  GOOGLE_CLIENT_ID: 'gid',
  GOOGLE_CLIENT_SECRET: 'gsecret'
};

test('numEnv honours an explicit zero', async () => {
  const cfg = await loadConfig({ ...MINIMUM, CODE_TTL_MS: '0' });
  assert.equal(cfg.CODE_TTL_MS, 0);
});

test('the issuer defaults to the public URL', async () => {
  const cfg = await loadConfig(MINIMUM);
  assert.equal(cfg.ISSUER, 'http://localhost:4570');
});

test('a trailing slash on PUBLIC_URL is removed', async () => {
  // Otherwise the redirect URI becomes .../callback/google with a double slash
  // and Google rejects it as unregistered.
  const cfg = await loadConfig({ ...MINIMUM, PUBLIC_URL: 'https://auth.example.com/' });
  assert.equal(cfg.PUBLIC_URL, 'https://auth.example.com');
  assert.equal(cfg.ISSUER, 'https://auth.example.com');
});

test('the process refuses to start without the Google credentials', async () => {
  await assert.rejects(() => loadConfig({ ...MINIMUM, GOOGLE_CLIENT_ID: '' }), /GOOGLE_CLIENT_ID/);
  await assert.rejects(() => loadConfig({ ...MINIMUM, GOOGLE_CLIENT_SECRET: '' }), /GOOGLE_CLIENT_SECRET/);
});

test('the process refuses to start without a public URL', async () => {
  await assert.rejects(() => loadConfig({ ...MINIMUM, PUBLIC_URL: '' }), /PUBLIC_URL/);
});

test('nothing is hardcoded to a domain', async () => {
  const cfg = await loadConfig({ ...MINIMUM, PUBLIC_URL: 'https://id.somewhere-else.test' });
  assert.equal(cfg.ISSUER, 'https://id.somewhere-else.test');
  assert.doesNotMatch(JSON.stringify(cfg.PUBLIC_URL), /opsidious/i);
});

test('the SSO cookie carries the __Host- prefix', async () => {
  const cfg = await loadConfig(MINIMUM);
  assert.match(cfg.SSO_COOKIE_NAME, /^__Host-/);
});

test('KEY_ROTATION_MS must be larger than KEY_GRACE_MS', async () => {
  await assert.rejects(
    () => loadConfig({ ...MINIMUM, KEY_ROTATION_MS: '3600000', KEY_GRACE_MS: '3600000' }),
    /KEY_ROTATION_MS.*must be larger than KEY_GRACE_MS/
  );
  await assert.rejects(
    () => loadConfig({ ...MINIMUM, KEY_ROTATION_MS: '1800000', KEY_GRACE_MS: '3600000' }),
    /KEY_ROTATION_MS.*must be larger than KEY_GRACE_MS/
  );
});
