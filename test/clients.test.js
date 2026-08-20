import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbGet } from '../lib/database.js';
import { createClient, getClient, verifyClientSecret, redirectAllowed } from '../lib/clients.js';

const CALLBACK = 'https://defnote.opsidious.com/auth/callback';

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

test('creating a client returns a secret that is never stored in the clear', async () => {
  const { client, secret } = await createClient({
    id: 'defnote',
    name: 'Defnote',
    redirectUris: [CALLBACK]
  });
  assert.equal(client.id, 'defnote');
  assert.ok(secret.length >= 32);

  const row = await dbGet('SELECT secret_hash FROM clients WHERE id = ?', ['defnote']);
  assert.ok(!row.secret_hash.includes(secret));
  assert.match(row.secret_hash, /^[0-9a-f]{64}$/);
});

test('the right secret verifies and a wrong one does not', async () => {
  const { client, secret } = await createClient({
    id: 'verifier',
    name: 'V',
    redirectUris: [CALLBACK]
  });
  assert.equal(verifyClientSecret(client, secret), true);
  assert.equal(verifyClientSecret(client, secret + 'x'), false);
  assert.equal(verifyClientSecret(client, ''), false);
  assert.equal(verifyClientSecret(client, 'short'), false);
});

test('a duplicate client id is refused', async () => {
  await createClient({ id: 'dupe', name: 'D', redirectUris: [CALLBACK] });
  await assert.rejects(() => createClient({ id: 'dupe', name: 'D', redirectUris: [CALLBACK] }));
});

test('a client with no redirect URI is refused', async () => {
  await assert.rejects(() => createClient({ id: 'empty', name: 'E', redirectUris: [] }));
});

test('an exact redirect URI is allowed', async () => {
  const { client } = await createClient({ id: 'exact', name: 'E', redirectUris: [CALLBACK] });
  assert.equal(redirectAllowed(client, CALLBACK), true);
});

test('near misses are all refused', async () => {
  // The classic hole in a hand-rolled OAuth provider. Each of these has been a
  // real vulnerability in a real provider.
  const { client } = await createClient({ id: 'strict', name: 'S', redirectUris: [CALLBACK] });
  for (const uri of [
    CALLBACK + '/',
    CALLBACK + '?next=x',
    CALLBACK + '#frag',
    CALLBACK.replace('https', 'http'),
    CALLBACK.toUpperCase(),
    CALLBACK.replace('/auth/callback', '/auth/callback/../callback'),
    CALLBACK.replace('defnote.opsidious.com', 'defnote.opsidious.com.evil.test'),
    'https://evil.test/auth/callback',
    ''
  ]) {
    assert.equal(redirectAllowed(client, uri), false, `must refuse: ${uri}`);
  }
});

test('a client may register several redirect URIs', async () => {
  const local = 'http://localhost:4567/auth/callback';
  const { client } = await createClient({
    id: 'multi',
    name: 'M',
    redirectUris: [CALLBACK, local]
  });
  assert.equal(redirectAllowed(client, CALLBACK), true);
  assert.equal(redirectAllowed(client, local), true);
  assert.equal(redirectAllowed(client, 'https://other.test/cb'), false);
});

test('an unknown client is undefined, not an error', async () => {
  assert.equal(await getClient('nobody'), undefined);
});
