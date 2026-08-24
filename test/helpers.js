import request from 'supertest';
import { app } from '../app.js';
import { createClient } from '../lib/clients.js';

export { app };
export const CALLBACK = 'https://defnote.test/auth/callback';
// The desktop shape: a loopback URI on a fixed pre-registered port, matched
// exactly like every other redirect URI. 127.0.0.1 rather than localhost,
// which can resolve to ::1 and would then not match this string.
export const LOOPBACK = 'http://127.0.0.1:47821/callback';

export function agentFor() {
  return request.agent(app);
}

// Registers a client and returns it with its plaintext secret, which is only
// ever available at creation.
export async function registerTestClient(over = {}) {
  const id = over.id || `client-${Math.random().toString(36).slice(2, 8)}`;
  return createClient({
    id,
    name: over.name || 'Test client',
    redirectUris: over.redirectUris || [CALLBACK]
  });
}

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
