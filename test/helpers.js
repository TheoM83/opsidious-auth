import request from 'supertest';
import { app } from '../app.js';
import { createClient } from '../lib/clients.js';

export { app };
export const CALLBACK = 'https://defnote.test/auth/callback';

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
