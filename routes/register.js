// Open client registration — RFC 7591 §3.
//
// No authentication, no operator, no account. An application posts what it is
// called and where to send people back, and gets credentials in the response.
//
// This is the endpoint that makes the service distributed rather than a private
// door for three applications, and it is safe for exactly one reason, stated in
// lib/registration.js: the subject a client receives is derived from its own
// client_id, so registering buys nothing that transfers anywhere else.
//
// What is deliberately NOT here:
//
//   * RFC 7592 client management. There is no registration_access_token, no
//     GET/PUT/DELETE on a client. Managing a client would mean holding
//     something that identifies its owner, and this service holds nothing
//     about anybody — including developers. A client whose redirect URI
//     changes registers again; the old row keeps working for nobody.
//   * `client_secret_expires_at` anything but 0. Rotating a secret is
//     management, and there is none.
//   * Any echo of the caller. No IP, no User-Agent, no timestamp finer than
//     the row's own created_at.

import { Router } from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { createClient } from '../lib/clients.js';
import { validateRegistration } from '../lib/registration.js';
import { randomToken } from '../lib/crypto.js';
import {
  REGISTRATION_ENABLED,
  REGISTER_RATE_LIMIT_WINDOW_MS,
  REGISTER_RATE_LIMIT_MAX
} from '../lib/config.js';

const router = Router();

// Its own limiter, far tighter than the global one: this is the only
// unauthenticated endpoint that writes a durable row.
const registerLimiter = rateLimit({
  windowMs: REGISTER_RATE_LIMIT_WINDOW_MS,
  limit: REGISTER_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req.ip),
  message: { error: 'too_many_requests' }
});

const fail = (res, status, error, description) =>
  res.status(status).json({ error, error_description: description });

router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    // A registration response carries a secret exactly once. Nothing may keep
    // a copy of it, including a proxy that thought this looked cacheable.
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    if (!REGISTRATION_ENABLED) {
      // A closed instance says so plainly rather than 404ing: the discovery
      // document is what a client reads, and it omits registration_endpoint
      // when this is off, so anyone arriving here anyway deserves the reason.
      return fail(res, 403, 'access_denied', 'this deployment does not accept open registration');
    }

    const checked = validateRegistration(req.body);
    if (!checked.ok) return fail(res, 400, checked.error, checked.description);

    const { name, redirectUris, isPublic, authMethod } = checked.metadata;

    // The caller does not choose its own client_id. A chosen id could be
    // `defnote`, and an id that looks like somebody else's is the one piece of
    // this exchange that could mislead a human reading a URL.
    const id = randomToken(16);
    const { secret } = await createClient({ id, name, redirectUris, isPublic });

    // Never the name, never the URIs: a log line is a place a caller-supplied
    // string could end up being read as trustworthy later.
    console.info(`client registered (public=${isPublic})`);

    return res.status(201).json({
      client_id: id,
      // RFC 7591 §3.2.1: omitted entirely for a public client, rather than sent
      // as null or "". A client library that tests for the field's presence and
      // one that tests its truthiness then agree.
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: authMethod,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      // Stated in the response so it is impossible to integrate without having
      // been told: this is the whole of what an application gets about a person.
      subject_type: 'pairwise'
    });
  } catch (err) {
    next(err);
  }
});

export default router;
