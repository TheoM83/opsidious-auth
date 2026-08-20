import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { join } from 'node:path';
import {
  GLOBAL_RATE_LIMIT_WINDOW_MS,
  GLOBAL_RATE_LIMIT_MAX,
  TOKEN_RATE_LIMIT_WINDOW_MS,
  TOKEN_RATE_LIMIT_MAX
} from './config.js';

// /authorize now redirects straight to Google, so an unbounded rate here makes
// this service an amplifier pointed at Google (spec §7.17).
export const globalLimiter = rateLimit({
  windowMs: GLOBAL_RATE_LIMIT_WINDOW_MS,
  max: GLOBAL_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});

export const tokenLimiter = rateLimit({
  windowMs: TOKEN_RATE_LIMIT_WINDOW_MS,
  max: TOKEN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  // Per client as well as per IP: one misbehaving client must not exhaust the
  // budget for the others. ipKeyGenerator normalises the IP (and collapses an
  // IPv6 /64) so the library's own validation does not reject the key.
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}:${(req.body && req.body.client_id) || '-'}`,
  message: { error: 'too_many_requests' }
});

// The only page besides /account. It names the failure and nothing else - no
// client id, no redirect URI, no query value of any kind (spec §7.3).
export function renderError(res, status, message) {
  res.status(status);
  return new Promise((resolve) => {
    res.render(join(res.app.get('views'), 'error.ejs'), { status, message }, (err, body) => {
      if (err) {
        res.type('text/plain').send(message);
        return resolve();
      }
      res.render(join(res.app.get('views'), 'layout.ejs'), { title: 'Erreur', body }, (e, html) => {
        res.send(e ? message : html);
        resolve();
      });
    });
  });
}
