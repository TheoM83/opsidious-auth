// Builds the Express app with NO side effects: importing this file must not
// open a database, bind a port, or start a timer. server.js owns all of that.
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initDatabase } from './lib/database.js';
import { globalLimiter, renderError } from './lib/middleware.js';

const here = dirname(fileURLToPath(import.meta.url));

export const app = express();

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', join(here, 'views'));
app.disable('x-powered-by');

app.use(
  helmet({
    // No external origin of any kind. There is no third-party script in this
    // service - Google is reached by redirecting the browser, never by loading
    // its SDK (spec §7.15).
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        // An identity provider must never be framable.
        frameAncestors: ["'none'"]
      }
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false
  })
);

app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// Registered before anything else so a broken database still reports the
// process as alive.
app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

app.use(express.static(join(here, 'public'), { maxAge: '7d' }));
app.use(globalLimiter);

// Route modules are mounted here as later tasks add them:
//   app.use(authorizeRoutes);   <- Task 10
//   app.use(callbackRoutes);    <- Task 11
//   app.use(tokenRoutes);       <- Task 12
//   app.use(wellKnownRoutes);   <- Task 13
//   app.use(accountRoutes);     <- Task 13

app.use((req, res) => renderError(res, 404, 'Page introuvable.'));

// Four arguments, or Express does not treat this as an error handler.
app.use((err, req, res, _next) => {
  // The message only. A stack in a log is fine; a query string is not.
  console.error('unhandled error:', err.message);
  renderError(res, 500, 'Erreur du service.');
});

export async function initForTest() {
  await initDatabase(':memory:');
}
