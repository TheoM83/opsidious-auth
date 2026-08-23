// Builds the Express app with NO side effects: importing this file must not
// open a database, bind a port, or start a timer. server.js owns all of that.
import express from 'express';
import compression from 'compression';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initDatabase } from './lib/database.js';
import { globalLimiter, renderError } from './lib/middleware.js';
import authorizeRoutes from './routes/authorize.js';
import callbackRoutes from './routes/callback.js';
import tokenRoutes from './routes/token.js';
import wellKnownRoutes from './routes/wellknown.js';
import accountRoutes from './routes/account.js';

const here = dirname(fileURLToPath(import.meta.url));

export const app = express();

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', join(here, 'views'));
app.disable('x-powered-by');

// Refuse explicitement les capacités que l'application n'utilise pas. Ne rien
// dire les laisse disponibles : une page compromise pourrait demander la caméra
// ou la position sans que rien ne s'y oppose. Les nommer coûte un en-tête et
// ferme la question.
const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'ambient-light-sensor=()',
  'autoplay=()',
  'battery=()',
  'camera=()',
  'display-capture=()',
  'geolocation=()',
  'gyroscope=()',
  'idle-detection=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'screen-wake-lock=()',
  'serial=()',
  'usb=()',
  'xr-spatial-tracking=()'
].join(', ');

// Le JWKS est relu par chaque application à chaque démarrage, et les pages
// sont du texte très répétitif. Defnote compressait, ce service non.
app.use(compression());

// Refuse explicitement les capacités que l'application n'utilise pas.
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
  next();
});

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

// globalLimiter first: mounted ahead of express.static, static assets were
// unrate-limited - an amplification lever of their own (spec §7.17), the
// same reasoning that already put this limiter ahead of every route below.
app.use(globalLimiter);
// Le bouton de marque et son emblème sont servis par le service lui-même :
// une application les référence par URL plutôt que de recopier des règles CSS
// et un SVG qu'elle devrait ensuite maintenir. Le jour où la marque change,
// elle change partout d'un coup.
//
// Cache long : ce sont des ressources de marque, pas du contenu. Elles sont
// aussi les deux SEULES choses que ce service expose à des origines tierces,
// d'où le CORS explicite et restreint à la lecture.
app.use(
  '/button.css',
  (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    // helmet pose Cross-Origin-Resource-Policy: same-origin sur tout le
    // service, et CORP prime sur CORS pour le CHARGEMENT d'une ressource : sans
    // cette ligne le navigateur bloquerait la feuille et l'emblème malgré
    // l'en-tête ci-dessus. Ces deux fichiers sont les seuls à être relâchés,
    // et ce sont deux ressources de marque publiques.
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    next();
  },
  express.static(join(here, 'client', 'button.css'))
);
app.use(
  '/emblem.svg',
  (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    // helmet pose Cross-Origin-Resource-Policy: same-origin sur tout le
    // service, et CORP prime sur CORS pour le CHARGEMENT d'une ressource : sans
    // cette ligne le navigateur bloquerait la feuille et l'emblème malgré
    // l'en-tête ci-dessus. Ces deux fichiers sont les seuls à être relâchés,
    // et ce sont deux ressources de marque publiques.
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    next();
  },
  express.static(join(here, 'public', 'emblem.svg'))
);

app.use(express.static(join(here, 'public'), { maxAge: '7d' }));

// Route modules are mounted here as later tasks add them:
app.use(authorizeRoutes);
app.use(callbackRoutes);
app.use(tokenRoutes);
app.use(wellKnownRoutes);
app.use(accountRoutes);

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
