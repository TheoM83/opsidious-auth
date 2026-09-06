// Builds the Express app with NO side effects: importing this file must not
// open a database, bind a port, or start a timer. server.js owns all of that.
import express from 'express';
import compression from 'compression';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initDatabase } from './lib/database.js';
import { globalLimiter, renderError, attachLocale } from './lib/middleware.js';
import { countRequest } from './lib/traffic.js';
import { makeAssetUrl, cacheControlPour, VERSION_PARAM } from './lib/assets.js';
import authorizeRoutes from './routes/authorize.js';
import callbackRoutes from './routes/callback.js';
import tokenRoutes from './routes/token.js';
import wellKnownRoutes from './routes/wellknown.js';
import accountRoutes from './routes/account.js';
import registerRoutes from './routes/register.js';
import langRoutes from './routes/lang.js';

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(here, 'public');

// Écrit dans les gabarits : `asset('/styles.css')` rend `/styles.css?v=<hash>`.
// Un déploiement qui change le fichier change l'adresse, donc l'ancienne
// réponse en cache n'est plus jamais demandée.
const asset = makeAssetUrl(PUBLIC_DIR);

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
    // Deux ans, comme les trois autres propriétés de la plateforme. L'apex
    // envoie `includeSubDomains`, donc il engage déjà ce sous-domaine : dire
    // autre chose ici ne faisait qu'ouvrir la question de qui a raison.
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: false },
    crossOriginEmbedderPolicy: false,
    // `same-origin-allow-popups`, et PAS `same-origin`.
    //
    // C'était `false` : un service d'identité est justement l'origine où une
    // référence `window.opener` qui traîne vaut le plus cher, et c'était la
    // seule des quatre propriétés à n'envoyer aucun COOP.
    //
    // La valeur stricte n'est pas la bonne ici pour autant. Depuis que
    // l'enregistrement est ouvert (RFC 7591), n'importe quelle application peut
    // se connecter comme elle l'entend, y compris en ouvrant /authorize dans une
    // popup - ce que `same-origin` couperait net en cassant son retour. Cette
    // valeur-ci coupe le lien dans le sens qui compte (ce qu'on ouvre) sans
    // casser celui qui nous ouvre.
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
  })
);

// Compté avant tout le reste pour que le chiffre soit celui des requêtes
// REÇUES, pas de celles qui ont survécu au limiteur. Un incrément en mémoire,
// rien d'autre sur le chemin de la requête, et rien de conservé sur l'appelant.
//
// `/healthz` et `/stats` sont exclus : la sonde de la plateforme frappe l'un
// toutes les quinze minutes et la page d'accueil lit l'autre, donc les inclure
// reviendrait surtout à mesurer notre propre supervision.
app.use((req, res, next) => {
  if (req.path === '/healthz' || req.path === '/stats') return next();
  return countRequest(req, res, next);
});

app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// After cookieParser (it reads the language cookie) and ahead of every route
// that can fail, so an error page is rendered in the same language as the page
// the person was asking for.
app.use(attachLocale);

// L'empreinte de la feuille de style, disponible dans tous les gabarits. Elle
// est calculée une fois et mise en cache par lib/assets.js ; ce n'est pas une
// lecture de fichier par requête.
app.use((req, res, next) => {
  res.locals.asset = asset;
  next();
});

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
// Une heure de fraîcheur, puis service périmé pendant la revalidation.
//
// C'était un jour. Ces fichiers portent l'identité visuelle et leur adresse est
// stable par obligation : une application tierce écrit `/button.css` en dur dans
// son HTML, donc l'adresse ne peut pas porter d'empreinte — on ne renomme pas
// une URL que d'autres ont recopiée. Le prix d'un cache long sur une adresse
// stable, c'est qu'un changement de marque met tout ce temps à sortir : la
// bascule du rouge au bleu est restée invisible des heures derrière un
// `cf-cache-status: HIT`, sur le bouton même qui demande de faire confiance.
//
// `stale-while-revalidate` garde le bénéfice — le visiteur est toujours servi
// instantanément depuis le bord — en ramenant la propagation à l'heure.
const BRAND_CACHE = 'public, max-age=3600, stale-while-revalidate=86400';

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
    res.setHeader('Cache-Control', BRAND_CACHE);
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
    res.setHeader('Cache-Control', BRAND_CACHE);
    next();
  },
  express.static(join(here, 'public', 'emblem.svg'))
);

// Le reste de /public, avec le cache décidé par l'empreinte demandée.
//
// C'était `maxAge: '7d'` sur des adresses qui ne changent jamais, et le défaut
// s'est vu en production : le passage du rouge au bleu était servi correctement
// par l'origine et invisible pour quiconque avait visité le service dans la
// semaine. Une adresse portant l'empreinte du contenu ne peut plus servir autre
// chose, donc elle se met en cache pour un an ; une adresse nue revalide.
app.use(
  express.static(PUBLIC_DIR, {
    setHeaders(res, filePath) {
      const urlPath = '/' + relative(join(here, 'public'), filePath).split(sep).join('/');
      res.setHeader('Cache-Control', cacheControlPour(PUBLIC_DIR, urlPath, res.req.query?.[VERSION_PARAM]));
    }
  })
);

// Route modules are mounted here as later tasks add them:
app.use(authorizeRoutes);
app.use(callbackRoutes);
app.use(tokenRoutes);
app.use(wellKnownRoutes);
app.use(accountRoutes);
app.use(registerRoutes);
app.use(langRoutes);

app.use((req, res) => renderError(res, 404, 'errors.notFound'));

// Four arguments, or Express does not treat this as an error handler.
app.use((err, req, res, _next) => {
  // A body this service could not parse is the CALLER's mistake, and it used to
  // be reported as a 500 - the service accusing itself of a fault that was
  // never its own. Registration is the endpoint where this matters: an
  // integrator sending slightly wrong JSON was told the identity provider had
  // broken. body-parser marks these with a `type` and a 4xx status of its own.
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    const status = err.status || 400;
    if (req.path === '/register') {
      return res.status(status).json({
        error: 'invalid_client_metadata',
        error_description: 'the request body could not be read as JSON'
      });
    }
    return renderError(res, status, 'errors.invalidRequest');
  }

  // The message only. A stack in a log is fine; a query string is not.
  console.error('unhandled error:', err.message);
  renderError(res, 500, 'errors.serverError');
});

export async function initForTest() {
  await initDatabase(':memory:');
}
