// Empreinte de contenu pour les fichiers de /public.
//
// Le problème qu'elle résout, et qui a été mesuré ici : `/styles.css` était
// servi avec `Cache-Control: max-age=604800` sous une adresse qui ne change
// JAMAIS. Le jour où l'accent est passé du rouge au bleu, l'origine servait
// bien la nouvelle feuille — et tout navigateur ayant visité le service dans
// les sept jours précédents continuait d'afficher l'ancienne. Mesuré : la même
// URL renvoyait `--brand: #ef4444` sans paramètre et `--brand: #78a9ff` avec,
// `cf-cache-status: HIT`, `Age: 28428`. Un changement de design était donc
// invisible pendant une semaine, sans que rien ne le signale.
//
// C'est la version portée de defnote, où le même défaut existait pour la même
// raison.
//
// La correction est l'inverse exact : l'adresse porte l'empreinte du contenu,
// donc un déploiement CHANGE l'adresse, et l'ancienne réponse en cache n'est
// plus jamais demandée. Ce qui permet, du même coup, de la mettre en cache pour
// de bon — `immutable`, un an — au lieu d'une semaine timide.
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join, normalize } from 'node:path';

// Clé : chemin d'URL. Valeur : { mtimeMs, hash }. Le mtime sert à invalider
// l'entrée en développement, où les fichiers changent sous le processus.
const cache = new Map();

export const VERSION_PARAM = 'v';
const LONGUEUR = 10;

function empreinte(racine, urlPath) {
  // `normalize` puis vérification du préfixe : un `../` dans l'appel ne doit
  // pas pouvoir faire lire un fichier hors de /public. Aucun appelant n'est
  // hostile aujourd'hui — les chemins sont écrits dans les gabarits — mais une
  // fonction qui lit un fichier d'après une chaîne se vérifie une fois pour
  // toutes plutôt qu'à chaque nouvel appel.
  const chemin = normalize(join(racine, urlPath));
  if (!chemin.startsWith(normalize(racine))) return null;

  let stat;
  try {
    stat = statSync(chemin);
  } catch {
    return null;
  }
  if (!stat.isFile()) return null;

  const connu = cache.get(urlPath);
  if (connu && connu.mtimeMs === stat.mtimeMs) return connu.hash;

  const hash = createHash('sha256').update(readFileSync(chemin)).digest('hex').slice(0, LONGUEUR);
  cache.set(urlPath, { mtimeMs: stat.mtimeMs, hash });
  return hash;
}

// Rend l'URL à écrire dans un gabarit. Un fichier introuvable ressort tel quel
// plutôt que de faire échouer le rendu : une page sans empreinte reste une page
// qui s'affiche, et le lien mort se voit immédiatement en console.
export function makeAssetUrl(racine) {
  return function asset(urlPath) {
    const hash = empreinte(racine, urlPath);
    return hash ? `${urlPath}?${VERSION_PARAM}=${hash}` : urlPath;
  };
}

// Décide l'en-tête de cache d'une réponse statique.
//
// Deux régimes, et le choix ne dépend que de l'adresse demandée :
//   - avec l'empreinte courante : le contenu ne peut plus changer sous cette
//     adresse, donc un an et `immutable` — le navigateur ne redemande même pas.
//   - sans, ou avec une empreinte périmée : `no-cache`, c'est-à-dire « garde-la
//     mais revalide toujours ». L'ETag rend la revalidation gratuite quand rien
//     n'a bougé. C'est le régime des adresses nues — /sw.js, /site.webmanifest,
//     les icônes du manifeste — qu'on ne contrôle pas et qui doivent pouvoir
//     changer d'un déploiement à l'autre.
export function cacheControlPour(racine, urlPath, version) {
  if (version && version === empreinte(racine, urlPath)) {
    return 'public, max-age=31536000, immutable';
  }
  return 'no-cache';
}
