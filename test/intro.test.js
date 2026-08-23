import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { app, initForTest } from '../app.js';
import { closeDatabase } from '../lib/database.js';
import { SEEN_COOKIE_NAME, SSO_COOKIE_NAME } from '../lib/config.js';
import { signInWithGoogleSub } from '../lib/accounts.js';
import { createSession } from '../lib/sessions.js';
import { registerTestClient, CALLBACK } from './helpers.js';

before(async () => {
  await initForTest();
  await registerTestClient({ id: 'defnote' });
});
after(async () => {
  await closeDatabase();
});

const authorize = () =>
  request(app).get('/authorize').query({
    client_id: 'defnote',
    redirect_uri: CALLBACK,
    response_type: 'code',
    scope: 'openid',
    state: 's1',
    nonce: 'n1'
  });

test('la toute première visite explique le mécanisme avant d’aller chez Google', async () => {
  const res = await authorize();
  assert.equal(res.status, 200, 'un écran, pas une redirection');

  // Le mot « anonyme » ne vaut rien : tous les services l'emploient. L'écran
  // doit dire ce que CHAQUE partie sait, ce qui se vérifie.
  for (const partie of ['Google', 'Opsidious', 'application']) {
    assert.match(res.text, new RegExp(partie), `l’écran doit nommer « ${partie} »`);
  }

  // Une seule action, et elle mène chez Google. Un second choix créerait une
  // hésitation là où il n'y a rien à décider.
  const liens = [...res.text.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
  const versGoogle = liens.filter((h) => h.includes('accounts.google.com'));
  assert.equal(versGoogle.length, 1, `un seul lien vers Google, trouvé : ${versGoogle.length}`);
});

test('l’écran ne s’affiche qu’une fois : il pose son cookie et se retire', async () => {
  const premiere = await authorize();
  const pose = (premiere.headers['set-cookie'] || []).find((c) => c.startsWith(SEEN_COOKIE_NAME));
  assert.ok(pose, 'la première visite doit poser le cookie');

  // Le cookie ne porte aucune identité — seulement « déjà vu ».
  assert.match(pose, /HttpOnly/i);
  assert.match(pose, /;\s*Secure/i);
  assert.doesNotMatch(pose, /Domain=/i);

  const suivante = await authorize().set('Cookie', `${SEEN_COOKIE_NAME}=1`);
  assert.equal(suivante.status, 302, 'les visites suivantes repassent en direct');
  assert.match(suivante.headers.location, /accounts\.google\.com/);
});

test('une session ouverte ne voit jamais cet écran, même sans le cookie', async () => {
  // C'est la propriété qui protège la connexion instantanée : quelqu'un de
  // déjà connecté à Opsidious ne doit rien voir passer, cookie « déjà vu » ou
  // pas. Sinon l'écran coûterait un aller-retour à chaque application.
  const { account, pairwiseSalt } = await signInWithGoogleSub('109384756102938475610');
  const { cookieValue } = await createSession(account.id, pairwiseSalt);

  const res = await authorize().set('Cookie', `${SSO_COOKIE_NAME}=${cookieValue}`);
  assert.equal(res.status, 302);
  const url = new URL(res.headers.location);
  assert.equal(url.origin + url.pathname, CALLBACK, 'retour direct à l’application');
  assert.ok(url.searchParams.get('code'), 'avec un code, sans passer par Google');
});

test('prompt=none n’affiche jamais l’écran', async () => {
  // « silencieusement ou pas du tout » : afficher une page serait exactement
  // ce que ce paramètre interdit.
  const res = await request(app).get('/authorize').query({
    client_id: 'defnote',
    redirect_uri: CALLBACK,
    response_type: 'code',
    scope: 'openid',
    state: 's1',
    prompt: 'none'
  });
  assert.equal(res.status, 302);
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'login_required');
});
