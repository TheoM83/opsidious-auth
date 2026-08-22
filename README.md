# Opsidious Auth

A small identity provider. Google is the only way in, and **no two
applications using it can tell they share a user** — not even by comparing
their databases.

## Integrating

```bash
npm install github:TheoM83/opsidious-auth
```

npm has no subdirectory support for git dependencies, so there is no install
command that can deliver [`client/`](client/README.md) on its own. The command
above installs this whole package — the service included — and the client is
reached through the subpath the root `package.json` exports.

**Import `opsidious-auth/client`, not `opsidious-auth-client`.**
`opsidious-auth-client` is the name inside `client/package.json`, and it is
what an npm release would be called; after a git install it resolves to
nothing. Pin a tag or a commit SHA — `github:TheoM83/opsidious-auth#v1.0.0` —
in anything you deploy; the bare form above tracks `main`.

The cost of a git dependency, stated rather than left to be discovered: this
pulls the service's own dependency tree with it, `sqlite3`'s native build
included — roughly 21 MB of `node_modules` for a client that is one file and
needs only `jose`. That is npm's limitation rather than a choice, and
publishing `opsidious-auth-client` to npm is what removes it. `express` and
`cookie-parser` you already have; they are peer dependencies, not extra
installs.

The smallest working integration:

```js
import cookieParser from 'cookie-parser';
import { opsidiousAuth } from 'opsidious-auth/client';

app.use(cookieParser()); // required: the client stores its transaction in a cookie

const auth = opsidiousAuth({
  issuer: 'https://auth.opsidious.com',
  clientId: process.env.OPSIDIOUS_CLIENT_ID,
  clientSecret: process.env.OPSIDIOUS_CLIENT_SECRET,
  redirectUri: 'https://yourapp.example/auth/callback'
});

app.get('/auth/start', auth.start());

app.get('/auth/callback', auth.callback(), (req, res) => {
  if (req.opsidious.error) return res.redirect('/?error=' + req.opsidious.error);
  req.opsidious.sub; // stable, opaque, and unique to THIS application
  // create your own session here, then redirect
  res.redirect('/app');
});
```

That is the whole integration: one install and two routes. Everything
`/authorize`, `/callback/google` and `/token` require — `state`, `nonce`,
`iss`/`aud` checks, a pinned signing algorithm, exchanging the code
server-side before ever redirecting — lives inside `auth.start()` and
`auth.callback()`. See [`client/README.md`](client/README.md) for the full
option list, the error shapes you can see in `req.opsidious.error`, and
`internalUrl` for calling the service over a private network instead of the
public internet.

To get a `clientId` / `clientSecret` pair, an operator of this service runs
[`scripts/register-client.mjs`](scripts/register-client.mjs) once — see
[Registering an application](#registering-an-application) below.

## The anonymity design

This is the product, not a footnote.

- **The service is never told an email or a name.** The authorization
  request this service sends to Google carries `scope=openid` and nothing
  else. Google returns a bare subject identifier and nothing more — there is
  no email, name or picture to store, log, discard, or promise to delete,
  because it is never requested in the first place.
- **Every application gets a different, unrelated subject for the same
  person.** `req.opsidious.sub` is *pairwise*: derived from the account and
  the requesting application's `client_id`, and recomputed on every token
  issue rather than stored. Two applications comparing their databases row by
  row cannot tell they share a user, because there is nothing shared between
  the two subjects to find.
- **No table records which applications an account has used — with one
  bounded exception, stated here rather than buried.** The schema has no
  column for it anywhere: `accounts` holds no client, and `codes` holds the
  already-derived `app_sub` rather than an `account_id`
  ([`docs/design.md` §4.2](docs/design.md#42-deliberate-omissions-in-the-schema)).
  The exception is a **live authorization code**. For the sixty seconds it is
  valid, that row carries `client_id` alongside the `sso_session_id` it was
  issued from — and a session row does name an account — so a dump taken in
  that window links that one account to that one application. Two mechanisms
  keep the window to sixty seconds and no longer:
  - the moment a code is consumed or rejected, the same `UPDATE` that marks
    it spent **nulls `app_sub`, `client_id`, `redirect_uri` and `nonce`**,
    leaving a tombstone that can still detect a replay and still revoke a
    session but no longer names an application;
  - a code that is simply abandoned — browser closed, back button, an
    application backend that never exchanges it — has no such `UPDATE` to
    clear it, so a dedicated sweep runs every 30 seconds and deletes it
    outright. Worst case, an abandoned row survives its own 60-second
    lifetime by half a minute.

  A dump therefore reveals, at most, that a handful of sign-ins were in
  flight when it was taken. It does not reveal the history of who signed in
  where, because that history is never written down.

- **The consequence, accepted:** because nothing links an account to an
  application, this service **cannot tell an application whom to erase**. It
  does not know which applications an account has used. The `/account` page
  says so plainly, in these words: delete your data in each application
  first, then delete your Opsidious account last — deleting an Opsidious
  account only means you can no longer sign in anywhere, it does not reach
  into any application's own data. See [Account deletion](#account-deletion).

The full mechanism — the envelope encryption that keeps the per-account
pairwise salt out of the database even in the clear, and the reasoning
behind every decision above — is in [`docs/design.md`](docs/design.md), the
design document this service was built from — and kept current with it since:
where the implementation deliberately diverged from the original design, the
document says so and says why, rather than pretending it was right the first
time. Read it before extending this service or reviewing it as a
security-sensitive dependency; §4 and §4.1 in particular are the whole
anonymity guarantee, stated precisely enough to be tested.

## The security properties, stated rather than left to be reverse-engineered

- **Authorization-code flow, RS256 ID tokens, a published JWKS.** Every
  token is signed with a key rotated automatically; a client verifies against
  `GET /.well-known/jwks.json`, keyed by `kid`.
- **An inert `access_token`, and no `refresh_token`.** There is no resource
  server behind this service, so the access token grants nothing: it is a fresh
  random string, never stored, examined by no endpoint here. It is returned
  because RFC 6749 §5.1 and OIDC Core §3.1.3.3 require it — omitting it was the
  original design, and pointing the reference client (`openid-client`) at this
  issuer failed the exchange outright with `"response" body "access_token"
  property must be a string`. `refresh_token` is optional, so it stays absent:
  there is no long-lived grant to refresh.
- **A `__Host-` prefixed, host-only SSO cookie.** `__Host-opsid_sso` carries
  no `Domain` attribute, so it is never readable by a sibling subdomain —
  the whole subdomain-trust question disappears rather than needing to be
  reasoned about. `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. Its value
  is 32 random bytes; only its hash is stored.
- **`POST /token` has exactly two failure shapes, and each one is
  indistinguishable inside itself.** Every *grant* failure answers
  `400 {"error":"invalid_grant"}` — a code that was wrong, expired, already
  used, never issued, presented with the wrong `redirect_uri`, or issued to a
  different client all produce the identical body, so probing tells a caller
  nothing about which. Every *client-authentication* failure answers
  `401 {"error":"invalid_client"}` — an unknown `client_id`, a wrong secret
  and a missing secret are likewise identical to each other. The two groups are
  deliberately told apart, and that is not a leak: a `client_id` is public by
  design — it rides in every sign-in redirect and sits in every integrator's
  configuration — so concealing whether one exists protects nothing, while
  separating "your credentials are wrong" from "your code is stale" is the
  difference between a five-minute fix and an afternoon of guessing. What
  must never leak is the secret, and nothing here distinguishes a wrong one
  from a missing one. (A `grant_type` other than `authorization_code` is
  refused with `400 unsupported_grant_type` before any code or credential is
  looked at.) `test/token.test.js` pins all of it.
- **Codes are single-use, and a leaked code costs its holder the session.** A
  code is claimed by one guarded `UPDATE` carrying every predicate that
  decides whether this caller may claim it at all — the code hash, the owning
  `client_id`, the exact `redirect_uri`, the expiry, and the row's current
  outcome — and requiring exactly one row changed. Two concurrent exchanges
  cannot both succeed, and another registered client holding a stolen code
  cannot move the row at all, let alone burn it. `used` is not a boolean but
  a four-valued outcome — unused, in flight, consumed, rejected — which is
  what lets the service tell a leak from a mistake. **A code presented again
  after it was successfully consumed, or presented twice at once, deletes the
  SSO session it was issued from**, so a stolen code is worth strictly less
  than nothing to whoever replays it. A code merely *rejected* — expired, or
  the wrong redirect URI — deletes nothing: a mismatch is not evidence of a
  leak, and signing a person out over their own application's
  misconfiguration would be a denial of service with extra steps. A row left
  in flight by a process that died mid-exchange is reclaimed by its own
  owner after five seconds rather than being read as a leak forever.
- **`prompt=login` replaces the session rather than stacking a second one.**
  An application asking for forced re-authentication sends the browser back
  through Google, and the session that browser was already carrying is
  deleted when the new one is created. Otherwise the old cookie value would
  go on working for the rest of its own fourteen days even though the
  browser had already moved on to a new one — which is exactly what
  "re-authenticate" is supposed to prevent.
- Redirect URIs are matched by **exact string equality** against a
  registered allowlist — no prefix, suffix, case-insensitive, or
  query-string-tolerant matching. An invalid `client_id` or `redirect_uri`
  renders an error page and never issues a redirect, because redirecting to
  an unverified URI *is* the open-redirect vulnerability.
- Full security requirement list, numbered so each one is a test: §7 of
  [`docs/design.md`](docs/design.md).

## What is *not* defended

A security document that claims more than it delivers is worse than one
that claims less, so this is stated as plainly as the guarantees above.

**A dump of this database is a total compromise of every application in
front of it, and impersonation is the worst of it — not anonymity.** The
anonymity mechanism is what the rest of this document is about, so it is
worth being blunt that a stolen database file is a bigger problem than
anything the mechanism is designed to resist:

- **It forges tokens.** `signing_keys.private_pem` is a plaintext PEM
  private key, and the matching public key is published at
  `/.well-known/jwks.json` for every application to trust. Whoever holds the
  file can mint an ID token with any `sub` and any `aud` they like, and every
  registered application will verify it and sign that person in. This is
  normal for an identity provider — the signing key has to be reachable by
  the process that signs — but it means "the database leaked" and "every
  account in every application is impersonable" are the same sentence. Rotate
  the keys (delete the `signing_keys` rows; the service mints a fresh one on
  the next sign-in, and every token in flight becomes unverifiable) and treat
  every application's own sessions as compromised.
- **It turns one Google subject into that person's identity everywhere.**
  The `clients` table enumerates every registered application, so an
  adversary holding the dump and one person's Google subject does not
  recover that person's subject in one application — they unwrap the salt
  once and derive it in *all* of them, with one HMAC per registered client.
  There is no "which applications did they use" question left to answer;
  the answer is "all of them, if they used them".
- **Matching Google subjects is a bulk sweep, not a per-person cost.** The
  lookup pepper is in the dump too, in `settings`. Anyone holding a *corpus*
  of candidate Google subjects — from another breach, or from any service
  that stores them — can hash the whole corpus under that pepper and join it
  against `google_sub_hash` in one pass, embarrassingly parallel and with no
  per-account work. The design document's older phrasing, that deanonymising
  someone is "a per-person cost, not a bulk one", is true only of the
  *unwrapping* step; it was never true of finding out which rows are in your
  corpus, and that is corrected in
  [`docs/design.md` §4.3](docs/design.md#43-the-salt-is-never-at-rest-in-the-clear).

  What the dump still does not yield is the reverse direction: a Google
  identifier for an account you did not already have a candidate subject
  for. `google_sub_hash` is an HMAC over Google's 21-digit subject
  identifiers, which is far too large a space to enumerate exhaustively — so
  the hashes can be matched against a list someone already holds, never
  turned back into an identifier on their own.

**Someone holding both an application's database and this service's
database can correlate the two.** The pairwise subject is a deterministic
HMAC of a per-account salt and the application's `client_id`. That
computation is not secret — it has to run on every sign-in — so an adversary
who obtains both the salt (from this database) and the application's stored
subjects (from that database) can recompute the HMAC and prove the two
databases share users. This service's design does not stop that, and
cannot: the alternative would require the subject to not be a deterministic
function of anything, which would break sign-in itself.

Also out of scope, from the design document's own threat model
([`docs/design.md`](docs/design.md#41-threat-model)):

- **The operator of the deployment.** Whoever runs this service can deploy a
  modified build that records whatever it likes. Nothing here defends
  against that, and nothing could — nobody who is the source of the code
  running can be defended against by the code itself. What this design does
  is make the correlating data structurally absent by default, so that
  collecting it requires a deliberate, auditable change rather than reading
  a table that was there all along.
- **Reverse-proxy or CDN access logs.** `GET /callback/google?code=…` carries
  a live Google authorization code in the URL. The application never logs
  it, but a reverse proxy in front will, unless told not to — see
  [Deploying it](#deploying-it) below. This is the gap most likely to be
  missed, because it is correct in the application and wrong one layer
  outside it.

See [`SECURITY.md`](SECURITY.md) for what is and is not in scope for a
vulnerability report, and [`docs/design.md`](docs/design.md) for the full
threat model this was drawn from.

## Running it

```bash
npm install
cp .env.example .env       # fill in the Google credentials
npm run dev
npm test                   # offline: no test touches the network
```

A Google **web application** OAuth client is required, with the redirect URI
set to exactly `{PUBLIC_URL}/callback/google`.

### Required environment variables

| Variable                | Required | Notes                                                                                          |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------------ |
| `PUBLIC_URL`             | yes      | The service's public origin. Used as the `iss` claim, the redirect URI base, and the cookie scope. No default — nothing here is hardcoded to any domain, so self-hosting under another domain needs no code change. |
| `GOOGLE_CLIENT_ID`       | yes      | Google OAuth **web application** client id.                                                     |
| `GOOGLE_CLIENT_SECRET`   | yes      | Google OAuth client secret. A real secret — keep it out of anything committed.                  |
| `ISSUER`                 | no       | Overrides the `iss` claim if it must differ from `PUBLIC_URL`. Defaults to `PUBLIC_URL`.        |
| `DB_PATH`                | no       | Defaults to `./data/opsidious-auth.db`.                                                          |
| `BACKUP_DIR`             | no       | See [Backups](#backups-and-restores) below. With none set, the service runs with **no backups** and logs a warning on boot. |
| `BACKUP_RETENTION_DAYS`  | no       | Defaults to 14.                                                                                  |

The full list, including session/code/key lifetimes and rate limits, is in
[`.env.example`](.env.example). The process refuses to start without
`PUBLIC_URL`, `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` — a
misconfigured deployment fails at boot, not at the first sign-in.

### Registering an application

```bash
npm run register-client -- defnote "Defnote" https://defnote.example/auth/callback
```

**The secret is printed exactly once, to the terminal, and is not
recoverable afterwards** — only its SHA-256 hash is stored. Copy it into the
application's configuration before closing that terminal; there is no
"forgot secret" flow, only re-registering under a new client id.

This script writes directly to whatever database `DB_PATH` (or the running
container's environment) points at. It is **not a dry-run tool and it asks
for no confirmation** — it is one `INSERT`, executed with the same
environment as the server. Running it against a production deployment is
exactly how a production client gets registered, which also means running it
by habit, or against the wrong `.env`, silently creates a real client with a
real secret in a real database. It prints which database it is about to
write to before it writes anything, precisely so that is never a surprise.

It loads the same configuration the server does, so it also refuses to run
without `PUBLIC_URL`, `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, even
though registering a client needs none of them. Run it from a directory with
a `.env`, or inside the container:

```bash
docker exec -it opsidious-auth node scripts/register-client.mjs \
  defnote "Defnote" https://defnote.example/auth/callback
```

Redirect URIs are matched **exactly** — a trailing slash is a different URI
from one without.

### Registering without ever seeing the secret

The command above prints the secret to a terminal, and from there it is copied
by hand into wherever the application keeps its configuration. Every step of
that is a place the value can be left behind: scrollback, a shell history, a
paste buffer, a screenshot.

The **Register a client** workflow does the same registration and never renders
the value. It runs the script in `--secret-only` mode, masks what it captures
before anything else can print it, and hands it to `gh secret set`, which
encrypts it with the target repository's public key before sending. The secret
goes from the server straight into the consuming repository's GitHub secrets
without being displayed to anyone.

Run it from the Actions tab with four inputs — the client id, its name, its
exact redirect URI, and the repository that should receive the secret. It needs
`REGISTRAR_TOKEN`, a token carrying `secrets: write` on that repository;
`GITHUB_TOKEN` deliberately cannot write to another repository, so this stays a
separately-granted capability rather than something the workflow has by default.

Re-running it against an existing client id rotates the secret and overwrites
the stored one.

## Self-hosting

Nothing is hardcoded to any domain: `PUBLIC_URL` decides the issuer, the
redirect URI and the cookie scope. Run it for your own projects.

## Deploying it

The image is built from the [`Dockerfile`](Dockerfile) in this repository:
non-root (`USER node`), `NODE_ENV`, `PORT`, `DB_PATH` and `BACKUP_DIR`
preset, and a `HEALTHCHECK` against `GET /healthz`.

**The image deliberately does not set `PUBLIC_URL`, and the service refuses
to start without it** — nothing here may be hardcoded to a domain, so the
value has to come from the deployment. A compose entry that forgets it does
not start; it crash-loops with `PUBLIC_URL must be set`.

**`/healthz` is a liveness probe and only a liveness probe.** It does no
I/O of any kind — no database, no network — so it answers "the process is
alive" and says nothing whatever about whether the database is healthy. A
database that is broken *at boot* never reaches this check at all: the
process logs a fatal error and exits 1, and the restart policy takes over. A
database that wedges *after* boot is a real gap this check does not close —
every route would 500 while the container went on reporting healthy — and
closing it would mean a database round trip on every probe forever, which
was judged the worse trade. The comment beside the `HEALTHCHECK` explains
why the interval, timeout, start period and retry count are each what they
are.

**The read-only root filesystem is a deployment setting, not a property of
the image.** The image expects it — only `/app/data` and the backup mount
need to be writable — but nothing in the `Dockerfile` can enforce it. The
compose entry must declare `read_only: true`, `no-new-privileges`,
`cap_drop: [ALL]` and a `tmpfs` for `/tmp` itself.

[`.github/workflows/publish-image.yml`](.github/workflows/publish-image.yml)
builds and publishes `ghcr.io/theom83/opsidious-auth` after
[`ci.yml`](.github/workflows/ci.yml) has completed successfully on `main` —
a red suite publishes nothing and deploys nothing — and pins the checkout to
the commit CI actually tested. The repository and the image are both public,
so pulling it needs no `docker login`.

**Turn off proxy access logs for this host, or strip query strings from
them.** `GET /callback/google?code=…` carries a live Google authorization
code. The application never logs it; a reverse proxy in front will, unless
told not to. This is the single easiest thing to overlook in the whole
deployment, because it is correct in the application and wrong one layer
out.

## Backups and restores

This database is the identity of every application in front of it. Losing
it loses every per-account salt, and therefore every user of every
application, permanently and with no recovery path — there is no "reset
password" for an account whose salt is gone.

- A timer runs `VACUUM INTO` daily against `BACKUP_DIR`, producing
  `opsidious-auth-YYYY-MM-DD.db`. `VACUUM INTO` is safe against a live WAL
  database, unlike copying the file, which can capture a torn state that
  will not open.
- 14 days are retained by default (`BACKUP_RETENTION_DAYS`); older files are
  deleted. Both success and failure are logged; a failed backup logs at
  error level so it is visible in ordinary log monitoring.
- **`BACKUP_DIR` must be a host bind mount, not a Docker volume.** A
  `docker volume rm` — run to clean up, or by an unrelated `docker system
  prune`, or by whoever tears down the stack — can take a named volume with
  it. A host directory survives every one of those.

**A restore is:** stop the container, replace the file at `DB_PATH` with one
of the files from `BACKUP_DIR`, start the container again. There is no
migration step and no partial-restore option — a backup file is a complete,
self-contained database at the moment it was taken, including the lookup
pepper and every account's sealed salt, so nothing needs to be regenerated
or re-derived after a restore. A restore rolls back every application's
sign-in state to that moment: any SSO session or authorization code created
after the backup was taken is gone, and affected users simply sign in again
through Google — accounts themselves are unaffected, since `google_sub_hash`
and `sealed_salt` are exactly what was backed up.

## Account deletion

Because no table links an account to the applications it has used (see [The
anonymity design](#the-anonymity-design) above), this service genuinely
cannot tell an application whom to erase. Deletion is therefore two-sided,
and `/account` states it in these terms:

- Deleting an account **in an application** erases everything that
  application holds. This is unchanged by anything here.
- Deleting the **Opsidious account**, on `/account`, means signing in
  nowhere is possible again — it does not, and cannot, reach into any
  application's own data.

The order matters: delete in each application first, then at Opsidious.
Deleting the Opsidious account first only makes the applications' already-
held data permanently unreachable rather than erased.

## Licence

MIT.
