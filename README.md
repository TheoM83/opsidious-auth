# Opsidious Auth

A small identity provider. Google is the only way in, and **no two
applications using it can tell they share a user** — not even by comparing
their databases.

## Integrating

The smallest working integration, using the client package this repository
ships in [`client/`](client/README.md):

```js
import cookieParser from 'cookie-parser';
import { opsidiousAuth } from 'opsidious-auth-client';

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

That is the whole integration: two routes and one dependency. Everything
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
  the requesting application's `client_id`, recomputed on every token issue,
  and never written to a table. Two applications comparing their databases
  row by row cannot tell they share a user, because there is nothing shared
  between the two subjects to find.
- **No table anywhere links an account to the applications it has used.**
  This is a deliberate omission from the schema, not an oversight — see
  `accounts` and `codes` in [`docs/design.md`](docs/design.md#5-data-model).
  A full dump of this database does not reveal that any two applications
  share a user.
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
design document this service was built from. Read it before extending this
service or reviewing it as a security-sensitive dependency; §4 and §4.1 in
particular are the whole anonymity guarantee, stated precisely enough to be
tested.

## The security properties, stated rather than left to be reverse-engineered

- **Authorization-code flow, RS256 ID tokens, a published JWKS.** Every
  token is signed with a key rotated automatically; a client verifies against
  `GET /.well-known/jwks.json`, keyed by `kid`.
- **No `access_token`, no `refresh_token`.** There is no resource server
  behind this service and nothing to refresh — it issues an ID token and
  nothing else. A strict OIDC client library may object; this service's own
  client will not.
- **A `__Host-` prefixed, host-only SSO cookie.** `__Host-opsid_sso` carries
  no `Domain` attribute, so it is never readable by a sibling subdomain —
  the whole subdomain-trust question disappears rather than needing to be
  reasoned about. `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. Its value
  is 32 random bytes; only its hash is stored.
- **One indistinguishable failure shape for every grant error.** `POST
  /token` answers `{ "error": "invalid_grant" }` whether the code was wrong,
  expired, already used, or never existed, and whether the client
  credentials were wrong or missing — a caller learns nothing by probing.
  The client package mirrors this on the application side for the same
  reason.
- **Codes are single-use, and a replay revokes the session.** An
  authorization code is consumed atomically (`UPDATE … WHERE used = 0`,
  requiring exactly one row changed) so two concurrent exchanges cannot both
  succeed. Presenting an already-used code does not just fail — it deletes
  the SSO session that code was issued from, so a stolen code is worth
  strictly less than nothing to whoever replays it.
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

Redirect URIs are matched **exactly** — a trailing slash is a different URI
from one without.

## Self-hosting

Nothing is hardcoded to any domain: `PUBLIC_URL` decides the issuer, the
redirect URI and the cookie scope. Run it for your own projects.

## Deploying it

The image is built from the [`Dockerfile`](Dockerfile) in this repository:
non-root (`USER node`), a `HEALTHCHECK` against `GET /healthz` (a route
mounted before anything that touches the database, so it can tell "the
process is alive" apart from "the process is alive but the database is
broken" — see the comment beside it in the Dockerfile for why the interval,
timeout, start period and retry count are each what they are), and a
read-only root filesystem in production — only `/app/data` and the backup
mount are writable.

[`.github/workflows/publish-image.yml`](.github/workflows/publish-image.yml)
builds and publishes `ghcr.io/theom83/opsidious-auth` on every push to
`main`. The repository and the image are both public, so pulling it needs no
`docker login`.

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
