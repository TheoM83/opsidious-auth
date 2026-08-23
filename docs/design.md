# Opsidious Auth — Design

**Status:** approved 2026-08-20; **implemented, and this document has been
brought back into line with what was actually delivered.**

It was written before the code existed and, until this pass, had not been
touched since — still byte-identical to the approved spec, and therefore
wrong in several places that mattered, while
[`README.md`](../README.md) went on telling readers to treat it as
authoritative before extending or auditing the service. It is now maintained
as a description of the delivered system, not a record of what was once
intended. **Where the implementation deliberately diverged from the original
design, the divergence is marked `[diverged]` and states its reason in
place**; that history is worth more to a reader than a document pretending it
was right the first time. Anything unmarked describes the code as it stands.

The divergences, gathered here so nobody has to hunt for them:

| What changed | Where | Why |
|---|---|---|
| `codes.app_sub`, `client_id`, `redirect_uri` and `nonce` became nullable, and are nulled the instant a code is resolved | §4.2, §5 | A live code row links an account to a named application through its `sso_session_id`. Tombstoning closes that window as soon as the code is spent; the original `NOT NULL` made it impossible. This is the single most important anonymity refinement made during implementation, and the original design missed it. |
| `codes.used` became a four-valued outcome rather than a boolean | §5, §6, §7.4, §7.5 | A code *rejected* for a mismatch is not evidence of a leak and must not revoke the session, while a genuine replay must. One bit cannot tell those apart. |
| `auth_requests.client_id` carries no foreign key | §5 | Not delivered as specified; the consequence was checked rather than assumed, and is bounded. See the note in §5. |
| `BASE_URL` became `PUBLIC_URL`, with no default | §7.19, §10 | Nothing may be hardcoded to a domain (§13), so the value has to come from the deployment and its absence has to be fatal. §10's prerequisite list omitted it entirely, which made a compose entry built from that section crash-loop on first boot. |
| Codes are swept on their own, much shorter cadence | §7.20 | An *abandoned* code has no resolution to tombstone it, so it names an application until it is deleted. Riding the ten-minute sweep let a 60-second row survive for eleven minutes. |
| A code left in flight by a crashed process is recovered, not read as a leak forever | §5, §7.5 | A process dying between claiming a code and resolving it used to leave a row indistinguishable from a live concurrent exchange. |
| Ownership is enforced inside the guarded `UPDATE` | §6, §7.4, §7.6 | A client that does not own a code can no longer move its row at all, rather than being rejected after the fact. |
| `prompt=login` revokes the session it re-authenticates past | §6 | Otherwise the cookie the browser had already abandoned kept working for the rest of its own fourteen days. |
| `/healthz` is a liveness probe and nothing more | §6 | Stated explicitly because an earlier comment claimed it could also tell a broken database apart, which it cannot. |
| The client is **installed** as `opsidious-auth` and **imported** as `opsidious-auth/client` | §3.2 | npm has no subdirectory support for git dependencies, so the distribution this design assumed could never deliver `client/`. Following the old instruction produced a package that did not resolve. |
| `POST /token` has two failure shapes, not one | §6 | Grant failures and client-authentication failures are deliberately distinguishable from each other, and indistinguishable within themselves. A `client_id` is public by design, so hiding whether one exists protects nothing. |
| The threat model states impersonation and bulk matching, not only linkage | §4, §4.1, §4.3 | A dump yields the plaintext signing key and therefore token forgery against every registered application — categorically worse than the anonymity questions this document was mostly about, and previously absent from it. |

**Goal:** one identity provider for every Opsidious project. Google is the only
sign-in method, the service learns nothing about a person beyond an opaque
Google subject id, and no two Opsidious apps can tell they are looking at the
same human.

**First consumer:** Defnote. It is not yet deployed and has zero accounts, so
its auth can be replaced now at no migration cost.

---

## 1. Scope

**In scope**

- A standalone service at `auth.opsidious.com`: OAuth 2.0 authorization-code
  flow, RS256 ID tokens, published JWKS.
- Silent re-authentication across Opsidious apps via a session held by the auth
  service itself.
- Per-application pairwise subject identifiers.
- Replacing Defnote's direct Google integration with this service.
- A client package that makes integrating a three-line job (§3.2).
- Automated database backups.
- A sign-in that costs one click and no interstitial page (§9.1).

**Out of scope (and why)**

- **PKCE.** Every Opsidious app is a confidential server-side client that
  exchanges the code from its own backend using a secret. `state`, a 60-second
  single-use code, and exact `redirect_uri` matching cover the threat. Adding
  PKCE later is additive and breaks nothing.
- **Refresh tokens and access tokens.** There is no Opsidious API to call on a
  user's behalf. The service issues an ID token and nothing else.
- **Full OIDC discovery, `userinfo`, dynamic registration.** This design is a
  strict subset of OIDC; growing into the full thing later is additive.
- **Back-channel logout.** Signing out of one app does not sign you out of the
  others. See §11.
- **Any sign-in method other than Google.**

---

## 2. Decisions and their reasons

Each of these was a real fork. Recording the reason so the next reader does not
re-open it.

| Decision | Reason |
|---|---|
| Central service, not a shared library | One Google OAuth client for all projects. A new app never touches the Google console again. |
| Pairwise subject per app | Two apps comparing their databases row by row must not be able to tell they share a user. This is the strong reading of "anonymous". |
| Silent SSO | Expected of a single brand. Costs nothing extra given the service is visited directly during `/authorize`. |
| Host-only SSO cookie, `__Host-` prefix | A `.opsidious.com` cookie is readable by every subdomain; one compromised subdomain would hand over every session. The browser visits `auth.opsidious.com` directly, so a host-only cookie is sufficient — the whole subdomain trust boundary disappears. |
| Per-account pairwise salt | A single global pepper would be one secret whose leak compromises every account's derivation, unrotatably. A per-account salt bounds the blast radius to one account. |
| Rotating signing keys with `kid` | A single permanent signing key cannot be replaced after a suspected leak. |
| Google `openid` scope only | We do not merely decline to store the email — we never request it. The strongest form of the guarantee is not having the data. |
| Server-side redirect to Google, not the JS SDK | No third-party script anywhere in the system. Both the auth service and Defnote get a CSP with zero external origins. |
| ID token lifetime of 120 s | It is used once, immediately, to establish the app's own session. |
| SSO session of 14 days, absolute | An identity-provider session is a higher-value bearer token than an app session. Not sliding, so a stolen cookie cannot be kept alive indefinitely by using it. |
| `jose`, no `google-auth-library` | §3.1. Dependency surface is a security property here. |
| Access logging off at the proxy | §7.28. The one hole that lives outside the application. |
| Salt envelope-encrypted, never at rest in the clear | §4.3. Without it, a database dump links every application to every other. Validated by spike before being specified. |
| No interstitial sign-in page | Google is the only method; a page offering one choice is friction and an extra attack surface. |
| A client package rather than integration docs | §3.2. It turns six client-side security requirements into one dependency. |
| Public repository | §13. An identity provider nobody can inspect is one nobody can audit. |

---

## 3. Architecture

```
Defnote                     auth.opsidious.com                    Google
   |                                |                                |
   |-- 302 /authorize ------------->|                                |
   |   client_id, redirect_uri,     |                                |
   |   state, nonce                 |                                |
   |                                |                                |
   |                    valid __Host-opsid_sso cookie? ------- yes --.
   |                                | no                             |
   |                                |-- 302 accounts.google.com ---->|
   |                                |   response_type=code           |
   |                                |   scope=openid                 |
   |                                |   state, nonce                 |
   |                                |<-- 302 /callback/google -------|
   |                                |   verify id_token              |
   |                                |   upsert account by sub hash   |
   |                                |   create SSO session           |
   |                                |                                |
   |<-- 302 redirect_uri -----------'                                |
   |    ?code=…&state=…             |                                |
   |                                |                                |
   |== POST /token ================>|  server to server, no browser  |
   |   code, client_id,             |                                |
   |   client_secret, redirect_uri  |                                |
   |<== { id_token } ===============|                                |
   |                                |                                |
   | verify RS256 against cached    |                                |
   | /.well-known/jwks.json         |                                |
   | sub = this app's own id        |                                |
   | -> create the app's session    |                                |
```

The service is a Node/Express/SQLite container in the same mould as Defnote:
`app.js` with no side effects, `server.js` owning them, `lib/` for the domain,
`routes/` for HTTP, EJS for the two pages it renders.

### 3.1 Dependencies

For an identity provider the dependency list is a security property, so it is
specified rather than left to whatever seems handy:

```
express  ejs  sqlite3  jose  helmet  cookie-parser  express-rate-limit
```

Two deliberate differences from Defnote:

- **`jose` instead of `jsonwebtoken`.** It is the maintained JOSE
  implementation, and it covers all four things this service needs in one
  audited package: generating and exporting our RS256 key pair, signing, and
  `createRemoteJWKSet` for verifying Google's tokens with caching and key
  rotation handled correctly. Hand-rolling remote JWKS fetching is exactly the
  kind of code that is subtly wrong for a year.
- **No `google-auth-library`.** The two calls we make to Google — the token
  exchange and the JWKS verification — are a `fetch` and a `jose` call. Pulling
  a large SDK to make one POST is dependency surface for nothing.

`compression` and `uuid` are not needed: the responses are redirects and small
JSON, and `crypto.randomUUID` is built in.

### 3.2 The client package

Integrating must take three lines, not thirty. The repository ships
`client/`, a package with `jose` as its only dependency:

```js
import { opsidiousAuth } from 'opsidious-auth/client';

const auth = opsidiousAuth({
  issuer:       'https://auth.opsidious.com',
  clientId:     process.env.OPSIDIOUS_CLIENT_ID,
  clientSecret: process.env.OPSIDIOUS_CLIENT_SECRET,
  redirectUri:  'https://defnote.opsidious.com/auth/callback',
  internalUrl:  process.env.OPSIDIOUS_AUTH_INTERNAL_URL   // optional, see §10
});

app.get('/auth/start', auth.start());
app.get('/auth/callback', auth.callback(), (req, res) => {
  req.opsidious.sub;   // verified pairwise subject — create your own session
  res.redirect('/app');
});
```

**This is a security decision as much as a convenience one.** Every requirement
in §7.2 — `state`, `nonce`, `iss`, `aud`, pinned `RS256`, redirect-after-exchange —
lives inside `auth.start()` and `auth.callback()`. Six things each application
would otherwise have to remember correctly become one dependency that either
works or does not. An application that hand-rolls the flow instead must
implement §7.2 itself, and the README says so plainly.

`auth.start()` accepts `{ silent: true }`, which sends `prompt=none` and calls
`next()` with `req.opsidious.error = 'login_required'` when there is no session
to reuse — the primitive behind §9's instant cross-app sign-in.

**Distribution `[diverged]`.** The plan was to consume this package from the
public repository by URL (`github:TheoM83/opsidious-auth#<tag>`) until it is
published to npm. That works — but not the way the design assumed, and the
assumption was wrong in a way that made the documented integration path fail
outright until it was fixed:

- **npm has no subdirectory support for git dependencies.** No install
  command delivers `client/` on its own.
  `npm install github:TheoM83/opsidious-auth` installs the *root* package —
  the service, `sqlite3` and all — and nothing named `opsidious-auth-client` appears
  in the consumer's `node_modules`. `require.resolve('opsidious-auth-client')`
  fails after following the instructions, which is as broken as an
  integration path gets.
- **The root package therefore exports the client as a subpath.**
  `package.json` maps `./client` onto `client/index.js`, so the specifier
  that actually resolves after a git install is **`opsidious-auth/client`**.
  `opsidious-auth-client` remains the name in `client/package.json` and is
  what an npm release would be called.
- **The cost is real and is documented rather than hidden**: a git dependency
  brings the whole service's tree with it, roughly 21 MB of `node_modules`
  including `sqlite3`'s native build, for a client that is one file needing
  only `jose`. Publishing to npm under its own name is what removes it, and
  is the reason to do so beyond convenience.

Both forms work in a Docker build; the URL form avoids blocking the first
release on an npm account.

---

## 4. The anonymity guarantee

This is the property the whole design exists to provide, stated precisely so it
can be tested:

> A full dump of the auth database links nothing. It cannot tell that two
> applications share a user, and it cannot tell which Google account
> corresponds to any activity. Deanonymising one person additionally requires
> that person's Google subject identifier, obtained from somewhere else.

An earlier draft of this design only claimed unlinkability *without* the auth
database — meaning a dump of it linked every app to every other. That was too
weak, and §4.3 is how it was fixed.

Two things that statement does **not** say, both of which matter more than
anything it does say, and both of which are easy to read into it by accident:

- **It is a statement about linkage, not about integrity.** A dump does not
  link accounts to applications; it *does* hand over `signing_keys.private_pem`
  and therefore the ability to mint an ID token for any subject and any
  audience. A database compromise is a total impersonation compromise of
  every registered application. That is normal for an identity provider and
  it is stated at length in §4.1 and in the README, because a reader who
  takes "a full dump links nothing" as reassurance about a stolen database
  file has been misled by this document.
- **"Links nothing" holds for the history, not for the sixty seconds a
  sign-in is in flight.** A live authorization code row carries a `client_id`
  next to the `sso_session_id` it was issued from, and a session names an
  account — so a dump taken at that instant links that one account to that
  one application. §4.2 and §5 describe the two mechanisms that bound this to
  sixty seconds: tombstoning on resolution, and a 30-second sweep for codes
  nobody ever comes back for.

It is enforced by four things.

**Derivation, not storage.**

```js
app_sub = base64url(hmacSha256(pairwise_salt, client_id))
```

`pairwise_salt` is 32 random bytes generated when the account is created. The
result is computed on every token issue rather than stored, and **no table
maps an account to the applications it has used**.

`[diverged]` — "never written down" was the original wording and it was not
quite true: `app_sub` is written onto the authorization code row, because the
code is what carries it from `/authorize` to `/token`. It lives there for at
most the code's sixty seconds, and the `UPDATE` that resolves the code nulls
it in the same statement (§4.2). Nothing keeps it after that, but "never
written down" overstated a design that does write it down, briefly, by
necessity.

**Nothing else is collected.** The Google authorization request carries
`scope=openid` and nothing more, so Google returns only `sub`. There is no
email, name or picture to leak, discard, or accidentally log.

**The Google subject is stored hashed.**

```js
google_sub_hash = hmacSha256(settings.lookup_pepper, google_sub)
```

Login has to find an existing account from a Google subject, so this one lookup
must be deterministic and therefore needs a service-wide pepper. A database
leak still yields no usable Google identifiers.

### 4.3 The salt is never at rest in the clear

The three mechanisms above still left `pairwise_salt` sitting in the accounts
table. Anyone holding a dump could compute every application's subject for
every account, and therefore prove that two apps share users — without needing
a single Google identifier. That is the weakness this section removes.

**The salt is envelope-encrypted under keys the service never retains.**

Two copies exist, wrapped differently, because two code paths need it and each
holds a different short-lived secret:

| Copy | Wrapping key | Held by the server only during |
|---|---|---|
| `accounts.sealed_salt` | `HKDF(google_sub, accounts.kdf_salt, "opsidious-pairwise-v1")` | a live Google sign-in |
| `sso_sessions.sealed_salt` | `HKDF(cookie_value, sessions.kdf_salt, "opsidious-session-v1")` | a request carrying the SSO cookie |

Both are AES-256-GCM. The Google subject is never stored; the cookie value is
never stored, only its hash. So the plaintext salt exists **only in memory,
only during a request that already carries the secret that unlocks it**.

The Google path unwraps from the account row. The silent path unwraps from the
session row and never touches the Google subject at all — which is what makes
silent SSO possible without weakening anything.

**What a full database dump does not yield:**

- No pairwise salt, so no application subject for anybody.
- No Google subject, hashed under a pepper and not otherwise reversible: the
  hashes can be matched against a list of candidate subjects someone already
  holds, never turned back into an identifier on their own.
- No record of which applications an account has used, beyond any sign-in
  that happened to be in flight at that instant (§4.2).

**What it does yield, stated with the same precision, because this is the
half that gets understated.** `[diverged]` — the original wording of this
section stopped at the bullets above and left a reader with a far more
comforting impression than the mechanism deserves:

- **A count of accounts**, and their creation dates rounded to the day.
- **Every registered application**, from the `clients` table: id, name and
  redirect URIs. There is no anonymity for *applications*, only for people.
- **The ability to mint tokens.** `signing_keys.private_pem` is a plaintext
  PEM private key whose public half every application trusts through the
  published JWKS. Whoever holds the dump can forge an ID token with any `sub`
  and any `aud`. **A database dump is token forgery against every registered
  application**, which is categorically worse than any anonymity question on
  this page, and no amount of envelope encryption around the salt changes it.
  Response is rotation: delete the `signing_keys` rows, let the service mint
  a fresh one, and treat every application's own sessions as compromised.
- **The lookup pepper**, from `settings`.

**What it still costs to deanonymise one person:** the dump *and* that
person's Google subject identifier, obtained elsewhere. With both, the lookup
hash finds their row and the subject unwraps their salt. This is unavoidable
— a login must be able to find an existing account from a Google subject.

Two corrections to how that cost used to be described here, both in the
direction of it being cheaper than claimed:

- **It is not one application's subject, it is all of them.** `clients`
  enumerates every registered application, so the salt is unwrapped once and
  then one HMAC per client yields that person's subject *everywhere they have
  an account* — and, since the derivation does not depend on whether they
  ever used the application, everywhere they might. There is no residual
  "which applications did they use" protection left once the salt is open.
- **It is not a per-person cost when the adversary has a corpus.** `[diverged]`
  — this section used to end with "it is a per-person cost, not a bulk one".
  That is true of the *unwrapping* step, which needs a Google subject per
  account, and it was never true of the *matching* step. The pepper is in the
  dump, so a corpus of candidate Google subjects — from another breach, or
  from any service that stores them — can be hashed under it and joined
  against `google_sub_hash` in a single embarrassingly-parallel pass, with no
  per-account work at all. The honest statement is: finding out which of the
  subjects you already hold have Opsidious accounts is a bulk sweep;
  unwrapping a salt is per-person and needs that person's actual subject.

*Validated before specifying.* A throwaway spike exercised the full mechanism:
two clients yielding different subjects, the subject stable across sessions,
the silent path recovering the salt without the Google subject, a wrong subject
failing to unwrap rather than returning garbage, and a serialised dump
containing none of the three secrets. Cost measured at 0.017 ms per sign-in,
which is not a consideration.

**Consequence, accepted:** neither the auth service nor any app can enumerate a
person's presence across apps. That is the point, and it is also why account
deletion works the way §11 describes.

### 4.1 Threat model

Who we are defending the guarantee against, and how.

| Adversary | Reaches | Defence |
|---|---|---|
| One app's database (leak, or the app itself) | pairwise subjects, pseudos, that app's content | Subjects are HMAC outputs over a salt the app never sees. Comparing two apps' dumps yields nothing. |
| The auth database — *anonymity* | account rows, sealed salts, sessions | No email or name exists to leak. Google subjects are stored hashed. **No row records which apps an account uses**, beyond a sign-in in flight at that instant (§4.2). |
| The auth database — *impersonation* | **the signing key, in the clear** | **Not defended.** `signing_keys.private_pem` is a plaintext PEM; the holder forges an ID token for any `sub` and any `aud`, and every registered application verifies it against the published JWKS. A dump is a total impersonation compromise of the whole estate — worse, and more urgent, than every anonymity row in this table. Recovery is key rotation, not damage limitation. §4.3. |
| The auth database *plus* a corpus of Google subjects | which of those subjects have accounts | **Not defended.** The lookup pepper is in the dump, so matching a corpus is one parallel pass, not a per-person cost. Unwrapping any one salt still needs that person's own subject. §4.3. |
| Network observer | TLS-encrypted traffic | Nothing to add. |
| Reverse-proxy or CDN logs | URLs, IPs, timestamps | §7.3 — access logging is disabled for this host. This is the gap most likely to be missed. |
| Someone holding *both* app databases and the auth database | everything | Not defended. Correlation is possible by recomputing the HMACs. |
| The operator | everything, over time | Not defended, and cannot be. See below. |

**The honest limit.** This design minimises what an *attacker*, a *leak*, or a
*careless future change* can obtain. It does not, and cannot, defend against
the operator of the service, who can deploy a modified build that records
whatever it likes. Claiming otherwise would be false. What the design does is
make the correlating data structurally absent, so that obtaining it requires a
deliberate act rather than reading a table that was there all along.

### 4.2 Deliberate omissions in the schema

Three things a normal service would store and this one does not:

- **The account on the code row.** `codes` holds the derived `app_sub`, not
  `account_id` (§5), so the row is app-scoped from the start.

  `[diverged]` — **this bullet used to claim more than it delivered.** It said
  a code row "does not, by itself, link a person to an application", and that
  was wrong: the row also carries `sso_session_id`, so the chain
  `codes.client_id` → `sso_session_id` → `sso_sessions.account_id` names both
  ends. Omitting `account_id` moved the link one join away; it did not remove
  it. Two mechanisms, both added during implementation, are what actually
  bound it:

  - **Tombstoning.** The moment a code is resolved — consumed *or* rejected —
    the same `UPDATE` that records the outcome sets `app_sub`, `client_id`,
    `redirect_uri` and `nonce` to `NULL`. What survives is exactly what
    replay detection and session revocation need: `code_hash`, `used`,
    `expires_at` and `sso_session_id`. A spent row can still cost a thief
    the session (§7.5) and can no longer name an application. This is why
    those four columns are nullable in §5, against the original schema.
  - **A dedicated sweep.** A code that is *abandoned* rather than resolved —
    browser closed, back button, an application backend that never
    exchanges it — has no `UPDATE` coming to tombstone it, so nulling on
    resolution alone would leave it naming an application until the general
    sweep noticed. Codes are therefore swept every 30 seconds, against the
    general sweep's ten minutes (§7.20), which keeps the exposure to the
    code's own sixty-second lifetime plus half a minute.
- **Precise timestamps on accounts.** `accounts.created_at` is rounded to the
  day. A millisecond-precision creation time is a fingerprint that can be
  matched against an app's own first-seen record.
- **`last_seen_at` on accounts.** Dropped entirely. It bought nothing and
  described an activity pattern.

---

## 5. Data model

SQLite, WAL, foreign keys on. All timestamps are epoch milliseconds.

```sql
accounts (
  id              TEXT PRIMARY KEY,    -- uuid
  google_sub_hash TEXT NOT NULL UNIQUE,
  kdf_salt        BLOB NOT NULL,       -- 16 bytes, HKDF salt
  sealed_salt     BLOB NOT NULL,       -- AES-256-GCM(HKDF(google_sub), pairwise_salt)
  created_at      INTEGER NOT NULL     -- rounded to the day, see §4.2
)
-- There is deliberately no `pairwise_salt` column. See §4.3.

clients (
  id            TEXT PRIMARY KEY,      -- 'defnote'
  name          TEXT NOT NULL,
  secret_hash   TEXT NOT NULL,         -- sha256 of a 32-byte random secret
  redirect_uris TEXT NOT NULL,         -- JSON array, matched exactly
  created_at    INTEGER NOT NULL
)

-- One in-flight /authorize, parked across the Google round trip.
auth_requests (
  id           TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,          -- [diverged] no REFERENCES, see below
  redirect_uri TEXT NOT NULL,
  state        TEXT NOT NULL,
  nonce        TEXT,
  google_nonce TEXT NOT NULL,
  expires_at   INTEGER NOT NULL        -- 10 minutes
)

-- [diverged] Every field here is nullable that the original design declared
-- NOT NULL, and that is the point rather than a relaxation: `app_sub`,
-- `client_id`, `redirect_uri` and `nonce` are nulled by the same UPDATE that
-- resolves the code, leaving a tombstone that can still detect a replay and
-- still revoke a session without naming an application (§4.2). Because the
-- schema can no longer enforce them at insert time, issueCode() validates
-- them itself: a caller bug that used to fail loudly as SQLITE_CONSTRAINT
-- would otherwise be accepted and surface later as a code that can never
-- legitimately validate.
codes (
  code_hash      TEXT PRIMARY KEY,     -- sha256; the code itself is never stored
  app_sub        TEXT,                 -- already derived; NOT account_id, see §4.2
  client_id      TEXT,
  redirect_uri   TEXT,
  nonce          TEXT,
  sso_session_id TEXT,                 -- deleted if this code is replayed
  used           INTEGER NOT NULL DEFAULT 0,   -- an outcome, not a flag; see below
  expires_at     INTEGER NOT NULL,     -- 60 seconds
  created_at     INTEGER NOT NULL
)

sso_sessions (
  id          TEXT PRIMARY KEY,
  token_hash  TEXT NOT NULL UNIQUE,    -- sha256; the cookie value is never stored
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kdf_salt    BLOB NOT NULL,           -- 16 bytes
  sealed_salt BLOB NOT NULL,           -- AES-256-GCM(HKDF(cookie_value), pairwise_salt)
  expires_at  INTEGER NOT NULL,        -- 14 days, absolute, not sliding
  created_at  INTEGER NOT NULL
)

-- `private_pem` is a plaintext PKCS#8 PEM. It cannot be sealed the way the
-- pairwise salt is: there is no per-request secret that unlocks it, because
-- signing happens on requests that carry none. Whoever holds this table can
-- forge a token for any subject and any audience (§4.1, §4.3).
signing_keys (
  kid         TEXT PRIMARY KEY,
  private_pem TEXT NOT NULL,
  public_jwk  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  retires_at  INTEGER NOT NULL,        -- stops signing here
  expires_at  INTEGER NOT NULL         -- stops being published here, then deleted
)

settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)   -- lookup_pepper
```

**`codes.used` is a four-valued outcome, not a boolean.** `[diverged]` — the
original design made it a flag and the replay path a single behaviour, which
cannot express the distinction the delivered service needs:

| value | meaning | on a later presentation |
|---|---|---|
| `0` unused | issued, never presented | claimable by its owner |
| `1` in flight | a presentation is resolving right now | within a five-second grace window, a second presentation is a leak of the code and **deletes the session**; past it, the row is read as a wedge left by a crashed process and its own owner may reclaim it |
| `2` consumed | exchanged successfully | a replay: **deletes the session** it was issued from (§7.5) |
| `3` rejected | expired, or the wrong `redirect_uri`, presented by the code's own owner | refused, and **the session is deliberately left alone** — a mismatch is not evidence of a leak, and signing a person out over an application's own misconfiguration would be a denial of service with extra steps |

A presentation by a client that does *not* own the code never transitions the
row at all: it is classified and refused, so a third party holding a stolen
code cannot burn it (§7.4, §7.6).

**`auth_requests.client_id` has no foreign key.** `[diverged]` — the original
declared `REFERENCES clients(id) ON DELETE CASCADE`; the delivered schema does
not, so deleting a registered client no longer takes its parked requests with
it. The consequence was checked rather than assumed and is bounded: a parked
row expires by itself after ten minutes and is swept, `/callback/google`
answers only on the `redirect_uri` that was verified against the allowlist
when the request was parked, and the exchange that follows fails at client
authentication because the client no longer exists. There is no open redirect
and no orphan that outlives its own TTL. `PRAGMA foreign_keys = ON` is set,
and the one cascade that carries a real anonymity obligation —
`sso_sessions.account_id`, which erases every session when an account is
deleted — is declared and delivered.

**Codes and session tokens are stored hashed.** Read access to the database
alone does not yield a usable credential — but read access to
`signing_keys.private_pem` does yield a usable *forgery*, which is a
different sentence and a worse one (§4.3).

**`lookup_pepper` and the signing keys live in the database, not the
environment.** They are generated on first boot if absent. Putting the pepper in
an env var invites someone to "fix" it later, which would silently orphan every
account in every app. Keeping it beside the data it derives means it is backed
up and restored with that data, together or not at all.

---

## 6. HTTP contract

### `GET /authorize`

Query: `client_id`, `redirect_uri`, `state` (required), `nonce` (optional but
Defnote always sends one), `prompt=login` (optional, forces re-authentication).

1. Look up `client_id`. Compare `redirect_uri` **exactly** against the client's
   registered list. If either fails, render an error page — never redirect,
   because an unverified `redirect_uri` is exactly what an open redirect is.
2. If a valid `__Host-opsid_sso` cookie is present and `prompt=login` is
   absent, issue a code and `302` to `redirect_uri?code=…&state=…`.
3. Otherwise park the request in `auth_requests` and **redirect straight to
   Google**. Google is the only method, so a page offering exactly one choice
   is pure friction — and one less rendered page is one less attack surface.
   The service renders only two pages in total: an error page and `/account`.
4. `prompt=none` never redirects to Google. With no valid session it returns
   `error=login_required` to the app, which is what lets an app attempt a
   silent sign-in and fall back gracefully.

Any error after step 1 redirects to `redirect_uri?error=…&state=…`. Every
response this route can produce — a redirect carrying a fresh code, or an
error page — is sent with `Cache-Control: no-store`, so no cache or
intermediary can replay one later.


**L'écran d'introduction — décision inversée après coup.** Le §6 disait « aucune
page intermédiaire, direct chez Google ». Cette décision supposait que les gens
sachent ce qu'est Opsidious. Ils ne le savent pas : le mot « anonyme » ne vaut
rien, tous les services l'emploient, et ce qui convainc est de montrer le
mécanisme — qui voit quoi, et surtout qui ne voit pas quoi.

Un écran s'affiche donc avant la PREMIÈRE redirection vers Google, une seule
fois par navigateur, marqué par un cookie `__Host-opsid_seen`. Ce cookie ne
porte aucune identité, et son absence ne coûte qu'un écran de plus — jamais un
échec de connexion.

Deux propriétés sont testées parce qu'elles protègent la connexion instantanée :
une session ouverte ne voit JAMAIS cet écran, même sans le cookie, sinon il
coûterait un aller-retour à chaque application au lieu d'une fois dans une vie ;
et `prompt=none` ne l'affiche jamais, puisque « silencieusement ou pas du tout »
interdit exactement d'afficher une page.

**L'alternative écartée** était un script servi aux applications, façon Google
One Tap, ouvrant une fenêtre modale dans leur page. Refusée pour une raison qui
tient au produit autant qu'à la sécurité : un service dont l'argument est
« personne ne vous piste » ne peut pas faire tourner son code sur toutes les
pages de toutes les applications. C'est la forme exacte de ce qu'il dénonce, ça
se voit dans un onglet réseau, et chaque application devrait rouvrir
`script-src` — un script tiers pouvant infiniment plus qu'une feuille de style.

### Redirecting to Google

Not a route of its own — step 3 of `/authorize` does it inline. The Google URL
carries `response_type=code`, `scope=openid`, `state` = the `auth_requests.id`,
`nonce` = `auth_requests.google_nonce`, and `redirect_uri` =
`{PUBLIC_URL}/callback/google`. `prompt=select_account` is added when the app
asked for `prompt=login`.

### `GET /callback/google`

1. Load the parked request by `state`; reject if missing or expired.
2. Exchange Google's code at the token endpoint using `GOOGLE_CLIENT_SECRET`.
3. Verify the returned ID token: signature against Google's JWKS, `iss`, `aud`
   equals our client id, `exp`, and `nonce` equals `google_nonce`.
4. Upsert the account by `google_sub_hash`. On insert, generate `pairwise_salt`
   and seal it under the Google subject (§4.3). On an existing account, unwrap
   it.
5. Create an SSO session: generate the cookie value, seal a second copy of the
   salt under it, set `__Host-opsid_sso`. `[diverged]` — **delete the session
   the browser arrived with first.** Reaching this point at all means either
   there was no session, or `prompt=login` forced re-authentication past one;
   in the second case the old session would otherwise keep working for the
   rest of its own fourteen days even though the browser has already moved on
   to a new cookie, which is exactly what asking to re-authenticate is meant
   to prevent.
6. Derive `app_sub`, issue a code, `302` back to the app's `redirect_uri`.
   The cookie is staged only once nothing else can fail, so a later error
   cannot leave the browser signed in while the application never receives a
   code.

### `POST /token`

Form body: `grant_type=authorization_code`, `code`, `client_id`,
`client_secret`, `redirect_uri`.

1. Reject any `grant_type` other than `authorization_code` with `400
   unsupported_grant_type`, before a code or a credential is looked at.
2. Authenticate the client: `sha256(secret)` compared with `timingSafeEqual`.
3. Claim the code with **one guarded `UPDATE`**, requiring `changes === 1`. A
   `SELECT` followed by a `DELETE` leaves a window in which two concurrent
   exchanges both succeed. `[diverged]` — the original design guarded only on
   `used = 0` and checked ownership and expiry afterwards (step 4 below); the
   delivered statement folds every predicate that decides whether *this*
   caller may claim the row into the `WHERE` clause — the code hash, the
   owning `client_id`, the exact `redirect_uri`, the expiry, and either
   `used = 0` or an in-flight row old enough to be a crash rather than a race
   (§5). A client that does not own the code therefore cannot move its row at
   all, rather than moving it and being rejected after the fact.
4. If nothing was claimed, read the row and classify it: unknown, replayed
   (deleting the SSO session it was issued from), rejected, or presented by
   the wrong client (classified only, never transitioned). See the table in
   §5 for which outcomes revoke a session and which deliberately do not.
5. Tombstone and return. The same `UPDATE` that marks the code consumed nulls
   `app_sub`, `client_id`, `redirect_uri` and `nonce` (§4.2); the response is
   `{ "id_token": "…", "token_type": "Bearer", "expires_in": 120 }` with
   `Cache-Control: no-store`.

**Two failure shapes, each indistinguishable within itself.** Every grant
failure — bad code, replay, expired, wrong `redirect_uri`, code issued to
another client — answers `400 {"error":"invalid_grant"}`. Every
client-authentication failure — unknown `client_id`, wrong secret, missing
secret — answers `401 {"error":"invalid_client"}`. `[diverged]` — the README
used to promise one shape covering both groups, which the code has never
done, and the code is right: a `client_id` is public by design (it rides in
every sign-in redirect and sits in every integrator's configuration), so
hiding whether one exists protects nothing, while telling an integrator
"your credentials are wrong" apart from "your code is stale" is the
difference between a five-minute fix and an afternoon. The secret itself is
what must not leak, and a wrong secret, a missing secret and an unregistered
id are identical on the wire. `test/token.test.js` pins this.

**`access_token` — decision reversed after measurement.** The original design
returned none, on the reasoning that an unused token for a service with no
resource server is cargo cult. That was right about the purpose and wrong about
the cost. RFC 6749 §5.1 and OIDC Core §3.1.3.3 make the field REQUIRED, and the
reference client (`openid-client`, on `oauth4webapi`) refuses the exchange
outright: `"response" body "access_token" property must be a string`. Adding the
field turned that failure into a completed flow, with discovery, exchange,
signature and nonce all verified by the library. A response no conformant client
can parse is a worse cargo cult than an unused field.

The token returned is deliberately inert: a fresh random string, never
persisted, accepted by no endpoint here. `refresh_token` remains absent — it is
optional, and there is no long-lived grant to refresh.

### `GET /.well-known/jwks.json`

Every key whose `expires_at` is in the future, newest first. `Cache-Control:
public, max-age=3600`.

A key has two boundaries, and both are needed. At `retires_at` it stops signing
new tokens; it keeps being published until `expires_at`, so tokens already
issued still verify. `expires_at` is `retires_at` plus one hour — comfortably
more than the 120-second token lifetime plus a client's one-hour JWKS cache.
Keys past `expires_at` are deleted by the same sweep as §7.20.

Rotation: a successor is minted once the live key is within one grace window
(one hour) of its own retirement, so there is always an overlap rather than a
cliff. Both the first mint and every rotation go through one
`BEGIN IMMEDIATE` transaction behind a same-process lock, because a plain
check-then-mint lets two racing processes — two replicas, or two requests
arriving before any key exists — each decide a key is due and each mint one.
That race was reproduced with four real processes against one fresh database
before it was fixed (`test/keys-mint-race.test.js`).

### Other

- `POST /logout` — clears the SSO session and its cookie.
- `GET /account` — one page: confirms you are signed in, offers deletion, and
  states plainly what deletion does and does not reach (§11).
- `GET /healthz` — no database, no network, mounted ahead of everything that
  touches either. It is therefore a **liveness probe and only a liveness
  probe**: it answers "the process is alive" and says nothing about whether
  the database is healthy. A database broken *at boot* never reaches it —
  startup logs a fatal error and exits 1 — while a database that wedges
  *after* boot is a gap it does not close: every route would 500 while the
  container went on reporting healthy. Closing that gap means a database
  round trip on every probe forever, which was judged the worse trade. Stated
  here because it is the kind of thing a reader assumes the other way.

### ID token claims

```json
{
  "iss": "https://auth.opsidious.com",
  "sub": "<pairwise, per client_id>",
  "aud": "<client_id>",
  "exp": "<iat + 120>",
  "iat": "…",
  "jti": "<uuid>",
  "nonce": "<echoed from /authorize>"
}
```

Signed RS256 with the newest non-retired key; `kid` in the header. No other
claim is ever added — there is nothing else to put in it.

---

## 7. Security requirements

Numbered so each becomes a test. Half of the security of an OAuth system lives
in the *client*, so §7.2 is as binding as §7.1 — an app that skips it is a hole
in the whole estate, not just in itself.

### 7.1 The service

1. `redirect_uri` is matched by exact string equality against a registered
   allowlist. No prefix, suffix or wildcard matching. A trailing slash, a
   different case, or an added query parameter is a different URI.
2. An invalid `client_id` or `redirect_uri` renders an error page and never
   issues a redirect. Redirecting to an unverified URI *is* the open-redirect
   vulnerability.
3. No value taken from the query string is ever rendered into a response body.
   The error page names the failure, never the `client_id` or `redirect_uri`
   that caused it. With no sign-in page, the only reflection risk left is the
   error page, and it reflects nothing.
4. Authorization codes are 32 random bytes, stored hashed, valid 60 seconds,
   and consumed atomically — one guarded `UPDATE` requiring exactly one row
   changed. A `SELECT` then `DELETE` leaves a race in which two concurrent
   exchanges both succeed. `[diverged]` — the guard is not `WHERE used = 0`
   but every predicate that decides whether this caller may claim the row:
   hash, owning `client_id`, exact `redirect_uri`, expiry, and outcome (§5,
   §6).
5. A **replayed** code — presented again after it was successfully consumed,
   or presented twice at once — invalidates the SSO session it was issued
   from and returns `invalid_grant`. `[diverged]` — a code merely *rejected*
   (expired, wrong `redirect_uri`) must **not** invalidate anything: a
   mismatch is not evidence of a leak. And a row left in flight by a process
   that died mid-exchange must be recoverable by its own owner after a grace
   period rather than being read as a leak forever (§5).
6. A code presented with the wrong `client_id` or `redirect_uri` is rejected,
   and a presentation by a client that does not own the code does not
   transition the row at all.
7. Client secrets are 32 random bytes, stored as SHA-256, compared with
   `timingSafeEqual`. Not bcrypt: a 32-byte random secret has nothing to
   dictionary-attack, and a slow hash on the token endpoint is a denial-of-service
   lever, not a defence.
8. The SSO cookie is `__Host-opsid_sso`: `Secure`, `HttpOnly`, `SameSite=Lax`,
   `Path=/`, no `Domain`. Its value is 32 random bytes; only the hash is stored.
9. ID tokens are RS256, live 120 seconds, and carry `iss`, `aud`, `exp`, `iat`,
   `jti` and `nonce`.
10. Google's ID token is verified for signature, `iss`, `aud`, `exp` and `nonce`
    before any account row is read or written.
11. The Google authorization request carries `scope=openid` and nothing else.
12. `frame-ancestors 'none'` and `X-Frame-Options: DENY` on every response. An
    identity provider must never be framable — a framed authorization endpoint
    is the clickjacking primitive, and `/account` carries a delete button.
13. `Referrer-Policy: no-referrer` on every response, so no state, request id or
    code leaves in a `Referer` header.
14. HSTS, `max-age` one year, `includeSubDomains`. **This commits every
    `*.opsidious.com` host to HTTPS**, which is intended, and is a decision
    that cannot be quickly undone.
15. `Content-Security-Policy: default-src 'self'` with no external origin of any
    kind — no script, style, font or image host.
16. Every SQL statement is parameterised. No string interpolation reaches the
    database.
17. Rate limits: `/authorize` per IP — it now redirects to Google directly, so
    an unbounded rate makes the service an amplifier against Google;
    `/callback/google` per IP; `/token` per IP and per client. `[diverged]`
    — the global limiter is mounted ahead of `express.static` as well as
    ahead of every route, because unrate-limited static assets are an
    amplification lever of their own.
18. Logs record `client_id` and an outcome. They never record a code, a token,
    a cookie value, a Google subject, an account id, a pairwise subject, or a
    full query string.
19. The process refuses to start without `GOOGLE_CLIENT_ID`,
    `GOOGLE_CLIENT_SECRET` and **`PUBLIC_URL`**. `[diverged]` — the variable
    is `PUBLIC_URL`, not `BASE_URL`, and it has **no default**: nothing here
    may be hardcoded to a domain (§13), so a deployment that omits it must
    fail at boot rather than inherit somebody else's origin. The image does
    not set it either (§10). `ISSUER` optionally overrides the `iss` claim
    and otherwise defaults to `PUBLIC_URL`.
20. Expired `codes`, `auth_requests`, `sso_sessions` and `signing_keys` are
    swept on a timer. `[diverged]` — **codes are swept on their own, much
    shorter cadence** (30 seconds, against ten minutes for everything else).
    The general interval is sized for rows that live minutes to weeks; an
    abandoned code names an application for as long as it survives, and
    riding the general cadence let a 60-second row live for eleven minutes
    (§4.2).
21. `POST /logout` and account deletion on `/account` require a CSRF token, and
    deletion additionally requires an explicit confirmation.

### 7.2 The client, binding on every app

22. The app generates `state` (32 random bytes), stores it in a short-lived
    `HttpOnly` cookie, and rejects a callback whose `state` does not match.
    Without this, an attacker signs *you* into *their* account.
23. The app generates a `nonce`, sends it on `/authorize`, and rejects an ID
    token whose `nonce` differs.
24. The app verifies `iss` equals the auth service, and `aud` equals its own
    `client_id`. A token minted for another client must be refused.
25. The app pins `algorithms: ['RS256']` when verifying. Accepting the token's
    own `alg` is the algorithm-confusion vulnerability.
26. The callback **exchanges the code server-side and then redirects**, so the
    URL carrying the code never becomes a page the user rests on, and never
    enters history or a `Referer`.
27. The client secret is server-side only. It never reaches a template, a log,
    or the browser.

### 7.3 The infrastructure

28. **Traefik access logging is disabled for `auth.opsidious.com`**, or
    configured to drop query strings. `GET /callback/google?code=…` puts a live
    Google authorization code in the log file otherwise. This is the single
    easiest thing to overlook in the whole design, because it is correct in the
    application and wrong one layer out.
29. The container runs with `no-new-privileges`, a read-only root filesystem,
    and all capabilities dropped. Only `/app/data` and the backup mount are
    writable.
30. The backup directory is a host bind mount, not a Docker volume, so removing
    volumes cannot remove the backups (§8).

---

## 8. Resilience

**If the auth service is down, nobody is signed out.** Each app holds its own
7-day session cookie; only *new* sign-ins fail. This is the correct failure
mode and it is the reason the service does not need to be highly available.

**Defnote caches the JWKS** and refetches only when it meets an unknown `kid`.
A warm cache means an auth outage does not even break token verification.

**Backups are part of the deliverable, not a follow-up.** This database is no
longer "one app's accounts" — it is the identity of every Opsidious project.
Losing it loses every `pairwise_salt`, and therefore every user of every app,
permanently and with no recovery path.

- A timer runs `VACUUM INTO '{BACKUP_DIR}/opsidious-auth-YYYY-MM-DD.db'` daily.
  `VACUUM INTO` is safe against a live WAL database, unlike copying the file.
- `BACKUP_DIR` is a host-mounted path, not a Docker volume, so a
  `docker volume rm` cannot take the backups with it.
- 14 days retained; older files deleted.
- Success and failure are both logged. A failed backup logs at error level.

**Startup is idempotent, but the two bootstrap values get there differently.**
`[diverged]` — this section used to say both were created with
`INSERT OR IGNORE`. Only the pepper is: a `PRIMARY KEY` picks one winner even
against concurrent processes, with no extra locking. The first signing key
has no such built-in guarantee — a plain `SELECT` has nothing stopping two
racing processes from both finding nothing and both minting — so the mint is
wrapped in a `BEGIN IMMEDIATE` transaction, serialised across processes by
the write lock and within a process by its own lock (§6, JWKS). Minting a
second pepper would orphan every account in every application; minting two
signing keys is merely wrong. Both are re-read rather than assumed after the
write, so a restart never creates a second one.

---

## 9. What changes in Defnote

This section describes the first consumer's migration and lives in another
repository; nothing in it is delivered here. It is kept because it is the
worked example of what integrating costs an existing application, which is
the question a reader of §3.2 asks next.

Defnote gets smaller, not larger.

| Before | After |
|---|---|
| `google-auth-library` dependency | removed |
| Google Identity Services script in the page | removed |
| CSP exceptions for `accounts.google.com` | removed — CSP becomes `default-src 'self'` |
| `users.google_sub` | `users.opsidious_sub` |
| `verifyGoogleIdToken()` | `exchangeCode()` + `verifyIdToken()` against cached JWKS |
| `POST /api/auth/google`, `POST /api/auth/google/register` | `GET /auth/start`, `GET /auth/callback` |
| Landing page renders a Google button widget | Landing page renders a link: "Continuer avec Opsidious" |

Unchanged: the `sessions` table and its revocation behaviour, the CSRF scheme,
the pseudo, and the dev-login route used for local development.

**The pseudo stays per app.** It has to: the subject differs between apps, so a
shared display name would itself be a correlation vector.

**First sign-in still asks for a pseudo.** `GET /auth/callback` verifies
`state`, exchanges the code, verifies the token, then looks up
`users.opsidious_sub` — and in **both** branches answers with a `302`, never
with a rendered page, so the URL holding the code is never one the user rests
on (§7.26):

- Known subject → issue Defnote's session cookie, `302` to `/app`.
- Unknown subject → park the verified subject in a signed, 10-minute cookie and
  `302` to `/auth/pseudo`, which renders the form. `POST /auth/pseudo` reads
  that cookie, creates the user, and signs them in. The subject is never
  accepted from a form field, for the same reason the old `signupToken` existed.

This replaces the old two-step `needsPseudo` JSON handshake with a plain page,
which is simpler and works without JavaScript.

New environment for Defnote: `OPSIDIOUS_AUTH_URL`, `OPSIDIOUS_CLIENT_ID`,
`OPSIDIOUS_CLIENT_SECRET`, and optionally `OPSIDIOUS_AUTH_INTERNAL_URL`.

### 9.1 Making it instant

Signing in should cost one click and feel like nothing happened. Four changes
get there:

**No pseudo form at sign-up.** Defnote assigns a readable pseudo automatically
(two words from a small curated French list, plus a numeric suffix on
collision) and lets it be changed in settings. It only *matters* when a tag is
published, so Defnote asks for a real one at that moment — where the pseudo
becomes public and the request makes sense — rather than blocking sign-up on a
decision nobody has an opinion about yet. Sign-up becomes: click, choose a
Google account, land in the notebook.

**No interstitial at the auth service.** §6 step 3: straight to Google.

**The token exchange never leaves the host.** Both containers sit on mercury's
`proxy` network, so Defnote calls `http://opsidious-auth:4567/token` and fetches
the JWKS the same way. No public round trip, no TLS handshake, no dependency on
the outside world for a sign-in. Browser-facing redirects still use the public
URL, and `iss` remains the public URL — only the two server-to-server calls take
the short path. Plain HTTP between two containers on one host's bridge network
is acceptable; leaving the host it would not be.

**A silent attempt before the landing page.** A signed-out visitor hitting
`/app`, `/study` or `/settings` is sent through `auth.start({ silent: true })`
rather than straight to `/`. With an Opsidious session they arrive at the page
they asked for, with no click and no Google screen. Without one, they land on
`/` as before. This is what makes a second Opsidious app feel like it already
knew them.

`/` itself never auto-redirects: it is the public landing page and has to stay
visible to first-time visitors and to search engines.

**Existing data:** Defnote has never been deployed and holds no production
accounts, so `users.google_sub` is renamed rather than migrated. Local
development databases are deleted; there is nothing in them worth keeping.

---

## 10. Deployment

New repository `opsidious-auth`, built like Defnote: `node:22-alpine`
multi-stage image, published to `ghcr.io/theom83/opsidious-auth`, deployed by
the same SSH step, declared in `mercury/infrastructure/docker-compose.yml`
behind Traefik on `auth.opsidious.com` with a `opsidious_auth_data` volume and a
host bind mount for backups.

Prerequisites, all of which must exist before first boot:

1. DNS `auth.opsidious.com` → mercury, before the container starts, or the
   Let's Encrypt challenge fails and the domain enters a rate-limited backoff.
2. A Google OAuth **web application** client with redirect URI
   `https://auth.opsidious.com/callback/google`. Unlike the current Defnote
   setup, this one has a real client **secret**.
3. **Three** required environment variables on the container, not two.
   `[diverged]` — this list used to name only the two Google ones, and a
   compose entry built from it **crash-loops on first boot** with
   `PUBLIC_URL must be set`: the variable has no default and the image
   deliberately does not set one (§7.19). Mercury namespaces its variables
   per service and the compose file maps them onto the container's own names,
   exactly as it already does for tarkovxyz:

   | mercury `.env` | container env (§7.19) | required |
   |---|---|---|
   | — (set directly in the compose entry) | `PUBLIC_URL` = `https://auth.opsidious.com` | **yes, no default** |
   | `OPSIDIOUS_AUTH_GOOGLE_CLIENT_ID` | `GOOGLE_CLIENT_ID` | yes |
   | `OPSIDIOUS_AUTH_GOOGLE_CLIENT_SECRET` | `GOOGLE_CLIENT_SECRET` | yes |

   The image presets `NODE_ENV`, `PORT`, `DB_PATH` and `BACKUP_DIR`, so those
   need no compose entry unless they are being overridden. Everything else in
   [`.env.example`](../.env.example) has a working default.

4. A host directory for backups, bind-mounted read-write.
5. **Traefik access logging disabled for this host, or stripped of query
   strings** (§7.28). Correct application behaviour does not help if the proxy
   in front writes `?code=…` to disk.
6. The compose service declares `read_only: true`, `no-new-privileges`,
   `cap_drop: [ALL]`, and `tmpfs` for `/tmp`, with only `/app/data` and the
   backup mount writable.

Defnote is registered as the first client by a small admin script run once
inside the container; it prints the generated `client_secret` a single time.

---

## 11. Account deletion

Pairwise subjects mean the auth service **cannot** tell an app which user to
delete. It does not know which apps an account has used, by design.

So deletion is two-sided, and the interface says so:

- Deleting a **Defnote** account erases everything Defnote holds. This already
  works and does not change.
- Deleting an **Opsidious** account means you can no longer sign in anywhere.
  Data already held by apps becomes unreachable rather than erased.

The order matters: delete in each app first, then at Opsidious. The
`/account` page states this in those words rather than burying it.

---

## 12. Testing

**Delivered as 20 suites, run one process each** (`npm test`; `lib/config.js`
and `lib/database.js` both hold module-level state that must not leak between
suites, and `--test` is passed so a failure in a `before`/`after` hook cannot
exit 0). Everything below is covered, plus what implementation turned up that
this list did not anticipate: the four-valued code outcome and its tombstone,
recovery of a code wedged in flight, ownership enforced inside the guarded
`UPDATE`, the signing-key mint race reproduced with four real OS processes,
and the client package exercised against the real service over a real port.

The auth service, all offline — Google is behind an injected fetcher, as
`lib/dict.js` already does in Defnote:

- Full happy path: `/authorize` → Google → `/callback/google` → `/token` →
  a verifiable ID token.
- Silent path: a second `/authorize` with a valid SSO cookie issues a code
  without touching Google.
- `prompt=login` bypasses the SSO cookie.
- Every item in §7.1 that can fail: unregistered `redirect_uri`, near-miss
  `redirect_uri` (trailing slash, different case, added query), wrong
  `client_secret`, expired code, replayed code, code presented by the wrong
  client, missing `state`, wrong Google `nonce`.
- Replayed code kills the SSO session.
- Concurrent exchange of one code: exactly one succeeds.
- Key rotation: a token signed by a retired-but-published key still verifies; a
  token signed by an expired-and-swept key does not.
- Response headers carry `frame-ancestors 'none'`, `Referrer-Policy:
  no-referrer`, HSTS, and a CSP with no external origin.
- No response body echoes the query string: a `client_id` containing markup
  appears nowhere in the error page.
- `/authorize` with no session issues a `302` to Google and renders nothing.
- `/authorize?prompt=none` with no session redirects back to the app with
  `error=login_required` and never contacts Google.
- Backup: `VACUUM INTO` produces a file that opens and contains the accounts.

The envelope encryption of §4.3, which is the core novel mechanism:

- A serialised dump of every table contains no pairwise salt, no application
  subject, and no Google subject. This is the anonymity guarantee as an
  assertion.
- The silent path derives the same subject as the Google path, without the
  Google subject being available to it.
- A wrong Google subject fails to unwrap and raises, rather than returning
  usable bytes.
- A tampered `sealed_salt` fails its GCM tag.
- Deleting the SSO session leaves the account row unusable for silent sign-in
  but still recoverable through Google.

Client-side, in Defnote, for §7.2:

- A callback with a mismatched or absent `state` is refused.
- A token whose `aud` is another client is refused.
- A token whose `nonce` differs from the one sent is refused.
- A token signed `alg: none`, or HS256 with the public key as secret, is
  refused — the algorithm-confusion pair.
- The callback answers `302` in both branches; the code never reaches a
  rendered page.

**The test that matters most:** one Google subject, two registered clients, two
`/authorize` flows — the two ID tokens carry different `sub` values, and
neither equals the account id or any stored column.

Defnote: its existing suite stays green, with the Google verification replaced
by a stub Opsidious server.

---

## 13. The repository is public

`opsidious-auth` is published openly. That is the right call for an identity
provider — a design nobody can inspect is one nobody can find the flaws in —
but it imposes rules.

**Nothing in the design may depend on the source being secret.** It already
does not: every secret is generated at runtime and lives in the database or the
environment. §7 is written so that an attacker reading the code learns only
what an attacker reading this document already knows.

**No real secret may ever enter the repository.** `.env.example` carries empty
values and comments. GitHub secret scanning is on by default for public
repositories; CI additionally fails on a commit containing a private key
header, a `GOCSPX-` Google secret, or a non-empty assignment to any variable
whose name ends in `_SECRET`.

**Nothing may be hardcoded to `opsidious.com`.** Someone else self-hosting this
is a good outcome, and it is also the discipline that keeps configuration out of
the code. Issuer, public URL and cookie names all come from the environment.

**A `SECURITY.md`** states how to report a vulnerability and what is in scope.

**A public repository means a public threat model.** §4.1 and §4.3 must stay
honest, including the two adversaries the design does not stop. Overclaiming in
a document strangers will read is worse than the gap it hides.

**The container image becomes public too**, which removes the `docker login
ghcr.io` step for this service on the server.

**Licence: MIT**, matching Defnote.

---

## 14. Deliberately deferred

Recorded so they are choices rather than oversights.

- **PKCE** — needed the day a public client (mobile, SPA) appears.
- **Back-channel logout** — needed the day "sign out everywhere" has to reach
  app sessions rather than just the SSO session.
- **`access_token` and a `userinfo` endpoint** — needed the day a third-party
  client integrates with a stock OIDC library.
- **Multiple sign-in methods** — the schema does not preclude it; nothing else
  anticipates it.
