# opsidious-auth-client

Express client for [Opsidious Auth](../README.md), an anonymous, Google-only
identity provider. This package turns the flow described in the service's
own spec (§7.2 — state, nonce, issuer/audience checks, a pinned signing
algorithm, a code exchanged server-side) into one dependency that either
works or refuses. You should not have to re-derive any of that by hand, and
this README should not be able to lead you into an insecure setup.

## The guarantee: pairwise subjects

`req.opsidious.sub` is a **pairwise** subject: it is derived from the
person's account _and_ your `client_id`, so the same person gets a
different, unrelated `sub` in every application that uses Opsidious. Two
applications cannot compare notes and work out they share a user, and
Opsidious itself has no record that would let it tell one application to
erase what another knows about "the same" person — each application's data
is keyed by a value nothing else can reproduce. Use `sub` as your user's
primary key. There is no email or name, by design; if you want a display
name, collect it yourself.

## Install

```bash
npm install github:theom83/opsidious-auth#v1.0.0 --workspace-root
```

This package has one real dependency, `jose`; Express and `cookie-parser`
are peer dependencies of whatever application installs it.

## Use

The smallest working integration is three routes:

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

`auth.callback()` never throws into your route: it always sets
`req.opsidious` to either `{ sub, claims }` or `{ error }` and calls
`next()`. A verification failure is a refusal, not a partially-trusted
session — check `req.opsidious.error` before you touch `sub`.

### Options

| option         | required | meaning                                                                                                                                |
| -------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`       | yes      | the service's **public** URL. Used for every browser redirect and is the value every token's `iss` and JWKS fetch are checked against. |
| `clientId`     | yes      | your registered client id.                                                                                                             |
| `clientSecret` | yes      | your registered client secret. Keep it server-side only.                                                                               |
| `redirectUri`  | yes      | must exactly match a URI registered for this client.                                                                                   |
| `internalUrl`  | no       | see [`internalUrl`](#internalurl) below.                                                                                               |
| `cookieName`   | no       | defaults to `opsid_tx`. Change only if it collides with another cookie your app sets.                                                  |

## Silent sign-in

`auth.start({ silent: true })` asks for `prompt=none`: if the visitor already
has an Opsidious session they are signed in with no click and no Google
screen; if not, `req.opsidious.error` is `login_required` and you can show
your landing page instead of a login screen. Use it when a signed-out
visitor hits a page that needs an account, to find out silently whether they
already have a session elsewhere.

## What it does for you

- generates `state` and `nonce` with a CSPRNG and binds them to the browser
  in a cookie, so a login-CSRF cannot sign someone into an attacker's account
- verifies `state` before anything else in the callback runs, and clears the
  cookie once used so it cannot be replayed
- verifies the ID token's signature against the service's published JWKS,
  and checks `iss`, `aud`, `exp` (with 30 seconds of clock-skew tolerance)
  and the `nonce` this request generated
- pins `algorithms: ['RS256']` on that verification. Without the pin, `jose`
  will accept a token signed with any algorithm the JWKS material can be
  coerced into — the "alg confusion" family of JWT attacks. This is not
  theoretical: against this service's own JWKS material, a token signed with
  `PS256` verifies successfully without the pin, and is rejected with the
  pin.
- exchanges the code server-side over a request with an explicit 5-second
  timeout, so a code never sits in a rendered page and an unreachable auth
  service fails your request instead of hanging it
- sets the transaction cookie `HttpOnly`, `Secure` (unconditionally — see
  below), `SameSite=Lax`, `Path=/`
- never logs a token, a code, a cookie value, a subject, or a full URL —
  every failure path collapses to one of a small set of error strings

Implementing the flow by hand means implementing all of that yourself, and
getting every one of them right every time.

### Why `Secure` is unconditional

The transaction cookie is always sent with `Secure`, even when your app runs
on plain HTTP in development. This is deliberate, not an oversight: browsers
already treat `http://localhost` as a trustworthy origin, so local
development is unaffected, and making `Secure` conditional on an environment
variable is exactly the class of bug that was found — twice — in this
service's own cookies. There is no configuration flag that turns it off.

## `internalUrl`

If the service runs on the same Docker network as your app, pass:

```js
opsidiousAuth({
  issuer: 'https://auth.opsidious.com', // still the public URL
  internalUrl: 'http://opsidious-auth:4570'
  // ...
});
```

`internalUrl`, when set, is used for exactly two things: the token exchange
and the JWKS fetch, both server-to-server calls that never touch the
browser. Every browser-facing redirect always uses `issuer`, and the `iss` /
`aud` check on the returned token is always against `issuer` too — never
`internalUrl`. That split is intentional: a misconfigured `internalUrl`
can send your server's own outbound requests to the wrong host, but it can
never cause a browser redirect to leak to an internal hostname, and it can
never widen which issuer a token is accepted from. If you don't pass
`internalUrl`, both kinds of request use `issuer`.

## Errors you may see in `req.opsidious.error`

| error                                                    | meaning                                                                                                                                                                                                                                                    |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_state`                                          | no transaction cookie, or it didn't match the callback's `state`. Usually an expired or replayed callback link.                                                                                                                                            |
| `invalid_nonce`                                          | the ID token's `nonce` didn't match this transaction's.                                                                                                                                                                                                    |
| `invalid_request`                                        | the callback arrived with no `code`.                                                                                                                                                                                                                       |
| `invalid_grant`                                          | the code exchange failed, the token didn't verify, or the auth service didn't respond in time. One shape covers all of these on purpose, the same way the service's own `/token` endpoint does — so a caller can't use the error to probe what went wrong. |
| any other value (e.g. `access_denied`, `login_required`) | passed through unchanged from the auth service's own callback.                                                                                                                                                                                             |

## Timeouts and resilience

Both server-to-server calls the client makes — the token exchange and the
JWKS fetch — carry an explicit 5-second timeout. An unreachable or hanging
auth service produces a fast `invalid_grant` instead of hanging your
request indefinitely.
