# Security

## Reporting a vulnerability

Open a [private security advisory](https://github.com/TheoM83/opsidious-auth/security/advisories/new).
Please do not open a public issue for a vulnerability.

## In scope

- Anything that lets one application learn that it shares a user with another
  application, using only what this service exposes or stores. This is the
  property the whole design exists to provide.
- Anything that links a stored value back to a Google account.
- The authorization-code flow: code replay, code substitution, open redirects,
  token forgery, algorithm confusion, session fixation.
- Anything that lets a client obtain a token minted for a different client.

## Out of scope

- The operator of a deployment. Whoever runs this service can deploy a modified
  build. The design minimises what an attacker or a leak obtains; it does not
  and cannot constrain the operator. This is stated in the design document
  rather than implied.
- An attacker who already holds a victim's Google subject identifier _and_ a
  dump of the database. Deanonymising that one person is then possible by
  design, because a login has to be able to find an existing account.
