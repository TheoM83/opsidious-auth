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
- **Anything an attacker can do while holding a dump of this service's
  database.** The signing key is stored in it as a plaintext PEM, so a dump
  yields token forgery against every registered application, and the lookup
  pepper is in it too, so a corpus of Google subjects can be matched against
  the account table in bulk. Both follow by construction rather than from a
  flaw, both are stated plainly in the README and in the design document's
  threat model, and neither is a vulnerability report. **How an attacker
  obtains the dump in the first place — that is in scope**, and is the report
  worth writing.
