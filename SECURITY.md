# Security Policy

Kalitka stands in front of admin panels, so a flaw in it can matter. Reports are
welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**
(<https://github.com/everycore-net/kalitka/security/advisories/new>).

If you would rather use e-mail, write to **git@everycore.net** with `kalitka
security` in the subject.

Please include enough to reproduce it: version or commit, configuration (with
secrets removed), and the steps. If you have a fix in mind, all the better.

You will get an acknowledgement within a few days. Once a fix is out, credit is
given in the release notes unless you would prefer to stay anonymous.

## Supported versions

This is a young project with a single active line. Fixes go onto the latest
release; there is no back-porting yet.

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| older   | no        |

## Where the sharp edges are

Two things are worth a second look in any deployment, both documented in the
README:

- **`TrustedProxies` must be set correctly.** Every allow/block/bypass decision
  rests on the client address, which is only trustworthy when forwarded headers
  come from a proxy you named.
- **A Google sign-in currently covers sibling hosts** under the cookie domain.
  Per-host isolation is tracked as a feature, not yet shipped.
