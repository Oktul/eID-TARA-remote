# Security policy

The relay holds a customer's TARA credential and parses tokens from callers
it has not yet authenticated. Report a vulnerability privately, so that
customers can upgrade before the details are public.

## Report a vulnerability

On GitHub, open this repository's **Security** tab and choose **Report a
vulnerability**. That opens a private advisory that only the maintainers can
read; the fix and the disclosure are coordinated there.

Never put details in a public issue, pull request or discussion. If you
cannot use the private advisory, open an issue that says only that you have a
security report and how to reach you.

A useful report says:

- the relay version (`relay version`, or the image tag or digest), and
  whether you ran it or read the code;
- how it is deployed: Compose with Caddy, Kubernetes, or your own proxy;
- what an attacker needs, and what they gain;
- the request or steps that show it, and the files and lines if you know
  them.

Leave out real secrets: the provider credential, a Forge Invocation Token
(FIT), and codes or tokens from a real login. Replace them with placeholders.

We confirm the report, agree a disclosure date with you, and name you in the
release notes unless you ask us not to.

## What to report

Anything in this repository: the relay, its image, the files in `deploy/`
and the release workflows in `.github/`. These break what the relay promises:

- a request that reaches the provider without a valid FIT for this app from
  the pinned site and Forge environment, or for anything other than
  `POST /oidc/token` ([`docs/PROTOCOL.md`](docs/PROTOCOL.md) section 3);
- the credential, a FIT or a request or response body in a log line, or the
  credential anywhere but the token request to the provider;
- a caller without a valid FIT that crashes the relay or holds more than its
  fixed limits allow;
- a released image that fails the signature check in
  [`docs/SETUP.md`](docs/SETUP.md) section 9, or differs from its tagged
  source.

These are by design:

- `GET /livez` and `GET /readyz` answer without a FIT (`docs/PROTOCOL.md`
  section 2).
- The relay serves plain HTTP. TLS, the IP filter and the connection cap
  belong to the reverse proxy in front of it (`docs/SETUP.md` section 6.3). A
  mistake in the supplied `Caddyfile` or Kubernetes files is still a report.

Problems in TARA or in Atlassian Forge go to their operators. The Forge app's
code is not in this repository, but a problem in how the app and the relay
work together may be reported here.

## Supported versions

[`docs/SUPPORT.md`](docs/SUPPORT.md) lists the supported release lines. A fix
ships as a patch release on each of them, and its release notes say whether
the upgrade is required, recommended or optional.
