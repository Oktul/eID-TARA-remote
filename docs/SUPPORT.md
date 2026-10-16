# Support policy

Which relay releases receive maintenance, how often, and how you learn about
upgrades (`PLAN.md` §12, V-5, M-2). "Support" here means maintenance
releases of the relay.

## Policy

- The **newest minor release of the current major** is supported.
- When a new major is released, the **previous major's newest minor** stays
  supported for **12 months** after it.
- Only the newest minor of each supported major receives maintenance. An
  older minor of the same major is no longer supported once the next minor
  is released; upgrading to it is a tag change (`docs/SETUP.md` section 9).
- Each supported line has a `release/X.Y` branch anchored at its published
  release, with its own Go pin, patch sequence and floating `:X.Y` image tag.
  Unreleased work on `main` never enters a patch release.

## Supported lines

**No release has been published yet, so no line is supported.**

| Line | Branch | Image tag | Latest release | End of support |
| ---- | ------ | --------- | -------------- | -------------- |
| none | -      | -         | -              | -              |

This table lists every supported line with its exact end-of-support date:

- the newest minor of the current major is supported until the next minor
  is released; that date is entered here when it happens;
- the previous major's newest minor ends 12 months after the new major's
  release, the date of its `vN.0.0` tag; that date is entered here on the
  day of the new major's release.

## What a supported line receives

- **Patch releases** (`X.Y.Z` to `X.Y.Z+1`) never change an endpoint,
  response code, header or setting. A security fix may enforce a rejection
  rule that `docs/PROTOCOL.md` already states; it never broadens or changes
  what is accepted.
- **A new Go patch release** of a line's pinned Go minor ships automatically
  as a patch release of that line, within a day of Go publishing it. A new
  builder image for the same Go version does the same. Each automatic
  release starts from the line's last published patch and passes every check
  before it is published; if the line's branch holds other unreleased
  changes, a person releases it instead.
- **A fix that needs a new Go minor**, for a reachable critical or high
  vulnerability, ships within 7 days, after review.
- **A rebuild at least once a year**, so the Go toolchain and the image's CA
  bundle stay current.
- **A weekly vulnerability scan** (`govulncheck`) of `main`, every supported
  release branch and each line's published binaries for both architectures.

Every image is built for `linux/amd64` and `linux/arm64`, signed with cosign
keyless signing, and published with SBOM and provenance attestations; how to
verify the signature is in `docs/SETUP.md` section 9. A `:X.Y.Z` tag never
changes after release; `:X.Y` only moves forward, and only to a verified
image. There is no `latest` tag.

## Protocol support

The Forge app accepts every protocol version that a supported line speaks. A
minimum relay version and the admin page's warning cannot remove support
before the published end-of-support date. An emergency exception needs a
decision by the project's owner, recorded in `PLAN.md`, and explicit upgrade
instructions for customers (`PLAN.md` §4.6).

## How you learn of upgrades

- **Release notes.** Each GitHub release says whether the upgrade is
  **required**, **recommended** or **optional**, and why. For an automatic
  Go patch release the notes are generated: `recommended` when
  `govulncheck` found a reachable vulnerability that the new Go fixes,
  otherwise `optional`, with links to Go's release notes. Only the project's
  owner marks a release `required`. To be notified, watch the repository's
  releases on GitHub.
- **The admin page** compares the version from `/relay/v1/info` with the
  minimum the Forge app expects, and shows a "relay too old" message.
- **Automatic patches.** If you follow `:X.Y`, patch releases arrive without
  action (`docs/SETUP.md` section 9). New minor and major releases always
  need a tag change by hand.

## Security issues

Report vulnerabilities privately, never in a public issue. `SECURITY.md`,
added when the repository is published, says how.
