# Project notes (read first)

This repository is the relay for the Oktul eID SSO Forge app: a small Go
container that a customer runs so the app can call an IP-allowlisted login
provider from the customer's static IP. Read `PLAN.md` before doing anything.

Hard constraints (from `PLAN.md`; change them only when the owner says so):

- **Stay on the plan's phase.** Do not build ahead of the phase the owner
  asked for (`PLAN.md` §14).
- **No dependencies:** the Go standard library only (`PLAN.md` D2,
  2026-10-15). FITs are verified with `crypto/rsa`, not a JOSE library
  (`PLAN.md` §4.4). A third-party module needs the owner's approval and a
  reason recorded in `PLAN.md` §7.
- **Fail closed.** No request reaches the upstream without a valid FIT, an
  allowed route and the site and environment pins (`PLAN.md` §4). A site
  mismatch must never fall back to installation membership; missing-site
  fallback needs unambiguous, recorded Phase 0 evidence (§4.4, §14). Reject
  expired signing-key snapshots (§4.5).
- **Never log** request or response bodies, raw rejected paths, query strings,
  header values, the FIT or the upstream credential. The sole header-derived
  exception is the validated trace ID defined in `PLAN.md` §10. Use matched
  routes and fixed error classes, never raw errors or unverified site IDs.
- **Public-ready from the first commit.** The repository is private for now
  but will be published. Never commit secrets, keys, customer names or
  internal hostnames.
- **The protocol is a contract** with old relays in the field. Changing a
  response code, header, endpoint or setting name follows `PLAN.md` §4 and
  §4.6. The plan is the complete local contract; historical requirement IDs
  do not import absent documents.
- **Release only tested maintenance changes.** Automatic Go patches start
  from the last published commit on a supported `release/X.Y` line, never
  unreleased `main`. Scan and verify images before moving a floating tag
  (`PLAN.md` §12). This documents future automation; do not push or tag
  during ordinary implementation work.

# Workflow

After every change, in this order:

1. `gofmt -w .`, then `go vet ./...`, `staticcheck ./...`,
   `go test -race ./...` and `govulncheck ./...`. Fix failures; never skip
   or silence them. Security-relevant code gets tests for its failure cases,
   not only the happy path.
2. Check `PLAN.md` against the change and update it in the same commit
   (decisions with their date, ticked items, spike results).
3. One focused commit with a short imperative subject. Do not push or tag
   unless asked.

# Code style

Verbose comments written for an intermediate developer who is new to Go and
to Forge remotes. Standard library first, no frameworks. Handlers start no
goroutines. Every limit and timeout is a named setting or constant, never an
inline number.
