# Project notes (read first)

This repository is the relay for the Oktul eID SSO Forge app: a small Go
container that a customer runs so the app can make TARA token exchanges
(`POST /oidc/token`) from the customer's static IP, which TARA production
allowlists. It forwards nothing else (`PLAN.md` D11). Read `PLAN.md` before
doing anything.

Hard constraints (from `PLAN.md`; change them only when the owner says so):

- **Stay on the plan's phase.** Do not build ahead of the phase the owner
  asked for (`PLAN.md` §14).
- **No dependencies:** the Go standard library only (`PLAN.md` D2,
  2026-10-15). FITs are verified with `crypto/rsa`, not a JOSE library
  (`PLAN.md` §4.4). A third-party module needs the owner's approval and a
  reason recorded in `PLAN.md` §7.
- **Fail closed.** No request reaches the upstream without a valid FIT, an
  allowed route and the site and environment pins (`PLAN.md` §4). A site
  mismatch or a missing invocation site is refused; installation contexts
  never stand in for the signed site (§4.4). Reject expired signing-key
  snapshots (§4.5).
- **Never log** request or response bodies, raw rejected paths, query strings,
  header values, the FIT or the upstream credential. The sole header-derived
  exception is the validated trace ID defined in `PLAN.md` §10. Use matched
  routes and fixed error classes, never raw errors or unverified site IDs.
- **Public from the first commit.** The repository is public (since
  2026-11-26) and its history was written to be. Never commit secrets,
  keys, customer names or internal hostnames.
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
3. One focused commit per logical change, on the change's own branch (see
   Review), with a short imperative subject. Do not push or tag unless asked.

# Code style

Follow `CONTRIBUTING.md`, including its review checklist. Comments are for a
developer new to Go and to Forge remotes: they explain why, cite `PLAN.md`,
and never restate the code. Concise beats verbose (owner, 2026-10-15).

# Review

Every change goes through three rounds. No code reaches `main` unless an
agent that did not write it has reviewed it.

1. **Claude writes.** Implement the change on a local branch, run the
   workflow above, check the diff against the `CONTRIBUTING.md` checklist
   and commit.
2. **Codex reviews and fixes.** Review `git diff main...<branch>` against the
   checklist and `PLAN.md`. Fix each defect in its own commit whose body
   says what was wrong and why. Never amend or rebase Claude's commits.
   Report, rather than fix, a finding that needs a design change or that
   you are unsure of.
3. **Claude reviews again.** Review the whole branch, Codex's commits in
   particular. A behaviour change made in this round goes back to round 2;
   comment and typo fixes do not.

Each round ends with a short report to the owner: commits added, findings
fixed, findings left open and why, disagreements, and the checks run with
their results.

**Disagreements go to the owner.** If one agent rejects the other's finding
or change, neither reverts it nor settles on a compromise. Stop and present:
the point with `file:line`, each side's position in a sentence or two with
its evidence (a `PLAN.md` section, a test, documentation), and what is
blocked. Until the owner decides, the stricter version stays on the branch.
Record the decision in `PLAN.md` with its date if it is a design decision,
otherwise in the body of the commit that applies it.

When round 3 ends with no open findings or disagreements and every check
passes, the owner fast-forwards `main` to the branch, or tells an agent to.
