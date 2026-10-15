# Contributing

The relay holds a customer's login credential and parses tokens from callers
it has not yet authenticated, so nearly every line is security code.
`PLAN.md` says what the relay does; this file says how its code is written.
Report vulnerabilities privately as described in `SECURITY.md`, never in a
public issue.

## Principles

- **Fail closed.** Every error path, missing value and zero value denies.
- **Standard library only** (`PLAN.md` D2). Tools such as `staticcheck` run
  with `go run <module>@<version>` or a separate install; never `go get -tool`,
  which adds them to `go.mod`.
- **Write what the plan asks for, nothing more.** No settings, interfaces or
  extension points without a plan entry. Delete unused code.
- **Small over clever.** Prefer one clear function to three generic ones, so
  a reviewer can see every path to "allow".

## Go style

Follow [Effective Go], [Go Code Review Comments] and the [Google Go Style
Guide]; where they differ from this file, this file wins. On top of them:

- **Packages** follow `PLAN.md` §11, all under `internal/`. No `util`,
  `common` or `helpers`. No package-level mutable state and no `init`.
  Dependencies are passed in explicitly.
- **Names** use the plan's terms (FIT, snapshot, route, upstream) and Go
  initialisms (`ID`, `URL`, `JWKS`, `FIT`). Short names in short scopes,
  descriptive ones at package level. No `Manager`, `Service` or `Helper`
  suffixes.
- **Interfaces** are declared by the consumer, with the fewest methods it
  needs, and only when there are two implementations. A test seam counts as
  one (the clock and the JWKS fetcher, `PLAN.md` §13).
- **`context.Context`** is the first parameter of anything that does I/O or
  waits, and is never stored in a struct.
- **Goroutines** belong to a component that starts and stops them and
  documents how each one exits. Handlers start none (`PLAN.md` §6, R-6).
  Shared state is an immutable snapshot behind `atomic.Pointer`, or a mutex
  whose comment names the fields it guards.
- **Limits and timeouts** are named constants or settings, never inline
  numbers. Arithmetic on sizes or durations from input or configuration is
  checked for overflow.
- **Current standard-library APIs** (`slices`, `maps`, `min`, `max`,
  `errors.Join`) over hand-written equivalents.

## Comments and documentation

The reader is a competent developer who is new to Go and to Forge remotes.
Comments give them what the code cannot: why it is this way.

- Every package has a package comment that says what it does and which
  `PLAN.md` sections it implements.
- Every exported identifier has a doc comment that starts with its name,
  in [Go doc comment] syntax. Unexported ones get one when the reason is not
  obvious from the code.
- Explain the threat, the plan rule or the Forge behaviour behind a check,
  and cite it (`PLAN.md` §4.4). Explain a Go idiom only when it carries
  security weight, for example why `http.MaxBytesReader` and not a plain read.
- Keep comments true. A change that makes a comment wrong updates it in the
  same commit.
- Every `.go` file starts with `// SPDX-License-Identifier: EUPL-1.2`,
  followed by a blank line so it stays out of the package documentation.

Not allowed: comments that restate the code, section banners, commented-out
code, `TODO` without a `PLAN.md` item, and words like "robust",
"comprehensive" or "seamless".

## Errors

- Handle every error. `_ =` on an error needs a comment saying why.
- Error strings are lowercase, without trailing punctuation, and add context
  rather than repeat it: `parse jwks: %w`, not `failed to parse JWKS: %w`.
- Either log an error or return it, never both.
- Errors that may contain untrusted input or secrets never reach a log line
  or a response. At those boundaries, map them to the fixed classes of
  `PLAN.md` §4.3 and §10 with `errors.Is` or `errors.As`.
- `panic` is for programmer errors only. The recover middleware is a safety
  net, not control flow.

## Security rules for code

- **Parse once, at the boundary.** Untrusted input becomes a typed value
  (claims, a matched route) in one place; the code after it takes that type,
  not strings.
- **Match exactly.** Comparisons are exact and case-sensitive unless the plan
  says otherwise. Do not apply `strings.EqualFold`, `strings.TrimSpace`,
  `path.Clean`, URL resolution or `http.ServeMux` patterns to security input
  without a plan rule that asks for it (`PLAN.md` §4.2, §5).
- **Bound everything.** Every read has a size limit, every network call a
  deadline, every queue and channel a capacity.
- **Secrets cannot print.** The credential is held in a type whose `String`,
  `GoString` and `LogValue` return a redaction marker. `fmt` cannot call
  those methods through unexported fields, so a struct that holds the
  credential is never printed whole; the startup summary lists settings one
  by one (`PLAN.md` §10).
- **Explicit HTTP.** No `http.DefaultClient`, `http.DefaultServeMux`,
  `http.ListenAndServe` or `net/http/pprof`; every client and server is built
  with the timeouts in `PLAN.md` §5 and §6.
- **No `unsafe`, `reflect`, `import "C"` or `os/exec`.** Random values come
  from `crypto/rand`.
- **Logs** use `log/slog` with the fixed keys in `PLAN.md` §10. Values are
  constants or verified data; never raw input.

## Tests

- Standard `testing` and `httptest` only, no assertion libraries.
- Every rejection rule in the plan has a test that fails if the rule is
  removed. Name tests and table cases after the rule they prove
  (`expired_beyond_skew`), not after the function (`TestVerify2`).
- Table-driven tests when cases share a shape; separate tests when they do
  not.
- Contract tests (`PLAN.md` §4.6) spell header names, error codes and
  setting names as literals, not through the production constants, so a
  rename breaks a test. Changing such a fixture is a protocol change.
- No sleeps and no outside network. Time comes from an injected clock;
  servers are `httptest` on loopback.
- Keys are generated during the test run, once per package. No private keys,
  live tokens or real IDs are committed; synthetic UUIDs only.
- Parsers have fuzz tests with a seed corpus in `testdata/fuzz/`.
- Coverage is not a target. Tests that only check that a mock was called do
  not count.

## Commits

- One logical change per commit, with `gofmt`, `go vet`, `staticcheck`,
  `go test -race` and `govulncheck` passing (see `AGENTS.md`).
- Subject: imperative, at most 72 characters (`Reject FITs with a crit
  header`). Body: why, and the `PLAN.md` section involved.
- A change that alters a plan decision updates `PLAN.md` in the same commit,
  with the date.
- Nothing is committed that could not be public: no secrets, keys, customer
  names, internal hostnames or live tokens.

## Review checklist

Every change is reviewed against this list before it reaches `main`.

1. It implements a `PLAN.md` rule for the current phase, and no more.
2. Every path to "allow" is reachable only after every required check.
3. Every input is bounded and every limit named.
4. No untrusted data or secret can reach a log line or response.
5. Each failure case has a test that would fail without the check.
6. Goroutines have an owner and an exit; `-race` passes; cancellation works.
7. The protocol in `PLAN.md` §4 is unchanged, or §4.6 was followed.
8. `go.mod` has no `require` lines.
9. Comments are accurate and explain why; nothing restates the code.
10. Nothing is unused, duplicated or more general than needed.

[Effective Go]: https://go.dev/doc/effective_go
[Go Code Review Comments]: https://go.dev/wiki/CodeReviewComments
[Google Go Style Guide]: https://google.github.io/styleguide/go/
[Go doc comment]: https://go.dev/doc/comment
