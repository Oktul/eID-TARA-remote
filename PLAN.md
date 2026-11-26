# eID TARA Remote — Plan

_Status 2026-11-26: Phases 1 and 2 are implemented ahead of Phase 0 (D10)
and checked locally and in CI (§16). Phase 0 ran on 2026-10-16: every gate
passed except PINNED, which needs a site with data residency (§14). Phase 3
is on the Forge app's main line since 2026-10-18 (owner's go-ahead); a TARA
demo login went through a local relay on 2026-10-20, and TARA live waits
for a live client and a registered IP. Every code change on `main` was
reviewed by an agent that did not write it, with no open findings; the
owner merged the 2026-10-21 test fix and Go 1.27.3 toolchain without a
Codex round, and the 2026-11-19 Go 1.27.4 toolchain and documentation
corrections, the 2026-11-24 `LICENSE`, `SECURITY.md`, licence copy in
the image and plan hash remap, and the 2026-11-26 name alignment with no
second agent's review (§16). An end-to-end security review on 2026-10-20 refused
everything it should; of its low and info findings, SR-4, SR-5, SR-8 and
SR-9 are fixed, the owner decided SR-5, SR-6 and SR-7, and SR-1 (FIT
replay) is closed without a fix, since a spike showed Forge reuses FITs
across calls (§14 Phase 4). The soak passed on 2026-10-21 (§13). The
toolchain is Go 1.27.4 since 2026-11-19 (GO-2026-6859, §16). `LICENSE` and
`SECURITY.md` are in since 2026-11-24, and the image carries the licence
text (§7, §16). `main` is in the repository `Oktul/eID-TARA-remote` since
2026-11-24, with its history rewritten to one author, and the repository is
public since 2026-11-26 (§16); `ci` runs on every push. The image is
`ghcr.io/oktul/eid-tara-remote`; `v1.0.0` is tagged on `release/1.0` on
2026-11-26, before the acceptance runs, which need a published image (§14
Phase 5, §16). Still open: the PINNED gate, the other acceptance runs of
§13 and the Phase 2 release verifications._

## 1. What it is

A small container, "the relay", that a customer runs in their own network. It
lets the Oktul eID SSO Forge app call TARA's token endpoint from an
allowlisted IP address (blocker B9 in the Forge app's plan). It forwards
only `POST /oidc/token`; other providers and endpoints are outside v1
(owner, 2026-10-17, D11).

- TARA sees the customer's own static IP.
- The TARA client secret lives only in the customer's relay, never in Forge
  or with us.
- Only requests that Atlassian signed for our app, on the customer's own site
  and Forge environment, get through.

This plan builds on three inputs from 2026-10-15: _Forge Relay –
Requirements_, two independent stack analyses, and the relay design in the
Forge app's `PLAN.md` §4.7 (2026-09-29). Where it changes the requirements,
§9 lists the change and the reason.

**Normative scope (2026-10-15 review).** This file is the complete local
implementation contract. Labels such as A-3, K-5 and V-4 are historical
traceability labels from the input requirements, which are not in this
repository; they do not import unwritten requirements. The rules, failure
cases and acceptance gates are stated here. Provider or Forge behavior that
still needs evidence is explicitly gated in §14 and §15.

## 2. Decisions (owner, 2026-10-15)

| #   | Decision                                                                                                               | Why                                                                                                                                                                                                                                            |
| --- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | **Customers run relays. We host none in v1.**                                                                          | Removes the relay key pair, end-to-end JWE, fingerprint pinning and key rotation from §4.7. No processor chain through a cloud provider: the customer runs the hop and is the controller. An Oktul-hosted relay can come later as protocol v2. |
| D2  | **Go and its standard library only. No third-party modules** (2026-10-15; was `go-jose/v4`).                           | The standard library covers HTTPS, JSON, RSA, timeouts and cancellation. The FIT is always RS256, so `crypto/rsa` checks it in a few lines, and every update becomes a Go patch, which ships automatically (D4). §7.                           |
| D3  | **Separate repository `eID-TARA-remote`, private at first** (public since 2026-11-26). Published under EUPL-1.2 before the first customer. | Different language, toolchain and release lifecycle from the Forge app, which stays closed. Customers must be able to pull the image without credentials and audit the code they run.                                                          |
| D4  | **CI on GitHub Actions. Go patch releases ship automatically;** every other change needs a human merge (2026-10-15).   | Go's `net/http` and `crypto/tls` get security fixes several times a year. A Go patch release carries only such fixes and the tests pin the protocol, so it ships unreviewed. Go minors and Actions can change more. §12.                       |
| D5  | **Every relay is pinned to the customer's site (`cloudId`) and Forge environment. Both are required settings.**        | The FIT's audience is our app ID, shared by every install. Without a pin, another site's admin could point their install at this relay and use the customer's IP and credential.                                                               |
| D6  | **No end-to-end encryption in v1.** TLS from Forge to the customer's reverse proxy, then plain HTTP inside their host. | With D1, everything that can read the traffic is the customer's own infrastructure.                                                                                                                                                            |
| D7  | **An upstream answer always comes back as `200` with the upstream status in `Relay-Upstream-Status`.**                 | Keeps upstream status distinct from relay errors: a provider's `401 invalid_client` must not look like the relay's `401 invalid_token`. Phase 0 found that backend `invokeRemote` also returns non-2xx answers intact (§14, 2026-10-16); v1 wrapping stays unchanged. |
| D8  | **Limits sized for token calls:** 10 s upstream timeout; 64 KiB request and response limits and 50 concurrent requests, fixed rather than settings (owner, 2026-10-16). | A provider's authorization code lives about 30 s, and a token request and response are a few KB. Fixed limits keep the memory bound a constant far below 128 MB (§6) and remove three settings and their budget check. |
| D9  | **Code conventions in `CONTRIBUTING.md`. Claude writes, Codex reviews and fixes, Claude reviews again** (2026-10-15).   | The code is public and security-critical but small, so it must be documented and concise. A second agent catches what the author misses; disagreements between them go to the owner (`AGENTS.md`, Review).                                     |
| D10 | **Implement Phases 1 and 2 in this repository now, before the Phase 0 spike** (2026-10-15).                             | The owner asked for all code that belongs in this repository. Phase 0 still gates the Phase 1 exit and any tag (§14): the missing-site fallback shipped disabled and was removed on 2026-10-16 (§4.4), and no gate counts as passed until it is recorded here.                       |
| D11 | **TARA token exchange only** (owner, 2026-10-17). Fix the route to `POST /oidc/token`, the upstream to an HTTPS origin without a base path and response headers to `Content-Type`, `Cache-Control`, `Pragma`; remove `RELAY_ROUTES` and `RELAY_RESPONSE_HEADERS`. | The relay serves this app's TARA token exchange. Configurable routes, base paths, response headers and other-provider setup add code and settings without a current use case. The existing optional credential setting is unchanged; the supported TARA setup supplies Basic authentication. No release exists, so these changes belong to the first protocol-v1 release. |

## 3. Request flow

```
 Atlassian cloud            Customer network (static outbound IP)
┌───────────────┐        ┌──────────────────────────────────────┐
│ Forge app /cb │──(1)──▶│ Reverse proxy ──(2)──▶ Relay         │──(3)──▶ Provider token endpoint
│ invokeRemote  │        │ (customer TLS)         (verifies FIT) │         (allowlists the
└───────────────┘        └───────────────────────────┬──────────┘          customer's IP)
┌───────────────┐                                    │
│ Atlassian     │◀────── fetch and cache signing keys ┘
│ JWKS          │
└───────────────┘
```

1. `/cb` calls `invokeRemote('token-relay', …)`. Atlassian adds a FIT signed for our app.
2. The customer's reverse proxy terminates TLS and passes the request to the relay.
3. The relay verifies the FIT and the route, adds the customer's credential
   and calls the provider from the customer's static IP. The answer goes back
   unchanged in the body (D7).

The Forge app still validates the ID token itself and fetches the provider's
JWKS directly, so the relay cannot fake a login.

## 4. Protocol v1

The contract between the Forge app and the relay. It is versioned; the Forge
app supports every protocol version still supported (V-2).

### 4.1 Endpoints

| Endpoint             | Auth | Purpose                                                                                                                                                                                 |
| -------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /livez`         | none | The process is running. Contacts nothing (O-1).                                                                                                                                         |
| `GET /readyz`        | none | A usable signing-key snapshot is within its maximum age and the relay is not shutting down (O-2; §4.5).                                                                                |
| `GET /relay/v1/info` | FIT  | Relay version, protocol version, upstream origin, the fixed token route, whether a credential is set (never its value). Used by the admin page's health check and its "relay too old" message. |
| `POST /oidc/token`  | FIT  | Forwarded to TARA's token endpoint.                                                                                                                                                    |

Only the token route is forwarded. Health and info are local endpoints;
every other method and request target is refused after authentication.

**Bodies (2026-10-15).** `/livez` and a ready `/readyz` answer `200` with
`{"status":"ok"}`; an unready `/readyz` answers `503 not_ready` as in §4.3.
`/relay/v1/info` answers `200` with
`{"relay_version":"1.2.0","protocol_version":1,"upstream_url":"https://tara.ria.ee","routes":["POST /oidc/token"],"credential_set":true}`,
where `upstream_url` is the configured HTTPS origin. Relay error
bodies are exactly `{"error":"<code>"}` with `Content-Type: application/json`.

### 4.2 Checks, in order

Exact `GET /livez` and `GET /readyz`, without a query, bypass FIT verification
and the forwarding semaphore. They never contact the upstream or JWKS.
All other requests follow the checks below; after authentication,
`GET /relay/v1/info` is handled locally rather than forwarded. No router may
clean paths, redirect them or implicitly accept `HEAD` for `GET` before
these checks.

1. If no usable, unexpired key snapshot is available, answer `503 not_ready`.
   Otherwise verify the FIT (§4.4), or answer `401 invalid_token`.
2. Require exactly `POST /oidc/token`, or answer
   `404 route_not_allowed`. The FIT check comes first, so a caller without a
   valid token learns nothing about the token route.
3. Take a concurrency slot without waiting, or answer `503 too_busy` (R-5).
   Only an authenticated token POST takes one, so callers without a valid
   FIT, including those waiting for an unknown key, cannot crowd out token
   exchanges; the proxy's connection limit (§6) bounds them instead (owner,
   2026-10-20, SR-2 in §16; it was the first check).
4. Read the body up to the limit, or answer `413 body_too_large`.
5. Forward (§5).

### 4.3 Responses

- **The upstream answered, with any status:** `200`, `Relay-Upstream-Status: <code>`,
  the upstream body unchanged, and only the allowed response headers.
- **The relay answers itself:** its own status, `Relay-Error: <code>`, and a
  JSON body `{"error":"<code>"}`. Codes are stable across versions (F-9):

| Status | Code                   | When                                                        |
| ------ | ---------------------- | ----------------------------------------------------------- |
| 401    | `invalid_token`        | Any FIT failure, with no detail (A-7)                       |
| 404    | `route_not_allowed`    | Method and path not allowed, a query string, or an odd path |
| 413    | `body_too_large`       | Request body over the limit                                 |
| 500    | `internal_error`       | A recovered internal error (R-6)                            |
| 502    | `upstream_unreachable` | DNS, connection or TLS failure to the upstream, or an answer that is not valid HTTP/1.1, including a status line other than HTTP/1.1 (HTTP/1.0 included, 2026-10-16), a final status below 200 and a header over 32 KiB (2026-10-15) |
| 502    | `upstream_too_large`   | Upstream body over the limit                                |
| 503    | `not_ready`            | No usable keys loaded, or their maximum age is reached (K-5) |
| 503    | `too_busy`             | Concurrency cap reached                                     |
| 504    | `upstream_timeout`     | Upstream timeout reached                                    |

- **Every application-generated response**, including health and overload
  responses, carries `Relay-Protocol: 1` (F-8). Errors rejected by the HTTP
  server before a handler runs, or generated by the reverse proxy, cannot
  promise relay headers. The HTTP server's own refusals are still logged
  (§10, SR-9). Neither can a request whose body cannot be read for
  a reason other than its size (the client left, timed out or sent broken
  chunked framing): the relay closes the connection without an answer
  (2026-10-15). `Relay-Version`
  (the release, for example `1.2.0`) is sent only on FIT-authenticated
  responses, so an anonymous scanner cannot read the version.
- **Caching and sniffing (owner's review, 2026-10-20, SR-8).** Every
  application-generated response carries `X-Content-Type-Options: nosniff`.
  Relay errors, health and info answers carry `Cache-Control: no-store`; a wrapped upstream answer
  keeps the upstream's `Cache-Control` and gets `no-store` only when the
  upstream sent none, since a token answer must never be stored (RFC 6749
  §5.1). Both are additions under §4.6: no client reads them, and the Forge
  app ignores them.

### 4.4 FIT verification

Claim names checked against Atlassian's _Forge Remote essentials_ on 2026-10-15.

- Require exactly one Authorization field with the case-insensitive scheme
  `Bearer`, one separating space and a non-empty compact JWS, without other
  whitespace or comma-joined credentials. The JWS header must name
  `alg: RS256` and a `kid`; any other algorithm is refused (A-2).
- `iss` is the exact string `forge/invocation-token`. `aud` is either the
  exact `RELAY_APP_ID` string (`ari:cloud:ecosystem::app/<uuid>`) or a
  non-empty array of non-empty strings containing that exact value (A-3).
- `exp` and `nbf` are required NumericDate JSON numbers in plain decimal
  notation: digits with an optional fraction. Parse them without float
  rounding or integer overflow; accept fractional seconds, bounded to the
  Unix-second interval 0 through `MaxNumericDateSeconds = 253402300799`
  inclusive. Exponent notation (`1.8e9`) is refused (owner, 2026-10-16): no
  JWT library writes a date that way, since JavaScript and Go switch to it
  only from 10²¹, and refusing it shrinks the parser to a few lines. Phase 0
  recorded the dates only as numbers, so fractions stay accepted. Require
  `exp > nbf`, `now < exp + skew` and `now + skew >= nbf` (A-4).
  Missing, null, string or out-of-range dates fail closed. Atlassian's
  example token lives 25 s; the relay does not depend on that lifetime
  beyond the cap below.
- **Lifetime cap and `iat` (owner, 2026-10-20, SR-6: "keep 5 minutes").** `exp - nbf` must be at
  most `MaxLifetime = 5 minutes`, or the token is refused with
  `auth_reason` `lifetime`. A FIT is usable about 25 s after it is issued
  (Phase 0), and its `exp - nbf` is 55 s, since Forge sets `nbf` 30 s
  before `iat` (SR-1 spike, 2026-10-20). The cap therefore leaves more
  than fivefold room before a longer Forge lifetime breaks relays. `iat`
  stays ignored: every FIT carries it, but Forge does not document it,
  and `nbf` already bounds the start. A tighter cap would not stop replay
  either: Forge reuses one FIT for several calls, so a FIT cannot be made
  single-use (SR-1, §14), and the cap only refuses tokens Forge did not
  mint. No pin on the remote key: the app has one remote, and Phase 0
  did not record which claim names it on this call path. The cap narrows
  the accepted contract; no relay is released, so under §4.6 it is part of
  the first release.
- `app.environment.id` = `RELAY_ENVIRONMENT_ID` (D5). Forge sends the
  environment's ARI, `ari:cloud:ecosystem::environment/<app>/<environment>`,
  not the bare environment UUID (Phase 0, 2026-10-16), so the setting holds
  the ARI.
- **Site pin (D5):** `context.cloudId` must be present and a non-empty
  string in `RELAY_CLOUD_IDS`. A missing, malformed, null or disallowed value
  is rejected. If installation contexts also contain cloud IDs, they must
  include the invocation site; they can never stand in for it. Multiple
  configured allowed sites do not relax this rule. (Until 2026-10-16 the plan
  allowed an installation-context fallback for a missing invocation site,
  gated on Phase 0; Phase 0 found `context.cloudId` on this app's backend
  invocation path, so the fallback was removed from code and plan, owner,
  2026-10-16, §14.)
  No unsigned request header or body field can provide the site pin.
  The site ID stays stable on reinstall, unlike `app.installationId`.
- `app.installationId` is in `RELAY_INSTALLATION_IDS`, only if that is set
  (an optional extra pin).
- A token with `icLabel` (Isolated Cloud) is refused: its keys live at
  another JWKS URL, and we do not support Isolated Cloud.
- Other claims are ignored, so new claims never break an old relay (A-5).
- **The relay does the token mechanics itself, with the standard library**
  (D2, 2026-10-15). It supports exactly one form, so there is nothing to
  negotiate:
  1. the token is at most 8 KiB (a named constant) and splits on `.` into
     exactly three non-empty parts;
  2. the header is strict base64url (no padding) and JSON. `alg` must be
     exactly `RS256` and `kid` a non-empty string. Any `crit`, `jku`, `jwk`,
     `x5u`, `x5c`, `zip` or `b64` member is refused, including a null value,
     and keys only ever come from the cache (§4.5);
  3. the signature is checked with `crypto/rsa.VerifyPKCS1v15` over the
     SHA-256 of the first two parts exactly as received;
  4. only after a valid signature is the payload decoded and each claim
     checked. All three compact parts use strict, unpadded base64url;
     whitespace, non-URL characters and non-canonical encodings are refused.

  The decoded header and payload must each be exactly one UTF-8 JSON object,
  with no trailing value, invalid Unicode or duplicate member names at any
  nesting level. Member-name matching is case-sensitive, including inside
  `app` and `context`; struct decoding must not silently match `ISS` to
  `iss`. Required objects and claims reject absence, null and wrong types.
  Optional pin claims reject malformed values when supplied. Unknown ordinary
  claims remain allowed, but are still subject to JSON validity and duplicate
  detection. Duplicate detection compares decoded member names, including
  escaped spellings. Parser size is determined by these rules, not a line
  budget.

  Tests cover every failure (§13), including a fuzz test of the parser.
  No default of any library defines the contract.

  **Implementation details (2026-10-15).** A NumericDate with a minus sign
  is refused, even `-0`. Dates are compared exactly at nanosecond
  resolution: for the validity window, a fractional `exp` rounds down and
  `nbf` rounds up. The lifetime cap uses `exp` rounded up and `nbf` rounded
  down (review fix, 2026-10-20), so sub-nanosecond rounding can only reject
  in either check. JSON documents nest at most
  16 levels; a FIT payload uses five (`app.installation.contexts[i]`), so
  the bound only refuses hostile input.
- The response never says which check failed. The log does (`auth_reason`,
  for example `audience` or `cloud_id`), which is what an operator needs.

### 4.5 Signing keys

- Fetch at startup without exiting on network failure; readiness stays false
  until a usable snapshot is loaded. Retry failures with exponential backoff
  from `JWKSRetryInitial = 1s` up to `JWKSRetryMax = 1m`. Refresh successful
  snapshots every `RELAY_JWKS_REFRESH` (default 6 h).
- Keep the last good snapshot through failed refreshes, but only until
  `RELAY_JWKS_MAX_AGE` (default 24 h) since its last successful fetch. At that
  age, readiness becomes false and protected endpoints answer `503 not_ready`.
  A successful usable refresh restores readiness. This explicitly permits
  at most 24 h of stale-key trust (of running time) by default during an
  outage; an operator may shorten the window. Require
  `0 < refresh < max age` at startup. The age is measured on Go's monotonic
  clock (owner, 2026-10-16), so a wall-clock step cannot expire good keys or
  revive old ones. On Linux that clock stops while the host is suspended,
  so after a resume a snapshot can be older than `RELAY_JWKS_MAX_AGE` in
  wall time: the next refresh, due within one refresh interval of running
  time, replaces it if it succeeds, and otherwise the maximum age of
  running time applies.
- One refresh worker serves startup, retries, periodic refreshes and all
  unknown key IDs. There is at most one network fetch in flight per cache,
  and unknown-key-triggered fetch starts are globally limited to once per
  `JWKSUnknownRefreshInterval = 1m`, regardless of the IDs supplied. Requests
  do not create goroutines or an unbounded queue of IDs.
- Unknown-key requests share the current refresh and wait at most
  `FITKeyWait = 1s`, further bounded by caller cancellation. If no key is
  available then, they return `401 invalid_token`; they never reach the
  upstream. The worker's lifecycle belongs to the process, not to the first
  waiting caller. Known-key verification uses an immutable snapshot without
  waiting for network I/O. The cooldown can delay acceptance of a newly
  rotated key; neither the relay nor Forge automatically replays a token
  exchange to hide that failure.
- The relay parses the JWKS itself with `encoding/json`. Eligible keys have
  `kty: RSA`, `use` absent or `sig`, `alg` absent or `RS256`, a non-empty
  string `kid`, and a modulus of at least 2048 bits. Unsupported key types,
  uses or algorithms and undersized keys are skipped with a fixed log reason;
  malformed parameters on an otherwise eligible RSA key fail the refresh.
  At most 20 keys are kept; the JWKS response is capped at 64 KiB and the
  fetch at 10 s.
- JSON must satisfy the strict object rules in §4.4. Duplicate key IDs,
  more than 20 usable keys, an empty usable set, invalid RSA parameters or a
  malformed document make the refresh fail atomically. Do not truncate the
  set or reset its successful-fetch time. A successful refresh replaces the
  entire snapshot, so removed keys stop being trusted immediately; do not
  merge historical keys into it. Logs contain fixed reasons, never raw keys
  or attacker-selected key IDs.
- The JWKS URL must be HTTPS. Default:
  `https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json`.
- **Implementation details (2026-10-15).** `n` and `e` are strict base64url
  without a leading zero octet. `e` is odd and between 3 and 2³¹−1, and the
  modulus is odd and has at most `MaxRSAModulusBits = 8192` bits, which
  bounds the cost of verification; `crypto/rsa` would refuse to verify with
  an even modulus or exponent, so such a key fails the refresh at once
  instead of failing every FIT later. A violation counts as invalid RSA
  parameters. These checks apply only to an otherwise eligible key: an RSA
  signing key whose strictly decoded modulus is under 2048 bits is skipped
  as undersized before `e` and the modulus parity are judged (2026-10-16).
  A malformed `n`, or a missing or empty `kid`, still fails the refresh,
  since only type, use, algorithm and size are reasons to skip. The JWKS fetch does not follow redirects, holds no idle
  connection and asks for no compression, so the size cap applies to the
  bytes received; its response header is capped at 32 KiB, and the TLS
  handshake and dial have their own timeouts. Only a `200` answer counts as
  a successful fetch. Skipped keys are logged as one count per reason, never
  per key.
- **Padded key parameters (owner, 2026-10-16).** `n` and `e` may also carry
  exactly the `=` padding that completes their last base64url quantum. RFC
  7518 §6.3.1 says unpadded, but Atlassian's live JWKS pads every `n`
  (Phase 0 dry run, 2026-10-16), so a relay that refused it never became
  ready. Any other `=` fails the refresh as invalid parameters: a wrong
  count, padding on a value that needs none, padding alone or inside the
  value. The decoded value must still be canonical (no stray trailing bits)
  and have no leading zero octet. FIT parts stay strictly unpadded (§4.4):
  a token's encoding is what is signed, while a key's two spellings decode
  to the same number. This broadens accepted input, so under §4.6 it ships
  in a minor release, never as an automatic patch; no release exists yet,
  so it is part of the first.

### 4.6 Compatibility and conformance (2026-10-15)

- The normative protocol consists of §4, forwarding behavior in §5 and the
  setting names, defaults and validation rules in §8. `docs/PROTOCOL.md`
  publishes the same contract; it must not introduce a second competing
  definition.
- Patch releases preserve that contract. Compatible additions require a
  minor release; incompatible endpoint, response, header, setting or pin
  changes require a new protocol version and relay major release. Existing
  versions continue to work for their support window (§12). Security fixes
  may enforce an already-documented rejection rule; broadening or changing
  the accepted contract is not an automatic toolchain patch.
- The Forge app must accept every supported protocol version. A minimum
  relay version and the admin warning cannot silently remove support before
  the published end-of-support date. Emergency exceptions require an owner
  decision recorded here and explicit customer upgrade instructions.
- Contract fixtures cover each application response code and header, health
  exemptions, info output, configuration defaults and rejection behavior.
  Introduce them in Phase 1 and reuse them for each supported release line.

## 5. Forwarding

- **Destination:** `RELAY_UPSTREAM_URL` is an HTTPS origin, one of TARA's
  two unless overridden (§8, SR-5); the relay always
  sends `POST` to its fixed `/oidc/token` path (owner, 2026-10-17, D11).
  Nothing in the request can change the scheme, host, port or path (F-3).
  The configured URL must have a host and no userinfo, query, fragment or
  path, except an optional root `/` that is normalized away.
- **Paths:** exact match only. A path with `..`, `//`, a backslash, an
  encoded slash or dot, or non-ASCII characters is refused. Query strings are
  refused in v1, since token calls have none.
  The raw request target must be exactly `/oidc/token`, without cleaning or
  decoding, and the method must be exactly `POST`.
- **Request headers:** `Host` becomes the upstream host. Only `Content-Type`
  and `Accept` pass from the caller, a fixed allowlist since a token call
  needs no other (owner, 2026-10-16; `RELAY_REQUEST_HEADERS` was removed
  before the first release). `Authorization`, hop-by-hop headers,
  `x-forge-oauth-*`, `x-b3-*`, idempotency headers and everything else are
  dropped, and so is an allowed header that `Connection` names. The relay's
  HTTP client adds `Content-Length` and its own `User-Agent`, Go's default,
  never the caller's (existing behaviour, written down 2026-11-19). The
  configured credential header is set last, so a caller cannot override it.
  The relay adds no `X-Forwarded-For`.
  The credential setting may supply `Authorization`, but cannot supply
  routing, framing, hop-by-hop, idempotency or relay-owned headers. Apply
  exclusions case-insensitively. Validate header names and reject CR/LF in
  configured values without printing them.
  The credential value also refuses every other control character except
  tab (2026-10-15).
- **Credential:** the supported TARA setup uses `client_secret_basic`,
  stored in the relay as `Authorization: Basic <credentials>`. Form-encode
  the client ID and secret separately, join them with `:`, then Base64-encode
  the result. TARA defaults to Basic; its official specification also
  permits `client_secret_post` for clients registered for that method.
  No body-credential feature is added here. The existing optional
  `Name: value` setting remains unchanged, including for synthetic fixtures.
  [TARA's token request specification](https://e-gov.github.io/TARA-Doku/TechnicalSpecification#43-identity-token-request)
  checked on 2026-10-17 (R12).
- **Response:** read up to the limit before anything is sent, so an oversize
  answer becomes a clean `502 upstream_too_large` (R-4). The response header
  is capped at `UpstreamMaxHeaderBytes = 32 KiB` before that limit applies
  (2026-10-15). Only `Content-Type`, `Cache-Control` and `Pragma` pass
  (owner, 2026-10-17, D11). Headers nominated by `Connection` are dropped
  even when in this fixed list. The relay adds `nosniff` and, without an
  upstream `Cache-Control`, `no-store` (§4.3, SR-8). The relay computes framing and sets
  its own protocol, version, upstream-status and error headers last. Upstream
  headers can never impersonate a relay error or change its protocol metadata.
- **Upstream client:**
  - redirects are not followed;
  - automatic decompression is off, so the body really is unchanged;
  - TLS 1.2 or later;
  - optionally only the CAs in `RELAY_UPSTREAM_CA_FILE` are trusted
    (TARA's documented trust anchors, R12);
  - HTTP/1.1 only;
  - connections are reused, with at most 10 idle per host (R-9);
  - a 30 s dial timeout and a 10 s TLS handshake timeout, because Go dials
    on a context detached from the request, so a stalled handshake would
    otherwise outlive it (2026-10-16; the JWKS client too).
- **No application retries (R-8).** A token exchange may have consumed the
  one-time code even if its response was lost. Neither the relay, the supplied
  proxy configuration nor Forge automatically retries that exchange. Drop
  idempotency headers and do not mark token POSTs as idempotent or provide a
  replay callback. Go's transport may recover a reused connection when
  nothing was written, or retry an idempotent GET; this does not authorize a
  second token POST after a possibly delivered request. Without a replay
  callback, Go does not resend a token POST with a body even when nothing
  was written; that rare case answers 502 `upstream_unreachable`
  (2026-10-16). Test the distinction
  with a connection that fails after receiving the token request.
- **Cancellation:** the caller's disconnect cancels the upstream call (R-3).
- **Outbound proxy:** `HTTPS_PROXY` and `NO_PROXY` are honoured for the
  upstream and the JWKS (standard library behaviour). Public-sector networks
  often send egress through a proxy; the startup log says when one is in use.

## 6. Robustness

| Requirement | How                                                                                                                                                                                                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R-1         | `http.Server` with `ReadHeaderTimeout` 5 s, `ReadTimeout` 10 s, `WriteTimeout` = upstream timeout + 5 s, `IdleTimeout` 60 s, `MaxHeaderBytes` 16 KiB.                                                                                                                        |
| R-2, R-3    | One context per request with the upstream timeout. It ends when the caller disconnects.                                                                                                                                                                                      |
| R-4, R-12   | Bounded reads on both sides, with fixed limits (D8): 50 concurrent requests × (64 KiB request + 64 KiB response) = 6.25 MiB of bodies at once. `GOMEMLIMIT=96MiB` in the image; the container limit is 128 MB. |
| R-5         | A semaphore (buffered channel) acquired without waiting.                                                                                                                                                                                                                     |
| R-6         | A recover middleware turns a panic into `500 internal_error` and a log line with the error class only. Handlers start no goroutines, so every panic is caught there.                                                                                                         |
| R-7         | The key refresh loop recovers from panics and keeps its backoff schedule.                                                                                                                                                                                                    |
| R-10        | No disk writes. The image has no writable path and runs with a read-only root filesystem.                                                                                                                                                                                    |
| R-11        | On SIGTERM or SIGINT: `/readyz` turns false, the server stops accepting, in-flight requests finish within `RELAY_SHUTDOWN_GRACE` (15 s), the key loop stops, and the process exits.                                                                                          |
| R-13        | All settings are parsed and checked before the listener opens. The first error names the setting and exits with code 2. An unreachable upstream or JWKS never stops startup.                                                                                                 |

**Write deadline (2026-10-15).** net/http starts `WriteTimeout` when the
request header has been read, so a slow body or an unknown-key wait would
use up time the answer needs, and a token exchange could succeed upstream
while its answer is dropped (R-8). The relay therefore restarts the write
deadline, upstream timeout + 5 s, once the body has been read or refused,
so a 413 gets the same budget (2026-10-16). Any local answer before the
body is read closes the connection when a body is declared or chunked, so
net/http cannot wait to drain that refused body before flushing the answer
(2026-10-16). Successful full reads preserve connection reuse. A 413 also
closes the connection (`Connection: close`) instead of reading the refused
body to keep the connection; when the limit is hit while reading, net/http
half-closes and waits briefly first, so a client still sending reads the
413 rather than a reset.

The 6.25 MiB body bound is a partial budget, not a proof of total memory
use: buffer growth, HTTP/TLS state, goroutine stacks and the runtime come on
top. `GOMEMLIMIT` is a
soft GC target, not a hard cap. Acceptance measures container memory under
the complete workload (§13).

The reverse proxy must limit open connections, including clients still
reading headers and idle keep-alives. The supplied deployment uses named
limits, initially `ProxyMaxConnections = 100` to the relay and
`ProxyReadHeaderTimeout = 5s`; verify or lower them during acceptance. A
proxy that cannot enforce them needs an equivalent documented ingress limit.
The proxy closes its idle connections to the relay before the relay's 60 s
`IdleTimeout` does (the supplied Caddyfile uses 50 s), so a token POST is
never written onto a connection the relay is closing (R-1, R-8; 2026-10-15).
The relay port is reachable only by that proxy and local/cluster health
probes, never directly from the public network. Health probes bypass the
forwarding semaphore, so a full relay answers `503 too_busy` to token
calls without causing a liveness restart. The relay serves plain HTTP
only; TLS is the proxy's job (D6). Built-in TLS (`RELAY_TLS_CERT_FILE`, `RELAY_TLS_KEY_FILE`, S-10)
was removed before the first release (owner, 2026-10-16): it served only a
relay exposed without a proxy, which this section does not support, and a
customer who wants TLS on the internal hop adds it with a sidecar or mesh.

## 7. Stack and image

- **Language:** Go, the newest supported release (check the patch level on
  the day the build starts). The toolchain is pinned in `go.mod`.
- **HTTP:** standard-library `net/http` on both sides, no framework.
  HTTP/2 is off inbound and outbound: the reverse proxy talks HTTP/1.1 anyway,
  and this removes a class of recent HTTP/2 vulnerabilities.
- **JOSE: no library** (owner, 2026-10-15; replaces `go-jose/v4`). The
  relay verifies FITs and parses the JWKS with `crypto/rsa`,
  `crypto/sha256`, `encoding/base64` and `encoding/json` (§4.4, §4.5),
  in `internal/fit/`. The strict parsing and failure cases in §4.4 determine
  the implementation size.
  - **Why:** the relay needs one algorithm out of the dozens `go-jose`
    supports, and `go-jose` has had advisories of its own (in 2025, a
    denial of service in its compact-token parsing). Without it, every
    update is a Go patch, which ships automatically (D4).
  - **Cost:** we own security-critical parsing code. This is offset by the
    attack tests and the fuzz test in §13, and by the security review in
    Phase 4.
- **Dependencies: none.** `go.mod` lists no modules. Adding one needs the
  owner's approval and a reason recorded here (S-1).
- **Logging:** `log/slog`, JSON to stdout.
- **Image:**
  - multi-stage build;
  - builder: the official `golang` image pinned by digest;
    `CGO_ENABLED=0`, `-trimpath`, and the version stamped with `-ldflags`;
  - final image: `FROM scratch` with the binary and the builder's CA bundle,
    `USER 65532:65532`, no shell or package manager (S-2, S-3); measured
    18.5 MB unpacked on 2026-10-15, since the binary keeps its symbols for
    `govulncheck -mode=binary`;
  - `/LICENSE` is the repository's `LICENSE`: Article 5 of the EUPL asks for
    a copy of the licence with every copy of the work, and an image is
    pulled without the repository. The smoke test checks its SHA-256
    (owner, 2026-11-24);
  - `scratch` rather than distroless leaves one base image to track instead
    of two, and the CA bundle refreshes with every toolchain rebuild.
- **Health check:** `relay healthcheck` calls `/livez` (or `/readyz` with
  `--ready`) on localhost and exits 0 or 1 (O-3).
- **Architectures:** `linux/amd64` and `linux/arm64`, cross-compiled by Go
  without emulation (S-4).
- **Considered and rejected:**
  - **TypeScript on Node** (the 2026-09-29 choice): the image ships a whole
    runtime, Node majors reach end of life in about 30 months, and memory and
    cold start are worse. Its one advantage is that the team knows it.
  - **Rust:** a credible second choice, but the HTTP stack is assembled from
    many crates, which works against S-1.
  - **`go-jose/v4`** (the choice until 2026-10-15): well reviewed and
    without further dependencies, but it is the only part of the relay that
    would need a human-reviewed update. See **JOSE** above.
  - **Envoy or nginx with JWT plugins:** too much configuration surface and
    frequent security releases. The error codes and the site pin would need
    scripting, and open-source nginx has no JWT support.

## 8. Configuration

Environment variables, read and checked once at startup. Any setting can
instead be read from a file named by `<NAME>_FILE`, for the secret mechanisms
of Docker, Kubernetes and others. A `RELAY_*` variable the relay does not know
logs a startup warning, which catches typos. The warning names the variable
only if the name looks like a setting name (`RELAY_` followed by `A-Z`, `0-9`
and `_`, at most 64 bytes); any other is logged once as
`RELAY_* (malformed name)`, because a `:` typed for `=` would put the value,
perhaps the credential, into the name (2026-10-15).
If both a setting and its `_FILE` variant are provided, startup fails with
the setting name only. File reads are bounded and configuration errors never
echo values. The credential header must obey the exclusions in §5.

**Validation rules (2026-10-15).** A `_FILE` value loses one trailing line
ending (`\n` or `\r\n`), since secret files usually end with one. A setting
that is present but empty is an error, never the default. List items are
separated by commas; spaces and tabs around an item are ignored, and empty or
duplicate items are errors. `RELAY_APP_ID` is `ari:cloud:ecosystem::app/`
followed by a lowercase UUID; other IDs are 1–256 printable ASCII characters
other than space and comma. Durations use Go syntax (`10s`, `6h`) and must
be positive, except that `RELAY_CLOCK_SKEW` may be `0`; it is at most
1 minute (owner, 2026-10-16), since FITs live about 25 s and a larger skew
would in effect switch `exp` and `nbf` off. `RELAY_LOG_LEVEL` is matched
exactly.
`RELAY_PORT` and a port in `RELAY_UPSTREAM_URL` or `RELAY_JWKS_URL` are
1–65535. Both URLs start with the literal `https://` and have a host and no
userinfo, query or fragment, since the startup summary prints them. The
upstream is an origin: only an optional root `/` is accepted and normalized
away; the JWKS URL may include its endpoint path.
**Upstream host guard (owner, 2026-10-20, SR-5: "dont start without
correct url").** `RELAY_UPSTREAM_URL` must be
exactly `https://tara.ria.ee` or `https://tara-test.ria.ee` after
normalization (lowercase, no port), unless `RELAY_UPSTREAM_ANY_HOST` is
`true`. The relay sends TARA's client secret to this origin, and the value
is copied from an admin page a Jira admin controls, so a wrong or
social-engineered origin is refused at startup rather than receiving the
secret on the first login. The override is exactly `true` or `false`
(default `false`) and exists for synthetic upstreams in tests, the load
fixture and the image smoke test; with it, every start logs `upstream is
not TARA`. The Forge app's block only ever writes TARA's two origins. A new
refusal narrows the accepted settings; no relay is released, so under §4.6
it is part of the first release. The refusal is an ordinary configuration
error: exit code 2 and one `invalid configuration` line with `setting`
`RELAY_UPSTREAM_URL` and `reason` `not one of https://tara.ria.ee,
https://tara-test.ria.ee; set RELAY_UPSTREAM_ANY_HOST=true for another
upstream`. Like every configuration error it never prints the configured
value.
`RELAY_UPSTREAM_CA_FILE` holds at most 1 MiB
of PEM `CERTIFICATE` blocks with only whitespace before, between and after
them; `_FILE` values are read up to 64 KiB. The
`RELAY_UPSTREAM_AUTH` value loses spaces and tabs around it and must not be
empty (2026-10-16).

| Setting                                     | Required | Default                             | Purpose                                                                |
| ------------------------------------------- | -------- | ----------------------------------- | ---------------------------------------------------------------------- |
| `RELAY_APP_ID`                              | yes      |                                     | Expected FIT audience                                                  |
| `RELAY_ENVIRONMENT_ID`                      | yes      |                                     | Expected `app.environment.id`, the environment ARI (D5)                |
| `RELAY_CLOUD_IDS`                           | yes      |                                     | Accepted site IDs, comma-separated (D5)                                |
| `RELAY_UPSTREAM_URL`                        | yes      |                                     | TARA HTTPS origin, e.g. `https://tara.ria.ee`                            |
| `RELAY_UPSTREAM_ANY_HOST`                   | no       | `false`                             | `true` allows an upstream other than TARA's two origins (tests only)    |
| `RELAY_UPSTREAM_AUTH`                       | no       | none                                | Credential header, `Name: value` (secret; usually via `_FILE`)         |
| `RELAY_UPSTREAM_CA_FILE`                    | no       | system bundle                       | Trust only these CAs for the upstream                                  |
| `RELAY_INSTALLATION_IDS`                    | no       | any                                 | Extra pin on `app.installationId`                                      |
| `RELAY_PORT`                                | no       | `8080`                              | Listen port                                                            |
| `RELAY_UPSTREAM_TIMEOUT`                    | no       | `10s`                               | Overall limit per upstream call                                        |
| `RELAY_CLOCK_SKEW`                          | no       | `10s`                               | Tolerance for `exp` and `nbf`                                          |
| `RELAY_JWKS_URL`                            | no       | Atlassian Forge JWKS                | Source of signing keys                                                 |
| `RELAY_JWKS_REFRESH`                        | no       | `6h`                                | Periodic refresh                                                       |
| `RELAY_JWKS_MAX_AGE`                        | no       | `24h`                               | Maximum trust age of the last successful key snapshot; §4.5             |
| `RELAY_SHUTDOWN_GRACE`                      | no       | `15s`                               | Time for in-flight requests on stop                                    |
| `RELAY_LOG_LEVEL`                           | no       | `info`                              | `debug`, `info`, `warn` or `error`                                     |

**The admin page writes most of this.** For TARA,
the Forge admin page shows a ready block with `RELAY_APP_ID`,
`RELAY_ENVIRONMENT_ID`, `RELAY_CLOUD_IDS` and `RELAY_UPSTREAM_URL`
filled in. The customer adds only the credential and TARA's CA file. This removes
the most likely setup mistakes.

## 9. Changes to the requirements (2026-10-15)

| Requirement            | Change                                                                                         | Reason                                                                                             |
| ---------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| A-6 (MAY)              | Site and environment pins are **required**; the installation pin stays optional                | D5                                                                                                 |
| F-4 (MUST)             | The credential header stays **optional**                                                      | Its existing schema is unchanged; synthetic fixtures need none. Supported TARA setup supplies Basic (D11). |
| F-7                    | Upstream status in `Relay-Upstream-Status`, HTTP status `200`                                  | D7                                                                                                 |
| F-8                    | `Relay-Protocol` on every application-generated response; `Relay-Version` only after a valid FIT | HTTP-server and proxy rejections may occur before a relay handler; hide the release from anonymous callers |
| F-2                    | The FIT is checked before the route                                                            | Routes are not revealed to callers without a token                                                 |
| F-10, R-2, §8 defaults | 64 KiB fixed body limits (was a 1 MB default), 10 s default timeout (was 20 s)                 | D8                                                                                                 |
| R-8 (MAY retry)        | No application retries or token POST replay after possible delivery; §5 defines transport recovery | A token call may already have spent a one-time code                                                |
| S-9 (SHOULD)           | **Deferred:** filter Atlassian's IP ranges at the reverse proxy, which sees the real client IP | Inside the relay it would have to trust `X-Forwarded-For`, which adds settings and a spoofing risk |
| new                    | Query strings and Isolated Cloud tokens are refused                                            | Not needed; fewer ways in                                                                          |

**Review decisions accepted on 2026-10-15:** D1-D8 remain in force. Site
fallbacks must be unambiguous and proven by the spike (§4.4); JSON parsing is
strict; cached-key trust has a 24 h default maximum (§4.5). Patch automation
operates only on supported release branches (§12). Connection bounds and
health exemptions supplement the payload budget (§6). The validated trace ID
is the sole header-derived logging exception (§10). Phase 0 has a limited
spike scope and explicit gates, and basic CI moves into Phase 1 (§14).

## 10. Operations

- **Logs** (O-4): one JSON line per request with `time`, `level`,
  `request_id`, `method`, `route`, `status`, `upstream_status`,
  `duration_ms`, `error`, `auth_reason` and `cloud_id`. The sole exception
  to the ban on logging header values is a validated `x-b3-traceid`: exactly
  16 or 32 hexadecimal characters, not all zero, normalized to lowercase.
  Missing, repeated or invalid trace headers produce a random request ID;
  never log the rejected value. A trace ID is correlation data, not proof
  of identity. Only a verified FIT supplies `cloud_id`; omit it before
  authentication succeeds.
  `route` is a matched local endpoint, `POST /oidc/token` or a fixed `unmatched` marker;
  never log raw or decoded rejected paths. Health probes log at `debug`
  (2026-10-15): orchestrators send one every few seconds. Methods `GET`,
  `POST`, `PUT`, `PATCH` and `DELETE` keep their names in logs; every other
  method uses an `other` marker. `error` and `auth_reason` are fixed
  classifications, never raw error strings, URLs, panic values or key IDs.
  Never bodies, query strings, other header values, the FIT or the credential
  (S-7). Tests inject secret markers into rejected inputs and assert that
  neither request logs nor startup diagnostics contain them.
  A request net/http answers itself before any handler runs (a header over
  `MaxHeaderBytes`, `431`; a malformed request, `400`; an unsupported
  transfer coding, `501`; an unexpected `Expect`, `417`) logs one `request`
  line too, with `route` `unmatched`, the `status`, `duration_ms` and
  `error` `http_server`, and no `method`, since nothing was parsed (owner's
  review, 2026-10-20, SR-9). The relay wraps its listener and reads only
  the status code net/http writes for a request that never reached the
  handler; nothing from the request reaches the line. A client that stops
  mid-header gets no answer and still leaves no line.
- **Startup** (O-5): the version, Go version and a summary of the settings.
  The credential shows as `set (from file)`, never its value (S-8). A
  credential given inline in `RELAY_UPSTREAM_AUTH` logs a `credential set
  inline` warning, since `docker inspect`, orchestrator UIs and the process
  environment show it (2026-10-20, SR-4); it is not refused, so a test
  setup still starts. The
  summary prints the configured upstream HTTPS origin and
  JWKS URL, which can hold no userinfo or query (§8).
- **Deploy files:**
  - `deploy/compose.yaml` (O-6): `restart: unless-stopped`, the health
    check, `mem_limit: 128m`, `pids_limit`, `read_only: true`,
    `cap_drop: [ALL]`, `no-new-privileges`, user 65532, and an optional Caddy
    service in front. Also `memswap_limit` equal to `mem_limit` (no swap),
    json-file logs rotated at 3 × 10 MB per service and a 30 s stop grace
    above `RELAY_SHUTDOWN_GRACE` (2026-10-15);
  - `deploy/kubernetes/` (O-7): Deployment, Service, Secret, NetworkPolicy,
    liveness on `/livez`, readiness on `/readyz`, and a matching
    `securityContext`. Also a 5 s `preStop` sleep, so endpoint removal
    reaches the ingress before SIGTERM (Kubernetes 1.30 or later), service
    links off, and the Secret created with `kubectl create secret` rather
    than by editing the example (2026-10-15).
- **Setup guide** `docs/SETUP.md` (O-8):
  - what the customer provides (the prerequisites below);
  - copying the block from the admin page;
  - firewall rules: inbound 443 from Atlassian's egress ranges, outbound
    only to the provider host and `forge.cdn.prod.atlassian-dev.net:443`;
  - registering the IP with the provider;
  - an IP-filter snippet for the reverse proxy (S-9);
  - connection limits and private relay-port exposure (§6), with proxy
    access/error logging configured to follow the same redaction rules as
    the relay; disable logs that cannot be safely redacted;
  - customer prerequisites: a host with a static outbound IP, a provider
    registration and credential or signing-key setup, DNS/TLS for inbound
    HTTPS, an accurate system clock, and access to the upstream and JWKS;
  - upgrades.

## 11. Repository layout

```
cmd/relay/            main: serve (default), healthcheck, version
internal/config/      environment parsing and validation
internal/fit/         FIT verification and the JWKS cache
internal/forward/     fixed token request, header filtering, upstream client
internal/server/      HTTP server, middleware (request ID, recover, limiter, logging), health
test/load/            small load generator for the acceptance runs (no dependencies)
deploy/               compose.yaml, Caddyfile, kubernetes/
docs/                 SETUP.md, PROTOCOL.md (§4, for implementers), SUPPORT.md
.github/workflows/    ci.yml, release.yml, weekly.yml, go-patch.yml, go-patch-line.yml (go-patch's per-line jobs)
.github/scripts/      the workflows' shell steps; main's copy runs against every release line
.github/dependabot.yml
Dockerfile, .dockerignore, go.mod, README.md, AGENTS.md, CONTRIBUTING.md, PLAN.md   (no go.sum: there are no modules)
LICENSE, SECURITY.md
```

The module path is `eid-tara-remote`, the image's name (§15 Q6; was
`eid-forge-remote` until 2026-11-26). Nothing imports the module from
outside, so it needs no host prefix.

`LICENSE` (EUPL-1.2) and `SECURITY.md` were added on 2026-11-24, ahead of
publication (D3; owner's request, §16). From the first commit, nothing goes
in that could not be public: no secrets, keys, customer names or internal
hostnames.

## 12. CI and releases

**Update model (owner, 2026-10-15, D4).** Building once and never updating
was considered and rejected: the relay parses headers and a JWT from callers
before it knows who they are, its frozen CA bundle would stop matching the
provider's certificates within a few years, and customers' image scanners
would flag the old Go version. Instead:

| Change                                         | How it ships                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------- |
| New Go patch release, or a new builder digest  | **Fully automatic:** `go-patch.yml` checks, commits, tags and releases          |
| New Go minor release                           | A pull request from `go-patch.yml`, merged by a person                          |
| GitHub Actions update                          | A Dependabot pull request, merged by a person: actions run in the signing job   |

A Go patch release contains only security and critical fixes, and the tests
pin every response code, header and setting of the protocol, so it can ship
without review. The other two can change behaviour or the supply chain. The
relay has no third-party modules (D2), so there are no module updates.

**Rule:** a patch release (`X.Y.Z` → `X.Y.Z+1`) never changes an endpoint,
response code, header or setting. This is what makes the floating `:X.Y` tag
below safe to follow automatically.

**Release lines (2026-10-15 review).** Development happens on `main`.
Each supported minor has a `release/X.Y` branch anchored at its published
release. Only the newest minor of each supported major receives maintenance;
the previous major's newest minor remains maintained for its 12-month window.
Each line has its own Go pin, patch sequence and floating tag. Changes to
release code or workflow policy require human review. Automation never
promotes unreleased work from `main` into a patch release.

- **`ci.yml`, on every push and pull request:**
  - basic source checks and contract fixtures begin in Phase 1; Docker and
    packaging checks join in Phase 2, before container publication;
  - `gofmt` check, `go vet`, `staticcheck` and `go test -race`;
  - `govulncheck ./...`;
  - `gitleaks` as a CLI (its GitHub Action needs a licence for organisation
    accounts);
  - a Docker build with a smoke test: the container starts read-only as a
    non-root user, `/livez` answers `200`, `/readyz` answers `503` while the
    JWKS URL is unreachable, and a bad setting exits with its name;
  - a check that the Go version in `go.mod`'s `toolchain` line and the
    builder image tag in the `Dockerfile` are the same;
  - the release-script cases (`lines-test.sh`, `release-test.sh` and
    `go-patch-test.sh`; bash, git and jq).
- **`release.yml`, on a `vX.Y.Z` tag, and callable from `go-patch.yml`**
  (`workflow_call`, because a tag pushed with a workflow's own token does not
  start other workflows):
  - check out the exact release commit, run the same checks, then `buildx`
    for amd64 and arm64. Scan each built binary with
    `govulncheck -mode=binary` and run the container smoke tests before
    assigning customer release tags;
  - push the verified candidate to
    `ghcr.io/oktul/eid-tara-remote` by digest or a staging tag; generate
    SBOM and provenance attestations and cosign keyless signatures using
    GitHub's OIDC token. Verify both architectures, their digests and the
    signature identity against this repository's trusted release workflow
    (S-5). Build permissions are read-only; signing/publishing permissions
    belong to the later trusted publication job;
  - after all checks and signature verification succeed, assign the
    immutable `:X.Y.Z` tag and only then move `:X.Y` to that verified digest
    (S-4). Never overwrite an existing version tag with different content,
    and never move a floating tag backwards. No `latest` in the docs;
  - serialize all manual and automatic publication for a release line.
    A rerun recovers the same verified commit/digest or stops; it must not
    quietly rebuild different content under an existing version. Failed
    candidates leave the floating tag untouched and open an owner-visible
    issue. Document rollback by previously verified image digest;
  - a GitHub release whose notes say whether the upgrade is **required,
    recommended or optional**, and why (V-6). A person writes them for a
    tagged release. For an automatic one they are generated: `recommended`
    when `govulncheck` found a reachable vulnerability that the new Go
    fixes, otherwise `optional`, with links to Go's release notes. Only the
    owner marks a release `required`, by editing its notes.
- **`go-patch.yml`, daily and manual:**
  - reads Go's releases from `https://go.dev/dl/?mode=json` and the digest of
    the matching official `golang` image;
  - processes every supported `release/X.Y` branch, including the previous
    major's maintained line. Start from its latest published patch commit;
    if the branch has additional commits, stop that line and open an issue
    for a human release rather than include them automatically;
  - for a new patch of that line's pinned Go minor, or a new image digest
    for the same Go version: update only the Go version/toolchain fields in
    `go.mod` and the builder tag/digest in `Dockerfile`. Verify the exact
    diff against the last published patch, including an explicit ban on
    source, test, workflow, configuration and protocol changes. A builder
    digest change may update its CA bundle or OS packages too; checks are
    required even when the Go version has not changed;
  - run every applicable `ci.yml` check on the candidate. Immediately before
    updating the branch, verify its tip still equals the tested base and
    publish the tested commit with an ordinary fast-forward push, never a
    force push. Serialize competing update runs per line; if a human push
    races the update, stop and re-evaluate instead of rebasing untested code;
  - only after those checks and a successful branch update, tag the next
    unused patch version and call `release.yml` with the exact commit. A
    failure before the branch update leaves it untouched. A later release
    failure records the completed publication steps for a safe rerun; failures
    before promotion leave the floating tag untouched, and no unverified
    candidate is promoted. Every failure opens or updates an owner-visible
    issue. The development branch is not part of automatic publication;
  - for a new Go minor, open a human-reviewed pull request for each supported
    line needing it; do not allow its toolchain to drift out of support.
    Changes that alter the protocol follow §4.6 rather than bypassing the
    compatibility rule as a security update;
  - use branch protection where available, plus the explicit diff and
    fast-forward guards above. Running tests alone does not provide branch
    protection or authorize unrelated changes.
- **`weekly.yml`, scheduled and manual:** `govulncheck` on `main`, every
  supported release branch and each line's latest published binaries for
  both architectures. A failure opens or updates an issue as well as using
  GitHub notifications; email delivery depends on the owner's notification
  settings. A reachable vulnerability that needs a new Go minor is the
  owner's to merge and tag on every affected supported line.
- **Dependabot**, monthly, plus its security updates as they appear: GitHub
  Actions only, since there are no Go modules. Never merged automatically.
  The builder image belongs to `go-patch.yml`, not Dependabot.
- **Hygiene:** actions pinned by commit SHA; minimal workflow permissions
  (`contents: read`; releases also `packages: write`, `id-token: write`;
  `go-patch.yml` also `contents: write`, `issues: write` and
  `pull-requests: write`).
- **Schedules:** GitHub disables scheduled workflows in a public repository
  after 60 days without activity. The automatic commits usually prevent
  that; after publication, check that both schedules are still enabled.
- **Cost:** a few minutes per run, plus under a minute a day for
  `go-patch.yml`, well within GitHub Free's 2,000 minutes a month for private
  repositories.
- **Implementation decisions (2026-10-15):**
  - `ci.yml` runs on pushes to branches, pull requests and `workflow_call`;
    a tag push runs `release.yml`, which calls `ci.yml` for the exact commit.
  - Schedules: `go-patch.yml` daily at 05:41 UTC, `weekly.yml` on Mondays
    at 04:23 UTC.
  - The cosign identity is `release.yml` at `refs/tags/vX.Y.Z` (a person's
    tag) or at `refs/heads/main`: scheduled workflows run on the default
    branch, and GitHub names a called workflow by the caller's ref. A call
    is accepted only from `main`.
  - `go-patch.yml` calls `go-patch-line.yml` once per supported line. Tests
    and third-party tools (source checks, native amd64 and arm64 builds and
    smoke tests) run in read-only jobs. Only jobs that run no third-party
    tool hold `contents: write` or `pull-requests: write`. The push job
    takes the candidate from a git bundle by the commit ID the prepare job
    reported, re-checks that only the `go.mod` toolchain line and the
    `Dockerfile` builder line changed against the base, and pushes the
    branch and tag in one atomic, non-forced push with git hooks off. A
    rerun after a push hands the existing tag on instead of pushing again
    when the tag names the tested commit and that commit is on the branch,
    also after a person has pushed on top of it; it then takes the commit
    from the branch and needs no bundle (2026-10-16).
  - A line's base is its latest published release: the newest `vX.Y.*` tag
    on any ref must be merged into `release/X.Y`, and the
    `org.opencontainers.image.revision` label of `:X.Y.Z` must equal that
    tag's commit; otherwise an issue is opened and nothing is built. The
    next patch number is one above that tag.
  - The supported minor of a major is its newest `release/X.Y` branch that
    has a `vX.Y.Z` tag; an unreleased newer branch does not displace it.
    Likewise, only tagged lines choose the current and previous major, so
    an unreleased future major ends no support (2026-10-16).
  - Release tags are annotated (`git tag -a`; `go-patch.sh` annotates its
    own), and `release.sh check-ref` refuses a lightweight one before the
    release build. The previous major's window starts at the `vN.0.0`
    tagger date. A lightweight tag carries only its commit's date, so while
    `vN.0.0` is missing or lightweight, `lines.sh` keeps the previous major
    and warns (owner, 2026-10-16).
  - The Go-minor job opens its pull request even when an earlier run pushed
    the branch but failed to open one.
  - Report jobs hold `contents: read` and `issues: write`; the publish job
    holds no `issues` scope.
  - BuildKit (`moby/buildkit`, through `setup-buildx-action`'s
    `driver-opts` in `ci.yml`, `release.yml` and `go-patch-line.yml`) and
    the SBOM generator (`docker/buildkit-syft-scanner`, in `release.yml`)
    are pinned by tag and digest (v0.33.1 and 1.12.0). Dependabot cannot
    update them, so a person does so in a reviewed pull request, checked at
    least with each monthly Dependabot review.
  - Issue titles: `release vX.Y.Z failed`, `go-patch: release/X.Y failed`,
    `go-patch: release/X.Y has unreleased commits`,
    `go-patch: release/X.Y: vX.Y.Z is not on the branch`,
    `go-patch: release/X.Y: vX.Y.Z is not published`,
    `go-patch: release/X.Y: vX.Y.Z differs from its image`,
    `go-patch: failed`, `weekly govulncheck: findings`.
  - `release.yml` accepts an automatic call only for `vX.Y.Z` with Z > 0
    whose commit has the commit of `vX.Y.(Z-1)` as its only parent and
    changes only the `go.mod` toolchain line and the `Dockerfile` builder
    line, on the same Go minor and never an older Go: the check `go-patch.sh`
    makes before its push (2026-10-16).
  - Workflow artifacts are kept for 30 days, as long as GitHub allows a run
    to be rerun, and the issue texts state that window; after it, a person
    releases the line by hand with a new tag. Artifact names are unique
    within a run: `go-patch-line.yml`'s carry the line, `release.yml`'s the
    version (`relay-oci-X.Y.Z`, `release-notes-X.Y.Z`), since `go-patch.yml`
    calls `release.yml` once per line in one run (2026-10-16).
  - Artifact hand-offs (2026-10-16): every job of a run holds the run's
    artifact token and can replace any of its artifacts, including the
    read-only jobs that run third-party tools (`ci.yml`'s jobs as
    `release.yml`'s `checks`, `go-patch-line.yml`'s source and image jobs,
    `release.yml`'s smoke and notes) and, in a `go-patch.yml` run, the other
    lines' jobs. Only a job's own steps can write its outputs, so each
    artifact a later job uses is tied to an output of its producer and
    checked right after the download, before anything uses it:
    - `go-patch-candidate-X.Y` (git bundle; prepare to source, image and
      push) is pinned by prepare's commit ID output: the checks check out
      that ID, and push re-runs the Go-patch check on it.
    - `relay-oci-X.Y.Z` (OCI archive; build to smoke, notes and publish):
      after its label check and scan, build outputs the archive's SHA-256
      and index digest; each consumer checks both, and publish stages,
      signs and tags only that digest.
    - `release-notes-X.Y.Z`: notes outputs the file's SHA-256, and publish
      checks it before creating the release.
    - `go-patch-release-X.Y` (hand-off record; prepare or push to collect)
      cannot be pinned, since `go-patch.yml` calls `go-patch-line.yml` in a
      matrix, which collapses outputs to one value. Known residual risk: a
      compromised tool can forge or drop it. A forged record can at worst
      make `go-patch.yml` call `release.yml` for an existing tag on its own
      line whose commit is a Go patch update of the previous patch tag;
      `release.yml` checks that from git, not from the record, and its
      never-overwrite, forward-only tag rules still govern the release. A
      dropped record leaves the tag unpublished, which the next run reports.
    - Trusted: the tools that run inside a producing job before it records
      its outputs (BuildKit, the SBOM generator, govulncheck and the setup
      actions in build; skopeo and govulncheck in notes; git, skopeo and
      buildx in prepare), and the pinned actions of the write jobs.
  - Repository settings needed before `go-patch.yml` can work: Actions may
    create pull requests, rules on `release/*` let `github-actions[bot]`
    fast-forward and push `v*` tags, and the ghcr.io package grants this
    repository write access.
- **Customers choose how they upgrade** (`docs/SETUP.md`):
  - **pinned** to `:X.Y.Z`, the default in the deploy files: they upgrade by
    hand after reading the release notes;
  - **automatic patches**, opt-in: follow `:X.Y` with Watchtower (Docker) or
    `imagePullPolicy: Always` and a scheduled rollout restart (Kubernetes).
    By the rule above, this never brings a protocol or setting change. A new
    minor still needs a manual tag change, which the admin page prompts
    for.
- **Support policy** (`docs/SUPPORT.md`, V-5, M-2):
  - the newest minor release of the current major is supported, and the
    previous major's newest minor for 12 months after a new major, counted
    from its annotated `vN.0.0` tag (owner, 2026-10-16). Publish the supported
    branches and exact end-of-support dates in `SUPPORT.md`;
  - a rebuild at least once a year; a Go patch release automatically within
    a day of Go publishing it; and within 7 days of a reachable critical or
    high fix that needs a new Go minor;
  - customers learn of upgrades from the release notes and from the admin
    page, which compares `/relay/v1/info` with the minimum version the Forge
    app expects.

## 13. Testing and acceptance

- **Unit tests** (Go `testing` and `httptest`, run in CI):
  - **FIT:** missing or repeated Authorization headers, malformed Bearer
    syntax, bad signature, wrong issuer or audience, expired or not-yet-valid
    token, missing required claims, wrong environment, wrong site, `icLabel`,
    missing `kid`, `alg: none`, HS256 signed with the RSA
    public key as the secret, and a tampered payload. All return the same
    `401`. Because the parser is our own (D2), also: two or four parts,
    empty parts, padded or non-URL base64, a token over 8 KiB, a header with
    `crit`, `jku`, `jwk`, `x5u`, `x5c`, `zip` or `b64`, an unknown `kid`, a key
    under 2048 bits, `exp` as a string, and a valid signature from a
    different key with the same `kid`. Correctly signed negative fixtures
    cover duplicate/escaped member names at every relevant nesting level,
    case-variant names, nulls, wrong object types, invalid UTF-8/Unicode,
    trailing JSON, audience string/array handling, fractional NumericDates,
    range/overflow boundaries and exact clock-skew boundaries. Positive
    fixtures show that unknown ordinary claims remain accepted.
    Site tests cover allowed invocation context, a mismatch that installation
    contexts must not rescue, conflicting context sources, malformed contexts
    and a missing invocation site. Never retain live FITs or identifiers in fixtures;
    use synthetic claims and locally generated test keys only.
  - **Fuzz:** a Go fuzz test (`go test -fuzz`, standard library) feeds the
    token parser arbitrary input and must never panic or accept a token
    without a valid signature. CI runs its seed corpus with the unit tests;
    a longer run (at least an hour) happens before v1.0.0. The same applies
    to the other parsers (2026-10-15): strict JSON, NumericDate (against an
    exact `math/big` oracle), JWKS, the upstream origin, the
    credential header, setting lists, CA bundles and unknown names,
    each with a seed corpus in its package's `testdata/fuzz/`.
  - **Keys:** unreachable at startup, backoff, rotation and removed keys,
    last-good snapshots kept only to their maximum age, readiness expiry
    and recovery, duplicate IDs, malformed/empty/oversized sets and atomic
    replacement. Flood with different unknown IDs to prove the global
    one-a-minute limit and single fetch; show known-key calls do not wait,
    unknown-key waits are bounded and cancel promptly, hold no forwarding
    slot, and one caller's cancellation does not cancel the shared worker.
    Inject a clock/fetcher so these tests do not wait for real refresh
    intervals. The fetcher is an injected function; the clock is the fake
    clock of a `testing/synctest` bubble, so production code needs no timer
    interface (2026-10-15).
  - **Forwarding:** the fixed `POST /oidc/token` route, path tricks, header filtering, the
    credential overriding a caller's header, no redirects, size limits before
    anything is sent, `504` on timeout, cancel on disconnect. Cover origin-only
    destination validation, request-target tricks before router normalization,
    the fixed response-header list, Connection-nominated headers,
    spoofed relay response headers, and no token POST replay after a request
    was delivered but the response was lost.
  - **Config:** every setting named without its value in its error, `_FILE`
    conflicts and bounded file reads, an unsafe credential header and JWKS age
    validation.
  - **Health, logs and contract:** health remains live and locally responsive
    while the forwarding cap is full; readiness reflects usable-key age and
    shutdown. Exercise §4.6 fixtures over HTTP, plus transport-level malformed
    requests where relay headers are not promised. Secret markers in paths,
    trace headers, bodies, credentials, configuration errors and upstream
    error text must not appear in logs. Verify valid trace IDs survive, bad
    or repeated ones are replaced and unverified site IDs are omitted.
- **Before v1.0.0, by hand, results recorded here** (load runs use
  `go run ./test/load -relay <proxy URL> -probe <relay URL>`, which serves a
  test JWKS and upstream and prints the settings to restart the relay with):
  - load above the concurrency cap with container memory under 128 MB
    (`test/load`), through the documented proxy limits. Include full-sized
    simultaneous request/response bodies, slow headers, idle connections,
    invalid-token floods and many distinct unknown key IDs, which must never
    answer `too_busy`. Record measured peak memory, connection counts, CPU
    and health-probe behavior; overload must not cause a liveness restart
    or unbounded memory growth;
  - a 72-hour soak on a VM: `-scenario soak -duration 72h`, valid FITs at
    `-rate` (default 5/s) with every tenth signature bad, a progress line
    per `-report-every` (default 5 min) and container memory sampled
    alongside (`docker stats`). Each valid FIT must be forwarded and each
    bad one answered `invalid_token`, no health probe may fail, no
    rejected request may reach the upstream, and memory must stay flat.
    **Done 2026-10-21, 21 h 25 min instead of 72 h (owner's decisions,
    2026-10-20 and 2026-10-21).** The owner ruled that a run on their
    Windows PC counts as the official soak instead of a VM, and stopped it
    early as clearly stable. Setup: relay image from `d55b4e4` and the
    generator in two containers on one Docker network (no Windows port
    forwarding), default JWKS settings, memory sampled every 5 minutes.
    Result: 385,550 requests, 346,995 forwarded and 38,555 rejected, each
    as its FIT required; no errors; 308,442 health probes, none failed,
    slowest 13 ms; p99 110.6 ms in 244 of the 257 five-minute windows and
    never above 114.7 ms; JWKS refreshed at 6, 12 and 18 h with no effect;
    relay memory flat at 16–17.7 MiB after the first five minutes (16
    processes); the relay logged nothing but its startup lines and the
    requests. The generator printed `FAIL: 346996 upstream calls for
    346995 forwarded answers` only because the stop (SIGINT) cancelled the
    request in flight after it reached the upstream: the relay logged that
    request as `client_canceled`. The upstream-call check should not run
    on an interrupted run (open, generator only);
  - a JWKS outage (`-scenario jwks-outage`, added 2026-10-20): the test
    JWKS answers 503 while valid FITs go on at `-rate`, with the relay
    started with the printed `RELAY_JWKS_REFRESH=30s` and
    `RELAY_JWKS_MAX_AGE=2m`. The keys must expire between max age minus
    refresh and max age into the outage (§4.5; later would trust keys past
    the bound), nothing may reach the upstream after that, `/readyz` must
    give the relay's own `503 not_ready` (no other failure) while `/livez`
    never fails (§6), and forwarding must resume within
    `JWKSRetryMax` once the JWKS is back. About 5 minutes. First runs
    2026-10-20, the relay image in Docker Desktop on Windows, the generator
    on the host: a 1-minute soak passed (299 requests, p99 229 ms, memory
    10–11 MiB); the outage expired the keys at 2m0s, forwarded nothing
    after, and forwarded again 33 s after the JWKS was back. Its first run
    failed on one `/readyz` probe timeout (1 s) while `/livez` passed;
    readiness is one atomic load, so that points at Docker Desktop's port
    forwarding, and the rerun passed with the slowest probe at 24 ms. These
    runs check the tool; an acceptance run of the outage is still to be
    recorded;
  - killing the process gives a healthy restart within 10 s;
  - SIGTERM lets in-flight requests finish;
  - an image scan (Trivy or Grype) shows only the Go binary and the Go
    standard library, no third-party modules;
  - amd64 and arm64 both run from `deploy/compose.yaml` unchanged.
- **End to end with the Forge app:**
  - a TARA demo login through a relay (the demo accepts any IP, so this
    proves the path);
  - then a TARA production login from the registered static IP, which proves
    the allowlisted path needed for B9.

## 14. Phases

0. **Approval and Forge spike** (in the Forge app, development
   environment). Until D10 (2026-10-15) the approval covered plan edits
   only; D10 authorized Phases 1 and 2 in this repository. Forge manifest
   changes still need approval. Once Phase 0 is approved,
   a bounded exception permits only the relay pieces needed for the spike:
   configuration, tested FIT/site/environment checks, one synthetic upstream
   route and the v1 status/header response. Use a temporary tunnel, synthetic
   payloads and no production credentials; do not add packaging, release
   automation or production integration. Do not log or retain live FITs.

   **Exit gates, all recorded as pass/fail with date and sanitized evidence:**
   - configure a remote with `permissions.remote.set`, and demonstrate the
     actual `/cb` web trigger calling it via backend `invokeRemote`;
   - inspect claim presence/types without retaining tokens or real IDs;
     prove the environment and calling-site pin on this exact path, and
     reject a wrong-site and wrong-environment call. Require the signed
     invocation site; installation contexts cannot substitute for it (§4.4).
     If no trustworthy site pin exists, stop and revise the plan;
   - observe the upstream body plus `Relay-Protocol` and
     `Relay-Upstream-Status` for synthetic upstream `200`, `400`, `401` and
     `302` responses wrapped according to D7. Observe relay-generated errors
     separately and record whether Forge exposes non-2xx bodies and headers;
   - measure the function-to-remote timeout using a delayed synthetic
     upstream; confirm the configured relay timeout and error response fit
     within it, including FIT refresh/body-read overhead. Resolve deadline
     ordering in §6 before core implementation if the budget is insufficient;
   - show that a configurable compute-only remote preserves PINNED status on
     an EU site, with both manifest and observed admin status recorded.

   A failed or unknown gate blocks progression. Record the result and required
   design correction here, rather than silently relaxing a pin or the protocol.

   **Phase 0 results (2026-10-16).** Owner-approved spike on the Forge app's
   `spike-relay-phase0` branch (development 6.0.0, a test site), with
   this relay built from `claude/jwks-padding`, a synthetic HTTPS stub as
   upstream, a claim inspector that prints only names, types and yes/no
   checks, and a Cloudflare quick tunnel. No production credential or real
   personal data was used; no FIT was stored.

   - **Remote configured and called from `/cb`'s function: PASS, with two
     platform findings.** `permissions.remote.set` from the admin page set
     the remote; Atlassian showed a consent modal naming the URL, and
     another on reset. `GET /relay-spike` in the `sso` web trigger, the
     function `/cb` runs in, called it with backend `invokeRemote`.
     (a) A customer-managed remote **without `baseUrl` could not be
     deployed**: the server refused it with `UPSERT_ENVIRONMENT_REQUEST_INVALID`
     ("Cannot read properties of undefined (reading 'address')"), also with
     `supportedPatterns` or an `endpoint` module, although the remotes
     reference makes `baseUrl` optional. The spike used the placeholder
     `https://relay.invalid`, which makes adding the remote a major version;
     `forge lint` called removing it again a major version too ("Removal of
     configurable remotes"), where the reference says minor.
     (b) With the remote unset, a call goes to the placeholder and returns
     `500` with an HTML page from Forge's egress proxy; nothing reaches a
     relay. Reset restores that state.
   - **Claims and pins: PASS.** Signature (RS256 from the live JWKS), `iss`
     and `aud` (a string) verify. `context.cloudId` is present, a bare
     UUID, and is the calling site; `app.installation.contexts` holds one
     entry with the same `cloudId` plus `workspaceId`, `name` and
     `apiBaseUrl`. `app.environment.id` is the **environment ARI**
     (106 characters), not the UUID: a relay set up with the UUID refused
     every call (`auth_reason environment`), so §4.4 and §8 now say ARI.
     `app.installationId` is an installation ARI. No `icLabel`. The FIT
     lives 25 s. A relay pinned to another cloud ID refused with
     `cloud_id`, one pinned to another environment with `environment`;
     both answered `401 invalid_token`. The installation-context fallback
     is not needed and was removed (owner, 2026-10-16, §4.4). A call from a second real site was
     not run; the pin compares the signed `context.cloudId` alone.
   - **D7 wrapping: PASS.** Upstream `200`, `400`, `401` and `302` all reach
     the function as `200` with `Relay-Upstream-Status`, `Relay-Protocol`,
     `Relay-Version` and the body unchanged; `WWW-Authenticate` and
     `Location` pass when allowed, and the `302` is not followed. Backend
     `invokeRemote` **returns non-2xx answers instead of throwing**, with
     status, headers and body: the relay's `401 invalid_token` and `404
     route_not_allowed` arrive intact, unlike the bridge docs' behavior.
     Infrastructure in between can answer too (Forge's proxy `500`, the
     tunnel's `504`); those carry no `Relay-Protocol`, which is how the
     Forge app must tell them apart.
   - **Timeout: PASS.** There is no separate remote limit for this path: a
     40 s upstream answered after 40.2 s. The bound is the web trigger's
     budget, about 55 s left at the call; a 70 s upstream ended the trigger
     after 56.6 s with Forge's `424 Failed Dependency`, and the function got
     nothing. The relay's 10 s `RELAY_UPSTREAM_TIMEOUT` answered `504
     upstream_timeout` at 10.0 s, 11 s end to end, well inside it. The
     Cloudflare tunnel replaced that 504's body and headers with its own
     error page, so a customer's proxy may rewrite relay 5xx answers.
   - **PINNED: NOT RUN.** The test site has no data residency (its
     admin page offers none), so the gate needs an EU-pinned site on a plan
     with data residency. The customer-managed egress guide says
     "customer-managed remotes are not eligible for data residency"; expect
     a FAIL, and the owner's decision on whether relay customers accept it.

1. **Relay core** (this repository): config, FIT and keys, forwarding,
   errors, health and logs, with failure-case tests and §4.6 contract fixtures.
   Add basic `ci.yml` immediately with formatting, vet, staticcheck, race
   tests, vulnerability and secret checks. Exit only when all Phase 0 gates
   and source CI pass. Not tagged: the first tag is `v1.0.0` (owner,
   2026-11-26), and only when tagging is explicitly requested.
2. **Packaging and release CI:** Dockerfile, deploy files, `docs/`, Docker
   checks added to `ci.yml`, the three remaining workflows, and a signed
   multi-arch release. Verify release-line isolation, competing release runs,
   failure before floating-tag promotion and signature/digest verification.
   No publication or tagging without the owner's request.
3. **Forge integration** (Forge app):
   - the remote;
   - `/cb` going through it for TARA's token exchange;
   - on the admin page: the relay URL, the configuration block, the health
     check and the "relay too old" message;
   - TARA demo and production.
   Built on the Forge app's main line on 2026-10-18; TARA demo through a
   local relay passed on 2026-10-20 (§16). TARA production still needs a
   live client from RIA and the relay on a registered IP.
4. **Acceptance:** §13 by hand, plus a security review of both sides.
   An end-to-end review ran on 2026-10-20 against a development build
   (§16). Its low and info findings, as handled and decided on
   2026-10-20:
   - SR-1: no replay protection. A FIT seen in clear (a TLS-terminating hop,
     a proxy that logs headers) can be reused with any body until
     `exp + RELAY_CLOCK_SKEW`, and the relay adds the credential each time.
     Check first whether FITs carry `jti` and whether Forge ever reuses one;
     then a seen set for `POST /oidc/token` until `exp + skew`.
     **Closed, not built (2026-10-20): Forge reuses FITs.** _Forge Remote
     essentials_ documents neither `jti` nor `iat`, so an owner-approved
     spike measured it in the Forge app's development environment
     (8.9.0, a never-merged branch; the app's `PLAN.md` §4.7, "FIT reuse
     spike"). A temporary route in the `sso` web trigger, the function
     `/cb` runs in, made three sequential and three parallel `invokeRemote`
     calls per request to `GET /relay/v1/info`. A standard-library
     inspector at the remote URL verified each FIT against the Forge JWKS
     and logged only claim names, the dates, whether `jti` was present and
     12-character hashes of `jti` and the signature. Of 24 calls, all
     validly signed: three invocations back to back made 18 calls with only
     11 distinct FITs, one of them used for 4 calls across all three
     invocations within about 3 s; one invocation 30 s later made 6 calls
     with 6 FITs. A `jti` always came with the same signature. Every FIT
     carries `jti` and `iat`; `nbf` is `iat - 30 s` and `exp - nbf` 55 s.
     Claims: `app`, `aud`, `context`, `exp`, `iat`, `iss`, `jti`, `nbf`.
     A one-time-use set, by `jti` or by signature, would therefore refuse
     legitimate logins, such as two users on one site within seconds, so
     it is not built. The exposure stays as described above: a FIT seen in
     clear is usable for about 35 s with the default skew. The mitigations
     are the deployment's: TLS terminated only by the customer's own front
     end, which must not log headers (`docs/SETUP.md` 6.3), and TARA's
     single-use codes bound to PKCE.
   - SR-4 (fixed 2026-10-20): an inline `RELAY_UPSTREAM_AUTH` (rather
     than `_FILE`) shows in `docker inspect` and the process environment;
     startup now warns about it (§10).
   - SR-5 (fixed; refusal decided by the owner, 2026-10-20):
     `RELAY_UPSTREAM_URL` accepted any HTTPS origin, so a wrong or
     social-engineered value would send TARA's credential there. Startup
     now refuses anything but TARA's two origins unless
     `RELAY_UPSTREAM_ANY_HOST=true`, with a documented
     `invalid configuration` line (§8).
   - SR-6 (info, owner decided 2026-10-20): `exp - nbf` is capped at 5
     minutes and `iat` stays ignored (§4.4); FITs span 55 s. The remote key is not pinned: the app
     has one remote, and which claim names it on this path is unrecorded.
   - SR-7 (info, decided not to build; owner, 2026-10-20: "no need to
     check that"): no `Content-Type` check on forwarded bodies. Only a
     caller holding a valid FIT reaches the forwarder, and it can send a
     well-formed form anyway; a refusal would need a new relay error code
     (say `415 unsupported_media_type`) that the Forge app would have to
     learn. The app sends only the fixed form from `/cb`, and TARA judges
     the body itself.
   - SR-8 (info, fixed 2026-10-20): relay answers now carry
     `Cache-Control: no-store` and `nosniff` (§4.3).
   - SR-9 (info, fixed 2026-10-20): errors Go's server answers itself
     (431, 400) now log a `request` line with `error` `http_server` (§10).

   Not covered by that review, still to do: TARA live (the allowlist and
   live client), the Caddy front end with its `remote_ip` filter and
   inbound HTTP/2, load and the JWKS outage acceptance run (the soak
   passed on 2026-10-21, §13), PINNED (§15 Q3), and `govulncheck` on a
   release build.
5. **Publish:** public repository (2026-11-26), `LICENSE` and `SECURITY.md`
   (both added 2026-11-24, §16), support policy, `v1.0.0` (tagged
   2026-11-26, ahead of Phase 4: owner's decision, §16).

## 15. Open questions

1. ~~Does a backend `invokeRemote` from a web trigger carry
   `context.cloudId`?~~ Yes, the calling site's bare UUID (Phase 0,
   2026-10-16, §14).
2. ~~Does `invokeRemote` give the function custom headers and non-2xx
   bodies?~~ Yes, both; non-2xx answers are returned, not thrown (§14).
3. Does a configurable compute-only remote keep the app PINNED? Not yet
   observed: needs a site with data residency; the egress guide says no
   (§14).
4. Decided (owner, 2026-10-17, D11): only TARA's token endpoint is in scope.
   The relay does not forward JWKS, profile or other-provider calls.
5. A customer with no host or static IP cannot use TARA production in v1
   (D1). Revisit if customers ask for it.
6. ~~The publication date and the image name.~~ Decided: the repository is
   `Oktul/eID-TARA-remote` (owner, 2026-11-24) and public since 2026-11-26;
   the image is `ghcr.io/oktul/eid-tara-remote`, the name `lib.sh` derives
   from the repository, and the first release is `v1.0.0` (owner,
   2026-11-26). The deploy files, module path and docs follow (§16).
7. Decided (owner, 2026-10-16, on the recommendation to keep it simple and
   secure): `RELAY_JWKS_MAX_AGE` is measured on the monotonic clock, not
   wall-clock time. A removed key is trusted until the next successful
   refresh: within one refresh interval of running time when the JWKS is
   reachable, and at most `RELAY_JWKS_MAX_AGE` of running time during an
   outage. Suspended time does not count, which only matters when the JWKS
   is also unreachable after a resume; a wall clock would add a way to fail
   instead, since an NTP step could expire good keys (§4.5).
8. Decided (owner, 2026-10-16, same recommendation): `RELAY_CLOCK_SKEW` is
   at most 1 minute; a clock further off must be fixed, not tolerated (§8).
9. Can a customer-managed remote be deployed without `baseUrl`, as the
   remotes reference says? Not on 2026-10-16 (§14); report it to Atlassian
   or accept a placeholder `baseUrl` and the major version it causes.

## 16. Review evidence and implementation gates (2026-10-15)

The plan review changes in §9 are accepted for documentation. No Phase 0
experiment had run then. This revision authorized no implementation; D10, later
the same day, authorized Phases 1 and 2 in this repository. Forge
integration, tags and pushes remain unauthorized.

- [x] Define unambiguous tenant pins, strict parsing and key trust expiry.
- [x] Isolate automatic patches from unreleased development work and specify
  maintenance for every supported line.
- [x] Define connection/health limits, log redaction and forwarding exclusions.
- [x] Make this plan self-contained and move basic CI before the first tag.
- [ ] Record Phase 0 approval and all exit-gate results in §14.
- [ ] Record Phase 1 contract/source checks and Phase 2 release failure tests.
- [ ] Record measured acceptance results, soak and security review before v1.

**Simplification follow-up (owner, 2026-10-17).** The body and concurrency
limits are constants throughout the implementation, with no constructor
options or per-instance copies solely for tests. Failure fixtures now use
the actual 64 KiB limits and 50 concurrent requests. Port and Unicode-escape
hex digits use bounded `strconv.ParseUint` rather than local parsers; port
rejections and strict Unicode tests remain. The obsolete decimal-parser
fuzzer and its seeds were removed with that parser.

`gofmt -w .`, `go vet ./...`, `staticcheck ./...`, `go test -race ./...`
and `govulncheck ./...` pass in order on this change; no vulnerabilities
found. Race tests use the pinned Go 1.27.2 Linux builder. No protocol or
setting changes are part of this cleanup.

**TARA-only follow-up (owner, 2026-10-17, `codex/simplify-tara`).** D11
replaces configurable routes, upstream base paths and response headers with
the fixed token exchange. The info document keeps its existing fields and
reports the single route. Deployment examples, the smoke test and the load
generator no longer supply removed settings. Tests retain raw-target and
wrong-method rejection, header filtering, body limits, cancellation and
token POST replay failures; obsolete route/path parser fuzzers were removed
with their implementations.

All five required Go checks pass in order, including race tests in the
pinned Go 1.27.2 Linux builder; no vulnerabilities found. The linux/amd64
image builds and passes the repository smoke test. Compose configuration
passes with and without Caddy. Independent agents reviewed the runtime
changes without open findings or disagreements. Claude's round 3
(2026-10-17) checked both commits against TARA's token request
specification and found no defects; it fixed comments only. The owner
fast-forwarded `main` to it on 2026-10-17; nothing is pushed or tagged.

**Code-convention review fixes (owner-approved, 2026-10-15):**

- [x] Scope disclosure checks to logs, diagnostics and relay-generated
  errors; preserve protocol-authorized forwarding of upstream bodies and
  headers (§4.3, §5, §10).
- [x] Keep reusable implementation packages under `internal/`, with the
  executable entry points in `cmd/relay/` and `test/load/` (§11).
- [x] Apply context-first to project-defined I/O and waiting functions;
  preserve standard-library interface signatures and propagate cancellation
  through the request or underlying operation (§6).

Validation of these documentation fixes (2026-10-15, before any source
existed): the five required Go commands were
attempted in order but could not start because `gofmt`, `go`, `staticcheck`
and `govulncheck` are unavailable. There is still no Go source or `go.mod`;
no passing source-check result is claimed.
The owner approved documentation-only commits with this limitation on
2026-10-15; the Go checks remain mandatory once source and tools exist.

Documentation validation for this revision (2026-10-15, before any source
existed): the required `gofmt -w .`,
`go vet ./...`, `staticcheck ./...`, `go test -race ./...` and
`govulncheck ./...` commands were attempted in order but could not start
because those executables are unavailable in this workspace's command path.
There is no Go source or `go.mod` yet, so no source-check result is claimed.
Document consistency and whitespace checks apply to this planning revision;
the Go checks remain mandatory once the Phase 0/1 source and tools exist.

**Implementation record (2026-10-16, D10).** Phase 1 was written on
`claude/phase-1-relay-core` and Phase 2 on `claude/phase-2-packaging`
(both merged into `main`, branches deleted 2026-10-17); Phase 2 forks from Phase 1 at `ec2357f`, before Codex's review, and carries
Codex's Phase 1 fixes as its own commits. Claude agents wrote both phases;
other Claude agents reviewed them in three rounds before Codex's round
(`AGENTS.md`), the third only of the second's fixes, each finding checked by
a skeptic: 87 confirmed findings were fixed (52, 25 and 10) and 12 refuted.
Results on the final tree, on Windows with Go 1.27.2:

- `gofmt`, `go vet ./...`, `staticcheck ./...` (2026.2.2) and
  `govulncheck ./...` (v1.9.0, no vulnerabilities) pass.
- `go test -race ./...` passes in the pinned `golang:1.27.2-trixie` image on
  linux/amd64; the workstation has no C compiler for the race detector.
- Every fuzz target ran for seconds to a minute; the hour-long run before
  v1.0.0 (§13) is still to do.
- The image builds; `.github/scripts/smoke.sh` passes on linux/amd64;
  linux/arm64 was cross-built only. `docker compose config` passes with and
  without the Caddy profile. `caddy validate` and `caddy fmt` pass on
  `deploy/Caddyfile` with the pinned Caddy 2.11.7, also with the S-9 IP
  filter switched on, and the adapted configuration carries the §6 proxy
  limits.
- Not run: any GitHub workflow (the repository has no remote), `gitleaks`,
  `shellcheck` and `actionlint` (not installed) and Kubernetes server-side
  validation (no cluster).
  The workflow scripts were exercised against local bare repositories with
  the registry, go.dev and `gh` stubbed.

**Codex review, round 2, packaging branch (2026-10-16).** The packaging
branch predates the Phase 1 review fixes; they are checked and carried here
as separate commits, alongside the Phase 2 review.

- Made the documented inbound connection cap a prerequisite of production
  Caddy deployments (§6). Its backend connection cap does not bound
  frontend clients; both the quick start and proxy guide now require the
  firewall/load-balancer cap already specified by the plan. All five
  required Go checks pass after this documentation change.
- Fixed the load generator's false acceptance when `full` never reaches
  the concurrency cap (§13). It now fails with a request to increase the
  worker count or upstream delay. The regression failed before the fix;
  a run seeing both forwarding and overload remains accepted. All five
  required Go checks pass, including Linux race tests; no vulnerabilities
  are reported.
- Fixed support selection so only release lines with a release tag can
  choose the current or previous major (§12). Preparing an unreleased
  future-major branch no longer drops the still-supported previous major
  from daily patches and weekly scans. Ten cases in one temporary Git
  repository cover
  unreleased majors/minors, transitions, no releases and support expiry;
  `ci.yml` and automatic-patch source checks run them. All five required
  Go checks and the ten release-line fixtures pass.
- Carried the HTTP/1.1-only upstream response check from the Phase 1 review
  (§4.3, §5). Raw TLS fixtures cover HTTP/1.0, HTTP/1.2 and HTTP/2.0
  rejection and a successful HTTP/1.1 answer.
  All five required Go checks pass on this branch, including the Linux
  race tests; `govulncheck` reports no vulnerabilities.
- Carried the Phase 1 suppression of standard-library HTTP diagnostics
  (§10). Both serve and healthcheck discard raw unsolicited-response
  diagnostics; explicit JSON request and lifecycle logs remain. HTTP
  regression fixtures cover both commands. All five required Go checks
  pass, including Linux race tests; no vulnerabilities are reported.
- Carried the Phase 1 early-response fix (§4.3, §6): local answers close
  connections with unread bodies before net/http can drain past the write
  deadline. Declared/chunked fixtures also verify keep-alive after a full
  forwarded-body read. All five required Go checks pass, including Linux
  race tests; no vulnerabilities are reported.
- Carried the Phase 1 removal of token POST replay callbacks (§5).
  A transport-boundary fixture verifies that nonempty token POSTs have no
  replay callback; existing delivered-but-lost-response coverage remains.
  Go therefore no longer resends such a POST when nothing was written, and
  a 307 or 308 answer to it skips Go's redirect parsing, so a malformed
  `Location` comes back wrapped (D7) instead of as 502.
  All five required Go checks pass, including Linux race tests; no
  vulnerabilities are reported.

**Open finding, owner decision required (2026-10-16).** Support expiry in
`.github/scripts/lines.sh` uses `creatordate` of `vN.0.0`. For an annotated
tag it is the tagger date; for a lightweight tag it is the commit date
([Git's field definitions](https://git-scm.com/docs/git-for-each-ref#_field_names)).
An isolated Git/jq reproduction created a lightweight `v2.0.0` today on a
two-year-old commit: selection immediately dropped `1.0`, contrary to its
12 months of support after the new major's release (§12). An annotated tag
created today on the identical commit kept both majors. The contract does
not require annotated tags or define another authoritative release-date
source. This finding is reported rather than fixed under `AGENTS.md`:
the owner must choose that source or a tag requirement before the support
automation is accepted. No design decision or disagreement is recorded.
Decided by the owner on 2026-10-16: `taggerdate`, annotated release tags,
and a warning while `vN.0.0` has no tagger date (§12).

Final local validation of the packaging review fixes (2026-10-16):

- `gofmt -w .`, `go vet ./...`, `staticcheck ./...`, `go test -race ./...`
  and `govulncheck ./...` pass; no vulnerabilities found. Race tests run in
  the pinned Go 1.27.2 Linux builder. The local `go.mod` had retained CRLF
  from its original creation; normalizing it to the existing LF attributes
  also made the Linux-mounted module/builder pin check pass, with no Git
  content change.
  The complete shared `source-checks.sh all` run also passes in the Linux
  builder, including the pinned analysis tools and the secret scan.
- All ten supported-line fixtures and their shared source-check entry
  point pass. actionlint v1.7.12 passes on all workflows. ShellCheck 0.10.0
  exits 1 with four informational diagnostics in existing scripts:
  SC2015 for an intentional compound guard, SC2153 twice for uppercase
  variables supplied by workflows, and SC2016 for literal Markdown in a
  single-quoted format string. Review found no defects in these cases; no
  diagnostic suppressions were added.
- Both image builds and the repository smoke script pass on linux/amd64
  and linux/arm64, the latter under local emulation. Compose config passes
  with and without Caddy; the pinned Caddy validates its configuration.
  An initial Windows smoke invocation failed because disabling path
  translation globally broke curl's `/dev/null`; limiting that adjustment
  to Docker made both complete smoke runs pass.
- The checksum-verified gitleaks 8.30.1 history scan passes, no leaks found.
- Independent Codex agents reviewed the release, maintenance and deployment
  changes and the review fixes; no additional confirmed findings remain.
  Claude's commits were neither amended nor rebased. Seven focused review
  fixes were added; the release-date finding above remains open. No merge,
  push, repository tag or publication was performed.

**Claude review, round 3 (2026-10-16).** All seven Codex fixes stand: each
defect reproduces, the six code fixes' regression tests fail with the fix
reverted, and no fix conflicts with the plan; nothing is reverted and there
is no disagreement. Round 3 changed only comments, docs and records: §4.3
and §5 now state the HTTP/1.1-only status line and the lost token POST
resend, `docs/PROTOCOL.md` matches them and the early-answer
`Connection: close`, stale comments are corrected and `README.md` is
rewritten as a short entry point. `gofmt`, `go vet`, `staticcheck`, `govulncheck` (no
vulnerabilities) and `go test` pass on Windows, `go test -race ./...` in the
pinned builder, and the ten release-line cases with jq. Open findings, which
block `main`:

- The release-date finding above. Recommended: read `taggerdate` instead of
  `creatordate`, so a lightweight `vN.0.0` keeps the previous major and
  warns; require annotated release tags in §12; add a lightweight-tag case.
- `TestServeKeyLoopStopsAfterInFlightRequests` fails about once in 100
  runs under `-race`. When the test takes over `FITKeyWait` (1 s) to
  release the held JWKS fetch, the relay rightly answers 401; a 1.1 s pause
  fails it every time. The test needs a timing margin, not the relay.
- `go-patch.sh` only logs a notice when a line has a release tag but none on
  its branch, while `lines.sh` still counts the line as supported, so it
  silently gets no Go patches. §12 requires an issue in that case.

Owner questions, not blocking: may a third major released inside the
previous major's 12-month window end the oldest major early (the code and
§12's wording say yes, `docs/SUPPORT.md` promises a fixed date)? Should every
3xx with a malformed `Location` come back wrapped, not only 307 and 308 to a
POST with a body? Follow-ups for the next change: more `lines-test.sh` cases
(pre-releases, several minors, the 12-month boundary) with Git's local
environment cleared; `logging_test.go` asserting `log.Writer() == io.Discard`;
and the load generator naming the proxy limit in its overload hint.

The packaging branch contains Phase 1 with the same fixes, so `main` can be
fast-forwarded to it once these findings are closed; the Phase 1 branch is
then superseded.

**Round-3 findings fixed (2026-10-16), awaiting Codex's review.** Each fix
has a case that fails without it:

- Release dates: `lines.sh` reads `taggerdate`, so a lightweight `vN.0.0`
  or a missing one keeps the previous major and warns;
  `release.sh check-ref` refuses lightweight release tags (§12).
  `lines-test.sh` and the new `release-test.sh` cover both. The pinned `actions/checkout` fetches
  `+refs/tags/*:refs/tags/*` for a commit with `fetch-depth: 0`, so
  check-ref sees tag objects (its source, read 2026-10-16).
- Off-branch releases: `go-patch.sh prepare` now opens the "not on the
  branch" issue also when none of a line's release tags is on its branch,
  instead of a notice, as §12 requires. The new `go-patch-test.sh` runs
  prepare against a local origin with a stub `gh`.
- Flaky test: `TestServeKeyLoopStopsAfterInFlightRequests` repeats, up to
  three times, an attempt answered 401 `invalid_token` after at least
  `FITKeyWait`, since the relay may then rightly have stopped waiting; any
  other failure, and a 401 sooner, fails at once. A key worker stopped at
  the signal fails it within milliseconds. 900 `-race` runs in the pinned
  builder pass; of 600 checked, 8 needed a second attempt.

Open at that point: Codex's review of these fixes (round 2), then Claude's round 3.

**Phase 0 dry-run fix (2026-10-16), branch `claude/jwks-padding`, awaiting
Codex's review.** Preparing the spike, the relay was run against
Atlassian's live JWKS and never became ready: each refresh failed with
`key_parameters` because Atlassian pads `n`. The owner decided to accept
exact padding on `n` and `e` only (§4.5). `jwks_test.go` covers both
padded lengths, a padded `e`, a set shaped like the live one and every
misplaced `=`; the fuzz oracle accepts both spellings, and a one-minute fuzz
run of `FuzzParseJWKS` passed. The relay built from this branch reached
`/readyz` 200 against the live JWKS.

Then still open before the Phase 1 exit: the Phase 0 gates, source CI
passing on GitHub and the review of the fixes above. Phase 2 also needs its release
verifications (§14) on a GitHub repository.

**Codex review, round 2, Phase 0 results (2026-10-16).** Removed the real
test-site label from the spike evidence in §14. Only the site's capability
matters to the PINNED gate; the label violated the sanitized-evidence rule.
The recorded observations and the open PINNED gate are unchanged.
`gofmt -w .`, `go vet ./...`, `staticcheck ./...`, `go test -race ./...`
and `govulncheck ./...` pass in order; no vulnerabilities found. Race tests
use the pinned Go 1.27.2 Linux builder. All release-script fixtures pass.

The protocol guide still described custom headers and non-2xx bodies as
unverified, and generalized bridge error handling to backend `invokeRemote`.
Updated `docs/PROTOCOL.md` and D7's rationale to agree with the observed
backend responses in §14; the v1 response contract is unchanged.
All five required Go checks pass again in order after this correction,
including Linux race tests; no vulnerabilities found.

Independent reviewers found no runtime defects in `claude/jwks-padding` or
the environment-ARI update, and confirmed the three inherited round-3
findings are fixed. The release-script fixtures pass, and the shutdown-order
test passes 20 additional repetitions. No disagreements remain. Claude's
round 3 was still required; no merge, push, tag or publication was performed.
`FuzzParseJWKS` passes a further one-minute run (1,834,667 inputs).

**Open public-ready finding (resolved by the owner's decision below):** the
removed site label remains in Claude's original local commits. `AGENTS.md` forbids amending or rebasing them, so
history sanitization or an explicit exception needs the owner's decision
before publication. The current tree contains no such label.

**Claude review, round 3, Phase 0 changes (2026-10-16).** Reviewed the
whole branch on top of `claude/phase-2-packaging` (`153e94a` to `d9a7371`;
hashes after the rewrite below), Codex's two commits in particular. Both
stand: `70a5ca9` removes the test-site label, which `AGENTS.md` forbids as
an internal hostname, and `d9a7371` makes D7's rationale and `docs/PROTOCOL.md` match §14 without
changing the v1 contract. No new findings and no disagreements.

- Checks on the tip: `gofmt -w .` (no changes), `go vet`, `staticcheck`
  and `govulncheck` (no vulnerabilities) pass; `go test -race ./...` passes
  in `golang:1.27.2-trixie`; `lines-test.sh`, `release-test.sh` and
  `go-patch-test.sh` pass in the same image with `jq` added.
- Identifier search: the tree and every branch's history were searched
  for the spike's site names, app, site, environment and installation IDs,
  trigger and tunnel names and test accounts. The tree was clean; the only
  hit in history was the site label that the original "Record the Phase 0
  gate results" commit added and Codex's sanitizing commit removed.
- Branches: `codex/review-phase-0-results` contains `main`, the packaging
  line, both Phase 0 branches and `codex/fix-code-conventions`.
  `claude/phase-1-relay-core` is superseded (its four Codex fixes are
  carried as `0de8b4e`, `a009555`, `9ca9e8d` and `8553f75`), and
  `claude/wip-backup` is an old work-in-progress backup whose content has
  landed. Neither was deleted without the owner's word; the owner had both
  deleted on 2026-10-17.

**Owner decision (2026-10-16): rewrite the unpushed line once, then
fast-forward `main`.** The owner allowed Claude a one-time exception to
`AGENTS.md`'s no-rewrite rule. "Record the Phase 0 gate results" was
replayed on `2d55c3b` with Codex's wording in place of the label (now
`a8b9f2a`), and the four later commits were cherry-picked unchanged with
their messages and authors (`76e588e`, `70a5ca9`, `d9a7371`, `627dae0`).
The final tree is identical to the old tip's, and no commit from `main` to
the tip contains the label; Codex's sanitizing commit now changes only §16.
The old commits stay in the local reflog until Git prunes them; nothing
was ever pushed. `claude/phase-0-results` and
`codex/review-phase-0-results` pointed to the rewritten commits (both
deleted 2026-10-17), and `main`
is fast-forwarded to this commit.

**End-to-end security review (2026-10-20, owner's request).** A local
image of `main` (`0.0.0-dev`, Docker Desktop, the hardened compose
settings) behind a Cloudflare quick tunnel, called by the Forge app's
development environment on a test site with TARA demo. Full report, with
the Forge side, in the Forge app repository's
`docs/token-relay-security-review.md`. Not a v1 gate: no release build,
no Caddy front end, no soak, `govulncheck` not run (no network).

- **Passed, black-box:** health exemption exact (`HEAD /livez`,
  `/readyz?x`, `/livez/` need a FIT); every other target without a FIT is
  `401 invalid_token`, so no route is disclosed (including `//`, `..`,
  `%74`, absolute form, `CONNECT`, `TRACE`, `OPTIONS *`); `alg` `none`,
  HS256, our own key with a real Atlassian `kid`, `jwk`/`jku`/`x5u`
  headers, tokens over 8 KiB and padded base64url refused; two
  `Authorization` fields refused; 30 KiB headers `431`; a 70 KiB body
  refused before it is read; double `Content-Length` `400`; `Content-Length`
  plus chunked gives one answer; no h2c; an unfinished header closed after
  5 s; logs hold fixed fields only (no token, path, credential or client
  IP); the image is `scratch` without a shell; the container runs as
  65532, read-only, without capabilities.
- **Passed, end to end:** a demo login through the relay
  (`upstream_status` 200); a wrong `RELAY_CLOUD_IDS` refused with
  `cloud_id` before the upstream; a wrong credential forwarded and TARA's
  `400 unauthorized_client` wrapped; a wrong CA file `502
  upstream_unreachable` without sending the credential; an unreadable CA
  file stops startup.
- **Findings**, numbered SR- (security review) so they do not clash with
  the R- requirements in §6. None is critical, high or medium.
  - SR-2 (reproduced, fixed 2026-10-20): the slot was taken before the FIT
    check; 80 parallel unknown-`kid` requests got 30 `503 too_busy` while
    one JWKS refresh ran (about 60 ms). The owner decided on 2026-10-20 to
    take the slot after the FIT and route checks (§4.2 step 3). Under §4.6
    this keeps protocol v1: every code and its meaning stay, a caller with a
    valid FIT sees `too_busy` only on a token POST, and `too_busy` now
    carries `Relay-Version` like every authenticated answer. No relay has
    been released, so none in the field behaves otherwise.
    `TestKeyWaitHoldsNoSlot` fails on the old order; the load test's
    `invalid` and `unknown-kid` scenarios now fail on any `too_busy`.
  - SR-3 (closed, owner 2026-10-20): the Caddyfile's Atlassian-range filter
    ships commented out, and Caddy bounds only its connections to the
    relay. It stays so: `docs/SETUP.md` 6.3 and 6.4 make the filter and an
    inbound connection cap required setup steps.
  - Docs (fixed 2026-10-20): `docs/SETUP.md` 6.3 now says a front end must
    pass the relay's answers through unchanged (the Cloudflare tunnel
    replaced the relay's `502` with its own page, so the app saw no
    `Relay-Protocol`), and that whatever terminates TLS in front of the
    relay sees the code and TARA's token answer (personal data). The host
    clock (the test VM's ran about 1 s ahead) was already in
    `docs/SETUP.md` 7.
  - SR-4, SR-5, SR-8 and SR-9 were fixed and SR-6 decided on
    2026-10-20; SR-1 was closed without a fix after a spike showed Forge
    reuses FITs, and SR-7 was decided not to be built (owner). Details and what the review did not cover: §14, Phase 4.

**Codex review, round 2, security hardening (2026-10-20).** Reviewed
`main...claude/security-review-hardening` through `84c59f7` against this
plan and the contributing checklist. Fixes live on
`codex/review-security-review-hardening`; Claude's commits are unchanged.

- Fixed SR-9 tracking on reused connections: a malformed request or an
  unsupported transfer coding already buffered behind a handled request
  can fail parsing without net/http emitting `StateActive`. The previous
  request's handled flag then hid the rejection. Resetting at `StateIdle`
  too preserves one fixed-field request line for each refusal (§10).
  Both pipelined regression cases fail without the fix. Additional
  fixtures cover the documented 417 and 501 refusals and log redaction.
- Replaced the exported mutable TARA-origin slice with two constants.
  The host guard implements a fixed policy (§8, SR-5); making it writable
  from other packages violated the contributing rule against package-level
  mutable state. Existing host-guard fixtures retain all acceptance and
  refusal cases, and the diagnostic text is unchanged.
- Fixed the lifetime cap's fractional boundary (§4.4, SR-6). Reusing the
  inward-rounded validity dates could admit a lifetime just over five
  minutes by less than two nanoseconds. The cap now compares outward
  bounds, retaining the rule that rounding can only reject. Both over-cap
  regression cases fail without the fix; exact nanosecond boundaries and
  an inexact lifetime within the cap remain accepted.
- `gofmt -w .`, `go vet ./...`, `staticcheck ./...`,
  `go test -race ./...` and `govulncheck ./...` pass in order; no
  vulnerabilities found. Race tests run in the pinned Go 1.27.2 Linux
  builder with networking disabled. The five checks pass again after each
  further fix. A local linux/amd64 image build and the repository
  smoke test pass with the new override setting.

SR-1 still needs the FIT-reuse evidence and SR-7 the owner's decision
recorded in §14; neither is silently closed by this review. No
disagreements. No merge, push or tag was performed.

**Claude review, round 3, security hardening (2026-10-20).** Reviewed
`main...codex/review-security-review-hardening`, Codex's three commits in
particular, against this plan and the contributing checklist. No new
findings and no disagreements; all three fixes are accepted as made.
Removing the `StateIdle` reset makes `TestPipelinedTransportRejection`
fail again, so it guards a real case. The lifetime cap now parses each
date twice with opposite rounding; the discarded errors cannot occur,
since the same values parsed a line earlier. `gofmt`, `go vet`,
`staticcheck`, `go test ./...`, `go test -race ./...` (Go 1.27.2 Linux
image) and `govulncheck` (no vulnerabilities) pass on Codex's tip. The
owner's open decisions remain: refusing rather than warning on a
non-TARA upstream, the 5-minute cap, the SR-1 spike and SR-7 (§14).
The SR-1 spike then ran the same day and showed that Forge reuses FITs,
so SR-1 is closed without a seen set (§14); the 5-minute cap fits the
measured 55 s `exp - nbf`. The owner then decided the rest on 2026-10-20:
keep refusing a non-TARA upstream (SR-5), keep the 5-minute cap (SR-6) and
do not check `Content-Type` (SR-7). A test now pins SR-5's startup line.

**Merge without a further Codex round (owner, 2026-10-20: "merge it
without another codex round").** Codex reviewed the branch through
`70ef315`. The three later commits change no relay behaviour: `b845c94`
is this plan only, `ec89262` docs and comments in `internal/fit/verify.go`,
and `fc6b63b` docs plus a test that pins the SR-5 startup error reviewed
in `ef61a91` and `1425571`. `AGENTS.md` sends only behaviour changes back
to round 2, so the owner had `main` fast-forwarded to
`claude/round3-security-review-hardening` with these commits reviewed by
Claude alone.

**Codex review, round 2, soak and JWKS outage (2026-10-20).** Review fixes
live on `codex/review-soak-jwks-outage`; Claude's commit is unchanged.
Four fixes:

- The outage's readiness exception now requires the exact relay
  `503 not_ready` answer, including its protocol, error header, content
  type and body (§4.1, §4.3). Previously any `/readyz` 503, including a
  proxy failure or `too_busy`, counted as evidence of expired keys.
  Negative fixtures cover these answers and oversized health bodies.
- The paced backlog and soak progress tests now use `testing/synctest` and
  an injected HTTP client (§13), removing their real 200 ms timeout and
  tickers as required by `CONTRIBUTING.md`. In-memory responses keep all
  waits inside the fake clock, including the held request in the backlog
  test. Both pass 100 repetitions under the race detector.
- The soak's upstream-call accounting moved into the shared verdict, so
  the JWKS outage (and `full`) checks it too (§4.2, §13). Previously an
  expired-key request could reach the upstream and then be answered
  `not_ready` without failing the outage. A fake-clock run of the complete
  five-minute outage proves expiry, readiness, restoration and recovery,
  fails when such hidden upstream calls are introduced, and passes 20
  race-enabled repetitions.
- The soak matches each answer to the FIT it sent (§4.4, §13). Accepting
  either outcome in aggregate could pass a relay that forwarded bad
  signatures (with `-body-bytes 0`) or refused most valid FITs. The paced
  observer now includes the request sequence; both faults are counted as
  fixed error classes and have fake-clock regression cases that pass 100
  race-enabled repetitions.

`gofmt -w .`, `go vet ./...`, `staticcheck ./...`, `go test -race ./...`
and `govulncheck ./...` pass in order after each fix, with no
vulnerabilities found; race tests use the pinned Go 1.27.2 Linux builder
with networking disabled. No open findings or disagreements remain in this
review. Claude's round 3 is still required; no merge, push or tag was
performed. The VM acceptance runs, including the 72-hour soak, remain open.

**Claude review, round 3, soak and JWKS outage (2026-10-20).** All four
Codex fixes stand; there is no disagreement and no behaviour change in
this round. Checked against the relay itself: `writeError` sends exactly
the `/readyz` answer the stricter probe requires (`server.go`), and every
`full` request that reaches the upstream returns a forwarded answer, so the
shared upstream-call check cannot fail a healthy `full` run. A live run of
the branch's generator (`5ca4e50`) against the relay image in Docker
Desktop passed: a 1-minute soak (300 requests, 30 rejected as sent, p99
172 ms) and the outage (`/readyz 503 not_ready` 187 times, never another
probe failure, keys expired at 2m0s, forwarding back at 3m33s, upstream
calls equal to forwarded answers). The five checks pass, `-race` in the
pinned builder without network. Round 3 changed only records: this entry
put in order and §13 aligned with the stricter checks.

**CI failure, caller-cancel test (2026-10-21).** CI's `go test -race` on
`main` (2026-10-20) failed `TestForwardCallerCancelCancelsUpstream` with a
nil error; it fails about 3 times in 20,000 runs in the pinned builder. A
test bug, not a relay bug: the stub upstream returned once the relay hung
up, so net/http sent an empty 200. Go's TLS client sends close_notify
before closing, the stub answered on seeing it, and Go's transport keeps a
response that races its own cancellation. Forward returned that complete,
bounded upstream answer; with the caller gone, nobody received it, and only
the log differs (the upstream status instead of `client_canceled`). Stalled stubs in `internal/forward` and the server tests' gate now
abort the connection instead of answering. The other checks passed, but
`govulncheck` reported GO-2026-6809 (`crypto/x509`, distrusts compromised
intermediate certificates, fixed in Go 1.27.3), reachable through
`server.Run` → `http.Server.Serve` → `x509.Certificate.Verify`. No
`release/X.Y` line exists yet, so §12's automatic patch does not apply;
`go.mod`'s toolchain and the `Dockerfile` builder (tag and index digest)
were moved to Go 1.27.3 by hand on the development branch. The five checks
then pass, `govulncheck` with no vulnerabilities and `-race` in the pinned
Go 1.27.3 Linux builder with networking disabled.

**Merge without a Codex round (owner, 2026-10-21).** The owner had `main`
fast-forwarded to `claude/recursing-pascal-648621` without round 2.
Claude sessions wrote `8088bd4` (the test fix) and `761d190` (the
toolchain); another Claude session read both diffs: the fix changes only
test stubs and this plan, and no Go 1.27.2 pin remains outside this plan's
history. On GitHub, `ci` passed every job on the branch; on `main` at
`bf1cb04` it had failed only on GO-2026-6809.

**Go 1.27.4 (2026-11-19), branch `claude/go-1.27.4`.** The weekly scan of
`main` failed on 2026-11-16 and opened `weekly govulncheck: findings`:
`govulncheck` reports GO-2026-6859 (`net/http`: an HTTP/1 server can crash
when a handler reads a `MaxBytesReader` body while it writes the response
header; fixed in Go 1.27.4). The relay reads the request body through
`MaxBytesReader` (`readBody`), but its handler reads the body and sets
headers on one goroutine, one after the other, so the race has no second
party here; that is read from the code, not tested. The finding still fails
`ci` on every push and would fail a release's checks. No `release/X.Y` line
exists, so §12's automatic patch does not apply, as on 2026-10-21:
`go.mod`'s toolchain and the `Dockerfile` builder (tag and index digest)
were moved to Go 1.27.4 by hand. On the change: `gofmt`, `go vet`,
`staticcheck` (2026.2.2), `go test ./...` on Windows and `govulncheck`
(v1.9.0, no vulnerabilities) pass; `go test -race ./...` passes in the
pinned Go 1.27.4 Linux builder; the linux/amd64 image builds and passes
`.github/scripts/smoke.sh`. No source, test, workflow or protocol change.

**Merge without a review round (owner, 2026-11-19: "Merge and push").**
Asked whether to merge the Go 1.27.4 commit (`86b81a0`) without a Codex
round, as on 2026-10-21, the owner had `main` fast-forwarded to
`claude/go-1.27.4` and pushed. A Claude session wrote the commit and no
other agent read it: it changes the `go.mod` toolchain line, the
`Dockerfile` builder line and this plan, which is the diff §12 lets
`go-patch.yml` ship unreviewed on a release line.

**Documentation review (2026-11-19, owner's request), branch
`claude/docs-mismatches`.** A review of `main`
compared the documents with the code. Settings, protocol, log strings and
deploy hardening matched; these did not, and are corrected with no code
change:

- `docs/SETUP.md` 10.3 still said a request the HTTP server refuses leaves
  no log line; since SR-9 it logs one (§10), as its section 11 says.
- `docs/PROTOCOL.md` §8 said the customer adds only the credential; §8 here
  and `docs/SETUP.md` say the credential and TARA's CA file.
  `docs/SETUP.md` 3.2 now links TARA's specification 5.1.2, which names the
  root certificates (read 2026-11-19).
- `README.md` and `docs/SETUP.md` said the admin-page parts "arrive with"
  Phase 3, which is on the Forge app's main line since 2026-10-18 (§14).
- `docs/SETUP.md` 8 omitted the startup summary's `set` (inline credential)
  and `system bundle` values, and section 2 said to copy the block
  unchanged where section 4 has its four values replaced one by one.
- §5 and `docs/PROTOCOL.md` 6.2 now state that the relay's HTTP client
  sends Go's own `User-Agent`, which the tests already pin.

Left for the owner, not changed:

- Watchtower, which §12 and `docs/SETUP.md` 9 name for automatic patches
  on Docker, was archived by its maintainers (GitHub, pushed last
  2025-12-17; read 2026-11-19). It needs a replacement, such as a
  scheduled `docker compose pull && docker compose up -d`.
- The deploy files pin `0.1.0` while §14 publishes `v1.0.0`.
- Nothing in `docs/SETUP.md` 8 detects a missing inbound connection cap
  (SR-3), and no step checks the credential, CA file and registered IP
  before the first login. A missing IP filter is now caught: step 5 asks
  for `/livez` from outside Atlassian's ranges and expects no answer. With
  the pinned Caddy 2.11.7 and the Caddyfile's `abort` matcher, `curl` over
  HTTP/1.1 printed `000` with the filter and `200` without it (local run,
  2026-11-19; HTTP/2 not tried).
- No update path for the Caddy pin in `deploy/compose.yaml`, cosign or the
  tools in `.github/scripts/lib.sh`; Dependabot covers actions only (§12).
- Before the first release: `release.yml`'s publish path has never run;
  the repository has no tag or branch rules, so any `vX.Y.Z` tag push is
  signed under the documented identity; Actions may not create pull
  requests and Dependabot alerts are off (§12's repository settings); and
  `release/X.Y` must be created at the tag's commit, or `go-patch.yml`
  finds no line and stays green without patching.

**Merge without a review round (owner, 2026-11-19: "merge and push").**
Asked whether Codex should read `claude/docs-mismatches` first, the owner
had `main` fast-forwarded to it and pushed. A Claude session wrote both
commits (`0c2859f`, the corrections above, and `c1f16a7`, the outside check
in `docs/SETUP.md` 8) and no other agent read them. Neither changes code,
tests or workflows; `0c2859f` adds the `User-Agent` sentence to §5 and
`docs/PROTOCOL.md` 6.2, which describes behaviour the tests already pin.
The owner also had `weekly govulncheck: findings` closed, since `main` is
clean on Go 1.27.4, and the merged branches deleted.

**`LICENSE` and `SECURITY.md` (2026-11-24, owner: "add LICENSE and
SECURITY.md"), branch `claude/license-security`.** §11 planned both for
publication; the owner asked for them while the repository is still private.

- `LICENSE` is the European Commission's English plain text of the EUPL
  v. 1.2, unchanged: `EUPL-1.2 EN.txt` from `joinup.ec.europa.eu`, 13,827
  bytes, SHA-256 `6fc9e709…b4d1e665`, fetched 2026-11-24. Its words match
  SPDX's `EUPL-1.2` text; the two differ only in dashes and spacing.
- `SECURITY.md` takes reports through GitHub's private vulnerability
  reporting, so it commits no contact address and needs no GitHub owner
  name (§15 Q6). It promises no response time. The fix and release-note
  rules it cites are those of `docs/SUPPORT.md`.
- `README.md`, `CONTRIBUTING.md` and `docs/SUPPORT.md` no longer say the two
  files come at publication, and link to them.

No code, test or workflow changes. `gofmt`, `go vet`, `staticcheck`,
`go test` and `govulncheck` (no vulnerabilities) pass on Windows, and
`go test -race ./...` in the pinned Go 1.27.4 builder.

Left for the owner, not changed:

- GitHub offers private vulnerability reporting for public repositories.
  Enable it when the repository is published; until then the first route in
  `SECURITY.md` does not exist.
- `README.md` names Oktul as the copyright holder, after the app's name. The
  legal name is the owner's to confirm.
- The image holds no copy of the licence, only the
  `org.opencontainers.image.licenses` label; Article 5 of the EUPL asks a
  licensee to pass a copy on with every copy of the work. Adding it changes
  the `Dockerfile` and `.dockerignore`.

**Merge without a review round (owner, 2026-11-24: "Merge and push").**
Asked whether to merge `claude/license-security` or have Codex review it
first, the owner had `main` fast-forwarded to it and pushed. A Claude
session wrote `965dc84` and no other agent read it. It changes no code,
tests or workflows. The three points above stay open.

**Licence copy in the image (owner, 2026-11-24: "add the licence copy to
the image"), branch `claude/licence-in-image`.** This closes the third
point above. The `Dockerfile` copies `LICENSE` to `/LICENSE` in the final
stage, `.dockerignore` admits the file, and §7 states the rule.
`.github/scripts/smoke.sh` reads `/LICENSE` out of the container and
compares its SHA-256 with the Commission's text: the workflows check the
scripts out without the source, so the script holds the digest. No Go code,
workflow or protocol change.

Checks: the smoke test passes on a linux/amd64 image built from this branch,
fails with `the image has no /LICENSE` on an image built from `main`'s
`Dockerfile`, and fails with `not the EUPL v. 1.2 text` on an image with
another file at `/LICENSE`. `gofmt`, `go vet`, `staticcheck`, `go test` and
`govulncheck` (no vulnerabilities) pass on Windows, and `go test -race ./...`
in the pinned Go 1.27.4 builder.

Left for the owner, not changed: the binary holds Go's runtime and standard
library, whose BSD licence asks that binary redistributions reproduce its
notice, and the image does not carry it. The builder has the text at
`/usr/local/go/LICENSE`.

**Merge without a review round (owner, 2026-11-24: "merge and push").**
Told that `e5c3473` changes the `Dockerfile` and a CI script, and asked
whether Codex should review it first, the owner had `main` fast-forwarded
to `claude/licence-in-image` and pushed. A Claude session wrote the commit
and no other agent read it. It changes no Go code, workflow or protocol.

**Move to Oktul and history rewrite (owner, 2026-11-24).** The repository
moved from a personal account to the Oktul organisation as a new private
repository, `Oktul/eID-TARA-remote`, rather than a transfer, so that no
pull request or cached commit keeps the old history reachable. Before the
push, every commit's author and committer became one Oktul identity and the
`Co-Authored-By` trailers were dropped, at the owner's request that each
commit show one author. Trees, dates and subjects are unchanged; every
commit hash changed. Hashes cited in commit messages were remapped during
the rewrite, and the 33 in this plan were remapped afterwards. Agents
still write and review as `AGENTS.md` describes; commits no longer name
them in trailers. On the new repository, CI's gitleaks scan of the whole
history passed, and a search of every file version found no secret,
personal address, real ID or internal host.

**Merge without a review round (owner, 2026-11-24: "merge and push").**
Asked whether Codex should review the hash remap first, the owner had
`main` fast-forwarded to `claude/rewrite-hashes` and pushed. A Claude
session wrote it and no other agent read it. It changes only this plan.

**Names aligned with the repository (owner, 2026-11-26: "align the
names", "first version is v1.0.0"), branch `claude/align-names`.** The
repository `Oktul/eID-TARA-remote` became public on 2026-11-26. A customer
found the deploy files naming `ghcr.io/OWNER/eid-forge-remote:0.1.0`, which
never existed. `release.yml` publishes under the repository's name
(`image_name` in `.github/scripts/lib.sh`), so the documents follow it:

- `eid-forge-remote` became `eid-tara-remote` everywhere: the image, the
  deploy files' Compose project and Kubernetes object names and labels
  (including the Secret `eid-tara-remote-upstream-auth`), the `Dockerfile`
  title label, the Go module path and its imports, and `docs/SETUP.md`.
  Nothing is released, so no installed relay carries the old names.
- The deploy files pin `ghcr.io/oktul/eid-tara-remote:1.0.0`, closing the
  `0.1.0` against `v1.0.0` point above; `docs/SETUP.md` 9 verifies
  signatures from `Oktul/eID-TARA-remote`, the identity `identity_regexp`
  in `lib.sh` checks.
- "eID Forge Remote" became "eID TARA Remote" in titles and comments.
- `AGENTS.md` no longer calls the repository private.

On GitHub on 2026-11-26: private vulnerability reporting is enabled, which
closes that point of 2026-11-24, and the repository has rulesets named
`main`, `release` and `release tags`. No code behaviour, test, workflow,
protocol or setting name changes.

Checks: `gofmt`, `go vet`, `staticcheck`, `go test` and `govulncheck` (no
vulnerabilities) pass on Windows, and `go test -race ./...` in the pinned
Go 1.27.4 builder with networking disabled. `docker compose config` passes
with and without the Caddy profile; the linux/amd64 image builds, carries
the title `eid-tara-remote` and passes `.github/scripts/smoke.sh`.

**Merge without a review round (owner, 2026-11-26: "Merge and push").**
Asked whether Codex should review `claude/align-names` first, the owner had
`main` fast-forwarded to it and pushed. A Claude session wrote `1f7f977`
and no other agent read it. Apart from the Go import paths it changes no
code, tests or workflows.

**`v1.0.0` before acceptance (owner, 2026-11-26: "we need to get it live
before we can start properly testing everything", "release v1.0.0").**
TARA production, the Caddy front end and the other §13 runs need the relay
on a customer host, pulled from the registry, so the first release comes
before Phase 4 instead of after it. `release/1.0` and the annotated tag
`v1.0.0` point to this commit; the tag starts `release.yml`, whose publish
path runs here for the first time. Its notes are a draft until the owner
writes them (§12, V-6). The `release tags` ruleset forbids moving or
deleting a `v*` tag, so a fix that needs new code ships as `v1.0.1`.

Open at this release, as listed above: the §13 acceptance runs (the
hour-long fuzz runs, load, the JWKS outage, TARA live, Caddy with its
`remote_ip` filter over HTTP/2, PINNED, `govulncheck` on a release build),
the Phase 2 release verifications (§14), a replacement for Watchtower in
`docs/SETUP.md` 9, Go's BSD licence notice in the image and the copyright
holder's legal name. `README.md` and `docs/SETUP.md` say the release
precedes the acceptance runs.

**`v1.0.2`: deploy files that pin their own tag (2026-11-26, owner chose
"Yes, release v1.0.2").** The deploy files at the `v1.0.1` tag still pinned
`1.0.0`, because `go-patch.yml` changes only the toolchain line in `go.mod`
and the builder line in the `Dockerfile`, so a customer who copied them from the release ran the older image; only
`main` pinned `1.0.1`. `docs/SUPPORT.md` still said no line was supported,
and the README and `docs/SETUP.md` status named only `v1.0.0`. `v1.0.2`
changes these files on `release/1.0` and `main` alike, and nothing the
relay runs: the deploy files pin `1.0.2`, `docs/SUPPORT.md` lists the 1.0
line, and both status lines name the 1.0 line instead of one release. Between the merge and
the tag the deploy files name an image that does not exist yet, so the tag
follows the merge at once: `go-patch.sh` also expects the branch tip to be
the latest tag's commit.

Left for the owner, not changed:

- An automatic Go patch (§12) leaves the deploy files' pin and the
  "Latest release" cell in `docs/SUPPORT.md` one release behind at its own
  tag. `go-patch.yml` could update both in the commit it tags.

A Claude session wrote both branches (`claude/release-1.0.2` on
`release/1.0`, `claude/sync-1.0.2` on `main`). The review was one
independent Claude agent, not Codex: round 2 of AGENTS.md is owed if the
owner wants it. No Go file changed, so the Go checks were not rerun.

Primary references consulted for the review on 2026-10-15:

- [Forge Remote essentials](https://developer.atlassian.com/platform/forge/remote/essentials/)
  documents backend `context.cloudId` and installation contexts, but the
  [backend Invoke Remote API reference](https://developer.atlassian.com/platform/forge/runtime-reference/invoke-remote-api/#context-and-security)
  says backend context is not automatically passed. Phase 0 must settle the
  actual web-trigger behavior; documentation alone does not pass that gate.
- [Go JSON parsing behavior](https://pkg.go.dev/encoding/json) motivates
  explicit duplicate detection and case-sensitive security claims.
- [JWT claim definitions](https://www.rfc-editor.org/rfc/rfc7519.html)
  describe NumericDate and audience forms; §4.4 defines this relay's subset.
- [Go HTTP transport](https://pkg.go.dev/net/http#Transport) documents its
  limited retry behavior; §5 constrains token exchanges accordingly.
- [Go memory limit](https://go.dev/doc/gc-guide#Memory_limit) is explicitly
  soft; connection and measured container-memory limits remain necessary.

## Appendix: the two stack analyses (2026-10-15)

Both chose Go, `net/http`, `go-jose/v4`, a hand-written key cache and a
shell-free image, and both found that the site or installation pin must be
required. This plan takes from each:

- **From the first:**
  - the conflicts with §4.7 (credentials, JWE, hosting, `401`, limits),
    resolved by D1 and D5–D8;
  - HTTP/2 off;
  - `govulncheck` reachability;
  - the separate repository and the conformance-minded `PROTOCOL.md`;
  - `GOMEMLIMIT` and the `healthcheck` subcommand.
- **From the second:**
  - `scratch` with a copied CA bundle;
  - automatic decompression off;
  - a shared refresh for an unknown `kid`;
  - `Host` set to the upstream rather than removed;
  - the memory budget check at startup (1 MB defaults would have used about
    100 MB on payloads alone; superseded 2026-10-16 by fixed limits, D8);
  - checking the Forge remote timeout per invocation path;
  - "the library handles mechanics, the relay enforces policy" (superseded
    on 2026-10-15: there is no library, and the relay does both, D2);
  - keeping protocol longevity apart from the security-update cadence.
- **New after checking Forge's docs:**
  - pin on `cloudId` rather than `installationId`, because the installation
    ID changes on reinstall;
  - refuse `icLabel`;
  - use `x-b3-traceid` as the request ID;
  - D7, because Forge treats `401` and non-2xx answers specially.
- **Later on 2026-10-15, by the owner:**
  - Go patch releases ship automatically (D4, §12);
  - `go-jose` dropped for standard-library RS256 verification, so the relay
    has no third-party modules (D2, §7).
