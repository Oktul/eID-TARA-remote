# eID Forge Remote — Plan

_Status 2026-10-15: planning only, no code. Private repository. Building the
relay and adding `remotes` to the Forge app still need the owner's approval
(Oktul eID SSO, `PLAN.md` §4.7)._

## 1. What it is

A small container, "the relay", that a customer runs in their own network. It
lets the Oktul eID SSO Forge app call a login provider's token endpoint that
accepts only allowlisted IP addresses (TARA live and Authentigate, blocker B9
in the Forge app's plan).

- The provider sees the customer's own static IP.
- The provider credential (for TARA, the client secret) lives only in the
  customer's relay, never in Forge or with us.
- Only requests that Atlassian signed for our app, on the customer's own site
  and Forge environment, get through.

This plan builds on three inputs from 2026-10-15: _Forge Relay –
Requirements_, two independent stack analyses, and the relay design in the
Forge app's `PLAN.md` §4.7 (2026-09-29). Where it changes the requirements,
§9 lists the change and the reason.

## 2. Decisions (owner, 2026-10-15)

| #   | Decision                                                                                                               | Why                                                                                                                                                                                                                                            |
| --- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | **Customers run relays. We host none in v1.**                                                                          | Removes the relay key pair, end-to-end JWE, fingerprint pinning and key rotation from §4.7. No processor chain through a cloud provider: the customer runs the hop and is the controller. An Oktul-hosted relay can come later as protocol v2. |
| D2  | **Go and its standard library only. No third-party modules** (2026-10-15; was `go-jose/v4`).                           | The standard library covers HTTPS, JSON, RSA, timeouts and cancellation. The FIT is always RS256, so `crypto/rsa` checks it in a few lines, and every update becomes a Go patch, which ships automatically (D4). §7.                           |
| D3  | **Separate repository `eID-forge-remote`, private at first.** Published under EUPL-1.2 before the first customer.      | Different language, toolchain and release lifecycle from the Forge app, which stays closed. Customers must be able to pull the image without credentials and audit the code they run.                                                          |
| D4  | **CI on GitHub Actions. Go patch releases ship automatically;** every other change needs a human merge (2026-10-15).   | Go's `net/http` and `crypto/tls` get security fixes several times a year. A Go patch release carries only such fixes and the tests pin the protocol, so it ships unreviewed. Go minors and Actions can change more. §12.                       |
| D5  | **Every relay is pinned to the customer's site (`cloudId`) and Forge environment. Both are required settings.**        | The FIT's audience is our app ID, shared by every install. Without a pin, another site's admin could point their install at this relay and use the customer's IP and credential.                                                               |
| D6  | **No end-to-end encryption in v1.** TLS from Forge to the customer's reverse proxy, then plain HTTP inside their host. | With D1, everything that can read the traffic is the customer's own infrastructure.                                                                                                                                                            |
| D7  | **An upstream answer always comes back as `200` with the upstream status in `Relay-Upstream-Status`.**                 | Forge reads `401` from a remote as a failed FIT check and treats `3xx` and other non-2xx answers as failures. An upstream `401 invalid_client` must not look like a FIT failure.                                                               |
| D8  | **Defaults sized for token calls:** 10 s upstream timeout, 64 KiB request and response limits.                         | A provider's authorization code lives about 30 s, and a token request and response are a few KB. Also keeps the memory budget far below 128 MB (§6).                                                                                           |

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
| `GET /readyz`        | none | Signing keys are loaded and the relay is not shutting down (O-2).                                                                                                                       |
| `GET /relay/v1/info` | FIT  | Relay version, protocol version, upstream origin, allowed routes, whether a credential is set (never its value). Used by the admin page's health check and its "relay too old" message. |
| `<method> <path>`    | FIT  | Forwarded to the upstream when method and path exactly match an allowed route.                                                                                                          |

`/livez`, `/readyz` and everything under `/relay/` are reserved; a route in
the configuration that uses them stops startup.

### 4.2 Checks, in order

1. Take a concurrency slot without waiting, or answer `503 too_busy` (R-5).
2. Verify the FIT (§4.4), or answer `401 invalid_token`.
3. Match method and path exactly against the allowed routes, or answer
   `404 route_not_allowed`. The FIT check comes first, so a caller without a
   valid token learns nothing about the routes.
4. Read the body up to the limit, or answer `413 body_too_large`.
5. Forward (§5).

### 4.3 Responses

- **The upstream answered, with any status:** `200`, `Relay-Upstream-Status: <code>`,
  the upstream body unchanged, and only the allowed response headers.
- **The relay answers itself:** its own status, `Relay-Error: <code>`, and a
  JSON body `{"error": "<code>"}`. Codes are stable across versions (F-9):

| Status | Code                   | When                                                        |
| ------ | ---------------------- | ----------------------------------------------------------- |
| 401    | `invalid_token`        | Any FIT failure, with no detail (A-7)                       |
| 404    | `route_not_allowed`    | Method and path not allowed, a query string, or an odd path |
| 413    | `body_too_large`       | Request body over the limit                                 |
| 500    | `internal_error`       | A recovered internal error (R-6)                            |
| 502    | `upstream_unreachable` | DNS, connection or TLS failure to the upstream              |
| 502    | `upstream_too_large`   | Upstream body over the limit                                |
| 503    | `not_ready`            | No signing keys loaded yet (K-5)                            |
| 503    | `too_busy`             | Concurrency cap reached                                     |
| 504    | `upstream_timeout`     | Upstream timeout reached                                    |

- **Every response** carries `Relay-Protocol: 1` (F-8). `Relay-Version`
  (the release, for example `1.2.0`) is sent only on FIT-authenticated
  responses, so an anonymous scanner cannot read the version.

### 4.4 FIT verification

Claim names checked against Atlassian's _Forge Remote essentials_ on 2026-10-15.

- The token is the `Authorization: Bearer` value, a compact JWS. The header
  must name `alg: RS256` and a `kid`; any other algorithm is refused (A-2).
- `iss` = `forge/invocation-token`; `aud` = `RELAY_APP_ID`
  (`ari:cloud:ecosystem::app/<uuid>`) (A-3).
- `exp` and `nbf` with the clock tolerance (A-4). Atlassian's example token
  lives 25 s; the relay does not depend on that.
- `app.environment.id` = `RELAY_ENVIRONMENT_ID` (D5).
- `context.cloudId` is in `RELAY_CLOUD_IDS` (D5). The site ID stays the same
  when the app is reinstalled, unlike `app.installationId`, so a reinstall
  does not break the relay. Whether a backend `invokeRemote` from a web
  trigger carries `context.cloudId` is a spike question (§14); the fallback
  is `app.installation.contexts[].cloudId`.
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
     exactly `RS256` and `kid` must be present. Any `crit`, `jku`, `jwk`,
     `x5u`, `x5c` or `zip` member is refused, and keys only ever come from
     the cache (§4.5);
  3. the signature is checked with `crypto/rsa.VerifyPKCS1v15` over the
     SHA-256 of the first two parts exactly as received;
  4. only after a valid signature is the payload decoded and each claim
     checked. `exp` and `nbf` must be JSON numbers.

  Tests cover every failure (§13), including a fuzz test of the parser.
  No default of any library defines the contract.
- The response never says which check failed. The log does (`auth_reason`,
  for example `audience` or `cloud_id`), which is what an operator needs.

### 4.5 Signing keys

- K-1 to K-6 as written: fetch at startup without exiting on failure, retry
  with backoff, refresh every 6 h, keep the last good keys, and refresh on an
  unknown `kid` at most once a minute.
- Concurrent requests that meet the same unknown `kid` share one refresh.
- The relay parses the JWKS itself with `encoding/json`. It keeps only keys
  with `kty: RSA`, `use` absent or `sig`, `alg` absent or `RS256`, a `kid`,
  and a modulus of at least 2048 bits. Others are skipped with a log line.
  At most 20 keys are kept; the JWKS response is capped at 64 KiB and the
  fetch at 10 s.
- The JWKS URL must be HTTPS. Default:
  `https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json`.

## 5. Forwarding

- **Destination:** `RELAY_UPSTREAM_URL` (HTTPS, an origin with an optional
  base path) plus the request path. Nothing in the request can change the
  scheme, host or port (F-3).
- **Paths:** exact match only. A path with `..`, `//`, a backslash, an
  encoded slash or dot, or non-ASCII characters is refused. Query strings are
  refused in v1, since token calls have none.
- **Request headers:** `Host` becomes the upstream host. `Authorization`,
  hop-by-hop headers, `x-forge-oauth-*`, `x-b3-*` and everything else are
  dropped. Only the allowed headers pass (default `Content-Type`, `Accept`).
  The configured credential header is set last, so a caller cannot override
  it. The relay adds no `X-Forwarded-For`.
- **Credentials:**
  - TARA: `Authorization: Basic base64(client_id:client_secret)`, stored in
    the relay (`client_secret_basic` is TARA's only method, R12).
  - Authentigate: `private_key_jwt`. Forge signs the client assertion and
    sends it in the body; the relay sets no credential.
- **Response:** read up to the limit before anything is sent, so an oversize
  answer becomes a clean `502 upstream_too_large` (R-4). Only allowed headers
  pass (default `Content-Type`, `Cache-Control`, `Pragma`).
- **Upstream client:**
  - redirects are not followed;
  - automatic decompression is off, so the body really is unchanged;
  - TLS 1.2 or later;
  - optionally only the CAs in `RELAY_UPSTREAM_CA_FILE` are trusted
    (TARA's documented trust anchors, R12);
  - HTTP/1.1 only;
  - connections are reused, with at most 10 idle per host (R-9).
- **No retries (R-8).** A token call spends a one-time code, so a retry can
  only fail. The Forge side decides what to do.
- **Cancellation:** the caller's disconnect cancels the upstream call (R-3).
- **Outbound proxy:** `HTTPS_PROXY` and `NO_PROXY` are honoured for the
  upstream and the JWKS (standard library behaviour). Public-sector networks
  often send egress through a proxy; the startup log says when one is in use.

## 6. Robustness

| Requirement | How                                                                                                                                                                                                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R-1         | `http.Server` with `ReadHeaderTimeout` 5 s, `ReadTimeout` 10 s, `WriteTimeout` = upstream timeout + 5 s, `IdleTimeout` 60 s, `MaxHeaderBytes` 16 KiB.                                                                                                                        |
| R-2, R-3    | One context per request with the upstream timeout. It ends when the caller disconnects.                                                                                                                                                                                      |
| R-4, R-12   | Bounded reads on both sides. **Startup refuses a configuration where concurrency × (request limit + response limit) exceeds 64 MiB**, naming the three settings. With the defaults: 50 × 128 KiB = 6.25 MiB. `GOMEMLIMIT=96MiB` in the image; the container limit is 128 MB. |
| R-5         | A semaphore (buffered channel) acquired without waiting.                                                                                                                                                                                                                     |
| R-6         | A recover middleware turns a panic into `500 internal_error` and a log line with the error class only. Handlers start no goroutines, so every panic is caught there.                                                                                                         |
| R-7         | The key refresh loop recovers from panics and keeps its backoff schedule.                                                                                                                                                                                                    |
| R-10        | No disk writes. The image has no writable path and runs with a read-only root filesystem.                                                                                                                                                                                    |
| R-11        | On SIGTERM or SIGINT: `/readyz` turns false, the server stops accepting, in-flight requests finish within `RELAY_SHUTDOWN_GRACE` (15 s), the key loop stops, and the process exits.                                                                                          |
| R-13        | All settings are parsed and checked before the listener opens. The first error names the setting and exits with code 2. An unreachable upstream or JWKS never stops startup.                                                                                                 |

## 7. Stack and image

- **Language:** Go, the newest supported release (check the patch level on
  the day the build starts). The toolchain is pinned in `go.mod`.
- **HTTP:** standard-library `net/http` on both sides, no framework.
  HTTP/2 is off inbound and outbound: the reverse proxy talks HTTP/1.1 anyway,
  and this removes a class of recent HTTP/2 vulnerabilities.
- **JOSE: no library** (owner, 2026-10-15; replaces `go-jose/v4`). The
  relay verifies FITs and parses the JWKS with `crypto/rsa`,
  `crypto/sha256`, `encoding/base64` and `encoding/json` (§4.4, §4.5),
  in `internal/fit/`, about 150 lines.
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
    `USER 65532:65532`, about 10 MB, no shell or package manager (S-2, S-3);
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
logs a startup warning, which catches typos.

| Setting                                     | Required | Default                             | Purpose                                                                |
| ------------------------------------------- | -------- | ----------------------------------- | ---------------------------------------------------------------------- |
| `RELAY_APP_ID`                              | yes      |                                     | Expected FIT audience                                                  |
| `RELAY_ENVIRONMENT_ID`                      | yes      |                                     | Expected `app.environment.id` (D5)                                     |
| `RELAY_CLOUD_IDS`                           | yes      |                                     | Accepted site IDs, comma-separated (D5)                                |
| `RELAY_UPSTREAM_URL`                        | yes      |                                     | Provider origin with an optional base path, HTTPS only                 |
| `RELAY_ROUTES`                              | yes      |                                     | Allowed `METHOD /path` pairs, comma-separated, e.g. `POST /oidc/token` |
| `RELAY_UPSTREAM_AUTH`                       | no       | none                                | Credential header, `Name: value` (secret; usually via `_FILE`)         |
| `RELAY_UPSTREAM_CA_FILE`                    | no       | system bundle                       | Trust only these CAs for the upstream                                  |
| `RELAY_INSTALLATION_IDS`                    | no       | any                                 | Extra pin on `app.installationId`                                      |
| `RELAY_REQUEST_HEADERS`                     | no       | `Content-Type,Accept`               | Request headers passed on                                              |
| `RELAY_RESPONSE_HEADERS`                    | no       | `Content-Type,Cache-Control,Pragma` | Response headers passed back                                           |
| `RELAY_PORT`                                | no       | `8080`                              | Listen port                                                            |
| `RELAY_TLS_CERT_FILE`, `RELAY_TLS_KEY_FILE` | no       | off                                 | Built-in TLS, 1.2 or later (S-10)                                      |
| `RELAY_UPSTREAM_TIMEOUT`                    | no       | `10s`                               | Overall limit per upstream call                                        |
| `RELAY_MAX_REQUEST_BYTES`                   | no       | `65536`                             | Request body limit                                                     |
| `RELAY_MAX_RESPONSE_BYTES`                  | no       | `65536`                             | Upstream body limit                                                    |
| `RELAY_MAX_CONCURRENT`                      | no       | `50`                                | Above this, `503 too_busy`                                             |
| `RELAY_CLOCK_SKEW`                          | no       | `10s`                               | Tolerance for `exp` and `nbf`                                          |
| `RELAY_JWKS_URL`                            | no       | Atlassian Forge JWKS                | Source of signing keys                                                 |
| `RELAY_JWKS_REFRESH`                        | no       | `6h`                                | Periodic refresh                                                       |
| `RELAY_SHUTDOWN_GRACE`                      | no       | `15s`                               | Time for in-flight requests on stop                                    |
| `RELAY_LOG_LEVEL`                           | no       | `info`                              | `debug`, `info`, `warn` or `error`                                     |

**The admin page writes most of this.** For a provider that needs the relay,
the Forge admin page shows a ready block with `RELAY_APP_ID`,
`RELAY_ENVIRONMENT_ID`, `RELAY_CLOUD_IDS`, `RELAY_UPSTREAM_URL` and
`RELAY_ROUTES` filled in. The customer adds only the credential. This removes
the most likely setup mistakes.

## 9. Changes to the requirements (2026-10-15)

| Requirement            | Change                                                                                         | Reason                                                                                             |
| ---------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| A-6 (MAY)              | Site and environment pins are **required**; the installation pin stays optional                | D5                                                                                                 |
| F-4 (MUST)             | The credential header is **optional**                                                          | Authentigate uses `private_key_jwt` signed in Forge                                                |
| F-7                    | Upstream status in `Relay-Upstream-Status`, HTTP status `200`                                  | D7                                                                                                 |
| F-8                    | `Relay-Protocol` on every response; `Relay-Version` only after a valid FIT                     | Do not show the release to anonymous callers                                                       |
| F-2                    | The FIT is checked before the route                                                            | Routes are not revealed to callers without a token                                                 |
| F-10, R-2, §8 defaults | 64 KiB bodies (was 1 MB), 10 s timeout (was 20 s)                                              | D8                                                                                                 |
| R-8 (MAY retry)        | No retries                                                                                     | A token call spends a one-time code                                                                |
| S-9 (SHOULD)           | **Deferred:** filter Atlassian's IP ranges at the reverse proxy, which sees the real client IP | Inside the relay it would have to trust `X-Forwarded-For`, which adds settings and a spoofing risk |
| new                    | Query strings and Isolated Cloud tokens are refused                                            | Not needed; fewer ways in                                                                          |

## 10. Operations

- **Logs** (O-4): one JSON line per request with `time`, `level`,
  `request_id`, `method`, `route`, `status`, `upstream_status`,
  `duration_ms`, `error` and `cloud_id`. The request ID is Forge's
  `x-b3-traceid` when present, so a line can be matched with Forge logs;
  otherwise a random ID. Never bodies, query strings, header values, the FIT
  or the credential (S-7).
- **Startup** (O-5): the version, Go version and a summary of the settings.
  The credential shows as `set (from file)`, never its value (S-8).
- **Deploy files:**
  - `deploy/compose.yaml` (O-6): `restart: unless-stopped`, the health
    check, `mem_limit: 128m`, `pids_limit`, `read_only: true`,
    `cap_drop: [ALL]`, `no-new-privileges`, user 65532, and an optional Caddy
    service in front;
  - `deploy/kubernetes/` (O-7): Deployment, Service, Secret, NetworkPolicy,
    liveness on `/livez`, readiness on `/readyz`, and a matching
    `securityContext`.
- **Setup guide** `docs/SETUP.md` (O-8):
  - what the customer provides (requirements §9);
  - copying the block from the admin page;
  - firewall rules: inbound 443 from Atlassian's egress ranges, outbound
    only to the provider host and `forge.cdn.prod.atlassian-dev.net:443`;
  - registering the IP with the provider;
  - an IP-filter snippet for the reverse proxy (S-9);
  - upgrades.

## 11. Repository layout

```
cmd/relay/            main: serve (default), healthcheck, version
internal/config/      environment parsing and validation
internal/fit/         FIT verification and the JWKS cache
internal/forward/     route matching, header filtering, upstream client
internal/server/      HTTP server, middleware (request ID, recover, limiter, logging), health
test/load/            small load generator for the acceptance runs (no dependencies)
deploy/               compose.yaml, kubernetes/
docs/                 SETUP.md, PROTOCOL.md (§4, for implementers), SUPPORT.md
.github/workflows/    ci.yml, release.yml, weekly.yml, go-patch.yml
Dockerfile, go.mod, AGENTS.md, PLAN.md   (no go.sum: there are no modules)
```

`LICENSE` (EUPL-1.2) and `SECURITY.md` are added when the repository is
published (D3). From the first commit, nothing goes in that could not be
public: no secrets, keys, customer names or internal hostnames.

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

- **`ci.yml`, on every push and pull request:**
  - `gofmt` check, `go vet`, `staticcheck` and `go test -race`;
  - `govulncheck ./...`;
  - `gitleaks` as a CLI (its GitHub Action needs a licence for organisation
    accounts);
  - a Docker build with a smoke test: the container starts read-only as a
    non-root user, `/livez` answers `200`, `/readyz` answers `503` while the
    JWKS URL is unreachable, and a bad setting exits with its name;
  - a check that the Go version in `go.mod`'s `toolchain` line and the
    builder image tag in the `Dockerfile` are the same.
- **`release.yml`, on a `vX.Y.Z` tag, and callable from `go-patch.yml`**
  (`workflow_call`, because a tag pushed with a workflow's own token does not
  start other workflows):
  - the same checks, then `buildx` for amd64 and arm64;
  - push to `ghcr.io/<owner>/eid-forge-remote:X.Y.Z` and move the floating
    `:X.Y` tag to it. No `latest` in the docs (S-4);
  - SBOM and provenance attestations, and cosign keyless signing with
    GitHub's OIDC token (S-5);
  - `govulncheck -mode=binary` on the built binaries;
  - a GitHub release whose notes say whether the upgrade is **required,
    recommended or optional**, and why (V-6). A person writes them for a
    tagged release. For an automatic one they are generated: `recommended`
    when `govulncheck` found a reachable vulnerability that the new Go
    fixes, otherwise `optional`, with links to Go's release notes. Only the
    owner marks a release `required`, by editing its notes.
- **`go-patch.yml`, daily and manual:**
  - reads Go's releases from `https://go.dev/dl/?mode=json` and the digest of
    the matching official `golang` image;
  - for a new patch of the pinned Go minor, or a new image digest for the
    same Go version: updates `go.mod` and the `Dockerfile` together, runs
    every `ci.yml` check on the change, and only if all pass commits to
    `main`, tags the next patch version and calls `release.yml`;
  - when a check fails it stops, leaves `main` untouched and opens an issue;
  - for a new Go minor it opens a pull request instead;
  - it does not need branch protection, which GitHub Free does not offer for
    private repositories, because it runs the checks itself before
    committing.
- **`weekly.yml`, scheduled and manual:** `govulncheck` on `main` and on the
  latest release's binary. A failure emails the owner through GitHub
  notifications. A reachable vulnerability that a newer Go patch fixes is
  already handled by `go-patch.yml`. One that needs a new Go minor is the
  owner's to merge and tag.
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
    previous major for 12 months after a new one;
  - a rebuild at least once a year; a Go patch release automatically within
    a day of Go publishing it; and within 7 days of a reachable critical or
    high fix that needs a new Go minor;
  - customers learn of upgrades from the release notes and from the admin
    page, which compares `/relay/v1/info` with the minimum version the Forge
    app expects.

## 13. Testing and acceptance

- **Unit tests** (Go `testing` and `httptest`, run in CI):
  - **FIT:** every failure in requirements §12, plus wrong environment, wrong
    site, `icLabel`, missing `kid`, `alg: none`, HS256 signed with the RSA
    public key as the secret, and a tampered payload. All return the same
    `401`. Because the parser is our own (D2), also: two or four parts,
    empty parts, padded or non-URL base64, a token over 8 KiB, a header with
    `crit`, `jku`, `jwk`, `x5u`, `x5c` or `zip`, an unknown `kid`, a key
    under 2048 bits, `exp` as a string, and a valid signature from a
    different key with the same `kid`.
  - **Fuzz:** a Go fuzz test (`go test -fuzz`, standard library) feeds the
    token parser arbitrary input and must never panic or accept a token
    without a valid signature. CI runs its seed corpus with the unit tests;
    a longer run (at least an hour) happens before v1.0.0.
  - **Keys:** unreachable at startup, rotation, the one-a-minute limit, last
    good keys kept, and one shared refresh.
  - **Forwarding:** route allowlist, path tricks, header filtering, the
    credential overriding a caller's header, no redirects, size limits before
    anything is sent, `504` on timeout, cancel on disconnect.
  - **Config:** every setting named in its error, and the memory budget check.
- **Before v1.0.0, by hand, results recorded here:**
  - load above the concurrency cap with memory under 128 MB (`test/load`);
  - a 72-hour soak on a VM;
  - killing the process gives a healthy restart within 10 s;
  - SIGTERM lets in-flight requests finish;
  - an image scan (Trivy or Grype) shows only the Go binary and the Go
    standard library, no third-party modules;
  - amd64 and arm64 both run from `deploy/compose.yaml` unchanged.
- **End to end with the Forge app:**
  - a TARA demo login through a relay (the demo accepts any IP, so this
    proves the path);
  - then an Authentigate demo login, which needs the allowlist and really
    proves B9.

## 14. Phases

0. **Approval and Forge spike** (in the Forge app, development
   environment). Questions to answer:
   - a configurable `remotes` entry with `permissions.remote.set`;
   - `invokeRemote` from the `/cb` web trigger;
   - which claims a backend call's FIT carries (`context.cloudId`,
     `app.environment.id`);
   - whether the function sees custom response headers and non-2xx bodies;
   - the function-to-remote timeout;
   - whether the app stays PINNED on an EU site.

   The relay for the spike is an early Phase 1 build behind a temporary
   tunnel.

1. **Relay core** (this repository): config, FIT and keys, forwarding,
   errors, health and logs, with unit tests. Tag `v0.1.0`.
2. **Packaging and CI:** Dockerfile, deploy files, `docs/`, the four
   workflows, and a signed multi-arch release.
3. **Forge integration** (Forge app):
   - the remote;
   - `/cb` going through it for providers that need a fixed IP;
   - on the admin page: the relay URL, the configuration block, the health
     check and the "relay too old" message;
   - live TARA and Authentigate.
4. **Acceptance:** §13 by hand, plus a security review of both sides.
5. **Publish:** public repository, `LICENSE`, `SECURITY.md`, support policy,
   `v1.0.0`.

## 15. Open questions

1. Does a backend `invokeRemote` from a web trigger carry `context.cloudId`?
   (Phase 0)
2. Does `invokeRemote` give the function custom headers and non-2xx bodies?
   (Phase 0; D7 needs the header.)
3. Does a configurable compute-only remote keep the app PINNED? (Phase 0,
   carried over from §4.7.)
4. Authentigate: are only token calls IP-restricted, or JWKS too? May one
   relay IP serve several clients? (Forge app's checklist.) If JWKS is
   restricted, it becomes a second route (`GET /…/jwks`), with no relay
   change.
5. A customer with no host or static IP cannot use TARA live or
   Authentigate in v1 (D1). Revisit if customers ask for it.
6. The publication date, and the GitHub owner for the image name.

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
    100 MB on payloads alone);
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
