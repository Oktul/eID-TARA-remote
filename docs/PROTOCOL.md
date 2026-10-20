# Relay protocol v1

The contract between the Oktul eID SSO Forge app and the relay, written for
implementers of the Forge side (`PLAN.md` §4.6).

> **Normative source.** Until the repository is published, `PLAN.md` §4, §5
> and §8 are normative. This file publishes the same contract; it is not a
> second definition. Any difference between the two files is a bug to fix,
> and until it is fixed `PLAN.md` wins.

Terms: the **relay** is the container the customer runs; the **upstream** is
the TARA origin named by `RELAY_UPSTREAM_URL`; a **FIT** is the Forge
Invocation Token that Atlassian adds when the app calls `invokeRemote`; a
**token route** is the fixed request `POST /oidc/token`.

## 1. Transport

- Forge calls the customer's reverse proxy over HTTPS; the proxy passes the
  request to the relay over plain HTTP inside the customer's host (`PLAN.md`
  D6). There is no end-to-end encryption in v1, and the relay itself serves
  plain HTTP only (`PLAN.md` §6).
- HTTP/2 is off inbound and outbound (`PLAN.md` §7). Inbound, the relay
  serves HTTP/1.x; outbound, it accepts only an HTTP/1.1 answer, and any
  other version is `502 upstream_unreachable` (section 4.2).
- No path cleaning, no redirects and no implicit `HEAD` for `GET` happen
  before the checks in section 3.
- Server limits (`PLAN.md` §6, R-1): request header block 16 KiB (net/http
  allows 4 KiB of slack on top), header
  read 5 s, whole request read 10 s, response write `RELAY_UPSTREAM_TIMEOUT`
  plus 5 s, idle keep-alive 60 s.
- The write deadline starts when the request header has been read, and the
  relay restarts it once the body has been read or refused. A slow body or a
  wait for an unknown key therefore never uses up the time the answer needs:
  an answer the upstream gives within `RELAY_UPSTREAM_TIMEOUT` keeps the 5 s
  margin for being written (`PLAN.md` §6). A token exchange can still succeed
  upstream while its answer is lost, for example when the upstream answers
  after that timeout (section 6.6, R-8).

## 2. Endpoints

| Request              | Auth | Answer                                                                                                                                                    |
| -------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /livez`         | none | `200` with `{"status":"ok"}` while the process runs. Contacts nothing.                                                                                    |
| `GET /readyz`        | none | `200` with `{"status":"ok"}` when a usable signing-key snapshot is within its maximum age and the relay is not shutting down; otherwise `503 not_ready`. |
| `GET /relay/v1/info` | FIT  | `200` with the info document (section 7).                                                                                                                 |
| `POST /oidc/token`  | FIT  | Forwarded to TARA's token endpoint (section 6).                                                                                                          |

- **Health exemption:** only `GET` with the request target exactly `/livez`
  or `/readyz`, without a query, bypasses FIT verification and the
  forwarding semaphore. Health requests never contact the upstream or the
  JWKS. Any other request to these paths, such as `HEAD /livez` or
  `GET /readyz?x`, follows the checks in section 3 and cannot match a route.
- **Info:** after authentication, `GET /relay/v1/info` is answered by the
  relay itself and never forwarded.

## 3. Checks, in order

1. If no usable, unexpired key snapshot is available, answer `503 not_ready`.
   Otherwise verify the FIT (section 5), or answer `401 invalid_token`.
2. Require exactly `POST /oidc/token`, or answer
   `404 route_not_allowed`. The FIT check comes first, so a caller without a
   valid token learns nothing about the token route.
3. Take one of 50 concurrency slots without waiting, or answer
   `503 too_busy` (R-5). Only an authenticated token POST takes a slot.
4. Read the body up to 64 KiB (65536 bytes), or answer
   `413 body_too_large` with `Connection: close`: the relay closes the
   connection rather than read the rest of a refused body to keep it. If the
   body cannot be read for another reason (the client left, timed out or
   sent broken chunked framing), the relay closes the connection without an
   answer.
5. Forward (section 6).

Any answer the relay gives itself (an error, health or info) before a
declared or chunked body has been read carries `Connection: close`; once the
body has been read in full, the relay itself no longer closes the
connection.

A recovered panic answers `500 internal_error` (R-6).

## 4. Responses

### 4.1 Upstream answers: the D7 wrapping rule

**An upstream answer always comes back as `200`**, whatever its status,
with:

- `Relay-Upstream-Status: <code>`, the upstream's status;
- the upstream body unchanged;
- only the upstream headers `Content-Type`, `Cache-Control`, `Pragma`;
- `Cache-Control: no-store` when the upstream sent no `Cache-Control`, and
  `X-Content-Type-Options: nosniff`;
- `Relay-Protocol: 1` and `Relay-Version`.

The wrapping lets the Forge app distinguish a provider's `401 invalid_client`
from the relay's `401 invalid_token` (`PLAN.md` D7). The relay does not follow
redirects, so a provider `302` arrives as `200` with
`Relay-Upstream-Status: 302`.

Phase 0 confirmed on 2026-10-16 that backend `invokeRemote` exposes custom
headers and bodies, including on non-2xx answers: relay-generated `401` and
`404` responses reached the function intact (`PLAN.md` §14). The v1 wrapping
rule remains unchanged. Forge infrastructure and customer proxies may also
generate or replace error responses; check `Relay-Protocol` before treating
one as a relay answer.

### 4.2 Relay answers

The relay's own status, `Relay-Error: <code>`, and a body that is exactly
`{"error":"<code>"}`, with `Content-Type: application/json`,
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Codes are
stable across versions (F-9):

| Status | Code                   | When                                                         | `Relay-Version`   |
| ------ | ---------------------- | ------------------------------------------------------------ | ----------------- |
| 401    | `invalid_token`        | Any FIT failure, with no detail (A-7)                        | no                |
| 404    | `route_not_allowed`    | Method and path not allowed, a query string, or an odd path  | yes               |
| 413    | `body_too_large`       | Request body over the limit                                  | yes               |
| 500    | `internal_error`       | A recovered internal error (R-6)                             | after a valid FIT |
| 502    | `upstream_unreachable` | DNS, connection or TLS failure to the upstream, an answer that is not valid HTTP/1.1 (a status line other than HTTP/1.1, HTTP/1.0 included, or a final status below 200), or an answer whose header is over 32 KiB | yes               |
| 502    | `upstream_too_large`   | Upstream body over the limit                                 | yes               |
| 503    | `not_ready`            | No usable keys loaded, or their maximum age is reached (K-5) | no                |
| 503    | `too_busy`             | Concurrency cap reached                                      | yes               |
| 504    | `upstream_timeout`     | Upstream timeout reached                                     | yes               |

`/readyz` answers `503 not_ready` when it is not ready (section 2).

A token exchange may have consumed the provider's one-time code even if its
response was lost, and nothing retries it automatically (section 6.6).

### 4.3 Responses that cannot promise relay headers

- errors that the HTTP server rejects before a handler runs;
- answers generated by the reverse proxy;
- a request whose body cannot be read for a reason other than its size
  (section 3, step 4): the relay closes the connection without an answer.

### 4.4 Headers

| Header                  | Sent on                                                                                  | Value                     |
| ----------------------- | ---------------------------------------------------------------------------------------- | ------------------------- |
| `Relay-Protocol`        | Every application-generated response, including health and overload responses (F-8)    | `1`                       |
| `Relay-Version`         | Only FIT-authenticated responses, so an anonymous scanner cannot read the version        | The release, e.g. `1.2.0` |
| `Relay-Upstream-Status` | Upstream answers (section 4.1)                                                           | The upstream status code  |
| `Relay-Error`           | Relay answers (section 4.2)                                                              | A code from section 4.2   |
| `Cache-Control`         | Relay answers, health and info; upstream answers without their own (section 4.1)        | `no-store`                |
| `X-Content-Type-Options` | Every application-generated response                                                    | `nosniff`                 |

The relay computes framing and sets its own protocol, version,
upstream-status and error headers last. Upstream headers can never
impersonate a relay error or change its protocol metadata (section 6.4).

### 4.5 Examples

`Date` and `Content-Length` are left out.

A provider error, wrapped (D7):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
X-Content-Type-Options: nosniff
Relay-Protocol: 1
Relay-Version: 1.2.0
Relay-Upstream-Status: 400

{"error":"invalid_grant"}
```

A relay error, to a `POST /oidc/token` that carried a body:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Cache-Control: no-store
X-Content-Type-Options: nosniff
Connection: close
Relay-Protocol: 1
Relay-Error: invalid_token

{"error":"invalid_token"}
```

The two bodies look alike; only the headers tell them apart.

## 5. FIT verification (`PLAN.md` §4.4)

Every failure below answers the same `401 invalid_token`. The response never
says which check failed; the relay's log does (`auth_reason`).

### 5.1 Authorization field

Exactly one `Authorization` field with the case-insensitive scheme `Bearer`,
one separating space and a non-empty compact JWS, without other whitespace
or comma-joined credentials.

### 5.2 Token form

The relay does the token mechanics itself, with the Go standard library
(`PLAN.md` D2). It supports exactly one form:

1. the token is at most 8 KiB and splits on `.` into exactly three non-empty
   parts;
2. the header is strict base64url (no padding) and JSON. `alg` must be
   exactly `RS256` and `kid` a non-empty string. Any `crit`, `jku`, `jwk`,
   `x5u`, `x5c`, `zip` or `b64` member is refused, including a null value,
   and keys only ever come from the relay's cache (section 5.5);
3. the signature is checked with RSASSA-PKCS1-v1_5 over the SHA-256 of the
   first two parts exactly as received;
4. only after a valid signature is the payload decoded and each claim
   checked. All three parts use strict, unpadded base64url; whitespace,
   non-URL characters and non-canonical encodings are refused.

The decoded header and payload must each be exactly one UTF-8 JSON object,
with no trailing value, invalid Unicode or duplicate member names at any
nesting level. Duplicates are detected on decoded member names, including
escaped spellings. Member names match case-sensitively, including inside
`app` and `context`: `ISS` is not `iss`. Required objects and claims reject
absence, null and wrong types. Optional pin claims reject malformed values
when supplied. Unknown ordinary claims remain allowed, but are still subject
to JSON validity, duplicate detection and the nesting bound: a JSON
document, here and in the JWKS (section 5.5), nests at most 16 levels. A FIT
payload uses five (`app.installation.contexts[i]`), so the bound only refuses
hostile input.

### 5.3 Claims

| Claim                | Requirement                                                                                                                      |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `iss`                | Exactly `forge/invocation-token`.                                                                                                |
| `aud`                | Exactly the `RELAY_APP_ID` string, or a non-empty array of non-empty strings that contains that exact value (A-3).              |
| `exp`, `nbf`         | Required NumericDate JSON numbers, `exp` at most 5 minutes after `nbf` (below).                                                  |
| `app.environment.id` | Equal to `RELAY_ENVIRONMENT_ID` (D5): the environment's ARI, `ari:cloud:ecosystem::environment/<app>/<environment>`.             |
| `context.cloudId`    | The site pin (section 5.4).                                                                                                      |
| `app.installationId` | In `RELAY_INSTALLATION_IDS`, only if that is set (an optional extra pin). A malformed value is refused when supplied.             |
| `icLabel`            | A token with `icLabel` (Isolated Cloud) is refused: its keys live at another JWKS URL, and Isolated Cloud is not supported.      |
| anything else        | Ignored, so new claims never break an old relay (A-5).                                                                           |

**Dates.** `exp` and `nbf` are plain decimal numbers, digits with an
optional fraction, parsed without float rounding or integer overflow.
Fractional seconds are accepted, bounded to the Unix-second interval 0
through 253402300799 inclusive; exponent notation (`1.8e9`) is refused. Missing, null, string or
out-of-range dates are refused, and so is a NumericDate with a minus sign,
even `-0`. With the skew `RELAY_CLOCK_SKEW`, the relay requires `exp > nbf`,
`exp - nbf <= 5 minutes`, `now < exp + skew` and `now + skew >= nbf` (A-4,
SR-6). `iat` is ignored like any other claim. The cap refuses only tokens
Forge did not mint: Forge's span 55 s, and since Forge reuses one FIT for
several calls, a FIT cannot be made single-use (`PLAN.md` §14, SR-1). Dates are compared exactly
at nanosecond resolution: for the validity window, a fractional `exp` rounds
down and `nbf` rounds up; the lifetime cap instead rounds `exp` up and `nbf`
down. Sub-nanosecond rounding can only reject in either check. Atlassian's example token
lives 25 s after `iat`; Forge sets `nbf` 30 s before `iat`, so `exp - nbf`
is 55 s. The relay depends on that lifetime only through the 5-minute cap.

### 5.4 Site pin (D5)

- `context.cloudId` must be present and a non-empty string in
  `RELAY_CLOUD_IDS`. A missing, malformed, null or disallowed value is
  refused. Several allowed sites in `RELAY_CLOUD_IDS` do not relax this rule.
- If installation contexts also contain cloud IDs, they must include the
  invocation site; they never stand in for a missing one (`PLAN.md` §4.4,
  §14).
- No unsigned request header or body field can provide the site pin. The
  site ID stays stable on reinstall, unlike `app.installationId`.

### 5.5 Signing keys (`PLAN.md` §4.5)

- The relay fetches the JWKS from `RELAY_JWKS_URL` at startup without
  exiting on network failure; readiness stays false until a usable snapshot
  is loaded. Failures are retried with exponential backoff from 1 s up to
  1 min. Successful snapshots are refreshed every `RELAY_JWKS_REFRESH`.
- The last good snapshot is kept through failed refreshes, but only until
  `RELAY_JWKS_MAX_AGE` since its last successful fetch. At that age,
  readiness becomes false and protected endpoints answer `503 not_ready`; a
  successful usable refresh restores readiness. By default this permits at
  most 24 h of stale-key trust, counted in running time, during an outage;
  an operator may shorten the window. `RELAY_JWKS_REFRESH` must be less than
  `RELAY_JWKS_MAX_AGE`. The age is measured on the monotonic clock: a
  wall-clock step does not change it, and on Linux time a host spends
  suspended does not count.
- One refresh worker serves startup, retries, periodic refreshes and all
  unknown key IDs, with at most one fetch in flight. Fetches started by
  unknown key IDs are limited to once a minute, whatever the IDs. Requests
  start no goroutines and queue no key IDs, and the worker belongs to the
  process, not to the first caller that waits for it. Unknown-key requests
  share the current refresh and wait at most 1 s, further bounded by the
  caller's cancellation. If no key is available then, they answer
  `401 invalid_token` and never reach the upstream. Known-key verification
  never waits for network I/O.
- The cooldown can delay acceptance of a newly rotated key; neither the
  relay nor Forge automatically replays a token exchange to hide that
  failure.
- Eligible keys have `kty` `RSA`, `use` absent or `sig`, `alg` absent or
  `RS256`, a non-empty string `kid` and a modulus of at least 2048 bits.
  Other key types, uses and algorithms, and smaller moduli, are skipped, and
  logged as one count per fixed reason, never per key.
  `n` and `e` are strict base64url without a leading zero octet, unpadded
  or with exactly the `=` padding that completes the last quantum, since
  Atlassian's JWKS pads `n` (any other `=` is invalid); `e` is odd
  and from 3 to 2³¹−1; the modulus is odd and has at most 8192 bits, which
  bounds the cost of verification. RSA verification refuses an even modulus
  or exponent, so such a key fails the refresh at once instead of failing
  every FIT later. A violation of these counts as invalid RSA parameters.
  They apply only to an otherwise eligible key: an RSA signing key whose
  strictly decoded modulus is under 2048 bits is skipped as undersized
  before `e` and the modulus parity are judged. A malformed `n`, or a
  missing or empty `kid`, still fails the refresh.
- The JWKS is JSON under the rules of section 5.2. Invalid RSA parameters on
  an otherwise eligible key, duplicate key IDs, more than 20 usable keys, an
  empty usable set or a malformed document make the refresh fail
  atomically: the set is never truncated, and the previous snapshot and its
  fetch time are kept. Logs carry fixed reasons, never raw keys or key IDs.
- The JWKS response body is capped at 64 KiB, its header at 32 KiB, and the
  fetch at 10 s, with a 30 s dial and a 10 s TLS handshake bound; a larger
  header fails the fetch. The fetch does not follow
  redirects, holds no idle connection and asks for no compression, so the
  size cap applies to the bytes received. Only a `200` answer counts as a
  successful fetch.
- A successful refresh replaces the entire snapshot, so a removed key stops
  being trusted immediately.
- The JWKS URL (`RELAY_JWKS_URL`, section 8) must be HTTPS. Default:
  `https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json`.

## 6. Forwarding (`PLAN.md` §5)

### 6.1 Destination and paths

- The destination is the configured HTTPS origin plus the fixed path
  `/oidc/token`, for example `https://tara.ria.ee/oidc/token`. The upstream
  request always uses `POST`. Nothing in the request can change the scheme,
  host, port or path (F-3).
- Matching is exact. A path with `..`, `//`, a backslash, an encoded slash
  or dot, or non-ASCII characters is refused, and so is any query string:
  token calls have none. The raw request target must be exactly
  `/oidc/token`, without cleaning or decoding.

### 6.2 Request headers

- `Host` becomes the upstream host. Only `Content-Type` and `Accept` pass,
  a fixed allowlist; `Authorization`, hop-by-hop headers, `x-forge-oauth-*`,
  `x-b3-*`, idempotency headers and everything else are dropped. Headers
  named by `Connection` are removed.
- The configured credential header is set last, so a caller cannot override
  it. The relay adds no `X-Forwarded-For`.

### 6.3 Credential

The supported TARA setup uses `client_secret_basic`: the relay supplies
`Authorization: Basic <credentials>` from its local secret file. Form-encode
the client ID and secret separately, join them with `:`, then Base64-encode
the result. TARA defaults to this method; it also permits
`client_secret_post` for clients registered for it, but this relay adds no
body-credential feature. See [TARA's token request specification](https://e-gov.github.io/TARA-Doku/TechnicalSpecification#43-identity-token-request).

### 6.4 Response

- The relay reads the upstream body up to 64 KiB (65536 bytes) before
  anything is sent, so an oversize answer becomes a clean
  `502 upstream_too_large` (R-4).
- The upstream's response header, which is read before that limit applies,
  may have at most 32 KiB; a larger one answers `502 upstream_unreachable`.
- Only `Content-Type`, `Cache-Control` and `Pragma` pass back. Headers
  nominated by the upstream's `Connection` header are also removed at runtime.
  The relay adds `X-Content-Type-Options: nosniff`, and `Cache-Control:
  no-store` when the upstream sent none (section 4.1).

### 6.5 Upstream client

- Redirects are not followed.
- Automatic decompression is off, so the body really is unchanged.
- TLS 1.2 or later. If `RELAY_UPSTREAM_CA_FILE` is set, only its CAs are
  trusted (TARA's documented trust anchors).
- HTTP/1.1 only; connections are reused, with at most 10 idle per host
  (R-9). A dial is bounded at 30 s and a TLS handshake at 10 s, even after
  the call that started them has ended.
- `RELAY_UPSTREAM_TIMEOUT` is the overall limit per upstream call
  (`504 upstream_timeout`). The caller's disconnect cancels the upstream
  call (R-3).
- `HTTPS_PROXY` and `NO_PROXY` are honoured for the upstream and the JWKS
  (standard library behaviour). The startup log says when a proxy is in use.

### 6.6 No application retries (R-8)

A token exchange may have consumed the one-time code even if its response
was lost. Neither the relay, the supplied proxy configuration nor Forge
automatically retries that exchange. The relay drops idempotency headers and
does not mark token `POST`s as idempotent or give them a replay callback.
Go's transport may recover a reused connection when nothing was written,
but not for a token `POST` with a body, which then fails as
`502 upstream_unreachable`. No token exchange is retried after possible
delivery.

## 7. Health and info bodies

`GET /livez` and a ready `GET /readyz` answer `200` with:

```json
{"status":"ok"}
```

An unready `GET /readyz` answers `503 not_ready` as in section 4.2. Health
responses carry `Relay-Protocol: 1` and, being unauthenticated, never
`Relay-Version`.

`GET /relay/v1/info` answers `200`, with `Relay-Protocol` and
`Relay-Version`, for example:

```json
{"relay_version":"1.2.0","protocol_version":1,"upstream_url":"https://tara.ria.ee","routes":["POST /oidc/token"],"credential_set":true}
```

| Member             | Meaning                                                              |
| ------------------ | -------------------------------------------------------------------- |
| `relay_version`    | The relay release                                                    |
| `protocol_version` | The protocol version                                                 |
| `upstream_url`     | The configured HTTPS origin in `RELAY_UPSTREAM_URL`                 |
| `routes`           | Always `["POST /oidc/token"]`                                       |
| `credential_set`   | Whether a credential is set; its value is never shown                |

The admin page uses this document for its health check and its "relay too
old" message.

## 8. Settings (`PLAN.md` §8)

Environment variables, read and checked once at startup, before the listener
opens. The admin page writes `RELAY_APP_ID`, `RELAY_ENVIRONMENT_ID`,
`RELAY_CLOUD_IDS` and `RELAY_UPSTREAM_URL`; the customer adds
only the credential.

| Setting                                     | Required | Default                             | Purpose                                                                 |
| ------------------------------------------- | -------- | ----------------------------------- | ----------------------------------------------------------------------- |
| `RELAY_APP_ID`                              | yes      |                                     | Expected FIT audience                                                   |
| `RELAY_ENVIRONMENT_ID`                      | yes      |                                     | Expected `app.environment.id`, the environment ARI (D5)                 |
| `RELAY_CLOUD_IDS`                           | yes      |                                     | Accepted site IDs, comma-separated (D5)                                 |
| `RELAY_UPSTREAM_URL`                        | yes      |                                     | TARA HTTPS origin, e.g. `https://tara.ria.ee`                             |
| `RELAY_UPSTREAM_ANY_HOST`                   | no       | `false`                             | `true` allows an upstream other than TARA's two origins (tests only)    |
| `RELAY_UPSTREAM_AUTH`                       | no       | none                                | Credential header, `Name: value` (secret; usually via `_FILE`)          |
| `RELAY_UPSTREAM_CA_FILE`                    | no       | system bundle                       | Trust only these CAs for the upstream                                   |
| `RELAY_INSTALLATION_IDS`                    | no       | any                                 | Extra pin on `app.installationId`                                       |
| `RELAY_PORT`                                | no       | `8080`                              | Listen port                                                             |
| `RELAY_UPSTREAM_TIMEOUT`                    | no       | `10s`                               | Overall limit per upstream call                                         |
| `RELAY_CLOCK_SKEW`                          | no       | `10s`                               | Tolerance for `exp` and `nbf`                                           |
| `RELAY_JWKS_URL`                            | no       | Atlassian Forge JWKS (section 5.5)  | Source of signing keys                                                  |
| `RELAY_JWKS_REFRESH`                        | no       | `6h`                                | Periodic refresh                                                        |
| `RELAY_JWKS_MAX_AGE`                        | no       | `24h`                               | Maximum trust age of the last successful key snapshot (section 5.5)     |
| `RELAY_SHUTDOWN_GRACE`                      | no       | `15s`                               | Time for in-flight requests on stop                                     |
| `RELAY_LOG_LEVEL`                           | no       | `info`                              | `debug`, `info`, `warn` or `error`                                      |

Validation rules:

- **Files.** Any setting can instead be read from a file named by
  `<NAME>_FILE`. If both a setting and its `_FILE` variant are provided,
  startup fails with the setting name only. File reads are bounded: 64 KiB
  for a `_FILE` value, 1 MiB for the file named by `RELAY_UPSTREAM_CA_FILE`.
  A `_FILE` value loses one
  trailing line ending (`\n` or `\r\n`).
- **Empty values.** A setting that is present but empty is an error, never
  the default.
- **Lists** are separated by commas. Spaces and tabs around an item are
  ignored; empty or duplicate items are errors.
- **IDs.** `RELAY_APP_ID` is `ari:cloud:ecosystem::app/` followed by a
  lowercase UUID. Other IDs are 1–256 printable ASCII characters other than
  space and comma (`!` to `~`, without `,`).
- **Durations** use Go syntax (`10s`, `6h`) and must be positive, except
  that `RELAY_CLOCK_SKEW` may be `0` and is at most 1 minute.
  `RELAY_JWKS_REFRESH` must be less than `RELAY_JWKS_MAX_AGE`.
- **`RELAY_PORT`** is a decimal port number from 1 to 65535, digits only.
- **`RELAY_LOG_LEVEL`** is matched exactly.
- **`RELAY_UPSTREAM_URL`** starts with `https://` and must have a host, a
  port from 1 to 65535 if it names one, and no userinfo, query or fragment.
  It has no path, except an optional root `/` that is normalized away.
  It must be exactly `https://tara.ria.ee` or `https://tara-test.ria.ee`
  (no port, lowercase), unless `RELAY_UPSTREAM_ANY_HOST` is `true`: the
  relay sends TARA's credential to this origin, so a wrong value must not
  pass silently (SR-5, owner 2026-10-20). Any other value stops startup
  with exit code 2 and the reason `not one of https://tara.ria.ee,
  https://tara-test.ria.ee; set RELAY_UPSTREAM_ANY_HOST=true for another
  upstream`, without the value. With the override, every start logs
  `upstream is not TARA`.
- **`RELAY_UPSTREAM_ANY_HOST`** is exactly `true` or `false`.
- **`RELAY_JWKS_URL`** starts with `https://` and must have a host, a port
  from 1 to 65535 if it names one, and no userinfo, query or fragment.
- **`RELAY_UPSTREAM_CA_FILE`** names a file of at most 1 MiB that holds one
  or more PEM `CERTIFICATE` blocks, each an X.509 certificate, with nothing
  but whitespace between and around them. Comment lines, other block types
  such as `TRUSTED CERTIFICATE` and damaged blocks are refused.
- **Credential header.** `RELAY_UPSTREAM_AUTH` is `Name: value`; the name
  must be valid, spaces and tabs around the value are removed and the
  remaining value must not be empty. It may
  supply `Authorization`, but cannot supply routing, framing, hop-by-hop,
  idempotency or relay-owned headers. These exclusions apply
  case-insensitively. Its value may contain no control character other than
  tab, so CR and LF are refused.
- **Errors.** All settings are parsed and checked before the listener opens.
  The first error names the setting, never its value, and exits with code 2
  (R-13). An unreachable upstream or JWKS never stops startup.
- **Unknown names.** A `RELAY_*` variable the relay does not know logs a
  startup warning, which catches typos. The warning names the variable only
  if the name looks like a setting name (`RELAY_` followed by `A-Z`, `0-9`
  and `_`, at most 64 bytes); any other is logged once as
  `RELAY_* (malformed name)`, because a `:` typed for `=` would put the
  value, perhaps the credential, into the name.
- **Outside the table:** `HTTPS_PROXY` and `NO_PROXY` (section 6.5), and
  `GOMEMLIMIT=96MiB`, which the image sets (`PLAN.md` §6).

## 9. Versioning and compatibility (`PLAN.md` §4.6, §12)

- The owner narrowed v1 to TARA token exchange on 2026-10-17, before any
  release. The fixed route, origin-only upstream and fixed response headers
  are part of the first published contract (`PLAN.md` D11).
- This is protocol version 1: `Relay-Protocol: 1` and `protocol_version: 1`.
- Patch releases (`X.Y.Z` to `X.Y.Z+1`) preserve this contract: they never
  change an endpoint, response code, header or setting. Security fixes may
  enforce an already-documented rejection rule; broadening or changing the
  accepted contract is not an automatic toolchain patch.
- Compatible additions require a minor release. Incompatible endpoint,
  response, header, setting or pin changes require a new protocol version
  and a relay major release.
- Existing versions continue to work for their support window
  (`docs/SUPPORT.md`).
- The Forge app must accept every supported protocol version. A minimum
  relay version and the admin warning cannot silently remove support before
  the published end-of-support date. Emergency exceptions require an owner
  decision recorded in `PLAN.md` and explicit customer upgrade instructions.
- Contract fixtures in the relay's tests cover each application response
  code and header, health exemptions, info output, configuration defaults
  and rejection behavior, and are reused for each supported release line.
