# eID TARA Remote

The TARA token relay for the Oktul eID SSO Forge app. TARA production accepts
token requests only from allowlisted IP addresses. A customer runs this
small container in their own network, so TARA sees the customer's static IP,
and the TARA credential stays in the customer's relay, never in Forge or
with Oktul.

```
Forge app ──HTTPS──▶ reverse proxy ──HTTP──▶ relay ──HTTPS──▶ TARA POST /oidc/token
                     (TLS, IP filter)          └──HTTPS──▶ Atlassian signing keys (JWKS)
```

A request reaches the provider only if it carries a valid Forge Invocation
Token for this app, from the pinned site and Forge environment, for exactly
`POST /oidc/token`. Everything else is refused. The relay never logs bodies,
tokens or the credential.

**Status: not yet released.** No image is published, so the `1.0.0` tag in
`deploy/` does not exist yet. The admin-page parts below belong to the Forge
integration (Phase 3), built on the Forge app's main line since 2026-10-18.
`PLAN.md` §14 tracks the phases.

## Run it

[`docs/SETUP.md`](docs/SETUP.md) is the full guide; its sections are cited
below.

1. **Host:** a static outbound IP, Docker Compose v2 or Kubernetes on
   `linux/amd64` or `linux/arm64`, an accurate clock, and outbound HTTPS to
   the provider and `forge.cdn.prod.atlassian-dev.net` (§1). Have the
   provider allowlist that IP (§6.2).
2. **Deploy files:** copy `deploy/compose.yaml` and `deploy/Caddyfile`, or
   `deploy/kubernetes/`, from the release tag, and set the image tag to that
   release (§4, §5).
3. **Settings:** replace the four `"<from the admin page>"` values with the
   block the Oktul eID SSO admin page shows, keeping the quotes (§2):
   `RELAY_APP_ID`, `RELAY_ENVIRONMENT_ID`, `RELAY_CLOUD_IDS`,
   and `RELAY_UPSTREAM_URL` (the TARA HTTPS origin).
4. **Credential:** `secrets/upstream_auth` holds one Basic authorization
   header, readable by user 65532; encode each credential component as
   described in §3.1. Also add TARA's CA file (§3.2).
5. **Network:** serve HTTPS at a reverse proxy that admits only Atlassian's
   egress ranges and caps inbound connections (§6.3). With the bundled
   Caddy, set your DNS name and the IP filter in `Caddyfile` (§6.4), then run
   `docker compose --profile caddy up -d`; behind your own proxy, run
   `docker compose up -d`. Never publish port 8080 on a public address.
   Kubernetes: §5 and §6.5.
6. **Check:** `docker compose exec relay /relay healthcheck --ready`, then
   enter the relay URL on the admin page (§8).

Every setting is listed in [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §8.
Upgrades pin `:X.Y.Z` or follow `:X.Y` for automatic patches; there is no
`latest` (§9).

## Develop

Go standard library only; the toolchain is pinned in `go.mod`. Before every
commit (`AGENTS.md`):

```sh
gofmt -w .
go vet ./...
staticcheck ./...
go test -race ./...
govulncheck ./...
```

Use the `staticcheck` and `govulncheck` versions pinned in
`.github/scripts/lib.sh`; `-race` needs cgo and a C compiler. On Linux,
`.github/scripts/source-checks.sh all` runs every CI source check. Build and
smoke-test the image as CI does (Docker Buildx, bash, curl):

```sh
docker buildx build --load --tag eid-tara-remote:dev .
.github/scripts/smoke.sh eid-tara-remote:dev
```

The acceptance load test, `go run ./test/load -relay <url>`, serves its own
JWKS and upstream and prints the settings to start the relay with
(`PLAN.md` §13). `-scenario soak -duration 72h` runs the soak and
`-scenario jwks-outage` a JWKS outage; `-h` lists every scenario.

| Path        | Contents                                      |
| ----------- | --------------------------------------------- |
| `cmd/relay` | the binary: `serve`, `healthcheck`, `version` |
| `internal/` | `config`, `fit`, `forward`, `server`          |
| `deploy/`   | Compose, Caddy and Kubernetes files           |
| `test/load` | acceptance load generator                     |
| `.github/`  | CI, releases, Go patches, weekly scans        |

## Documentation

- [`docs/SETUP.md`](docs/SETUP.md): setup, network, upgrades and
  troubleshooting.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): protocol v1 and every setting.
- [`docs/SUPPORT.md`](docs/SUPPORT.md): supported release lines.
- [`PLAN.md`](PLAN.md): design and decisions; normative until publication.
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`AGENTS.md`](AGENTS.md): code style,
  checks and review.

## License and security

Copyright (c) 2026 Oktul. Licensed under the EUPL-1.2; see
[`LICENSE`](LICENSE). Report vulnerabilities privately as
[`SECURITY.md`](SECURITY.md) describes, never in a public issue.
