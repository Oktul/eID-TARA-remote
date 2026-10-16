# eID Forge Remote

The relay for the Oktul eID SSO Forge app: a small container that a customer
runs in their own network, so that the app can call a login provider's token
endpoint that accepts only allowlisted IP addresses, such as TARA live or
Authentigate.

- The provider sees the customer's own static IP.
- The provider credential, such as TARA's client secret, stays in the
  customer's relay, never in Forge or with Oktul.
- Only requests that Atlassian signed for the app, from the customer's own
  site and Forge environment, get through.

The relay is written in Go with the standard library only, and is built as a
`scratch` image for `linux/amd64` and `linux/arm64`.

## Status

**Not yet released.** No image is published and no release line is
supported yet. `PLAN.md` §14 tracks the phases.

## Documentation

- [`docs/SETUP.md`](docs/SETUP.md): running a relay, from prerequisites to
  upgrades and troubleshooting.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): protocol v1, for implementers of
  the Forge side.
- [`docs/SUPPORT.md`](docs/SUPPORT.md): supported release lines and
  maintenance.
- [`PLAN.md`](PLAN.md): design, decisions and phases; normative until
  publication.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md): how the
  code is written, checked and reviewed.

## Build and test

Go's toolchain version is pinned in `go.mod`; there are no third-party
modules.

```sh
go vet ./...
go test ./...
go build -trimpath -o relay ./cmd/relay
```

The image and its smoke test, the same ones CI runs (`.github/workflows/ci.yml`),
need Docker with Buildx, bash and curl:

```sh
docker buildx build --load --tag eid-forge-remote:dev .
.github/scripts/smoke.sh eid-forge-remote:dev
```

The deploy files are in `deploy/`: `compose.yaml` with an optional
`Caddyfile`, and `kubernetes/`.

## License and security

Licensed under the EUPL-1.2; the `LICENSE` file and `SECURITY.md` are added
when the repository is published (`PLAN.md` D3, §11). Report vulnerabilities
privately, never in a public issue.
