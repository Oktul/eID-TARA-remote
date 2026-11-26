# Relay setup

This guide is for the administrator who runs the relay for the Oktul eID SSO
Forge app's TARA integration. TARA production accepts token calls only from
allowlisted IP addresses. The relay runs in your network, calls TARA's token
endpoint from your static IP, and keeps the TARA credential on your side
(`PLAN.md` §1, §10 O-8).

> **Status.** Not yet released: no image is published, so the tag `1.0.0`
> of `ghcr.io/oktul/eid-tara-remote` in the deploy files does not exist
> yet. The admin-page parts below belong to the Forge integration, built on
> the Forge app's main line since 2026-10-18 (`PLAN.md` §14, Phase 3).

```
Forge app ──HTTPS──▶ your reverse proxy ──HTTP──▶ relay ──HTTPS──▶ TARA POST /oidc/token
                     (TLS, IP filter)              │
                                                   └──HTTPS──▶ Atlassian signing keys (JWKS)
```

## 1. What you need

- A host with a **static outbound IP**: Docker with Compose v2, or a
  Kubernetes cluster, on `linux/amd64` or `linux/arm64`. The relay's
  container limit is 128 MB of memory.
- A **TARA registration** with a client ID and client secret.
- A **public DNS name and TLS certificate** for inbound HTTPS, served by a
  reverse proxy. The compose file includes an optional Caddy service that
  obtains the certificate itself.
- An **accurate system clock** (section 7).
- **Outbound access** to the provider host and to
  `forge.cdn.prod.atlassian-dev.net:443`, where Atlassian publishes its
  signing keys.

## 2. The configuration block

For TARA, the Oktul eID SSO admin page shows a
ready block of settings. Copy its four values unchanged into the deploy file
(sections 4 and 5). It looks like this (synthetic values):

```sh
RELAY_APP_ID=ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000001
RELAY_ENVIRONMENT_ID=ari:cloud:ecosystem::environment/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002
RELAY_CLOUD_IDS=00000000-0000-4000-8000-000000000003
RELAY_UPSTREAM_URL=https://tara.ria.ee
```

- `RELAY_CLOUD_IDS` pins the relay to your site, and `RELAY_ENVIRONMENT_ID` to
  the app's Forge environment. The environment is the whole
  `ari:cloud:ecosystem::environment/…` value, not only its last part. They stop another site's administrator from
  pointing their installation at your relay and using your IP and credential.
  If several of your own sites share one relay, list each site's ID,
  comma-separated. Never add a site you do not control.
- `RELAY_UPSTREAM_URL` is TARA's HTTPS origin, without a path:
  `https://tara.ria.ee` (live) or `https://tara-test.ria.ee` (demo). The
  relay refuses to start with any other value, including an explicit
  `:443`, because it sends your TARA credential there (section 10.1). If
  someone asks you to change it, check with the admin page first. The relay forwards only `POST /oidc/token`.
- `RELAY_INSTALLATION_IDS` is an optional extra pin on the installation. A
  reinstall changes the installation ID, so you must then update it.
- You add only the credential and TARA's CA file (section 3). Every setting, its
  default and its rules are listed in `docs/PROTOCOL.md` section 8.

## 3. The provider credential

Any setting can be read from a file named by `<NAME>_FILE`. The deploy files
use this for the credential, so it reaches the relay as a secret file rather
than an environment variable: `RELAY_UPSTREAM_AUTH_FILE`. Do not set both
`RELAY_UPSTREAM_AUTH` and `RELAY_UPSTREAM_AUTH_FILE`: startup refuses that.
The startup log shows the credential only as `set (from file)`.

### 3.1 TARA

TARA defaults to `client_secret_basic`; it also supports `client_secret_post`
for clients registered for that method. This setup uses Basic: the relay
sends the header for you, so the credential file holds exactly one line:

```
Authorization: Basic <base64(form_encoded_client_id:form_encoded_client_secret)>
```

First form-encode the client ID and secret separately, as required by
[TARA's token request specification](https://e-gov.github.io/TARA-Doku/TechnicalSpecification#431-using-client_secret_basic-client-authentication-method).
Letters, digits and `-._*` remain unchanged; spaces become `+` and other
bytes use percent-encoding. To write the header without the secret reaching
your shell history or the process list (bash, in the directory that holds
`compose.yaml`):

```bash
umask 077
mkdir -p secrets
read -r -p 'Form-encoded client_id: ' id
read -rs -p 'Form-encoded client_secret: ' secret; echo
printf 'Authorization: Basic %s\n' \
  "$(printf '%s:%s' "$id" "$secret" | base64 | tr -d '\n')" > secrets/upstream_auth
unset id secret
# Compose only: the relay runs as 65532 and must be able to read the file.
sudo chown 65532:65532 secrets/upstream_auth
sudo chmod 0400 secrets/upstream_auth
```

Compose mounts the file as it is, with the owner and mode it has on the host,
and the relay runs as user 65532 without capabilities. A file owned by
another user with mode `0600` stops startup with `invalid configuration`,
setting `RELAY_UPSTREAM_AUTH_FILE`, reason `file is not readable`. For Kubernetes, skip the
last two commands: `kubectl` reads the file as you, and the Deployment sets
the mode of the mounted Secret.

The `chown` above assumes Docker runs as root without user-namespace
remapping, so that user 65532 in the container is user 65532 on the host.
Otherwise the container's user 65532 is another host user: with
`userns-remap`, the first ID of the remap user's range in `/etc/subuid`
plus 65532; with rootless Docker, the first ID of your own user's range
there plus 65531. The group follows the same rule with `/etc/subgid`. Give
the file that owner and group instead, still with mode `0400`.

One trailing line ending is removed when the file is read.

### 3.2 The upstream CA file

For TARA, also set `RELAY_UPSTREAM_CA_FILE` to a PEM file with the CA
certificates that TARA's documentation names as trust anchors for its
endpoints:
[TARA's technical specification, 5.1.2](https://e-gov.github.io/TARA-Doku/TechnicalSpecification#512-verifying-the-tls-connection-to-endpoints)
lists the root certificates and where to download them. The relay then
trusts only those CAs for the upstream. When TARA
announces a CA change, update the file in time, or calls fail with
`upstream_unreachable`.

The file must be at most 1 MiB and contain only `CERTIFICATE` blocks, with
nothing but whitespace between them. Some distribution bundles have `#`
comment lines, certificate names or `TRUSTED CERTIFICATE` blocks; startup
refuses those. Keep only the certificate blocks:

```sh
sed -n '/^-----BEGIN CERTIFICATE-----/,/^-----END CERTIFICATE-----/p' \
  downloaded.pem > secrets/upstream_ca.pem
```

The deploy files do not mount a CA file; add it yourself.

- **Compose:** in `compose.yaml`, add to the relay service and the top-level
  `secrets`, and give `secrets/upstream_ca.pem` the same owner and mode as
  the credential file:

  ```yaml
  services:
    relay:
      environment:
        RELAY_UPSTREAM_CA_FILE: /run/secrets/upstream_ca
      secrets:
        - upstream_auth
        - upstream_ca
  secrets:
    upstream_ca:
      file: ./secrets/upstream_ca.pem
  ```

- **Kubernetes:** add the file to the Secret
  (`--from-file=upstream-ca.pem=secrets/upstream_ca.pem` in section 5, step
  3) and this variable to `deployment.yaml`:

  ```yaml
  - name: RELAY_UPSTREAM_CA_FILE
    value: /run/secrets/relay/upstream-ca.pem
  ```

## 4. Quick start: Docker Compose

`deploy/compose.yaml` runs the relay hardened as `PLAN.md` §10 requires:
user `65532:65532`, a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, `mem_limit: 128m` without swap, `pids_limit: 256`, the
image's health check, `restart: unless-stopped` and rotated logs (section
11). It publishes no relay port, so only containers on its network reach the
relay. The optional Caddy service (`deploy/Caddyfile`) runs only with the
`caddy` profile.

1. Copy `deploy/compose.yaml` and `deploy/Caddyfile` from this repository at
   the release tag you deploy into one directory. The commands below run
   there.
2. In `compose.yaml`, replace the four `"<from the admin page>"` values with
   the block from section 2. Keep the quotes, so that YAML reads every value
   as a string.
3. Change the image tag to the release you deploy (section 9).
4. Create `secrets/upstream_auth` (section 3.1) and the CA file (section 3.2).
5. Start it:
   - **With Caddy in front:** edit `Caddyfile` (section 6.4) and configure
     the required inbound connection limit at your firewall or load balancer
     (section 6.3, item 3), then run `docker compose --profile caddy up -d`.
   - **Behind your own proxy:** run `docker compose up -d`. Attach the proxy
     container to the compose network `eid-tara-remote_default` and send to
     `relay:8080`, or, for a proxy running on the host itself, uncomment the
     `ports` entry `127.0.0.1:8080:8080`. Never publish the relay port on a
     public address (section 6.3).
6. Check it (section 8):

   ```sh
   docker compose ps
   docker compose exec relay /relay healthcheck --ready && echo ready
   docker compose logs relay
   ```

## 5. Quick start: Kubernetes

`deploy/kubernetes/` holds:

- `deployment.yaml` (Kubernetes 1.30 or later, for its `preStop` sleep):
  the Deployment `eid-tara-remote`, one replica, running
  as user and group 65532 with a read-only root filesystem, no privilege
  escalation, all capabilities dropped, the `RuntimeDefault` seccomp profile
  and a 128Mi memory limit. It probes liveness on `/livez` and readiness on
  `/readyz`, and mounts the Secret at `/run/secrets/relay`.
- `service.yaml`: the `ClusterIP` Service `eid-tara-remote`, port 8080,
  named `http`.
- `secret.yaml`: the Secret `eid-tara-remote-upstream-auth` with the key
  `upstream-auth`, as a placeholder only, which stops startup. Do not fill it
  in, since a filled-in copy is easy to commit: create the Secret with
  `kubectl` (step 3) and delete this file from your copy.
- `networkpolicy.yaml`: ingress to port 8080 only from the ingress
  controller's namespace; egress only to cluster DNS and TCP 443.

There is no Ingress: you route your own ingress controller to the Service
(section 6.5).

1. Copy `deploy/kubernetes/` from this repository at the release tag you
   deploy.
2. In `deployment.yaml`, replace the four `"<from the admin page>"` values
   with the block from section 2, and set the image tag (section 9).
3. Create the Secret from the credential file (section 3.1), then delete
   `secret.yaml` from your copy, so that applying the directory cannot
   overwrite your Secret with the placeholder:

   ```sh
   kubectl -n <namespace> create secret generic eid-tara-remote-upstream-auth \
     --from-file=upstream-auth=secrets/upstream_auth
   ```

   The relay reads `/run/secrets/relay/upstream-auth`.
4. In `networkpolicy.yaml`, replace the namespace `ingress` with your ingress
   controller's namespace and check the DNS selectors. A NetworkPolicy takes
   effect only with a network plugin that enforces it, and it matches IP
   addresses, not host names. Its TCP 443 egress rule therefore allows any
   address. Do not narrow it with `ipBlock` entries for the JWKS host:
   `forge.cdn.prod.atlassian-dev.net` is served by a CDN whose addresses
   change, so pinned addresses work until the CDN moves, and then the key
   refresh fails and, once `RELAY_JWKS_MAX_AGE` has passed, every login.
   Enforce the host rules of section 6.1 where host names are known instead:
   at an egress firewall or outbound proxy that filters by name, or with your
   network plugin's host-name (FQDN) policies if it has them. With an
   outbound proxy (section 6.6), add a rule for the proxy's address
   (`ipBlock`) and port, such as 3128. A host matched by `NO_PROXY` is still
   reached directly, so keep the port 443 rule while the startup log shows
   `"upstream_proxy":false` or `"jwks_proxy":false` (section 8). Remove it
   only when both are `true`.
5. Apply and check it (section 8):

   ```sh
   kubectl -n <namespace> apply -f deploy/kubernetes/
   kubectl -n <namespace> get pods -l app.kubernetes.io/name=eid-tara-remote
   kubectl -n <namespace> logs deploy/eid-tara-remote
   ```

Keep `enableServiceLinks: false` in the Deployment: otherwise a Service named
`relay` in the same namespace injects variables such as `RELAY_PORT`, which
the relay reads as its own settings.

One replica is enough. More work too, since the relay keeps no state, but
every replica must leave the cluster through the registered static IP.

## 6. Network

### 6.1 Firewall

| Direction     | Allow                                                                                         | Why                    |
| ------------- | --------------------------------------------------------------------------------------------- | ---------------------- |
| Inbound       | TCP 443 to the reverse proxy, only from Atlassian's egress IP ranges (with ACME, see below)   | Forge calls the relay  |
| Outbound      | TCP 443 to the provider host in `RELAY_UPSTREAM_URL`                                          | The token call         |
| Outbound      | TCP 443 to `forge.cdn.prod.atlassian-dev.net`                                                 | Atlassian signing keys |
| Anything else | Deny, apart from the DNS and time synchronization your host needs                             |                        |

Atlassian publishes its IP ranges at `https://ip-ranges.atlassian.com/`; use
the egress ranges and keep them current. With an outbound proxy (section
6.6), also allow the proxy's address and port, and keep the outbound 443
rules for any host the startup log shows with `"upstream_proxy":false` or
`"jwks_proxy":false`: a host in `NO_PROXY` is reached directly.

**Certificates from ACME.** If your proxy obtains its certificate from an
ACME CA such as Let's Encrypt with an HTTP or TLS-ALPN challenge, as Caddy
does by default, the CA's validation servers must reach the proxy on ports 80
and 443 from addresses that are not published in advance. A firewall that
admits only Atlassian's ranges on 443 then blocks certificate issuance and
renewal. In that case open 80 and 443 at the firewall and filter in the
proxy instead: Caddy answers the ACME challenges before its site routes run,
so its `remote_ip` filter (section 6.4) does not block them. With a
certificate obtained another way, such as a DNS challenge or your own CA,
filter at the firewall as well.

### 6.2 Register the static IP

The provider must see, and allowlist, the public IP your relay's outbound
traffic leaves from: your NAT or egress gateway, or the outbound proxy's. Ask
the provider to register it for your client, following its documentation.
Register a new address before you switch to it.

### 6.3 Reverse proxy

The reverse proxy is part of the relay's protection (`PLAN.md` §6, S-9). It
must:

1. **Terminate TLS** for your public name and pass the request to the relay
   over HTTP/1.1, with `Authorization` unchanged and exactly once.
2. **Admit only Atlassian's egress ranges** (S-9). The relay does not filter
   addresses itself, because it would have to trust `X-Forwarded-For`
   (`PLAN.md` §9). The FIT remains the authentication; the filter keeps
   scanners away. The proxy must see the real client address.
3. **Limit connections**: at most 100 to the relay
   (`ProxyMaxConnections = 100`), a 5 s header read timeout
   (`ProxyReadHeaderTimeout = 5s`), and a bound on all open client
   connections, including clients still sending headers and idle
   keep-alives. These are starting values; acceptance testing may lower
   them. If your proxy cannot enforce a limit, enforce it in front of the
   proxy (firewall or load balancer).
4. **Keep the relay port private**: only the proxy and local or cluster
   health probes may reach it, never the public network. The relay serves
   plain HTTP only; the proxy provides TLS.
5. **Never retry** a request to the relay. A token exchange may already have
   used the provider's one-time code (R-8). For the same reason, close idle
   connections to the relay before it does: keep the proxy's upstream
   keep-alive under the relay's 60 s idle timeout, so a request is never
   written onto a connection the relay is closing.
6. **Wait long enough**: allow more than `RELAY_UPSTREAM_TIMEOUT` (10 s) plus
   a few seconds for the relay's answer, so its own `504 upstream_timeout`
   reaches Forge rather than a proxy error.
7. **Log as the relay does**: no request or response bodies, request paths,
   query strings or header values (above all `Authorization`, which carries
   the FIT). Check error logs as well as access logs, since some proxies add
   the request line or headers to error entries. Disable any log you cannot
   redact.
8. **Pass the relay's answers through unchanged**, errors included. Turn off
   custom error pages and response rewriting for the relay: the app tells
   a relay answer by its `Relay-Protocol` header, so a `502` or `503`
   replaced by the proxy's own page shows only as a proxy failure, without
   the relay's error code. Hosted tunnels and CDNs often replace 5xx pages
   by default.

Whatever terminates TLS in front of the relay sees each request and answer
in clear: the token request with its one-time code, and TARA's token answer,
which holds the user's personal data. Run it on infrastructure you control
under the same rules as the relay, or, if a provider terminates TLS for you
(a hosted tunnel, a CDN or a cloud load balancer), cover that provider in
your data processing agreements.

### 6.4 Caddy (Compose)

`deploy/Caddyfile` already sets:

- `read_header 5s` (`ProxyReadHeaderTimeout`), `read_body 10s`, `idle 60s`
  and `max_header_size 16KiB`, matching the relay's own limits;
- `reverse_proxy relay:8080` with `max_conns_per_host 100`
  (`ProxyMaxConnections`), HTTP/1.1 to the relay, `keepalive 50s` (below
  the relay's 60 s idle timeout), `lb_retries 0`, and the
  `Idempotency-Key` and `X-Idempotency-Key` request headers removed;
- no access log (there is no `log` directive), and its handler error and
  proxy logs, which record URIs and header values, dropped. Caddy's other
  logs, such as certificate renewals, go to its container output;
- HTTP/1.1 and HTTP/2 from clients, but no HTTP/3: the compose file
  publishes no UDP port.

You change two things:

1. Replace `relay.example.com` with your relay's public DNS name, and point
   that name at the host. Caddy obtains the certificate itself over ACME, so
   ports 80 and 443 must be reachable (section 6.1).
2. Turn on the IP filter: uncomment these two lines and replace the
   documentation ranges with Atlassian's current egress ranges.

   ```caddyfile
   @outside not remote_ip 192.0.2.0/24 2001:db8::/32
   abort @outside
   ```

   `abort` closes the connection without an answer. `remote_ip` is the TCP
   peer, which is right when Caddy faces the internet directly; behind
   another load balancer, use `client_ip` with `trusted_proxies` instead.
   Check that Caddy sees real client addresses: connections that pass
   through Docker's userland proxy, such as IPv6 to an IPv4-only network,
   arrive from the network's gateway, and the filter refuses them.

Before production use, cap all inbound client connections at the firewall
or load balancer in front of Caddy (section 6.3, item 3), including clients
still sending headers and idle keep-alives. `max_conns_per_host` limits only
connections from Caddy to the relay; it does not provide this inbound cap.

### 6.5 Kubernetes ingress controller

The Kubernetes files ship no Ingress. Route your controller to the Service
`eid-tara-remote`, port `http`, with TLS and the requirements of section
6.3. The settings to look for, with their names in nginx and HAProxy, on
which many controllers are built:

| Requirement                   | nginx                                       | HAProxy                                      |
| ----------------------------- | ------------------------------------------- | -------------------------------------------- |
| `ProxyMaxConnections = 100`   | `max_conns=100` on the upstream server      | `maxconn 100` on the `server` line           |
| `ProxyReadHeaderTimeout = 5s` | `client_header_timeout 5s`                  | `timeout http-request 5s`                    |
| No access log for this host   | `access_log off`                            | `no log` in the frontend                     |
| No retries                    | `proxy_next_upstream off`                   | `retries 0`                                  |
| Upstream keep-alive under 60 s | `keepalive_timeout 50s` in the `upstream` block (ingress-nginx: ConfigMap key `upstream-keepalive-timeout: "50"`) | `http-reuse never`                           |
| Wait for the relay's answer   | `proxy_read_timeout` above 15 s             | `timeout server` above 15 s                  |
| Atlassian's egress ranges     | `allow` and `deny`                          | an `acl` on `src` with `http-request deny`   |

Common defaults are not below the relay's 60 s idle timeout: ingress-nginx
keeps idle connections to the relay for 60 s and Traefik for 90 s. For
Traefik, set `forwardingTimeouts.idleConnTimeout` to `50s` in the
`serversTransport` it uses for the relay (section 6.3, item 5).

Error logs that record the request line or headers must be off or redacted
too. For the IP filter, the controller must see the client's address, for
example with `externalTrafficPolicy: Local` on its `LoadBalancer` Service or
the PROXY protocol from your load balancer. If the certificate comes from an
ACME HTTP challenge through the same controller, exempt
`/.well-known/acme-challenge/` from the IP filter, or use a DNS challenge.

### 6.6 Outbound proxy

If your egress must go through a proxy, set `HTTPS_PROXY` (and `NO_PROXY` for
exceptions) in the relay's environment, for example
`HTTPS_PROXY: http://proxy.example.org:3128`. The relay uses it for the
provider and for the signing keys, and its startup log shows
`"upstream_proxy":true` and `"jwks_proxy":true` when a proxy is in use.

- With an `http://` proxy URL the relay opens a `CONNECT` tunnel, and TLS to
  the provider and to Atlassian stays end to end. The proxy must tunnel to
  both hosts on port 443 without TLS interception: the relay trusts only
  `RELAY_UPSTREAM_CA_FILE`, when set, for the provider and the image's CA
  bundle for the signing keys.
- With an `https://` proxy URL the relay also checks the proxy's own
  certificate, with the same trust: `RELAY_UPSTREAM_CA_FILE`, when set, must
  then also contain the CA of the proxy's certificate, and for the signing
  keys that certificate must chain to a CA in the image's bundle. For a proxy
  with a private CA, use the `http://` form.
- The proxy must not retry requests (R-8). When the proxy carries the
  provider traffic (`"upstream_proxy":true`), the provider sees the proxy's
  address: register that one (section 6.2). If `NO_PROXY` exempts the
  provider, it sees the relay host's own address instead.
- In Kubernetes, `networkpolicy.yaml` must also allow the proxy's address
  and port. Keep its port 443 rule while `NO_PROXY` exempts the provider or
  the signing-key host, which the relay then reaches directly (section 5,
  step 4).

## 7. Clock

FITs are short-lived. The relay checks their `exp` and `nbf` against its own
clock with a tolerance of `RELAY_CLOCK_SKEW` (10 s). A container uses its
host's clock, so keep the host synchronized with NTP (for example chrony or
`systemd-timesyncd`). A wrong clock shows as `auth_reason` `expired` or
`not_yet_valid`. Fix the clock rather than raising the skew; the relay
refuses a skew over 1 minute.

## 8. Check the relay

1. **Startup log.** A `starting` line with `version`, `go`, `upstream_proxy`,
   `jwks_proxy` and one field per setting. `RELAY_UPSTREAM_AUTH` shows
   `set (from file)`, `not set`, or `set` for an inline value, which also
   logs a `credential set inline` warning. `RELAY_UPSTREAM_CA_FILE` shows
   only `set` or `system bundle`. A configuration error logs
   `invalid configuration` with the `setting` and a `reason`, never the
   value, and exits with code 2 (section 10.1). A
   warning `unknown setting` names a `RELAY_*` variable the relay does not
   know, usually a typo, or shows `RELAY_* (malformed name)` for a name that
   cannot be a setting name (section 10.1).
2. **Signing keys.** `signing keys ready` follows once the keys are loaded.
   Until then the relay is live but not ready, and protected requests answer
   `503 not_ready`.
3. **Health.** The Compose health check runs `/relay healthcheck`, which asks
   `/livez`: `healthy` in `docker compose ps` means the process answers, not
   that it is ready. Ask `/readyz` with `--ready`; the command exits 0 when
   the relay is ready and 1 otherwise. The image has no shell, but it does
   have the relay binary:

   ```sh
   docker compose exec relay /relay healthcheck --ready && echo ready
   kubectl -n <namespace> exec deploy/eid-tara-remote -- /relay healthcheck --ready
   ```

   In Kubernetes, a pod shows `READY 1/1` once `/readyz` answers `200`.
   `/relay version` prints the release.
4. **End to end.** Enter the relay's public URL on the admin page. Its health
   check calls `/relay/v1/info` through Forge, your proxy and the relay, and
   shows the relay version and whether a credential is set.
5. **From outside.** From an address outside Atlassian's ranges, such as
   your own workstation, ask the public name for `/livez`:

   ```sh
   curl -s -o /dev/null -w '%{http_code}\n' https://relay.example.com/livez
   ```

   With the supplied Caddyfile this prints `000`: the IP filter closes the
   connection without an answer (section 6.4). Another proxy may answer with
   its own refusal, such as `403`. `200` means the filter is off and the
   relay is open to every address. The FIT still guards the token route,
   but turn the filter on before production use (section 6.3, item 2).

## 9. Upgrades

Images are tagged `:X.Y.Z` (never changed after release) and `:X.Y` (moves to
the newest verified patch of that line). There is no `latest`. Choose how you
upgrade:

| Mode                          | Image tag | How                                                                                                                                                   |
| ----------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pinned (default in `deploy/`) | `:X.Y.Z`  | You read the release notes and change the tag by hand.                                                                                                |
| Automatic patches (opt-in)    | `:X.Y`    | Docker: Watchtower, set to update only the relay. Kubernetes: `imagePullPolicy: Always` plus a scheduled `kubectl rollout restart` of the Deployment. |

A patch release never changes an endpoint, response code, header or setting,
so following `:X.Y` never brings a protocol or setting change. A new minor or
major release always needs a tag change by hand; the admin page tells you
when your relay is older than the app expects.

Every release note says whether the upgrade is **required**, **recommended**
or **optional**, and why:

- **required:** only the project's owner marks a release required; upgrade
  as the note says.
- **recommended:** for example, the new Go release fixes a vulnerability
  that is reachable in the relay.
- **optional:** no reachable vulnerability is fixed; upgrade when convenient.

To upgrade a pinned relay, read the notes, verify the new image (below),
change the tag, and repeat the checks in section 8:

- **Compose:** `docker compose pull relay && docker compose up -d relay`.
  Logins fail for a few seconds while the new container starts and loads the
  signing keys, so upgrade at a quiet time.
- **Kubernetes:** `kubectl -n <namespace> apply -f deploy/kubernetes/deployment.yaml`.
  The rolling update starts the new pod and keeps the old one until the new
  one is ready.

**Verify the image.** Every release image is signed with cosign keyless
signing by this repository's release workflow, and the index and each
platform image carry a signature. Check the signature before you deploy a
digest:

```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/Oktul/eID-TARA-remote/\.github/workflows/release\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/oktul/eid-tara-remote@sha256:<digest>
```

The identity is `release.yml` of this repository, started by a `vX.Y.Z` tag
(a release made by a person) or from `main` (an automatic Go patch release).
Write the owner and repository as GitHub spells them, with dots escaped.
Each release's notes contain this command with the real names and the
image's index digest. The SBOM and provenance attestations are attached to
the image index; `docker buildx imagetools inspect
ghcr.io/oktul/eid-tara-remote:X.Y.Z --format '{{json .Provenance}}'` shows
the provenance (`.SBOM` the SBOM).

**Rollback:** note the digest of the image you run before upgrading, for
example with `docker inspect --format '{{index .RepoDigests 0}}'
ghcr.io/oktul/eid-tara-remote:X.Y.Z`. To roll back, deploy that digest
(`ghcr.io/oktul/eid-tara-remote@sha256:<digest>`).

Which lines are supported, and until when: `docs/SUPPORT.md`.

## 10. Troubleshooting

### 10.1 Startup

| Log line                                  | What to check                                                                                                                                         |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid configuration`, `setting`, `reason` | The setting named, against `docs/PROTOCOL.md` section 8. The process exits with code 2, and Compose and Kubernetes restart it until you fix it.  |
| `unknown setting`, `name`                 | A mistyped `RELAY_*` name. It often explains a `required` error for the setting you meant.                                                             |
| `unknown setting`, `name` `RELAY_* (malformed name)` | A `RELAY_` variable whose name has characters other than `A-Z`, `0-9` and `_`, or more than 64 bytes; the name is not logged. Usually `:` was typed for `=` in the deploy file, so the value became part of the name. Correct the entry, and if it holds the credential, remove it from the deploy file and use the secret file (section 3). |
| `upstream is not TARA`, `setting` `RELAY_UPSTREAM_ANY_HOST` | `RELAY_UPSTREAM_ANY_HOST=true` lets the relay send the credential to an origin that is not TARA's. Only for test setups; unset it. |
| `credential set inline`, `setting` `RELAY_UPSTREAM_AUTH` | The credential is in the environment, where `docker inspect`, orchestrator UIs and the process environment show it. Move it to a secret file and set `RELAY_UPSTREAM_AUTH_FILE` instead (section 3). |
| `listen failed`                           | `RELAY_PORT` is in use, or is a port the runtime does not let an unprivileged user open: the relay runs without capabilities.                         |
| `stopped`, `error` `shutdown_timeout`     | In-flight requests ran longer than `RELAY_SHUTDOWN_GRACE` when the relay stopped.                                                                      |

The `setting` is the `_FILE` name when the file is the problem, and the
setting itself when its content is wrong. Common cases:

- `RELAY_UPSTREAM_AUTH_FILE`: `file is not readable` (owner and mode,
  section 3.1), `file does not exist` (the path, or a missing secret mount),
  `file is empty`.
- `RELAY_UPSTREAM_AUTH`: `want "Name: value" with a non-empty value and no
  control characters` (the file's content; the placeholder in `secret.yaml`
  fails this way), or `header may not be configured` (a forbidden header
  name).
- `RELAY_UPSTREAM_CA_FILE`: `unexpected text outside the PEM blocks`,
  `PEM block is not a CERTIFICATE`, `malformed PEM block`,
  `invalid certificate` or `no PEM certificate` (section 3.2).
- `RELAY_UPSTREAM_URL`: `not one of https://tara.ria.ee,
  https://tara-test.ria.ee; set RELAY_UPSTREAM_ANY_HOST=true for another
  upstream`. The value is not exactly one of TARA's two origins (the log
  does not show it). Copy it again from the admin page, without a path,
  port or trailing dot. `RELAY_UPSTREAM_ANY_HOST=true` lifts the check for
  test setups with a synthetic upstream; never set it for a real relay.
- `RELAY_APP_ID`: `want ari:cloud:ecosystem::app/ followed by a lowercase
  UUID`, which is also what an unreplaced `<from the admin page>` gives.
- `set only one of RELAY_UPSTREAM_AUTH and RELAY_UPSTREAM_AUTH_FILE`, and
  likewise for any other setting.
- `empty; unset it to use the default`: a variable that is present but
  empty never means the default.

### 10.2 Signing keys

| Log line                                     | What to check                                                                                                                                                         |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `jwks refresh failed`, `reason` `fetch`      | DNS, connection, TLS or timeout to `RELAY_JWKS_URL`, or an answer header over 32 KiB: the outbound firewall, `HTTPS_PROXY` and `NO_PROXY`, or a proxy that intercepts TLS or rewrites answers (section 6.6). |
| `jwks refresh failed`, `reason` `status`     | The JWKS host answered with something other than `200`, a redirect included: `RELAY_JWKS_URL`, or the proxy.                                                          |
| `jwks refresh failed`, other `reason`        | `too_large`, `malformed`, `key_parameters`, `duplicate_kid`, `too_many_keys` or `no_usable_keys`: the document is not a usable Atlassian key set. Check `RELAY_JWKS_URL` and anything that rewrites answers. `panic` is a relay bug; report it. |
| `signing keys expired`                       | No refresh has succeeded for `RELAY_JWKS_MAX_AGE`; the relay answers `503 not_ready` until one does. See the `jwks refresh failed` lines before it.                  |
| `signing keys ready`                         | Keys are loaded, at startup or again after an expiry.                                                                                                                  |
| `jwks keys skipped`, `reason`, `count`       | Normal: keys the relay does not use (`kty`, `use`, `alg` or `undersized`).                                                                                             |

Failed fetches are retried after 1 s, doubling up to 1 min. The last good
keys stay in use until `RELAY_JWKS_MAX_AGE` (24 h).

### 10.3 Request errors

The Forge side sees an error code in `Relay-Error`; the relay's log line for
the same request has it in `error`, with the detail in `auth_reason`.

| Code                   | What to check                                                                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| no `Relay-*` headers   | The answer came from the proxy or never reached a relay handler: the IP filter, the proxy's timeouts, or a relay the proxy cannot reach.  |
| `invalid_token`        | The log's `auth_reason` (section 10.4).                                                                                                   |
| `route_not_allowed`    | The request is not exactly `POST /oidc/token`, including its case, or has a query string.                                                 |
| `body_too_large`       | A request over 64 KiB. Token requests are a few KB, so check what is calling.                                                            |
| `internal_error`       | A relay bug (`error` `panic`). Report it with the log line; never include tokens or credentials.                                         |
| `upstream_unreachable` | DNS for TARA, the outbound firewall, `HTTPS_PROXY` and `NO_PROXY`, `RELAY_UPSTREAM_CA_FILE` (still TARA's CAs?), or an outage. Also an answer that is not valid HTTP/1.1 or whose header is over 32 KiB: check `RELAY_UPSTREAM_URL` and anything that rewrites answers. |
| `upstream_too_large`   | A TARA answer over 64 KiB. Unusual for token calls; check `RELAY_UPSTREAM_URL`.                                                             |
| `not_ready`            | The signing keys (section 10.2). `/readyz` also answers it while the relay shuts down.                                                    |
| `too_busy`             | More than 50 token exchanges at once, each with a valid FIT. Logins rarely come close; check for a slow TARA (`upstream_timeout`) or a FIT replayed by someone who saw it in clear (`PLAN.md` §14 Phase 4, SR-1). |
| `upstream_timeout`     | A slow provider, or a firewall that silently drops outbound packets.                                                                      |

Two more `error` values have no code, because nobody receives an answer:

- `client_canceled`: the caller left while the provider call was running;
  the line shows status `502`. If it recurs, a proxy timeout is probably
  shorter than the relay's (section 6.3, item 6).
- `request_read`: the request body could not be read (the client left, took
  longer than 10 s, or sent broken chunked framing). The relay closed the
  connection without an answer.

A request the HTTP server rejects before the relay sees it, such as a header
block over 16 KiB, logs a `request` line with `error` `http_server`
(section 11). Failures inside the HTTP server itself log only
`http server error` at `debug` level, without detail.

### 10.4 `auth_reason`

| `auth_reason`    | Meaning                                                                       | What to check                                                                    |
| ---------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `authorization`  | `Authorization` missing, repeated or not `Bearer <token>`                     | The proxy drops or duplicates `Authorization`, or the caller is not Forge.       |
| `token_format`   | Not three strict base64url parts of at most 8 KiB, or a header that is not strict JSON | Not a FIT; usually a scanner.                                            |
| `header`         | Not `RS256` with a `kid`, or a forbidden header member                        | Not a FIT.                                                                       |
| `key_unknown`    | No trusted signing key for the token's `kid`                                  | A key Atlassian rotated in within the last minute (it is accepted after the next refresh), or `RELAY_JWKS_URL`. |
| `signature`      | The signature does not verify                                                 | Something altered the token on the way, or it is forged.                         |
| `payload`        | The payload is not one strict JSON object, or has no `app` object              | Not a valid FIT. Report it if Forge calls fail this way.                         |
| `issuer`         | `iss` is not `forge/invocation-token`                                         | Not a FIT.                                                                       |
| `audience`       | The token is not for `RELAY_APP_ID`                                           | `RELAY_APP_ID` differs from the admin-page block.                                |
| `dates`          | `exp` or `nbf` missing, malformed or out of range, or `exp` not after `nbf`    | Not a valid FIT.                                                                 |
| `lifetime`       | `exp` is more than 5 minutes after `nbf`; Forge's tokens span 55 s           | Not a token Forge minted. Report it if Forge calls fail this way.                |
| `expired`        | The token expired, beyond the skew                                            | The host clock (section 7).                                                      |
| `not_yet_valid`  | The token is not valid yet, beyond the skew                                   | The host clock (section 7).                                                      |
| `environment`    | The app environment is not `RELAY_ENVIRONMENT_ID`                             | The block was copied from another app environment.                               |
| `installation`   | `app.installationId` malformed, or not in `RELAY_INSTALLATION_IDS`            | A reinstall changes the installation ID: update or unset the setting.            |
| `cloud_id`       | The site is not allowed, malformed, missing or conflicting                    | `RELAY_CLOUD_IDS` is not your site's, or another site points at your relay.      |
| `isolated_cloud` | The token comes from Isolated Cloud                                           | Isolated Cloud is not supported.                                                 |

A rejected token's site is never logged (`cloud_id` stays empty), because it
is unverified.

**The provider answered with an error.** The Forge side sees `200` with the
provider's status in `Relay-Upstream-Status`, and the log line has it in
`upstream_status`. A `401` usually means a wrong credential: check the
format and content of the credential file. A refusal because of your IP
address is provider-specific; check that the registered IP is the one your
relay really leaves from (section 6.2).

## 11. Logs

The relay writes JSON lines to standard output (`docker compose logs relay`,
`kubectl logs`) and nothing to disk. Every line has `time`, `level` and
`msg`. `RELAY_LOG_LEVEL` sets the level. Each request produces one line with
`msg` `request`; health checks log at `debug`, so an unready `/readyz` does
not show at `info`.

| Field             | Content                                                                                                                       |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `request_id`      | The request's `x-b3-traceid` if it is valid (16 or 32 hex characters, not all zero, lowercased), otherwise a random ID. Use it to correlate with Forge. |
| `method`          | `GET`, `POST`, `PUT`, `PATCH` or `DELETE`; every other method is `other`.                                                       |
| `route`           | The matched route (`GET /livez`, `GET /readyz`, `GET /relay/v1/info` or `POST /oidc/token`), or `unmatched`.                    |
| `status`          | The status the relay answered with.                                                                                           |
| `upstream_status` | The provider's status, when it answered.                                                                                      |
| `duration_ms`     | The time to answer.                                                                                                           |
| `error`           | The relay's error code, or `client_canceled`, `request_read` or `panic` (section 10.3), or `http_server` (below). Never a raw error message. |
| `auth_reason`     | Why a FIT was refused (section 10.4).                                                                                         |
| `cloud_id`        | The site, only from a verified FIT.                                                                                           |

A request the HTTP server refuses before the relay sees it, such as a
header over 16 KiB (`431`) or a malformed request (`400`), also logs a
`request` line, with `route` `unmatched`, its `status` and `error`
`http_server`, but no `method`, since the request was never parsed. Many
of them usually mean a scanner or a misconfigured front end.

The logs never contain request or response bodies, query strings, request
paths that matched no route, header values other than the validated trace
ID, the FIT, the credential, raw error text, key IDs or unverified site IDs
(`PLAN.md` §10). Startup diagnostics follow the same rules. The only URLs in
the logs are the configured `RELAY_UPSTREAM_URL` origin and
`RELAY_JWKS_URL`, in the `starting` summary, which lists the settings one by
one; neither URL can hold userinfo or a query (`docs/PROTOCOL.md` section
8). The summary shows the credential only as set or not set.

**Log rotation.** `compose.yaml` already rotates the logs of each service:
Docker's `json-file` driver keeps at most three files of 10 MB (`PLAN.md`
§10). Change the size or count in its `x-logging` block. That block
overrides the host's default log driver; to use the host's instead, such as
a log shipper set in `/etc/docker/daemon.json`, remove the two
`logging: *logging` lines and make sure the host's driver rotates too.

In Kubernetes, the kubelet rotates container logs (`containerLogMaxSize` and
`containerLogMaxFiles`).
