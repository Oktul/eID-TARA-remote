#!/usr/bin/env bash
# Smoke-tests a relay image the way customers run it (PLAN.md §12 ci.yml):
# read-only root, non-root user, no capabilities (§6 R-10, §7), live while
# the JWKS is unreachable but not ready (§4.5), and a bad setting exits 2
# naming the setting without its value (§6 R-13, §8). Also checks that the
# image carries the licence text (§7).
# Usage: smoke.sh <image>
set -euo pipefail
# shellcheck source=.github/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

image=${1:?usage: smoke.sh <image>}

readonly user=65532:65532
readonly start_attempts=30 # one per second while the container starts
# The SHA-256 of the Commission's EUPL v. 1.2 text, which is LICENSE in the
# repository. The scripts are checked out without the source, so the image
# is compared with this digest, not with the file.
readonly licence_sha256=6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665

hardening=(--read-only --user "$user" --cap-drop ALL --security-opt no-new-privileges)
# Synthetic values only. ".invalid" never resolves (RFC 2606), so the relay
# starts but never loads a signing key.
settings=(
	-e RELAY_APP_ID=ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000000
	-e RELAY_ENVIRONMENT_ID=00000000-0000-4000-8000-000000000001
	-e RELAY_CLOUD_IDS=00000000-0000-4000-8000-000000000002
	-e RELAY_UPSTREAM_URL=https://upstream.invalid
	-e RELAY_UPSTREAM_ANY_HOST=true
	-e RELAY_JWKS_URL=https://jwks.invalid/.well-known/jwks.json
)

[[ $(docker image inspect --format '{{.Config.User}}' "$image") == "$user" ]] ||
	die "the image must declare USER $user (PLAN.md §7)"

container=$(docker run --detach "${hardening[@]}" --publish 127.0.0.1::8080 "${settings[@]}" "$image")
cleanup() {
	local status=$?
	if ((status != 0)); then
		docker logs "$container" || true
	fi
	docker rm --force "$container" >/dev/null || true
}
trap cleanup EXIT

addr=$(docker port "$container" 8080/tcp | head -n 1)
base="http://$addr"
curl -fsS --retry "$start_attempts" --retry-delay 1 --retry-all-errors --max-time 2 -o /dev/null "$base/livez" ||
	die "/livez never answered"

headers=$(mktemp)
status=$(curl -sS --max-time 5 -o /dev/null -D "$headers" -w '%{http_code}' "$base/livez")
[[ $status == 200 ]] || die "GET /livez answered $status, want 200"
grep -qix 'relay-protocol: 1' < <(tr -d '\r' <"$headers") || die "GET /livez has no Relay-Protocol: 1 (PLAN.md §4.3)"

status=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$base/readyz")
[[ $status == 503 ]] || die "GET /readyz answered $status with an unreachable JWKS, want 503"

[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container") == true ]] ||
	die "the root filesystem is writable"
# docker top runs ps on the host, so this is the relay's real user, not a
# claim from the image.
ids=$(docker top "$container" -o pid,uid,gid | awk 'NR > 1 { print $2 ":" $3 }' | sort -u)
[[ $ids == "$user" ]] || die "the container runs as ${ids//$'\n'/ }, want $user"

# The image has no shell, so docker cp reads the file; it writes a tar stream.
sum=$(docker cp "$container:/LICENSE" - | tar --extract --to-stdout | sha256sum | cut -d ' ' -f 1) ||
	die "the image has no /LICENSE (PLAN.md §7)"
[[ $sum == "$licence_sha256" ]] || die "/LICENSE in the image is not the EUPL v. 1.2 text (PLAN.md §7)"

docker exec "$container" /relay healthcheck || die "/relay healthcheck failed while /livez is up"
rc=0
docker exec "$container" /relay healthcheck --ready || rc=$?
((rc == 1)) || die "/relay healthcheck --ready exited $rc while not ready, want 1"

rc=0
out=$(docker run --rm "${hardening[@]}" "${settings[@]}" -e RELAY_PORT=notaport "$image" 2>&1) || rc=$?
((rc == 2)) || die "a bad RELAY_PORT exited $rc, want 2"
grep -q RELAY_PORT <<<"$out" || die "the configuration error does not name RELAY_PORT"
if grep -q notaport <<<"$out"; then
	die "the configuration error echoes the setting's value (PLAN.md §8)"
fi

echo "smoke test passed: $image"
