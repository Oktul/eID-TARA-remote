#!/usr/bin/env bash
# Runs the ci.yml source checks (PLAN.md §12) on the module in the current
# directory: one named check, or "all". ci.yml runs them as separate steps and
# go-patch-line.yml runs all of them, so both use the same commands.
set -euo pipefail
# shellcheck source=.github/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# module enforces PLAN.md D2 and §12: no modules, and one Go version for the
# tests and the image builder.
check_module() {
	local toolchain goversion builder
	if grep -Eq '^[[:space:]]*(require|replace|tool)([[:space:](]|$)' go.mod; then
		die "go.mod must not list modules or tools (PLAN.md D2)"
	fi
	[[ ! -e go.sum ]] || die "go.sum must not exist: there are no modules (PLAN.md §11)"
	toolchain=$(toolchain_version go.mod)
	goversion=$(go env GOVERSION)
	[[ $goversion == "go$toolchain" ]] || die "the checks run $goversion, but go.mod pins go$toolchain"
	if [[ ! -e Dockerfile ]]; then
		notice "No Dockerfile yet (PLAN.md §14 Phase 1): skipping the builder pin check"
		return
	fi
	builder=$(builder_ref Dockerfile)
	[[ ${builder%% *} == "$toolchain" ]] ||
		die "go.mod pins go$toolchain, but the Dockerfile builds with golang:${builder%% *}-trixie"
}

check_gofmt() {
	local files
	files=$(gofmt -l .)
	[[ -z $files ]] || die "gofmt -l lists files that need formatting: ${files//$'\n'/ }"
}

check_vet() {
	go vet ./...
}

check_staticcheck() {
	go run "$STATICCHECK" ./...
}

check_test() {
	go test -race ./...
}

check_govulncheck() {
	go run "$GOVULNCHECK" ./...
}

# gitleaks runs as a checksum-verified CLI: its GitHub Action needs a licence
# for organisation accounts (PLAN.md §12).
check_gitleaks() {
	local arch sum dir asset
	case $(uname -m) in
	x86_64) arch=x64 sum=$GITLEAKS_SHA256_X64 ;;
	aarch64) arch=arm64 sum=$GITLEAKS_SHA256_ARM64 ;;
	*) die "no pinned gitleaks build for $(uname -m)" ;;
	esac
	asset="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"
	dir=$(mktemp -d)
	curl -fsSL --retry 3 --max-time 120 -o "$dir/$asset" \
		"https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$asset"
	(cd "$dir" && printf '%s  %s\n' "$sum" "$asset" | sha256sum --check --strict -)
	tar -xzf "$dir/$asset" -C "$dir" gitleaks
	"$dir/gitleaks" git --redact --no-banner .
	rm -rf "$dir"
}

run_check() {
	case $1 in
	module) check_module ;;
	gofmt) check_gofmt ;;
	vet) check_vet ;;
	staticcheck) check_staticcheck ;;
	test) check_test ;;
	govulncheck) check_govulncheck ;;
	gitleaks) check_gitleaks ;;
	*) die "usage: source-checks.sh all|module|gofmt|vet|staticcheck|test|govulncheck|gitleaks" ;;
	esac
}

if [[ ${1:-} == all ]]; then
	for c in module gofmt vet staticcheck test govulncheck gitleaks; do
		echo "::group::$c"
		run_check "$c"
		echo "::endgroup::"
	done
else
	run_check "${1:-}"
fi
