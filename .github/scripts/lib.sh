# shellcheck shell=bash disable=SC2034 # the constants are for the sourcing scripts
# Shared helpers for the workflow scripts (PLAN.md §12). Sourced after
# "set -euo pipefail". Bash ignores -e inside a function called from an if,
# || or && test, so callers run the helpers that can fail as plain
# statements, and each helper also checks its own commands.

shopt -s inherit_errexit

# Tool versions are pinned here once, so every workflow runs the same ones.
readonly STATICCHECK=honnef.co/go/tools/cmd/staticcheck@2026.2.2
readonly GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck@v1.9.0
readonly GITLEAKS_VERSION=8.30.1
readonly GITLEAKS_SHA256_X64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
readonly GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080

readonly OIDC_ISSUER=https://token.actions.githubusercontent.com
readonly BOT_NAME='github-actions[bot]'
readonly BOT_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'

# The labels release.yml puts on every image, read back to verify a build
# (release.sh) and to find the commit a release was built from (go-patch.sh).
readonly LABEL_VERSION=org.opencontainers.image.version
readonly LABEL_REVISION=org.opencontainers.image.revision

die() {
	printf '::error::%s\n' "$*" >&2
	exit 1
}

notice() {
	printf '::notice::%s\n' "$*"
}

# output sets a step output for later steps and jobs.
output() {
	printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:?}"
}

# github_auth hands the workflow token (GH_TOKEN) to git and skopeo in the
# calling script only, through its environment, so the token is never stored
# in the clone or the Docker configuration. That does not hide it from other
# code in the same job, which is why go-patch-line.yml runs tests and
# third-party tools only in read-only jobs (PLAN.md §12 hygiene). Git hooks
# are off for the same reason: a hook would run with the token in its
# environment.
github_auth() {
	local basic registry
	: "${GH_TOKEN:?}" "${GITHUB_ACTOR:?}"
	basic=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w 0)
	registry=$(printf '%s:%s' "$GITHUB_ACTOR" "$GH_TOKEN" | base64 -w 0)
	printf '::add-mask::%s\n' "$basic" "$registry"
	export GIT_CONFIG_COUNT=2
	export GIT_CONFIG_KEY_0="http.${GITHUB_SERVER_URL:?}/.extraheader"
	export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $basic"
	export GIT_CONFIG_KEY_1=core.hooksPath
	export GIT_CONFIG_VALUE_1=/dev/null
	auth_dir=$(mktemp -d)
	trap 'rm -rf "$auth_dir"' EXIT
	printf '{"auths":{"ghcr.io":{"auth":"%s"}}}\n' "$registry" >"$auth_dir/auth.json"
	export REGISTRY_AUTH_FILE=$auth_dir/auth.json
}

run_url() {
	printf '%s/%s/actions/runs/%s\n' "${GITHUB_SERVER_URL:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}"
}

# image_name is the release image, lowercased because registries require it.
image_name() {
	printf 'ghcr.io/%s\n' "${GITHUB_REPOSITORY,,}"
}

# identity_regexp matches the keyless signing identity of release.yml
# (PLAN.md §12, S-5). GitHub names a workflow by the ref that started the
# run: a vX.Y.Z tag push, or main for the call from go-patch.yml, which runs
# on the default branch.
identity_regexp() {
	local repo=${GITHUB_REPOSITORY:?}
	repo=${repo//./\\.}
	printf '%s\n' "^https://github\.com/${repo}/\.github/workflows/release\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)\$"
}

valid_line() {
	[[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# version_gt reports whether dotted version $1 is greater than $2.
version_gt() {
	[[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1) == "$1" ]]
}

# toolchain_version prints X.Y.Z from go.mod's single "toolchain goX.Y.Z" line.
toolchain_version() {
	local v
	v=$(sed -nE 's/^toolchain go([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' "$1")
	[[ -n $v && $v != *$'\n'* ]] || die "$1: expected exactly one 'toolchain goX.Y.Z' line"
	printf '%s\n' "$v"
}

# builder_ref prints "<Go version> <index digest>" of the Dockerfile's single
# golang builder, which PLAN.md §7 pins by digest.
builder_ref() {
	local refs
	[[ -f $1 ]] || die "$1 is missing"
	mapfile -t refs < <(grep -Ei '^[[:space:]]*FROM[[:space:]]' "$1" |
		grep -Eo '(^|[[:space:]])(docker\.io/library/)?golang:[^[:space:]]+' |
		sed -E 's/^[[:space:]]+//')
	((${#refs[@]} == 1)) || die "$1: expected exactly one golang builder FROM line, found ${#refs[@]}"
	[[ ${refs[0]} =~ ^(docker\.io/library/)?golang:([0-9]+\.[0-9]+\.[0-9]+)-trixie@(sha256:[0-9a-f]{64})$ ]] ||
		die "$1: the builder must be golang:<version>-trixie@sha256:<digest> (PLAN.md §7)"
	printf '%s %s\n' "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

# check_line checks that the only change to file $4 from commit $2 to commit
# $3 of repository $1 is one line, whose text $5 became $6.
check_line() {
	local diff lines removed added
	diff=$(git -C "$1" diff --unified=0 --no-color "$2" "$3" -- "$4")
	mapfile -t lines < <(grep -E '^[-+]' <<<"$diff" | grep -Ev '^(---|\+\+\+) ' || true)
	((${#lines[@]} == 2)) && [[ ${lines[0]} == -* && ${lines[1]} == +* ]] ||
		die "$4: the update must change exactly one line"
	removed=${lines[0]#-}
	added=${lines[1]#+}
	[[ $removed == *"$5"* && $added == "${removed/"$5"/"$6"}" ]] ||
		die "$4: the changed line is not the expected update"
}

# check_update checks that commit $3 of repository $1 has commit $2 as its
# only parent and changes nothing but go.mod's toolchain line and the
# Dockerfile builder line (PLAN.md §12: no source, test, workflow,
# configuration or protocol change). It prints the builder of $2, then that
# of $3, each as "<Go version> <digest>" on its own line.
check_update() {
	local repo=$1 base=$2 commit=$3 dir old new old_go new_go files want
	[[ $(git -C "$repo" rev-list --parents -n 1 "$commit") == "$(git -C "$repo" rev-parse --verify "$commit^{commit}") $base" ]] ||
		die "the update commit must have $base as its only parent"
	dir=$(mktemp -d)
	git -C "$repo" cat-file blob "$base:go.mod" >"$dir/base.mod"
	git -C "$repo" cat-file blob "$commit:go.mod" >"$dir/new.mod"
	git -C "$repo" cat-file blob "$base:Dockerfile" >"$dir/base.Dockerfile"
	git -C "$repo" cat-file blob "$commit:Dockerfile" >"$dir/new.Dockerfile"
	old_go=$(toolchain_version "$dir/base.mod")
	new_go=$(toolchain_version "$dir/new.mod")
	old=$(builder_ref "$dir/base.Dockerfile")
	new=$(builder_ref "$dir/new.Dockerfile")
	rm -rf "$dir"
	[[ ${old%% *} == "$old_go" && ${new%% *} == "$new_go" ]] || die "go.mod and the Dockerfile pin different Go versions"

	files=$(git -C "$repo" diff --no-renames --name-only "$base" "$commit" | sort)
	want=Dockerfile
	if [[ $new_go != "$old_go" ]]; then
		want=$'Dockerfile\ngo.mod'
	fi
	[[ $files == "$want" ]] || die "the update may change only ${want//$'\n'/ and }, but changes ${files//$'\n'/, }"
	check_line "$repo" "$base" "$commit" Dockerfile "golang:$old_go-trixie@${old#* }" "golang:$new_go-trixie@${new#* }"
	if [[ $new_go != "$old_go" ]]; then
		check_line "$repo" "$base" "$commit" go.mod "toolchain go$old_go" "toolchain go$new_go"
	fi
	printf '%s\n%s\n' "$old" "$new"
}

# check_go_patch checks that commit $3 of repository $1 is the only update
# PLAN.md §12 ships unreviewed: check_update from commit $2, on the same Go
# minor and never to an older Go. go-patch.sh checks it before the push, and
# release.sh again before an automatic release.
check_go_patch() {
	local builders old_go new_go
	builders=$(check_update "$1" "$2" "$3")
	old_go=${builders%% *}
	new_go=${builders#*$'\n'}
	new_go=${new_go%% *}
	if [[ ${new_go%.*} != "${old_go%.*}" ]] || version_gt "$old_go" "$new_go"; then
		die "an automatic update stays on Go ${old_go%.*} and never goes back, but this one moves Go $old_go to $new_go"
	fi
}

# replace_once replaces the literal text $2 with $3 in file $1, and fails
# unless it occurs on exactly one line.
replace_once() {
	local tmp
	tmp=$(mktemp)
	awk -v old="$2" -v new="$3" '
		{ i = index($0, old); if (i) { $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); n++ } print }
		END { if (n != 1) exit 3 }' "$1" >"$tmp" || die "$1: expected exactly one occurrence of $2"
	cat "$tmp" >"$1"
	rm -f "$tmp"
}

# manifest_digest prints the digest of the manifest or index that a skopeo
# reference names, computed from its exact bytes.
manifest_digest() {
	local f sum
	f=$(mktemp)
	skopeo inspect --raw "$1" >"$f" || die "cannot read the manifest of $1"
	[[ -s $f ]] || die "empty manifest for $1"
	sum=$(sha256sum "$f" | cut -d ' ' -f 1)
	rm -f "$f"
	printf 'sha256:%s\n' "$sum"
}

# platform_digest prints the digest of the single linux/<arch> image in the
# index that skopeo reference $1 names.
platform_digest() {
	local raw
	raw=$(skopeo inspect --raw "$1") || die "cannot read the index of $1"
	jq -er --arg a "$2" '
		[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $a)]
		| if length == 1 then .[0].digest else error("want exactly one linux/\($a) image") end' <<<"$raw" ||
		die "$1: no single linux/$2 image"
}

# image_tags prints the tags of image $1, one per line, and nothing when the
# repository does not exist yet. Any other answer stops the script, so a
# registry error never looks like "unpublished" (PLAN.md §12: never
# overwrite a version tag).
image_tags() {
	local dir
	dir=$(mktemp -d)
	if skopeo list-tags "docker://$1" >"$dir/tags.json" 2>"$dir/err"; then
		jq -r '.Tags | if type == "array" then .[] else error("no tag list") end' "$dir/tags.json" ||
			die "cannot parse the tags of $1"
	elif grep -qi 'name unknown' "$dir/err"; then
		:
	else
		cat "$dir/err" >&2
		die "cannot list the tags of $1"
	fi
	rm -rf "$dir"
}

# tag_in reports whether tag $2 is in the newline-separated list $1.
tag_in() {
	grep -qxF -- "$2" <<<"$1"
}

# image_label prints label $3 of the linux/<arch> image of skopeo reference $1.
image_label() {
	local info
	info=$(skopeo inspect --override-os linux --override-arch "$2" "$1") || die "cannot inspect $1 for $2"
	jq -er --arg l "$3" '.Labels[$l] // ""' <<<"$info" || die "$1: unreadable labels"
}

# go_releases prints Go's supported stable releases (X.Y.Z), newest first.
go_releases() {
	local json
	json=$(curl -fsSL --retry 3 --max-time 30 'https://go.dev/dl/?mode=json') || die "cannot read go.dev/dl"
	jq -er '.[] | select(.stable == true) | .version' <<<"$json" >/dev/null || die "go.dev/dl lists no stable release"
	jq -r '.[] | select(.stable == true) | .version' <<<"$json" |
		sed -nE 's/^go([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' | sort -rV
}

# golang_digest prints the index digest of golang:<version>-trixie, read two
# ways that must agree, after checking that it has both architectures.
golang_digest() {
	local ref="docker.io/library/golang:$1-trixie" f d1 d2 arch
	f=$(mktemp)
	skopeo inspect --raw "docker://$ref" >"$f" || die "cannot read $ref"
	d1="sha256:$(sha256sum "$f" | cut -d ' ' -f 1)"
	for arch in amd64 arm64; do
		jq -e --arg a "$arch" 'any(.manifests[]?; .platform.os == "linux" and .platform.architecture == $a)' "$f" >/dev/null ||
			die "$ref has no linux/$arch image"
	done
	rm -f "$f"
	d2=$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$ref" | jq -er .digest) ||
		die "cannot read $ref with buildx"
	[[ $d1 == "$d2" ]] || die "$ref: skopeo and buildx disagree about the index digest"
	printf '%s\n' "$d1"
}
