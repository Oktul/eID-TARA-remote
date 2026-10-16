#!/usr/bin/env bash
# The steps of release.yml (PLAN.md §12). Read-only jobs check and build;
# only "publish" runs with write permissions.
#
# Usage (settings in the environment; see release.yml):
#   release.sh meta            resolve and validate the tag, commit and line
#   release.sh check-ref       in the source: the tag names the commit, on release/X.Y,
#                              and an automatic release is a Go patch of the previous tag
#   release.sh labels          the OCI archive has both platforms and this release's labels
#   release.sh scan            govulncheck -mode=binary on both binaries in the archive
#   release.sh record-archive  output the checked archive's SHA-256 and index digest
#   release.sh check-archive   the downloaded archive is the one build recorded
#   release.sh notes <file>    write the release notes, generated for automatic releases,
#                              and output their SHA-256
#   release.sh check-notes     the downloaded notes are the ones the notes job wrote
#   release.sh publish         push, sign, verify, tag and create the GitHub release
set -euo pipefail
here=$(dirname "${BASH_SOURCE[0]}")
# shellcheck source=.github/scripts/lib.sh
source "$here/lib.sh"

readonly arches=(amd64 arm64)

meta() {
	local tag commit auto
	if [[ -n ${INPUT_COMMIT:-} ]]; then
		tag=${INPUT_TAG:-} commit=$INPUT_COMMIT auto=${INPUT_AUTO:-false}
		# The signing identity names the ref the run started from (lib.sh,
		# identity_regexp); calls come only from go-patch.yml on main.
		[[ $GITHUB_REF == refs/heads/main ]] || die "release.yml may be called only from main, not $GITHUB_REF"
	else
		[[ $GITHUB_REF_TYPE == tag && $GITHUB_REF == "refs/tags/$GITHUB_REF_NAME" ]] || die "release.yml starts from a tag push or a call"
		tag=$GITHUB_REF_NAME commit=$GITHUB_SHA auto=false
	fi
	[[ $tag =~ ^v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*))\.(0|[1-9][0-9]*)$ ]] || die "the tag must be vX.Y.Z"
	output line "${BASH_REMATCH[1]}"
	[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "the commit must be a full commit ID"
	[[ $auto == true || $auto == false ]] || die "auto must be true or false"
	output tag "$tag"
	output version "${tag#v}"
	output commit "$commit"
	output auto "$auto"
}

check_ref() {
	local tagged patch prev base branch="refs/remotes/origin/release/$LINE"
	[[ $(git rev-parse HEAD) == "$COMMIT" ]] || die "the checkout is not $COMMIT"
	tagged=$(git rev-parse --verify "refs/tags/$TAG^{commit}")
	[[ $tagged == "$COMMIT" ]] || die "$TAG points to $tagged, not $COMMIT"
	if [[ $AUTO == true ]]; then
		# A compromised tool in a go-patch.yml job can forge the hand-off
		# record (PLAN.md §12, known residual risk), so an automatic release,
		# with its generated notes, is only what go-patch.sh pushes: a Go
		# patch update whose only parent is the previous patch tag. Any other
		# tag keeps the notes a person writes (V-6).
		patch=${TAG##*.}
		((patch > 0)) || die "$TAG cannot be an automatic release: it has no previous patch tag"
		prev=v$LINE.$((patch - 1))
		base=$(git rev-parse --quiet --verify "refs/tags/$prev^{commit}") || die "$TAG cannot be an automatic release: $prev does not exist"
		check_go_patch . "$base" "$COMMIT"
	fi
	if git rev-parse --verify --quiet "$branch" >/dev/null && git merge-base --is-ancestor "$COMMIT" "$branch"; then
		return
	fi
	[[ $AUTO != true ]] || die "$COMMIT is not on release/$LINE; automatic releases come only from a release line"
	echo "::warning::$TAG is not on release/$LINE. Releases normally come from their release line (PLAN.md §12)."
}

# check_labels checks that skopeo reference $1 is an index with one image per
# architecture, each labelled with this release's version and commit.
check_labels() {
	local arch value
	for arch in "${arches[@]}"; do
		platform_digest "$1" "$arch" >/dev/null
		value=$(image_label "$1" "$arch" "$LABEL_REVISION")
		[[ $value == "$COMMIT" ]] || die "$1: linux/$arch has revision label '$value', want $COMMIT"
		value=$(image_label "$1" "$arch" "$LABEL_VERSION")
		[[ $value == "$VERSION" ]] || die "$1: linux/$arch has version label '$value', want $VERSION"
	done
}

labels() {
	check_labels "oci-archive:${ARCHIVE:?}"
}

scan() {
	local arch dir
	dir=$(mktemp -d)
	for arch in "${arches[@]}"; do
		"$here/extract-binary.sh" "oci-archive:${ARCHIVE:?}" "$arch" "$dir/relay-$arch"
		echo "::group::govulncheck linux/$arch"
		go run "$GOVULNCHECK" -mode=binary "$dir/relay-$arch"
		echo "::endgroup::"
	done
}

# file_sha256 prints the SHA-256 of file $1.
file_sha256() {
	local sum
	[[ -f $1 ]] || die "$1 is missing"
	sum=$(sha256sum <"$1")
	printf '%s\n' "${sum%% *}"
}

# check_file stops unless file $1 has SHA-256 $2, the output of the job that
# produced it.
check_file() {
	local sum
	[[ $2 =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 was recorded for $1"
	sum=$(file_sha256 "$1")
	[[ $sum == "$2" ]] || die "$1 is not the file its producing job recorded"
}

# Any job of the run can replace an artifact, including the jobs that run
# third-party tools, but only the producing job can write its own outputs.
# So each artifact a later job uses is tied to its producer's outputs and
# checked right after the download (PLAN.md §12, artifact hand-offs).
#
# record_archive outputs the SHA-256 and index digest of the archive that
# labels and scan checked; publish signs only that digest.
record_archive() {
	local sum digest
	sum=$(file_sha256 "${ARCHIVE:?}")
	digest=$(manifest_digest "oci-archive:$ARCHIVE")
	output archive_sha256 "$sum"
	output archive_digest "$digest"
}

check_archive() {
	local digest
	check_file "${ARCHIVE:?}" "${ARCHIVE_SHA256:-}"
	[[ ${ARCHIVE_DIGEST:-} =~ ^sha256:[0-9a-f]{64}$ ]] || die "no index digest was recorded for $ARCHIVE"
	digest=$(manifest_digest "oci-archive:$ARCHIVE")
	[[ $digest == "$ARCHIVE_DIGEST" ]] || die "$ARCHIVE has index digest $digest, not the recorded $ARCHIVE_DIGEST"
}

record_notes() {
	local sum
	sum=$(file_sha256 "$1")
	output notes_sha256 "$sum"
}

check_notes() {
	check_file "${NOTES:?}" "${NOTES_SHA256:-}"
}

# vulns prints the IDs of vulnerabilities whose code govulncheck finds in
# binary $1 (findings with a function, the binary-mode notion of reachable).
vulns() {
	local json
	json=$(go run "$GOVULNCHECK" -mode=binary -format json "$1")
	jq -r 'select(.finding != null and (((.finding.trace // [])[0].function // "") != "")) | .finding.osv' <<<"$json" | sort -u
}

notes() {
	local out=$1 image tags prev t go builder dir arch fixed upgrade why
	if [[ ${AUTO:?} != true ]]; then
		cat >"$out" <<'EOF'
## Upgrade: required | recommended | optional

Why: <replace with the reason. Only the owner marks a release required (PLAN.md §12).>

## Changes

- <one line per change customers notice>
EOF
		return
	fi

	image=$(image_name)
	tags=$(image_tags "$image")
	prev=
	while IFS= read -r t; do
		if [[ $t =~ ^${LINE//./\\.}\.(0|[1-9][0-9]*)$ ]] && version_gt "$VERSION" "$t"; then
			prev=$t
		fi
	done < <(sort -V <<<"$tags")
	go=$(toolchain_version go.mod)
	builder=$(builder_ref Dockerfile)

	# "recommended" when the previous release's binaries contain vulnerable
	# code that this release's binaries do not (PLAN.md §12).
	fixed=
	if [[ -n $prev ]]; then
		dir=$(mktemp -d)
		for arch in "${arches[@]}"; do
			"$here/extract-binary.sh" "docker://$image:$prev" "$arch" "$dir/prev-$arch"
			"$here/extract-binary.sh" "oci-archive:${ARCHIVE:?}" "$arch" "$dir/new-$arch"
			vulns "$dir/prev-$arch" >>"$dir/prev"
			vulns "$dir/new-$arch" >>"$dir/new"
		done
		fixed=$(comm -23 <(sort -u "$dir/prev") <(sort -u "$dir/new"))
	fi
	if [[ -n $fixed ]]; then
		upgrade=recommended
		why="govulncheck -mode=binary finds these vulnerabilities in $prev and not in this release:"
		why+=$'\n\n'"$(sed -E 's|^(.*)$|- [\1](https://pkg.go.dev/vuln/\1)|' <<<"$fixed")"
	else
		upgrade=optional
		why="govulncheck -mode=binary finds no vulnerability ${prev:+in $prev }that this release fixes."
	fi

	cat >"$out" <<EOF
## Upgrade: $upgrade

$why

This automatic release rebuilds ${prev:-the previous release} with Go $go and the
builder golang:$go-trixie@${builder#* }. Only the toolchain line in go.mod and the
builder line in the Dockerfile change, so no endpoint, response code, header or
setting changes.

Go release notes: https://go.dev/doc/devel/release#go$go
EOF
}

# verify_image checks index $2 of image $1 before anything points to it:
# both platforms carry this release's labels, and the index and each platform
# image have a keyless signature from release.yml (PLAN.md §12, S-5).
verify_image() {
	local regexp ref arch pd refs=("$1@$2")
	regexp=$(identity_regexp)
	check_labels "docker://$1@$2"
	for arch in "${arches[@]}"; do
		pd=$(platform_digest "docker://$1@$2" "$arch")
		refs+=("$1@$pd")
	done
	for ref in "${refs[@]}"; do
		cosign verify --certificate-identity-regexp "$regexp" --certificate-oidc-issuer "$OIDC_ISSUER" "$ref" >/dev/null
	done
}

# copy_tag points tag $3 of image $1 at digest $2, preserving the digest.
copy_tag() {
	skopeo copy --all --preserve-digests "docker://$1@$2" "docker://$1:$3"
	[[ $(manifest_digest "docker://$1:$3") == "$2" ]] || die "$1:$3 does not have digest $2 after the copy"
}

publish() {
	local image tags digest staging current current_digest releases latest final t
	: "${VERSION:?}" "${LINE:?}" "${TAG:?}" "${COMMIT:?}" "${AUTO:?}" "${ARCHIVE:?}" "${ARCHIVE_DIGEST:?}" "${NOTES:?}"
	image=$(image_name)

	# A published version is never rebuilt or overwritten. A rerun verifies
	# it and resumes with the steps after it (PLAN.md §12).
	tags=$(image_tags "$image")
	if tag_in "$tags" "$VERSION"; then
		digest=$(manifest_digest "docker://$image:$VERSION")
		verify_image "$image" "$digest"
		notice "$image:$VERSION already exists at $digest and verifies; resuming"
	else
		# build's output, not the digest read from the downloaded archive,
		# names what is signed (record_archive).
		digest=$ARCHIVE_DIGEST
		staging=candidate-$COMMIT
		skopeo copy --all --preserve-digests "oci-archive:$ARCHIVE" "docker://$image:$staging"
		[[ $(manifest_digest "docker://$image:$staging") == "$digest" ]] || die "the staged candidate does not have digest $digest"
		cosign sign --yes --recursive "$image@$digest"
		verify_image "$image" "$digest"
		tags=$(image_tags "$image")
		if tag_in "$tags" "$VERSION"; then
			die "$image:$VERSION appeared during this run"
		fi
		copy_tag "$image" "$digest" "$VERSION"
	fi

	# The floating tag only moves forward, and only to a verified digest.
	tags=$(image_tags "$image")
	if tag_in "$tags" "$LINE"; then
		current_digest=$(manifest_digest "docker://$image:$LINE")
		current=$(image_label "docker://$image:$LINE" amd64 "$LABEL_VERSION")
		[[ $current =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$image:$LINE has no readable version label"
		if [[ $current == "$VERSION" ]]; then
			[[ $current_digest == "$digest" ]] || die "$image:$LINE claims $VERSION with a different digest"
			notice "$image:$LINE already points to $VERSION"
		elif version_gt "$VERSION" "$current"; then
			copy_tag "$image" "$digest" "$LINE"
		else
			notice "$image:$LINE stays at the newer $current"
		fi
	else
		copy_tag "$image" "$digest" "$LINE"
	fi

	releases=$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" --jq '.[].tag_name')
	if tag_in "$releases" "$TAG"; then
		notice "the GitHub release $TAG exists"
		return
	fi
	final=$(mktemp)
	{
		cat "$NOTES"
		printf '\n## Image\n\n`%s:%s`, index digest `%s` (linux/amd64, linux/arm64).\n\n' "$image" "$VERSION" "$digest"
		printf 'Verify the signature:\n\n```sh\ncosign verify \\\n  --certificate-identity-regexp '\''%s'\'' \\\n  --certificate-oidc-issuer %s \\\n  %s@%s\n```\n' \
			"$(identity_regexp)" "$OIDC_ISSUER" "$image" "$digest"
	} >"$final"
	if [[ $AUTO != true ]]; then
		# A person writes the notes of a tagged release (PLAN.md §12, V-6).
		gh release create "$TAG" --verify-tag --draft --title "$TAG" --notes-file "$final"
		return
	fi
	latest=true
	while IFS= read -r t; do
		if [[ $t =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && version_gt "$t" "$VERSION"; then
			latest=false
		fi
	done <<<"$tags"
	gh release create "$TAG" --verify-tag --title "$TAG" --latest="$latest" --notes-file "$final"
}

case ${1:-} in
meta) meta ;;
check-ref) check_ref ;;
labels) labels ;;
scan) scan ;;
record-archive) record_archive ;;
check-archive) check_archive ;;
check-notes) check_notes ;;
publish) publish ;;
notes)
	[[ $# == 2 ]] || die "usage: release.sh notes <file>"
	notes "$2"
	record_notes "$2"
	;;
*)
	die "usage: release.sh meta|check-ref|labels|scan|record-archive|check-archive|notes <file>|check-notes|publish"
	;;
esac
