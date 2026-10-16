#!/usr/bin/env bash
# The per-line steps of go-patch-line.yml (PLAN.md §12). A Go patch, or a new
# digest of the same golang builder, ships automatically; a newer Go minor
# becomes a pull request. Automation starts only from a line's latest
# published release and never from main.
#
# Usage, in a clone of main (prepare, push and minor need GH_TOKEN and
# GH_REPO, and keep the token to themselves; see github_auth in lib.sh):
#   go-patch.sh prepare <X.Y> <worktree> <bundle>  commit an update in a new worktree and bundle it
#   go-patch.sh unbundle <bundle> <dir>            check out the bundled COMMIT in a new repository
#   go-patch.sh push <X.Y> <bundle>                verify and publish the tested commit (BASE, COMMIT, TAG)
#   go-patch.sh collect <dir>                      print the pushed releases as a JSON matrix
#   go-patch.sh minor <X.Y> <worktree>             open a pull request for a newer Go minor
set -euo pipefail
here=$(dirname "${BASH_SOURCE[0]}")
# shellcheck source=.github/scripts/lib.sh
source "$here/lib.sh"

# fetch_line refreshes the line's branch and every tag. A tag that moved on
# the remote makes the fetch fail instead of being followed.
fetch_line() {
	git fetch --quiet origin "+refs/heads/release/$1:refs/remotes/origin/release/$1"
	git fetch --quiet --tags origin
}

# patch_tags prints the vX.Y.Z tags of line $1 among the tags in $2.
patch_tags() {
	grep -E "^v${1//./\\.}\.(0|[1-9][0-9]*)$" <<<"$2" | sort -V || true
}

# golang_published reports whether golang:<version>-trixie is on Docker Hub
# yet; it can appear hours after go.dev lists the release.
golang_published() {
	local err
	err=$(mktemp)
	if skopeo inspect --raw "docker://docker.io/library/golang:$1-trixie" >/dev/null 2>"$err"; then
		return 0
	fi
	if grep -qi 'manifest unknown' "$err"; then
		return 1
	fi
	cat "$err" >&2
	die "cannot read golang:$1-trixie"
}

# update edits worktree $1 from Go $2 and builder digest $3 to Go $4 and
# digest $5, commits with message $6, and proves the commit is exactly that
# update (check_update).
update() {
	local wt=$1 old=$2 old_digest=$3 new=$4 digest=$5 message=$6 base builders
	base=$(git -C "$wt" rev-parse HEAD)
	if [[ $new != "$old" ]]; then
		replace_once "$wt/go.mod" "toolchain go$old" "toolchain go$new"
	fi
	replace_once "$wt/Dockerfile" "golang:$old-trixie@$old_digest" "golang:$new-trixie@$digest"
	git -C "$wt" -c user.name="$BOT_NAME" -c user.email="$BOT_EMAIL" commit --quiet --all --message "$message"
	[[ -z $(git -C "$wt" status --porcelain) ]] || die "the worktree has changes outside the commit"
	builders=$(check_update "$wt" "$base" HEAD)
	[[ $builders == "$old $old_digest"$'\n'"$new $digest" ]] || die "the commit is not the update to Go $new and $digest"
}

prepare() {
	local line=$1 wt=$2 bundle=$3 branch tip all latest last tag_commit image tags arch revision
	local go builder digest_old go_minor releases newest new digest message commit
	valid_line "$line" || die "bad release line"
	github_auth
	branch="release/$line"
	fetch_line "$line"
	tip=$(git rev-parse --verify "refs/remotes/origin/$branch^{commit}")
	all=$(git tag --list "v$line.*" --merged "refs/remotes/origin/$branch")
	latest=$(patch_tags "$line" "$all" | tail -n 1)
	# The base must be the line's latest published release (PLAN.md §12). A
	# newer tag off the branch, such as a hotfix, would otherwise be left out,
	# and the floating tag would move past it to a build without its changes.
	# lines.sh counts a tag on any ref, so a line whose releases are all off
	# the branch is supported too and gets the same issue.
	all=$(git tag --list "v$line.*")
	last=$(patch_tags "$line" "$all" | tail -n 1)
	if [[ -z $last ]]; then
		notice "$branch has no release yet, so there is nothing to patch"
		return
	fi
	if [[ $last != "$latest" ]]; then
		"$here/issue.sh" "go-patch: $branch: $last is not on the branch" \
			"$last is the newest v$line release, but $branch contains ${latest:-no v$line release}, so go-patch.yml leaves this line alone (PLAN.md §12). Move $branch to $last if it descends from the branch, or release the line by hand with a newer tag on $branch; automatic Go patches resume from that release."
		return
	fi
	tag_commit=$(git rev-parse --verify "refs/tags/$latest^{commit}")
	image=$(image_name)
	tags=$(image_tags "$image")
	if ! tag_in "$tags" "${latest#v}"; then
		"$here/issue.sh" "go-patch: $branch: $latest is not published" \
			"$latest is tagged on $branch, but $image:${latest#v} does not exist, so go-patch.yml leaves this line alone (PLAN.md §12). Rerun the failed jobs of the go-patch.yml or release.yml run that should have published it, within 30 days of that run, while GitHub allows a rerun and keeps its artifacts; the next run then continues. Later, release the line by hand with a new tag on $branch."
		return
	fi
	# The image records the commit it was built from. A tag that moved after
	# its release must not let the commit it now names ship unreviewed.
	for arch in amd64 arm64; do
		revision=$(image_label "docker://$image:${latest#v}" "$arch" "$LABEL_REVISION")
		if [[ $revision != "$tag_commit" ]]; then
			"$here/issue.sh" "go-patch: $branch: $latest differs from its image" \
				"$latest points to $tag_commit, but linux/$arch of $image:${latest#v} was built from '$revision', so go-patch.yml leaves this line alone (PLAN.md §12). Find out why the tag moved, and release the line by hand with a new tag."
			return
		fi
	done
	if [[ $tip != "$tag_commit" ]]; then
		"$here/issue.sh" "go-patch: $branch has unreleased commits" \
			"$branch is at $tip, ahead of its latest release $latest ($tag_commit). go-patch.yml never releases such commits automatically (PLAN.md §12): release them with a new tag by hand, and automatic Go patches resume from that release."
		return
	fi

	git worktree add --quiet --detach "$wt" "$tip"
	go=$(toolchain_version "$wt/go.mod")
	builder=$(builder_ref "$wt/Dockerfile")
	digest_old=${builder#* }
	[[ ${builder%% *} == "$go" ]] || die "$branch: go.mod and the Dockerfile pin different Go versions"

	go_minor=${go%.*}
	releases=$(go_releases)
	newest=$(grep -E "^${go_minor//./\\.}\.[0-9]+$" <<<"$releases" | head -n 1 || true)
	new=$go
	if [[ -z $newest ]]; then
		notice "go.dev no longer supports Go $go_minor; checking only the builder digest"
	elif version_gt "$newest" "$go"; then
		new=$newest
	elif version_gt "$go" "$newest"; then
		die "$branch pins Go $go, newer than go.dev's newest $go_minor release $newest"
	fi
	if ! golang_published "$new"; then
		notice "golang:$new-trixie is not on Docker Hub yet; the next run tries again"
		return
	fi
	digest=$(golang_digest "$new")
	if [[ $new == "$go" && $digest == "$digest_old" ]]; then
		notice "$branch is up to date: Go $go, builder $digest"
		return
	fi

	if [[ $new != "$go" ]]; then
		message="Update Go to $new on $branch"
	else
		message="Update the golang:$go-trixie builder digest on $branch"
	fi
	message+=$'\n\n'"Automatic Go patch update (PLAN.md §12). It changes only the toolchain"
	message+=$'\n'"line in go.mod and the builder line in the Dockerfile."
	message+=$'\n\n'"Builder: golang:$new-trixie@$digest"
	update "$wt" "$go" "$digest_old" "$new" "$digest" "$message"
	# The check and push jobs receive the commit in a bundle, and test and
	# publish it by the ID output here (go-patch-line.yml).
	commit=$(git -C "$wt" rev-parse HEAD)
	git -C "$wt" bundle create --quiet "$bundle" HEAD

	output candidate true
	output base "$tip"
	output commit "$commit"
	# $latest is the newest tag of the line on any ref (checked above), so
	# versions only grow and the floating tag can follow them.
	output tag "v$line.$((${latest##*.} + 1))"
}

# unbundle checks out COMMIT from bundle $1 in the new repository $2, so the
# read-only check jobs test exactly the commit that push publishes.
unbundle() {
	[[ ${COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || die "COMMIT must be a commit ID"
	git init --quiet "$2"
	git -C "$2" fetch --quiet --no-tags "$1" HEAD
	git -C "$2" -c advice.detachedHead=false checkout --quiet --detach "$COMMIT"
}

push() {
	local line=$1 bundle=$2 branch remote tagged all last rc
	valid_line "$line" || die "bad release line"
	[[ ${BASE:-} =~ ^[0-9a-f]{40}$ && ${COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || die "BASE and COMMIT must be commit IDs"
	[[ ${TAG:-} =~ ^v${line//./\\.}\.(0|[1-9][0-9]*)$ ]] || die "TAG must be a v$line.Z tag"
	github_auth
	branch="release/$line"
	fetch_line "$line"

	# The bundle passed through the check jobs, which run third-party tools,
	# so only COMMIT, the ID from the prepare job, is trusted. The ID fixes
	# the content; verify it again as the only update PLAN.md §12 ships
	# unreviewed. A rerun after the push finds COMMIT on the branch, also
	# when a person has pushed on top of it since, and needs no bundle, so
	# it does not depend on the candidate artifact.
	if ! git merge-base --is-ancestor "$COMMIT" "refs/remotes/origin/$branch" 2>/dev/null; then
		[[ -f $bundle ]] || die "the candidate bundle is missing"
		git fetch --quiet --no-tags "$bundle" HEAD
	fi
	git cat-file -e "$COMMIT^{commit}" || die "the bundle does not hold $COMMIT"
	check_go_patch . "$BASE" "$COMMIT"

	remote=$(git ls-remote --exit-code origin "refs/heads/$branch" | cut -f 1)
	tagged=$(git rev-parse --quiet --verify "refs/tags/$TAG^{commit}" || true)
	# A remote tip this clone has not fetched fails the ancestor test and
	# ends at the "moved" check below.
	if [[ $tagged == "$COMMIT" ]] && git merge-base --is-ancestor "$COMMIT" "$remote" 2>/dev/null; then
		# An earlier attempt of this job pushed both; a rerun only hands the
		# tag on to the release (go-patch-line.yml), whose check_ref accepts
		# a tag on the branch.
		notice "$TAG already points to $COMMIT, which is on $branch; handing the tag on"
		return
	fi
	# A person may have pushed since the checks ran. Stop rather than rebase
	# untested work; the next run re-evaluates (PLAN.md §12).
	[[ $remote == "$BASE" ]] || die "$branch moved from $BASE to $remote during the update"
	all=$(git tag --list "v$line.*")
	last=$(patch_tags "$line" "$all" | tail -n 1)
	[[ -n $last && $(git rev-parse --verify "refs/tags/$last^{commit}") == "$BASE" ]] ||
		die "BASE is not the commit of the newest v$line tag ${last:-(none)}"
	[[ $TAG == "v$line.$((${last##*.} + 1))" ]] || die "TAG must be the patch after $last"
	rc=0
	git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null || rc=$?
	case $rc in
	0) die "$TAG already exists" ;;
	2) ;;
	*) die "cannot list the remote tags" ;;
	esac

	git -c user.name="$BOT_NAME" -c user.email="$BOT_EMAIL" tag --annotate --message "$TAG" "$TAG" "$COMMIT"
	# A plain push is a fast-forward or nothing; --atomic moves the branch and
	# creates the tag together, so a tag never exists without its branch
	# update. github_auth has turned hooks off.
	git push --atomic origin "$COMMIT:refs/heads/$branch" "refs/tags/$TAG:refs/tags/$TAG"
}

collect() {
	local files
	shopt -s nullglob
	files=("$1"/release-*.json)
	if ((${#files[@]} == 0)); then
		echo '[]'
		return
	fi
	jq -cs 'map(select(.tag != null)) | sort_by(.line)' "${files[@]}"
}

minor() {
	local line=$1 wt=$2 branch tip go releases newest pr_branch prs rc commit parent builders digest builder message body
	valid_line "$line" || die "bad release line"
	github_auth
	branch="release/$line"
	fetch_line "$line"
	tip=$(git rev-parse --verify "refs/remotes/origin/$branch^{commit}")
	git worktree add --quiet --detach "$wt" "$tip"
	go=$(toolchain_version "$wt/go.mod")
	releases=$(go_releases)
	newest=$(head -n 1 <<<"$releases")
	if ! version_gt "${newest%.*}" "${go%.*}"; then
		notice "$branch already uses the newest Go minor, ${go%.*}"
		return
	fi

	pr_branch="go-patch/$line-go$newest"
	# A pull request, open or closed, is a person's to decide on.
	prs=$(gh pr list --head "$pr_branch" --state all --json number --jq length)
	if ((prs > 0)); then
		notice "$pr_branch has a pull request; it waits for a person"
		return
	fi
	rc=0
	git ls-remote --exit-code --heads origin "refs/heads/$pr_branch" >/dev/null || rc=$?
	case $rc in
	0)
		# An earlier run pushed the branch but could not open the pull
		# request. Open it now, for the update the branch really holds.
		git fetch --quiet --no-tags origin "refs/heads/$pr_branch"
		commit=$(git rev-parse --verify "FETCH_HEAD^{commit}")
		parent=$(git rev-parse --verify "$commit^1")
		builders=$(check_update . "$parent" "$commit")
		go=${builders%% *}
		builder=${builders#*$'\n'}
		[[ ${builder%% *} == "$newest" ]] || die "$pr_branch does not update Go to $newest; delete it, and the next run recreates it"
		digest=${builder#* }
		;;
	2)
		if ! golang_published "$newest"; then
			notice "golang:$newest-trixie is not on Docker Hub yet; the next run tries again"
			return
		fi
		digest=$(golang_digest "$newest")
		builder=$(builder_ref "$wt/Dockerfile")
		[[ ${builder%% *} == "$go" ]] || die "$branch: go.mod and the Dockerfile pin different Go versions"
		message="Update Go to $newest on $branch"$'\n\n'"Go $newest is a new minor release, so a person reviews this change"
		message+=$'\n'"(PLAN.md §12). Builder: golang:$newest-trixie@$digest"
		update "$wt" "$go" "${builder#* }" "$newest" "$digest" "$message"
		commit=$(git -C "$wt" rev-parse HEAD)
		git push origin "$commit:refs/heads/$pr_branch"
		;;
	*) die "cannot list the remote branches" ;;
	esac
	body=$(
		cat <<EOF
Go $newest is a new minor release, and $branch pins Go $go. This updates only
the toolchain line in go.mod and the Dockerfile builder to
golang:$newest-trixie@$digest.

A new Go minor can change behaviour, so it ships only after a person reviews
and merges it and tags the next release by hand (PLAN.md §12). Check whether
the go line in go.mod should move too, and follow PLAN.md §4.6 if anything
in the protocol would change.

Pull requests opened with the workflow token do not start ci.yml: close and
reopen this one to run the checks.

Go release notes: https://go.dev/doc/devel/release#go$newest
EOF
	)
	gh pr create --base "$branch" --head "$pr_branch" --title "Update Go to $newest on $branch" --body "$body"
}

case ${1:-} in
prepare)
	[[ $# == 4 ]] || die "usage: go-patch.sh prepare <X.Y> <worktree> <bundle>"
	prepare "$2" "$3" "$4"
	;;
unbundle)
	[[ $# == 3 ]] || die "usage: go-patch.sh unbundle <bundle> <dir>"
	unbundle "$2" "$3"
	;;
minor)
	[[ $# == 3 ]] || die "usage: go-patch.sh minor <X.Y> <worktree>"
	minor "$2" "$3"
	;;
push)
	[[ $# == 3 ]] || die "usage: go-patch.sh push <X.Y> <bundle>"
	push "$2" "$3"
	;;
collect)
	[[ $# == 2 ]] || die "usage: go-patch.sh collect <dir>"
	collect "$2"
	;;
*)
	die "usage: go-patch.sh prepare|unbundle|push|collect|minor ..."
	;;
esac
