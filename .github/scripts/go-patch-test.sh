#!/usr/bin/env bash
# Exercises the release-base check of go-patch.sh prepare (PLAN.md §12) with
# a local origin and a stub gh that records the issues opened. Every case
# stops before prepare's first network call, and nothing leaves the
# temporary directory.
set -euo pipefail

command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }
script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/go-patch.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
clone=$tmp/clone
git init --quiet --bare "$tmp/origin.git"
git init --quiet "$clone"
git -C "$clone" config user.name review
git -C "$clone" config user.email review@example.invalid
git -C "$clone" config commit.gpgsign false
git -C "$clone" config tag.gpgsign false
git -C "$clone" remote add origin "$tmp/origin.git"
git -C "$clone" commit --quiet --allow-empty --message release
released=$(git -C "$clone" rev-parse HEAD)
git -C "$clone" push --quiet origin HEAD:refs/heads/release/1.0
git -C "$clone" commit --quiet --allow-empty --message 'off the branch'

mkdir "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
# Stands in for gh: there are no open issues, and each new issue's title is
# recorded in $ISSUES.
case "$1 $2" in
'issue list') echo '[]' ;;
'issue create') printf '%s\n' "$4" >>"$ISSUES" ;;
*) echo "unexpected: gh $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$tmp/bin/gh"

# assert_issues runs prepare for line 1.0 and compares the titles of the
# issues it opened with $2.
assert_issues() {
	local name=$1 expected=$2 actual
	: >"$tmp/issues"
	(cd "$clone" && PATH="$tmp/bin:$PATH" ISSUES=$tmp/issues GH_TOKEN=fixture GH_REPO=fixture/fixture \
		GITHUB_ACTOR=fixture GITHUB_SERVER_URL=https://github.invalid \
		bash "$script" prepare 1.0 "$tmp/worktree" "$tmp/bundle" >/dev/null)
	actual=$(<"$tmp/issues")
	if [[ $actual != "$expected" ]]; then
		printf '%s: want issues [%s], got [%s]\n' "$name" "$expected" "$actual" >&2
		exit 1
	fi
	printf '%s: [%s]\n' "$name" "$actual"
}

tag() {
	git -C "$clone" tag --annotate --message "$1" "$1" "$2"
	git -C "$clone" push --quiet origin "refs/tags/$1"
}

assert_issues 'no release' ''
tag v1.0.1 HEAD
assert_issues 'only release off the branch' 'go-patch: release/1.0: v1.0.1 is not on the branch'
tag v1.0.0 "$released"
assert_issues 'newest release off the branch' 'go-patch: release/1.0: v1.0.1 is not on the branch'
