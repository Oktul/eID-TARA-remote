#!/usr/bin/env bash
# Exercises support selection with real Git refs and tag dates (PLAN.md §12).
# All fixture tags stay in a temporary repository, never the caller's clone.
set -euo pipefail

command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }
script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lines.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
git init --quiet "$fixture"
git -C "$fixture" config user.name review
git -C "$fixture" config user.email review@example.invalid
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config tag.gpgsign false
git -C "$fixture" commit --quiet --allow-empty --message fixture

assert_lines() {
	local name=$1 expected=$2 actual
	actual=$(cd "$fixture" && bash "$script")
	if [[ $actual != "$expected" ]]; then
		printf '%s: want %s, got %s\n' "$name" "$expected" "$actual" >&2
		exit 1
	fi
	printf '%s: %s\n' "$name" "$actual"
}

branch() {
	git -C "$fixture" update-ref "refs/remotes/origin/release/$1" HEAD
}

tag_at() {
	GIT_COMMITTER_DATE=$2 git -C "$fixture" tag --annotate --message "$1" "$1"
}

recent=$(date -u -d yesterday '+%Y-%m-%dT%H:%M:%SZ')
expired=$(date -u -d '2 years ago' '+%Y-%m-%dT%H:%M:%SZ')
assert_lines 'no branches' '[]'
branch 1.0
assert_lines 'no released lines' '[]'
tag_at v1.0.0 "$expired"
assert_lines 'one released major' '["1.0"]'
branch 1.1
assert_lines 'unreleased newest minor' '["1.0"]'
branch 2.0
assert_lines 'unreleased second major' '["1.0"]'
tag_at v2.0.0 "$recent"
assert_lines 'two majors in support' '["2.0","1.0"]'
branch 2.1
assert_lines 'unreleased minor preserves both majors' '["2.0","1.0"]'
branch 3.0
assert_lines 'unreleased major preserves both majors' '["2.0","1.0"]'
tag_at v3.0.0 "$recent"
assert_lines 'released major replaces oldest major' '["3.0","2.0"]'
git -C "$fixture" tag --delete v3.0.0 v2.0.0 >/dev/null
tag_at v2.0.0 "$expired"
assert_lines 'previous major support expires' '["2.0"]'
