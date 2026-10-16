#!/usr/bin/env bash
# Exercises release.sh check-ref with real Git refs (PLAN.md §12): a release
# tag must be annotated, so lines.sh can date it. All refs stay in a
# temporary repository, never the caller's clone.
set -euo pipefail

script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release.sh
fixture=$(mktemp -d)
# check-ref's stderr, where die writes the error, is kept here so an
# expected ::error:: does not become an annotation of every CI run.
errors=$(mktemp)
trap 'rm -rf "$fixture" "$errors"' EXIT
git init --quiet "$fixture"
git -C "$fixture" config user.name review
git -C "$fixture" config user.email review@example.invalid
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config tag.gpgsign false
git -C "$fixture" commit --quiet --allow-empty --message fixture
commit=$(git -C "$fixture" rev-parse HEAD)
git -C "$fixture" update-ref refs/remotes/origin/release/1.0 HEAD

# run_check_ref runs check-ref for tag $1 on this commit.
run_check_ref() {
	(cd "$fixture" && TAG=$1 LINE=1.0 COMMIT=$commit AUTO=false bash "$script" check-ref >/dev/null 2>"$errors")
}

git -C "$fixture" tag --annotate --message v1.0.0 v1.0.0
if ! run_check_ref v1.0.0; then
	printf 'annotated tag: want success, got %s\n' "$(<"$errors")" >&2
	exit 1
fi
echo 'annotated tag: accepted'

git -C "$fixture" tag v1.0.1
if run_check_ref v1.0.1; then
	echo 'lightweight tag: want a refusal, got success' >&2
	exit 1
fi
if [[ $(<"$errors") != '::error::v1.0.1 is a lightweight tag'* ]]; then
	printf 'lightweight tag: want the lightweight-tag error, got %s\n' "$(<"$errors")" >&2
	exit 1
fi
echo 'lightweight tag: refused'
