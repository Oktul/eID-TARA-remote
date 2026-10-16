#!/usr/bin/env bash
# Prints the supported release lines as a compact JSON array, such as
# ["2.1","1.4"] (PLAN.md §12 Release lines): the newest released minor of the
# newest major, plus the previous major's newest released minor until 12
# months after the newest major's vN.0.0 tag. Run in a clone with every
# branch and tag fetched.
set -euo pipefail
# shellcheck source=.github/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

all=$(git for-each-ref --format='%(refname:lstrip=4)' refs/remotes/origin/release/)
mapfile -t branches < <(grep -E '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' <<<"$all" || true)
if ((${#branches[@]} == 0)); then
	echo '[]'
	exit 0
fi
tags=$(git tag --list 'v*')

majors=$(printf '%s\n' "${branches[@]}" | cut -d . -f 1 | sort -un)
# newest_minor prints the newest release/X.Y line of major $1 that has a
# vX.Y.Z tag. A new release/X.Y branch is made before its first release, and
# until then the previous minor is still the one customers run. Without any
# tag (a major not released yet) it prints the newest line.
newest_minor() {
	local minors minor released=
	minors=$(printf '%s\n' "${branches[@]}" | grep -E "^$1\." | sort -V)
	while IFS= read -r minor; do
		if grep -qE "^v${minor//./\\.}\.(0|[1-9][0-9]*)$" <<<"$tags"; then
			released=$minor
		fi
	done <<<"$minors"
	printf '%s\n' "${released:-$(tail -n 1 <<<"$minors")}"
}

major=$(tail -n 1 <<<"$majors")
lines=("$(newest_minor "$major")")

previous=$(awk -v m="$major" '$1 < m' <<<"$majors" | tail -n 1)
if [[ -n $previous ]]; then
	# A missing vN.0.0 tag means the new major is not released yet, so the
	# previous major's window has not started.
	created=$(git for-each-ref --format='%(creatordate:unix)' "refs/tags/v$major.0.0")
	keep=true
	if [[ -n $created ]]; then
		start=$(date -u -d "@$created" '+%Y-%m-%d %H:%M:%S')
		end=$(date -u -d "$start UTC next year" '+%s')
		(($(date -u '+%s') < end)) || keep=false
	fi
	if [[ $keep == true ]]; then
		lines+=("$(newest_minor "$previous")")
	fi
fi

jq -cn '$ARGS.positional' --args "${lines[@]}"
