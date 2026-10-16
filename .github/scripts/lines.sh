#!/usr/bin/env bash
# Prints the supported release lines as a compact JSON array, such as
# ["2.1","1.4"] (PLAN.md §12 Release lines): the newest released minor of the
# newest major, plus the previous major's newest released minor until 12
# months after the newest major's vN.0.0 tag. Unreleased branches do not
# displace a supported line. Run in a clone with every branch and tag fetched.
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

# A branch can be prepared before its major or minor is released. Only
# tagged lines participate in support selection, or an unreleased future
# major could displace a previous major still in its support window (§12).
released=()
for line in "${branches[@]}"; do
	if grep -qE "^v${line//./\\.}\.(0|[1-9][0-9]*)$" <<<"$tags"; then
		released+=("$line")
	fi
done
if ((${#released[@]} == 0)); then
	echo '[]'
	exit 0
fi
branches=("${released[@]}")

majors=$(printf '%s\n' "${branches[@]}" | cut -d . -f 1 | sort -un)
newest_minor() {
	printf '%s\n' "${branches[@]}" | grep -E "^$1\." | sort -V | tail -n 1
}

major=$(tail -n 1 <<<"$majors")
lines=("$(newest_minor "$major")")

previous=$(awk -v m="$major" '$1 < m' <<<"$majors" | tail -n 1)
if [[ -n $previous ]]; then
	# Without the initial-major tag there is no recorded start for the
	# previous major's window, so keep it rather than end support early.
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
