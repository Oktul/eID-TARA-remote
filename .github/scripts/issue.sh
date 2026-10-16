#!/usr/bin/env bash
# Opens an issue, or comments on the open issue with the same title, so the
# owner sees every automation failure (PLAN.md §12). A comment identical to
# the latest one is skipped, so a state that persists for days (such as a
# line waiting for a human release) does not repeat itself.
# Needs GH_TOKEN and GH_REPO. Usage: issue.sh <title> <body>
set -euo pipefail
# shellcheck source=.github/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# == 2 && -n $1 && -n $2 ]] || die "usage: issue.sh <title> <body>"
title=$1
body=$2

# The issue list, unlike the search API, includes issues created moments ago.
issues=$(gh issue list --state open --limit 200 --json number,title)
number=$(jq -r --arg t "$title" '[.[] | select(.title == $t)][0].number // empty' <<<"$issues")

if [[ -z $number ]]; then
	gh issue create --title "$title" --body "$body"
	exit 0
fi

latest=$(gh issue view "$number" --json body,comments | jq -r '(.comments | last | .body) // .body')
if [[ $latest == "$body" ]]; then
	echo "issue #$number already says this"
	exit 0
fi
gh issue comment "$number" --body "$body"
