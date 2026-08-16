#!/usr/bin/env bash
set -euo pipefail

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree must be clean before syncing upstream." >&2
  exit 1
fi

git fetch upstream
git switch main
git merge --ff-only upstream/main
git push origin main
git switch openagent

echo "Upstream main is synchronized. Rebase openagent with: git rebase main"
