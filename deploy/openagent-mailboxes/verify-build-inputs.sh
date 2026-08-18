#!/usr/bin/env bash
set -euo pipefail

dockerfiles=(openagent/Dockerfile.stalwart openagent/gateway/Dockerfile)
for dockerfile in "${dockerfiles[@]}"; do
  while IFS= read -r image; do
    if [[ ! "$image" =~ @sha256:[a-f0-9]{64}$ ]]; then
      echo "$dockerfile has an unpinned external base image: $image" >&2
      exit 1
    fi
  done < <(awk '$1 == "FROM" { for (i = 2; i <= NF; i++) if ($i !~ /^--/ && $i != "AS") { print $i; break } }' "$dockerfile" | grep -E '[/]|^node:' || true)
done

grep -Eq '^[[:space:]]*apt-get upgrade -yq' openagent/Dockerfile.stalwart || {
  echo "OpenAgent Stalwart runtime must upgrade fixed base packages before release scanning" >&2
  exit 1
}

echo "OpenAgent mailbox build inputs are digest-pinned"
