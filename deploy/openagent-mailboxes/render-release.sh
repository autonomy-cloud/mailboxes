#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "Usage: STALWART_IMAGE_DIGEST=... GATEWAY_IMAGE_DIGEST=... $0 OUTPUT_FILE" >&2
  exit 1
fi

output_file="$1"
stalwart_digest="${STALWART_IMAGE_DIGEST#sha256:}"
gateway_digest="${GATEWAY_IMAGE_DIGEST#sha256:}"
for digest in "$stalwart_digest" "$gateway_digest"; do
  if [[ ! "$digest" =~ ^[a-f0-9]{64}$ ]]; then
    echo "Both image digests must be lowercase sha256 digests" >&2
    exit 1
  fi
done
if [[ -e "$output_file" ]]; then
  echo "Output file already exists: $output_file" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'find "$work_dir" -depth -delete' EXIT
cp -R deploy/openagent-mailboxes/base "$work_dir/base"
sed -i.bak "/name: openagent-stalwart/,/newTag:/ s/newTag: SET_BY_RELEASE_PIPELINE/digest: sha256:${stalwart_digest}/" \
  "$work_dir/base/kustomization.yaml"
sed -i.bak "/name: openagent-mailbox-gateway/,/newTag:/ s/newTag: SET_BY_RELEASE_PIPELINE/digest: sha256:${gateway_digest}/" \
  "$work_dir/base/kustomization.yaml"
kubectl kustomize "$work_dir/base" >"$output_file"
bash deploy/openagent-mailboxes/verify-manifests.sh "$output_file"
printf 'Rendered OpenAgent mailbox release manifest to %s\n' "$output_file"
