#!/usr/bin/env bash
set -euo pipefail

source_manifest="${1:-}"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
if [[ -n "$source_manifest" ]]; then
  cp "$source_manifest" "$rendered"
else
  kubectl kustomize deploy/openagent-mailboxes/base >"$rendered"
fi

if grep -Eiq 'SET_BY_RELEASE_PIPELINE|REPLACE_WITH' "$rendered"; then
  echo "Mailbox manifests still contain release placeholders" >&2
  exit 1
fi
for image in mailboxes-stalwart openagent-mailbox-gateway; do
  if ! grep -Eq "image: ghcr\\.io/autonomy-cloud/${image}@sha256:[a-f0-9]{64}$" "$rendered"; then
    echo "$image is not pinned to an immutable digest" >&2
    exit 1
  fi
done
for kind in StatefulSet Deployment Job Ingress NetworkPolicy Service; do
  if ! grep -Eq "^kind: ${kind}$" "$rendered"; then
    echo "Mailbox release is missing ${kind}" >&2
    exit 1
  fi
done
if ! grep -Fq 'OPENAGENT_BOOTSTRAP_ONLY' "$rendered" || ! grep -Fq 'value: "true"' "$rendered"; then
  echo "Mailbox release is missing the one-shot bootstrap contract" >&2
  exit 1
fi
if ! grep -Fq 'port: 443' "$rendered" || ! grep -Fq 'port: 25' "$rendered" || ! grep -Fq 'port: 465' "$rendered" || ! grep -Fq 'port: 993' "$rendered"; then
  echo "Mailbox release is missing required ACME or public mail ports" >&2
  exit 1
fi

kubectl create --dry-run=client --validate=false -f "$rendered" >/dev/null
echo "OpenAgent mailbox deployment manifests are release-ready"
