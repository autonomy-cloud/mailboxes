# OpenAgent mailbox production rollout

This runbook makes Stalwart the canonical receiver for `agents.openagent.md`. Cloudflare may remain
the authoritative DNS provider and proxy the HTTPS records, but Cloudflare Email Routing must not
own this subdomain's MX records: doing so would bypass the persistent agent inboxes.

## Release contract

- Identity issuer: `https://id.openagent.md/oidc`
- JMAP and provisioning origin: `https://inbox.openagent.md`
- SMTP receiver and submission host: `mail.openagent.md`
- Agent addresses: `<unique-local-part>@agents.openagent.md`
- Provisioning path: `POST https://inbox.openagent.md/v1/mailboxes/ensure`

The ingress sends `/v1/mailboxes/*` to the OpenAgent gateway and all other HTTPS paths to Stalwart.
The load balancer sends HTTPS 443 (for ACME TLS-ALPN), SMTP 25, submissions 465, and IMAPS 993
directly to Stalwart.

## Required platform inputs

1. A default StorageClass with encrypted, snapshot-capable `ReadWriteOnce` volumes, or an overlay
   that selects an equivalent class explicitly.
2. NGINX ingress, cert-manager with `letsencrypt-production`, and an external load balancer that
   preserves source addresses.
3. Secret-manager delivery of `openagent-mailboxes-secrets`. The recovery and permanent admin
   values must initially agree; remove the recovery value after confirming the permanent account.
4. Signed multi-architecture images for Stalwart and the gateway, each referenced by digest.
5. Volume snapshots plus an independent backup of Stalwart configuration, data, and blobs. Restore
   the backup into an isolated namespace before accepting production traffic.

## Render and deploy

```bash
STALWART_IMAGE_DIGEST=sha256:... \
GATEWAY_IMAGE_DIGEST=sha256:... \
bash deploy/openagent-mailboxes/render-release.sh /secure/release/mailboxes.yaml

kubectl apply -f deploy/openagent-mailboxes/base/namespace.yaml
# Reconcile openagent-mailboxes-secrets with the cluster secret manager here.
kubectl apply -f /secure/release/mailboxes.yaml
kubectl wait -n openagent-mailboxes --for=condition=ready pod/stalwart-0 --timeout=15m
kubectl wait -n openagent-mailboxes --for=condition=complete \
  job/openagent-mailboxes-bootstrap --timeout=10m
kubectl rollout status -n openagent-mailboxes deployment/mailbox-gateway --timeout=10m
```

Do not expose public MX until the bootstrap Job has completed and its logs contain
`bootstrap.completed` without administrative credentials.

## DNS and transport security

1. Point `mail.openagent.md` A/AAAA at the mail load balancer and `inbox.openagent.md` at the HTTPS
   ingress. This separation prevents two controllers from fighting over one DNS record.
2. Publish `agents.openagent.md` MX records pointing only to `mail.openagent.md`.
3. Publish SPF, DKIM, DMARC, MTA-STS, TLS-RPT, reverse DNS, and client autodiscovery records.
4. Production bootstrap enables Stalwart's automatic certificate management. Port 443 on the mail
   load balancer must remain reachable for ACME TLS-ALPN renewal; the ingress certificate for
   `inbox.openagent.md` is separate. Do not accept user traffic until the `mail.openagent.md`
   certificate is issued and STARTTLS/implicit TLS chains pass from outside the cluster.
5. Enable signed Stalwart webhooks and route their audit events to the production event sink.

## Promotion canary

Run the repository live E2E against production with a short-lived, dedicated Management API token.
It must end with `"result":"pass"` and verify identity, mailbox provisioning, persisted calendar,
contact and file content, cross-agent isolation, authenticated SMTP, and inbox delivery. Then test
an unrelated external sender, outbound delivery to an external mailbox, suspension, grant
revocation, token expiry, DKIM verification, and abuse-rate limits.

Hold the rollback window until queue depth, SMTP rejection rates, JMAP latency, disk saturation,
certificate expiry, authentication failures, and backup freshness are all monitored.

## Rollback

Stop new provisioning traffic first, preserve the StatefulSet PVCs, and roll back only the gateway
or Stalwart image digest that changed. Never delete the namespace or PVCs during rollback. If a
schema/storage rollback is not supported by the selected Stalwart release, restore the tested
snapshot into a new namespace and move traffic only after protocol canaries pass.
