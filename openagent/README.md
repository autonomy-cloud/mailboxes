# OpenAgent mailbox integration

## Local services

The local stack uses the 64xx range:

- Stalwart HTTP/JMAP/admin: `http://localhost:6401`
- OpenAgent mailbox gateway: `http://localhost:6402`
- SMTP: `localhost:6425`
- SMTP submission with implicit TLS: `localhost:6487`
- IMAP with implicit TLS: `localhost:6493`

Copy `.env.example` to `.env`, set the same strong recovery credential on both
services, and run:

```bash
docker compose --env-file openagent/.env \
  -f openagent/compose.yaml up --build
```

The gateway health endpoints are `/health/live` and `/health/ready`.

For local tenant routing, Identity must use
`ENDPOINT=http://127.0.0.1:6201` for the default tenant and
`ADMIN_ENDPOINT=http://localhost:6201` for the admin tenant. This ensures the
issuer's discovery document and JWKS expose the same signing key used for agent
tokens.

The Stalwart image is built from this fork with the AGPL feature set. The first
build compiles the Rust server and storage backends and can take a while on a
small machine; later builds use the Docker cache.

## Gateway API

The legacy endpoint remains available and requires an OpenAgent Identity bearer
token for audience `https://mail.openagent.md`.

```http
POST /v1/mailboxes/ensure
Authorization: Bearer <agent-mail-token>
```

The response contains only the calling agent's address, Stalwart account ID,
and protocol discovery URLs. The same bearer token is then used directly with
Stalwart JMAP.

Cast-native endpoints use a separate service bearer token configured through
`CAST_MAILBOX_GATEWAY_TOKEN` (minimum 32 characters):

```http
POST /v1/cast/mailboxes/ensure
POST /v1/cast/mailboxes/retire
POST /v1/cast/mailboxes/send
Authorization: Bearer <cast-mailbox-gateway-token>
Content-Type: application/json
```

`ensure` accepts `workspaceId`, `agentId`, `displayName`, `permanentAddress`,
and `aliases`. It derives and validates the canonical address
`agt-<agent-id>@wsp-<workspace-id>.agents.openagent.md`, then idempotently
creates the workspace tenant, tenant-owned domain, and tenant-owned mailbox.
`LEGACY_AGENT_MAIL_DOMAINS` is an empty-by-default comma/space separated cleanup
allowlist. After the replacement mailbox is fully ensured, the gateway removes
only the exact derived legacy account whose account and workspace domain belong
to that same tenant. The old workspace domain is removed only when no accounts
remain. Set this to `agents.visca.ai` for the explicitly authorized Stage
migration; keep it empty where destructive cleanup is not approved.
`retire` preserves mailbox data while disabling aliases and setting a blocking
storage quota; a later `ensure` restores normal quotas and aliases. `send`
accepts `from`, `to`, `cc`, `bcc`, `subject`, `messageId`, optional `text`/`html`,
threading headers, and base64 attachments, then imports and submits the message
through the mailbox account.

Set `STALWART_CONFIGURE_CAST_MAIL=true` to reconcile parent-domain signing with
`CAST_DKIM_SELECTOR=cast1`. The reconciler configures the signing domain to
`OPENAGENT_MAIL_DOMAIN`, generates one RSA key at the stable selector, and
freezes automatic rotation after the active key exists. The private
`GET /v1/cast/mail/dkim` endpoint returns only the exact selector, domain, DNS
name, public TXT value, algorithm, and whether public DNS matches; it never
returns the private key. `outboundDelivery` remains false until the authenticated
configuration is exact, the public TXT record matches, and an operator sets
`MAIL_PUBLIC_DELIVERY_CONFIGURED=true` after an external delivery probe confirms
the received `DKIM-Signature` uses `d=<OPENAGENT_MAIL_DOMAIN>; s=cast1`.

Calendar event projection uses the same bearer token and tenant-bound mailbox:

```http
POST   /v1/cast/calendars/events
PUT    /v1/cast/calendars/events/<external-id>
DELETE /v1/cast/calendars/events/<external-id>
```

Create accepts `workspaceId`, `agentId`, `idempotencyKey`, and an `event` with
`title`, `startsAt`, `endsAt`, and optional `description`/`location`. Update
accepts the same workspace/agent scope and event; delete accepts the scope.
The create idempotency key is mapped to a stable calendar UID.

The readiness response includes vendor-neutral capability flags. Inbound
forwarding becomes ready when `MAIL_TELEMETRY_WEBHOOK_CONFIGURED=true` and all
of `MAIL_TELEMETRY_WEBHOOK_SECRET`, `CAST_AGENT_MAIL_WEBHOOK_URL`, and
`CAST_MAILBOX_WEBHOOK_SECRET` are configured. The mail server telemetry webhook
must post the `message-ingest.ham` and `message-ingest.spam` events to the
private gateway endpoint below and sign the raw request body with the matching
secret using base64-encoded HMAC-SHA256 in `X-Signature`:

```http
POST /v1/mail-events/ingest
```

The gateway uses the event's tenant-scoped account and full email ID to fetch
the raw RFC 5322 message (hard-capped at 25 MiB), then forwards those bytes as
`message/rfc822` to `CAST_AGENT_MAIL_WEBHOOK_URL`. The request uses
`agent-mail-webhook-auth`, `agent-mail-recipient`, `agent-mail-source-id`, and
optional `agent-mail-message-id` headers. The full email ID is emitted by this fork's
mail-ingest telemetry event; the gateway and mail-server image must therefore
be promoted together.

## Real live verification

With Identity running on port 6201 and the mailbox stack healthy, provide a
default-tenant Management API token and run:

```bash
cd openagent/gateway
OPENAGENT_LIVE_MANAGEMENT_TOKEN='<management-api-token>' npm run test:live
```

The script creates two temporary agents with distinct Ed25519 credentials and
verifies provisioning, JMAP discovery, a persisted calendar event, a persisted
contact card, uploaded and read-back file content, cross-account isolation,
SMTP OAUTHBEARER authentication, and inbox delivery. A successful run ends with
`"result":"pass"`. It does not use mock identities or mock mail.

## Production boundary

The Compose stack is a complete local protocol integration, not an
Internet-reachable mail deployment. Production additionally requires public
DNS and MX, SPF, DKIM, DMARC, MTA-STS/TLS-RPT, trusted TLS certificates,
durable object/database storage, backups with restore tests, rate limits,
monitoring, and secret-manager delivery of the recovery credential.

The digest-pinned Kubernetes packaging and rollout procedure live in
`deploy/openagent-mailboxes` and `docs/openagent/production.md`.
