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

The Stalwart image is built from this fork with the AGPL feature set. The first
build compiles the Rust server and storage backends and can take a while on a
small machine; later builds use the Docker cache.

## Gateway API

Every mailbox endpoint is private to Cast and requires the service bearer
token configured through `CAST_MAILBOX_GATEWAY_TOKEN` (minimum 32 characters):

```http
POST /v1/cast/mailboxes/ensure
POST /v1/cast/mailboxes/retire
POST /v1/cast/mailboxes/send
Authorization: Bearer <cast-mailbox-gateway-token>
Content-Type: application/json
```

`ensure` accepts `workspaceId`, `agentId`, `displayName`, `permanentAddress`,
and `aliases`. It derives and validates the canonical address
`agt-<agent-id>@wsp-<workspace-id>.<OPENAGENT_MAIL_DOMAIN>`, then idempotently
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

With `MAIL_PUBLIC_DELIVERY_CONFIGURED=false` (the default), native agent
submission permits only recipient domains registered in Stalwart. Any external
To, Cc or Bcc recipient rejects the entire request with HTTP 403 and
`external_delivery_disabled`, before upload or submission. Internal mail and
mailbox/alias provisioning remain available. Keep this flag false during the
domain-only rollout; the hosted mail policy also denies external SMTP egress.

Turning the flag on does not open sending by itself. A message with an external
recipient is still refused whole, with HTTP 403 and before upload or
submission, unless it passes every check below. Messages with only local
recipients are never affected.

| Check | Setting | Refusal code |
|---|---|---|
| The sender is a platform address, at `OPENAGENT_MAIL_DOMAIN` or under it. A workspace-owned sender domain is not a sending domain at the relay. | none | `external_sender_not_allowed` |
| At most 50 recipients on the message, the relay's limit. | none | `external_recipient_limit_exceeded` |
| Every external recipient is on the allowed list. | `MAIL_EXTERNAL_RECIPIENT_ALLOWLIST`, `MAIL_EXTERNAL_RECIPIENT_POLICY` | `external_recipient_not_allowed` |

`MAIL_EXTERNAL_RECIPIENT_ALLOWLIST` holds entries separated by spaces or commas:
`name@example.com` for one address, `@example.com` for every address at exactly
that domain. There is no wildcard and a subdomain is a different domain. The
default is empty, which admits nobody. `MAIL_EXTERNAL_RECIPIENT_POLICY=open`
removes the list check; the default is `allowlist`. An invalid entry stops the
gateway from starting.

The 403 body carries the code in `error`, a sentence in `message` and, for
`external_recipient_not_allowed`, the refused addresses in `recipients`. The
gateway logs the code and the number of refused recipients, never the
addresses. A successful send logs `externalRecipientCount`.

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

## Production boundary

The Compose stack is a complete local protocol integration, not an
Internet-reachable mail deployment. Production additionally requires public
DNS and MX, SPF, DKIM, DMARC, MTA-STS/TLS-RPT, trusted TLS certificates,
durable object/database storage, backups with restore tests, rate limits,
monitoring, and secret-manager delivery of the recovery credential.

Deployment manifests live in the infrastructure repository, which pins both
images by digest. `STALWART_SERVER_HOSTNAME` is used only by the one-time
bootstrap and defaults to `STALWART_MAIL_HOST`.

## Workspace domain aliases

The default Agent mail namespace is `agents.visca.ai`. Cast's existing workspace
subdomain produces addresses such as `sales@software-factory.agents.visca.ai`.
Cast remains the domain ownership and address authority. The gateway accepts
additional alias domains only on the private Cast service-token endpoint, creates
them under the same workspace tenant, and rejects adoption of another tenant's
domain. An existing account retains its permanent ID-based primary address and
mailbox contents across default-domain and display-name changes. Account updates
retain historical aliases. Never use `LEGACY_AGENT_MAIL_DOMAINS` to retain domains:
it authorizes deletion and must be empty during this additive migration.

`POST /v1/cast/mail-domains/ensure` prepares a tenant-owned custom mail domain and
returns its real MX, DKIM and DMARC records. DKIM key generation is asynchronous;
Cast keeps readiness off until the returned key is published. Custom domains
use their own signing keys, while platform subdomains share the corresponding
parent signer. `send` optionally accepts the preserved `permanentAddress`, so
changing the default base cannot redirect an existing mailbox. The gateway still
verifies the sender is an enabled alias owned by that exact agent and tenant.

Run `npm run test:cast-domains` in `openagent/gateway` with the local gateway
and Stalwart URLs and their test credentials in the process environment. This
acceptance runner rejects non-local endpoints and host ports outside 7xxx,
sends only between synthetic mailboxes, tests old-primary preservation, alias
provisioning, rename, tenant isolation, sender spoofing, custom-domain key
setup and persisted delivery, and retires both mailboxes afterwards.
