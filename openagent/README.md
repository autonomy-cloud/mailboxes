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

All mailbox endpoints require an OpenAgent Identity bearer token for audience
`https://mail.openagent.md`.

```http
POST /v1/mailboxes/ensure
Authorization: Bearer <agent-mail-token>
```

The response contains only the calling agent's address, Stalwart account ID,
and protocol discovery URLs. The same bearer token is then used directly with
Stalwart JMAP.

## Real live verification

With Identity running on port 6201 and the mailbox stack healthy, provide a
default-tenant Management API token and run:

```bash
cd openagent/gateway
OPENAGENT_LIVE_MANAGEMENT_TOKEN='<management-api-token>' npm run test:live
```

The script creates two temporary agents with distinct Ed25519 credentials and
verifies provisioning, JMAP discovery, calendar, contacts, files, cross-account
isolation, SMTP OAUTHBEARER authentication, and inbox delivery. A successful
run ends with `"result":"pass"`. It does not use mock identities or mock mail.

## Production boundary

The Compose stack is a complete local protocol integration, not an
Internet-reachable mail deployment. Production additionally requires public
DNS and MX, SPF, DKIM, DMARC, MTA-STS/TLS-RPT, trusted TLS certificates,
durable object/database storage, backups with restore tests, rate limits,
monitoring, and secret-manager delivery of the recovery credential.
