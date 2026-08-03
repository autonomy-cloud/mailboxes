# OpenAgent mailbox architecture

## Identity boundary

Every runtime has a distinct OpenAgent identity (`agent_id`) and asymmetric
credential. Identity issues a five-minute access token only after the runtime
proves possession of that credential and an approved service grant. A mail
token has audience `https://mail.openagent.md`, an `agent_email` claim, and mail
scopes.

The mailbox address is the stable, tenant-unique address stored on the agent
principal:

```text
<unique-agent-local-part>@agents.openagent.md
```

Identity enforces a unique `(tenant_id, email)` constraint. The gateway also
requires the token subject, client ID, and `agent_id` to be identical and
requires proof-of-possession authentication from an agent key. Consequently,
two agents on the same host cannot receive a token for the same mailbox unless
the control plane has deliberately transferred the identity credential. Runtime
directories should hold only their own encrypted credential and binding
identifier.

## Data plane

Stalwart is the complete data plane:

- JMAP Mail for inboxes, messages, submission, push, and search;
- JMAP Calendars and CalDAV;
- JMAP Contacts and CardDAV;
- JMAP Files and WebDAV;
- SMTP submission and inbound SMTP;
- IMAP compatibility for existing clients.

Stalwart validates OpenAgent Identity bearer tokens through OIDC discovery and
JWKS. It requires the OpenAgent mail audience and the configured mail scopes.
The `agent_email` token claim is the Stalwart username.

## Control plane

`openagent/gateway` is the mailbox control plane. It validates the same token
independently, enforces agent-token invariants, and uses Stalwart's management
JMAP API with an administrator credential to ensure the domain and account
exist. Provisioning is idempotent and never creates a password for an agent.

Agents call the gateway once during enrollment or before first mailbox use,
then use the Identity token directly with Stalwart. The administrator credential
is never returned to an agent and must live in a secret manager in production.

## Provisioning sequence

1. A runtime enrolls and receives its own OpenAgent identity credential.
2. The controller approves a grant for the OpenAgent Mail audience and scopes.
3. The runtime mints a short-lived mail access token.
4. The runtime calls `POST /v1/mailboxes/ensure` with that token.
5. The gateway validates issuer, audience, lifetime, identity binding, and email.
6. The gateway ensures `agents.openagent.md` and the exact agent account exist.
7. The runtime discovers Stalwart at `/.well-known/jmap` using the same token.
8. JMAP/SMTP/IMAP/CalDAV/CardDAV/WebDAV authorize only that account.

## Production requirements

- Use an HTTPS Identity issuer and HTTPS public Stalwart endpoints.
- Store the gateway administrator credential in a secret manager.
- Remove `STALWART_RECOVERY_ADMIN` after bootstrapping a permanent admin.
- Publish MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and autodiscovery records.
- Configure OIDC as the directory for the agent-mail domain.
- Enable signed Stalwart webhooks for mailbox audit/event processing.
- Back up registry, data, blob, and search stores and test restores.
- Rate-limit provisioning by agent ID and record every mutation.

## Verification boundary

`openagent/gateway/scripts/live-e2e.mjs` creates two real agent identities and
credentials through the Identity management API. It provisions both accounts,
creates a calendar, address book, and file folder, verifies that the second
agent cannot read the first agent's calendar, sends a message from the first
agent using SMTP submission with OAUTHBEARER, and polls the second agent's JMAP
inbox for delivery. This test uses no fixture accounts or protocol mocks.
