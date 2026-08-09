# OpenAgent Mailboxes

This repository is the Autonomy Cloud fork of Stalwart. The `main` branch tracks
upstream; the `openagent` branch contains the integration needed to give each
OpenAgent identity a real mailbox, calendar, contacts, and file store.

The Stalwart server remains the protocol and storage engine. OpenAgent adds a
small control-plane gateway that:

- validates short-lived agent access tokens issued by OpenAgent Identity;
- pre-provisions the matching Stalwart account before inbound mail arrives;
- exposes only identity-scoped mailbox metadata to the calling agent; and
- leaves JMAP, SMTP, IMAP, CalDAV, CardDAV, and WebDAV traffic on Stalwart.

See [docs/openagent/architecture.md](docs/openagent/architecture.md) for the
security model and [openagent/README.md](openagent/README.md) for local setup.
