# OpenAgent Mailboxes promotion

Mailboxes follows CAST's `develop -> stage -> release` contract while publishing two coordinated
images: `mailboxes-stalwart` and `openagent-mailbox-gateway`.

- `develop` verifies the gateway and build inputs and may publish development images.
- `stage` builds both multi-architecture candidates once, emits provenance and SBOMs, signs them,
  and fails on unfixed high or critical vulnerabilities.
- `release` verifies that its merge commit contains the exact stage tree and retags both stage images
  without rebuilding them.

Cluster deployment starts only after LatticeRuntime has Identity and Mailboxes overlays that pin both
digests and reference production secrets. Public MX and external delivery are later launch gates;
local persistent JMAP/SMTP/calendar/contact/file behavior can be verified before DNS cutover.
