# OpenAgent Mailboxes promotion

Mailboxes follows CAST's `develop -> stage -> release` contract while publishing two coordinated
images: `mailboxes-stalwart` and `openagent-mailbox-gateway`.

- `develop` verifies the gateway and build inputs and may publish development images.
- `stage` builds both multi-architecture candidates once, emits provenance and SBOMs, signs them,
  and fails on unfixed high or critical vulnerabilities.
- `release` verifies that its merge commit contains the exact stage tree and retags both stage images
  without rebuilding them.

Cluster deployment is owned by the infrastructure repository, which pins both digests and references
production secrets. External delivery is a separate launch gate and stays off by default.
