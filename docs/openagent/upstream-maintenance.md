# Importing upstream mailbox changes

The deployable OpenAgent Mailboxes line has a clean root history and does not merge Stalwart's Git
history. `stalwartlabs/stalwart` remains a provenance and patch source.

For an upstream update:

1. Record the exact upstream tag and commit in the change description.
2. Materialize that upstream tree in a temporary checkout, never on `develop`, `stage`, or `release`.
3. Review the snapshot diff against the current OpenAgent tree, including license notices,
   migrations, storage compatibility, protocols, and security advisories.
4. Port the approved diff onto a feature branch and run the OpenAgent gateway, manifest, live JMAP,
   SMTP, calendar, contact, file, isolation, backup, and restore gates.
5. Squash the reviewed update into `develop`, then promote through `stage` and `release` with merge
   commits. Release must reuse the stage-built image digests.

Never force-update an environment branch without first preserving its exact old tip under an archive
reference. Upstream history may remain available through a separate remote or archival branch, but
it is not part of the deployable OpenAgent commit graph.
