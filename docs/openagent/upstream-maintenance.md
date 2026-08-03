# Maintaining the fork

`main` is reserved for an unmodified mirror of `stalwartlabs/stalwart`. Product
work belongs on `openagent` or branches created from it.

```bash
git fetch upstream
git switch main
git merge --ff-only upstream/main
git push origin main
git switch openagent
git rebase main
```

Run `scripts/sync-upstream.sh` for the fetch and fast-forward checks. Resolve any
OpenAgent integration conflicts on `openagent`, never on `main`.
