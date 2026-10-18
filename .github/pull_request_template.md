<!-- conventions:begin: synced from vexouLuna/conventions; edit it there, then run `conventions sync` -->
## What changed

## Checklist
- [ ] The branch is named per [Conventional Branch](../CONTRIBUTING.md#branches) (`feature/`, `bugfix/`, `hotfix/`, `release/`, `chore/`).
- [ ] New behaviour has a test, and docs that describe the changed behaviour are updated in this PR.
- [ ] Nothing synced from vexouLuna/conventions was edited by hand (`.conventions/`, managed blocks).
- [ ] **No private infrastructure**: no machine hostnames, private IPs, server paths, proxy/tunnel config or deploy scripts. Those belong in the private infrastructure repo.
- [ ] No secret values anywhere in the diff, the description or the commit messages.
<!-- conventions:end -->

## This repo
- [ ] A schema change is a new migration with a working downgrade (CI runs every revision down and up again).
- [ ] Nothing a site sends is trusted for more than it proves: return URLs, redirect URIs and origins are checked against the configuration.
- [ ] No Twitch token, client secret or session token is logged or returned to a browser.
