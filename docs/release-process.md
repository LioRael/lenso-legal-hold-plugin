# Release process

Publish `lenso-capability-legal-hold` before
`lenso-legal-hold-postgres-plugin`. Publication is manual-only from reviewed
`main` through `.github/workflows/release-plz.yml`.

## Trusted Publisher configuration

Configure one crates.io Trusted Publisher for each crate:

- owner: `LioRael`
- repository: `lenso-legal-hold-plugin`
- workflow: `release-plz.yml`
- environment: unset

The live workflow has no long-lived Cargo token fallback. It requests a
short-lived crates.io credential with GitHub OIDC and requires `main`,
`live=true`, and confirmation `publish`.

If a crate name has never existed on crates.io, its first release must allocate
the name before crates.io permits a Trusted Publisher to be configured. Use a
temporary, narrowly scoped new-package token for that one allocation and revoke
it immediately; never store it in this repository or GitHub Actions.

## Publication gates

Run all CI gates plus `./scripts/check-public-packages.sh`, then execute the
PostgreSQL acceptance test with `LENSO_LEGAL_HOLD_TEST_DATABASE_URL` set. Before
the first Capability publication, the package gate strictly verifies the
Capability archive and the Plugin source set because Cargo cannot resolve the
Plugin's normalized registry dependency graph until those names exist.
