# Lenso Legal Hold Plugin

A removable PostgreSQL-backed Legal Hold backend and Retention Guard for Lenso Apps.

The Plugin owns legal holds, scoped preservation rules, revisioned mutations,
idempotency receipts, activity, and durable guard-decision evidence. It does not
own Organizations, identities, memberships, RBAC policy, export assembly, or
retention execution.

## Capabilities

The Plugin provides:

- `lenso.legal-hold@1`: create/get/list holds, add/remove scopes, release a hold,
  and page through hold activity.
- `lenso.retention-guard@1`: decide whether a specific delete or anonymize action
  is blocked by an active hold before destructive retention participants run.

It requires exactly one Provider for each of:

- `lenso.secrets@1`
- `lenso.organization-membership@1`
- `lenso.access-control@1`

The private, stateless `lenso.legal-hold.agent-tools` adapter exposes the seven
administrative operations to a Console Agent. It requires exactly one
`lenso.legal-hold@1`, forwards invocation authority unchanged, and does not
expose the Retention Guard role.

Administrative requests require an exact configured caller Instance, an Auth
ActorAssertion bound to the exact operation, active Organization membership,
and an Access Control decision. Guard requests use a separate exact caller list
and never inherit ambient end-user authority.

## Domain guarantees

- PostgreSQL is the only runtime state; there is no in-memory durability fallback.
- Every mutation has a caller/actor/operation-scoped idempotency receipt.
- Scope and release mutations require a decimal `expected_revision` and lock the
  hold row before compare-and-swap.
- Released holds are immutable. A new legal obligation is represented by a new hold.
- A nullable scope subject means every subject in that scope is preserved; a
  concrete subject narrows the hold.
- Every guard evaluation writes its exact matching hold ids and revisions before
  returning the decision.

## Permissions

Access Control uses `{ kind: "organization", id: organization_id }`:

- `legal-hold.read`
- `legal-hold.write`
- `legal-hold.release`

## Schema lifecycle

`LegalHoldOperator::setup` creates the owned schema and migration ledger.
`LegalHoldOperator::upgrade` applies pending migrations. Runtime activation only
verifies and opens the authored schema through `OwnedPostgres::prepare`.

## Verification

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
./scripts/check-repository-boundary.sh
```

Set `LENSO_LEGAL_HOLD_TEST_DATABASE_URL` to execute the optional restart and
guard-decision acceptance test against PostgreSQL 15 or newer.

## Honest limits

v1 matches exact `(scope_kind, scope_id, subject?)` tuples. It does not infer a
resource hierarchy, ingest legal documents, notify custodians, or provide a Web
surface. Those remain separate replaceable Plugins.
