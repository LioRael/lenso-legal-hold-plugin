# Legal Hold v1 Plugin card

## Owner and deletion boundary

The PostgreSQL Plugin owns legal holds, scopes, activity, command receipts, and
guard-decision evidence. Removing the Plugin Instance and owned schema removes
Legal Hold behavior without deleting Organizations, identities, Access Control
grants, exports, or retention policies.

## Provided behavior

`lenso.legal-hold@1` is the administrative contract. Holds are immutable legal
records with explicit active/released state; scope and release mutations use
CAS revisions and durable idempotency.

`lenso.retention-guard@1` is the execution boundary consumed by the Retention
coordinator. Every configured guard runs before any destructive participant.
An active exact scope blocks both delete and anonymize and returns
`active_legal_hold` with a deterministic decision id.

## Authorization boundary

Administrative callers and retention coordinators use independent exact caller
allowlists. Admin operations additionally require exact-operation Auth,
Organization membership, and one target-owned Access Control permission. A
dependency rejection or Runtime failure never becomes an allow decision.

## Lifecycle and durability

Setup and upgrade are explicit operator workflows. Activation resolves the
database URL through Secrets and refuses a missing or stale schema. PostgreSQL
transactions serialize idempotency replay, scope mutation, revisions, release,
activity, and guard evidence across restarts.

## Honest limits

v1 has exact scopes only, no hierarchy expansion, custodian acknowledgements,
document upload, discovery export, external matter sync, or Console UI.
