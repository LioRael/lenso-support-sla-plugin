# Lenso Support SLA Plugin

A removable, PostgreSQL-backed SLA backend for Lenso Support Case workflows.
It owns SLA policies, pinned case observations, response and resolution clocks,
breach receipts, and transactional scheduling/notification outboxes. It does
not own cases, messages, Organizations, identities, Access Control policy,
Jobs, or notification delivery.

## Capability

The linked native Rust Plugin provides `lenso.support-sla@1`:

- create/get/list/update/archive SLA policies;
- ingest bounded case snapshots and message facts;
- reconcile at most 200 due clocks per call;
- get/list clocks and list breach plus notification-outbox receipts.

It requires exactly one Provider for `lenso.secrets@1`,
`lenso.organization-membership@1`, and `lenso.access-control@1`. It accepts zero
or one bound `lenso.jobs@1` Provider; activation rejects multiple bindings.

Management requests require an exact configured caller, an Auth 0.2.1 Actor
Assertion audienced to the exact operation, live Organization membership, and
an independent Access Control decision. Read operations require
`support.sla.read`; policy mutations require `support.sla.manage`. Observation
and reconcile operations use separate, disjoint exact caller lists and never
inherit management authority.

## Support Case observation boundary

Support Case currently exposes requests, not an event stream. This Plugin does
not read Support Case tables or import its implementation types. A trusted,
independent observer adapter must poll or otherwise observe Support Case and
push:

- a bounded case snapshot with an opaque case ID, source revision, policy,
  priority, state, and timestamps; and
- a bounded message fact with an opaque message ID, visibility, author kind,
  and occurrence time. Message bodies are never accepted.

The adapter supplies stable observation IDs and must retry until accepted.
Case observations reject stale timestamps and conflicting replays; message
facts deduplicate both observation ID and message ID. This is an at-least-once
observer boundary, not an exactly-once event stream. Removing this Plugin does
not change or remove `lenso.support-case@1` behavior.

## SLA semantics

- Each policy maps all four Support Case priorities to first-response and
  resolution targets.
- v1 supports only the honest `utc_24x7` business calendar. It does not claim
  office hours, holidays, waiting-state pauses, or calendar exceptions.
- A case pins policy revision, priority, target values, and start time on first
  observation. Later policy edits never rewrite historical clocks.
- The first public agent message satisfies the first-response clock. A resolved
  or closed snapshot satisfies the resolution clock and cancels any still-
  running response clock.
- Running clocks own positive CAS revisions and `next_fire_at`. A bounded
  reconcile marks due clocks breached and writes one immutable breach plus one
  notification-outbox receipt in the same transaction.

## One-shot Jobs and notification delivery

`lenso.jobs@1` is a one-shot queue. The SLA Plugin therefore owns recurring
state and a durable successor outbox. Every accepted observation arranges a
successor in its transaction. Every reconcile attempt first commits an
idempotent watchdog successor; a successful reconcile tightens its fire time to
the next due clock. A bound Jobs Provider receives a stable enqueue idempotency
key after commit. A Jobs runtime or domain failure is recorded and returned as
a Runtime Failure; the pending successor remains retryable. With no Jobs
Provider, callers receive
`pending_external_worker` and an external scheduler must invoke `reconcile`.

Jobs does not itself call the SLA Capability: a worker adapter must claim the
job and invoke `reconcile` as one exact configured worker caller. Queue delivery
and observer delivery are at least once. Clock, run, observation, breach, and
outbox receipts make retries safe; the Plugin does not claim exactly-once
execution.

The current transactional Notification Capability is specific to Organization
Invitation and Access Request workflows, so v1 does not misuse it. Breach
notification intent remains in the SLA-owned outbox with status
`pending_adapter` until a support-notification contract/adapter delivers and
records it.

Observer adapters should publish already-known case/message facts before
running the corresponding reconciliation window. v1 does not retract an
already-issued breach when a source fact arrives late; the original fact and
breach receipt remain auditable.

## Lifecycle and verification

`SupportSlaOperator::setup` and `upgrade` own DDL. Runtime activation resolves
the database URL from Secrets and verifies the exact migration ledger.
PostgreSQL is the only durable state; there is no memory fallback or ambient
provider registry.

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen check crates/lenso-capability-support-sla/capability.json --rust crates/lenso-capability-support-sla/src/generated.rs
./scripts/check-repository-boundary.sh
LENSO_PACKAGE_ALLOW_DIRTY=1 ./scripts/check-public-packages.sh
```

For the optional real PostgreSQL slice, set
`LENSO_SUPPORT_SLA_POSTGRES_TEST_URL` to a dedicated database and run:

```sh
cargo test --locked -p lenso-support-sla-postgres-plugin --features postgres-acceptance -- --ignored --test-threads=1
```
