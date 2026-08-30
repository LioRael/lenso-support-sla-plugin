# Support SLA v1 Plugin card

## Outcome and deletion boundary

Support teams can define response/resolution targets, observe opaque Support
Case facts, reconcile clocks, and consume durable breach receipts. Removing the
Plugin Instance, bindings, and its owned schema removes SLA behavior without
changing cases or messages. A composition proof guards that deletion boundary.

## Owned facts

The Plugin owns policies and targets, policy command receipts, pinned case
observations, message dedupe facts, clocks and revisions, reconcile receipts,
breaches, notification intents, and successor scheduling outbox rows.

It owns no Support Case lifecycle, message body, identity, Organization
membership, permission, Jobs lease, or delivered notification fact.

## Roles and authority

- Management: exact callers plus exact-operation Auth assertions, membership,
  and Access Control (`support.sla.read` / `support.sla.manage`).
- Observation: separate exact trusted adapters; no borrowed end-user authority.
- Worker: separate exact reconcile callers; no borrowed observer or management
  authority.

The target remains final authority over CAS, archival, observation monotonicity,
dedupe, bounded work, and terminal clock invariants. Dependency Runtime
Failures fail closed.

## Scheduling and delivery truth

Jobs is optional and one-shot. The Plugin transactionally owns each successor
intent, including a watchdog committed before each reconcile attempt, then
idempotently enqueues it. The worker adapter converts a claimed job to an exact-
caller `reconcile`; neither Jobs nor the SLA Plugin claims automatic cross-
Capability execution. Both observation and Jobs delivery are at least once,
with durable receipts.

The v1 notification outbox is an adapter boundary because the existing
transactional Notification contract has no generic support-breach operation.

## Honest v1 limits

The only calendar is 24x7 UTC. There are no holidays, office hours, waiting-
customer pauses, escalation matrices, UI Contribution, or Support Case event
subscription. Observer adapters poll/push exact snapshots and facts.
