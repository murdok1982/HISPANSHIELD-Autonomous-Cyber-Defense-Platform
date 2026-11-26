# ADR-013 — Outbox signaling: LISTEN/NOTIFY plus polling, no generic `jobs` table

- **Status:** Accepted (2026-11-26)
- **Context:** TASK-008 required a transactional outbox with low-latency dispatch
  and originally mentioned a separate `jobs` table. The platform already has
  domain-specific durable queues (`playbook_executions` claimed with
  `SKIP LOCKED`, connector schedules, idempotency records).

## Decision

1. Keep `outbox_events` as the single durable event queue, with leases,
   retries, DLQ and `(org_id, dedupe_key)` idempotency.
2. Add an `AFTER INSERT` trigger that calls
   `pg_notify('hispanshield_outbox', NEW.id::text)`. PostgreSQL delivers the
   notification only after the producing transaction commits, so a consumer
   cannot observe rolled-back events.
3. The worker opens a dedicated `LISTEN` connection and uses notifications only
   as a wake-up signal. The existing one-second polling loop and lease
   reclamation remain the correctness mechanism. A lost notification adds at
   most one polling interval of latency; it never loses an event.
4. Do **not** add a generic `jobs` table. Playbook executions and connector
   sync already have typed tables with their own state machines. A generic table
   would duplicate them, weaken type safety and add operational cost without a
   demonstrated requirement.

## Consequences

- Outbox latency is sub-second in the common case and bounded by the poll
  interval when notifications are unavailable (e.g. proxy/restart).
- Exactly-once external side effects are still not provided; consumers must be
  idempotent. The built-in notification consumer is idempotent via
  `notifications.source_event_id`.
- Tests cover commit-time delivery, rollback suppression, listener wake-up and
  the polling fallback.
