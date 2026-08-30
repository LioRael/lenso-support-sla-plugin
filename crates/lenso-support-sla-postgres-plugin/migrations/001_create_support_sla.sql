CREATE TABLE sla_policies (
    organization_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    name TEXT NOT NULL,
    business_calendar TEXT NOT NULL CHECK (business_calendar = 'utc_24x7'),
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    archived_at TIMESTAMPTZ,
    PRIMARY KEY (organization_id, policy_id)
);

CREATE TABLE sla_policy_targets (
    organization_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    first_response_seconds BIGINT NOT NULL CHECK (first_response_seconds BETWEEN 60 AND 31536000),
    resolution_seconds BIGINT NOT NULL CHECK (resolution_seconds BETWEEN 60 AND 31536000),
    CHECK (resolution_seconds >= first_response_seconds),
    PRIMARY KEY (organization_id, policy_id, priority),
    FOREIGN KEY (organization_id, policy_id) REFERENCES sla_policies(organization_id, policy_id) ON DELETE CASCADE
);

CREATE TABLE sla_policy_commands (
    caller_instance TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    response JSONB,
    status TEXT NOT NULL CHECK (status IN ('processing', 'completed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_instance, actor_subject, operation, idempotency_key)
);

CREATE TABLE sla_cases (
    organization_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    priority TEXT NOT NULL CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    state TEXT NOT NULL CHECK (state IN ('open', 'in_progress', 'waiting_customer', 'resolved', 'closed')),
    source_case_revision TEXT NOT NULL,
    source_created_at TIMESTAMPTZ NOT NULL,
    source_updated_at TIMESTAMPTZ NOT NULL,
    source_resolved_at TIMESTAMPTZ,
    source_closed_at TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, case_id),
    FOREIGN KEY (organization_id, policy_id) REFERENCES sla_policies(organization_id, policy_id)
);

CREATE TABLE sla_case_observations (
    caller_instance TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    observation_kind TEXT NOT NULL CHECK (observation_kind IN ('case_snapshot', 'case_message')),
    organization_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    source_case_revision TEXT NOT NULL,
    source_fact_id TEXT,
    request_hash BYTEA NOT NULL,
    response JSONB,
    status TEXT NOT NULL CHECK (status IN ('processing', 'completed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_instance, observation_id)
);

CREATE UNIQUE INDEX sla_snapshot_fact_dedupe
    ON sla_case_observations(organization_id, case_id, source_case_revision)
    WHERE observation_kind = 'case_snapshot';

CREATE UNIQUE INDEX sla_message_fact_dedupe
    ON sla_case_observations(organization_id, case_id, source_fact_id)
    WHERE observation_kind = 'case_message';

CREATE TABLE sla_case_messages (
    organization_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    source_case_revision TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal')),
    author_kind TEXT NOT NULL CHECK (author_kind IN ('requester', 'agent', 'system')),
    occurred_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, case_id, message_id),
    FOREIGN KEY (organization_id, case_id) REFERENCES sla_cases(organization_id, case_id) ON DELETE CASCADE
);

CREATE TABLE sla_clocks (
    clock_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    priority TEXT NOT NULL CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    kind TEXT NOT NULL CHECK (kind IN ('first_response', 'resolution')),
    target_seconds BIGINT NOT NULL CHECK (target_seconds > 0),
    started_at TIMESTAMPTZ NOT NULL,
    target_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'met', 'breached', 'canceled')),
    satisfied_at TIMESTAMPTZ,
    breached_at TIMESTAMPTZ,
    next_fire_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (organization_id, case_id, kind),
    FOREIGN KEY (organization_id, case_id) REFERENCES sla_cases(organization_id, case_id) ON DELETE CASCADE
);

CREATE INDEX sla_clocks_due ON sla_clocks(next_fire_at, clock_id) WHERE status = 'running';
CREATE INDEX sla_clocks_listing ON sla_clocks(organization_id, clock_id);

CREATE TABLE sla_breaches (
    breach_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    clock_id TEXT NOT NULL UNIQUE REFERENCES sla_clocks(clock_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('first_response', 'resolution')),
    target_at TIMESTAMPTZ NOT NULL,
    breached_at TIMESTAMPTZ NOT NULL,
    clock_revision BIGINT NOT NULL CHECK (clock_revision > 0)
);

CREATE INDEX sla_breaches_listing ON sla_breaches(organization_id, breach_id);

CREATE TABLE sla_notification_outbox (
    notification_outbox_id TEXT PRIMARY KEY,
    breach_id TEXT NOT NULL UNIQUE REFERENCES sla_breaches(breach_id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_adapter' CHECK (status IN ('pending_adapter', 'delivered', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_attempt_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE sla_reconcile_runs (
    caller_instance TEXT NOT NULL,
    run_id TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    response JSONB,
    status TEXT NOT NULL CHECK (status IN ('processing', 'completed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_instance, run_id)
);

CREATE TABLE sla_schedule_outbox (
    schedule_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    available_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'enqueued', 'consumed', 'failed')),
    job_id TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_attempt_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX sla_schedule_pending ON sla_schedule_outbox(available_at, schedule_id)
    WHERE status IN ('pending', 'failed');
