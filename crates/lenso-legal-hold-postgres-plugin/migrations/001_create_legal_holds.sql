CREATE TABLE legal_holds (
    hold_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    legal_authority TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'released')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_by TEXT,
    released_at TIMESTAMPTZ,
    release_reason TEXT
);

CREATE INDEX legal_holds_org_status_idx
    ON legal_holds (organization_id, status, created_at DESC, hold_id DESC);

CREATE TABLE legal_hold_scopes (
    scope_row_id BIGSERIAL PRIMARY KEY,
    hold_id TEXT NOT NULL REFERENCES legal_holds(hold_id) ON DELETE CASCADE,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    subject TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE NULLS NOT DISTINCT (hold_id, scope_kind, scope_id, subject)
);

CREATE INDEX legal_hold_scopes_guard_idx
    ON legal_hold_scopes (scope_kind, scope_id, subject, hold_id);

CREATE TABLE legal_hold_commands (
    caller_instance TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (caller_instance, actor_subject, operation, idempotency_key)
);

CREATE TABLE legal_hold_activity (
    activity_id BIGSERIAL PRIMARY KEY,
    organization_id TEXT NOT NULL,
    hold_id TEXT NOT NULL REFERENCES legal_holds(hold_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX legal_hold_activity_cursor_idx
    ON legal_hold_activity (organization_id, hold_id, activity_id);

CREATE TABLE legal_hold_guard_decisions (
    decision_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    caller_instance TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    allowed BOOLEAN NOT NULL,
    reason_code TEXT,
    matching_holds JSONB NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX legal_hold_guard_action_idx
    ON legal_hold_guard_decisions (caller_instance, action_id, evaluated_at DESC);
