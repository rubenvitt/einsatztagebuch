-- Minimal retained equality source. No Entry/Object/Record/Job linkage exists.
-- Restore this key and ALL tokens atomically with the acquisition sources.
CREATE TABLE incident_number_retained_key (
    singleton INTEGER PRIMARY KEY CHECK(singleton=0),
    key_bytes BLOB NOT NULL CHECK(length(key_bytes)=32)
) STRICT;
CREATE TABLE incident_number_retained_token (
    token BLOB PRIMARY KEY NOT NULL CHECK(length(token)=32)
) STRICT;
CREATE TRIGGER incident_number_retained_key_no_update BEFORE UPDATE ON incident_number_retained_key
BEGIN SELECT RAISE(ABORT,'retained equality key is immutable'); END;
CREATE TRIGGER incident_number_retained_key_no_delete BEFORE DELETE ON incident_number_retained_key
BEGIN SELECT RAISE(ABORT,'retained equality key is immutable'); END;
CREATE TRIGGER incident_number_retained_token_no_update BEFORE UPDATE ON incident_number_retained_token
BEGIN SELECT RAISE(ABORT,'retained equality tokens are append-only'); END;
CREATE TRIGGER incident_number_retained_token_no_delete BEFORE DELETE ON incident_number_retained_token
BEGIN SELECT RAISE(ABORT,'retained equality tokens are append-only'); END;

-- Signed event + native signed audit are atomic; state is reduced from exact
-- events. Registry context columns only route historical verification.
CREATE TABLE destruction_job_event (
    insertion_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16),
    event_hash BLOB NOT NULL UNIQUE CHECK(length(event_hash)=32),
    exact_event BLOB NOT NULL,
    audit_event_id BLOB NOT NULL UNIQUE REFERENCES local_audit_event(event_id),
    execution_registry_version INTEGER NOT NULL CHECK(execution_registry_version>=0),
    execution_registry_head_hash BLOB NOT NULL CHECK(length(execution_registry_head_hash)=32),
    execution_sequence INTEGER NOT NULL CHECK(execution_sequence>=0),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER destruction_job_event_no_update BEFORE UPDATE ON destruction_job_event
BEGIN SELECT RAISE(ABORT,'destruction events are append-only'); END;
CREATE TRIGGER destruction_job_event_no_delete BEFORE DELETE ON destruction_job_event
BEGIN SELECT RAISE(ABORT,'destruction events are append-only'); END;
