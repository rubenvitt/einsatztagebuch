-- Pre-loss source capture is distinct from restore and successful testing.
CREATE TABLE recovery_source_scope (
  source_hash BLOB PRIMARY KEY NOT NULL CHECK(length(source_hash)=32),
  exact_envelope BLOB NOT NULL CHECK(length(exact_envelope) BETWEEN 1 AND 524288),
  capture_audit_event_id BLOB NOT NULL CHECK(length(capture_audit_event_id)=16),
  FOREIGN KEY(capture_audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER recovery_source_scope_no_update BEFORE UPDATE ON recovery_source_scope
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-SOURCE-IMMUTABLE'); END;
CREATE TRIGGER recovery_source_scope_no_delete BEFORE DELETE ON recovery_source_scope
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-SOURCE-IMMUTABLE'); END;

-- A new target contains one exact restored snapshot; no merge or replacement.
-- The external source audit remains inside its verified exact envelope.
CREATE TABLE recovery_restore_binding (
  singleton INTEGER PRIMARY KEY CHECK(singleton=0),
  source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
  exact_envelope BLOB NOT NULL CHECK(length(exact_envelope) BETWEEN 1 AND 524288),
  snapshot_hash BLOB NOT NULL CHECK(length(snapshot_hash)=32),
  migrations_hash BLOB NOT NULL CHECK(length(migrations_hash)=32),
  target_machine BLOB NOT NULL CHECK(length(target_machine)=32),
  target_installation BLOB NOT NULL CHECK(length(target_installation)=32),
  restored_content_hash BLOB NOT NULL CHECK(length(restored_content_hash)=32),
  registry_version INTEGER NOT NULL CHECK(registry_version>0),
  registry_head BLOB NOT NULL CHECK(length(registry_head)=32),
  proposed_sequence INTEGER NOT NULL CHECK(proposed_sequence>=0),
  restore_audit_event_id BLOB NOT NULL CHECK(length(restore_audit_event_id)=16),
  FOREIGN KEY(restore_audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER recovery_restore_binding_no_update BEFORE UPDATE ON recovery_restore_binding
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-RESTORE-IMMUTABLE'); END;
CREATE TRIGGER recovery_restore_binding_no_delete BEFORE DELETE ON recovery_restore_binding
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-RESTORE-IMMUTABLE'); END;

-- Only a verified complete report and its committed signed local audit may be
-- interpreted as readiness. Table presence or caller observations never suffice.
CREATE TABLE recovery_test_report (
  report_hash BLOB PRIMARY KEY NOT NULL CHECK(length(report_hash)=32),
  source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
  exact_report BLOB NOT NULL CHECK(length(exact_report) BETWEEN 1 AND 1048576),
  completion_audit_event_id BLOB NOT NULL UNIQUE CHECK(length(completion_audit_event_id)=16),
  completed_at INTEGER NOT NULL,
  next_due_at INTEGER NOT NULL CHECK(next_due_at>=completed_at),
  FOREIGN KEY(completion_audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER recovery_test_report_no_update BEFORE UPDATE ON recovery_test_report
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-REPORT-IMMUTABLE'); END;
CREATE TRIGGER recovery_test_report_no_delete BEFORE DELETE ON recovery_test_report
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-REPORT-IMMUTABLE'); END;
