-- Diagnostic failures never alter the last successful completion or next due time.
CREATE TABLE recovery_test_failure (
  failure_hash BLOB PRIMARY KEY NOT NULL CHECK(length(failure_hash)=32),
  source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
  context_hash BLOB NOT NULL CHECK(length(context_hash)=32),
  exact_report BLOB NOT NULL CHECK(length(exact_report) BETWEEN 1 AND 1048576),
  failure_audit_event_id BLOB NOT NULL UNIQUE CHECK(length(failure_audit_event_id)=16),
  failed_at INTEGER NOT NULL CHECK(failed_at>=0),
  FOREIGN KEY(failure_audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE INDEX recovery_test_failure_time ON recovery_test_failure(failed_at DESC,failure_hash);
CREATE TRIGGER recovery_test_failure_no_update BEFORE UPDATE ON recovery_test_failure
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-FAILURE-IMMUTABLE'); END;
CREATE TRIGGER recovery_test_failure_no_delete BEFORE DELETE ON recovery_test_failure
BEGIN SELECT RAISE(ABORT,'EA-RECOVERY-FAILURE-IMMUTABLE'); END;
