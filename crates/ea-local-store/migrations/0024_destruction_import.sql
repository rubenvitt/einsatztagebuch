-- Native admission of exact existing v1 progress objects. No mutable state flag.
CREATE TABLE destruction_import_batch (
 insertion_sequence INTEGER PRIMARY KEY,
 organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
 destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
 set_hash BLOB NOT NULL CHECK(length(set_hash)=32),
 context_hash BLOB NOT NULL CHECK(length(context_hash)=32),
 exact_context BLOB NOT NULL CHECK(length(exact_context) BETWEEN 1 AND 16800000),
 login_audit_id BLOB NOT NULL REFERENCES local_audit_event(event_id),
 state_audit_id BLOB NOT NULL REFERENCES local_audit_event(event_id),
 UNIQUE(organization_id,destruction_id,set_hash),
 FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER destruction_import_no_update BEFORE UPDATE ON destruction_import_batch
BEGIN SELECT RAISE(ABORT,'EA-DESTRUCTION-IMMUTABLE'); END;
CREATE TRIGGER destruction_import_no_delete BEFORE DELETE ON destruction_import_batch
BEGIN SELECT RAISE(ABORT,'EA-DESTRUCTION-IMMUTABLE'); END;
