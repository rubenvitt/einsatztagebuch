-- Exact signed device-wide claims. Columns route/reconcile; bytes confer authority.
CREATE TABLE destruction_local_attestation (
    job_hash BLOB NOT NULL CHECK(length(job_hash)=32),
    replica_id BLOB NOT NULL CHECK(length(replica_id)=16),
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    object_hash BLOB NOT NULL UNIQUE CHECK(length(object_hash)=32),
    exact_attestation BLOB NOT NULL,
    execution_registry_version INTEGER NOT NULL CHECK(execution_registry_version>=0),
    execution_registry_head_hash BLOB NOT NULL CHECK(length(execution_registry_head_hash)=32),
    execution_sequence INTEGER NOT NULL CHECK(execution_sequence>=0),
    PRIMARY KEY(job_hash,replica_id),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER destruction_local_attestation_no_update BEFORE UPDATE ON destruction_local_attestation
BEGIN SELECT RAISE(ABORT,'local attestations are append-only'); END;
CREATE TRIGGER destruction_local_attestation_no_delete BEFORE DELETE ON destruction_local_attestation
BEGIN SELECT RAISE(ABORT,'local attestations are append-only'); END;
