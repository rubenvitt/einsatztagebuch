-- Signed immutable pre-state, never a mutable authority/completion flag.
CREATE TABLE destruction_job (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
    signer_certificate_hash BLOB NOT NULL CHECK(length(signer_certificate_hash)=32),
    exact_inventory BLOB NOT NULL,
    exact_core BLOB NOT NULL,
    exact_signature BLOB NOT NULL,
    PRIMARY KEY(organization_id,destruction_id),
    FOREIGN KEY(organization_id,destruction_id)
        REFERENCES destruction_inventory(organization_id,destruction_id)
);
CREATE TRIGGER destruction_job_no_update BEFORE UPDATE ON destruction_job
BEGIN SELECT RAISE(ABORT,'destruction pre-state is immutable'); END;
CREATE TRIGGER destruction_job_no_delete BEFORE DELETE ON destruction_job
BEGIN SELECT RAISE(ABORT,'destruction pre-state is immutable'); END;
