-- Local post-state measurement, never global completion or signing authority.
CREATE TABLE destruction_local_measurement (
    job_hash BLOB NOT NULL CHECK(length(job_hash)=32),
    location_id BLOB NOT NULL CHECK(length(location_id)=32),
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    replica_id BLOB NOT NULL CHECK(length(replica_id)=16),
    exact_measurement BLOB NOT NULL,
    PRIMARY KEY(job_hash,location_id),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER destruction_local_measurement_no_update BEFORE UPDATE ON destruction_local_measurement
BEGIN SELECT RAISE(ABORT,'local destruction measurements are append-only'); END;
CREATE TRIGGER destruction_local_measurement_no_delete BEFORE DELETE ON destruction_local_measurement
BEGIN SELECT RAISE(ABORT,'local destruction measurements are append-only'); END;
