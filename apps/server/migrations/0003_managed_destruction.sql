-- Exact native signed events are immutable; technical state is only an index.
CREATE TABLE destruction_event_cores (
    object_hash BYTEA PRIMARY KEY REFERENCES object_index(object_hash),
    organization_id BYTEA NOT NULL,
    destruction_id BYTEA NOT NULL,
    event_id BYTEA NOT NULL CHECK(octet_length(event_id)=16),
    exact_bytes BYTEA NOT NULL,
    UNIQUE(organization_id, destruction_id, event_id),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destructions(organization_id,destruction_id)
);
CREATE FUNCTION ea_destruction_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable destruction evidence'; END;
$$;
CREATE TRIGGER destruction_event_cores_immutable BEFORE UPDATE OR DELETE ON destruction_event_cores
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
CREATE TRIGGER destruction_transitions_immutable BEFORE UPDATE OR DELETE ON destruction_transitions
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
CREATE TRIGGER destruction_attestations_immutable BEFORE UPDATE OR DELETE ON destruction_attestations
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();

CREATE TABLE destruction_jobs (
    organization_id BYTEA NOT NULL,
    destruction_id BYTEA NOT NULL,
    job_hash BYTEA NOT NULL CHECK(octet_length(job_hash)=32),
    authorization_hash BYTEA NOT NULL CHECK(octet_length(authorization_hash)=32),
    exact_upload BYTEA NOT NULL,
    admitted_at_millis BIGINT NOT NULL,
    catalog_revision BIGINT NOT NULL,
    principal_certificate BYTEA NOT NULL CHECK(octet_length(principal_certificate)=32),
    PRIMARY KEY(organization_id,destruction_id),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destructions(organization_id,destruction_id)
);
CREATE TABLE destruction_job_objects (
    organization_id BYTEA NOT NULL,
    destruction_id BYTEA NOT NULL,
    object_hash BYTEA NOT NULL CHECK(octet_length(object_hash)=32),
    object_type_code SMALLINT NOT NULL CHECK(object_type_code IN(1,2)),
    size_bytes BIGINT NOT NULL CHECK(size_bytes>=0),
    PRIMARY KEY(organization_id,destruction_id,object_hash),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_jobs(organization_id,destruction_id)
);
CREATE TABLE destruction_job_versions (
    organization_id BYTEA NOT NULL,
    destruction_id BYTEA NOT NULL,
    object_hash BYTEA NOT NULL CHECK(octet_length(object_hash)=32),
    storage_key TEXT NOT NULL CHECK(length(storage_key)>0),
    version_id TEXT NOT NULL CHECK(length(version_id)>0),
    delete_marker BOOLEAN NOT NULL,
    retained_until_millis BIGINT,
    legal_hold BOOLEAN NOT NULL,
    PRIMARY KEY(organization_id,destruction_id,object_hash,storage_key,version_id),
    FOREIGN KEY(organization_id,destruction_id,object_hash) REFERENCES destruction_job_objects(organization_id,destruction_id,object_hash)
);
CREATE TRIGGER destruction_jobs_immutable BEFORE UPDATE OR DELETE ON destruction_jobs
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
CREATE TRIGGER destruction_job_objects_immutable BEFORE UPDATE OR DELETE ON destruction_job_objects
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
CREATE TRIGGER destruction_job_versions_immutable BEFORE UPDATE OR DELETE ON destruction_job_versions
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();

CREATE TABLE destruction_job_stubs (
    organization_id BYTEA NOT NULL, destruction_id BYTEA NOT NULL,
    object_hash BYTEA NOT NULL REFERENCES object_index(object_hash),
    PRIMARY KEY(organization_id,destruction_id,object_hash),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_jobs(organization_id,destruction_id)
);
CREATE TABLE destruction_server_measurements (
    organization_id BYTEA NOT NULL, destruction_id BYTEA NOT NULL,
    job_hash BYTEA NOT NULL CHECK(octet_length(job_hash)=32),
    event_hash BYTEA NOT NULL REFERENCES destruction_event_cores(object_hash),
    component_certificate BYTEA NOT NULL CHECK(octet_length(component_certificate)=32),
    controller_certificate BYTEA NOT NULL CHECK(octet_length(controller_certificate)=32),
    attestation_hash BYTEA NOT NULL REFERENCES destruction_attestations(object_hash),
    exact_attestation BYTEA NOT NULL, measured_at_millis BIGINT NOT NULL,
    result_code SMALLINT NOT NULL CHECK(result_code IN(0,1,2)),
    catalog_revision BIGINT NOT NULL,
    PRIMARY KEY(organization_id,destruction_id,attestation_hash),
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_jobs(organization_id,destruction_id)
);
CREATE TRIGGER destruction_job_stubs_immutable BEFORE UPDATE OR DELETE ON destruction_job_stubs
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
CREATE TRIGGER destruction_server_measurements_immutable BEFORE UPDATE OR DELETE ON destruction_server_measurements
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();

CREATE TABLE destruction_attestation_intake (
    object_hash BYTEA PRIMARY KEY REFERENCES destruction_attestations(object_hash),
    job_hash BYTEA NOT NULL CHECK(octet_length(job_hash)=32),
    principal_certificate BYTEA NOT NULL CHECK(octet_length(principal_certificate)=32),
    signer_certificate BYTEA NOT NULL CHECK(octet_length(signer_certificate)=32),
    exact_bytes BYTEA NOT NULL, catalog_revision BIGINT NOT NULL, admitted_at_millis BIGINT NOT NULL
);
CREATE TRIGGER destruction_attestation_intake_immutable BEFORE UPDATE OR DELETE ON destruction_attestation_intake
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();

CREATE TABLE destruction_removed_objects (
    organization_id BYTEA NOT NULL, destruction_id BYTEA NOT NULL,
    object_hash BYTEA NOT NULL,
    attestation_hash BYTEA NOT NULL REFERENCES destruction_attestations(object_hash),
    PRIMARY KEY(organization_id,destruction_id,object_hash),
    FOREIGN KEY(organization_id,destruction_id,object_hash) REFERENCES destruction_job_objects(organization_id,destruction_id,object_hash)
);
CREATE TRIGGER destruction_removed_objects_immutable BEFORE UPDATE OR DELETE ON destruction_removed_objects
    FOR EACH ROW EXECUTE FUNCTION ea_destruction_immutable();
