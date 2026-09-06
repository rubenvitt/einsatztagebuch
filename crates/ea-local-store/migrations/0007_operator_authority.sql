-- Dedicated authority state; the whole database is SQLCipher protected.
-- Request bodies contain public references; replies are already HPKE encrypted.
CREATE TABLE operator_authority_request (
    request_hash BLOB PRIMARY KEY CHECK(length(request_hash)=32),
    request_bytes BLOB NOT NULL CHECK(length(request_bytes) BETWEEN 1 AND 262144),
    reply_bytes BLOB CHECK(reply_bytes IS NULL OR length(reply_bytes) BETWEEN 1 AND 262144),
    state INTEGER NOT NULL CHECK(state IN (0,1)),
    CHECK((state=0 AND reply_bytes IS NULL) OR (state=1 AND reply_bytes IS NOT NULL))
) STRICT;
-- A short-lived physical identity attestation, never a plaintext exchange file.
CREATE TABLE operator_authority_identity (
    target_certificate_hash BLOB PRIMARY KEY CHECK(length(target_certificate_hash)=32),
    registry_head_hash BLOB NOT NULL CHECK(length(registry_head_hash)=32),
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    operator_subject_id BLOB NOT NULL CHECK(length(operator_subject_id)=16),
    role TEXT NOT NULL CHECK(role IN ('writer','reader','organization-admin')),
    display_name TEXT NOT NULL,
    function_label TEXT NOT NULL,
    profile_commitment_salt BLOB NOT NULL CHECK(length(profile_commitment_salt)=32),
    previous_binding_hash BLOB CHECK(previous_binding_hash IS NULL OR length(previous_binding_hash)=32),
    attested_at INTEGER NOT NULL
) STRICT;
-- Exact public objects issued by this authority, also used to scope audit replies.
CREATE TABLE operator_authority_target (
    target_hash BLOB PRIMARY KEY CHECK(length(target_hash)=32),
    authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
    request_hash BLOB NOT NULL REFERENCES operator_authority_request(request_hash),
    target_certificate_hash BLOB NOT NULL CHECK(length(target_certificate_hash)=32),
    authorization BLOB NOT NULL,
    target BLOB NOT NULL,
    action_code INTEGER NOT NULL CHECK(action_code IN (1,4))
) STRICT;
