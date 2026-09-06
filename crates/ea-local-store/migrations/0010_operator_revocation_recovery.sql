-- Freeze the exact target before the first offline authorization request.
-- Only public Root signatures are retained; private Root material never enters
-- the target host. Replay rows, audit and the final journal commit together.
CREATE TABLE operator_revocation_intent (
    binding_hash BLOB PRIMARY KEY CHECK(length(binding_hash)=32),
    chain_id BLOB NOT NULL CHECK(length(chain_id)=16),
    admin_binding_hash BLOB NOT NULL CHECK(length(admin_binding_hash)=32),
    admin_certificate_hash BLOB NOT NULL CHECK(length(admin_certificate_hash)=32),
    target_payload BLOB NOT NULL,
    authorization BLOB,
    root_signature BLOB,
    CHECK(root_signature IS NULL OR authorization IS NOT NULL)
) STRICT;
