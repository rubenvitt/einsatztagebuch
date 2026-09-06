-- Public signed material retained before the single publication transaction.
-- Exact request ownership is the canonical authenticated envelope hash.
CREATE TABLE operator_authority_staged (
    request_hash BLOB PRIMARY KEY CHECK(length(request_hash)=32),
    authorization BLOB NOT NULL CHECK(length(authorization) BETWEEN 1 AND 49152),
    target_payload BLOB NOT NULL CHECK(length(target_payload) BETWEEN 1 AND 49152),
    root_signature BLOB CHECK(root_signature IS NULL OR length(root_signature) BETWEEN 1 AND 4096),
    FOREIGN KEY(request_hash) REFERENCES operator_authority_request(request_hash)
) STRICT;
