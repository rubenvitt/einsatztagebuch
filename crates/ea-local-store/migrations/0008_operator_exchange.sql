-- Target-side public object staging and replayable revocation delivery.
CREATE TABLE operator_pending_exchange (
    operation_hash BLOB PRIMARY KEY CHECK(length(operation_hash)=32),
    request_bytes BLOB NOT NULL,
    reply_private_key BLOB NOT NULL CHECK(length(reply_private_key)=32)
) STRICT;
CREATE TABLE operator_remote_object (
    object_hash BLOB PRIMARY KEY CHECK(length(object_hash)=32),
    exact_bytes BLOB NOT NULL
) STRICT;
CREATE TABLE operator_revocation_journal (
    binding_hash BLOB PRIMARY KEY CHECK(length(binding_hash)=32),
    authorization BLOB NOT NULL,
    registry BLOB NOT NULL
) STRICT;
