-- Local publication fence only. No new archive or trust wire object.
CREATE TABLE writer_destruction_evidence (
    entry_hash BLOB PRIMARY KEY CHECK(length(entry_hash)=32),
    entry_object_hash BLOB NOT NULL CHECK(length(entry_object_hash)=32),
    exact_binding BLOB NOT NULL,
    binding_hash BLOB NOT NULL CHECK(length(binding_hash)=32)
) STRICT;
CREATE TRIGGER writer_destruction_evidence_no_update BEFORE UPDATE ON writer_destruction_evidence
BEGIN SELECT RAISE(ABORT,'evidence publication bindings are immutable'); END;
CREATE TRIGGER writer_destruction_evidence_no_delete BEFORE DELETE ON writer_destruction_evidence
BEGIN SELECT RAISE(ABORT,'evidence publication bindings are immutable'); END;
