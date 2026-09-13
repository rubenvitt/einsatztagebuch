-- Encrypted local commit bytes, scoped to one pinned archive configuration.
CREATE TABLE local_commit_scope (
    namespace BLOB PRIMARY KEY CHECK(length(namespace) = 32),
    object_limit INTEGER NOT NULL CHECK(object_limit > 0),
    byte_limit INTEGER NOT NULL CHECK(byte_limit > 0)
) STRICT;
CREATE TABLE local_commit_object (
    namespace BLOB NOT NULL REFERENCES local_commit_scope(namespace),
    relative_path TEXT NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096),
    exact_bytes BLOB NOT NULL,
    PRIMARY KEY(namespace, relative_path)
) STRICT;
CREATE TABLE local_commit_probe (
    namespace BLOB PRIMARY KEY REFERENCES local_commit_scope(namespace),
    probe_bytes BLOB NOT NULL
) STRICT;
CREATE TRIGGER local_commit_scope_no_update BEFORE UPDATE ON local_commit_scope
BEGIN SELECT RAISE(ABORT, 'immutable local commit scope'); END;
CREATE TRIGGER local_commit_scope_no_delete BEFORE DELETE ON local_commit_scope
BEGIN SELECT RAISE(ABORT, 'immutable local commit scope'); END;
CREATE TRIGGER local_commit_object_no_update BEFORE UPDATE ON local_commit_object
BEGIN SELECT RAISE(ABORT, 'immutable local commit bytes'); END;
