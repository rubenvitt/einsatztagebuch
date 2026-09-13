-- Empty required layout directories are durable state, not queue objects.
CREATE TABLE local_commit_directory (
    namespace BLOB NOT NULL REFERENCES local_commit_scope(namespace),
    directory TEXT NOT NULL CHECK(length(directory) BETWEEN 1 AND 4096),
    PRIMARY KEY(namespace, directory)
) STRICT;
CREATE TRIGGER local_commit_directory_no_update BEFORE UPDATE ON local_commit_directory
BEGIN SELECT RAISE(ABORT, 'immutable local archive directory'); END;
CREATE TRIGGER local_commit_directory_no_delete BEFORE DELETE ON local_commit_directory
BEGIN SELECT RAISE(ABORT, 'immutable local archive directory'); END;

-- One locally registered archive component per independent anchor. A changed
-- profile cannot silently choose an empty namespace and orphan pending bytes.
-- An audited profile migration needs its own explicit transition integration;
-- the native opener itself can neither replace nor delete this binding.
CREATE TABLE native_archive_component (
    anchor_hash BLOB PRIMARY KEY CHECK(length(anchor_hash) = 32),
    profile_hash BLOB NOT NULL CHECK(length(profile_hash) = 32),
    namespace BLOB NOT NULL UNIQUE REFERENCES local_commit_scope(namespace),
    exact_profile BLOB NOT NULL CHECK(length(exact_profile) BETWEEN 1 AND 65536)
) STRICT;
CREATE TRIGGER native_archive_component_no_update BEFORE UPDATE ON native_archive_component
BEGIN SELECT RAISE(ABORT, 'immutable native archive component'); END;
CREATE TRIGGER native_archive_component_no_delete BEFORE DELETE ON native_archive_component
BEGIN SELECT RAISE(ABORT, 'immutable native archive component'); END;
