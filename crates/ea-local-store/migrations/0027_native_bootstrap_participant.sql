-- Private SQLCipher-only preparation journal; no certificate, active binding,
-- Registry, backup confirmation or bootstrap Step-3 authority.
CREATE TABLE native_bootstrap_participant (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    exact_journal BLOB NOT NULL CHECK (
        typeof(exact_journal) = 'blob'
        AND length(exact_journal) > 0
        AND length(exact_journal) <= 4194304
    )
) STRICT;
