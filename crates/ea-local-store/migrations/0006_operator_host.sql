-- Profile stays in operator_profile. This singleton owns only unpublished signed
-- objects and publication progress; it commits atomically with the profile CAS.
CREATE TABLE operator_binding_journal (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 0),
    binding_hash BLOB NOT NULL CHECK (length(binding_hash) = 32),
    chain_id BLOB NOT NULL CHECK (length(chain_id) = 16),
    previous_binding_hash BLOB CHECK (previous_binding_hash IS NULL OR length(previous_binding_hash) = 32),
    binding_authorization BLOB NOT NULL CHECK (length(binding_authorization) BETWEEN 1 AND 1048576),
    binding BLOB NOT NULL CHECK (length(binding) BETWEEN 1 AND 1048576),
    activation_authorization BLOB CHECK (activation_authorization IS NULL OR length(activation_authorization) BETWEEN 1 AND 1048576),
    activation BLOB CHECK (activation IS NULL OR length(activation) BETWEEN 1 AND 1048576),
    valid_through BLOB NOT NULL CHECK (length(valid_through) = 8),
    not_after INTEGER NOT NULL,
    prepared_at INTEGER NOT NULL,
    activation_issued_at INTEGER,
    -- 0 binding prepared; 1 activation request frozen (authorization may be unknown); 2 ready; 3 publication uncertain;
    -- 4 published; 5 active; 6 abandoned.
    state INTEGER NOT NULL CHECK (state IN (0,1,2,3,4,5,6)),
    CHECK ((state = 0 AND activation_authorization IS NULL AND activation IS NULL)
        OR (state = 1 AND activation IS NULL AND activation_issued_at IS NOT NULL)
        OR (state IN (2,3,4,5) AND activation_authorization IS NOT NULL AND activation IS NOT NULL AND activation_issued_at IS NOT NULL)
        OR state = 6)
) STRICT;
