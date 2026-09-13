-- Internal operational evidence, not an archive or Registry authority object.
CREATE TABLE go_live_posture_evidence (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 0),
  object_hash BLOB NOT NULL CHECK (length(object_hash) = 32),
  issued_at INTEGER NOT NULL,
  exact_envelope BLOB NOT NULL CHECK (length(exact_envelope) BETWEEN 1 AND 8192)
);
-- An OS rollback cannot resurrect an expired local evidence window on reopen.
CREATE TABLE go_live_posture_issued (
  object_hash BLOB PRIMARY KEY CHECK (length(object_hash) = 32),
  exact_envelope BLOB NOT NULL CHECK (length(exact_envelope) BETWEEN 1 AND 8192)
);
-- This local observation never raises the authenticated trust time floor.
CREATE TABLE go_live_posture_clock (
  installation_id BLOB PRIMARY KEY CHECK (length(installation_id) = 32),
  last_observed_wall INTEGER NOT NULL
);
