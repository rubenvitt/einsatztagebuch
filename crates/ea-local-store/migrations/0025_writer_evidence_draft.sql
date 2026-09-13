-- One ordinary draft, routed to its immutable destruction job.
-- No archive object, payload codec, signing context, or action authority.
CREATE TABLE writer_evidence_draft (
    singleton INTEGER PRIMARY KEY CHECK(singleton=0),
    draft_id BLOB NOT NULL CHECK(length(draft_id)=16),
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
    preflight_hash BLOB NOT NULL CHECK(length(preflight_hash)=32),
    FOREIGN KEY(singleton) REFERENCES draft(singleton) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,destruction_id)
        REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER writer_evidence_draft_no_update BEFORE UPDATE ON writer_evidence_draft
BEGIN SELECT RAISE(ABORT,'EA-DRAFT-EVIDENCE-BINDING'); END;
