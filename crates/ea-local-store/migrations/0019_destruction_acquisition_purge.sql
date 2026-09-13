-- Preserve the existing dynamic Writer acquisition source on old installs.
CREATE TABLE IF NOT EXISTS writer_incident_claim (claim_id INTEGER PRIMARY KEY AUTOINCREMENT,draft_id BLOB NOT NULL,draft_revision INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS writer_incident_claim_released (claim_id INTEGER PRIMARY KEY REFERENCES writer_incident_claim(claim_id));
CREATE TABLE IF NOT EXISTS writer_original_identity (entry_hash BLOB PRIMARY KEY NOT NULL,object_hash BLOB NOT NULL,record_id BLOB NOT NULL,sequence INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS writer_original_published (entry_hash BLOB PRIMARY KEY NOT NULL REFERENCES writer_original_identity(entry_hash));

-- These rows exist only inside the verified service's exclusive transaction.
-- Every OLD field must match. No global disable/allow flag exists.
CREATE TABLE destruction_identity_purge_permit (entry_hash BLOB PRIMARY KEY NOT NULL,object_hash BLOB NOT NULL,record_id BLOB NOT NULL,sequence INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL) STRICT;
CREATE TABLE destruction_claim_purge_permit (claim_id INTEGER PRIMARY KEY,draft_id BLOB NOT NULL,draft_revision INTEGER NOT NULL,organization_id BLOB NOT NULL,civil_year INTEGER NOT NULL,incident_number TEXT NOT NULL) STRICT;

DROP TRIGGER IF EXISTS writer_original_identity_no_DELETE;
CREATE TRIGGER writer_original_identity_no_DELETE BEFORE DELETE ON writer_original_identity
WHEN NOT EXISTS(SELECT 1 FROM destruction_identity_purge_permit p WHERE p.entry_hash=OLD.entry_hash AND p.object_hash=OLD.object_hash AND p.record_id=OLD.record_id AND p.sequence=OLD.sequence AND p.organization_id=OLD.organization_id AND p.civil_year=OLD.civil_year AND p.incident_number=OLD.incident_number)
BEGIN SELECT RAISE(ABORT,'append-only'); END;
DROP TRIGGER IF EXISTS writer_original_published_no_DELETE;
CREATE TRIGGER writer_original_published_no_DELETE BEFORE DELETE ON writer_original_published
WHEN NOT EXISTS(SELECT 1 FROM destruction_identity_purge_permit p JOIN writer_original_identity i ON i.entry_hash=p.entry_hash AND i.object_hash=p.object_hash AND i.record_id=p.record_id AND i.sequence=p.sequence AND i.organization_id=p.organization_id AND i.civil_year=p.civil_year AND i.incident_number=p.incident_number WHERE p.entry_hash=OLD.entry_hash)
BEGIN SELECT RAISE(ABORT,'append-only'); END;
DROP TRIGGER IF EXISTS writer_incident_claim_no_DELETE;
CREATE TRIGGER writer_incident_claim_no_DELETE BEFORE DELETE ON writer_incident_claim
WHEN NOT EXISTS(SELECT 1 FROM destruction_claim_purge_permit p WHERE p.claim_id=OLD.claim_id AND p.draft_id=OLD.draft_id AND p.draft_revision=OLD.draft_revision AND p.organization_id=OLD.organization_id AND p.civil_year=OLD.civil_year AND p.incident_number=OLD.incident_number)
BEGIN SELECT RAISE(ABORT,'append-only'); END;
DROP TRIGGER IF EXISTS writer_incident_claim_released_no_DELETE;
CREATE TRIGGER writer_incident_claim_released_no_DELETE BEFORE DELETE ON writer_incident_claim_released
WHEN NOT EXISTS(SELECT 1 FROM destruction_claim_purge_permit p JOIN writer_incident_claim c ON c.claim_id=p.claim_id AND c.draft_id=p.draft_id AND c.draft_revision=p.draft_revision AND c.organization_id=p.organization_id AND c.civil_year=p.civil_year AND c.incident_number=p.incident_number WHERE p.claim_id=OLD.claim_id)
BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS writer_original_identity_no_UPDATE BEFORE UPDATE ON writer_original_identity BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS writer_original_published_no_UPDATE BEFORE UPDATE ON writer_original_published BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS writer_incident_claim_no_UPDATE BEFORE UPDATE ON writer_incident_claim BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS writer_incident_claim_released_no_UPDATE BEFORE UPDATE ON writer_incident_claim_released BEGIN SELECT RAISE(ABORT,'append-only'); END;

CREATE TABLE destruction_acquisition_purge (
    job_hash BLOB PRIMARY KEY NOT NULL CHECK(length(job_hash)=32),
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    exact_measurement BLOB NOT NULL,
    FOREIGN KEY(organization_id,destruction_id) REFERENCES destruction_job(organization_id,destruction_id)
) STRICT;
CREATE TRIGGER destruction_acquisition_purge_no_update BEFORE UPDATE ON destruction_acquisition_purge BEGIN SELECT RAISE(ABORT,'acquisition purge is append-only'); END;
CREATE TRIGGER destruction_acquisition_purge_no_delete BEFORE DELETE ON destruction_acquisition_purge BEGIN SELECT RAISE(ABORT,'acquisition purge is append-only'); END;
