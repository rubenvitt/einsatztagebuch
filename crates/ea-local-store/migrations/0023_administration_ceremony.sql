-- Native-only exact ceremony journal. No public archive wire changes.
CREATE TABLE administration_ceremony_intent (
  intent_hash BLOB PRIMARY KEY NOT NULL CHECK(length(intent_hash)=32),
  organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
  chain_id BLOB NOT NULL CHECK(length(chain_id)=16),
  trust_anchor_hash BLOB NOT NULL CHECK(length(trust_anchor_hash)=32),
  admin_certificate_hash BLOB NOT NULL CHECK(length(admin_certificate_hash)=32),
  admin_binding_hash BLOB NOT NULL CHECK(length(admin_binding_hash)=32),
  registry_version INTEGER NOT NULL CHECK(registry_version>=0),
  registry_head_hash BLOB NOT NULL CHECK(length(registry_head_hash)=32),
  proposed_sequence INTEGER NOT NULL CHECK(proposed_sequence>=0),
  target_payload BLOB NOT NULL CHECK(length(target_payload) BETWEEN 1 AND 65536),
  source_kind INTEGER NOT NULL CHECK(source_kind BETWEEN 0 AND 2),
  source_bytes BLOB CHECK(source_bytes IS NULL OR length(source_bytes) BETWEEN 1 AND 65536),
  ceremony_round INTEGER NOT NULL CHECK(ceremony_round IN (0,1)),
  parent_intent_hash BLOB REFERENCES administration_ceremony_intent(intent_hash),
  created_at INTEGER NOT NULL CHECK(created_at>=0),
  CHECK((source_kind=0 AND source_bytes IS NULL) OR (source_kind IN(1,2) AND source_bytes IS NOT NULL))
) STRICT;
-- Exact evidence is appended for one reached step; a step flag alone never
-- authorizes signing, export or publication. Reopening verifies exact records.
CREATE TABLE administration_ceremony_record (
  intent_hash BLOB NOT NULL REFERENCES administration_ceremony_intent(intent_hash),
  stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 5),
  exact_record BLOB NOT NULL CHECK(length(exact_record) BETWEEN 1 AND 262144),
  audit_event_id BLOB REFERENCES local_audit_event(event_id),
  PRIMARY KEY(intent_hash,stage),
  CHECK(audit_event_id IS NULL OR length(audit_event_id)=16)
) STRICT;
-- Root signature staging belongs to the existing authenticated request journal.
CREATE TABLE administration_root_artifact (
  request_hash BLOB NOT NULL REFERENCES operator_authority_request(request_hash),
  artifact_kind INTEGER NOT NULL CHECK(artifact_kind BETWEEN 0 AND 2),
  exact_bytes BLOB NOT NULL CHECK(length(exact_bytes) BETWEEN 1 AND 262144),
  PRIMARY KEY(request_hash,artifact_kind)
) STRICT;
CREATE TRIGGER administration_intent_no_update BEFORE UPDATE ON administration_ceremony_intent
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
CREATE TRIGGER administration_intent_no_delete BEFORE DELETE ON administration_ceremony_intent
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
CREATE TRIGGER administration_record_no_update BEFORE UPDATE ON administration_ceremony_record
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
CREATE TRIGGER administration_record_no_delete BEFORE DELETE ON administration_ceremony_record
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
CREATE TRIGGER administration_artifact_no_update BEFORE UPDATE ON administration_root_artifact
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
CREATE TRIGGER administration_artifact_no_delete BEFORE DELETE ON administration_root_artifact
BEGIN SELECT RAISE(ABORT,'EA-ADMINISTRATION-IMMUTABLE'); END;
