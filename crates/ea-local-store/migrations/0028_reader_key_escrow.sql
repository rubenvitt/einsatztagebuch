-- Reader-Key-Escrow v1.1 (Profil §5 und §8, DRK-458). Nur Hashes, exakte
-- Objektbytes und der versiegelte Umschlag; kein Klartext, kein PIN, kein Pfad.
-- Der Verbrauch von authorization-id und nonce liegt im geteilten Namensraum
-- operator_admin_replay (Dimension 0 und 1) und nicht hier.

-- Zeremonie A: die exakt publizierten Bytes, append-only. package_hash ist der
-- Objekthash der Paketdatei und trägt die Idempotenz derselben Übergabe.
CREATE TABLE reader_key_escrow_publication (
  package_hash BLOB PRIMARY KEY NOT NULL CHECK(length(package_hash)=32),
  organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
  reader_certificate_hash BLOB NOT NULL CHECK(length(reader_certificate_hash)=32),
  reader_subject_id BLOB NOT NULL CHECK(length(reader_subject_id)=16),
  approval_object_hash BLOB NOT NULL UNIQUE CHECK(length(approval_object_hash)=32),
  escrow_object_hash BLOB NOT NULL UNIQUE CHECK(length(escrow_object_hash)=32),
  exact_approval BLOB NOT NULL CHECK(length(exact_approval) BETWEEN 1 AND 65536),
  exact_escrow BLOB NOT NULL CHECK(length(exact_escrow) BETWEEN 1 AND 65536),
  audit_event_id BLOB NOT NULL UNIQUE CHECK(length(audit_event_id)=16),
  FOREIGN KEY(audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER reader_key_escrow_publication_no_update BEFORE UPDATE ON reader_key_escrow_publication
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-PUBLICATION-IMMUTABLE'); END;
CREATE TRIGGER reader_key_escrow_publication_no_delete BEFORE DELETE ON reader_key_escrow_publication
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-PUBLICATION-IMMUTABLE'); END;

-- Zeremonie B: der Verbrauch einer Öffnungsautorisierung. NIE zurückgesetzt,
-- damit ein Versuch gelingt (Profil §8).
CREATE TABLE reader_key_escrow_opening (
  authorization_object_hash BLOB PRIMARY KEY NOT NULL CHECK(length(authorization_object_hash)=32),
  organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
  escrow_object_hash BLOB NOT NULL CHECK(length(escrow_object_hash)=32),
  target_transport_key_thumbprint BLOB NOT NULL CHECK(length(target_transport_key_thumbprint)=32),
  consumed_at_ms INTEGER NOT NULL,
  consume_audit_event_id BLOB NOT NULL UNIQUE CHECK(length(consume_audit_event_id)=16),
  FOREIGN KEY(consume_audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER reader_key_escrow_opening_no_update BEFORE UPDATE ON reader_key_escrow_opening
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-CONSUMPTION-IMMUTABLE'); END;
CREATE TRIGGER reader_key_escrow_opening_no_delete BEFORE DELETE ON reader_key_escrow_opening
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-CONSUMPTION-IMMUTABLE'); END;

-- Das dauerhafte verschlüsselte Ergebnis: die EINZIGE Tabelle mit DELETE.
-- Höchstens eines je Autorisierung, immer an den Abdruck seines Verbrauchs
-- gebunden — eine Umverschlüsselung an einen anderen Schlüssel ist schon hier
-- ausgeschlossen. Die Höchsthaltedauer von 86 400 000 ms steht im Schema.
CREATE TABLE reader_key_escrow_result (
  authorization_object_hash BLOB PRIMARY KEY NOT NULL
    REFERENCES reader_key_escrow_opening(authorization_object_hash),
  target_transport_key_thumbprint BLOB NOT NULL CHECK(length(target_transport_key_thumbprint)=32),
  exact_envelope BLOB NOT NULL CHECK(length(exact_envelope) BETWEEN 1 AND 4096),
  stored_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms = stored_at_ms + 86400000)
) STRICT;

-- Der Abschluss eines Ergebnisses: abgeholt (0) oder verfallen (1). Er steht
-- VOR der Löschung, sperrt jede Neuanlage und ist selbst unveränderlich.
CREATE TABLE reader_key_escrow_result_closure (
  authorization_object_hash BLOB PRIMARY KEY NOT NULL
    REFERENCES reader_key_escrow_opening(authorization_object_hash),
  reason INTEGER NOT NULL CHECK(reason IN (0,1)),
  closed_at_ms INTEGER NOT NULL,
  audit_event_id BLOB NOT NULL UNIQUE CHECK(length(audit_event_id)=16),
  FOREIGN KEY(audit_event_id) REFERENCES local_audit_event(event_id)
) STRICT;
CREATE TRIGGER reader_key_escrow_result_closure_needs_result BEFORE INSERT ON reader_key_escrow_result_closure
WHEN NOT EXISTS (
  SELECT 1 FROM reader_key_escrow_result
  WHERE authorization_object_hash = NEW.authorization_object_hash
)
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-RESULT-MISSING'); END;
CREATE TRIGGER reader_key_escrow_result_closure_no_update BEFORE UPDATE ON reader_key_escrow_result_closure
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-CLOSURE-IMMUTABLE'); END;
CREATE TRIGGER reader_key_escrow_result_closure_no_delete BEFORE DELETE ON reader_key_escrow_result_closure
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-CLOSURE-IMMUTABLE'); END;

-- Die Bindung des Ergebnisses; nach beiden Tabellen angelegt, weil sie beide
-- nennt.
CREATE TRIGGER reader_key_escrow_result_no_update BEFORE UPDATE ON reader_key_escrow_result
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-RESULT-IMMUTABLE'); END;
CREATE TRIGGER reader_key_escrow_result_bound_insert BEFORE INSERT ON reader_key_escrow_result
WHEN NOT EXISTS (
    SELECT 1 FROM reader_key_escrow_opening
    WHERE authorization_object_hash = NEW.authorization_object_hash
      AND target_transport_key_thumbprint = NEW.target_transport_key_thumbprint
  )
  OR EXISTS (
    SELECT 1 FROM reader_key_escrow_result_closure
    WHERE authorization_object_hash = NEW.authorization_object_hash
  )
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-RESULT-UNBOUND'); END;
CREATE TRIGGER reader_key_escrow_result_closed_delete BEFORE DELETE ON reader_key_escrow_result
WHEN NOT EXISTS (
  SELECT 1 FROM reader_key_escrow_result_closure
  WHERE authorization_object_hash = OLD.authorization_object_hash
)
BEGIN SELECT RAISE(ABORT,'EA-ESCROW-RESULT-UNCLOSED'); END;
