-- Technischer Index der angenommenen Reader-Key-Escrows (v1.1-Profil §3.1),
-- KEINE Autorität: gültig ist, was ea-trust beweist. Die eigentliche Sperre
-- gegen zwei gleichzeitige Escrows ist der Katalogzaun beim Indexieren; diese
-- Tabelle ist der Rückfall und hält höchstens EIN Escrow je
-- Reader-Zertifikat fest. Ein zweites, byte-verschiedenes Escrow zum selben
-- Zertifikat ist nie zulässig (Konflikt, solange das erste gilt; inaktiv nach
-- einem Widerruf).
--
-- Die Personenkennung ist bewusst NICHT eindeutig: der Ersatz nach U2 ist ein
-- neues Zertifikat zur selben Person, und ob das alte widerrufen ist, hängt
-- am gewählten Kopf, den die Datenbank nicht kennt.
CREATE TABLE reader_key_escrows (
    -- Kein Fremdschlüssel auf trust_events: eine Katalogreparatur darf
    -- trust_events weiter leeren (0002, TRUNCATE-Trigger). Die Zeile entsteht
    -- ausschließlich in derselben Transaktion wie ihr Trust-Ereignis.
    object_hash BYTEA PRIMARY KEY CHECK (octet_length(object_hash) = 32),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    reader_certificate_object_hash BYTEA NOT NULL
        CHECK (octet_length(reader_certificate_object_hash) = 32),
    reader_subject_id BYTEA NOT NULL CHECK (octet_length(reader_subject_id) = 16),
    UNIQUE (organization_id, reader_certificate_object_hash)
);

CREATE INDEX reader_key_escrows_subject
    ON reader_key_escrows (organization_id, reader_subject_id);

-- Append-only wie die Vernichtungsbelege: ein Escrow wird nie umgeschrieben.
CREATE FUNCTION ea_reader_key_escrow_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable reader key escrow index'; END;
$$;
CREATE TRIGGER reader_key_escrows_immutable BEFORE UPDATE OR DELETE ON reader_key_escrows
    FOR EACH ROW EXECUTE FUNCTION ea_reader_key_escrow_immutable();
