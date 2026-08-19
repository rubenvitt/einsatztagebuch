-- Migration 0001 — die Writer-Tabellen der Stufe 2.
--
-- EINE REGISTRIERTE MIGRATION WIRD NIE MEHR GEAENDERT. Jede weitere
-- Schemaaenderung ist eine neue, aufsteigende Datei; `0002_discard.sql` legt
-- die Uebergangstabelle des Verwerfens an, `0003_master_data.sql` die
-- Aufbewahrungstabelle der exakten `import-report-v1`-Bytes.
--
-- Alle Tabellen sind `STRICT`: SQLite prueft die Spaltentypen dann selbst, und
-- eine Bytefolge kann nicht als Text in eine Blob-Spalte rutschen.

-- 1. Der Einzelentwurf. `design.md`:426 — es existiert GENAU EIN aktiver
--    Entwurf, und `singleton = 0` macht das zur Schemazusage statt zur
--    Programmzusage. Keine fachliche Spalte: der Inhalt liegt ausschliesslich
--    als AEAD-Chiffrat vor, verschluesselt unter dem `draftDEK`, BEVOR die
--    Zeile SQLCipher erreicht.
CREATE TABLE draft (
    singleton              INTEGER PRIMARY KEY CHECK (singleton = 0),
    draft_id               BLOB    NOT NULL CHECK (length(draft_id) = 16),
    payload_ciphertext     BLOB    NOT NULL,
    payload_nonce          BLOB    NOT NULL CHECK (length(payload_nonce) = 12),
    dek_keystore_provider  INTEGER NOT NULL,
    dek_account_instance   BLOB    NOT NULL CHECK (length(dek_account_instance) = 32),
    save_revision          INTEGER NOT NULL CHECK (save_revision >= 0),
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL
) STRICT;

-- 2. Die anhaengende Auditzeile. Sie traegt die EXAKTEN
--    `local-audit-event-v1`-Bytes, ihren `object_hash` und eine monotone
--    Einfuegereihenfolge. Es gibt keinen Aenderungs- und keinen Loeschpfad —
--    weder im Programm noch im Schema: die beiden Trigger brechen jede
--    Aenderung und jede Loeschung ab, auch die einer fremden SQL-Zeile.
CREATE TABLE local_audit_event (
    insertion_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id           BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    exact_bytes        BLOB NOT NULL,
    object_hash        BLOB NOT NULL CHECK (length(object_hash) = 32)
) STRICT;

CREATE TRIGGER local_audit_event_is_append_only_on_update
BEFORE UPDATE ON local_audit_event
BEGIN
    SELECT RAISE(ABORT, 'EA-STORE-AUDIT-APPEND-ONLY');
END;

CREATE TRIGGER local_audit_event_is_append_only_on_delete
BEFORE DELETE ON local_audit_event
BEGIN
    SELECT RAISE(ABORT, 'EA-STORE-AUDIT-APPEND-ONLY');
END;

-- 3. Das Register verbrauchter Einsatznummern. Der Schluessel ist genau der von
--    `design.md`:361-373: Organisation, oertliches Kalenderjahr und die
--    NFC-normalisierten UTF-8-Bytes der menschenlesbaren Nummer. Die Nummer
--    steht als BLOB und nicht als TEXT, damit der Vergleich byteweise ist und
--    keine Kollation ihn aufweichen kann.
--
--    Das Register ist eine ERFASSUNGSQUELLE und kein abgeleiteter Zustand; die
--    Rekonstruktionspflicht aus `design.md` §19.3 gilt ihm deshalb nicht, und
--    eine gesalzene Zusage braucht es nicht. Es liegt in der verschluesselten
--    Datenbank, was `design.md`:1955 verlangt: Klartext-Einsatznummern sind in
--    Protokollen, Abzuegen und unverschluesselter Konfiguration verboten, nicht
--    im verschluesselten lokalen Speicher.
CREATE TABLE incident_number_register (
    organization_id       BLOB    NOT NULL CHECK (length(organization_id) = 16),
    local_civil_year      INTEGER NOT NULL,
    human_incident_number BLOB    NOT NULL,
    claimed_at_ms         INTEGER NOT NULL,
    UNIQUE (organization_id, local_civil_year, human_incident_number)
) STRICT;

-- 4. Die Einzelzeile des Bedienerprofils: die fuenf Zusageeingaben plus der
--    Bindungshash, in genau der Reihenfolge, in der Stufe 1 sie kodiert
--    (`crates/ea-schema/src/model.rs`:86-93, Kodierer
--    `crates/ea-schema/src/encode.rs`:429-445). Stufe 2 KONSUMIERT diese Zeile
--    und stellt sie nie aus: das Ausstellen des Profils und der Root-signierten
--    Bindung ist Stufe-5-Arbeit. Es entsteht kein neues Byte-Urbild — Urbild,
--    Domaintrennung, Kanonisierung und Feldreihenfolge sind eingefroren
--    (`crates/ea-crypto/src/digest.rs`:30, :61).
CREATE TABLE operator_profile (
    singleton                    INTEGER PRIMARY KEY CHECK (singleton = 0),
    organization_id              BLOB NOT NULL CHECK (length(organization_id) = 16),
    operator_subject_id          BLOB NOT NULL CHECK (length(operator_subject_id) = 16),
    display_name                 TEXT NOT NULL,
    function_label               TEXT NOT NULL,
    profile_commitment_salt      BLOB NOT NULL CHECK (length(profile_commitment_salt) = 32),
    operator_binding_object_hash BLOB NOT NULL CHECK (length(operator_binding_object_hash) = 32)
) STRICT;
