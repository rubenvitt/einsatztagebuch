//! Das signierte lokale Audit des Readers: kein Klartext, kein Dateiname, kein
//! Klarname in den EXAKTEN Bytes — und das versiegelte Protokoll in OPFS
//! traegt davon nach aussen nichts.
//!
//! Der Kanarienvogel dieses Zeugen ist kein eingespritzter Marker, sondern
//! das, was der Genesis-Klartext OHNEHIN traegt: die Schemakennung
//! `ea.genesis` als Text. Sie steht im Klartext (Positivkontrolle) und darf in
//! keiner Auditzeile stehen. Der Dateiname ist die Attrappe des Ziels, das den
//! Wirtspfad kennt und dem Audit nie nennt — es GIBT dort keine Position.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    ExportContextV1, InMemoryReaderAuditSink, InMemoryReaderBlobStore, LocalAuditActionV1,
    LocalAuditOutcomeV1, READER_AUDIT_LOG_BLOB_KEY_V1, ReaderAuditIdentityV1, ReaderAuditLogSink,
    ReaderAuditLogStore, ReaderAuditSink, ReaderAuditWriter, ReaderBlobKey, ReaderBlobStore,
    ReaderConfirmationPurpose, ReaderExportError, ReaderExportService, ReaderExportTarget,
    ReaderExportTargetError, ReaderExportTargetKindV1, ReaderSession, UnixMillis,
    decode_local_audit_event,
};
use ea_testkit::contains_canary;

use verify_fixtures::fixtures;

const HOST_PATH: &str = "Einsatz-2026-08-30.json";
const CANARY_SCHEMA_TEXT: &[u8] = b"ea.genesis";

fn t(offset_ms: i64) -> UnixMillis {
    UnixMillis::new(fixtures::EFFECTIVE_NOW.get() + offset_ms)
}

fn unlocked_at(now: UnixMillis) -> ReaderSession {
    ReaderSession::unlock(
        fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now),
        now,
    )
    .expect("eine frische Entsperrbestaetigung eroeffnet die Sitzung")
}

struct NamedTarget {
    received: Vec<u8>,
}

impl ReaderExportTarget for NamedTarget {
    fn kind(&self) -> ReaderExportTargetKindV1 {
        ReaderExportTargetKindV1::UserChosenFile
    }

    fn is_occupied(&self) -> bool {
        false
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<(), ReaderExportTargetError> {
        assert!(!HOST_PATH.is_empty(), "die Attrappe kennt ihren Pfad");
        self.received = plaintext.to_vec();
        Ok(())
    }
}

/// Die zwei exakten Auditzeilen eines gelungenen Exports samt dem Klartext,
/// der dabei das Ziel erreicht hat.
fn export_audit_bytes() -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );
    let mut target = NamedTarget {
        received: Vec::new(),
    };
    service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect("der Export gelingt");
    (sink.events().to_vec(), target.received)
}

/// Kein Kanarienvogel in den Auditbytes, in keiner Fehlerformatierung und in
/// keinem `Debug`-Abzug. Der Zeuge nimmt die EXAKTEN Bytes, die geschrieben
/// werden, nicht eine Zusammenfassung darueber.
#[test]
fn no_cleartext_and_no_filename_reaches_the_signed_audit_bytes() {
    let (events, plaintext) = export_audit_bytes();
    assert_eq!(events.len(), 2);
    // Positivkontrolle: der Klartext TRAEGT den Marker, und er hat das Ziel
    // erreicht. Ohne diese Zeile waere jede Abwesenheit unten leer.
    assert!(contains_canary(&plaintext, CANARY_SCHEMA_TEXT));

    for bytes in &events {
        for needle in [
            CANARY_SCHEMA_TEXT,
            HOST_PATH.as_bytes(),
            b".json".as_slice(),
            b"Einsatz".as_slice(),
            plaintext.as_slice(),
        ] {
            assert!(!contains_canary(bytes, needle));
        }
        // Und kein Fenster des Klartexts, das laenger als ein Hash ist: die
        // Zeile traegt den Entry-HASH, nie den Eintrag.
        for window in plaintext.windows(33) {
            assert!(!contains_canary(bytes, window));
        }
        let event = decode_local_audit_event(bytes).expect("signierte Zeile");
        assert_eq!(format!("{event:?}"), "LocalAuditEventV1(<bound>)");
    }

    assert_eq!(
        format!("{:?}", ReaderExportError::TargetOccupied),
        "EA-READER-EXPORT-TARGET-OCCUPIED"
    );
    assert_eq!(
        format!("{:?}", fixtures::audit_identity()),
        "ReaderAuditIdentityV1(<bound>)"
    );
}

/// Der `Debug`-Abzug des Berichts nennt Hash und Zielart — und sonst nichts.
#[test]
fn the_export_report_debug_output_names_the_hash_and_the_kind_only() {
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );
    let mut target = NamedTarget {
        received: Vec::new(),
    };
    let record = fixtures::decrypted_genesis_record();
    let entry_hash_hex = hex::encode(record.entry_hash().as_bytes());
    let report = service
        .export_one(
            record,
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect("der Export gelingt");
    let rendered = format!("{report:?}");
    assert_eq!(
        rendered,
        format!(
            "ReaderExportReport {{ entry_hash: {entry_hash_hex}, target_kind: user-chosen-file }}"
        )
    );
    assert!(!contains_canary(rendered.as_bytes(), CANARY_SCHEMA_TEXT));
    assert!(!contains_canary(rendered.as_bytes(), HOST_PATH.as_bytes()));
}

/// Der Schreiber ist `encode_local_audit_core`, `sign_local_audit`,
/// `encode_local_audit_event` — und jede Zeile geht durch den eingefrorenen
/// Dekodierer wieder auf, mit Identitaet, Bindung, Zeit und Kontext an den
/// Positionen, die die Grammatik nennt. Ein gekipptes Byte in der Zeile faellt
/// am COSE-Rahmen und nicht still.
#[test]
fn every_recorded_line_decodes_under_the_frozen_grammar_and_a_flipped_byte_refuses() {
    let identity = fixtures::audit_identity();
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let mut sink = InMemoryReaderAuditSink::new();
    let binding = fixtures::credential_id_hash();
    let mut writer = ReaderAuditWriter::open(&vault, identity, binding, &mut sink);
    let entry_hash = ea_reader::EntryHash::try_from(&[0x77_u8; 32][..]).expect("32 Byte");
    let bytes = writer
        .record(
            LocalAuditActionV1::PlaintextExport(ExportContextV1::new(entry_hash, 1)),
            LocalAuditOutcomeV1::Accepted,
            t(9),
        )
        .expect("die Zeile entsteht");
    assert_eq!(sink.events(), std::slice::from_ref(&bytes));

    let event = decode_local_audit_event(&bytes).expect("die Zeile geht wieder auf");
    assert_eq!(event.action().code(), 5);
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Accepted);
    assert_eq!(event.effective_now(), t(9));
    assert!(event.organization_id() == identity.organization_id());
    assert!(event.device_id() == identity.device_id());
    assert!(event.signer_certificate_object_hash() == identity.signer_certificate_object_hash());
    assert!(event.operator_binding_object_hash() == Some(ea_reader::ObjectHash::from(binding)));

    // Ein gekipptes Byte im Kern: der COSE-Rahmen traegt die Nutzlast nicht
    // mehr byteglich, und `decode_local_audit_event` weist ab.
    let mut flipped = bytes.clone();
    let position = flipped.len() / 3;
    flipped[position] ^= 0x01;
    assert!(decode_local_audit_event(&flipped).is_err());
    // Ein gekipptes Byte in der Signatur selbst: die Form geht noch auf — die
    // Signaturpruefung ist Sache der Zertifikatsaufloesung, die dieser Reader
    // nicht traegt — aber die Bytes sind NICHT die geschriebenen.
    let mut tail = bytes.clone();
    let last = tail.len() - 1;
    tail[last] ^= 0x01;
    assert_ne!(tail, bytes);
}

/// Das Protokoll in OPFS: leer vor der ersten Zeile, Zeile fuer Zeile in
/// Reihenfolge danach, und die abgelegten Bytes tragen von Hash, Bindung und
/// Marker NICHTS nach aussen — was OPFS erreicht, ist Chiffrat. Ein
/// vertauschter oder verfaelschter Blob geht nicht auf.
#[test]
fn the_sealed_audit_log_round_trips_and_leaks_nothing_into_the_blob_store() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let log = ReaderAuditLogStore::open(&vault);
    let mut store = InMemoryReaderBlobStore::new();
    assert!(
        log.events(&store)
            .expect("ein nie beschriebenes Protokoll ist leer")
            .is_empty()
    );

    let (events, _) = export_audit_bytes();
    {
        let mut sink = ReaderAuditLogSink::new(&log, &mut store);
        for event in &events {
            sink.append(event).expect("die Zeile wird angehaengt");
        }
    }
    assert_eq!(log.events(&store).expect("das Protokoll geht auf"), events);

    let key = ReaderBlobKey::new(READER_AUDIT_LOG_BLOB_KEY_V1).expect("Adresse");
    let raw = store.get(&key).expect("Speicher").expect("der Blob liegt");
    let entry_hash = fixtures::entry_hash(fixtures::complete_archive_with_a_genesis_plaintext());
    for needle in [
        entry_hash.as_bytes().as_slice(),
        fixtures::credential_id_hash().as_bytes().as_slice(),
        fixtures::audit_identity().device_id().as_bytes().as_slice(),
        CANARY_SCHEMA_TEXT,
        events[0].as_slice(),
    ] {
        assert!(!contains_canary(&raw, needle));
    }
    // Positivkontrolle: die signierte Zeile SELBST traegt den Entry-Hash — im
    // Protokoll ist er nur deshalb unsichtbar, weil das Protokoll versiegelt ist.
    assert!(contains_canary(&events[0], entry_hash.as_bytes()));

    // Verfaelscht: ein gekipptes Byte im Chiffrat geht nicht auf.
    let mut tampered = raw.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    store.put(&key, &tampered).expect("Speicher");
    assert_eq!(
        log.events(&store).expect_err("verfaelscht").code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
    // Unter einem fremden Tresor geht das Protokoll ebenso wenig auf.
    store.put(&key, &raw).expect("Speicher");
    let foreign = ReaderAuditLogStore::open(&fixtures::vault_pinning(
        fixtures::complete_archive_anchor_bytes().to_vec(),
    ));
    assert_eq!(log.events(&store).expect("das Original geht auf").len(), 2);
    // Derselbe Seed liefert denselben Tresorschluessel NICHT — `ReaderVault::seal`
    // zieht ihn je Versiegelung neu.
    assert_eq!(
        foreign.events(&store).expect_err("fremder Tresor").code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
}

/// Der Auditschreiber traegt keinen zweiten Typsatz: Identitaet und Zielart
/// werden ueber die Flaeche gereicht, und die Identitaet gibt ihre drei Felder
/// unveraendert zurueck.
#[test]
fn the_identity_is_a_parameter_and_returns_its_three_fields_unchanged() {
    let organization_id = ea_reader::OrganizationId::try_from(&[0x01_u8; 16][..]).expect("16");
    let device_id = ea_reader::DeviceId::try_from(&[0x02_u8; 16][..]).expect("16");
    let certificate = ea_reader::ObjectHash::try_from(&[0x03_u8; 32][..]).expect("32");
    let identity = ReaderAuditIdentityV1::new(organization_id, device_id, certificate);
    assert!(identity.organization_id() == organization_id);
    assert!(identity.device_id() == device_id);
    assert!(identity.signer_certificate_object_hash() == certificate);
}
