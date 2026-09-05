//! Der authenticator-bestaetigte Einzelexport nach `web-reader-design.md`
//! §8.2: bewusste Zielwahl, frische Bestaetigung, GENAU EIN Datensatz je
//! Aufruf, und zwei signierte Auditzeilen um die unwiderrufliche Grenze.
//!
//! Die vier Abbruchpunkte des Abschnitts `session-and-export` in
//! `docs/traceability/stage-4-fault-points.json` haben ihre Zeugen hier und in
//! `session_lock.rs`; jeder ist eine Rust-Testfunktion, weil `witness_resolves`
//! nur solche aufloest.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    InMemoryReaderAuditSink, LocalAuditOutcomeV1, READER_BACKGROUND_INACTIVITY_MS_V1,
    READER_CONFIRMATION_VALIDITY_MS_V1, READER_INACTIVITY_MS_V1, ReaderAuditError, ReaderAuditSink,
    ReaderConfirmationPurpose, ReaderExportError, ReaderExportService, ReaderExportTarget,
    ReaderExportTargetError, ReaderExportTargetKindV1, ReaderSession, ReaderSessionState,
    TabVisibility, UnixMillis, decode_local_audit_event,
};

use verify_fixtures::fixtures;

/// Die Uhr des Laufs, relativ zur Kulissenuhr.
fn t(offset_ms: i64) -> UnixMillis {
    UnixMillis::new(fixtures::EFFECTIVE_NOW.get() + offset_ms)
}

fn unlocked_at(now: UnixMillis) -> ReaderSession {
    ReaderSession::unlock(
        fixtures::session_vault(),
        fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now),
        now,
    )
    .expect("eine frische Entsperrbestaetigung eroeffnet die Sitzung")
}

/// Ein Ziel im Speicher. Es traegt einen WIRTSPFAD — als Attrappe dessen, was
/// der Browser kennt und das Audit nie sehen darf.
struct MemoryTarget {
    kind: ReaderExportTargetKindV1,
    occupied: bool,
    refuses: bool,
    host_path: &'static str,
    received: Option<Vec<u8>>,
}

impl MemoryTarget {
    fn new(kind: ReaderExportTargetKindV1) -> Self {
        Self {
            kind,
            occupied: false,
            refuses: false,
            host_path: "Einsatz-2026-08-30.json",
            received: None,
        }
    }

    fn occupied() -> Self {
        Self {
            occupied: true,
            ..Self::new(ReaderExportTargetKindV1::UserChosenFile)
        }
    }

    fn refusing() -> Self {
        Self {
            refuses: true,
            ..Self::new(ReaderExportTargetKindV1::UserInitiatedDownload)
        }
    }
}

impl ReaderExportTarget for MemoryTarget {
    fn kind(&self) -> ReaderExportTargetKindV1 {
        self.kind
    }

    fn is_occupied(&self) -> bool {
        self.occupied
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<(), ReaderExportTargetError> {
        assert!(!self.host_path.is_empty(), "die Attrappe traegt einen Pfad");
        if self.refuses {
            return Err(ReaderExportTargetError);
        }
        self.received = Some(plaintext.to_vec());
        Ok(())
    }
}

/// Eine Senke, die ab der n-ten Zeile abweist — der Abbruch NACH dem
/// Schreiben.
struct FailingSink {
    inner: InMemoryReaderAuditSink,
    fail_from: usize,
}

impl ReaderAuditSink for FailingSink {
    fn append(&mut self, signed_event: &[u8]) -> Result<(), ReaderAuditError> {
        if self.inner.events().len() >= self.fail_from {
            return Err(ReaderAuditError::Sink);
        }
        self.inner.append(signed_event)
    }
}

fn outcomes_of(sink: &InMemoryReaderAuditSink) -> Vec<LocalAuditOutcomeV1> {
    sink.events()
        .iter()
        .map(|event| {
            decode_local_audit_event(event)
                .expect("jede Zeile der Senke ist ein gueltiges signiertes Ereignis")
                .outcome()
        })
        .collect()
}

/// Vier Abweisungen VOR der Grenze, jede mit eigenem Code: kein Ziel, besetztes
/// Ziel, fehlende Frische, falscher Zweck. Ein gemeinsamer Sammelcode waere
/// hier der Defekt — „die Person hat abgebrochen" und „der Nachweis passt nicht
/// zu dieser Handlung" sind verschiedene Aussagen. Keine der vier hinterlaesst
/// eine Auditzeile: es ist nichts angenommen worden.
#[test]
fn a_single_export_refuses_without_a_deliberate_target_and_a_fresh_confirmation() {
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );

    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            None,
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect_err("ohne Ziel kein Export");
    assert_eq!(refused.code(), "EA-READER-EXPORT-NO-TARGET");

    let mut occupied = MemoryTarget::occupied();
    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut occupied),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect_err("ein besetztes Ziel wird nie ueberschrieben");
    assert_eq!(refused.code(), "EA-READER-EXPORT-TARGET-OCCUPIED");
    assert!(occupied.received.is_none());

    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    let expired = fixtures::confirmation(
        ReaderConfirmationPurpose::SingleExport,
        t(1_000 - READER_CONFIRMATION_VALIDITY_MS_V1 - 1),
    );
    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            expired,
        )
        .expect_err("eine abgelaufene Bestaetigung traegt keinen Export");
    assert_eq!(refused.code(), "EA-READER-EXPORT-CONFIRMATION-STALE");

    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::Unlock, t(500)),
        )
        .expect_err("eine Entsperrbestaetigung exportiert nichts");
    assert_eq!(refused.code(), "EA-READER-EXPORT-CONFIRMATION-PURPOSE");
    assert!(target.received.is_none());

    assert!(
        sink.events().is_empty(),
        "keine Abweisung vor der Grenze hinterlaesst eine Zeile"
    );
    assert!(!refused.plaintext_left());
    assert!(refused.audit_error().is_none());
}

/// Die Flaeche selbst ist die Zusage: GENAU EIN Datensatz je Aufruf, im Typ
/// des Berichts als Array der Laenge eins. Der `compile_fail`-Doctest gegen
/// eine `Vec`-Ueberladung steht im Modulkopf von
/// `crates/ea-reader/src/export.rs` — eine Laufzeitzusicherung koennte eine
/// Massenexportmethode nicht verbieten, die es GIBT.
#[test]
fn the_export_surface_carries_exactly_one_record_per_call() {
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );

    let record = fixtures::decrypted_genesis_record();
    let entry_hash = record.entry_hash();
    let expected_plaintext = record.with_plaintext(<[u8]>::to_vec);
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    let report = service
        .export_one(
            record,
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect("ein gewaehltes freies Ziel mit frischer Bestaetigung exportiert");

    assert_eq!(report.exported_entry_hashes().len(), 1);
    assert!(report.entry_hash() == entry_hash);
    assert_eq!(
        report.target_kind(),
        ReaderExportTargetKindV1::UserChosenFile
    );
    assert_eq!(
        target.received.as_deref(),
        Some(expected_plaintext.as_slice())
    );
    assert_eq!(report.accepted_event(), sink.events()[0].as_slice());
    assert_eq!(report.completed_event(), sink.events()[1].as_slice());
    assert_ne!(report.accepted_event(), report.completed_event());
}

/// Zwei Zeilen je Versuch, und der Grund ist der Abbruch dazwischen: ein
/// Export, der nach der Bestaetigung und vor dem Schreiben stirbt, hinterliesse
/// sonst keine Spur. `LocalAuditOutcomeV1` traegt dafuer bereits drei Werte; es
/// entsteht kein vierter. Jede Zeile ist Code 5 mit Kontext-Tag 3, traegt
/// Entry-Hash und Zielart, die pseudonyme Bindung und die Zeit des Dienstes.
#[test]
fn an_export_records_accepted_at_the_boundary_and_then_completed_or_failed() {
    let identity = fixtures::audit_identity();
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(&mut session, identity, &mut sink, t(1_000));

    let record = fixtures::decrypted_genesis_record();
    let entry_hash = record.entry_hash();
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserInitiatedDownload);
    service
        .export_one(
            record,
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect("der Export gelingt");
    assert_eq!(
        outcomes_of(&sink),
        vec![
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    for event in sink.events() {
        let event = decode_local_audit_event(event).expect("signierte Zeile");
        assert_eq!(event.action().code(), 5);
        assert_eq!(event.action().context_tag(), 3);
        let ea_reader::LocalAuditActionV1::PlaintextExport(context) = event.action() else {
            panic!("die Zeile traegt den Exportkontext");
        };
        assert!(context.entry_hash() == entry_hash);
        assert_eq!(
            context.target_kind(),
            ReaderExportTargetKindV1::UserInitiatedDownload.target_kind()
        );
        assert_eq!(event.effective_now(), t(1_000));
        assert!(event.organization_id() == identity.organization_id());
        assert!(event.device_id() == identity.device_id());
        assert!(
            event.signer_certificate_object_hash() == identity.signer_certificate_object_hash()
        );
        assert!(
            event.operator_binding_object_hash()
                == Some(ea_reader::ObjectHash::from(fixtures::credential_id_hash()))
        );
    }
    // Zwei verschiedene Ereigniskennungen und zwei verschiedene Nonces.
    let first = decode_local_audit_event(&sink.events()[0]).expect("Zeile");
    let second = decode_local_audit_event(&sink.events()[1]).expect("Zeile");
    assert!(first.event_id() != second.event_id());
    assert_ne!(first.nonce(), second.nonce());

    // Und der Fehlschlag des Ziels: `Accepted`, dann `Failed`, und der Aufrufer
    // erfaehrt, dass das Ziel abgewiesen hat.
    let mut session = unlocked_at(t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(&mut session, identity, &mut sink, t(1_000));
    let mut refusing = MemoryTarget::refusing();
    let failed = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut refusing),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect_err("ein Ziel, das abweist, ist ein Fehlschlag");
    assert_eq!(failed.code(), "EA-READER-EXPORT-TARGET-WRITE");
    assert!(failed.plaintext_left());
    assert_eq!(
        outcomes_of(&sink),
        vec![LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Failed]
    );
}

/// Abbruchpunkt `lock-during-target-choice`: die Sitzung ist waehrend der
/// offenen Zielwahl abgelaufen. Der Export wird abgewiesen, es entsteht KEINE
/// Zeile — es gibt keinen Tresor mehr, der sie signieren koennte —, und das
/// Ziel sieht kein Byte.
#[test]
fn a_session_that_locked_while_the_target_was_being_chosen_refuses_without_an_audit_line() {
    let mut session = unlocked_at(t(0));
    let record = fixtures::decrypted_genesis_record();
    session.open_record(record);
    let entry_hash = session.open_records()[0].entry_hash();
    // Die Person waehlt ein Ziel ... und die Frist laeuft waehrenddessen ab.
    let now = t(READER_INACTIVITY_MS_V1);
    let confirmation = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, now);
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, now);
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);

    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            confirmation,
        )
        .expect_err("eine gesperrte Sitzung exportiert nicht");
    assert_eq!(refused.code(), "EA-READER-EXPORT-SESSION-LOCKED");
    assert!(target.received.is_none());
    assert!(sink.events().is_empty());
    assert_eq!(session.state_at(now), ReaderSessionState::Locked);
    // Der offene Datensatz ist mit der Sperre gefallen.
    assert!(session.take_open_record(entry_hash).is_none());
}

/// Abbruchpunkt `background-tab-before-write`: die Bestaetigung ist noch frisch
/// (eine Minute), aber der Tab war zwischen Bestaetigung und Schreiben laenger
/// als die verkuerzte Frist im Hintergrund. Die Sperre gewinnt; kein Byte
/// verlaesst den Speicher, keine Zeile entsteht. Die Kontrolle daneben: eine
/// Millisekunde vor der Frist gelingt derselbe Export.
#[test]
fn a_tab_hidden_past_the_shortened_deadline_locks_before_the_bytes_leave() {
    let mut session = unlocked_at(t(0));
    let confirmation = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(0));
    session.note_visibility(TabVisibility::Hidden, t(0));
    let now = t(READER_BACKGROUND_INACTIVITY_MS_V1);
    assert!(confirmation.is_fresh_for(ReaderConfirmationPurpose::SingleExport, now));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, now);
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserInitiatedDownload);
    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            confirmation,
        )
        .expect_err("die verkuerzte Frist sperrt vor dem Schreiben");
    assert_eq!(refused.code(), "EA-READER-EXPORT-SESSION-LOCKED");
    assert!(target.received.is_none());
    assert!(sink.events().is_empty());

    let mut session = unlocked_at(t(0));
    let confirmation = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(0));
    session.note_visibility(TabVisibility::Hidden, t(0));
    let now = t(READER_BACKGROUND_INACTIVITY_MS_V1 - 1);
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, now);
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserInitiatedDownload);
    service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            confirmation,
        )
        .expect("eine Millisekunde vor der Frist ist die Sitzung offen");
    assert!(target.received.is_some());
    assert_eq!(sink.events().len(), 2);
}

/// Abbruchpunkt `audit-failure-after-bytes-left`: die Bytes sind draussen, und
/// die zweite Zeile laesst sich nicht schreiben. Der Fehler MUSS entstehen und
/// darf nicht verschluckt werden: eigener Code, `plaintext_left()` wahr, der
/// Auditbefund erreichbar, und die `Accepted`-Zeile steht. Die Gegenprobe:
/// weist die Senke schon die ERSTE Zeile ab, verlaesst kein Byte den Speicher.
#[test]
fn a_failing_completed_line_after_the_bytes_left_surfaces_instead_of_being_swallowed() {
    let mut session = unlocked_at(t(0));
    let mut sink = FailingSink {
        inner: InMemoryReaderAuditSink::new(),
        fail_from: 1,
    };
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    let failed = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect_err("die fehlende zweite Zeile ist ein Fehler");
    assert_eq!(failed.code(), "EA-READER-EXPORT-AUDIT-AFTER-WRITE");
    assert!(failed.plaintext_left());
    assert_eq!(
        failed.audit_error().map(ReaderAuditError::code),
        Some("EA-READER-AUDIT-SINK")
    );
    assert!(target.received.is_some(), "die Bytes SIND draussen");
    assert_eq!(
        outcomes_of(&sink.inner),
        vec![LocalAuditOutcomeV1::Accepted]
    );

    let mut session = unlocked_at(t(0));
    let mut sink = FailingSink {
        inner: InMemoryReaderAuditSink::new(),
        fail_from: 0,
    };
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    let failed = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(500)),
        )
        .expect_err("ohne Accepted-Zeile kein Schreiben");
    assert_eq!(failed.code(), "EA-READER-EXPORT-AUDIT-BEFORE-WRITE");
    assert!(!failed.plaintext_left());
    assert!(
        target.received.is_none(),
        "KEIN Byte hat den Speicher verlassen"
    );
    assert!(sink.inner.events().is_empty());
}

/// Die Zielarten und ihre Zahlen: `UserChosenFile` ist `1`, weil der
/// eingefrorene Vektor `event/accepted-plaintext-export` diese Zahl bereits
/// traegt; `UserInitiatedDownload` ist `2`. Der Wortlaut geht hin und zurueck,
/// ein fremder Wortlaut ist keine Zielart.
#[test]
fn the_target_kinds_carry_the_frozen_numbers_and_round_trip_their_labels() {
    assert_eq!(ReaderExportTargetKindV1::UserChosenFile.target_kind(), 1);
    assert_eq!(
        ReaderExportTargetKindV1::UserInitiatedDownload.target_kind(),
        2
    );
    for kind in [
        ReaderExportTargetKindV1::UserChosenFile,
        ReaderExportTargetKindV1::UserInitiatedDownload,
    ] {
        assert_eq!(
            ReaderExportTargetKindV1::from_label(kind.label()),
            Some(kind)
        );
    }
    assert_eq!(ReaderExportTargetKindV1::from_label("clipboard"), None);
    assert_eq!(ReaderExportTargetKindV1::from_label(""), None);
    // Die Abweisungscodes formatieren AUSSCHLIESSLICH ihren Code.
    assert_eq!(
        format!("{:?}", ReaderExportError::TargetOccupied),
        "EA-READER-EXPORT-TARGET-OCCUPIED"
    );
    assert_eq!(
        format!("{}", ReaderExportError::NoTarget),
        "EA-READER-EXPORT-NO-TARGET"
    );
}

/// Die Frische der Bestaetigung wird gegen die SITZUNGSZEIT gemessen, nicht
/// gegen die rohe Uhr des Dienstes: eine Uhr, die hinter die monotone
/// Untergrenze zurueckfaellt, verlaengert die Minute der Bestaetigung so wenig
/// wie die Frist der Sitzung. Gemessen im Review — vorher nahm der Dienst
/// mit einer Uhr bei 10 ms eine Bestaetigung an, die die Sitzung laengst als
/// abgelaufen sah, und stempelte die alte Zeit in die Auditzeile.
#[test]
fn a_service_clock_behind_the_session_floor_does_not_revive_a_stale_confirmation() {
    let mut session = unlocked_at(t(0));
    session.note_activity(t(200_000));
    let stale = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(0));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, t(10));
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            stale,
        )
        .expect_err("die Untergrenze der Sitzung gilt auch fuer die Bestaetigung");
    assert_eq!(refused.code(), "EA-READER-EXPORT-CONFIRMATION-STALE");
    assert!(target.received.is_none());
    assert!(sink.events().is_empty());

    // Und die Auditzeit ist die Sitzungszeit: ein Export mit frischer
    // Bestaetigung und zurueckgefallener Dienstuhr traegt die Untergrenze.
    let mut session = unlocked_at(t(0));
    session.note_activity(t(200_000));
    let fresh = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(200_000));
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, t(10));
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserChosenFile);
    service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            fresh,
        )
        .expect("frisch an der Untergrenze");
    for event in sink.events() {
        assert_eq!(
            decode_local_audit_event(event)
                .expect("Zeile")
                .effective_now(),
            t(200_000)
        );
    }
}

/// Eine Bestaetigung, die gegen einen FREMDEN Tresor belegt wurde, exportiert
/// nichts — und die Weigerung faellt VOR der Grenze: keine Zeile, kein Byte.
#[test]
fn a_confirmation_from_a_foreign_vault_exports_nothing_and_leaves_no_line() {
    let mut session = unlocked_at(t(0));
    let foreign = ea_reader::ReaderAuthenticatorConfirmation::prove(
        &fixtures::sealed_vault_pinning(vec![0xee; 40]),
        &fixtures::authenticator(),
        ReaderConfirmationPurpose::SingleExport,
        t(500),
    )
    .expect("gegen den fremden Tresor belegt");
    let mut sink = InMemoryReaderAuditSink::new();
    let mut service = ReaderExportService::open(
        &mut session,
        fixtures::audit_identity(),
        &mut sink,
        t(1_000),
    );
    let mut target = MemoryTarget::new(ReaderExportTargetKindV1::UserInitiatedDownload);
    let refused = service
        .export_one(
            fixtures::decrypted_genesis_record(),
            Some(&mut target),
            foreign,
        )
        .expect_err("eine fremde Bindung exportiert nicht");
    assert_eq!(refused.code(), "EA-READER-EXPORT-CONFIRMATION-VAULT");
    assert!(!refused.plaintext_left());
    assert!(target.received.is_none());
    assert!(sink.events().is_empty());
}
