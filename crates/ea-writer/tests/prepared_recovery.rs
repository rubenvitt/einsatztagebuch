//! Jeder Unterbrechungspunkt fuehrt auf GENAU zwei Zustaende.
//!
//! Entweder der Entwurf ist wiederherstellbar und die Sequenz unverbraucht,
//! oder dieselbe vorbereitete Transaktion ist vollendet. Ein dritter Zustand —
//! ein halb veroeffentlichter Bestand, ein committed `.eip` neben einem
//! nutzbaren `draftDEK`, eine zweimal benutzte Sequenz — existiert nicht, und
//! diese Datei ist der Beleg dafuer.
//!
//! Die EINE Ausnahme ist benannt und gemessen:
//! [`FinalizationFaultPoint::BackupRestoreAfterKeyDeletion`] ist kein Punkt der
//! Reihenfolge, sondern ein Ereignis von aussen, und es nimmt die vorbereiteten
//! Bytes MIT. Der Entwurf ist dann verloren und der Bestand unberuehrt — kein
//! halber Zustand, aber auch keine Vollendung.

mod support;

use ea_writer::{FinalizationFaultPoint, FinalizationStep, RecoveryOutcome};
use support::{FIXTURE_INCIDENT_NUMBER, WriterHarness, valid_incident};

#[test]
fn every_fault_recovers_the_draft_or_completes_the_same_prepared_transaction() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut harness = WriterHarness::with_incident();
        let interrupted = harness
            .finalize_with_fault(point)
            .unwrap_or_else(|error| panic!("{point:?} muss erreichbar sein: {error:?}"));

        // Der Abbruch hat WIRKLICH etwas getan. Ohne diese Zusicherung waere
        // die ganze Schleife auch gruen, wenn die Fehlerinjektion nichts tut —
        // gemessen mit Mutation 2.
        assert!(
            interrupted.reached_step().is_some(),
            "{point:?}: der Lauf hat keinen einzigen Schritt ausgefuehrt"
        );

        // Die Rueckspielung nimmt die Datenbankdateien des Zustands VOR der
        // Finalisierung zurueck; die Abschlussmarke ist damit fort, obwohl der
        // `draftDEK` geloescht bleibt. Das ist der Grund, warum dieser Punkt
        // ueberhaupt ein eigener ist.
        let restored_backup = point == FinalizationFaultPoint::BackupRestoreAfterKeyDeletion;
        // Ab der Datenbanktransaktion liegt eine Abschlussmarke, also darf die
        // Wiederherstellung NICHT „nichts zu tun" melden.
        let marker_expected = !restored_backup
            && !matches!(
                point,
                FinalizationFaultPoint::BeforeStagingCreate
                    | FinalizationFaultPoint::AfterStagingCreateBeforeFileFlush
                    | FinalizationFaultPoint::AfterStagingFileFlushBeforeDirectoryFlush
                    | FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker
            );
        if marker_expected {
            assert!(
                interrupted.prepared().is_some(),
                "{point:?}: ab der Datenbanktransaktion MUSS eine Marke liegen"
            );
        }

        let source = harness.source();
        let service = harness.service(&source);
        let first = service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: recover muss tragen: {error:?}"));

        // Die Klassifikation des Punktes ENTSCHEIDET den Ausgang, und das ist
        // die eigentliche Zusage: vor der Grenze ist der Entwurf
        // wiederherstellbar und die Sequenz unverbraucht, hinter ihr MUSS
        // dieselbe vorbereitete Transaktion vollendet werden. Ein
        // `matches!` ueber alle drei Arme waere hier gruen, ohne etwas zu
        // sagen.
        if marker_expected {
            assert_ne!(
                first,
                RecoveryOutcome::NothingPending,
                "{point:?}: eine liegende Marke MUSS aufgeloest werden"
            );
        }
        if restored_backup {
            // Die eigene, ANDERE Messung dieses Punktes: die Marke ist mit der
            // Sicherung verschwunden, also findet die Wiederherstellung nichts
            // vor — an [`FinalizationFaultPoint::AfterAbsenceConfirmation`],
            // demselben Programmpunkt ohne Rueckspielung, vollendet sie
            // dagegen. Der Bestand bleibt unberuehrt, und der `draftDEK` ist
            // fort: die vorbereitete Transaktion ist verloren, nicht halb
            // vollzogen.
            assert_eq!(
                first,
                RecoveryOutcome::NothingPending,
                "die Rueckspielung hat die vorbereiteten Bytes mitgenommen"
            );
            assert!(
                harness.published_entry_paths().is_empty(),
                "die Rueckspielung veroeffentlicht nichts"
            );
            // Gefragt ist der SCHLUESSELSPEICHER und nicht die Ablage:
            // `draft_dek_is_present` liest ueber `load_or_create` und wiederholt
            // damit genau die Bedingung, an der `recover_pending` den Fall
            // ueberhaupt erkannt hat. `draft_dek_entry_is_absent` fragt den
            // Speicher unter der Adresse, die die Fixture beim Saeen genommen
            // hat — die zweite Seite desselben Ereignisses und keine
            // Wiederholung.
            assert!(
                harness.draft_dek_entry_is_absent(),
                "der geraetegebundene Schluesselspeichereintrag kehrt NICHT mit den Dateien zurueck"
            );
        } else if point.phase().is_irreversible() {
            assert!(
                matches!(first, RecoveryOutcome::CommittedFromPreparedBytes { .. }),
                "{point:?} liegt hinter der Grenze, wurde aber als {first:?} aufgeloest"
            );
        } else {
            assert!(
                first.is_original_draft(),
                "{point:?} liegt vor der Grenze, wurde aber als {first:?} aufgeloest"
            );
        }

        // Ein ZWEITES recover ist ein no-op — eine GLEICHHEIT und keine
        // Beschreibung.
        let second = service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: das zweite recover muss tragen: {error:?}"));
        assert_eq!(
            second,
            RecoveryOutcome::NothingPending,
            "ein zweites recover ist ein no-op: {point:?}"
        );

        // Die TRAGENDE Zusage: nie beides zugleich.
        //
        // Gemessen wird der ENTWURF und nicht die blosse Anwesenheit EINES
        // `draftDEK`: Schritt 13 oeffnet einen leeren Entwurf mit FRISCHEM
        // Schluessel, und der ist die Nachbedingung und nicht der Verstoss. Die
        // Zusage lautet „kein nutzbarer `draftDEK` DIESES Eintrags", und der
        // Zeuge dafuer ist, dass sein Inhalt fort ist.
        let committed = harness.published_entry_paths().len();
        assert!(
            committed == 0 || harness.draft_is_blank(),
            "{point:?}: ein committed .eip und der ihn erzeugende Entwurf zugleich lesbar"
        );
        assert!(committed <= 1, "{point:?}: kein Duplikat");
    }
}

#[test]
fn after_the_key_boundary_recovery_completes_the_exact_prepared_bytes() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let interrupted = service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationFaultPoint::AfterAbsenceConfirmation,
        )
        .expect("der Abbruch an der Grenze muss erreichbar sein");
    let prepared = interrupted
        .prepared()
        .expect("hinter der Grenze liegt eine Abschlussmarke");
    let prepared_bytes = prepared.exact_bytes().to_vec();
    let sequence = prepared.sequence();
    let draws_before = ea_writer::entropy_draws();

    let recovered = service
        .recover_pending()
        .expect("die Wiederherstellung hinter der Grenze muss tragen");
    assert_eq!(
        recovered,
        RecoveryOutcome::CommittedFromPreparedBytes { sequence }
    );

    // KEINE neue Zufallsziehung — die tragende Zusage von `design.md` §9.4.
    assert_eq!(
        ea_writer::entropy_draws(),
        draws_before,
        "die Wiederherstellung zieht keine Zufallswerte"
    );

    // Und dieselben Bytes: das committed `.eip` ist genau das der Marke.
    let entries = harness.published_entry_paths();
    assert_eq!(entries.len(), 1);
    let committed = harness
        .backend()
        .read_for_test(&entries[0])
        .expect("das committed .eip muss lesbar sein");
    assert!(
        prepared_bytes
            .windows(committed.len())
            .any(|w| w == committed),
        "die veroeffentlichten Bytes stehen unveraendert in der Abschlussmarke"
    );
}

#[test]
fn before_the_key_boundary_the_sequence_stays_unused() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let interrupted = service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationFaultPoint::AfterPreparedMarkerCommit,
        )
        .expect("der Abbruch vor der Grenze muss erreichbar sein");
    let sequence = interrupted.prepared().expect("die Marke liegt").sequence();

    assert_eq!(
        service.recover_pending().expect("recover muss tragen"),
        RecoveryOutcome::DraftRestored {
            unused_sequence: sequence
        }
    );
    assert!(
        harness.draft_dek_is_present(),
        "vor der Grenze bleibt der Entwurf lesbar"
    );
    assert!(
        harness.published_entry_paths().is_empty(),
        "vor der Grenze ist nichts veroeffentlicht"
    );
}

/// „Die Sequenz gilt dann als NICHT verbraucht" ist eine Zusage ueber den
/// NAECHSTEN Lauf.
///
/// Eine liegengebliebene `entries/<seq>_<hash>.eip.staging` traegt dieselben
/// Bytes wie das Archivobjekt und damit dasselbe Exact-Object-Praefix. Zaehlte
/// sie als Kettenknoten, stuende `verified_head` auf einem Objekt, das NIE
/// veroeffentlicht wurde: Schritt 3 verlangte `EA-WRITER-HEAD-RECONCILIATION-\
/// REQUIRED` auf einem Bestand, in dem nichts liegt — dauerhaft —, und ein
/// spaeterer Eintrag bindet einen Vorgaenger, den es nicht gibt.
///
/// Der Zeuge laeuft ueber BEIDE Punkte, an denen Staging liegen bleibt: den mit
/// Abschlussmarke und den ohne.
#[test]
fn leftover_staging_objects_do_not_consume_the_sequence() {
    for point in [
        FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker,
        FinalizationFaultPoint::AfterPreparedMarkerCommit,
    ] {
        let mut harness = WriterHarness::with_incident();
        harness
            .finalize_with_fault(point)
            .unwrap_or_else(|error| panic!("{point:?} muss erreichbar sein: {error:?}"));

        let source = harness.source();
        let service = harness.service(&source);
        service
            .recover_pending()
            .unwrap_or_else(|error| panic!("{point:?}: recover muss tragen: {error:?}"));

        // Die Staging-Datei liegt WEITERHIN da. Der Port hat keine
        // Loeschprimitive, und der Zeuge misst deshalb den Filter und nicht
        // eine Bereinigung.
        assert!(
            harness.staged_object_count() > 0,
            "{point:?}: ohne liegengebliebenes Staging messe dieser Test nichts"
        );
        assert!(harness.published_entry_paths().is_empty());

        // Und der naechste Lauf gelingt — auf DERSELBEN Sequenz und ohne
        // Vorgaenger.
        let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
        let preview = service
            .preview(&proof, valid_incident(), harness.observed_now())
            .unwrap_or_else(|error| {
                panic!("{point:?}: die Sequenz MUSS unverbraucht sein: {error:?}")
            });
        assert_eq!(preview.proposed_sequence().get(), 0);
        assert!(
            preview.previous_entry_hash().is_none(),
            "{point:?}: ein Bestand ohne veroeffentlichten Eintrag hat keinen Vorgaenger"
        );
        let out = service
            .finalize(&proof, valid_incident(), &preview, harness.observed_now())
            .unwrap_or_else(|error| panic!("{point:?}: der zweite Anlauf muss tragen: {error:?}"));
        assert_eq!(out.sequence.get(), 0);
        assert_eq!(harness.published_entry_paths().len(), 1);
    }
}

#[test]
fn a_prepared_finalization_beats_a_second_finalization_attempt() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    service
        .finalize_interrupted_at(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationFaultPoint::AfterPreparedMarkerCommit,
        )
        .expect("der Abbruch muss erreichbar sein");

    let preview = service.preview(&proof, valid_incident(), harness.observed_now());
    assert_eq!(
        preview.err().map(|error| error.code()),
        Some("EA-WRITER-PREPARED-FINALIZATION-PRESENT"),
        "solange eine Marke liegt, beginnt keine zweite Finalisierung"
    );
}

/// Eine liegende Abschlussmarke verhindert ein Verwerfen des Entwurfs.
///
/// Der Vorrangpunkt aus Task 7, von dieser Seite gemessen: nach Schritt 8 liegt
/// die Marke, und `begin_discard` MUSS fail-closed abweisen.
#[test]
fn a_prepared_finalization_beats_a_pending_discard_intent() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    service
        .finalize_up_to(
            &proof,
            valid_incident(),
            harness.observed_now(),
            FinalizationStep::StageAndFlush,
        )
        .expect("Schritt 8 muss erreichbar sein");
    assert!(harness.prepared_marker_is_present());

    let discard = ea_draft::DiscardService::new(
        harness.repository(),
        harness.provider() as std::sync::Arc<dyn ea_key_provider::KeyProvider>,
        harness.binding().binding_object_hash,
        harness.head().preexisting_effective_now(),
    );
    assert_eq!(
        discard
            .begin_discard(harness.proof_for(ea_operator::ReauthPurpose::DiscardDraft))
            .err()
            .map(|error| error.code()),
        Some("EA-DRAFT-PREPARED-FINALIZATION-PRESENT")
    );
}

/// Eine Ablage, die den leeren Entwurf NICHT anlegen kann.
///
/// Sie existiert fuer genau eine Messung: Schritt 13 wechselt Abschlussmarke
/// und leeren Entwurf in EINEM dauerhaften Schritt, und diese Zusage ist nur
/// dort messbar, wo dieser Schritt FEHLSCHLAEGT. Gegen die echte Ablage kann er
/// es nicht — der In-Prozess-Schluesselspeicher liefert immer.
///
/// `DraftError::LocalRng` ist der ehrliche Fehler: `create_blank` zieht den
/// frischen `draftDEK` und eine `draft_id` aus der Zufallsquelle, und genau
/// dieser Zug liegt INNERHALB der Transaktion.
struct BlankDraftRefusingRepository {
    inner: std::sync::Arc<dyn ea_draft::DraftRepository>,
}

impl ea_draft::DraftRepository for BlankDraftRefusingRepository {
    fn load_or_create(&self) -> Result<ea_draft::Draft, ea_draft::DraftError> {
        self.inner.load_or_create()
    }

    fn save(&self, draft: ea_draft::Draft) -> Result<ea_draft::SavedDraft, ea_draft::DraftError> {
        self.inner.save(draft)
    }

    fn draft_dek_handle(
        &self,
        draft: &ea_draft::SavedDraft,
    ) -> Result<ea_key_provider::KeyHandle, ea_draft::DraftError> {
        self.inner.draft_dek_handle(draft)
    }

    fn commit_discard_intent(
        &self,
        draft: &ea_draft::SavedDraft,
    ) -> Result<ea_draft::DiscardIntent, ea_draft::DraftError> {
        self.inner.commit_discard_intent(draft)
    }

    fn pending_discard(&self) -> Result<Option<ea_draft::DiscardIntent>, ea_draft::DraftError> {
        self.inner.pending_discard()
    }

    fn replace_with_blank(&self) -> Result<ea_draft::SavedDraft, ea_draft::DraftError> {
        Err(ea_draft::DraftError::LocalRng)
    }

    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &ea_draft::DiscardIntent,
    ) -> Result<ea_draft::DiscardOutcome, ea_draft::DraftError> {
        self.inner.remove_ciphertext_and_intent_create_blank(intent)
    }

    fn prepared_finalization_marker(
        &self,
    ) -> Result<Option<ea_draft::PreparedFinalizationMarker>, ea_draft::DraftError> {
        self.inner.prepared_finalization_marker()
    }

    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<ea_draft::PreparedFinalizationMarker>,
    ) -> Result<(), ea_draft::DraftError> {
        self.inner.replace_prepared_finalization_marker(marker)
    }

    fn acquire_draft_lock(&self) -> Result<ea_draft::DraftLock, ea_draft::DraftError> {
        self.inner.acquire_draft_lock()
    }
}

/// Schritt 13 wechselt Marke und leeren Entwurf in EINEM dauerhaften Schritt.
///
/// Der Zwischenzustand „Marke fort, alter Entwurf mit geloeschtem `draftDEK`
/// noch da" ist der EINZIGE, aus dem kein Arm mehr herausfuehrt: `load_or_create`
/// scheitert an `unwrap_secret`, `recover_pending` findet keine Marke und meldet
/// `NothingPending`, und das Geraet ist ohne Eingriff in die Datenbank
/// unbenutzbar. Diese Zusicherung ist FALSIFIZIERBAR: schreibt Schritt 13 die
/// Marke wieder in einem eigenen, vorangestellten Schritt fort, ist die Marke
/// hier fort und `recover_pending` meldet `NothingPending` — beide Zeilen unten
/// fallen dann.
#[test]
fn a_failed_blank_draft_leaves_the_prepared_marker_and_stays_recoverable() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);

    let refusing = std::sync::Arc::new(BlankDraftRefusingRepository {
        inner: harness.repository(),
    }) as std::sync::Arc<dyn ea_draft::DraftRepository>;
    let blocked = ea_writer::WriterService::new(
        refusing,
        harness.provider() as std::sync::Arc<dyn ea_key_provider::KeyProvider>,
        harness.backend(),
        &source,
        harness.head(),
        &[],
        ea_draft::IncidentNumberRegister::new(harness.database()),
        ea_draft::OperatorProfileRepository::new(harness.database()),
        harness.binding(),
    );
    let preview = blocked
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau beruehrt Schritt 13 nicht");
    let error = blocked
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect_err("der leere Entwurf laesst sich nicht anlegen");
    assert_eq!(error.code(), "EA-DRAFT-LOCAL-RNG");

    // Der Eintrag ist committed — Schritt 13 liegt HINTER der Grenze.
    assert_eq!(harness.published_entry_paths().len(), 1);
    // Und die Marke steht noch: der Wechsel ist nicht zur Haelfte passiert.
    assert!(
        harness.prepared_marker_is_present(),
        "die Marke MUSS liegen, sonst gibt es keinen Weg zurueck"
    );

    // Damit bleibt das Geraet benutzbar: derselbe Veroeffentlichungspfad
    // vollendet aus denselben vorbereiteten Bytes.
    let service = harness.service(&source);
    let outcome = service
        .recover_pending()
        .expect("die Wiederaufnahme muss die Marke finden");
    assert!(matches!(
        outcome,
        RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert_eq!(harness.published_entry_paths().len(), 1);
    assert!(!harness.prepared_marker_is_present());
    assert!(harness.draft_is_blank());
}

/// Ein Renamefehler bei FREIER Zieladresse schreibt nichts unter den
/// Commit-Namen.
///
/// # Was hier gemessen wird
///
/// Der Fallback auf `create_if_absent` gilt AUSSCHLIESSLICH dem
/// Wiederholungsfall, in dem die Zieladresse schon liegt. Fiel er bei JEDEM
/// Renamefehler an, liefe sein `create_new` + `write_all` auf die ENDADRESSE:
/// ein Abbruch mittendrin — volles Medium — liesse eine abgeschnittene Datei
/// unter ihrem endgueltigen Commit-Marker-Namen zurueck, und jeder weitere
/// Anlauf traefe sie mit `EA-ARCHIVE-BYTE-CONFLICT`.
///
/// Der eingespielte Fehler ist ein Rename ueber eine Dateisystemgrenze, weil
/// nur er im Testwirt reproduzierbar ist und VOR jeder Dateisystemarbeit
/// greift; die Zusage gilt fuer jeden Renamefehler gleich, denn das Backend
/// meldet sie alle als `Io` oder `NotSameFilesystem` und unterscheidet sie
/// nicht.
///
/// Die Zusicherung ist FALSIFIZIERBAR: faellt der Zweig wieder auf JEDEN
/// Fehler in `create_if_absent`, dann VEROEFFENTLICHT dieser Lauf, die
/// Wiederaufnahme meldet Erfolg statt Fehler, und die Zeile ueber
/// `exists_for_test` faellt.
#[test]
fn a_rename_failure_with_a_free_target_never_writes_under_the_commit_name() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename)
        .expect("der Abbruch vor dem Eintragsrename muss erreichbar sein");
    assert!(harness.published_entry_paths().is_empty());

    // Die Zieladresse dieser vorbereiteten Transaktion — abgeleitet aus der
    // liegenden Staging-Adresse und nicht neu gebildet.
    let staged = harness
        .backend()
        .relative_paths_below_for_test("entries/")
        .into_iter()
        .find(|path| path.ends_with(".eip.staging"))
        .expect("Schritt 8 hat die Eintragsbytes gestagt");
    let target = staged
        .strip_suffix(".staging")
        .expect("die Staging-Adresse ist die Zieladresse plus Suffix")
        .to_owned();

    harness.backend().mark_foreign_filesystem_for_test(&target);
    let source = harness.source();
    let service = harness.service(&source);
    let error = service
        .recover_pending()
        .expect_err("ein Rename ueber die Dateisystemgrenze MUSS propagieren");
    assert_eq!(error.code(), "EA-ARCHIVE-NOT-SAME-FILESYSTEM");
    assert!(
        !harness.backend().exists_for_test(&target),
        "unter dem Commit-Namen darf NICHTS liegen, wenn der Rename gescheitert ist"
    );
    assert!(
        harness.backend().exists_for_test(&staged),
        "das unversehrte Staging MUSS liegen bleiben, sonst gibt es keinen zweiten Anlauf"
    );
    assert!(harness.prepared_marker_is_present());

    // Und der Zustand ist fortsetzbar: dieselbe Marke, dieselben Bytes,
    // derselbe Pfad.
    harness.backend().clear_foreign_filesystem_for_test(&target);
    let outcome = service
        .recover_pending()
        .expect("die Wiederaufnahme muss nach dem Fehler tragen");
    assert!(matches!(
        outcome,
        RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert_eq!(harness.published_entry_paths(), vec![target]);
}

/// Eine gebuchte Verwerfensabsicht blockiert die Finalisierung NICHT — und das
/// ist eine Entscheidung und kein Versehen.
///
/// # Warum diese Zeile hier steht
///
/// Die Vorrangregel („keiner der beiden wird dauerhaft geschrieben, solange der
/// andere vorliegt") haelt am Schreibort in beide Richtungen: `commit_discard_intent`
/// weist eine liegende Abschlussmarke fail-closed ab
/// (`crates/ea-draft/tests/discard_faults.rs`). Die Gegenrichtung — Marke
/// schreiben, waehrend eine Absicht gebucht ist — ist AUSDRUECKLICH offen:
/// `draft_transition` ist EIN Platz, die Marke verdraengt die Absicht
/// strukturell, und der Bediener behaelt damit einen Weg aus einem gebuchten
/// Verwerfen heraus. Die Alternative waere eine dauerhafte Blockade: die
/// Verwerfenskommandos des Wirts sind in dieser Stufe Stummel, ein gebuchtes
/// Verwerfen hat also keinen Aufloesungspfad an der Oberflaeche, und eine
/// fail-closed Abweisung an dieser Stelle machte das Geraet unbenutzbar.
///
/// Die Zeile ist ein Waechter fuer genau diese Abwaegung: wer hier eine
/// Blockade einbaut, faellt hier auf und muss den Aufloesungspfad mitliefern.
#[test]
fn a_booked_discard_intent_is_displaced_by_the_prepared_finalization() {
    let harness = WriterHarness::with_incident();
    let repository = harness.repository();
    let draft = repository
        .load_or_create()
        .expect("der Entwurf der Fixture muss lesbar sein");
    let saved = repository.save(draft).expect("das Speichern muss tragen");
    repository
        .commit_discard_intent(&saved)
        .expect("ohne liegende Marke MUSS die Buchung tragen");
    assert!(
        repository
            .pending_discard()
            .expect("die Uebergangstabelle muss lesbar sein")
            .is_some()
    );

    let source = harness.source();
    let service = harness.service(&source);
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die gebuchte Absicht blockiert die Vorschau nicht");
    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("die gebuchte Absicht blockiert den Abschluss nicht");

    assert_eq!(harness.published_entry_paths().len(), 1);
    assert!(
        repository
            .pending_discard()
            .expect("die Uebergangstabelle muss lesbar sein")
            .is_none(),
        "die Absicht ist mit der Marke verdraengt und mit Schritt 13 geraeumt"
    );
    assert!(!harness.prepared_marker_is_present());
}

/// Ein Schluesselspeicher, der ein `delete` MELDET und nicht loescht, kommt
/// nicht ueber die Grenze.
///
/// `WriterError::KeyDeletionNotConfirmed` (Schritt 9) ist der EINZIGE Waechter
/// der unwiderruflichen Grenze, und er hatte in allen Testverzeichnissen null
/// Treffer — waehrend derselbe Waechter der VERWERFENSSEITE
/// (`crates/ea-draft/tests/discard_faults.rs`,
/// `a_keystore_that_reports_a_deletion_without_deleting_stops_the_discard`)
/// bezeugt war. Diese Asymmetrie war der Befund; dieser Test schliesst sie mit
/// demselben Doppelgaenger und derselben Zweiteilung.
///
/// Gegen einen wahrhaftigen Provider kann die Abwesenheitsbestaetigung nie
/// fehlschlagen — ohne den tauben Doppelgaenger waere sie eine Zeile, die kein
/// Test je ausfuehrt.
#[test]
fn a_keystore_that_reports_a_deletion_without_deleting_stops_the_finalization() {
    let harness = WriterHarness::with_incident();
    // `let Err(...) else` statt `expect_err`: `FinalizeOutcome` leitet kein
    // `Debug` ab — ein Abschlussergebnis gehoert in keine Protokollzeile.
    let Err(refused) = harness.finalize_with_deaf_keystore() else {
        panic!("ein gemeldetes, nicht ausgefuehrtes Loeschen MUSS den Abschluss anhalten");
    };
    assert_eq!(refused.code(), "EA-WRITER-KEY-DELETION-NOT-CONFIRMED");

    // Die POSITIVKONTROLLE: der Lauf hat die Grenze wirklich erreicht. Ohne
    // diese zwei Zeilen waere „nichts veroeffentlicht" darunter auch fuer einen
    // Lauf gruen, der schon an Schritt 1 gescheitert ist — dort ist ebenfalls
    // nichts veroeffentlicht, und der Fehlercode allein sagt nicht, wie weit
    // gekommen wurde.
    assert!(
        harness.prepared_marker_is_present(),
        "Schritt 8 liegt VOR Schritt 9: die Abschlussmarke MUSS stehen"
    );
    assert_eq!(
        harness.staged_object_count(),
        harness.expected_grant_count() + 1,
        "jeder Grant und der Eintrag liegen gestaget"
    );

    // Und trotzdem ist NICHTS veroeffentlicht.
    assert!(harness.published_entry_paths().is_empty());
    assert!(harness.published_grant_paths().is_empty());

    // Der `draftDEK` liegt weiter — der taube Speicher hat ihn nicht entfernt.
    // Die Grenze ist damit NICHT ueberschritten, und deshalb ist der richtige
    // Neustartausgang die WIEDERHERSTELLUNG des Entwurfs und nicht die
    // Vollendung: `recover.rs` liest den ENTWURF als Zeugen der Grenze, und er
    // laesst sich oeffnen. Eine Vollendung hier waere ein Eintrag, dessen
    // `draftDEK` noch benutzbar ist — genau der Zustand, den die vierte
    // Invariante ausschliesst.
    assert!(!harness.draft_dek_entry_is_absent());
    let source = harness.source();
    let service = harness.service(&source);
    let first = service
        .recover_pending()
        .expect("die Wiederaufnahme muss tragen");
    assert!(
        first.is_original_draft(),
        "vor der Grenze wird der Entwurf wiederhergestellt, nicht vollendet: {first:?}"
    );
    assert_eq!(
        service
            .recover_pending()
            .expect("das zweite recover muss tragen"),
        RecoveryOutcome::NothingPending,
        "ein zweites recover ist ein no-op"
    );
    // Der Abbruch verklemmt nichts: die Marke ist geloest, der Entwurf traegt
    // weiter seinen Inhalt, und veroeffentlicht ist nach wie vor nichts.
    assert!(!harness.prepared_marker_is_present());
    assert!(!harness.draft_is_blank());
    assert!(harness.published_entry_paths().is_empty());
}

/// Die Adresse der GESTAGTEN Eintragsbytes dieser vorbereiteten Transaktion.
fn staged_entry_path(harness: &WriterHarness) -> String {
    harness
        .backend()
        .relative_paths_below_for_test("entries/")
        .into_iter()
        .find(|path| path.ends_with(".eip.staging"))
        .expect("Schritt 8 hat die Eintragsbytes gestagt")
}

/// Der `initialGrantPlanHash`, den das vorbereitete `.eip` SIGNIERT.
///
/// Er wird aus den gestagten Bytes gelesen und nicht neu gerechnet: die Marke
/// soll gegen das gemessen werden, was der Writer unterschrieben hat, und eine
/// zweite Rechnung waere eine zweite Wahrheit.
fn signed_grant_plan_hash(harness: &WriterHarness) -> [u8; 32] {
    let bytes = harness
        .backend()
        .read_for_test(&staged_entry_path(harness))
        .expect("die gestagten Eintragsbytes muessen lesbar sein");
    let parsed = ea_format::decode_exact_object(&bytes).expect("das .eip muss dekodieren");
    let ea_format::ParsedArchiveObject::Entry(entry) = &parsed else {
        panic!("unter entries/ liegt ein .eip");
    };
    entry.value().manifest().fields().initial_grant_plan_hash
}

/// Die liegenden Markenbytes.
fn prepared_marker_bytes(harness: &WriterHarness) -> Vec<u8> {
    harness
        .repository()
        .prepared_finalization_marker()
        .expect("die Ablage muss lesbar sein")
        .expect("hinter der Grenze liegt eine Marke")
        .as_bytes()
        .to_vec()
}

/// Legt `bytes` als Abschlussmarke ab.
fn put_prepared_marker(harness: &WriterHarness, bytes: Vec<u8>) {
    harness
        .repository()
        .replace_prepared_finalization_marker(Some(ea_draft::PreparedFinalizationMarker::new(
            bytes,
        )))
        .expect("die Marke muss sich ersetzen lassen");
}

/// Eine Marke, deren Grant-Plan-Hash NICHT der ist, den das `.eip` signiert,
/// wird fail-closed abgewiesen.
///
/// # Was hier gemessen wird
///
/// `grant_plan_hash` steht MIT in der Marke, „damit die Wiederherstellung
/// belegen kann, dass die uebernommenen Grants zu dem Plan gehoeren, den das
/// `.eip` signiert" (`crates/ea-writer/src/marker.rs`) — und dieser Beleg wurde
/// nie gefuehrt: das Feld wurde geschrieben, gelesen und nie verglichen. Ohne
/// den Vergleich uebernimmt die Wiederaufnahme hinter der unwiderruflichen
/// Grenze eine BELIEBIGE Grantmenge unter einem `.eip`, das einen anderen Plan
/// bindet — und `design.md` §9.4 verlangt genau umgekehrt, dass vorab
/// veroeffentlichte Grants „nur von der ZUGEHOERIGEN vorbereiteten Transaktion
/// uebernommen" werden.
///
/// Manipuliert wird GENAU dieses Feld und kein beliebiges Byte: der Hash steht
/// zweimal in der Marke — einmal als ihr eigenes Feld, einmal im eingebetteten
/// `manifestCore` des `.eip` —, und nur die ERSTE Fundstelle ist das Feld. Eine
/// Manipulation an einer beliebigen Stelle fiele schon an der Gestalt auf und
/// wuerde diesen Leser nie erreichen.
#[test]
fn a_marker_whose_grant_plan_hash_contradicts_the_entry_is_refused() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterAbsenceConfirmation)
        .expect("der Abbruch hinter der Grenze muss erreichbar sein");

    let plan_hash = signed_grant_plan_hash(&harness);
    let mut bytes = prepared_marker_bytes(&harness);
    let occurrences = bytes
        .windows(plan_hash.len())
        .filter(|window| *window == plan_hash.as_slice())
        .count();
    assert_eq!(
        occurrences, 2,
        "der Plan-Hash steht als eigenes Markenfeld UND im signierten manifestCore — \
         ohne beide Fundstellen misst dieser Test nichts"
    );
    let field = bytes
        .windows(plan_hash.len())
        .position(|window| window == plan_hash.as_slice())
        .expect("die erste Fundstelle ist das Markenfeld");
    bytes[field..field + plan_hash.len()].copy_from_slice(&[0xa5; 32]);
    put_prepared_marker(&harness, bytes);

    let source = harness.source();
    let service = harness.service(&source);
    let refused = service
        .recover_pending()
        .expect_err("eine Marke, die ihrem eigenen .eip widerspricht, MUSS abgewiesen werden");
    assert_eq!(
        refused.code(),
        "EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT"
    );
    assert!(
        harness.published_entry_paths().is_empty(),
        "eine abgewiesene Marke veroeffentlicht nichts"
    );
    assert!(harness.published_grant_paths().is_empty());
}

/// Eine Marke OHNE einen einzigen Grant wird fail-closed abgewiesen.
///
/// Der Grant-Plan traegt „genau einen aktiven Recovery-Empfaenger und
/// ausnahmslos jedes aktive Reader-Zertifikat" (`design.md` §9.3 Schritt 5), ist
/// also NIE leer. Eine leere Marke ist damit keine Transaktion dieses Bauwerks,
/// und sie zu vollenden hiesse, einen Eintrag zu veroeffentlichen, den kein
/// Recovery-Empfaenger je wieder oeffnen kann.
///
/// Gebaut wird sie aus der ECHTEN Marke: die Grantliste wird an ihrer Grenze
/// abgeschnitten und durch die leere Liste ersetzt. Die Grenze ist die Stelle
/// unmittelbar hinter den eingebetteten Eintragsbytes, und die Zusicherung ueber
/// das dort stehende Byte belegt, dass wirklich der Listenkopf getroffen wurde.
#[test]
fn a_marker_without_a_single_grant_is_refused() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterAbsenceConfirmation)
        .expect("der Abbruch hinter der Grenze muss erreichbar sein");

    let entry_bytes = harness
        .backend()
        .read_for_test(&staged_entry_path(&harness))
        .expect("die gestagten Eintragsbytes muessen lesbar sein");
    let mut bytes = prepared_marker_bytes(&harness);
    let start = bytes
        .windows(entry_bytes.len())
        .position(|window| window == entry_bytes.as_slice())
        .expect("die Marke TRAEGT die Eintragsbytes");
    let list = start + entry_bytes.len();
    assert_eq!(
        bytes[list],
        0x80 | u8::try_from(harness.expected_grant_count()).expect("weniger als 24 Grants"),
        "hinter den Eintragsbytes steht der Kopf der Grantliste"
    );
    bytes.truncate(list);
    bytes.push(0x80);
    put_prepared_marker(&harness, bytes);

    let source = harness.source();
    let service = harness.service(&source);
    let refused = service
        .recover_pending()
        .expect_err("eine Marke ohne Grant MUSS abgewiesen werden");
    assert_eq!(
        refused.code(),
        "EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT"
    );
    assert!(harness.published_entry_paths().is_empty());
    assert!(harness.published_grant_paths().is_empty());
}

/// Eine Marke, die sich nicht DEKODIEREN laesst, haelt die Wiederaufnahme an.
///
/// # Der Unterschied zu den zwei Zeugen darueber
///
/// Dort sind die Bytes WOHLGEFORMT und widersprechen sich
/// (`EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT`); hier haben sie die Gestalt
/// dieses Baustands gar nicht erst. Die Klausel
/// (`crates/ea-writer/src/recover.rs`) ist die aelteste fail-closed Zusage des
/// Wiederaufnahmepfads — „aus halb gelesenen Bytes darf kein Bestand entstehen"
/// — und war in keinem Testverzeichnis getroffen: jede Marke, die je zur
/// Wiederaufnahme kam, hatte dieser Lauf selbst geschrieben.
///
/// Der Zwilling der Verwerfensseite ist
/// `crates/ea-draft/tests/discard_faults.rs`
/// ::a_transient_key_failure_aborts_the_restart_path_and_destroys_nothing:
/// dieselbe Bauart, ein Doppelgaenger fuer eine Lage, die der wahrhaftige Pfad
/// nie erzeugt.
#[test]
fn a_marker_that_does_not_decode_stops_the_recovery() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterPreparedMarkerCommit)
        .expect("der Abbruch vor der Grenze muss erreichbar sein");
    // Nicht leer und nicht zufaellig: ein CBOR-Feld der FALSCHEN Stelligkeit.
    // Damit faellt die Marke am ersten Gestalttor und nicht an einem
    // Laengenfehler, den ein Dekodierer auch anders melden koennte.
    put_prepared_marker(&harness, vec![0x86, 0x01]);

    let source = harness.source();
    let service = harness.service(&source);
    let refused = service
        .recover_pending()
        .expect_err("eine unlesbare Marke MUSS die Wiederaufnahme anhalten");
    assert_eq!(refused.code(), "EA-WRITER-PREPARED-FINALIZATION-UNREADABLE");

    // Nichts ist geschehen: nicht veroeffentlicht, und die Marke ist NICHT
    // geloest — ein Abbruch raeumt keinen Zustand weg, den er nicht versteht.
    assert!(harness.published_entry_paths().is_empty());
    assert!(harness.published_grant_paths().is_empty());
    assert!(harness.prepared_marker_is_present());
    assert!(!harness.draft_is_blank(), "der Entwurf steht unveraendert");
}

/// Eine Ablage, deren `load_or_create` GENAU EINMAL an einem
/// VORUEBERGEHENDEN Schluesselfehler scheitert.
///
/// Sie ist der Doppelgaenger fuer die Lage, die `recover_pending` ausdruecklich
/// benennt und die kein wahrhaftiger Port erzeugt: „Geraet gesperrt, TPM
/// belegt" — eine Aussage ueber JETZT und nicht ueber den Entwurf.
///
/// EINMALIG und nicht dauerhaft, aus demselben Grund wie
/// `BrieflyLockedProvider` auf der Verwerfensseite: erst das spaetere
/// Durchlassen belegt, dass der Entwurf die ganze Zeit wiederherstellbar war —
/// und damit, dass das Abbrechen die richtige Antwort war und keine verpasste
/// Gelegenheit.
struct BrieflyLockedRepository {
    inner: std::sync::Arc<dyn ea_draft::DraftRepository>,
    refusals_left: std::sync::atomic::AtomicUsize,
}

impl ea_draft::DraftRepository for BrieflyLockedRepository {
    fn load_or_create(&self) -> Result<ea_draft::Draft, ea_draft::DraftError> {
        use std::sync::atomic::Ordering;
        if self
            .refusals_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ea_draft::DraftError::Key(
                ea_key_provider::KeyError::PurposeMismatch,
            ));
        }
        self.inner.load_or_create()
    }

    fn save(&self, draft: ea_draft::Draft) -> Result<ea_draft::SavedDraft, ea_draft::DraftError> {
        self.inner.save(draft)
    }

    fn draft_dek_handle(
        &self,
        draft: &ea_draft::SavedDraft,
    ) -> Result<ea_key_provider::KeyHandle, ea_draft::DraftError> {
        self.inner.draft_dek_handle(draft)
    }

    fn commit_discard_intent(
        &self,
        draft: &ea_draft::SavedDraft,
    ) -> Result<ea_draft::DiscardIntent, ea_draft::DraftError> {
        self.inner.commit_discard_intent(draft)
    }

    fn pending_discard(&self) -> Result<Option<ea_draft::DiscardIntent>, ea_draft::DraftError> {
        self.inner.pending_discard()
    }

    fn replace_with_blank(&self) -> Result<ea_draft::SavedDraft, ea_draft::DraftError> {
        self.inner.replace_with_blank()
    }

    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &ea_draft::DiscardIntent,
    ) -> Result<ea_draft::DiscardOutcome, ea_draft::DraftError> {
        self.inner.remove_ciphertext_and_intent_create_blank(intent)
    }

    fn prepared_finalization_marker(
        &self,
    ) -> Result<Option<ea_draft::PreparedFinalizationMarker>, ea_draft::DraftError> {
        self.inner.prepared_finalization_marker()
    }

    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<ea_draft::PreparedFinalizationMarker>,
    ) -> Result<(), ea_draft::DraftError> {
        self.inner.replace_prepared_finalization_marker(marker)
    }

    fn acquire_draft_lock(&self) -> Result<ea_draft::DraftLock, ea_draft::DraftError> {
        self.inner.acquire_draft_lock()
    }
}

/// Ein VORUEBERGEHENDER Schluesselfehler bricht die Wiederaufnahme ab und
/// vollendet NICHTS.
///
/// # Was hier gemessen wird
///
/// `recover_pending` liest den ENTWURF als Zeugen der unwiderruflichen Grenze
/// und zaehlt GENAU ZWEI Fehler auf, die „der Schluessel ist fort" heissen:
/// `Key(NotFound)` und `Crypto(AeadOpen)`. Jeder andere Schluesselfehler ist
/// eine Aussage ueber JETZT — Geraet gesperrt, TPM belegt — und bricht ab.
/// Diese Klausel war unbezeugt.
///
/// Die Zusicherung ist FALSIFIZIERBAR und misst wirklich die enge Aufzaehlung:
/// waere sie zu `Err(_) => key_present = false` verallgemeinert, laese die
/// Wiederaufnahme den gesperrten Speicher als „Grenze ueberschritten", vollendete
/// aus den vorbereiteten Bytes — `publish_from_prepared` fragt keinen
/// Schluesselport — und veroeffentlichte ein `.eip`, dessen `draftDEK` in
/// Wahrheit noch benutzbar ist. Genau der Zustand, den `design.md` §9.4 mit
/// „zu keinem Zeitpunkt gleichzeitig ein committed `.eip` und ein nutzbarer
/// `draftDEK`" ausschliesst. Die Zeile ueber `published_entry_paths` faellt
/// dann.
#[test]
fn a_transient_key_failure_stops_the_recovery_and_completes_nothing() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterPreparedMarkerCommit)
        .expect("der Abbruch vor der Grenze muss erreichbar sein");
    let source = harness.source();
    let locked = std::sync::Arc::new(BrieflyLockedRepository {
        inner: harness.repository(),
        refusals_left: std::sync::atomic::AtomicUsize::new(1),
    }) as std::sync::Arc<dyn ea_draft::DraftRepository>;
    let service = ea_writer::WriterService::new(
        locked,
        harness.provider() as std::sync::Arc<dyn ea_key_provider::KeyProvider>,
        harness.backend(),
        &source,
        harness.head(),
        &[],
        ea_draft::IncidentNumberRegister::new(harness.database()),
        ea_draft::OperatorProfileRepository::new(harness.database()),
        harness.binding(),
    );

    let refused = service
        .recover_pending()
        .expect_err("ein voruebergehender Schluesselfehler MUSS abbrechen");
    assert_eq!(refused.code(), "EA-KEY-PURPOSE-MISMATCH");

    // Nichts ist dauerhaft geworden — und der Zustandscode allein sagte das
    // nicht: gemessen wird, dass NICHTS veroeffentlicht ist und die Marke
    // unberuehrt liegt.
    assert!(
        harness.published_entry_paths().is_empty(),
        "ein gesperrtes Geraet vollendet keine Transaktion"
    );
    assert!(harness.published_grant_paths().is_empty());
    assert!(harness.prepared_marker_is_present());

    // Und der Entwurf war die ganze Zeit wiederherstellbar: derselbe Dienst,
    // ein Zugriff spaeter, loest dieselbe Marke als Wiederherstellung auf.
    assert!(
        service
            .recover_pending()
            .expect("nach dem Entsperren muss die Wiederaufnahme tragen")
            .is_original_draft()
    );
    assert!(!harness.draft_is_blank());
    assert!(harness.published_entry_paths().is_empty());
}

/// Eine Finalisierung, die VOR der unwiderruflichen Grenze scheitert, gibt die
/// beanspruchte Einsatznummer wieder FREI.
///
/// # Warum der Zeuge einen tauben Schluesselspeicher braucht
///
/// Der dauerhafte Anspruch faellt erst im BESTAETIGTEN Lauf
/// (`crates/ea-writer/src/finalize.rs`, Schritt 5); ein Abbruch ueber
/// `finalize_interrupted_at` beansprucht die Nummer gar nicht erst und maesse
/// deshalb nichts. Gebraucht wird ein VOLLER Lauf, der zwischen dem Anspruch
/// und der Grenze scheitert — und der taube Speicher ist genau das: er haelt an
/// `EA-WRITER-KEY-DELETION-NOT-CONFIRMED` an, und dieser Code faellt
/// AUSSCHLIESSLICH, wenn `contains` den `draftDEK` positiv gemeldet hat. Die
/// Grenze ist damit nachweislich NICHT ueberschritten, der Entwurf ist
/// wiederherstellbar, und die Nummer gehoert demselben realen Einsatz.
///
/// Ohne die Freigabe muesste der Bediener sich fuer denselben Einsatz eine
/// andere Nummer ausdenken — dieselbe Abwaegung, die
/// `crates/ea-writer/tests/sequence_id.rs`
/// ::a_refused_finalization_does_not_burn_the_incident_number vor dem Anspruch
/// fuehrt, hier hinter ihm.
#[test]
fn a_finalization_that_fails_before_the_boundary_releases_the_incident_number() {
    let harness = WriterHarness::with_incident();
    let Err(refused) = harness.finalize_with_deaf_keystore() else {
        panic!("ein gemeldetes, nicht ausgefuehrtes Loeschen MUSS den Abschluss anhalten");
    };
    assert_eq!(refused.code(), "EA-WRITER-KEY-DELETION-NOT-CONFIRMED");
    // Die POSITIVKONTROLLE: der Lauf hat den Anspruch wirklich passiert. Ohne
    // sie waere „die Nummer ist frei" auch fuer einen Lauf gruen, der schon an
    // Schritt 3 gescheitert ist.
    assert!(
        harness.prepared_marker_is_present(),
        "Schritt 8 liegt hinter dem Anspruch: die Abschlussmarke MUSS stehen"
    );

    assert!(
        !harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER),
        "vor der Grenze gibt ein Fehlschlag die Nummer wieder frei"
    );

    // Und sie ist wirklich WIEDER BENUTZBAR — das ist die Zusage, nicht die
    // Registerzeile. Derselbe Bestand, dieselbe Nummer, ein wahrhaftiger
    // Speicher.
    let source = harness.source();
    let service = harness.service(&source);
    assert!(
        service
            .recover_pending()
            .expect("die Wiederaufnahme muss tragen")
            .is_original_draft()
    );
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let preview = service
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau MUSS erneut entstehen");
    service
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("derselbe Einsatz MUSS danach abschliessbar sein");
    assert!(harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER));
    assert_eq!(harness.published_entry_paths().len(), 1);
}

/// Hinter der Grenze bleibt die Einsatznummer VERBRAUCHT.
///
/// Der Waechter gegen eine zu grosszuegige Freigabe, und er ist die haertere
/// Haelfte: Schritt 13 scheitert, der Eintrag ist COMMITTED, und seine
/// Einsatznummer steht in einer veroeffentlichten Nutzlast. Gaebe die Freigabe
/// sie hier zurueck, koennte ein zweiter Einsatz dieselbe Nummer beanspruchen,
/// und die lokale Eindeutigkeitspruefung von `design.md`:1900 waere gebrochen —
/// bei zwei committed Eintraegen, die sich nicht mehr zuruecknehmen lassen.
///
/// Die Zusicherung ist FALSIFIZIERBAR: wandert die Entwaffnung der Freigabe
/// hinter Schritt 13, faellt die letzte Zeile.
#[test]
fn a_finalization_that_fails_after_the_boundary_keeps_the_incident_number() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ea_operator::ReauthPurpose::Finalize);
    let refusing = std::sync::Arc::new(BlankDraftRefusingRepository {
        inner: harness.repository(),
    }) as std::sync::Arc<dyn ea_draft::DraftRepository>;
    let blocked = ea_writer::WriterService::new(
        refusing,
        harness.provider() as std::sync::Arc<dyn ea_key_provider::KeyProvider>,
        harness.backend(),
        &source,
        harness.head(),
        &[],
        ea_draft::IncidentNumberRegister::new(harness.database()),
        ea_draft::OperatorProfileRepository::new(harness.database()),
        harness.binding(),
    );
    let preview = blocked
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau beruehrt Schritt 13 nicht");
    let error = blocked
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect_err("der leere Entwurf laesst sich nicht anlegen");
    assert_eq!(error.code(), "EA-DRAFT-LOCAL-RNG");

    // Der Eintrag ist committed — Schritt 13 liegt HINTER der Grenze.
    assert_eq!(harness.published_entry_paths().len(), 1);
    assert!(
        harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER),
        "hinter der Grenze traegt ein veroeffentlichter Eintrag die Nummer"
    );
}
