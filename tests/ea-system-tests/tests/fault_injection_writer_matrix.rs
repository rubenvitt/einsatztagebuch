//! Die Fehlermatrix der Stufe 2 — jeder deklarierte Abbruchpunkt, ein Ausgang.
//!
//! # Was diese Datei messen kann, was keine einzelne Crate messen kann
//!
//! `crates/ea-writer/tests/prepared_recovery.rs`,
//! `crates/ea-draft/tests/discard_faults.rs` und
//! `crates/ea-archive-fs/tests/profile_migration.rs` messen JE IHRE Invariante.
//! Diese Datei setzt Writer, Entwurfsablage, Wirtsbestand, Gesundheitscheck und
//! Verifikation in EINEN Prozess und fuegt genau das hinzu, was dort nirgends
//! stehen kann:
//!
//! * nach JEDEM Abbruchpunkt ist JEDES veroeffentlichte Archivobjekt
//!   vollstaendig — dieselbe Aussage, die der Buendelexport fail-closed
//!   verlangt, hier ueber einen Bestand, den der Writer selbst geschrieben hat;
//! * unter zwei Medienverweigerungen an jedem dieser Punkte entsteht kein
//!   halbes Archivobjekt, gemessen gegen das Inventar VOR der Verweigerung;
//! * die Vorrangregel des vorbereiteten Abschlusses gegen ein liegendes
//!   Verwerfen, gemessen am Neustartpfad der Entwurfsablage.
//!
//! Die Doppelung mit den crateweisen Tests ist ABSICHT und keine Nachlaessigkeit:
//! die Stufenabnahme braucht eine eigene, benannte Belegzeile, die den ganzen
//! Stapel in einem Lauf traegt.

mod support;

use ea_archive::{ArchiveBackendError, QuarantineReason};
use ea_archive_fs::{HealthFinding, MigrationFaultPoint};
use ea_draft::{DiscardFaultPoint, RestartState};
use ea_format::{ActiveProfilePointerCoreV1, EAG_PREFIX_V1, EIP_PREFIX_V1};
use ea_writer::{FinalizationFaultPoint, RecoveryOutcome, WriterError};

use support::{
    MatrixOutcome, MediumFailure, WriterMatrixHarness, archive_support, draft_support, occurrences,
    published_objects_are_complete, single_offset,
};

/// Die Befunde, die einen HALB geschriebenen Bestand bezeugen wuerden.
///
/// Die drei und nicht alle zehn, und das ist gemessen und nicht abgesprochen:
/// die Fixture des Writers legt ihre Vertrauenslinie NICHT im Bestand ab (der
/// Writer liest sie aus dem Vertrauensspeicher), also meldet jeder Lauf ueber
/// einen von ihr erzeugten Bestand
/// [`HealthFinding::IncompleteTrustData`] — strukturell und unabhaengig von
/// jeder Injektion. Und eine liegengebliebene Staging-Adresse ist
/// [`HealthFinding::OrphanGrantOrTemporaryFile`], aber ausdruecklich KEIN halbes
/// Archivobjekt: sie traegt den Suffix `.staging`, ist nicht veroeffentlicht und
/// gehoert dem Bestand nicht. Die drei hier sind die, die genau die Zusage
/// dieses Tests brechen wuerden.
const HALF_WRITTEN_ARCHIVE_FINDINGS: [HealthFinding; 3] = [
    HealthFinding::MissingFile,
    HealthFinding::ModifiedFile,
    HealthFinding::HashSignatureOrChainError,
];

#[test]
fn every_declared_stage_two_fault_point_has_exactly_one_survivable_outcome() {
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        let mut harness = WriterMatrixHarness::with_incident();
        let prepared = harness.interrupt_at(point);
        let resumed = harness.restart_from_disk();
        match resumed {
            MatrixOutcome::DraftUnchanged => {
                assert_eq!(
                    harness.draft_notes().as_deref(),
                    Some(harness.notes_before()),
                    "{point:?} liegt vor der Grenze: der Entwurf MUSS unveraendert lesbar sein"
                );
                assert!(
                    harness.archive_has_no_entry(),
                    "{point:?} liegt vor der Grenze und hat dennoch veroeffentlicht"
                );
            }
            MatrixOutcome::Committed => {
                let prepared = prepared.expect("hinter der Grenze liegt eine Abschlussmarke");
                let committed = harness
                    .committed_entry_bytes()
                    .expect("eine Vollendung veroeffentlicht genau einen Eintrag");
                // BYTEIDENTITAET, und nicht Enthaltensein. `CommittedFinalization`
                // mit `exact_bytes` ist nicht gebaut (`crates/ea-writer/src/lib.rs`
                // nennt den Grund), also wird gegen die Marke selbst gemessen —
                // aber in DREI Aussagen, von denen keine eine
                // Teilmengenpruefung ist:
                //
                // 1. der veroeffentlichte Eintrag steht GENAU EINMAL in der
                //    Marke, und die Scheibe an dieser Stelle ist ihm GLEICH;
                // 2. dasselbe fuer JEDEN veroeffentlichten Grant;
                // 3. die Marke traegt GENAU SO VIELE Archivobjekte, wie
                //    veroeffentlicht wurden — kein Objekt der Marke blieb
                //    liegen, und keines kam hinzu.
                //
                // Ohne 3. sagte 1. nur „etwas davon steht drin"; ohne 1. sagte
                // 3. nichts ueber die Bytes.
                let offset = single_offset(&prepared, &committed).unwrap_or_else(|| {
                    panic!(
                        "{point:?}: die veroeffentlichten Eintragsbytes stehen nicht GENAU EINMAL \
                         in der Abschlussmarke"
                    )
                });
                assert_eq!(
                    &prepared[offset..offset + committed.len()],
                    committed.as_slice(),
                    "{point:?}: die Abschlussmarke traegt an dieser Stelle andere Bytes"
                );
                for (path, bytes) in harness.committed_grant_bytes() {
                    let grant_offset = single_offset(&prepared, &bytes).unwrap_or_else(|| {
                        panic!("{point:?}: {path} steht nicht GENAU EINMAL in der Abschlussmarke")
                    });
                    assert_eq!(
                        &prepared[grant_offset..grant_offset + bytes.len()],
                        bytes.as_slice(),
                        "{point:?}: {path} traegt in der Marke andere Bytes"
                    );
                }
                assert_eq!(
                    occurrences(&prepared, &EIP_PREFIX_V1),
                    harness.inner().published_entry_paths().len(),
                    "{point:?}: die Marke fuehrt nicht genau die veroeffentlichten .eip-Objekte"
                );
                assert_eq!(
                    occurrences(&prepared, &EAG_PREFIX_V1),
                    harness.inner().published_grant_paths().len(),
                    "{point:?}: die Marke fuehrt nicht genau die veroeffentlichten .eag-Objekte"
                );
                // Und die veroeffentlichte Zahl gegen die GEPLANTE: ohne diese
                // Zeile sagten die beiden Zaehlungen nur, dass Marke und
                // Bestand einander gleichen — auch bei einem Grant zu wenig
                // auf beiden Seiten.
                assert_eq!(
                    harness.inner().published_grant_paths().len(),
                    harness.inner().expected_grant_count(),
                    "{point:?}: nicht jeder geplante Grant ist veroeffentlicht"
                );
                // Die Zusage, die `docs/traceability/stage-2-gate.md` von
                // dieser Datei zitiert: ein committed `.eip` und ein nutzbarer
                // `draftDEK` existieren NIE zugleich. Sie stand hier als
                // `draft_is_blank() || !draft_dek_is_present()` und konnte sie
                // nicht messen — `draft_dek_is_present` ist
                // `load_or_create().is_ok()`, und nach Schritt 13 liegt ein
                // leerer Entwurf mit FRISCHEM Schluessel, also war die linke
                // Haelfte immer wahr und die rechte immer falsch. Gemessen wird
                // jetzt der CIPHERTEXT: kein Geheimnis, das dieser
                // Schluesselspeicher hergibt, oeffnet den veroeffentlichten
                // Eintrag — mit Positivkontrolle in
                // `writer_keys_cannot_decrypt`.
                let entry_hash = harness
                    .committed_entry_hash()
                    .expect("eine Vollendung veroeffentlicht genau einen Eintrag");
                assert!(
                    harness.inner().writer_keys_cannot_decrypt(entry_hash),
                    "{point:?}: ein Geheimnis dieses Writers oeffnet den committed Eintrag"
                );
                // Und die Nachbedingung von Schritt 13 daneben, als eigene
                // Aussage statt als Oder-Zweig: der Entwurf ist leer.
                assert!(
                    harness.inner().draft_is_blank(),
                    "{point:?}: ein committed Eintrag und der ihn erzeugende Entwurf zugleich"
                );
            }
            MatrixOutcome::BackupTookThePreparedBytes => {
                // Der EINE benannte Sonderfall. Er ist an genau diesen Punkt
                // gebunden; jeder andere Punkt, der hier landete, waere ein
                // Defekt und kein dritter Ausgang.
                assert_eq!(
                    point,
                    FinalizationFaultPoint::BackupRestoreAfterKeyDeletion,
                    "nur die Rueckspielung darf die vorbereiteten Bytes mitnehmen"
                );
                assert!(
                    harness.archive_has_no_entry(),
                    "die Rueckspielung veroeffentlicht nichts"
                );
                // Gefragt wird der SCHLUESSELSPEICHER und nicht die Ablage.
                // Hier stand `draft_is_blank() || !draft_dek_is_present()`, und
                // das war eine WIEDERHOLUNG der Bedingung, die diesen Arm
                // ueberhaupt erkennt: `restart_from_disk` klassifiziert
                // `BackupTookThePreparedBytes` genau dann, wenn `draft_notes()`
                // nichts liefert — und das ist derselbe fehlgeschlagene
                // `load_or_create`. Die Zusicherung konnte deshalb nicht
                // fehlschlagen. Der Speicher ist die andere Seite: er fuehrt
                // den Eintrag unter der Adresse, die die Fixture beim Saeen
                // genommen hat (Positivkontrolle in
                // `WriterMatrixHarness::with_incident`), und nach dem Loeschen
                // fuehrt er ihn nicht mehr — die Rueckspielung der
                // DATENBANKDATEIEN bringt ihn nicht zurueck.
                assert!(
                    harness.inner().draft_dek_entry_is_absent(),
                    "der geraetegebundene Schluesselspeichereintrag kehrt NICHT mit den Dateien \
                     zurueck"
                );
            }
        }
        // Die Zusage, die keine crateweise Datei traegt: was veroeffentlicht
        // ist, ist VOLLSTAENDIG. Abgeschnittene Bytes behalten ihr
        // Exact-Object-Praefix und scheitern am Parser dahinter.
        harness
            .every_published_object_is_complete()
            .unwrap_or_else(|defect| panic!("{point:?}: {defect}"));
    }
}

#[test]
fn every_declared_discard_fault_point_restarts_into_one_of_two_states() {
    for point in DiscardFaultPoint::ALL.iter().copied() {
        let mut harness = draft_support::DraftHarness::with_nonempty_draft();
        let _ = harness.discard_with_fault(point);
        let state = harness
            .restart_and_resume()
            .unwrap_or_else(|error| panic!("{point:?}: der Neustart muss tragen: {error:?}"));
        assert!(
            state == RestartState::OriginalDraftUnchanged || state == RestartState::NewBlankDraft,
            "{point:?} restarted into {state:?}"
        );
        // Ein halb verworfener Entwurf ist keiner der beiden Zustaende, und
        // genau das wird hier zusaetzlich gemessen: nach dem Neustart steht
        // KEINE Verwerfensabsicht mehr offen.
        assert!(
            harness.pending_discard_is_absent(),
            "{point:?}: nach dem Neustart steht noch eine Verwerfensabsicht offen"
        );
    }
}

/// Wie eine Medienverweigerung an einem Abbruchpunkt UEBERHAUPT einen
/// dauerhaften Schreibvorgang treffen kann.
///
/// # Warum diese Klassifikation ueberhaupt noetig ist
///
/// `WriterService::finalize` weist einen zweiten Anlauf an der Markenpruefung
/// ab, BEVOR ein einziges Byte geschrieben wird. Fuer jeden Punkt ab
/// [`FinalizationFaultPoint::AfterPreparedMarkerCommit`] beruehrt eine zweite
/// Finalisierung das Medium also NIE, und ein blosses `is_err()` waere dort aus
/// einem mit dem Medium unverwandten Grund wahr. Hinter der Grenze ist
/// `WriterService::recover_pending` der einzige Weg, auf dem noch Bytes in den
/// Bestand gehen — und er geht denselben `publish_from_prepared`-Pfad wie der
/// glatte Lauf. Deshalb faehrt dieser Test je Punkt GENAU die Operation, die
/// dort noch schreiben kann, und sichert den erwarteten FEHLERTYP zu statt
/// irgendeinen Fehler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediumProbe {
    /// Vor der Abschlussmarke: eine neue Finalisierung laeuft an und schreibt in
    /// den Staging-Bereich. Das Medium MUSS sie abweisen.
    FinalizeIsRefused,
    /// Die Marke liegt und der `draftDEK` ist noch da: der Neustart LOEST die
    /// Marke und schreibt keinen Byte in den Bestand.
    RecoveryReleasesTheMarker,
    /// Die Marke liegt, der Schluessel ist fort und es steht noch ein Objekt
    /// aus: der Neustart will veroeffentlichen, und das Medium MUSS ihn
    /// abweisen.
    RecoveryPublishIsRefused,
    /// Die Marke liegt, und JEDES ihrer Objekte ist schon veroeffentlicht. Die
    /// Wiederholung schreibt keinen NEUEN Byte — `create_if_absent` traegt die
    /// bytegleiche Wiederholung — und vollendet deshalb auch auf einem
    /// verweigernden Medium. Ein Fehler waere hier der Defekt.
    RepetitionWritesNothing,
    /// Die zurueckgespielte Sicherung wurde VOR dem Buchen der Marke
    /// aufgenommen: es liegt keine Marke, der Schluessel ist fort, und der
    /// Neustart hat nichts zu tun. Kein Weg fuehrt hier noch an das Medium.
    NoMarkerAndNothingPending,
}

impl MediumProbe {
    /// Ob an diesem Punkt eine Abschlussmarke in der Ablage steht.
    ///
    /// Die Erwartung steht als LITERAL neben dem Punkt und wird gegen die
    /// gemessene Ablage geprueft: verschiebt ein spaeterer Baustand die Grenze,
    /// faellt die Klassifikation auf und nicht bloss die Zusicherung dahinter.
    const fn expects_a_prepared_marker(self) -> bool {
        matches!(
            self,
            Self::RecoveryReleasesTheMarker
                | Self::RecoveryPublishIsRefused
                | Self::RepetitionWritesNothing
        )
    }

    /// Ob diese Klasse das Medium wirklich erreicht.
    const fn reaches_the_medium(self) -> bool {
        matches!(
            self,
            Self::FinalizeIsRefused | Self::RecoveryPublishIsRefused
        )
    }
}

/// Die Klasse JEDES der zwoelf Punkte, als unabhaengiges Literal.
const fn medium_probe_of(point: FinalizationFaultPoint) -> MediumProbe {
    match point {
        FinalizationFaultPoint::BeforeStagingCreate
        | FinalizationFaultPoint::AfterStagingCreateBeforeFileFlush
        | FinalizationFaultPoint::AfterStagingFileFlushBeforeDirectoryFlush
        | FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker => {
            MediumProbe::FinalizeIsRefused
        }
        FinalizationFaultPoint::AfterPreparedMarkerCommit => MediumProbe::RecoveryReleasesTheMarker,
        FinalizationFaultPoint::AfterKeystoreDelete
        | FinalizationFaultPoint::AfterAbsenceConfirmation
        | FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename => {
            MediumProbe::RecoveryPublishIsRefused
        }
        // Die drei letzten Punkte der Reihenfolge haben ihre Objekte schon
        // veroeffentlicht: `.eag` und `.eip` liegen, und die Wiederaufnahme
        // wiederholt sie bytegleich.
        FinalizationFaultPoint::AfterEntryRenameBeforeDirectoryFlush
        | FinalizationFaultPoint::AfterEntryDirectoryFlush
        | FinalizationFaultPoint::AfterReconciliationBeforeBlankDraft => {
            MediumProbe::RepetitionWritesNothing
        }
        FinalizationFaultPoint::BackupRestoreAfterKeyDeletion => {
            MediumProbe::NoMarkerAndNothingPending
        }
    }
}

/// Wie viele der 24 Iterationen (12 Punkte x 2 Verweigerungen) das Medium
/// WIRKLICH erreichen.
///
/// Die Zahl steht als Literal und nicht als Nebenprodukt: acht Iterationen vor
/// der Grenze (vier Staging-Punkte) und sechs dahinter (die drei Punkte, an
/// denen die Wiederaufnahme noch veroeffentlichen muss). Die uebrigen zehn
/// haben nichts zu schreiben, und diese Datei sagt das AUS statt sie als
/// Messung mitzuzaehlen.
const ITERATIONS_THAT_REACH_THE_MEDIUM: usize = 14;

/// Die Fehler, mit denen das MEDIUM eine Verweigerung meldet.
///
/// Eng aufgezaehlt und nicht `is_err()`: `AlreadyLocked`,
/// `PreparedFinalizationPresent` oder ein Entwurfsfehler waeren ebenfalls
/// `Err`, sagten aber nichts ueber das Medium.
fn is_a_medium_refusal(error: &WriterError) -> bool {
    matches!(
        error,
        WriterError::Backend(ArchiveBackendError::Io | ArchiveBackendError::FlushFailed)
    )
}

#[test]
fn a_media_failure_at_any_durable_step_never_produces_a_half_written_archive() {
    let mut reached_the_medium = 0_usize;
    for point in FinalizationFaultPoint::ALL.iter().copied() {
        for failure in [MediumFailure::NoSpaceLeft, MediumFailure::ReadOnlyMount] {
            let probe = medium_probe_of(point);
            let mut harness = WriterMatrixHarness::with_incident();
            let _ = harness.interrupt_at(point);
            assert_eq!(
                harness.inner().prepared_marker_is_present(),
                probe.expects_a_prepared_marker(),
                "{point:?}: die Ablage widerspricht der Klasse {probe:?}"
            );
            // Das ERWARTETE Inventar entsteht VOR der Verweigerung. Aus den
            // tatsaechlichen Bytes gebildet koennten `MissingFile` und
            // `ModifiedFile` nie feuern, und die Zusicherung waere leer.
            let expected = harness.inventory();
            let before = harness.archive_digest_map();
            harness.fail_the_medium(failure);
            // GENAU die Operation, die an diesem Punkt noch schreiben kann —
            // und ihr erwarteter Ausgang, nicht bloss „irgendein Fehler".
            match probe {
                MediumProbe::FinalizeIsRefused => {
                    let error = harness.finalize().map_or_else(
                        |error| error,
                        |outcome| {
                            panic!(
                                "{point:?}/{failure:?}: das Medium verweigert, und der Abschluss \
                                 meldet {outcome:?}"
                            )
                        },
                    );
                    assert!(
                        is_a_medium_refusal(&error),
                        "{point:?}/{failure:?}: abgewiesen wurde mit {error:?} und nicht vom Medium"
                    );
                    reached_the_medium += 1;
                }
                MediumProbe::RecoveryReleasesTheMarker => {
                    let resumed = harness
                        .resume_pending()
                        .expect("die Marke vor der Grenze MUSS sich loesen lassen");
                    assert!(
                        matches!(resumed, RecoveryOutcome::DraftRestored { .. }),
                        "{point:?}/{failure:?}: {resumed:?} statt eines geloesten Entwurfs"
                    );
                    assert!(
                        !harness.inner().prepared_marker_is_present(),
                        "{point:?}/{failure:?}: die Marke liegt noch"
                    );
                }
                MediumProbe::RecoveryPublishIsRefused => {
                    let error = harness.resume_pending().map_or_else(
                        |error| error,
                        |outcome| {
                            panic!(
                                "{point:?}/{failure:?}: das Medium verweigert, und die \
                                 Wiederaufnahme meldet {outcome:?}"
                            )
                        },
                    );
                    assert!(
                        is_a_medium_refusal(&error),
                        "{point:?}/{failure:?}: abgewiesen wurde mit {error:?} und nicht vom Medium"
                    );
                    reached_the_medium += 1;
                }
                MediumProbe::RepetitionWritesNothing => {
                    // Sie VOLLENDET. Die Zusage traegt hier NICHT das `Ok` —
                    // es sagt nur, dass die Wiederholung nichts mehr
                    // anzufordern hatte —, sondern die Bytekarte unten:
                    // `archive_digest_map() == before` ist die Aussage „kein
                    // neuer Byte". Ein Fehler waere trotzdem der Defekt: er
                    // hiesse, dass die Wiederholung ein schon liegendes Objekt
                    // NEU schreiben will.
                    let resumed = harness.resume_pending().unwrap_or_else(|error| {
                        panic!("{point:?}/{failure:?}: nichts steht aus, und dennoch {error:?}")
                    });
                    assert!(
                        matches!(resumed, RecoveryOutcome::CommittedFromPreparedBytes { .. }),
                        "{point:?}/{failure:?}: {resumed:?} statt einer Vollendung"
                    );
                }
                MediumProbe::NoMarkerAndNothingPending => {
                    let resumed = harness.resume_pending().unwrap_or_else(|error| {
                        panic!("{point:?}/{failure:?}: nichts steht aus, und dennoch {error:?}")
                    });
                    assert_eq!(
                        resumed,
                        RecoveryOutcome::NothingPending,
                        "{point:?}/{failure:?}: die zurueckgespielte Sicherung traegt keine Marke"
                    );
                }
            }
            // Der TRAGENDE Zeuge: der verweigerte Schreibvorgang hat den
            // Bestand nicht angetastet. Er wird VOR dem Heilen und vor dem
            // Gesundheitscheck genommen, weil der Capability-Test des Checks
            // selbst in die Kratzwurzel schreibt.
            assert_eq!(
                harness.archive_digest_map(),
                before,
                "{point:?}/{failure:?}: der abgewiesene Schreibvorgang hat Bytes im Bestand \
                 veraendert"
            );
            harness.heal_the_medium();
            let report = harness.health_against(&expected);
            for finding in HALF_WRITTEN_ARCHIVE_FINDINGS {
                assert!(
                    !report.contains(finding),
                    "{point:?}/{failure:?} hinterliess {finding:?}; gemeldet wurde {:?}",
                    report.findings()
                );
            }
            harness
                .every_published_object_is_complete()
                .unwrap_or_else(|defect| panic!("{point:?}/{failure:?}: {defect}"));
        }
    }
    // Die POSITIVKONTROLLE der Matrix selbst: eine Klassifikation, die alles
    // als „nichts zu schreiben" fuehrte, waere gruen und leer.
    assert_eq!(
        reached_the_medium, ITERATIONS_THAT_REACH_THE_MEDIUM,
        "so viele Iterationen haben das Medium wirklich erreicht"
    );
    assert_eq!(
        FinalizationFaultPoint::ALL
            .iter()
            .copied()
            .filter(|point| medium_probe_of(*point).reaches_the_medium())
            .count()
            * 2,
        ITERATIONS_THAT_REACH_THE_MEDIUM
    );
}

#[test]
fn an_interrupted_profile_migration_leaves_exactly_one_active_pointer() {
    for point in MigrationFaultPoint::ALL.iter().copied() {
        let harness = archive_support::migration_harness();
        let migrator = harness.migrator();
        let outcome = migrator.with_fault(point).run();
        assert!(outcome.is_err(), "{point:?} MUSS die Migration abbrechen");
        // GENAU EIN aktiver Zeiger — und gelesen AUS DER ABLAGE.
        //
        // `migrator.active_profile_hash()` liest den In-Memory-Spiegel DERSELBEN
        // abgebrochenen Instanz; ein Zeiger, der auf der Platte das Zielprofil
        // nennt, waehrend der Spiegel das Quellprofil zeigt, fiele dort nicht
        // auf. Der dauerhafte Zeiger liegt in der Wurzel des ZIELprofils —
        // dorthin schreiben Umschaltung UND Ruecknahme
        // (`crates/ea-archive-fs/src/profile_migration.rs`) —, also werden
        // BEIDE Wurzeln gelesen.
        let on_disk: Vec<(&str, Vec<u8>)> = [
            ("die Quellwurzel", harness.source()),
            ("die Zielwurzel", harness.target()),
        ]
        .into_iter()
        .filter_map(|(label, backend)| {
            backend
                .active_profile_pointer_bytes()
                .map(|bytes| (label, bytes))
        })
        .collect();
        assert!(
            on_disk.len() <= 1,
            "{point:?}: zwei Wurzeln fuehren einen aktiven Profilzeiger: {:?}",
            on_disk.iter().map(|(label, _)| *label).collect::<Vec<_>>()
        );
        if let Some((label, bytes)) = on_disk.first() {
            // GLEICHHEIT gegen die einzigen zwei erreichbaren Zeiger und keine
            // Beschreibung: Generation 1 entsteht beim Umschalten, Generation 2
            // bei der Ruecknahme, und beide MUESSEN das QUELLprofil nennen.
            // Ein Zeiger auf das Zielprofil faellt hier auf, gleich welcher
            // Generation.
            let allowed: Vec<Vec<u8>> = [1_u64, 2]
                .into_iter()
                .map(|generation| {
                    ea_format::encode_active_profile_pointer_core(&ActiveProfilePointerCoreV1::new(
                        archive_support::source_profile_hash(),
                        generation,
                    ))
                    .expect("der Zeiger der Fixture ist kodierbar")
                })
                .collect();
            assert!(
                allowed.contains(bytes),
                "{point:?}: {label} fuehrt einen Zeiger, der nicht das Quellprofil bei \
                 Generation 1 oder 2 nennt"
            );
        }
        // Und der Spiegel sagt dasselbe wie die Ablage.
        assert_eq!(
            migrator.active_profile_hash().as_bytes(),
            archive_support::source_profile_hash().as_bytes(),
            "{point:?} liess mehr als das alte Profil aktiv"
        );
        assert!(
            migrator.finalization_lock().is_available(),
            "{point:?} gab die Finalisierungssperre nicht frei"
        );
        // Und der Bestand ist danach GANZ lesbar: jedes Archivobjekt des
        // Quellprofils traegt weiterhin alle seine Bytes.
        published_objects_are_complete(harness.source())
            .unwrap_or_else(|defect| panic!("{point:?}: {defect}"));
    }
}

#[test]
fn a_prepared_finalization_survives_a_crash_and_beats_a_pending_discard() {
    let mut harness = draft_support::DraftHarness::with_nonempty_draft();
    // Erst die Absicht buchen, dann die Marke legen: die Vorrangregel gilt an
    // JEDEM Eingang, also auch an dem, an dem das Verwerfen schon dauerhaft
    // gebucht ist.
    harness
        .discard_with_fault(DiscardFaultPoint::AfterIntentCommit)
        .expect("die gebuchte Absicht muss erreichbar sein");
    harness.set_prepared_finalization_marker();
    let state = harness
        .restart_and_resume()
        .expect("die Wiederaufnahme muss gelingen");
    assert_eq!(
        state,
        RestartState::PreparedFinalizationPending,
        "eine liegende Abschlussmarke hat Vorrang vor einer gebuchten Verwerfensabsicht"
    );
    // Sie hat Vorrang, und sie VERBRAUCHT die Absicht nicht: ein zweiter
    // Neustart meldet denselben Zustand. Eine GLEICHHEIT und keine
    // Beschreibung.
    assert_eq!(
        harness
            .restart_and_resume()
            .expect("der zweite Neustart muss tragen"),
        RestartState::PreparedFinalizationPending
    );
    assert!(
        harness.draft_dek_is_present(),
        "solange die Marke liegt, wird kein Verwerfen fortgesetzt"
    );
}

/// Eine liegengebliebene `.eip.staging` macht denselben Bestand nach einem
/// zweiten Anlauf NICHT „geforkt".
///
/// # Der Weg, und warum er der gewoehnliche ist
///
/// Ein Absturz an [`FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker`]
/// laesst die geflushten Stagingbytes liegen; die Wiederaufnahme raeumt sie
/// ausdruecklich nicht auf, weil der Port kein Loeschprimitiv hat. Der zweite
/// Anlauf zieht frischen CEK, frische Nonce und frische `recordId`, hat damit
/// einen ANDEREN `entryHash` — und committet dieselbe Sequenz, weil der Kopf
/// des Writers weiterhin davor steht. Damit lagen zwei Eintragsobjekte mit
/// derselben Sequenz und verschiedenem `entryHash` im Bestand, SOBALD ein
/// Leser die Staging-Adresse als Archivobjekt nimmt.
///
/// # Was hier gemessen wird
///
/// Dass ALLE Leser derselben Bytes denselben Bestand sehen: die Regel steht in
/// [`ea_archive::is_staging_path`], und die Lesesicht des Wirtsbestands wendet
/// sie an. Beide Haelften sind noetig, und die zweite ist die scharfe: ohne sie
/// waere dieselbe Zusicherung auch gruen, wenn die Datei UEBERALL unsichtbar
/// waere — dann waere aus einem falschen Fork-Alarm ein verschwiegener
/// Gesundheitsbefund geworden.
///
/// Die Zusicherung ist FALSIFIZIERBAR: sieht die Lesesicht die Staging-Adresse
/// wieder, meldet der Verifikationslauf ein bestrittenes Objekt und der
/// Gesundheitsbericht [`HealthFinding::UnexpectedSequenceForkOrRollback`] —
/// DAUERHAFT, denn es gibt kein Loeschprimitiv.
#[test]
fn a_leftover_staging_object_never_forks_a_successful_second_attempt() {
    let mut harness = WriterMatrixHarness::with_incident();
    let _ = harness.interrupt_at(FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker);
    assert!(matches!(
        harness.restart_from_disk(),
        MatrixOutcome::DraftUnchanged
    ));
    assert!(
        harness.inner().staged_object_count() > 0,
        "ohne liegengebliebenes Staging messe dieser Test nichts"
    );
    assert!(harness.archive_has_no_entry());

    // Der gewoehnliche zweite Anlauf — dieselbe Sequenz, andere Geheimnisse.
    let committed = harness
        .finalize()
        .expect("der zweite Anlauf muss tragen, die Sequenz war unverbraucht");
    assert_eq!(committed.sequence.get(), 0);
    assert_eq!(harness.inner().published_entry_paths().len(), 1);
    assert!(
        harness.inner().staged_object_count() > 0,
        "die Reste liegen weiter — gemessen wird der Filter und keine Bereinigung"
    );

    // 1. Die Kette ist unbestritten und lueckenlos.
    let verification = harness.verification();
    assert_eq!(verification.gaps().len(), 0, "die Kette hat keine Luecke");
    assert!(
        !verification
            .quarantined_objects()
            .any(|object| object.reason() == QuarantineReason::Conflicting),
        "kein Objekt ist bestritten"
    );

    // 2. Und der Gesundheitsbericht trennt die beiden Aussagen: kein Fork,
    //    aber die temporaere Datei ist gemeldet.
    let expected = harness.inventory();
    let report = harness.health_against(&expected);
    assert!(
        !report.contains(HealthFinding::UnexpectedSequenceForkOrRollback),
        "ein korrekter Bestand traegt keinen Fork-Befund; gemeldet wurde {:?}",
        report.findings()
    );
    assert!(
        report.contains(HealthFinding::OrphanGrantOrTemporaryFile),
        "die liegengebliebene Staging-Datei MUSS gemeldet bleiben; gemeldet wurde {:?}",
        report.findings()
    );
    harness
        .every_published_object_is_complete()
        .unwrap_or_else(|defect| panic!("{defect}"));
}
