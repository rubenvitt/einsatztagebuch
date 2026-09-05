//! Der Datei-Modus des Readers, SYSTEMweit: derselbe Bestand im Server-Modus,
//! als Ein-Datei-Buendel und als Buendel ohne Quittungen — dazu das
//! untergeschobene Archiv gegen den gepinnten Anker.
//!
//! Plan: `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`,
//! Absatz *Datei-Modus* des Task-14-Abschnitts. Lauf (a) und (b) belegen
//! die INTEROPERABILITAET, NUR Lauf (c) traegt die Ledgerzeilen `WR-053` und
//! `WR-054`; der Negativfall ist die systemweite Wiederholung von
//! `crates/ea-reader/tests/file_mode_anchor.rs` und `pinned_anchor.rs`, deren
//! primaerer Beleg dort bleibt.
//!
//! # Was hier GEMESSEN wurde und den Plantext korrigiert
//!
//! Der Plan sagt, Lauf (b) sei „dasselbe, exportierte Ein-Datei-Buendel" des
//! quittungstragenden Bestands, und misst `write_archive_bundle` als den
//! Exporteur, der jede Adresse einschliesslich der `.esr` einpackt. Beides
//! stimmt fuer den Kodierer — und trotzdem kann der Exporteur in diesem Baum
//! KEINEN quittungstragenden Bestand exportieren: Schritt 4 von
//! `write_archive_bundle` (`crates/ea-archive-fs/src/bundle.rs`) verlangt
//! `is_fully_verified()`, und jeder quittungstragende Bestand der Kulisse
//! traegt die Vorlauf-Luecke `0..=RECEIPT_PRE_ENTRY_GAP_THROUGH_V1`
//! (`crates/ea-verify/tests/support/mod.rs`, `RECEIPT_PRE_ENTRY_GAP_THROUGH_V1`
//! — „Wer sie wegrepariert, macht die Fixtures unwahr"). Der Stufe-2-Bestand
//! der Writer-Fixture verifiziert ebenfalls nicht vollstaendig
//! (`apps/server/tests/writer_sync_e2e.rs`, Modulkopf), und die einzige Linie,
//! die der volle Verifizierer MIT Serverquittungszertifikat bestaetigt, steht
//! hinter dem echten Server und ausserhalb der Kanten dieser Crate.
//!
//! Die Aufteilung ist deshalb:
//!
//! - (a)/(b) laufen ueber den quittungstragenden Kulissenbestand; das Buendel
//!   entsteht ueber `exported_bundle_bytes` aus
//!   `crates/ea-reader/tests/verify_fixtures/fixtures.rs` — denselben
//!   Containerkodierer, gegen den `ArchiveBundleSource::from_bytes` beim
//!   Oeffnen jede Strukturregel prueft. Die Weigerung des Exporteurs ueber
//!   genau diesem Bestand ist als eigener Zeuge GEPINNT, damit ein kuenftiger
//!   lueckenfreier Quittungsbestand diesen Zeugen rot faerbt und (b) auf den
//!   echten Exporteur umgehaengt wird.
//! - (c) laeuft ZWEIMAL: einmal ueber DEMSELBEN quittungstragenden Bestand mit
//!   vorenthaltenen `.esr` (die orthogonale Dimension senkt nichts — dieselben
//!   Objektergebnisse, dieselben Luecken, nur die Spalte kippt), und einmal
//!   ueber dem lueckenlosen Bestand durch den ECHTEN `write_archive_bundle`
//!   auf einer echten `LocalPathBackend`-Wurzel, wo `gaps()` leer und
//!   `is_fully_verified()` wahr ist. Nur der zweite traegt `WR-053`/`WR-054`.
//!
//! # Die Einstiegspunkte
//!
//! Server-Modus ist `ReaderVerifier::new(ReaderMode::Server, ..).classify`
//! ueber einer `ArchiveSource`; Datei-Modus ist `ReaderFileMode::open_bundle`
//! beziehungsweise `open_bundle_observed` ueber den Containerbytes — OHNE
//! Ankerparameter, der gepinnte Anker des Tresors ist die einzige
//! Vertrauensquelle (`crates/ea-reader/src/file_mode.rs`).

mod file_mode_interop_support;

use ea_archive_fs::{BundleError, LocalPathBackend, write_archive_bundle};
use ea_reader::{
    ArchiveSource, ChainSequence, GATE_ORDER_V1, ObjectResultKindV1, PinnedTrustAnchor,
    ReaderClassification, ReaderFileMode, ReaderMode, ReaderVerifier, RecordingObserver,
    ServerConfirmationV1, SilentObserver, UnlockedVault, decode_trust_anchor,
};
use ea_verify::{VerifyOptions, verify_archive};

use file_mode_interop_support::{
    archive_fs_support, gap_rows, receipt_count, result_rows,
    verify_fixtures::{fixtures, verify_support},
    without_receipts,
};

/// Lauf (a): der Server-Modus ueber einer Quelle, still.
///
/// Der Server-Modus des Readers nimmt seine Bytes aus dem Lesestapel; die
/// KLASSIFIKATION selbst ist `ReaderVerifier::classify`, und `classify` liest
/// den Modus nicht (`crates/ea-reader/src/verify.rs`, Typkommentar). Genau
/// deshalb ist ein Lauf mit `ReaderMode::Server` ueber derselben Quelle der
/// Vergleichslauf, den der Plan meint.
fn server_mode(source: &dyn ArchiveSource, vault: &UnlockedVault) -> ReaderClassification {
    ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(source, vault, &mut SilentObserver)
        .expect("ein Kulissenbestand laesst sich im Server-Modus klassifizieren")
}

/// Lauf (a) gegen Lauf (b): `archiveObjectCount`, `chainHead`, die Menge der
/// `objectResults` UND die Spalte `serverConfirmation` sind IDENTISCH.
///
/// Das belegt, dass Gate-Schritt 7 die mitgereisten Quittungen auswertet,
/// statt sie zu ignorieren: jede Zeile steht in (b) auf `serverConfirmed`, und
/// zwar auf genau derselben wie in (a). Die Berichtsgleichheit darueber ist
/// die staerkere Aussage und steht dazu — `reportHash` kennt keinen
/// Pfadhinweis, und die Kulissenquelle ist nicht sortiert, der Container
/// schon.
#[test]
fn the_bundle_reports_identically_to_the_server_mode_run_including_server_confirmation() {
    let archive = fixtures::archive_with_receipts();
    let vault = fixtures::unlocked_vault_with_pinned_anchor();

    // (a)
    let server = server_mode(archive, &vault);
    // (b)
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(archive),
        &vault,
        fixtures::EFFECTIVE_NOW,
    )
    .expect("das Buendel des Quittungsbestands muss oeffnen");
    assert_eq!(opened.mode(), ReaderMode::File);

    let (a, b) = (server.report(), opened.report());

    // ANTI-LEERLAUF: der Bestand traegt zu JEDEM Eintrag eine Quittung, und er
    // traegt Eintraege. Ohne diese Zeile waere „alle serverbestaetigt" auch
    // ueber einem leeren Bericht gruen.
    assert!(a.object_results().len() > 0);
    assert_eq!(receipt_count(archive), a.object_results().len());

    assert_eq!(a.archive_object_count(), b.archive_object_count());
    assert_eq!(a.chain_head(), b.chain_head());
    assert_eq!(result_rows(a), result_rows(b));
    assert!(
        a.object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed)
    );
    assert!(
        b.object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed)
    );
    assert!(
        b.object_results()
            .all(|result| result.result() == ObjectResultKindV1::Valid)
    );
    // KEIN `assert_eq!`: `Hash32` leitet kein `Debug` ab.
    assert!(a.report_hash() == b.report_hash());
    // Und die Zustandszeilen, die der Reader daraus bildet, sind dieselben.
    assert_eq!(
        server.states().len(),
        opened.classification().states().len()
    );
}

/// Lauf (c), erste Haelfte: DERSELBE Bestand, dem die `.esr` vorenthalten
/// sind, und die orthogonale Dimension senkt nichts.
///
/// Verglichen wird gegen Lauf (a) ueber dem vollen Bestand: dieselben
/// Eintraege bekommen dieselben Objektergebnisse (`Valid`), die Lueckenliste
/// ist DIESELBE, und die einzige Spalte, die kippt, ist `serverConfirmation`.
/// `is_fully_verified()` ist in BEIDEN Laeufen GEMESSEN falsch — wegen der
/// Vorlauf-Luecke der Quittungslinie und aus keinem Grund, der mit dem
/// Datei-Modus zu tun hat; gepinnt wird der Wert je Lauf und nicht die
/// Gleichheit, damit ein Bestand, der auf beiden Seiten still wahr wuerde,
/// rot bleibt. Die Zusage „`gaps()` leer und `is_fully_verified()` wahr"
/// traegt der Zeuge darunter ueber dem lueckenlosen Bestand.
#[test]
fn withholding_the_receipts_from_the_same_archive_flips_only_the_server_confirmation_column() {
    let archive = fixtures::archive_with_receipts();
    let withheld = without_receipts(archive);
    let vault = fixtures::unlocked_vault_with_pinned_anchor();

    // ANTI-LEERLAUF: es wurde wirklich etwas vorenthalten, und sonst nichts.
    assert!(receipt_count(archive) > 0);
    assert_eq!(receipt_count(&withheld), 0);
    assert_eq!(withheld.len(), archive.len() - receipt_count(archive));

    let full = server_mode(archive, &vault);
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(&withheld),
        &vault,
        fixtures::EFFECTIVE_NOW,
    )
    .expect("auch das Buendel ohne Quittungen muss oeffnen");
    let (a, c) = (full.report(), opened.report());

    assert_eq!(opened.mode(), ReaderMode::File);
    assert_eq!(
        c.archive_object_count(),
        a.archive_object_count() - receipt_count(archive)
    );
    assert_eq!(a.chain_head(), c.chain_head());
    assert_eq!(c.object_results().len(), a.object_results().len());
    assert!(
        c.object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed)
    );
    assert!(
        c.object_results()
            .all(|result| result.result() == ObjectResultKindV1::Valid)
    );
    // Bis auf die eine Spalte dieselben Zeilen.
    let strip_column = |rows: std::collections::BTreeSet<file_mode_interop_support::ResultRow>| {
        rows.into_iter()
            .map(|(hash, object_type, result, _)| (hash, object_type, result))
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(strip_column(result_rows(a)), strip_column(result_rows(c)));
    // Die Luecken sind DIESELBEN: das Vorenthalten der Quittungen hat keine
    // hinzugefuegt. GEMESSEN ist es genau eine, die Vorlauf-Luecke der Linie.
    assert_eq!(gap_rows(a), gap_rows(c));
    assert_eq!(c.gaps().len(), 1);
    let gap = c
        .gaps()
        .next()
        .expect("die Linie traegt ihre Vorlauf-Luecke");
    assert_eq!(gap.from_sequence(), ChainSequence::new(0));
    assert_eq!(
        gap.through_sequence(),
        ChainSequence::new(verify_support::RECEIPT_PRE_ENTRY_GAP_THROUGH_V1)
    );
    assert_eq!(c.quarantined_objects().len(), 0);
    assert_eq!(c.format_errors().len(), 0);
    assert_eq!(c.signature_errors().len(), 0);
    // Je Lauf der gemessene Wert, nicht die Gleichheit der beiden: die
    // Vorlauf-Luecke steht in (a) UND in (c).
    assert!(!a.is_fully_verified());
    assert!(!c.is_fully_verified());
}

/// Lauf (c), zweite Haelfte und Traeger von `WR-053`/`WR-054`: ein Buendel
/// aus dem ECHTEN Exporteur ueber dem lueckenlosen Bestand, ohne eine einzige
/// `.esr`.
///
/// Jedes Objekt steht auf `notServerConfirmed` UND `Valid`, `gaps()` ist
/// leer und `is_fully_verified()` bleibt wahr — die orthogonale Dimension
/// senkt nichts (`web-reader-design.md` §17.4). Systemweit ist daran die
/// Strecke: `LocalPathBackend` auf der Platte, `write_archive_bundle` mit
/// `O_CREAT|O_EXCL` und Flush, `fs::read` der Zieldatei, `open_bundle` —
/// und derselbe Bestand im Server-Modus ueber dem Verzeichnis, aus dem das
/// Buendel kam, ergibt denselben `reportHash`.
#[test]
fn a_bundle_without_receipts_is_not_server_confirmed_and_never_a_gap() {
    let harness = archive_fs_support::BundleHarness::finalized_archive();
    let vault = fixtures::unlocked_vault_with_pinned_anchor();

    // Der Tresor pinnt den Anker DIESES Plattenbestands — gemessen, nicht
    // angenommen: zwei Kopien der Fixturekette, ein Anker.
    assert!(harness.anchor().trust_anchor_hash() == fixtures::pinned_anchor_hash());
    // ANTI-LEERLAUF: der Bestand traegt keine Quittung und ist nicht leer.
    let relative = harness
        .backend()
        .relative_paths()
        .expect("der Plattenbestand muss lesbar sein");
    assert!(!relative.is_empty());
    assert!(
        relative
            .iter()
            .all(|path| !path.ends_with(file_mode_interop_support::RECEIPT_SUFFIX_V1))
    );

    let opened =
        ReaderFileMode::open_bundle(harness.exported_bytes(), &vault, fixtures::EFFECTIVE_NOW)
            .expect("das exportierte Buendel muss oeffnen");
    let report = opened.report();

    assert_eq!(opened.mode(), ReaderMode::File);
    assert_eq!(
        report.object_results().len(),
        fixtures::ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1
    );
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed)
    );
    assert!(
        report
            .object_results()
            .all(|result| result.result() == ObjectResultKindV1::Valid)
    );
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
    assert!(report.is_fully_verified());
    assert_eq!(
        opened.classification().states().len(),
        fixtures::ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1
    );

    // (a) ueber dem Verzeichnis, aus dem das Buendel kam.
    let server = server_mode(&harness.directory_source(), &vault);
    assert!(server.report().is_fully_verified());
    assert_eq!(
        server.report().archive_object_count(),
        report.archive_object_count()
    );
    assert_eq!(server.report().chain_head(), report.chain_head());
    assert_eq!(result_rows(server.report()), result_rows(report));
    assert!(server.report().report_hash() == report.report_hash());
}

/// Die GEMESSENE Abweichung vom Plantext, gepinnt.
///
/// `write_archive_bundle` packt jede Adresse einschliesslich der `.esr` ein
/// — und weigert sich trotzdem ueber dem quittungstragenden Bestand dieser
/// Kulisse, weil dessen Linie die Vorlauf-Luecke `0..=1` traegt und Schritt 4
/// `is_fully_verified()` verlangt. Es entsteht KEIN Ziel. Faellt dieser Zeuge
/// eines Tages rot, gibt es einen lueckenfreien Quittungsbestand, und Lauf (b)
/// oben gehoert auf den echten Exporteur umgehaengt.
#[test]
fn write_archive_bundle_refuses_the_receipt_bearing_fixture_because_its_line_carries_a_gap() {
    let (_lock, root) = archive_fs_support::temp_root("reader-file-mode-interop");
    let backend = LocalPathBackend::open(
        root.join("archive"),
        archive_fs_support::local_profile(),
        &archive_fs_support::policy_allowing_only_source(),
    )
    .expect("der Bestand muss sich oeffnen lassen");
    let archive = fixtures::archive_with_receipts();
    for (path_hint, bytes) in fixtures::directory_blobs(archive) {
        backend.materialize_for_test(path_hint, bytes);
    }
    assert!(receipt_count(archive) > 0);
    let anchor = decode_trust_anchor(fixtures::complete_archive_anchor_bytes())
        .expect("der Anker der Fixturelinie traegt seinen eigenen Bootstrap-Hash");
    let target = root.join(format!(
        "receipts.{}",
        ea_archive_fs::BUNDLE_FILE_EXTENSION_V1
    ));

    assert!(matches!(
        write_archive_bundle(&backend, &anchor, fixtures::EFFECTIVE_NOW, &target),
        Err(BundleError::SourceNotFullyVerified)
    ));
    assert!(!target.exists(), "ein Befund erzeugt kein Ziel");

    // Der Grund, ueber der Platte gemessen: genau die Vorlauf-Luecke der
    // Linie — und jeder Eintrag ist trotzdem gueltig UND serverbestaetigt.
    let report = verify_archive(
        &backend.as_archive_source(),
        &anchor,
        VerifyOptions::new(fixtures::EFFECTIVE_NOW),
    )
    .expect("der Plattenbestand muss berichten");
    assert!(!report.is_fully_verified());
    assert_eq!(report.gaps().len(), 1);
    let gap = report.gaps().next().expect("die eine Luecke");
    assert_eq!(gap.from_sequence(), ChainSequence::new(0));
    assert_eq!(
        gap.through_sequence(),
        ChainSequence::new(verify_support::RECEIPT_PRE_ENTRY_GAP_THROUGH_V1)
    );
    assert_eq!(report.object_results().len(), receipt_count(archive));
    assert!(report.object_results().all(|result| {
        result.result() == ObjectResultKindV1::Valid
            && result.server_confirmation() == ServerConfirmationV1::ServerConfirmed
    }));
}

/// Der Negativfall: ein untergeschobenes Archiv mit vollstaendiger EIGENER
/// Vertrauenskette endet gegen den gepinnten Anker fail-closed an Gate
/// `trust`, `objectResults` bleibt leer und `publicKeyThumbprints` bleibt
/// leer.
///
/// ADVERSARISCH GEPAART, Positivkontrolle ZUERST: dieselben Containerbytes —
/// vom ECHTEN Exporteur gegen den EIGENEN Anker verifiziert und geschrieben —
/// tragen gegen ihren eigenen gepinnten Anker vollstaendig. Der fremde Anker
/// kommt ueber denselben oeffentlichen Weg wie in
/// `apps/cli/tests/exit_codes.rs`: `RegistryLineBuilder::with_first_admin_revoked_from`
/// liefert Ankerbytes, die sich selbst tragen und trotzdem nicht die dieses
/// Bestands sind. Ein Anker, der schon an `decode_trust_anchor` scheiterte,
/// fiele zu frueh und maesse etwas anderes.
///
/// SYSTEMweit daran: Datei-Modus UND Server-Modus ueber demselben
/// Plattenbestand sagen gegen den fremden Tresor dasselbe — nichts.
#[test]
fn a_substituted_archive_with_its_own_trust_chain_says_nothing_about_any_entry() {
    let harness = archive_fs_support::BundleHarness::finalized_archive();
    let bundle = harness.exported_bytes();

    // Positivkontrolle.
    let own_vault = fixtures::unlocked_vault_with_pinned_anchor();
    let own = ReaderFileMode::open_bundle(bundle.clone(), &own_vault, fixtures::EFFECTIVE_NOW)
        .expect("der eigene Bestand muss oeffnen");
    assert!(own.report().is_fully_verified());
    assert_eq!(
        own.report().object_results().len(),
        fixtures::ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1
    );

    // Der FREMDE, in sich stimmige Anker.
    let foreign_line =
        verify_support::archive_support::trust_support::RegistryLineBuilder::with_first_admin_revoked_from(
            Some(ChainSequence::new(1)),
        );
    let foreign_anchor_bytes = foreign_line.exact_anchor_bytes().to_vec();
    let foreign_anchor = decode_trust_anchor(&foreign_anchor_bytes)
        .expect("der fremde Anker traegt seinen eigenen Bootstrap-Hash");
    assert!(foreign_anchor.trust_anchor_hash() != fixtures::pinned_anchor_hash());
    let foreign_vault = fixtures::vault_pinning(foreign_anchor_bytes);

    let mut observer = RecordingObserver::new();
    let opened = ReaderFileMode::open_bundle_observed(
        bundle,
        &foreign_vault,
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect("ein Befund ueber die Vertrauenskette ist nie ein Err");
    let report = opened.report();

    assert_eq!(observer.events(), &GATE_ORDER_V1[..2]);
    assert!(!report.is_fully_verified());
    assert_eq!(report.object_results().len(), 0);
    assert_eq!(report.public_key_thumbprints().len(), 0);
    assert!(opened.classification().states().is_empty());
    // GEMESSEN: alle sechs Mangelfelder bleiben LEER — der Lauf steigt nach
    // `protocol.enter(Gate::Trust)` mit `return report.seal()` aus.
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert_eq!(report.evidence_errors().len(), 0);
    assert_eq!(report.decryption_errors().len(), 0);
    // Der Kopf ist das Sentinel des GEPINNTEN Ankers.
    let pinned = PinnedTrustAnchor::from_vault(&foreign_vault);
    assert_eq!(report.chain_head().sequence(), ChainSequence::new(0));
    assert!(report.chain_head().chain_id() == pinned.as_trust_anchor().chain_id());
    assert!(report.chain_head().entry_hash() != pinned.as_trust_anchor().genesis_entry_hash());

    // Und der Server-Modus ueber dem Verzeichnis sagt gegen denselben Tresor
    // dasselbe.
    let server = server_mode(&harness.directory_source(), &foreign_vault);
    assert!(!server.report().is_fully_verified());
    assert_eq!(server.report().object_results().len(), 0);
    assert_eq!(server.report().public_key_thumbprints().len(), 0);
    assert!(server.states().is_empty());
    assert_eq!(server.report().chain_head(), report.chain_head());
    assert_eq!(
        server.report().archive_object_count(),
        report.archive_object_count()
    );
}
