//! Die Gates `chain-position` und `grant-plan` gegen fuenf unterscheidbare
//! Bestaende.
//!
//! Der Kern dieses Targets ist die UNTERSCHEIDBARKEIT. Ein Pruefbericht, der
//! einen vertauschten Vorgaenger, eine fehlende Sequenz, einen verwaisten
//! Grant, einen abweichenden Planhash und einen fehlenden Recovery-Grant in
//! dieselbe Aussage faltete, waere schlimmer als gar keiner: er verwechselte
//! einen ANGRIFF mit einem VERLUST. Deshalb prueft dieser Test nicht nur je
//! Fall den erwarteten Befund, sondern am Ende auch, dass die fuenf Bilder
//! paarweise verschieden sind.
//!
//! DIE GENESIS-LUECKE RECHNET JEDER FALL MIT. Kein Bestand dieses Moduls
//! traegt einen Eintrag auf Sequenz null — `support::GENESIS_GAP_SEQUENCE_V1`
//! haelt die Messung fest, warum das mit `trust_support::RegistryLineBuilder`
//! nicht herstellbar ist. `ea_chain::build_chain` zaehlt ab null und meldet die
//! fehlende Genesis deshalb als Luecke `0..=0`. Das ist die WAHRE Aussage ueber
//! diese Bestaende und wird nicht weggerechnet, sondern benannt.

#[path = "support/mod.rs"]
mod support;

use ea_archive::QuarantineReason;
use ea_format::FormatError;
use ea_types::UnixMillis;
use ea_verify::{
    ChainGapV1, GRANT_PLAN_MISMATCH_CODE_V1, VerificationReportV1, VerifyOptions, verify_archive,
};

use support::{
    FIRST_ENTRY_SEQUENCE_V1, FIXTURE_OS_WALL_CLOCK_V1, GENESIS_GAP_SEQUENCE_V1,
    MISSING_MIDDLE_SEQUENCE_V1, archive_with_a_mismatched_grant_plan_hash,
    archive_with_a_missing_middle_entry, archive_with_an_orphan_grant,
    archive_with_swapped_predecessors, archive_without_a_recovery_grant,
};

fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
}

/// Das Bild, das ein Bericht abgibt — grob genug fuer einen Vergleich, fein
/// genug, um fuenf verschiedene Befunde auseinanderzuhalten.
#[derive(Debug, Eq, PartialEq)]
struct Picture {
    gaps: Vec<(u64, u64)>,
    quarantined: Vec<QuarantineReason>,
    signature_error_codes: Vec<&'static str>,
    head_sequence: u64,
}

fn picture(report: &VerificationReportV1) -> Picture {
    Picture {
        gaps: report
            .gaps()
            .map(|gap| (gap.from_sequence().get(), gap.through_sequence().get()))
            .collect(),
        quarantined: report
            .quarantined_objects()
            .map(|entry| entry.reason())
            .collect(),
        signature_error_codes: report
            .signature_errors()
            .map(|error| error.code())
            .collect(),
        head_sequence: report.chain_head().sequence().get(),
    }
}

/// Die Genesis-Luecke, die jeder Bestand dieses Moduls traegt.
fn is_genesis_gap(gap: &ChainGapV1) -> bool {
    gap.from_sequence().get() == GENESIS_GAP_SEQUENCE_V1
        && gap.through_sequence().get() == GENESIS_GAP_SEQUENCE_V1
}

#[test]
fn swap_gap_orphan_grant_and_plan_hash_have_distinct_outcomes() {
    // ---------------------------------------------------------------- 1 ----
    // VERTAUSCHTE VORGAENGERBINDUNG: zwei Widersprueche, keine Luecke.
    let built = archive_with_swapped_predecessors();
    let anchor = built.anchor();
    let swapped = verify_archive(&built.fixture, &anchor, options())
        .expect("der getauschte Bestand muss berichten");

    assert_eq!(
        swapped.quarantined_objects().len(),
        2,
        "quarantined objects after predecessor swap"
    );
    let isolated: Vec<_> = swapped.quarantined_objects().collect();
    for entry in &isolated {
        assert_eq!(
            entry.reason(),
            QuarantineReason::Conflicting,
            "ein gebrochener Vorgaenger ist ein WIDERSPRUCH, kein Zuordnungsmangel"
        );
    }
    // BEIDE getauschten Eintraege, jeder einzeln nachgewiesen. Eine blosse
    // Teilmengenaussage („jedes isolierte Objekt ist eines der beiden") waere
    // schwaecher, als sie klaenge: sie liesse zweimal dasselbe Objekt zu.
    for expected in &built.entry_object_hashes[1..] {
        assert!(
            isolated
                .iter()
                .any(|entry| entry.object_hash() == *expected),
            "beide getauschten Eintraege muessen isoliert sein"
        );
    }
    assert!(
        isolated
            .iter()
            .all(|entry| entry.object_hash() != built.entry_object_hashes[0]),
        "der unstrittige erste Eintrag bleibt unberuehrt — ein Fehlschlag isoliert"
    );
    let gaps: Vec<_> = swapped.gaps().collect();
    assert_eq!(
        gaps.len(),
        1,
        "ein vorhandener, widerspruechlicher Eintrag ist NIE eine Luecke"
    );
    assert!(
        is_genesis_gap(gaps[0]),
        "die einzige Luecke ist die fehlende Genesis"
    );
    assert_eq!(
        swapped.signature_errors().len(),
        0,
        "ein Kettenwiderspruch erscheint in genau EINEM Array"
    );
    // Der Kopf haelt vor der kleinsten strittigen Sequenz an.
    assert_eq!(
        swapped.chain_head().sequence().get(),
        FIRST_ENTRY_SEQUENCE_V1
    );
    assert!(
        swapped.chain_head().entry_hash() == built.entry_hashes[0],
        "der Kettenkopf ist der letzte UNSTRITTIGE Eintrag"
    );
    assert!(
        swapped.chain_head().chain_id() == anchor.chain_id(),
        "die Kettenkennung stammt IMMER aus dem Anker"
    );

    // ---------------------------------------------------------------- 2 ----
    // FEHLENDER MITTLERER EINTRAG: genau eine Luecke, kein Widerspruch.
    let built = archive_with_a_missing_middle_entry();
    let anchor = built.anchor();
    let gapped = verify_archive(&built.fixture, &anchor, options())
        .expect("der lueckenhafte Bestand muss berichten");

    let gaps: Vec<_> = gapped.gaps().collect();
    let above_genesis: Vec<_> = gaps
        .iter()
        .filter(|gap| !is_genesis_gap(gap))
        .copied()
        .collect();
    assert_eq!(
        above_genesis.len(),
        1,
        "ein fehlender Eintrag erzeugt GENAU EINE Luecke"
    );
    assert_eq!(
        above_genesis[0].from_sequence().get(),
        MISSING_MIDDLE_SEQUENCE_V1
    );
    assert_eq!(
        above_genesis[0].through_sequence().get(),
        MISSING_MIDDLE_SEQUENCE_V1
    );
    assert!(
        above_genesis[0].chain_id() == anchor.chain_id(),
        "die Kettenkennung einer Luecke stammt IMMER aus dem Anker"
    );
    assert_eq!(
        gapped.quarantined_objects().len(),
        0,
        "ein FEHLENDES Objekt laesst sich nicht isolieren"
    );
    assert_eq!(gapped.signature_errors().len(), 0);
    assert_eq!(
        gapped.chain_head().sequence().get(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        "der Kopf haelt vor der Luecke an"
    );

    // ---------------------------------------------------------------- 3 ----
    // VERWAISTER GRANT: nicht zuordenbar, und die Kette bleibt unberuehrt.
    let built = archive_with_an_orphan_grant();
    let anchor = built.anchor();
    let orphaned = verify_archive(&built.fixture, &anchor, options())
        .expect("der Bestand mit verwaistem Grant muss berichten");

    let isolated: Vec<_> = orphaned.quarantined_objects().collect();
    assert_eq!(isolated.len(), 1, "genau ein isoliertes Objekt");
    assert!(
        Some(isolated[0].object_hash()) == built.orphan_grant_object_hash,
        "isoliert wird der Grant, nicht ein Eintrag"
    );
    assert_eq!(
        isolated[0].reason(),
        QuarantineReason::Unattributable,
        "ein Grant ohne Eintrag ist niemandem zuzuordnen"
    );
    let gaps: Vec<_> = orphaned.gaps().collect();
    assert_eq!(gaps.len(), 1, "ein Grant beansprucht kein Sequenzfach");
    assert!(is_genesis_gap(gaps[0]));
    assert_eq!(orphaned.signature_errors().len(), 0);
    assert_eq!(
        orphaned.chain_head().sequence().get(),
        FIRST_ENTRY_SEQUENCE_V1 + 1,
        "die beiden Eintraege bleiben verifiziert"
    );

    // ---------------------------------------------------------------- 4 ----
    // ABWEICHENDER PLANHASH: ein Signaturbefund mit dem Code DIESES Gates.
    let built = archive_with_a_mismatched_grant_plan_hash();
    let anchor = built.anchor();
    let mismatched = verify_archive(&built.fixture, &anchor, options())
        .expect("der Bestand mit falschem Planhash muss berichten");

    let errors: Vec<_> = mismatched.signature_errors().collect();
    assert_eq!(errors.len(), 1, "genau ein Befund");
    assert!(errors[0].object_hash() == built.entry_object_hashes[0]);
    assert_eq!(errors[0].code(), GRANT_PLAN_MISMATCH_CODE_V1);
    assert!(
        errors[0].code().starts_with("EA-VERIFY-GRANT-PLAN"),
        "der Code gehoert in die Familie des Gates"
    );
    assert_eq!(
        mismatched.quarantined_objects().len(),
        0,
        "ein Objekt erscheint in genau EINEM Fehlerarray"
    );
    assert_eq!(
        mismatched.chain_head().sequence().get(),
        FIRST_ENTRY_SEQUENCE_V1,
        "Gate 6 faellt hinter Gate 5: die Kettenposition steht"
    );

    // ---------------------------------------------------------------- 5 ----
    // FEHLENDER RECOVERY-GRANT: fail-closed, mit dem Code aus `ea-format`.
    let built = archive_without_a_recovery_grant();
    let anchor = built.anchor();
    let without_recovery = verify_archive(&built.fixture, &anchor, options())
        .expect("der Bestand ohne Recovery-Grant muss berichten");

    let errors: Vec<_> = without_recovery.signature_errors().collect();
    assert_eq!(errors.len(), 1, "genau ein Befund");
    assert!(errors[0].object_hash() == built.entry_object_hashes[0]);
    assert_eq!(
        errors[0].code(),
        FormatError::MissingRecovery.code(),
        "der Code kommt unveraendert aus `ea-format`, es wird keiner erfunden"
    );
    assert_eq!(errors[0].code(), "EA-GRANT-MISSING-RECOVERY");
    assert_eq!(without_recovery.quarantined_objects().len(), 0);

    // ------------------------------------------------------------ Bilder ---
    // Fuenf Faelle, fuenf verschiedene Bilder. Ohne diese Aussage koennte jeder
    // Einzelfall gruen sein und der Bericht trotzdem einen Angriff mit einem
    // Verlust verwechseln.
    let pictures = [
        picture(&swapped),
        picture(&gapped),
        picture(&orphaned),
        picture(&mismatched),
        picture(&without_recovery),
    ];
    for (index, left) in pictures.iter().enumerate() {
        for right in &pictures[index + 1..] {
            assert_ne!(
                left, right,
                "zwei Faelle geben dasselbe Bild ab und sind damit nicht unterscheidbar"
            );
        }
    }

    // Kein Bestand mit einem Befund gilt als vollstaendig verifiziert.
    for report in [&swapped, &gapped, &orphaned, &mismatched, &without_recovery] {
        assert!(!report.is_fully_verified());
    }
}
