//! Die Zeugen der geschlossenen Schrittfolge einer Trust-Zeremonie (Stufe 5,
//! Task 6).
//!
//! Die Schritte sind eine Aufzaehlung und keine Abkuerzung: der Wirt geht sie
//! einzeln, und keine Art der Zeremonie darf einen Schritt ueberspringen, den
//! sie braucht — nur `FingerprintConfirmed` entfaellt dort, wo kein
//! Geraetefingerprint zu vergleichen ist.

use ea_admin::ceremony_steps::{
    TrustCeremonyKind, TrustCeremonyStep, next_step, reauth_purpose, requires_fresh_reauth,
};
use ea_operator::ReauthPurpose;

/// Laeuft die Folge ab `PendingRequest` bis zum Ende ab und sammelt sie.
fn walk(kind: TrustCeremonyKind) -> Vec<TrustCeremonyStep> {
    let mut steps = vec![TrustCeremonyStep::PendingRequest];
    let mut current = TrustCeremonyStep::PendingRequest;
    while let Some(next) = next_step(kind, current) {
        steps.push(next);
        current = next;
        assert!(
            steps.len() <= TrustCeremonyStep::ALL.len(),
            "die Folge darf keinen Kreis schliessen"
        );
    }
    steps
}

/// Die Geraetefreigabe durchlaeuft ALLE sechs Schritte in
/// Deklarationsreihenfolge — und nichts sonst.
#[test]
fn device_approve_walks_all_six_steps_in_order() {
    assert_eq!(
        walk(TrustCeremonyKind::DeviceApprove),
        TrustCeremonyStep::ALL.to_vec()
    );
}

/// Die drei anderen Arten ueberspringen GENAU `FingerprintConfirmed`.
#[test]
fn the_other_three_kinds_skip_exactly_the_fingerprint_step() {
    let without_fingerprint: Vec<TrustCeremonyStep> = TrustCeremonyStep::ALL
        .into_iter()
        .filter(|step| *step != TrustCeremonyStep::FingerprintConfirmed)
        .collect();
    assert_eq!(without_fingerprint.len(), 5);
    for kind in [
        TrustCeremonyKind::DeviceRevoke,
        TrustCeremonyKind::PolicyChange,
        TrustCeremonyKind::WriterTransition,
    ] {
        assert_eq!(walk(kind), without_fingerprint, "{kind:?}");
        // Der uebersprungene Schritt hat fuer diese Arten trotzdem einen
        // wohldefinierten Nachfolger — wer ihn dennoch erreicht, faellt nicht
        // aus der Folge.
        assert_eq!(
            next_step(kind, TrustCeremonyStep::FingerprintConfirmed),
            Some(TrustCeremonyStep::AdminAuthorized)
        );
    }
}

/// Kein Schritt erreicht einen Schritt, der ZWEI Positionen vor ihm liegt —
/// mit der einen benannten Ausnahme der drei fingerprintlosen Arten.
#[test]
fn no_step_jumps_two_positions_ahead() {
    for kind in TrustCeremonyKind::ALL {
        for (index, step) in TrustCeremonyStep::ALL.into_iter().enumerate() {
            let Some(next) = next_step(kind, step) else {
                continue;
            };
            let next_index = TrustCeremonyStep::ALL
                .iter()
                .position(|candidate| *candidate == next)
                .expect("der Nachfolger ist ein Schritt der Aufzaehlung");
            let skips_fingerprint = kind != TrustCeremonyKind::DeviceApprove
                && step == TrustCeremonyStep::PendingRequest
                && next == TrustCeremonyStep::AdminAuthorized;
            let expected_distance = if skips_fingerprint { 2 } else { 1 };
            assert_eq!(
                next_index,
                index + expected_distance,
                "{kind:?}: {step:?} -> {next:?}"
            );
        }
    }
}

/// Genau zwei Schritte verlangen einen FRISCHEN Bedienernachweis: die
/// Admin-Autorisierung und die Veroeffentlichung.
#[test]
fn exactly_the_two_root_touching_steps_require_fresh_reauth() {
    let requiring: Vec<TrustCeremonyStep> = TrustCeremonyStep::ALL
        .into_iter()
        .filter(|step| requires_fresh_reauth(*step))
        .collect();
    assert_eq!(
        requiring,
        vec![
            TrustCeremonyStep::AdminAuthorized,
            TrustCeremonyStep::RegistryPublished,
        ]
    );
}

/// Die Veroeffentlichung ist der letzte Schritt jeder Art.
#[test]
fn registry_published_has_no_successor_for_any_kind() {
    for kind in TrustCeremonyKind::ALL {
        assert_eq!(
            next_step(kind, TrustCeremonyStep::RegistryPublished),
            None,
            "{kind:?}"
        );
    }
}

/// Alle vier Arten sind Root-Zeremonien und verlangen denselben Zweck.
#[test]
fn every_kind_reauthenticates_for_the_admin_root_ceremony() {
    for kind in TrustCeremonyKind::ALL {
        assert_eq!(reauth_purpose(kind), ReauthPurpose::AdminRootCeremony);
    }
}

/// Die `ALL`-Felder tragen jede Variante genau einmal.
#[test]
fn the_all_arrays_are_complete_and_free_of_duplicates() {
    assert_eq!(TrustCeremonyKind::ALL.len(), 4);
    assert_eq!(TrustCeremonyStep::ALL.len(), 6);
    for (index, kind) in TrustCeremonyKind::ALL.iter().enumerate() {
        assert_eq!(
            TrustCeremonyKind::ALL.iter().position(|k| k == kind),
            Some(index)
        );
    }
    for (index, step) in TrustCeremonyStep::ALL.iter().enumerate() {
        assert_eq!(
            TrustCeremonyStep::ALL.iter().position(|s| s == step),
            Some(index)
        );
    }
}
