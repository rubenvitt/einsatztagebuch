//! `authorizedDestructions` und `publicKeyThumbprints`: die letzten beiden
//! Pflichtfelder ohne Produzenten.
//!
//! DER ZUSTAND EINES VORGANGS STAMMT AUSSCHLIESSLICH AUS SEINER
//! EREIGNISKETTE. Weder der Pfad, unter dem ein Objekt liegt, noch die blosse
//! Anwesenheit einer Autorisierung sagt etwas ueber den Stand; nur die
//! signierten Transitionen tun das. Deshalb misst dieser Test nicht, ob ein
//! Vorgang IM BESTAND ist, sondern welchen Zustand seine Kette BEWEIST.

#[path = "support/mod.rs"]
mod support;

use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::{DestructionStateV1, VerificationReportV1, VerifyOptions, verify_archive};

use support::{
    DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1, DESTRUCTION_STATE_IN_PROGRESS_V1,
    DESTRUCTION_STATE_INCOMPLETE_UNREACHABLE_REPLICA_V1,
    DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1, DESTRUCTION_STATE_REQUESTED_V1, DestructionArchive,
    DestructionSpec, FIXTURE_OS_WALL_CLOCK_V1, destruction_archive, writer_device_key_thumbprint,
};

fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
}

fn run(built: &DestructionArchive, anchor: &TrustAnchorV1) -> VerificationReportV1 {
    verify_archive(&built.fixture, anchor, options()).expect("der Bestand muss berichten")
}

/// Der Kern des Tasks: ein Vorgang erreicht GENAU den Zustand, den seine
/// Ereigniskette beweist — und ein unzulaessiger Uebergang verschiebt ihn
/// nicht, sondern wird zum Widerspruch.
#[test]
fn a_destruction_reaches_exactly_the_state_its_event_chain_proves() {
    // ---------------------------------------------------------------- 1 ----
    // requested -> inProgress -> pendingBackupExpiry.
    let built = destruction_archive(&[DestructionSpec::new(
        0x51,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
        ],
    )]);
    let anchor = built.anchor();
    let report = run(&built, &anchor);

    assert_eq!(
        report.authorized_destructions().len(),
        1,
        "authorized destructions"
    );
    let entry = report
        .authorized_destructions()
        .next()
        .expect("der Vorgang muss im Bericht stehen");
    assert!(
        entry.destruction_id() == built.destructions[0].destruction_id,
        "der Eintrag traegt die Kennung des Vorgangs"
    );
    assert!(
        entry.authorization_object_hash() == built.destructions[0].authorization_object_hash,
        "der Eintrag traegt den Objekthash seiner Autorisierung"
    );
    assert_eq!(
        entry.state(),
        DestructionStateV1::PendingBackupExpiry,
        "der Zustand ist der letzte, den die Kette beweist"
    );
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert!(
        report.is_fully_verified(),
        "ein Bestand aus Linie und lupenreinem Vorgang hat keinen Befund"
    );

    // ---------------------------------------------------------------- 2 ----
    // Derselbe Vorgang mit EINEM zusaetzlichen Ereignis:
    // pendingBackupExpiry -> requested. Nach `design.md`:1826-1841 gibt es
    // diesen Rueckweg nicht. Er ist deshalb kein stiller Zustandswechsel,
    // sondern ein Widerspruch.
    let contested = destruction_archive(&[DestructionSpec::new(
        0x51,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
            DESTRUCTION_STATE_REQUESTED_V1,
        ],
    )]);
    let contested_anchor = contested.anchor();
    let contested_report = run(&contested, &contested_anchor);

    assert_eq!(contested_report.authorized_destructions().len(), 1);
    assert_eq!(
        contested_report
            .authorized_destructions()
            .next()
            .expect("der Vorgang bleibt im Bericht")
            .state(),
        DestructionStateV1::PendingBackupExpiry,
        "ein unzulaessiger Uebergang verschiebt den Zustand NICHT"
    );
    let quarantined: Vec<_> = contested_report.quarantined_objects().collect();
    assert_eq!(
        quarantined.len(),
        1,
        "genau das unzulaessige Ereignis wird isoliert"
    );
    assert!(
        quarantined[0].object_hash() == contested.destructions[0].event_object_hashes[3],
        "isoliert wird das unzulaessige Ereignis, nicht die unstrittige Kette"
    );
    assert_eq!(
        quarantined[0].reason(),
        ea_archive::QuarantineReason::Conflicting,
        "ein unzulaessiger Uebergang ist ein Widerspruch, kein Formfehler"
    );
    assert_eq!(
        contested_report.signature_errors().len(),
        0,
        "das Ereignis ist tadellos signiert; unzulaessig ist sein Uebergang"
    );
    assert!(!contested_report.is_fully_verified());
}

/// Alle FUENF Zustaende sind erreichbar, und jeder nur ueber eine Kette, die
/// ihn beweist.
#[test]
fn every_one_of_the_five_states_is_reachable_through_its_own_chain() {
    let built = destruction_archive(&[
        DestructionSpec::new(0x61, &[DESTRUCTION_STATE_REQUESTED_V1]),
        DestructionSpec::new(
            0x62,
            &[
                DESTRUCTION_STATE_REQUESTED_V1,
                DESTRUCTION_STATE_IN_PROGRESS_V1,
            ],
        ),
        DestructionSpec::new(
            0x63,
            &[
                DESTRUCTION_STATE_REQUESTED_V1,
                DESTRUCTION_STATE_IN_PROGRESS_V1,
                DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
            ],
        ),
        DestructionSpec::new(
            0x64,
            &[
                DESTRUCTION_STATE_REQUESTED_V1,
                DESTRUCTION_STATE_IN_PROGRESS_V1,
                DESTRUCTION_STATE_PENDING_BACKUP_EXPIRY_V1,
                DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
            ],
        )
        .with_attestation(),
        DestructionSpec::new(
            0x65,
            &[
                DESTRUCTION_STATE_REQUESTED_V1,
                DESTRUCTION_STATE_IN_PROGRESS_V1,
                DESTRUCTION_STATE_INCOMPLETE_UNREACHABLE_REPLICA_V1,
            ],
        ),
    ]);
    let anchor = built.anchor();
    let report = run(&built, &anchor);

    let states: Vec<_> = report
        .authorized_destructions()
        .map(ea_verify::AuthorizedDestructionV1::state)
        .collect();
    assert_eq!(
        states,
        vec![
            DestructionStateV1::Requested,
            DestructionStateV1::InProgress,
            DestructionStateV1::PendingBackupExpiry,
            DestructionStateV1::CompleteManagedScope,
            DestructionStateV1::IncompleteUnreachableReplica,
        ],
        "die Vorgaenge stehen nach destructionId aufsteigend, jeder in seinem Zustand"
    );
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert!(report.is_fully_verified());

    // Der Bericht validiert weiterhin gegen sein Schema — hier gemessen an der
    // Zeichenmenge, die der kanonische Schreiber durchlaesst. Die
    // `destructionId` sind 32 Hex-Zeichen, die Objekthashes 64.
    let json = report
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    for destruction in &built.destructions {
        assert!(
            json.contains(&hex::encode(destruction.destruction_id.as_bytes())),
            "die Vorgangskennung steht als 32 Hex-Zeichen im Bericht"
        );
        assert!(
            json.contains(&hex::encode(
                destruction.authorization_object_hash.as_bytes()
            )),
            "der Autorisierungshash steht als 64 Hex-Zeichen im Bericht"
        );
    }
}

/// `publicKeyThumbprints` ist Nachweis des GEPRUEFTEN — nicht mehr und nicht
/// weniger.
#[test]
fn public_key_thumbprints_carry_exactly_the_signers_that_passed() {
    // Ein Vorgang mit gueltiger Signatur und einer Loeschbestaetigung.
    let built = destruction_archive(&[DestructionSpec::new(
        0x71,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
        ],
    )
    .with_attestation()]);
    let anchor = built.anchor();
    let report = run(&built, &anchor);

    let thumbprints: Vec<_> = report.public_key_thumbprints().collect();
    // ZWEI und nicht drei: die Registrierungslinie stellt JEDES
    // Geraetezertifikat auf denselben Schluessel aus — Loeschzeuge und
    // Schreiber teilen ihn, die Rolle kommt vom ZERTIFIKAT. Der Bestand traegt
    // keinen Eintrag, also kann der Geraeteabdruck hier nur aus einer
    // gepruefen Destruction-Signatur stammen.
    assert_eq!(thumbprints.len(), 2);
    assert!(
        thumbprints
            .iter()
            .any(|thumbprint| *thumbprint == anchor.root_key_thumbprint()),
        "die Wurzel hat die Registrierungslinie getragen"
    );
    assert!(
        thumbprints
            .iter()
            .any(|thumbprint| *thumbprint == writer_device_key_thumbprint()),
        "der Loeschzeuge hat die Transitionen getragen"
    );

    // DERSELBE Vorgang, signiert vom Schreiberzertifikat: tadelloses Ed25519,
    // aber weder die Rolle `deletionAttest` noch die gleichnamige Faehigkeit.
    // Eine gefallene Pruefung legt NIE einen Abdruck ab — und ohne getragene
    // Transition gibt es auch keinen Zustand.
    let unauthorized = destruction_archive(&[DestructionSpec::new(
        0x71,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
            DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
        ],
    )
    .signed_by_the_writer()]);
    let unauthorized_anchor = unauthorized.anchor();
    let unauthorized_report = run(&unauthorized, &unauthorized_anchor);

    assert_eq!(
        unauthorized_report.authorized_destructions().len(),
        0,
        "ohne getragene Transition gibt es keinen Zustand"
    );
    assert_eq!(
        unauthorized_report.signature_errors().len(),
        3,
        "jede der drei Transitionen traegt ihren eigenen Befund"
    );
    let unauthorized_thumbprints: Vec<_> = unauthorized_report.public_key_thumbprints().collect();
    assert_eq!(
        unauthorized_thumbprints.len(),
        1,
        "nur die Wurzel bleibt: eine gefallene Pruefung legt keinen Abdruck ab"
    );
    assert!(
        unauthorized_thumbprints[0] == unauthorized_anchor.root_key_thumbprint(),
        "der eine verbliebene Abdruck ist der der Wurzel"
    );
    assert!(
        !unauthorized_thumbprints
            .iter()
            .any(|thumbprint| *thumbprint == writer_device_key_thumbprint()),
        "publicKeyThumbprints ist kein Katalogabzug"
    );
}

/// Zwei Ereignisse mit derselben `event_id` sind kein Zustandswechsel, sondern
/// ein Widerspruch.
#[test]
fn two_events_under_one_event_id_contest_each_other() {
    let built = destruction_archive(&[DestructionSpec::new(
        0x81,
        &[
            DESTRUCTION_STATE_REQUESTED_V1,
            DESTRUCTION_STATE_IN_PROGRESS_V1,
        ],
    )
    .with_one_event_id()]);
    let anchor = built.anchor();
    let report = run(&built, &anchor);

    assert_eq!(
        report.authorized_destructions().len(),
        0,
        "ohne unstrittiges Ereignis gibt es keinen Zustand"
    );
    let quarantined: Vec<_> = report.quarantined_objects().collect();
    assert_eq!(
        quarantined.len(),
        2,
        "BEIDE Ereignisse sind beteiligt; welches das echte ist, ist gerade nicht entscheidbar"
    );
    for entry in quarantined {
        assert_eq!(entry.reason(), ea_archive::QuarantineReason::Conflicting);
    }
    assert!(!report.is_fully_verified());
}

/// ZWEI LEASES, EIN VORWAERTSLAUF: die Kopfabfragen ordnen sich nach Sequenz,
/// nicht nach Objekthash.
///
/// Die Registrierungslinie laesst sich nur VORWAERTS nachziehen — ein einmal
/// gepinnter Kopf geht nie zurueck. Fragte die Pipeline ihre Koepfe in
/// Inventarreihenfolge ab, entschiede der Zufall der Objekthashes darueber,
/// welcher Vorgang noch in der Lease seines Kopfes liegt: pinnt der Vorgang aus
/// der ZWEITEN Lease zuerst, faellt der aus der ersten mit
/// `EA-VERIFY-DESTRUCTION-HEAD-UNAVAILABLE`.
///
/// MIT NUR EINER LEASE WAERE DAS UNSICHTBAR, und dasselbe gilt fuer
/// `randomized_paths()`: das Inventar ordnet ohnehin nach Objekthash um. Nur
/// zwei verschiedene `authorizationSequence` decken es auf.
#[test]
fn two_leases_are_pinned_in_sequence_order_not_in_object_hash_order() {
    let chain = [
        DESTRUCTION_STATE_REQUESTED_V1,
        DESTRUCTION_STATE_IN_PROGRESS_V1,
        DESTRUCTION_STATE_COMPLETE_MANAGED_SCOPE_V1,
    ];
    let built = destruction_archive(&[
        DestructionSpec::new(0xa1, &chain),
        DestructionSpec::new(0xa2, &chain).in_the_second_lease(),
    ]);
    let anchor = built.anchor();
    let report = run(&built, &anchor);

    assert_eq!(
        report.signature_errors().len(),
        0,
        "kein Vorgang darf seinen Kopf verlieren, weil ein anderer frueher gepinnt hat"
    );
    let states: Vec<_> = report
        .authorized_destructions()
        .map(ea_verify::AuthorizedDestructionV1::state)
        .collect();
    assert_eq!(
        states,
        vec![
            DestructionStateV1::CompleteManagedScope,
            DestructionStateV1::CompleteManagedScope,
        ],
        "beide Vorgaenge erreichen ihren Endzustand, in beiden Leases"
    );
    assert_eq!(report.quarantined_objects().len(), 0);
    assert!(report.is_fully_verified());
}
