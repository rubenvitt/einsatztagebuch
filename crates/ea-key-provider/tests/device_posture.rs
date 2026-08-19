//! Die Gerätehaltung eines Produktivgeraets.
//!
//! Ein `Unknown` ist nie ein Pass. Es ist eine unaufgeloeste Anforderung, die
//! eine Go-live-Evidenzzeile erzwingt; ein `Fail` sperrt die Sitzung und
//! erzeugt keine solche Zeile, weil an einem gemessenen Mangel nichts
//! aufzuklaeren ist.

use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    DevicePostureProvider, DevicePostureProviderFake, DevicePostureReport, PostureCheck,
    PostureRequirement, SupportMatrixRow,
};

#[test]
fn an_unreportable_posture_requirement_is_never_claimed_as_passed() {
    let provider = DevicePostureProviderFake::unreportable();
    let report = provider.report().unwrap();
    assert_eq!(
        report.full_disk_encryption,
        PostureCheck::Unknown {
            evidence_code: "EA-POSTURE-FDE-UNREPORTABLE"
        }
    );
    assert!(!report.is_production_ready());
    assert!(
        report
            .go_live_follow_up()
            .contains(&PostureRequirement::FullDiskEncryption)
    );
}

#[test]
fn a_failed_posture_check_blocks_a_production_role_session() {
    let provider = DevicePostureProviderFake::failing_screen_lock();
    let report = provider.report().unwrap();
    assert!(!report.is_production_ready());
    assert!(report.go_live_follow_up().is_empty());
}

#[test]
fn a_report_is_production_ready_only_when_all_four_checks_pass() {
    let report = DevicePostureProviderFake::all_passing().report().unwrap();
    assert!(report.is_production_ready());
    assert!(report.go_live_follow_up().is_empty());

    // Jede der vier Anforderungen sperrt allein, und jede einzelne, die nicht
    // berichtet werden kann, erzeugt ihre eigene Go-live-Zeile. Ohne diese
    // Schleife wuerde ein `is_production_ready`, das nur auf einem Feld
    // entscheidet, unentdeckt bleiben.
    for requirement in PostureRequirement::ALL {
        let failing = DevicePostureProviderFake::failing(requirement)
            .report()
            .unwrap();
        assert!(!failing.is_production_ready(), "{requirement:?} must block");
        assert!(failing.go_live_follow_up().is_empty());

        let unresolved = DevicePostureProviderFake::unknown(requirement)
            .report()
            .unwrap();
        assert!(
            !unresolved.is_production_ready(),
            "{requirement:?} must block"
        );
        assert_eq!(unresolved.go_live_follow_up(), vec![requirement]);
    }
}

/// Die Haltung, die der native Adapter DIESES Hosts meldet.
///
/// Stufe 2 traegt keine native API-Familie (`ADR-0001:152-153`, K-02 der
/// Vorpruefung), also kann kein Adapter eine der vier Anforderungen belegen und
/// meldet `Unknown` mit dem jeweiligen Beweiscode. Das ist der von
/// `design.md`:1489 und dem Task verlangte Ausgang und ausdruecklich kein
/// automatischer Pass: die Sitzung bleibt gesperrt und alle vier Anforderungen
/// stehen als Go-live-Zeilen.
#[test]
fn the_host_posture_adapter_resolves_nothing_and_claims_nothing() {
    let row = SupportMatrixRow::current_host().expect("the host is a support-matrix row");
    let report = row.posture_provider().report().unwrap();
    assert!(!report.is_production_ready());
    assert_eq!(report.go_live_follow_up(), PostureRequirement::ALL.to_vec());
    for check in [
        report.full_disk_encryption,
        report.locked_non_shared_account,
        report.automatic_screen_lock,
        report.supported_os_patch_level,
    ] {
        assert!(matches!(check, PostureCheck::Unknown { .. }));
    }
}

/// Das Schutzprofil einer Support-Matrix-Zeile bleibt das Wire-Format-Profil.
#[test]
fn every_support_matrix_row_reaches_only_the_os_wrapped_floor() {
    for row in SupportMatrixRow::ALL {
        let reached: KeyProtectionProfileV1 = row.reachable_protection_profile();
        assert_eq!(reached, KeyProtectionProfileV1::OsWrapped);
    }
    let _: fn(&DevicePostureReport) -> bool = DevicePostureReport::is_production_ready;
}

/// Die zwoelf Beweiscodes stehen fest und gehoeren der Anforderung, nicht dem
/// Adapter.
///
/// Task 18 traegt genau diese Zeichenketten als Go-live-Evidenzzeilen in die
/// Rueckverfolgbarkeitstabelle ein; ein umbenannter Code bricht dort still. Er
/// bricht hier laut. `PostureCheck::evidence_code` ist der einzige Leser, den
/// ein Aufrufer dafuer braucht.
#[test]
fn every_requirement_owns_three_stable_evidence_codes() {
    assert_eq!(
        PostureRequirement::ALL
            .into_iter()
            .flat_map(|requirement| [
                requirement.pass().evidence_code(),
                requirement.fail().evidence_code(),
                requirement.unknown().evidence_code(),
            ])
            .collect::<Vec<_>>(),
        vec![
            "EA-POSTURE-FDE-ENABLED",
            "EA-POSTURE-FDE-DISABLED",
            "EA-POSTURE-FDE-UNREPORTABLE",
            "EA-POSTURE-ACCOUNT-LOCKED-EXCLUSIVE",
            "EA-POSTURE-ACCOUNT-SHARED",
            "EA-POSTURE-ACCOUNT-UNREPORTABLE",
            "EA-POSTURE-SCREEN-LOCK-ENFORCED",
            "EA-POSTURE-SCREEN-LOCK-ABSENT",
            "EA-POSTURE-SCREEN-LOCK-UNREPORTABLE",
            "EA-POSTURE-OS-PATCH-SUPPORTED",
            "EA-POSTURE-OS-PATCH-UNSUPPORTED",
            "EA-POSTURE-OS-PATCH-UNREPORTABLE",
        ]
    );
}
