//! Die Zeugen des Go-live-Aggregats (Stufe 5, Task 6).
//!
//! Die eine Zusage, die alles andere traegt: `Unknown` ist nie gruen.
//! `production_ready()` ist `true` NUR, wenn jede der fuenfzehn Anforderungen
//! `Confirmed` ist; ein `NotMet` UND ein `NotAutomaticallyVerifiable` an
//! beliebiger Stelle machen es `false`. Dazu die feste Reihenfolge, die
//! deterministische Ausgabe und das Fehlen von Zeitstempeln und Pfaden darin.

use ea_admin::{
    KeyBackupRecordV1,
    anchor_media::AnchorMediumId,
    bootstrap::BackedUpKeyClass,
    go_live::{
        GO_LIVE_REQUIREMENT_CODES, GoLiveChecklist, GoLiveEvidence, GoLiveRequirementStatus,
        RecoveryTestFreshness, RegistryFreshness, evaluate_go_live,
    },
    production_state::ProductionState,
    writer_transition::WriterTransitionPhase,
};
use ea_key_provider::{DevicePostureReport, PostureRequirement};
use ea_types::{ChainSequence, Hash32, KeyThumbprint, UnixMillis};

const NOW: UnixMillis = UnixMillis::new(1_788_000_000_000);
const UNAVAILABLE: &str = "EA-GOLIVE-EVIDENCE-UNAVAILABLE";

const EXPECTED_CODES: [&str; 15] = [
    "EA-GOLIVE-TWO-ADMINS",
    "EA-GOLIVE-KEY-BACKUP-ROOT",
    "EA-GOLIVE-KEY-BACKUP-ADMIN",
    "EA-GOLIVE-KEY-BACKUP-RECOVERY-KEM",
    "EA-GOLIVE-KEY-BACKUP-HGA",
    "EA-GOLIVE-REGISTRY-AGE",
    "EA-GOLIVE-REGISTRY-LEASE",
    "EA-GOLIVE-POLICY",
    "EA-GOLIVE-EVIDENCE-POLICY",
    "EA-GOLIVE-RECOVERY-TEST",
    "EA-GOLIVE-WRITER-TRANSITION",
    "EA-POSTURE-FULL-DISK-ENCRYPTION",
    "EA-POSTURE-ACCOUNT-EXCLUSIVE",
    "EA-POSTURE-SCREEN-LOCK",
    "EA-POSTURE-OS-PATCH-LEVEL",
];

fn thumbprint(seed: u8) -> KeyThumbprint {
    KeyThumbprint::from(Hash32::try_from([seed; 32].as_slice()).expect("zweiunddreissig Bytes"))
}

fn backup(class: BackedUpKeyClass, media_count: usize) -> KeyBackupRecordV1 {
    KeyBackupRecordV1 {
        class,
        key_thumbprint: thumbprint(0x40),
        media: (0..media_count)
            .map(|index| AnchorMediumId::new([u8::try_from(index).expect("klein"); 16]))
            .collect(),
    }
}

fn all_backups() -> Vec<KeyBackupRecordV1> {
    [
        BackedUpKeyClass::Root,
        BackedUpKeyClass::Admin,
        BackedUpKeyClass::RecoveryKem,
        BackedUpKeyClass::HistoricalGrantAuthority,
    ]
    .into_iter()
    .map(|class| backup(class, 2))
    .collect()
}

fn passing_posture() -> DevicePostureReport {
    DevicePostureReport {
        full_disk_encryption: PostureRequirement::FullDiskEncryption.pass(),
        locked_non_shared_account: PostureRequirement::LockedNonSharedAccount.pass(),
        automatic_screen_lock: PostureRequirement::AutomaticScreenLock.pass(),
        supported_os_patch_level: PostureRequirement::SupportedOsPatchLevel.pass(),
    }
}

fn posture_with(
    requirement: PostureRequirement,
    check: ea_key_provider::PostureCheck,
) -> DevicePostureReport {
    let mut report = passing_posture();
    match requirement {
        PostureRequirement::FullDiskEncryption => report.full_disk_encryption = check,
        PostureRequirement::LockedNonSharedAccount => report.locked_non_shared_account = check,
        PostureRequirement::AutomaticScreenLock => report.automatic_screen_lock = check,
        PostureRequirement::SupportedOsPatchLevel => report.supported_os_patch_level = check,
    }
    report
}

fn fresh_registry() -> RegistryFreshness {
    RegistryFreshness {
        age_ms: 1_000,
        max_age_ms: 86_400_000,
        lease_valid_through: ChainSequence::new(500),
        next_sequence: ChainSequence::new(42),
        not_after: UnixMillis::new(NOW.get() + 86_400_000),
        now: NOW,
    }
}

fn fresh_recovery_test(state: &ProductionState) -> RecoveryTestFreshness<'_> {
    RecoveryTestFreshness::for_testing(state, UnixMillis::new(NOW.get() - 3_600_000), 30 * 86_400_000, NOW)
}

/// Die Kulisse eines VOLLSTAENDIG belegten Bestands; jeder Zeuge veraendert
/// davon genau eine Stelle.
struct Scene {
    backups: Vec<KeyBackupRecordV1>,
    posture: DevicePostureReport,
    state: ProductionState,
}

impl Scene {
    fn satisfied() -> Self {
        Self {
            backups: all_backups(),
            posture: passing_posture(),
            state: ProductionState::Ready,
        }
    }

    fn evidence(&self) -> GoLiveEvidence<'_> {
        GoLiveEvidence {
            active_admin_count: Some(2),
            key_backups: Some(&self.backups),
            registry: Some(fresh_registry()),
            policy_present: Some(true),
            evidence_policy_present: Some(true),
            last_recovery_test: Some(fresh_recovery_test(&self.state)),
            writer_transition: Some(WriterTransitionPhase::NoTransition),
            device_posture: Some(&self.posture),
        }
    }
}

fn unknown_evidence() -> GoLiveEvidence<'static> {
    GoLiveEvidence {
        active_admin_count: None,
        key_backups: None,
        registry: None,
        policy_present: None,
        evidence_policy_present: None,
        last_recovery_test: None,
        writer_transition: None,
        device_posture: None,
    }
}

fn statuses(checklist: &GoLiveChecklist) -> Vec<GoLiveRequirementStatus> {
    checklist
        .requirements()
        .iter()
        .map(|requirement| requirement.status())
        .collect()
}

fn codes(checklist: &GoLiveChecklist) -> Vec<&'static str> {
    checklist
        .requirements()
        .iter()
        .map(|requirement| requirement.code())
        .collect()
}

/// Ohne jeden Beleg: fuenfzehn Anforderungen, alle nicht automatisch pruefbar,
/// und der Bestand ist NICHT produktionsbereit.
#[test]
fn all_none_evidence_yields_fifteen_unverifiable_requirements() {
    let checklist = evaluate_go_live(&unknown_evidence());
    assert_eq!(checklist.requirements().len(), 15);
    assert!(
        statuses(&checklist)
            .iter()
            .all(|status| *status == GoLiveRequirementStatus::NotAutomaticallyVerifiable)
    );
    assert!(
        checklist
            .requirements()
            .iter()
            .all(|requirement| requirement.evidence_code() == UNAVAILABLE)
    );
    assert!(!checklist.production_ready());
    assert_eq!(checklist.unresolved().count(), 15);
}

/// Ein vollstaendig belegter Bestand ist produktionsbereit — und NUR der.
#[test]
fn a_fully_satisfied_evidence_set_is_production_ready() {
    let scene = Scene::satisfied();
    let checklist = evaluate_go_live(&scene.evidence());
    assert!(
        statuses(&checklist)
            .iter()
            .all(|status| *status == GoLiveRequirementStatus::Confirmed)
    );
    assert!(checklist.production_ready());
    assert_eq!(checklist.unresolved().count(), 0);
    assert!(
        checklist
            .requirements()
            .iter()
            .all(|requirement| requirement.evidence_code() != UNAVAILABLE)
    );
}

/// Die Reihenfolge ist fest und gleich der Codeliste.
#[test]
fn the_requirement_order_is_fixed_and_equals_the_code_list() {
    assert_eq!(GO_LIVE_REQUIREMENT_CODES, EXPECTED_CODES);
    let scene = Scene::satisfied();
    assert_eq!(codes(&evaluate_go_live(&scene.evidence())), EXPECTED_CODES);
    assert_eq!(
        codes(&evaluate_go_live(&unknown_evidence())),
        EXPECTED_CODES
    );
}

/// `Unknown` ist nie gruen: JEDE einzelne Anforderung, auf `NotMet` ODER auf
/// „nicht pruefbar" gekippt, kippt `production_ready()` auf `false`.
#[test]
#[allow(clippy::too_many_lines)]
fn flipping_any_single_requirement_flips_production_ready_to_false() {
    let posture_requirements = PostureRequirement::ALL;
    for (index, code) in EXPECTED_CODES.iter().enumerate() {
        // --- NotMet -----------------------------------------------------
        let mut scene = Scene::satisfied();
        let mut not_met = None;
        match index {
            0 => {
                not_met = Some(GoLiveEvidence {
                    active_admin_count: Some(1),
                    ..scene.evidence()
                })
            }
            1..=4 => {
                let dropped = scene.backups[index - 1].class;
                scene.backups.retain(|record| record.class != dropped);
                // Ein einzelnes Medium zaehlt ebenfalls nicht.
                scene.backups.push(backup(dropped, 1));
            }
            5 => {
                not_met = Some(GoLiveEvidence {
                    registry: Some(RegistryFreshness {
                        age_ms: 86_400_001,
                        ..fresh_registry()
                    }),
                    ..scene.evidence()
                })
            }
            6 => {
                not_met = Some(GoLiveEvidence {
                    registry: Some(RegistryFreshness {
                        next_sequence: ChainSequence::new(501),
                        ..fresh_registry()
                    }),
                    ..scene.evidence()
                })
            }
            7 => {
                not_met = Some(GoLiveEvidence {
                    policy_present: Some(false),
                    ..scene.evidence()
                })
            }
            8 => {
                not_met = Some(GoLiveEvidence {
                    evidence_policy_present: Some(false),
                    ..scene.evidence()
                })
            }
            9 => scene.state = ProductionState::BlockedRecoveryTest,
            10 => {
                not_met = Some(GoLiveEvidence {
                    writer_transition: Some(WriterTransitionPhase::Prepared),
                    ..scene.evidence()
                })
            }
            11..=14 => {
                let requirement = posture_requirements[index - 11];
                scene.posture = posture_with(requirement, requirement.fail());
            }
            _ => unreachable!("fuenfzehn Anforderungen"),
        }
        let evidence = not_met.unwrap_or_else(|| scene.evidence());
        let checklist = evaluate_go_live(&evidence);
        let requirement = &checklist.requirements()[index];
        assert_eq!(requirement.code(), *code);
        assert_eq!(
            requirement.status(),
            GoLiveRequirementStatus::NotMet,
            "{code} muss NotMet sein"
        );
        assert_ne!(requirement.evidence_code(), UNAVAILABLE);
        assert!(
            !checklist.production_ready(),
            "{code} NotMet darf nie gruen sein"
        );
        assert_eq!(
            checklist.unresolved().map(|r| r.code()).collect::<Vec<_>>(),
            vec![*code]
        );
        // Alle anderen bleiben bestaetigt: der Kipp trifft genau EINE Stelle.
        for (other_index, other) in checklist.requirements().iter().enumerate() {
            if other_index != index {
                assert_eq!(
                    other.status(),
                    GoLiveRequirementStatus::Confirmed,
                    "{}",
                    other.code()
                );
            }
        }

        // --- NotAutomaticallyVerifiable -----------------------------------
        let mut scene = Scene::satisfied();
        let mut unknown = None;
        match index {
            0 => {
                unknown = Some(GoLiveEvidence {
                    active_admin_count: None,
                    ..scene.evidence()
                })
            }
            1..=4 => {
                unknown = Some(GoLiveEvidence {
                    key_backups: None,
                    ..scene.evidence()
                })
            }
            5 | 6 => {
                unknown = Some(GoLiveEvidence {
                    registry: None,
                    ..scene.evidence()
                })
            }
            7 => {
                unknown = Some(GoLiveEvidence {
                    policy_present: None,
                    ..scene.evidence()
                })
            }
            8 => {
                unknown = Some(GoLiveEvidence {
                    evidence_policy_present: None,
                    ..scene.evidence()
                })
            }
            9 => {
                unknown = Some(GoLiveEvidence {
                    last_recovery_test: None,
                    ..scene.evidence()
                })
            }
            10 => {
                unknown = Some(GoLiveEvidence {
                    writer_transition: None,
                    ..scene.evidence()
                })
            }
            11..=14 => {
                let requirement = posture_requirements[index - 11];
                scene.posture = posture_with(requirement, requirement.unknown());
            }
            _ => unreachable!("fuenfzehn Anforderungen"),
        }
        let evidence = unknown.unwrap_or_else(|| scene.evidence());
        let checklist = evaluate_go_live(&evidence);
        let requirement = &checklist.requirements()[index];
        assert_eq!(requirement.code(), *code);
        assert_eq!(
            requirement.status(),
            GoLiveRequirementStatus::NotAutomaticallyVerifiable,
            "{code} muss unpruefbar sein"
        );
        assert!(
            !checklist.production_ready(),
            "{code} unbekannt darf nie gruen sein"
        );
        assert!(checklist.unresolved().any(|r| r.code() == *code));
    }
}

/// Die Haltungszeilen tragen den Beweiscode des BERICHTS, nicht einen eigenen.
#[test]
fn posture_rows_carry_the_report_evidence_codes() {
    let scene = Scene {
        posture: posture_with(
            PostureRequirement::AutomaticScreenLock,
            PostureRequirement::AutomaticScreenLock.unknown(),
        ),
        ..Scene::satisfied()
    };
    let checklist = evaluate_go_live(&scene.evidence());
    let by_code = |code: &str| {
        checklist
            .requirements()
            .iter()
            .find(|requirement| requirement.code() == code)
            .expect("Code vorhanden")
    };
    assert_eq!(
        by_code("EA-POSTURE-FULL-DISK-ENCRYPTION").evidence_code(),
        "EA-POSTURE-FDE-ENABLED"
    );
    assert_eq!(
        by_code("EA-POSTURE-SCREEN-LOCK").evidence_code(),
        "EA-POSTURE-SCREEN-LOCK-UNREPORTABLE"
    );
    assert_eq!(
        by_code("EA-POSTURE-SCREEN-LOCK").status(),
        GoLiveRequirementStatus::NotAutomaticallyVerifiable
    );
}

/// Das Lease deckt die NAECHSTE Sequenz UND `now <= not_after`; ein
/// abgelaufener Kopf ist nicht bestaetigt, auch wenn die Sequenz reicht.
#[test]
fn an_expired_head_fails_the_lease_requirement() {
    let scene = Scene::satisfied();
    let checklist = evaluate_go_live(&GoLiveEvidence {
        registry: Some(RegistryFreshness {
            not_after: UnixMillis::new(NOW.get() - 1),
            ..fresh_registry()
        }),
        ..scene.evidence()
    });
    assert_eq!(
        checklist.requirements()[6].status(),
        GoLiveRequirementStatus::NotMet
    );
    assert_eq!(
        checklist.requirements()[5].status(),
        GoLiveRequirementStatus::Confirmed
    );
    assert!(!checklist.production_ready());
}

/// Ein Recovery-Test, der laenger als das Intervall zurueckliegt oder in der
/// Zukunft liegt, ist nicht bestaetigt.
#[test]
fn a_stale_or_future_recovery_test_is_not_met() {
    let scene = Scene::satisfied();
    for completed_at in [
        UnixMillis::new(NOW.get() - 30 * 86_400_000 - 1),
        UnixMillis::new(NOW.get() + 1),
    ] {
        let checklist = evaluate_go_live(&GoLiveEvidence {
            last_recovery_test: Some(RecoveryTestFreshness::for_testing(&scene.state,completed_at,30 * 86_400_000,NOW)),
            ..scene.evidence()
        });
        assert_eq!(
            checklist.requirements()[9].status(),
            GoLiveRequirementStatus::NotMet,
            "{completed_at:?}"
        );
    }
    // Genau am Intervall ist noch frisch.
    let checklist = evaluate_go_live(&GoLiveEvidence {
        last_recovery_test: Some(RecoveryTestFreshness::for_testing(&scene.state,UnixMillis::new(NOW.get() - 30 * 86_400_000),30 * 86_400_000,NOW)),
        ..scene.evidence()
    });
    assert_eq!(
        checklist.requirements()[9].status(),
        GoLiveRequirementStatus::Confirmed
    );
}

/// Die Ausgabe ist deterministisch, nennt das Schema und GENAU die
/// unaufgeloesten Codes.
#[test]
fn the_unresolved_report_is_deterministic_and_lists_exactly_the_unresolved_codes() {
    let mut scene = Scene::satisfied();
    scene.state = ProductionState::BlockedRecoveryTest;
    let checklist = evaluate_go_live(&GoLiveEvidence {
        active_admin_count: None,
        ..scene.evidence()
    });
    let first = checklist.unresolved_report_json();
    let second = checklist.unresolved_report_json();
    assert_eq!(first.as_bytes(), second.as_bytes());

    let parsed: serde_json::Value = serde_json::from_str(&first).expect("gueltiges JSON");
    assert_eq!(parsed["schema"], "ea.go-live-checklist/v1");
    let unresolved = parsed["unresolved"].as_array().expect("Liste");
    let listed: Vec<&str> = unresolved
        .iter()
        .map(|entry| entry["requirementCode"].as_str().expect("Code"))
        .collect();
    assert_eq!(
        listed,
        vec!["EA-GOLIVE-TWO-ADMINS", "EA-GOLIVE-RECOVERY-TEST"]
    );
    assert_eq!(unresolved[0]["status"], "NotAutomaticallyVerifiable");
    assert_eq!(unresolved[0]["evidenceCode"], UNAVAILABLE);
    assert_eq!(unresolved[1]["status"], "NotMet");
    // Bestaetigte Anforderungen stehen NICHT darin.
    assert!(!first.contains("EA-GOLIVE-POLICY"));

    // Ein vollstaendig belegter Bestand liefert eine leere Liste — und
    // trotzdem das Schema.
    let clean = evaluate_go_live(&Scene::satisfied().evidence()).unresolved_report_json();
    let parsed: serde_json::Value = serde_json::from_str(&clean).expect("gueltiges JSON");
    assert_eq!(parsed["schema"], "ea.go-live-checklist/v1");
    assert_eq!(parsed["unresolved"].as_array().map(Vec::len), Some(0));
}

/// Kein Zahlenwert (also kein Zeitstempel) und kein Pfad in der Ausgabe — nur
/// Codes. Der einzige Schraegstrich ist der der Schemakennung.
#[test]
fn the_unresolved_report_carries_no_numbers_and_no_paths() {
    fn assert_no_number(value: &serde_json::Value) {
        match value {
            serde_json::Value::Number(number) => panic!("Zahl in der Ausgabe: {number}"),
            serde_json::Value::Array(items) => items.iter().for_each(assert_no_number),
            serde_json::Value::Object(fields) => fields.values().for_each(assert_no_number),
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            }
        }
    }
    let report = evaluate_go_live(&unknown_evidence()).unresolved_report_json();
    let parsed: serde_json::Value = serde_json::from_str(&report).expect("gueltiges JSON");
    assert_no_number(&parsed);
    let without_schema = report.replace("ea.go-live-checklist/v1", "");
    assert!(!without_schema.contains('/'), "{report}");
    assert!(!without_schema.contains('\\'), "{report}");
    assert!(!report.contains(char::is_whitespace), "kompakt: {report}");
}

/// Die Statusaufzaehlung fuehrt ihre drei Varianten in fester Reihenfolge.
#[test]
fn the_status_enum_lists_its_three_variants_in_order() {
    assert_eq!(
        GoLiveRequirementStatus::ALL,
        [
            GoLiveRequirementStatus::Confirmed,
            GoLiveRequirementStatus::NotMet,
            GoLiveRequirementStatus::NotAutomaticallyVerifiable,
        ]
    );
    assert_eq!(
        WriterTransitionPhase::ALL,
        [
            WriterTransitionPhase::NoTransition,
            WriterTransitionPhase::Prepared,
            WriterTransitionPhase::Activated,
        ]
    );
}
