use super::*;

fn open_without_posture_document(installation: &RecoveryInstallation) -> OperatorRuntime {
    let native = NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&installation.config).unwrap(),
        &installation.anchor,
        support::live_clock(),
        false,
        native,
        Arc::from(
            ea_key_provider::SupportMatrixRow::current_host()
                .unwrap()
                .posture_provider(),
        ),
    )
    .unwrap()
}

fn raw_checklist(runtime: &OperatorRuntime) -> ea_admin::GoLiveChecklist {
    let posture = runtime.device_posture_report().unwrap();
    ea_admin::evaluate_go_live(&ea_admin::GoLiveEvidence {
        active_admin_count: Some(
            runtime
                .head()
                .active_certificates()
                .filter(|(_, fields)| {
                    fields.certificate_kind == CertificateKindV1::OrganizationAdmin
                })
                .count(),
        ),
        key_backups: None,
        registry: None,
        policy_present: None,
        evidence_policy_present: None,
        last_recovery_test: None,
        writer_transition: None,
        device_posture: Some(&posture),
    })
}

#[test]
fn native_go_live_without_inventory_reads_unknown_posture_without_backend_mutation() {
    let installed = RecoveryInstallation::new();
    let runtime = open_without_posture_document(&installed);
    assert_eq!(
        runtime.ensure_current().unwrap_err().code(),
        "EA-OPERATOR-POSTURE"
    );
    assert!(
        !runtime
            .device_posture_report()
            .unwrap()
            .go_live_follow_up()
            .is_empty()
    );
    let database = Arc::clone(runtime.database());
    let audit_count = || {
        database
            .query_row("SELECT count(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
    };
    let before = audit_count();
    assert!(!installed.archive.join("README-FORMAT.txt").exists());
    assert!(!installed.archive.join(".ea-writer.lock").exists());
    let checklist =
        RecoveryTestRuntime::evaluate_go_live_without_inventory(runtime, raw_checklist).unwrap();
    assert!(!checklist.production_ready());
    assert_eq!(
        checklist.requirements()[0].status(),
        ea_admin::GoLiveRequirementStatus::Confirmed
    );
    assert_eq!(
        checklist.requirements()[9].status(),
        ea_admin::GoLiveRequirementStatus::NotAutomaticallyVerifiable
    );
    assert!(
        checklist.requirements()[11..].iter().any(
            |row| row.status() == ea_admin::GoLiveRequirementStatus::NotAutomaticallyVerifiable
        )
    );
    assert!(!installed.archive.join("README-FORMAT.txt").exists());
    assert!(!installed.archive.join(".ea-writer.lock").exists());
    assert_eq!(audit_count(), before);

    let runtime = open_without_posture_document(&installed);
    let path = installed.archive.join("entries/000000000000_entry.eip");
    let original = fs::read(&path).unwrap();
    let mut changed = original.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let result = RecoveryTestRuntime::evaluate_go_live_without_inventory(runtime, |current| {
        let checklist = raw_checklist(current);
        fs::write(&path, &changed).unwrap();
        checklist
    });
    fs::write(&path, original).unwrap();
    assert!(
        result.is_err(),
        "changed actual source cannot release an earlier diagnostic snapshot"
    );
}
