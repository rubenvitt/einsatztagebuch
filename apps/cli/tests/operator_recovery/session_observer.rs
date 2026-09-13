//! Native proof handoff witnesses; no synthetic session or alternate authority.
use super::*;
use ea_admin::recovery_test_runtime::{
    RecoveryMediumInput, RecoveryMediumObservation, RecoveryMediumRequest,
    RecoveryNativeSigningSlot, RecoverySessionObserver, RecoveryTestAbort, RecoveryTestGuide,
};
use ea_operator::{OperatorSessionProof, ReauthPurpose};

struct OneNativeMedium {
    medium: ObjectHash,
    delivered: usize,
}
impl RecoveryTestGuide for OneNativeMedium {
    fn request_medium(
        &mut self,
        request: &RecoveryMediumRequest,
    ) -> Result<Option<RecoveryMediumInput>, RecoveryTestAbort> {
        Ok((request.medium_id_hash() == self.medium).then_some(
            RecoveryMediumInput::NativeSigningSlot(RecoveryNativeSigningSlot::Admin),
        ))
    }
    fn medium_result(
        &mut self,
        result: &RecoveryMediumObservation,
    ) -> Result<(), RecoveryTestAbort> {
        if result.medium_id_hash() == self.medium {
            assert_eq!(
                result.status(),
                ea_admin::recovery_test_runtime::RecoveryMediumStatus::Passed
            );
            self.delivered += 1;
            return Err(RecoveryTestAbort);
        }
        Ok(())
    }
    fn ensure_active(&self) -> Result<(), RecoveryTestAbort> {
        Ok(())
    }
}

struct NativeSessionInbox {
    runtime: OperatorRuntime,
    deny_epoch: bool,
    last_login_sequence: i64,
    proofs: Vec<Arc<OperatorSessionProof>>,
}
impl RecoverySessionObserver for NativeSessionInbox {
    fn verified_session(
        &mut self,
        proof: Arc<OperatorSessionProof>,
    ) -> Result<(), RecoveryTestAbort> {
        self.runtime = self.runtime.reopened_for_action().unwrap();
        self.runtime.ensure_current().unwrap();
        let config = self.runtime.config();
        ea_operator::verify_current_session(
            self.runtime.head(),
            config.device_certificate_hash,
            config.role,
            proof.as_ref(),
            ReauthPurpose::RecoveryTest,
            self.runtime.native().as_ref(),
        )
        .unwrap();
        assert!(
            ea_operator::verify_current_session(
                self.runtime.head(),
                config.device_certificate_hash,
                config.role,
                proof.as_ref(),
                ReauthPurpose::AdminRootCeremony,
                self.runtime.native().as_ref(),
            )
            .is_err(),
            "the observer cannot reinterpret RecoveryTest as another action"
        );
        assert!(
            !proof.is_valid_at(ReauthPurpose::RecoveryTest, proof.expires_at()),
            "sharing the same proof does not extend its exclusive deadline"
        );

        // This actual read also proves no SQLCipher transaction is held while
        // the observer consumes the already audited native session.
        let row = self.runtime.database().query_row(
            "SELECT insertion_sequence,exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1", &[],
        ).unwrap().unwrap();
        let sequence = row.integer(0).unwrap();
        assert!(
            sequence > self.last_login_sequence,
            "each delivered proof has a fresh durable Login"
        );
        let exact = row.blob(1).unwrap();
        let audit = ea_format::decode_local_audit_event(exact).unwrap();
        assert!(matches!(
            audit.action(),
            ea_format::LocalAuditActionV1::Login(_)
        ));
        assert_eq!(audit.outcome(), ea_format::LocalAuditOutcomeV1::Completed);
        let mut decoder = minicbor::Decoder::new(exact);
        decoder.array().unwrap();
        decoder.skip().unwrap();
        let start = decoder.position();
        decoder.skip().unwrap();
        let context = ea_crypto::VerificationContext::local_audit(
            audit.exact_core(),
            self.runtime.next_sequence(),
            ea_crypto::SignerRole::OrganizationAdmin,
            self.runtime.head().registry_version(),
        )
        .unwrap();
        ea_crypto::verify_cose_sign1(
            &exact[start..decoder.position()],
            self.runtime.head(),
            &context,
        )
        .unwrap();
        self.last_login_sequence = sequence;
        if let Some(previous) = self.proofs.last() {
            assert_ne!(
                previous.as_ref(),
                proof.as_ref(),
                "new actual presence, not replayed proof"
            );
        }
        self.proofs.push(proof);
        if self.deny_epoch {
            Err(RecoveryTestAbort)
        } else {
            Ok(())
        }
    }
}

fn report_counts(runtime: &RecoveryTestRuntime) -> (i64, i64) {
    let count = |table: &str| {
        runtime
            .runtime()
            .database()
            .query_row(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
    };
    (
        count("recovery_test_report"),
        count("recovery_test_failure"),
    )
}

fn observe_native_medium(deny_epoch: bool) {
    let export = PathBuf::from(std::env::var_os("EA_T9_PORTABLE_SOURCE").unwrap());
    let target = PathBuf::from(std::env::var_os("EA_T9_TARGET_DIRECTORY").unwrap());
    let inventory = KeyInventory::parse(&fs::read(export.join("inventory.json")).unwrap()).unwrap();
    let mut runtime = open_portable_target(&export, &target);
    renew_portable_fixture_posture(&runtime);
    let restored = runtime
        .reopen_restored_source(&inventory, &target.join("restored-sources.sqlite"))
        .unwrap();
    let medium = inventory
        .media()
        .iter()
        .find(|medium| {
            medium.role() == RecoveryKeyRole::OrganizationAdmin
                && medium.protection() == ea_format::KeyProtectionProfileV1::OsWrapped
        })
        .unwrap();
    let before = report_counts(&runtime);
    let mut guide = OneNativeMedium {
        medium: medium.pseudonymous_id_hash(),
        delivered: 0,
    };
    let last_login_sequence = runtime
        .runtime()
        .database()
        .query_row("SELECT max(insertion_sequence) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    let mut observer = NativeSessionInbox {
        runtime: runtime.runtime().reopened_for_action().unwrap(),
        deny_epoch,
        last_login_sequence,
        proofs: Vec::new(),
    };
    let result = runtime.run_restored_test_guided_with_session_observer(
        &restored,
        &inventory,
        &mut guide,
        &mut observer,
    );
    assert_eq!(
        result
            .err()
            .expect("observer or guide aborts before terminal report")
            .code(),
        "EA-RECOVERY-TEST-CANCELLED"
    );
    assert_eq!(
        observer.proofs.len(),
        if deny_epoch { 1 } else { 2 },
        "actual audited session must reach the native observer"
    );
    assert_eq!(
        guide.delivered,
        usize::from(!deny_epoch),
        "a denied observer vetoes before the actual medium result"
    );
    assert_eq!(report_counts(&runtime), before);
    restored.verify_unchanged().unwrap();
    drop(observer);
    drop(restored);
    drop(runtime);
    let reopened = open_portable_target(&export, &target);
    assert_eq!(
        report_counts(&reopened),
        before,
        "no hidden Completed or Failed after restart"
    );
}

#[test]
#[ignore = "actual foreign-machine restore and native per-medium RecoveryTest presence"]
fn portable_native_recovery_observer_receives_fresh_audited_sessions() {
    observe_native_medium(false);
}

#[test]
#[ignore = "actual native observer epoch denial before medium and report writes"]
fn portable_native_recovery_observer_denial_preserves_previous_reports() {
    observe_native_medium(true);
}
