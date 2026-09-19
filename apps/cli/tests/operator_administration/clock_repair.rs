use super::*;
use ea_admin::operator_runtime::OperatorArchiveSnapshot;
use ea_admin::operator_runtime::clock_repair::{ClockRepairRuntime, ClockRepairRuntimeError};
use ea_key_provider::{
    DevicePostureProvider, DevicePostureProviderFake, DevicePostureReport, KeyError,
    PostureRequirement,
};
use ea_trust::{
    TrustStateKey, TrustStateStore as _, load_trust_state, prepare_local_time,
    verify_receipt_time, verify_registry_candidate, verify_trust,
};
use std::sync::Mutex;

struct Reference {
    server: CertificateHash,
    registry: ea_types::RegistryVersion,
    head: Hash32,
    policy: ObjectHash,
}
fn persist_reference(
    installation: &AdministrationInstallation,
    store: &mut ea_admin::operator_trust_store::OperatorTrustStateStore,
    key: TrustStateKey,
    reference: &Reference,
    accepted: UnixMillis,
) {
    let now = support::live_clock();
    let snapshot = OperatorArchiveSnapshot::open(
        &installation.directory.path().join("archive"),
        &installation.anchor,
        now,
    )
    .unwrap();
    let trust = verify_trust(
        snapshot.anchor(),
        snapshot.inventory(),
        load_trust_state(store, key).unwrap(),
    )
    .unwrap();
    let candidate = verify_registry_candidate(&trust, snapshot.next_sequence()).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_support::device_signing_secret(),
    ));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: key.organization_id,
        chain_id: snapshot.anchor().chain_id(),
        chain_sequence: snapshot.next_sequence(),
        entry_hash: snapshot.anchor().genesis_entry_hash(),
        entry_object_hash: ea_crypto::object_hash(b"clock native receipt exact entry"),
        previous_entry_hash: Some(snapshot.anchor().genesis_entry_hash()),
        registry_version: reference.registry,
        registry_head_hash: reference.head,
        policy_object_hash: reference.policy,
        initial_grant_plan_hash: Hash32::try_from(&[0x21; 32][..]).unwrap(),
        initial_grant_object_hashes: vec![ea_crypto::object_hash(b"clock native grant")],
        accepted_at_server: accepted,
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: reference.server,
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact =
        ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(exact.as_bytes()).unwrap()
    else {
        panic!()
    };
    let verified =
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    drop(prepare_local_time(store, &candidate, now, &[verified]).unwrap());
}
fn provider(installation: &AdministrationInstallation) -> Arc<NativeOperatorProvider> {
    NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap()
}

/// Tatsächlicher Neustart mit einem dauerhaft verifizierten, zu alten
/// ServerReceipt-Zeitbezug: der gewöhnliche Einstieg verweigert FutureSkew.
struct BlockedInstallation {
    installation: AdministrationInstallation,
    config: OperatorRuntimeConfig,
    store: ea_admin::operator_trust_store::OperatorTrustStateStore,
    key: TrustStateKey,
    reference: Reference,
    accepted: UnixMillis,
}
impl BlockedInstallation {
    fn new() -> Self {
        let installation = AdministrationInstallation::new();
        let runtime = installation.open();
        let reference = Reference {
            server: runtime
                .head()
                .active_certificates()
                .find(|(_, fields)| {
                    fields.certificate_kind == ea_format::CertificateKindV1::ServerReceipt
                })
                .unwrap()
                .0,
            registry: runtime.head().registry_version(),
            head: Hash32::try_from(runtime.head().registry_head_hash().as_bytes().as_slice())
                .unwrap(),
            policy: runtime.head().policy_object_hash(),
        };
        let key = TrustStateKey {
            organization_id: runtime.anchor().organization_id(),
            device_id: DeviceId::try_from(&[0x52; 16][..]).unwrap(),
        };
        let mut store = runtime.trust_store().clone();
        let config = runtime.config().clone();
        let accepted = UnixMillis::new(
            support::live_clock().get()
                - i64::try_from(runtime.head().policy_fields().max_future_clock_skew_ms).unwrap()
                - 30_000,
        );
        persist_reference(&installation, &mut store, key, &reference, accepted);
        drop(runtime);
        let blocked = Self {
            installation,
            config,
            store,
            key,
            reference,
            accepted,
        };
        blocked.assert_ordinary_future_skew("restart with the old verified reference");
        blocked
    }
    fn assert_ordinary_future_skew(&self, context: &str) {
        let ordinary = OperatorRuntime::open_with_test_native(
            self.config.clone(),
            &self.installation.anchor,
            support::live_clock(),
            false,
            provider(&self.installation),
        );
        assert!(
            matches!(ordinary, Err(ref error) if error.code() == "EA-TRUST-FUTURE-SKEW"),
            "{context}: ordinary admission must stay FutureSkew"
        );
    }
    fn repair_config(&self) -> OperatorRuntimeConfig {
        let mut config = self.config.clone();
        config.purpose = ea_operator::ReauthPurpose::ClockSkewRelease;
        config
    }
    fn open_repair(&self) -> Result<ClockRepairRuntime, ClockRepairRuntimeError> {
        ClockRepairRuntime::open_with_test_native(
            self.repair_config(),
            &self.installation.anchor,
            provider(&self.installation),
        )
    }
    fn open_repair_with_posture(
        &self,
        posture: Arc<dyn DevicePostureProvider>,
    ) -> Result<ClockRepairRuntime, ClockRepairRuntimeError> {
        ClockRepairRuntime::open_with_test_native_and_posture(
            self.repair_config(),
            &self.installation.anchor,
            provider(&self.installation),
            posture,
        )
    }
    fn path(&self, name: &str) -> PathBuf {
        self.installation.directory.path().join(name)
    }
    fn database(&self) -> EncryptedDatabase {
        let (provider, key) = database_provider_for(true);
        EncryptedDatabase::open(&self.path("operator.sqlite"), &provider, &key).unwrap()
    }
    /// Persistierter Trust-Zustand: jeder Consume/Commit erhöht die Revision.
    fn trust_revision(&self) -> u64 {
        self.store.clone().load(self.key).unwrap().revision()
    }
    /// (Login/Completed, ClockSkewRelease/Accepted) in der echten SQLCipher-Datenbank.
    fn clock_audits(&self) -> (usize, usize) {
        let db = self.database();
        let count = db
            .query_row("SELECT count(*) FROM local_audit_event", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap();
        let (mut logins, mut releases) = (0, 0);
        for offset in 0..count {
            let row = db
                .query_row(
                    "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence LIMIT 1 OFFSET ?1",
                    &[StoreValue::Integer(offset)],
                )
                .unwrap()
                .unwrap();
            let event = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
            match (event.action(), event.outcome()) {
                (ea_format::LocalAuditActionV1::Login(_), ea_format::LocalAuditOutcomeV1::Completed) => {
                    logins += 1
                }
                (
                    ea_format::LocalAuditActionV1::ClockSkewRelease(_),
                    ea_format::LocalAuditOutcomeV1::Accepted,
                ) => releases += 1,
                _ => {}
            }
        }
        (logins, releases)
    }
    fn presence_signatures(&self) -> usize {
        fs::read_to_string(self.path("helper-calls"))
            .unwrap_or_default()
            .matches("sign operator-instance")
            .count()
    }
    /// Kein Trust-Consume, keine Audit-Ausgabe, normaler Reopen weiter gesperrt.
    fn assert_untouched(&self, revision: u64, audits: (usize, usize), context: &str) {
        assert_eq!(self.trust_revision(), revision, "{context}: no trust consume");
        assert_eq!(self.clock_audits(), audits, "{context}: no durable audit");
        self.assert_ordinary_future_skew(context);
    }
    /// Hält die tatsächliche native Präsenz-Signatur an, führt `during` aus und
    /// gibt sie danach wieder frei. Liefert den Fehler von `release`.
    fn release_holding_presence(&self, during: impl FnOnce()) -> ClockRepairRuntimeError {
        let barrier = self.path("hold-operator-signature");
        let paused = self.path("operator-signature-paused");
        let repair = self
            .open_repair()
            .expect("control: the sealed Clock path opens");
        fs::write(&barrier, b"").unwrap();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                repair.release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while !paused.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "presence must pause"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            during();
            fs::remove_file(&barrier).unwrap();
            match worker.join().unwrap() {
                Ok(_) => panic!("a changed held operation must not release"),
                Err(error) => error,
            }
        })
    }
}

#[test]
fn native_clock_only_restart_persists_audits_consumes_once_and_old_reference_still_blocks_normal_reopen()
 {
    let blocked = BlockedInstallation::new();
    let revision = blocked.trust_revision();
    let repair = blocked
        .open_repair()
        .expect("actual restart admits only the sealed Clock repair path");
    let completed = repair
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .expect("native presence, durable Login/Clock audits and atomic one-use selection");
    let login = ea_format::decode_local_audit_event(completed.login().exact_bytes()).unwrap();
    assert!(matches!(
        login.action(),
        ea_format::LocalAuditActionV1::Login(_)
    ));
    assert_eq!(login.outcome(), ea_format::LocalAuditOutcomeV1::Completed);
    let audit = ea_format::decode_clock_release_audit(completed.release().exact_bytes()).unwrap();
    assert_eq!(audit.outcome(), ea_format::LocalAuditOutcomeV1::Accepted);
    assert!(
        blocked.trust_revision() > revision,
        "the exact selection was atomically consumed"
    );
    assert_eq!(blocked.clock_audits(), (1, 1));
    assert_eq!(blocked.presence_signatures(), 1);
    blocked.assert_ordinary_future_skew("a one-use release never grants a persistent exception");
    let mut store = blocked.store.clone();
    persist_reference(
        &blocked.installation,
        &mut store,
        blocked.key,
        &blocked.reference,
        support::live_clock(),
    );
    let recovered = OperatorRuntime::open_with_test_native(
        blocked.config.clone(),
        &blocked.installation.anchor,
        support::live_clock(),
        false,
        provider(&blocked.installation),
    )
    .expect("only a genuinely new verified signed time reference restores normal admission");
    for event in [completed.login(), completed.release()] {
        let row = recovered
            .database()
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
                &[StoreValue::Blob(event.id().as_bytes().to_vec())],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.blob(0).unwrap(), event.exact_bytes());
    }
}

/// Fixture-Posture: fest oder ab der ersten tatsächlichen Präsenz-Signatur Fail.
struct ClockPosture {
    report: Mutex<DevicePostureReport>,
    fail_after_presence: Option<PathBuf>,
}
impl DevicePostureProvider for ClockPosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        if self.fail_after_presence.as_ref().is_some_and(|path| {
            fs::read_to_string(path).is_ok_and(|calls| calls.contains("sign operator-instance"))
        }) {
            return Ok(DevicePostureProviderFake::failing_screen_lock()
                .report()
                .unwrap());
        }
        Ok(*self.report.lock().unwrap())
    }
}

#[test]
fn native_clock_repair_admits_only_measured_pass_and_refuses_fail_or_unknown_before_presence() {
    let blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    for requirement in PostureRequirement::ALL {
        for report in [
            DevicePostureProviderFake::failing(requirement)
                .report()
                .unwrap(),
            DevicePostureProviderFake::unknown(requirement)
                .report()
                .unwrap(),
        ] {
            let posture = Arc::new(ClockPosture {
                report: Mutex::new(report),
                fail_after_presence: None,
            });
            let refused = blocked.open_repair_with_posture(posture);
            assert!(
                matches!(refused, Err(ref error) if error.code() == "EA-OPERATOR-POSTURE"),
                "{requirement:?}: only actual Pass admits the Clock path"
            );
        }
    }
    assert_eq!(blocked.presence_signatures(), 0, "no presence dialog");
    blocked.assert_untouched(revision, audits, "Fail/Unknown posture");
}

#[test]
fn native_clock_repair_posture_failing_after_presence_leaves_no_audit_and_no_consume() {
    let blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    let posture = Arc::new(ClockPosture {
        report: Mutex::new(DevicePostureProviderFake::all_passing().report().unwrap()),
        fail_after_presence: Some(blocked.path("helper-calls")),
    });
    let repair = blocked
        .open_repair_with_posture(posture)
        .expect("control: measured Pass opens the Clock path");
    let refused = repair
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .err()
        .expect("posture Fail after the presence signature must refuse");
    assert_eq!(refused.code(), "EA-OPERATOR-POSTURE");
    assert_eq!(blocked.presence_signatures(), 1, "the dialog really ran");
    blocked.assert_untouched(revision, audits, "posture Fail after presence");
}

#[test]
fn native_clock_repair_lock_during_held_presence_leaves_no_audit_and_no_consume() {
    let blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    let action = blocked.path("watch-action");
    let delivered = blocked.path("watch-delivered");
    let refused = blocked.release_holding_presence(|| {
        // Tatsächliches natives Sperrereignis, während der Dialog offen ist.
        fs::write(&action, "watch-event").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !delivered.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "lock must be delivered"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    fs::remove_file(&action).unwrap();
    // Die nach dem Sperrereignis gelieferte Signatur wird verworfen.
    assert_eq!(refused.code(), "EA-OPERATOR-PRESENCE-PROOF-INVALID");
    blocked.assert_untouched(revision, audits, "lock during the presence dialog");
}

#[test]
fn native_clock_repair_reference_change_during_held_presence_leaves_no_audit_and_no_consume() {
    let blocked = BlockedInstallation::new();
    let audits = blocked.clock_audits();
    let refused = blocked.release_holding_presence(|| {
        // Neuere, aber weiterhin zu alte signierte Referenz: Revision und
        // Referenz ändern sich, die FutureSkew-Sperre bleibt bestehen.
        let mut store = blocked.store.clone();
        persist_reference(
            &blocked.installation,
            &mut store,
            blocked.key,
            &blocked.reference,
            UnixMillis::new(blocked.accepted.get() + 1_000),
        );
    });
    assert_eq!(refused.code(), "EA-TRUST-CLOCK-RELEASE-MISMATCH");
    let revision = blocked.trust_revision();
    blocked.assert_untouched(revision, audits, "reference change during presence");
}

#[test]
fn native_clock_repair_revocation_during_held_presence_leaves_no_audit_and_no_consume() {
    use ea_trust::TrustObjectSource as _;
    let mut blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    let binding = blocked.config.binding_object_hash;
    let archive = blocked.path("archive");
    let mut prior = std::collections::BTreeSet::new();
    blocked
        .installation
        .line
        .source()
        .visit_trust_object_hashes(&mut |hash| {
            prior.insert(hash);
            Ok(())
        })
        .unwrap();
    blocked.installation.line.push(
        ActionSpec::Revoke {
            target_kind: 1,
            object_hash: binding,
        },
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            ..HeadOptions::default()
        },
    );
    let mut revocation = Vec::new();
    let source = blocked.installation.line.source();
    source
        .visit_trust_object_hashes(&mut |hash| {
            if !prior.contains(&hash) {
                revocation.push((hash, source.read_exact_trust_object(hash)?.unwrap()));
            }
            Ok(())
        })
        .unwrap();
    assert!(!revocation.is_empty());
    let refused = blocked.release_holding_presence(|| {
        // Signierte Sperrung der Admin-Bindung erscheint in der Archivquelle.
        for (hash, exact) in &revocation {
            fs::write(
                archive.join(format!("{}.etb", hex::encode(hash.as_bytes()))),
                exact,
            )
            .unwrap();
        }
    });
    assert_eq!(refused.code(), "EA-OPERATOR-ARCHIVE");
    assert_eq!(blocked.trust_revision(), revision, "no trust consume");
    assert_eq!(blocked.clock_audits(), audits, "no durable audit");
    let reopened = blocked.open_repair();
    assert_eq!(
        reopened.err().map(|error| error.code()),
        Some("EA-TRUST-SIGNER-INACTIVE"),
        "the revoked binding cannot open a new Clock repair either"
    );
    assert_eq!(blocked.clock_audits(), audits);
}

#[test]
fn native_clock_repair_failed_login_audit_transaction_records_no_presence_and_releases_no_bytes() {
    let blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    blocked
        .database()
        .execute(
            "CREATE TRIGGER refuse_clock_login BEFORE INSERT ON local_audit_event BEGIN SELECT RAISE(ABORT,'fixture audit write unavailable'); END",
            &[],
        )
        .unwrap();
    let repair = blocked.open_repair().expect("control: Clock path opens");
    let refused = repair
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .err()
        .expect("a failed durable Login transaction must refuse");
    assert_eq!(refused.code(), "EA-STORE-CONSTRAINT");
    blocked.assert_untouched(revision, audits, "failed Login transaction");
    blocked
        .database()
        .execute("DROP TRIGGER refuse_clock_login", &[])
        .unwrap();
    // Kontrollprobe: derselbe unverbrauchte Zustand lässt genau eine Freigabe zu.
    blocked
        .open_repair()
        .unwrap()
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .expect("nothing was consumed by the failed attempt");
    assert_eq!(blocked.clock_audits(), (audits.0 + 1, audits.1 + 1));
}

#[test]
fn native_clock_repair_failed_release_audit_transaction_releases_no_bytes_and_no_consume() {
    let blocked = BlockedInstallation::new();
    let (revision, audits) = (blocked.trust_revision(), blocked.clock_audits());
    let before = blocked
        .database()
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    // Login darf dauerhaft werden, erst die Freigabe-Transaktion scheitert.
    blocked
        .database()
        .execute(
            &format!(
                "CREATE TRIGGER refuse_clock_release BEFORE INSERT ON local_audit_event WHEN (SELECT count(*) FROM local_audit_event) > {before} BEGIN SELECT RAISE(ABORT,'fixture audit write unavailable'); END"
            ),
            &[],
        )
        .unwrap();
    let refused = blocked
        .open_repair()
        .unwrap()
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .err()
        .expect("a failed durable release transaction must refuse");
    assert_eq!(refused.code(), "EA-STORE-CONSTRAINT");
    blocked.assert_untouched(
        revision,
        (audits.0 + 1, audits.1),
        "failed ClockSkewRelease transaction",
    );
}

#[test]
fn native_clock_repair_consumed_release_bytes_cannot_be_replayed() {
    let blocked = BlockedInstallation::new();
    let completed = blocked
        .open_repair()
        .unwrap()
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .unwrap();
    let revision = blocked.trust_revision();
    // Exakt dieselben dauerhaft signierten Bytes gegen den tatsächlich
    // persistierten Zustand, mit der signierten beobachteten Uhrzeit.
    let audit = ea_format::decode_clock_release_audit(completed.release().exact_bytes()).unwrap();
    let mut store = blocked.store.clone();
    let snapshot = OperatorArchiveSnapshot::open(
        &blocked.path("archive"),
        &blocked.installation.anchor,
        support::live_clock(),
    )
    .unwrap();
    let trust = verify_trust(
        snapshot.anchor(),
        snapshot.inventory(),
        load_trust_state(&mut store, blocked.key).unwrap(),
    )
    .unwrap();
    let candidate = verify_registry_candidate(&trust, snapshot.next_sequence()).unwrap();
    let mut block = prepare_local_time(
        &mut store,
        &candidate,
        audit.context().observed_os_wall_clock(),
        &[],
    )
    .unwrap();
    let replay =
        ea_trust::verify_clock_release(&candidate, &mut block, completed.release().exact_bytes());
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some("EA-TRUST-CLOCK-RELEASE-REPLAY"),
        "consumed release bytes are refused"
    );
    drop(block);
    assert_eq!(blocked.trust_revision(), revision, "replay consumes nothing");
    assert_eq!(blocked.clock_audits(), (1, 1));
    blocked.assert_ordinary_future_skew("after refused replay");
}
