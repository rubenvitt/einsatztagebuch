use super::*;
use ea_admin::destruction_runtime::{DestructionHostGuard, NativeDestructionError};
use ea_crypto::{SignerRole, VerificationContext};
use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1};
use std::sync::atomic::{AtomicU64, Ordering};

fn database(f: &NativeDestructionFixture, admin: bool) -> EncryptedDatabase {
    let (provider, key) = database_provider_for(admin);
    EncryptedDatabase::open_existing(
        &if admin {
            &f.admin_directory
        } else {
            &f.writer_directory
        }
        .join("local.sqlite"),
        &provider,
        &key,
    )
    .unwrap()
}
fn count(db: &EncryptedDatabase, table: &str) -> i64 {
    assert!(matches!(
        table,
        "local_audit_event" | "destruction_request" | "destruction_job"
    ));
    db.query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}
fn calls(f: &NativeDestructionFixture, admin: bool, operation: &str) -> usize {
    fs::read_to_string(
        if admin {
            &f.admin_directory
        } else {
            &f.writer_directory
        }
        .join("helper-calls"),
    )
    .unwrap()
    .lines()
    .filter(|line| *line == operation)
    .count()
}
fn open_writer(f: &NativeDestructionFixture) -> OperatorRuntime {
    let native = NativeOperatorProvider::open_test_fixture(
        f.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap()
}

#[test]
fn native_destruction_custodian_presence_is_independent_and_grants_no_admin_session() {
    let f = NativeDestructionFixture::without_server();
    let observer = open_writer(&f);
    let mut runtime = f.runtime();
    runtime.unlock().unwrap();
    let writer = database(&f, false);
    let admin = database(&f, true);
    let writer_audits = count(&writer, "local_audit_event");
    let admin_audits = count(&admin, "local_audit_event");
    let writer_presence = calls(&f, false, "sign operator-instance");
    let admin_presence = calls(&f, true, "sign operator-instance");
    let watches = calls(&f, false, "watch-session ");
    assert!(watches > 0);
    assert!(
        runtime.authenticate_custodian().is_ok(),
        "explicit actual Writer presence must complete"
    );
    assert_eq!(count(&writer, "local_audit_event"), writer_audits + 1);
    assert_eq!(count(&admin, "local_audit_event"), admin_audits);
    assert_eq!(
        calls(&f, false, "sign operator-instance"),
        writer_presence + 1
    );
    assert_eq!(calls(&f, true, "sign operator-instance"), admin_presence);
    assert_eq!(
        calls(&f, false, "watch-session "),
        watches,
        "presence uses the same continuous watch"
    );
    assert_eq!(count(&writer, "destruction_request"), 0);
    assert_eq!(count(&writer, "destruction_job"), 0);
    assert!(
        runtime.administration().is_err(),
        "discarded Writer login never supplies an Admin session"
    );
    let row = writer
        .query_row(
            "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence DESC LIMIT 1",
            &[],
        )
        .unwrap()
        .unwrap();
    let exact = row.blob(0).unwrap();
    let audit = ea_format::decode_local_audit_event(exact).unwrap();
    assert!(matches!(audit.action(), LocalAuditActionV1::Login(_)));
    assert_eq!(audit.outcome(), LocalAuditOutcomeV1::Completed);
    assert_eq!(
        audit.signer_certificate_object_hash().as_bytes(),
        f.writer_certificate.as_bytes()
    );
    let mut decoder = minicbor::Decoder::new(exact);
    assert_eq!(decoder.array().unwrap(), Some(2));
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    let head = observer.head();
    let context = VerificationContext::local_audit(
        audit.exact_core(),
        head.proposed_sequence(),
        SignerRole::Writer,
        head.registry_version(),
    )
    .unwrap();
    ea_crypto::verify_cose_sign1(&exact[start..decoder.position()], head, &context).unwrap();
    runtime.unlock().unwrap();
    assert!(
        runtime
            .administration()
            .unwrap()
            .known_destruction_ids
            .is_empty()
    );
}

struct Epoch(Arc<AtomicU64>);
impl DestructionHostGuard for Epoch {
    fn require_open(&self) -> Result<(), NativeDestructionError> {
        if self.0.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(NativeDestructionError::Session)
        }
    }
}
#[test]
fn native_destruction_custodian_presence_refuses_host_closure_during_writer_dialog() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let epoch = Arc::new(AtomicU64::new(0));
    runtime.set_host_guard(Arc::new(Epoch(epoch.clone())));
    let barrier = f.writer_directory.join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let action = std::thread::spawn(move || {
        let result = runtime.authenticate_custodian();
        (runtime, result)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !f
        .writer_directory
        .join("operator-signature-paused")
        .exists()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "actual independent Writer presence"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    epoch.store(1, Ordering::SeqCst);
    fs::remove_file(barrier).unwrap();
    let (mut runtime, result) = action.join().unwrap();
    assert!(matches!(result, Err(NativeDestructionError::Session)));
    assert!(runtime.administration().is_err());
    let writer = database(&f, false);
    assert_eq!(count(&writer, "destruction_request"), 0);
    assert_eq!(count(&writer, "destruction_job"), 0);
}
#[test]
fn native_destruction_custodian_presence_does_not_replace_an_invalidated_watch() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let watches = calls(&f, false, "watch-session ");
    assert!(watches > 0);
    let presence = calls(&f, false, "sign operator-instance");
    let action = f.writer_directory.join("watch-action");
    fs::write(&action, b"watch-event").unwrap();
    assert!(runtime.authenticate_custodian().is_err());
    fs::remove_file(action).unwrap();
    assert!(
        runtime.authenticate_custodian().is_err(),
        "same watch remains permanently invalid"
    );
    assert_eq!(
        calls(&f, false, "watch-session "),
        watches,
        "no implicit native provider replacement"
    );
    assert_eq!(calls(&f, false, "sign operator-instance"), presence);
    drop(runtime);
    let mut explicitly_reopened = f.runtime();
    explicitly_reopened.authenticate_custodian().unwrap();
    assert!(
        explicitly_reopened.administration().is_err(),
        "even an explicit fresh Writer login is not Admin authority"
    );
}
