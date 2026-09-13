#[path = "../../ea-trust/tests/support/clock_repair_fixture.rs"]
mod fixture;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;
use ea_audit::{ClockRepairAuditService, LocalAuditRepository, SqliteLocalAuditRepository};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::{
    ClockReleaseJustificationV1, KeyProtectionProfileV1, LocalAuditActionV1, LocalAuditOutcomeV1,
};
use ea_key_provider::{
    CoseSign1Bytes, InMemoryKeyProvider, KeyError, KeyHandle, KeyProvider, SecretPurpose,
};
use ea_local_store::{EncryptedDatabase, StoreError};
use ea_operator::{
    ClockRepairProfileSnapshot, OperatorError, OsAccountProvider, authenticate_clock_repair,
};
use ea_types::{CertificateHash, DeviceId, Hash32, OrganizationId, UnixMillis};
use ed25519_dalek::{Signer, SigningKey};
use std::{path::PathBuf, sync::Arc};

struct Account;
impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _: OrganizationId,
        _: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(fixture::account_hash())
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(fixture::instance_public()))
    }
}
struct Provider {
    inner: InMemoryKeyProvider,
    wrong: bool,
    advance_after_sign: std::sync::atomic::AtomicBool,
    observed_now: std::sync::atomic::AtomicI64,
}
impl KeyProvider for Provider {
    fn generate(&self, p: SecretPurpose, k: KeyProtectionProfileV1) -> Result<KeyHandle, KeyError> {
        self.inner.generate(p, k)
    }
    fn sign(
        &self,
        _: &KeyHandle,
        t: ContentType,
        c: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        let key = SigningKey::from_bytes(&if self.wrong {
            [0x77; 32]
        } else {
            support::second_admin_signing_secret()
        });
        let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes())?;
        let header = ProtectedHeader::normal(t, public.thumbprint(), c);
        if self
            .advance_after_sign
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.observed_now
                .store(fixture::NOW + 300_000, std::sync::atomic::Ordering::SeqCst);
        }
        CoseSign1Bytes::compose(
            &header,
            payload,
            &key.sign(&header.sig_structure_bytes(payload)).to_bytes(),
        )
    }
    fn wrap_secret(&self, p: SecretPurpose, s: SecretBytes<32>) -> Result<KeyHandle, KeyError> {
        self.inner.wrap_secret(p, s)
    }
    fn unwrap_secret(&self, h: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        self.inner.unwrap_secret(h)
    }
    fn unwrap_database_key(&self, h: &KeyHandle) -> Result<SecretVec, KeyError> {
        self.inner.unwrap_database_key(h)
    }
    fn delete(&self, h: &KeyHandle) -> Result<(), KeyError> {
        self.inner.delete(h)
    }
    fn contains(&self, h: &KeyHandle) -> Result<bool, KeyError> {
        self.inner.contains(h)
    }
    fn reached_protection_profile(
        &self,
        h: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.inner.reached_protection_profile(h)
    }
}
struct Harness {
    path: PathBuf,
    provider: Arc<Provider>,
    key: KeyHandle,
    signing: KeyHandle,
    database: Arc<EncryptedDatabase>,
}
impl Harness {
    fn new(wrong: bool) -> Self {
        let path = std::env::temp_dir().join(format!(
            "clock-audit-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let provider = Arc::new(Provider {
            inner: InMemoryKeyProvider::new_for_test([0x73; 32]),
            wrong,
            advance_after_sign: std::sync::atomic::AtomicBool::new(false),
            observed_now: std::sync::atomic::AtomicI64::new(fixture::NOW),
        });
        let key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let signing = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let database = Arc::new(EncryptedDatabase::open(&path, provider.as_ref(), &key).unwrap());
        Self {
            path,
            provider,
            key,
            signing,
            database,
        }
    }
    fn service(&self) -> ClockRepairAuditService {
        ClockRepairAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(self.database.clone())),
            self.provider.clone(),
            self.signing,
        )
    }
}
fn profile(binding: ea_types::ObjectHash) -> ClockRepairProfileSnapshot<'static> {
    ClockRepairProfileSnapshot {
        organization_id: support::organization(),
        operator_subject_id: fixture::subject(),
        binding_hash: binding,
        display_name: fixture::NAME,
        function_label: fixture::FUNCTION,
        salt: &fixture::SALT,
    }
}
#[test]
fn clock_login_and_release_are_exact_signed_and_durably_readable_after_database_reopen() {
    let f = fixture::fixture();
    let presence = authenticate_clock_repair(
        &f.authority,
        &Account,
        &fixture::signing_public(),
        &profile(f.binding),
        |bytes| {
            Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                .sign(bytes)
                .to_bytes())
        },
    )
    .unwrap();
    let harness = Harness::new(false);
    let service = harness.service();
    let login = service
        .record_login(&presence, UnixMillis::new(fixture::NOW))
        .expect("real durable Clock login");
    let decoded = ea_format::decode_local_audit_event(login.event().exact_bytes()).unwrap();
    assert_eq!(decoded.outcome(), LocalAuditOutcomeV1::Completed);
    assert!(matches!(decoded.action(), LocalAuditActionV1::Login(_)));
    let release = service
        .record_release(
            presence,
            &login,
            ClockReleaseJustificationV1::OperatorVerifiedWallClock,
            UnixMillis::new(fixture::NOW + 1),
        )
        .expect("real durable one-use release");
    let decoded = ea_format::decode_clock_release_audit(release.exact_bytes()).unwrap();
    assert_eq!(decoded.outcome(), LocalAuditOutcomeV1::Accepted);
    assert_eq!(decoded.context().trusted_time_floor().get(), 700);
    assert_eq!(
        decoded.context().observed_os_wall_clock().get(),
        fixture::NOW
    );
    assert_eq!(decoded.context().expires_at().get(), fixture::NOW + 300_000);
    fixture::signing_public()
        .verify_strict(decoded.exact_cose())
        .unwrap();
    let expected = release.exact_bytes().to_vec();
    let id = release.id();
    drop(service);
    drop(harness.database);
    let reopened = Arc::new(
        EncryptedDatabase::open(&harness.path, harness.provider.as_ref(), &harness.key).unwrap(),
    );
    let persisted = SqliteLocalAuditRepository::new(reopened).event(id).unwrap();
    assert_eq!(persisted.exact_bytes(), expected);
    drop(harness.provider);
    std::fs::remove_file(harness.path).unwrap();
}
#[test]
fn wrong_signer_failed_sql_transaction_foreign_presence_and_expiry_never_release_bytes() {
    let f = fixture::fixture();
    let authenticate = || {
        authenticate_clock_repair(
            &f.authority,
            &Account,
            &fixture::signing_public(),
            &profile(f.binding),
            |bytes| {
                Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                    .sign(bytes)
                    .to_bytes())
            },
        )
        .unwrap()
    };
    let presence = authenticate();
    let wrong = Harness::new(true);
    assert!(
        wrong
            .service()
            .record_login(&presence, UnixMillis::new(fixture::NOW))
            .is_err()
    );
    let harness = Harness::new(false);
    harness.database.transaction::<_,StoreError>(|tx|tx.execute(
        "CREATE TRIGGER reject_clock_audit BEFORE INSERT ON local_audit_event BEGIN SELECT RAISE(ABORT, 'fixture flush'); END",&[]).map(|_|())).unwrap();
    assert!(
        harness
            .service()
            .record_login(&presence, UnixMillis::new(fixture::NOW))
            .is_err()
    );
    harness
        .database
        .transaction::<_, StoreError>(|tx| {
            tx.execute("DROP TRIGGER reject_clock_audit", &[])
                .map(|_| ())
        })
        .unwrap();
    let service = harness.service();
    let login = service
        .record_login(&presence, UnixMillis::new(fixture::NOW))
        .unwrap();
    let other = authenticate();
    assert!(
        service
            .record_release(
                other,
                &login,
                ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                UnixMillis::new(fixture::NOW)
            )
            .is_err()
    );
    assert!(
        service
            .record_release(
                presence,
                &login,
                ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                UnixMillis::new(fixture::NOW + 300_000)
            )
            .is_err()
    );
    let mut presence = authenticate();
    let login = service
        .record_login(&presence, UnixMillis::new(fixture::NOW))
        .unwrap();
    presence.invalidate_on_lock();
    assert!(
        service
            .record_release(
                presence,
                &login,
                ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                UnixMillis::new(fixture::NOW + 1)
            )
            .is_err()
    );
}

#[test]
fn a_signature_finishing_after_the_action_deadline_never_commits_a_successful_login() {
    let f = fixture::fixture();
    let presence = authenticate_clock_repair(
        &f.authority,
        &Account,
        &fixture::signing_public(),
        &profile(f.binding),
        |bytes| {
            Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                .sign(bytes)
                .to_bytes())
        },
    )
    .unwrap();
    let harness = Harness::new(false);
    harness
        .provider
        .advance_after_sign
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let result = harness.service().record_login_checked(&presence, || {
        Ok(UnixMillis::new(
            harness
                .provider
                .observed_now
                .load(std::sync::atomic::Ordering::SeqCst),
        ))
    });
    assert!(result.is_err());
    let row = harness
        .database
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        row.integer(0).unwrap(),
        0,
        "late successful signature must not commit Login/Completed"
    );
}

#[test]
fn a_signature_finishing_after_the_action_deadline_never_commits_an_accepted_release() {
    let f = fixture::fixture();
    let presence = authenticate_clock_repair(
        &f.authority,
        &Account,
        &fixture::signing_public(),
        &profile(f.binding),
        |bytes| {
            Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                .sign(bytes)
                .to_bytes())
        },
    )
    .unwrap();
    let harness = Harness::new(false);
    let service = harness.service();
    let login = service
        .record_login(&presence, UnixMillis::new(fixture::NOW))
        .unwrap();
    harness
        .provider
        .advance_after_sign
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let result = service.record_release_checked(
        presence,
        &login,
        ClockReleaseJustificationV1::OperatorVerifiedWallClock,
        || {
            Ok(UnixMillis::new(
                harness
                    .provider
                    .observed_now
                    .load(std::sync::atomic::Ordering::SeqCst),
            ))
        },
    );
    assert!(result.is_err());
    let row = harness
        .database
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        row.integer(0).unwrap(),
        1,
        "only the earlier durable Login may remain"
    );
}
