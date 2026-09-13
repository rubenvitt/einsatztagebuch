use super::support;
use ea_audit::{SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec, object_hash,
};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    CoseSign1Bytes, InMemoryKeyProvider, KeyError, KeyHandle, KeyProvider, SecretPurpose,
};
use ea_local_store::EncryptedDatabase;
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OsAccountProvider, ReauthPurpose,
};
use ea_recovery::*;
use ea_types::{CertificateHash, DeviceId, Hash32, OrganizationId};
use ed25519_dalek::{Signer, SigningKey};
use std::{cell::Cell, sync::Arc};
use support::verify_support::{
    self as fixture, archive_support::trust_support, historical::HistoricalFixture,
};

pub struct Account;
impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _: OrganizationId,
        _: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(trust_support::hash32(0x44))
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(
            CanonicalPublicCoseKey::ed25519(
                SigningKey::from_bytes(&[0x61; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
        ))
    }
}
pub struct Authenticator(pub BoundOperator);
impl OperatorAuthenticator for Authenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.0
    }
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        Ok(SigningKey::from_bytes(&[0x61; 32])
            .sign(challenge)
            .to_bytes())
    }
}
pub struct Registry<'a> {
    pub fixture: &'a HistoricalFixture,
    pub now: Cell<i64>,
}
impl GrantRegistrySource for Registry<'_> {
    fn current_head(&self) -> Result<ea_trust::SelectedRegistryHead, HistoricalGrantError> {
        Ok(self.fixture.selected(1, self.now.get(), self.now.get()))
    }
}
struct Provider(InMemoryKeyProvider);
impl KeyProvider for Provider {
    fn generate(&self, p: SecretPurpose, k: KeyProtectionProfileV1) -> Result<KeyHandle, KeyError> {
        self.0.generate(p, k)
    }
    fn sign(
        &self,
        _: &KeyHandle,
        t: ContentType,
        c: CertificateHash,
        p: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        let secret = SigningKey::from_bytes(&trust_support::second_admin_signing_secret());
        let key = CanonicalPublicCoseKey::ed25519(secret.verifying_key().to_bytes()).unwrap();
        let header = ProtectedHeader::normal(t, key.thumbprint(), c);
        CoseSign1Bytes::compose(
            &header,
            p,
            &secret.sign(&header.sig_structure_bytes(p)).to_bytes(),
        )
    }
    fn wrap_secret(&self, p: SecretPurpose, s: SecretBytes<32>) -> Result<KeyHandle, KeyError> {
        self.0.wrap_secret(p, s)
    }
    fn unwrap_secret(&self, h: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        self.0.unwrap_secret(h)
    }
    fn unwrap_database_key(&self, h: &KeyHandle) -> Result<SecretVec, KeyError> {
        self.0.unwrap_database_key(h)
    }
    fn delete(&self, h: &KeyHandle) -> Result<(), KeyError> {
        self.0.delete(h)
    }
    fn contains(&self, h: &KeyHandle) -> Result<bool, KeyError> {
        self.0.contains(h)
    }
    fn reached_protection_profile(
        &self,
        h: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.0.reached_protection_profile(h)
    }
}

pub struct Harness {
    pub fixture: HistoricalFixture,
    pub root: support::TempDir,
    pub source: FsArchiveSource,
    pub entry: VerifiedRecoveryEntry,
    pub proof: ea_operator::OperatorSessionProof,
    pub db: Arc<EncryptedDatabase>,
    pub audit: SignedLocalAuditService,
}
impl Harness {
    pub fn new(f: HistoricalFixture) -> Self {
        let root = support::temp_dir("historical-grant");
        let archive = root.path().join("archive");
        std::fs::create_dir(&archive).unwrap();
        support::materialize(&f.fixture, &archive);
        let source = FsArchiveSource::open(&archive).unwrap();
        let entry = VerifiedRecoveryEntry::verify(
            &source,
            &f.anchor,
            f.entry_hash,
            object_hash(&f.original_bytes),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        let head = f.selected(1, 800, 800);
        let proof = Authenticator(BoundOperator::resolve(&head, f.operator_binding).unwrap())
            .reauthenticate(Box::new(Account), ReauthPurpose::HistoricalRegrant)
            .unwrap();
        let provider = Arc::new(Provider(InMemoryKeyProvider::new_for_test([0x63; 32])));
        let dbkey = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let db = Arc::new(
            EncryptedDatabase::open(&root.path().join("audit.sqlite"), provider.as_ref(), &dbkey)
                .unwrap(),
        );
        let signing = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(db.clone())),
            provider,
            signing,
            f.line.second_bootstrap_admin_hash(),
            ea_types::UnixMillis::new(800),
        );
        Self {
            fixture: f,
            root,
            source,
            entry,
            proof,
            db,
            audit,
        }
    }
    pub fn create(
        &self,
        auth: &ea_trust::VerifiedGrantAuthorization,
    ) -> Result<ea_format::ExactObjectBytes, HistoricalGrantError> {
        self.create_using(
            auth,
            &fixture::complete_recipient_private_key(),
            &trust_support::authorized_device_signer(),
            &self.proof,
            &Account,
            &self.audit,
            &Registry {
                fixture: &self.fixture,
                now: Cell::new(800),
            },
            &self.fixture.recipient_certificate,
        )
    }
    pub fn create_using(
        &self,
        auth: &ea_trust::VerifiedGrantAuthorization,
        recovery: &dyn RecoveryKem,
        authority: &dyn HistoricalGrantSigner,
        proof: &ea_operator::OperatorSessionProof,
        account: &dyn OsAccountProvider,
        audit: &dyn ea_audit::LocalAuditService,
        registry: &dyn GrantRegistrySource,
        recipient: &[u8],
    ) -> Result<ea_format::ExactObjectBytes, HistoricalGrantError> {
        HistoricalGrantService::create(
            &self.entry,
            auth,
            recovery,
            authority,
            self.fixture.hga_certificate,
            recipient,
            registry,
            GrantOperatorContext {
                device_certificate: self.fixture.line.second_bootstrap_admin_hash().into(),
                proof,
                account,
            },
            audit,
        )
    }
}
