//! Separate Recovery-KEM, HGA and two-person authorization roles.
use crate::FsArchiveSource;
use ea_audit::LocalAuditService;
use ea_crypto::{
    CoseSigner, CryptoError, HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info,
    hpke_open,
};
use ea_format::{EntryPackageV1, ExactObjectBytes, GrantV1, Parsed};
use ea_operator::{OperatorSessionProof, OsAccountProvider};
use ea_trust::{SelectedRegistryHead, TrustAnchorV1, VerifiedGrantAuthorization};
use ea_types::{CertificateHash, EntryHash, KeyThumbprint, ObjectHash, UnixMillis};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HistoricalGrantError {
    Archive,
    Authorization(ea_trust::GrantAuthorizationError),
    Original,
    Recipient,
    Issuer,
    Key,
    Operator,
    Audit,
    Context,
    Crypto,
    Output,
}
impl HistoricalGrantError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Output => "EA-GRANT-OUTPUT-IO",
            Self::Archive => "EA-GRANT-ARCHIVE-UNVERIFIED",
            Self::Authorization(e) => e.code(),
            Self::Original => "EA-GRANT-RECOVERY-MISMATCH",
            Self::Recipient => "EA-GRANT-RECIPIENT-MISMATCH",
            Self::Issuer => "EA-GRANT-ISSUER-UNAUTHORIZED",
            Self::Key => "EA-GRANT-RECOVERY-KEY",
            Self::Operator => "EA-GRANT-OPERATOR-UNAUTHORIZED",
            Self::Audit => "EA-GRANT-AUDIT-FAILED",
            Self::Context => "EA-GRANT-CONTEXT-UNAVAILABLE",
            Self::Crypto => "EA-GRANT-CRYPTO-FAILED",
        }
    }
}

impl std::fmt::Display for HistoricalGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::fmt::Debug for HistoricalGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for HistoricalGrantError {}
impl From<std::io::Error> for HistoricalGrantError {
    fn from(_: std::io::Error) -> Self {
        Self::Output
    }
}

/// Nonexporting providers implement this narrow original-CEK operation.
pub trait RecoveryKem {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError>;
    fn decapsulate(&self, original: &GrantV1) -> Result<SecretBytes<32>, CryptoError>;
}
impl RecoveryKem for HpkeRecipientPrivateKey {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(ea_crypto::CanonicalPublicCoseKey::x25519(*self.public_key().as_bytes())?.thumbprint())
    }
    fn decapsulate(&self, original: &GrantV1) -> Result<SecretBytes<32>, CryptoError> {
        let body = original.grant_body();
        let fields = body.fields();
        let context = body.exact_grant_context().ok_or(CryptoError::InvalidCose)?;
        hpke_open(
            self,
            &HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)?,
            &hpke_info(context),
            &hpke_aad(context),
        )
    }
}
/// Signs only the typed historical-grant body, not arbitrary digests.
pub trait HistoricalGrantSigner {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError>;
    fn sign_historical_grant(&self, body: &ea_format::GrantBodyV1) -> Result<Vec<u8>, CryptoError>;
}
impl HistoricalGrantSigner for CoseSigner {
    fn key_thumbprint(&self) -> Result<KeyThumbprint, CryptoError> {
        Ok(self.public_key()?.thumbprint())
    }
    fn sign_historical_grant(&self, body: &ea_format::GrantBodyV1) -> Result<Vec<u8>, CryptoError> {
        CoseSigner::sign_historical_grant(self, body.exact_bytes())
    }
}
/// Reselects from the current persistent head/time floor at every call.
pub trait GrantRegistrySource {
    fn current_head(&self) -> Result<SelectedRegistryHead, HistoricalGrantError>;
}
pub struct GrantOperatorContext<'a> {
    pub device_certificate: CertificateHash,
    pub proof: &'a OperatorSessionProof,
    pub account: &'a dyn OsAccountProvider,
}
pub struct VerifiedRecoveryEntry {
    entry: Parsed<EntryPackageV1>,
    original: Parsed<GrantV1>,
}
impl VerifiedRecoveryEntry {
    pub fn verify(
        source: &FsArchiveSource,
        anchor: &TrustAnchorV1,
        entry_hash: EntryHash,
        original_hash: ObjectHash,
        now: UnixMillis,
    ) -> Result<Self, HistoricalGrantError> {
        let report = ea_verify::verify_archive(source, anchor, ea_verify::VerifyOptions::new(now))
            .map_err(|_| HistoricalGrantError::Archive)?;
        if !report.is_fully_verified() {
            return Err(HistoricalGrantError::Archive);
        }
        let inventory = ea_archive::ArchiveInventory::build(source)
            .map_err(|_| HistoricalGrantError::Archive)?;
        let entry = inventory
            .entries()
            .iter()
            .find(|p| p.value().entry_hash() == entry_hash)
            .ok_or(HistoricalGrantError::Archive)?;
        let original = inventory
            .grants()
            .iter()
            .find(|p| p.object_hash() == original_hash)
            .ok_or(HistoricalGrantError::Original)?;
        ea_verify::verify_original_recovery_grant(&inventory, anchor, entry, original, now)
            .map_err(|_| HistoricalGrantError::Original)?;
        let ea_format::ParsedArchiveObject::Entry(entry) =
            ea_format::decode_exact_object(entry.exact_bytes().as_bytes())
                .map_err(|_| HistoricalGrantError::Archive)?
        else {
            return Err(HistoricalGrantError::Archive);
        };
        let ea_format::ParsedArchiveObject::Grant(original) =
            ea_format::decode_exact_object(original.exact_bytes().as_bytes())
                .map_err(|_| HistoricalGrantError::Original)?
        else {
            return Err(HistoricalGrantError::Original);
        };
        Ok(Self { entry, original })
    }
    pub fn entry_hash(&self) -> EntryHash {
        self.entry.value().entry_hash()
    }
}
pub struct HistoricalGrantService;
impl HistoricalGrantService {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        entry: &VerifiedRecoveryEntry,
        authorization: &VerifiedGrantAuthorization,
        recovery: &dyn RecoveryKem,
        authority: &dyn HistoricalGrantSigner,
        issuer_certificate: CertificateHash,
        recipient_certificate: &[u8],
        registry: &dyn GrantRegistrySource,
        operator: GrantOperatorContext<'_>,
        audit: &dyn LocalAuditService,
    ) -> Result<ExactObjectBytes, HistoricalGrantError> {
        use ea_crypto::{
            CanonicalPublicCoseKey, HpkeRecipientPublicKey, VerificationContext, object_hash,
            verify_cose_sign1,
        };
        use ea_format::{
            CertificateKindV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPurposeV1,
        };
        let head = registry.current_head()?;
        validate_context(&head, authorization, &operator)?;
        let auth = authorization.fields();
        let original = entry.original.value();
        let fields = original.grant_body().fields();
        if auth.organization_id != fields.organization_id
            || !auth.entry_hashes.contains(&entry.entry_hash())
            || head.chain_id() != fields.chain_id
        {
            return Err(HistoricalGrantError::Authorization(
                ea_trust::GrantAuthorizationError::Mismatch,
            ));
        }
        if recovery
            .key_thumbprint()
            .map_err(|_| HistoricalGrantError::Key)?
            != fields.recipient_key_thumbprint
        {
            return Err(HistoricalGrantError::Key);
        }
        if object_hash(recipient_certificate).as_bytes()
            != auth.recipient_certificate_hash.as_bytes()
        {
            return Err(HistoricalGrantError::Recipient);
        }
        let recipient = head
            .active_certificate_fields(auth.recipient_certificate_hash)
            .ok_or(HistoricalGrantError::Recipient)?;
        if recipient.certificate_kind != CertificateKindV1::Reader
            || recipient.kem_key_thumbprint != Some(auth.recipient_key_thumbprint)
        {
            return Err(HistoricalGrantError::Recipient);
        }
        let CanonicalPublicCoseKey::X25519(public) =
            CanonicalPublicCoseKey::from_deterministic_cbor(
                recipient
                    .kem_public_cose_key
                    .as_deref()
                    .ok_or(HistoricalGrantError::Recipient)?,
            )
            .map_err(|_| HistoricalGrantError::Recipient)?
        else {
            return Err(HistoricalGrantError::Recipient);
        };
        let recipient_key = HpkeRecipientPublicKey::from_bytes(public)
            .map_err(|_| HistoricalGrantError::Recipient)?;
        let issuer = head
            .active_certificate_fields(issuer_certificate)
            .ok_or(HistoricalGrantError::Issuer)?;
        let issuer_thumb = authority
            .key_thumbprint()
            .map_err(|_| HistoricalGrantError::Issuer)?;
        if issuer.certificate_kind != CertificateKindV1::HistoricalGrantAuthority
            || issuer.signing_key_thumbprint != Some(issuer_thumb)
            || !issuer.capabilities.iter().any(|c| c == "historicalGrant")
        {
            return Err(HistoricalGrantError::Issuer);
        }
        let make_fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
            organization_id: fields.organization_id,
            chain_id: fields.chain_id,
            entry_hash: entry.entry_hash(),
            kind: GrantKindV1::Historical,
            purpose: GrantPurposeV1::Reader,
            recipient_key_thumbprint: auth.recipient_key_thumbprint,
            recipient_certificate_hash: auth.recipient_certificate_hash,
            issuer_key_thumbprint: issuer_thumb,
            issuer_certificate_hash: issuer_certificate,
            registry_version: auth.registry_version,
            registry_head_hash: auth.registry_head_hash,
            created_at_device: head.preexisting_effective_now().value(),
            original_recovery_grant_object_hash: Some(entry.original.object_hash()),
            grant_authorization_object_hash: Some(authorization.object_hash()),
            encapsulated_key,
            wrapped_cek,
        };
        let draft = GrantBodyV1::new(make_fields([0; 32], [0; 48]))
            .map_err(|_| HistoricalGrantError::Crypto)?;
        let context = draft
            .exact_grant_context()
            .ok_or(HistoricalGrantError::Crypto)?;
        let cek = recovery
            .decapsulate(original)
            .map_err(|_| HistoricalGrantError::Key)?;
        let sealed = ea_crypto::hpke_seal(
            &recipient_key,
            &cek,
            &hpke_info(context),
            &hpke_aad(context),
        )
        .map_err(|_| HistoricalGrantError::Crypto)?;
        drop(cek);
        let body = GrantBodyV1::new(make_fields(
            *sealed.encapsulated_key(),
            *sealed.wrapped_cek(),
        ))
        .map_err(|_| HistoricalGrantError::Crypto)?;
        let signature = authority
            .sign_historical_grant(&body)
            .map_err(|_| HistoricalGrantError::Issuer)?;
        let context =
            VerificationContext::historical_grant(body.exact_bytes(), head.proposed_sequence())
                .map_err(|_| HistoricalGrantError::Issuer)?;
        verify_cose_sign1(&signature, &head, &context).map_err(|_| HistoricalGrantError::Issuer)?;
        let grant = ea_format::encode_grant(
            &GrantV1::new(body, signature).map_err(|_| HistoricalGrantError::Crypto)?,
        )
        .map_err(|_| HistoricalGrantError::Crypto)?;
        let fresh = registry.current_head()?;
        if fresh.preexisting_effective_now().value() < head.preexisting_effective_now().value() {
            return Err(HistoricalGrantError::Context);
        }
        validate_context(&fresh, authorization, &operator)?;
        let audit_context = ea_format::HistoricalRegrantContextV1::new(
            authorization.object_hash(),
            entry.entry_hash(),
            entry.original.object_hash(),
            object_hash(recipient_certificate),
            object_hash(grant.as_bytes()),
        );
        let signed = audit
            .record_signed(
                ea_audit::AuditActorProof::OperatorSession(operator.proof),
                ea_audit::TypedLocalAuditEvent {
                    action: ea_format::LocalAuditActionV1::HistoricalRegrant(audit_context),
                    outcome: ea_format::LocalAuditOutcomeV1::Completed,
                },
            )
            .map_err(|_| HistoricalGrantError::Audit)?;
        let event = ea_format::decode_local_audit_event(signed.exact_bytes())
            .map_err(|_| HistoricalGrantError::Audit)?;
        let ea_format::LocalAuditActionV1::HistoricalRegrant(recorded) = event.action() else {
            return Err(HistoricalGrantError::Audit);
        };
        if event.organization_id() != auth.organization_id
            || event.device_id() != operator.proof.device_id()
            || event.operator_binding_object_hash() != Some(operator.proof.binding_object_hash())
            || event.signer_certificate_object_hash().as_bytes()
                != operator.device_certificate.as_bytes()
            || event.outcome() != ea_format::LocalAuditOutcomeV1::Completed
            || recorded.authorization_object_hash() != authorization.object_hash()
            || recorded.entry_hash() != entry.entry_hash()
            || recorded.original_recovery_grant_object_hash() != entry.original.object_hash()
            || recorded.recipient_certificate_object_hash() != object_hash(recipient_certificate)
            || recorded.new_grant_object_hash() != object_hash(grant.as_bytes())
        {
            return Err(HistoricalGrantError::Audit);
        }
        let mut decoder = minicbor::Decoder::new(signed.exact_bytes());
        decoder.array().map_err(|_| HistoricalGrantError::Audit)?;
        decoder.skip().map_err(|_| HistoricalGrantError::Audit)?;
        let signature = &signed.exact_bytes()[decoder.position()..];
        let context = VerificationContext::local_audit(
            event.exact_core(),
            fresh.proposed_sequence(),
            ea_crypto::SignerRole::OrganizationAdmin,
            fresh.registry_version(),
        )
        .map_err(|_| HistoricalGrantError::Audit)?;
        verify_cose_sign1(signature, &fresh, &context).map_err(|_| HistoricalGrantError::Audit)?;
        let release = registry.current_head()?;
        if release.preexisting_effective_now().value() < fresh.preexisting_effective_now().value() {
            return Err(HistoricalGrantError::Context);
        }
        validate_context(&release, authorization, &operator)?;
        Ok(grant)
    }
}

fn validate_context(
    head: &SelectedRegistryHead,
    authorization: &VerifiedGrantAuthorization,
    operator: &GrantOperatorContext<'_>,
) -> Result<(), HistoricalGrantError> {
    ea_trust::verify_grant_authorization(authorization.exact_bytes(), head)
        .map_err(HistoricalGrantError::Authorization)?;
    ea_operator::verify_current_session(
        head,
        operator.device_certificate,
        ea_format::OperatorRoleV1::OrganizationAdmin,
        operator.proof,
        ea_operator::ReauthPurpose::HistoricalRegrant,
        operator.account,
    )
    .map_err(|_| HistoricalGrantError::Operator)
}
