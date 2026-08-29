//! Echte `.eip`- und `.eag`-Objekte fuer den Commit-Pfad.
//!
//! Jedes Objekt hier ist ECHT: das Manifest laeuft durch
//! [`ea_format::ManifestCoreV1`], die Schreibersignatur durch
//! `CoseSigner::sign_record`, jeder Grant durch [`ea_format::GrantBodyV1`] und
//! `sign_initial_grant`, und der Plan entsteht ausschliesslich ueber den
//! eingefrorenen Konstruktor [`ea_format::GrantPlanV1::new`]. Der Server
//! prueft sie danach mit demselben `ea_crypto::verify_cose_sign1`, mit dem ein
//! Reader sie prueft — eine Attrappe gaebe es hier nicht zu bauen.
//!
//! # Was NICHT echt ist, und warum das keine Luecke ist
//!
//! Die HPKE-Kapselung und der umschlossene CEK eines Grants sind Fuellbytes
//! fester Groesse. Der Server ist BLIND: er oeffnet weder Eintrag noch Grant,
//! und `grant-context-v1` bindet die Kapselung nicht an die
//! Ausstellersignatur. Eine echte Versiegelung waere hier Aufwand, den keine
//! Zusicherung dieses Pfades misst — sie gehoert zu `ea-writer` und
//! `ea-verify` und wird dort gefuehrt. Der CIPHERTEXT des Eintrags ist aus
//! demselben Grund ein Fuellmuster: er ist ueber `ciphertext_hash` an das
//! Manifest gebunden, und genau diese Bindung prueft `ea-format` beim Parsen.

#![allow(dead_code)]

use ea_crypto::{CoseSigner, SecretBytes};
use ea_format::{
    EntryPackageV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1,
    GrantPurposeV1, GrantV1, ManifestCoreFieldsV1, ManifestCoreV1, ParsedArchiveObject,
    SignedManifestV1, encode_entry_package, encode_grant,
};
use ea_sync_protocol::EntryCommitRequestV1;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, OrganizationId, RegistryVersion,
    UnixMillis,
};

use super::trust_closure::{self, ExtendedClosure};

/// Ein Empfaenger des initialen Grant-Plans.
#[derive(Clone, Copy)]
pub struct Recipient {
    pub kem_seed: [u8; 32],
    pub certificate_hash: CertificateHash,
    pub purpose: GrantPurposeV1,
}

impl Recipient {
    #[must_use]
    pub fn reader(closure: &ExtendedClosure) -> Self {
        Self {
            kem_seed: trust_closure::READER_KEM_SEED,
            certificate_hash: closure.reader_certificate_hash,
            purpose: GrantPurposeV1::Reader,
        }
    }

    /// Der ZWEITE Reader — nur in einem Abschluss vorhanden, der ihn traegt.
    ///
    /// # Panics
    ///
    /// Wenn der Abschluss ohne zweiten Reader gebaut wurde.
    #[must_use]
    pub fn second_reader(closure: &ExtendedClosure) -> Self {
        Self {
            kem_seed: trust_closure::SECOND_READER_KEM_SEED,
            certificate_hash: closure
                .second_reader_certificate_hash
                .expect("this closure carries a second reader"),
            purpose: GrantPurposeV1::Reader,
        }
    }

    #[must_use]
    pub fn recovery(closure: &ExtendedClosure) -> Self {
        Self {
            kem_seed: trust_closure::RECOVERY_KEM_SEED,
            certificate_hash: closure.recovery_certificate_hash,
            purpose: GrantPurposeV1::Recovery,
        }
    }

    fn plan_item(self) -> GrantPlanItemV1 {
        GrantPlanItemV1::new(
            trust_closure::kem_key(self.kem_seed).thumbprint(),
            self.certificate_hash,
            self.purpose,
        )
    }
}

/// Alles, was ein Commit-Koerper braucht, an einer Stelle.
pub struct CommitSpec<'a> {
    pub closure: &'a ExtendedClosure,
    pub sequence: u64,
    pub previous_entry_hash: Option<EntryHash>,
    pub recipients: &'a [Recipient],
    /// Unterscheidet zwei sonst gleiche Eintraege — er geht in den Ciphertext
    /// und damit in `entryHash` und `objectHash`.
    pub marker: u8,
    /// Ein ANDERER Schreiber als der des Abschlusses: Zertifikat und
    /// Signaturschluessel. Fuer den Fall „unzulaessiger Writer" — das Manifest
    /// muss dann von genau diesem Schluessel signiert sein, sonst faellt es
    /// schon in `ea-format`.
    pub writer_override: Option<(CertificateHash, [u8; 32])>,
    /// Ein ANDERER Registry-Head, als der Server ihn waehlen wird. Fuer den
    /// Fall „das Paket bindet einen aelteren Kopf".
    pub registry_override: Option<(RegistryVersion, [u8; 32])>,
}

impl CommitSpec<'_> {
    fn writer_certificate_hash(&self) -> CertificateHash {
        self.writer_override
            .map_or(self.closure.writer_certificate_hash, |(hash, _)| hash)
    }

    fn writer_seed(&self) -> [u8; 32] {
        self.writer_override
            .map_or(trust_closure::WRITER_SEED, |(_, seed)| seed)
    }

    fn registry(&self) -> (RegistryVersion, [u8; 32]) {
        self.registry_override.unwrap_or((
            self.closure.registry_version,
            *self.closure.registry_head_hash.as_bytes(),
        ))
    }
}

fn writer_signer() -> CoseSigner {
    signer_for(trust_closure::WRITER_SEED)
}

fn signer_for(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

/// Der initiale Grant-Plan ueber genau diese Empfaenger.
///
/// # Panics
///
/// Wenn der eingefrorene Konstruktor den Plan abweist — kein
/// Recovery-Empfaenger, ein zweiter, oder ein doppelter Empfaenger.
#[must_use]
pub fn plan(recipients: &[Recipient]) -> GrantPlanV1 {
    GrantPlanV1::new(recipients.iter().map(|r| r.plan_item()).collect())
        .expect("the fixture plan is well formed")
}

/// Die exakten `.eip`-Bytes eines echten Eintragspakets.
///
/// # Panics
///
/// Wenn Manifest, Signatur oder Kodierung fehlschlagen.
#[must_use]
pub fn entry_bytes(spec: &CommitSpec<'_>, plan: &GrantPlanV1) -> Vec<u8> {
    let ciphertext = vec![spec.marker; 48];
    let manifest = ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: spec.closure.organization_id,
            chain_id: spec.closure.chain_id,
            chain_sequence: ChainSequence::new(spec.sequence),
            previous_entry_hash: spec.previous_entry_hash,
            writer_certificate_hash: spec.writer_certificate_hash(),
            // Ein behaupteter Schreiberwechsel ist auf diesem Stand
            // fail-closed unzulaessig; die Kulisse behauptet keinen.
            writer_transition_event_hash: None,
            registry_version: spec.registry().0,
            registry_head_hash: spec.registry().1,
            initial_grant_plan_hash: *plan.hash().as_bytes(),
            nonce: [spec.marker; 12],
        },
        &ciphertext,
    )
    .expect("the fixture manifest is well formed");
    let signed = SignedManifestV1::new(manifest, &ciphertext)
        .expect("the fixture signed manifest is well formed");
    let signature = signer_for(spec.writer_seed())
        .sign_record(signed.exact_bytes())
        .expect("signing the fixture manifest must succeed");
    let package = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("the fixture entry package is well formed");
    encode_entry_package(&package)
        .expect("encoding the fixture entry cannot fail")
        .into_vec()
}

/// Der `entryHash` exakter `.eip`-Bytes.
///
/// # Panics
///
/// Wenn die Bytes kein Eintragspaket sind.
#[must_use]
pub fn entry_hash_of(entry_bytes: &[u8]) -> EntryHash {
    let ParsedArchiveObject::Entry(parsed) =
        ea_format::decode_exact_object(entry_bytes).expect("the fixture entry parses")
    else {
        panic!("the fixture entry is an entry package");
    };
    parsed.value().entry_hash()
}

/// Die exakten `.eag`-Bytes eines echten initialen Grants.
///
/// # Panics
///
/// Wenn Rumpf, Signatur oder Kodierung fehlschlagen.
#[must_use]
pub fn grant_bytes(
    closure: &ExtendedClosure,
    entry_hash: EntryHash,
    recipient: Recipient,
) -> Vec<u8> {
    grant_bytes_with(
        closure,
        entry_hash,
        recipient,
        closure.writer_certificate_hash,
        trust_closure::WRITER_SEED,
        (
            closure.registry_version,
            *closure.registry_head_hash.as_bytes(),
        ),
    )
}

/// Derselbe Grant, aber mit ausdruecklich gesetztem Aussteller und Kopf.
///
/// # Panics
///
/// Wenn Rumpf, Signatur oder Kodierung fehlschlagen.
#[must_use]
pub fn grant_bytes_with(
    closure: &ExtendedClosure,
    entry_hash: EntryHash,
    recipient: Recipient,
    issuer_certificate_hash: CertificateHash,
    issuer_seed: [u8; 32],
    registry: (RegistryVersion, [u8; 32]),
) -> Vec<u8> {
    let body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: closure.organization_id,
        chain_id: closure.chain_id,
        entry_hash,
        kind: GrantKindV1::Initial,
        purpose: recipient.purpose,
        recipient_key_thumbprint: trust_closure::kem_key(recipient.kem_seed).thumbprint(),
        recipient_certificate_hash: recipient.certificate_hash,
        issuer_key_thumbprint: signer_for(issuer_seed)
            .public_key()
            .expect("the declared issuer seed loads")
            .thumbprint(),
        issuer_certificate_hash,
        registry_version: registry.0,
        registry_head_hash: Hash32::try_from(registry.1.as_slice())
            .expect("a registry head hash is 32 bytes"),
        created_at_device: UnixMillis::new(100),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: [recipient.kem_seed[0]; ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE],
        wrapped_cek: [recipient.kem_seed[0]; ea_crypto::HPKE_WRAPPED_CEK_SIZE],
    })
    .expect("the fixture grant body is well formed");
    let signature = signer_for(issuer_seed)
        .sign_initial_grant(body.exact_bytes())
        .expect("signing the fixture grant must succeed");
    let grant = GrantV1::new(body, signature).expect("the fixture grant is well formed");
    encode_grant(&grant)
        .expect("encoding the fixture grant cannot fail")
        .into_vec()
}

/// Ein vollstaendiger `entry-commit-request-v1`.
///
/// # Panics
///
/// Wenn der Rahmen eine seiner Grenzen reisst.
#[must_use]
pub fn commit_request(spec: &CommitSpec<'_>) -> EntryCommitRequestV1 {
    let plan = plan(spec.recipients);
    let entry = entry_bytes(spec, &plan);
    let entry_hash = entry_hash_of(&entry);
    let grants = spec
        .recipients
        .iter()
        .map(|recipient| {
            grant_bytes_with(
                spec.closure,
                entry_hash,
                *recipient,
                spec.writer_certificate_hash(),
                spec.writer_seed(),
                spec.registry(),
            )
        })
        .collect();
    EntryCommitRequestV1::new(entry, plan, grants).expect("the fixture commit request is valid")
}

/// Der Standardfall: ein Reader und der verpflichtende Recovery-Empfaenger.
#[must_use]
pub fn valid_commit(
    closure: &ExtendedClosure,
    sequence: u64,
    previous_entry_hash: Option<EntryHash>,
    marker: u8,
) -> EntryCommitRequestV1 {
    commit_request(&CommitSpec {
        closure,
        sequence,
        previous_entry_hash,
        recipients: &[Recipient::reader(closure), Recipient::recovery(closure)],
        marker,
        writer_override: None,
        registry_override: None,
    })
}

/// Die Kennung, unter der der Commit-Endpunkt seine Kette anspricht.
#[must_use]
pub fn entry_commit_path(chain_id: ChainId) -> String {
    format!(
        "/v1/chains/{}/entry-commits",
        hex::encode(chain_id.as_bytes())
    )
}

/// Die Organisation eines Abschlusses als getypter Wert — Bequemlichkeit fuer
/// die Aufrufer.
#[must_use]
pub const fn organization_of(closure: &ExtendedClosure) -> OrganizationId {
    closure.organization_id
}

/// Die Registry-Version eines Abschlusses.
#[must_use]
pub const fn registry_version_of(closure: &ExtendedClosure) -> RegistryVersion {
    closure.registry_version
}

// ---------------------------------------------------------------------------
// Historischer Re-Grant und kontrollierte Vernichtung
// ---------------------------------------------------------------------------
//
// Die drei Bauer unten sind so echt wie alles darueber: `grantAuthorization`
// und `destructionAuthorization` entstehen ueber die eingefrorenen
// `TrustPayloadV1`-Konstruktoren und werden von ZWEI verschiedenen
// Approver-Schluesseln ueber `sign_historical_grant_approval_digest`
// beziehungsweise `sign_destruction_approval_digest` unterschrieben — also
// ueber genau die Kante, die der Server anschliessend prueft. Eine Attrappe
// gaebe es hier nicht zu bauen: `ea-crypto` leitet den Digest selbst aus dem
// Nutzinhalt ab und weist eine Abweichung ab.

use ea_format::{
    DestructionAuthorizationFieldsV1, DestructionTargetV1, GrantAuthorizationFieldsV1,
    TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_types::{AuthorizationId, DestructionId, KeyThumbprint, ObjectHash};

/// Die Sequenz, unter der eine Mehr-Augen-Autorisierung ihre Approver
/// aufloest.
///
/// Dieselbe wie die des committeten Eintrags: die Approver-Zertifikate sind
/// genau dort aktiv, und eine andere Sequenz waehlte einen Kopf, der sie noch
/// nicht kennt.
#[must_use]
pub const fn authorization_sequence() -> u64 {
    ExtendedClosure::commit_sequence()
}

fn signer_of(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

/// Der Abdruck eines deklarierten Signaturschluessels.
#[must_use]
pub fn signing_thumbprint(seed: [u8; 32]) -> KeyThumbprint {
    signer_of(seed)
        .public_key()
        .expect("a declared Ed25519 seed loads")
        .thumbprint()
}

/// Die beiden Approver eines Abschlusses — Zertifikat und Schluessel.
///
/// # Panics
///
/// Wenn der Abschluss ohne die Grant- und Vernichtungsrollen gebaut wurde.
#[must_use]
pub fn approvers(closure: &ExtendedClosure) -> [(CertificateHash, [u8; 32]); 2] {
    let hashes = closure
        .approver_certificate_hashes
        .expect("this closure carries two key approvers");
    [
        (hashes[0], trust_closure::APPROVER_A_SEED),
        (hashes[1], trust_closure::APPROVER_B_SEED),
    ]
}

/// Eine `grantAuthorization` ueber genau diesen Eintrag und diesen Empfaenger.
///
/// `signers` sind die Approver, die unterschreiben. ZWEI verschiedene sind der
/// Normalfall; derselbe zweimal ist der Fall, den der Server abweisen MUSS.
///
/// # Panics
///
/// Wenn ein Konstruktor oder eine Signatur fehlschlaegt — beides waere ein
/// Fehler dieser Kulisse.
#[must_use]
pub fn grant_authorization(
    closure: &ExtendedClosure,
    entry_hashes: Vec<EntryHash>,
    recipient: Recipient,
    expires_at: i64,
    marker: u8,
    signers: &[(CertificateHash, [u8; 32])],
) -> Vec<u8> {
    let payload = TrustPayloadV1::grant_authorization(GrantAuthorizationFieldsV1 {
        authorization_id: AuthorizationId::try_from([marker; 16].as_slice()).expect("16 bytes"),
        organization_id: closure.organization_id,
        registry_version: closure.registry_version,
        registry_head_hash: Hash32::try_from(closure.registry_head_hash.as_bytes().as_slice())
            .expect("a registry head hash is 32 bytes"),
        authorization_sequence: authorization_sequence(),
        entry_hashes,
        recipient_key_thumbprint: trust_closure::kem_key(recipient.kem_seed).thumbprint(),
        recipient_certificate_hash: recipient.certificate_hash,
        expires_at: UnixMillis::new(expires_at),
    })
    .expect("the grant authorization payload is well formed");
    let signatures = signers
        .iter()
        .map(|(certificate_hash, seed)| {
            signer_of(*seed)
                .sign_historical_grant_approval_digest(
                    *certificate_hash,
                    payload.exact_digest_input(),
                )
                .expect("signing the grant approval must succeed")
        })
        .collect();
    encode_trust(&TrustObjectV1::new(payload, signatures).expect("the trust object is well formed"))
        .expect("encoding a well formed trust object cannot fail")
        .into_vec()
}

/// Eine `destructionAuthorization` ueber genau diese Ziele.
///
/// # Panics
///
/// Wie [`grant_authorization`].
#[must_use]
pub fn destruction_authorization(
    closure: &ExtendedClosure,
    targets: Vec<(EntryHash, u64)>,
    marker: u8,
    signers: &[(CertificateHash, [u8; 32])],
) -> Vec<u8> {
    let payload = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
        destruction_id: DestructionId::try_from([marker; 16].as_slice()).expect("16 bytes"),
        organization_id: closure.organization_id,
        registry_version: closure.registry_version,
        registry_head_hash: Hash32::try_from(closure.registry_head_hash.as_bytes().as_slice())
            .expect("a registry head hash is 32 bytes"),
        authorization_sequence: authorization_sequence(),
        targets: targets
            .into_iter()
            .map(|(entry_hash, sequence)| {
                DestructionTargetV1::new(*entry_hash.as_bytes(), sequence)
            })
            .collect(),
        scope_code: 0,
        legal_reason_code: 0,
    })
    .expect("the destruction authorization payload is well formed");
    let signatures = signers
        .iter()
        .map(|(certificate_hash, seed)| {
            signer_of(*seed)
                .sign_destruction_approval_digest(*certificate_hash, payload.exact_digest_input())
                .expect("signing the destruction approval must succeed")
        })
        .collect();
    encode_trust(&TrustObjectV1::new(payload, signatures).expect("the trust object is well formed"))
        .expect("encoding a well formed trust object cannot fail")
        .into_vec()
}

/// Die Kennung, die eine `destructionAuthorization` dieses Markers traegt.
#[must_use]
pub fn destruction_id_of(marker: u8) -> DestructionId {
    DestructionId::try_from([marker; 16].as_slice()).expect("16 bytes")
}

/// Die exakten `.eag`-Bytes eines echten HISTORISCHEN Grants.
///
/// Er bindet Eintrag, Empfaengerzertifikat, den urspruenglichen
/// Recovery-Grant, die Authorization und die aktuelle Registrierung —
/// `design.md` §16.2 zaehlt genau diese fuenf auf.
///
/// # Panics
///
/// Wenn Rumpf, Signatur oder Kodierung fehlschlagen.
#[must_use]
pub fn historical_grant_bytes(
    closure: &ExtendedClosure,
    entry_hash: EntryHash,
    recipient: Recipient,
    original_recovery_grant_object_hash: ObjectHash,
    grant_authorization_object_hash: ObjectHash,
) -> Vec<u8> {
    let authority = closure
        .historical_grant_authority_certificate_hash
        .expect("this closure carries a historical grant authority");
    let body = GrantBodyV1::new(GrantBodyFieldsV1 {
        organization_id: closure.organization_id,
        chain_id: closure.chain_id,
        entry_hash,
        kind: GrantKindV1::Historical,
        purpose: recipient.purpose,
        recipient_key_thumbprint: trust_closure::kem_key(recipient.kem_seed).thumbprint(),
        recipient_certificate_hash: recipient.certificate_hash,
        issuer_key_thumbprint: signing_thumbprint(trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED),
        issuer_certificate_hash: authority,
        registry_version: closure.registry_version,
        registry_head_hash: Hash32::try_from(closure.registry_head_hash.as_bytes().as_slice())
            .expect("a registry head hash is 32 bytes"),
        created_at_device: UnixMillis::new(100),
        original_recovery_grant_object_hash: Some(original_recovery_grant_object_hash),
        grant_authorization_object_hash: Some(grant_authorization_object_hash),
        encapsulated_key: [0xa7; ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE],
        wrapped_cek: [0xa8; ea_crypto::HPKE_WRAPPED_CEK_SIZE],
    })
    .expect("the fixture historical grant body is well formed");
    let signature = signer_of(trust_closure::HISTORICAL_GRANT_AUTHORITY_SEED)
        .sign_historical_grant(body.exact_bytes())
        .expect("signing the fixture historical grant must succeed");
    let grant = GrantV1::new(body, signature).expect("the fixture historical grant is well formed");
    encode_grant(&grant)
        .expect("encoding the fixture grant cannot fail")
        .into_vec()
}

/// Der Pfad des historischen Re-Grants.
#[must_use]
pub fn historical_grant_path(entry_hash: EntryHash) -> String {
    format!(
        "/v1/entries/{}/historical-grants",
        hex::encode(entry_hash.as_bytes())
    )
}

/// Der Pfad der Grantliste.
#[must_use]
pub fn entry_grants_path(entry_hash: EntryHash) -> String {
    format!("/v1/entries/{}/grants", hex::encode(entry_hash.as_bytes()))
}
