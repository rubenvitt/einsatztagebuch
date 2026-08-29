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
