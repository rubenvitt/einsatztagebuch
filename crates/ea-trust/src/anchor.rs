use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use ea_cbor::ParserLimits;
use ea_crypto::{
    CanonicalPublicCoseKey, CoseVerifier, VerificationContext, bootstrap_anchor_hash,
    trust_anchor_hash, trust_digest,
};
use ea_format::{
    DecodedTrustPayloadV1, DeviceCertificateFieldsV1, OperatorBindingFieldsV1,
    RootCertificateFieldsV1, TrustObjectV1, TrustSubtypeV1,
};
use ea_time::TrustedTimeState;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId,
};
use minicbor::{Decoder, Encoder};

use crate::{
    RegistryHeadPin, TrustError, TrustObjectSource, TrustStateKey, TrustStateSnapshot,
    catalog::TrustCatalog,
    resolver::{BootstrapRootResolver, PreviousHeadState},
};

const PRE_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1";
const FINAL_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-v1";

pub struct TrustAnchorV1 {
    bootstrap_anchor_hash: Hash32,
    organization_id: OrganizationId,
    chain_id: ChainId,
    root_public_cose_key: CanonicalPublicCoseKey,
    exact_root_public_cose_key: Vec<u8>,
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    initial_admin_certificate_object_hashes: Vec<ObjectHash>,
    initial_admin_operator_binding_object_hashes: Vec<ObjectHash>,
    genesis_entry_hash: EntryHash,
    exact_pre_anchor_bytes: Vec<u8>,
    exact_bytes: Vec<u8>,
    trust_anchor_hash: Hash32,
}

impl TrustAnchorV1 {
    #[must_use]
    pub const fn bootstrap_anchor_hash(&self) -> Hash32 {
        self.bootstrap_anchor_hash
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn root_public_cose_key(&self) -> &CanonicalPublicCoseKey {
        &self.root_public_cose_key
    }

    #[must_use]
    pub fn root_public_cose_key_bytes(&self) -> &[u8] {
        &self.exact_root_public_cose_key
    }

    #[must_use]
    pub const fn root_key_thumbprint(&self) -> KeyThumbprint {
        self.root_key_thumbprint
    }

    #[must_use]
    pub const fn root_certificate_object_hash(&self) -> ObjectHash {
        self.root_certificate_object_hash
    }

    #[must_use]
    pub fn initial_admin_certificate_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_certificate_object_hashes
    }

    #[must_use]
    pub fn initial_admin_operator_binding_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_operator_binding_object_hashes
    }

    #[must_use]
    pub const fn genesis_entry_hash(&self) -> EntryHash {
        self.genesis_entry_hash
    }

    #[must_use]
    pub fn exact_pre_anchor_bytes(&self) -> &[u8] {
        &self.exact_pre_anchor_bytes
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn trust_anchor_hash(&self) -> Hash32 {
        self.trust_anchor_hash
    }
}

/// Die VORSTUFE des Trust Anchors — der Gegenstand des vierten
/// Einrichtungsschrittes.
///
/// Sie traegt genau die acht Felder, die die Spezifikation in
/// `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1737-1748`
/// als `organization-trust-anchor-pre-v1` festlegt, und wird VOR der ersten
/// Administrationsautorisierung auf mindestens zwei schreibgeschuetzte
/// Recovery-Medien geschrieben (`:1339`, `:1780`). Der finale Anker uebernimmt
/// diese Felder spaeter BYTEGLEICH; hinzu kommen nur die finale Domain,
/// `bootstrap-anchor-hash` und `genesis-entry-hash` (`:1346`).
///
/// `exact_bytes` sind die Bytes, die auf dem Medium stehen — nicht eine
/// Neukodierung derselben Felder. Der Unterschied ist der ganze Zweck: nur die
/// festgeschriebenen Bytes belegen, worauf sich die Zeremonie WIRKLICH
/// festgelegt hat.
pub struct PreAnchorV1 {
    organization_id: OrganizationId,
    chain_id: ChainId,
    root_public_cose_key: CanonicalPublicCoseKey,
    exact_root_public_cose_key: Vec<u8>,
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    initial_admin_certificate_object_hashes: Vec<ObjectHash>,
    initial_admin_operator_binding_object_hashes: Vec<ObjectHash>,
    exact_bytes: Vec<u8>,
    bootstrap_anchor_hash: Hash32,
}

impl PreAnchorV1 {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn root_public_cose_key(&self) -> &CanonicalPublicCoseKey {
        &self.root_public_cose_key
    }

    #[must_use]
    pub fn root_public_cose_key_bytes(&self) -> &[u8] {
        &self.exact_root_public_cose_key
    }

    #[must_use]
    pub const fn root_key_thumbprint(&self) -> KeyThumbprint {
        self.root_key_thumbprint
    }

    #[must_use]
    pub const fn root_certificate_object_hash(&self) -> ObjectHash {
        self.root_certificate_object_hash
    }

    #[must_use]
    pub fn initial_admin_certificate_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_certificate_object_hashes
    }

    #[must_use]
    pub fn initial_admin_operator_binding_object_hashes(&self) -> &[ObjectHash] {
        &self.initial_admin_operator_binding_object_hashes
    }

    /// Die exakten Bytes, wie sie auf den Recovery-Medien stehen.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// `bootstrapAnchorHash` ueber genau diese Bytes — der volle Fingerprint,
    /// der ueber den zweiten Kanal bestaetigt wird (`:1780`).
    #[must_use]
    pub const fn bootstrap_anchor_hash(&self) -> Hash32 {
        self.bootstrap_anchor_hash
    }
}

pub struct VerifiedTrust {
    pub(crate) inner: Arc<VerifiedTrustInner>,
}

pub(crate) struct VerifiedTrustInner {
    organization_id: OrganizationId,
    chain_id: ChainId,
    trust_anchor_hash: Hash32,
    state_key: TrustStateKey,
    state_revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) catalog: Arc<TrustCatalog>,
    pub(crate) previous_head: PreviousHeadState,
}

impl VerifiedTrust {
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.inner.organization_id
    }

    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        self.inner.chain_id
    }

    #[must_use]
    pub fn trust_anchor_hash(&self) -> Hash32 {
        self.inner.trust_anchor_hash
    }

    #[must_use]
    pub fn state_key(&self) -> TrustStateKey {
        self.inner.state_key
    }

    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.inner.state_revision
    }

    #[must_use]
    pub fn trusted_time(&self) -> &TrustedTimeState {
        &self.inner.trusted_time
    }

    #[must_use]
    pub fn pinned_head(&self) -> Option<&RegistryHeadPin> {
        self.inner.pinned_head.as_ref()
    }

    #[must_use]
    pub(crate) fn previous_head(&self) -> &PreviousHeadState {
        &self.inner.previous_head
    }

    #[must_use]
    pub fn initial_admin_pair_count(&self) -> usize {
        self.previous_head().initial_admin_pair_count()
    }
}

pub fn verify_trust(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    snapshot: TrustStateSnapshot,
) -> Result<VerifiedTrust, TrustError> {
    if snapshot.key().organization_id != anchor.organization_id() {
        return Err(TrustError::BootstrapPair);
    }

    let catalog = Arc::new(TrustCatalog::load(source)?);
    let mut direct = DirectBootstrapObjects::from_catalog(&catalog)?;
    direct.require_exact_anchor_sets(anchor)?;

    let root_hash = anchor.root_certificate_object_hash();
    let root_fields = direct
        .roots
        .remove(&root_hash)
        .ok_or(TrustError::AnchorPin)?;
    verify_root_anchor_fields(anchor, &root_fields)?;
    let root_object = catalog_object(&catalog, root_hash)?;
    let root_signature = only_signature(root_object)?;
    CoseVerifier::verify_initial_root_pop(
        root_signature,
        anchor.root_public_cose_key(),
        trust_digest(root_object.exact_digest_input()).as_bytes(),
    )
    .map_err(|_| TrustError::Signature)?;

    let root_certificate_hash = CertificateHash::from(root_hash);
    let root_resolver = BootstrapRootResolver::new(
        root_certificate_hash,
        catalog
            .get(&root_hash)
            .ok_or(TrustError::AnchorPin)?
            .exact_bytes()
            .as_bytes(),
    );

    let mut certificates = BTreeMap::new();
    for object_hash in anchor.initial_admin_certificate_object_hashes() {
        let fields = direct
            .admin_certificates
            .remove(object_hash)
            .ok_or(TrustError::AnchorPin)?;
        let certificate = verify_admin_certificate(
            &catalog,
            *object_hash,
            fields,
            &root_resolver,
            root_certificate_hash,
            anchor.organization_id(),
        )?;
        if certificates
            .insert(CertificateHash::from(*object_hash), certificate)
            .is_some()
        {
            return Err(TrustError::BootstrapPair);
        }
    }

    let mut bindings =
        Vec::with_capacity(anchor.initial_admin_operator_binding_object_hashes().len());
    for object_hash in anchor.initial_admin_operator_binding_object_hashes() {
        let fields = direct
            .admin_bindings
            .remove(object_hash)
            .ok_or(TrustError::AnchorPin)?;
        bindings.push(verify_admin_binding(
            &catalog,
            *object_hash,
            fields,
            &root_resolver,
            root_certificate_hash,
            anchor.organization_id(),
        )?);
    }
    validate_admin_pairs(&certificates, &bindings)?;

    let active_certificates = certificates
        .into_values()
        .map(|certificate| (certificate.object_hash, certificate.fields))
        .collect();
    let active_bindings = bindings
        .into_iter()
        .map(|binding| (binding.object_hash, binding.fields))
        .collect();
    let previous_head = PreviousHeadState::from_verified_bootstrap(
        Arc::clone(&catalog),
        &snapshot,
        (root_hash, root_fields),
        active_certificates,
        active_bindings,
    )?;
    let inner = VerifiedTrustInner {
        organization_id: anchor.organization_id(),
        chain_id: anchor.chain_id(),
        trust_anchor_hash: anchor.trust_anchor_hash(),
        state_key: snapshot.key(),
        state_revision: snapshot.revision(),
        trusted_time: snapshot.trusted_time().clone(),
        pinned_head: snapshot.pinned_head().copied(),
        catalog,
        previous_head,
    };
    Ok(VerifiedTrust {
        inner: Arc::new(inner),
    })
}

struct DirectBootstrapObjects {
    roots: BTreeMap<ObjectHash, RootCertificateFieldsV1>,
    admin_certificates: BTreeMap<ObjectHash, DeviceCertificateFieldsV1>,
    admin_bindings: BTreeMap<ObjectHash, OperatorBindingFieldsV1>,
}

impl DirectBootstrapObjects {
    fn from_catalog(catalog: &TrustCatalog) -> Result<Self, TrustError> {
        let mut direct = Self {
            roots: BTreeMap::new(),
            admin_certificates: BTreeMap::new(),
            admin_bindings: BTreeMap::new(),
        };
        for object_hash in catalog.hashes_for_subtype(TrustSubtypeV1::RootCertificate) {
            match catalog_object(catalog, *object_hash)?
                .decoded_payload()
                .map_err(|_| TrustError::Source)?
            {
                DecodedTrustPayloadV1::InitialRoot(fields) => {
                    direct.roots.insert(*object_hash, fields);
                }
                DecodedTrustPayloadV1::AuthorizedRoot(_) => {}
                _ => return Err(TrustError::Source),
            }
        }
        for object_hash in catalog.hashes_for_subtype(TrustSubtypeV1::DeviceCertificate) {
            match catalog_object(catalog, *object_hash)?
                .decoded_payload()
                .map_err(|_| TrustError::Source)?
            {
                DecodedTrustPayloadV1::InitialAdminDevice(fields) => {
                    direct.admin_certificates.insert(*object_hash, fields);
                }
                DecodedTrustPayloadV1::AuthorizedDevice(_) => {}
                _ => return Err(TrustError::Source),
            }
        }
        for object_hash in catalog.hashes_for_subtype(TrustSubtypeV1::OperatorBinding) {
            match catalog_object(catalog, *object_hash)?
                .decoded_payload()
                .map_err(|_| TrustError::Source)?
            {
                DecodedTrustPayloadV1::InitialAdminOperatorBinding(fields) => {
                    direct.admin_bindings.insert(*object_hash, fields);
                }
                DecodedTrustPayloadV1::AuthorizedOperatorBinding(_) => {}
                _ => return Err(TrustError::Source),
            }
        }
        Ok(direct)
    }

    fn require_exact_anchor_sets(&self, anchor: &TrustAnchorV1) -> Result<(), TrustError> {
        if !self
            .roots
            .keys()
            .copied()
            .eq(std::iter::once(anchor.root_certificate_object_hash()))
            || !self.admin_certificates.keys().copied().eq(anchor
                .initial_admin_certificate_object_hashes()
                .iter()
                .copied())
            || !self.admin_bindings.keys().copied().eq(anchor
                .initial_admin_operator_binding_object_hashes()
                .iter()
                .copied())
        {
            return Err(TrustError::AnchorPin);
        }
        Ok(())
    }
}

fn verify_root_anchor_fields(
    anchor: &TrustAnchorV1,
    fields: &RootCertificateFieldsV1,
) -> Result<(), TrustError> {
    if fields.organization_id != anchor.organization_id()
        || fields.root_public_cose_key != anchor.root_public_cose_key_bytes()
        || fields.root_key_thumbprint != anchor.root_key_thumbprint()
        || fields.previous_root_certificate_object_hash.is_some()
    {
        return Err(TrustError::AnchorPin);
    }
    Ok(())
}

struct VerifiedAdminCertificate {
    object_hash: ObjectHash,
    fields: DeviceCertificateFieldsV1,
    signing_thumbprint: KeyThumbprint,
    subject: [u8; 16],
}

fn verify_admin_certificate(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
    fields: DeviceCertificateFieldsV1,
    root_resolver: &BootstrapRootResolver<'_>,
    root_certificate_hash: CertificateHash,
    organization_id: OrganizationId,
) -> Result<VerifiedAdminCertificate, TrustError> {
    verify_initial_admin_signature(catalog, object_hash, root_resolver, root_certificate_hash)?;
    if fields.organization_id != organization_id {
        return Err(TrustError::BootstrapPair);
    }
    let exact_key = fields
        .signing_public_cose_key
        .as_deref()
        .ok_or(TrustError::BootstrapPair)?;
    let public_key = CanonicalPublicCoseKey::from_deterministic_cbor(exact_key)
        .map_err(|_| TrustError::BootstrapPair)?;
    if !matches!(public_key, CanonicalPublicCoseKey::Ed25519(_))
        || fields.kem_public_cose_key.is_some()
        || fields.kem_key_thumbprint.is_some()
    {
        return Err(TrustError::BootstrapPair);
    }
    let signing_thumbprint = fields
        .signing_key_thumbprint
        .ok_or(TrustError::BootstrapPair)?;
    if public_key.thumbprint() != signing_thumbprint
        || !fields
            .capabilities
            .iter()
            .any(|capability| capability == "organizationAdminApprove")
    {
        return Err(TrustError::BootstrapPair);
    }
    if fields.effective_from_sequence != ChainSequence::new(0)
        || fields
            .revoked_from_sequence
            .is_some_and(|revoked| revoked <= ChainSequence::new(0))
    {
        return Err(TrustError::SignerInactive);
    }
    let subject = fields
        .authority_subject_id
        .ok_or(TrustError::SubjectMismatch)?;
    Ok(VerifiedAdminCertificate {
        object_hash,
        fields,
        signing_thumbprint,
        subject: *subject.as_bytes(),
    })
}

struct VerifiedAdminBinding {
    object_hash: ObjectHash,
    fields: OperatorBindingFieldsV1,
}

fn verify_admin_binding(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
    fields: OperatorBindingFieldsV1,
    root_resolver: &BootstrapRootResolver<'_>,
    root_certificate_hash: CertificateHash,
    organization_id: OrganizationId,
) -> Result<VerifiedAdminBinding, TrustError> {
    verify_initial_admin_signature(catalog, object_hash, root_resolver, root_certificate_hash)?;
    if fields.organization_id != organization_id {
        return Err(TrustError::BootstrapPair);
    }
    if fields.effective_from_sequence != ChainSequence::new(0)
        || fields
            .revoked_from_sequence
            .is_some_and(|revoked| revoked <= ChainSequence::new(0))
    {
        return Err(TrustError::SignerInactive);
    }
    Ok(VerifiedAdminBinding {
        object_hash,
        fields,
    })
}

fn verify_initial_admin_signature(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
    root_resolver: &BootstrapRootResolver<'_>,
    root_certificate_hash: CertificateHash,
) -> Result<(), TrustError> {
    let object = catalog_object(catalog, object_hash)?;
    let context = VerificationContext::initial_admin_trust_digest(
        object.exact_digest_input(),
        root_certificate_hash,
    )
    .map_err(|_| TrustError::Signature)?;
    CoseVerifier::verify_normal(only_signature(object)?, root_resolver, &context)
        .map_err(|_| TrustError::Signature)?;
    Ok(())
}

fn validate_admin_pairs(
    certificates: &BTreeMap<CertificateHash, VerifiedAdminCertificate>,
    bindings: &[VerifiedAdminBinding],
) -> Result<(), TrustError> {
    if certificates.len() != bindings.len() || certificates.len() < 2 {
        return Err(TrustError::BootstrapPair);
    }

    let mut signing_thumbprints = BTreeSet::new();
    let mut authority_subjects = BTreeSet::new();
    for certificate in certificates.values() {
        if !signing_thumbprints.insert(certificate.signing_thumbprint) {
            return Err(TrustError::BootstrapPair);
        }
        if !authority_subjects.insert(certificate.subject) {
            return Err(TrustError::SubjectMismatch);
        }
    }

    let mut paired_certificates = BTreeSet::new();
    let mut os_accounts = BTreeSet::new();
    let mut instance_keys = BTreeSet::new();
    for binding in bindings {
        let certificate_hash = binding.fields.device_certificate_hash;
        let certificate = certificates
            .get(&certificate_hash)
            .ok_or(TrustError::BootstrapPair)?;
        if !paired_certificates.insert(certificate_hash) {
            return Err(TrustError::BootstrapPair);
        }
        if certificate.subject != *binding.fields.operator_subject_id.as_bytes() {
            return Err(TrustError::SubjectMismatch);
        }
        if !os_accounts.insert(binding.fields.os_account_binding_hash)
            || !instance_keys.insert(binding.fields.operator_instance_key_thumbprint)
            || binding.fields.operator_instance_key_thumbprint == certificate.signing_thumbprint
        {
            return Err(TrustError::BootstrapPair);
        }
    }
    if paired_certificates.len() != certificates.len() {
        return Err(TrustError::BootstrapPair);
    }
    Ok(())
}

fn catalog_object(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
) -> Result<&TrustObjectV1, TrustError> {
    catalog
        .get(&object_hash)
        .map(ea_format::Parsed::value)
        .ok_or(TrustError::AnchorPin)
}

fn only_signature(object: &TrustObjectV1) -> Result<&[u8], TrustError> {
    match object.signatures() {
        [signature] => Ok(signature),
        _ => Err(TrustError::Source),
    }
}

pub fn decode_trust_anchor(exact_bytes: &[u8]) -> Result<TrustAnchorV1, TrustError> {
    preflight_flat_anchor(exact_bytes)?;
    ea_cbor::validate(exact_bytes, ParserLimits::V1).map_err(|_| TrustError::AnchorShape)?;

    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 12)?;
    expect_text(&mut decoder, FINAL_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    let embedded_bootstrap_hash = hash32(read_exact_bytes(&mut decoder, 32)?)?;
    let organization_id = OrganizationId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let chain_id = ChainId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let exact_root_public_cose_key = decoder
        .bytes()
        .map_err(|_| TrustError::AnchorShape)?
        .to_vec();
    let root_key_thumbprint = KeyThumbprint::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let root_certificate_object_hash = ObjectHash::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let initial_admin_certificate_object_hashes = read_hash_list(&mut decoder)?;
    let initial_admin_operator_binding_object_hashes = read_hash_list(&mut decoder)?;
    let genesis_entry_hash = EntryHash::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }

    validate_anchor_hash_lists(
        &initial_admin_certificate_object_hashes,
        &initial_admin_operator_binding_object_hashes,
    )?;

    let root_public_cose_key =
        pinned_root_public_key(&exact_root_public_cose_key, root_key_thumbprint)?;

    let exact_pre_anchor_bytes = encode_pre_anchor(
        organization_id,
        chain_id,
        &exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        &initial_admin_certificate_object_hashes,
        &initial_admin_operator_binding_object_hashes,
    );
    if bootstrap_anchor_hash(&exact_pre_anchor_bytes) != embedded_bootstrap_hash {
        return Err(TrustError::AnchorHash);
    }

    Ok(TrustAnchorV1 {
        bootstrap_anchor_hash: embedded_bootstrap_hash,
        organization_id,
        chain_id,
        root_public_cose_key,
        exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        initial_admin_certificate_object_hashes,
        initial_admin_operator_binding_object_hashes,
        genesis_entry_hash,
        exact_pre_anchor_bytes,
        exact_bytes: exact_bytes.to_vec(),
        trust_anchor_hash: trust_anchor_hash(exact_bytes),
    })
}

/// Baut die Vorstufe aus ihren acht Feldern und gibt ihre EXAKTEN Bytes heraus.
///
/// Kodiert wird ausschliesslich ueber [`encode_pre_anchor`] — dieselbe private
/// Funktion, die [`decode_trust_anchor`] benutzt, um die Vorstufe eines finalen
/// Ankers nachzurechnen. Ein zweiter Kodierer waere eine zweite Wahrheit: schon
/// ein Byte Abweichung zwischen beiden liesse den `bootstrapAnchorHash` des
/// finalen Ankers dauerhaft nicht mehr auf die festgeschriebene Vorstufe
/// passen.
///
/// Geprueft wird vor dem Kodieren dasselbe wie beim Dekodieren eines finalen
/// Ankers: die beiden Admin-Hashlisten sind byteweise sortiert, duplikatfrei,
/// gleich lang und enthalten mindestens zwei Werte
/// (Spezifikation `:1780`), und der Wurzelschluessel ist ein kanonischer
/// Ed25519-COSE_Key, dessen Abdruck nach RFC 9679 NEU GERECHNET wird statt
/// geglaubt zu werden (vergleiche `decode_trust_anchor`, dieselbe Datei).
///
/// # Errors
/// [`TrustError::AnchorShape`] fuer jede Listenverletzung,
/// [`TrustError::AnchorPin`] fuer einen Schluessel, der nicht kanonisch,
/// nicht Ed25519 oder nicht der des Abdrucks ist.
pub fn encode_pre_anchor_v1(
    organization_id: OrganizationId,
    chain_id: ChainId,
    exact_root_public_cose_key: &[u8],
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Result<PreAnchorV1, TrustError> {
    validate_anchor_hash_lists(certificates, bindings)?;
    let root_public_cose_key =
        pinned_root_public_key(exact_root_public_cose_key, root_key_thumbprint)?;

    let exact_bytes = encode_pre_anchor(
        organization_id,
        chain_id,
        exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        certificates,
        bindings,
    );

    Ok(PreAnchorV1 {
        organization_id,
        chain_id,
        root_public_cose_key,
        exact_root_public_cose_key: exact_root_public_cose_key.to_vec(),
        root_key_thumbprint,
        root_certificate_object_hash,
        initial_admin_certificate_object_hashes: certificates.to_vec(),
        initial_admin_operator_binding_object_hashes: bindings.to_vec(),
        bootstrap_anchor_hash: bootstrap_anchor_hash(&exact_bytes),
        exact_bytes,
    })
}

/// Liest die exakten Bytes, die auf einem Recovery-Medium stehen.
///
/// Der Aufbau spiegelt [`decode_trust_anchor`] Schritt fuer Schritt: erst ein
/// Vorlauf ueber GELIEHENE Slices, der die vollstaendige flache Drahtform
/// prueft, dann `ea_cbor::validate` mit [`ParserLimits::V1`], dann erst die
/// besitzende Dekodierung und die inhaltlichen Pruefungen. Ueberzaehlige Bytes
/// hinter dem Feld gelten als Formfehler.
///
/// Anders als der finale Anker traegt die Vorstufe keinen eingebetteten Hash
/// ueber sich selbst; ihr Fingerprint wird hier gerechnet und ist genau der
/// Wert, den Schritt 4 ueber den zweiten Kanal bestaetigt (`:1339`, `:1780`).
///
/// # Errors
/// [`TrustError::AnchorShape`] fuer jede Abweichung von
/// `organization-trust-anchor-pre-v1` (`:1737-1748`),
/// [`TrustError::AnchorPin`] fuer einen Wurzelschluessel, der nicht zu seinem
/// Abdruck gehoert.
pub fn decode_pre_anchor(exact_bytes: &[u8]) -> Result<PreAnchorV1, TrustError> {
    preflight_flat_pre_anchor(exact_bytes)?;
    ea_cbor::validate(exact_bytes, ParserLimits::V1).map_err(|_| TrustError::AnchorShape)?;

    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 10)?;
    expect_text(&mut decoder, PRE_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    let organization_id = OrganizationId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let chain_id = ChainId::try_from(read_exact_bytes(&mut decoder, 16)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let exact_root_public_cose_key = decoder
        .bytes()
        .map_err(|_| TrustError::AnchorShape)?
        .to_vec();
    let root_key_thumbprint = KeyThumbprint::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let root_certificate_object_hash = ObjectHash::try_from(read_exact_bytes(&mut decoder, 32)?)
        .map_err(|_| TrustError::AnchorShape)?;
    let initial_admin_certificate_object_hashes = read_hash_list(&mut decoder)?;
    let initial_admin_operator_binding_object_hashes = read_hash_list(&mut decoder)?;
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }

    validate_anchor_hash_lists(
        &initial_admin_certificate_object_hashes,
        &initial_admin_operator_binding_object_hashes,
    )?;
    let root_public_cose_key =
        pinned_root_public_key(&exact_root_public_cose_key, root_key_thumbprint)?;

    Ok(PreAnchorV1 {
        organization_id,
        chain_id,
        root_public_cose_key,
        exact_root_public_cose_key,
        root_key_thumbprint,
        root_certificate_object_hash,
        initial_admin_certificate_object_hashes,
        initial_admin_operator_binding_object_hashes,
        exact_bytes: exact_bytes.to_vec(),
        bootstrap_anchor_hash: bootstrap_anchor_hash(exact_bytes),
    })
}

fn preflight_flat_pre_anchor(exact_bytes: &[u8]) -> Result<(), TrustError> {
    // Wie `preflight_flat_anchor`, nur ohne `bootstrap-anchor-hash` und
    // `genesis-entry-hash`: geliehene Slices, keine Allokation, und erst hinter
    // dieser Grenze wird etwas besessen.
    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 10)?;
    expect_text(&mut decoder, PRE_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    read_exact_bytes(&mut decoder, 16)?;
    read_exact_bytes(&mut decoder, 16)?;
    let root_key = decoder.bytes().map_err(|_| TrustError::AnchorShape)?;
    if root_key.len() != 40 {
        return Err(TrustError::AnchorShape);
    }
    read_exact_bytes(&mut decoder, 32)?;
    read_exact_bytes(&mut decoder, 32)?;
    let certificate_count = preflight_hash_list(&mut decoder)?;
    let binding_count = preflight_hash_list(&mut decoder)?;
    if certificate_count != binding_count {
        return Err(TrustError::AnchorShape);
    }
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

/// Der Wurzelschluessel eines Ankers: kanonisch, Ed25519, und sein Abdruck
/// NEU GERECHNET.
///
/// Eine Stelle fuer Vorstufe und finalen Anker. Zwei Kopien dieser drei Zeilen
/// koennten auseinanderlaufen, und dann hinge an einem Anker ein Schluessel,
/// den die jeweils andere Flaeche abgewiesen haette.
fn pinned_root_public_key(
    exact_root_public_cose_key: &[u8],
    root_key_thumbprint: KeyThumbprint,
) -> Result<CanonicalPublicCoseKey, TrustError> {
    let root_public_cose_key =
        CanonicalPublicCoseKey::from_deterministic_cbor(exact_root_public_cose_key)
            .map_err(|_| TrustError::AnchorPin)?;
    if !matches!(&root_public_cose_key, CanonicalPublicCoseKey::Ed25519(_)) {
        return Err(TrustError::AnchorPin);
    }
    if root_public_cose_key.thumbprint() != root_key_thumbprint {
        return Err(TrustError::AnchorPin);
    }
    Ok(root_public_cose_key)
}

fn preflight_flat_anchor(exact_bytes: &[u8]) -> Result<(), TrustError> {
    // This pass checks the complete flat wire shape using borrowed slices only.
    // Canonical validation and all owned allocations happen after this boundary.
    let mut decoder = Decoder::new(exact_bytes);
    expect_array(&mut decoder, 12)?;
    expect_text(&mut decoder, FINAL_ANCHOR_DOMAIN)?;
    expect_u64(&mut decoder, 1)?;
    read_exact_bytes(&mut decoder, 32)?;
    read_exact_bytes(&mut decoder, 16)?;
    read_exact_bytes(&mut decoder, 16)?;
    let root_key = decoder.bytes().map_err(|_| TrustError::AnchorShape)?;
    if root_key.len() != 40 {
        return Err(TrustError::AnchorShape);
    }
    read_exact_bytes(&mut decoder, 32)?;
    read_exact_bytes(&mut decoder, 32)?;
    let certificate_count = preflight_hash_list(&mut decoder)?;
    let binding_count = preflight_hash_list(&mut decoder)?;
    if certificate_count != binding_count {
        return Err(TrustError::AnchorShape);
    }
    read_exact_bytes(&mut decoder, 32)?;
    expect_array(&mut decoder, 0)?;
    if decoder.position() != exact_bytes.len() {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn preflight_hash_list(decoder: &mut Decoder<'_>) -> Result<usize, TrustError> {
    let count = exact_array_length(decoder)?;
    let count = usize::try_from(count).map_err(|_| TrustError::AnchorShape)?;
    if !(2..=ParserLimits::V1.max_container_items).contains(&count) {
        return Err(TrustError::AnchorShape);
    }
    for _ in 0..count {
        read_exact_bytes(decoder, 32)?;
    }
    Ok(count)
}

fn read_hash_list(decoder: &mut Decoder<'_>) -> Result<Vec<ObjectHash>, TrustError> {
    let count =
        usize::try_from(exact_array_length(decoder)?).map_err(|_| TrustError::AnchorShape)?;
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(
            ObjectHash::try_from(read_exact_bytes(decoder, 32)?)
                .map_err(|_| TrustError::AnchorShape)?,
        );
    }
    Ok(hashes)
}

fn validate_anchor_hash_lists(
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Result<(), TrustError> {
    if certificates.len() != bindings.len()
        || certificates.len() < 2
        || !is_strictly_sorted(certificates)
        || !is_strictly_sorted(bindings)
    {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn is_strictly_sorted(hashes: &[ObjectHash]) -> bool {
    hashes.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_pre_anchor(
    organization_id: OrganizationId,
    chain_id: ChainId,
    exact_root_public_cose_key: &[u8],
    root_key_thumbprint: KeyThumbprint,
    root_certificate_object_hash: ObjectHash,
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Vec<u8> {
    let certificate_count =
        u64::try_from(certificates.len()).expect("validated Anchor list length fits u64");
    let binding_count =
        u64::try_from(bindings.len()).expect("validated Anchor list length fits u64");
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(10)
        .and_then(|encoder| encoder.str(PRE_ANCHOR_DOMAIN))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(exact_root_public_cose_key))
        .and_then(|encoder| encoder.bytes(root_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(root_certificate_object_hash.as_bytes()))
        .and_then(|encoder| encoder.array(certificate_count))
        .expect("encoding a validated fixed-shape Pre-Anchor into Vec cannot fail");
    for hash in certificates {
        encoder
            .bytes(hash.as_bytes())
            .expect("encoding a validated fixed-size certificate hash cannot fail");
    }
    encoder
        .array(binding_count)
        .expect("encoding a validated Binding list into Vec cannot fail");
    for hash in bindings {
        encoder
            .bytes(hash.as_bytes())
            .expect("encoding a validated fixed-size Binding hash cannot fail");
    }
    encoder
        .array(0)
        .expect("encoding closed empty critical extensions cannot fail");
    bytes
}

fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), TrustError> {
    if exact_array_length(decoder)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn exact_array_length(decoder: &mut Decoder<'_>) -> Result<u64, TrustError> {
    decoder
        .array()
        .map_err(|_| TrustError::AnchorShape)?
        .ok_or(TrustError::AnchorShape)
}

fn expect_text(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), TrustError> {
    if decoder.str().map_err(|_| TrustError::AnchorShape)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn expect_u64(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), TrustError> {
    if decoder.u64().map_err(|_| TrustError::AnchorShape)? != expected {
        return Err(TrustError::AnchorShape);
    }
    Ok(())
}

fn read_exact_bytes<'a>(
    decoder: &mut Decoder<'a>,
    expected_length: usize,
) -> Result<&'a [u8], TrustError> {
    let bytes = decoder.bytes().map_err(|_| TrustError::AnchorShape)?;
    if bytes.len() != expected_length {
        return Err(TrustError::AnchorShape);
    }
    Ok(bytes)
}

fn hash32(bytes: &[u8]) -> Result<Hash32, TrustError> {
    Hash32::try_from(bytes).map_err(|_| TrustError::AnchorShape)
}
