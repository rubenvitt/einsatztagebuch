use std::{collections::BTreeMap, sync::Arc};

use ea_crypto::{CryptoError, ResolvedSigner, SignerCertificateResolver};
use ea_format::{
    DeviceCertificateFieldsV1, OperatorBindingFieldsV1, Parsed, RootCertificateFieldsV1,
    TrustObjectV1,
};
use ea_types::{CertificateHash, ChainSequence, Hash32, ObjectHash, RegistryVersion};

use crate::{
    TrustError, TrustStateSnapshot,
    catalog::TrustCatalog,
    certificate::{ActiveCertificate, RootAuthority},
    operator_binding::ActiveOperatorBinding,
};

pub(crate) struct PreviousHeadState {
    pub(crate) registry_version: RegistryVersion,
    pub(crate) registry_head_hash: Hash32,
    catalog: Arc<TrustCatalog>,
    pub(crate) root: RootAuthority,
    pub(crate) admin_certificates: BTreeMap<CertificateHash, ActiveCertificate>,
    pub(crate) admin_bindings: BTreeMap<ObjectHash, ActiveOperatorBinding>,
}

impl PreviousHeadState {
    pub(crate) fn from_verified_bootstrap(
        catalog: Arc<TrustCatalog>,
        snapshot: &TrustStateSnapshot,
        root: (ObjectHash, RootCertificateFieldsV1),
        admin_certificates: Vec<(ObjectHash, DeviceCertificateFieldsV1)>,
        admin_bindings: Vec<(ObjectHash, OperatorBindingFieldsV1)>,
    ) -> Result<Self, TrustError> {
        if snapshot.key().organization_id != root.1.organization_id {
            return Err(TrustError::BootstrapPair);
        }
        let root = RootAuthority {
            object_hash: root.0,
            fields: root.1,
        };
        require_catalog_object(&catalog, root.object_hash)?;
        let mut certificates = BTreeMap::new();
        for (object_hash, fields) in admin_certificates {
            let certificate_hash = CertificateHash::from(object_hash);
            let certificate = ActiveCertificate {
                object_hash,
                fields,
            };
            require_catalog_object(&catalog, object_hash)?;
            if certificates.insert(certificate_hash, certificate).is_some() {
                return Err(TrustError::BootstrapPair);
            }
        }
        let mut bindings = BTreeMap::new();
        for (object_hash, fields) in admin_bindings {
            let binding = ActiveOperatorBinding {
                object_hash,
                fields,
            };
            require_catalog_object(&catalog, object_hash)?;
            if bindings.insert(object_hash, binding).is_some() {
                return Err(TrustError::BootstrapPair);
            }
        }
        Ok(Self {
            registry_version: RegistryVersion::new(0),
            registry_head_hash: Hash32::ZERO,
            catalog,
            root,
            admin_certificates: certificates,
            admin_bindings: bindings,
        })
    }

    pub(crate) fn initial_admin_pair_count(&self) -> usize {
        debug_assert_eq!(self.admin_certificates.len(), self.admin_bindings.len());
        self.admin_bindings.len()
    }

    pub(crate) fn catalog_object(&self, object_hash: ObjectHash) -> Option<&Parsed<TrustObjectV1>> {
        self.catalog.get(&object_hash)
    }
}

fn require_catalog_object(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
) -> Result<(), TrustError> {
    catalog
        .get(&object_hash)
        .map(|_| ())
        .ok_or(TrustError::AnchorPin)
}

pub(crate) struct PreviousHeadResolver<'a> {
    state: &'a PreviousHeadState,
}

impl<'a> PreviousHeadResolver<'a> {
    pub(crate) const fn new(state: &'a PreviousHeadState) -> Self {
        Self { state }
    }
}

impl SignerCertificateResolver for PreviousHeadResolver<'_> {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        if bound_registry != self.state.registry_version {
            return Err(CryptoError::SignerUnresolved);
        }
        if certificate_hash == CertificateHash::from(self.state.root.object_hash) {
            // An InitialRoot establishes the accepted line for the Registry-0
            // bootstrap context even when its wire activation field is version 1.
            let _wire_effective_version = self.state.root.fields.effective_from_registry_version;
            return Ok(ResolvedSigner {
                exact_certificate_bytes: self
                    .state
                    .catalog
                    .get(&self.state.root.object_hash)
                    .ok_or(CryptoError::SignerUnresolved)?
                    .exact_bytes()
                    .as_bytes(),
                registry_effective_from_sequence: ChainSequence::new(0),
                registry_revoked_from_sequence: None,
                registry_revoked: false,
                root_line_accepted: true,
            });
        }
        let certificate = self
            .state
            .admin_certificates
            .get(&certificate_hash)
            .ok_or(CryptoError::SignerUnresolved)?;
        debug_assert!(CertificateHash::from(certificate.object_hash) == certificate_hash);
        Ok(ResolvedSigner {
            exact_certificate_bytes: self
                .state
                .catalog
                .get(&certificate.object_hash)
                .ok_or(CryptoError::SignerUnresolved)?
                .exact_bytes()
                .as_bytes(),
            registry_effective_from_sequence: certificate.fields.effective_from_sequence,
            registry_revoked_from_sequence: certificate.fields.revoked_from_sequence,
            registry_revoked: false,
            root_line_accepted: true,
        })
    }
}

pub(crate) struct BootstrapRootResolver<'a> {
    root_hash: CertificateHash,
    exact_root_bytes: &'a [u8],
}

impl<'a> BootstrapRootResolver<'a> {
    pub(crate) const fn new(root_hash: CertificateHash, exact_root_bytes: &'a [u8]) -> Self {
        Self {
            root_hash,
            exact_root_bytes,
        }
    }
}

impl SignerCertificateResolver for BootstrapRootResolver<'_> {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        if certificate_hash != self.root_hash || bound_registry != RegistryVersion::new(0) {
            return Err(CryptoError::SignerUnresolved);
        }
        Ok(ResolvedSigner {
            exact_certificate_bytes: self.exact_root_bytes,
            registry_effective_from_sequence: ChainSequence::new(0),
            registry_revoked_from_sequence: None,
            registry_revoked: false,
            root_line_accepted: true,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use ea_crypto::{
        CanonicalPublicCoseKey, ContentType, CoseSigner, CryptoError, ProtectedHeader, SecretBytes,
        SignerCertificateResolver, bootstrap_anchor_hash, object_hash, trust_digest,
        validate_signer_certificate,
    };
    use ea_format::{
        CertificateKindV1, DecodedTrustPayloadV1, DeviceCertificateFieldsV1,
        KeyProtectionProfileV1, OperatorBindingFieldsV1, OperatorRoleV1, RootCertificateFieldsV1,
        TrustObjectV1, TrustPayloadV1, encode_trust,
    };
    use ea_time::TrustedTimeState;
    use ea_types::{
        CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, KeyThumbprint, ObjectHash,
        OperatorSubjectId, OrganizationId, RegistryVersion, SubjectId, UnixMillis,
    };
    use minicbor::Encoder;

    use super::PreviousHeadResolver;
    use crate::{
        IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit,
        StateStoreError, TrustObjectSource, TrustSourceError, TrustStateKey, TrustStateStore,
        decode_trust_anchor, load_trust_state, verify_trust,
    };

    pub(crate) const ROOT_SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    pub(crate) const ROOT_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    pub(crate) const ADMIN_PUBLIC: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];
    pub(crate) const ADMIN_TWO_PUBLIC: [u8; 32] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ];

    #[test]
    fn previous_head_resolver_exposes_only_verified_registry_zero_authority() {
        let root_bytes = exact_root_certificate();
        let root_hash = object_hash(&root_bytes);
        let admin_bytes = exact_admin_certificate(
            CertificateHash::from(root_hash),
            ADMIN_PUBLIC,
            0x51,
            0x41,
            Some(ChainSequence::new(1)),
        );
        let admin_hash = object_hash(&admin_bytes);
        let second_admin_bytes = exact_admin_certificate(
            CertificateHash::from(root_hash),
            ADMIN_TWO_PUBLIC,
            0x52,
            0x42,
            None,
        );
        let second_admin_hash = object_hash(&second_admin_bytes);
        let binding_bytes = exact_admin_binding(
            CertificateHash::from(root_hash),
            CertificateHash::from(admin_hash),
            0x41,
            0x81,
            0x91,
            Some(ChainSequence::new(1)),
        );
        let binding_hash = object_hash(&binding_bytes);
        let second_binding_bytes = exact_admin_binding(
            CertificateHash::from(root_hash),
            CertificateHash::from(second_admin_hash),
            0x42,
            0x82,
            0x92,
            None,
        );
        let second_binding_hash = object_hash(&second_binding_bytes);
        let prepared_bytes = exact_prepared_certificate(CertificateHash::from(root_hash));
        let prepared_hash = object_hash(&prepared_bytes);
        let source = CatalogSource::new([
            root_bytes.clone(),
            admin_bytes.clone(),
            second_admin_bytes.clone(),
            binding_bytes.clone(),
            second_binding_bytes.clone(),
            prepared_bytes.clone(),
        ]);
        assert!(validate_signer_certificate(&prepared_bytes).is_ok());
        let prepared = match ea_format::decode_exact_object(&prepared_bytes).unwrap() {
            ea_format::ParsedArchiveObject::Trust(parsed) => parsed,
            _ => panic!("prepared certificate must be a Trust object"),
        };
        assert!(matches!(
            prepared.value().decoded_payload().unwrap(),
            DecodedTrustPayloadV1::AuthorizedDevice(_)
        ));
        let root = match ea_format::decode_exact_object(&root_bytes).unwrap() {
            ea_format::ParsedArchiveObject::Trust(parsed) => parsed,
            _ => panic!("Root must be a Trust object"),
        };
        let root_fields = match root.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::InitialRoot(fields) => fields,
            _ => panic!("Root must use the direct initial form"),
        };
        assert_eq!(
            root_fields.effective_from_registry_version,
            RegistryVersion::new(1)
        );
        let admin = match ea_format::decode_exact_object(&admin_bytes).unwrap() {
            ea_format::ParsedArchiveObject::Trust(parsed) => parsed,
            _ => panic!("Admin must be a Trust object"),
        };
        let admin_fields = match admin.value().decoded_payload().unwrap() {
            DecodedTrustPayloadV1::InitialAdminDevice(fields) => fields,
            _ => panic!("fixture Admin must use the direct initial form"),
        };
        assert_eq!(
            admin_fields.revoked_from_sequence,
            Some(ChainSequence::new(1))
        );

        let anchor = decode_trust_anchor(&exact_anchor(
            root_hash,
            &[admin_hash, second_admin_hash],
            &[binding_hash, second_binding_hash],
        ))
        .unwrap();
        let state_key = TrustStateKey {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[0xf0; 16][..]).unwrap(),
        };
        let persisted_unverified_pin = RegistryHeadPin::new(RegistryVersion::new(9), prepared_hash);
        let mut store = SnapshotStore {
            key: state_key,
            record: Some(PersistedTrustRecord::new(
                5,
                TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
                Some(persisted_unverified_pin),
            )),
        };
        let snapshot = load_trust_state(&mut store, state_key).unwrap();
        let verified = verify_trust(&anchor, &source, snapshot)
            .expect("the shared production bootstrap builder must accept the valid basis");
        assert!(
            verified
                .pinned_head()
                .is_some_and(|pin| pin.registry_head_hash() == prepared_hash)
        );
        drop(source);
        assert_eq!(
            verified
                .inner
                .catalog
                .get(&prepared_hash)
                .expect("prepared object remains owned for later activation")
                .exact_bytes()
                .as_bytes(),
            prepared_bytes
        );
        let resolver = PreviousHeadResolver::new(&verified.inner.previous_head);
        let resolved_root = resolver
            .resolve(CertificateHash::from(root_hash), RegistryVersion::new(0))
            .expect("the Anchor Root is a special Registry-0 bootstrap signer");
        assert_eq!(resolved_root.exact_certificate_bytes, root_bytes.as_slice());
        assert_eq!(
            resolved_root.registry_effective_from_sequence,
            ChainSequence::new(0)
        );
        assert_eq!(resolved_root.registry_revoked_from_sequence, None);
        assert!(!resolved_root.registry_revoked);
        assert!(resolved_root.root_line_accepted);

        let resolved_admin = resolver
            .resolve(CertificateHash::from(admin_hash), RegistryVersion::new(0))
            .expect("a verified bootstrap Admin resolves at Registry 0");
        assert_eq!(
            resolved_admin.exact_certificate_bytes,
            admin_bytes.as_slice()
        );
        assert_eq!(
            resolved_admin.registry_effective_from_sequence,
            ChainSequence::new(0)
        );
        assert_eq!(
            resolved_admin.registry_revoked_from_sequence,
            Some(ChainSequence::new(1))
        );
        assert!(!resolved_admin.registry_revoked);
        assert!(resolved_admin.root_line_accepted);

        let resolved_second_admin = resolver
            .resolve(
                CertificateHash::from(second_admin_hash),
                RegistryVersion::new(0),
            )
            .expect("the second verified bootstrap Admin resolves at Registry 0");
        assert_eq!(
            resolved_second_admin.exact_certificate_bytes,
            second_admin_bytes.as_slice()
        );
        assert_eq!(resolved_second_admin.registry_revoked_from_sequence, None);

        let retained_binding = verified
            .inner
            .previous_head
            .admin_bindings
            .get(&binding_hash)
            .expect("the first verified Binding schedule is retained");
        assert!(retained_binding.object_hash == binding_hash);
        assert_eq!(
            retained_binding.fields.revoked_from_sequence,
            Some(ChainSequence::new(1))
        );
        let retained_second_binding = verified
            .inner
            .previous_head
            .admin_bindings
            .get(&second_binding_hash)
            .expect("the second verified Binding schedule is retained");
        assert_eq!(retained_second_binding.fields.revoked_from_sequence, None);

        assert!(matches!(
            resolver.resolve(
                CertificateHash::from(prepared_hash),
                RegistryVersion::new(0)
            ),
            Err(CryptoError::SignerUnresolved)
        ));
        assert!(matches!(
            resolver.resolve(CertificateHash::from(root_hash), RegistryVersion::new(1)),
            Err(CryptoError::SignerUnresolved)
        ));
        assert!(matches!(
            resolver.resolve(CertificateHash::from(admin_hash), RegistryVersion::new(1)),
            Err(CryptoError::SignerUnresolved)
        ));
    }

    pub(crate) fn exact_root_certificate() -> Vec<u8> {
        let key = CanonicalPublicCoseKey::ed25519(ROOT_PUBLIC).unwrap();
        let payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
            organization_id: organization(),
            root_public_cose_key: key.to_deterministic_cbor(),
            root_key_thumbprint: key.thumbprint(),
            previous_root_certificate_object_hash: None,
            effective_from_registry_version: RegistryVersion::new(1),
        })
        .unwrap();
        let signature = root_signer()
            .sign_initial_root(trust_digest(payload.exact_digest_input()).as_bytes())
            .unwrap();
        encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec()
    }

    pub(crate) fn exact_admin_certificate(
        root_hash: CertificateHash,
        public_key: [u8; 32],
        device: u8,
        subject: u8,
        revoked_from_sequence: Option<ChainSequence>,
    ) -> Vec<u8> {
        let key = CanonicalPublicCoseKey::ed25519(public_key).unwrap();
        let payload = TrustPayloadV1::initial_admin_device_certificate(DeviceCertificateFieldsV1 {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[device; 16][..]).unwrap(),
            certificate_kind: CertificateKindV1::OrganizationAdmin,
            signing_public_cose_key: Some(key.to_deterministic_cbor()),
            kem_public_cose_key: None,
            signing_key_thumbprint: Some(key.thumbprint()),
            kem_key_thumbprint: None,
            capabilities: vec!["organizationAdminApprove".into()],
            key_protection_profile: KeyProtectionProfileV1::OsWrapped,
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence,
            authority_subject_id: Some(SubjectId::try_from(&[subject; 16][..]).unwrap()),
        })
        .unwrap();
        let signature = root_signer()
            .sign_initial_admin_trust_digest(root_hash, payload.exact_digest_input())
            .unwrap();
        encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec()
    }

    pub(crate) fn exact_admin_binding(
        root_hash: CertificateHash,
        admin_hash: CertificateHash,
        subject: u8,
        os_account: u8,
        instance_key: u8,
        revoked_from_sequence: Option<ChainSequence>,
    ) -> Vec<u8> {
        let payload = TrustPayloadV1::initial_admin_operator_binding(OperatorBindingFieldsV1 {
            organization_id: organization(),
            operator_subject_id: OperatorSubjectId::try_from(&[subject; 16][..]).unwrap(),
            operator_profile_commitment: hash32(0x71),
            device_certificate_hash: admin_hash,
            operator_role: OperatorRoleV1::OrganizationAdmin,
            os_account_binding_hash: hash32(os_account),
            operator_instance_key_thumbprint: key_thumbprint(instance_key),
            effective_from_sequence: ChainSequence::new(0),
            revoked_from_sequence,
        })
        .unwrap();
        let signature = root_signer()
            .sign_initial_admin_trust_digest(root_hash, payload.exact_digest_input())
            .unwrap();
        encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec()
    }

    fn exact_prepared_certificate(root_hash: CertificateHash) -> Vec<u8> {
        let key = CanonicalPublicCoseKey::ed25519(ADMIN_PUBLIC).unwrap();
        let payload = TrustPayloadV1::authorized_device_certificate(
            DeviceCertificateFieldsV1 {
                organization_id: organization(),
                device_id: DeviceId::try_from(&[0x61; 16][..]).unwrap(),
                certificate_kind: CertificateKindV1::Writer,
                signing_public_cose_key: Some(key.to_deterministic_cbor()),
                kem_public_cose_key: None,
                signing_key_thumbprint: Some(key.thumbprint()),
                kem_key_thumbprint: None,
                capabilities: vec!["initialGrant".into()],
                key_protection_profile: KeyProtectionProfileV1::OsWrapped,
                effective_from_sequence: ChainSequence::new(0),
                revoked_from_sequence: None,
                authority_subject_id: None,
            },
            object_hash(b"prepared authorization"),
        )
        .unwrap();
        let protected =
            ProtectedHeader::normal(ContentType::TrustDigest, key.thumbprint(), root_hash)
                .to_deterministic_cbor();
        let mut signature = Vec::new();
        Encoder::new(&mut signature)
            .tag(minicbor::data::Tag::new(18))
            .unwrap()
            .array(4)
            .unwrap()
            .bytes(&protected)
            .unwrap()
            .map(0)
            .unwrap()
            .bytes(trust_digest(payload.exact_digest_input()).as_bytes())
            .unwrap()
            .bytes(&[0x5a; 64])
            .unwrap();
        encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec()
    }

    pub(crate) fn exact_anchor(
        root_hash: ObjectHash,
        admin_hashes: &[ObjectHash],
        binding_hashes: &[ObjectHash],
    ) -> Vec<u8> {
        let root_key = CanonicalPublicCoseKey::ed25519(ROOT_PUBLIC).unwrap();
        let root_key_bytes = root_key.to_deterministic_cbor();
        let mut admin_hashes = admin_hashes.to_vec();
        let mut binding_hashes = binding_hashes.to_vec();
        admin_hashes.sort_unstable();
        binding_hashes.sort_unstable();
        let chain_id = ChainId::try_from(&[0x31; 16][..]).unwrap();
        let mut pre_anchor = Vec::new();
        let mut encoder = Encoder::new(&mut pre_anchor);
        encoder
            .array(10)
            .unwrap()
            .str("EINSATZARCHIV-TRUST-ANCHOR-PRE-v1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(organization().as_bytes())
            .unwrap()
            .bytes(chain_id.as_bytes())
            .unwrap()
            .bytes(&root_key_bytes)
            .unwrap()
            .bytes(root_key.thumbprint().as_bytes())
            .unwrap()
            .bytes(root_hash.as_bytes())
            .unwrap()
            .array(u64::try_from(admin_hashes.len()).unwrap())
            .unwrap();
        for hash in &admin_hashes {
            encoder.bytes(hash.as_bytes()).unwrap();
        }
        encoder
            .array(u64::try_from(binding_hashes.len()).unwrap())
            .unwrap();
        for hash in &binding_hashes {
            encoder.bytes(hash.as_bytes()).unwrap();
        }
        encoder.array(0).unwrap();

        let mut anchor = Vec::new();
        let mut encoder = Encoder::new(&mut anchor);
        encoder
            .array(12)
            .unwrap()
            .str("EINSATZARCHIV-TRUST-ANCHOR-v1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(bootstrap_anchor_hash(&pre_anchor).as_bytes())
            .unwrap()
            .bytes(organization().as_bytes())
            .unwrap()
            .bytes(chain_id.as_bytes())
            .unwrap()
            .bytes(&root_key_bytes)
            .unwrap()
            .bytes(root_key.thumbprint().as_bytes())
            .unwrap()
            .bytes(root_hash.as_bytes())
            .unwrap()
            .array(u64::try_from(admin_hashes.len()).unwrap())
            .unwrap();
        for hash in &admin_hashes {
            encoder.bytes(hash.as_bytes()).unwrap();
        }
        encoder
            .array(u64::try_from(binding_hashes.len()).unwrap())
            .unwrap();
        for hash in &binding_hashes {
            encoder.bytes(hash.as_bytes()).unwrap();
        }
        encoder.bytes(&[0x44; 32]).unwrap().array(0).unwrap();
        anchor
    }

    fn root_signer() -> CoseSigner {
        CoseSigner::from_secret(SecretBytes::new(ROOT_SECRET))
    }

    pub(crate) fn organization() -> OrganizationId {
        OrganizationId::try_from(&[0x21; 16][..]).unwrap()
    }

    pub(crate) fn hash32(byte: u8) -> Hash32 {
        Hash32::try_from(&[byte; 32][..]).unwrap()
    }

    pub(crate) fn key_thumbprint(byte: u8) -> KeyThumbprint {
        KeyThumbprint::try_from(&[byte; 32][..]).unwrap()
    }

    pub(crate) struct CatalogSource(BTreeMap<ObjectHash, Arc<[u8]>>);

    impl CatalogSource {
        pub(crate) fn new(objects: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self(
                objects
                    .into_iter()
                    .map(|bytes| (object_hash(&bytes), Arc::<[u8]>::from(bytes)))
                    .collect(),
            )
        }
    }

    impl TrustObjectSource for CatalogSource {
        fn visit_trust_object_hashes(
            &self,
            visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
        ) -> Result<(), TrustSourceError> {
            for object_hash in self.0.keys().rev().copied() {
                visitor(object_hash)?;
            }
            Ok(())
        }

        fn read_exact_trust_object(
            &self,
            object_hash: ObjectHash,
        ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
            Ok(self.0.get(&object_hash).map(Arc::clone))
        }
    }

    pub(crate) struct SnapshotStore {
        pub(crate) key: TrustStateKey,
        pub(crate) record: Option<PersistedTrustRecord>,
    }

    impl TrustStateStore for SnapshotStore {
        fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
            if key != self.key {
                return Err(StateStoreError::Unavailable);
            }
            self.record.take().ok_or(StateStoreError::Unavailable)
        }

        fn commit_independent_time(
            &mut self,
            _key: TrustStateKey,
            _expected_revision: u64,
            _commit: &IndependentTimeCommit,
        ) -> Result<PersistedTrustRecord, StateStoreError> {
            Err(StateStoreError::Unavailable)
        }

        fn clock_release_consumed(
            &mut self,
            _key: &crate::ClockReleaseReplayKey,
        ) -> Result<bool, StateStoreError> {
            Err(StateStoreError::Unavailable)
        }

        fn commit_registry_selection(
            &mut self,
            _key: TrustStateKey,
            _expected_revision: u64,
            _commit: &RegistrySelectionCommit,
        ) -> Result<PersistedTrustRecord, StateStoreError> {
            Err(StateStoreError::Unavailable)
        }
    }
}
