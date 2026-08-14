use std::{collections::BTreeMap, sync::Arc};

use ea_format::{Parsed, ParsedArchiveObject, TrustObjectV1, TrustSubtypeV1};
use ea_types::ObjectHash;

use crate::{
    MAX_TOTAL_TRUST_OBJECT_BYTES_V1, MAX_TRUST_OBJECTS_V1, TrustError, TrustObjectSource,
    TrustSourceError,
};

pub(crate) struct TrustCatalog {
    by_hash: BTreeMap<ObjectHash, Parsed<TrustObjectV1>>,
    by_subtype: BTreeMap<&'static str, Vec<ObjectHash>>,
}

impl TrustCatalog {
    pub(crate) fn load(source: &dyn TrustObjectSource) -> Result<Self, TrustError> {
        let mut declared_hashes = Vec::new();
        let mut count_limit_hit = false;
        let visit_result = source.visit_trust_object_hashes(&mut |object_hash| {
            if declared_hashes.len() == MAX_TRUST_OBJECTS_V1 {
                count_limit_hit = true;
                return Err(TrustSourceError::CountLimit);
            }
            declared_hashes.push(object_hash);
            Ok(())
        });
        if count_limit_hit {
            return Err(TrustError::SourceCountLimit);
        }
        visit_result.map_err(TrustError::from)?;

        declared_hashes.sort_unstable();
        if declared_hashes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TrustError::Source);
        }

        let mut by_hash = BTreeMap::new();
        let mut by_subtype: BTreeMap<&'static str, Vec<ObjectHash>> = BTreeMap::new();
        let mut total_exact_bytes = 0;
        for declared_hash in declared_hashes {
            let exact_bytes = source
                .read_exact_trust_object(declared_hash)
                .map_err(TrustError::from)?
                .ok_or(TrustError::Source)?;
            let exact_bytes = admit_exact_trust_bytes(&mut total_exact_bytes, exact_bytes)?;
            if ea_crypto::object_hash(&exact_bytes) != declared_hash {
                return Err(TrustError::Source);
            }
            let parsed = match ea_format::decode_exact_object(&exact_bytes)
                .map_err(|_| TrustError::Source)?
            {
                ParsedArchiveObject::Trust(parsed) => parsed,
                _ => return Err(TrustError::Source),
            };
            by_subtype
                .entry(parsed.value().subtype().as_str())
                .or_default()
                .push(declared_hash);
            if by_hash.insert(declared_hash, parsed).is_some() {
                return Err(TrustError::Source);
            }
        }
        Ok(Self {
            by_hash,
            by_subtype,
        })
    }

    pub(crate) fn get(&self, object_hash: &ObjectHash) -> Option<&Parsed<TrustObjectV1>> {
        self.by_hash.get(object_hash)
    }

    pub(crate) fn hashes_for_subtype(&self, subtype: TrustSubtypeV1) -> &[ObjectHash] {
        self.by_subtype
            .get(subtype.as_str())
            .map_or(&[], Vec::as_slice)
    }
}

fn admit_exact_trust_bytes(
    total_exact_bytes: &mut usize,
    exact_bytes: Arc<[u8]>,
) -> Result<Arc<[u8]>, TrustError> {
    let next_total = total_exact_bytes
        .checked_add(exact_bytes.len())
        .ok_or(TrustError::SourceByteLimit)?;
    if next_total > MAX_TOTAL_TRUST_OBJECT_BYTES_V1 {
        return Err(TrustError::SourceByteLimit);
    }
    *total_exact_bytes = next_total;
    Ok(exact_bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, object_hash, trust_digest};
    use ea_format::{
        RootCertificateFieldsV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1, encode_trust,
    };
    use ea_types::{ObjectHash, OrganizationId, RegistryVersion};

    use super::{TrustCatalog, admit_exact_trust_bytes};
    use crate::{
        MAX_TOTAL_TRUST_OBJECT_BYTES_V1, MAX_TRUST_OBJECTS_V1, TrustObjectSource, TrustSourceError,
    };

    #[test]
    fn trust_catalog_source_attacks_are_closed() {
        for (source_error, expected_code) in [
            (TrustSourceError::Unavailable, "EA-TRUST-SOURCE"),
            (TrustSourceError::CountLimit, "EA-TRUST-SOURCE-COUNT-LIMIT"),
            (TrustSourceError::ByteLimit, "EA-TRUST-SOURCE-BYTE-LIMIT"),
        ] {
            assert_eq!(source_error.code(), expected_code);
            assert_eq!(source_error.to_string(), expected_code);
            assert_eq!(format!("{source_error:?}"), expected_code);
        }

        let first_bytes = exact_initial_root_object(0x11);
        let second_bytes = exact_initial_root_object(0x22);
        let first_hash = object_hash(&first_bytes);
        let second_hash = object_hash(&second_bytes);
        assert!(first_hash != second_hash);
        let (low_hash, low_bytes, high_hash, high_bytes) = if first_hash < second_hash {
            (first_hash, first_bytes, second_hash, second_bytes)
        } else {
            (second_hash, second_bytes, first_hash, first_bytes)
        };

        let unsorted_source = FakeSource::new(
            vec![high_hash, low_hash],
            [
                (low_hash, Arc::clone(&low_bytes)),
                (high_hash, Arc::clone(&high_bytes)),
            ],
        );
        let catalog = match TrustCatalog::load(&unsorted_source) {
            Ok(catalog) => catalog,
            Err(error) => panic!("unsorted valid source must normalize: {}", error.code()),
        };
        let root_hashes = catalog.hashes_for_subtype(TrustSubtypeV1::RootCertificate);
        assert!(root_hashes == [low_hash, high_hash]);
        assert!(catalog.get(&low_hash).is_some());
        assert!(catalog.get(&high_hash).is_some());
        assert_eq!(unsorted_source.read_count(low_hash), 1);
        assert_eq!(unsorted_source.read_count(high_hash), 1);

        let exact_count_source = FakeSource::new(
            (0..MAX_TRUST_OBJECTS_V1).map(indexed_hash).collect(),
            std::iter::empty(),
        );
        let exact_count_error = match TrustCatalog::load(&exact_count_source) {
            Ok(_) => panic!("missing bytes after the exact count boundary must fail closed"),
            Err(error) => error,
        };
        assert_eq!(exact_count_error.code(), "EA-TRUST-SOURCE");
        assert_eq!(exact_count_source.visit_count(), MAX_TRUST_OBJECTS_V1);
        assert_eq!(exact_count_source.total_read_count(), 1);

        let over_count_source = FakeSource::new(
            (0..=MAX_TRUST_OBJECTS_V1).map(indexed_hash).collect(),
            std::iter::empty(),
        );
        let over_count_error = match TrustCatalog::load(&over_count_source) {
            Ok(_) => panic!("the N+1 Trust hash must fail before catalog growth or reads"),
            Err(error) => error,
        };
        assert_eq!(over_count_error.code(), "EA-TRUST-SOURCE-COUNT-LIMIT");
        assert_eq!(over_count_source.visit_count(), MAX_TRUST_OBJECTS_V1 + 1);
        assert_eq!(over_count_source.total_read_count(), 0);

        let swallowing_source = FakeSource::new(
            (0..=MAX_TRUST_OBJECTS_V1).map(indexed_hash).collect(),
            std::iter::empty(),
        )
        .ignoring_visitor_errors();
        let swallowing_error = match TrustCatalog::load(&swallowing_source) {
            Ok(_) => panic!("ea-trust must enforce count even if a source swallows visitor errors"),
            Err(error) => error,
        };
        assert_eq!(swallowing_error.code(), "EA-TRUST-SOURCE-COUNT-LIMIT");
        assert_eq!(swallowing_source.total_read_count(), 0);

        let non_etb_probe: Arc<[u8]> = Arc::from([0x80]);
        let mut exact_total = MAX_TOTAL_TRUST_OBJECT_BYTES_V1 - non_etb_probe.len();
        let admitted = admit_exact_trust_bytes(&mut exact_total, Arc::clone(&non_etb_probe))
            .expect("the exact aggregate-byte boundary is admitted before decode");
        assert_eq!(exact_total, MAX_TOTAL_TRUST_OBJECT_BYTES_V1);
        assert!(Arc::ptr_eq(&admitted, &non_etb_probe));

        let mut over_total = MAX_TOTAL_TRUST_OBJECT_BYTES_V1;
        let over_byte_error =
            match admit_exact_trust_bytes(&mut over_total, Arc::clone(&non_etb_probe)) {
                Ok(_) => panic!("aggregate limit + 1 must fail before non-ETB decode or retention"),
                Err(error) => error,
            };
        assert_eq!(over_byte_error.code(), "EA-TRUST-SOURCE-BYTE-LIMIT");
        assert_eq!(over_total, MAX_TOTAL_TRUST_OBJECT_BYTES_V1);

        let mut overflow_total = usize::MAX;
        let overflow_error = match admit_exact_trust_bytes(&mut overflow_total, non_etb_probe) {
            Ok(_) => panic!("aggregate length overflow must fail closed"),
            Err(error) => error,
        };
        assert_eq!(overflow_error.code(), "EA-TRUST-SOURCE-BYTE-LIMIT");
        assert_eq!(overflow_total, usize::MAX);

        let non_etb_bytes: Arc<[u8]> = Arc::from([0x80]);
        let non_etb_hash = object_hash(&non_etb_bytes);
        let attacks = [
            (
                "duplicate declarations",
                FakeSource::new(
                    vec![low_hash, low_hash],
                    [(low_hash, Arc::clone(&low_bytes))],
                ),
            ),
            (
                "missing exact bytes",
                FakeSource::new(vec![low_hash], std::iter::empty()),
            ),
            (
                "non-ETB bytes",
                FakeSource::new(
                    vec![non_etb_hash],
                    [(non_etb_hash, Arc::clone(&non_etb_bytes))],
                ),
            ),
            (
                "actual hash differs from lookup key",
                FakeSource::new(vec![low_hash], [(low_hash, Arc::clone(&high_bytes))]),
            ),
            (
                "source read error",
                FakeSource::new(vec![low_hash], [(low_hash, Arc::clone(&low_bytes))])
                    .with_read_error(low_hash),
            ),
            ("source listing error", FakeSource::listing_error()),
        ];

        for (label, source) in attacks {
            let error = match TrustCatalog::load(&source) {
                Ok(_) => panic!("{label} must fail closed"),
                Err(error) => error,
            };
            assert_eq!(error.code(), "EA-TRUST-SOURCE", "{label}");
            assert_eq!(error.to_string(), "EA-TRUST-SOURCE", "{label}");
            assert_eq!(format!("{error:?}"), "EA-TRUST-SOURCE", "{label}");
        }
    }

    struct FakeSource {
        hashes: Result<Vec<ObjectHash>, TrustSourceError>,
        objects: BTreeMap<ObjectHash, Arc<[u8]>>,
        read_errors: BTreeSet<ObjectHash>,
        reads: RefCell<BTreeMap<ObjectHash, usize>>,
        visits: Cell<usize>,
        ignore_visitor_errors: bool,
    }

    impl FakeSource {
        fn new(
            hashes: Vec<ObjectHash>,
            objects: impl IntoIterator<Item = (ObjectHash, Arc<[u8]>)>,
        ) -> Self {
            Self {
                hashes: Ok(hashes),
                objects: objects.into_iter().collect(),
                read_errors: BTreeSet::new(),
                reads: RefCell::new(BTreeMap::new()),
                visits: Cell::new(0),
                ignore_visitor_errors: false,
            }
        }

        fn listing_error() -> Self {
            Self {
                hashes: Err(TrustSourceError::Unavailable),
                objects: BTreeMap::new(),
                read_errors: BTreeSet::new(),
                reads: RefCell::new(BTreeMap::new()),
                visits: Cell::new(0),
                ignore_visitor_errors: false,
            }
        }

        fn with_read_error(mut self, hash: ObjectHash) -> Self {
            self.read_errors.insert(hash);
            self
        }

        fn ignoring_visitor_errors(mut self) -> Self {
            self.ignore_visitor_errors = true;
            self
        }

        fn read_count(&self, hash: ObjectHash) -> usize {
            self.reads.borrow().get(&hash).copied().unwrap_or(0)
        }

        fn total_read_count(&self) -> usize {
            self.reads.borrow().values().sum()
        }

        fn visit_count(&self) -> usize {
            self.visits.get()
        }
    }

    impl TrustObjectSource for FakeSource {
        fn visit_trust_object_hashes(
            &self,
            visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
        ) -> Result<(), TrustSourceError> {
            let hashes = self.hashes.as_ref().map_err(|error| *error)?;
            for hash in hashes {
                self.visits.set(self.visits.get() + 1);
                if let Err(error) = visitor(*hash)
                    && !self.ignore_visitor_errors
                {
                    return Err(error);
                }
            }
            Ok(())
        }

        fn read_exact_trust_object(
            &self,
            object_hash: ObjectHash,
        ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
            *self.reads.borrow_mut().entry(object_hash).or_default() += 1;
            if self.read_errors.contains(&object_hash) {
                return Err(TrustSourceError::Unavailable);
            }
            Ok(self.objects.get(&object_hash).cloned())
        }
    }

    fn exact_initial_root_object(organization_byte: u8) -> Arc<[u8]> {
        let public_key = CanonicalPublicCoseKey::ed25519(
            decode_hex("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
            organization_id: OrganizationId::try_from([organization_byte; 16].as_slice()).unwrap(),
            root_public_cose_key: public_key.to_deterministic_cbor(),
            root_key_thumbprint: public_key.thumbprint(),
            previous_root_certificate_object_hash: None,
            effective_from_registry_version: RegistryVersion::new(1),
        })
        .unwrap();
        let digest = trust_digest(payload.exact_digest_input());
        let signer = CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| {
            u8::try_from(index).unwrap()
        })));
        let signature = signer.sign_initial_root(digest.as_bytes()).unwrap();
        let object = TrustObjectV1::new(payload, vec![signature]).unwrap();
        Arc::from(encode_trust(&object).unwrap().into_vec())
    }

    fn indexed_hash(index: usize) -> ObjectHash {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
        ObjectHash::try_from(bytes.as_slice()).unwrap()
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |value| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("fixture contains only lowercase hexadecimal"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect()
    }
}
