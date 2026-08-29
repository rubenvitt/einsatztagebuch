//! Byte-stabile Rahmen: Commit-Identitaet, Lesestapel, technischer Cursor,
//! Fehlerkoerper und die Grenzen, die vor jeder Verarbeitung greifen.

use ea_sync_protocol::{
    EndpointAuthentication, EndpointV1, EntryCommitRequestV1, MAX_ENTRY_COMMIT_BODY_BYTES_V1,
    MAX_GRANT_OBJECT_BYTES_V1, MAX_READER_PAGE_OBJECTS_V1, ObjectRecordV1, ProtocolErrorV1,
    ReaderBatchV1, SyncProtocolError, TechnicalCursorFieldsV1, TechnicalCursorScopeV1,
    TechnicalCursorV1,
};
use ea_types::{
    ChainId, EntryHash, Hash32, ObjectHash, OrganizationId, RegistryVersion, UnixMillis,
};

mod fixtures {
    use std::{fs, path::PathBuf};

    use ea_crypto::{CanonicalPublicCoseKey, CryptoError, object_hash};
    use ea_format::{GrantPlanItemV1, GrantPlanV1, GrantPurposeV1};
    use ea_sync_protocol::{TechnicalCursorSigner, TechnicalCursorVerifier};
    use ea_types::{CertificateHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId};
    use ed25519_dalek::{Signer, SigningKey};

    #[must_use]
    pub fn organization() -> OrganizationId {
        OrganizationId::try_from([0x11; 16].as_slice()).unwrap()
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn vector(relative: &str) -> Vec<u8> {
        fs::read(workspace_root().join(relative)).unwrap()
    }

    /// Die eingefrorenen `.eip`-Bytes der Stufe 1 — echte Objektbytes statt
    /// eines nachgebauten Rahmens.
    #[must_use]
    pub fn entry() -> Vec<u8> {
        vector("vectors/format/v1/valid/eip/valid.bin")
    }

    #[must_use]
    pub fn initial_reader_grant() -> Vec<u8> {
        vector("vectors/grants/v1/grant/accepted-initial-reader.bin")
    }

    #[must_use]
    pub fn historical_reader_grant() -> Vec<u8> {
        vector("vectors/grants/v1/grant/accepted-historical-reader.bin")
    }

    /// Die eingefrorenen `.etb`-Bytes der Stufe 1.
    #[must_use]
    pub fn trust_object() -> Vec<u8> {
        vector("vectors/format/v1/valid/etb/valid.bin")
    }

    #[must_use]
    pub fn hash_of(bytes: &[u8]) -> ObjectHash {
        object_hash(bytes)
    }

    /// Ein Plan mit genau einer Wiederherstellung und einem Leser — die
    /// kleinste Form, die `GrantPlanV1::new` annimmt.
    #[must_use]
    pub fn plan() -> GrantPlanV1 {
        GrantPlanV1::new(vec![
            GrantPlanItemV1::new(
                KeyThumbprint::from(Hash32::try_from([0x41; 32].as_slice()).unwrap()),
                CertificateHash::from(ObjectHash::from(
                    Hash32::try_from([0x42; 32].as_slice()).unwrap(),
                )),
                GrantPurposeV1::Recovery,
            ),
            GrantPlanItemV1::new(
                KeyThumbprint::from(Hash32::try_from([0x43; 32].as_slice()).unwrap()),
                CertificateHash::from(ObjectHash::from(
                    Hash32::try_from([0x44; 32].as_slice()).unwrap(),
                )),
                GrantPurposeV1::Reader,
            ),
        ])
        .unwrap()
    }

    /// Der Serverschluessel als Testdouble. Die COSE-Huelle des produktiven
    /// Serverschluessels entsteht im Serverschluessel-Port; dieses Double
    /// beweist ausschliesslich, dass der Cursor ueber genau seinen
    /// domaenengetrennten Digest authentisiert wird.
    pub struct ServerKey(SigningKey);

    impl ServerKey {
        #[must_use]
        pub fn new(secret: [u8; 32]) -> Self {
            Self(SigningKey::from_bytes(&secret))
        }

        fn public(&self) -> CanonicalPublicCoseKey {
            CanonicalPublicCoseKey::ed25519(*self.0.verifying_key().as_bytes()).unwrap()
        }
    }

    impl TechnicalCursorSigner for ServerKey {
        fn sign_technical_cursor_digest(&self, digest: Hash32) -> Result<Vec<u8>, CryptoError> {
            Ok(self.0.sign(digest.as_bytes()).to_bytes().to_vec())
        }
    }

    impl TechnicalCursorVerifier for ServerKey {
        fn verify_technical_cursor_digest(
            &self,
            digest: Hash32,
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| CryptoError::SignatureInvalid)?;
            self.public()
                .verify_ed25519_strict(digest.as_bytes(), &signature)
        }
    }
}

#[test]
fn commit_identity_is_independent_of_transport_order() {
    let initial = fixtures::initial_reader_grant();
    let historical = fixtures::historical_reader_grant();
    let initial_hash = fixtures::hash_of(&initial);
    let historical_hash = fixtures::hash_of(&historical);
    assert!(
        historical_hash.as_bytes() < initial_hash.as_bytes(),
        "die Vektoren muessen sich in Transport- und Sortierreihenfolge unterscheiden"
    );

    let request = EntryCommitRequestV1::new(
        fixtures::entry(),
        fixtures::plan(),
        vec![initial.clone(), historical.clone()],
    )
    .unwrap();
    assert_eq!(
        request
            .identity()
            .sorted_grant_object_hashes()
            .iter()
            .map(|hash| *hash.as_bytes())
            .collect::<Vec<_>>(),
        vec![*historical_hash.as_bytes(), *initial_hash.as_bytes()]
    );

    let reversed = EntryCommitRequestV1::new(
        fixtures::entry(),
        fixtures::plan(),
        vec![historical, initial],
    )
    .unwrap();
    assert_eq!(request.identity(), reversed.identity());
    assert_eq!(request.exact_bytes(), reversed.exact_bytes());
}

#[test]
fn the_commit_identity_carries_exactly_its_four_normative_positions() {
    let request = EntryCommitRequestV1::new(
        fixtures::entry(),
        fixtures::plan(),
        vec![fixtures::initial_reader_grant()],
    )
    .unwrap();
    let identity = request.identity();
    assert_eq!(
        identity.entry_object_hash().as_bytes(),
        fixtures::hash_of(&fixtures::entry()).as_bytes()
    );
    assert_eq!(
        identity.initial_grant_plan_hash().as_bytes(),
        fixtures::plan().hash().as_bytes()
    );
    assert_eq!(identity.sorted_grant_object_hashes().len(), 1);
    assert_ne!(identity.entry_hash().as_bytes(), &[0u8; 32]);
}

#[test]
fn an_entry_commit_request_round_trips_through_its_exact_bytes() {
    let request = EntryCommitRequestV1::new(
        fixtures::entry(),
        fixtures::plan(),
        vec![
            fixtures::initial_reader_grant(),
            fixtures::historical_reader_grant(),
        ],
    )
    .unwrap();
    let decoded = EntryCommitRequestV1::decode(request.exact_bytes()).unwrap();
    assert_eq!(decoded.exact_bytes(), request.exact_bytes());
    assert_eq!(decoded.identity(), request.identity());
}

#[test]
fn duplicate_grant_objects_are_rejected_before_service_invocation() {
    let grant = fixtures::initial_reader_grant();
    assert_eq!(
        EntryCommitRequestV1::new(
            fixtures::entry(),
            fixtures::plan(),
            vec![grant.clone(), grant]
        )
        .unwrap_err()
        .code(),
        "EA-SYNC-DUPLICATE-OBJECT"
    );
}

#[test]
fn the_grant_ceiling_is_enforced_before_the_grant_is_parsed() {
    // Der Puffer ist kein gueltiges `.eag`. Der Groessenfehler MUSS trotzdem
    // gewinnen, sonst laeuft der Parser vor der Grenze.
    assert_eq!(
        EntryCommitRequestV1::new(
            fixtures::entry(),
            fixtures::plan(),
            vec![vec![0u8; MAX_GRANT_OBJECT_BYTES_V1 + 1]]
        )
        .unwrap_err()
        .code(),
        "EA-SYNC-GRANT-LIMIT"
    );
}

#[test]
fn a_body_beyond_the_commit_ceiling_is_rejected_before_it_is_decoded() {
    let oversized = vec![0u8; MAX_ENTRY_COMMIT_BODY_BYTES_V1 + 1];
    assert_eq!(
        EntryCommitRequestV1::decode(&oversized).unwrap_err().code(),
        "EA-SYNC-BODY-LIMIT"
    );
}

#[test]
fn a_reader_batch_round_trips_and_rejects_unsorted_duplicate_and_oversized_pages() {
    let chain = ChainId::try_from([0x51; 16].as_slice()).unwrap();
    let head = EntryHash::from(Hash32::try_from([0x52; 32].as_slice()).unwrap());
    let after = EntryHash::from(Hash32::try_from([0x53; 32].as_slice()).unwrap());
    let records = vec![
        ObjectRecordV1::new(record_hash(1), b"eins".to_vec()),
        ObjectRecordV1::new(record_hash(2), b"zwei".to_vec()),
    ];
    let batch = ReaderBatchV1::new(chain, 7, after, head, records.clone(), None, 9).unwrap();
    assert_eq!(
        ReaderBatchV1::decode(batch.exact_bytes())
            .unwrap()
            .exact_bytes(),
        batch.exact_bytes()
    );

    let mut unsorted = records.clone();
    unsorted.reverse();
    assert_eq!(
        ReaderBatchV1::new(chain, 7, after, head, unsorted, None, 9)
            .unwrap_err()
            .code(),
        "EA-SYNC-UNSORTED-OBJECTS"
    );
    assert_eq!(
        ReaderBatchV1::new(
            chain,
            7,
            after,
            head,
            vec![records[0].clone(), records[0].clone()],
            None,
            9
        )
        .unwrap_err()
        .code(),
        "EA-SYNC-DUPLICATE-OBJECT"
    );
    let too_many = (0..=MAX_READER_PAGE_OBJECTS_V1)
        .map(|index| ObjectRecordV1::new(record_hash(u8::try_from(index % 251).unwrap()), vec![1]))
        .collect();
    assert_eq!(
        ReaderBatchV1::new(chain, 7, after, head, too_many, None, 9)
            .unwrap_err()
            .code(),
        "EA-SYNC-ITEM-LIMIT"
    );
}

fn record_hash(seed: u8) -> ObjectHash {
    ObjectHash::from(Hash32::try_from([seed; 32].as_slice()).unwrap())
}

#[test]
fn a_technical_cursor_is_opaque_bound_to_its_endpoint_and_expiring() {
    let key = fixtures::ServerKey::new([0x61; 32]);
    let fields = TechnicalCursorFieldsV1 {
        organization_id: fixtures::organization(),
        endpoint: EndpointV1::ChainEntries,
        chain_id: Some(ChainId::try_from([0x62; 16].as_slice()).unwrap()),
        start_head_entry_hash: Some(EntryHash::from(
            Hash32::try_from([0x63; 32].as_slice()).unwrap(),
        )),
        last_technical_index: 42,
        expires_at: UnixMillis::new(1_800_000_000_000),
        nonce: [0x64; 16],
    };
    let cursor = TechnicalCursorV1::issue(&fields, &key).unwrap();
    let scope = TechnicalCursorScopeV1 {
        organization_id: fixtures::organization(),
        endpoint: EndpointV1::ChainEntries,
        chain_id: fields.chain_id,
        start_head_entry_hash: fields.start_head_entry_hash,
    };
    let valid = UnixMillis::new(1_799_999_999_000);

    let opened = TechnicalCursorV1::open(cursor.token_bytes(), &key, valid, &scope).unwrap();
    assert_eq!(opened.last_technical_index(), 42);

    assert_eq!(
        TechnicalCursorV1::open(
            cursor.token_bytes(),
            &key,
            UnixMillis::new(1_800_000_001_000),
            &scope,
        )
        .unwrap_err()
        .code(),
        "EA-SYNC-CURSOR-EXPIRED"
    );

    // Jede der vier Bindungspositionen muss einzeln greifen: ein authentischer
    // Cursor eines anderen Endpunkts, einer anderen Organisation, einer anderen
    // Kette oder eines anderen Startkopfes blaetterte sonst in einer fremden
    // Lesestrecke weiter.
    for (label, other) in [
        (
            "endpoint",
            TechnicalCursorScopeV1 {
                endpoint: EndpointV1::Checkpoints,
                ..scope
            },
        ),
        (
            "organization",
            TechnicalCursorScopeV1 {
                organization_id: OrganizationId::try_from([0x99; 16].as_slice()).unwrap(),
                ..scope
            },
        ),
        (
            "chain",
            TechnicalCursorScopeV1 {
                chain_id: Some(ChainId::try_from([0x9a; 16].as_slice()).unwrap()),
                ..scope
            },
        ),
        (
            "chain absent",
            TechnicalCursorScopeV1 {
                chain_id: None,
                ..scope
            },
        ),
        (
            "start head",
            TechnicalCursorScopeV1 {
                start_head_entry_hash: Some(EntryHash::from(
                    Hash32::try_from([0x9b; 32].as_slice()).unwrap(),
                )),
                ..scope
            },
        ),
        (
            "start head absent",
            TechnicalCursorScopeV1 {
                start_head_entry_hash: None,
                ..scope
            },
        ),
    ] {
        assert_eq!(
            TechnicalCursorV1::open(cursor.token_bytes(), &key, valid, &other)
                .unwrap_err()
                .code(),
            "EA-SYNC-CURSOR-SCOPE",
            "{label}"
        );
    }

    let foreign = fixtures::ServerKey::new([0x65; 32]);
    assert_eq!(
        TechnicalCursorV1::open(cursor.token_bytes(), &foreign, valid, &scope)
            .unwrap_err()
            .code(),
        "EA-SYNC-CURSOR-INVALID"
    );
}

#[test]
fn protocol_error_bodies_are_equal_modulo_the_request_id() {
    let first = ProtocolErrorV1::new(
        SyncProtocolError::NonceReplay,
        request_id(1),
        Some(RegistryVersion::new(7)),
        Some(Hash32::try_from([0x71; 32].as_slice()).unwrap()),
    );
    let second = ProtocolErrorV1::new(
        SyncProtocolError::NonceReplay,
        request_id(2),
        Some(RegistryVersion::new(7)),
        Some(Hash32::try_from([0x71; 32].as_slice()).unwrap()),
    );
    assert_ne!(first.exact_bytes(), second.exact_bytes());
    assert!(first.equals_modulo_request_id(&second));

    let decoded = ProtocolErrorV1::decode(first.exact_bytes()).unwrap();
    assert_eq!(decoded.error_code(), "EA-HTTP-NONCE-REPLAY");
    assert_eq!(decoded.request_id(), request_id(1));
    assert!(!decoded.retryable());
    assert_eq!(
        decoded.required_registry_version(),
        Some(RegistryVersion::new(7))
    );
    assert!(decoded.equals_modulo_request_id(&second));
}

fn request_id(seed: u8) -> ea_sync_protocol::RequestIdV1 {
    ea_sync_protocol::RequestIdV1::try_from([seed; 16].as_slice()).unwrap()
}

#[test]
fn only_technical_failures_are_marked_retryable() {
    for error in SyncProtocolError::ALL {
        let body = ProtocolErrorV1::new(error, request_id(0), None, None);
        assert_eq!(
            body.retryable(),
            matches!(error.http_status(), 429 | 500 | 503),
            "{}",
            error.code()
        );
    }
}

#[test]
fn every_error_variant_carries_a_distinct_code_and_a_mapped_status() {
    let mut codes = std::collections::BTreeSet::new();
    for error in SyncProtocolError::ALL {
        assert!(
            error.code().starts_with("EA-HTTP-") || error.code().starts_with("EA-SYNC-"),
            "{}",
            error.code()
        );
        assert!(codes.insert(error.code()), "{} is used twice", error.code());
        assert!(
            matches!(
                error.http_status(),
                400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500 | 503
            ),
            "{} maps to {}",
            error.code(),
            error.http_status()
        );
    }
}

#[test]
fn the_endpoint_table_is_the_closed_seventeen_line_v1_surface() {
    assert_eq!(EndpointV1::ALL.len(), 17);
    let mut paths = std::collections::BTreeSet::new();
    let mut codes = std::collections::BTreeSet::new();
    let mut unsigned = 0;
    let mut proof_of_possession = 0;
    for endpoint in EndpointV1::ALL {
        assert!(
            endpoint.path_template().starts_with("/v1/"),
            "{}",
            endpoint.path_template()
        );
        assert!(paths.insert((endpoint.method(), endpoint.path_template())));
        assert!(codes.insert(endpoint.code()));
        match endpoint.authentication() {
            EndpointAuthentication::Unsigned => unsigned += 1,
            EndpointAuthentication::ProofOfPossession => proof_of_possession += 1,
            EndpointAuthentication::Signed => {}
        }
        assert!(matches!(endpoint.success_status(), 200 | 201 | 202 | 204));
    }
    assert_eq!(unsigned, 2, "challenge endpoint and vault blob retrieval");
    assert_eq!(proof_of_possession, 1, "device registration only");
}

#[test]
fn only_the_object_endpoint_leaves_the_structured_media_type() {
    for endpoint in EndpointV1::ALL {
        match endpoint.response_media_type() {
            Some(media_type) if endpoint == EndpointV1::Objects => {
                assert_eq!(media_type, ea_sync_protocol::OBJECT_MEDIA_TYPE_V1);
            }
            Some(media_type) => {
                assert_eq!(media_type, ea_sync_protocol::STRUCTURED_MEDIA_TYPE_V1);
            }
            // Ein Endpunkt ohne Antwortmedientyp liefert keinen Inhalt aus:
            // 201 und 202 quittieren die Annahme, 204 die Kenntnisnahme.
            None => assert!(
                matches!(endpoint.success_status(), 201 | 202 | 204),
                "{}",
                endpoint.path_template()
            ),
        }
    }
}

/// Jeder strukturierte Rahmen, den diese Crate ausliefert, muss durch seine
/// EXAKTEN Bytes zurueckkommen.
///
/// Der Test ist nicht dekorativ: eine Kodierung mit anderer Arity als ihr
/// Dekodierer faellt sonst erst im Serverpfad auf, und genau diese Bauform hat
/// hier schon einmal danebengelegen.
#[test]
fn every_structured_frame_round_trips_through_its_exact_bytes() {
    use ea_sync_protocol::{
        ArchiveExportManifestV1, CheckpointListResponseV1, DestructionRequestV1,
        DestructionStatusResponseV1, EntryCommitOutcome, EntryCommitResponseV1,
        ExportObjectRecordV1, GrantListResponseV1, HistoricalGrantUploadV1, TrustEventRecordV1,
        TrustEventUploadV1, TrustRegistryResponseV1,
    };
    use ea_types::DestructionId;

    let entry_hash = EntryHash::from(Hash32::try_from([0x81; 32].as_slice()).unwrap());
    let records = vec![
        ObjectRecordV1::new(record_hash(1), b"eins".to_vec()),
        ObjectRecordV1::new(record_hash(2), b"zwei".to_vec()),
    ];

    macro_rules! assert_round_trip {
        ($type:ty, $value:expr) => {{
            let value = $value;
            let decoded = <$type>::decode(value.exact_bytes()).unwrap();
            assert_eq!(
                decoded.exact_bytes(),
                value.exact_bytes(),
                concat!(stringify!($type), " must round trip")
            );
        }};
    }

    assert_round_trip!(
        EntryCommitResponseV1,
        EntryCommitResponseV1::new(EntryCommitOutcome::Accepted, b"receipt".to_vec(), None)
    );
    assert_round_trip!(
        EntryCommitResponseV1,
        EntryCommitResponseV1::new(
            EntryCommitOutcome::IdempotentReplay,
            b"receipt".to_vec(),
            Some(b"checkpoint".to_vec())
        )
    );
    assert_round_trip!(
        TrustEventUploadV1,
        TrustEventUploadV1::new(fixtures::trust_object()).unwrap()
    );
    assert_round_trip!(
        HistoricalGrantUploadV1,
        HistoricalGrantUploadV1::new(fixtures::historical_reader_grant()).unwrap()
    );
    assert_round_trip!(
        DestructionRequestV1,
        DestructionRequestV1::new(fixtures::trust_object()).unwrap()
    );
    assert_round_trip!(
        TrustRegistryResponseV1,
        TrustRegistryResponseV1::new(
            RegistryVersion::new(3),
            vec![
                TrustEventRecordV1::new(RegistryVersion::new(4), record_hash(9), b"a".to_vec()),
                TrustEventRecordV1::new(RegistryVersion::new(5), record_hash(8), b"b".to_vec()),
            ]
        )
        .unwrap()
    );
    assert_round_trip!(
        GrantListResponseV1,
        GrantListResponseV1::new(entry_hash, records.clone()).unwrap()
    );
    assert_round_trip!(
        CheckpointListResponseV1,
        CheckpointListResponseV1::new(None, records.clone(), Some(b"cursor".to_vec())).unwrap()
    );
    assert_round_trip!(
        ArchiveExportManifestV1,
        ArchiveExportManifestV1::new(
            fixtures::organization(),
            vec![
                ExportObjectRecordV1::new(ea_format::ObjectTypeV1::Entry, record_hash(3), 530),
                ExportObjectRecordV1::new(ea_format::ObjectTypeV1::Grant, record_hash(4), 641),
            ],
            Some(b"cursor".to_vec())
        )
        .unwrap()
    );
    assert_round_trip!(
        DestructionStatusResponseV1,
        DestructionStatusResponseV1::new(
            DestructionId::try_from([0x82; 16].as_slice()).unwrap(),
            4,
            record_hash(5),
            records.clone(),
            records
        )
        .unwrap()
    );
}

/// Die drei signierten Protokollkoerper laufen ueber die Codecs von `ea-crypto`
/// und ueber `encode_signed_protocol_wrapper`. Ihr Dekodierer besteht auf
/// Bytegleichheit mit der Eingabe — dieser Test weist nach, dass diese
/// Gleichheit fuer echte, signierte Koerper auch eintritt.
#[test]
fn the_three_signed_protocol_bodies_round_trip_through_their_exact_bytes() {
    use ea_crypto::{
        CanonicalPublicCoseKey, ChallengeResponseCoreV1, CoseSigner,
        DeviceRegistrationRequestCoreV1, ReaderAckCoreV1, SecretBytes,
        encode_challenge_response_core, encode_device_registration_request_core,
        encode_reader_ack_core,
    };
    use ea_sync_protocol::{ChallengeResponseV1, DeviceRegistrationRequestV1, ReaderAckV1};
    use ea_types::{CertificateHash, ChainSequence, DeviceId};

    let signer = CoseSigner::from_secret(SecretBytes::new([0x71; 32]));
    let certificate_hash = CertificateHash::from(ObjectHash::from(
        Hash32::try_from([0x72; 32].as_slice()).unwrap(),
    ));

    let challenge_core = ChallengeResponseCoreV1 {
        organization_id: fixtures::organization(),
        nonce: [0x73; 32],
        issued_at_server: UnixMillis::new(1_800_000_000_000),
        expires_at: UnixMillis::new(1_800_000_060_000),
        server_certificate_hash: certificate_hash,
    };
    let challenge_signature = signer
        .sign_challenge_response(&encode_challenge_response_core(&challenge_core).unwrap())
        .unwrap();
    let challenge = ChallengeResponseV1::new(challenge_core, &challenge_signature).unwrap();
    assert_eq!(
        ChallengeResponseV1::decode(challenge.exact_bytes())
            .unwrap()
            .exact_bytes(),
        challenge.exact_bytes()
    );

    let requested = CoseSigner::from_secret(SecretBytes::new([0x74; 32]));
    let requested_public = CanonicalPublicCoseKey::ed25519(
        *ed25519_dalek::SigningKey::from_bytes(&[0x74; 32])
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    let registration_core = DeviceRegistrationRequestCoreV1 {
        organization_id: fixtures::organization(),
        device_id: DeviceId::try_from([0x75; 16].as_slice()).unwrap(),
        requested_role: 1,
        signing_public_cose_key: requested_public,
        kem_public_cose_key: None,
        supported_format_versions: vec![1],
        supported_suite_ids: vec![ea_types::SUITE_ID_V1.to_owned()],
    };
    let registration_signature = requested
        .sign_enrollment(&encode_device_registration_request_core(&registration_core).unwrap())
        .unwrap();
    let registration =
        DeviceRegistrationRequestV1::new(registration_core, &registration_signature).unwrap();
    assert_eq!(
        DeviceRegistrationRequestV1::decode(registration.exact_bytes())
            .unwrap()
            .exact_bytes(),
        registration.exact_bytes()
    );

    let ack_core = ReaderAckCoreV1 {
        organization_id: fixtures::organization(),
        chain_id: ChainId::try_from([0x76; 16].as_slice()).unwrap(),
        reader_certificate_hash: certificate_hash,
        through_sequence: ChainSequence::new(7),
        head_entry_hash: EntryHash::from(Hash32::try_from([0x77; 32].as_slice()).unwrap()),
        acknowledged_at_device: UnixMillis::new(1_800_000_000_000),
    };
    let ack_signature = signer
        .sign_reader_ack(&encode_reader_ack_core(&ack_core).unwrap())
        .unwrap();
    let ack = ReaderAckV1::new(ack_core, &ack_signature).unwrap();
    assert_eq!(
        ReaderAckV1::decode(ack.exact_bytes())
            .unwrap()
            .exact_bytes(),
        ack.exact_bytes()
    );
}

#[test]
fn a_broken_cbor_parser_budget_is_a_413_and_a_broken_frame_stays_a_400() {
    use ea_cbor::CborError;

    // Tiefen-, Element-, Container- und Tokenbudget sind PARSERGRENZEN. Das
    // Addendum bindet Byte-, Zaehl- und Parsergrenzen gleichermassen auf 413;
    // ein 400 verschoebe genau diese Zeile der Abbildung.
    for error in [
        CborError::ItemLimit,
        CborError::DepthLimit,
        CborError::ContainerLimit,
        CborError::TokenLimit,
    ] {
        assert_eq!(
            SyncProtocolError::Cbor(error).http_status(),
            413,
            "{}",
            error.code()
        );
        assert!(!SyncProtocolError::Cbor(error).retryable());
    }
    // Alles Uebrige bleibt fehlerhafte Rahmung.
    for error in [
        CborError::Indefinite,
        CborError::TrailingBytes,
        CborError::NonMinimal,
        CborError::Float,
        CborError::InvalidUtf8,
        CborError::NonNfc,
        CborError::MapOrder,
        CborError::DuplicateKey,
        CborError::Invalid,
        CborError::Encode,
    ] {
        assert_eq!(
            SyncProtocolError::Cbor(error).http_status(),
            400,
            "{}",
            error.code()
        );
    }
    // Derselbe Schnitt gilt fuer den durchgereichten Formatbefund.
    assert_eq!(
        SyncProtocolError::Format(ea_format::FormatError::Cbor(CborError::DepthLimit))
            .http_status(),
        413
    );
    assert_eq!(
        SyncProtocolError::Format(ea_format::FormatError::Cbor(CborError::TrailingBytes))
            .http_status(),
        400
    );
}

#[test]
fn a_trust_page_is_bounded_by_its_count_and_by_its_bytes() {
    use ea_sync_protocol::{
        MAX_READER_PAGE_BYTES_V1, MAX_TRUST_PAGE_EVENTS_V1, TrustEventRecordV1,
        TrustRegistryResponseV1,
    };

    // Zaehldecke.
    let too_many = (0..=MAX_TRUST_PAGE_EVENTS_V1)
        .map(|index| {
            TrustEventRecordV1::new(
                RegistryVersion::new(index as u64),
                record_hash(u8::try_from(index % 251).unwrap()),
                vec![1],
            )
        })
        .collect();
    assert_eq!(
        TrustRegistryResponseV1::new(RegistryVersion::new(0), too_many)
            .unwrap_err()
            .code(),
        "EA-SYNC-ITEM-LIMIT"
    );

    // Bytedecke: zwei Saetze, die zusammen ueber der Seitendecke liegen. Ohne
    // sie waeren 1 000 `.etb` zu je 4 MiB zaehlbar zulaessig und trotzdem vier
    // Gigabyte.
    let half = MAX_READER_PAGE_BYTES_V1 / 2 + 1;
    let heavy = vec![
        TrustEventRecordV1::new(RegistryVersion::new(1), record_hash(1), vec![0; half]),
        TrustEventRecordV1::new(RegistryVersion::new(2), record_hash(2), vec![0; half]),
    ];
    assert_eq!(
        TrustRegistryResponseV1::new(RegistryVersion::new(0), heavy)
            .unwrap_err()
            .code(),
        "EA-SYNC-BODY-LIMIT"
    );

    // Und dieselbe Decke greift VOR dem Parser.
    assert_eq!(
        TrustRegistryResponseV1::decode(&vec![0u8; MAX_READER_PAGE_BYTES_V1 + 1])
            .unwrap_err()
            .code(),
        "EA-SYNC-BODY-LIMIT"
    );
}

#[test]
fn a_single_object_upload_rejects_every_foreign_object_family() {
    use ea_sync_protocol::{DestructionRequestV1, HistoricalGrantUploadV1, TrustEventUploadV1};

    // Ein `.eip` auf dem Trust-Endpunkt ist wohlgeformt und trotzdem falsch.
    assert_eq!(
        TrustEventUploadV1::new(fixtures::entry())
            .unwrap_err()
            .code(),
        "EA-SYNC-OBJECT-TYPE"
    );
    assert_eq!(
        DestructionRequestV1::new(fixtures::entry())
            .unwrap_err()
            .code(),
        "EA-SYNC-OBJECT-TYPE"
    );
    assert_eq!(
        HistoricalGrantUploadV1::new(fixtures::trust_object())
            .unwrap_err()
            .code(),
        "EA-SYNC-OBJECT-TYPE"
    );
    assert_eq!(
        TrustEventUploadV1::new(fixtures::initial_reader_grant())
            .unwrap_err()
            .code(),
        "EA-SYNC-OBJECT-TYPE"
    );
    // Der Befund ist 422: wohlgeformt, aber unzulaessig.
    assert_eq!(SyncProtocolError::ObjectTypeMismatch.http_status(), 422);
    // Die richtige Familie laeuft durch.
    assert!(TrustEventUploadV1::new(fixtures::trust_object()).is_ok());
    assert!(HistoricalGrantUploadV1::new(fixtures::historical_reader_grant()).is_ok());
}

#[test]
fn the_upload_ceiling_measures_the_object_and_not_the_frame() {
    use ea_sync_protocol::HistoricalGrantUploadV1;

    // Ein `.eag` GENAU auf der Decke muss durch seinen eigenen Rahmen wieder
    // hereinkommen. Waere die Decke einmal auf das Objekt und einmal auf den
    // Rahmen gemessen, wiese `decode` genau die Bytes zurueck, die `new`
    // erzeugt hat.
    let mut at_the_ceiling = ea_format::EAG_PREFIX_V1.to_vec();
    at_the_ceiling.resize(MAX_GRANT_OBJECT_BYTES_V1, 0);
    let upload = HistoricalGrantUploadV1::new(at_the_ceiling.clone()).unwrap();
    assert_eq!(
        HistoricalGrantUploadV1::decode(upload.exact_bytes())
            .unwrap()
            .exact_eag_bytes(),
        at_the_ceiling.as_slice()
    );

    // Ein Byte darueber ist die `.eag`-Decke des Commitpfades, nicht eine
    // allgemeine Koerpergrenze.
    let mut over_the_ceiling = ea_format::EAG_PREFIX_V1.to_vec();
    over_the_ceiling.resize(MAX_GRANT_OBJECT_BYTES_V1 + 1, 0);
    assert_eq!(
        HistoricalGrantUploadV1::new(over_the_ceiling)
            .unwrap_err()
            .code(),
        "EA-SYNC-GRANT-LIMIT"
    );

    // Und ein Koerper jenseits von Decke plus Rahmen faellt vor dem Parser.
    assert_eq!(
        HistoricalGrantUploadV1::decode(&vec![0u8; MAX_GRANT_OBJECT_BYTES_V1 * 2])
            .unwrap_err()
            .code(),
        "EA-SYNC-BODY-LIMIT"
    );
}
