//! Die Quittung wird GENAU EINMAL gebildet — und ihre Bytes sind eingefroren.
//!
//! Zwei Aussagen, die dieselbe Zeile aus `design.md`:929 tragen:
//!
//! 1. Im Standardprofil ist `evidence-due-at = null`; im Evidence-Grade-Profil
//!    gilt exakt `accepted-at-server + policy.evidenceMaxDelayMs`, und ein
//!    Ueberlauf ist ungueltig statt gekappt.
//! 2. Die Objektbytes entstehen AUSSCHLIESSLICH ueber
//!    [`ea_format::encode_receipt`]. `ReceiptCoreV1::exact_bytes` liefert die
//!    KERNBYTES; ein Goldtest gegen sie stuende gruen und froere die falschen
//!    Bytes ein. Gelesen wird die Faelligkeit deshalb ueber
//!    `core().fields().evidence_due_at` — derselbe Zugriff, mit dem
//!    `ea_verify::run_evidence_gate` sie liest.
//!
//! Der Goldvektor `vectors/receipts/v1/receipt/accepted-with-evidence-due.bin`
//! ist EINGEFROREN und wird hier nur gelesen. Er traegt seine eigenen Zeiten —
//! `acceptedAtServer = 1_700_000_003_000` und `evidenceDueAt =
//! 1_700_086_400_000` —, also ist seine Evidence-Frist die Differenz der
//! beiden. Die Rechenaussage und die Byteaussage stehen deshalb in ZWEI
//! Zusicherungen und nicht in einer: eine einzige koennte nur eine von beiden
//! treffen.

use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, CryptoError, SecretBytes};
use ea_format::{PolicyFieldsV1, encode_receipt};
use ea_sync_protocol::{TechnicalCursorSigner, TechnicalCursorVerifier};
use ea_sync_server::{
    ServerSigner,
    receipt::{ReceiptBindingV1, ReceiptError, accepted_at, build_receipt},
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};

mod fixtures {
    use super::{
        CanonicalPublicCoseKey, CertificateHash, ChainId, ChainSequence, CoseSigner, CryptoError,
        EntryHash, Hash32, ObjectHash, OrganizationId, PolicyFieldsV1, ReceiptBindingV1,
        RegistryVersion, SecretBytes, ServerSigner, TechnicalCursorSigner, TechnicalCursorVerifier,
    };

    /// Die eingefrorenen Werte von `vectors/receipts/v1`.
    ///
    /// Sie stehen hier als Konstanten, weil `ea-testkit` sie privat haelt und
    /// diese Aufgabe an `crates/ea-testkit` nichts aendert. Der SCHLUESSEL
    /// dagegen wird nicht abgeschrieben: er kommt aus dem oeffentlichen
    /// [`ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED`].
    pub const ORGANIZATION_ID: [u8; 16] = [0x50; 16];
    pub const CHAIN_ID: [u8; 16] = [0x51; 16];
    pub const ENTRY_HASH: [u8; 32] = [0x52; 32];
    pub const ENTRY_OBJECT_HASH: [u8; 32] = [0x53; 32];
    pub const PREVIOUS_ENTRY_HASH: [u8; 32] = [0x54; 32];
    pub const REGISTRY_HEAD_HASH: [u8; 32] = [0x55; 32];
    pub const POLICY_OBJECT_HASH: [u8; 32] = [0x56; 32];
    pub const INITIAL_GRANT_PLAN_HASH: [u8; 32] = [0x57; 32];
    pub const SERVER_CERTIFICATE_HASH: [u8; 32] = [0x59; 32];
    pub const GRANT_OBJECT_HASHES: [[u8; 32]; 3] = [[0x60; 32], [0x61; 32], [0x62; 32]];
    pub const REGISTRY_VERSION: u64 = 11;
    pub const CHAIN_SEQUENCE: u64 = 7;
    pub const ACCEPTED_AT_SERVER_MS: i64 = 1_700_000_003_000;
    pub const EVIDENCE_DUE_AT_MS: i64 = 1_700_086_400_000;

    /// Die Evidence-Frist des Goldvektors — GERECHNET, nicht abgeschrieben.
    ///
    /// Der Vektor traegt Annahmezeit und Faelligkeit; die Richtlinie, aus der
    /// beide entstehen, traegt die DIFFERENZ. Sie hier zu rechnen haelt die
    /// beiden Zahlen aneinander gebunden, statt eine dritte danebenzustellen.
    pub const fn frozen_evidence_delay_ms() -> u64 {
        EVIDENCE_DUE_AT_MS.abs_diff(ACCEPTED_AT_SERVER_MS)
    }

    /// Der Serverschluessel des Goldvektors.
    ///
    /// Ed25519 signiert deterministisch, und dieser Seed ist derselbe, mit dem
    /// `ea-testkit` die eingefrorene Quittung erzeugt hat. Ein anderer Seed
    /// ergaebe andere Signaturbytes und damit ein anderes Objekt.
    pub struct FrozenServerSigner {
        signer: CoseSigner,
        public_key: CanonicalPublicCoseKey,
    }

    impl FrozenServerSigner {
        pub fn new() -> Self {
            let signer = CoseSigner::from_secret(SecretBytes::new(
                ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED,
            ));
            let public_key = signer
                .public_key()
                .expect("a declared Ed25519 seed yields a canonical public key");
            Self { signer, public_key }
        }
    }

    impl ServerSigner for FrozenServerSigner {
        fn certificate_hash(&self) -> CertificateHash {
            certificate_hash(SERVER_CERTIFICATE_HASH)
        }

        fn key_thumbprint(&self) -> ea_types::KeyThumbprint {
            self.public_key.thumbprint()
        }

        fn key_generation(&self) -> u32 {
            1
        }

        fn sign_receipt(&self, exact_receipt_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.signer.sign_receipt(exact_receipt_core)
        }

        fn sign_checkpoint(&self, exact_checkpoint_core: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.signer
                .sign_checkpoint(self.certificate_hash(), exact_checkpoint_core)
        }

        fn sign_challenge_response(
            &self,
            exact_challenge_core: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.signer.sign_challenge_response(exact_challenge_core)
        }
    }

    impl TechnicalCursorSigner for FrozenServerSigner {
        fn sign_technical_cursor_digest(
            &self,
            digest: ea_types::Hash32,
        ) -> Result<Vec<u8>, CryptoError> {
            self.signer
                .sign_technical_cursor(self.certificate_hash(), digest)
        }
    }

    impl TechnicalCursorVerifier for FrozenServerSigner {
        fn verify_technical_cursor_digest(
            &self,
            digest: ea_types::Hash32,
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            ea_crypto::verify_technical_cursor(
                signature,
                &self.public_key,
                self.certificate_hash(),
                digest,
            )
        }
    }

    fn certificate_hash(bytes: [u8; 32]) -> CertificateHash {
        CertificateHash::try_from(bytes.as_slice()).expect("32 bytes")
    }

    fn object_hash(bytes: [u8; 32]) -> ObjectHash {
        ObjectHash::try_from(bytes.as_slice()).expect("32 bytes")
    }

    fn hash32(bytes: [u8; 32]) -> Hash32 {
        Hash32::try_from(bytes.as_slice()).expect("32 bytes")
    }

    /// Das Standardprofil: `operatingProfile = 0`, also `evidence-due-at =
    /// null`, ganz gleich welche Frist die Richtlinie sonst traegt.
    pub fn standard_policy() -> PolicyFieldsV1 {
        policy(0, 500)
    }

    /// Das Evidence-Grade-Profil mit genau dieser Frist.
    pub fn evidence_policy(evidence_max_delay_ms: u64) -> PolicyFieldsV1 {
        policy(1, evidence_max_delay_ms)
    }

    /// Eine technisch vollstaendige Richtlinie. Nur `operating_profile` und
    /// `evidence_max_delay_ms` tragen hier eine Aussage; die uebrigen Felder
    /// sind Pflichtpositionen der Produktion und keine Behauptung dieses
    /// Tests.
    fn policy(operating_profile: u8, evidence_max_delay_ms: u64) -> PolicyFieldsV1 {
        PolicyFieldsV1 {
            organization_id: OrganizationId::try_from(ORGANIZATION_ID.as_slice())
                .expect("16 bytes"),
            policy_version: 1,
            previous_policy_object_hash: None,
            operating_profile,
            max_registry_age_ms: 86_400_000,
            max_future_clock_skew_ms: 60_000,
            registry_expiry_behavior: 0,
            evidence_max_delay_ms,
            reader_inactivity_ms: 900_000,
            reader_trust_refresh_ms: 3_600_000,
            reader_history_access_allowed: false,
            allowed_archive_profile_hashes: Vec::new(),
            backup_frequency_ms: 86_400_000,
            restore_test_interval_ms: 2_592_000_000,
            retention_policy: ea_format::RetentionPolicyFieldsV1 {
                minimum_retention_ms: None,
                destruction_enabled: false,
                eds_privacy_decision_document_hash: None,
            },
            free_text_policy: ea_format::FreeTextPolicyFieldsV1 {
                free_text_allowed: false,
                rule_set_version: "1".to_owned(),
                local_pattern_warning_enabled: true,
            },
            allowed_crypto_suite_ids: vec![ea_crypto::SUITE_ID.to_owned()],
            allowed_format_versions: vec![1],
            effective_from_sequence: ChainSequence::new(0),
        }
    }

    /// Die Bindung des Goldvektors.
    pub fn frozen_binding() -> ReceiptBindingV1 {
        ReceiptBindingV1 {
            organization_id: OrganizationId::try_from(ORGANIZATION_ID.as_slice())
                .expect("16 bytes"),
            chain_id: ChainId::try_from(CHAIN_ID.as_slice()).expect("16 bytes"),
            chain_sequence: ChainSequence::new(CHAIN_SEQUENCE),
            entry_hash: EntryHash::try_from(ENTRY_HASH.as_slice()).expect("32 bytes"),
            entry_object_hash: object_hash(ENTRY_OBJECT_HASH),
            previous_entry_hash: Some(
                EntryHash::try_from(PREVIOUS_ENTRY_HASH.as_slice()).expect("32 bytes"),
            ),
            registry_version: RegistryVersion::new(REGISTRY_VERSION),
            registry_head_hash: hash32(REGISTRY_HEAD_HASH),
            policy_object_hash: object_hash(POLICY_OBJECT_HASH),
            initial_grant_plan_hash: hash32(INITIAL_GRANT_PLAN_HASH),
            initial_grant_object_hashes: GRANT_OBJECT_HASHES
                .iter()
                .map(|bytes| object_hash(*bytes))
                .collect(),
        }
    }

    /// Eine Bindung mit genau EINEM Grant — die kleinste, die
    /// `receipt-core-v1` zulaesst.
    pub fn single_grant_binding() -> ReceiptBindingV1 {
        ReceiptBindingV1 {
            initial_grant_object_hashes: vec![object_hash(GRANT_OBJECT_HASHES[0])],
            ..frozen_binding()
        }
    }

    /// Die EINGEFRORENEN Objektbytes des Evidence-Grade-Vektors.
    pub fn expected_evidence_receipt_bytes() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../vectors/receipts/v1/receipt/accepted-with-evidence-due.bin"),
        )
        .expect("the frozen receipt vector must read")
    }
}

/// Die Evidence-Frist entsteht aus der Richtlinie — einmal, mit exakter
/// Addition.
#[test]
fn evidence_due_time_is_signed_once_from_receipt_policy() {
    let signer = fixtures::FrozenServerSigner::new();

    let standard = build_receipt(
        fixtures::single_grant_binding(),
        &fixtures::standard_policy(),
        UnixMillis::new(100),
        &signer,
    )
    .expect("a standard receipt is well formed");
    assert_eq!(standard.core().fields().evidence_due_at, None);

    let evidence = build_receipt(
        fixtures::single_grant_binding(),
        &fixtures::evidence_policy(500),
        UnixMillis::new(100),
        &signer,
    )
    .expect("an evidence receipt is well formed");
    assert_eq!(
        evidence.core().fields().evidence_due_at,
        Some(UnixMillis::new(600))
    );
}

/// Dieselbe Bildung, gegen die EINGEFRORENEN Objektbytes.
///
/// Gelesen werden die Objektbytes ueber [`encode_receipt`] und ausdruecklich
/// NICHT ueber `ReceiptCoreV1::exact_bytes`: jene sind die Kernbytes, und ein
/// Vergleich gegen sie wuerde gruen stehen, ohne das Objekt zu treffen.
#[test]
fn the_built_receipt_is_byte_identical_to_the_frozen_vector() {
    let signer = fixtures::FrozenServerSigner::new();
    let receipt = build_receipt(
        fixtures::frozen_binding(),
        &fixtures::evidence_policy(fixtures::frozen_evidence_delay_ms()),
        UnixMillis::new(fixtures::ACCEPTED_AT_SERVER_MS),
        &signer,
    )
    .expect("the frozen receipt is well formed");

    assert_eq!(
        receipt.core().fields().evidence_due_at,
        Some(UnixMillis::new(fixtures::EVIDENCE_DUE_AT_MS))
    );
    assert_eq!(
        encode_receipt(&receipt)
            .expect("encoding the frozen receipt cannot fail")
            .as_bytes(),
        fixtures::expected_evidence_receipt_bytes().as_slice()
    );
}

/// Eine ueberlaufende Frist ist UNGUELTIG und wird nicht gekappt.
#[test]
fn an_overflowing_evidence_delay_is_rejected_instead_of_saturated() {
    let signer = fixtures::FrozenServerSigner::new();
    let failure = build_receipt(
        fixtures::single_grant_binding(),
        &fixtures::evidence_policy(u64::MAX),
        UnixMillis::new(fixtures::ACCEPTED_AT_SERVER_MS),
        &signer,
    )
    .err()
    .expect("an overflowing evidence delay must not produce a receipt");
    assert_eq!(failure, ReceiptError::EvidenceOverflow);
    assert_eq!(failure.code(), "EA-RECEIPT-EVIDENCE-OVERFLOW");
}

/// Die Annahmezeit faellt je Kette nie unter die des Vorgaengers.
#[test]
fn accepted_time_never_precedes_prior_receipt() {
    assert_eq!(
        accepted_at(UnixMillis::new(90), Some(UnixMillis::new(100))),
        UnixMillis::new(100)
    );
    assert_eq!(
        accepted_at(UnixMillis::new(120), Some(UnixMillis::new(100))),
        UnixMillis::new(120)
    );
    // Die erste Sequenz einer Kette hat keinen Vorgaenger; dann gilt die
    // Serverzeit unveraendert.
    assert_eq!(accepted_at(UnixMillis::new(90), None), UnixMillis::new(90));
}

/// Doppelte Grant-Hashes sind ein Befund und keine still entfernte Dublette.
#[test]
fn duplicate_grant_hashes_are_rejected() {
    let signer = fixtures::FrozenServerSigner::new();
    let mut binding = fixtures::frozen_binding();
    binding.initial_grant_object_hashes[1] = binding.initial_grant_object_hashes[0];
    let failure = build_receipt(
        binding,
        &fixtures::standard_policy(),
        UnixMillis::new(fixtures::ACCEPTED_AT_SERVER_MS),
        &signer,
    )
    .err()
    .expect("a duplicate grant hash must not produce a receipt");
    assert_eq!(failure, ReceiptError::GrantHashes);
}

/// Unsortiert gelieferte Grant-Hashes werden SORTIERT, nicht abgewiesen: die
/// Sortierung gehoert zur Quittung und nicht zum Aufrufer.
#[test]
fn unsorted_grant_hashes_are_sorted_into_the_receipt() {
    let signer = fixtures::FrozenServerSigner::new();
    let mut binding = fixtures::frozen_binding();
    binding.initial_grant_object_hashes.reverse();
    let receipt = build_receipt(
        binding,
        &fixtures::evidence_policy(fixtures::frozen_evidence_delay_ms()),
        UnixMillis::new(fixtures::ACCEPTED_AT_SERVER_MS),
        &signer,
    )
    .expect("an unsorted delivery still yields the one sorted receipt");
    assert_eq!(
        encode_receipt(&receipt)
            .expect("encoding cannot fail")
            .as_bytes(),
        fixtures::expected_evidence_receipt_bytes().as_slice()
    );
}
