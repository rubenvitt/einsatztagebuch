//! Das Systemziel des Reader-Key-Escrows (v1.1-Profil §11, Scheibe f, WR-075).
//!
//! EIN Durchgang durch die komponierten Teile:
//!
//! 1. Ein Bestand mit einem ersten Eintrag; der Reader wird ERST DANACH
//!    enrollt (die historische Kulisse aus `ea-verify`).
//! 2. Native Root-Zeremonie der Bundle-Freigabe und Zeremonie A über ihre
//!    `test-support`-Eingänge in `ea-admin` — der echte Zeremoniekern mit
//!    echtem SQLCipher-Audit, hinter dem ECHTEN Cutover-Port
//!    (`ActiveWebBundleRelease`); die Laufzeit-Hülle bezeugt der CLI-Zeuge.
//!    Das Paket kommt aus demselben Codec, den der Browser trägt.
//! 3. Offline-Verifikation des Bestands ohne Serverdaten.
//! 4. Live-Server (PostgreSQL und Object Store): Freigabe, Publikations-
//!    freigabe und Escrow einzeln über `publish_trust_event`, in dieser
//!    Reihenfolge.
//! 5. Export über den Exportdienst, Einfuhr in ein FRISCHES Verzeichnis nur
//!    mit dem Anker: dieselben Objekte, derselbe Bericht wie offline. Danach
//!    ist ein zweites Escrow zum selben Reader-Zertifikat ein Konflikt.
//! 6. Zeremonie B: Transport-Schlüssel T aus dem eingeführten Bestand, zwei
//!    Approver binden die Öffnung an T, der echte Öffnungsdienst über das
//!    SQLCipher-Ledger, der Reader öffnet den Umschlag mit T — der KEM ist der
//!    des Zertifikats. Ein Öffnungsversuch mit einem fremden Schlüssel T′
//!    wird abgewiesen, und NACH ihm ist nichts verbraucht (Verbrauch,
//!    Ergebnis, Replay-Schlüssel, Audit).
//! 7. Kanarienvogel: kein Byte des Reader-KEM in Bericht, Export und Audit.
#![allow(clippy::duplicate_mod)]
#[path = "../../../crates/ea-audit/tests/support/mod.rs"]
mod audit_support;
#[path = "../../../crates/ea-recovery/tests/support/mod.rs"]
mod support;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use ea_admin::{
    reader_key_escrow_opening::ReaderKeyEscrowLedger,
    reader_key_escrow_publication::{
        ActiveWebBundleRelease, ReaderKeyEscrowPublicationContext,
        publish_reader_key_escrow_in_context,
    },
    web_bundle_release::{
        WebBundleCeremonyContext, WebBundleRequest, publish_web_bundle_object_in_context,
    },
};
use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_audit::{LocalAuditRepository, SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, HpkeRecipientPrivateKey, ProtectedHeader, SecretBytes,
    object_hash,
};
use ea_format::{
    KeyProtectionProfileV1, ObjectTypeV1, ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1, encode_reader_key_escrow_envelope,
    encode_reader_key_escrow_package,
};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_recovery::{FsArchiveSource, ReaderKeyEscrowError, ReaderKeyEscrowOpeningService};
use ea_sync_server::{
    ObjectStore as _, ServerClock, TrustIndexOutcome,
    trust::{TrustPublishError, TrustServiceError},
};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, escrow_with_approval, seal_reader_kem_key_for_escrow,
    signed_reader_key_escrow_recovery_authorization,
};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustAnchorV1, TrustObjectSource,
    VerifiedTrust, load_trust_state, prepare_local_time, select_registry_head,
    verify_reader_key_escrow_recovery_authorization, verify_registry_candidate, verify_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, SubjectId, UnixMillis,
};
use ea_verify::{
    EphemeralTrustStateStore, VerificationReportV1, VerifyOptions, verification_state_key,
    verify_archive,
};
use ed25519_dalek::{Signer as _, SigningKey};
use einsatzarchiv_server::adapters::{
    postgres::PostgresRepository, s3::S3ObjectStore, server_keys::ServerKeyStore,
    trust_authority::PostgresTrustAuthority,
};
use support::verify_support as fixture;
// Die Audit-Fixture nennt die Trust-Fixture `crate::trust_support`.
use fixture::archive_support::trust_support;

/// Die Uhr des ganzen Durchgangs — Kopfwahl, Zeremonien und Server.
const NOW: i64 = 800;
/// Die Person des Escrows — als Kanarienvogel unverwechselbar.
const ESCROW_SUBJECT: [u8; 16] = [0x5c; 16];

struct Clock(AtomicI64);
impl ServerClock for Clock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}

fn millis(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

fn subject() -> SubjectId {
    SubjectId::try_from(ESCROW_SUBJECT.as_slice()).unwrap()
}

/// Eine COSE_Sign1 im Normalprofil über einen Trust-Digest — derselbe Aufbau,
/// den `KeyProvider::sign` des Autoritätswirts liefert.
fn trust_digest_cose(seed: [u8; 32], certificate: CertificateHash, digest: Hash32) -> Vec<u8> {
    let key = SigningKey::from_bytes(&seed);
    let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes()).unwrap();
    let protected =
        ProtectedHeader::normal(ContentType::TrustDigest, public.thumbprint(), certificate);
    let signature = key.sign(&protected.sig_structure_bytes(digest.as_bytes()));
    let mut bytes = vec![0xd2, 0x84];
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder.bytes(&protected.to_deterministic_cbor()).unwrap();
    encoder.map(0).unwrap();
    encoder.bytes(digest.as_bytes()).unwrap();
    encoder.bytes(&signature.to_bytes()).unwrap();
    bytes
}

fn public(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
        .unwrap()
}

/// Wählt den Kopf `version` über `source`, zur Sequenz `sequence`, und gibt
/// den `VerifiedTrust` DESSELBEN Durchlaufs mit heraus.
fn select_over(
    anchor: &TrustAnchorV1,
    source: &dyn TrustObjectSource,
    sequence: u64,
    version: RegistryVersion,
) -> (VerifiedTrust, SelectedRegistryHead) {
    let key = verification_state_key(anchor.organization_id());
    let mut store = EphemeralTrustStateStore::new(key, millis(NOW));
    loop {
        let snapshot = load_trust_state(&mut store, key).unwrap();
        let trust = verify_trust(anchor, source, snapshot).unwrap();
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(sequence)).unwrap();
        let candidate_version = candidate.registry_version();
        let time = prepare_local_time(&mut store, &candidate, millis(NOW), &[]).unwrap();
        match select_registry_head(candidate, time, None).unwrap() {
            RegistrySelectionOutcome::Selected(head) if candidate_version == version => {
                return (trust, head);
            }
            RegistrySelectionOutcome::Selected(_) | RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => panic!("unexpected future head"),
        }
    }
}

/// Ein Archivverzeichnis auf der Platte: jede Datei unter ihrem Pfadhinweis.
struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ea-e2e-escrow-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn put(&self, hint: &str, bytes: &[u8]) {
        let path = self.0.join(hint);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn put_trust(&self, bytes: &[u8]) {
        self.put(
            &format!(
                "{}{}.etb",
                ea_archive::TRUST_DIR_V1,
                hex::encode(object_hash(bytes).as_bytes())
            ),
            bytes,
        );
    }

    fn source(&self) -> FsArchiveSource {
        FsArchiveSource::open(&self.0).unwrap()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn object_hashes(source: &dyn ArchiveSource) -> BTreeSet<[u8; 32]> {
    let inventory = ArchiveInventory::build(source).unwrap();
    let mut hashes = BTreeSet::new();
    for object in inventory.trust() {
        hashes.insert(*object.object_hash().as_bytes());
    }
    for object in inventory.entries() {
        hashes.insert(*object.object_hash().as_bytes());
    }
    for object in inventory.grants() {
        hashes.insert(*object.object_hash().as_bytes());
    }
    hashes
}

fn report_of(source: &dyn ArchiveSource, anchor: &TrustAnchorV1) -> VerificationReportV1 {
    verify_archive(source, anchor, VerifyOptions::new(millis(NOW))).unwrap()
}

/// Das SQLCipher-Konto des Autoritätswirts: Datenbank, Auditdienst und ein
/// echter Präsenznachweis der Audit-Fixture.
struct Host {
    _root: Directory,
    database: Arc<EncryptedDatabase>,
    audit: SignedLocalAuditService,
    proof: ea_operator::OperatorSessionProof,
}

impl Host {
    fn new() -> Self {
        let root = Directory::new("host");
        let proof = audit_support::AuditHarness::new().operator_session();
        let provider = Arc::new(InMemoryKeyProvider::new_for_test([0x4d; 32]));
        let database_key = provider
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
        let database = Arc::new(
            EncryptedDatabase::open(
                &root.0.join("operator.sqlite"),
                provider.as_ref(),
                &database_key,
            )
            .unwrap(),
        );
        let audit = SignedLocalAuditService::new(
            Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&database)))
                as Arc<dyn LocalAuditRepository>,
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
            signing,
            ObjectHash::try_from([0x33; 32].as_slice()).unwrap(),
            millis(NOW),
        );
        Self {
            _root: root,
            database,
            audit,
            proof,
        }
    }

    fn count(&self, table: &str) -> i64 {
        self.database
            .query_row(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
    }

    fn audit_bytes(&self) -> Vec<Vec<u8>> {
        let mut rows = Vec::new();
        let mut after = 0_i64;
        while let Some(row) = self
            .database
            .query_row(
                "SELECT insertion_sequence,exact_bytes FROM local_audit_event WHERE insertion_sequence>?1 ORDER BY insertion_sequence LIMIT 1",
                &[StoreValue::Integer(after)],
            )
            .unwrap()
        {
            after = row.integer(0).unwrap();
            rows.push(row.blob(1).unwrap().to_vec());
        }
        rows
    }
}

/// Der Escrow-Core des nach dem Eintrag enrollten Readers: sein KEM,
/// versiegelt an den Recovery-Empfänger der Linie.
fn escrow_core(
    material: &fixture::historical::HistoricalFixture,
    issued_at: i64,
) -> ReaderKeyEscrowCoreV1 {
    let reader_head = material
        .line
        .heads()
        .iter()
        .find(|head| {
            head.direct_object_hash.is_some_and(|hash| {
                CertificateHash::from(hash) == material.recipient_certificate_hash
            })
        })
        .copied()
        .expect("the reader enrollment head");
    let recovery = material
        .line
        .heads()
        .iter()
        .filter_map(|head| head.direct_object_hash)
        .find(|hash| {
            let Ok(ea_format::ParsedArchiveObject::Trust(parsed)) =
                ea_format::decode_exact_object(material.line.exact_object_bytes(*hash))
            else {
                return false;
            };
            matches!(
                parsed.value().decoded_payload(),
                Ok(ea_format::DecodedTrustPayloadV1::AuthorizedDevice(fields))
                    if fields.fields().certificate_kind
                        == ea_format::CertificateKindV1::RecoveryRecipient
            )
        })
        .expect("the recovery recipient certificate");
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: material.anchor.organization_id(),
        reader_certificate_object_hash: material.recipient_certificate_hash,
        reader_subject_id: subject(),
        enrollment_registry_version: reader_head.version,
        enrollment_registry_head_hash: Hash32::try_from(
            reader_head.object_hash.as_bytes().as_slice(),
        )
        .unwrap(),
        enrollment_sequence: reader_head.effective_from,
        recovery_certificate_object_hash: CertificateHash::from(recovery),
        recovery_kem_key_thumbprint: fixture::complete_recipient_key_thumbprint(),
        encapsulated_key: [0; 32],
        encrypted_reader_kem_key: [0; 48],
        issued_at: millis(issued_at),
        root_key_thumbprint: public(trust_support::root_signing_secret()).thumbprint(),
    };
    let (encapsulated_key, encrypted) = seal_reader_kem_key_for_escrow(
        &SecretBytes::new(fixture::other_recipient_secret_bytes()),
        *fixture::complete_recipient_private_key()
            .public_key()
            .as_bytes(),
        &core,
    )
    .unwrap();
    core.encapsulated_key = encapsulated_key;
    core.encrypted_reader_kem_key = encrypted;
    core
}

fn root_signer(material: &fixture::historical::HistoricalFixture) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: trust_support::root_signing_secret(),
        certificate_hash: CertificateHash::from(material.line.current_root_hash()),
    }
}

fn admin_signer(material: &fixture::historical::HistoricalFixture) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: trust_support::second_admin_signing_secret(),
        certificate_hash: CertificateHash::from(material.line.second_bootstrap_admin_hash()),
    }
}

/// Die Öffnungsautorisierung beider Approver, gebunden an den Abdruck `target`.
fn recovery_authorization(
    material: &fixture::historical::HistoricalFixture,
    core: &ReaderKeyEscrowCoreV1,
    escrow_hash: ObjectHash,
    target: ea_types::KeyThumbprint,
) -> Vec<u8> {
    let fields = ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        authorization_id: AuthorizationId::try_from([0xe1; 16].as_slice()).unwrap(),
        organization_id: material.anchor.organization_id(),
        registry_version: material.head.version,
        registry_head_hash: Hash32::try_from(material.head.object_hash.as_bytes().as_slice())
            .unwrap(),
        authorization_sequence: material.current_sequence,
        escrow_object_hash: escrow_hash,
        reader_certificate_object_hash: core.reader_certificate_object_hash,
        reader_subject_id: core.reader_subject_id,
        enrollment_registry_version: core.enrollment_registry_version,
        enrollment_registry_head_hash: core.enrollment_registry_head_hash,
        target_transport_key_thumbprint: target,
        issued_at: millis(NOW - 100),
        expires_at: millis(NOW + 600),
        nonce: [0xe2; 32],
    };
    let signers: Vec<_> = material
        .approvers
        .iter()
        .map(|certificate| FixtureTrustSigner {
            seed: trust_support::device_signing_secret(),
            certificate_hash: *certificate,
        })
        .collect();
    signed_reader_key_escrow_recovery_authorization(&fields, &signers)
}

/// Ein Konflikt im Sinne von HTTP 409: als Ausgang des Index oder als Befund.
fn is_conflict(result: &Result<TrustIndexOutcome, TrustPublishError>) -> bool {
    matches!(result, Ok(TrustIndexOutcome::Conflict))
        || matches!(
            result,
            Err(TrustPublishError {
                error: TrustServiceError::Conflict,
                ..
            })
        )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Der eine Durchgang. Braucht `DATABASE_URL` und `EA_OBJECT_STORE_ENDPOINT`
/// (Integrationsdienste).
#[tokio::test]
async fn publish_admit_export_import_and_reopen_a_reader_key_escrow() {
    // 1. Ein erster Eintrag; der Reader wird erst danach enrollt.
    let material = fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1);
    let anchor = &material.anchor;
    let organization_id = anchor.organization_id();
    let base = ArchiveInventory::build(&material.fixture).unwrap();
    assert_eq!(base.entries().len(), 1, "one entry before the reader");
    let reader_enrollment = material
        .line
        .heads()
        .iter()
        .find(|head| {
            head.direct_object_hash.is_some_and(|hash| {
                CertificateHash::from(hash) == material.recipient_certificate_hash
            })
        })
        .unwrap()
        .effective_from;
    let entry_sequence = base.entries()[0].value().manifest().fields().chain_sequence;
    assert!(
        entry_sequence < reader_enrollment,
        "the reader is enrolled after the first entry"
    );

    let offline = Directory::new("offline");
    for (hint, bytes) in material.fixture.blobs() {
        offline.put(hint, bytes);
    }
    let (trust, head) = select_over(
        anchor,
        &base,
        material.current_sequence,
        material.head.version,
    );

    // 2a. Native Root-Zeremonie: die v1.1-Freigabe des Bundles.
    let catalog_bytes: Vec<Vec<u8>> = base
        .trust()
        .iter()
        .map(|object| object.exact_bytes().as_bytes().to_vec())
        .collect();
    let catalog: Vec<&[u8]> = catalog_bytes.iter().map(Vec::as_slice).collect();
    let root_sign = |certificate, digest| {
        Ok(trust_digest_cose(
            trust_support::root_signing_secret(),
            certificate,
            digest,
        ))
    };
    let admin_sign = |certificate, digest| {
        Ok(trust_digest_cose(
            trust_support::second_admin_signing_secret(),
            certificate,
            digest,
        ))
    };
    let released = std::cell::RefCell::new(Vec::new());
    let write_release = |bytes: &[u8]| {
        released.borrow_mut().push(bytes.to_vec());
        offline.put_trust(bytes);
        Ok(())
    };
    let release = publish_web_bundle_object_in_context(
        &WebBundleCeremonyContext {
            anchor,
            head: &head,
            catalog: &catalog,
            reauthenticate: &|_| Ok(()),
            root_sign: &root_sign,
            session_current: &|| Ok(()),
            write: &write_release,
            now: millis(NOW),
        },
        WebBundleRequest::Release {
            bundle_hash: ea_crypto::web_bundle_hash(b"reader bundle with escrow"),
            bundle_version: ea_trust::MIN_ESCROW_BUNDLE_VERSION.to_owned(),
            effective_from: None,
        },
    )
    .unwrap();
    assert_eq!(release.carries_reader_key_escrow, Some(true));

    // 2b. Zeremonie A hinter dem echten Port, Paket aus dem Codec des Browsers.
    let host = Host::new();
    let core = escrow_core(&material, NOW);
    let package = encode_reader_key_escrow_package(&core).unwrap();
    let mut with_release = catalog.clone();
    with_release.push(&release.exact_bytes);
    let distribute = |bytes: &[u8]| {
        offline.put_trust(bytes);
        Ok(())
    };
    let published = publish_reader_key_escrow_in_context(
        &ActiveWebBundleRelease,
        &ReaderKeyEscrowPublicationContext {
            anchor,
            catalog: &with_release,
            distribute: &distribute,
            database: &host.database,
            trust: &trust,
            head: &head,
            audit: &host.audit,
            proof: &host.proof,
            admin_certificate: CertificateHash::from(material.line.second_bootstrap_admin_hash()),
            admin_binding: material.operator_binding,
            admin_sign: &admin_sign,
            root_sign: &root_sign,
            now: millis(NOW),
            session_current: &|| Ok(()),
            fresh_approval_ids: &|| Ok(([0x91; 16], [0x9a; 32])),
        },
        &package,
    )
    .unwrap();
    assert_eq!(host.count("reader_key_escrow_publication"), 1);

    // 3. Offline, ohne Serverdaten: Gate `trust` trägt über die ganze Menge.
    let offline_source = offline.source();
    let offline_report = report_of(&offline_source, anchor);
    // Gate `trust` hat getragen: der Lauf ging über alle Gates, und der
    // Bericht nennt geprüfte Schlüssel.
    assert!(offline_report.public_key_thumbprints().len() > 0);
    assert_eq!(offline_report.entry_package_count(), 1);
    assert_eq!(offline_report.signature_errors().len(), 0);
    assert_eq!(offline_report.quarantined_objects().len(), 0);
    let offline_trust = {
        let inventory = ArchiveInventory::build(&offline_source).unwrap();
        select_over(
            anchor,
            &inventory,
            material.current_sequence,
            material.head.version,
        )
        .0
    };
    let escrows = ea_trust::verify_reader_key_escrows(
        &offline_trust,
        ea_trust::ReaderKeyEscrowHead::CatalogLineTip,
    )
    .unwrap();
    assert_eq!(
        escrows
            .get(published.escrow_object_hash)
            .map(ea_trust::VerifiedReaderKeyEscrow::standing),
        Some(ea_trust::ReaderKeyEscrowStanding::Valid)
    );

    // 4. Live-Server.
    let server = Server::start(anchor, &material).await;
    for object in base.trust() {
        server
            .seed(ObjectTypeV1::Trust, object.exact_bytes().as_bytes())
            .await;
        sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0)")
            .bind(organization_id.as_bytes().as_slice())
            .bind(&object.object_hash().as_bytes()[..16])
            .bind(object.object_hash().as_bytes().as_slice())
            .bind(object.value().subtype().as_str())
            .execute(&server.pool)
            .await
            .unwrap();
    }
    server.seed_entry(&material, &base).await;
    for (name, bytes) in [
        ("webBundleRelease", &release.exact_bytes),
        ("readerKeyEscrowApproval", &published.exact_approval),
        ("readerKeyEscrow", &published.exact_escrow),
    ] {
        let outcome = server.publish(bytes).await;
        assert!(
            matches!(outcome, Ok(TrustIndexOutcome::Indexed)),
            "{name} must be admitted: {:?}",
            outcome.as_ref().err().map(|error| error.error.code())
        );
    }
    // 5. Export über den Exportdienst, Einfuhr in ein frisches Verzeichnis
    //    NUR mit dem Anker.
    let exported = server.export().await;
    let imported = Directory::new("imported");
    for (kind, bytes) in &exported {
        let directory = match kind {
            ObjectTypeV1::Trust => ea_archive::TRUST_DIR_V1,
            ObjectTypeV1::Entry => ea_archive::ENTRIES_DIR_V1,
            ObjectTypeV1::Grant => ea_archive::GRANTS_DIR_V1,
            other => panic!("unexpected exported object type {}", other.code()),
        };
        imported.put(
            &format!(
                "{directory}{}.bin",
                hex::encode(object_hash(bytes).as_bytes())
            ),
            bytes,
        );
    }
    let fresh_anchor = ea_trust::decode_trust_anchor(material.line.exact_anchor_bytes()).unwrap();
    let imported_source = imported.source();
    let offline_hashes = object_hashes(&offline_source);
    assert_eq!(
        object_hashes(&imported_source),
        offline_hashes,
        "same objects offline and imported"
    );
    let imported_report = report_of(&imported_source, &fresh_anchor);
    assert_eq!(
        imported_report.to_canonical_json().unwrap(),
        offline_report.to_canonical_json().unwrap(),
        "the imported archive reports exactly as offline"
    );

    // Ein zweites Escrow zum selben Reader-Zertifikat (eigene Freigabe, eigener
    // Core) ist ein Konflikt; es liegt danach weder im Index noch im Store.
    let second_core = escrow_core(&material, NOW - 1);
    let second_approval = ReaderKeyEscrowApprovalCoreV1 {
        authorization_id: AuthorizationId::try_from([0x93; 16].as_slice()).unwrap(),
        organization_id,
        registry_version: head.registry_version(),
        registry_head_hash: Hash32::try_from(head.registry_head_hash().as_bytes().as_slice())
            .unwrap(),
        authorization_sequence: material.current_sequence,
        admin_key_thumbprint: public(trust_support::second_admin_signing_secret()).thumbprint(),
        admin_certificate_object_hash: CertificateHash::from(
            material.line.second_bootstrap_admin_hash(),
        ),
        admin_operator_binding_object_hash: material.operator_binding,
        escrow_core_hash: Hash32::ZERO,
        reader_certificate_object_hash: material.recipient_certificate_hash,
        reader_subject_id: subject(),
        issued_at: millis(NOW - 1),
        expires_at: millis(NOW - 1 + 300_000),
        nonce: [0x94; 32],
    };
    let (second_approval_bytes, second_escrow_bytes) = escrow_with_approval(
        &second_core,
        &second_approval,
        &admin_signer(&material),
        &root_signer(&material),
    );
    let approval_outcome = server.publish(&second_approval_bytes).await;
    let escrow_outcome = server.publish(&second_escrow_bytes).await;
    // Die Freigabe allein ist Katalogstoff; erst das Escrow kollidiert (409).
    assert!(
        matches!(approval_outcome, Ok(TrustIndexOutcome::Indexed)),
        "the second approval alone is admissible: {:?}",
        approval_outcome
            .as_ref()
            .err()
            .map(|error| error.error.code())
    );
    assert!(
        is_conflict(&escrow_outcome),
        "a second escrow for the same reader certificate conflicts: {:?}",
        escrow_outcome
            .as_ref()
            .err()
            .map(|error| error.error.code())
    );
    assert!(!server.indexed(&second_escrow_bytes).await);

    // 6. Zeremonie B an T, aus dem eingeführten Bestand.
    let transport = ea_reader::ReaderKeyEscrowTransportV1::begin(
        &fresh_anchor,
        &imported_source,
        subject(),
        millis(NOW),
    )
    .unwrap();
    assert!(transport.escrow_object_hash() == published.escrow_object_hash);
    let request = ea_format::decode_reader_key_escrow_transport_request(
        transport.transport_request().unwrap().exact_bytes(),
    )
    .unwrap();
    let authorization_bytes = recovery_authorization(
        &material,
        &core,
        published.escrow_object_hash,
        transport.fingerprint(),
    );
    let outcome = server.publish(&authorization_bytes).await;
    assert!(
        matches!(outcome, Ok(TrustIndexOutcome::Indexed)),
        "the recovery authorization is admitted: {:?}",
        outcome.as_ref().err().map(|error| error.error.code())
    );
    imported.put_trust(&authorization_bytes);
    let (opening_trust, opening_head) = {
        let inventory = ArchiveInventory::build(&imported.source()).unwrap();
        select_over(
            &fresh_anchor,
            &inventory,
            material.current_sequence,
            material.head.version,
        )
    };
    let authorization = verify_reader_key_escrow_recovery_authorization(
        &opening_trust,
        &opening_head,
        &authorization_bytes,
        millis(NOW),
    )
    .unwrap();
    // Ein Öffnungsversuch wie `open_reader_key_escrow`: erst die Typbindung
    // an den autorisierten Transport-Key, dann der echte Öffnungsdienst über
    // das SQLCipher-Ledger.
    let ledger = ReaderKeyEscrowLedger::new(&host.database, &host.audit, &host.proof);
    let recovery_kem = fixture::complete_recipient_private_key();
    let session = || Ok(());
    let service = ReaderKeyEscrowOpeningService::new(&recovery_kem, &ledger, &session);
    let attempt_opening = |transport_public: [u8; 32]| {
        authorization
            .require_target_transport_key(transport_public)
            .map_err(|_| ReaderKeyEscrowError::TransportMismatch)
            .and_then(|target| service.open(&authorization, &target))
    };
    let ledger_state = || {
        [
            "reader_key_escrow_opening",
            "reader_key_escrow_result",
            "operator_admin_replay",
            "local_audit_event",
        ]
        .map(|table| host.count(table))
    };
    // T′: der Versuch mit einem fremden Schlüssel wird abgewiesen, und NACH
    // ihm ist nichts verbraucht — kein Verbrauch, kein Ergebnis, kein
    // Replay-Schlüssel, keine Auditzeile.
    let foreign = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x6e; 32]))
        .unwrap()
        .public_key();
    let before = ledger_state();
    let refused = attempt_opening(*foreign.as_bytes());
    assert_eq!(ledger_state(), before, "nothing consumed");
    assert!(
        refused.err() == Some(ReaderKeyEscrowError::TransportMismatch),
        "the foreign transport key is refused as a transport mismatch"
    );
    // Derselbe Weg mit T öffnet — die Autorisierung ist nicht verbrannt.
    let envelope = attempt_opening(request.target_transport_public_key)
        .unwrap_or_else(|_| panic!("the bound transport key opens"));
    assert_eq!(host.count("reader_key_escrow_opening"), 1, "consumed once");
    let exact_envelope = encode_reader_key_escrow_envelope(&envelope).unwrap();
    let restored = transport.open(&exact_envelope).unwrap();
    assert!(
        restored.kem_key_thumbprint() == fixture::other_recipient_key_thumbprint(),
        "the restored KEM is the certificate's KEM"
    );
    assert!(restored.organization_id() == organization_id);
    assert!(restored.subject_id() == subject());

    // 7. Kanarienvogel: kein Byte des Reader-KEM irgendwo.
    let secret = fixture::other_recipient_secret_bytes();
    let hex_secret = hex::encode(secret);
    for (name, bytes) in [
        (
            "offline report",
            offline_report.to_canonical_json().unwrap().into_bytes(),
        ),
        (
            "imported report",
            imported_report.to_canonical_json().unwrap().into_bytes(),
        ),
        (
            "export",
            exported
                .iter()
                .flat_map(|(_, bytes)| bytes.iter().copied())
                .collect(),
        ),
        ("envelope", exact_envelope.clone()),
        ("audit", host.audit_bytes().concat()),
    ] {
        assert!(!contains(&bytes, &secret), "{name} carries the raw KEM");
        assert!(
            !contains(&bytes, hex_secret.as_bytes()),
            "{name} carries the KEM as hex"
        );
    }

    server.stop().await;
}

/// Der In-Process-Server über echte Adapter.
struct Server {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    database_name: String,
    client: aws_sdk_s3::Client,
    bucket: String,
    clock: Arc<Clock>,
    repo: Arc<PostgresRepository>,
    objects: Arc<S3ObjectStore>,
    authority: PostgresTrustAuthority,
    organization_id: OrganizationId,
}

impl Server {
    async fn start(
        anchor: &TrustAnchorV1,
        material: &fixture::historical::HistoricalFixture,
    ) -> Self {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let database_name = format!("ea_test_escrow_{suffix}");
        let database_url =
            std::env::var("DATABASE_URL").expect("controller-owned integration environment");
        let admin = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{database_name}\""
        )))
        .execute(&admin)
        .await
        .unwrap();
        let (prefix, _) = database_url.rsplit_once('/').unwrap();
        let pool = sqlx::PgPool::connect(&format!("{prefix}/{database_name}"))
            .await
            .unwrap();
        sqlx_core::migrate::Migrator::new(Path::new("../../apps/server/migrations"))
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .http_client(http)
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(std::env::var("EA_OBJECT_STORE_ENDPOINT").unwrap())
            .force_path_style(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "einsatzarchiv",
                "einsatzarchiv",
                None,
                None,
                "escrow-fixture",
            ))
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        let bucket = format!("ea-escrow-{suffix}");
        client.create_bucket().bucket(&bucket).send().await.unwrap();
        let repo = Arc::new(PostgresRepository::new(pool.clone()));
        let clock = Arc::new(Clock(AtomicI64::new(NOW)));
        let objects = Arc::new(S3ObjectStore::new(
            client.clone(),
            bucket.clone(),
            anchor.organization_id(),
            repo.clone(),
            repo.clone(),
            clock.clone(),
        ));
        sqlx::query("INSERT INTO organizations(organization_id,root_key_thumbprint,trust_anchor_bytes,created_at_millis) VALUES($1,$2,$3,0)")
            .bind(anchor.organization_id().as_bytes().as_slice())
            .bind(anchor.root_key_thumbprint().as_bytes().as_slice())
            .bind(material.line.exact_anchor_bytes())
            .execute(&pool)
            .await
            .unwrap();
        let authority = PostgresTrustAuthority::new(pool.clone(), objects.clone());
        Self {
            admin,
            pool,
            database_name,
            client,
            bucket,
            clock,
            repo,
            objects,
            authority,
            organization_id: anchor.organization_id(),
        }
    }

    async fn seed(&self, kind: ObjectTypeV1, bytes: &[u8]) {
        let staged = self
            .objects
            .stage_stream(
                kind,
                aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()),
                1_048_576,
            )
            .await
            .unwrap();
        let stored = self.objects.put_if_absent(staged).await.unwrap();
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,$3,$4,0)")
            .bind(stored.object_hash().as_bytes().as_slice())
            .bind(self.organization_id.as_bytes().as_slice())
            .bind(match kind {
                ObjectTypeV1::Entry => 1_i16,
                ObjectTypeV1::Grant => 2,
                ObjectTypeV1::Trust => 5,
                _ => panic!("only entries, grants and trust objects are seeded"),
            })
            .bind(i64::try_from(bytes.len()).unwrap())
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Der erste Eintrag, sein ursprünglicher Grant und der Kettenkopf — der
    /// vorbestehende, schon angenommene Stand.
    async fn seed_entry(
        &self,
        material: &fixture::historical::HistoricalFixture,
        base: &ArchiveInventory,
    ) {
        self.seed(ObjectTypeV1::Entry, &material.entry_bytes).await;
        self.seed(ObjectTypeV1::Grant, &material.original_bytes)
            .await;
        let entry = &base.entries()[0];
        let manifest = entry.value().manifest().fields();
        let org = self.organization_id.as_bytes().as_slice().to_vec();
        sqlx::query("INSERT INTO entries(entry_hash,organization_id,chain_id,sequence_number,entry_object_hash,initial_grant_plan_hash,receipt_object_hash,device_id,accepted_at_server_millis,registry_version,registry_head_hash) VALUES($1,$2,$3,0,$4,$5,$6,$7,100,$8,$9)")
            .bind(material.entry_hash.as_bytes().as_slice())
            .bind(&org)
            .bind(material.anchor.chain_id().as_bytes().as_slice())
            .bind(entry.object_hash().as_bytes().as_slice())
            .bind(manifest.initial_grant_plan_hash.as_slice())
            .bind(&[0_u8; 32][..])
            .bind(&[0x55_u8; 16][..])
            .bind(i64::try_from(manifest.registry_version.get()).unwrap())
            .bind(manifest.registry_head_hash.as_slice())
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO grants(object_hash,organization_id,entry_hash,recipient_key_thumbprint,grant_kind_code) VALUES($1,$2,$3,$4,'initial')")
            .bind(object_hash(&material.original_bytes).as_bytes().as_slice())
            .bind(&org)
            .bind(material.entry_hash.as_bytes().as_slice())
            .bind(fixture::complete_recipient_key_thumbprint().as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chain_heads(organization_id,chain_id,head_sequence,head_entry_hash,head_accepted_at_server_millis) VALUES($1,$2,0,$3,100)")
            .bind(&org)
            .bind(material.anchor.chain_id().as_bytes().as_slice())
            .bind(material.entry_hash.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn publish(&self, bytes: &[u8]) -> Result<TrustIndexOutcome, TrustPublishError> {
        ea_sync_server::trust::publish_trust_event(
            bytes,
            self.organization_id,
            &ea_sync_server::trust::TrustPorts {
                clock: self.clock.as_ref(),
                objects: self.objects.as_ref(),
                events: self.repo.as_ref(),
                validator: &self.authority,
            },
        )
        .await
    }

    async fn indexed(&self, bytes: &[u8]) -> bool {
        use sqlx::Row as _;
        sqlx::query("SELECT count(*) AS n FROM trust_events WHERE object_hash = $1")
            .bind(object_hash(bytes).as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
            .get::<i64, _>("n")
            == 1
    }

    /// Alle Seiten des Exports, die exakten Bytes je Objekt aus dem Store.
    async fn export(&self) -> Vec<(ObjectTypeV1, Vec<u8>)> {
        let signer = ServerKeyStore::new(
            SecretBytes::new([0x91; 32]),
            CertificateHash::try_from([0x92; 32].as_slice()).unwrap(),
            0,
        )
        .unwrap();
        let ports = ea_sync_server::export::ExportPorts {
            clock: self.clock.as_ref(),
            signer: &signer,
            inventory: self.repo.as_ref(),
        };
        let mut cursor: Option<Vec<u8>> = None;
        let mut objects = Vec::new();
        loop {
            let page = ea_sync_server::export::export_page(
                self.organization_id,
                cursor.as_deref(),
                [0x5e; 16],
                &ports,
            )
            .await
            .unwrap_or_else(|_| panic!("the export page must be planned"));
            for record in page.objects() {
                let bytes = self
                    .objects
                    .get_exact_in(record.kind, record.object_hash)
                    .await
                    .unwrap()
                    .collect()
                    .await
                    .unwrap()
                    .into_bytes()
                    .to_vec();
                assert!(object_hash(&bytes) == record.object_hash);
                objects.push((record.kind, bytes));
            }
            match page.manifest().export_cursor() {
                Some(next) => cursor = Some(next.to_vec()),
                None => break,
            }
        }
        objects
    }

    async fn stop(self) {
        let Self {
            admin,
            pool,
            database_name,
            client,
            bucket,
            repo,
            objects,
            authority,
            ..
        } = self;
        drop(authority);
        drop(objects);
        drop(repo);
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE \"{database_name}\""
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
        let listed = client
            .list_objects_v2()
            .bucket(&bucket)
            .send()
            .await
            .unwrap();
        for object in listed.contents() {
            client
                .delete_object()
                .bucket(&bucket)
                .key(object.key().unwrap())
                .send()
                .await
                .unwrap();
        }
        client.delete_bucket().bucket(&bucket).send().await.unwrap();
    }
}
