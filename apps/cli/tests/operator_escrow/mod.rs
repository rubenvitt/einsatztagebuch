// Die Reader-Key-Escrow-Kommandos gegen die echte native Laufzeit (DRK-458):
// Sperre der Publikation, Öffnung mit Software- und modulgestütztem
// Recovery-Schlüssel, einmalige Auslieferung, abgelaufene Sitzung VOR dem
// Verbrauch und die Kanarienvogelsuche durch Ausgabe, Dateinamen und Audit.
use super::*;
use ea_crypto::{HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open};
use ea_format::{
    ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1, ReaderKeyEscrowTransferKindV1,
    ReaderKeyEscrowTransportRequestV1, encode_reader_key_escrow_package,
    encode_reader_key_escrow_transport_request, reader_key_escrow_transfer_file_name,
};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, escrow_with_approval, seal_reader_kem_key_for_escrow,
    signed_reader_key_escrow_recovery_authorization,
};
use ea_types::{AuthorizationId, KeyThumbprint, SubjectId};
use support::verify_support as fixture;

/// Die Person des Escrows — als Kanarienvogel unverwechselbar.
const ESCROW_SUBJECT: [u8; 16] = [0x5c; 16];
/// Der flüchtige Ziel-Transport-Schlüssel des Browsers.
const TRANSPORT_SEED: [u8; 32] = [0xb4; 32];
/// Die PIN der modulgestützten Variante — als Kanarienvogel unverwechselbar.
const ESCROW_PIN: &str = "12345678";

fn x25519_public(seed: [u8; 32]) -> [u8; 32] {
    *HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
        .unwrap()
        .public_key()
        .as_bytes()
}

fn thumbprint_of(seed: [u8; 32]) -> KeyThumbprint {
    CanonicalPublicCoseKey::x25519(x25519_public(seed))
        .unwrap()
        .thumbprint()
}

/// Ein installierter Admin-Wirt mit veröffentlichtem Escrow im Bestand.
struct EscrowInstallation {
    directory: support::TempDir,
    anchor: PathBuf,
    config: PathBuf,
    database: PathBuf,
    inbox: PathBuf,
    outbox: PathBuf,
    material: fixture::historical::HistoricalFixture,
    core: ReaderKeyEscrowCoreV1,
    escrow_hash: ObjectHash,
}

impl EscrowInstallation {
    fn new(name: &str, purpose: &str) -> Self {
        let directory = support::temp_dir(name);
        install_fixture_helper(directory.path());
        fs::write(directory.path().join("authority-fixture"), b"").unwrap();
        let subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
        let mut material = fixture::historical::fixture_with_host_options(
            |_, _| fixture::COMPLETE_PLAINTEXT_V1.to_vec(),
            Some(fixture::historical::HostOptions {
                not_after: support::LIVE_WRITER_NOT_AFTER_V1,
                max_age: support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                instance: ADMIN_INSTANCE_SECRET,
                account_hash: native_account_hash_for(
                    true,
                    DeviceId::try_from(&[0x52; 16][..]).unwrap(),
                ),
                commitment: ea_crypto::operator_profile_commitment(
                    trust_support::organization(),
                    subject,
                    TEST_NAME,
                    TEST_FUNCTION,
                    &PROFILE_SALT,
                ),
            }),
        );
        let now = support::live_clock().get();
        let core = escrow_core(&material, now - 60_000);
        let (approval, escrow) = escrow_with_approval(
            &core,
            &approval_core(&material, now - 60_000),
            &FixtureTrustSigner {
                seed: trust_support::second_admin_signing_secret(),
                certificate_hash: CertificateHash::from(
                    material.line.second_bootstrap_admin_hash(),
                ),
            },
            &FixtureTrustSigner {
                seed: trust_support::root_signing_secret(),
                certificate_hash: CertificateHash::from(material.line.current_root_hash()),
            },
        );
        let escrow_hash = ea_crypto::object_hash(&escrow);
        material
            .fixture
            .push_exact_bytes("trust/reader-key-escrow-approval.etb", approval);
        material
            .fixture
            .push_exact_bytes("trust/reader-key-escrow.etb", escrow);
        let archive = directory.path().join("archive");
        support::materialize(&material.fixture, &archive);
        let anchor = directory.path().join("independent-anchor.etb");
        fs::write(&anchor, material.line.exact_anchor_bytes()).unwrap();
        let database = directory.path().join("operator.sqlite");
        let (provider, key) = database_provider_for(true);
        let db = EncryptedDatabase::open(&database, &provider, &key).unwrap();
        db.execute(
            "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
            &[
                StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                StoreValue::Blob(subject.as_bytes().to_vec()),
                StoreValue::Text(TEST_NAME.into()),
                StoreValue::Text(TEST_FUNCTION.into()),
                StoreValue::Blob(PROFILE_SALT.to_vec()),
                StoreValue::Blob(material.operator_binding.as_bytes().to_vec()),
            ],
        )
        .unwrap();
        drop(db);
        let config = directory.path().join("operator.json");
        let mut value = json!({
            "archive_directory":"archive","database_path":"operator.sqlite",
            "device_certificate_hash":hex::encode(material.line.second_bootstrap_admin_hash().as_bytes()),
            "binding_object_hash":hex::encode(material.operator_binding.as_bytes()),
            "role":"organization-admin","purpose":purpose
        });
        if purpose == "admin-root-ceremony" {
            value["authority"] = json!(true);
            value["target_certificate_hash"] =
                json!(hex::encode(material.recipient_certificate_hash.as_bytes()));
        }
        fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        let inbox = directory.path().join("escrow-inbox");
        let outbox = directory.path().join("escrow-outbox");
        fs::create_dir(&inbox).unwrap();
        fs::create_dir(&outbox).unwrap();
        Self {
            directory,
            anchor,
            config,
            database,
            inbox,
            outbox,
            material,
            core,
            escrow_hash,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Die Öffnungsautorisierung zweier Approver gegen den gewählten Kopf.
    fn authorization(&self, id: u8, transport_seed: [u8; 32]) -> PathBuf {
        let now = support::live_clock().get();
        let fields = ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
            authorization_id: AuthorizationId::try_from([id; 16].as_slice()).unwrap(),
            organization_id: self.material.anchor.organization_id(),
            registry_version: self.material.head.version,
            registry_head_hash: Hash32::try_from(
                self.material.head.object_hash.as_bytes().as_slice(),
            )
            .unwrap(),
            authorization_sequence: self.material.current_sequence,
            escrow_object_hash: self.escrow_hash,
            reader_certificate_object_hash: self.core.reader_certificate_object_hash,
            reader_subject_id: self.core.reader_subject_id,
            enrollment_registry_version: self.core.enrollment_registry_version,
            enrollment_registry_head_hash: self.core.enrollment_registry_head_hash,
            target_transport_key_thumbprint: thumbprint_of(transport_seed),
            issued_at: UnixMillis::new(now - 1_000),
            expires_at: UnixMillis::new(now + 600_000),
            nonce: [id.wrapping_add(0x10); 32],
        };
        let signers: Vec<_> = self
            .material
            .approvers
            .iter()
            .map(|certificate| FixtureTrustSigner {
                seed: trust_support::device_signing_secret(),
                certificate_hash: *certificate,
            })
            .collect();
        let path = self.path(&format!("authorization-{id:02x}.etb"));
        fs::write(
            &path,
            signed_reader_key_escrow_recovery_authorization(&fields, &signers),
        )
        .unwrap();
        path
    }

    /// Legt eine Transportdatei für dieses Escrow in die Inbox.
    fn transport(&self, seed: [u8; 32]) -> PathBuf {
        let bytes =
            encode_reader_key_escrow_transport_request(&ReaderKeyEscrowTransportRequestV1 {
                organization_id: self.material.anchor.organization_id(),
                escrow_object_hash: self.escrow_hash,
                target_transport_public_key: x25519_public(seed),
            })
            .unwrap();
        let path = self.inbox.join(reader_key_escrow_transfer_file_name(
            ReaderKeyEscrowTransferKindV1::TransportRequest,
            &bytes,
        ));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn run(&self, arguments: &[&str], marker: Option<&str>) -> std::process::Output {
        if let Some(marker) = marker {
            fs::write(self.path(marker), b"").unwrap();
        }
        let mut full = vec!["--trust-anchor", self.anchor.to_str().unwrap()];
        full.extend_from_slice(arguments);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_native::fixture_cli",
                "--nocapture",
            ])
            .env("EA_OPERATOR_FIXTURE_DIRECTORY", self.directory.path())
            .env(
                "EA_OPERATOR_FIXTURE_ARGS",
                serde_json::to_string(&full.iter().map(|a| a.to_string()).collect::<Vec<_>>())
                    .unwrap(),
            )
            .output()
            .unwrap();
        if let Some(marker) = marker {
            fs::remove_file(self.path(marker)).unwrap();
        }
        output
    }

    fn open(&self, recovery_key: &str, authorization: &Path) -> std::process::Output {
        self.open_marked(recovery_key, authorization, None)
    }

    /// Eine Öffnung mit einem Fixture-Marker für den Laufzeitöffner.
    fn open_marked(
        &self,
        recovery_key: &str,
        authorization: &Path,
        marker: Option<&str>,
    ) -> std::process::Output {
        self.run(
            &[
                "reader-key-escrow",
                "open",
                "--operator-config",
                self.config.to_str().unwrap(),
                "--recovery-key",
                recovery_key,
                "--authorization",
                authorization.to_str().unwrap(),
                "--escrow-inbox",
                self.inbox.to_str().unwrap(),
                "--escrow-outbox",
                self.outbox.to_str().unwrap(),
            ],
            marker,
        )
    }

    fn pickup(&self, authorization: &Path) -> std::process::Output {
        self.pickup_marked(authorization, None)
    }

    /// Eine Abholung mit einem Fixture-Marker für den Laufzeitöffner.
    fn pickup_marked(&self, authorization: &Path, marker: Option<&str>) -> std::process::Output {
        self.run(
            &[
                "reader-key-escrow",
                "pickup",
                "--operator-config",
                self.config.to_str().unwrap(),
                "--authorization",
                authorization.to_str().unwrap(),
                "--escrow-inbox",
                self.inbox.to_str().unwrap(),
                "--escrow-outbox",
                self.outbox.to_str().unwrap(),
            ],
            marker,
        )
    }

    fn software_recovery_key(&self) -> String {
        let path = self.path("recovery.key");
        fs::write(&path, fixture::complete_recipient_secret_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn database(&self) -> EncryptedDatabase {
        let (provider, key) = database_provider_for(true);
        EncryptedDatabase::open_existing(&self.database, &provider, &key).unwrap()
    }

    fn count(&self, table: &str) -> i64 {
        self.database()
            .query_row(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap()
    }

    /// Alle dekodierten Auditzeilen, in Buchungsfolge.
    fn audit_rows(&self) -> Vec<ea_format::LocalAuditEventV1> {
        let database = self.database();
        let mut rows = Vec::new();
        let mut after = 0_i64;
        while let Some(row) = database
            .query_row(
                "SELECT insertion_sequence,exact_bytes FROM local_audit_event WHERE insertion_sequence>?1 ORDER BY insertion_sequence LIMIT 1",
                &[StoreValue::Integer(after)],
            )
            .unwrap()
        {
            after = row.integer(0).unwrap();
            rows.push(ea_format::decode_local_audit_event(row.blob(1).unwrap()).unwrap());
        }
        rows
    }

    fn escrow_outcomes(&self) -> Vec<LocalAuditOutcomeV1> {
        self.audit_rows()
            .into_iter()
            .filter(|row| matches!(row.action(), LocalAuditActionV1::ReaderKeyEscrowOpening(_)))
            .map(|row| row.outcome())
            .collect()
    }

    /// Die einzige Umschlagdatei im Ausgang, geöffnet mit dem privaten
    /// Transport-Schlüssel des Browsers.
    fn restored_reader_kem(&self) -> SecretBytes<32> {
        let files: Vec<_> = fs::read_dir(&self.outbox)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "exactly the sealed envelope is written");
        let bytes = fs::read(&files[0]).unwrap();
        assert_eq!(
            files[0].file_name().unwrap().to_str().unwrap(),
            reader_key_escrow_transfer_file_name(ReaderKeyEscrowTransferKindV1::Envelope, &bytes)
        );
        let envelope = ea_format::decode_reader_key_escrow_envelope(&bytes).unwrap();
        let context = envelope.restore_context.encode();
        hpke_open(
            &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(TRANSPORT_SEED)).unwrap(),
            &HpkeSealed::from_parts(envelope.encapsulated_key, envelope.sealed_reader_kem_key)
                .unwrap(),
            &hpke_info(&context),
            &hpke_aad(&context),
        )
        .unwrap()
    }

    /// Kanarienvogelsuche: weder Pfad, PIN, Label noch Person stehen in
    /// Ausgabe, Dateinamen oder Auditbytes. Die 32 Klartextbytes des
    /// Reader-KEM und der Recovery-Seed stehen darüber hinaus auch nicht im
    /// INHALT der Ausgangsdateien und nicht in einem gespeicherten Umschlag —
    /// weder roh noch als Hex oder Base64 (review-c P3-3).
    fn assert_no_canaries(&self, outputs: &[&std::process::Output]) {
        let subject_hex = hex::encode(ESCROW_SUBJECT);
        let mut haystacks: Vec<Vec<u8>> = Vec::new();
        for output in outputs {
            haystacks.push(output.stdout.clone());
            haystacks.push(output.stderr.clone());
        }
        let mut outbox_contents = Vec::new();
        for entry in fs::read_dir(&self.outbox).unwrap() {
            let entry = entry.unwrap();
            haystacks.push(entry.file_name().into_encoded_bytes());
            outbox_contents.push(fs::read(entry.path()).unwrap());
        }
        for row in self.audit_rows() {
            haystacks.push(row.exact_bytes().to_vec());
        }
        let directory = self.directory.path().to_str().unwrap().as_bytes().to_vec();
        for haystack in &haystacks {
            let text = String::from_utf8_lossy(haystack);
            assert!(!text.contains(&subject_hex), "subject id leaked");
            assert!(!text.contains(ESCROW_PIN), "pin leaked");
            assert!(!text.contains("drk250-fixture"), "token label leaked");
            assert!(!text.contains("pin-file"), "key source leaked");
            assert!(!contains(haystack, &directory), "path leaked");
            assert!(!contains(haystack, &ESCROW_SUBJECT), "raw subject id leaked");
        }
        // Die Person steht legitim im Restore-Kontext des Umschlags; dort
        // wird nur nach den Schlüsselbytes gesucht.
        let mut secret_haystacks = haystacks;
        secret_haystacks.extend(outbox_contents);
        let database = self.database();
        let mut after = Vec::new();
        while let Some(row) = database
            .query_row(
                "SELECT authorization_object_hash,exact_envelope FROM reader_key_escrow_result WHERE authorization_object_hash>?1 ORDER BY authorization_object_hash LIMIT 1",
                &[StoreValue::Blob(after.clone())],
            )
            .unwrap()
        {
            after = row.blob(0).unwrap().to_vec();
            secret_haystacks.push(row.blob(1).unwrap().to_vec());
        }
        for (name, secret) in [
            ("reader KEM", fixture::other_recipient_secret_bytes()),
            ("recovery seed", fixture::complete_recipient_secret_bytes()),
        ] {
            let encodings = secret_encodings(&secret);
            for haystack in &secret_haystacks {
                for encoding in &encodings {
                    assert!(!contains(haystack, encoding), "{name} leaked");
                }
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Ein Geheimnis roh, als Hex (klein und groß) und als Base64 (Standard und
/// URL-sicher, je mit und ohne Auffüllung).
fn secret_encodings(secret: &[u8; 32]) -> Vec<Vec<u8>> {
    const STANDARD: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let base64 = |alphabet: &[u8; 64], pad: bool| {
        let mut encoded = Vec::new();
        for chunk in secret.chunks(3) {
            let bits = chunk
                .iter()
                .enumerate()
                .fold(0_u32, |bits, (index, byte)| {
                    bits | u32::from(*byte) << (16 - 8 * index)
                });
            for position in 0..=chunk.len() {
                encoded.push(alphabet[((bits >> (18 - 6 * position)) & 0x3f) as usize]);
            }
            if pad {
                encoded.extend(std::iter::repeat_n(b'=', 3 - chunk.len()));
            }
        }
        encoded
    };
    vec![
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
        base64(STANDARD, true),
        base64(STANDARD, false),
        base64(URL_SAFE, true),
        base64(URL_SAFE, false),
    ]
}

/// Der Core des Escrows: der Reader-KEM der Fixture, versiegelt an ihren
/// Recovery-Empfänger.
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
                    if fields.fields().certificate_kind == CertificateKindV1::RecoveryRecipient
            )
        })
        .expect("the recovery recipient certificate");
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: material.anchor.organization_id(),
        reader_certificate_object_hash: material.recipient_certificate_hash,
        reader_subject_id: SubjectId::try_from(ESCROW_SUBJECT.as_slice()).unwrap(),
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
        issued_at: UnixMillis::new(issued_at),
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

fn approval_core(
    material: &fixture::historical::HistoricalFixture,
    issued_at: i64,
) -> ReaderKeyEscrowApprovalCoreV1 {
    ReaderKeyEscrowApprovalCoreV1 {
        authorization_id: AuthorizationId::try_from([0x91; 16].as_slice()).unwrap(),
        organization_id: material.anchor.organization_id(),
        registry_version: material.head.version,
        registry_head_hash: Hash32::try_from(material.head.object_hash.as_bytes().as_slice())
            .unwrap(),
        authorization_sequence: material.current_sequence,
        admin_key_thumbprint: public(trust_support::second_admin_signing_secret()).thumbprint(),
        admin_certificate_object_hash: CertificateHash::from(
            material.line.second_bootstrap_admin_hash(),
        ),
        admin_operator_binding_object_hash: material.operator_binding,
        escrow_core_hash: Hash32::ZERO,
        reader_certificate_object_hash: material.recipient_certificate_hash,
        reader_subject_id: SubjectId::try_from(ESCROW_SUBJECT.as_slice()).unwrap(),
        issued_at: UnixMillis::new(issued_at),
        expires_at: UnixMillis::new(issued_at + 300_000),
        nonce: [0x9a; 32],
    }
}

/// Pflicht bis (f): die Publikation endet als erster Schritt mit Exit 21 —
/// keine Präsenz, keine Signatur, keine Sperr-, Publikations- oder
/// Auditzeile, keine Datei.
#[test]
fn reader_key_escrow_publish_is_locked_before_any_side_effect() {
    let installation = EscrowInstallation::new("escrow-publish-locked", "admin-root-ceremony");
    let package = encode_reader_key_escrow_package(&installation.core).unwrap();
    fs::write(
        installation
            .inbox
            .join(reader_key_escrow_transfer_file_name(
                ReaderKeyEscrowTransferKindV1::Package,
                &package,
            )),
        &package,
    )
    .unwrap();
    let output = installation.run(
        &[
            "organization",
            "reader-key-escrow-publish",
            "--operator-config",
            installation.config.to_str().unwrap(),
            "--escrow-inbox",
            installation.inbox.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(21),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("EA-ESCROW-CUTOVER-NOT-READY"));
    let calls = fs::read_to_string(installation.path("helper-calls")).unwrap_or_default();
    for forbidden in [
        "sign operator-instance",
        "sign admin-signing",
        "sign root-signing",
    ] {
        assert!(!calls.contains(forbidden), "{forbidden}");
    }
    assert_eq!(installation.count("operator_admin_replay"), 0);
    assert_eq!(installation.count("reader_key_escrow_publication"), 0);
    assert_eq!(installation.count("local_audit_event"), 0);
    assert_eq!(fs::read_dir(&installation.outbox).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&installation.inbox).unwrap().count(), 1);
}

/// Pflichtzeuge: eine abgelaufene Sitzung VOR dem Verbrauch bucht
/// `sessionExpired` (DRK-282-Pfad), verbraucht nichts, und dieselbe
/// Autorisierung gelingt danach. Die Auslieferung ist einmalig.
#[test]
fn reader_key_escrow_open_delivers_the_envelope_once_through_the_cli() {
    let installation = EscrowInstallation::new("escrow-open", "reader-key-escrow-recovery");
    installation.transport(TRANSPORT_SEED);
    let authorization = installation.authorization(0xf1, TRANSPORT_SEED);
    let recovery = installation.software_recovery_key();

    // Die Laufzeit läuft während der Zeremonie ab, vor dem Verbrauch.
    let expired = installation.run(
        &[
            "reader-key-escrow",
            "open",
            "--operator-config",
            installation.config.to_str().unwrap(),
            "--recovery-key",
            &recovery,
            "--authorization",
            authorization.to_str().unwrap(),
            "--escrow-inbox",
            installation.inbox.to_str().unwrap(),
            "--escrow-outbox",
            installation.outbox.to_str().unwrap(),
        ],
        Some("escrow-stale-runtime"),
    );
    assert_eq!(
        expired.status.code(),
        Some(12),
        "{}",
        String::from_utf8_lossy(&expired.stderr)
    );
    assert!(String::from_utf8_lossy(&expired.stderr).contains("EA-ESCROW-OPERATOR-UNAUTHORIZED"));
    assert!(
        installation
            .audit_rows()
            .iter()
            .any(|row| matches!(row.action(), LocalAuditActionV1::SessionExpired(_))),
        "the expiry is booked as sessionExpired"
    );
    assert_eq!(installation.count("reader_key_escrow_opening"), 0);
    assert_eq!(installation.count("operator_admin_replay"), 0);
    assert_eq!(fs::read_dir(&installation.outbox).unwrap().count(), 0);

    // Dieselbe Autorisierung öffnet danach.
    let opened = installation.open(&recovery, &authorization);
    assert_eq!(
        opened.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    let stdout = String::from_utf8_lossy(&opened.stdout);
    let report = stdout
        .lines()
        .find(|line| line.starts_with("reader-key-escrow opened "))
        .expect("the hash-only report line");
    let authorization_hash =
        hex::encode(ea_crypto::object_hash(&fs::read(&authorization).unwrap()).as_bytes());
    assert!(report.contains(&format!("authorization={authorization_hash}")));
    assert!(
        installation
            .restored_reader_kem()
            .matches(&fixture::other_recipient_secret_bytes())
    );
    assert_eq!(
        installation.escrow_outcomes(),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    assert_eq!(installation.count("reader_key_escrow_result"), 0);
    assert_eq!(installation.count("reader_key_escrow_result_closure"), 1);

    // Einmalig: dieselbe Autorisierung ist verbraucht, die Abholung ist
    // abgeschlossen.
    let again = installation.open(&recovery, &authorization);
    assert_eq!(again.status.code(), Some(12));
    assert!(String::from_utf8_lossy(&again.stderr).contains("EA-TRUST-AUTH-REPLAY"));
    let pickup = installation.pickup(&authorization);
    assert_eq!(pickup.status.code(), Some(12));
    assert!(String::from_utf8_lossy(&pickup.stderr).contains("EA-ESCROW-RESULT-DELIVERED"));
    installation.assert_no_canaries(&[&expired, &opened, &again, &pickup]);
}

/// Die echte modulgestützte Öffnung: der Recovery-KEM liegt nicht
/// exportierbar im SoftHSM-Token (`id=c1`), die PIN kommt aus einer Datei.
#[cfg(feature = "pkcs11-fixture")]
#[test]
fn reader_key_escrow_open_uses_the_nonexporting_pkcs11_recovery_key() {
    use std::os::unix::fs::OpenOptionsExt as _;
    let installation = EscrowInstallation::new("escrow-pkcs11", "reader-key-escrow-recovery");
    installation.transport(TRANSPORT_SEED);
    let authorization = installation.authorization(0xf2, TRANSPORT_SEED);
    let module = std::env::var("EA_TEST_PKCS11_MODULE").expect("explicit isolated module required");
    let pin = installation.path("pin.txt");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    std::io::Write::write_all(&mut options.open(&pin).unwrap(), ESCROW_PIN.as_bytes()).unwrap();
    let source = format!(
        "pkcs11:module={module};token=drk250-fixture;id=c1;pin-file={}",
        pin.display()
    );
    let opened = installation.open(&source, &authorization);
    assert_eq!(
        opened.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    assert!(
        installation
            .restored_reader_kem()
            .matches(&fixture::other_recipient_secret_bytes())
    );
    assert_eq!(
        installation.escrow_outcomes(),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    let module_path = module.as_bytes().to_vec();
    for haystack in [&opened.stdout, &opened.stderr] {
        assert!(
            !haystack
                .windows(module_path.len())
                .any(|window| window == module_path.as_slice()),
            "module path leaked"
        );
    }
    installation.assert_no_canaries(&[&opened]);
}

/// Eine Abholung mit einer Transportdatei an einen ANDEREN Schlüssel ändert
/// nichts; die Abholung mit dem richtigen gelingt danach genau einmal.
#[test]
fn reader_key_escrow_pickup_refuses_another_transport_key() {
    let installation = EscrowInstallation::new("escrow-pickup", "reader-key-escrow-recovery");
    let right = installation.transport(TRANSPORT_SEED);
    let authorization = installation.authorization(0xf3, TRANSPORT_SEED);
    let recovery = installation.software_recovery_key();
    // Eine Öffnung, deren Auslieferung scheitert: der Ausgang fehlt.
    fs::remove_dir(&installation.outbox).unwrap();
    let broken = installation.open(&recovery, &authorization);
    assert_eq!(broken.status.code(), Some(20));
    assert!(String::from_utf8_lossy(&broken.stderr).contains("EA-ESCROW-OUTPUT-IO"));
    fs::create_dir(&installation.outbox).unwrap();
    assert_eq!(installation.count("reader_key_escrow_result"), 1);
    let stored = installation
        .database()
        .query_row("SELECT exact_envelope FROM reader_key_escrow_result", &[])
        .unwrap()
        .unwrap()
        .blob(0)
        .unwrap()
        .to_vec();

    // Abholung mit einer Transportdatei an einen anderen Schlüssel.
    fs::remove_file(&right).unwrap();
    let wrong = installation.transport([0x5e; 32]);
    let refused = installation.pickup(&authorization);
    assert_eq!(refused.status.code(), Some(12));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("EA-ESCROW-TRANSPORT-MISMATCH"));
    assert_eq!(
        installation
            .database()
            .query_row("SELECT exact_envelope FROM reader_key_escrow_result", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
        stored.as_slice()
    );
    assert_eq!(
        installation.escrow_outcomes(),
        [LocalAuditOutcomeV1::Accepted]
    );

    // Mit dem richtigen Schlüssel gelingt die Abholung.
    fs::remove_file(&wrong).unwrap();
    installation.transport(TRANSPORT_SEED);
    let picked = installation.pickup(&authorization);
    assert_eq!(
        picked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&picked.stderr)
    );
    assert!(String::from_utf8_lossy(&picked.stdout).contains("reader-key-escrow picked-up "));
    assert!(
        installation
            .restored_reader_kem()
            .matches(&fixture::other_recipient_secret_bytes())
    );
    assert_eq!(
        installation.escrow_outcomes(),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );
    installation.assert_no_canaries(&[&broken, &refused, &picked]);
}

/// Pflichtzeuge für die ECHTE Sitzungsprüfung der Zeremonie B: die Laufzeit
/// besteht Prüfung, Transportdatei, Reauthentifizierung und die erste
/// Sitzungsprüfung, läuft aber zwischen dem Verbrauch und der privaten
/// Operation über die Uhr ab. Dann wird nichts entkapselt und nichts
/// gespeichert oder ausgeliefert; der Verbrauch steht mit 14/`failed` im
/// Audit, und die Autorisierung ist verbrannt.
#[test]
fn reader_key_escrow_open_refuses_a_session_expiring_after_consumption() {
    let installation = EscrowInstallation::new("escrow-expiring", "reader-key-escrow-recovery");
    installation.transport(TRANSPORT_SEED);
    let authorization = installation.authorization(0xf4, TRANSPORT_SEED);
    let recovery = installation.software_recovery_key();

    let expired = installation.open_marked(
        &recovery,
        &authorization,
        Some("escrow-expires-after-consumption"),
    );
    assert_eq!(
        expired.status.code(),
        Some(12),
        "{}",
        String::from_utf8_lossy(&expired.stderr)
    );
    assert!(String::from_utf8_lossy(&expired.stderr).contains("EA-ESCROW-OPERATOR-UNAUTHORIZED"));
    assert_eq!(installation.count("reader_key_escrow_opening"), 1);
    assert_eq!(installation.count("operator_admin_replay"), 2);
    assert_eq!(
        installation.escrow_outcomes(),
        [LocalAuditOutcomeV1::Accepted, LocalAuditOutcomeV1::Failed]
    );
    assert_eq!(installation.count("reader_key_escrow_result"), 0);
    assert_eq!(installation.count("reader_key_escrow_result_closure"), 0);
    assert_eq!(fs::read_dir(&installation.outbox).unwrap().count(), 0);

    // Verbrannt: dieselbe Autorisierung läuft nie wieder, auch nicht mit
    // gültiger Laufzeit.
    let again = installation.open(&recovery, &authorization);
    assert_eq!(again.status.code(), Some(12));
    assert!(String::from_utf8_lossy(&again.stderr).contains("EA-TRUST-AUTH-REPLAY"));
    assert_eq!(installation.count("reader_key_escrow_result"), 0);
    assert_eq!(fs::read_dir(&installation.outbox).unwrap().count(), 0);
    installation.assert_no_canaries(&[&expired, &again]);
}

/// Verfall beim Kommandostart (review-c P3-1, Controller-Ruling): ein
/// abgelaufenes Ergebnis wird gelöscht, BEVOR die Reauthentifizierung läuft
/// — auch wenn sie danach scheitert. Die Löschung steht mit 14/`failed` unter
/// dem geprüften Gerät (ohne Bedienerbindung) im Audit, atomar mit der
/// Abschlusszeile (Grund 1).
#[test]
fn an_expired_result_is_purged_before_a_failing_reauthentication() {
    expired_result_is_purged_before_reauthentication("escrow-purge-open", 0xf5, false);
}

/// Dasselbe für die Abholung: auch `pickup` löscht vor der Reauthentifizierung.
#[test]
fn an_expired_result_is_purged_before_a_failing_pickup() {
    expired_result_is_purged_before_reauthentication("escrow-purge-pickup", 0xf6, true);
}

fn expired_result_is_purged_before_reauthentication(name: &str, id: u8, pickup: bool) {
    let installation = EscrowInstallation::new(name, "reader-key-escrow-recovery");
    installation.transport(TRANSPORT_SEED);
    let authorization = installation.authorization(id, TRANSPORT_SEED);
    let recovery = installation.software_recovery_key();

    // Ein Verbrauch ohne Ergebnis; dann ein Ergebnis dazu, das seit
    // 86 400 000 ms verfallen ist.
    let consumed = installation.open_marked(
        &recovery,
        &authorization,
        Some("escrow-expires-after-consumption"),
    );
    assert_eq!(consumed.status.code(), Some(12));
    let authorization_hash = ea_crypto::object_hash(&fs::read(&authorization).unwrap());
    installation
        .database()
        .execute(
            "INSERT INTO reader_key_escrow_result(authorization_object_hash,target_transport_key_thumbprint,exact_envelope,stored_at_ms,expires_at_ms) VALUES(?1,?2,?3,0,86400000)",
            &[
                StoreValue::Blob(authorization_hash.as_bytes().to_vec()),
                StoreValue::Blob(thumbprint_of(TRANSPORT_SEED).as_bytes().to_vec()),
                StoreValue::Blob(vec![0x5a; 64]),
            ],
        )
        .unwrap();
    assert_eq!(installation.count("reader_key_escrow_result"), 1);

    // Die Reauthentifizierung scheitert (abgelaufene Laufzeit) — das
    // verfallene Ergebnis ist trotzdem weg.
    let refused = if pickup {
        installation.pickup_marked(&authorization, Some("escrow-stale-runtime"))
    } else {
        installation.open_marked(&recovery, &authorization, Some("escrow-stale-runtime"))
    };
    assert_eq!(
        refused.status.code(),
        Some(12),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    if pickup {
        // Die Abholung endet schon am gelöschten Ergebnis, vor der
        // Reauthentifizierung; ohne den Verfall beim Start läge es noch da.
        assert!(String::from_utf8_lossy(&refused.stderr).contains("EA-ESCROW-RESULT-EXPIRED"));
    } else {
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("EA-ESCROW-OPERATOR-UNAUTHORIZED")
        );
        assert!(
            installation
                .audit_rows()
                .iter()
                .any(|row| matches!(row.action(), LocalAuditActionV1::SessionExpired(_))),
            "the reauthentication failed"
        );
    }
    assert_eq!(installation.count("reader_key_escrow_result"), 0);
    let closure = installation
        .database()
        .query_row("SELECT reason FROM reader_key_escrow_result_closure", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    assert_eq!(closure, 1, "closed as expired");
    let escrow_rows: Vec<_> = installation
        .audit_rows()
        .into_iter()
        .filter(|row| matches!(row.action(), LocalAuditActionV1::ReaderKeyEscrowOpening(_)))
        .collect();
    assert_eq!(
        escrow_rows
            .iter()
            .map(|row| row.outcome())
            .collect::<Vec<_>>(),
        [
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Failed,
            LocalAuditOutcomeV1::Failed
        ]
    );
    // Die Verfallszeile entstand ohne Bedienernachweis, also vor der
    // Reauthentifizierung, unter dem geprüften Gerät.
    let purge = escrow_rows.last().unwrap();
    assert!(purge.operator_binding_object_hash().is_none());
    assert_eq!(
        purge.signer_certificate_object_hash().as_bytes(),
        installation
            .material
            .line
            .second_bootstrap_admin_hash()
            .as_bytes()
    );
    assert!(
        escrow_rows[1].operator_binding_object_hash()
            == Some(installation.material.operator_binding)
    );
    installation.assert_no_canaries(&[&consumed, &refused]);
}

/// Die Kodierungen der Kanarienvogelsuche treffen, was sie suchen sollen.
#[test]
fn the_canary_encodings_match_known_base64() {
    let secret: [u8; 32] = std::array::from_fn(|index| {
        u8::try_from((index * 37 + 0xf0) % 256).unwrap()
    });
    let encodings = secret_encodings(&secret);
    assert!(encodings.contains(&b"8BU6X4SpzvMYPWKHrNH2G0Bliq/U+R5DaI2y1/whRms=".to_vec()));
    assert!(encodings.contains(&b"8BU6X4SpzvMYPWKHrNH2G0Bliq_U-R5DaI2y1_whRms".to_vec()));
    assert!(encodings.contains(&hex::encode(secret).into_bytes()));
}
