//! Der Writer-Sync gegen den ECHTEN Server — die ANNEHMENDE Haelfte des
//! Quittungspfades.
//!
//! # Warum dieses Ziel hier liegt und nicht in `ea-sync-client`
//!
//! Weil eine Registrierungslinie, die der VOLLE Verifizierer bestaetigt, in
//! diesem Arbeitsbereich nur hier steht. Die Stufe-2-Writer-Fixture
//! (`crates/ea-writer/tests/support/mod.rs`) ist auf den GENESIS-Eintrag der
//! Sequenz null gebaut; der Kopf, den `ea_verify::verify_archive` fuer diese
//! Sequenz waehlt, ist ihr erster und traegt noch kein Schreiberzertifikat, und
//! ihr Eintrag kommt deshalb als `Unattributable` heraus — gemessen, mit und
//! ohne Serverquittungszertifikat. Der Abschluss dieses Pakets dagegen setzt
//! seinen Eintrag bewusst auf eine Sequenz im Bereich des LETZTEN Kopfes, der
//! alle Zertifikate traegt.
//!
//! # Was hier ECHT ist
//!
//! Alles ausser der Uhr: ein echter TLS-1.3-Lauscher, der echte Axum-Router,
//! die echten Adapter, die echte Datenbank, der echte Object Store, der echte
//! `SyncClient` mit dem echten `hyper`-Transport, und die Quittung, die
//! zurueckkommt, ist die, die der Server gebildet und signiert hat.
//!
//! # Die zwei Zusagen
//!
//! 1. `design.md`:1584 — `synchronisiert` erst, wenn die vom VOLLEN
//!    Verifizierer bestaetigte Quittung in der lokalen Archivkomponente liegt.
//! 2. Brief Schritt 4 — „an interrupted response resumes idempotently to the
//!    same Receipt": die Antwort geht verloren, NACHDEM der Server committet
//!    hat; der Wiederanlauf trifft auf denselben Commit, bekommt dieselben
//!    Quittungsbytes und legt GENAU EINE Quittung ab.

mod common;

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicUsize, Ordering},
};

use common::{archive_objects, trust_closure};
use ea_archive::{ArchiveBackendProfileV1, LocalPathProfileV1};
use ea_key_provider::KeyProvider as _;
use ea_sync_client::{
    SyncClient, SyncClientConfigV1, SyncStatus, SyncTransportV1, TransportErrorV1,
    TransportRequestV1, TransportResponseV1,
};

/// Die Uhr dieses Ziels — dieselbe, die der Server bekommt.
const NOW_MILLIS: i64 = 1_000;
/// Der Seed des Writer-Signierers, mit dem der Klient seine Requests signiert.
///
/// GENAU der des Abschlusses: der Server loest `keyid` gegen das
/// Schreiberzertifikat auf, und `EndpointV1::EntryCommits` verlangt die
/// Capability `initialGrant`.
const CLIENT_SEED: [u8; 32] = trust_closure::WRITER_SEED;

/// Ein Transport, der die Antwort GENAU EINMAL verschluckt.
///
/// Er ruft den echten Transport und wirft dessen Antwort auf dem ersten
/// Commit weg. Das ist der Zustand, den Schritt 4 des Briefes beschreibt: der
/// Server HAT committet, der Klient weiss es nicht. Ein Doppel, das den
/// Request gar nicht erst absetzte, wuerde etwas anderes messen — dann laege
/// serverseitig nichts, und der zweite Anlauf waere kein Replay.
struct DropsTheFirstResponse {
    inner: ea_sync_client::HyperTlsTransport,
    commits: AtomicUsize,
    /// Jede Antwort, die wirklich vom Server kam — auch die verschluckte.
    seen: Mutex<Vec<Vec<u8>>>,
    /// Jeder Rumpf, den der Klient gesendet hat.
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl DropsTheFirstResponse {
    fn new(inner: ea_sync_client::HyperTlsTransport) -> Self {
        Self {
            inner,
            commits: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            bodies: Mutex::new(Vec::new()),
        }
    }

    fn commit_calls(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }

    fn receipts_from_the_server(&self) -> Vec<Vec<u8>> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn commit_bodies(&self) -> Vec<Vec<u8>> {
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[ea_sync_client::async_trait]
impl SyncTransportV1 for DropsTheFirstResponse {
    async fn send(
        &self,
        request: TransportRequestV1,
    ) -> Result<TransportResponseV1, TransportErrorV1> {
        let is_commit = request.target.ends_with("/entry-commits");
        if is_commit {
            self.bodies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.body.clone());
        }
        let response = self.inner.send(request).await?;
        if !is_commit {
            return Ok(response);
        }
        let attempt = self.commits.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(response.body.clone());
        if attempt == 0 {
            // Die Leitung reisst NACH der Annahme. Der Server hat committet.
            return Err(TransportErrorV1::Timeout);
        }
        Ok(response)
    }
}

/// Der lokale Bestand, aus dem der Klient seine Warteschlange ableitet.
struct LocalArchive {
    backend: Arc<ea_archive_fs::LocalPathBackend>,
    database: Arc<ea_local_store::EncryptedDatabase>,
    anchor_bytes: Vec<u8>,
    entry_object_hash: ea_types::ObjectHash,
    _directory: std::path::PathBuf,
}

/// Die EXAKTEN Ankerbytes der eingefrorenen Linie, gegen die der Klient
/// verifiziert.
///
/// Dieselbe Datei, aus der `trust_closure::frozen_context` liest, und dieselbe,
/// die der Server ueber `seed_trust_fixture` bekommt — eine zweite Quelle waere
/// eine zweite Wahrheit ueber dieselbe Linie.
fn frozen_anchor_bytes() -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/trust/v1")
            .join(trust_closure::ROTATION_CASE)
            .join("anchor.bin"),
    )
    .expect("the frozen anchor must read")
}

/// Baut den lokalen Bestand: Vertrauensablage, ein committetes `.eip` und
/// seine initialen `.eag`.
///
/// Die Objekte sind DIESELBEN, die der Server annimmt — sie kommen aus
/// `archive_objects`, nicht aus einer zweiten Herstellung daneben. Der
/// Pfadhinweis ist ein Hinweis; klassifiziert wird am Exact-Object-Praefix.
fn build_local_archive(closure: &trust_closure::ExtendedClosure) -> (LocalArchive, Vec<u8>) {
    let directory =
        std::env::temp_dir().join(format!("ea-writer-sync-e2e-{}", common::unique_suffix()));
    std::fs::create_dir_all(&directory).expect("the fixture root must be creatable");
    let profile = ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "writer-sync-e2e".to_owned(),
        capability_test_vector_id: "cap-v1-e2e".to_owned(),
    });
    let policy = ea_archive::BoundArchiveProfilePolicyV1::from_policy(&policy_allowing(&profile));
    let backend =
        ea_archive_fs::LocalPathBackend::open(directory.join("archive"), profile, &policy)
            .expect("the local archive must open");

    // 1. Die Vertrauensablage — sonst waehlt der Verifizierer keinen Kopf.
    for object in &closure.objects {
        let hash = ea_crypto::object_hash(&object.bytes);
        backend.materialize_for_test(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            &object.bytes,
        );
    }
    for name in FROZEN_TRUST_OBJECTS {
        let bytes = frozen_object_bytes(name);
        let hash = ea_crypto::object_hash(&bytes);
        backend.materialize_for_test(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            &bytes,
        );
    }

    // 2. Der Eintrag und seine initialen Grants — GENAU die Bytes, die der
    //    Server ueber `POST /v1/chains/{chainId}/entry-commits` annimmt.
    let recipients = [
        archive_objects::Recipient::reader(closure),
        archive_objects::Recipient::recovery(closure),
    ];
    let plan = archive_objects::plan(&recipients);
    let spec = archive_objects::CommitSpec {
        closure,
        sequence: trust_closure::ExtendedClosure::commit_sequence(),
        previous_entry_hash: Some(
            ea_types::EntryHash::try_from(&common::READ_SEEDED_HEAD_ENTRY_HASH[..])
                .expect("32 bytes"),
        ),
        recipients: &recipients,
        marker: 0x5e,
        writer_override: None,
        registry_override: None,
    };
    let entry = archive_objects::entry_bytes(&spec, &plan);
    let entry_hash = archive_objects::entry_hash_of(&entry);
    let entry_object_hash = ea_crypto::object_hash(&entry);
    backend.materialize_for_test(
        &format!(
            "{}{:012}_entry.eip",
            ea_archive::ENTRIES_DIR_V1,
            spec.sequence
        ),
        &entry,
    );
    for recipient in &recipients {
        let grant = archive_objects::grant_bytes(closure, entry_hash, *recipient);
        backend.materialize_for_test(
            &format!(
                "{}{}.eag",
                ea_archive::GRANTS_DIR_V1,
                hex::encode(ea_crypto::object_hash(&grant).as_bytes())
            ),
            &grant,
        );
    }

    // 3. Die verschluesselte lokale Ablage fuer den Wiederaufnahmezustand.
    let provider = ea_key_provider::InMemoryKeyProvider::new_for_test([0x4c; 32]);
    let handle = provider
        .generate(
            ea_key_provider::SecretPurpose::LocalDatabaseKey,
            ea_format::KeyProtectionProfileV1::OsWrapped,
        )
        .expect("the in-process provider reaches OsWrapped");
    let database =
        ea_local_store::EncryptedDatabase::open(&directory.join("store.db"), &provider, &handle)
            .expect("the local store must open");

    (
        LocalArchive {
            backend: Arc::new(backend),
            database: Arc::new(database),
            anchor_bytes: frozen_anchor_bytes(),
            entry_object_hash,
            _directory: directory,
        },
        entry,
    )
}

/// Die eingefrorenen Objekte der Linie, die VOR dem Abschluss stehen.
///
/// `ExtendedClosure::objects` traegt nur die FORTSCHREIBUNG; die Wurzel, der
/// Administrator, seine Bindung und die zwei Koepfe liegen als eingefrorene
/// Vektoren daneben, und der Server bekommt sie ueber `seed_trust_fixture`.
/// Der lokale Bestand braucht dieselben, sonst schliesst seine Vertrauenskette
/// nicht.
const FROZEN_TRUST_OBJECTS: [&str; 13] = [
    "root-certificate.bin",
    "admin-certificate-a.bin",
    "admin-binding-a.bin",
    "admin-certificate-b.bin",
    "admin-binding-b.bin",
    "admin-certificate-rotated.bin",
    "rotation-authorization.bin",
    "policy-authorization.bin",
    "policy.bin",
    "head-authorization.bin",
    "head-event.bin",
    "second-head-authorization.bin",
    "second-head-event.bin",
];

fn frozen_object_bytes(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/trust/v1")
            .join(trust_closure::ROTATION_CASE)
            .join(name),
    )
    .expect("a frozen object must read")
}

/// Eine Archivprofil-Zulassung, die genau dieses Profil traegt.
///
/// Sie ist eine KLIENTENSEITIGE Konfiguration und keine Aussage der Linie: der
/// lokale Bestand prueft mit ihr, ob sein eigenes Profil freigegeben ist. Sie
/// wird deshalb hier gebaut und nicht aus dem eingefrorenen `policy.bin`
/// gezogen — jenes traegt die Profilliste der SERVERSEITIGEN Kulisse, und ein
/// Profil dieses Testziels steht dort zu Recht nicht drin.
fn policy_allowing(profile: &ArchiveBackendProfileV1) -> ea_format::PolicyFieldsV1 {
    ea_format::PolicyFieldsV1 {
        organization_id: trust_closure::frozen_context().organization_id,
        policy_version: 1,
        previous_policy_object_hash: None,
        operating_profile: 0,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 900_000,
        reader_trust_refresh_ms: 86_400_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: vec![
            profile.profile_hash().expect("the profile must hash"),
        ],
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
        allowed_crypto_suite_ids: vec![ea_types::SUITE_ID_V1.to_owned()],
        allowed_format_versions: vec![1],
        effective_from_sequence: ea_types::ChainSequence::new(0),
    }
}

fn client(
    archive: &LocalArchive,
    closure: &trust_closure::ExtendedClosure,
    authority: &str,
    observed_now: i64,
    transport: Arc<dyn SyncTransportV1>,
) -> SyncClient {
    SyncClient::new(SyncClientConfigV1 {
        backend: Arc::clone(&archive.backend),
        anchor_bytes: archive.anchor_bytes.clone(),
        network: None,
        transport,
        signer: Arc::new(common::request_signer(CLIENT_SEED)),
        organization_id: closure.organization_id,
        chain_id: closure.chain_id,
        authority: authority.to_owned(),
        database: Arc::clone(&archive.database),
        retry: ea_types::RetryConfig::new(3, 10, 100).expect("bounds are non-zero"),
        max_resume_attempts: 3,
        observed_now: ea_types::UnixMillis::new(observed_now),
    })
    .expect("the sync client must stand up")
}

fn receipt_paths(archive: &LocalArchive) -> Vec<String> {
    archive
        .backend
        .relative_paths()
        .expect("the archive must read")
        .into_iter()
        .filter(|path| path.ends_with(".esr"))
        .collect()
}

// ---------------------------------------------------------------------------
// Der Zeuge
// ---------------------------------------------------------------------------

/// Der ECHTE Weg bis an das Quittungstor — und die fail-closed Abweisung davor.
///
/// # Was dieser Zeuge beweist
///
/// 1. Der lokale Bestand, aus committeten Bytes dieses Abschlusses gebaut,
///    VERIFIZIERT: `verify_archive` waehlt einen Registrierungskopf und fuehrt
///    den Eintrag als `Valid`. (Die Stufe-2-Writer-Fixture kann das nicht —
///    Begruendung im Modulkopf.)
/// 2. Der echte `SyncClient` mit dem echten `hyper`-Transport signiert nach
///    RFC 9421, holt eine frische Challenge und bringt den Commit beim echten
///    Server durch: `200`.
/// 3. Geht die Antwort verloren, ist der Wiederanlauf IDEMPOTENT: derselbe
///    Rumpf, und der Server liefert BYTEIDENTISCH dieselbe Quittung unter
///    `idempotentReplay` — die Zusage aus Schritt 4 des Briefes, auf der
///    Serverseite gemessen.
/// 4. Und der Klient legt sie trotzdem NICHT ab: die Kulisse traegt kein
///    Zertifikat der Art `ServerReceipt`, also bestaetigt Gate `receipt` die
///    Quittung nicht, und `synchronisiert` bleibt aus. Fail-closed gegen eine
///    ECHTE Serverquittung — schaerfer als gegen eine gefaelschte.
///
/// # Was er NICHT beweist, und warum
///
/// Den letzten Schritt: verifizierte Quittung abgelegt, Zustand
/// `synchronisiert`. Er ist an dieser Kulisse unerreichbar, und die Ursache ist
/// GEMESSEN und benannt: `trust_closure::build_with` stellt Zertifikate der
/// Arten `Writer`, `Reader`, `RecoveryRecipient`, `HistoricalGrantAuthority`
/// und `KeyApprover` aus — KEINES der Art `ServerReceipt`. Der Lauscher
/// signiert seine Quittungen dagegen mit `READ_SERVER_SECRET` unter dem
/// SYNTHETISCHEN Zertifikatshash `READ_SERVER_CERTIFICATE_HASH` (`[0x52; 32]`),
/// den kein Trust-Objekt der Linie fuehrt. `VerificationContext::receipt`
/// verlangt die Capability `serverReceipt`, und `ea_trust::verify_receipt_time`
/// loest den Signierer gegen den gewaehlten Kopf auf — der Befund lautet
/// deshalb `EA-VERIFY-RECEIPT-UNTRUSTED-TIME`, und zwar fuer JEDE Quittung,
/// die diese Kulisse ausstellen kann.
#[tokio::test]
async fn a_real_server_receipt_is_replayed_idempotently_and_refused_without_its_certificate() {
    common::install_crypto_provider();
    let database = common::fresh_database().await;
    let ready = common::stand_up_read_server(&database, NOW_MILLIS, false).await;
    let (archive, _entry) = build_local_archive(&ready.closure);

    // Der lokale Bestand VERIFIZIERT — das ist die Vorbedingung, an der die
    // Stufe-2-Fixture scheitert, und ohne sie misst alles Weitere nichts.
    let anchor =
        ea_trust::decode_trust_anchor(&archive.anchor_bytes).expect("der Anker muss dekodieren");
    let before = ea_verify::verify_archive(
        &archive.backend.as_archive_source(),
        &anchor,
        ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(NOW_MILLIS)),
    )
    .expect("der Verifikationslauf muss ein Ergebnis liefern");
    assert_eq!(
        before.registry_versions().len(),
        1,
        "der lokale Bestand MUSS einen Registrierungskopf waehlen"
    );
    assert!(
        before
            .object_results()
            .any(|result| result.object_hash() == archive.entry_object_hash
                && result.result() == ea_verify::ObjectResultKindV1::Valid),
        "der committete Eintrag MUSS gueltig sein"
    );
    assert!(receipt_paths(&archive).is_empty());

    let transport = Arc::new(DropsTheFirstResponse::new(common::hyper_transport(
        &ready.server,
    )));

    // Erster Anlauf: der Server nimmt an, die Antwort geht verloren.
    let first = client(
        &archive,
        &ready.closure,
        &ready.server.authority,
        NOW_MILLIS,
        Arc::clone(&transport) as Arc<dyn SyncTransportV1>,
    )
    .push_pending(4)
    .await
    .expect("ein Leitungsabriss ist ein ZUSTAND und kein Fehler");
    assert_eq!(first.pushed(), 0);
    assert_ne!(first.status(), SyncStatus::Synchronized);

    // Zweiter Anlauf. Die Uhr geht ueber den gebuchten Backoff hinaus, aber um
    // WENIGER als eine Sekunde: sonst wanderte die `created`-Sekunde der
    // RFC-9421-Signatur vor die Uhr des Servers, und der Request scheiterte an
    // seinem Signaturfenster statt am Kettenzustand.
    let refused = client(
        &archive,
        &ready.closure,
        &ready.server.authority,
        NOW_MILLIS + 400,
        Arc::clone(&transport) as Arc<dyn SyncTransportV1>,
    )
    .push_pending(4)
    .await
    .expect_err("ohne Serverquittungszertifikat MUSS die Quittung abgewiesen werden");
    assert_eq!(refused.code(), "EA-SYNC-RECEIPT-INVALID");
    assert!(
        receipt_paths(&archive).is_empty(),
        "eine unbestaetigte Quittung darf den Bestand NIE erreichen"
    );

    // Der Server hat BEIDE Male angenommen, und beim zweiten Mal als
    // WIEDERGABE — mit byteidentischer Quittung. Das ist Schritt 4 des
    // Briefes, auf der Serverseite gemessen.
    assert_eq!(transport.commit_calls(), 2);
    let answers = transport.receipts_from_the_server();
    let accepted = ea_sync_protocol::EntryCommitResponseV1::decode(&answers[0])
        .expect("die erste Antwort muss rahmen");
    let replay = ea_sync_protocol::EntryCommitResponseV1::decode(&answers[1])
        .expect("die zweite Antwort muss rahmen");
    // Die QUITTUNG ist byteidentisch, der AUSGANG nicht — und genau so soll es
    // sein: `design.md`:1547 verlangt, dass Annahmezeit, Faelligkeit und
    // Signatur bei einem Commit nie neu berechnet werden, waehrend die Antwort
    // ehrlich sagt, dass dies eine Wiedergabe war. Ein Vergleich der ganzen
    // Rahmen ginge an beidem vorbei.
    assert_eq!(
        accepted.receipt_bytes(),
        replay.receipt_bytes(),
        "eine unterbrochene Antwort fuehrt auf DIESELBE Quittung"
    );
    assert_eq!(
        accepted.outcome(),
        ea_sync_protocol::EntryCommitOutcome::Accepted,
        "der erste Anlauf ist der Commit"
    );
    assert_ne!(
        answers[0], answers[1],
        "und die Rahmen unterscheiden sich GENAU im Ausgang"
    );
    let bodies = transport.commit_bodies();
    assert_eq!(
        bodies[0], bodies[1],
        "und auf denselben Rumpf — die Warteschlange entsteht jedes Mal neu aus denselben committeten Bytes"
    );
    assert_eq!(
        replay.outcome(),
        ea_sync_protocol::EntryCommitOutcome::IdempotentReplay,
        "der zweite Anlauf ist eine WIEDERGABE und kein zweiter Commit"
    );

    // Und der Grund der Abweisung ist GENAU der benannte — nicht irgendeiner.
    archive
        .backend
        .materialize_for_test("receipts/candidate.esr", replay.receipt_bytes());
    let after = ea_verify::verify_archive(
        &archive.backend.as_archive_source(),
        &anchor,
        ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(NOW_MILLIS)),
    )
    .expect("der Verifikationslauf muss ein Ergebnis liefern");
    assert!(
        after
            .signature_errors()
            .any(|error| error.code() == "EA-VERIFY-RECEIPT-UNTRUSTED-TIME"),
        "der Befund ist der fehlende Serverquittungs-Signierer"
    );
    assert!(
        after
            .object_results()
            .all(|result| result.server_confirmation()
                == ea_verify::ServerConfirmationV1::NotServerConfirmed),
        "ohne Zertifikat wird KEIN Eintrag serverbestaetigt"
    );

    database.cleanup().await;
}
