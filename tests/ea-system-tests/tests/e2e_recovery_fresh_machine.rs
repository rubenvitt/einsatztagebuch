//! Recovery auf einer FRISCHEN Maschine — in einem Durchgang.
//!
//! # Die eine Aussage
//!
//! Ein Bestand, ein Anker und benannte Offline-Schluesselquellen genuegen, um
//! auf einem Rechner, der sonst NICHTS von dieser Organisation hat, den
//! Bestand zu verifizieren, das Schluesselinventar abzuarbeiten, den
//! ausgewaehlten alten Eintrag zu entschluesseln und einem neuen Lesegeraet
//! per Re-Grant genau diesen einen Eintrag zu oeffnen — und der gefuehrte
//! Recovery-Test faellt sein Urteil ueber GENAU DIESE Messung.
//!
//! Die Kette laeuft durch: der private Empfaengerschluessel wird in Abschnitt
//! 1 aus einem verschluesselten Container geholt, und DERSELBE aufgeloeste
//! Schluessel entschluesselt in Abschnitt 2 und stellt in Abschnitt 5 den
//! Re-Grant aus. Kein Abschnitt greift hinter die Quelle zurueck.
//!
//! # Kulissen, nicht Nachbauten
//!
//! `crates/ea-recovery/tests/support/mod.rs` (und ueber sie die Fixturkette
//! von `ea-verify`, `ea-archive`, `ea-trust`) traegt Bestand, Anker und
//! Schluessel; `crates/ea-recovery/tests/historical_grant/support.rs` traegt
//! den Ausstellungsdienst; `crates/ea-admin/tests/support/mod.rs` traegt die
//! Einrichtungszeremonie. Hier wird nichts davon nachgebaut.
//!
//! # Die Naht, die der Lauf NICHT schliesst
//!
//! Schritt 12 der Zeremonie und die gemessene Probe laufen auf ZWEI
//! Organisationen. Das ist die Gestalt der Kulissen: die Zeremoniefixture hat
//! keinen Bestand (ihr Genesis-Eintragshash ist eine Konstante), und die
//! Bestandsfixture hat keine Zeremonie. Gebuendelt ist deshalb das URTEIL:
//! `ea_admin::verify_fresh_machine_recovery_test` bewertet in Abschnitt 3 die
//! WIRKLICH gemessene Probe aus Abschnitt 2 — Medien, Anker, Abdruck,
//! Lesbarkeit und Sample kommen aus dem Lauf und nicht aus einer Konstanten —,
//! und in Abschnitt 4 fuehrt dieselbe Funktion die Organisation der Zeremonie
//! von `BlockedRecoveryTest` nach `Ready`.
//!
//! Der NATIVE gefuehrte Recovery-Test (`RecoveryTestRuntime`, Zeugen
//! `process_native::recovery::guided::`) bleibt ausserhalb: er verlangt eine
//! echte Fremdmaschine und ist in `apps/cli` mit `#[ignore]` geparkt
//! (`docs/traceability/stage-5-gate.md`, AK 52). „Frische Maschine" heisst
//! hier: ein Wurzelverzeichnis, das nur Bestand, Anker und das benannte
//! Offline-Medium enthaelt — kein Entwurfsspeicher, kein Writer-Schluessel,
//! kein Bedienerprofil.
//!
//! # Dienste
//!
//! Keine. Rein dateisystem- und prozessintern, wie `e2e_registry_
//! effectiveness` und `e2e_writer_transition`; kein `xtask integration up`.
#![allow(clippy::duplicate_mod, clippy::too_many_lines)]

// Der Name `support` ist hier Pflicht: das Ausstellungsmodul von `ea-recovery`
// greift ueber `super::support` auf genau diese Kulisse zu.
#[path = "../../../crates/ea-recovery/tests/support/mod.rs"]
mod support;

#[allow(dead_code)]
#[path = "../../../crates/ea-recovery/tests/historical_grant/support.rs"]
mod issuance;

#[path = "../../../crates/ea-admin/tests/support/mod.rs"]
mod ceremony_support;

// Die schemagueltige Nutzlast der Recovery-Probe — dieselbe, die
// `crates/ea-recovery/tests/recovery_test.rs` einbindet.
#[path = "../../../crates/ea-recovery/tests/recovery_fixture/mod.rs"]
mod recovery_fixture;

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use ea_admin::{ProductionState, RecoveryTestObservation, verify_fresh_machine_recovery_test};
use ea_crypto::{SecretBytes, SecretVec, object_hash};
use ea_recovery::{
    ContainedKeyKind, EncryptedKeyContainer, KeyInventory, RecoveryArchiveProbe, RecoveryKem as _,
    RecoveryKeyRole, RecoveryTestKind, ResolvedRecipientKey, resolve_recipient_key,
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint, UnixMillis};

use support::verify_support::{self as fixture, archive_support::trust_support};

/// Die Fixturzeit jeder Bewertung dieses Zeugen.
const NOW_MS: i64 = 800;

/// Die Passphrase des Offline-Containers — eine Zeile, wie `read_secret_file`
/// sie verlangt.
const CONTAINER_PASSPHRASE: &str = "ea-drk-427-offline-medium\n";

// ===========================================================================
// Der Lauf
// ===========================================================================

#[test]
fn a_fresh_machine_recovers_the_archive_and_regrants_the_selected_old_entry() {
    let organization = fixture::historical::fixture_with_two_old_entries_and_payload(
        recovery_fixture::recovery_payload,
    );
    let machine = issuance::Harness::new(organization);

    // 1. Die Offline-Schluesselquellen.
    let medium = support::temp_dir("drk427-offline-medium");
    let recovery_key = the_recovery_key_comes_from_a_named_offline_source(medium.path());

    // 2. Die Recovery auf der frischen Maschine — mit genau diesem Schluessel.
    let measured = the_fresh_machine_verifies_and_decrypts(&machine, &recovery_key);

    // 3. Das Urteil des gefuehrten Recovery-Tests ueber GENAU diese Messung.
    the_guided_recovery_test_judges_the_measured_run(&measured);

    // 4. Und die Recovery-Bereitschaft der Organisation der Zeremonie.
    the_ceremony_reaches_production_state_only_through_step_twelve();

    // 5. Der Re-Grant: genau der ausgewaehlte alte Eintrag oeffnet.
    the_regrant_opens_exactly_the_selected_old_entry(&machine, &recovery_key);
}

// ---------------------------------------------------------------------------
// 1. Offline-Schluesselquellen
//
// Zeuge: `crates/ea-recovery/tests/offline_sources.rs` — die drei Quellarten,
// ihre Grammatik, der Container und die Rechte der Geheimnisdatei.
// ---------------------------------------------------------------------------

fn the_recovery_key_comes_from_a_named_offline_source(medium: &Path) -> ResolvedRecipientKey {
    let container_path = medium.join("recovery-recipient.eakc");
    let passphrase_path = medium.join("recovery-recipient.pass");
    write_secret_file(&passphrase_path, CONTAINER_PASSPHRASE.as_bytes());
    let passphrase = SecretVec::new(CONTAINER_PASSPHRASE.trim_end().as_bytes().to_vec());

    EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        SecretBytes::new(fixture::complete_recipient_secret_bytes()),
        &passphrase,
    )
    .expect("der Container versiegelt den Empfaengerschluessel")
    .write_new(&container_path)
    .expect("der Container liegt auf dem Medium");

    // Die Quelle wird BENANNT und nicht gesucht: Pfad positional, die
    // Passphrasendatei als benanntes Feld.
    let spec = ea_recovery::KeySourceSpec::parse(OsStr::new(&format!(
        "container:{};passphrase-file={}",
        container_path.display(),
        passphrase_path.display()
    )))
    .expect("die Quellenangabe parst");

    // Eine falsche Passphrase oeffnet nichts — und der Fehler nennt keinen
    // Hostpfad.
    let wrong_passphrase_path = medium.join("wrong.pass");
    write_secret_file(&wrong_passphrase_path, b"ea-drk-427-falsch\n");
    let wrong = ea_recovery::KeySourceSpec::parse(OsStr::new(&format!(
        "container:{};passphrase-file={}",
        container_path.display(),
        wrong_passphrase_path.display()
    )))
    .expect("die Quellenangabe parst");
    let refused = resolve_recipient_key(&wrong)
        .err()
        .expect("eine falsche Passphrase oeffnet den Container nicht");
    let rendered = refused.to_string();
    assert_eq!(refused.code(), "EA-RECOVERY-CONTAINER-OPEN");
    assert!(
        !rendered.contains(&medium.display().to_string()),
        "keine Fehlerdarstellung nennt einen Hostpfad"
    );

    let resolved = resolve_recipient_key(&spec).expect("die benannte Quelle loest auf");
    assert!(
        resolved
            .key_thumbprint()
            .expect("der aufgeloeste Schluessel hat einen Abdruck")
            == fixture::complete_recipient_key_thumbprint(),
        "die Quelle liefert genau den Empfaengerschluessel des Bestands"
    );
    resolved
}

/// Eine Geheimnisdatei, wie `read_secret_file` sie annimmt: nur dem Eigentuemer
/// lesbar.
fn write_secret_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::write(path, bytes).expect("die Geheimnisdatei muss schreibbar sein");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("die Rechte der Geheimnisdatei muessen setzbar sein");
}

// ---------------------------------------------------------------------------
// 2. Die Recovery auf der frischen Maschine
//
// Zeugen: `crates/ea-recovery/tests/recovery_test.rs::recovery_probe_opens_
// validates_and_preserves_the_exact_original_archive` (6/0/0) und
// `::real_backup_challenges_are_fresh_bound_to_the_signed_certificate_and_
// never_productive`.
// ---------------------------------------------------------------------------

/// Was die frische Maschine WIRKLICH gemessen hat.
struct MeasuredRecovery {
    media_expected: usize,
    media_present: usize,
    anchor_hash: Hash32,
    key_thumbprint: KeyThumbprint,
    test_entry_readable: bool,
    sample_entries_expected: usize,
    sample_entries_decrypted: usize,
}

fn the_fresh_machine_verifies_and_decrypts(
    machine: &issuance::Harness,
    recovery_key: &ResolvedRecipientKey,
) -> MeasuredRecovery {
    let f = &machine.fixture;

    // Die frische Maschine traegt nur Bestand, Anker und Medium — kein
    // Entwurfsspeicher, kein Writer-Schluessel, kein Bedienerprofil.
    assert!(
        machine.root.path().join("archive").is_dir(),
        "die frische Maschine traegt den Bestand"
    );

    // Der Bestand verifiziert gegen den Anker, BEVOR ein Schluessel angefasst
    // wird.
    let probe = RecoveryArchiveProbe::verify(&machine.source, &f.anchor, UnixMillis::new(NOW_MS))
        .expect("der Bestand der frischen Maschine verifiziert gegen seinen Anker");

    // Das Schluesselinventar: EIN Medium, das den Wiederherstellungsempfaenger
    // des Bestands nennt.
    let grant_fields = original_grant_fields(&f.original_bytes);
    let inventory = key_inventory(
        "recovery-a",
        RecoveryKeyRole::RecoveryRecipient,
        RecoveryTestKind::RecoveryDecrypt,
        grant_fields.0,
        grant_fields.1,
    );
    assert_eq!(inventory.media().len(), 1);
    assert_eq!(inventory.media()[0].id(), "recovery-a");
    assert_eq!(
        inventory.media()[0].role(),
        RecoveryKeyRole::RecoveryRecipient
    );

    // Ein Inventar, das nicht der Grammatik folgt, ist kein Inventar.
    assert_eq!(
        KeyInventory::parse(b"{\"schemaId\":\"ea.key-inventory/v1\"}")
            .err()
            .expect("ein Inventar ohne Medien ist unvollstaendig")
            .code(),
        "EA-RECOVERY-INVENTORY-INVALID"
    );

    // Die Probe: der ausgewaehlte alte Eintrag wird entschluesselt, und der
    // GANZE Bestand ist dabei verifiziert.
    let setup_grant = object_hash(&f.original_bytes);
    let tested = probe
        .test_recovery_medium(
            &inventory.media()[0],
            f.entry_hash,
            setup_grant,
            recovery_key,
        )
        .expect("das benannte Medium entschluesselt den Bestand");
    assert!(tested.full_archive_verified());
    assert!(
        tested
            .samples()
            .iter()
            .any(|sample| sample.entry_hash().as_bytes() == f.entry_hash.as_bytes()),
        "das Sample enthaelt den Einrichtungseintrag"
    );
    // Der Bestand traegt zwei alte Eintraege, und BEIDE tragen einen eigenen
    // urspruenglichen Recovery-Grant fuer dieses Medium. Das Sample ist
    // deshalb vollstaendig genau dann, wenn beide entschluesselt sind.
    let expected_samples = 1 + usize::from(f.second_old_entry.is_some());
    assert_eq!(expected_samples, 2);
    assert_eq!(tested.samples().len(), expected_samples);

    // Gegenprobe 1: ein FREMDER Schluessel besteht das Medium nicht — sein
    // Abdruck ist nicht der erwartete.
    assert_eq!(
        probe
            .test_recovery_medium(
                &inventory.media()[0],
                f.entry_hash,
                setup_grant,
                &fixture::other_recipient_private_key(),
            )
            .err()
            .expect("ein fremder Schluessel ist der falsche Key")
            .code(),
        "EA-RECOVERY-TEST-KEY"
    );

    // Gegenprobe 2: ein Medium der falschen Rolle wird gar nicht erst
    // entschluesselt.
    let wrong_role = key_inventory(
        "reader-a",
        RecoveryKeyRole::Reader,
        RecoveryTestKind::RecoveryDecrypt,
        grant_fields.0,
        grant_fields.1,
    );
    assert_eq!(
        probe
            .test_recovery_medium(
                &wrong_role.media()[0],
                f.entry_hash,
                setup_grant,
                recovery_key
            )
            .err()
            .expect("ein Lesemedium ist kein Wiederherstellungsmedium")
            .code(),
        "EA-RECOVERY-TEST-ROLE"
    );

    MeasuredRecovery {
        media_expected: inventory.media().len(),
        media_present: 1,
        anchor_hash: f.anchor.trust_anchor_hash(),
        key_thumbprint: recovery_key
            .key_thumbprint()
            .expect("der aufgeloeste Schluessel hat einen Abdruck"),
        test_entry_readable: tested.full_archive_verified(),
        sample_entries_expected: expected_samples,
        sample_entries_decrypted: tested.samples().len(),
    }
}

/// Abdruck und Zertifikat des urspruenglichen Recovery-Grants.
fn original_grant_fields(original_bytes: &[u8]) -> (KeyThumbprint, CertificateHash) {
    let ea_format::ParsedArchiveObject::Grant(grant) =
        ea_format::decode_exact_object(original_bytes).expect("der Originalgrant dekodiert")
    else {
        panic!("die Fixture legt einen Grant vor");
    };
    let fields = grant.value().grant_body().fields().clone();
    (
        fields.recipient_key_thumbprint,
        fields.recipient_certificate_hash,
    )
}

/// Ein Inventar mit GENAU einem Medium.
fn key_inventory(
    medium_id: &str,
    role: RecoveryKeyRole,
    test_kind: RecoveryTestKind,
    thumbprint: KeyThumbprint,
    certificate: CertificateHash,
) -> KeyInventory {
    let test_kind = match test_kind {
        RecoveryTestKind::RecoveryDecrypt => "recoveryDecrypt",
        RecoveryTestKind::SignatureChallenge => "signatureChallenge",
        RecoveryTestKind::ProviderPresence => "providerPresence",
    };
    let document = serde_json::json!({
        "schemaId": "ea.key-inventory/v1",
        "inventoryId": "aa".repeat(16),
        "media": [{
            "mediumId": medium_id,
            "keyRole": role.label(),
            "expectedKeyThumbprint": hex::encode(thumbprint.as_bytes()),
            "certificateObjectHash": hex::encode(certificate.as_bytes()),
            "protectionProfile": "offlineEncryptedContainer",
            "testKind": test_kind,
        }],
    });
    KeyInventory::parse(&serde_json::to_vec(&document).expect("das Inventar kodiert"))
        .expect("das Inventar der Kulisse parst")
}

// ---------------------------------------------------------------------------
// 3. Der gefuehrte Recovery-Test urteilt ueber die Messung
//
// Zeuge: `crates/ea-admin/tests/bootstrap.rs::a_partial_recovery_test_never_
// becomes_a_successful_one` und `::a_recovery_test_on_the_ceremony_machine_is_
// not_a_fresh_machine_test` (53/0/0).
//
// Die Beobachtung ist hier KEINE Konstante: jeder ihrer fuenf Ausgaenge traegt
// eine Zahl aus Abschnitt 2.
// ---------------------------------------------------------------------------

fn the_guided_recovery_test_judges_the_measured_run(measured: &MeasuredRecovery) {
    let ceremony_machine = ceremony_support::ceremony_machine();
    let fresh_machine = ceremony_support::fresh_machine();
    assert!(fresh_machine != ceremony_machine);

    let observation = |machine: Hash32, adjust: fn(&mut RecoveryTestObservation)| {
        let mut observation = RecoveryTestObservation {
            machine_fingerprint: machine,
            media_expected: measured.media_expected,
            media_present: measured.media_present,
            expected_trust_anchor_hash: measured.anchor_hash,
            observed_trust_anchor_hash: measured.anchor_hash,
            expected_key_thumbprint: measured.key_thumbprint,
            observed_key_thumbprint: measured.key_thumbprint,
            test_entry_readable: measured.test_entry_readable,
            sample_entries_expected: measured.sample_entries_expected,
            sample_entries_decrypted: measured.sample_entries_decrypted,
        };
        adjust(&mut observation);
        observation
    };

    // Der volle Lauf besteht.
    let proof =
        verify_fresh_machine_recovery_test(ceremony_machine, &observation(fresh_machine, |_| {}))
            .expect("die gemessene Probe ist ein bestandener Frischrechner-Test");
    assert!(proof.machine_fingerprint() == fresh_machine);
    assert!(proof.expected_trust_anchor_hash() == measured.anchor_hash);

    // Derselbe Lauf auf der ZEREMONIENMASCHINE hat die Frage gar nicht
    // gestellt, auf die es ankommt.
    assert_eq!(
        verify_fresh_machine_recovery_test(
            ceremony_machine,
            &observation(ceremony_machine, |_| {})
        )
        .err()
        .expect("Schritt 12 verlangt einen FRISCHEN Rechner")
        .code(),
        "EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE"
    );

    // Und jeder der vier Teilerfolge ist ein fehlgeschlagener Gesamttest.
    for (name, adjust) in [
        (
            "ein fehlendes Medium",
            (|observation: &mut RecoveryTestObservation| observation.media_present -= 1)
                as fn(&mut RecoveryTestObservation),
        ),
        ("ein abweichender Anchor", |observation| {
            observation.observed_trust_anchor_hash = Hash32::ZERO;
        }),
        ("ein falscher Key", |observation| {
            observation.observed_key_thumbprint = KeyThumbprint::from(trust_support::hash32(0x7a));
        }),
        ("ein unvollstaendiges Sample", |observation| {
            observation.sample_entries_decrypted -= 1;
        }),
    ] {
        assert_eq!(
            verify_fresh_machine_recovery_test(
                ceremony_machine,
                &observation(fresh_machine, adjust)
            )
            .err()
            .expect("ein Teilerfolg ist kein bestandener Test")
            .code(),
            "EA-CEREMONY-RECOVERY-TEST-FAILED",
            "{name} macht den GESAMTEN Test fehlgeschlagen"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Recovery-Bereitschaft der Organisation
//
// Zeuge: `crates/ea-admin/tests/bootstrap.rs::production_state_requires_all_
// twelve_steps_and_fresh_recovery` (53/0/0).
//
// NAHT: die Zeremonie hat keinen Bestand; ihr Genesis-Eintragshash ist eine
// Fixturkonstante. Der Uebergang nach `Ready` wird deshalb an IHREM Anker
// gemessen und nicht an dem der Bestandsfixture — `record_fresh_machine_
// recovery_test` vergleicht den Anker des Nachweises gegen den in Schritt 11
// angenommenen (`crates/ea-admin/src/bootstrap.rs:1899`).
// ---------------------------------------------------------------------------

fn the_ceremony_reaches_production_state_only_through_step_twelve() {
    let mut ceremony = ceremony_support::BootstrapHarness::new();
    ceremony
        .complete_through_genesis()
        .expect("die elf Schritte der Einrichtung tragen");
    assert_eq!(
        ceremony.production_state(),
        ProductionState::BlockedRecoveryTest
    );

    // Ein fehlendes Medium und die Zeremonienmaschine lassen den Zustand, wo
    // er ist.
    assert_eq!(
        ceremony
            .run_fresh_machine_recovery_missing_one_medium()
            .expect_err("ein fehlendes Medium macht den GESAMTEN Test fehlgeschlagen")
            .code(),
        "EA-CEREMONY-RECOVERY-TEST-FAILED"
    );
    assert_eq!(
        ceremony.production_state(),
        ProductionState::BlockedRecoveryTest
    );
    assert_eq!(
        ceremony
            .run_recovery_on_the_ceremony_machine()
            .expect_err("Schritt 12 verlangt einen FRISCHEN Rechner")
            .code(),
        "EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE"
    );
    assert_eq!(
        ceremony.production_state(),
        ProductionState::BlockedRecoveryTest
    );

    // Und der vollstaendige Lauf auf dem frischen Rechner.
    ceremony
        .run_fresh_machine_recovery()
        .expect("der vollstaendige Frischrechner-Test besteht");
    assert_eq!(ceremony.production_state(), ProductionState::Ready);
}

// ---------------------------------------------------------------------------
// 5. Der Re-Grant (AK 12, AK 40)
//
// Zeuge: `crates/ea-recovery/tests/historical_grant.rs::of_two_old_entries_
// only_the_selected_one_opens_for_the_new_reader_after_the_regrant` (8/0/0)
// und der Serverpfad `tests/ea-system-tests/tests/e2e_historical_grant.rs`
// (1/0/0, mit `xtask integration up`) — der hier ausdruecklich NICHT
// wiederholt wird: dieser Lauf braucht keinen Dienst.
//
// Der Re-Grant benutzt GENAU den Schluessel, den Abschnitt 1 aus dem
// Offline-Container geholt hat.
// ---------------------------------------------------------------------------

fn the_regrant_opens_exactly_the_selected_old_entry(
    machine: &issuance::Harness,
    recovery_key: &ResolvedRecipientKey,
) {
    struct Decapsulations(usize);
    impl ea_verify::GateObserver for Decapsulations {
        fn on_gate(&mut self, _: ea_verify::Gate) {}
        fn on_decapsulation(&mut self) {
            self.0 += 1;
        }
    }

    let f = &machine.fixture;
    let second = f
        .second_old_entry
        .as_ref()
        .expect("die Fixture traegt einen zweiten alten Eintrag");
    assert!(second.entry_hash != f.entry_hash);

    let reader = fixture::other_recipient_private_key();
    let stranger =
        ea_crypto::HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x7a; 32])).unwrap();
    let stranger_thumbprint = fixture::key_thumbprint_of(&stranger);
    assert!(stranger_thumbprint != fixture::other_recipient_key_thumbprint());

    let open = |archive: &fixture::archive_support::ArchiveFixture,
                thumbprint,
                key: &ea_crypto::HpkeRecipientPrivateKey| {
        let mut observer = Decapsulations(0);
        let report = ea_verify::verify_archive_observed(
            archive,
            &f.anchor,
            ea_verify::VerifyOptions::new(UnixMillis::new(NOW_MS)).with_recipient(thumbprint, key),
            &mut observer,
        )
        .expect("der Bestand verifiziert");
        (report, observer.0)
    };

    // Die Autorisierung waehlt GENAU den ersten Eintrag aus.
    let authorization = ea_trust::verify_grant_authorization(
        &f.authorization(NOW_MS),
        &f.selected(f.current_sequence, NOW_MS, NOW_MS),
    )
    .expect("die Mehr-Augen-Autorisierung des Re-Grants traegt");

    let mut before = fixture::archive_support::ArchiveFixture::new();
    for (path, bytes) in f.fixture.blobs() {
        before.push_exact_bytes(path, bytes.clone());
    }
    before.push_exact_bytes(
        "trust/authorization.etb",
        authorization.exact_bytes().to_vec(),
    );

    // VORHER: beide Eintraege gueltig, keiner geoeffnet.
    let (report, decapsulations) =
        open(&before, fixture::other_recipient_key_thumbprint(), &reader);
    assert!(report.is_fully_verified(), "{report:?}");
    assert_eq!(report.recipient_grants().count(), 0, "{report:?}");
    assert_eq!(decapsulations, 0);

    // Der Re-Grant ueber den ECHTEN Ausstellungsdienst — mit dem Schluessel
    // aus dem Offline-Container und einem frischen Nachweis des Zwecks
    // `HistoricalRegrant`.
    let grant = machine
        .create_using(
            &authorization,
            recovery_key,
            &trust_support::authorized_device_signer(),
            &machine.proof,
            &issuance::Account,
            &machine.audit,
            &issuance::Registry {
                fixture: f,
                now: Cell::new(NOW_MS),
            },
            &f.recipient_certificate,
        )
        .expect("die gueltige Zeremonie stellt den Re-Grant aus");
    let grant_object = object_hash(grant.as_bytes());

    let mut after = before;
    after.push_object("grants/historical.eag", grant);

    // NACHHER: genau der ausgewaehlte Eintrag oeffnet, der andere nicht.
    let (report, decapsulations) = open(&after, fixture::other_recipient_key_thumbprint(), &reader);
    assert!(report.is_fully_verified(), "{report:?}");
    let opened: Vec<_> = report.recipient_grants().collect();
    assert_eq!(opened.len(), 1, "{report:?}");
    assert!(
        opened[0].0 == f.entry_hash,
        "geoeffnet ist der AUSGEWAEHLTE"
    );
    assert!(opened[0].1 == grant_object);
    assert!(
        report
            .recipient_grants()
            .all(|(entry, _, _)| entry != second.entry_hash),
        "der NICHT ausgewaehlte alte Eintrag hat keinen Grant fuer den neuen Reader"
    );
    assert_eq!(
        decapsulations, 1,
        "genau eine Entkapselung: die des ausgewaehlten Eintrags"
    );

    // Ein DRITTER Schluessel bekommt nichts.
    let (report, decapsulations) = open(&after, stranger_thumbprint, &stranger);
    assert!(report.is_fully_verified(), "{report:?}");
    assert_eq!(report.recipient_grants().count(), 0, "{report:?}");
    assert_eq!(decapsulations, 0);

    // Und die beiden alten `.eip` liegen Byte fuer Byte, wie sie lagen.
    for (relative, bytes) in [
        ("archive/entries/000000000000_entry.eip", &f.entry_bytes),
        (
            "archive/entries/000000000001_entry.eip",
            &second.entry_bytes,
        ),
    ] {
        assert_eq!(
            &fs::read(machine.root.path().join(relative)).expect("das alte .eip liegt"),
            bytes,
            "der Re-Grant ruehrt die alten Eintragsbytes nicht an"
        );
    }
}
