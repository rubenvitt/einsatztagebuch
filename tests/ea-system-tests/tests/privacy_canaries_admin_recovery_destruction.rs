//! Die Kanarienvögel der Stufe 5: kein Bedienername, kein Profilsalz, kein
//! Schlüsselmaterial, kein Wiederherstellungsklartext und kein fachlicher
//! Inhalt überlebt in einem signierten Auditdatensatz, einem Bericht, einer
//! Fehlerausgabe oder einer Datei, die die Verwaltungs-, Wiederherstellungs-
//! und Vernichtungspfade schreiben.
//!
//! Plan Stufe 5, Task 14, Step 3 (`docs/superpowers/plans/
//! 2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`). Die Form
//! folgt Stufe 3 (Ruling R41): kein `xtask test-privacy`, sondern
//! `cargo test -p ea-system-tests --test
//! privacy_canaries_admin_recovery_destruction`. Direktes Vorbild ist
//! `privacy_canaries_writer.rs`.
//!
//! # Abgedeckt — ECHT in diesem Prozess erzeugt, danach roh durchsucht
//!
//! | Ereignis | Erzeuger (Produktcode) | Szene |
//! |---|---|---|
//! | `login` (`completed`) | `OperatorBindingService::verify_session`, `crates/ea-admin/src/operator.rs:995` | [`login_scene`] |
//! | `login` (`failed`) + `reauthFailure` | dieselbe Funktion, `operator.rs:995` und `:1006` | [`login_scene`] |
//! | `registryStaleWarnAcceptance` samt anschließendem Abschluss | `WriterService::acknowledge_stale_registry`, `crates/ea-writer/src/stale_registry.rs:195` | [`stale_warning_scene`] |
//! | `historicalRegrant` | `HistoricalGrantService::create`, `crates/ea-recovery/src/historical_grant.rs:296` | [`recovery_scene`] |
//! | Wiederherstellungsprobe (entschlüsselt den Klartext) | `RecoveryArchiveProbe::test_recovery_medium`, `crates/ea-recovery/src/recovery_sample.rs:100` | [`recovery_scene`] |
//! | `clockSkewRelease` samt Anwendung und Wiedereinspielung | `ClockReleaseService::issue`, `crates/ea-admin/src/clock_release.rs:406` | [`clock_release_scene`] |
//! | `destruction` (Anfrage) | `DestructionRequestService::request`, `crates/ea-destruction/src/service.rs:252` | [`destruction_scene`] |
//!
//! Durchsucht werden je Szene ALLE entstandenen Bytes: jede Datei unter der
//! Szenenwurzel ROH (SQLCipher-Datenbank samt `-wal`/`-shm`, Archivdateien),
//! jeder Datei- und Verzeichnisname, jede signierte Auditzeile so, wie die
//! entschlüsselte Datenbank sie herausgibt, die exakten Rückgabebytes (Grant,
//! Auditzeile der Vernichtungsanfrage) und die Fehler- und
//! Diagnosetexte, die die Pfade an einen Bediener oder ein Protokoll reichen
//! können (`Debug`, `Display`, `code()`).
//!
//! Jeder Kanarienvogel wird ROH, hexadezimal (klein und groß) und base64
//! (Standard- und URL-Alphabet, in allen drei Ausrichtungen) gesucht:
//! [`needle_encodings`].
//!
//! # Die Kanarienarten
//!
//! - **Bedienername und Funktionsbezeichnung.** In der Anmeldeszene frei
//!   gewählt ([`LOGIN_DISPLAY_NAME`], [`LOGIN_FUNCTION_LABEL`]); in der
//!   Writer- und der Wiederherstellungsszene die Fixturwerte, die die
//!   geteilten Kulissen fest verdrahten und hier nicht geändert werden dürfen
//!   (`"Ada Lovelace"` in `crates/ea-writer/tests/support/mod.rs:153`,
//!   `"Erika Beispiel"` in `crates/ea-verify/tests/support/historical.rs`).
//! - **Profilsalz.** Frei gewählt ([`LOGIN_PROFILE_SALT`]) bzw. die Fixturwerte
//!   `[0x33; 32]` und `[0x30; 32]`.
//! - **Schlüsselmaterial.** Nur Geheimnisse, die der jeweilige Pfad WIRKLICH
//!   benutzt: der Instanzschlüssel der Bedienerin ([`LOGIN_INSTANCE_SECRET`],
//!   frei gewählt), der Gerätesignierschlüssel der Auditzeilen, der private
//!   Recovery-KEM-Schlüssel, der Signierschlüssel der Historical-Grant-
//!   Authority, der Wurzelschlüssel der Linie und der Instanzschlüssel der
//!   Vernichtungsbedienerin. Der Instanzschlüssel des Adminbedieners der
//!   historischen Kulisse fehlt mit Grund: seine 32 Byte sind zugleich eine
//!   öffentliche Nonce der Vertrauenslinie (siehe
//!   [`RECOVERY_FIXTURE_PROFILE_SALT`] und die Notiz darunter).
//! - **Wiederherstellungsklartext.** Der Inhaltsschlüssel (CEK), den
//!   `HistoricalGrantService::create` über den Recovery-KEM zurückgewinnt —
//!   hier unabhängig über dieselbe KEM-Operation nachgerechnet und als Nadel
//!   gesetzt —, und der entschlüsselte Einsatzklartext der
//!   Wiederherstellungsprobe.
//! - **Fachlicher Inhalt.** Die neun Writer-Marker aus
//!   `support::CANARY_MARKERS` (beide Ausprägungen) und die eigenen Marker des
//!   Wiederherstellungseinsatzes ([`RECOVERY_CANARIES`]).
//!
//! # NICHT abgedeckt — ausdrücklich, mit Grund und Entstehungsort
//!
//! Nichts davon wird hier gefälscht oder nachgebaut.
//!
//! - **`bindingChange` und `revocation`** (`crates/ea-admin/src/operator.rs:408`,
//!   `:427`, `:764`; `crates/ea-admin/src/operator_host.rs:777`;
//!   `crates/ea-admin/src/operator_ceremony.rs:489`). `provision`/`revoke`
//!   verlangen einen `OperatorAuthorizationPort`, einen
//!   `NativeOperatorProvisioning`-Wirt und einen
//!   `ExternalOperatorIdentityVerifier`. Die einzige Fixtur dafür liegt in
//!   `crates/ea-admin/tests/support/operator_lifecycle.rs` und hängt an
//!   `crates/ea-admin/tests/support/mod.rs`, das `RecoveryTestObservation`
//!   und `verify_fresh_machine_recovery_test` importiert — beide existieren
//!   nur unter dem Merkmal `test-support` von `ea-admin`
//!   (`crates/ea-admin/src/lib.rs:146`), und dieses Merkmal bleibt für
//!   `ea-system-tests` laut `tests/ea-system-tests/Cargo.toml` AUS.
//! - **`adminRootCeremony`** (`crates/ea-admin/src/root_ceremony.rs:242`,
//!   `:416`). Derselbe Grund: die Zeremonienkulisse (`BootstrapHarness`,
//!   `ceremony_service`) liegt in `crates/ea-admin/tests/support/mod.rs`.
//! - **`recoveryTest`** (`crates/ea-admin/src/recovery_test_runtime.rs:223`,
//!   `:346`; `recovery_test_runtime/execution.rs:410`, `:477`;
//!   `recovery_test_runtime/import.rs:153`) und der JSON-Bericht von
//!   `RecoveryTestRun` (`crates/ea-recovery/src/test_run.rs:98`, `:110`).
//!   Die signierte Zeile schreibt nur die native `RecoveryTestRuntime`; der
//!   Bericht verlangt einen signierten Recovery-Source-Umschlag, den im
//!   Bestand nur `crates/ea-recovery/tests/source_manifest.rs` mit einer
//!   TESTSIGNIERTEN Zeile baut. Abgedeckt ist hier der Teil davor, der den
//!   Klartext wirklich entschlüsselt (die Wiederherstellungsprobe).
//! - **`destruction` nach der Anfrage** (Ausführung und Stub,
//!   `crates/ea-destruction/src/execution.rs:106`;
//!   `crates/ea-admin/src/destruction_runtime/import.rs:184`). Nur der
//!   Anfragepfad ist ohne Server/Objektspeicher in-process erreichbar.
//! - **`plaintextExport`** (`crates/ea-reader/src/export.rs:355`). Abgedeckt
//!   von `privacy_canaries_reader.rs`
//!   (`the_signed_local_audit_log_carries_binding_and_hashes_and_never_a_marker`)
//!   gegen die fachlichen Reader-Marker; hier nicht wiederholt.
//! - **Die Admin-Autoritätsantworten** der Operationen `describe-admin`
//!   (`crates/ea-admin/src/operator_authority.rs:580`, JSON `:596-603`) und
//!   `identity` (`collect_identity`, `:719`, JSON `:831-834`, dazu die Zeile
//!   in `operator_authority_identity`, `:826`). Sie tragen Bedienername,
//!   Funktion und Profilsalz (hex) BEABSICHTIGT als Nutzlast der
//!   Operator-Exchange-Antwort an die anfragende Gegenstelle; erzeugt nur
//!   über den nativen `OperatorRuntime` (`runtime.reauthenticate()`). Ob diese
//!   Antwort irgendwo protokolliert oder unverschlüsselt abgelegt wird, misst
//!   dieser Zeuge NICHT.
//! - **CLI-, UI- und Serverprotokolle** der Prozesspfade
//!   (`apps/cli`, `apps/desktop`, `apps/server`). Sie entstehen nur im
//!   nativen Prozess; `apps/server/tests/privacy_canaries_server.rs` misst
//!   die Serverseite getrennt.
//!
//! Die Uhrfreigabe- und die Vernichtungsszene tragen KEIN Bedienerprofil und
//! keinen fachlichen Inhalt: ihre Kulissen setzen keines, und ihre
//! Auditkontexte (`ClockReleaseContextV1`, `DestructionContextV1`,
//! `crates/ea-format/src/local_audit.rs:63-74`, `:626-629`) führen nur Zeiten,
//! Hashes und Aufzählungen. Gesucht wird dort ausschließlich nach
//! Schlüsselmaterial.
//!
//! Drei Nadeln sind Fixturkonstanten aus EINEM wiederholten Byte
//! (`[0x33; 32]`, `[0x30; 32]`, `[0x44; 32]`) und gehören nicht diesem
//! Zeugen. Ein künftiger Fund auf einer von ihnen ist zuerst gegen den
//! Präzedenzfall `[0x61; 32]` (öffentliche Nonce der Vertrauenslinie, siehe
//! [`RECOVERY_FIXTURE_PROFILE_SALT`]) zu prüfen, bevor er als Produktleck
//! gilt.
//!
//! # Zeugengüte
//!
//! - Positivkontrollen je Szene: der Kanarienvogel steckt nachweislich IM
//!   System (die entschlüsselte Datenbank gibt Bedienernamen und Salz zurück;
//!   der Einsatz trägt die Marker VOR dem Abschluss; die Probe entschlüsselt
//!   genau den Kanarieneinsatz; der KEM-Schlüssel öffnet den Originalgrant).
//! - Anti-Leerlauf NAMENTLICH: jede Szene verlangt ihre Flächen beim Namen
//!   und die erwartete Zahl und Art der Auditzeilen.
//! - [`the_search_finds_every_encoding_of_a_marker_that_really_lies_in_a_scene`]:
//!   die Suche FINDET jeden Kanarienvogel in jeder Kodierung, wenn er
//!   wirklich in einer Szenendatei liegt — auch base64 mitten in einem
//!   größeren Blob, in jeder der drei Ausrichtungen.
//!
//! # Keine Bytes in Zusicherungen
//!
//! Meldungen nennen Kanarienvogel, Kodierung und Fläche — nie den Inhalt.
#![allow(clippy::duplicate_mod, clippy::too_many_lines)]

// Der Name `support` ist hier Pflicht: das Ausstellungsmodul von `ea-recovery`
// greift über `super::support` auf genau diese Kulisse zu.
#[path = "../../../crates/ea-recovery/tests/support/mod.rs"]
mod support;

#[allow(dead_code)]
#[path = "../../../crates/ea-recovery/tests/historical_grant/support.rs"]
mod issuance;

#[path = "../../../crates/ea-destruction/tests/support/mod.rs"]
mod destruction_support;

#[path = "support/mod.rs"]
mod writer_canary;

#[path = "registry_effectiveness_support/mod.rs"]
mod registry_support;

use std::path::Path;
use std::sync::Arc;

use ea_admin::{OperatorBindingService, VerifiedLocalDeviceIdentity, VerifySessionRequest};
use ea_audit::{LocalAuditRepository, SignedLocalAuditService, SqliteLocalAuditRepository};
use ea_crypto::{CanonicalPublicCoseKey, object_hash};
use ea_format::{
    CertificateKindV1, KeyProtectionProfileV1, LocalAuditActionV1, LocalAuditOutcomeV1,
    OperatorRoleV1, ParsedArchiveObject, decode_exact_object, decode_local_audit_event,
};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OsAccountProvider, ReauthPurpose,
};
use ea_recovery::RecoveryKem as _;
use ea_trust::{RegistryHeadPin, RegistrySelectionOutcome, SelectedRegistryHead};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, Hash32, ObjectHash, OperatorSubjectId,
    OrganizationId, RegistryVersion, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

use registry_support::trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};
use writer_canary::{
    CANARY_MARKERS, CanaryVariantV1, canary_incident, every_file_under, every_path_name_under,
};

// ===========================================================================
// Die Kanarienvögel
// ===========================================================================

/// Der Bedienername der Anmeldeszene — frei gewählt, weil diese Szene ihre
/// Profilzeile selbst setzt.
const LOGIN_DISPLAY_NAME: &str = "KANARIE-BEDIENERNAME-5a91";
/// Die Funktionsbezeichnung der Anmeldeszene.
const LOGIN_FUNCTION_LABEL: &str = "KANARIE-FUNKTION-6b02";
/// Das Profilsalz der Anmeldeszene: 32 Byte, als ASCII lesbar, damit ein Fund
/// in einem Protokoll auch ohne Werkzeug auffiele.
const LOGIN_PROFILE_SALT: [u8; 32] = *b"KANARIE-PROFILSALZ-3e71-9d02-xq!";
/// Der Instanzschlüssel der Bedienerin: ein gültiges Ed25519-Geheimnis (jede
/// 32-Byte-Folge ist eines) und zugleich ein Kanarienvogel.
const LOGIN_INSTANCE_SECRET: [u8; 32] = *b"KANARIE-INSTANZSCHLUESSEL-7c4e1!";
/// Die Kontobindung, die Bindung und Konto gemeinsam nennen.
const LOGIN_ACCOUNT_MARKER: u8 = 0x73;
/// Die Betreffkennung der Bedienerin.
const LOGIN_SUBJECT_MARKER: u8 = 0x71;

/// Bedienername, Funktion und Salz der geteilten Writer-Kulisse
/// (`crates/ea-writer/tests/support/mod.rs:153-155`, privat dort).
const WRITER_FIXTURE_DISPLAY_NAME: &str = "Ada Lovelace";
const WRITER_FIXTURE_PROFILE_SALT: [u8; 32] = [0x33; 32];

/// Bedienername und Salz, die die historische Fixtur fest an die
/// Writer-Bindung bindet (`crates/ea-verify/tests/support/historical.rs`).
/// Die Wiederherstellungsprobe prüft den Klartext GEGEN diese Zusage; ein
/// eigener Name hier ließe die Probe scheitern.
const RECOVERY_FIXTURE_DISPLAY_NAME: &str = "Erika Beispiel";
const RECOVERY_FIXTURE_FUNCTION_LABEL: &str = "Einsatzleitung";
const RECOVERY_FIXTURE_PROFILE_SALT: [u8; 32] = [0x30; 32];
/// Der Instanzschlüssel des Adminbedieners der historischen Kulisse
/// (`crates/ea-recovery/tests/historical_grant/support.rs`) ist `[0x61; 32]`
/// und taugt NICHT als Nadel: dieselben 32 Byte sind die öffentliche
/// Ereignis-Nonce der ersten Registeränderung jeder `ea-trust`-Linie
/// (`crates/ea-trust/tests/support/mod.rs:572-574`: `0x21 + 0x40`), stehen
/// also rechtmäßig in `archive/trust/registry-events/`. Gemessen am
/// 2026-09-19 — die erste Fassung dieses Zeugen meldete genau dort einen
/// Fund. Der Instanzschlüssel bleibt deshalb ungesucht.
/// Der Instanzschlüssel der Vernichtungsbedienerin
/// (`crates/ea-destruction/tests/support/mod.rs`).
const DESTRUCTION_INSTANCE_SECRET: [u8; 32] = [0x44; 32];

/// Die fachlichen Marker des Wiederherstellungseinsatzes, je Feld EIN Marker.
const RECOVERY_CANARIES: [(&str, &str); 5] = [
    ("Stichwort", "KANARIE-WH-STICHWORT-41d6"),
    ("Ort", "KANARIE-WH-ORT-92ab"),
    ("Leergrund Personal", "KANARIE-WH-GRUND-PERSONAL-17ce"),
    ("Leergrund Fahrzeuge", "KANARIE-WH-GRUND-FAHRZEUG-5f30"),
    ("Freitext", "KANARIE-WH-FREITEXT-c84e"),
];

/// Eine Nadel: benannt, einer Art zugeordnet, mit den ROHEN Bytes.
struct Needle {
    label: String,
    kind: &'static str,
    bytes: Vec<u8>,
}

impl Needle {
    fn new(kind: &'static str, label: impl Into<String>, bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref().to_vec();
        assert!(
            bytes.len() >= 9,
            "eine Nadel unter neun Byte faende sich zufaellig; sie waere kein Kanarienvogel"
        );
        Self {
            label: label.into(),
            kind,
            bytes,
        }
    }
}

const KIND_OPERATOR: &str = "Bedieneridentitaet";
const KIND_SALT: &str = "Profilsalz";
const KIND_KEY: &str = "Schluesselmaterial";
const KIND_RECOVERY: &str = "Wiederherstellungsklartext";
const KIND_FACHLICH: &str = "fachlicher Inhalt";

// ===========================================================================
// Die Suche
// ===========================================================================

const BASE64_STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 OHNE Auffüllung; eine unvollständige letzte Gruppe trägt nur die
/// Zeichen, deren Bits sie kennt.
fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b0 = u32::from(group[0]);
        let b1 = u32::from(group.get(1).copied().unwrap_or(0));
        let b2 = u32::from(group.get(2).copied().unwrap_or(0));
        let word = (b0 << 16) | (b1 << 8) | b2;
        let chars = group.len() + 1;
        for index in 0..chars {
            let shift = 18 - 6 * index;
            out.push(alphabet[((word >> shift) & 0x3f) as usize]);
        }
    }
    out
}

/// Die base64-Zeichen, die ALLEIN von `needle` abhängen, wenn `needle` mit
/// `offset` Byte Versatz (`0..3`) in einem größeren base64-Blob steht.
///
/// Die ersten `[0, 2, 3][offset]` Zeichen hängen am unbekannten Vorgänger,
/// das letzte angefangene Zeichen am unbekannten Nachfolger; beide fallen
/// weg. Was bleibt, steht in JEDEM Blob, der die Nadel mit diesem Versatz
/// kodiert — genau das macht die Suche unabhängig von der Ausrichtung.
fn stable_base64(needle: &[u8], offset: usize, alphabet: &[u8; 64]) -> Vec<u8> {
    let mut shifted = vec![0_u8; offset];
    shifted.extend_from_slice(needle);
    let encoded = base64(&shifted, alphabet);
    let full_groups = shifted.len() / 3;
    let known_tail = [0, 1, 2][shifted.len() % 3];
    let end = 4 * full_groups + known_tail;
    let start = [0, 2, 3][offset];
    encoded[start..end].to_vec()
}

/// Jede Kodierung, in der eine Nadel gesucht wird, benannt.
fn needle_encodings(needle: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut encodings = vec![
        ("roh".to_owned(), needle.to_vec()),
        ("hex".to_owned(), hex::encode(needle).into_bytes()),
        ("HEX".to_owned(), hex::encode_upper(needle).into_bytes()),
    ];
    for offset in 0..3 {
        encodings.push((
            format!("base64 (Versatz {offset})"),
            stable_base64(needle, offset, BASE64_STANDARD),
        ));
        encodings.push((
            format!("base64url (Versatz {offset})"),
            stable_base64(needle, offset, BASE64_URL),
        ));
    }
    encodings
}

/// Jeder Fund als Satz „Nadel, Kodierung, Fläche" — ohne den Inhalt.
fn leaks(streams: &[(String, Vec<u8>)], needles: &[Needle]) -> Vec<String> {
    let mut found = Vec::new();
    for needle in needles {
        for (encoding, bytes) in needle_encodings(&needle.bytes) {
            for (place, haystack) in streams {
                if ea_testkit::contains_canary(haystack, &bytes) {
                    found.push(format!(
                        "{} [{}] als {encoding} in {place}",
                        needle.label, needle.kind
                    ));
                }
            }
        }
    }
    found
}

fn assert_no_leak(scene: &str, streams: &[(String, Vec<u8>)], needles: &[Needle]) {
    let found = leaks(streams, needles);
    assert!(
        found.is_empty(),
        "{scene}: {} Klartextfund(e):\n{}",
        found.len(),
        found.join("\n")
    );
}

/// Verlangt jede benannte Fläche — ein `streams.len() > 0` hielte auch über
/// einer Szene, der die Datenbank fehlt.
fn assert_surfaces(scene: &str, streams: &[(String, Vec<u8>)], required: &[&str]) {
    for surface in required {
        assert!(
            streams
                .iter()
                .any(|(place, bytes)| place.contains(surface) && !bytes.is_empty()),
            "{scene}: die Fläche {surface:?} fehlt oder ist leer; die Suche liefe dort ins Leere"
        );
    }
}

/// Jede Datei unter `root` ROH, dazu alle Datei- und Verzeichnisnamen.
fn files_and_names(prefix: &str, root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut streams: Vec<(String, Vec<u8>)> = every_file_under(root)
        .into_iter()
        .map(|(path, bytes)| (format!("{prefix}: Datei {path}"), bytes))
        .collect();
    streams.push((
        format!("{prefix}: jeder Datei- und Verzeichnisname"),
        every_path_name_under(root),
    ));
    streams
}

/// Jede Zeile von `local_audit_event`, wie die ENTSCHLÜSSELTE Datenbank sie
/// herausgibt, in Einfügereihenfolge.
fn audit_rows(database: &EncryptedDatabase) -> Vec<Vec<u8>> {
    let mut rows = Vec::new();
    loop {
        let offset = i64::try_from(rows.len()).expect("die Zeilenzahl passt in i64");
        let Some(row) = database
            .query_row(
                "SELECT exact_bytes FROM local_audit_event ORDER BY rowid LIMIT 1 OFFSET ?1",
                &[StoreValue::Integer(offset)],
            )
            .expect("die Auditablage muss lesbar sein")
        else {
            return rows;
        };
        rows.push(row.blob(0).expect("exact_bytes ist ein Blob").to_vec());
    }
}

fn audit_streams(prefix: &str, rows: &[Vec<u8>]) -> Vec<(String, Vec<u8>)> {
    rows.iter()
        .enumerate()
        .map(|(index, bytes)| {
            let action = decode_local_audit_event(bytes).map_or_else(
                |_| "undekodierbar".to_owned(),
                |event| format!("Aktion {}", event.action().code()),
            );
            (
                format!("{prefix}: signierte Auditzeile {index} ({action})"),
                bytes.clone(),
            )
        })
        .collect()
}

/// Die Rohdatei einer SQLCipher-Datenbank beginnt NICHT mit dem
/// SQLite-Kopf — sonst wäre jede Klartextsuche in ihr wertlos, weil der
/// Inhalt dann seitenweise lesbar läge und nur zufällig nicht getroffen würde.
fn assert_database_file_is_encrypted(scene: &str, path: &Path) {
    let bytes = std::fs::read(path).expect("die Datenbankdatei muss lesbar sein");
    assert!(
        bytes.len() > 16 && !bytes.starts_with(b"SQLite format 3\0"),
        "{scene}: {} ist keine verschlüsselte Datenbank",
        path.display()
    );
}

// ===========================================================================
// Szene 1: Anmeldung, gescheiterte Anmeldung, Reauthentisierungsfehler
// ===========================================================================

/// Die Bindung des Kopfes der Anmeldeszene.
const LOGIN_BINDING_HEAD: usize = 2;
/// Die vorgeschlagene Sequenz der Anmeldeszene.
const LOGIN_PROPOSED_SEQUENCE: u64 = 50;
/// Der Zeitboden und die Uhr der Anmeldeszene.
const LOGIN_NOW_MS: i64 = 1_000;

struct LoginAccount;

impl OsAccountProvider for LoginAccount {
    fn os_account_binding_hash(
        &self,
        _organization: OrganizationId,
        _device: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(registry_support::trust_support::hash32(
            LOGIN_ACCOUNT_MARKER,
        ))
    }

    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(registry_support::public_key(LOGIN_INSTANCE_SECRET)))
    }
}

struct LoginAuthenticator {
    bound: BoundOperator,
    fail: bool,
}

impl OperatorAuthenticator for LoginAuthenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }

    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        if self.fail {
            return Err(OperatorError::PresenceProofInvalid);
        }
        Ok(SigningKey::from_bytes(&LOGIN_INSTANCE_SECRET)
            .sign(challenge)
            .to_bytes())
    }
}

/// Was die Anmeldeszene hinterlässt.
struct LoginScene {
    root: support::TempDir,
    database_path: std::path::PathBuf,
    rows: Vec<Vec<u8>>,
    diagnostics: Vec<u8>,
    decrypted_display_name: String,
    decrypted_salt: Vec<u8>,
    binding: ObjectHash,
}

fn login_head(line: &RegistryLineBuilder) -> SelectedRegistryHead {
    let head = line.heads()[LOGIN_BINDING_HEAD];
    let key = registry_support::trust_support::state_key();
    let trusted_time = ea_time::TrustedTimeState::initial(UnixMillis::new(LOGIN_NOW_MS));
    let trust =
        line.verified_with_record(Pin::Head(LOGIN_BINDING_HEAD), 17, trusted_time.clone(), key);
    let candidate =
        ea_trust::verify_registry_candidate(&trust, ChainSequence::new(LOGIN_PROPOSED_SEQUENCE))
            .expect("der Kandidat der Anmeldeszene verifiziert");
    let mut store = registry_support::WorkflowStore::new(
        key,
        17,
        trusted_time,
        Some(RegistryHeadPin::new(head.version, head.object_hash)),
    );
    let local_time =
        ea_trust::prepare_local_time(&mut store, &candidate, UnixMillis::new(LOGIN_NOW_MS), &[])
            .expect("die lokale Zeit der Anmeldeszene ist vorbereitbar");
    let RegistrySelectionOutcome::Selected(selected) =
        ea_trust::select_registry_head(candidate, local_time, None)
            .expect("die Auswahl der Anmeldeszene gelingt")
    else {
        panic!("die Anmeldeszene muss ihren eigenen Kopf wählen");
    };
    selected
}

/// Eine echte Bedienerin mit Kanarien-Profil in einer echten
/// SQLCipher-Datei; drei Auditzeilen über den produktiven Dienst.
fn login_scene() -> LoginScene {
    let window = |start, end| HeadOptions {
        effective_from: Some(start),
        valid_through: Some(end),
        not_after: UnixMillis::new(10_000_000),
        ..HeadOptions::default()
    };
    let organization = registry_support::trust_support::organization();
    let subject = OperatorSubjectId::try_from(&[LOGIN_SUBJECT_MARKER; 16][..])
        .expect("16 Byte sind eine Betreffkennung");
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        window(1, 10),
    );
    let certificate = line
        .push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            window(11, 20),
        )
        .direct_object_hash
        .expect("das Gerätezertifikat ist ein direktes Ziel");
    let binding = line
        .push(
            ActionSpec::OperatorBinding {
                certificate_hash: certificate,
                role: OperatorRoleV1::Writer,
                marker: LOGIN_SUBJECT_MARKER,
                effective_from: None,
            },
            HeadOptions {
                binding_operator_profile_commitment_override: Some(
                    ea_crypto::operator_profile_commitment(
                        organization,
                        subject,
                        LOGIN_DISPLAY_NAME,
                        LOGIN_FUNCTION_LABEL,
                        &LOGIN_PROFILE_SALT,
                    ),
                ),
                binding_instance_key_thumbprint_override: Some(
                    registry_support::public_key(LOGIN_INSTANCE_SECRET).thumbprint(),
                ),
                binding_os_account_hash_override: Some(registry_support::trust_support::hash32(
                    LOGIN_ACCOUNT_MARKER,
                )),
                ..window(21, 100)
            },
        )
        .direct_object_hash
        .expect("die Bindung ist ein direktes Ziel");
    let head = login_head(&line);

    let root = support::temp_dir("privacy-stage5-login");
    let database_path = root.path().join("profile.sqlite");
    let provider = InMemoryKeyProvider::new_for_test([0x6c; 32]);
    let database_key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .expect("der Datenbankschlüssel entsteht");
    let database = Arc::new(
        EncryptedDatabase::open(&database_path, &provider, &database_key)
            .expect("die Profildatenbank öffnet"),
    );
    database
        .execute(
            "INSERT INTO operator_profile VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                StoreValue::Blob(organization.as_bytes().to_vec()),
                StoreValue::Blob(subject.as_bytes().to_vec()),
                StoreValue::Text(LOGIN_DISPLAY_NAME.to_owned()),
                StoreValue::Text(LOGIN_FUNCTION_LABEL.to_owned()),
                StoreValue::Blob(LOGIN_PROFILE_SALT.to_vec()),
                StoreValue::Blob(binding.as_bytes().to_vec()),
            ],
        )
        .expect("die Profilzeile lässt sich setzen");

    let signer = Arc::new(registry_support::FixtureKeyProvider::new(
        registry_support::trust_support::device_signing_secret(),
    ));
    let handle = signer.handle();
    let audit = SignedLocalAuditService::new(
        Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&database)))
            as Arc<dyn LocalAuditRepository>,
        signer as Arc<dyn KeyProvider>,
        handle,
        certificate,
        head.preexisting_effective_now().value(),
    );
    let certificate_hash = CertificateHash::from(certificate);
    let device = head
        .active_certificate_fields(certificate_hash)
        .expect("das Gerätezertifikat ist aktiv")
        .device_id;
    let local = VerifiedLocalDeviceIdentity::verify(&head, certificate_hash, device)
        .expect("die lokale Geräteidentität verifiziert");
    let service = OperatorBindingService::new(&head, &audit, local);
    let request = |authenticator| VerifySessionRequest {
        database: &database,
        binding_object_hash: binding,
        device_certificate_hash: certificate_hash,
        role: OperatorRoleV1::Writer,
        purpose: ReauthPurpose::AdminRootCeremony,
        account: Arc::new(LoginAccount),
        authenticator,
    };

    let mut diagnostics = Vec::new();
    let present = LoginAuthenticator {
        bound: BoundOperator::resolve(&head, binding).expect("die Bindung ist aktiv"),
        fail: false,
    };
    let session = service
        .verify_session(request(&present))
        .expect("die Anmeldung der Kanarienbedienerin gelingt");
    // Positivkontrolle: die ENTSCHLÜSSELTE Ablage trägt die Kanarienvögel.
    let decrypted_display_name = session.profile().display_name().to_owned();
    let decrypted_salt = session.profile().profile_commitment_salt().to_vec();
    drop(session);

    let absent = LoginAuthenticator {
        bound: BoundOperator::resolve(&head, binding).expect("die Bindung ist aktiv"),
        fail: true,
    };
    let refused = service
        .verify_session(request(&absent))
        .err()
        .expect("ohne Präsenz scheitert die Anmeldung");
    diagnostics.extend_from_slice(format!("{refused:?}\n{refused}\n").as_bytes());

    let rows = audit_rows(&database);
    LoginScene {
        root,
        database_path,
        rows,
        diagnostics,
        decrypted_display_name,
        decrypted_salt,
        binding,
    }
}

fn login_needles() -> Vec<Needle> {
    vec![
        Needle::new(KIND_OPERATOR, "Bedienername", LOGIN_DISPLAY_NAME),
        Needle::new(KIND_OPERATOR, "Funktionsbezeichnung", LOGIN_FUNCTION_LABEL),
        Needle::new(KIND_SALT, "Profilsalz", LOGIN_PROFILE_SALT),
        Needle::new(
            KIND_KEY,
            "Instanzschluessel der Bedienerin",
            LOGIN_INSTANCE_SECRET,
        ),
        Needle::new(
            KIND_KEY,
            "Geraetesignierschluessel der Auditzeilen",
            registry_support::trust_support::device_signing_secret(),
        ),
    ]
}

impl LoginScene {
    fn streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = files_and_names("Anmeldung", self.root.path());
        streams.extend(audit_streams("Anmeldung", &self.rows));
        streams.push((
            "Anmeldung: Fehlerausgabe (Debug und Display)".to_owned(),
            self.diagnostics.clone(),
        ));
        streams
    }
}

#[test]
fn login_failed_login_and_reauth_failure_audits_carry_no_operator_profile_or_key() {
    let scene = login_scene();

    // Positivkontrollen: die Kanarienvögel liegen WIRKLICH im System.
    assert_eq!(scene.decrypted_display_name, LOGIN_DISPLAY_NAME);
    assert_eq!(scene.decrypted_salt, LOGIN_PROFILE_SALT);
    assert_database_file_is_encrypted("Anmeldung", &scene.database_path);

    // Anti-Leerlauf: genau die drei Zeilen, in genau dieser Reihenfolge.
    let actions: Vec<(u8, LocalAuditOutcomeV1)> = scene
        .rows
        .iter()
        .map(|bytes| {
            let event = decode_local_audit_event(bytes).expect("die Auditzeile dekodiert");
            (event.action().code(), event.outcome())
        })
        .collect();
    assert_eq!(
        actions,
        [
            (0, LocalAuditOutcomeV1::Completed),
            (0, LocalAuditOutcomeV1::Failed),
            (1, LocalAuditOutcomeV1::Failed),
        ],
        "Anmeldung, gescheiterte Anmeldung und Reauthentisierungsfehler MÜSSEN gebucht sein"
    );
    for bytes in &scene.rows {
        let event = decode_local_audit_event(bytes).expect("die Auditzeile dekodiert");
        assert!(
            event.operator_binding_object_hash() == Some(scene.binding),
            "jede Zeile nennt die Bindung — als Hash, nicht als Profil"
        );
        assert!(matches!(
            event.action(),
            LocalAuditActionV1::Login(_) | LocalAuditActionV1::ReauthFailure(_)
        ));
    }

    let streams = scene.streams();
    assert_surfaces(
        "Anmeldung",
        &streams,
        &[
            "Datei profile.sqlite",
            "signierte Auditzeile 0",
            "signierte Auditzeile 2",
            "Fehlerausgabe",
            "Datei- und Verzeichnisname",
        ],
    );
    assert_no_leak("Anmeldung", &streams, &login_needles());
}

// ===========================================================================
// Szene 2: Stale-Registry-Quittung und Abschluss mit fachlichen Kanarien
// ===========================================================================

struct StaleWarningScene {
    harness: writer_canary::writer_support::WriterHarness,
    audit: Vec<u8>,
    rows: Vec<Vec<u8>>,
    diagnostics: Vec<u8>,
}

fn stale_warning_scene(variant: CanaryVariantV1) -> StaleWarningScene {
    let harness = writer_canary::writer_support::WriterHarness::with_incident();
    let mut diagnostics = Vec::new();
    let audit;
    {
        let source = harness.source();
        let store = ea_writer::StaleRegistryStore::new(harness.database())
            .expect("die Quittungsablage öffnet");
        let service = harness.service(&source).with_stale_registry_store(store);
        let initial = harness.proof_for(ReauthPurpose::Finalize);
        let now = harness.observed_now_after_expiry();
        let preview = service
            .preview(&initial, canary_incident(variant), now)
            .expect("die Vorschau des Kanarieneinsatzes gelingt");
        let proof = harness.context_proof(&preview, ReauthPurpose::RegistryStaleFinalize, now);
        let acknowledgement = service
            .acknowledge_stale_registry(proof, canary_incident(variant), &preview, true, now)
            .expect("die Stale-Warnung wird quittiert");
        audit = harness.audit_bytes(acknowledgement.event_id());
        let proof = harness.context_proof(&preview, ReauthPurpose::Finalize, now);
        let outcome = service.finalize_with_stale_registry(
            &proof,
            canary_incident(variant),
            &preview,
            &acknowledgement,
            now,
        );
        diagnostics.extend_from_slice(format!("{outcome:?}\n").as_bytes());
        outcome.expect("der Abschluss unter der Quittung gelingt");
        // Der Fehlerweg gehört in den Strom: die zweite Verwendung derselben
        // Quittung wird abgewiesen, und ihre Zeile sähe ein Bediener.
        let replay = service.finalize_with_stale_registry(
            &proof,
            canary_incident(variant),
            &preview,
            &acknowledgement,
            now,
        );
        diagnostics.extend_from_slice(format!("{replay:?}\n").as_bytes());
        assert!(replay.is_err(), "eine Quittung trägt genau einen Abschluss");
    }
    let rows = audit_rows(&harness.database());
    StaleWarningScene {
        harness,
        audit,
        rows,
        diagnostics,
    }
}

fn writer_needles() -> Vec<Needle> {
    let mut needles: Vec<Needle> = CANARY_MARKERS
        .iter()
        .map(|(field, marker)| Needle::new(KIND_FACHLICH, format!("Writer-Feld {field}"), marker))
        .collect();
    needles.push(Needle::new(
        KIND_OPERATOR,
        "Bedienername der Writer-Kulisse",
        WRITER_FIXTURE_DISPLAY_NAME,
    ));
    needles.push(Needle::new(
        KIND_SALT,
        "Profilsalz der Writer-Kulisse",
        WRITER_FIXTURE_PROFILE_SALT,
    ));
    needles
}

impl StaleWarningScene {
    fn streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = files_and_names("Stale-Quittung", self.harness.root());
        streams.push((
            "Stale-Quittung: exakte Quittungszeile".to_owned(),
            self.audit.clone(),
        ));
        streams.extend(audit_streams("Stale-Quittung", &self.rows));
        streams.push((
            "Stale-Quittung: Abschluss- und Fehlerausgabe (Debug)".to_owned(),
            self.diagnostics.clone(),
        ));
        streams
    }
}

#[test]
fn stale_warning_acceptance_audit_and_its_finalization_carry_no_fachliche_canary() {
    for variant in CanaryVariantV1::ALL {
        let scene = stale_warning_scene(variant);

        // Positivkontrolle: der Einsatz trug die Marker, und GENAU er wurde
        // abgeschlossen — seine Einsatznummer ist verbraucht.
        assert!(
            scene
                .harness
                .incident_number_is_taken(writer_canary::canary("human_incident_number")),
            "{variant:?}: der Kanarieneinsatz MUSS abgeschlossen sein"
        );
        // Positivkontrolle: die entschlüsselte Ablage trägt den Bedienernamen.
        let stored_name = scene
            .harness
            .database()
            .query_row("SELECT display_name FROM operator_profile", &[])
            .expect("die Profilzeile ist lesbar")
            .expect("die Kulisse setzt eine Profilzeile");
        assert_eq!(
            stored_name.text(0).expect("der Name ist Text"),
            WRITER_FIXTURE_DISPLAY_NAME
        );

        let quittung = decode_local_audit_event(&scene.audit).expect("die Quittung dekodiert");
        assert!(matches!(
            quittung.action(),
            LocalAuditActionV1::RegistryStaleWarnAcceptance(_)
        ));
        assert_eq!(quittung.outcome(), LocalAuditOutcomeV1::Accepted);
        assert!(
            scene.rows.iter().any(|row| row == &scene.audit),
            "{variant:?}: die Quittung MUSS in der Auditablage liegen"
        );

        let streams = scene.streams();
        assert_surfaces(
            "Stale-Quittung",
            &streams,
            &[
                "Datei writer.sqlite3",
                "exakte Quittungszeile",
                "signierte Auditzeile 0",
                "Abschluss- und Fehlerausgabe",
            ],
        );
        assert_no_leak(
            &format!("Stale-Quittung {variant:?}"),
            &streams,
            &writer_needles(),
        );
    }
}

// ===========================================================================
// Szene 3: Historischer Re-Grant und Wiederherstellungsprobe
// ===========================================================================

fn recovery_canary(field: &str) -> &'static str {
    RECOVERY_CANARIES
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, marker)| *marker)
        .expect("jedes benannte Feld trägt einen Marker")
}

/// Ein GÜLTIGER Einsatzklartext für die historische Fixtur, dessen
/// fachliche Felder je einen Marker tragen und dessen Bedienerschnappschuss
/// die Zusage der Fixtur erfüllt.
fn canary_recovery_payload(version: RegistryVersion, binding: ObjectHash) -> Vec<u8> {
    use ea_schema::{
        CommonHeaderV1, IncidentV1, KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1,
        OperatorSnapshotV1, PatientCount, PayloadV1, encode_payload,
    };
    let mut id = [1_u8; 16];
    id[6] = 0x70;
    id[8] = 0x80;
    let header = CommonHeaderV1::new(
        ea_types::RecordId::try_from(id.as_slice()).expect("16 Byte sind eine Satzkennung"),
        UnixMillis::new(0),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            support::verify_support::archive_support::trust_support::organization(),
            OperatorSubjectId::try_from(&[0x20; 16][..]).expect("16 Byte"),
            RECOVERY_FIXTURE_DISPLAY_NAME,
            RECOVERY_FIXTURE_FUNCTION_LABEL,
            RECOVERY_FIXTURE_PROFILE_SALT,
            binding,
        )
        .expect("der Schnappschuss ist gültig"),
        NativeSourceV1::new("ea.system-tests.stage5-canary", 1).expect("die Quelle ist gültig"),
        version,
    )
    .expect("der Kopf ist gültig");
    encode_payload(&PayloadV1::Incident(
        IncidentV1::new(
            header,
            "1970-4711",
            OccurredAtV1::new(UnixMillis::new(0), None).expect("das Intervall ist gültig"),
            KeywordV1::free_text(recovery_canary("Stichwort")).expect("das Stichwort ist gültig"),
            LocationV1::free_text(recovery_canary("Ort"), None).expect("der Ort ist gültig"),
            vec![],
            Some(recovery_canary("Leergrund Personal").to_owned()),
            vec![],
            Some(recovery_canary("Leergrund Fahrzeuge").to_owned()),
            PatientCount::Unknown,
            Some(recovery_canary("Freitext").to_owned()),
            vec![],
        )
        .expect("der Einsatz ist gültig"),
    ))
    .expect("der Einsatz kodiert")
}

struct RecoveryScene {
    harness: issuance::Harness,
    payload: Vec<u8>,
    content_key: [u8; 32],
    rows: Vec<Vec<u8>>,
    grant: Vec<u8>,
    diagnostics: Vec<u8>,
    samples: usize,
}

fn recovery_scene() -> RecoveryScene {
    use support::verify_support as fixture;
    let mut payload = Vec::new();
    let historical = fixture::historical::fixture_with_payload(|version, binding| {
        payload = canary_recovery_payload(version, binding);
        payload.clone()
    });

    // Der Wiederherstellungsklartext des Re-Grants: der CEK, den der
    // Recovery-KEM aus dem Originalgrant zurückgewinnt — hier über DIESELBE
    // KEM-Operation nachgerechnet, die `HistoricalGrantService::create` ruft.
    let ParsedArchiveObject::Grant(original) =
        decode_exact_object(&historical.original_bytes).expect("der Originalgrant dekodiert")
    else {
        panic!("der Originalgrant ist ein Grant");
    };
    let content_key = fixture::complete_recipient_private_key()
        .decapsulate(original.value())
        .expect("der Recovery-Schlüssel öffnet den Originalgrant")
        .with_exposed(|bytes| *bytes);

    let harness = issuance::Harness::new(historical);
    let mut diagnostics = Vec::new();

    // Der Re-Grant, echt ausgestellt und signiert auditiert.
    let authorization = ea_trust::verify_grant_authorization(
        &harness.fixture.authorization(800),
        &harness.fixture.selected(1, 800, 800),
    )
    .expect("die Grant-Autorisierung verifiziert");
    let grant = harness
        .create(&authorization)
        .expect("der historische Re-Grant wird ausgestellt")
        .as_bytes()
        .to_vec();
    // Der Fehlerweg des Re-Grants: ein fremder Recovery-Schlüssel.
    let refused = harness
        .create_using(
            &authorization,
            &fixture::other_recipient_private_key(),
            &registry_support::trust_support::authorized_device_signer(),
            &harness.proof,
            &issuance::Account,
            &harness.audit,
            &issuance::Registry {
                fixture: &harness.fixture,
                now: std::cell::Cell::new(800),
            },
            &harness.fixture.recipient_certificate,
        )
        .err()
        .expect("ein fremder Recovery-Schlüssel stellt keinen Grant aus");
    diagnostics
        .extend_from_slice(format!("{refused:?}\n{refused}\n{}\n", refused.code()).as_bytes());

    // Die Wiederherstellungsprobe: sie ENTSCHLÜSSELT den Kanarieneinsatz aus
    // dem Archiv und prüft ihn gegen Schema und Bedienerzusage.
    let archive = harness.root.path().join("archive");
    let source = ea_recovery::FsArchiveSource::open(&archive).expect("das Archiv öffnet");
    let probe = ea_recovery::RecoveryArchiveProbe::verify(
        &source,
        &harness.fixture.anchor,
        UnixMillis::new(800),
    )
    .expect("das Archiv verifiziert");
    let fields = original.value().grant_body().fields().clone();
    let inventory = ea_recovery::KeyInventory::parse(
        &serde_json::to_vec(&serde_json::json!({
            "schemaId": "ea.key-inventory/v1",
            "inventoryId": "aa".repeat(16),
            "media": [{
                "mediumId": "recovery-a",
                "keyRole": "recoveryRecipient",
                "expectedKeyThumbprint": hex::encode(fields.recipient_key_thumbprint.as_bytes()),
                "certificateObjectHash": hex::encode(fields.recipient_certificate_hash.as_bytes()),
                "protectionProfile": "offlineEncryptedContainer",
                "testKind": "recoveryDecrypt"
            }]
        }))
        .expect("das Inventar kodiert"),
    )
    .expect("das Inventar ist gültig");
    let medium = &inventory.media()[0];
    let tested = probe
        .test_recovery_medium(
            medium,
            harness.fixture.entry_hash,
            object_hash(&harness.fixture.original_bytes),
            &fixture::complete_recipient_private_key(),
        )
        .expect("die Probe entschlüsselt und prüft den Kanarieneinsatz");
    let samples = tested.samples().len();
    for sample in tested.samples() {
        diagnostics.extend_from_slice(
            format!(
                "{} {} {} {}\n",
                sample.schema_id(),
                sample.schema_version(),
                sample.suite_id(),
                sample.sequence().get()
            )
            .as_bytes(),
        );
    }
    let wrong_key = probe
        .test_recovery_medium(
            medium,
            harness.fixture.entry_hash,
            object_hash(&harness.fixture.original_bytes),
            &fixture::other_recipient_private_key(),
        )
        .err()
        .expect("ein fremder Schlüssel besteht die Probe nicht");
    diagnostics.extend_from_slice(format!("{wrong_key:?}\n").as_bytes());

    let rows = audit_rows(&harness.db);
    RecoveryScene {
        harness,
        payload,
        content_key,
        rows,
        grant,
        diagnostics,
        samples,
    }
}

fn recovery_needles(content_key: [u8; 32]) -> Vec<Needle> {
    use support::verify_support as fixture;
    let mut needles: Vec<Needle> = RECOVERY_CANARIES
        .iter()
        .map(|(field, marker)| {
            Needle::new(
                KIND_FACHLICH,
                format!("Wiederherstellungsfeld {field}"),
                marker,
            )
        })
        .collect();
    needles.extend([
        Needle::new(
            KIND_OPERATOR,
            "Bedienername im Einsatzklartext",
            RECOVERY_FIXTURE_DISPLAY_NAME,
        ),
        Needle::new(
            KIND_SALT,
            "Profilsalz im Einsatzklartext",
            RECOVERY_FIXTURE_PROFILE_SALT,
        ),
        Needle::new(
            KIND_RECOVERY,
            "zurueckgewonnener Inhaltsschluessel",
            content_key,
        ),
        Needle::new(
            KIND_KEY,
            "privater Recovery-KEM-Schluessel",
            fixture::complete_recipient_secret_bytes(),
        ),
        Needle::new(
            KIND_KEY,
            "Signierschluessel der Auditzeile (zweiter Bootstrap-Admin)",
            registry_support::trust_support::second_admin_signing_secret(),
        ),
        Needle::new(
            KIND_KEY,
            "Signierschluessel der Historical-Grant-Authority",
            registry_support::trust_support::device_signing_secret(),
        ),
    ]);
    needles
}

impl RecoveryScene {
    fn streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = files_and_names("Wiederherstellung", self.harness.root.path());
        streams.extend(audit_streams("Wiederherstellung", &self.rows));
        streams.push((
            "Wiederherstellung: exakte Bytes des Re-Grants".to_owned(),
            self.grant.clone(),
        ));
        streams.push((
            "Wiederherstellung: Proben-, Fehler- und Codeausgabe".to_owned(),
            self.diagnostics.clone(),
        ));
        streams
    }
}

#[test]
fn historical_regrant_audit_and_recovery_probe_leak_no_recovered_plaintext_or_key() {
    let scene = recovery_scene();

    // Positivkontrollen: der Klartext trägt die Marker und den
    // Bedienerschnappschuss, und die Probe hat GENAU ihn entschlüsselt.
    for (field, marker) in RECOVERY_CANARIES {
        assert!(
            ea_testkit::contains_canary(&scene.payload, marker.as_bytes()),
            "der Einsatzklartext MUSS den Marker für {field} tragen"
        );
    }
    assert!(ea_testkit::contains_canary(
        &scene.payload,
        RECOVERY_FIXTURE_DISPLAY_NAME.as_bytes()
    ));
    assert_eq!(
        scene.samples, 1,
        "die Probe MUSS genau den Kanarieneinsatz entschlüsselt haben"
    );
    assert!(
        scene.content_key != [0; 32],
        "der zurückgewonnene Inhaltsschlüssel ist echtes Material"
    );
    assert_database_file_is_encrypted(
        "Wiederherstellung",
        &scene.harness.root.path().join("audit.sqlite"),
    );

    assert_eq!(
        scene.rows.len(),
        1,
        "genau der gelungene Re-Grant ist auditiert"
    );
    let event = decode_local_audit_event(&scene.rows[0]).expect("die Auditzeile dekodiert");
    let LocalAuditActionV1::HistoricalRegrant(context) = event.action() else {
        panic!("die Auditzeile MUSS ein historicalRegrant sein");
    };
    assert!(context.new_grant_object_hash() == object_hash(&scene.grant));
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Completed);

    let streams = scene.streams();
    assert_surfaces(
        "Wiederherstellung",
        &streams,
        &[
            "Datei audit.sqlite",
            "Datei archive",
            "signierte Auditzeile 0",
            "exakte Bytes des Re-Grants",
            "Proben-, Fehler- und Codeausgabe",
        ],
    );
    assert_no_leak(
        "Wiederherstellung",
        &streams,
        &recovery_needles(scene.content_key),
    );
}

// ===========================================================================
// Szene 4: Vernichtungsanfrage
// ===========================================================================

struct DestructionScene {
    fixture: destruction_support::RequestFixture,
    audit: Vec<u8>,
    rows: Vec<Vec<u8>>,
    diagnostics: Vec<u8>,
}

fn destruction_scene() -> DestructionScene {
    use destruction_support::{Account, RequestFixture, event, event_fields};
    let fixture = RequestFixture::new();
    let head = fixture.f.head();
    let (authorization, target) = fixture.authorization();
    let requested_event = event(
        &fixture.f,
        &authorization,
        event_fields(&fixture.f, &authorization, 1, None, 0, None),
    );
    let proof = fixture.proof(&head, ReauthPurpose::Destruction);
    let audit_service = fixture.audit(&head, false, false);
    let repository = ea_destruction::SqliteDestructionRepository::new(fixture.database.clone());
    let service = ea_destruction::DestructionRequestService {
        head: &head,
        certificate: fixture.certificate,
        role: OperatorRoleV1::Writer,
        account: &Account { matching: true },
        audit: &audit_service,
        repository: &repository,
    };
    let requested = service
        .request(&authorization, &requested_event, &[target], &proof)
        .expect("die Vernichtungsanfrage wird signiert auditiert");
    let audit = requested.audit_exact_bytes().to_vec();
    let mut diagnostics = format!("{:?}\n", requested.state()).into_bytes();
    // Der Fehlerweg: ein widersprechendes Zustandsereignis zur selben
    // Autorisierung.
    let conflicting = event(
        &fixture.f,
        &authorization,
        event_fields(&fixture.f, &authorization, 2, None, 0, None),
    );
    let (_, target) = fixture.authorization();
    let refused = service
        .request(&authorization, &conflicting, &[target], &proof)
        .err()
        .expect("ein widersprechendes Ereignis wird abgewiesen");
    diagnostics.extend_from_slice(format!("{refused:?}\n{}\n", refused.code()).as_bytes());
    let rows = audit_rows(&fixture.database);
    DestructionScene {
        fixture,
        audit,
        rows,
        diagnostics,
    }
}

fn destruction_needles() -> Vec<Needle> {
    vec![
        Needle::new(
            KIND_KEY,
            "Signierschluessel der Auditzeile",
            destruction_support::trust::device_signing_secret(),
        ),
        Needle::new(
            KIND_KEY,
            "Instanzschluessel der Vernichtungsbedienerin",
            DESTRUCTION_INSTANCE_SECRET,
        ),
        Needle::new(
            KIND_KEY,
            "Wurzelschluessel der Linie",
            destruction_support::trust::root_signing_secret(),
        ),
    ]
}

impl DestructionScene {
    fn streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = files_and_names("Vernichtung", &self.fixture.directory);
        streams.push((
            "Vernichtung: exakte Auditbytes der Anfrage".to_owned(),
            self.audit.clone(),
        ));
        streams.extend(audit_streams("Vernichtung", &self.rows));
        streams.push((
            "Vernichtung: Zustands- und Fehlerausgabe".to_owned(),
            self.diagnostics.clone(),
        ));
        streams
    }
}

#[test]
fn destruction_request_audit_and_its_local_store_carry_no_key_material() {
    let scene = destruction_scene();
    assert_database_file_is_encrypted("Vernichtung", &scene.fixture.directory.join("local.db"));
    assert_eq!(scene.rows.len(), 1, "genau die Anfrage ist auditiert");
    assert_eq!(scene.rows[0], scene.audit);
    let event = decode_local_audit_event(&scene.audit).expect("die Auditzeile dekodiert");
    assert!(matches!(event.action(), LocalAuditActionV1::Destruction(_)));
    assert_eq!(event.outcome(), LocalAuditOutcomeV1::Completed);

    let streams = scene.streams();
    assert_surfaces(
        "Vernichtung",
        &streams,
        &[
            "Datei local.db",
            "exakte Auditbytes der Anfrage",
            "signierte Auditzeile 0",
            "Zustands- und Fehlerausgabe",
        ],
    );
    assert_no_leak("Vernichtung", &streams, &destruction_needles());
}

// ===========================================================================
// Szene 5: Administrative Uhrfreigabe
// ===========================================================================

/// Die Marke des Adminzertifikats und seiner Bindung.
const CLOCK_ADMIN_MARKER: u8 = 0x11;
/// Die Köpfe der Uhrszene: 0 Anfangspolicy, 1 Adminzertifikat,
/// 2 Adminbindung, 3 Wachrichtlinie.
const CLOCK_HEAD_GUARD_POLICY: usize = 3;
/// Die vorgeschlagene Sequenz im Lease der Wachrichtlinie.
const CLOCK_PROPOSED_SEQUENCE: u64 = 35;
/// Zeitboden, unabhängige Referenz und die zwei Wanduhren — dieselben Zahlen
/// wie in `e2e_registry_effectiveness.rs`: `3_201 > 3_000 + 50` sperrt.
const CLOCK_FLOOR_MS: i64 = 3_100;
const CLOCK_REFERENCE_MS: i64 = 3_000;
const CLOCK_WALL_MS: i64 = 3_000;
const CLOCK_BLOCKED_WALL_MS: i64 = 3_201;
const CLOCK_ISSUED_AT_MS: i64 = 3_150;
const CLOCK_EXPIRES_AT_MS: i64 = 3_250;
const CLOCK_GUARD_SKEW_MS: u64 = 50;

struct ClockReleaseScene {
    root: support::TempDir,
    release: Vec<u8>,
    rows: Vec<Vec<u8>>,
    diagnostics: Vec<u8>,
    consumed: usize,
}

fn clock_trust(
    line: &RegistryLineBuilder,
    store: &registry_support::WorkflowStore,
) -> ea_trust::VerifiedTrust {
    let pin = store.pinned_head().map_or(Pin::None, |head| {
        Pin::Exact(head.registry_version(), head.registry_head_hash())
    });
    line.verified_with_record(
        pin,
        store.revision(),
        store.trusted_time().clone(),
        store.key(),
    )
}

/// Eine echte Freigabe über den produktiven Dienst, signiert in eine echte
/// SQLCipher-Auditablage, danach angewandt und einmal wiedereingespielt.
fn clock_release_scene() -> ClockReleaseScene {
    use ea_admin::clock_release::{
        ClockReleaseAvailability, ClockReleaseRequest, ClockReleaseService, apply_clock_release,
    };
    let window = |effective_from, valid_through| HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        ..HeadOptions::default()
    };
    let policy = || ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    };
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), window(1, 9));
    let admin_certificate = line
        .push(
            ActionSpec::AdminIssue {
                marker: CLOCK_ADMIN_MARKER,
                effective_from: None,
            },
            window(10, 19),
        )
        .direct_object_hash
        .expect("das Adminzertifikat ist ein direktes Ziel");
    let admin_binding = line
        .push(
            ActionSpec::OperatorBinding {
                certificate_hash: admin_certificate,
                role: OperatorRoleV1::OrganizationAdmin,
                marker: CLOCK_ADMIN_MARKER,
                effective_from: None,
            },
            HeadOptions {
                binding_instance_key_thumbprint_override: Some(
                    registry_support::public_key(registry_support::INSTANCE_SECRET).thumbprint(),
                ),
                binding_os_account_hash_override: Some(registry_support::trust_support::hash32(
                    registry_support::OS_ACCOUNT_MARKER,
                )),
                ..window(20, 29)
            },
        )
        .direct_object_hash
        .expect("die Adminbindung ist ein direktes Ziel");
    line.push(
        policy(),
        HeadOptions {
            policy_max_future_clock_skew_ms_override: Some(CLOCK_GUARD_SKEW_MS),
            ..window(30, 39)
        },
    );

    let key = ea_trust::TrustStateKey {
        organization_id: registry_support::trust_support::organization(),
        device_id: DeviceId::try_from(&[CLOCK_ADMIN_MARKER.wrapping_add(0x40); 16][..])
            .expect("16 Byte sind eine Gerätekennung"),
    };
    let trusted_time = ea_time::TrustedTimeState::from_persisted(
        UnixMillis::new(CLOCK_FLOOR_MS),
        Some(ea_time::IndependentTimeInput::new(
            ea_time::IndependentTimeKind::Receipt,
            ObjectHash::from(registry_support::trust_support::hash32(0xc5)),
            UnixMillis::new(CLOCK_REFERENCE_MS),
        )),
    )
    .expect("die Referenz liegt nicht hinter dem Zeitboden");
    let guard = line.heads()[CLOCK_HEAD_GUARD_POLICY];
    let mut store = registry_support::WorkflowStore::new(
        key,
        17,
        trusted_time,
        Some(RegistryHeadPin::new(guard.version, guard.object_hash)),
    );
    let trust = clock_trust(&line, &store);
    let RegistrySelectionOutcome::Selected(guard_head) =
        ea_admin::registry::RegistryWorkflowService::new(&mut store)
            .select(
                &trust,
                ChainSequence::new(CLOCK_PROPOSED_SEQUENCE),
                UnixMillis::new(CLOCK_WALL_MS),
                &[],
                None,
            )
            .unwrap_or_else(|error| panic!("die Wachkopfauswahl scheitert: {}", error.code()))
    else {
        panic!("die Uhrszene muss ihren Wachkopf wählen");
    };
    let proof = registry_support::operator_proof(
        &guard_head,
        admin_binding,
        ReauthPurpose::ClockSkewRelease,
    );

    let root = support::temp_dir("privacy-stage5-clock");
    let provider = InMemoryKeyProvider::new_for_test([0x6d; 32]);
    let database_key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .expect("der Datenbankschlüssel entsteht");
    let database = Arc::new(
        EncryptedDatabase::open(&root.path().join("admin.sqlite"), &provider, &database_key)
            .expect("die Auditdatenbank öffnet"),
    );
    let signer = Arc::new(registry_support::FixtureKeyProvider::new(
        registry_support::trust_support::device_signing_secret(),
    ));
    let handle = signer.handle();
    let audit = SignedLocalAuditService::new(
        Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&database)))
            as Arc<dyn LocalAuditRepository>,
        signer as Arc<dyn KeyProvider>,
        handle,
        admin_certificate,
        UnixMillis::new(CLOCK_BLOCKED_WALL_MS),
    );
    let service = ClockReleaseService::new(&guard_head, &audit, admin_binding);
    let time = store.trusted_time().clone();
    assert_eq!(
        service
            .availability(&time, UnixMillis::new(CLOCK_BLOCKED_WALL_MS))
            .expect("die gesperrte Uhr ist bewertbar"),
        ClockReleaseAvailability::Offered,
        "die Freigabe MUSS angeboten werden, sonst misst die Szene nichts"
    );
    let candidate = ea_trust::verify_registry_candidate(
        &clock_trust(&line, &store),
        ChainSequence::new(CLOCK_PROPOSED_SEQUENCE),
    )
    .expect("der gesperrte Kandidat verifiziert");
    let issued = service
        .issue(
            ClockReleaseRequest {
                candidate: &candidate,
                trusted_time: &time,
                observed_os_wall_clock: UnixMillis::new(CLOCK_BLOCKED_WALL_MS),
                justification: ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                issued_at: UnixMillis::new(CLOCK_ISSUED_AT_MS),
                expires_at: UnixMillis::new(CLOCK_EXPIRES_AT_MS),
            },
            &proof,
        )
        .expect("die Freigabe wird ausgestellt");
    let mut diagnostics = format!("{issued:?}\n").into_bytes();
    let release = issued.exact_bytes().to_vec();

    let trust = clock_trust(&line, &store);
    let applied = apply_clock_release(
        &mut store,
        &trust,
        ChainSequence::new(CLOCK_PROPOSED_SEQUENCE),
        UnixMillis::new(CLOCK_BLOCKED_WALL_MS),
        &[],
        &release,
    )
    .unwrap_or_else(|error| panic!("die Freigabe trägt die Auswahl nicht: {}", error.code()));
    assert!(matches!(applied, RegistrySelectionOutcome::Selected(_)));
    let trust = clock_trust(&line, &store);
    let replay = apply_clock_release(
        &mut store,
        &trust,
        ChainSequence::new(CLOCK_PROPOSED_SEQUENCE),
        UnixMillis::new(CLOCK_BLOCKED_WALL_MS),
        &[],
        &release,
    )
    .err()
    .expect("dieselbe Freigabe trägt kein zweites Mal");
    diagnostics.extend_from_slice(format!("{}\n", replay.code()).as_bytes());

    let rows = audit_rows(&database);
    ClockReleaseScene {
        root,
        release,
        rows,
        diagnostics,
        consumed: store.consumed_releases(),
    }
}

fn clock_release_needles() -> Vec<Needle> {
    vec![
        Needle::new(
            KIND_KEY,
            "Signierschluessel der Freigabezeile (Adminzertifikat)",
            registry_support::trust_support::device_signing_secret(),
        ),
        Needle::new(
            KIND_KEY,
            "Instanzschluessel des Adminbedieners",
            registry_support::INSTANCE_SECRET,
        ),
        Needle::new(
            KIND_KEY,
            "Wurzelschluessel der Linie",
            registry_support::trust_support::root_signing_secret(),
        ),
    ]
}

impl ClockReleaseScene {
    fn streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = files_and_names("Uhrfreigabe", self.root.path());
        streams.push((
            "Uhrfreigabe: exakte Freigabebytes".to_owned(),
            self.release.clone(),
        ));
        streams.extend(audit_streams("Uhrfreigabe", &self.rows));
        streams.push((
            "Uhrfreigabe: Ausgabe- und Fehlercode".to_owned(),
            self.diagnostics.clone(),
        ));
        streams
    }
}

#[test]
fn clock_release_audit_and_its_application_carry_no_key_material() {
    let scene = clock_release_scene();
    assert_database_file_is_encrypted("Uhrfreigabe", &scene.root.path().join("admin.sqlite"));
    assert_eq!(
        scene.consumed, 1,
        "die Freigabe ist genau einmal verbraucht"
    );
    assert_eq!(scene.rows.len(), 1, "genau die Ausstellung ist auditiert");
    let event = decode_local_audit_event(&scene.rows[0]).expect("die Auditzeile dekodiert");
    assert!(matches!(
        event.action(),
        LocalAuditActionV1::ClockSkewRelease(_)
    ));

    let streams = scene.streams();
    assert_surfaces(
        "Uhrfreigabe",
        &streams,
        &[
            "Datei admin.sqlite",
            "exakte Freigabebytes",
            "signierte Auditzeile 0",
            "Ausgabe- und Fehlercode",
        ],
    );
    assert_no_leak("Uhrfreigabe", &streams, &clock_release_needles());
}

// ===========================================================================
// Die Gegenkontrollen
// ===========================================================================

#[test]
fn the_search_finds_every_encoding_of_a_marker_that_really_lies_in_a_scene() {
    // Die GEGENKONTROLLE der ganzen Datei: liegt eine Nadel wirklich in einer
    // Szenendatei, MUSS die Suche sie finden — roh, hex, HEX und base64 in
    // jeder Ausrichtung mitten in einem größeren Blob. Ohne sie wäre jede
    // Abwesenheitszusicherung auch dann grün, wenn die Stromsammlung leer
    // liefe oder eine Kodierung falsch berechnet wäre.
    let scene = login_scene();
    let needles = login_needles();
    assert!(
        leaks(&scene.streams(), &needles).is_empty(),
        "vor der Probe darf keine Nadel gefunden werden"
    );
    for needle in &needles {
        let encodings = needle_encodings(&needle.bytes);
        let mut probes: Vec<(String, Vec<u8>)> = Vec::new();
        probes.push(("roh".to_owned(), needle.bytes.clone()));
        probes.push(("hex".to_owned(), hex::encode(&needle.bytes).into_bytes()));
        probes.push((
            "HEX".to_owned(),
            hex::encode_upper(&needle.bytes).into_bytes(),
        ));
        for offset in 0..3 {
            for (name, alphabet) in [("base64", BASE64_STANDARD), ("base64url", BASE64_URL)] {
                let mut blob = b"vorlauf-".repeat(3)[..offset + 5].to_vec();
                blob.extend_from_slice(&needle.bytes);
                blob.extend_from_slice(b"-nachlauf");
                probes.push((
                    format!("{name} (Versatz {offset})"),
                    base64(&blob, alphabet),
                ));
            }
        }
        for (probe_name, probe_bytes) in probes {
            let file = scene.root.path().join("ea-kanarie-probe.bin");
            std::fs::write(&file, &probe_bytes).expect("die Probe ist schreibbar");
            let found = leaks(&scene.streams(), std::slice::from_ref(needle));
            assert!(
                found
                    .iter()
                    .any(|line| line.contains("Datei ea-kanarie-probe.bin")),
                "{} als {probe_name} MUSS in der geplanten Probedatei gefunden werden",
                needle.label
            );
            std::fs::remove_file(&file).expect("die Probe ist entfernbar");
        }
        assert_eq!(encodings.len(), 9, "roh, hex, HEX und sechs base64-Formen");
    }
    assert!(
        leaks(&scene.streams(), &needles).is_empty(),
        "nach der Probe ist die Szene wieder sauber"
    );
}

#[test]
fn every_needle_is_distinct_and_long_enough_to_mean_something() {
    // Zwei Arten mit derselben Nadel ließen offen, was geleckt hat; eine zu
    // kurze Nadel fände sich zufällig und machte jede Szene rot, eine leere
    // machte `contains_canary` stumm.
    let mut all: Vec<Needle> = login_needles();
    all.extend(writer_needles());
    all.extend(recovery_needles([0x5a; 32]));
    all.extend(destruction_needles());
    all.extend(clock_release_needles());
    let mut seen = std::collections::BTreeSet::new();
    for needle in &all {
        assert!(needle.bytes.len() >= 9, "{} ist zu kurz", needle.label);
        for (encoding, bytes) in needle_encodings(&needle.bytes) {
            assert!(
                bytes.len() >= 8,
                "{} als {encoding} ist zu kurz, um etwas zu bedeuten",
                needle.label
            );
        }
        // Dieselben Bytes dürfen nur als DERSELBE Schlüssel in zwei Szenen
        // vorkommen (der Gerätesignierschlüssel der Linie).
        seen.insert((needle.bytes.clone(), needle.kind));
    }
    let values: std::collections::BTreeSet<&Vec<u8>> =
        seen.iter().map(|(bytes, _)| bytes).collect();
    assert_eq!(
        values.len(),
        seen.len(),
        "keine Nadel darf zwei Arten zugleich angehören"
    );
    // Die Kodierungen sind so berechnet, wie ein Produkt sie schriebe.
    assert_eq!(base64(b"Man", BASE64_STANDARD), b"TWFu");
    assert_eq!(base64(b"Ma", BASE64_STANDARD), b"TWE");
    assert_eq!(base64(&[0xfb, 0xff], BASE64_URL), b"-_8");
}
