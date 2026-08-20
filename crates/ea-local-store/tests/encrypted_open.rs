//! Ohne Schluessel wird nicht geoeffnet, und JEDE Datei ist verschluesselt.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue};

const DATABASE_FILE: &str = "writer.sqlite3";
const KEYED_SEED: [u8; 32] = [0x5a; 32];
/// Der Startwert eines Providers, in dem NIE ein Datenbankschluessel erzeugt
/// wurde. Er ist zugleich die Kontoinstanz, unter der der Griff adressiert.
const KEYLESS_SEED: [u8; 32] = [0xa5; 32];

/// Die laufende Nummer der Harness-Wurzel dieses Prozesses.
static HARNESS_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Eine Rohdatei, die die Datenbank angelegt hat.
pub struct RawFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub struct StoreHarness {
    root: PathBuf,
    database: EncryptedDatabase,
}

impl StoreHarness {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Der Zaehler ist TRAGEND und keine Verzierung: die beiden Tests dieses
        // Ziels laufen als Faeden EINES Prozesses, also ist `process::id()` fuer
        // beide gleich, und `SystemTime::now()` liefert unter Last durchaus
        // zweimal denselben Wert. Zwei gleiche Wurzeln hiessen, dass das
        // `remove_dir_all` des zweiten Harness die gerade geoeffnete Datenbank
        // des ersten unter den Fuessen wegloescht — beobachtet als
        // `EA-STORE-DATABASE` in einem vollen `--workspace`-Lauf.
        let unique = HARNESS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ea-local-store-{}-{nanos}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let provider = InMemoryKeyProvider::new_for_test(KEYED_SEED);
        let handle = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let database = EncryptedDatabase::open(&root.join(DATABASE_FILE), &provider, &handle)
            .expect("die verschluesselte Datenbank muss sich oeffnen lassen");
        Self { root, database }
    }

    /// Der Versuch, ohne Schluesselmaterial zu oeffnen.
    ///
    /// Der Griff ist ECHT — er kommt aus `generate` —, und der Eintrag hinter
    /// ihm ist danach GELOESCHT: genau der Zustand nach einem entfernten
    /// Schluesselspeichereintrag, einer Neuinstallation oder einer
    /// Wiederherstellung auf ein fremdes Geraet. Es gibt keinen Konstruktor,
    /// dem man diesen Schritt ersparen koennte — `open` nimmt keinen Pfad
    /// allein, und genau das macht die Zusage strukturell statt prozedural.
    fn open_without_key(&self) -> Result<EncryptedDatabase, StoreError> {
        let provider = InMemoryKeyProvider::new_for_test(KEYLESS_SEED);
        let handle = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        provider.delete(&handle).unwrap();
        assert!(!provider.contains(&handle).unwrap());
        EncryptedDatabase::open(&self.root.join("keyless.sqlite3"), &provider, &handle)
    }

    /// Schreibt den Kanarienvogel als ROHEN KLARTEXT in die Entwurfszeile.
    ///
    /// AUSDRUECKLICH ohne die AEAD des Entwurfs: dieser Test misst
    /// AUSSCHLIESSLICH die Zusage von SQLCipher. Liefe der Kanarienvogel erst
    /// durch `aead_seal`, bestuende der Test auch dann, wenn die Datenbank
    /// selbst unverschluesselt auf der Platte laege — die eine Zusage wuerde
    /// die andere verdecken. Wer diesen Aufruf spaeter „richtigstellt", zerstoert
    /// den Test lautlos.
    fn save_draft_notes(&self, notes: &str) {
        self.database
            .execute(
                "INSERT INTO draft (singleton, draft_id, payload_ciphertext, payload_nonce, \
                 dek_keystore_provider, dek_account_instance, save_revision, created_at_ms, \
                 updated_at_ms) VALUES (0, ?1, ?2, ?3, 1, ?4, 0, 0, 0)",
                &[
                    StoreValue::Blob(vec![0x01; 16]),
                    StoreValue::Blob(notes.as_bytes().to_vec()),
                    StoreValue::Blob(vec![0x02; 12]),
                    StoreValue::Blob(vec![0x03; 32]),
                ],
            )
            .expect("die Entwurfszeile muss sich schreiben lassen");
    }

    /// Die Hauptdatei UND jede Nebendatei, die die Datenbank angelegt hat.
    fn raw_database_files(&self) -> Vec<RawFile> {
        let mut files: Vec<RawFile> = fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(DATABASE_FILE))
            })
            .map(|path| RawFile {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes: fs::read(&path).unwrap(),
            })
            .collect();
        files.sort_by(|left, right| left.name.cmp(&right.name));
        files
    }

    fn pragma(&self, name: &str) -> String {
        self.database
            .query_row(&format!("PRAGMA {name}"), &[] as &[StoreValue])
            .unwrap()
            .expect("ein Pragma meldet einen Wert")
            .pragma_string(0)
            .unwrap()
    }
}

#[test]
fn the_database_does_not_open_without_the_provider_key() {
    let harness = StoreHarness::new();
    assert_eq!(
        harness.open_without_key().unwrap_err().code(),
        "EA-STORE-KEY-REQUIRED"
    );
}

#[test]
fn every_database_file_including_the_wal_is_encrypted_and_no_temp_spill_is_allowed() {
    let harness = StoreHarness::new();
    harness.save_draft_notes("CANARY-DRAFT");
    let files = harness.raw_database_files();
    assert!(files.iter().any(|file| file.name.ends_with("-wal")));
    for file in &files {
        assert!(
            !ea_testkit::contains_canary(&file.bytes, b"CANARY-DRAFT"),
            "Klartext in {}",
            file.name
        );
    }
    assert_eq!(harness.pragma("journal_mode"), "wal");
    assert_eq!(harness.pragma("temp_store"), "2");

    // Das Write-Ahead-Log darf nicht LEER sein: eine Nebendatei ohne Seiten
    // enthaelt den Kanarienvogel schon deshalb nicht, weil sie nichts enthaelt.
    // Ohne diese Zusicherung bestuende die Schleife oben aus dem falschen
    // Grund.
    let wal = files
        .iter()
        .find(|file| file.name.ends_with("-wal"))
        .expect("das Write-Ahead-Log ist oben bereits nachgewiesen");
    assert!(!wal.bytes.is_empty(), "{} ist leer", wal.name);

    // ADR 0002 *Consequences* legt diesem Task auf, den WIRKSAMEN Unterbau
    // beobachtbar zu machen: `LIBSQLITE3_SYS_USE_PKG_CONFIG` kann das
    // gebundelte SQLCipher lautlos durch ein Klartext-SQLite ersetzen, das
    // `PRAGMA key` als unbekanntes Pragma annimmt. Ohne diese Zusicherung
    // bestuende die Kanarienpruefung fuer eine unverschluesselte Datenbank
    // genau dann nicht mehr — und der Test saehe wie ein Rueckschritt aus,
    // ohne zu sagen, warum.
    assert!(
        !harness.database.cipher_version().trim().is_empty(),
        "der wirksame Unterbau meldet keine SQLCipher-Fassung"
    );
}
