//! Die Eingabefassaden von `grant` und `recovery-test`, ohne Prozessstart.
//!
//! # Was hier gemessen wird
//!
//! Die REIHENFOLGE, in der beide Fassaden ihre Eingaben anfassen — sie ist
//! der Gegenstand der Task-7-Scheibe, weil der Dienst dahinter (Task 8
//! beziehungsweise Task 9) noch nicht existiert und die Fassade deshalb
//! ausschliesslich aus ihrer Ordnung besteht:
//!
//! - `grant` loest den Recovery-Schluessel VOR der Verifikation auf, weil der
//!   Bericht seinen Abdruck braucht (dieselbe Ordnung wie
//!   `ea_recovery::decrypt_directory`); danach verifiziert es; ein Befund
//!   gewinnt gegen jeden spaeteren Fehler — den Autoritaetsschluessel und
//!   die beiden Dateien; erst dann wird der Autoritaetsschluessel aufgeloest
//!   und werden die Dateien gelesen.
//! - `recovery-test` verifiziert ohne Schluessel; ein Befund gewinnt; danach
//!   muss das Ziel frei sein, BEVOR das Inventar gelesen wird.
//!
//! # Warum die Live-Familie
//!
//! Die Uhr ist hier zwar ein Parameter, aber die Fassaden werden mit
//! [`live_clock`] gefahren, damit dieselben Bestaende auch die Prozesszeugen
//! in `apps/cli/tests/full_grammar.rs` tragen — eine Fixture, zwei Ebenen.

#[path = "support/mod.rs"]
mod support;

use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use ea_crypto::{SecretBytes, SecretVec};
use ea_recovery::{
    ContainedKeyKind, EncryptedKeyContainer, ExitCode, KeySourceSpec, RecoveryError, exit_code_for,
    exit_code_for_error, grant_inputs, recovery_test_inputs,
};
use support::{
    LiveArchive, TempDir, live_clock, live_clock_archive,
    live_clock_archive_with_foreign_encapsulation,
    live_clock_archive_with_mutated_writer_signature, materialize, temp_dir,
    verify_support::complete_recipient_secret_bytes,
};

/// Ein abgelegter Bestand samt einem Verzeichnis AUSSERHALB fuer alle
/// weiteren Eingaben.
///
/// Schluessel, Passphrasen, Autorisierung und Zertifikat liegen niemals im
/// Bestand: `ea_recovery::FsArchiveSource::open` zaehlte sie sonst als
/// Beiwerk, und der Bestand saehe je nach Testaufbau anders aus.
struct Laid {
    archive: TempDir,
    outside: TempDir,
}

impl Laid {
    fn outside(&self, name: &str) -> PathBuf {
        self.outside.path().join(name)
    }
}

/// Legt `built` ab und daneben die rohe Schluesseldatei des Empfaengers.
fn lay_out(tag: &str, built: &LiveArchive) -> Laid {
    let archive = temp_dir(&format!("{tag}-archive"));
    materialize(&built.fixture, archive.path());
    let outside = temp_dir(&format!("{tag}-outside"));
    fs::write(
        outside.path().join("recovery.key"),
        complete_recipient_secret_bytes(),
    )
    .expect("die Schluesseldatei muss schreibbar sein");
    Laid { archive, outside }
}

/// Die Dateiform als Quellenangabe.
fn file_spec(path: &Path) -> KeySourceSpec {
    KeySourceSpec::parse(path.as_os_str()).expect("ein Pfad parst immer")
}

/// Eine Passphrase als `SecretVec`.
fn passphrase(text: &str) -> SecretVec {
    SecretVec::new(text.as_bytes().to_vec())
}

/// Schreibt `bytes` nach `path` mit den Rechten `mode`.
#[cfg(unix)]
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::write(path, bytes).expect("die Datei muss schreibbar sein");
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("die Rechte muessen setzbar sein");
}

/// Legt einen Container der Art `kind` samt Passphrasendatei (0600) an und
/// liefert die Quellenangabe.
#[cfg(unix)]
fn container_spec(laid: &Laid, name: &str, kind: ContainedKeyKind, fill: u8) -> KeySourceSpec {
    let container = laid.outside(&format!("{name}.container"));
    EncryptedKeyContainer::seal(kind, SecretBytes::new([fill; 32]), &passphrase("richtig"))
        .expect("versiegeln muss gelingen")
        .write_new(&container)
        .expect("der Container muss anlegbar sein");
    let passphrase_file = laid.outside(&format!("{name}.passphrase"));
    write_with_mode(&passphrase_file, b"richtig\n", 0o600);
    let argument = format!(
        "container:{};passphrase-file={}",
        container.display(),
        passphrase_file.display()
    );
    KeySourceSpec::parse(OsStr::new(&argument)).expect("die Containerangabe parst")
}

/// Eine PKCS#11-Referenz auf eine existierende Moduldatei mit einer
/// PIN-Datei der Rechte `pin_mode`.
#[cfg(unix)]
fn pkcs11_spec(laid: &Laid, name: &str, pin_mode: u32) -> KeySourceSpec {
    let module = laid.outside(&format!("{name}.so"));
    fs::write(&module, b"kein echtes Modul").expect("die Moduldatei muss schreibbar sein");
    let pin_file = laid.outside(&format!("{name}.pin"));
    write_with_mode(&pin_file, b"1234\n", pin_mode);
    let argument = format!(
        "pkcs11:module={};token=Recovery;id=0a;pin-file={}",
        module.display(),
        pin_file.display()
    );
    KeySourceSpec::parse(OsStr::new(&argument)).expect("die Referenz parst")
}

/// Legt die beiden Dateieingaben von `grant` mit erkennbarem Inhalt an.
fn lay_out_grant_files(laid: &Laid) -> (PathBuf, PathBuf) {
    let authorization = laid.outside("authorization.bin");
    fs::write(&authorization, b"authorization-bytes").expect("schreibbar");
    let recipient_certificate = laid.outside("recipient.cert");
    fs::write(&recipient_certificate, b"recipient-certificate-bytes").expect("schreibbar");
    (authorization, recipient_certificate)
}

// ======================================================================
// 1 — `grant`
// ======================================================================

/// Der Erfolgspfad: alle vier Eingaben aufgeloest, der Bericht makellos.
///
/// Die Bytes der beiden Dateien kommen UNVERAENDERT heraus — geparst wird
/// hier nichts, der Parser ist Task 8.
#[cfg(unix)]
#[test]
fn grant_inputs_resolve_every_input_on_a_clean_archive() {
    let built = live_clock_archive();
    let laid = lay_out("grant-ok", &built);
    let authority = container_spec(&laid, "authority", ContainedKeyKind::Signing, 0x5d);
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let inputs = grant_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &file_spec(&laid.outside("recovery.key")),
        &authority,
        &authorization,
        &recipient_certificate,
    )
    .expect("auf einem makellosen Bestand loest alles auf");

    assert_eq!(exit_code_for(&inputs.report), ExitCode::Success);
    let resolved = inputs
        .resolved
        .as_ref()
        .expect("ohne Befund sind die Eingaben aufgeloest");
    assert_eq!(resolved.authorization_bytes, b"authorization-bytes");
    assert_eq!(
        resolved.recipient_certificate_bytes,
        b"recipient-certificate-bytes"
    );
    // Die Schluessel sind DA, aber nur ueber ihre Zugriffe — kein Feld, kein
    // `Debug`.
    let _ = resolved.recovery_key();
    let _ = resolved.authority();
}

/// EIN BEFUND GEWINNT gegen den Autoritaetsschluessel und die Dateien.
///
/// Der Autoritaetsschluessel ist eine PKCS#11-Referenz mit OFFENER
/// PIN-Datei (Aufruffehler 2), die Dateien fehlen (20) — und trotzdem kommt
/// der Bericht mit seinem Signaturbefund (10) zurueck: nichts davon wurde
/// angefasst. Das ist verify-before-use in seiner messbaren Form.
#[cfg(unix)]
#[test]
fn a_finding_wins_over_an_exposed_authority_key_and_missing_files() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let laid = lay_out("grant-finding", &built);
    let authority = pkcs11_spec(&laid, "authority", 0o644);

    let inputs = grant_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &file_spec(&laid.outside("recovery.key")),
        &authority,
        &laid.outside("fehlt.bin"),
        &laid.outside("fehlt.cert"),
    )
    .expect("ein Befund ist kein Fehler");

    assert_eq!(exit_code_for(&inputs.report), ExitCode::Integrity);
    assert!(
        inputs.resolved.is_none(),
        "bei einem Befund wird kein weiterer Schluessel aufgeloest"
    );
}

/// Der Recovery-Schluessel geht mit seinem Abdruck in die Verifikation.
///
/// Ein Grant auf FREMDES Material wird dadurch als Entschluesselungsbefund
/// sichtbar (14) — wie bei `decrypt` und ausdruecklich nicht als fehlender
/// Grant. Ohne Schluessel bliebe der Bestand makellos.
#[test]
fn a_foreign_encapsulation_becomes_a_decryption_finding() {
    let built = live_clock_archive_with_foreign_encapsulation();
    let laid = lay_out("grant-foreign", &built);
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let inputs = grant_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &file_spec(&laid.outside("recovery.key")),
        &file_spec(&laid.outside("recovery.key")),
        &authorization,
        &recipient_certificate,
    )
    .expect("ein Befund ist kein Fehler");

    assert_eq!(exit_code_for(&inputs.report), ExitCode::Key);
    assert!(inputs.resolved.is_none());
}

/// Eine fehlende Autorisierungsdatei ist ein Dateisystemfehler, 20.
#[test]
fn a_missing_authorization_file_is_an_io_error() {
    let built = live_clock_archive();
    let laid = lay_out("grant-missing-file", &built);
    let recipient_certificate = laid.outside("recipient.cert");
    fs::write(&recipient_certificate, b"cert").expect("schreibbar");

    let Err(error) = grant_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &file_spec(&laid.outside("recovery.key")),
        &file_spec(&laid.outside("recovery.key")),
        &laid.outside("fehlt.bin"),
        &recipient_certificate,
    ) else {
        panic!("eine fehlende Datei kann nicht gelesen werden");
    };
    assert!(
        matches!(error, RecoveryError::Io(ErrorKind::NotFound)),
        "war {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Ein Container der FALSCHEN Art als Autoritaetsschluessel ist ein
/// Aufruffehler: der Kopf traegt die Art, und ein Recovery-Schluessel wird
/// nie als Signierschluessel gelesen.
#[cfg(unix)]
#[test]
fn a_recipient_container_is_refused_as_authority_key() {
    let built = live_clock_archive();
    let laid = lay_out("grant-wrong-kind", &built);
    let authority = container_spec(&laid, "authority", ContainedKeyKind::RecipientKem, 0x4c);
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let Err(error) = grant_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &file_spec(&laid.outside("recovery.key")),
        &authority,
        &authorization,
        &recipient_certificate,
    ) else {
        panic!("die falsche Art darf nicht aufloesen");
    };
    assert!(matches!(error, RecoveryError::KeySource), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
}

/// Eine PKCS#11-Referenz als Recovery-Schluessel endet an der benannten
/// Grenze — und zwar VOR dem Bestand: der Archivpfad existiert hier gar
/// nicht, und trotzdem kommt 21 und nicht 20. Der Recovery-Schluessel steht
/// vor der Verifikation, weil der Bericht seinen Abdruck braucht.
#[cfg(unix)]
#[test]
fn a_pkcs11_recovery_key_ends_at_the_boundary_before_the_archive_is_read() {
    let built = live_clock_archive();
    let laid = lay_out("grant-pkcs11", &built);
    let recovery = pkcs11_spec(&laid, "recovery", 0o600);
    let (authorization, recipient_certificate) = lay_out_grant_files(&laid);

    let Err(error) = grant_inputs(
        &laid.outside("kein-bestand"),
        &built.anchor(),
        live_clock(),
        &recovery,
        &file_spec(&laid.outside("recovery.key")),
        &authorization,
        &recipient_certificate,
    ) else {
        panic!("in dieser Stufe bindet nichts an ein Modul");
    };
    assert!(matches!(error, RecoveryError::Pkcs11Provider(ea_recovery::Pkcs11ProviderError::Unavailable)), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Unsupported);
}

// ======================================================================
// 2 — `recovery-test`
// ======================================================================

/// Der Erfolgspfad: verifiziert, Ziel frei, Inventar gelesen — und NICHTS
/// angelegt.
#[test]
fn recovery_test_inputs_read_the_inventory_and_create_nothing() {
    let built = live_clock_archive();
    let laid = lay_out("recovery-test-ok", &built);
    let inventory = laid.outside("inventory.json");
    fs::write(&inventory, b"{}").expect("schreibbar");
    let output = laid.outside("recovery-test.json");

    let inputs = recovery_test_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &inventory,
        &output,
    )
    .expect("auf einem makellosen Bestand loest alles auf");

    assert_eq!(exit_code_for(&inputs.report), ExitCode::Success);
    assert_eq!(inputs.key_inventory_bytes.as_deref(), Some(&b"{}"[..]));
    assert!(!output.exists(), "die Fassade legt kein Ziel an");
}

/// Ein BELEGTES Ziel faellt VOR dem Inventar auf: das Inventar fehlt hier,
/// und trotzdem kommt `OutputExists` (2) und nicht `Io` (20).
#[test]
fn an_existing_output_is_refused_before_the_inventory_is_read() {
    let built = live_clock_archive();
    let laid = lay_out("recovery-test-busy", &built);
    let output = laid.outside("recovery-test.json");
    fs::write(&output, b"schon da").expect("schreibbar");

    let Err(error) = recovery_test_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &laid.outside("fehlt.json"),
        &output,
    ) else {
        panic!("ein belegtes Ziel wird nicht ueberschrieben");
    };
    assert!(matches!(error, RecoveryError::OutputExists), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
    assert_eq!(
        fs::read(&output).expect("lesbar"),
        b"schon da",
        "das belegte Ziel bleibt unberuehrt"
    );

    // Ein HAENGENDER Symlink ist ebenfalls „etwas an diesem Pfad": `create_new`
    // scheiterte an ihm, und `metadata` saehe ihn nicht. Auch er ist 2.
    #[cfg(unix)]
    {
        let dangling = laid.outside("haengt.json");
        std::os::unix::fs::symlink(laid.outside("nirgends.json"), &dangling)
            .expect("der Symlink muss anlegbar sein");
        let Err(error) = recovery_test_inputs(
            laid.archive.path(),
            &built.anchor(),
            live_clock(),
            &laid.outside("fehlt.json"),
            &dangling,
        ) else {
            panic!("ein haengender Symlink ist ein belegtes Ziel");
        };
        assert!(matches!(error, RecoveryError::OutputExists), "war {error}");
        assert!(
            fs::symlink_metadata(&dangling)
                .expect("der Symlink bleibt")
                .is_symlink(),
            "der Symlink bleibt unberuehrt"
        );
    }
}

/// Ein fehlendes Inventar ist ein Dateisystemfehler, 20.
#[test]
fn a_missing_inventory_is_an_io_error() {
    let built = live_clock_archive();
    let laid = lay_out("recovery-test-missing", &built);

    let Err(error) = recovery_test_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &laid.outside("fehlt.json"),
        &laid.outside("recovery-test.json"),
    ) else {
        panic!("ein fehlendes Inventar kann nicht gelesen werden");
    };
    assert!(
        matches!(error, RecoveryError::Io(ErrorKind::NotFound)),
        "war {error:?}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Ein Befund gewinnt gegen das belegte Ziel UND das fehlende Inventar.
#[test]
fn a_finding_wins_over_an_existing_output_and_a_missing_inventory() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let laid = lay_out("recovery-test-finding", &built);
    let output = laid.outside("recovery-test.json");
    fs::write(&output, b"schon da").expect("schreibbar");

    let inputs = recovery_test_inputs(
        laid.archive.path(),
        &built.anchor(),
        live_clock(),
        &laid.outside("fehlt.json"),
        &output,
    )
    .expect("ein Befund ist kein Fehler");

    assert_eq!(exit_code_for(&inputs.report), ExitCode::Integrity);
    assert!(inputs.key_inventory_bytes.is_none());
}
