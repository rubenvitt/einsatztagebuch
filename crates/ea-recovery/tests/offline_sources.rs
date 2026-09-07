//! Die expliziten Offline-Schluesselquellen der Stufe 5 (Task 7).
//!
//! # DREI QUELLARTEN, KEIN SCANNEN, KEINE VOREINSTELLUNG
//!
//! Eine Quelle wird BENANNT: als Datei der Stufe-4-Form, als verschluesselter
//! Container mit Passphrasendatei oder als PKCS#11-Referenz mit Modul, Token,
//! Schluessel-ID und PIN-Datei. Nichts davon wird geraten, gesucht oder aus
//! einem „ersten Token" abgeleitet — die Global Constraint des Stage-5-Plans
//! verbietet, einen Root-/Recovery-/HGA-/Approver-Schluessel durch Absuchen
//! eines Mediums zu finden.
//!
//! # WAS HIER GEMESSEN WIRD
//!
//! 1. Die Grammatik der Quellenangabe, Feld fuer Feld, samt der Fehler, die
//!    jedes fehlende, doppelte oder unbekannte Feld WOERTLICH benennen.
//! 2. Der Container: Rundreise fuer beide Schluesselarten, falsche Passphrase,
//!    Artverwechslung, jedes verkippte Byte, und die Rechte beim Schreiben und
//!    Lesen.
//! 3. Die Geheimnisdatei: genau ein Zeilenende, nie leer, nie offen, nie ein
//!    Link.
//! 4. Die Aufloesung: die Dateiform ist byteweise dieselbe wie in Stufe 4, und
//!    die PKCS#11-Referenz endet an ihrer benannten Grenze.
//! 5. Keine Fehlerdarstellung nennt einen Hostpfad oder ein Geheimnis.

#[path = "support/mod.rs"]
mod support;

use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Instant,
};

use ea_crypto::{CanonicalPublicCoseKey, SecretBytes, SecretVec};
use ea_recovery::{
    ContainedKeyKind, EncryptedKeyContainer, ExitCode, KeySourceKind, KeySourceSpec,
    KeySourceSpecError, MAX_SECRET_FILE_BYTES_V1, PKCS11_KEY_ID_MAX_BYTES, PKCS11_UNBOUND_CODE,
    RecoveryError, exit_code_for_error, load_recipient_key, read_secret_file,
    resolve_recipient_key, resolve_signing_key,
};

use support::temp_dir;

// ======================================================================
// 1 — Grammatik
// ======================================================================

/// Ein blosser Pfad und `file:<pfad>` benennen DIESELBE Quellart: die Datei
/// der Stufe 4 mit 32 Rohbytes oder 64 Hexzeichen.
#[test]
fn a_bare_path_and_the_file_prefix_both_name_the_stage_four_file_form() {
    let bare = KeySourceSpec::parse(OsStr::new("/medium/recovery.key")).expect("ein Pfad parst");
    assert!(
        bare == KeySourceSpec::File(PathBuf::from("/medium/recovery.key")),
        "ein blosser Pfad ist die Dateiform"
    );

    let prefixed =
        KeySourceSpec::parse(OsStr::new("file:/medium/recovery.key")).expect("file: parst");
    assert!(
        prefixed == bare,
        "`file:` ist nur die ausgeschriebene Form desselben Pfades"
    );

    // Der Praefixvergleich ist EXAKT und klein geschrieben: `FILE:` ist kein
    // Praefix, sondern der Anfang eines Pfades — auf einem Dateisystem, das
    // Doppelpunkte zulaesst, ein gueltiger Name.
    let upper = KeySourceSpec::parse(OsStr::new("FILE:/medium/recovery.key")).expect("parst");
    assert!(
        upper == KeySourceSpec::File(PathBuf::from("FILE:/medium/recovery.key")),
        "ein grossgeschriebenes Praefix ist Teil des Pfades"
    );
}

/// `container:<pfad>;passphrase-file=<pfad>`: der Pfad steht positional, die
/// Passphrasendatei als benanntes Feld.
#[test]
fn a_container_source_carries_its_path_and_passphrase_file() {
    let spec = KeySourceSpec::parse(OsStr::new(
        "container:/medium/recovery.container;passphrase-file=/medium/pass.txt",
    ))
    .expect("ein vollstaendiger Container parst");
    assert!(
        spec == KeySourceSpec::Container {
            path: PathBuf::from("/medium/recovery.container"),
            passphrase_file: PathBuf::from("/medium/pass.txt"),
        },
        "beide Felder kommen unveraendert an"
    );
}

/// `pkcs11:module=<pfad>;token=<label>;id=<hex>;pin-file=<pfad>`: alle vier
/// Felder sind Pflicht, die Reihenfolge der benannten Felder ist frei.
#[test]
fn a_pkcs11_source_carries_all_four_fields_in_any_order() {
    let ordered = KeySourceSpec::parse(OsStr::new(
        "pkcs11:module=/usr/lib/softhsm.so;token=Recovery;id=0a1b;pin-file=/medium/pin.txt",
    ))
    .expect("eine vollstaendige Referenz parst");
    let shuffled = KeySourceSpec::parse(OsStr::new(
        "pkcs11:pin-file=/medium/pin.txt;id=0A1B;module=/usr/lib/softhsm.so;token=Recovery",
    ))
    .expect("die Feldreihenfolge ist frei");
    assert!(
        ordered == shuffled,
        "dieselben Felder in anderer Reihenfolge und anderer Hex-Schreibung sind dieselbe Quelle"
    );

    let KeySourceSpec::Pkcs11 {
        reference,
        pin_file,
    } = ordered
    else {
        panic!("die Quellart ist pkcs11");
    };
    assert_eq!(reference.module(), PathBuf::from("/usr/lib/softhsm.so"));
    assert_eq!(reference.token_label(), "Recovery");
    assert_eq!(reference.key_id(), &[0x0a, 0x1b]);
    assert_eq!(pin_file, PathBuf::from("/medium/pin.txt"));
}

/// Jedes fehlende, doppelte, unbekannte oder leere Feld ist ein EIGENER
/// Fehler, und seine Anzeige nennt das Feld woertlich — sonst muesste der
/// Betreiber am Recovery-Medium raten, welches der vier Felder er vertippt
/// hat.
#[test]
fn every_missing_duplicate_unknown_and_empty_field_is_named_verbatim() {
    let cases: [(&str, KeySourceSpecError, &str); 13] = [
        (
            "container:/medium/recovery.container",
            KeySourceSpecError::MissingField {
                source: KeySourceKind::Container,
                field: "passphrase-file=",
            },
            "container: missing `passphrase-file=`",
        ),
        (
            "container:;passphrase-file=/medium/pass.txt",
            KeySourceSpecError::EmptyValue {
                source: KeySourceKind::Container,
                field: "path",
            },
            "container: `path` is empty",
        ),
        (
            "container:/a;passphrase-file=/b;passphrase-file=/c",
            KeySourceSpecError::DuplicateField {
                source: KeySourceKind::Container,
                field: "passphrase-file=",
            },
            "container: duplicate field `passphrase-file=`",
        ),
        (
            "container:/a;passphrase-file=/b;pin-file=/c",
            KeySourceSpecError::UnknownField {
                source: KeySourceKind::Container,
                field: "pin-file".to_owned(),
            },
            "container: unknown field `pin-file`",
        ),
        (
            "container:/a;passphrase-file=",
            KeySourceSpecError::EmptyValue {
                source: KeySourceKind::Container,
                field: "passphrase-file=",
            },
            "container: `passphrase-file=` is empty",
        ),
        (
            "pkcs11:module=/m;token=t;id=0a",
            KeySourceSpecError::MissingField {
                source: KeySourceKind::Pkcs11,
                field: "pin-file=",
            },
            "pkcs11: missing `pin-file=`",
        ),
        (
            "pkcs11:token=t;id=0a;pin-file=/p",
            KeySourceSpecError::MissingField {
                source: KeySourceKind::Pkcs11,
                field: "module=",
            },
            "pkcs11: missing `module=`",
        ),
        (
            "pkcs11:module=/m;module=/n;token=t;id=0a;pin-file=/p",
            KeySourceSpecError::DuplicateField {
                source: KeySourceKind::Pkcs11,
                field: "module=",
            },
            "pkcs11: duplicate field `module=`",
        ),
        (
            "pkcs11:module=/m;token=t;id=0a;pin-file=/p;foo=bar",
            KeySourceSpecError::UnknownField {
                source: KeySourceKind::Pkcs11,
                field: "foo".to_owned(),
            },
            "pkcs11: unknown field `foo`",
        ),
        (
            "pkcs11:module=/m;token=t;id=0g;pin-file=/p",
            KeySourceSpecError::NotHex {
                source: KeySourceKind::Pkcs11,
                field: "id=",
            },
            "pkcs11: `id=` is not hex",
        ),
        // Ungerade Laenge ist DASSELBE Urteil wie eine fremde Ziffer: eine
        // halbe Hexstelle benennt kein Byte.
        (
            "pkcs11:module=/m;token=t;id=0a1;pin-file=/p",
            KeySourceSpecError::NotHex {
                source: KeySourceKind::Pkcs11,
                field: "id=",
            },
            "pkcs11: `id=` is not hex",
        ),
        (
            "pkcs11:module=/m;token=;id=0a;pin-file=/p",
            KeySourceSpecError::EmptyValue {
                source: KeySourceKind::Pkcs11,
                field: "token=",
            },
            "pkcs11: `token=` is empty",
        ),
        (
            "pkcs11:module=/m;token=t;/etc/pin;pin-file=/p",
            KeySourceSpecError::MalformedField {
                source: KeySourceKind::Pkcs11,
            },
            "pkcs11: field without `=`",
        ),
    ];
    for (argument, expected, rendered) in cases {
        let Err(error) = KeySourceSpec::parse(OsStr::new(argument)) else {
            panic!("{argument:?} darf nicht parsen");
        };
        assert_eq!(error, expected, "fuer {argument:?}");
        assert_eq!(error.to_string(), rendered, "fuer {argument:?}");
        assert!(
            error.code().starts_with("EA-KEY-SOURCE-SPEC-"),
            "jeder Grammatikfehler traegt einen stabilen Code, war {}",
            error.code()
        );
    }

    // Eine Schluessel-ID jenseits von 255 Bytes ist kein PKCS#11-CKA_ID mehr:
    // der Wert wird abgewiesen, ohne dass seine Bytes in die Anzeige geraten.
    let too_long = format!(
        "pkcs11:module=/m;token=t;id={};pin-file=/p",
        "ab".repeat(256)
    );
    let Err(error) = KeySourceSpec::parse(OsStr::new(&too_long)) else {
        panic!("eine ueberlange ID darf nicht parsen");
    };
    assert_eq!(
        error,
        KeySourceSpecError::ValueTooLong {
            source: KeySourceKind::Pkcs11,
            field: "id=",
        }
    );
    assert_eq!(error.to_string(), "pkcs11: `id=` exceeds 255 bytes");
    assert!(
        !error.to_string().contains("abab"),
        "die Anzeige nennt keinen Wert"
    );

    // Und GENAU an der Grenze wird angenommen: 255 Bytes sind eine CKA_ID.
    let at_limit = format!(
        "pkcs11:module=/m;token=t;id={};pin-file=/p",
        "ab".repeat(PKCS11_KEY_ID_MAX_BYTES)
    );
    let KeySourceSpec::Pkcs11 { reference, .. } =
        KeySourceSpec::parse(OsStr::new(&at_limit)).expect("eine ID an der Grenze parst")
    else {
        panic!("die Quellart ist pkcs11");
    };
    assert_eq!(reference.key_id().len(), PKCS11_KEY_ID_MAX_BYTES);
}

/// `pkcs11:` ohne ein einziges Feld nennt `module=` — das ERSTE Feld der
/// dokumentierten Reihenfolge — und nicht ein leeres Glied ohne `=`.
///
/// Die Reihenfolge ist Teil des Vertrags: wer mehrere Felder vergessen hat,
/// bekommt immer dasselbe zuerst genannt und arbeitet die Grammatik von vorn
/// ab.
#[test]
fn a_pkcs11_spec_with_every_field_absent_names_module_first() {
    let Err(error) = KeySourceSpec::parse(OsStr::new("pkcs11:")) else {
        panic!("eine leere Referenz darf nicht parsen");
    };
    assert_eq!(
        error,
        KeySourceSpecError::MissingField {
            source: KeySourceKind::Pkcs11,
            field: "module=",
        }
    );
    assert_eq!(error.to_string(), "pkcs11: missing `module=`");
}

/// Ein Argument, das kein gueltiges UTF-8 ist, ist ein PFAD — Pfade duerfen
/// das nach der Regel der CLI —, und deshalb die Dateiform.
#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_a_bare_file_path() {
    use std::os::unix::ffi::OsStrExt as _;

    let raw = OsStr::from_bytes(b"/medium/\xff\xfe/recovery.key");
    let spec = KeySourceSpec::parse(raw).expect("ein Nicht-UTF-8-Pfad parst als Datei");
    assert!(
        spec == KeySourceSpec::File(PathBuf::from(raw)),
        "die Bytes kommen unveraendert als Pfad an"
    );

    // Auch wenn die Bytes mit einem Praefix BEGINNEN: ohne UTF-8 gibt es keine
    // Praefixgrammatik, und der Rest waere sonst ein halb gelesener Pfad.
    let disguised = OsStr::from_bytes(b"container:/medium/\xff;passphrase-file=/p");
    let spec = KeySourceSpec::parse(disguised).expect("parst als Datei");
    assert!(
        spec == KeySourceSpec::File(PathBuf::from(disguised)),
        "ohne UTF-8 gibt es keinen Praefix"
    );
}

/// Keine Anzeige eines Grammatikfehlers nennt einen Pfad oder einen Wert.
///
/// Der Pfad eines Recovery-Mediums ist nach der Global Constraint ein
/// sensibler Pfad; ein Fehler, der ihn zurueckspiegelt, truege ihn in jedes
/// Protokoll, das stderr sammelt.
#[test]
fn a_spec_error_never_echoes_a_path_or_a_value() {
    let root = temp_dir("spec-error-echo");
    let secret_path = root.path().join("geheim.container");
    let rendered_path = secret_path.display().to_string();
    let arguments = [
        format!("container:{rendered_path}"),
        format!("container:{rendered_path};passphrase-file={rendered_path};x=1"),
        format!("pkcs11:module={rendered_path};token=t;id=zz;pin-file={rendered_path}"),
        format!("pkcs11:module={rendered_path};{rendered_path};id=0a;pin-file={rendered_path}"),
    ];
    for argument in arguments {
        let Err(error) = KeySourceSpec::parse(OsStr::new(&argument)) else {
            panic!("{argument:?} darf nicht parsen");
        };
        for shown in [format!("{error}"), format!("{error:?}")] {
            assert!(
                !shown.contains(&rendered_path) && !shown.contains("geheim.container"),
                "die Fehlerdarstellung nennt den Pfad: {shown}"
            );
        }
    }

    // Ein Pfad, der selbst ein `=` traegt, ist KEIN unbekanntes Feld: er
    // wuerde sonst bis zum ersten `=` als Feldname zurueckgespiegelt. Nur ein
    // Glied, dessen Name wie ein Feldname aussieht, wird als solcher genannt;
    // alles andere ist ein Glied ohne Grammatik.
    for argument in [
        "container:/a;/media/recovery=1/pass.txt",
        "pkcs11:module=/m;token=t;id=0a;/media/KEY=2026/pin.txt",
    ] {
        let Err(error) = KeySourceSpec::parse(OsStr::new(argument)) else {
            panic!("{argument:?} darf nicht parsen");
        };
        assert!(
            matches!(error, KeySourceSpecError::MalformedField { .. }),
            "{argument:?}: ein Pfad mit `=` ist kein Feldname, war {error:?}"
        );
        for shown in [format!("{error}"), format!("{error:?}")] {
            assert!(
                !shown.contains("/media") && !shown.contains("recovery") && !shown.contains("KEY"),
                "die Fehlerdarstellung nennt ein Pfadstueck: {shown}"
            );
        }
    }
}

// ======================================================================
// 2 — Der verschluesselte Container
// ======================================================================

/// Eine Passphrase als `SecretVec`.
fn passphrase(text: &str) -> SecretVec {
    SecretVec::new(text.as_bytes().to_vec())
}

/// Ein Schluessel mit erkennbarem Muster.
fn secret_material(fill: u8) -> SecretBytes<32> {
    SecretBytes::new([fill; 32])
}

/// Beide Arten reisen durch Versiegeln, Bytes, Dekodieren und Oeffnen —
/// und kommen als dieselben 32 Bytes zurueck.
#[test]
fn a_container_round_trips_both_key_kinds() {
    let started = Instant::now();
    for (kind, fill) in [
        (ContainedKeyKind::RecipientKem, 0x4c_u8),
        (ContainedKeyKind::Signing, 0x5d_u8),
    ] {
        let sealed =
            EncryptedKeyContainer::seal(kind, secret_material(fill), &passphrase("richtig"))
                .expect("versiegeln muss gelingen");
        assert_eq!(sealed.kind(), kind);
        let bytes = sealed.to_bytes();
        let decoded =
            EncryptedKeyContainer::from_bytes(&bytes).expect("die eigenen Bytes dekodieren");
        assert!(
            decoded == sealed,
            "Bytes und Container sind dieselbe Aussage"
        );
        let opened = decoded
            .open(kind, &passphrase("richtig"))
            .expect("die richtige Passphrase oeffnet");
        assert!(
            opened.matches(&[fill; 32]),
            "es kommt derselbe Schluessel zurueck"
        );
    }
    eprintln!("zwei Rundreisen (vier KDF-Laeufe): {:?}", started.elapsed());
}

/// Setzt die Rechte einer Datei exakt.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("die Rechte muessen setzbar sein");
}

/// Die Rechtebits einer Datei.
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    fs::metadata(path)
        .expect("die Datei muss existieren")
        .permissions()
        .mode()
        & 0o777
}

/// Schreibt `bytes` nach `path` und gibt der Datei die Rechte `mode`.
#[cfg(unix)]
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("die Datei muss schreibbar sein");
    set_mode(path, mode);
}

/// Die falsche Passphrase ist [`RecoveryError::ContainerOpen`], Exitcode 14 —
/// dieselbe Antwort wie fuer ein verstuemmeltes Chiffrat, damit der Fehler
/// nichts verraet, und ausdruecklich NICHT `KeySource`: der Container hat die
/// Form erfuellt, gescheitert ist die Entschluesselung.
#[test]
fn the_wrong_passphrase_is_a_container_open_error() {
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");
    let Err(error) = sealed.open(ContainedKeyKind::RecipientKem, &passphrase("falsch")) else {
        panic!("die falsche Passphrase oeffnet nicht");
    };
    assert_eq!(error, RecoveryError::ContainerOpen);
    assert_eq!(exit_code_for_error(&error), ExitCode::Key);
}

/// Eine Artverwechslung wird VOR dem KDF abgewiesen — bewiesen OHNE Uhr.
///
/// # DER BEWEIS
///
/// `open` prueft in fester Reihenfolge: Art, dann Passphrase (nicht leer),
/// dann KDF und AEAD. Eine LEERE Passphrase ist der Marker, an dem sich die
/// Reihenfolge ablesen laesst: bei falscher Art kommt `KeySource` zurueck —
/// die Artpruefung hat den Lauf beendet, bevor die Passphrase je angesehen
/// wurde —, bei richtiger Art `SecretEmpty` — die Passphrasenpruefung steht
/// vor dem KDF. Zusammen: Art vor Passphrase vor KDF. Kein Timing, keine
/// Instrumentierung.
///
/// Der zweite Teil nimmt einen Container, dessen Chiffrat Muell ist: auch er
/// wird bei falscher Art mit `KeySource` abgewiesen, und zwar aus der
/// Artpruefung, weil derselbe Container mit richtiger Art und leerer
/// Passphrase `SecretEmpty` sagt — das Chiffrat wurde also in beiden Faellen
/// nie angefasst.
#[test]
fn a_kind_mismatch_is_refused_before_the_kdf_runs() {
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");
    let empty = SecretVec::new(Vec::new());
    assert!(
        matches!(
            sealed.open(ContainedKeyKind::Signing, &empty),
            Err(RecoveryError::KeySource)
        ),
        "die falsche Art faellt vor der Passphrase"
    );
    assert!(
        matches!(
            sealed.open(ContainedKeyKind::RecipientKem, &empty),
            Err(RecoveryError::SecretEmpty)
        ),
        "die richtige Art laesst die leere Passphrase auffallen — vor dem KDF"
    );
    // Und mit gefuellter Passphrase sagt die falsche Art dasselbe.
    assert!(
        matches!(
            sealed.open(ContainedKeyKind::Signing, &passphrase("richtig")),
            Err(RecoveryError::KeySource)
        ),
        "die richtige Passphrase hilft der falschen Art nicht"
    );

    // Ein Container mit Muell als Chiffrat.
    let mut bytes = sealed.to_bytes();
    for byte in &mut bytes[CIPHERTEXT_AT..] {
        *byte ^= 0xff;
    }
    let garbage = EncryptedKeyContainer::from_bytes(&bytes).expect("die Form ist noch gueltig");
    assert!(
        matches!(
            garbage.open(ContainedKeyKind::Signing, &empty),
            Err(RecoveryError::KeySource)
        ),
        "die Artpruefung sieht das Chiffrat nie"
    );
    assert!(
        matches!(
            garbage.open(ContainedKeyKind::RecipientKem, &empty),
            Err(RecoveryError::SecretEmpty)
        ),
        "und die Passphrasenpruefung auch nicht"
    );
}

// Die Byteform des Containers, wie sie `from_bytes` verlangt. Die Zahlen sind
// aus dem Modulkopf von `encrypted_container.rs` abgeleitet und werden im
// Test gegen die tatsaechliche Laenge gepinnt:
//   0        0x87                   Array(7)
//   1..33    0x78 0x1e + 30 Bytes   domain
//   33       0x01                   version
//   34       0x01 | 0x02            kind
//   35       0x84                   kdf: Array(4)
//   36       0x01                   Argon2id
//   37..42   0x1a 00 01 00 00       m = 65536
//   42       0x03                   t
//   43       0x04                   p
//   44..61   0x50 + 16 Bytes        salt
//   61..74   0x4c + 12 Bytes        nonce
//   74..124  0x58 0x30 + 48 Bytes   ciphertext
const CONTAINER_LEN: usize = 124;
const VERSION_AT: usize = 33;
const KIND_AT: usize = 34;
const KDF_ID_AT: usize = 36;
const MEMORY_AT: usize = 38;
const ITERATIONS_AT: usize = 42;
const PARALLELISM_AT: usize = 43;
const SALT_AT: usize = 45;
const NONCE_AT: usize = 62;
const CIPHERTEXT_AT: usize = 76;

/// JEDES einzelne verkippte Byte wird abgewiesen — beim Dekodieren oder,
/// wenn die Form noch traegt, beim Oeffnen.
///
/// Der erste Teil laeuft ueber ALLE 124 Bytes und verlangt: entweder
/// dekodiert der Container nicht mehr — dann ist es `KeySource`, Exitcode 2,
/// die Form ist gebrochen —, oder er dekodiert zu einem ANDEREN Container —
/// kein Byte ist bedeutungslos. Der zweite Teil oeffnet fuenf dieser
/// Varianten, je eine pro gebundenem Feld (Art, Salz, Nonce, Chiffrat, Tag);
/// jede scheitert an der AAD oder am Tag, und zwar als `ContainerOpen`,
/// Exitcode 14: die Form hat getragen, die Entschluesselung ist gescheitert.
/// Das Salz ist dabei der schaerfste Fall — es aendert nur, was der KDF und
/// die AAD sehen, und selbst das ist keine Frage der Form mehr. Fuenf und
/// nicht alle, weil jeder Oeffnungsversuch einen KDF-Lauf kostet und die
/// AAD-Bindung an EINEM verkippten Byte je Feld vollstaendig bewiesen ist.
///
/// Die Grenze zwischen 2 und 14 verlaeuft damit an `from_bytes`: beim
/// Dekodieren faellt nie `ContainerOpen`, beim Oeffnen nie `KeySource`.
#[test]
fn every_single_flipped_byte_is_refused() {
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");
    let bytes = sealed.to_bytes();
    assert_eq!(bytes.len(), CONTAINER_LEN, "die Byteform ist gepinnt");
    assert_eq!(bytes[0], 0x87);
    assert_eq!(&bytes[1..3], &[0x78, 0x1e]);
    assert_eq!(&bytes[3..33], b"EINSATZARCHIV-KEY-CONTAINER-v1");
    assert_eq!(bytes[VERSION_AT], 1);
    assert_eq!(bytes[KIND_AT], 1);
    assert_eq!(
        &bytes[35..44],
        &[0x84, 0x01, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x03, 0x04]
    );
    assert_eq!(bytes[44], 0x50);
    assert_eq!(bytes[61], 0x4c);
    assert_eq!(&bytes[74..76], &[0x58, 0x30]);

    let mut refused_at_decode = 0_usize;
    let mut decoded_differently = 0_usize;
    for index in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[index] ^= 0x01;
        match EncryptedKeyContainer::from_bytes(&flipped) {
            Err(RecoveryError::KeySource) => refused_at_decode += 1,
            // Insbesondere nie `ContainerOpen`: die Form ist nicht die
            // Entschluesselung.
            Err(other) => panic!("Byte {index}: unerwarteter Fehler {other}"),
            Ok(decoded) => {
                assert!(
                    decoded != sealed,
                    "Byte {index}: ein verkipptes Byte darf nicht denselben Container ergeben"
                );
                decoded_differently += 1;
            }
        }
    }
    assert!(
        refused_at_decode > 0 && decoded_differently > 0,
        "beide Ausgaenge muessen vorkommen: {refused_at_decode} gebrochen, \
         {decoded_differently} anders dekodiert"
    );
    assert_eq!(refused_at_decode + decoded_differently, CONTAINER_LEN);

    // Die fuenf Oeffnungsversuche.
    let started = Instant::now();
    let cases: [(&str, usize, u8); 5] = [
        ("kind", KIND_AT, 0x03),
        ("salt", SALT_AT, 0x01),
        ("nonce", NONCE_AT, 0x01),
        ("ciphertext", CIPHERTEXT_AT, 0x01),
        ("tag", CONTAINER_LEN - 1, 0x01),
    ];
    for (field, index, mask) in cases {
        let mut flipped = bytes.clone();
        flipped[index] ^= mask;
        let decoded = EncryptedKeyContainer::from_bytes(&flipped)
            .unwrap_or_else(|error| panic!("{field}: die Form traegt noch, war {error}"));
        // Die Art wird so geoeffnet, wie der Kopf sie jetzt nennt — sonst
        // bewiese der Fall nur die Artpruefung.
        let Err(error) = decoded.open(decoded.kind(), &passphrase("richtig")) else {
            panic!("{field}: ein verkipptes Byte muss die AEAD scheitern lassen");
        };
        assert_eq!(
            error,
            RecoveryError::ContainerOpen,
            "{field}: die Form hat getragen, also ist es die Entschluesselung"
        );
        assert_eq!(
            exit_code_for_error(&error),
            ExitCode::Key,
            "{field}: Entschluesselung fehlgeschlagen ist 14, nicht 2"
        );
    }
    eprintln!(
        "fuenf Oeffnungsversuche (fuenf KDF-Laeufe): {:?}",
        started.elapsed()
    );
}

/// Ein nachlaufendes Byte und jede fremde Parametrierung werden beim
/// DEKODIEREN abgewiesen — bevor ein KDF oder eine AEAD je liefe.
///
/// „Auch wenn die AEAD sich oeffnen liesse": `from_bytes` ruft weder KDF noch
/// AEAD auf, die Ablehnung kommt aus dem Vergleich mit den gepinnten Werten.
/// Ein Container mit `m = 8 MiB` wird deshalb nicht erst probiert und dann
/// verworfen, sondern gar nicht erst als Container gelesen.
#[test]
fn a_trailing_byte_and_a_foreign_kdf_parametrisation_are_refused_at_decode() {
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::Signing,
        secret_material(0x5d),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");
    let bytes = sealed.to_bytes();

    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(
        matches!(
            EncryptedKeyContainer::from_bytes(&trailing),
            Err(RecoveryError::KeySource)
        ),
        "ein nachlaufendes Byte ist kein Container"
    );
    assert!(
        matches!(
            EncryptedKeyContainer::from_bytes(&bytes[..bytes.len() - 1]),
            Err(RecoveryError::KeySource)
        ),
        "ein fehlendes Byte auch nicht"
    );
    assert!(
        matches!(
            EncryptedKeyContainer::from_bytes(&[]),
            Err(RecoveryError::KeySource)
        ),
        "und nichts erst recht nicht"
    );

    // m = 8192 KiB, kanonisch als 0x1a 00 00 20 00 — gueltiges CBOR, falsche
    // Zahl.
    let mut memory = bytes.clone();
    memory[MEMORY_AT..MEMORY_AT + 4].copy_from_slice(&8192_u32.to_be_bytes());
    // t = 2, p = 1, KDF-Kennung 2, Version 2: je ein Byte.
    let mut iterations = bytes.clone();
    iterations[ITERATIONS_AT] = 0x02;
    let mut parallelism = bytes.clone();
    parallelism[PARALLELISM_AT] = 0x01;
    let mut kdf_id = bytes.clone();
    kdf_id[KDF_ID_AT] = 0x02;
    let mut version = bytes.clone();
    version[VERSION_AT] = 0x02;
    let mut kind = bytes.clone();
    kind[KIND_AT] = 0x03;
    let mut domain = bytes.clone();
    domain[3] = b'e';
    for (name, patched) in [
        ("m", memory),
        ("t", iterations),
        ("p", parallelism),
        ("kdf", kdf_id),
        ("version", version),
        ("kind", kind),
        ("domain", domain),
    ] {
        assert!(
            matches!(
                EncryptedKeyContainer::from_bytes(&patched),
                Err(RecoveryError::KeySource)
            ),
            "{name}: eine fremde Parametrierung ist kein Container dieser Form"
        );
    }
}

/// `write_new` legt mit `0600` an und ueberschreibt nie.
#[cfg(unix)]
#[test]
fn write_new_creates_0600_and_refuses_an_existing_path() {
    let root = temp_dir("container-write");
    let path = root.path().join("recovery.container");
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");

    sealed
        .write_new(&path)
        .expect("ein freies Ziel muss beschreibbar sein");
    assert_eq!(
        mode_of(&path),
        ea_recovery::OUTPUT_FILE_MODE_V1,
        "der Container traegt 0600"
    );
    assert_eq!(
        fs::read(&path).expect("lesbar"),
        sealed.to_bytes(),
        "geschrieben werden genau die Containerbytes"
    );

    let Err(error) = sealed.write_new(&path) else {
        panic!("ein belegtes Ziel darf nicht beschrieben werden");
    };
    assert!(matches!(error, RecoveryError::OutputExists));
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
    assert_eq!(
        fs::read(&path).expect("lesbar"),
        sealed.to_bytes(),
        "die vorhandene Datei bleibt unberuehrt"
    );
}

/// `read_from` verweigert offene Rechte VOR dem ersten gelesenen Byte und
/// nimmt `0600` wie `0400`.
///
/// Dass nicht gelesen wird, zeigen zwei Dateien: eine mit GUELTIGEM Inhalt
/// und `0644` scheitert, und eine mit MUELL und `0644` scheitert mit demselben
/// Fehler — nicht mit `KeySource`, was der Inhalt ergaebe.
#[cfg(unix)]
#[test]
fn read_from_refuses_open_permissions_without_reading_and_accepts_0600_and_0400() {
    let root = temp_dir("container-read");
    let sealed = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln muss gelingen");

    let valid = root.path().join("gueltig.container");
    write_with_mode(&valid, &sealed.to_bytes(), 0o644);
    let Err(error) = EncryptedKeyContainer::read_from(&valid) else {
        panic!("ein weltlesbarer Container darf nicht gelesen werden");
    };
    assert!(
        matches!(error, RecoveryError::KeySourceExposed),
        "war {error}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);

    let garbage = root.path().join("muell.container");
    write_with_mode(&garbage, b"kein Container", 0o644);
    let Err(error) = EncryptedKeyContainer::read_from(&garbage) else {
        panic!("Muell mit offenen Rechten darf nicht gelesen werden");
    };
    assert!(
        matches!(error, RecoveryError::KeySourceExposed),
        "die Rechte fallen vor dem Inhalt auf, war {error}"
    );

    // Gruppenrechte allein reichen fuer die Ablehnung.
    set_mode(&valid, 0o640);
    assert!(matches!(
        EncryptedKeyContainer::read_from(&valid),
        Err(RecoveryError::KeySourceExposed)
    ));

    set_mode(&valid, 0o600);
    let read = EncryptedKeyContainer::read_from(&valid).expect("0600 ist eingegrenzt");
    assert!(read == sealed);
    set_mode(&valid, 0o400);
    let read = EncryptedKeyContainer::read_from(&valid).expect("0400 ist eingegrenzt");
    assert!(read == sealed);

    // Ein Symlink auf eine eingegrenzte Datei ist trotzdem keine
    // eingegrenzte Datei.
    let link = root.path().join("link.container");
    std::os::unix::fs::symlink(&valid, &link).expect("der Symlink muss anlegbar sein");
    assert!(matches!(
        EncryptedKeyContainer::read_from(&link),
        Err(RecoveryError::KeySourceExposed)
    ));

    // Und Muell mit richtigen Rechten ist `KeySource`, nicht `Exposed`.
    set_mode(&garbage, 0o600);
    assert!(matches!(
        EncryptedKeyContainer::read_from(&garbage),
        Err(RecoveryError::KeySource)
    ));

    // Eine fehlende Datei bleibt ein Dateisystemfehler.
    let Err(error) = EncryptedKeyContainer::read_from(&root.path().join("fehlt")) else {
        panic!("eine fehlende Datei kann keinen Container geben");
    };
    assert!(matches!(error, RecoveryError::Io(ErrorKind::NotFound)));
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Legt eine FIFO an `path` an, oder `false`, wenn `mkfifo` auf diesem Host
/// fehlt — dann ist der Fall nicht messbar und wird uebersprungen.
///
/// Ueber das Werkzeug und nicht ueber eine Kiste: der Test nimmt keine neue
/// Dependency auf.
#[cfg(unix)]
fn make_fifo(path: &Path) -> bool {
    match std::process::Command::new("mkfifo").arg(path).status() {
        Ok(status) if status.success() => true,
        Ok(status) => panic!("mkfifo ist da, scheitert aber: {status}"),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            eprintln!("mkfifo fehlt auf diesem Host; der FIFO-Fall wird uebersprungen");
            false
        }
        Err(error) => panic!("mkfifo laesst sich nicht starten: {error}"),
    }
}

/// Fuehrt `call` in einem eigenen Thread aus und verlangt, dass es
/// innerhalb einer grosszuegigen Frist ZURUECKKEHRT.
///
/// Der Punkt ist das Zurueckkehren: `File::open` auf einer FIFO ohne
/// Schreiber blockiert fuer immer, und ein Test, der daran haengt, meldet
/// keinen Fehler, sondern gar nichts. Die Frist macht aus einem Haenger einen
/// roten Test.
#[cfg(unix)]
fn returns_within_timeout<T: Send + 'static>(
    what: &str,
    call: impl FnOnce() -> T + Send + 'static,
) -> T {
    use std::{sync::mpsc, thread, time::Duration};

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // Ein geschlossener Empfaenger heisst: die Frist ist bereits
        // abgelaufen und der Test gefallen; das Ergebnis interessiert nicht
        // mehr.
        let _ = sender.send(call());
    });
    receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("{what} kehrt nicht zurueck: die Datei ist eine FIFO"))
}

/// Eine FIFO wird VOR `File::open` abgewiesen — sonst blockierte das Oeffnen
/// ohne Schreiber fuer immer, und ein Aufrufer am Recovery-Medium saehe ein
/// Werkzeug, das einfach steht.
///
/// Beide Leser — Geheimnisdatei und Container — fragen die Metadaten des
/// Pfades schon fuer den Symlink ab; dieselben Metadaten sagen auch, ob es
/// eine regulaere Datei ist. Die Antwort ist `KeySourceExposed`, wie beim
/// Symlink: keine regulaere Datei ist als eingegrenzt erwiesen.
#[cfg(unix)]
#[test]
fn a_fifo_is_refused_before_it_is_opened_and_the_call_returns() {
    let root = temp_dir("fifo-refused");
    let fifo = root.path().join("geheim.fifo");
    if !make_fifo(&fifo) {
        return;
    }
    set_mode(&fifo, 0o600);

    let secret_fifo = fifo.clone();
    let error = returns_within_timeout("read_secret_file", move || {
        read_secret_file(&secret_fifo).map(|_| ())
    })
    .expect_err("eine FIFO ist kein Geheimnis");
    assert!(
        matches!(error, RecoveryError::KeySourceExposed),
        "war {error}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);

    let container_fifo = fifo;
    let error = returns_within_timeout("EncryptedKeyContainer::read_from", move || {
        EncryptedKeyContainer::read_from(&container_fifo).map(|_| ())
    })
    .expect_err("eine FIFO ist kein Container");
    assert!(
        matches!(error, RecoveryError::KeySourceExposed),
        "war {error}"
    );
}

// ======================================================================
// 3 — Die Geheimnisdatei
// ======================================================================

/// Genau ein Zeilenende faellt, nie zwei; leer ist leer; offen und verlinkt
/// wird nicht gelesen.
#[cfg(unix)]
#[test]
fn read_secret_file_strips_one_line_ending_and_refuses_empty_open_and_symlinked_files() {
    let root = temp_dir("secret-file");
    let cases: [(&[u8], &[u8]); 5] = [
        (b"geheim\n", b"geheim"),
        (b"geheim\r\n", b"geheim"),
        (b"geheim\n\n", b"geheim\n"),
        (b"geheim", b"geheim"),
        (b"\n\n", b"\n"),
    ];
    for (index, (content, expected)) in cases.iter().enumerate() {
        let path = root.path().join(format!("pass-{index}.txt"));
        write_with_mode(&path, content, 0o600);
        let secret = read_secret_file(&path).expect("eine eingegrenzte Datei liest sich");
        assert!(
            secret.matches(expected),
            "Fall {index}: genau ein Zeilenende faellt"
        );
    }

    for (index, content) in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()]
        .iter()
        .enumerate()
    {
        let path = root.path().join(format!("leer-{index}.txt"));
        write_with_mode(&path, content, 0o600);
        let Err(error) = read_secret_file(&path) else {
            panic!("Fall {index}: eine leere Passphrase ist keine");
        };
        assert!(matches!(error, RecoveryError::SecretEmpty), "war {error}");
        assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
    }

    let open = root.path().join("offen.txt");
    write_with_mode(&open, b"geheim\n", 0o644);
    assert!(matches!(
        read_secret_file(&open),
        Err(RecoveryError::KeySourceExposed)
    ));
    set_mode(&open, 0o604);
    assert!(matches!(
        read_secret_file(&open),
        Err(RecoveryError::KeySourceExposed)
    ));

    let confined = root.path().join("eng.txt");
    write_with_mode(&confined, b"geheim\n", 0o600);
    let link = root.path().join("link.txt");
    std::os::unix::fs::symlink(&confined, &link).expect("der Symlink muss anlegbar sein");
    assert!(matches!(
        read_secret_file(&link),
        Err(RecoveryError::KeySourceExposed)
    ));

    let Err(error) = read_secret_file(&root.path().join("fehlt.txt")) else {
        panic!("eine fehlende Datei kann kein Geheimnis geben");
    };
    assert!(matches!(error, RecoveryError::Io(ErrorKind::NotFound)));
}

/// Eine Geheimnisdatei hat eine Obergrenze: genau an der Grenze wird sie
/// gelesen, ein Byte darueber ist sie kein Geheimnis dieser Form —
/// `KeySource`, Exitcode 2 — und wird nicht erst vollstaendig in den
/// Speicher geholt.
///
/// Gezaehlt werden die DATEIBYTES, das Zeilenende eingeschlossen: die Grenze
/// gilt dem, was gelesen wird, nicht dem, was danach uebrig bleibt.
#[cfg(unix)]
#[test]
fn read_secret_file_reads_up_to_its_limit_and_refuses_one_byte_more() {
    let root = temp_dir("secret-file-limit");

    let at_limit = root.path().join("grenze.txt");
    write_with_mode(&at_limit, &[b'p'; MAX_SECRET_FILE_BYTES_V1], 0o600);
    let secret = read_secret_file(&at_limit).expect("genau an der Grenze wird gelesen");
    assert!(secret.matches(&[b'p'; MAX_SECRET_FILE_BYTES_V1]));

    let over = root.path().join("darueber.txt");
    write_with_mode(&over, &[b'p'; MAX_SECRET_FILE_BYTES_V1 + 1], 0o600);
    let Err(error) = read_secret_file(&over) else {
        panic!("ein Byte ueber der Grenze ist kein Geheimnis dieser Form");
    };
    assert!(matches!(error, RecoveryError::KeySource), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
}

// ======================================================================
// 4 — Die Aufloesung
// ======================================================================

/// Die Dateiform liefert ueber `resolve_recipient_key` DENSELBEN Schluessel
/// wie `load_recipient_key` — roh und hex.
#[test]
fn resolve_recipient_key_from_a_file_equals_load_recipient_key() {
    let root = temp_dir("resolve-file");
    let raw_path = root.path().join("roh.key");
    fs::write(&raw_path, [0x4c_u8; 32]).expect("schreibbar");
    let hex_path = root.path().join("hex.key");
    fs::write(&hex_path, format!("{}\n", "4c".repeat(32))).expect("schreibbar");

    for path in [&raw_path, &hex_path] {
        let loaded = load_recipient_key(path).expect("die Stufe-4-Form laedt");
        let resolved = resolve_recipient_key(&KeySourceSpec::File(path.clone()))
            .expect("die Dateiform loest auf");
        assert!(
            loaded.public_key() == resolved.public_key(),
            "beide Wege liefern denselben Schluessel"
        );
    }

    let bad_path = root.path().join("kaputt.key");
    fs::write(&bad_path, [0x4c_u8; 31]).expect("schreibbar");
    assert!(matches!(
        resolve_recipient_key(&KeySourceSpec::File(bad_path)),
        Err(RecoveryError::KeySource)
    ));
}

/// Die Dateiform liest NUR eine regulaere Datei und NUR so viele Bytes, wie
/// eine der beiden Formen lang sein kann.
///
/// Ein Verzeichnis ist kein Schluessel — `KeySource` und nicht der
/// Dateisystemfehler, den `read` daraus machte —, und eine Datei jenseits
/// von 64 Hexzeichen plus Zeilenende ist keine der beiden Formen, ohne dass
/// sie dafuer vollstaendig gelesen wuerde. Beides ist die FORM, also 2.
///
/// Die Rechte der Datei werden hier ausdruecklich NICHT geprueft: die
/// Dateiform ist die der Stufe 4, und jeder Aufruf der Stufe 4 laeuft
/// unveraendert weiter.
#[test]
fn the_file_form_refuses_a_directory_and_an_oversized_file_as_key_source() {
    let root = temp_dir("resolve-file-shape");

    let oversized = root.path().join("zu-lang.key");
    fs::write(&oversized, [b'4'; 200]).expect("schreibbar");
    let Err(error) = resolve_recipient_key(&KeySourceSpec::File(oversized)) else {
        panic!("200 Bytes sind keine der beiden Formen");
    };
    assert!(matches!(error, RecoveryError::KeySource), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);

    let directory = root.path().join("verzeichnis.key");
    fs::create_dir(&directory).expect("anlegbar");
    let Err(error) = resolve_recipient_key(&KeySourceSpec::File(directory.clone())) else {
        panic!("ein Verzeichnis ist kein Schluessel");
    };
    assert!(
        matches!(error, RecoveryError::KeySource),
        "ein Verzeichnis ist die falsche Form, kein Dateisystemfehler, war {error}"
    );
    assert!(matches!(
        resolve_signing_key(&KeySourceSpec::File(directory)),
        Err(RecoveryError::KeySource)
    ));

    // Eine fehlende Datei bleibt ein Dateisystemfehler, 20.
    let Err(error) = resolve_recipient_key(&KeySourceSpec::File(root.path().join("fehlt.key")))
    else {
        panic!("eine fehlende Datei kann keinen Schluessel geben");
    };
    assert!(matches!(error, RecoveryError::Io(ErrorKind::NotFound)));
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);
}

/// Die Dateiform als Signierschluessel ist der Ed25519-Seed, und der
/// oeffentliche Schluessel ist der von `ed25519_dalek` aus demselben Seed.
#[test]
fn resolve_signing_key_from_a_file_matches_the_dalek_seed() {
    let root = temp_dir("resolve-signing");
    let seed = [0x5d_u8; 32];
    let raw_path = root.path().join("seed.key");
    fs::write(&raw_path, seed).expect("schreibbar");
    let hex_path = root.path().join("seed.hex");
    fs::write(&hex_path, "5d".repeat(32)).expect("schreibbar");

    let expected = CanonicalPublicCoseKey::ed25519(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    )
    .expect("ein Dalek-Schluessel ist kanonisch")
    .thumbprint();
    for path in [raw_path, hex_path] {
        let signer = resolve_signing_key(&KeySourceSpec::File(path)).expect("der Seed loest auf");
        let actual = signer
            .public_key()
            .expect("der Signierer kennt seinen oeffentlichen Schluessel")
            .thumbprint();
        assert!(actual == expected, "derselbe Seed, derselbe Abdruck");
    }
}

/// Ein Container loest zu seiner Art auf und wird fuer die andere verweigert.
#[cfg(unix)]
#[test]
fn a_container_resolves_to_its_kind_and_refuses_the_other() {
    let root = temp_dir("resolve-container");
    let passphrase_file = root.path().join("pass.txt");
    write_with_mode(&passphrase_file, b"richtig\n", 0o600);

    let recipient = ea_crypto::HpkeRecipientPrivateKey::from_bytes(secret_material(0x4c))
        .expect("ein X25519-Schluessel");
    let container_path = root.path().join("recovery.container");
    EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase("richtig"),
    )
    .expect("versiegeln")
    .write_new(&container_path)
    .expect("schreiben");

    let spec = KeySourceSpec::Container {
        path: container_path.clone(),
        passphrase_file: passphrase_file.clone(),
    };
    let resolved = resolve_recipient_key(&spec).expect("der Container loest auf");
    assert!(resolved.public_key() == recipient.public_key());

    let Err(error) = resolve_signing_key(&spec) else {
        panic!("ein Recovery-Schluessel ist kein Signierschluessel");
    };
    assert!(matches!(error, RecoveryError::KeySource), "war {error}");
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);

    // Die Passphrasendatei faellt VOR dem Container auf: eine offene
    // Passphrase mit fehlendem Container ist `Exposed`, nicht `Io`.
    set_mode(&passphrase_file, 0o644);
    let missing = KeySourceSpec::Container {
        path: root.path().join("fehlt.container"),
        passphrase_file,
    };
    assert!(matches!(
        resolve_recipient_key(&missing),
        Err(RecoveryError::KeySourceExposed)
    ));
}

/// Die PKCS#11-Referenz endet an ihrer benannten Grenze — nach vollstaendig
/// geprueffter PIN-Datei und vorhandenem Modul.
#[cfg(unix)]
#[test]
fn a_pkcs11_source_ends_at_the_named_boundary_after_checking_the_pin_file_first() {
    let root = temp_dir("resolve-pkcs11");
    let module = root.path().join("softhsm.so");
    fs::write(&module, b"kein echtes Modul").expect("schreibbar");
    let pin_file = root.path().join("pin.txt");
    write_with_mode(&pin_file, b"1234\n", 0o600);

    let spec_for = |module: PathBuf, pin_file: PathBuf| {
        let argument = format!(
            "pkcs11:module={};token=Recovery;id=0a1b;pin-file={}",
            module.display(),
            pin_file.display()
        );
        KeySourceSpec::parse(OsStr::new(&argument)).expect("die Referenz parst")
    };

    // Vollstaendig: die Grenze, mit 21.
    for resolve in [
        |spec: &KeySourceSpec| resolve_recipient_key(spec).map(|_| ()),
        |spec: &KeySourceSpec| resolve_signing_key(spec).map(|_| ()),
    ] {
        let Err(error) = resolve(&spec_for(module.clone(), pin_file.clone())) else {
            panic!("in dieser Stufe bindet nichts an ein Modul");
        };
        assert!(matches!(error, RecoveryError::Pkcs11Unbound), "war {error}");
        assert_eq!(exit_code_for_error(&error), ExitCode::Unsupported);
        assert_eq!(error.code(), PKCS11_UNBOUND_CODE);
    }

    // Ein fehlendes Modul ist ein Dateisystemfehler, 20.
    let Err(error) =
        resolve_recipient_key(&spec_for(root.path().join("fehlt.so"), pin_file.clone()))
    else {
        panic!("ein fehlendes Modul kann nicht binden");
    };
    assert!(
        matches!(error, RecoveryError::Io(ErrorKind::NotFound)),
        "war {error}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Io);

    // Eine offene PIN-Datei faellt VOR dem Modul auf: mit fehlendem Modul
    // kommt trotzdem `Exposed` (2), nicht `Io` (20).
    set_mode(&pin_file, 0o644);
    let Err(error) = resolve_recipient_key(&spec_for(root.path().join("fehlt.so"), pin_file))
    else {
        panic!("eine offene PIN-Datei darf nicht gelesen werden");
    };
    assert!(
        matches!(error, RecoveryError::KeySourceExposed),
        "war {error}"
    );
    assert_eq!(exit_code_for_error(&error), ExitCode::Usage);
}

// ======================================================================
// 5 — Darstellung und Codes
// ======================================================================

/// Keine Darstellung eines neuen Fehlers nennt einen Pfad oder ein Geheimnis.
#[cfg(unix)]
#[test]
fn no_new_error_display_names_a_path_or_a_secret() {
    let root = temp_dir("error-display");
    let host_path = root.path().display().to_string();
    let secret_text = "SEHR-GEHEIME-PASSPHRASE";

    let open = root.path().join("offen.txt");
    write_with_mode(&open, format!("{secret_text}\n").as_bytes(), 0o644);
    let empty = root.path().join("leer.txt");
    write_with_mode(&empty, b"", 0o600);
    let pin = root.path().join("pin.txt");
    write_with_mode(&pin, format!("{secret_text}\n").as_bytes(), 0o600);
    let module = root.path().join("modul.so");
    fs::write(&module, b"x").expect("schreibbar");
    let wrong = root.path().join("falsch.txt");
    write_with_mode(&wrong, format!("{secret_text}-falsch\n").as_bytes(), 0o600);
    let container = root.path().join("recovery.container");
    EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        secret_material(0x4c),
        &passphrase(secret_text),
    )
    .expect("versiegeln")
    .write_new(&container)
    .expect("schreiben");

    let errors = [
        read_secret_file(&open).map(|_| ()).expect_err("offen"),
        read_secret_file(&empty).map(|_| ()).expect_err("leer"),
        resolve_recipient_key(
            &KeySourceSpec::parse(OsStr::new(&format!(
                "pkcs11:module={};token=t;id=0a;pin-file={}",
                module.display(),
                pin.display()
            )))
            .expect("parst"),
        )
        .map(|_| ())
        .expect_err("Grenze"),
        resolve_recipient_key(&KeySourceSpec::Container {
            path: container,
            passphrase_file: wrong,
        })
        .map(|_| ())
        .expect_err("falsche Passphrase"),
    ];
    let expected = [
        RecoveryError::KeySourceExposed,
        RecoveryError::SecretEmpty,
        RecoveryError::Pkcs11Unbound,
        RecoveryError::ContainerOpen,
    ];
    for (error, expected) in errors.iter().zip(expected) {
        assert_eq!(*error, expected);
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(
                !rendered.contains(&host_path) && !rendered.contains(secret_text),
                "die Fehlerdarstellung nennt Pfad oder Geheimnis: {rendered}"
            );
        }
    }
}

/// DIE CODES UND ZAHLEN SIND DER VERTRAG: jede neue Variante mit ihrem Code
/// und ihrem Exitcode, damit keine davon still ihre Zeile wechseln kann.
#[test]
fn the_new_variants_carry_their_codes_and_exit_codes() {
    let table: [(RecoveryError, &str, ExitCode); 4] = [
        (
            RecoveryError::KeySourceExposed,
            "EA-RECOVERY-KEY-SOURCE-EXPOSED",
            ExitCode::Usage,
        ),
        (
            RecoveryError::ContainerOpen,
            "EA-RECOVERY-CONTAINER-OPEN",
            ExitCode::Key,
        ),
        (
            RecoveryError::SecretEmpty,
            "EA-RECOVERY-SECRET-EMPTY",
            ExitCode::Usage,
        ),
        (
            RecoveryError::Pkcs11Unbound,
            "EA-RECOVERY-PKCS11-UNBOUND",
            ExitCode::Unsupported,
        ),
    ];
    for (error, code, exit) in table {
        assert_eq!(error.code(), code);
        assert_eq!(error.to_string(), code);
        assert_eq!(exit_code_for_error(&error), exit);
    }
    assert_eq!(PKCS11_UNBOUND_CODE, "EA-RECOVERY-PKCS11-UNBOUND");
    assert_eq!(
        KeySourceSpecError::MalformedField {
            source: KeySourceKind::Pkcs11
        }
        .exit_code(),
        ExitCode::Usage,
        "ein Grammatikfehler ist immer ein Aufruffehler"
    );
}
