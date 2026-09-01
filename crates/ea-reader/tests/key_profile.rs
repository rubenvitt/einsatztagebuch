//! Das Schluesselprofil des Readers, und die eine Klausel, die ohne Zeugen
//! stillschweigend verschwaende.
//!
//! `web-reader-design.md` §6.1 gibt dem Reader ZWEI getrennte Schluessel: einen
//! X25519-Schluessel fuer die HPKE-Entkapselung und einen Ed25519-Schluessel
//! fuer Geraet und Audit. `ReaderKeyProfile::validate` entscheidet fail-closed
//! gegen die GEPARSTEN Felder eines `DeviceCertificateFieldsV1` und nie gegen
//! rohe Zeichenketten — dieselbe Regel, die
//! `WriterKeyProfile::validate_capabilities` in
//! `crates/ea-key-provider/src/profile.rs` aufschreibt.
//!
//! # Warum die Rollenkollision einen EIGENEN Code bekommt
//!
//! Drei der vier Klauseln — Rolle, Anwesenheit beider Schluessel, Abdruck
//! passt zum Schluessel — faengt jede sorgfaeltige Pruefung ohnehin. Die
//! vierte nicht: `CanonicalPublicCoseKey::to_deterministic_cbor` schreibt die
//! Kurve mit (`crv 6` fuer Ed25519, `crv 4` fuer X25519), DIESELBEN 32 Bytes
//! tragen in beiden Rollen also zwei VERSCHIEDENE Abdruecke und passierten
//! jede Prueferei, die nur Abdruecke vergleicht. `EA-KEY-ROLE-COLLISION` ist
//! deshalb der einzige neue Code dieser Datei, und
//! `reader_requires_distinct_kem_and_authentication_keys` ist seine einzige
//! Messung.
//!
//! # Die drei Fehlfaelle vergleichen CODES und nicht `is_err()`
//!
//! Die Aussage von `key_profile.rs`, die Rolle entscheide VOR der Ausstattung,
//! ist nur ueber den Code messbar: `writer_certificate()` traegt keinen
//! KEM-Schluessel und faellt deshalb auch an Klausel 2. Ein `is_err()` bliebe
//! gruen, wenn die `certificate_kind`-Pruefung hinter die Anwesenheitspruefung
//! wanderte — der Zeuge saehe dann `EA-READER-KEY-MISSING-PUBLIC-KEY` statt
//! `EA-READER-KEY-CERTIFICATE-KIND` und meldete nichts. Der Codevergleich ist
//! das Einzige, was die dokumentierte Klauselreihenfolge festhaelt.

mod fixtures;

use ea_crypto::CanonicalPublicCoseKey;
use ea_reader::ReaderKeyProfile;

#[test]
fn reader_requires_distinct_kem_and_authentication_keys() {
    let collided = fixtures::reader_certificate_with_one_key_in_both_roles();
    assert_eq!(
        ReaderKeyProfile::validate(&collided).unwrap_err().code(),
        "EA-KEY-ROLE-COLLISION"
    );

    let profile = ReaderKeyProfile::validate(&fixtures::reader_certificate()).unwrap();
    assert!(matches!(
        profile.kem_public_key(),
        CanonicalPublicCoseKey::X25519(_)
    ));
    assert!(matches!(
        profile.signing_public_key(),
        CanonicalPublicCoseKey::Ed25519(_)
    ));
    // `assert_ne!` geht hier NICHT: `KeyThumbprint` entsteht aus `hash_newtype!`
    // in `crates/ea-types/src/ids.rs` und leitet bewusst kein `Debug` ab — ein
    // Abdruck soll sich nicht beilaeufig in eine Fehlermeldung schreiben.
    assert!(profile.kem_key_thumbprint() != profile.signing_key_thumbprint());

    for (wrong, expected_code) in [
        (
            fixtures::reader_certificate_without_kem_key(),
            "EA-READER-KEY-MISSING-PUBLIC-KEY",
        ),
        (
            fixtures::reader_certificate_without_signing_key(),
            "EA-READER-KEY-MISSING-PUBLIC-KEY",
        ),
        // Ein VOLLSTAENDIG gueltiges Writer-Zertifikat faellt an der ERSTEN
        // Klausel. `is_err()` genuegte hier nicht: `writer_certificate()`
        // traegt keinen KEM-Schluessel und fiele auch an Klausel 2 — der
        // Codevergleich ist das Einzige, was die Reihenfolge misst.
        (
            fixtures::writer_certificate(),
            "EA-READER-KEY-CERTIFICATE-KIND",
        ),
    ] {
        assert_eq!(
            ReaderKeyProfile::validate(&wrong).unwrap_err().code(),
            expected_code
        );
    }
}
