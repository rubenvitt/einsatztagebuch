#![no_main]

//! Fuzzt Objektrahmen, Objektgrenzen und Ressourcenlimits aus `ea-format` —
//! zwei der fuenf Flaechen, die `design.md` 22.1 verlangt.
//!
//! `decode_exact_object` verlangt zuerst neun Praefixbytes
//! (`85 44 45 41 31 00 <typ> 01 80`). Rohe Mutatorbytes treffen sie praktisch
//! nie, ein Ziel ohne Praefixsynthese uebte also nur die erste Ablehnung. Das
//! erste Eingabebyte waehlt deshalb den Modus: Modus 0 laesst die Bytes roh
//! durch und haelt Praefix-, Versions- und Erweiterungsablehnung am Leben,
//! Modus 1..=6 setzt das Praefix des jeweiligen Objekttyps davor, damit der
//! Mutator am Rumpf arbeitet.
//!
//! Die Grenzwerte aus Global Constraint Zeile 30 des Stufe-1-Plans stehen
//! unten als Uebersetzungszeit-Assertions. Sie verteilen sich auf zwei Kisten:
//! die sechs Familienrohgrenzen und die globale Objektgrenze exportiert
//! `ea-format`, die Wert- und Arbeitsgrenzen `ea-cbor` ueber
//! `ParserLimits::V1`, und `MAX_PLAINTEXT_BYTES_V1`/`MAX_CIPHERTEXT_BYTES_V1`
//! sind nur ueber `ea_crypto::checked_ciphertext_length` erreichbar.

use libfuzzer_sys::fuzz_target;

// Familienrohgrenzen und globale Objektgrenze.
const _: () = assert!(ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1 == 4_194_304);
const _: () = assert!(ea_format::EIP_MAX_RAW_BYTES_V1 == 2_097_152);
const _: () = assert!(ea_format::EAG_MAX_RAW_BYTES_V1 == 65_536);
const _: () = assert!(ea_format::ESR_MAX_RAW_BYTES_V1 == 65_536);
const _: () = assert!(ea_format::ECP_MAX_RAW_BYTES_V1 == 4_194_304);
const _: () = assert!(ea_format::ETB_MAX_RAW_BYTES_V1 == 4_194_304);
const _: () = assert!(ea_format::EDS_MAX_RAW_BYTES_V1 == 262_144);

// Wert- und Arbeitsgrenzen: MAX_CBOR_TEXT_OR_BYTES_V1, Verschachtelung 16,
// MAX_CONTAINER_ITEMS_V1 und MAX_TOTAL_ITEMS_V1.
const _: () = assert!(ea_cbor::ParserLimits::V1.max_text_or_bytes == 1_048_592);
const _: () = assert!(ea_cbor::ParserLimits::V1.max_depth == 16);
const _: () = assert!(ea_cbor::ParserLimits::V1.max_container_items == 10_000);
const _: () = assert!(ea_cbor::ParserLimits::V1.max_total_items == 10_000);

/// Die sechs Objekttypen mit ihrem Rahmenpraefix und ihrer Familienrohgrenze,
/// in der Reihenfolge der Typtags `.eip=1` bis `.eds=6`.
const FRAMES: [([u8; 9], usize); 6] = [
    (ea_format::EIP_PREFIX_V1, ea_format::EIP_MAX_RAW_BYTES_V1),
    (ea_format::EAG_PREFIX_V1, ea_format::EAG_MAX_RAW_BYTES_V1),
    (ea_format::ESR_PREFIX_V1, ea_format::ESR_MAX_RAW_BYTES_V1),
    (ea_format::ECP_PREFIX_V1, ea_format::ECP_MAX_RAW_BYTES_V1),
    (ea_format::ETB_PREFIX_V1, ea_format::ETB_MAX_RAW_BYTES_V1),
    (ea_format::EDS_PREFIX_V1, ea_format::EDS_MAX_RAW_BYTES_V1),
];

fuzz_target!(|data: &[u8]| {
    // MAX_PLAINTEXT_BYTES_V1 = 1_048_576 und MAX_CIPHERTEXT_BYTES_V1 =
    // 1_048_592 haengen ueber den AEAD-Zuschlag zusammen; die Beziehung ist
    // nur zur Laufzeit erreichbar.
    assert_eq!(
        ea_crypto::checked_ciphertext_length(1_048_576),
        Ok(1_048_592),
        "the v1 ciphertext limit must stay the plaintext limit plus the AEAD overhead"
    );

    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let input = if *mode == 0 {
        rest.to_vec()
    } else {
        let (prefix, _) = FRAMES[usize::from(mode - 1) % FRAMES.len()];
        let mut synthesized = Vec::with_capacity(prefix.len() + rest.len());
        synthesized.extend_from_slice(&prefix);
        synthesized.extend_from_slice(rest);
        synthesized
    };

    let Ok(object) = ea_format::decode_exact_object(&input) else {
        return;
    };

    // Jede angenommene Eingabe gehoert zu genau einem Objekttyp und MUSS
    // dessen Familienrohgrenze einhalten — die Vergleichsrichtung spiegelt
    // `preflight`, das oberhalb der Grenze ablehnt.
    let (exact, family_limit) = match &object {
        ea_format::ParsedArchiveObject::Entry(parsed) => {
            (parsed.exact_bytes(), ea_format::EIP_MAX_RAW_BYTES_V1)
        }
        ea_format::ParsedArchiveObject::Grant(parsed) => {
            (parsed.exact_bytes(), ea_format::EAG_MAX_RAW_BYTES_V1)
        }
        ea_format::ParsedArchiveObject::Receipt(parsed) => {
            (parsed.exact_bytes(), ea_format::ESR_MAX_RAW_BYTES_V1)
        }
        ea_format::ParsedArchiveObject::Evidence(parsed) => {
            (parsed.exact_bytes(), ea_format::ECP_MAX_RAW_BYTES_V1)
        }
        ea_format::ParsedArchiveObject::Trust(parsed) => {
            (parsed.exact_bytes(), ea_format::ETB_MAX_RAW_BYTES_V1)
        }
        ea_format::ParsedArchiveObject::Destroyed(parsed) => {
            (parsed.exact_bytes(), ea_format::EDS_MAX_RAW_BYTES_V1)
        }
    };
    let exact = exact.as_bytes();

    assert_eq!(
        exact,
        input.as_slice(),
        "an accepted object must expose exactly the input bytes"
    );
    assert!(
        exact.len() <= family_limit,
        "an accepted object must stay inside its family raw limit"
    );
    assert!(
        exact.len() <= ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1,
        "an accepted object must stay inside the global raw limit"
    );

    // Die Rahmenpruefung laeuft ueber `ea_cbor::validate` mit den v1-Grenzen;
    // eine angenommene Eingabe MUSS sie folglich auch einzeln einhalten und
    // bereits kanonisch kodiert sein.
    assert!(
        ea_cbor::validate(exact, ea_cbor::ParserLimits::V1).is_ok(),
        "an accepted object must satisfy the v1 parser limits"
    );
    let canonical = ea_cbor::canonical_reencode(exact, ea_cbor::ParserLimits::V1)
        .expect("an accepted object must have a canonical representation");
    assert_eq!(
        canonical, exact,
        "an accepted object must already be canonical"
    );

    // Idempotenz: die exakten Bytes einer angenommenen Eingabe dekodieren
    // erneut.
    ea_format::decode_exact_object(exact)
        .expect("the exact bytes of an accepted object must decode again");
});
