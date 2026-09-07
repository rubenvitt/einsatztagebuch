//! Die Zeugen des menschenlesbaren Fingerprints (Stufe 5, Task 6).
//!
//! Der Fingerprint IST der Objekthash der exakten Zertifikatsbytes
//! (`crates/ea-admin/src/device.rs`); diese Datei bewacht nur seine
//! Schreibweise: 32 Paare Gross-Hex, durch Doppelpunkte getrennt — und den
//! Rueckweg, der Gross- und Kleinschreibung sowie fehlende Doppelpunkte
//! annimmt und alles andere mit einem stabilen Code abweist.

use ea_admin::fingerprint::{
    FINGERPRINT_PARSE_ERROR, FingerprintParseError, human_readable_fingerprint,
    parse_human_readable_fingerprint,
};
use ea_types::ObjectHash;

fn hash(seed: u8) -> ObjectHash {
    let mut bytes = [seed; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = byte.wrapping_add(u8::try_from(index).expect("index < 32"));
    }
    ObjectHash::try_from(bytes.as_slice()).expect("zweiunddreissig Bytes")
}

/// Prueft die Form `^([0-9A-F]{2}:){31}[0-9A-F]{2}$` ohne Regex-Kiste.
fn has_fingerprint_shape(text: &str) -> bool {
    let pairs: Vec<&str> = text.split(':').collect();
    pairs.len() == 32
        && pairs.iter().all(|pair| {
            pair.len() == 2
                && pair
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
        })
}

/// Formatieren und Zurueckparsen ergibt denselben Hash.
#[test]
fn formatting_and_parsing_round_trip() {
    for seed in [0x00, 0x0a, 0x7f, 0xf0, 0xff] {
        let original = hash(seed);
        let text = human_readable_fingerprint(&original);
        let parsed = parse_human_readable_fingerprint(&text).expect("eigene Ausgabe ist lesbar");
        // `ObjectHash` fuehrt bewusst kein `Debug`; verglichen werden die Bytes.
        assert_eq!(parsed.as_bytes(), original.as_bytes());
    }
}

/// Die Ausgabe hat GENAU die Form aus dem Plan.
#[test]
fn the_formatter_emits_thirty_two_uppercase_pairs_joined_by_colons() {
    let text = human_readable_fingerprint(&hash(0xa0));
    assert_eq!(text.len(), 32 * 2 + 31);
    assert!(has_fingerprint_shape(&text), "{text}");
    assert!(
        !text.chars().any(|c| c.is_ascii_lowercase()),
        "kein Kleinbuchstabe in {text}"
    );
    // Der Anfang ist bekannt: 0xa0, 0xa1, 0xa2.
    assert!(text.starts_with("A0:A1:A2:"), "{text}");
}

/// Kleinschreibung und fehlende Doppelpunkte werden angenommen, Leerraum an
/// den Enden ebenfalls.
#[test]
fn lowercase_and_colon_less_input_parse_to_the_same_hash() {
    let original = hash(0x3c);
    let canonical = human_readable_fingerprint(&original);
    let lowercase = canonical.to_ascii_lowercase();
    let colon_less: String = canonical.chars().filter(|c| *c != ':').collect();
    let padded = format!("  {canonical}\n");
    for variant in [&lowercase, &colon_less, &padded] {
        assert_eq!(
            parse_human_readable_fingerprint(variant)
                .expect("lesbar")
                .as_bytes(),
            original.as_bytes(),
            "{variant:?}"
        );
    }
}

/// Alles andere ist mit dem einen Code unlesbar.
#[test]
fn malformed_input_fails_with_the_unreadable_code() {
    let canonical = human_readable_fingerprint(&hash(0x11));
    let thirty_one_pairs = canonical
        .rsplit_once(':')
        .map(|(head, _)| head.to_owned())
        .expect("hat Doppelpunkte");
    let thirty_three_pairs = format!("{canonical}:AB");
    let non_hex = canonical.replacen("11", "1G", 1);
    let embedded_whitespace = canonical.replacen(':', " ", 1);
    // Leerraum in der MITTE, von der Paarzahl entkoppelt: `embedded_whitespace`
    // oben verschmilzt zwei Paare zu einem fuenf Zeichen langen und ist damit
    // auch ueber die Laenge unlesbar. Diese drei halten die Paarzahl (oder die
    // 64 Zeichen der kompakten Form) bei und tragen NUR den Leerraum als
    // Fehler — getrimmt wird ausschliesslich an den Enden.
    let colon_then_space = canonical.replacen(':', ": ", 1);
    let compact: String = canonical.chars().filter(|c| *c != ':').collect();
    let mut compact_with_space_for_a_digit = compact.clone();
    compact_with_space_for_a_digit.replace_range(32..33, " ");
    let mut compact_with_an_inserted_space = compact.clone();
    compact_with_an_inserted_space.insert(32, ' ');
    assert_eq!(compact_with_space_for_a_digit.len(), 64);
    let colon_less_short: String = compact.chars().take(62).collect();
    for malformed in [
        thirty_one_pairs,
        thirty_three_pairs,
        non_hex,
        embedded_whitespace,
        colon_then_space,
        compact_with_space_for_a_digit,
        compact_with_an_inserted_space,
        colon_less_short,
        String::new(),
        "::".to_owned(),
    ] {
        let error = parse_human_readable_fingerprint(&malformed)
            .err()
            .unwrap_or_else(|| panic!("{malformed:?} darf nicht lesbar sein"));
        assert_eq!(error.code(), FINGERPRINT_PARSE_ERROR);
        assert_eq!(error.code(), "EA-WORKFLOW-FINGERPRINT-UNREADABLE");
        assert_eq!(error.to_string(), FINGERPRINT_PARSE_ERROR);
        assert_eq!(format!("{error:?}"), FINGERPRINT_PARSE_ERROR);
    }
}

/// Der Fehlertyp ist vergleichbar und kopierbar, wie die Nachbarn.
#[test]
fn the_error_type_is_a_plain_value() {
    let error: FingerprintParseError = parse_human_readable_fingerprint("nope")
        .err()
        .expect("unlesbar");
    let copy = error;
    assert_eq!(copy, error);
}
