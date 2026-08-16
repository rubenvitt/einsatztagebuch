//! Der handgeschriebene kanonische JSON-Schreiber des Verifikationsberichts.
//!
//! Kein `serde_json`, kein `jsonschema`: beide zoegen `getrandom 0.3.4` in den
//! wasm-Graphen, und `ea-verify` steht auf der wasm32-Positivliste von
//! `tools/xtask/src/main.rs`. Der Schemanachweis liegt deshalb ausserhalb
//! dieser Crate, in `tests/ea-system-tests`.
//!
//! DER ENTSCHEIDENDE PUNKT dieses Moduls ist nicht das Formatieren, sondern
//! die geschlossene Zeichenmenge: der Bericht kennt AUSSCHLIESSLICH
//! Kleinbuchstaben-Hex, festverdrahtete Bezeichner, geschlossene Enum-Literale
//! und Dezimalzahlen. Jede ausgegebene Zeichenkette laeuft durch
//! [`quoted`] und wird gegen ihre [`TokenClass`] geprueft; faellt je ein
//! Zeichen heraus, bricht der Schreiber mit
//! [`VerifyError::NonCanonicalReport`] ab. Deshalb kommt in diesem Modul kein
//! einziges Maskierungszeichen vor — und deshalb kann kein unkontrollierter
//! Text in den Bericht gelangen. Ein Escaper waere die bequemere und
//! gefaehrlichere Loesung: er wuerde freien Text zulassen und ihn nur
//! huebsch verpacken.
//!
//! FORM, EINGEFROREN: zwei Leerzeichen Einrueckung je Ebene, `": "` zwischen
//! Schluessel und Wert, `",\n"` zwischen Gliedern, leere Sammlungen als `{}`
//! beziehungsweise `[]`, KEIN abschliessender Zeilenumbruch. Task 10 friert
//! genau diese Bytes ein.

use crate::VerifyError;

/// Die geschlossenen Zeichenklassen des Berichts.
///
/// Es gibt bewusst keine Klasse fuer freien Text. Kaeme je ein Berichtsfeld
/// dazu, das echten Text traegt, muesste diese Aufzaehlung erweitert werden —
/// und genau diese Aenderung soll auffallen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TokenClass {
    /// Der eine Schemabezeichner. Wird auf Gleichheit geprueft, nicht auf
    /// Zeichen: `schemaId` ist im Schema ein `const`.
    SchemaId,
    /// Kleinbuchstaben-Hex, `[0-9a-f]`. Kennungen und Hashes.
    LowerHex,
    /// Ein festverdrahteter Bezeichner aus Buchstaben: Feldnamen des Schemas
    /// und die geschlossenen Enum-Literale in `camelCase`.
    Identifier,
    /// Ein stabiler Fehlercode: `EA-` gefolgt von `[A-Z0-9-]+`. Deckt sich mit
    /// `formatError.code` (`^EA-[A-Z0-9-]+$`) im Berichtsschema.
    ErrorCode,
}

/// Der eine zugelassene Wert von `schemaId`.
pub(crate) const SCHEMA_ID_V1: &str = "ea.verification-report/v1";

impl TokenClass {
    /// Erfuellt `value` diese Klasse vollstaendig?
    fn accepts(self, value: &str) -> bool {
        match self {
            Self::SchemaId => value == SCHEMA_ID_V1,
            Self::LowerHex => {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            }
            Self::Identifier => !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphabetic()),
            Self::ErrorCode => {
                value.len() > 3
                    && value.starts_with("EA-")
                    && value.bytes().skip(3).all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }
        }
    }
}

/// Eine gepruefte, in Anfuehrungszeichen gesetzte Zeichenkette.
///
/// # Errors
///
/// [`VerifyError::NonCanonicalReport`], sobald `value` seine Klasse verletzt.
pub(crate) fn quoted(value: &str, class: TokenClass) -> Result<String, VerifyError> {
    if !class.accepts(value) {
        return Err(VerifyError::NonCanonicalReport);
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    out.push_str(value);
    out.push('"');
    Ok(out)
}

/// Kleinbuchstaben-Hex ueber `bytes`, in Anfuehrungszeichen.
///
/// Laeuft trotz Erzeugung aus Bytes durch dieselbe Pruefung wie jede andere
/// Zeichenkette: eine Ausnahme waere genau die Stelle, an der die Zusicherung
/// spaeter still verloren ginge.
///
/// # Errors
///
/// [`VerifyError::NonCanonicalReport`], falls die Umwandlung je etwas anderes
/// als `[0-9a-f]` erzeugte.
pub(crate) fn hex_string(bytes: &[u8]) -> Result<String, VerifyError> {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(
            char::from_digit(u32::from(byte >> 4), 16).ok_or(VerifyError::NonCanonicalReport)?,
        );
        hex.push(
            char::from_digit(u32::from(byte & 0x0f), 16).ok_or(VerifyError::NonCanonicalReport)?,
        );
    }
    quoted(&hex, TokenClass::LowerHex)
}

/// Eine vorzeichenlose Dezimalzahl.
pub(crate) fn uint(value: u64) -> String {
    value.to_string()
}

/// Rueckt `depth` Ebenen ein.
fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Ein JSON-Objekt aus bereits auf `depth + 1` gerenderten Werten.
///
/// Die Reihenfolge der Glieder ist die uebergebene und wird NICHT sortiert:
/// die Objektfelder des Berichts folgen dem `required`-Array des Schemas, nicht
/// dem Alphabet. Die Sortierung betrifft ausschliesslich Arrays, und die
/// entsteht in `report.rs` aus `BTreeMap`/`BTreeSet`, nie hier.
///
/// # Errors
///
/// [`VerifyError::NonCanonicalReport`], wenn ein Schluessel kein Bezeichner ist.
pub(crate) fn object(depth: usize, members: &[(&str, String)]) -> Result<String, VerifyError> {
    if members.is_empty() {
        return Ok("{}".to_owned());
    }
    let mut out = String::from("{\n");
    for (index, (key, value)) in members.iter().enumerate() {
        indent(&mut out, depth + 1);
        out.push_str(&quoted(key, TokenClass::Identifier)?);
        out.push_str(": ");
        out.push_str(value);
        if index + 1 < members.len() {
            out.push(',');
        }
        out.push('\n');
    }
    indent(&mut out, depth);
    out.push('}');
    Ok(out)
}

/// Ein JSON-Array aus bereits auf `depth + 1` gerenderten Werten.
///
/// Die Reihenfolge ist die uebergebene. Sortiert und dedupliziert wird in
/// `report.rs` durch die Wahl der Behaelter — `BTreeMap`/`BTreeSet` ueber genau
/// den `x-ea-unique-key` des Schemas. In dieser Crate kommt deshalb weder
/// `HashMap` noch `HashSet` vor: eine Streuordnung waere in Unit-Tests
/// unauffaellig und wuerde den Schematest sporadisch kippen.
pub(crate) fn array(depth: usize, items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_owned();
    }
    let mut out = String::from("[\n");
    for (index, item) in items.iter().enumerate() {
        indent(&mut out, depth + 1);
        out.push_str(item);
        if index + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    indent(&mut out, depth);
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::{TokenClass, array, hex_string, object, quoted, uint};

    #[test]
    fn every_token_class_rejects_a_foreign_character() {
        for (value, class) in [
            ("ea.verification-report/v2", TokenClass::SchemaId),
            ("00AB", TokenClass::LowerHex),
            ("", TokenClass::LowerHex),
            ("valid entry", TokenClass::Identifier),
            ("EA_FORMAT_SHAPE", TokenClass::ErrorCode),
            ("EA-", TokenClass::ErrorCode),
            ("EA-format-shape", TokenClass::ErrorCode),
        ] {
            assert!(
                quoted(value, class).is_err(),
                "{value:?} must not pass {class:?}"
            );
        }
    }

    #[test]
    fn a_quote_or_backslash_never_survives_any_class() {
        for class in [
            TokenClass::SchemaId,
            TokenClass::LowerHex,
            TokenClass::Identifier,
            TokenClass::ErrorCode,
        ] {
            for value in ["\"", "\\", "a\"b", "EA-A\\B"] {
                assert!(quoted(value, class).is_err());
            }
        }
    }

    #[test]
    fn the_pinned_shape_is_two_space_indented_and_has_no_trailing_newline() {
        let inner = object(1, &[("sequence", uint(0))]).unwrap();
        let document = object(0, &[("chainHead", inner), ("gaps", array(1, &[]))]).unwrap();
        assert_eq!(
            document,
            "{\n  \"chainHead\": {\n    \"sequence\": 0\n  },\n  \"gaps\": []\n}"
        );
    }

    /// Die Gestalt, die `verify_archive` in dieser Fassung nie erzeugt.
    ///
    /// `registryVersions` und `publicKeyThumbprints` sind Arrays aus SKALAREN,
    /// nicht aus Objekten; sie bleiben leer, solange die Pipeline nicht
    /// vollstaendig laeuft. Task 10 friert ihre Bytes dennoch ein, also wird
    /// die Gestalt hier gepinnt statt erst dann entdeckt.
    #[test]
    fn a_scalar_array_indents_its_items_one_level_deeper() {
        let versions = object(0, &[("registryVersions", array(1, &[uint(3), uint(7)]))]).unwrap();
        assert_eq!(
            versions,
            "{\n  \"registryVersions\": [\n    3,\n    7\n  ]\n}"
        );

        let thumbprints = object(
            0,
            &[(
                "publicKeyThumbprints",
                array(1, &[hex_string(&[0x0a]).unwrap()]),
            )],
        )
        .unwrap();
        assert_eq!(
            thumbprints,
            "{\n  \"publicKeyThumbprints\": [\n    \"0a\"\n  ]\n}"
        );
    }

    #[test]
    fn hex_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex_string(&[0x00, 0xff, 0x0a]).unwrap(), "\"00ff0a\"");
    }
}
