//! Der Dokumentemitter und der Zielschreiber des Berichts.
//!
//! # `ea-verify` GIBT `runtimeMetadata` NIE AUS — bewusst
//!
//! Sein Schreiber kennt keine freien Zeichenketten: jede ausgegebene
//! Zeichenkette laeuft dort durch eine geschlossene Zeichenklasse, und faellt
//! je ein Zeichen heraus, bricht er ab (`crates/ea-verify/src/json.rs:8-23`).
//! Das ist die Zusicherung, die verhindert, dass unkontrollierter Text in einen
//! Bericht gelangt — sie aufzuweichen waere der teuerste denkbare Weg zu einem
//! Bequemlichkeitsfeld.
//!
//! Das Schema fuehrt `runtimeMetadata` gleichwohl als optionale Property NACH
//! `reportHash` (`schemas/reports/v1/verification-report.schema.json`). Genau
//! dieses eine Glied entsteht deshalb HIER und nicht dort: `hostName` und
//! `inputPath` sind die EINZIGEN freien Zeichenketten des ganzen Dokuments, und
//! sie sind die einzigen Werte, fuer die [`escaped`] ueberhaupt existiert. Die
//! Trennung ist der Punkt — in `ea-verify` bleibt die geschlossene Zeichenmenge
//! unangetastet, und der Escaper steht an genau einer Stelle, wo er gemessen
//! werden kann.
//!
//! # DIE EINGEFRORENE FORM WIRD GEPRUEFT, NICHT GEGLAUBT
//!
//! [`emit_report_document`] rechnet nichts nach: es nimmt
//! [`VerificationReportV1::to_canonical_json`], PRUEFT mit einem harten
//! `ends_with("\n}")`, dass die eingefrorene Form unveraendert ist, schneidet
//! genau diese zwei Bytes ab und haengt das Glied an. Ein leeres Objekt gaebe
//! `{}` — ohne Zeilenumbruch —, und genau deshalb ist die Pruefung ein `Err`
//! und kein `debug_assert`: sie muss auch im Auslieferungsbau tragen.
//!
//! # `reportHash` BLEIBT UNBERUEHRT
//!
//! Sein Urbild ist das Dokument OHNE `reportHash`, `reportSignature` und
//! `runtimeMetadata` (`crates/ea-verify/src/report.rs::canonical_hash_preimage`),
//! und `seal()` hat ihn laengst mit `ea_crypto::verification_report_hash`
//! gerechnet. Hier wird er ausgegeben und NICHT nachgerechnet: ein zweiter
//! Rechenweg auf denselben Wert waere eine zweite Autoritaet ueber ihn, und
//! zwei Autoritaeten laufen auseinander.
//!
//! # DIE UHR IST AUCH HIER KEIN PARAMETER DIESER CRATE
//!
//! `generated_at` und `runtime_ms` kommen als Zahlen HEREIN. Nirgends in dieser
//! Datei steht `SystemTime::now()` oder `Instant::now()`; die Begruendung ist
//! dieselbe wie in [`crate::verify`]. Es gibt genau eine Uhr im Werkzeug, und
//! sie steht in `apps/cli/src/main.rs`.

use std::{
    fs::{File, OpenOptions, Permissions},
    io::{self, Write as _},
    path::Path,
};

use ea_verify::{VerificationReportV1, VerifyError};

use crate::RecoveryError;

/// Die nichtdeterministischen Felder eines Laufs.
///
/// Sie erscheinen AUSSCHLIESSLICH auf ausdrueckliches Verlangen
/// (`--include-runtime-metadata`) und nie beilaeufig. Der Grund ist der
/// Determinismus des Berichts: Uhrzeit, Rechnername, Eingabepfad und Laufzeit
/// sind die vier Werte, die zwei Laeufe ueber denselben Bestand
/// unterschiedliche Bytes schreiben liessen. Wer sie will, sagt es; wer sie
/// nicht will, bekommt einen Bericht, den er byteweise vergleichen kann.
///
/// Die Feldreihenfolge ist die Property-Reihenfolge des Schemas und zugleich
/// die Ausgabereihenfolge: `generatedAt`, `hostName`, `inputPath`, `runtimeMs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeMetadataV1 {
    /// Der Zeitpunkt des Laufs in Unix-Millisekunden.
    ///
    /// DIESELBE Zahl, gegen die der Lauf verifiziert hat. Ein zweiter
    /// Zeitstempel waere eine zweite Uhr, und ein Bericht, dessen Kopfzeile
    /// eine andere Zeit naennte als sein Urteil, waere irrefuehrend.
    pub generated_at: i64,
    /// Der Rechner, auf dem der Lauf stattfand.
    pub host_name: String,
    /// Der Pfad des Bestands, WIE IHN DER AUFRUFER EINGEGEBEN HAT.
    ///
    /// Nicht aufgeloest und nicht kanonisiert: ein aufgeloester Pfad naennte
    /// Hostbestandteile, die der Aufrufer nie eingegeben hat, und die Global
    /// Constraint des Stage-1-Plans haelt Hostpfade aus allem heraus, was nicht
    /// unmittelbar aus der Eingabezeile stammt.
    pub input_path: String,
    /// Die Dauer des Laufs in Millisekunden.
    pub runtime_ms: u64,
}

/// Der Rueckgabewert, wenn die eingefrorene Dokumentform nicht mehr stimmt.
///
/// [`VerifyError::NonCanonicalReport`] und ausdruecklich kein eigener Code: die
/// Aussage ist dieselbe, die `ea-verify` an dieser Stelle macht — das Dokument
/// hat nicht die Form, in der es kanonisch ist. `exit_code_for_error` bildet
/// sie auf [`crate::ExitCode::Integrity`] ab, und das ist richtig: hier ist
/// nichts am Dateisystem gescheitert, sondern etwas am Dokument.
const NON_CANONICAL: RecoveryError = RecoveryError::Verify(VerifyError::NonCanonicalReport);

/// Die zwei Bytes, auf die jedes nichtleere kanonische Dokument endet.
///
/// `crates/ea-verify/src/json.rs::object` schliesst ein Objekt mit einem
/// Zeilenumbruch, der Einrueckung seiner Tiefe und der Klammer; auf Tiefe null
/// ist die Einrueckung leer. Ein LEERES Objekt gaebe dagegen `{}`, und genau
/// diesen Fall faengt die Pruefung mit ab.
const CANONICAL_DOCUMENT_TAIL_V1: &str = "\n}";

/// Die Rechte der Zieldatei unter unix: nur der Eigentuemer, nur lesen und
/// schreiben.
///
/// Ein Bericht nennt Objekthashes, Kettenkoepfe und Abdruecke eines Bestands.
/// Das ist kein Klartext, aber auch nichts, was auf einem geteilten Rechner
/// jeder mitlesen soll. Dieselbe Zahl gilt fuer jede Datei, die dieses Werkzeug
/// je schreibt.
#[cfg(unix)]
pub const OUTPUT_FILE_MODE_V1: u32 = 0o600;

/// Das Berichtsdokument, wahlweise mit angehaengtem `runtimeMetadata`.
///
/// # Errors
///
/// [`RecoveryError::Verify`] mit [`VerifyError::NonCanonicalReport`], falls der
/// Bericht je eine Zeichenkette ausser der Reihe truege oder die eingefrorene
/// Dokumentform sich geaendert haette.
pub fn emit_report_document(
    report: &VerificationReportV1,
    runtime: Option<&RuntimeMetadataV1>,
) -> Result<String, RecoveryError> {
    let document = report.to_canonical_json()?;
    let Some(runtime) = runtime else {
        return Ok(document);
    };

    let Some(body) = document.strip_suffix(CANONICAL_DOCUMENT_TAIL_V1) else {
        return Err(NON_CANONICAL);
    };

    let mut out = String::with_capacity(document.len() + 128);
    out.push_str(body);
    out.push_str(",\n  \"runtimeMetadata\": ");
    out.push_str(&runtime_object(runtime));
    out.push_str(CANONICAL_DOCUMENT_TAIL_V1);
    Ok(out)
}

/// Schreibt `document` in eine NEU angelegte Datei.
///
/// # DIE ZIELDATEI DARF NICHT EXISTIEREN
///
/// Gepruefft wird das nicht mit einem vorherigen `exists()`, sondern mit
/// `create_new(true)`: zwischen einer Frage und einer Tat liegt ein Zeitfenster,
/// in dem sich die Antwort aendern kann, und ein Wiederherstellungswerkzeug,
/// das eine fremde Datei ueberschreibt, weil es zu frueh gefragt hat, ist genau
/// der Schaden, den es verhindern soll. Existiert das Ziel, endet der Lauf mit
/// [`RecoveryError::OutputExists`] und die vorhandene Datei bleibt UNBERUEHRT —
/// `create_new` kuerzt nicht.
///
/// Das uebergeordnete Verzeichnis wird ausdruecklich NICHT angelegt. Ein
/// fehlendes Elternverzeichnis ist ein Bedienfehler und liefert
/// [`RecoveryError::Io`] (20); es stillschweigend zu erzeugen hiesse, an einer
/// Stelle Verzeichnisse zu bauen, an der der Aufrufer sich vertan hat.
///
/// # Errors
///
/// [`RecoveryError::OutputExists`], wenn das Ziel existiert;
/// [`RecoveryError::Io`] fuer jeden anderen Dateisystemfehler.
pub fn write_report_document(document: &str, output: &Path) -> Result<(), RecoveryError> {
    let mut file = create_new_file(output)?;
    file.write_all(document.as_bytes())?;
    // Ein Bericht, den ein Stromausfall zwischen `write` und dem Zurueckschreiben
    // des Puffers verschluckt, ist als Nachweis wertlos.
    file.sync_all()?;
    Ok(())
}

/// Legt `output` NEU an und gibt ihm restriktive Rechte.
///
/// Auch der Klartextschreiber aus [`crate::decrypt`] geht hier hindurch: die
/// Zusicherung „neu angelegt, nie ueberschrieben, 0600" gilt fuer JEDE Datei,
/// die dieses Werkzeug schreibt, und sie steht deshalb genau einmal da.
///
/// Die Rechte stehen schon im `open`-Aufruf und werden danach EXAKT gesetzt:
/// `mode` unterliegt der `umask` und kann Bits nur wegnehmen, weshalb ein
/// gesetztes `mode` allein zwar nie zu VIEL erlaubt, aber auch nicht garantiert,
/// dass genau 0600 herauskommt. Das zweite Setzen geschieht auf dem offenen
/// HANDLE und nicht auf dem Pfad: ein Pfad koennte zwischen beiden Schritten auf
/// etwas anderes zeigen.
pub(crate) fn create_new_file(output: &Path) -> Result<File, RecoveryError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(OUTPUT_FILE_MODE_V1);
    }
    let file = match options.open(output) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(RecoveryError::OutputExists);
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        file.set_permissions(Permissions::from_mode(OUTPUT_FILE_MODE_V1))?;
    }
    Ok(file)
}

/// Das `runtimeMetadata`-Objekt auf Tiefe 1.
///
/// Die Form ist die von `crates/ea-verify/src/json.rs:20-23` eingefrorene: zwei
/// Leerzeichen je Ebene, `": "` zwischen Schluessel und Wert, `",\n"` zwischen
/// Gliedern. Die Glieder stehen in Schema-Property-Reihenfolge und nicht
/// alphabetisch — dieselbe Regel, nach der die Berichtsglieder dem
/// `required`-Array folgen.
fn runtime_object(runtime: &RuntimeMetadataV1) -> String {
    format!(
        "{{\n    \"generatedAt\": {},\n    \"hostName\": {},\n    \"inputPath\": {},\n    \
         \"runtimeMs\": {}\n  }}",
        runtime.generated_at,
        escaped(&runtime.host_name),
        escaped(&runtime.input_path),
        runtime.runtime_ms,
    )
}

/// Eine freie Zeichenkette als JSON-Zeichenkette nach RFC 8259 §7.
///
/// # Der ENGE Escaper, und warum er eng ist
///
/// Maskiert wird genau, was maskiert werden MUSS: `"` und `\`, sowie jedes
/// Zeichen unterhalb `0x20` als `\u00XX`. Alles Uebrige geht unveraendert als
/// UTF-8 hinaus — der Standard verlangt weder eine Maskierung von `/` noch eine
/// von Zeichen jenseits von ASCII, und beides zu tun hiesse, eine zweite,
/// ungeprueft erfundene Kodierung einzufuehren.
///
/// # Windows-Pfade sind der REGELFALL
///
/// `inputPath` traegt auf Windows Rueckstriche, und zwar in jedem einzelnen
/// Aufruf. Ein Escaper, der sie nicht verdoppelte, erzeugte dort systematisch
/// ungueltige JSON — kein Randfall, sondern der Normalfall der Plattform.
fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{RuntimeMetadataV1, escaped, runtime_object};

    /// Die drei Klassen, die maskiert werden — und die, die es NICHT werden.
    #[test]
    fn the_escaper_covers_exactly_the_required_classes() {
        assert_eq!(escaped(r#"a"b"#), r#""a\"b""#);
        assert_eq!(escaped(r"C:\Einsatz\archiv"), r#""C:\\Einsatz\\archiv""#);
        assert_eq!(escaped("a\nb"), r#""a\u000ab""#);
        assert_eq!(escaped("a\tb\rc"), r#""a\u0009b\u000dc""#);
        assert_eq!(escaped("\u{0}"), r#""\u0000""#);
        assert_eq!(escaped("\u{1f}"), r#""\u001f""#);

        // NICHT maskiert: RFC 8259 verlangt es nicht, und wer hier maskierte,
        // erfaende eine zweite Kodierung ueber derselben Zeichenkette.
        assert_eq!(escaped("a/b"), r#""a/b""#);
        assert_eq!(escaped("Grüße/日本"), "\"Grüße/日本\"");
        assert_eq!(escaped(""), r#""""#);
    }

    /// Die Form des Glieds, Byte fuer Byte.
    ///
    /// Vier Leerzeichen vor jedem Glied, zwei vor der schliessenden Klammer:
    /// das Objekt steht auf Tiefe 1, seine Glieder auf Tiefe 2.
    #[test]
    fn the_runtime_member_carries_the_frozen_shape() {
        let rendered = runtime_object(&RuntimeMetadataV1 {
            generated_at: 1_786_938_024_364,
            host_name: "recovery-1".to_owned(),
            input_path: "/mnt/archiv".to_owned(),
            runtime_ms: 42,
        });
        assert_eq!(
            rendered,
            "{\n    \"generatedAt\": 1786938024364,\n    \"hostName\": \"recovery-1\",\n    \
             \"inputPath\": \"/mnt/archiv\",\n    \"runtimeMs\": 42\n  }"
        );
    }
}
