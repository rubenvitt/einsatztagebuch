//! Kommando `decrypt`: pruefen, dann Klartext in ein neues Ziel schreiben.
//!
//! # DIE REIHENFOLGE IST DER GEGENSTAND
//!
//! `decrypt` ist nicht „entschluesseln und nebenbei pruefen". Die Global
//! Constraint des Stage-1-Plans (Zeile 26) macht verify-before-use zur
//! Bedingung des Kommandos: es wird VOLLSTAENDIG verifiziert, und erst wenn
//! der Bericht keinen Befund traegt, entsteht ueberhaupt ein Ziel. Ein
//! Werkzeug, das erst schriebe und dann urteilte, hinterliesse Klartext aus
//! einem Bestand, ueber den es nichts sagen kann.
//!
//! Die Schritte, und sie sind nicht vertauschbar:
//!
//! 1. Diese Plattform kann restriktive Rechte setzen — sonst wird nicht
//!    gelesen und nicht geschrieben.
//! 2. Bestand EINMAL einlesen, vollstaendig verifizieren.
//! 3. Traegt der Bericht einen Befund, endet der Lauf mit dessen Code, und es
//!    entsteht kein Ziel.
//! 4. Das Ziel ist neu oder leer — sonst Exitcode 2.
//! 5. Es gibt mindestens einen eigenen Grant — sonst Exitcode 14.
//! 6. Erst jetzt wird geoeffnet und geschrieben.
//!
//! Schritt 5 steht VOR dem Anlegen des Ziels und HINTER seiner Pruefung. Das
//! ist kein Zufall: ein Aufruf gegen ein belegtes Ziel ist ein AUFRUFFEHLER
//! und traegt nach `design.md`:1802-1815 den kleineren Code 2, waehrend ein
//! Lauf ohne eigenen Grant ein Verzeichnis hinterliesse, das beim naechsten
//! Versuch selbst als belegt gaelte.
//!
//! # WARUM DIE ENTSCHLUESSELUNG HIER NEU ENTSTEHT
//!
//! `ea_verify::open_entry` (`crates/ea-verify/src/recipient.rs:196-225`) tut
//! exakt dasselbe — und VERWIRFT den Klartext absichtlich, weil er in einem
//! Verifikationslauf nichts zu suchen hat. Die Funktion ist `pub(crate)`, und
//! das ist richtig so. Hier wird der Klartext GEBRAUCHT, und deshalb steht der
//! Weg ein zweites Mal da, statt `ea-verify` seine Zusicherung aufzuweichen.
//!
//! # DER KLARTEXT BEKOMMT KEINEN ZWEITEN AUFENTHALTSORT
//!
//! Er lebt als [`ea_crypto::SecretVec`], wird INNERHALB von
//! [`ea_crypto::SecretVec::with_exposed`] unmittelbar in die bereits geoeffnete
//! Zieldatei geschrieben und danach fallen gelassen. Kein `Vec`, der ihn
//! herausreicht, keine `.tmp`, kein Umbenennen, kein
//! [`std::env::temp_dir`] — gemessen in
//! `apps/cli/tests/decrypt.rs::no_plaintext_temporary_file_is_created`.

use std::{fs, io::Write as _, path::Path};

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource as _};
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, CanonicalPublicCoseKey, HPKE_ENCAPSULATED_KEY_SIZE,
    HPKE_WRAPPED_CEK_SIZE, HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, SecretVec, aead_open,
    hpke_aad, hpke_info, hpke_open, payload_aad,
};
use ea_format::{
    EntryPackageV1, GrantBodyV1, GrantKindV1, GrantV1, Parsed, ParsedArchiveObject,
    decode_exact_object,
};
use ea_trust::TrustAnchorV1;
use ea_types::{KeyThumbprint, UnixMillis};
use ea_verify::{ObjectResultKindV1, ObjectTypeV1, VerificationReportV1, VerifyError};

use crate::{
    ExitCode, FsArchiveSource, RecoveryError, exit_code_for,
    report::create_new_file,
    target::{
        output_directory_is_free, prepare_output_directory, restrictive_permissions_available,
    },
    verify::verify_source,
};

/// Die Zahl der Rohbytes eines Empfaengerschluessels.
///
/// X25519, also 32 — dieselbe Groesse, die
/// [`HpkeRecipientPrivateKey::from_bytes`] verlangt.
pub const RECIPIENT_KEY_SIZE_V1: usize = 32;

/// Das Ergebnis eines vollstaendigen `decrypt`-Laufs.
///
/// Traegt den BERICHT und nicht bloss einen Code: der Aufrufer leitet den
/// Exitcode mit [`exit_code_for`] daraus ab — derselbe Weg wie bei `verify`,
/// `list` und `report`, damit es fuer denselben Bericht nur EINE Ableitung
/// gibt.
///
/// # Kein Klartext, nirgends
///
/// Kein Feld dieses Typs traegt entschluesselte Bytes, und es gibt kein
/// `Debug`: [`written_entries`](Self::written_entries) zaehlt Dateien, mehr
/// nicht.
pub struct DecryptionV1 {
    /// Der vollstaendige Verifikationsbericht des Laufs.
    pub report: VerificationReportV1,
    /// Die Zahl der geschriebenen Klartextdateien.
    ///
    /// Niemals null bei einem erfolgreichen Lauf: ein Lauf ohne einen einzigen
    /// eigenen Grant endet mit [`RecoveryError::NoOwnGrant`].
    pub written_entries: usize,
}

/// Prueft den Bestand unter `root` und schreibt seinen Klartext nach `output`.
///
/// # Errors
///
/// [`RecoveryError::RestrictivePermissionsUnsupported`], wenn diese Plattform
/// die Rechte nicht setzen kann; [`RecoveryError::Io`] und
/// [`RecoveryError::ArchiveTooLarge`] aus dem Einlesen;
/// [`RecoveryError::Verify`], wenn gar kein Bericht entsteht;
/// [`RecoveryError::OutputExists`], wenn das Ziel belegt ist;
/// [`RecoveryError::NoOwnGrant`], wenn kein Grant auf `key` lautet;
/// [`RecoveryError::Decryption`], wenn ein Grant sich nicht oeffnen laesst.
///
/// Ein BEFUND ist kein Fehler: er kommt als `Ok` mit einem Bericht zurueck,
/// dessen [`exit_code_for`] ihn benennt, und mit
/// [`DecryptionV1::written_entries`] gleich null.
///
/// # EIN FEHLER AB SCHRITT 6 LAESST GESCHRIEBENEN KLARTEXT LIEGEN
///
/// Bis Schritt 5 gilt „kein Ziel, solange nicht geschrieben wird" — jeder
/// Ausgang davor hinterlaesst nichts. AB Schritt 6 gilt das nicht mehr, und
/// zwar unvermeidlich: `write_plaintext` laeuft je Planeintrag, und der erste
/// Fehler — `ENOSPC` und `EIO` sind die realistischen — bricht die Schleife ab.
/// Die bereits geschriebenen Dateien bleiben dann im Ziel stehen. Sie tragen
/// 0600 und liegen in einem Verzeichnis mit 0700; sie sind also nicht
/// preisgegeben, aber sie sind DA.
///
/// AUFGERAEUMT WIRD ABSICHTLICH NICHT. Ein Loeschpfad im Fehlerfall braucht
/// selbst eine Antwort auf sein eigenes Scheitern, und die zweite Antwort waere
/// dieselbe wie die erste: der Klartext liegt noch da. Statt eine Zusicherung zu
/// behaupten, die nicht zu halten ist, steht sie hier ausdruecklich nicht: wer
/// diese Funktion aufruft und einen Fehler bekommt, MUSS das von ihm selbst
/// benannte Ziel als moeglicherweise teilbefuellt behandeln.
pub fn decrypt_directory(
    root: &Path,
    anchor: &TrustAnchorV1,
    now: UnixMillis,
    key: &HpkeRecipientPrivateKey,
    output: &Path,
) -> Result<DecryptionV1, RecoveryError> {
    // 1 — VOR jedem gelesenen Byte. Wo die Zusicherung nicht zu halten ist,
    // wird nicht ersatzweise ohne sie gearbeitet. Dieselbe Reihenfolge, die
    // `apps/cli/src/commands/report.rs` fuer seine Verweigerung waehlt.
    restrictive_permissions_available()?;

    // Der Abdruck wird GERECHNET und nie gelesen. Kaeme er aus der
    // Schluesseldatei, koennten Abdruck und Material auseinanderfallen, und
    // `crates/ea-verify/src/archive.rs:97-105` haelt ausdruecklich fest, dass
    // genau dieser Fall als ENTSCHLUESSELUNGSFEHLER sichtbar werden muss und
    // nicht als fehlender Grant.
    let key_thumbprint = recipient_key_thumbprint(key)?;

    // 2 — EINMAL einlesen. Der Puffer, ueber den geurteilt wird, ist derselbe,
    // aus dem danach entschluesselt wird; siehe `crate::verify::verify_source`.
    let source = FsArchiveSource::open(root)?;
    let report = verify_source(&source, anchor, now, Some((key_thumbprint, key)))?;

    // 3 — ein Befund beendet den Lauf, bevor irgendetwas entsteht.
    if exit_code_for(&report) != ExitCode::Success {
        return Ok(DecryptionV1 {
            report,
            written_entries: 0,
        });
    }

    // 4 — die Zielpruefung, OHNE anzulegen. Sie steht vor Schritt 5, damit der
    // kleinere Aufrufcode 2 den groesseren Schluesselcode 14 ueberstimmt, so
    // wie `design.md`:1815 es verlangt.
    output_directory_is_free(output)?;

    // 5 — ohne eigenen Grant gibt es nichts zu schreiben, und ein leeres Ziel
    // waere die falscheste aller Antworten. Der Plan entsteht VOR dem Anlegen,
    // damit dieser Ausgang kein Verzeichnis hinterlaesst.
    let plan = decryption_plan(&source, &report, key_thumbprint)?;
    if plan.is_empty() {
        return Err(RecoveryError::NoOwnGrant);
    }

    // 6 — erst jetzt. AB HIER KANN EIN FEHLER KLARTEXT ZURUECKLASSEN; der
    // `# Errors`-Abschnitt oben fuehrt aus, warum das so bleibt.
    prepare_output_directory(output)?;
    for (entry, grant) in &plan {
        write_plaintext(entry, grant, key, output)?;
    }

    Ok(DecryptionV1 {
        report,
        written_entries: plan.len(),
    })
}

/// Laedt den privaten Empfaengerschluessel aus einer Datei.
///
/// # ZWEI FORMEN, UND SONST KEINE
///
/// GENAU 32 Rohbytes oder GENAU 64 Hexzeichen mit optional einem
/// abschliessenden Zeilenumbruch. Die Rohform wird ZUERST geprueft und dabei
/// NICHTS abgeschnitten: ein Schluessel, dessen letztes Byte zufaellig `0x0a`
/// ist, wuerde durch ein vorgezogenes Trimmen auf 31 Bytes verstuemmelt und
/// dann abgelehnt — ein Fehler, den nur jeder 256. Schluessel zeigt.
///
/// # Errors
///
/// [`RecoveryError::Io`], wenn die Datei nicht lesbar ist;
/// [`RecoveryError::KeySource`], wenn sie keine dieser beiden Formen traegt
/// oder ihre Bytes kein X25519-Schluessel sind.
pub fn load_recipient_key(path: &Path) -> Result<HpkeRecipientPrivateKey, RecoveryError> {
    // Die gelesenen Bytes SIND Schluesselmaterial. Sie wandern deshalb sofort
    // in einen `SecretVec`, der beim Verlassen dieses Rahmens ueberschrieben
    // wird — ein blosser `Vec` bliebe als Kopie des Schluessels im Speicher
    // liegen.
    let file_bytes = SecretVec::new(fs::read(path)?);
    let material = file_bytes
        .with_exposed(recipient_key_material)
        .ok_or(RecoveryError::KeySource)?;
    HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(material))
        .map_err(|_| RecoveryError::KeySource)
}

/// Der Abdruck, unter dem dieser Schluessel in einem Grant steht.
///
/// # Errors
///
/// [`RecoveryError::KeySource`], wenn der oeffentliche Punkt kein kanonischer
/// COSE-Schluessel ist.
pub fn recipient_key_thumbprint(
    key: &HpkeRecipientPrivateKey,
) -> Result<KeyThumbprint, RecoveryError> {
    Ok(CanonicalPublicCoseKey::x25519(*key.public_key().as_bytes())
        .map_err(|_| RecoveryError::KeySource)?
        .thumbprint())
}

/// Die 32 Schluesselbytes aus dem Dateiinhalt, oder nichts.
fn recipient_key_material(bytes: &[u8]) -> Option<[u8; RECIPIENT_KEY_SIZE_V1]> {
    if let Ok(raw) = <[u8; RECIPIENT_KEY_SIZE_V1]>::try_from(bytes) {
        return Some(raw);
    }
    // Genau ein Zeilenende, und beide Schreibweisen: eine Hexdatei entsteht
    // ueblicherweise in einem Editor, und der haengt eines an.
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    if trimmed.len() != 2 * RECIPIENT_KEY_SIZE_V1 {
        return None;
    }
    let mut material = [0_u8; RECIPIENT_KEY_SIZE_V1];
    for (target, pair) in material.iter_mut().zip(trimmed.chunks_exact(2)) {
        *target = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(material)
}

/// Der Wert einer Hexziffer.
///
/// Von Hand und nicht ueber `hex`: die Kiste ist eine DEV-Dependency dieser
/// Crate und gehoert nicht in den Auslieferungsgraphen. Dieselbe Entscheidung
/// trifft `apps/cli/src/output.rs` fuer die Gegenrichtung.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Ein Eintrag samt dem eigenen Grant, der ihn oeffnet.
///
/// PAARWEISE und nicht zwei getrennte Listen: ein Eintrag ohne Grant wird nicht
/// geschrieben, und ein Grant ohne Eintrag oeffnet nichts. Die Zuordnung wird
/// EINMAL gebildet und danach nur noch abgearbeitet.
type OpenablePairV1 = (Parsed<EntryPackageV1>, Parsed<GrantV1>);

/// Die Paare aus Eintrag und eigenem Grant, in Sequenzreihenfolge.
///
/// # NUR WAS DER BERICHT ALS `valid` FUEHRT
///
/// Ein Objekt, ueber das der Bericht nichts oder nichts Gutes sagt, ist NICHT
/// verifiziert — und was nicht verifiziert ist, wird nicht geoeffnet. Der
/// Bericht ist hier die einzige Autoritaet; ein zweites Urteil an dieser Stelle
/// waere eine zweite Gelegenheit, es anders zu faellen.
///
/// # Historische Grants bleiben aussen vor
///
/// Sie tragen eine Authorization, die dieser Lauf nicht aufloesen kann, und
/// `crates/ea-verify/src/recipient.rs:76-84` haelt fest, dass mit ihnen
/// deshalb NICHTS geoeffnet wird. Ein `decrypt`, das sie doch benutzte, oeffnete
/// mehr als der Verifikationslauf geprueft hat.
fn decryption_plan(
    source: &FsArchiveSource,
    report: &VerificationReportV1,
    key_thumbprint: KeyThumbprint,
) -> Result<Vec<OpenablePairV1>, RecoveryError> {
    let mut entries: Vec<Parsed<EntryPackageV1>> = Vec::new();
    let mut grants: Vec<Parsed<GrantV1>> = Vec::new();
    source
        .visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            // Ein nicht dekodierbarer Blob wird UEBERGANGEN und nicht gemeldet:
            // der Bericht hat ihn laengst beurteilt, und dieser Lauf ist nur
            // erfolgreich, wenn er dabei keinen Befund erhoben hat. Beiwerk —
            // README, Schemadateien — faellt in denselben Zweig.
            match decode_exact_object(blob.bytes()) {
                Ok(ParsedArchiveObject::Entry(entry)) => entries.push(entry),
                Ok(ParsedArchiveObject::Grant(grant)) => grants.push(grant),
                Ok(_) | Err(_) => {}
            }
            Ok::<(), ArchiveError>(())
        })
        // Unerreichbar, und trotzdem kein `expect`: `FsArchiveSource::visit_blobs`
        // kann nach `crates/ea-recovery/src/source.rs:99-100` gar nicht mehr
        // scheitern — gelesen wurde alles bereits in `open`. Sollte der Port das je
        // aendern, bekommt der Fehler denselben Code wie in der Pipeline, statt
        // diesen Lauf abzubrechen.
        .map_err(|error| RecoveryError::Verify(VerifyError::Archive(error)))?;

    let mut plan: Vec<OpenablePairV1> = Vec::new();
    for entry in entries {
        if !is_valid_entry(report, &entry) {
            continue;
        }
        let entry_hash = entry.value().entry_hash();
        let position = grants.iter().position(|grant| {
            let fields = grant.value().grant_body().fields();
            grant.value().kind() == GrantKindV1::Initial
                && fields.entry_hash == entry_hash
                && fields.recipient_key_thumbprint == key_thumbprint
        });
        if let Some(position) = position {
            plan.push((entry, grants.swap_remove(position)));
        }
    }
    // Die Reihenfolge des Durchlaufs haengt an Dateinamen; die Reihenfolge des
    // Schreibens soll an der KETTE haengen. Beides faellt bei diesem Layout
    // zusammen, aber nur eines davon ist zugesichert.
    plan.sort_by_key(|(entry, _)| entry.value().manifest().fields().chain_sequence);
    Ok(plan)
}

/// Ob der Bericht ueber genau dieses Eintragsobjekt `valid` sagt.
fn is_valid_entry(report: &VerificationReportV1, entry: &Parsed<EntryPackageV1>) -> bool {
    let object_hash = entry.object_hash();
    report.object_results().any(|result| {
        result.object_hash() == object_hash
            && result.object_type() == ObjectTypeV1::Entry
            && result.result() == ObjectResultKindV1::Valid
    })
}

/// Oeffnet einen Eintrag und schreibt seinen Klartext in eine NEUE Datei.
///
/// Der Dateiname ist die Kettensequenz, zwoelfstellig mit fuehrenden Nullen —
/// dieselbe Form, in der der Bestand seine Eintraege ablegt. Er benennt damit
/// die STELLE IN DER KETTE und nicht die Reihenfolge des Schreibens; zwei Laeufe
/// ueber denselben Bestand liefern dieselben Namen.
///
/// # ZWEI EINTRAEGE AUF DERSELBEN SEQUENZ UEBERSCHREIBEN EINANDER NICHT
///
/// Innerhalb einer Kette kann das nicht vorkommen — eine doppelte Sequenz waere
/// ein Fork und faellt schon an Gate `chain-position`. Ueber zwei Ketten hinweg
/// waere es denkbar, und dann scheitert [`create_new_file`] mit
/// [`RecoveryError::OutputExists`]: der Lauf endet, und die bereits
/// geschriebene Datei bleibt UNBERUEHRT. Fail-closed und ausdruecklich kein
/// Ueberschreiben; ein zweiter Klartext unter demselben Namen waere der
/// stillste denkbare Datenverlust.
fn write_plaintext(
    entry: &Parsed<EntryPackageV1>,
    grant: &Parsed<GrantV1>,
    key: &HpkeRecipientPrivateKey,
    output: &Path,
) -> Result<(), RecoveryError> {
    let body = grant.value().grant_body();
    let context = exact_grant_context(body).ok_or(RecoveryError::Decryption)?;
    let fields = body.fields();
    let sealed = HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)
        .map_err(|_| RecoveryError::Decryption)?;
    let cek: SecretBytes<CEK_SIZE> =
        hpke_open(key, &sealed, &hpke_info(context), &hpke_aad(context))
            .map_err(|_| RecoveryError::Decryption)?;
    let manifest = entry.value().manifest();
    let nonce: SecretBytes<AEAD_NONCE_SIZE> = SecretBytes::new(manifest.fields().nonce);
    let plaintext = aead_open(
        &cek,
        &nonce,
        entry.value().ciphertext(),
        &payload_aad(manifest.exact_bytes()),
    )
    .map_err(|_| RecoveryError::Decryption)?;

    // UNMITTELBAR in die endgueltige Datei. `create_new(true)` legt sie an oder
    // scheitert; es gibt keinen Zwischenstand, der umbenannt werden muesste,
    // und damit auch keinen Ort, an dem Klartext liegen bliebe.
    let sequence = manifest.fields().chain_sequence.get();
    let mut file = create_new_file(&output.join(format!("{sequence:012}.bin")))?;
    // Der Klartext ist NUR innerhalb dieses Rueckrufs sichtbar und wird nicht
    // vorher in einen `Vec` kopiert: der Sinn der bereichsgebundenen Form ist,
    // dass kein Klartextpuffer laenger lebt als noetig.
    plaintext.with_exposed(|bytes| file.write_all(bytes))?;
    // Klartext, den ein Stromausfall zwischen `write` und dem Zurueckschreiben
    // des Puffers verschluckt, waere eine halbe Wiederherstellung.
    file.sync_all()?;
    Ok(())
}

/// Die exakten Bytes des `grant-context-v1` aus einem `grant-body-v1`.
///
/// # DUPLIKAT MIT ANGABE DER QUELLE, UND ES MUSS EINES SEIN
///
/// Wort fuer Wort dieselbe Rekonstruktion wie
/// `crates/ea-verify/src/recipient.rs:266-288`. Sie steht hier ein zweites Mal,
/// weil `ea-format` den Kontext nicht herausgibt — `GrantBodyV1` kennt nur
/// `exact_bytes()` und `fields()` — und weil `ea-format` GESCHLOSSEN ist. Die
/// Alternative waere, `ea_verify::open_entry` oeffentlich zu machen; dann aber
/// verliesse der Klartext die Verifikationspipeline, und genau das verhindert
/// sie mit Absicht.
///
/// # DER SCHNITT IST BEWIESEN, NICHT GERATEN
///
/// `grant-body-v1` ist ein CBOR-Array fester Laenge drei (`0x83`), dessen
/// zweites und drittes Glied Bytefolgen fester Groesse 32 und 48 sind. Beide
/// werden kanonisch als `0x58 0x20 || …` beziehungsweise `0x58 0x30 || …`
/// kodiert. Dieser Schwanz wird unabhaengig aus den dekodierten Feldern
/// nachgebaut und gegen den Rumpf geprueft; stimmt er exakt, ist alles nach dem
/// Arraykopf definitionsgemaess das erste Glied — der Kontext.
///
/// Faellt der Waechter, wird `None` geliefert und NICHTS geoeffnet.
fn exact_grant_context(body: &GrantBodyV1) -> Option<&[u8]> {
    /// CBOR-Kopf einer Bytefolge mit einbytiger Laengenangabe.
    const BYTE_STRING_ONE_BYTE_LENGTH: u8 = 0x58;
    /// CBOR-Kopf eines Arrays fester Laenge drei.
    const ARRAY_OF_THREE: u8 = 0x83;

    let exact = body.exact_bytes();
    let fields = body.fields();
    let mut tail = Vec::with_capacity(4 + HPKE_ENCAPSULATED_KEY_SIZE + HPKE_WRAPPED_CEK_SIZE);
    tail.push(BYTE_STRING_ONE_BYTE_LENGTH);
    tail.push(u8::try_from(HPKE_ENCAPSULATED_KEY_SIZE).ok()?);
    tail.extend_from_slice(&fields.encapsulated_key);
    tail.push(BYTE_STRING_ONE_BYTE_LENGTH);
    tail.push(u8::try_from(HPKE_WRAPPED_CEK_SIZE).ok()?);
    tail.extend_from_slice(&fields.wrapped_cek);

    let context_end = exact.len().checked_sub(tail.len())?;
    let (head, actual_tail) = exact.split_at(context_end);
    if actual_tail != tail.as_slice() || head.first() != Some(&ARRAY_OF_THREE) {
        return None;
    }
    head.get(1..)
}

#[cfg(test)]
mod tests {
    use super::{RECIPIENT_KEY_SIZE_V1, recipient_key_material};

    /// Die beiden zulaessigen Formen — und die, die es NICHT sind.
    #[test]
    fn the_key_source_accepts_exactly_two_forms() {
        let raw = [0x4c_u8; RECIPIENT_KEY_SIZE_V1];
        assert_eq!(recipient_key_material(&raw), Some(raw));

        let hex = b"4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";
        assert_eq!(recipient_key_material(hex), Some(raw));
        assert_eq!(
            recipient_key_material(
                b"4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C"
            ),
            Some(raw)
        );
        assert_eq!(
            recipient_key_material(
                b"4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c\n"
            ),
            Some(raw)
        );
        assert_eq!(
            recipient_key_material(
                b"4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c\r\n"
            ),
            Some(raw)
        );

        // Zu kurz, zu lang, und Hex mit einer Ziffer ausser der Reihe.
        assert_eq!(recipient_key_material(&[0x4c_u8; 31]), None);
        assert_eq!(recipient_key_material(&[0x4c_u8; 33]), None);
        assert_eq!(recipient_key_material(b""), None);
        assert_eq!(
            recipient_key_material(
                b"4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4z"
            ),
            None
        );
    }

    /// DIE ROHFORM WIRD NICHT GETRIMMT.
    ///
    /// Ein Schluessel, dessen letztes Byte `0x0a` ist, sieht wie eine Zeile mit
    /// Zeilenende aus. Wuerde vor der Laengenpruefung getrimmt, bliebe er als
    /// 31 Bytes uebrig und gaelte als ungueltig — bei jedem 256. Schluessel.
    #[test]
    fn a_raw_key_ending_in_a_newline_byte_survives() {
        let mut raw = [0x4c_u8; RECIPIENT_KEY_SIZE_V1];
        raw[RECIPIENT_KEY_SIZE_V1 - 1] = b'\n';
        assert_eq!(recipient_key_material(&raw), Some(raw));
    }
}
