//! Gate `recipient-grant` und die Entkapselung, die KEIN Gate ist.
//!
//! `design.md` §14.1 Schritt 9 (:1583): „eigenen Grant, dessen
//! Aussteller-Capability, Authorization, Nutzungsfrist gemaess `effectiveNow`
//! und `entryHash`". Danach — und ausdruecklich nicht als zehntes Gate — folgt
//! `hpke-open`.
//!
//! # Drei Zustaende, die nie zusammenfallen duerfen
//!
//! `design.md`:1595 haelt sie auseinander, und dieses Modul auch:
//!
//! - FEHLENDER GRANT: es gibt keinen Grant auf den eigenen Abdruck. Der
//!   Eintrag bleibt `valid` und in der Kettenansicht sichtbar, er wird nicht
//!   entschluesselt, und es entsteht KEIN Befund — weder ein
//!   `decryptionErrors`-Eintrag noch eine Kettenluecke.
//! - UNBEKANNTER SCHLUESSEL: der Grant ist da, aber das Material des Aufrufers
//!   oeffnet ihn nicht. Das ist ein `decryptionErrors`-Eintrag.
//! - KEIN SCHLUESSEL: der Aufrufer hat gar keinen hinterlegt. Dann wird nichts
//!   versucht, nichts protokolliert und nichts abgewertet.
//!
//! # Was der Aussteller angeht, prueft `ea-crypto` bereits vollstaendig
//!
//! [`ea_crypto::VerificationContext::initial_grant`] bindet Digest,
//! Zertifikatshash, Ausstellerabdruck, Rolle `Writer`, die Capability
//! `initialGrant` und die Registrierungsbindung des Grantrumpfes in EINEN
//! Kontext; [`ea_crypto::verify_cose_sign1`] loest das Zertifikat dann gegen
//! den fuer die Eintragssequenz GEWAEHLTEN Kopf auf und prueft Aktivitaet,
//! Widerruf und Signatur (`crates/ea-crypto/src/cose.rs:1423-1459`). Die
//! Capability wird hier deshalb nicht ein zweites Mal von Hand aus
//! `SelectedRegistryHead::active_capabilities` gelesen — eine zweite Fassung
//! derselben Regel waere eine zweite Gelegenheit, sie falsch zu schreiben.
//!
//! Die NUTZUNGSFRIST steckt in genau diesem Kopf: `select_registry_head` gibt
//! einen Kopf nur heraus, solange `effectiveNow` innerhalb seines
//! `not-before`/`not-after` liegt (`crates/ea-trust/src/registry.rs:556-600`).
//! Ein Grant ist damit exakt so lange benutzbar, wie die Registrierung, auf
//! die er sich beruft, Autoritaet traegt.

use core::fmt;

use ea_archive::ArchiveInventory;
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, HpkeSealed, SecretBytes, VerificationContext, aead_open, hpke_aad,
    hpke_info, hpke_open, payload_aad, verify_cose_sign1,
};
use ea_format::{EntryPackageV1, GrantKindV1, GrantV1, Parsed};
use ea_trust::SelectedRegistryHead;
use ea_types::KeyThumbprint;

use crate::{Decapsulation, ObjectErrorV1, RecipientKeyV1, VerificationReportV1};

/// Der Befund von Gate `recipient-grant` ueber GENAU EIN Objekt.
///
/// EIGENE FAMILIE wie bei den uebrigen Gates: der Code benennt das GATE. Die
/// Befunde tragen den Objekthash des GRANTS und nie den des Eintrags — der
/// Eintrag ist gueltig, es ist der Grant, der nicht traegt, und ein Objekt
/// erscheint in genau einem Feld des Berichts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecipientGrantErrorV1 {
    /// Der Aussteller des Grants liess sich nicht nachweisen.
    ///
    /// Deckt jede Bedingung ab, die
    /// [`ea_crypto::VerificationContext::initial_grant`] beziehungsweise
    /// `historical_grant` in den Kontext bindet: Digest, Zertifikatshash,
    /// Ausstellerabdruck, Rolle, Capability, Registrierungsbindung,
    /// Aktivitaet zur Eintragssequenz und die Signatur selbst.
    IssuerUnverifiable,
    /// Fuer die Eintragssequenz liess sich gar kein Kopf mehr gewinnen.
    ///
    /// Ohne Registrierungsautoritaet ist ueber die Capability des Ausstellers
    /// nichts zu sagen — die konservative Antwort, kein Freispruch.
    HeadUnavailable,
    /// Der Grant beruft sich auf eine Authorization, die dieser Lauf nicht
    /// aufloesen kann.
    ///
    /// FAIL-CLOSED UND AUSDRUECKLICH KEINE PRUEFUNG, dieselbe Lage wie bei
    /// `crate::entry::claims_unverifiable_writer_transition`: ein historischer
    /// Grant MUSS nach `design.md`:772 eine Authorization tragen, die Eintrag
    /// und Empfaenger exakt abdeckt, und diese Aufloesung ist von `ea-verify`
    /// aus nicht erreichbar — `ea-trust` exportiert dafuer keine Pruefung und
    /// haelt seinen Katalog `pub(crate)`. Ein solcher Grant wird deshalb NICHT
    /// benutzt, und es wird nichts mit ihm geoeffnet.
    AuthorizationUnverifiable,
}

impl RecipientGrantErrorV1 {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::IssuerUnverifiable => "EA-VERIFY-GRANT-ISSUER-UNVERIFIABLE",
            Self::HeadUnavailable => "EA-VERIFY-GRANT-HEAD-UNAVAILABLE",
            Self::AuthorizationUnverifiable => "EA-VERIFY-GRANT-AUTHORIZATION-UNVERIFIABLE",
        }
    }
}

impl fmt::Display for RecipientGrantErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Der Befund der Entkapselung ueber GENAU EIN Objekt.
///
/// KEIN Gate-Befund: die Entkapselung entscheidet nichts ueber die
/// Verifikation. Sie kann aber scheitern, und dann MUSS das sichtbar sein —
/// sonst saehe ein Bestand, den niemand oeffnen kann, aus wie einer, den jeder
/// oeffnen kann.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DecryptionErrorV1 {
    /// Der umschlossene CEK liess sich mit diesem Schluessel nicht oeffnen.
    ///
    /// Der Zustand UNBEKANNTER SCHLUESSEL aus `design.md`:1595: der Grant
    /// nennt den eigenen Abdruck, das vorgelegte Material passt aber nicht zu
    /// ihm.
    CekUnwrapFailed,
    /// Der CEK war da, der Ciphertext liess sich damit trotzdem nicht oeffnen.
    ///
    /// Erreicht nur, wenn AAD, `nonce` oder Ciphertext nicht zusammenpassen —
    /// und der Ciphertexthash steht im signierten Manifest, ist also bereits
    /// an Gate `manifest-signature` gebunden. Bleibt trotzdem behandelt: eine
    /// Entschluesselung, die nicht gelingt, darf nie als gelungen gelten.
    PayloadOpenFailed,
}

impl DecryptionErrorV1 {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CekUnwrapFailed => "EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED",
            Self::PayloadOpenFailed => "EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED",
        }
    }
}

impl fmt::Display for DecryptionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Der eigene INITIALE Grant auf `entry`, sofern der Bestand einen enthaelt.
///
/// DREI BINDUNGEN, UND SIE SIND ABGELEITET, NICHT ZITIERT. `design.md` §14.1
/// Schritt 9 (`:1595`) nennt vier Verpflichtungen ausdruecklich — die
/// Aussteller-Capability, die Authorization, die Nutzungsfrist gegen
/// `effectiveNow` und den `entryHash` — und eine fuenfte steckt im Wort
/// „eigenen": den eigenen Schluesselabdruck. DIESE Stelle traegt davon die
/// AUSWAHL, und das sind zwei: der `entryHash` — nicht der Objekthash, denn
/// der Grant bezieht sich auf den EINTRAG — und der eigene
/// Schluesselabdruck. Ein Grant auf einen anderen Empfaenger ist nicht der
/// eigene, und sein Fehlen ist der Zustand FEHLENDER GRANT. Ueber die
/// Aussteller-Capability entscheidet [`verify_own_grant`] durch den Kontext,
/// den es waehlt; Authorization und Nutzungsfrist gehoeren zu den historischen
/// Grants und bleiben mit ihnen Stufe 5 (FR-145).
///
/// # Die dritte Bindung ist die Art, und ohne sie waere dieser Lauf angreifbar
///
/// [`GrantKindV1::Initial`], nach genau demselben Praedikat, mit dem
/// `crates/ea-verify/src/entry.rs:118` den initialen Plan bildet und
/// `crates/ea-recovery/src/decrypt.rs:321` den Entschluesselungsplan. Auch sie
/// ist keine Ergaenzung zur Norm, sondern deren Voraussetzung: die Capability
/// aus Schritt 9 ist nach `design.md`:782 eine Funktion der ART, und wer die
/// Art nicht kennt, kann Schritt 9 nicht ausfuehren. Vorher
/// filterte diese Stelle allein nicht — und `grants()` entsteht aus einer
/// `BTreeMap` ueber dem OBJEKTHASH
/// (`crates/ea-archive/src/inventory.rs:600`), `find` liefert also den
/// KLEINSTEN passenden Hash.
///
/// Ein untergeschobener historischer Grant mit kleinerem Objekthash verdraengte
/// damit den echten initialen: [`verify_own_grant`] kehrte fuer ihn mit
/// [`RecipientGrantErrorV1::AuthorizationUnverifiable`] um, und weil das VOR
/// [`verify_cose_sign1`] geschieht, wurde seine Ausstellersignatur dabei nie
/// geprueft — der Rumpf ist ohne jedes Schluesselmaterial herstellbar
/// (`crates/ea-format/src/eag.rs:324-337` bindet nur Digest und Abdruecke an
/// sich selbst, und der Signaturbeweis aus
/// `crates/ea-crypto/src/cose.rs:653-669` laeuft auf diesem Pfad nie). Ein
/// einziges gefaelschtes `.eag` machte so jeden Eintrag fuer den benannten
/// Empfaenger unentschluesselbar, waehrend `verify` ohne Schluessel weiter
/// stumm blieb und Gate `grant-plan` es nie zu sehen bekam.
///
/// EIN OBJEKT, DESSEN SIGNATUR NIE GEPRUEFT WURDE, TRAEGT KEINEN BEFUND —
/// dieselbe Regel, nach der `crates/ea-verify/src/archive.rs:570` ein
/// isoliertes Grant uebergeht. Ein historischer Grant ist fuer diesen Lauf
/// deshalb so gut wie keiner: der Eintrag bleibt gueltig und sichtbar, er wird
/// nur nicht geoeffnet.
///
/// GEMESSEN, und nicht bloss behauptet, in
/// `crates/ea-verify/tests/evidence_recipient_grant.rs`,
/// `a_forged_historical_grant_with_a_smaller_object_hash_does_not_displace_the_own_grant`:
/// ohne dieses Praedikat traegt der Bericht dort einen
/// `signatureErrors`-Eintrag ueber die Faelschung.
pub(crate) fn own_grant<'a>(
    inventory: &'a ArchiveInventory,
    entry: &Parsed<EntryPackageV1>,
    key_thumbprint: KeyThumbprint,
) -> Option<&'a Parsed<GrantV1>> {
    let entry_hash = entry.value().entry_hash();
    inventory.grants().iter().find(|grant| {
        let fields = grant.value().grant_body().fields();
        fields.kind == GrantKindV1::Initial
            && fields.entry_hash == entry_hash
            && fields.recipient_key_thumbprint == key_thumbprint
    })
}

/// Prueft den eigenen Grant gegen den gewaehlten Kopf.
///
/// Liefert bei Erfolg den Schluesselabdruck des AUSSTELLERS — er hat eine
/// Signaturpruefung dieses Laufs getragen und gehoert damit in
/// `publicKeyThumbprints`.
pub(crate) fn verify_own_grant(
    grant: &Parsed<GrantV1>,
    entry: &Parsed<EntryPackageV1>,
    selected: &SelectedRegistryHead,
) -> Result<KeyThumbprint, RecipientGrantErrorV1> {
    let sequence = entry.value().manifest().fields().chain_sequence;
    let body = grant.value().grant_body();
    let context = match grant.value().kind() {
        GrantKindV1::Initial => VerificationContext::initial_grant(body.exact_bytes(), sequence),
        // UNERREICHBAR DURCH KONSTRUKTION: [`own_grant`] gibt nur initiale
        // Grants heraus, und das ist der einzige Weg hierher
        // (`crates/ea-verify/src/archive.rs:561`). Der Zweig bleibt als
        // Absicherung stehen — `VerificationContext::initial_grant` gilt
        // ausschliesslich fuer die initiale Art, und ein historischer Grant
        // traegt eine Authorization, die Suite v1 nicht aufloest. Er darf
        // deshalb nie in diesen Kontext geraten, auch nicht, wenn ein
        // spaeterer Aufrufer die Auswahl umgeht.
        GrantKindV1::Historical => {
            return Err(RecipientGrantErrorV1::AuthorizationUnverifiable);
        }
    }
    .map_err(|_| RecipientGrantErrorV1::IssuerUnverifiable)?;
    let signer = verify_cose_sign1(grant.value().issuer_signature(), selected, &context)
        .map_err(|_| RecipientGrantErrorV1::IssuerUnverifiable)?;
    Ok(signer.key_thumbprint())
}

/// Entkapselt den CEK und oeffnet den Ciphertext des Eintrags.
///
/// DER KLARTEXT VERLAESST DIESE FUNKTION NIE. `design.md` §14 haelt fest, dass
/// entschluesselte Inhalte nicht in Berichte, Zwischenablagen oder temporaere
/// Dateien gehoeren; hier wird der Erfolg deshalb als blosses
/// [`Decapsulation::Performed`] gemeldet und der [`ea_crypto::SecretVec`] beim
/// Verlassen des Rahmens ueberschrieben.
pub(crate) fn open_entry(
    grant: &Parsed<GrantV1>,
    entry: &Parsed<EntryPackageV1>,
    recipient: RecipientKeyV1<'_>,
) -> Result<(), DecryptionErrorV1> {
    let body = grant.value().grant_body();
    let context = body
        .exact_grant_context()
        .ok_or(DecryptionErrorV1::CekUnwrapFailed)?;
    let fields = body.fields();
    let sealed = HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)
        .map_err(|_| DecryptionErrorV1::CekUnwrapFailed)?;
    let cek = hpke_open(
        recipient.private_key(),
        &sealed,
        &hpke_info(context),
        &hpke_aad(context),
    )
    .map_err(|_| DecryptionErrorV1::CekUnwrapFailed)?;
    let cek: SecretBytes<CEK_SIZE> = cek;
    let manifest = entry.value().manifest();
    let nonce: SecretBytes<AEAD_NONCE_SIZE> = SecretBytes::new(manifest.fields().nonce);
    let plaintext = aead_open(
        &cek,
        &nonce,
        entry.value().ciphertext(),
        &payload_aad(manifest.exact_bytes()),
    )
    .map_err(|_| DecryptionErrorV1::PayloadOpenFailed)?;
    drop(plaintext);
    Ok(())
}

/// Traegt den Ausgang der Entkapselung in den Bericht ein.
///
/// Erfolg aendert am Bericht NICHTS: der Klartext gehoert nie hinein, und die
/// Entkapselung entscheidet nichts. Nur ein Fehlschlag ist sichtbar.
pub(crate) fn record_decapsulation(
    report: &mut VerificationReportV1,
    grant: &Parsed<GrantV1>,
    outcome: Result<(), DecryptionErrorV1>,
) -> Decapsulation {
    match outcome {
        Ok(()) => Decapsulation::Performed,
        Err(error) => {
            report
                .decryption_errors
                .insert(ObjectErrorV1::new(grant.object_hash(), error.code()));
            Decapsulation::Skipped
        }
    }
}
