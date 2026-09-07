//! Der Writer-Uebergang: Aktion 3 `writerTransition`, Aenderung 3.
//!
//! # Was hier NICHT passiert
//!
//! Dieses Modul signiert nicht, kodiert nicht selbst und prueft keine Regel
//! nach, die der Kern schon hat. Das Transitionsobjekt und seine
//! Registry-Wirkung stehen seit Stufe 1–3: die Felder
//! [`WriterTransitionFieldsV1`] (`crates/ea-format/src/etb.rs:238-247`), der
//! EINE Kodierer [`TrustPayloadV1::writer_transition`] (`etb.rs:467`), die
//! Kernpruefung `validate_writer_transition_target`
//! (`crates/ea-trust/src/registry.rs:1427` — gleiche Organisation und Kette,
//! `effective_from_sequence` gleich der des Ereignisses, alt ≠ neu, beide
//! Writer, das alte an `preTransitionSequence` und das neue an
//! `effective_from` bereichsaktiv, das alte gleich dem laufenden Writer) und
//! die Anwendung `PreviousHeadState::apply_writer_transition`
//! (`crates/ea-trust/src/resolver.rs`). Signiert wird ausschliesslich in
//! [`crate::RootCeremonyService::publish_authorized_target`]; das Ereignis
//! plant ausschliesslich [`RegistryEventFactory::plan`].
//!
//! Was dieses Modul leistet, ist der ADMINISTRATIVE Rahmen darum: aus einem
//! abgeglichenen Kettenkopf und zwei Zertifikatshashes die Felder bauen, die
//! der Kern spaeter annehmen wird — und die Aktivierung an die BYTES binden,
//! die die Zeremonie wirklich herausgegeben hat.
//!
//! # Der Ablauf
//!
//! 1. [`WriterTransitionService::prepare`]: Antrag gegen den gewaehlten Kopf
//!    pruefen, Felder bauen, Nutzlast ueber den EINEN Kodierer bilden.
//! 2. Die Wurzelzeremonie: `publish_authorized_target(intent,
//!    prepared.payload().clone(), …)` liefert die exakten Objektbytes.
//! 3. [`WriterTransitionService::activate`]: die veroeffentlichten Bytes
//!    gegen die Vorbereitung halten, das Aenderung-3-Ereignis planen.
//! 4. Ausserhalb dieser Crate: das Ereignis Wurzel-signieren, den
//!    Nachfolgekopf waehlen, und der NEUE Writer finalisiert seinen ersten
//!    Eintrag als `keyTransition` ueber `ea-writer`. `ea-admin` haelt bewusst
//!    keine `ea-writer`-Kante; deshalb liefert `activate` KEINEN Eintrag,
//!    sondern die Felder des Ereignisses.
//!
//! # Warum die Aktivierung BYTES nimmt und keinen Hash
//!
//! Dieselbe Bauart wie [`crate::device::PendingDeviceRegistration`]: Art und
//! Inhalt werden aus den exakten Bytes GELESEN und nicht danebengestellt. Ein
//! Aufrufer, der einen Objekthash tippte, koennte den Hash eines beliebigen
//! Katalogobjekts nennen — die Aenderung 3 traefe dann ein Objekt, ueber das
//! nie ein Antrag vorbereitet wurde. Der Kern wiese das an seinem
//! Kopfuebergang ab; der Admin soll es aber nicht erst dort erfahren, und er
//! soll kein Ereignis planen, von dem er weiss, dass der Kern es abweist.

use core::fmt;
use std::{fs::File, io::Read as _, path::Path};

use ea_crypto::object_hash;
use ea_format::{
    DecodedTrustPayloadV1, FormatError, ParsedArchiveObject, RegistryEventFieldsV1, TrustPayloadV1,
    WriterTransitionFieldsV1, decode_exact_object,
};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, ChainSequence, EntryHash, Hash32, ObjectHash};
use serde::Deserialize;

use crate::{
    RegistryWindow,
    registry::{RegistryActionV1, RegistryEventFactory, RegistryWorkflowError},
};

/// Ein Fehlschlag an der Grenze des Writer-Uebergangs.
///
/// # Warum das Praefix `EA-TRANSITION-` heisst
///
/// Drei naheliegende Familien sind vergeben, und zwar an etwas anderes:
///
/// `EA-WRITER-` gehoert den LOKALEN Finalisierungsfehlern von `ea-writer`
/// (`crates/ea-writer/src/error.rs`); dort entsteht in dieser Stufe auch
/// `EA-WRITER-REVOKED` — der Befund des zurueckgespielten alten Writers, der
/// nicht mehr der laufende ist. Ein Admin-Befund im selben Namensraum liesse
/// offen, WER ihn meldet: das Geraet, das schreiben will, oder die
/// Verwaltung, die den Uebergang vorbereitet.
///
/// `EA-WORKFLOW-` ist die Familie von [`RegistryWorkflowError`]
/// (`crates/ea-admin/src/registry.rs`): Auswahl, Geraetefreigabe, Widerruf,
/// initiale Policy. Ihre Arme sind Aussagen ueber die Gegenstaende jener
/// Ablaeufe; der Uebergang hat eigene Gegenstaende — den abgeglichenen
/// Kettenkopf, zwei Writer und ein veroeffentlichtes Objekt.
///
/// `EA-CEREMONY-` benennt die Schritte der Wurzelzeremonie
/// (`crates/ea-admin/src/error.rs`), und die laeuft hier unveraendert;
/// dieses Modul fuegt ihr keinen Schritt hinzu.
///
/// `EA-TRANSITION-` benennt genau diesen Gegenstand und ist im Baum sonst
/// nirgends vergeben (`grep -rhoE '"EA-[A-Z0-9-]+"' crates apps | sort -u`
/// kennt 48 Familien, diese nicht; `EA-COMMIT-WRITER-TRANSITION` und
/// `EA-DRAFT-TRANSITION-UNAVAILABLE` gehoeren zu `EA-COMMIT-` und
/// `EA-DRAFT-`).
///
/// Die durchgereichten Arme behalten den Code ihrer Herkunft: ein Fenster
/// ausserhalb des Lease bleibt `EA-OPERATOR-REGISTRY-WINDOW`, eine Nutzlast,
/// die ihre Grammatik nicht erfuellt, bleibt `EA-FORMAT-…`.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum WriterTransitionError {
    /// Der als alt benannte Writer ist am gewaehlten Kopf nicht der LAUFENDE
    /// Writer — oder der Kopf kennt noch gar keinen.
    ///
    /// Das ist der Arm, der einen bereits vollzogenen Uebergang abweist:
    /// am Nachfolgekopf ist der alte Writer widerrufen, und derselbe Antrag
    /// ist dort nicht mehr vorbereitbar.
    OldWriterNotCurrent,
    /// Der als neu benannte Writer ist an der Wirksamkeitssequenz kein
    /// FREIGEGEBENES, bereichsaktives Writer-Zertifikat.
    ///
    /// Ein Arm fuer drei Faelle, weil der Befund derselbe ist: ein
    /// Zertifikat, das der Kopf nicht kennt; eines einer anderen Art; und
    /// eines, dessen eigene `effective_from_sequence` HINTER der des
    /// Uebergangs liegt. Alle drei liest
    /// [`SelectedRegistryHead::approved_writer_certificate_fields`] als
    /// `None`, und der Kern (`validate_writer_transition_target`) wiese alle
    /// drei mit `EA-TRUST-ACTION-MISMATCH` ab.
    NewWriterNotApproved,
    /// Alter und neuer Writer sind dasselbe Zertifikat.
    SameWriter,
    /// Der abgeglichene Kopf steht an der letzten Sequenz des Zahlenraums;
    /// eine naechste gibt es nicht.
    SequenceOverflow,
    /// Die vorgelegten Bytes sind nicht das vorbereitete Transitionsobjekt.
    ///
    /// Ein Arm fuer jede Abweichung: keine Objektbytes, ein anderer Subtyp,
    /// ein `writerTransition` mit anderen Feldern — oder mit denselben
    /// Feldern unter einer ANDEREN Autorisierung. Verglichen wird die
    /// signierte Nutzlast als Ganzes, nicht eine Auswahl ihrer Felder.
    TransitionObjectMismatch,
    /// Das Fenster des Ereignisses beginnt nicht an der Wirksamkeitssequenz
    /// des Uebergangs.
    ///
    /// Der Kern verlangt Gleichheit (`fields.effective_from_sequence !=
    /// effective_from` → `EA-TRUST-ACTION-MISMATCH`); der Admin plant kein
    /// Ereignis, von dem er das schon weiss.
    WindowMismatch,
    /// Ein Befund der Registrierungsablaeufe, unveraendert durchgereicht.
    Registry(RegistryWorkflowError),
    /// Ein Befund der Formatschicht, unveraendert durchgereicht.
    Format(FormatError),
}

impl WriterTransitionError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OldWriterNotCurrent => "EA-TRANSITION-OLD-WRITER-NOT-CURRENT",
            Self::NewWriterNotApproved => "EA-TRANSITION-NEW-WRITER-NOT-APPROVED",
            Self::SameWriter => "EA-TRANSITION-SAME-WRITER",
            Self::SequenceOverflow => "EA-TRANSITION-SEQUENCE-OVERFLOW",
            Self::TransitionObjectMismatch => "EA-TRANSITION-OBJECT-MISMATCH",
            Self::WindowMismatch => "EA-TRANSITION-WINDOW-MISMATCH",
            Self::Registry(error) => error.code(),
            Self::Format(error) => error.code(),
        }
    }
}

impl fmt::Debug for WriterTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for WriterTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for WriterTransitionError {}

impl From<RegistryWorkflowError> for WriterTransitionError {
    fn from(error: RegistryWorkflowError) -> Self {
        Self::Registry(error)
    }
}

impl From<FormatError> for WriterTransitionError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

/// Der abgeglichene Kettenkopf: der letzte Eintrag des alten Writers.
///
/// # Was dieser Typ NICHT feststellt
///
/// Dass er stimmt. Der Abgleich — gegen eine Serverquittung, einen Reader
/// oder einen extern signierten Checkpoint — ist Sache des Aufrufers, und
/// zwar bewusst: `ea-admin` haelt weder eine `ea-sync-client`- noch eine
/// `ea-reader`-Kante, und ein Uebergang, der seinen eigenen Kettenkopf
/// nachsaehe, braeuchte genau die Quelle, deren Unabhaengigkeit der Abgleich
/// belegen soll. Was hier steht, wird UNVERAENDERT in die Felder des
/// Uebergangs uebernommen: `entry_hash` als `previous_entry_hash`,
/// `chain_sequence + 1` als `effective_from_sequence`. Der erste Eintrag des
/// neuen Writers muss an genau diesen Hash anschliessen.
#[derive(Clone, Copy)]
pub struct TrustedChainHead {
    /// Die Sequenz des letzten Eintrags des alten Writers. Fuer eine Kette,
    /// die noch keinen Eintrag ueber Genesis hinaus hat, ist das `0`; der
    /// neue Writer schreibt dann ab `1`.
    pub chain_sequence: ChainSequence,
    /// Der Hash dieses Eintrags.
    pub entry_hash: EntryHash,
}

/// Der Antrag auf einen Writer-Uebergang.
///
/// Organisation und Kette stehen NICHT im Antrag: sie kommen aus dem
/// gewaehlten Kopf, gegen den der Dienst handelt. Ein Antrag, der sie selbst
/// nennte, koennte vom Kopf abweichen, und der Kern wiese ihn ab.
///
/// `reason_code` ist auf dem Draht ein blosser `uint`
/// (`schemas/archive/v1/trust.cddl`), und weder Spezifikation noch Baum
/// fuehren eine Tabelle seiner Werte. Der Dienst reicht ihn durch und
/// erfindet keine — eine hier ausgedachte Tabelle waere eine Bedeutung, die
/// kein Leser des Objekts teilt.
#[derive(Clone, Copy)]
pub struct WriterTransitionRequest {
    /// Der laufende Writer, der abgibt.
    pub old_writer_certificate_hash: CertificateHash,
    /// Der freigegebene Writer, der uebernimmt.
    pub new_writer_certificate_hash: CertificateHash,
    /// Der abgeglichene Kettenkopf.
    pub trusted_head: TrustedChainHead,
    pub reason_code: u64,
}

/// Die Obergrenze einer Antragsdatei — dieselbe wie die der Bedienerdatei
/// (`operator_runtime::CONFIG_LIMIT`): vier Felder brauchen einige hundert
/// Byte, und eine irrtuemlich benannte Datei soll nicht in den Speicher
/// gelesen werden.
const REQUEST_LIMIT: usize = 65_536;

/// Die Drahtform der Antragsdatei.
///
/// Dieselbe Bauart wie `WireConfig` in [`crate::operator_runtime`]:
/// `deny_unknown_fields`, Hashes als 64 Hex-Zeichen, die hier dekodiert und
/// nicht durchgereicht werden. Ein Feld, das der Antrag nicht kennt, ist ein
/// Formfehler und keine stille Zugabe — Organisation und Kette etwa stehen
/// ausdruecklich NICHT im Antrag (siehe [`WriterTransitionRequest`]), und
/// eine Datei, die sie nennte, soll das nicht unbemerkt tun.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    old_writer_certificate_hash: String,
    new_writer_certificate_hash: String,
    trusted_head: WireTrustedHead,
    reason_code: u64,
    admin_authorization_object_hash: Option<String>,
}

/// Der Inhalt einer Antragsdatei: der Antrag und — wenn die Datei ihn
/// nennt — der Hash der erteilten Administrationsautorisierung.
///
/// # Warum der Hash NICHT im Antrag steht
///
/// [`WriterTransitionRequest`] ist das, was [`WriterTransitionService::prepare`]
/// PRUEFT; der Autorisierungshash ist das, womit es KODIERT — der zweite
/// Parameter von `prepare`, und der Dienst prueft ihn nicht (die Zeremonie
/// tut das, ueber ihren Beweiszustand). Die beiden Haelften bleiben deshalb
/// getrennt: ein Antrag ist vor der Zeremonie derselbe wie nach ihr, nur der
/// Hash kommt hinzu. Ein Aufrufer ohne Hash — die Vorbereitung VOR der
/// Zeremonie — setzt den Platzhalter `ObjectHash::from(Hash32::ZERO)` ein;
/// einer MIT Hash bildet genau die Nutzlast, die die Zeremonie signiert hat,
/// und kann die veroeffentlichten Bytes in [`WriterTransitionService::activate`]
/// dagegen halten.
#[derive(Clone, Copy)]
pub struct LoadedWriterTransitionRequest {
    /// Der Antrag, wie der Dienst ihn prueft.
    pub request: WriterTransitionRequest,
    /// Der Hash der erteilten Administrationsautorisierung, falls die Datei
    /// ihn nennt.
    pub admin_authorization_object_hash: Option<ObjectHash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrustedHead {
    chain_sequence: u64,
    entry_hash: String,
}

/// Ein Fehlschlag beim Lesen der Antragsdatei.
///
/// Ein eigener Typ neben [`WriterTransitionError`] und nicht zwei Arme darin:
/// jener Typ traegt Befunde ueber den UEBERGANG — Kopf, Writer, Objekt —, und
/// die entstehen erst, wenn ein Antrag vorliegt. Eine Datei, die keinen
/// Antrag ergibt, ist ein Befund ueber die EINGABE; `prepare` hat sie nie
/// gesehen. Die Familie bleibt `EA-TRANSITION-`, weil der Gegenstand derselbe
/// ist; das Segment `REQUEST` benennt die Stufe.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum WriterTransitionRequestError {
    /// Die Datei ist nicht zu oeffnen, nicht zu lesen oder groesser als die
    /// Obergrenze. Kein Byte ihres Inhalts wurde gedeutet.
    Unreadable,
    /// Die Datei ist lesbar, aber kein Antrag: kein JSON, ein fehlendes oder
    /// unbekanntes Feld, ein Hash, der keine 64 Hex-Zeichen ist.
    Shape,
}

impl WriterTransitionRequestError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unreadable => "EA-TRANSITION-REQUEST-UNREADABLE",
            Self::Shape => "EA-TRANSITION-REQUEST-SHAPE",
        }
    }
}

impl fmt::Debug for WriterTransitionRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for WriterTransitionRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for WriterTransitionRequestError {}

impl WriterTransitionRequest {
    /// Liest den Antrag aus `bytes`, der Drahtform einer Antragsdatei.
    ///
    /// ```json
    /// {
    ///   "old_writer_certificate_hash": "<64 hex>",
    ///   "new_writer_certificate_hash": "<64 hex>",
    ///   "trusted_head": { "chain_sequence": 41, "entry_hash": "<64 hex>" },
    ///   "reason_code": 1,
    ///   "admin_authorization_object_hash": "<64 hex>"
    /// }
    /// ```
    ///
    /// Das letzte Feld ist optional: vor der Zeremonie gibt es den Hash noch
    /// nicht (siehe [`LoadedWriterTransitionRequest`]).
    ///
    /// # Errors
    ///
    /// [`WriterTransitionRequestError::Unreadable`] ueber der Obergrenze,
    /// [`WriterTransitionRequestError::Shape`] fuer jede Abweichung von der
    /// Drahtform.
    pub fn from_json(
        bytes: &[u8],
    ) -> Result<LoadedWriterTransitionRequest, WriterTransitionRequestError> {
        if bytes.len() > REQUEST_LIMIT {
            return Err(WriterTransitionRequestError::Unreadable);
        }
        let wire: WireRequest =
            serde_json::from_slice(bytes).map_err(|_| WriterTransitionRequestError::Shape)?;
        Ok(LoadedWriterTransitionRequest {
            request: Self {
                old_writer_certificate_hash: CertificateHash::from(ObjectHash::from(parse_hash(
                    &wire.old_writer_certificate_hash,
                )?)),
                new_writer_certificate_hash: CertificateHash::from(ObjectHash::from(parse_hash(
                    &wire.new_writer_certificate_hash,
                )?)),
                trusted_head: TrustedChainHead {
                    chain_sequence: ChainSequence::new(wire.trusted_head.chain_sequence),
                    entry_hash: EntryHash::from(parse_hash(&wire.trusted_head.entry_hash)?),
                },
                reason_code: wire.reason_code,
            },
            admin_authorization_object_hash: wire
                .admin_authorization_object_hash
                .as_deref()
                .map(parse_hash)
                .transpose()?
                .map(ObjectHash::from),
        })
    }

    /// Liest den Antrag aus der Datei an `path`.
    ///
    /// Begrenzt wie [`crate::operator_runtime::OperatorRuntimeConfig::load`]:
    /// es wird hoechstens ein Byte ueber der Obergrenze gelesen, und dieses
    /// eine Byte macht die Datei unlesbar.
    ///
    /// # Errors
    ///
    /// [`WriterTransitionRequestError::Unreadable`], wenn die Datei nicht zu
    /// oeffnen oder zu lesen ist; sonst wie [`Self::from_json`].
    pub fn load(
        path: &Path,
    ) -> Result<LoadedWriterTransitionRequest, WriterTransitionRequestError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| WriterTransitionRequestError::Unreadable)?
            .take(REQUEST_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WriterTransitionRequestError::Unreadable)?;
        Self::from_json(&bytes)
    }
}

/// Genau die Dekodierung von `operator_runtime::parse_hash`: 64 Zeichen,
/// Hex, 32 Byte. Jene Funktion ist privat und traegt den Fehlertyp der
/// Laufzeit; hier steht dieselbe Regel mit dem Fehlertyp des Antrags.
fn parse_hash(value: &str) -> Result<Hash32, WriterTransitionRequestError> {
    if value.len() != 64 {
        return Err(WriterTransitionRequestError::Shape);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| WriterTransitionRequestError::Shape)?;
    Hash32::try_from(bytes.as_slice()).map_err(|_| WriterTransitionRequestError::Shape)
}

/// Ein vorbereiteter Uebergang: die Felder und die Nutzlast, die die
/// Zeremonie unterschreiben soll.
///
/// Ohne oeffentliche Felder und ohne oeffentlichen Konstruktor: der Wert
/// entsteht ausschliesslich in [`WriterTransitionService::prepare`], und dort
/// ist jede Abweichung vom Kopf ein Fehlerarm. Dieselbe Bauart wie
/// [`crate::revocation::ClassifiedRevocationTarget`] — ein Zustand, den nur
/// die Pruefung erreicht. Insbesondere ist damit gebunden, dass
/// `new_writer_certificate_hash` ein Writer-Zertifikat ist:
/// [`SelectedRegistryHead::approved_writer_certificate_fields`] antwortet
/// fuer jede andere Art `None`, und `prepare` macht daraus
/// [`WriterTransitionError::NewWriterNotApproved`].
///
/// ```compile_fail,E0451
/// use ea_admin::writer_transition::PreparedWriterTransition;
/// use ea_format::{TrustPayloadV1, WriterTransitionFieldsV1};
///
/// fn forge(fields: WriterTransitionFieldsV1, payload: TrustPayloadV1) -> PreparedWriterTransition {
///     PreparedWriterTransition { fields, payload }
/// }
/// ```
///
/// Der positive Gegenzeuge, damit der obige an seinem Gegenstand scheitert
/// und nicht an seinen Importen:
///
/// ```
/// use ea_admin::writer_transition::WriterTransitionError;
///
/// assert_eq!(
///     WriterTransitionError::OldWriterNotCurrent.code(),
///     "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
/// );
/// let _ = ea_admin::writer_transition::WriterTransitionService::prepare;
/// let _ = ea_admin::writer_transition::WriterTransitionService::activate;
/// let _ = ea_format::TrustPayloadV1::writer_transition;
/// ```
#[derive(Clone)]
pub struct PreparedWriterTransition {
    fields: WriterTransitionFieldsV1,
    payload: TrustPayloadV1,
}

impl PreparedWriterTransition {
    /// Die Felder, die der Kern spaeter gegen das Ereignis haelt.
    #[must_use]
    pub const fn fields(&self) -> &WriterTransitionFieldsV1 {
        &self.fields
    }

    /// Die Nutzlast fuer [`crate::RootCeremonyService::publish_authorized_target`].
    ///
    /// Sie traegt bereits den Hash der Administrationsautorisierung; der
    /// Beweiszustand der Zeremonie wird ueber GENAU diese Nutzlast gefuehrt
    /// (`ea_trust::verify_intended_trust_target`).
    #[must_use]
    pub const fn payload(&self) -> &TrustPayloadV1 {
        &self.payload
    }

    /// Die erste Sequenz des neuen Writers — die Sequenz, an der das
    /// Aenderung-3-Ereignis beginnen MUSS.
    #[must_use]
    pub const fn effective_from_sequence(&self) -> ChainSequence {
        self.fields.effective_from_sequence
    }
}

/// Ein aktivierter Uebergang: das geplante Aenderung-3-Ereignis und der
/// Objekthash der veroeffentlichten Bytes, die es nennt.
///
/// Ohne oeffentliche Felder und ohne oeffentlichen Konstruktor, aus demselben
/// Grund wie [`PreparedWriterTransition`]: der Wert belegt, dass die
/// Aktivierung gegen die veroeffentlichten Bytes gehalten wurde.
///
/// ```compile_fail,E0451
/// use ea_admin::writer_transition::ActivatedWriterTransition;
/// use ea_format::RegistryEventFieldsV1;
/// use ea_types::ObjectHash;
///
/// fn forge(event: RegistryEventFieldsV1, hash: ObjectHash) -> ActivatedWriterTransition {
///     ActivatedWriterTransition { event, transition_object_hash: hash }
/// }
/// ```
#[derive(Clone)]
pub struct ActivatedWriterTransition {
    event: RegistryEventFieldsV1,
    transition_object_hash: ObjectHash,
}

impl ActivatedWriterTransition {
    /// Die Felder des Aenderung-3-Ereignisses, geplant ueber
    /// [`RegistryEventFactory::plan`]: Version `+1` auf den gepruefte
    /// Vorgaengerkopf, gebunden an dessen Hash, mit dessen Policy.
    #[must_use]
    pub const fn event(&self) -> &RegistryEventFieldsV1 {
        &self.event
    }

    /// Der Objekthash des veroeffentlichten Transitionsobjekts — derselbe,
    /// den das Ereignis in seiner Aenderung nennt und den das Manifest des
    /// ersten neuen Eintrags als `writer_transition_event_hash` tragen wird.
    #[must_use]
    pub const fn transition_object_hash(&self) -> ObjectHash {
        self.transition_object_hash
    }
}

/// Der Dienst des Writer-Uebergangs ueber genau einem gewaehlten Kopf.
///
/// Er wird JE KOPFAUSWAHL gebaut, wie [`crate::RootCeremonyService`]: der
/// laufende Writer, die freigegebenen Zertifikate, Organisation und Kette
/// sind Aussagen UEBER DIESEN Kopf. Ein Dienst, der ueber zwei Kopfauswahlen
/// hinweg lebte, fuehrte zwei Wahrheiten darueber, wer gerade schreibt.
pub struct WriterTransitionService<'a> {
    head: &'a SelectedRegistryHead,
}

impl<'a> WriterTransitionService<'a> {
    #[must_use]
    pub const fn new(head: &'a SelectedRegistryHead) -> Self {
        Self { head }
    }

    /// Der Kopf, gegen den dieser Dienst handelt.
    #[must_use]
    pub const fn head(&self) -> &SelectedRegistryHead {
        self.head
    }

    /// Prueft den Antrag gegen den gewaehlten Kopf und baut die Nutzlast.
    ///
    /// # Die Reihenfolge
    ///
    /// 1. Der alte Writer ist der LAUFENDE Writer des Kopfes
    ///    ([`SelectedRegistryHead::current_writer_certificate_hash`]). Nicht
    ///    `active_certificate_fields`: das liesse auch ein Zertifikat durch,
    ///    das aktiv, aber kein Writer ist — und der Kern verlangt den
    ///    laufenden Writer, nicht irgendeinen aktiven.
    /// 2. Alt ≠ neu.
    /// 3. `effective_from_sequence = trusted_head.chain_sequence + 1`, mit
    ///    Ueberlaufpruefung. Der Genesis-Fall — Kettenkopf an Sequenz `0` —
    ///    ergibt `1`.
    /// 4. Der neue Writer ist an `effective_from_sequence` ein freigegebenes,
    ///    bereichsaktives Writer-Zertifikat
    ///    ([`SelectedRegistryHead::approved_writer_certificate_fields`]).
    ///    `active_certificate_fields` taugt hier nicht: es verbirgt jedes
    ///    Writer-Zertifikat, das nicht der laufende Writer ist — also genau
    ///    das neue.
    /// 5. Die Felder, und die Nutzlast ueber den EINEN Kodierer
    ///    [`TrustPayloadV1::writer_transition`] mit dem Hash der
    ///    Administrationsautorisierung. Formfehler behalten ihren
    ///    `EA-FORMAT-`-Code.
    ///
    /// Organisation und Kette kommen aus dem Kopf: die Kette aus
    /// [`SelectedRegistryHead::chain_id`], die Organisation aus der
    /// Wurzelurkunde des Kopfes — dieselbe Quelle, aus der
    /// `OperatorBindingService::registry_event` sie fuer das Ereignis liest,
    /// damit Ziel und Ereignis nicht auseinanderlaufen koennen.
    ///
    /// # Was diese Pruefung NICHT ist
    ///
    /// Keine Fensterpruefung. Ob `effective_from_sequence` im Lease des
    /// Kopfes oder an seiner naechsten Grenze liegt, entscheidet allein die
    /// Ereignisfabrik in [`Self::activate`]; eine zweite Rechnung hier waere
    /// die zweite Uhr, die `crates/ea-admin/src/registry.rs` verbietet.
    ///
    /// # Errors
    ///
    /// [`WriterTransitionError::OldWriterNotCurrent`],
    /// [`WriterTransitionError::SameWriter`],
    /// [`WriterTransitionError::SequenceOverflow`],
    /// [`WriterTransitionError::NewWriterNotApproved`] in dieser Reihenfolge;
    /// [`WriterTransitionError::Format`] fuer die Kodierung.
    pub fn prepare(
        &self,
        request: &WriterTransitionRequest,
        admin_authorization_object_hash: ObjectHash,
    ) -> Result<PreparedWriterTransition, WriterTransitionError> {
        // 1.
        if self.head.current_writer_certificate_hash() != Some(request.old_writer_certificate_hash)
        {
            return Err(WriterTransitionError::OldWriterNotCurrent);
        }
        // 2.
        if request.old_writer_certificate_hash == request.new_writer_certificate_hash {
            return Err(WriterTransitionError::SameWriter);
        }
        // 3.
        let effective_from_sequence = ChainSequence::new(
            request
                .trusted_head
                .chain_sequence
                .get()
                .checked_add(1)
                .ok_or(WriterTransitionError::SequenceOverflow)?,
        );
        // 4.
        if self
            .head
            .approved_writer_certificate_fields(
                request.new_writer_certificate_hash,
                effective_from_sequence,
            )
            .is_none()
        {
            return Err(WriterTransitionError::NewWriterNotApproved);
        }
        // 5.
        let fields = WriterTransitionFieldsV1 {
            organization_id: self.head.root_certificate_fields().organization_id,
            chain_id: self.head.chain_id(),
            old_writer_certificate_hash: request.old_writer_certificate_hash,
            new_writer_certificate_hash: request.new_writer_certificate_hash,
            effective_from_sequence,
            previous_entry_hash: request.trusted_head.entry_hash,
            reason_code: request.reason_code,
        };
        let payload =
            TrustPayloadV1::writer_transition(fields.clone(), admin_authorization_object_hash)?;
        Ok(PreparedWriterTransition { fields, payload })
    }

    /// Haelt die veroeffentlichten Bytes gegen die Vorbereitung und plant das
    /// Aenderung-3-Ereignis.
    ///
    /// # Die Reihenfolge
    ///
    /// 1. Die Bytes sind ein Trust-Objekt, dessen Nutzlast als
    ///    `writerTransition` dekodiert — gelesen ueber
    ///    [`ea_format::decode_exact_object`] und die Trust-Sicht, nicht
    ///    ueber einen mitgefuehrten Subtyp.
    /// 2. Die signierte Nutzlast ist GENAU die vorbereitete: Subtyp, Felder
    ///    und Autorisierungshash. Verglichen wird der exakte Digest-Eingang
    ///    — das, was die Wurzel unterschrieben hat —, nicht eine Auswahl
    ///    von Feldern. Ein `writerTransition` mit denselben Feldern unter
    ///    einer anderen Autorisierung ist ein anderes Objekt.
    /// 3. Das Fenster beginnt an `effective_from_sequence`. Der Kern
    ///    verlangt es ohnehin; der Admin plant kein Ereignis, das er abweisen
    ///    sieht.
    /// 4. Das Ereignis ueber [`RegistryEventFactory::plan`] mit
    ///    [`RegistryActionV1::WriterTransition`] — Aktionscode 3, Aenderung
    ///    3, Objekthash der exakten Bytes. Fenster, Version und Vorgaenger
    ///    kommen von dort und nirgends sonst.
    ///
    /// # Errors
    ///
    /// [`WriterTransitionError::TransitionObjectMismatch`] fuer jede
    /// Abweichung der Bytes von der Vorbereitung — auch fuer Bytes, die kein
    /// Trust-Objekt sind: der Befund „nicht das vorbereitete Objekt" gilt
    /// fuer sie genauso, und ihr Formfehler hat fuer den Aufrufer keinen
    /// eigenen Wert; [`WriterTransitionError::WindowMismatch`] fuer ein
    /// Fenster, das nicht an der Wirksamkeitssequenz beginnt;
    /// [`WriterTransitionError::Registry`] mit dem Code der Ereignisfabrik,
    /// insbesondere `EA-OPERATOR-REGISTRY-WINDOW`.
    pub fn activate(
        &self,
        prepared: &PreparedWriterTransition,
        exact_transition_object: &[u8],
        events: &RegistryEventFactory<'_>,
        window: RegistryWindow,
    ) -> Result<ActivatedWriterTransition, WriterTransitionError> {
        // 1.
        let Ok(ParsedArchiveObject::Trust(parsed)) = decode_exact_object(exact_transition_object)
        else {
            return Err(WriterTransitionError::TransitionObjectMismatch);
        };
        let object = parsed.value();
        let Ok(DecodedTrustPayloadV1::WriterTransition(core)) = object.decoded_payload() else {
            return Err(WriterTransitionError::TransitionObjectMismatch);
        };
        // 2. Der Feldvergleich ist im Digest-Vergleich enthalten; er steht
        //    trotzdem hier, damit die Zusage lesbar bleibt: DIESE Felder,
        //    DIESE Autorisierung.
        if core.fields() != prepared.fields()
            || object.exact_digest_input() != prepared.payload().exact_digest_input()
        {
            return Err(WriterTransitionError::TransitionObjectMismatch);
        }
        // 3.
        if window.effective_from_sequence != prepared.effective_from_sequence() {
            return Err(WriterTransitionError::WindowMismatch);
        }
        // 4.
        let transition_object_hash = object_hash(exact_transition_object);
        let event = events.plan(
            window,
            &RegistryActionV1::WriterTransition {
                transition_object_hash,
            },
        )?;
        Ok(ActivatedWriterTransition {
            event,
            transition_object_hash,
        })
    }
}
