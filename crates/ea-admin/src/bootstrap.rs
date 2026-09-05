//! Der Zwoelfschrittablauf der Ersteinrichtung (`§12.1`).
//!
//! Die Spezifikation zaehlt den gefuehrten Prozess in zwoelf Nummern ab
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1336-1347`).
//! [`BootstrapStep`] traegt genau diese zwoelf und keine dreizehnte; jede
//! Variante nennt ihre Zeile.
//!
//! # Was dieser Koordinator ZUSICHERT
//!
//! 1. **Vorwaerts, persistent, wiederaufnehmbar.** Der Zustand liegt hinter
//!    [`BootstrapStore`]. Ein Neustart nimmt denselben Schritt wieder auf;
//!    ein Schritt HINTER dem persistierten wird abgewiesen
//!    ([`AdminError::BootstrapStepRegression`]), ein Schritt VOR dem naechsten
//!    ebenso ([`AdminError::BootstrapStepOutOfOrder`]).
//! 2. **Die Versiegelung aus Schritt 4.** Sobald
//!    [`crate::confirm_on_media`] eine [`crate::MediaConfirmation`] ueber die
//!    Vorstufe ausgestellt hat, ist sie eingefroren. Jede spaetere Abweichung
//!    in einem ihrer Felder endet mit `EA-ANCHOR-PRE-FIELD-CHANGED`, und das
//!    einzige Heilmittel ist [`BootstrapCoordinator::restart_with_new_ids`] —
//!    „Jede Aenderung eines bereits in Schritt 4 festgeschriebenen Feldes
//!    bricht das Setup ab und beginnt mit neuen Organisations-/Ketten-IDs"
//!    (`:1349`).
//! 3. **Nur oeffentlicher Zeremoniezustand.** [`BootstrapStateV1`] traegt
//!    Kennungen, Objekthashes, oeffentliche COSE-Schluessel, Abdruecke, die
//!    exakten Ankerbytes und OPAKE [`KeyHandle`]-Griffe. Ein Griff ist eine
//!    Adresse, kein Zugriff (`crates/ea-key-provider/src/contract.rs:137-146`).
//!    Kein privater Schluessel, kein Startwert, kein Geheimnis hat hier ein
//!    Feld — es gibt schlicht keines, in das eines passte.
//! 4. **Kein Weg in den Produktivzustand ausser Schritt 12.** Siehe
//!    [`crate::production_state`].
//!
//! # Was dieser Koordinator DELEGIERT — die Grenze dieser Scheibe
//!
//! Ausdruecklich und ohne Ersatzhandlung:
//!
//! - **Die aeusseren Schluessel** (Wurzel, Recovery-KEM, Historical Grant
//!   Authority, Approver). `ea_key_provider::SecretPurpose` kennt genau vier
//!   LOKALE Zwecke eines Writer-Geraets, und ein Wurzelzweck fehlt dort
//!   ausdruecklich (`contract.rs:32-51`, `:340-350`). Wie schon
//!   [`crate::RootCeremonyService::new`] nimmt der Koordinator die GRIFFE und
//!   das OEFFENTLICHE Material vom Wirt entgegen. Er erzeugt sie nicht und
//!   taeuscht sie nicht vor.
//! - **Die Writer-Finalisierung** und damit der `genesisEntryHash` — sie lebt
//!   in `ea-writer`. Siehe [`crate::genesis`].
//! - **Der Frischrechner-Recovery-Testlauf** selbst — er lebt in
//!   `ea-recovery` und auf einem anderen Rechner. Hierher kommt seine
//!   BEOBACHTUNG ([`crate::RecoveryTestObservation`]), und das Urteil darueber
//!   faellt [`crate::verify_fresh_machine_recovery_test`].
//! - **Die Medien und der zweite Kanal** — Ports in
//!   [`crate::anchor_media`].
//! - **Das Signieren Wurzel-signierter Trust-Objekte** in Schritt 10 —
//!   [`crate::RootCeremonyService::publish_authorized_target`], unveraendert.
//!   Der Koordinator haelt nur fest, WELCHE Objekte entstanden sind.
//!
//! `ea-admin` waechst dafuer um keine Kante zu `ea-writer`, `ea-recovery`,
//! `ea-chain` oder `ea-archive*`.
//!
//! # Das signierte Bootstrap-Transkript
//!
//! Vor dem Bootstrap gibt es weder eine Bedienerbindung noch ein
//! registriertes Geraet und damit keine lokale Auditidentitaet.
//! `LocalAuditService::record_signed` (`crates/ea-audit/src/event.rs:237`)
//! verlangt dafuer einen `AuditActorProof`, und der ist GESCHLOSSEN: drei
//! Arme, mehr gibt es nicht (`event.rs:157-166`). Keiner von ihnen passt
//! hierher — `OperatorSession` verlangt eine Bedienerbindung,
//! `AuthenticatedDevice` ein bereits geprueftes Geraet, und beides entsteht
//! erst in den Schritten 3 und 8; `Expired` ist der Zustand, in den ein
//! entwerteter Nachweis zusammenfaellt, und keine Identitaet. Einen davon hier
//! zu waehlen hiesse, eine Identitaet zu behaupten, die es zu diesem Zeitpunkt
//! noch gar nicht gab, und die Auditzeile waere falsch zugerechnet. Der Koordinator
//! schreibt deshalb KEINE Auditzeile, sondern haelt den initialen Root und die
//! zwei ankergepinnten Admin-Zertifikat-/Bindungs-PAARE in einem
//! Wurzel-signierten [`BootstrapTranscriptV1`] fest. Ab Schritt 10 uebernimmt
//! der gewoehnliche Weg ueber [`crate::RootCeremonyService`] mit einer echten
//! Bedienerbindung.

use std::collections::BTreeSet;

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, object_hash, parse_cose_sign1,
};
use ea_format::{ExactObjectBytes, OperatorRoleV1, TrustPayloadV1};
use ea_key_provider::{KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose};
use ea_operator::OperatorSessionProof;
use ea_trust::{
    PreAnchorV1, TrustAnchorV1, TrustStateStore, VerifiedAdminAuthorizationIntent,
    decode_pre_anchor, decode_trust_anchor, encode_pre_anchor_v1,
};
use ea_types::{
    CertificateHash, ChainId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
};

use crate::{
    AdminError, AnchorMedia, AnchorMediumId, FreshMachineRecoveryProof, GenesisBinding,
    ProductionState, RootCeremonyService, SecondChannelConfirmation,
    confirm_final_anchor_fingerprint, confirm_on_media, verify_anchor_transition,
};

/// Die Domaene des Transkripts.
///
/// Sie steht als erstes Element IN den Transkriptbytes und trennt sie damit
/// von jedem anderen Objekt dieses Produkts — auch dann, wenn die COSE
/// daneben einen fremden Content-Type traegt (siehe
/// [`BootstrapTranscriptV1`]).
const TRANSCRIPT_DOMAIN: &[u8] = b"EINSATZARCHIV-BOOTSTRAP-TRANSCRIPT-v1";

/// Die Domaene des persistierten Zeremoniezustands.
const STATE_DOMAIN: &[u8] = b"EINSATZARCHIV-BOOTSTRAP-STATE-v1";

/// Die zwoelf Schritte aus `:1336-1347`, in ihrer Reihenfolge.
///
/// `Ord` folgt der Deklarationsreihenfolge und ist damit die Reihenfolge der
/// Spezifikation; „nur vorwaerts" ist deshalb ein `<`-Vergleich und keine
/// Tabelle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BootstrapStep {
    /// `:1336` — „zufaellige Organisations- und Ketten-ID erzeugen".
    GenerateIds,
    /// `:1337` — „Organisations-Root offline erzeugen".
    GenerateOfflineRoot,
    /// `:1338` — mindestens zwei Organisationsadministratoren erzeugen an
    /// getrennten produktiven OS-Konten je ein initiales Admin-
    /// `deviceCertificate` samt direkt Wurzel-signiertem `operatorBinding`.
    CreateAdminPairs,
    /// `:1339` — „vor der ersten Admin-Autorisierung
    /// `organization-trust-anchor-pre-v1` […] auf mindestens zwei
    /// Recovery-Medien dauerhaft festschreiben und dessen Fingerprint ueber
    /// den zweiten Kanal bestaetigen".
    PinPreAnchorOnMedia,
    /// `:1340` — „getrennten Recovery-KEM-Schluessel und
    /// Historical-Grant-Authority-Signaturschluessel erzeugen".
    GenerateRecoveryAndHgaKeys,
    /// `:1341` — „mindestens zwei Key Approver […] und Capabilities
    /// zuweisen".
    EnrollKeyApprovers,
    /// `:1342` — „mindestens zwei getrennte Sicherungen fuer Root-, Admin-,
    /// Recovery- und Historical-Grant-Authority-Schluessel verifizieren".
    VerifyKeyBackups,
    /// `:1343` — Writer, Server und erste Reader erzeugen ihre Schluessel
    /// lokal; die menschlichen OS-Konten werden als normal admin-autorisierte
    /// `operatorBinding`-Objekte provisioniert.
    ProvisionComponentKeys,
    /// `:1344` — „Fingerprints ueber QR-Code oder zweiten Kanal
    /// vergleichen".
    CompareFingerprints,
    /// `:1345` — „nach Admin-Autorisierung Geraete-, Operator-, Approver- und
    /// Komponenten-Zertifikate, initiale Registry und Richtlinie
    /// Root-signieren".
    RootSignBootstrapTargets,
    /// `:1346` — „Genesis als Sequenz 0 erzeugen, Trust Bundle archivieren und
    /// `organization-trust-anchor-v1` aus unveraenderten Vorstufenfeldern,
    /// `bootstrap-anchor-hash` und `genesis-entry-hash` bilden".
    CreateGenesisAndFinalAnchor,
    /// `:1347` — „Testeintrag finalisieren, auf einem frischen Rechner mit
    /// explizitem finalem Trust Anchor offline verifizieren und per Recovery
    /// entschluesseln".
    RunFreshMachineRecoveryTest,
}

impl BootstrapStep {
    /// Alle zwoelf, aufsteigend.
    ///
    /// Eine Konstante und keine Ableitung: sie ist zugleich der Zeuge dafuer,
    /// dass es zwoelf sind.
    pub const ALL: [Self; 12] = [
        Self::GenerateIds,
        Self::GenerateOfflineRoot,
        Self::CreateAdminPairs,
        Self::PinPreAnchorOnMedia,
        Self::GenerateRecoveryAndHgaKeys,
        Self::EnrollKeyApprovers,
        Self::VerifyKeyBackups,
        Self::ProvisionComponentKeys,
        Self::CompareFingerprints,
        Self::RootSignBootstrapTargets,
        Self::CreateGenesisAndFinalAnchor,
        Self::RunFreshMachineRecoveryTest,
    ];

    /// Die Nummer aus der Spezifikation, eins-basiert.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::GenerateIds => 1,
            Self::GenerateOfflineRoot => 2,
            Self::CreateAdminPairs => 3,
            Self::PinPreAnchorOnMedia => 4,
            Self::GenerateRecoveryAndHgaKeys => 5,
            Self::EnrollKeyApprovers => 6,
            Self::VerifyKeyBackups => 7,
            Self::ProvisionComponentKeys => 8,
            Self::CompareFingerprints => 9,
            Self::RootSignBootstrapTargets => 10,
            Self::CreateGenesisAndFinalAnchor => 11,
            Self::RunFreshMachineRecoveryTest => 12,
        }
    }

    /// Der Schritt zu einer Nummer aus [`Self::number`].
    ///
    /// Die Umkehrung von [`Self::number`], und sie steht daneben, damit beide
    /// Richtungen an derselben Stelle nachlesbar sind. Sie wird von
    /// [`BootstrapStateV1::from_persisted_image`] gebraucht: eine Nummer aus
    /// einer Datei ist eine BEHAUPTUNG, und eine, die keinen der zwoelf
    /// Schritte nennt, ist keine.
    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.number() == number)
    }

    /// Der STABILE Aussenname dieses Schritts.
    ///
    /// # Warum eine Tabelle und kein `Debug`
    ///
    /// Der Name verlaesst den Prozess: `apps/cli` druckt ihn in der
    /// Statuszeile von `organization init`. Ein abgeleitetes `Debug` waere
    /// dafuer eine Zusicherung, die niemand gegeben hat — es ist ein
    /// Diagnosewerkzeug. Die Tabelle steht deshalb neben [`Self::number`],
    /// damit beide Aussenangaben eines Schritts an derselben Stelle stehen und
    /// ein Zeuge sie zusammen misst. Dass sie heute zeichengleich mit dem
    /// Variantennamen ist, haelt `crates/ea-admin/tests/bootstrap.rs` fest;
    /// dieselbe Entscheidung traegt [`ProductionState`] mit ihrem
    /// handgeschriebenen `Debug`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GenerateIds => "GenerateIds",
            Self::GenerateOfflineRoot => "GenerateOfflineRoot",
            Self::CreateAdminPairs => "CreateAdminPairs",
            Self::PinPreAnchorOnMedia => "PinPreAnchorOnMedia",
            Self::GenerateRecoveryAndHgaKeys => "GenerateRecoveryAndHgaKeys",
            Self::EnrollKeyApprovers => "EnrollKeyApprovers",
            Self::VerifyKeyBackups => "VerifyKeyBackups",
            Self::ProvisionComponentKeys => "ProvisionComponentKeys",
            Self::CompareFingerprints => "CompareFingerprints",
            Self::RootSignBootstrapTargets => "RootSignBootstrapTargets",
            Self::CreateGenesisAndFinalAnchor => "CreateGenesisAndFinalAnchor",
            Self::RunFreshMachineRecoveryTest => "RunFreshMachineRecoveryTest",
        }
    }
}

/// Der Zufallsport fuer Schritt 1.
///
/// # Warum ein eigener Port und kein vorhandener
///
/// Es gibt im Baum keinen. `getrandom::fill` wird an 18 Stellen in ACHT Kisten
/// DIREKT gerufen — `ea-audit` (1), `ea-crypto` (1), `ea-draft` (1),
/// `ea-operator` (1), `ea-reader` (9), `ea-reader-wasm` (3), `ea-sync-client`
/// (1) und `ea-writer` (1) — und keine dieser Stellen liegt hinter einem
/// gemeinsamen Port. Der einzige Trait dieser Art — `CryptoRandomSource` in
/// `crates/ea-crypto/src/hpke.rs:24` — ist crate-privat und dient dort dem
/// HPKE-Seal. Ein Port muss hier trotzdem sein: Schritt 1 erzeugt die beiden
/// Kennungen, an denen die ganze Zeremonie haengt, und ein Zeuge muss sie
/// vorhersagen koennen, um „die neue Zeremonie traegt NEUE IDs" ueberhaupt
/// messen zu koennen.
///
/// [`SystemRandomSource`] ist die produktive Umsetzung und ruft dasselbe
/// `getrandom::fill` wie jene 18 Stellen.
pub trait CeremonyRandomSource {
    /// Fuellt `destination` mit kryptografisch zufaelligen Bytes.
    ///
    /// # Errors
    /// [`AdminError::Crypto`] mit `EA-LOCAL-CRYPTO-RNG`, wenn die Quelle nicht
    /// liefert. Ein eigener Code waere hier eine zweite Wahrheit: der Befund
    /// „die lokale Zufallsquelle liefert nicht" gehoert `ea-crypto`.
    fn fill_random(&mut self, destination: &mut [u8]) -> Result<(), AdminError>;
}

/// Die produktive Zufallsquelle.
pub struct SystemRandomSource;

impl CeremonyRandomSource for SystemRandomSource {
    fn fill_random(&mut self, destination: &mut [u8]) -> Result<(), AdminError> {
        getrandom::fill(destination)
            .map_err(|_| AdminError::Crypto(ea_crypto::CryptoError::LocalRng))
    }
}

/// Das oeffentliche Material des Organisations-Roots (Schritt 2).
///
/// Kein privater Schluessel: `signing_handle` ist die ADRESSE des Eintrags im
/// Speicher des Wirts, alles andere ist oeffentlich und steht so auch in der
/// Vorstufe (`:1737-1748`).
#[derive(Clone)]
pub struct RootKeyMaterialV1 {
    /// Der Griff auf den Wurzelschluessel beim Wirt.
    pub signing_handle: KeyHandle,
    /// Die exakten Deterministic-CBOR-Bytes des kanonischen COSE_Key.
    pub exact_public_cose_key: Vec<u8>,
    /// Der RFC-9679-Abdruck dieses Schluessels.
    pub key_thumbprint: KeyThumbprint,
    /// Der `objectHash` der Wurzelurkunde.
    pub certificate_object_hash: ObjectHash,
}

/// Ein ankergepinntes Admin-Paar aus Schritt 3.
///
/// Zertifikat und Bindung bilden nach `:1780` eine Eins-zu-eins-Paarung; hier
/// stehen sie deshalb als Paar und nicht als zwei lose Listen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AdminBootstrapPairV1 {
    /// Der `objectHash` des Admin-`deviceCertificate`.
    pub certificate_object_hash: ObjectHash,
    /// Der `objectHash` des direkt Wurzel-signierten `operatorBinding`.
    pub operator_binding_object_hash: ObjectHash,
}

/// Ein aeusserer Schluessel, den der Wirt haelt (Schritte 5 und 6).
#[derive(Clone)]
pub struct OuterKeyRecordV1 {
    /// Der Griff beim Wirt — eine Adresse, kein Zugriff.
    pub handle: KeyHandle,
    /// Der oeffentliche RFC-9679-Abdruck.
    pub key_thumbprint: KeyThumbprint,
}

/// Die vier Schluesselklassen, fuer die `:1342` Sicherungen verlangt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BackedUpKeyClass {
    /// Der Organisations-Root.
    Root,
    /// Ein Organisationsadministrator.
    Admin,
    /// Der Recovery-KEM-Schluessel.
    RecoveryKem,
    /// Der Historical-Grant-Authority-Signaturschluessel.
    HistoricalGrantAuthority,
}

impl BackedUpKeyClass {
    const ALL: [Self; 4] = [
        Self::Root,
        Self::Admin,
        Self::RecoveryKem,
        Self::HistoricalGrantAuthority,
    ];

    const fn code(self) -> u8 {
        match self {
            Self::Root => 0,
            Self::Admin => 1,
            Self::RecoveryKem => 2,
            Self::HistoricalGrantAuthority => 3,
        }
    }

    /// Die Umkehrung von [`Self::code`] fuer das persistierte Abbild.
    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.code() == code)
    }
}

/// Eine verifizierte Sicherung aus Schritt 7.
#[derive(Clone)]
pub struct KeyBackupRecordV1 {
    /// Welche Klasse gesichert wurde.
    pub class: BackedUpKeyClass,
    /// Der Abdruck des gesicherten Schluessels.
    pub key_thumbprint: KeyThumbprint,
    /// Die Medien, auf denen die Sicherung VERIFIZIERT wurde — `:1342`
    /// verlangt „mindestens zwei getrennte".
    pub media: Vec<AnchorMediumId>,
}

/// Ein provisioniertes Komponentenpaar aus Schritt 8.
#[derive(Clone, Copy)]
pub struct ComponentBindingV1 {
    /// Die Rolle des Kontos.
    pub role: OperatorRoleV1,
    /// Der `objectHash` des Komponentenzertifikats.
    pub certificate_object_hash: ObjectHash,
    /// Der `objectHash` des `operatorBinding`.
    pub operator_binding_object_hash: ObjectHash,
}

/// Das Wurzel-signierte Bootstrap-Transkript.
///
/// # Warum es dieses Objekt gibt
///
/// Siehe die Moduldokumentation: vor dem Bootstrap existiert keine
/// Bedienerbindung, und `AuditActorProof::OperatorSession` verlangt eine.
/// Statt eine Identitaet vorzutaeuschen, die es nicht gab, haelt dieses
/// Transkript fest, WAS die Zeremonie in ihren ersten Schritten festgelegt
/// hat: den initialen Root und die zwei ankergepinnten Admin-Paare.
///
/// # Der Content-Type
///
/// Die COSE traegt [`ContentType::TrustDigest`]. `ea_crypto::ContentType` ist
/// eine GESCHLOSSENE Menge von zwoelf Werten
/// (`crates/ea-crypto/src/cose.rs:25-52`); ein dreizehnter fuer dieses Objekt
/// gehoerte nach `ea-crypto` und ist ausdruecklich nicht Gegenstand dieser
/// Scheibe. Verwechselbar wird das Transkript dadurch nicht: die signierten
/// Bytes beginnen mit [`TRANSCRIPT_DOMAIN`], und kein Trust-Objekt dieses
/// Produkts tut das. Die Domaenentrennung liegt also im Urbild und nicht im
/// Header.
#[derive(Clone)]
pub struct BootstrapTranscriptV1 {
    organization_id: OrganizationId,
    chain_id: ChainId,
    root_certificate_object_hash: ObjectHash,
    admin_pairs: Vec<AdminBootstrapPairV1>,
    pre_anchor_fingerprint: Hash32,
    exact_bytes: Vec<u8>,
    root_signature: Vec<u8>,
}

impl BootstrapTranscriptV1 {
    /// Die Organisation dieser Zeremonie.
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// Die Kette dieser Zeremonie.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Der initiale Root.
    #[must_use]
    pub const fn root_certificate_object_hash(&self) -> ObjectHash {
        self.root_certificate_object_hash
    }

    /// Die ankergepinnten Admin-Paare — mindestens zwei (`:1338`, `:1780`).
    #[must_use]
    pub fn admin_pairs(&self) -> &[AdminBootstrapPairV1] {
        &self.admin_pairs
    }

    /// Der in Schritt 4 bestaetigte Fingerprint der Vorstufe.
    #[must_use]
    pub const fn pre_anchor_fingerprint(&self) -> Hash32 {
        self.pre_anchor_fingerprint
    }

    /// Die exakten Bytes, ueber die die Wurzelsignatur gebildet wurde.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// Die COSE-Sign1 der Wurzel ueber diese Bytes.
    #[must_use]
    pub fn root_signature_bytes(&self) -> &[u8] {
        &self.root_signature
    }
}

/// Der persistierte Zeremoniezustand.
///
/// Jedes Feld ist oeffentlicher Zeremoniezustand oder ein opaker Griff. Es
/// gibt kein Feld fuer privates Schluesselmaterial — nicht „es wird nichts
/// hineingeschrieben", sondern es passt nichts hinein.
#[derive(Clone)]
pub struct BootstrapStateV1 {
    step: BootstrapStep,
    aborted: bool,
    production_state: ProductionState,
    organization_id: OrganizationId,
    chain_id: ChainId,
    root: Option<RootKeyMaterialV1>,
    admin_pairs: Vec<AdminBootstrapPairV1>,
    exact_pre_anchor_bytes: Option<Vec<u8>>,
    sealed_pre_anchor_fingerprint: Option<Hash32>,
    /// Die Medien, auf denen Schritt 4 die Vorstufe festgeschrieben hat —
    /// WELCHE und nicht nur wie viele.
    ///
    /// `:1346` verlangt die finalen Ankerbytes „auf beiden Medien", also auf
    /// denselben. Eine blosse Zahl liesse Schritt 11 zwei beliebige andere
    /// Datentraeger annehmen; [`KeyBackupRecordV1::media`] fuehrt aus
    /// demselben Grund Kennungen und keine Anzahl.
    sealed_media: Vec<AnchorMediumId>,
    recovery_kem: Option<OuterKeyRecordV1>,
    hga_signing: Option<OuterKeyRecordV1>,
    approvers: Vec<OuterKeyRecordV1>,
    backups: Vec<KeyBackupRecordV1>,
    components: Vec<ComponentBindingV1>,
    fingerprints_compared: bool,
    published_target_object_hashes: Vec<ObjectHash>,
    genesis_entry_hash: Option<EntryHash>,
    exact_final_anchor_bytes: Option<Vec<u8>>,
    transcript: Option<BootstrapTranscriptV1>,
    recovery_test_machine: Option<Hash32>,
    /// Der Rechner, auf dem DIESE Zeremonie laeuft — festgehalten in Schritt 1.
    ///
    /// `:1347` verlangt fuer Schritt 12 „einen frischen Rechner". Woran sich
    /// „frisch" misst, darf nicht der Aufrufer von Schritt 12 bestimmen: er
    /// ist die Partei, die [`ProductionState::Ready`] will. Der Wirt benennt
    /// seinen Rechner deshalb EINMAL, beim Beginn, und der Vergleich laeuft
    /// gegen diesen festgehaltenen Wert.
    ///
    /// `None` heisst „dieser Wirt hat seinen Rechner nicht benannt" — und ist
    /// fail-closed: eine solche Zeremonie erreicht Schritt 12 nicht, weil sich
    /// „nicht derselbe Rechner" ueber nichts messen liesse.
    ceremony_machine: Option<Hash32>,
}

impl BootstrapStateV1 {
    /// Der Zustand einer GERADE begonnenen Zeremonie: Schritt 1 und sonst
    /// nichts (`:1336`).
    ///
    /// Eine Stelle fuer zwei Aufrufer — [`BootstrapCoordinator::start`] und
    /// [`Self::from_persisted_image`]. Zwei Stellen waeren zwei Wahrheiten
    /// darueber, wie eine leere Zeremonie aussieht, und der Wiedereinleser
    /// verglaeche gegen die falsche.
    fn fresh(
        organization_id: OrganizationId,
        chain_id: ChainId,
        ceremony_machine: Option<Hash32>,
    ) -> Self {
        Self {
            step: BootstrapStep::GenerateIds,
            aborted: false,
            production_state: ProductionState::BlockedRecoveryTest,
            organization_id,
            chain_id,
            root: None,
            admin_pairs: Vec::new(),
            exact_pre_anchor_bytes: None,
            sealed_pre_anchor_fingerprint: None,
            sealed_media: Vec::new(),
            recovery_kem: None,
            hga_signing: None,
            approvers: Vec::new(),
            backups: Vec::new(),
            components: Vec::new(),
            fingerprints_compared: false,
            published_target_object_hashes: Vec::new(),
            genesis_entry_hash: None,
            exact_final_anchor_bytes: None,
            transcript: None,
            recovery_test_machine: None,
            ceremony_machine,
        }
    }

    /// Liest ein Byteabbild aus [`Self::persisted_image`] zurueck.
    ///
    /// # Warum das VOLLSTAENDIG geht — und warum es das muss
    ///
    /// Die Zusage der Moduldokumentation lautet „Ein Neustart nimmt denselben
    /// Schritt wieder auf". Sie ist nur wahr, wenn jeder Zustand zurueckkommt,
    /// den [`BootstrapStore::store`] hinausschreibt — und geschrieben werden
    /// alle zwoelf. Ein Wiedereinleser, der nur Schritt 1 annaehme, machte aus
    /// jeder Zeremonie ab Schritt 2 eine Sackgasse: `resume`,
    /// `resume_or_begin`, `begin` und `restart_with_new_ids` faenden dann
    /// gemeinsam denselben unlesbaren Zustand vor, und das einzige Heilmittel
    /// waere, die Datei von Hand zu loeschen.
    ///
    /// Ein [`KeyHandle`] steht dem nicht im Weg. Er traegt fuenf Stuecke, und
    /// alle fuenf sind entweder im Abbild oder eine Konstante:
    /// `KeystoreProvider` und `SecretPurpose` sind geschlossene Aufzaehlungen
    /// und stehen als Kennziffer darin, die Kontoinstanz als Bindungshash, die
    /// Anwendung ist `APPLICATION_NAMESPACE`, und `KeyEntryPolicy` hat GENAU
    /// EINEN Wert und keinen zweiten Konstruktor
    /// (`crates/ea-key-provider/src/contract.rs:83-112`, `:146-159`). Ein
    /// Griff ist damit vollstaendig durch `(Speicher, Kontoinstanz, Zweck)`
    /// bestimmt — geraten wird nichts.
    ///
    /// # Die Pruefung ist EIN Zug und keine Feldliste
    ///
    /// Gelesen wird Feld fuer Feld, und danach wird das Ergebnis mit
    /// demselben [`Self::persisted_image`] neu kodiert, das es hervorgebracht
    /// hat; die beiden Bytefolgen muessen gleich sein. Damit faellt jedes
    /// abgeschnittene, jedes veraenderte und jedes um ein Feld reichere Abbild
    /// auf denselben Befund — und die Pruefung kann nicht hinter das Abbild
    /// zurueckfallen, weil sie dasselbe benutzt, das sie prueft.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStateShape`] fuer jedes Abbild, das nicht
    /// bytegleich eine Zeremonie dieses Bauwerks beschreibt.
    pub fn from_persisted_image(image: &[u8]) -> Result<Self, AdminError> {
        let state = Self::decode_image(image)?;
        if state.persisted_image() == image {
            Ok(state)
        } else {
            Err(AdminError::BootstrapStateShape)
        }
    }

    /// Liest die Felder — ohne den Byteabgleich, der in
    /// [`Self::from_persisted_image`] darueber liegt.
    fn decode_image(image: &[u8]) -> Result<Self, AdminError> {
        let mut reader = ImageReader::new(image);
        if reader.take(STATE_DOMAIN.len())? != STATE_DOMAIN {
            return Err(AdminError::BootstrapStateShape);
        }
        let step =
            BootstrapStep::from_number(reader.byte()?).ok_or(AdminError::BootstrapStateShape)?;
        let aborted = reader.flag()?;
        let production_state = match reader.byte()? {
            0 => ProductionState::BlockedRecoveryTest,
            1 => ProductionState::Ready,
            _ => return Err(AdminError::BootstrapStateShape),
        };
        let organization_id = OrganizationId::try_from(reader.take(16)?)
            .map_err(|_| AdminError::BootstrapStateShape)?;
        let chain_id =
            ChainId::try_from(reader.take(16)?).map_err(|_| AdminError::BootstrapStateShape)?;
        let ceremony_machine = reader.optional_hash()?;
        let root = if reader.flag()? {
            Some(RootKeyMaterialV1 {
                signing_handle: reader.handle()?,
                exact_public_cose_key: reader.slice()?.to_vec(),
                key_thumbprint: KeyThumbprint::from(reader.hash32()?),
                certificate_object_hash: reader.object_hash()?,
            })
        } else {
            None
        };
        let mut admin_pairs = Vec::new();
        for _ in 0..reader.count()? {
            admin_pairs.push(AdminBootstrapPairV1 {
                certificate_object_hash: reader.object_hash()?,
                operator_binding_object_hash: reader.object_hash()?,
            });
        }
        let exact_pre_anchor_bytes = reader.optional_slice()?;
        let sealed_pre_anchor_fingerprint = reader.optional_hash()?;
        let mut sealed_media = Vec::new();
        for _ in 0..reader.count()? {
            sealed_media.push(reader.medium()?);
        }
        let recovery_kem = reader.optional_outer_key()?;
        let hga_signing = reader.optional_outer_key()?;
        let mut approvers = Vec::new();
        for _ in 0..reader.count()? {
            approvers.push(OuterKeyRecordV1 {
                handle: reader.handle()?,
                key_thumbprint: KeyThumbprint::from(reader.hash32()?),
            });
        }
        let mut backups = Vec::new();
        for _ in 0..reader.count()? {
            let class = BackedUpKeyClass::from_code(reader.byte()?)
                .ok_or(AdminError::BootstrapStateShape)?;
            let key_thumbprint = KeyThumbprint::from(reader.hash32()?);
            let mut media = Vec::new();
            for _ in 0..reader.count()? {
                media.push(reader.medium()?);
            }
            backups.push(KeyBackupRecordV1 {
                class,
                key_thumbprint,
                media,
            });
        }
        let mut components = Vec::new();
        for _ in 0..reader.count()? {
            components.push(ComponentBindingV1 {
                role: operator_role_from_code(reader.byte()?)?,
                certificate_object_hash: reader.object_hash()?,
                operator_binding_object_hash: reader.object_hash()?,
            });
        }
        let fingerprints_compared = reader.flag()?;
        let mut published_target_object_hashes = Vec::new();
        for _ in 0..reader.count()? {
            published_target_object_hashes.push(reader.object_hash()?);
        }
        let genesis_entry_hash = if reader.flag()? {
            Some(
                EntryHash::try_from(reader.take(32)?)
                    .map_err(|_| AdminError::BootstrapStateShape)?,
            )
        } else {
            None
        };
        let exact_final_anchor_bytes = reader.optional_slice()?;
        let signed_transcript = if reader.flag()? {
            Some((reader.slice()?.to_vec(), reader.slice()?.to_vec()))
        } else {
            None
        };
        let recovery_test_machine = reader.optional_hash()?;
        if !reader.is_exhausted() {
            return Err(AdminError::BootstrapStateShape);
        }

        let mut state = Self {
            step,
            aborted,
            production_state,
            organization_id,
            chain_id,
            root,
            admin_pairs,
            exact_pre_anchor_bytes,
            sealed_pre_anchor_fingerprint,
            sealed_media,
            recovery_kem,
            hga_signing,
            approvers,
            backups,
            components,
            fingerprints_compared,
            published_target_object_hashes,
            genesis_entry_hash,
            exact_final_anchor_bytes,
            transcript: None,
            recovery_test_machine,
            ceremony_machine,
        };
        if let Some((exact_bytes, root_signature)) = signed_transcript {
            // Das Abbild traegt vom Transkript nur, was NICHT schon woanders
            // darin steht: seine Bytes und die Signatur. Alles andere wird aus
            // dem Zustand rekonstruiert — und dass diese Rekonstruktion
            // stimmt, sagt hier kein Kommentar, sondern der Vergleich mit den
            // gespeicherten Bytes.
            let root = state.root.as_ref().ok_or(AdminError::BootstrapStateShape)?;
            let pre_anchor_fingerprint = state
                .sealed_pre_anchor_fingerprint
                .ok_or(AdminError::BootstrapStateShape)?;
            if transcript_exact_bytes(&state, root, pre_anchor_fingerprint) != exact_bytes {
                return Err(AdminError::BootstrapStateShape);
            }
            state.transcript = Some(BootstrapTranscriptV1 {
                organization_id: state.organization_id,
                chain_id: state.chain_id,
                root_certificate_object_hash: root.certificate_object_hash,
                admin_pairs: state.admin_pairs.clone(),
                pre_anchor_fingerprint,
                exact_bytes,
                root_signature,
            });
        }
        Ok(state)
    }

    /// Der zuletzt ABGESCHLOSSENE Schritt.
    #[must_use]
    pub const fn step(&self) -> BootstrapStep {
        self.step
    }

    /// Ob diese Zeremonie durch eine Feldaenderung nach Schritt 4 abgebrochen
    /// wurde (`:1349`).
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// Der Freigabezustand.
    #[must_use]
    pub const fn production_state(&self) -> ProductionState {
        self.production_state
    }

    /// Die Organisations-ID dieser Zeremonie.
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// Die Ketten-ID dieser Zeremonie.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Die exakten Vorstufenbytes, sobald Schritt 3 sie gebaut hat.
    #[must_use]
    pub fn exact_pre_anchor_bytes(&self) -> Option<&[u8]> {
        self.exact_pre_anchor_bytes.as_deref()
    }

    /// Der in Schritt 4 bestaetigte Fingerprint, falls versiegelt.
    #[must_use]
    pub const fn sealed_pre_anchor_fingerprint(&self) -> Option<Hash32> {
        self.sealed_pre_anchor_fingerprint
    }

    /// Die exakten finalen Ankerbytes, sobald Schritt 11 sie angenommen hat.
    #[must_use]
    pub fn exact_final_anchor_bytes(&self) -> Option<&[u8]> {
        self.exact_final_anchor_bytes.as_deref()
    }

    /// Das Wurzel-signierte Transkript, sobald Schritt 11 es gebildet hat.
    #[must_use]
    pub const fn transcript(&self) -> Option<&BootstrapTranscriptV1> {
        self.transcript.as_ref()
    }

    /// Das VOLLSTAENDIGE Byteabbild dieses Zustands.
    ///
    /// Der Vertrag von [`BootstrapStore::store`] lautet: eine Umsetzung
    /// persistiert genau dieses Abbild und nichts darueber hinaus. Damit ist
    /// „im persistierten Zustand steht kein Schluesselmaterial" eine Aussage,
    /// die ein Zeuge an BYTES messen kann und nicht nur an Feldnamen.
    ///
    /// Es ist bewusst kein CBOR: der Zeremoniezustand ist lokal, hat keine
    /// Drahtform in der Spezifikation, und eine zweite CBOR-Grammatik neben
    /// `ea-format` waere eine zweite Wahrheit ueber Objektbytes, die dieses
    /// Abbild gar nicht sein will. Es ist eine flache, laengenpraefigierte
    /// Aneinanderreihung mit eigener Domaene.
    #[must_use]
    pub fn persisted_image(&self) -> Vec<u8> {
        let mut image = Vec::new();
        image.extend_from_slice(STATE_DOMAIN);
        image.push(self.step.number());
        image.push(u8::from(self.aborted));
        image.push(match self.production_state {
            ProductionState::BlockedRecoveryTest => 0,
            ProductionState::Ready => 1,
        });
        image.extend_from_slice(self.organization_id.as_bytes());
        image.extend_from_slice(self.chain_id.as_bytes());
        push_optional_hash(&mut image, self.ceremony_machine);
        match &self.root {
            None => image.push(0),
            Some(root) => {
                image.push(1);
                push_handle(&mut image, root.signing_handle);
                push_slice(&mut image, &root.exact_public_cose_key);
                image.extend_from_slice(root.key_thumbprint.as_bytes());
                image.extend_from_slice(root.certificate_object_hash.as_bytes());
            }
        }
        push_count(&mut image, self.admin_pairs.len());
        for pair in &self.admin_pairs {
            image.extend_from_slice(pair.certificate_object_hash.as_bytes());
            image.extend_from_slice(pair.operator_binding_object_hash.as_bytes());
        }
        push_optional_slice(&mut image, self.exact_pre_anchor_bytes.as_deref());
        push_optional_hash(&mut image, self.sealed_pre_anchor_fingerprint);
        push_count(&mut image, self.sealed_media.len());
        for medium in &self.sealed_media {
            image.extend_from_slice(medium.as_bytes());
        }
        push_optional_outer_key(&mut image, self.recovery_kem.as_ref());
        push_optional_outer_key(&mut image, self.hga_signing.as_ref());
        push_count(&mut image, self.approvers.len());
        for approver in &self.approvers {
            push_handle(&mut image, approver.handle);
            image.extend_from_slice(approver.key_thumbprint.as_bytes());
        }
        push_count(&mut image, self.backups.len());
        for backup in &self.backups {
            image.push(backup.class.code());
            image.extend_from_slice(backup.key_thumbprint.as_bytes());
            push_count(&mut image, backup.media.len());
            for medium in &backup.media {
                image.extend_from_slice(medium.as_bytes());
            }
        }
        push_count(&mut image, self.components.len());
        for component in &self.components {
            image.push(component.role as u8);
            image.extend_from_slice(component.certificate_object_hash.as_bytes());
            image.extend_from_slice(component.operator_binding_object_hash.as_bytes());
        }
        image.push(u8::from(self.fingerprints_compared));
        push_count(&mut image, self.published_target_object_hashes.len());
        for hash in &self.published_target_object_hashes {
            image.extend_from_slice(hash.as_bytes());
        }
        match self.genesis_entry_hash {
            None => image.push(0),
            Some(hash) => {
                image.push(1);
                image.extend_from_slice(hash.as_bytes());
            }
        }
        push_optional_slice(&mut image, self.exact_final_anchor_bytes.as_deref());
        match &self.transcript {
            None => image.push(0),
            Some(transcript) => {
                image.push(1);
                push_slice(&mut image, &transcript.exact_bytes);
                push_slice(&mut image, &transcript.root_signature);
            }
        }
        push_optional_hash(&mut image, self.recovery_test_machine);
        image
    }
}

fn push_count(image: &mut Vec<u8>, count: usize) {
    let value = u32::try_from(count).unwrap_or(u32::MAX);
    image.extend_from_slice(&value.to_be_bytes());
}

fn push_slice(image: &mut Vec<u8>, bytes: &[u8]) {
    push_count(image, bytes.len());
    image.extend_from_slice(bytes);
}

/// Ein Griff ist eine ADRESSE: Speicher, Anwendung, Kontoinstanz-Bindungshash,
/// Zweck und Verbreitungspolitik. Kein Byte davon ist geheim
/// (`crates/ea-key-provider/src/contract.rs:170-183`).
///
/// Alle fuenf stehen hier — auch die Politik, die heute genau einen Wert hat.
/// Sie steht nicht, weil sie sich aendern koennte, sondern damit ein Griff mit
/// einer ANDEREN Politik am Byteabgleich in
/// [`BootstrapStateV1::from_persisted_image`] auffiele, statt still auf
/// `DEVICE_LOCAL` zurueckgelesen zu werden.
fn push_handle(image: &mut Vec<u8>, handle: KeyHandle) {
    image.push(keystore_provider_code(handle.keystore_provider()));
    push_slice(image, handle.application().as_bytes());
    image.extend_from_slice(handle.account_instance().as_bytes());
    image.push(secret_purpose_code(handle.purpose()));
    let policy = handle.entry_policy();
    image.push(u8::from(policy.is_roaming()));
    image.push(u8::from(policy.is_cloud_synchronised()));
    image.push(u8::from(policy.is_included_in_ordinary_backup()));
}

const fn keystore_provider_code(provider: KeystoreProvider) -> u8 {
    match provider {
        KeystoreProvider::OperatingSystem => 0,
        KeystoreProvider::InMemory => 1,
    }
}

fn keystore_provider_from_code(code: u8) -> Result<KeystoreProvider, AdminError> {
    match code {
        0 => Ok(KeystoreProvider::OperatingSystem),
        1 => Ok(KeystoreProvider::InMemory),
        _ => Err(AdminError::BootstrapStateShape),
    }
}

const fn secret_purpose_code(purpose: SecretPurpose) -> u8 {
    match purpose {
        SecretPurpose::WriterSigningKey => 0,
        SecretPurpose::OperatorInstanceKey => 1,
        SecretPurpose::DraftDek => 2,
        SecretPurpose::LocalDatabaseKey => 3,
    }
}

fn secret_purpose_from_code(code: u8) -> Result<SecretPurpose, AdminError> {
    match code {
        0 => Ok(SecretPurpose::WriterSigningKey),
        1 => Ok(SecretPurpose::OperatorInstanceKey),
        2 => Ok(SecretPurpose::DraftDek),
        3 => Ok(SecretPurpose::LocalDatabaseKey),
        _ => Err(AdminError::BootstrapStateShape),
    }
}

fn operator_role_from_code(code: u8) -> Result<OperatorRoleV1, AdminError> {
    match code {
        0 => Ok(OperatorRoleV1::Writer),
        1 => Ok(OperatorRoleV1::Reader),
        2 => Ok(OperatorRoleV1::OrganizationAdmin),
        _ => Err(AdminError::BootstrapStateShape),
    }
}

fn push_optional_slice(image: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        None => image.push(0),
        Some(value) => {
            image.push(1);
            push_slice(image, value);
        }
    }
}

/// Der Leser des Abbilds — laengengepruefte Bewegungen, kein `unwrap`.
///
/// Jede Bewegung, die ueber das Ende hinausliefe, endet auf
/// [`AdminError::BootstrapStateShape`]; ein abgeschnittenes Abbild ist kein
/// halber Zustand, sondern keiner.
struct ImageReader<'a> {
    rest: &'a [u8],
}

impl<'a> ImageReader<'a> {
    const fn new(image: &'a [u8]) -> Self {
        Self { rest: image }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AdminError> {
        if self.rest.len() < length {
            return Err(AdminError::BootstrapStateShape);
        }
        let (head, tail) = self.rest.split_at(length);
        self.rest = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, AdminError> {
        Ok(self.take(1)?[0])
    }

    fn flag(&mut self) -> Result<bool, AdminError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AdminError::BootstrapStateShape),
        }
    }

    fn count(&mut self) -> Result<usize, AdminError> {
        let raw = self.take(4)?;
        let value = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        usize::try_from(value).map_err(|_| AdminError::BootstrapStateShape)
    }

    fn slice(&mut self) -> Result<&'a [u8], AdminError> {
        let length = self.count()?;
        self.take(length)
    }

    fn optional_slice(&mut self) -> Result<Option<Vec<u8>>, AdminError> {
        if self.flag()? {
            self.slice().map(<[u8]>::to_vec).map(Some)
        } else {
            Ok(None)
        }
    }

    fn hash32(&mut self) -> Result<Hash32, AdminError> {
        Hash32::try_from(self.take(32)?).map_err(|_| AdminError::BootstrapStateShape)
    }

    fn optional_hash(&mut self) -> Result<Option<Hash32>, AdminError> {
        if self.flag()? {
            self.hash32().map(Some)
        } else {
            Ok(None)
        }
    }

    fn object_hash(&mut self) -> Result<ObjectHash, AdminError> {
        ObjectHash::try_from(self.take(32)?).map_err(|_| AdminError::BootstrapStateShape)
    }

    fn medium(&mut self) -> Result<AnchorMediumId, AdminError> {
        let raw: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| AdminError::BootstrapStateShape)?;
        Ok(AnchorMediumId::new(raw))
    }

    fn handle(&mut self) -> Result<KeyHandle, AdminError> {
        let provider = keystore_provider_from_code(self.byte()?)?;
        // Die Anwendung ist eine Konstante des Griffkonstruktors; sie steht im
        // Abbild, damit ein fremder Wert am Byteabgleich auffaellt, und wird
        // hier nicht in den Griff zurueckgetragen.
        let _application = self.slice()?;
        let account_instance = self.hash32()?;
        let purpose = secret_purpose_from_code(self.byte()?)?;
        let _policy = self.take(3)?;
        Ok(KeyHandle::new(provider, account_instance, purpose))
    }

    fn optional_outer_key(&mut self) -> Result<Option<OuterKeyRecordV1>, AdminError> {
        if !self.flag()? {
            return Ok(None);
        }
        Ok(Some(OuterKeyRecordV1 {
            handle: self.handle()?,
            key_thumbprint: KeyThumbprint::from(self.hash32()?),
        }))
    }

    const fn is_exhausted(&self) -> bool {
        self.rest.is_empty()
    }
}

fn push_optional_hash(image: &mut Vec<u8>, hash: Option<Hash32>) {
    match hash {
        None => image.push(0),
        Some(value) => {
            image.push(1);
            image.extend_from_slice(value.as_bytes());
        }
    }
}

fn push_optional_outer_key(image: &mut Vec<u8>, key: Option<&OuterKeyRecordV1>) {
    match key {
        None => image.push(0),
        Some(record) => {
            image.push(1);
            push_handle(image, record.handle);
            image.extend_from_slice(record.key_thumbprint.as_bytes());
        }
    }
}

/// Der Persistenzport der Zeremonie.
///
/// Eine Zeremonie ueberlebt Neustarts, Stromausfaelle und den Weg von einem
/// Raum in den naechsten; ohne persistierten Zustand faenge sie jedes Mal von
/// vorn an — und „von vorn" hiesse nach `:1349` neue Kennungen.
pub trait BootstrapStore {
    /// Liest den persistierten Zustand, falls es einen gibt.
    ///
    /// # Errors
    /// Ein Befund der Ablage, ueblicherweise
    /// [`AdminError::BootstrapStoreUnavailable`].
    fn load(&self) -> Result<Option<BootstrapStateV1>, AdminError>;

    /// Persistiert GENAU [`BootstrapStateV1::persisted_image`].
    ///
    /// Eine Umsetzung, die mehr schreibt als dieses Abbild, bricht die Zusage
    /// dieser Crate, dass nur oeffentlicher Zeremoniezustand die Maschine
    /// ueberlebt.
    ///
    /// # Errors
    /// Ein Befund der Ablage, ueblicherweise
    /// [`AdminError::BootstrapStoreUnavailable`].
    fn store(&mut self, state: &BootstrapStateV1) -> Result<(), AdminError>;
}

/// Der Koordinator des Zwoelfschrittablaufs.
///
/// Er ist SYNCHRON wie der ganze Rust-Kern; Async lebt ausschliesslich in
/// `apps/desktop/src-tauri` ueber `spawn_blocking`
/// (`crates/ea-key-provider/src/contract.rs:337-343`).
pub struct BootstrapCoordinator<'a> {
    store: &'a mut dyn BootstrapStore,
    state: BootstrapStateV1,
    pre_anchor: Option<PreAnchorV1>,
}

impl<'a> BootstrapCoordinator<'a> {
    /// Beginnt eine NEUE Zeremonie: Schritt 1, zufaellige Organisations- und
    /// Ketten-ID (`:1336`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepRegression`], wenn bereits eine Zeremonie
    /// persistiert ist — eine zweite daneben zu beginnen hiesse, zwei
    /// Wahrheiten ueber dieselbe Organisation zu fuehren; der Weg dorthin ist
    /// [`Self::restart_with_new_ids`]. Ausserdem jeder Befund des Ports.
    pub fn begin(
        store: &'a mut dyn BootstrapStore,
        random: &mut dyn CeremonyRandomSource,
        ceremony_machine: Option<Hash32>,
    ) -> Result<Self, AdminError> {
        if store.load()?.is_some() {
            return Err(AdminError::BootstrapStepRegression);
        }
        let (organization_id, chain_id) = fresh_ids(random)?;
        Self::start(store, organization_id, chain_id, ceremony_machine)
    }

    /// Setzt eine persistierte Zeremonie fort — beim SELBEN Schritt.
    ///
    /// # Errors
    /// Jeder Befund des Ports, sowie
    /// [`AdminError::BootstrapStateShape`], wenn die persistierte Vorstufe
    /// nicht mehr dekodierbar ist.
    pub fn resume(store: &'a mut dyn BootstrapStore) -> Result<Option<Self>, AdminError> {
        let Some(state) = store.load()? else {
            return Ok(None);
        };
        Self::over(store, state).map(Some)
    }

    /// Fortsetzen, wenn es etwas fortzusetzen gibt, sonst beginnen.
    ///
    /// # Warum hier GENAU EINMAL geladen wird
    ///
    /// Zwei Ladevorgaenge sind zwei Fragen an eine Ablage, die sich zwischen
    /// ihnen aendern darf: ein nebenlaeufiger Lauf, eine zweite Instanz
    /// desselben Pfades oder eine von Hand geloeschte Zustandsdatei liefern
    /// erst `Some` und dann `None`. Wer aus dem ersten Ergebnis auf das zweite
    /// schliesst, hat die Ablage nicht gefragt, sondern geraten — und dieser
    /// Pfad ist der EINZIGE, ueber den `apps/cli` in die Zeremonie kommt
    /// (`apps/cli/src/commands/organization.rs`). Der Zustand wird deshalb
    /// einmal geholt und danach benutzt.
    ///
    /// # Errors
    /// Wie [`Self::begin`] und [`Self::resume`].
    pub fn resume_or_begin(
        store: &'a mut dyn BootstrapStore,
        random: &mut dyn CeremonyRandomSource,
        ceremony_machine: Option<Hash32>,
    ) -> Result<Self, AdminError> {
        let Some(state) = store.load()? else {
            return Self::begin(store, random, ceremony_machine);
        };
        Self::over(store, state)
    }

    /// Der Koordinator ueber einem BEREITS gelesenen Zustand.
    ///
    /// Eine Stelle fuer beide Wiederaufnahmewege, damit „was aus der Ablage
    /// kommt, wird so und nicht anders gedeutet" eine einzige Wahrheit
    /// bleibt.
    fn over(
        store: &'a mut dyn BootstrapStore,
        state: BootstrapStateV1,
    ) -> Result<Self, AdminError> {
        let pre_anchor = match state.exact_pre_anchor_bytes.as_deref() {
            None => None,
            Some(bytes) => {
                Some(decode_pre_anchor(bytes).map_err(|_| AdminError::BootstrapStateShape)?)
            }
        };
        Ok(Self {
            store,
            state,
            pre_anchor,
        })
    }

    /// Beginnt nach einem Abbruch mit NEUEN Kennungen von vorn (`:1349`).
    ///
    /// Das ist die einzige Stelle, an der der Schritt zurueckfaellt — und sie
    /// ist keine Ausnahme von „nur vorwaerts", sondern ihre Bestaetigung: was
    /// hier beginnt, ist eine ANDERE Zeremonie mit anderer Organisations- und
    /// Ketten-ID. Die alte wird nicht fortgesetzt, sie ist abgebrochen.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepRegression`], wenn die persistierte
    /// Zeremonie gar nicht abgebrochen ist — eine laufende Zeremonie faengt
    /// nicht einfach neu an; [`AdminError::Crypto`] mit `EA-LOCAL-CRYPTO-RNG`,
    /// wenn die Zufallsquelle dieselben Kennungen noch einmal liefert, denn
    /// dann waere die geforderte Neuheit nicht erreicht.
    pub fn restart_with_new_ids(
        store: &'a mut dyn BootstrapStore,
        random: &mut dyn CeremonyRandomSource,
        ceremony_machine: Option<Hash32>,
    ) -> Result<Self, AdminError> {
        let previous = store.load()?;
        if !previous.as_ref().is_some_and(BootstrapStateV1::is_aborted) {
            return Err(AdminError::BootstrapStepRegression);
        }
        let (organization_id, chain_id) = fresh_ids(random)?;
        if let Some(previous) = previous.as_ref()
            && (organization_id == previous.organization_id || chain_id == previous.chain_id)
        {
            return Err(AdminError::Crypto(ea_crypto::CryptoError::LocalRng));
        }
        Self::start(store, organization_id, chain_id, ceremony_machine)
    }

    fn start(
        store: &'a mut dyn BootstrapStore,
        organization_id: OrganizationId,
        chain_id: ChainId,
        ceremony_machine: Option<Hash32>,
    ) -> Result<Self, AdminError> {
        let state = BootstrapStateV1::fresh(organization_id, chain_id, ceremony_machine);
        store.store(&state)?;
        Ok(Self {
            store,
            state,
            pre_anchor: None,
        })
    }

    /// Der zuletzt abgeschlossene Schritt.
    #[must_use]
    pub const fn step(&self) -> BootstrapStep {
        self.state.step
    }

    /// Die Organisations-ID dieser Zeremonie.
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.state.organization_id
    }

    /// Die Ketten-ID dieser Zeremonie.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.state.chain_id
    }

    /// Der Freigabezustand.
    #[must_use]
    pub const fn production_state(&self) -> ProductionState {
        self.state.production_state
    }

    /// Der gesamte persistierte Zustand.
    #[must_use]
    pub const fn state(&self) -> &BootstrapStateV1 {
        &self.state
    }

    /// Die Vorstufe, sobald Schritt 3 sie gebaut hat.
    #[must_use]
    pub const fn pre_anchor(&self) -> Option<&PreAnchorV1> {
        self.pre_anchor.as_ref()
    }

    /// Betritt einen Schritt erneut — die Bewegung eines Wiederanlaufs.
    ///
    /// Genau der persistierte Schritt gelingt und wird zurueckgegeben; alles
    /// davor und alles danach nicht.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepRegression`] mit
    /// `EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION` fuer einen frueheren Schritt,
    /// [`AdminError::BootstrapStepOutOfOrder`] mit
    /// `EA-CEREMONY-BOOTSTRAP-STEP-OUT-OF-ORDER` fuer einen spaeteren.
    pub fn re_enter(&self, step: BootstrapStep) -> Result<BootstrapStep, AdminError> {
        if step < self.state.step {
            return Err(AdminError::BootstrapStepRegression);
        }
        if step > self.state.step {
            return Err(AdminError::BootstrapStepOutOfOrder);
        }
        Ok(step)
    }

    /// Schritt 2: der offline erzeugte Organisations-Root (`:1337`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 1 fehlt;
    /// [`AdminError::AnchorPreFieldChanged`], wenn die Vorstufe bereits
    /// versiegelt ist und dieses Material ein Feld von ihr aendert; jeder
    /// Befund des Ports.
    pub fn generate_offline_root(&mut self, root: RootKeyMaterialV1) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::GenerateIds)?;
        if self
            .state
            .root
            .as_ref()
            .is_some_and(|existing| same_root(existing, &root))
        {
            return Ok(());
        }
        // Dieselbe Bewegung wie in [`Self::create_admin_pairs`], und aus
        // demselben Grund: `:1349` unterscheidet die festgeschriebenen Felder
        // nicht, also darf sich auch die FOLGE nicht danach unterscheiden,
        // welches von ihnen sich geaendert hat. Ein Pfad, der nur abwiese,
        // liesse eine nicht abgebrochene Zeremonie stehen — und
        // [`Self::restart_with_new_ids`], das einzige Heilmittel der
        // Spezifikation, verlangt genau den Abbruch.
        if let Err(error) = self.require_unsealed() {
            self.abort()?;
            return Err(error);
        }
        let snapshot = self.state.clone();
        self.state.root = Some(root);
        if let Err(error) = self.rebuild_pre_anchor() {
            self.restore(snapshot);
            if error == AdminError::AnchorPreFieldChanged {
                self.abort()?;
            }
            return Err(error);
        }
        self.commit(snapshot, BootstrapStep::GenerateOfflineRoot)
    }

    /// Schritt 3: die mindestens zwei ankergepinnten Admin-Paare (`:1338`) —
    /// und damit die exakten Vorstufenbytes.
    ///
    /// Gibt den Fingerprint der Vorstufe zurueck, also genau den Wert, den
    /// Schritt 4 ueber den zweiten Kanal bestaetigen laesst (`:1339`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 2 fehlt;
    /// [`AdminError::BootstrapQuorumMissing`] fuer weniger als zwei Paare und
    /// fuer eine Paarmenge, die die Eins-zu-eins-Paarung aus `:1780` gar nicht
    /// tragen kann (siehe [`require_distinct_pairing`]);
    /// [`AdminError::AnchorPreFieldChanged`], wenn die Vorstufe bereits
    /// versiegelt ist und diese Paare sie aendern — die Zeremonie ist danach
    /// ABGEBROCHEN und nur ueber [`Self::restart_with_new_ids`] fortsetzbar;
    /// [`AdminError::Trust`] fuer eine Vorstufe, die `ea-trust` nicht
    /// kodiert.
    pub fn create_admin_pairs(
        &mut self,
        pairs: &[AdminBootstrapPairV1],
    ) -> Result<Hash32, AdminError> {
        self.require_completed(BootstrapStep::GenerateOfflineRoot)?;
        if pairs.len() < 2 {
            return Err(AdminError::BootstrapQuorumMissing);
        }
        require_distinct_pairing(pairs)?;
        let snapshot = self.state.clone();
        self.state.admin_pairs = pairs.to_vec();
        if let Err(error) = self.rebuild_pre_anchor() {
            // Der abgebrochene Zustand darf nicht die ZURUECKGEWIESENEN Paare
            // tragen: er wird noch gelesen — [`Self::restart_with_new_ids`]
            // vergleicht seine Kennungen — und ein Zustand, dessen Paare nicht
            // zu seinen versiegelten Vorstufenbytes passen, waere in sich
            // widerspruechlich. Erst zuruecksetzen, dann abbrechen.
            self.restore(snapshot);
            if error == AdminError::AnchorPreFieldChanged {
                self.abort()?;
            }
            return Err(error);
        }
        let fingerprint = self
            .pre_anchor
            .as_ref()
            .expect("Schritt 3 hat die Vorstufe gerade gebaut")
            .bootstrap_anchor_hash();
        if self.state.step >= BootstrapStep::CreateAdminPairs {
            // Ein reiner Wiedereintritt mit identischen Paaren persistiert
            // nichts und faellt auch nicht zurueck.
            return Ok(fingerprint);
        }
        self.commit(snapshot, BootstrapStep::CreateAdminPairs)?;
        Ok(fingerprint)
    }

    /// Schritt 4: die Vorstufe auf mindestens zwei schreibgeschuetzten
    /// Recovery-Medien festschreiben und ueber den zweiten Kanal bestaetigen
    /// (`:1339`).
    ///
    /// Danach ist sie VERSIEGELT.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 3 fehlt; jeder
    /// Befund von [`confirm_on_media`] — insbesondere
    /// [`AdminError::MediaQuorumMissing`],
    /// [`AdminError::MediaReadbackMismatch`] und
    /// [`AdminError::SecondChannelMismatch`]; jeder Befund des Ports. Bei
    /// jedem Fehlschlag bleibt die Vorstufe UNVERSIEGELT.
    pub fn pin_pre_anchor_on_media(
        &mut self,
        media: &mut dyn AnchorMedia,
        ids: &[AnchorMediumId],
        fingerprint_confirmed: SecondChannelConfirmation,
    ) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::CreateAdminPairs)?;
        let exact_bytes = self
            .state
            .exact_pre_anchor_bytes
            .clone()
            .ok_or(AdminError::BootstrapStepOutOfOrder)?;
        let confirmation = confirm_on_media(media, ids, &exact_bytes, fingerprint_confirmed)?;
        let snapshot = self.state.clone();
        self.state.sealed_pre_anchor_fingerprint = Some(confirmation.fingerprint());
        // WELCHE Medien und nicht nur wie viele: `:1346` verlangt die finalen
        // Ankerbytes „auf beiden Medien", und „beide" meint dieselben.
        // `confirm_on_media` hat die Kennungen bereits auf Unterscheidbarkeit
        // geprueft und ihre Zahl gemeldet — die Liste steht sortiert, damit
        // das Abbild nicht von der Aufrufreihenfolge abhaengt.
        let mut sealed: Vec<AnchorMediumId> = ids.to_vec();
        sealed.sort_unstable();
        debug_assert_eq!(sealed.len(), confirmation.medium_count());
        self.state.sealed_media = sealed;
        self.commit(snapshot, BootstrapStep::PinPreAnchorOnMedia)
    }

    /// Schritt 5: Recovery-KEM und Historical Grant Authority (`:1340`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapPreAnchorUnconfirmed`] mit
    /// `EA-CEREMONY-PRE-ANCHOR-UNCONFIRMED`, solange Schritt 4 nicht
    /// abgeschlossen ist; [`AdminError::BootstrapQuorumMissing`], wenn die
    /// beiden Schluessel nicht GETRENNT sind — voneinander oder von der
    /// Wurzel (`:1340`); jeder Befund des Ports.
    pub fn generate_recovery_and_hga_keys(
        &mut self,
        recovery_kem: OuterKeyRecordV1,
        hga_signing: OuterKeyRecordV1,
    ) -> Result<(), AdminError> {
        self.require_sealed()?;
        // `:1340` sagt „getrennten Recovery-KEM-Schluessel UND
        // Historical-Grant-Authority-Signaturschluessel". Zwei Namen fuer
        // denselben Abdruck sind ein Schluessel, und ein Recovery-Schluessel,
        // der die Wurzel IST, macht aus der Wiederherstellung eine zweite
        // Verwendung des Schluessels, gegen dessen Verlust sie versichert.
        let mut distinct = BTreeSet::new();
        for thumbprint in [
            recovery_kem.key_thumbprint,
            hga_signing.key_thumbprint,
            self.state
                .root
                .as_ref()
                .ok_or(AdminError::BootstrapStepOutOfOrder)?
                .key_thumbprint,
        ] {
            if !distinct.insert(*thumbprint.as_bytes()) {
                return Err(AdminError::BootstrapQuorumMissing);
            }
        }
        let snapshot = self.state.clone();
        self.state.recovery_kem = Some(recovery_kem);
        self.state.hga_signing = Some(hga_signing);
        self.commit(snapshot, BootstrapStep::GenerateRecoveryAndHgaKeys)
    }

    /// Schritt 6: mindestens zwei Key Approver (`:1341`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 5 fehlt;
    /// [`AdminError::BootstrapQuorumMissing`] fuer weniger als zwei
    /// UNTERSCHIEDLICHE Abdruecke — zwei Eintraege desselben Schluessels sind
    /// ein Approver — und fuer einen Approver, der die Wurzel, der
    /// Recovery-KEM- oder der HGA-Schluessel dieser Zeremonie ist; jeder
    /// Befund des Ports.
    pub fn enroll_key_approvers(
        &mut self,
        approvers: &[OuterKeyRecordV1],
    ) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::GenerateRecoveryAndHgaKeys)?;
        let distinct: BTreeSet<[u8; 32]> = approvers
            .iter()
            .map(|approver| *approver.key_thumbprint.as_bytes())
            .collect();
        if distinct.len() < 2 {
            return Err(AdminError::BootstrapQuorumMissing);
        }
        // Ein Approver ist ein WEITERER Schluessel. Waere er die Wurzel, der
        // Recovery- oder der HGA-Schluessel, genehmigte in `:1341` eine Partei
        // sich selbst — und die Trennung, um deretwillen `:1340` zwei getrennte
        // Schluessel verlangt, waere im naechsten Schritt wieder aufgehoben.
        for own in self.own_key_thumbprints() {
            if distinct.contains(own.as_bytes()) {
                return Err(AdminError::BootstrapQuorumMissing);
            }
        }
        let snapshot = self.state.clone();
        self.state.approvers = approvers.to_vec();
        self.commit(snapshot, BootstrapStep::EnrollKeyApprovers)
    }

    /// Schritt 7: je mindestens zwei getrennte, VERIFIZIERTE Sicherungen fuer
    /// Root, Admin, Recovery und HGA (`:1342`).
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 6 fehlt;
    /// [`AdminError::BootstrapQuorumMissing`], wenn eine der vier Klassen
    /// fehlt, eine Sicherung auf weniger als zwei UNTERSCHEIDBAREN Medien
    /// verifiziert wurde oder eine Sicherung einen anderen Schluessel nennt
    /// als den, den diese Zeremonie unter dieser Klasse fuehrt; jeder Befund
    /// des Ports.
    pub fn verify_key_backups(&mut self, backups: &[KeyBackupRecordV1]) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::EnrollKeyApprovers)?;
        let classes: BTreeSet<BackedUpKeyClass> =
            backups.iter().map(|backup| backup.class).collect();
        if !BackedUpKeyClass::ALL
            .iter()
            .all(|class| classes.contains(class))
        {
            return Err(AdminError::BootstrapQuorumMissing);
        }
        for backup in backups {
            let distinct: BTreeSet<AnchorMediumId> = backup.media.iter().copied().collect();
            if distinct.len() < 2 {
                return Err(AdminError::BootstrapQuorumMissing);
            }
            // Gesichert werden muss der Schluessel DIESER Zeremonie. Ohne
            // diesen Vergleich erfuellten vier unbeteiligte Abdruecke `:1342`
            // vollstaendig — und die Sicherung, auf die es ankommt, gaebe es
            // trotzdem nicht.
            let expected = match backup.class {
                BackedUpKeyClass::Root => Some(
                    self.state
                        .root
                        .as_ref()
                        .ok_or(AdminError::BootstrapStepOutOfOrder)?
                        .key_thumbprint,
                ),
                BackedUpKeyClass::RecoveryKem => Some(
                    self.state
                        .recovery_kem
                        .as_ref()
                        .ok_or(AdminError::BootstrapStepOutOfOrder)?
                        .key_thumbprint,
                ),
                BackedUpKeyClass::HistoricalGrantAuthority => Some(
                    self.state
                        .hga_signing
                        .as_ref()
                        .ok_or(AdminError::BootstrapStepOutOfOrder)?
                        .key_thumbprint,
                ),
                // Die Admin-Schluessel: Schritt 3 haelt von ihnen die
                // Objekthashes von Zertifikat und Bindung fest, nicht ihre
                // RFC-9679-Abdruecke — die stehen in den Zertifikaten, und die
                // liegen dieser Scheibe nicht vor. Geprueft wird deshalb, was
                // sich hier pruefen laesst: dass die Admin-Sicherung nicht eine
                // der DREI anderen Klassen noch einmal ist.
                BackedUpKeyClass::Admin => None,
            };
            match expected {
                Some(expected) if expected != backup.key_thumbprint => {
                    return Err(AdminError::BootstrapQuorumMissing);
                }
                Some(_) => {}
                None => {
                    if self.own_key_thumbprints().contains(&backup.key_thumbprint) {
                        return Err(AdminError::BootstrapQuorumMissing);
                    }
                }
            }
        }
        let snapshot = self.state.clone();
        self.state.backups = backups.to_vec();
        self.commit(snapshot, BootstrapStep::VerifyKeyBackups)
    }

    /// Schritt 8: Writer-, Server- und erste Reader-Schluessel samt ihren
    /// `operatorBinding`-Objekten (`:1343`).
    ///
    /// Der Koordinator haelt die entstandenen Paare fest; erzeugt werden sie
    /// auf den jeweiligen Geraeten, nicht hier.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 7 fehlt;
    /// [`AdminError::BootstrapQuorumMissing`] fuer eine leere Liste; jeder
    /// Befund des Ports.
    pub fn provision_component_keys(
        &mut self,
        components: &[ComponentBindingV1],
    ) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::VerifyKeyBackups)?;
        if components.is_empty() {
            return Err(AdminError::BootstrapQuorumMissing);
        }
        let snapshot = self.state.clone();
        self.state.components = components.to_vec();
        self.commit(snapshot, BootstrapStep::ProvisionComponentKeys)
    }

    /// Schritt 9: Fingerprints ueber QR-Code oder zweiten Kanal vergleichen
    /// (`:1344`).
    ///
    /// Die Bestaetigung wird VERBRAUCHT und muss ueber die Vorstufe DIESER
    /// Zeremonie ausgestellt worden sein.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 8 fehlt;
    /// [`AdminError::SecondChannelMismatch`], wenn die Bestaetigung einen
    /// anderen Fingerprint traegt als die versiegelte Vorstufe; jeder Befund
    /// des Ports.
    pub fn compare_fingerprints(
        &mut self,
        fingerprint_confirmed: SecondChannelConfirmation,
    ) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::ProvisionComponentKeys)?;
        let sealed = self
            .state
            .sealed_pre_anchor_fingerprint
            .ok_or(AdminError::BootstrapPreAnchorUnconfirmed)?;
        // Die Bestaetigung deckt genau EINE Vorstufe. Sie wird hier ueber die
        // Medien gefuehrt, weil `confirm_on_media` die einzige Stelle ist, die
        // eine `SecondChannelConfirmation` an Bytes bindet — und die Bytes
        // sind die versiegelten.
        let exact_bytes = self
            .state
            .exact_pre_anchor_bytes
            .clone()
            .ok_or(AdminError::BootstrapPreAnchorUnconfirmed)?;
        let mut mirror = ConfirmedMedia::new(&exact_bytes);
        let confirmation = confirm_on_media(
            &mut mirror,
            &[SEALED_MIRROR_FIRST, SEALED_MIRROR_SECOND],
            &exact_bytes,
            fingerprint_confirmed,
        )?;
        if confirmation.fingerprint() != sealed {
            return Err(AdminError::SecondChannelMismatch);
        }
        let snapshot = self.state.clone();
        self.state.fingerprints_compared = true;
        self.commit(snapshot, BootstrapStep::CompareFingerprints)
    }

    /// Schritt 10: ein admin-autorisiertes, Wurzel-signiertes Trust-Objekt
    /// veroeffentlichen (`:1345`).
    ///
    /// Der Koordinator SIGNIERT NICHT selbst — er reicht unveraendert an
    /// [`RootCeremonyService::publish_authorized_target`] durch und haelt
    /// danach den `objectHash` des entstandenen Objekts fest.
    ///
    /// # Was hier geprueft wird, und was NICHT
    ///
    /// Geprueft wird die ORGANISATION: beide Sperrschluessel der
    /// Administrationsautorisierung nennen sie
    /// (`crates/ea-trust/src/admin_authorization.rs:138`,
    /// `crates/ea-trust/src/state.rs:194-197`), und ein Ziel einer anderen
    /// gehoert nicht in diese Zeremonie.
    ///
    /// NICHT geprueft wird der Pre-Registry-Nullkontext aus `:1124-1145` — die
    /// Regel, dass vor der ersten Registrierungsfassung ausschliesslich die im
    /// Anker gepinnten Admin-Paare autorisieren duerfen. Der Beweiszustand,
    /// den dieser Schritt entgegennimmt, entsteht in `ea-trust`, und ob jene
    /// Regel dort auf DIESEM Weg durchgesetzt wird, sagt dieser Koordinator
    /// nicht — er kann es an einem [`VerifiedAdminAuthorizationIntent`] auch
    /// nicht ablesen. Die Ketten-ID kann er ebenfalls nicht vergleichen: die
    /// Autorisierung nennt keine.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 9 fehlt;
    /// [`AdminError::BootstrapContextMismatch`], wenn die Autorisierung eine
    /// andere Organisation nennt; jeder Befund von
    /// [`RootCeremonyService::publish_authorized_target`]; jeder Befund des
    /// Ports.
    pub fn root_sign_bootstrap_target(
        &mut self,
        service: &RootCeremonyService<'_>,
        intent: &VerifiedAdminAuthorizationIntent,
        target: TrustPayloadV1,
        exact_admin_authorization_object: &[u8],
        trust_store: &mut dyn TrustStateStore,
        proof: &OperatorSessionProof,
    ) -> Result<ExactObjectBytes, AdminError> {
        self.require_completed(BootstrapStep::CompareFingerprints)?;
        // Die Autorisierung nennt ihre Organisation in beiden Sperrschluesseln
        // (`crates/ea-trust/src/admin_authorization.rs:138`). Ein Ziel einer
        // ANDEREN Organisation gehoert nicht in diese Zeremonie — der
        // Koordinator haelt danach seinen Objekthash fest, und ein Transkript,
        // das ueber zwei Organisationen spraeche, waere keines.
        if intent
            .replay_keys()
            .iter()
            .any(|key| key.organization_id() != self.state.organization_id)
        {
            return Err(AdminError::BootstrapContextMismatch);
        }
        let published = service.publish_authorized_target(
            intent,
            target,
            exact_admin_authorization_object,
            trust_store,
            proof,
        )?;
        let snapshot = self.state.clone();
        self.state
            .published_target_object_hashes
            .push(object_hash(published.as_bytes()));
        self.commit(snapshot, BootstrapStep::RootSignBootstrapTargets)?;
        Ok(published)
    }

    /// Schritt 11: Genesis und der finale Anker (`:1346`).
    ///
    /// Der finale Anker wird dekodiert, gegen die in Schritt 4 VERSIEGELTE
    /// Vorstufe gehalten ([`verify_anchor_transition`]) und muss genau den
    /// Genesis-Eintragshash nennen, den [`GenesisBinding`] traegt. Danach
    /// gehen seine EXAKTEN Bytes auf dieselben Medien, die Schritt 4
    /// festgeschrieben hat, und ihr voller Fingerprint muss ueber den zweiten
    /// Kanal zurueckgemeldet worden sein — `:1346`: „die finalen Anchor-Bytes
    /// auf beiden Medien sowie ihr voller Fingerprint werden erneut ueber den
    /// zweiten Kanal bestaetigt", `:1780`: „Mindestens zwei schreibgeschuetzte
    /// Recovery-Medien erhalten zuerst die exakten Vorstufen- und vor Go-live
    /// die finalen Anchor-Bytes". Erst danach entsteht das Wurzel-signierte
    /// [`BootstrapTranscriptV1`].
    ///
    /// # Warum der Fingerprint hier ein [`Hash32`] ist und keine
    /// [`SecondChannelConfirmation`]
    ///
    /// Weil es fuer die finalen Ankerbytes keine gibt: der einzige
    /// Konstruktor, [`crate::confirm_pre_anchor_fingerprint`], bindet an eine
    /// [`PreAnchorV1`] und damit an die VORSTUFENbytes
    /// (`crates/ea-admin/src/anchor_media.rs:164-174`). Eine Bestaetigung
    /// ueber die Vorstufe deckt den finalen Anker nicht — sie wird hier
    /// folgerichtig mit `EA-CEREMONY-SECOND-CHANNEL-MISMATCH` abgewiesen.
    /// Der Vergleich ist derselbe, den [`confirm_on_media`] fuer Schritt 4
    /// fuehrt: der gemeldete Wert gegen den, den diese Maschine ueber genau
    /// diese Bytes rechnet.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 10 fehlt;
    /// [`AdminError::Trust`], wenn die Ankerbytes kein
    /// `organization-trust-anchor-v1` sind;
    /// [`AdminError::AnchorPreFieldChanged`] mit
    /// `EA-ANCHOR-PRE-FIELD-CHANGED`, wenn der Anker eine ANDERE Vorstufe
    /// fortsetzt — die Zeremonie ist danach ABGEBROCHEN;
    /// [`AdminError::GenesisContextMismatch`], wenn der Anker einen anderen
    /// Genesis nennt; [`AdminError::SecondChannelMismatch`],
    /// [`AdminError::MediaQuorumMissing`] und
    /// [`AdminError::MediaReadbackMismatch`] fuer die Bestaetigung der finalen
    /// Ankerbytes auf den versiegelten Medien; [`AdminError::Key`] fuer die
    /// Wurzelsignatur des Transkripts und
    /// [`AdminError::RootSignatureMismatch`], wenn diese Signatur der Wurzel
    /// nicht zuschreibbar ist; jeder Befund des Ports.
    pub fn create_genesis_and_final_anchor(
        &mut self,
        key_provider: &dyn KeyProvider,
        genesis: &GenesisBinding,
        exact_final_anchor_bytes: &[u8],
        media: &mut dyn AnchorMedia,
        media_ids: &[AnchorMediumId],
        reported_final_anchor_fingerprint: Hash32,
    ) -> Result<TrustAnchorV1, AdminError> {
        self.require_completed(BootstrapStep::RootSignBootstrapTargets)?;
        let sealed = self
            .pre_anchor
            .as_ref()
            .ok_or(AdminError::BootstrapPreAnchorUnconfirmed)?;
        if self.state.sealed_pre_anchor_fingerprint.is_none() {
            return Err(AdminError::BootstrapPreAnchorUnconfirmed);
        }
        let final_anchor =
            decode_trust_anchor(exact_final_anchor_bytes).map_err(AdminError::Trust)?;
        if let Err(error) = verify_anchor_transition(sealed, &final_anchor) {
            self.abort()?;
            return Err(error);
        }
        if final_anchor.genesis_entry_hash() != genesis.genesis_entry_hash() {
            return Err(AdminError::GenesisContextMismatch);
        }
        // Erst NACH dem Uebergangsurteil: ein Anker, der eine fremde Vorstufe
        // fortsetzt, darf gar nicht erst auf ein schreibgeschuetztes Medium
        // gelangen.
        confirm_final_anchor_on_media(
            media,
            media_ids,
            &self.state.sealed_media,
            &final_anchor,
            exact_final_anchor_bytes,
            reported_final_anchor_fingerprint,
        )?;
        let transcript = self.sign_transcript(key_provider)?;
        let snapshot = self.state.clone();
        self.state.genesis_entry_hash = Some(genesis.genesis_entry_hash());
        self.state.exact_final_anchor_bytes = Some(exact_final_anchor_bytes.to_vec());
        self.state.transcript = Some(transcript);
        self.commit(snapshot, BootstrapStep::CreateGenesisAndFinalAnchor)?;
        Ok(final_anchor)
    }

    /// Schritt 12: der Frischrechner-Recovery-Test — und erst damit
    /// [`ProductionState::Ready`] (`:1347`, `:1349`).
    ///
    /// Der Nachweis wird VERBRAUCHT.
    ///
    /// # Was hier NOCH einmal geprueft wird — und warum
    ///
    /// [`crate::verify_fresh_machine_recovery_test`] faellt sein Urteil ueber
    /// EINE Beobachtung; es kennt die Zeremonie nicht und bekommt den
    /// Zeremonienrechner vom Aufrufer genannt. Der Aufrufer ist aber die
    /// Partei, die [`ProductionState::Ready`] will. Drei Bindungen fallen
    /// deshalb hier, wo die Zeremonie steht:
    ///
    /// 1. **Der Rechner.** Verglichen wird gegen den, den Schritt 1
    ///    festgehalten hat, nicht gegen den, den Schritt 12 nennt. Hat diese
    ///    Zeremonie keinen Rechner festgehalten, laesst sich „nicht derselbe"
    ///    ueber nichts messen — und dann gibt es keine Freigabe.
    /// 2. **Der Anker.** `:1347` verlangt den Test „mit explizitem finalem
    ///    Trust Anchor"; gemeint ist der aus Schritt 11 dieser Zeremonie. Ein
    ///    vollstaendig gelungener Lauf gegen den Anker einer FREMDEN
    ///    Organisation ist ein bestandener Test — nur nicht dieser.
    /// 3. **Die Medien.** Ein Lauf, der weniger Medien erwartet hat, als
    ///    Schritt 4 versiegelt hat, hat den Bestand nicht vollstaendig
    ///    geprueft.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStepOutOfOrder`], wenn Schritt 11 fehlt;
    /// [`AdminError::RecoveryTestSameMachine`], wenn der Test auf der
    /// Zeremonienmaschine lief oder diese Zeremonie keine benannt hat;
    /// [`AdminError::RecoveryTestFailed`], wenn der Lauf einen anderen Anker
    /// oder zu wenige Medien geprueft hat; [`AdminError::Trust`] fuer
    /// Ankerbytes, die sich nicht mehr dekodieren lassen; jeder Befund des
    /// Ports.
    pub fn record_fresh_machine_recovery_test(
        &mut self,
        proof: FreshMachineRecoveryProof,
    ) -> Result<ProductionState, AdminError> {
        self.require_completed(BootstrapStep::CreateGenesisAndFinalAnchor)?;
        let ceremony_machine = self
            .state
            .ceremony_machine
            .ok_or(AdminError::RecoveryTestSameMachine)?;
        if proof.machine_fingerprint() == ceremony_machine {
            return Err(AdminError::RecoveryTestSameMachine);
        }
        let exact_final_anchor_bytes = self
            .state
            .exact_final_anchor_bytes
            .as_deref()
            .ok_or(AdminError::BootstrapStepOutOfOrder)?;
        let final_anchor =
            decode_trust_anchor(exact_final_anchor_bytes).map_err(AdminError::Trust)?;
        if proof.expected_trust_anchor_hash() != final_anchor.trust_anchor_hash()
            || proof.media_expected() < self.state.sealed_media.len()
        {
            return Err(AdminError::RecoveryTestFailed);
        }
        let snapshot = self.state.clone();
        self.state.recovery_test_machine = Some(proof.machine_fingerprint());
        self.state.production_state = ProductionState::Ready;
        self.commit(snapshot, BootstrapStep::RunFreshMachineRecoveryTest)?;
        Ok(self.state.production_state)
    }

    // -- innere Bewegungen -------------------------------------------------

    /// Die Abdruecke der Schluessel, die DIESE Zeremonie selbst fuehrt.
    ///
    /// Wurzel, Recovery-KEM und Historical Grant Authority — die drei, deren
    /// Abdruecke der Zeremoniezustand kennt. Die Admin-Schluessel stehen nicht
    /// darin: von ihnen haelt Schritt 3 Objekthashes und keine
    /// RFC-9679-Abdruecke fest.
    fn own_key_thumbprints(&self) -> Vec<KeyThumbprint> {
        let mut thumbprints = Vec::new();
        if let Some(root) = self.state.root.as_ref() {
            thumbprints.push(root.key_thumbprint);
        }
        if let Some(recovery) = self.state.recovery_kem.as_ref() {
            thumbprints.push(recovery.key_thumbprint);
        }
        if let Some(hga) = self.state.hga_signing.as_ref() {
            thumbprints.push(hga.key_thumbprint);
        }
        thumbprints
    }

    fn require_completed(&self, step: BootstrapStep) -> Result<(), AdminError> {
        if self.state.aborted {
            return Err(AdminError::AnchorPreFieldChanged);
        }
        if self.state.step < step {
            return Err(AdminError::BootstrapStepOutOfOrder);
        }
        Ok(())
    }

    fn require_sealed(&self) -> Result<(), AdminError> {
        self.require_completed(BootstrapStep::CreateAdminPairs)?;
        if self.state.sealed_pre_anchor_fingerprint.is_none()
            || self.state.step < BootstrapStep::PinPreAnchorOnMedia
        {
            return Err(AdminError::BootstrapPreAnchorUnconfirmed);
        }
        Ok(())
    }

    fn require_unsealed(&self) -> Result<(), AdminError> {
        if self.state.sealed_pre_anchor_fingerprint.is_some() {
            return Err(AdminError::AnchorPreFieldChanged);
        }
        Ok(())
    }

    /// Baut die Vorstufe aus dem aktuellen Zustand neu — und faellt mit
    /// [`AdminError::AnchorPreFieldChanged`], wenn sie bereits versiegelt ist
    /// und sich dabei aendert.
    ///
    /// Sie bricht die Zeremonie NICHT selbst ab: der Aufrufer hat den Zustand
    /// veraendert, also setzt der Aufrufer ihn zurueck und entscheidet ueber
    /// den Abbruch.
    fn rebuild_pre_anchor(&mut self) -> Result<(), AdminError> {
        let Some(root) = self.state.root.clone() else {
            return Ok(());
        };
        if self.state.admin_pairs.len() < 2 {
            return Ok(());
        }
        let mut certificates: Vec<ObjectHash> = self
            .state
            .admin_pairs
            .iter()
            .map(|pair| pair.certificate_object_hash)
            .collect();
        let mut bindings: Vec<ObjectHash> = self
            .state
            .admin_pairs
            .iter()
            .map(|pair| pair.operator_binding_object_hash)
            .collect();
        certificates.sort_unstable_by_key(|hash| *hash.as_bytes());
        bindings.sort_unstable_by_key(|hash| *hash.as_bytes());
        let pre = encode_pre_anchor_v1(
            self.state.organization_id,
            self.state.chain_id,
            &root.exact_public_cose_key,
            root.key_thumbprint,
            root.certificate_object_hash,
            &certificates,
            &bindings,
        )
        .map_err(AdminError::Trust)?;
        if let Some(sealed) = self.state.exact_pre_anchor_bytes.as_deref()
            && self.state.sealed_pre_anchor_fingerprint.is_some()
            && sealed != pre.exact_bytes()
        {
            // Diese Funktion PERSISTIERT nicht und bricht nicht ab; sie
            // stellt nur fest. Der Abbruch gehoert dem Aufrufer, weil nur er
            // den Zustand vorher wieder stimmig machen kann.
            return Err(AdminError::AnchorPreFieldChanged);
        }
        self.state.exact_pre_anchor_bytes = Some(pre.exact_bytes().to_vec());
        self.pre_anchor = Some(pre);
        Ok(())
    }

    fn abort(&mut self) -> Result<(), AdminError> {
        let snapshot = self.state.clone();
        self.state.aborted = true;
        if let Err(error) = self.store.store(&self.state) {
            self.restore(snapshot);
            return Err(error);
        }
        Ok(())
    }

    /// Der Zustand, wie er VOR der laufenden Bewegung war.
    ///
    /// [`PreAnchorV1`] traegt kein `Clone`; die Vorstufe wird deshalb aus den
    /// zurueckgelegten Bytes neu gelesen. Das ist keine Naeherung: dieselben
    /// Bytes ergeben dieselbe Vorstufe, und `ea-trust` bleibt die einzige
    /// Stelle, die sie deutet.
    fn restore(&mut self, snapshot: BootstrapStateV1) {
        self.pre_anchor = snapshot
            .exact_pre_anchor_bytes
            .as_deref()
            .and_then(|bytes| decode_pre_anchor(bytes).ok());
        self.state = snapshot;
    }

    /// Persistiert den erreichten Schritt — und laesst den Zustand im Speicher
    /// nur dann stehen, wenn die Ablage ihn AUCH hat.
    ///
    /// # Warum der Rueckfall vollstaendig ist und nicht nur der Schritt
    ///
    /// Der Aufrufer hat vor diesem Aufruf Felder gesetzt; `snapshot` ist der
    /// Zustand von VOR jenen Feldern. Scheitert die Ablage, meldet der
    /// Aufrufer einen Fehlschlag — und ein Koordinator, der danach trotzdem
    /// die neuen Felder truege, widerspraeche seiner eigenen Meldung. Am
    /// teuersten waere das in Schritt 12: [`Self::production_state`] meldete
    /// [`ProductionState::Ready`] fuer eine Zeremonie, von der nichts
    /// persistiert ist.
    ///
    /// Ein RUECKWAERTS gerichteter Schritt wird abgewiesen, bevor irgendetwas
    /// geschrieben wird — die Zeremonie ist ausschliesslich vorwaerts
    /// gerichtet, und ihre Ablage prueft dasselbe noch einmal
    /// ([`crate::FileBootstrapStore`]).
    fn commit(
        &mut self,
        snapshot: BootstrapStateV1,
        step: BootstrapStep,
    ) -> Result<(), AdminError> {
        if step < self.state.step {
            self.restore(snapshot);
            return Err(AdminError::BootstrapStepRegression);
        }
        self.state.step = step;
        if let Err(error) = self.store.store(&self.state) {
            self.restore(snapshot);
            return Err(error);
        }
        Ok(())
    }

    fn sign_transcript(
        &self,
        key_provider: &dyn KeyProvider,
    ) -> Result<BootstrapTranscriptV1, AdminError> {
        let root = self
            .state
            .root
            .as_ref()
            .ok_or(AdminError::BootstrapStepOutOfOrder)?;
        let fingerprint = self
            .state
            .sealed_pre_anchor_fingerprint
            .ok_or(AdminError::BootstrapPreAnchorUnconfirmed)?;
        let exact_bytes = transcript_exact_bytes(&self.state, root, fingerprint);
        let digest = object_hash(&exact_bytes);
        let certificate_hash = CertificateHash::from(root.certificate_object_hash);
        let signature = key_provider
            .sign(
                &root.signing_handle,
                ContentType::TrustDigest,
                certificate_hash,
                digest.as_bytes(),
            )
            .map_err(AdminError::Key)?;
        require_root_attribution(root, signature.as_bytes(), digest.as_bytes())?;
        Ok(BootstrapTranscriptV1 {
            organization_id: self.state.organization_id,
            chain_id: self.state.chain_id,
            root_certificate_object_hash: root.certificate_object_hash,
            admin_pairs: self.state.admin_pairs.clone(),
            pre_anchor_fingerprint: fingerprint,
            exact_bytes,
            root_signature: signature.as_bytes().to_vec(),
        })
    }
}

/// Prueft, dass die eben erzeugte COSE der WURZEL dieser Zeremonie
/// zuschreibbar ist.
///
/// # Warum das Transkript diese Pruefung braucht
///
/// Es ist der einzige Wurzel-signierte Gegenstand, den dieser Koordinator
/// SELBST hervorbringt — und er wird persistiert und weitergereicht, ohne dass
/// irgendwo im Baum jemand ihn nachprueft. Ein Schluesselport, der im
/// geschuetzten Kopf den Abdruck der Wurzel NENNT und mit einem anderen
/// Schluessel unterschreibt, kaeme sonst durch: `CoseSign1Bytes::compose` liest
/// seine Bytes nur gegen `parse_cose_sign1` zurueck, und das prueft keine
/// Signatur.
///
/// Dieselbe Bewegung und derselbe Grund wie
/// [`RootCeremonyService::require_root_attribution`]
/// (`crates/ea-admin/src/root_ceremony.rs:329-360`); der Unterschied ist
/// allein, woher die zwei oeffentlichen Werte der Wurzel kommen — dort aus dem
/// gewaehlten Registrierungskopf, hier aus dem Wurzelmaterial, das Schritt 2
/// festgehalten hat. Vor Schritt 10 gibt es keinen Kopf.
fn require_root_attribution(
    root: &RootKeyMaterialV1,
    exact_cose: &[u8],
    expected_payload: &[u8],
) -> Result<(), AdminError> {
    let certificate_hash = CertificateHash::from(root.certificate_object_hash);
    let parsed = parse_cose_sign1(exact_cose, &[]).map_err(AdminError::Crypto)?;
    if parsed.content_type() != ContentType::TrustDigest
        || parsed.certificate_hash() != Some(certificate_hash)
        || parsed.payload() != expected_payload
        || parsed.key_thumbprint() != root.key_thumbprint
    {
        return Err(AdminError::RootSignatureMismatch);
    }
    let key = CanonicalPublicCoseKey::from_deterministic_cbor(&root.exact_public_cose_key)
        .map_err(AdminError::Crypto)?;
    let protected = ProtectedHeader::normal(
        ContentType::TrustDigest,
        parsed.key_thumbprint(),
        certificate_hash,
    );
    key.verify_ed25519_strict(
        &protected.sig_structure_bytes(expected_payload),
        parsed.signature_bytes(),
    )
    .map_err(|_| AdminError::RootSignatureMismatch)
}

/// Schreibt die finalen Ankerbytes auf DIESELBEN Medien, die Schritt 4
/// festgeschrieben hat, und liest sie von jedem zurueck (`:1346`, `:1780`).
///
/// Die Reihenfolge ist die von [`confirm_on_media`], und aus denselben
/// Gruenden: erst die Bindung an den zweiten Kanal, dann das Medienquorum,
/// dann alle Schreibvorgaenge, erst danach die Lesevorgaenge — sonst
/// bestaetigte das erste Medium sich selbst, waehrend das zweite noch die
/// Vorstufe truege.
///
/// Verlangt werden GENAU die versiegelten Medien. „Auf beiden Medien" (`:1346`)
/// meint dieselben beiden: zwei frische Datentraeger truegen den finalen Anker
/// zwar, aber die zwei, auf denen die Vorstufe steht, blieben mit einem
/// Bestand zurueck, der vor Go-live stehen geblieben ist.
fn confirm_final_anchor_on_media(
    media: &mut dyn AnchorMedia,
    ids: &[AnchorMediumId],
    sealed_media: &[AnchorMediumId],
    final_anchor: &TrustAnchorV1,
    exact_bytes: &[u8],
    reported_fingerprint: Hash32,
) -> Result<(), AdminError> {
    // GENAU die versiegelten Medien. „Auf beiden Medien" (`:1346`) meint
    // dieselben beiden: zwei frische Datentraeger truegen den finalen Anker
    // zwar, aber die zwei, auf denen die Vorstufe steht, blieben mit einem
    // Bestand zurueck, der vor Go-live stehen geblieben ist. Diese Frage
    // gehoert hierher, weil nur die Zeremonie weiss, was sie versiegelt hat.
    let distinct: Vec<AnchorMediumId> = ids
        .iter()
        .copied()
        .collect::<BTreeSet<AnchorMediumId>>()
        .into_iter()
        .collect();
    if distinct.len() != ids.len() || distinct != sealed_media {
        return Err(AdminError::MediaQuorumMissing);
    }

    // Alles Weitere — die Bindung an die Bytes, das Quorum, erst alle
    // Schreib-, dann alle Lesevorgaenge — ist WORTGLEICH das, was Schritt 4
    // tut. Es steht deshalb genau einmal, in `confirm_on_media`. Der
    // Unterschied liegt allein in der Domaene des Fingerprints, und die reist
    // in der Bestaetigung mit: `confirm_final_anchor_fingerprint` stellt sie
    // ueber `trustAnchorHash` aus (`:1774-1777`), nicht ueber
    // `bootstrapAnchorHash`.
    let confirmation = confirm_final_anchor_fingerprint(final_anchor, reported_fingerprint)?;
    confirm_on_media(media, ids, exact_bytes, confirmation)?;
    Ok(())
}

/// Weist eine Admin-Paarmenge zurueck, die die Eins-zu-eins-Paarung aus
/// `:1780` gar nicht tragen KANN.
///
/// # Was hier geprueft wird — und was ausdruecklich nicht
///
/// `:1766` bindet Zertifikat und Bindung ueber
/// `operatorBinding.deviceCertificateHash` aneinander. Diese Gleichung steht
/// IM Bindungsobjekt, und dieser Scheibe liegen von beiden nur die
/// Objekthashes vor — sie kann die Paarung also nicht nachrechnen. Was sie
/// sehen kann, ist der Fall, in dem gar keine Eins-zu-eins-Paarung existieren
/// kann: zwei Paare, die sich ein Zertifikat oder eine Bindung teilen, und ein
/// Paar, das zweimal denselben Objekthash nennt. Der Befund faellt damit hier,
/// wo die Zeremonie laeuft, und nicht beim ersten `verify_trust`, wenn die
/// Vorstufe laengst auf schreibgeschuetzten Medien steht und das einzige
/// Heilmittel eine ganz neue Zeremonie ist.
fn require_distinct_pairing(pairs: &[AdminBootstrapPairV1]) -> Result<(), AdminError> {
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for pair in pairs {
        if !seen.insert(*pair.certificate_object_hash.as_bytes())
            || !seen.insert(*pair.operator_binding_object_hash.as_bytes())
        {
            return Err(AdminError::BootstrapQuorumMissing);
        }
    }
    Ok(())
}

/// Die exakten Transkriptbytes zu einem Zeremoniezustand.
///
/// EINE Stelle fuer zwei Aufrufer — [`BootstrapCoordinator::sign_transcript`]
/// baut sie, [`BootstrapStateV1::decode_image`] rechnet sie nach. Zwei Stellen
/// waeren zwei Wahrheiten darueber, worueber die Wurzel unterschrieben hat,
/// und der Wiedereinleser verglaeche gegen die falsche.
fn transcript_exact_bytes(
    state: &BootstrapStateV1,
    root: &RootKeyMaterialV1,
    pre_anchor_fingerprint: Hash32,
) -> Vec<u8> {
    let mut exact_bytes = Vec::new();
    exact_bytes.extend_from_slice(TRANSCRIPT_DOMAIN);
    exact_bytes.extend_from_slice(state.organization_id.as_bytes());
    exact_bytes.extend_from_slice(state.chain_id.as_bytes());
    exact_bytes.extend_from_slice(root.certificate_object_hash.as_bytes());
    exact_bytes.extend_from_slice(root.key_thumbprint.as_bytes());
    push_slice(&mut exact_bytes, &root.exact_public_cose_key);
    push_count(&mut exact_bytes, state.admin_pairs.len());
    for pair in &state.admin_pairs {
        exact_bytes.extend_from_slice(pair.certificate_object_hash.as_bytes());
        exact_bytes.extend_from_slice(pair.operator_binding_object_hash.as_bytes());
    }
    exact_bytes.extend_from_slice(pre_anchor_fingerprint.as_bytes());
    exact_bytes
}

fn same_root(left: &RootKeyMaterialV1, right: &RootKeyMaterialV1) -> bool {
    left.signing_handle == right.signing_handle
        && left.exact_public_cose_key == right.exact_public_cose_key
        && left.key_thumbprint == right.key_thumbprint
        && left.certificate_object_hash == right.certificate_object_hash
}

fn fresh_ids(
    random: &mut dyn CeremonyRandomSource,
) -> Result<(OrganizationId, ChainId), AdminError> {
    let mut organization = [0_u8; 16];
    random.fill_random(&mut organization)?;
    let mut chain = [0_u8; 16];
    random.fill_random(&mut chain)?;
    let organization_id = OrganizationId::try_from(&organization[..])
        .map_err(|_| AdminError::Crypto(ea_crypto::CryptoError::LocalRng))?;
    let chain_id = ChainId::try_from(&chain[..])
        .map_err(|_| AdminError::Crypto(ea_crypto::CryptoError::LocalRng))?;
    Ok((organization_id, chain_id))
}

/// Die zwei Kennungen des Spiegels aus Schritt 9.
///
/// Schritt 9 schreibt NICHTS auf ein Medium — er vergleicht nur Fingerprints
/// (`:1344`). Die Bindung einer [`SecondChannelConfirmation`] an genau die
/// versiegelten Bytes liegt aber ausschliesslich in [`confirm_on_media`], und
/// ein zweiter Binder waere eine zweite Wahrheit. Der Spiegel ist deshalb ein
/// reiner Speicher, der die bereits versiegelten Bytes zurueckliest.
const SEALED_MIRROR_FIRST: AnchorMediumId = AnchorMediumId::new([0xf1; 16]);
const SEALED_MIRROR_SECOND: AnchorMediumId = AnchorMediumId::new([0xf2; 16]);

struct ConfirmedMedia<'a> {
    sealed: &'a [u8],
}

impl<'a> ConfirmedMedia<'a> {
    const fn new(sealed: &'a [u8]) -> Self {
        Self { sealed }
    }
}

impl AnchorMedia for ConfirmedMedia<'_> {
    fn write_exact_bytes(
        &mut self,
        _medium: AnchorMediumId,
        exact_bytes: &[u8],
    ) -> Result<(), AdminError> {
        if exact_bytes == self.sealed {
            Ok(())
        } else {
            Err(AdminError::MediaReadbackMismatch)
        }
    }

    fn read_exact_bytes(&self, _medium: AnchorMediumId) -> Result<Vec<u8>, AdminError> {
        Ok(self.sealed.to_vec())
    }
}
