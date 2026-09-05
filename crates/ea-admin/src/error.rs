//! Der Fehlerbegriff der Zeremonie.

use core::fmt;

use ea_crypto::CryptoError;
use ea_format::FormatError;
use ea_key_provider::KeyError;
use ea_trust::TrustError;

/// Ein Fehlschlag an der Grenze des Zeremoniendienstes.
///
/// # Warum das Praefix `EA-CEREMONY-` heisst und nicht `EA-ADMIN-`
///
/// `EA-ADMIN-` ist bereits vergeben, und zwar als AKTIONSCODE-Namensraum der
/// acht Serverzeilen des technischen Verwaltungsaudits
/// (`apps/server/src/admin_audit.rs`, in `docs/traceability/stage-3-gate.md`
/// als „acht `EA-ADMIN-`-Codes" gefuehrt). Jene Codes stehen IN ausgelieferten
/// Auditzeilen und benennen eine Handlung; ein Fehlercode desselben Praefixes
/// benennte einen Abbruch. Beides in einer Familie zu fuehren hiesse, dass ein
/// Leser einer Zeile nicht mehr entscheiden kann, ob `EA-ADMIN-…` eine
/// vollzogene Handlung oder ihr Scheitern meldet.
///
/// `EA-CEREMONY-` benennt stattdessen den Gegenstand dieser Crate — die
/// Zeremonie — und ist im ganzen Baum frei
/// (`grep -o '"EA-[A-Z0-9]*-' crates apps` kennt 45 Familien, diese nicht).
///
/// # Warum `EA-ANCHOR-` eine EIGENE Familie ist und kein `EA-TRUST-ANCHOR-`
///
/// `EA-TRUST-ANCHOR-{SHAPE,HASH,PIN}` (`crates/ea-trust/src/error.rs:35-37`)
/// sind Aussagen ueber Bytes, die man BEREITS HAELT: hat dieses Feld die Form
/// aus `:1737-1748`, ist es in sich stimmig, gehoert der Schluessel zu seinem
/// Abdruck. Alle drei fallen beim Dekodieren.
///
/// `EA-ANCHOR-PRE-FIELD-CHANGED` faellt in einem anderen Moment und ueber einen
/// anderen Gegenstand: waehrend die Zeremonie GEBAUT wird, und ueber das
/// VERHAELTNIS zweier Anker — ein finaler Anker setzt eine ANDERE Vorstufe
/// fort als die, die auf den Medien bestaetigt wurde.
/// [`ea_trust::decode_trust_anchor`] kann das strukturell nicht sehen; es
/// rechnet die Vorstufe aus den eigenen Feldern des finalen Ankers nach
/// (`crates/ea-trust/src/anchor.rs:665-676`) und findet an einer
/// nachtraeglich durchgaengig korrigierten Zeremonie nichts. Anderer Zeitpunkt,
/// anderes Objekt, andere Familie. Das Praefix ist im Baum sonst nirgends
/// vergeben (`grep -ro '"EA-ANCHOR-[A-Z-]*"' crates apps`).
///
/// Die Medien- und Kanalarme bleiben dagegen `EA-CEREMONY-`: sie melden, dass
/// ein SCHRITT der Zeremonie nicht stattgefunden hat, und das ist genau der
/// Gegenstand dieser Crate.
///
/// Die durchgereichten Arme behalten den Code ihrer Herkunft. Insbesondere ist
/// die Wiedereinspielung einer Administrationsautorisierung weiterhin
/// [`TrustError::AuthReplay`] mit `EA-TRUST-AUTH-REPLAY`: die Zusage gehoert
/// `ea-trust`, und ein zweiter Code fuer denselben Befund waere eine zweite
/// Wahrheit.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum AdminError {
    /// Der Bedienernachweis dient einem anderen Zweck, ist abgelaufen oder
    /// durch die Bildschirmsperre entwertet.
    ReauthMismatch,
    /// Der Nachweis gehoert zu einer ANDEREN Bedienerbindung.
    ///
    /// `OperatorSessionProof::is_valid_for` prueft die Bindung ausdruecklich
    /// nicht; dieser Arm ist die Stelle, an der dieser Dienst sie prueft.
    BindingMismatch,
    /// Die Bedienerbindung ist am gewaehlten Kopf nicht aktiv.
    BindingInactive,
    /// Der Beweiszustand wurde gegen einen ANDEREN Registrierungsstand
    /// gefuehrt als den, gegen den dieser Dienst handelt.
    ///
    /// Zeit, Bedienerbindung, Wurzelzertifikat und Auditdienst kommen aus dem
    /// gewaehlten Kopf; ein Beweis aus einem veralteten Bestand duerfte unter
    /// einem aktuellen Kopf nicht wirken.
    HeadMismatch,
    /// Die vorgelegten Autorisierungsbytes sind nicht die, ueber die der
    /// Beweiszustand spricht.
    AuthorizationMismatch,
    /// Die vorgelegte Nutzlast traegt einen anderen Subtyp als den, den der
    /// Beweiszustand deckt.
    TargetMismatch,
    /// Der Zertifikatshash, unter dem dieser Dienst signieren laesst, ist
    /// nicht der der Wurzelurkunde des gewaehlten Kopfes.
    RootCertificateMismatch,
    /// Die erzeugte COSE ist der Wurzel dieses Kopfes NICHT zuschreibbar.
    ///
    /// Ein Arm fuer beide Haelften desselben Befundes: der Schluesselabdruck
    /// im geschuetzten Kopf weicht vom `rootKeyThumbprint` der Wurzelurkunde
    /// ab, ODER die Signatur verifiziert unter deren oeffentlichem Schluessel
    /// nicht. Beides heisst „diese Bytes stammen nicht von der Wurzel", und
    /// ein Aufrufer soll daran keine zwei Faelle unterscheiden muessen.
    RootSignatureMismatch,
    /// Die Auditzeile konnte nicht gebucht werden — die Zielbytes bleiben
    /// zurueck.
    AuditFailed,
    /// Der finale Anker setzt eine ANDERE Vorstufe fort als die, die in
    /// Schritt 4 auf den Medien bestaetigt wurde.
    ///
    /// Die Spezifikation ist an dieser Stelle normativ: „Jede Aenderung eines
    /// bereits in Schritt 4 festgeschriebenen Feldes bricht das Setup ab und
    /// beginnt mit neuen Organisations-/Ketten-IDs"
    /// (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1349`).
    /// Dieser Arm IST dieser Abbruch.
    AnchorPreFieldChanged,
    /// Weniger als zwei UNTERSCHIEDLICHE Medien.
    ///
    /// `:1780` verlangt „mindestens zwei schreibgeschuetzte Recovery-Medien".
    /// Zwei Kennungen fuer dasselbe Medium sind ein Medium; ein Bestand, der
    /// mit einem Datentraeger untergeht, ist kein Bestand.
    MediaQuorumMissing,
    /// Ein Medium liest andere Bytes zurueck, als auf es geschrieben wurden.
    ///
    /// Festgeschrieben ist nur, was NACH dem Schreiben bytegleich wieder
    /// herauskommt.
    MediaReadbackMismatch,
    /// Ein Medium hat auf Schreiben oder Lesen nicht geantwortet.
    MediaUnavailable,
    /// Ein Schritt HINTER dem persistierten wurde betreten.
    ///
    /// Die Zeremonie ist ausschliesslich vorwaerts gerichtet. Auch der Versuch,
    /// eine zweite Zeremonie neben einer bereits persistierten zu beginnen,
    /// faellt hierher: das waeren zwei Wahrheiten ueber dieselbe Organisation.
    BootstrapStepRegression,
    /// Ein Schritt VOR seinem Vorgaenger wurde betreten.
    ///
    /// Ein eigener Arm neben [`Self::BootstrapStepRegression`], weil sich die
    /// Abhilfe unterscheidet: nach vorn fehlt Arbeit, nach hinten ist Arbeit
    /// bereits getan.
    BootstrapStepOutOfOrder,
    /// Die Vorstufe ist noch nicht auf den Medien festgeschrieben und ueber
    /// den zweiten Kanal bestaetigt.
    ///
    /// `:1339` sagt „VOR der ersten Admin-Autorisierung"; jeder Schritt nach
    /// dem vierten laeuft ohne diese Bestaetigung ins Leere, denn er baute auf
    /// einer Vorstufe auf, die sich noch aendern koennte.
    BootstrapPreAnchorUnconfirmed,
    /// Eine der Mindestzahlen aus `:1338`, `:1341`, `:1342` oder `:1343` ist
    /// nicht erreicht.
    ///
    /// Ein Arm fuer alle vier, weil die Folge dieselbe ist: der Schritt hat
    /// nicht stattgefunden. WELCHE Zahl fehlt, gehoert in die Oberflaeche, die
    /// den Schritt fuehrt.
    BootstrapQuorumMissing,
    /// Ein Schritt legt etwas vor, das zu einer ANDEREN Zeremonie gehoert.
    ///
    /// Die zwoelf Schritte reichen Objekte durch, die anderswo entstanden
    /// sind — eine Administrationsautorisierung aus `ea-trust`, eine
    /// Beobachtung aus `ea-recovery`. Jedes davon nennt eine Organisation,
    /// eine Kette oder einen Anker, und keines davon gehoert automatisch zu
    /// der Zeremonie, die es vorgelegt bekommt. Dieser Arm ist der Befund
    /// „gehoert nicht hierher"; er unterscheidet sich von
    /// [`Self::GenesisContextMismatch`] nur im Gegenstand, nicht in der Folge.
    BootstrapContextMismatch,
    /// Die Ablage des Zeremoniezustands hat nicht geantwortet.
    BootstrapStoreUnavailable,
    /// Der persistierte Zeremoniezustand ist nicht mehr deutbar.
    BootstrapStateShape,
    /// Genesis ist nicht Sequenz 0 ohne Vorgaengerbindung.
    ///
    /// `design.md:927`: „Fuer Genesis ist `previous-entry-hash = null`; danach
    /// sind exakt 32 Bytes erforderlich."
    GenesisSequence,
    /// Genesis nennt eine andere Organisation, Kette, Richtlinie oder einen
    /// anderen Registrierungskopf als diese Zeremonie (`:1145`).
    GenesisContextMismatch,
    /// Der Recovery-Test ist als GANZES fehlgeschlagen.
    ///
    /// `:1897`: „Ein fehlendes Medium, falscher Key, abweichender Anchor,
    /// nicht lesbarer Testeintrag oder unvollstaendiges Sample macht den
    /// Gesamttest fehlgeschlagen; Teilerfolg darf nicht als erfolgreicher
    /// Recovery-Test erscheinen." Ein Arm fuer alle fuenf, weil die Folge in
    /// allen fuenf dieselbe ist.
    RecoveryTestFailed,
    /// Der Recovery-Test lief auf der ZEREMONIENMASCHINE.
    ///
    /// `:1347` verlangt „einen frischen Rechner". Das ist kein Teilerfolg des
    /// Tests aus `:1897`, sondern ein anderer Test — deshalb ein eigener Arm.
    RecoveryTestSameMachine,
    /// Der ueber den ZWEITEN Kanal zurueckgemeldete Fingerprint ist nicht der,
    /// den diese Maschine ueber diese Bytes rechnet.
    ///
    /// Deckt beide Haelften desselben Befundes: die Rueckmeldung wich schon
    /// beim Abgleich ab, ODER eine Bestaetigung wird fuer ANDERE Bytes
    /// vorgelegt als die, ueber die sie ausgestellt wurde.
    SecondChannelMismatch,
    /// Ein Befund der Vertrauensschicht, unveraendert durchgereicht.
    Trust(TrustError),
    /// Ein Befund der Kryptografieschicht, unveraendert durchgereicht.
    Crypto(CryptoError),
    /// Ein Befund des Schluesselports, unveraendert durchgereicht.
    Key(KeyError),
    /// Ein Befund der Formatschicht, unveraendert durchgereicht.
    Format(FormatError),
}

impl AdminError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReauthMismatch => "EA-CEREMONY-REAUTH-MISMATCH",
            Self::BindingMismatch => "EA-CEREMONY-BINDING-MISMATCH",
            Self::BindingInactive => "EA-CEREMONY-BINDING-INACTIVE",
            Self::HeadMismatch => "EA-CEREMONY-HEAD-MISMATCH",
            Self::AuthorizationMismatch => "EA-CEREMONY-AUTHORIZATION-MISMATCH",
            Self::TargetMismatch => "EA-CEREMONY-TARGET-MISMATCH",
            Self::RootCertificateMismatch => "EA-CEREMONY-ROOT-CERTIFICATE-MISMATCH",
            Self::RootSignatureMismatch => "EA-CEREMONY-ROOT-SIGNATURE-MISMATCH",
            Self::AuditFailed => "EA-CEREMONY-AUDIT-FAILED",
            Self::AnchorPreFieldChanged => "EA-ANCHOR-PRE-FIELD-CHANGED",
            Self::MediaQuorumMissing => "EA-CEREMONY-MEDIA-QUORUM-MISSING",
            Self::MediaReadbackMismatch => "EA-CEREMONY-MEDIA-READBACK-MISMATCH",
            Self::MediaUnavailable => "EA-CEREMONY-MEDIA-UNAVAILABLE",
            Self::BootstrapStepRegression => "EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION",
            Self::BootstrapStepOutOfOrder => "EA-CEREMONY-BOOTSTRAP-STEP-OUT-OF-ORDER",
            Self::BootstrapPreAnchorUnconfirmed => "EA-CEREMONY-PRE-ANCHOR-UNCONFIRMED",
            Self::BootstrapQuorumMissing => "EA-CEREMONY-BOOTSTRAP-QUORUM-MISSING",
            Self::BootstrapContextMismatch => "EA-CEREMONY-BOOTSTRAP-CONTEXT-MISMATCH",
            Self::BootstrapStoreUnavailable => "EA-CEREMONY-BOOTSTRAP-STORE-UNAVAILABLE",
            Self::BootstrapStateShape => "EA-CEREMONY-BOOTSTRAP-STATE-SHAPE",
            Self::GenesisSequence => "EA-CEREMONY-GENESIS-SEQUENCE",
            Self::GenesisContextMismatch => "EA-CEREMONY-GENESIS-CONTEXT-MISMATCH",
            Self::RecoveryTestFailed => "EA-CEREMONY-RECOVERY-TEST-FAILED",
            Self::RecoveryTestSameMachine => "EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE",
            Self::SecondChannelMismatch => "EA-CEREMONY-SECOND-CHANNEL-MISMATCH",
            Self::Trust(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Key(error) => error.code(),
            Self::Format(error) => error.code(),
        }
    }
}

impl From<TrustError> for AdminError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<CryptoError> for AdminError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<KeyError> for AdminError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<FormatError> for AdminError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for AdminError {}
