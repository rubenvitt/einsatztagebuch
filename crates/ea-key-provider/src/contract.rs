//! Der Port, hinter dem natives Schluesselmaterial liegt.
//!
//! Diese Crate ist die Grenze zwischen dem synchronen Rust-Kern und dem
//! Schluesselspeicher des Betriebssystems. Sie exportiert einen Griff, einen
//! Fehler, zwei disjunkte Zweck-Aufzaehlungen und einen Trait — und
//! ausdruecklich KEIN Schluesselmaterial.

use core::fmt;

use ea_crypto::{ContentType, CryptoError, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_types::{CertificateHash, Hash32};
use minicbor::Encoder;

/// COSE_Sign1 traegt CBOR-Tag 18 (RFC 9052 §4.2).
const COSE_SIGN1_TAG: u64 = 18;

/// Der Anwendungsnamensraum, unter dem jeder Eintrag dieses Produkts liegt.
///
/// Ein Schluesselspeicher adressiert seine Eintraege ueber Dienst und Konto.
/// Der Dienst ist fuer alle Eintraege dieses Produkts derselbe und steht
/// deshalb genau hier.
pub const APPLICATION_NAMESPACE: &str = "de.einsatzarchiv.writer";

/// Der Zweck eines LOKAL eingepackten Geheimnisses DIESES Geraets.
///
/// Scharf getrennt von [`KeyPurpose`]: die beiden Aufzaehlungen sind disjunkt
/// und ausdruecklich NICHT ineinander umwandelbar. Es gibt keine
/// `From`-Implementierung zwischen ihnen, und das ist der Zweck der Trennung —
/// ein fremder Zweck kann nicht versehentlich zu einem lokalen werden.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretPurpose {
    /// Der Signaturschluessel des Writers.
    WriterSigningKey,
    /// Der geraete- und kontogebundene Bedienerschluessel.
    OperatorInstanceKey,
    /// Der Schluessel des laufenden Entwurfs.
    DraftDek,
    /// Der Schluessel der lokalen, vollstaendig verschluesselten Datenbank.
    LocalDatabaseKey,
}

/// Der Zweck FREMDEN Schluesselmaterials.
///
/// Kein privater Schluessel dieser Zwecke existiert je auf einem
/// Writer-Geraet. Die Aufzaehlung existiert, damit die Produktinvariante
/// uebersetzt und nicht nur beschrieben ist: [`WriterKeyProfile::validate`]
/// lehnt jeden dieser Zwecke ab.
///
/// [`WriterKeyProfile::validate`]: crate::WriterKeyProfile::validate
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyPurpose {
    /// Der KEM-Empfaengerschluessel eines Readers.
    ReaderKem,
    /// Der KEM-Empfaengerschluessel der Wiederherstellung.
    RecoveryKem,
    /// Der Signaturschluessel der Historical Grant Authority.
    HistoricalGrantAuthority,
    /// Der Signaturschluessel eines Key Approvers.
    KeyApprover,
}

/// Der Speicher, in dem das Material eines Griffs liegt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeystoreProvider {
    /// Der native Schluesselspeicher des Betriebssystems.
    OperatingSystem,
    /// Der deterministische In-Prozess-Provider von `test-support`.
    InMemory,
}

/// Wie das Betriebssystem einen Eintrag verbreiten darf.
///
/// `design.md`:1491 legt fuer jeden Eintrag dieses Produkts genau eine Politik
/// fest: nicht roamend, nicht cloud-synchronisierend, aus der gewoehnlichen
/// Anwendungs- und Systemsicherung ausgenommen. Deshalb gibt es genau eine
/// Konstante und keinen zweiten Konstruktor.
///
/// Die drei Leser sind kein Selbstzweck: ein nativer Provider muss die Politik
/// in die Kennzeichen seiner Plattform uebersetzen — `kSecAttrSynchronizable`
/// unter macOS, das Roaming-Kennzeichen von DPAPI unter Windows — und liest
/// sie dafuer genau hier ab.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyEntryPolicy {
    roaming: bool,
    cloud_synchronised: bool,
    included_in_ordinary_backup: bool,
}

impl KeyEntryPolicy {
    /// Die einzige Politik, die dieses Produkt kennt.
    pub const DEVICE_LOCAL: Self = Self {
        roaming: false,
        cloud_synchronised: false,
        included_in_ordinary_backup: false,
    };

    #[must_use]
    pub const fn is_roaming(self) -> bool {
        self.roaming
    }

    #[must_use]
    pub const fn is_cloud_synchronised(self) -> bool {
        self.cloud_synchronised
    }

    #[must_use]
    pub const fn is_included_in_ordinary_backup(self) -> bool {
        self.included_in_ordinary_backup
    }
}

/// Ein undurchsichtiger Verweis auf einen Eintrag im Schluesselspeicher.
///
/// Der Griff traegt KEIN Schluesselmaterial und hat keinen Leser, der Bytes
/// eines Schluessels herausgibt; die `compile_fail`-Doctests in
/// [`crate`] belegen das. Er traegt ausschliesslich die Bindung: Speicher,
/// Anwendung, Kontoinstanz, Zweck und Verbreitungspolitik.
///
/// Diese fuenf Stuecke sind zugleich die Adresse des Eintrags. Ein
/// Schluesselspeicher adressiert ueber Dienst und Konto, und dieses Produkt
/// legt je Kontoinstanz genau EINEN Eintrag je Zweck an — es gibt genau einen
/// aktiven Entwurf, einen Writer-Signaturschluessel, einen Bedienerschluessel
/// und eine lokale Datenbank. Zwei Griffe desselben Zwecks derselben
/// Kontoinstanz sind deshalb gleich, und ein zweites Einpacken ERSETZT das
/// erste, statt einen zweiten Eintrag entstehen zu lassen.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct KeyHandle {
    provider: KeystoreProvider,
    application: &'static str,
    account_instance: Hash32,
    purpose: SecretPurpose,
    policy: KeyEntryPolicy,
}

impl KeyHandle {
    /// Baut den Griff auf einen Eintrag.
    ///
    /// Oeffentlich, weil eine Providerimplementierung ausserhalb dieser Crate
    /// liegen kann — der native Provider spaeterer Tasks tut das. Ein gebauter
    /// Griff verschafft nichts: er ist eine Adresse, kein Zugriff, und ein
    /// Provider, der unter ihr nichts findet, meldet
    /// [`KeyError::NotFound`]. Die Verbreitungspolitik setzt dieser
    /// Konstruktor und nicht der Aufrufer.
    #[must_use]
    pub const fn new(
        provider: KeystoreProvider,
        account_instance: Hash32,
        purpose: SecretPurpose,
    ) -> Self {
        Self {
            provider,
            application: APPLICATION_NAMESPACE,
            account_instance,
            purpose,
            policy: KeyEntryPolicy::DEVICE_LOCAL,
        }
    }

    #[must_use]
    pub const fn keystore_provider(&self) -> KeystoreProvider {
        self.provider
    }

    #[must_use]
    pub const fn application(&self) -> &'static str {
        self.application
    }

    /// Die Kontoinstanz, an die der Eintrag gebunden ist.
    ///
    /// Ein Bindungshash, kein Geheimnis: derselbe Wert, den
    /// `ea_crypto::*_os_account_binding_hash` bildet.
    #[must_use]
    pub const fn account_instance(&self) -> Hash32 {
        self.account_instance
    }

    #[must_use]
    pub const fn purpose(&self) -> SecretPurpose {
        self.purpose
    }

    #[must_use]
    pub const fn entry_policy(&self) -> KeyEntryPolicy {
        self.policy
    }

    /// Prueft den Zweck, BEVOR der Provider bemueht wird.
    ///
    /// Ein Griff dient genau einem Zweck. Die Pruefung steht hier und nicht im
    /// Provider, damit sie vor jedem Zugriff auf den Schluesselspeicher
    /// stattfindet und kein Provider sie auslassen kann.
    pub fn require_purpose(&self, admitted: &[SecretPurpose]) -> Result<(), KeyError> {
        if admitted.contains(&self.purpose) {
            Ok(())
        } else {
            Err(KeyError::PurposeMismatch)
        }
    }
}

impl fmt::Debug for KeyHandle {
    /// Nennt die Adresse, nie ein Geheimnis — und auch nicht die Kontoinstanz,
    /// die als Bindungshash in eine Diagnose nichts beitraegt.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyHandle")
            .field("provider", &self.provider)
            .field("application", &self.application)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

/// Die exakten Bytes eines COSE_Sign1.
///
/// Ein Newtype ueber [`Vec<u8>`] IN DIESER CRATE. `ea-crypto` bekommt dadurch
/// keinen Signierport und aendert kein Byte: die Struktur entsteht hier neu,
/// die Logik bleibt dort.
///
/// Aus diesen Bytes fuehrt kein Weg zurueck zu einem Signaturschluessel; der
/// `compile_fail`-Doctest in [`crate`] belegt das.
pub struct CoseSign1Bytes(Vec<u8>);

impl CoseSign1Bytes {
    /// Setzt COSE_Sign1 aus einem geschuetzten Kopf, der Nutzlast und einer
    /// fertigen Signatur zusammen.
    ///
    /// Der Signaturschluessel kommt hier NICHT vor: ein nativer Provider laesst
    /// den Schluesselspeicher ueber
    /// [`ProtectedHeader::sig_structure_bytes`] signieren und uebergibt nur das
    /// Ergebnis. Genau deshalb komponiert dieser Port die Bytes selbst, statt
    /// `ea_crypto::CoseSigner` zu bemuehen, dessen einziger Konstruktor den
    /// privaten Schluessel verlangt.
    ///
    /// Das Ergebnis wird gegen `ea_crypto::parse_cose_sign1` gegengelesen; was
    /// diese Crate herausgibt, ist damit immer ein wohlgeformtes COSE_Sign1.
    pub fn compose(
        protected: &ProtectedHeader,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<Self, KeyError> {
        let exact_protected = protected.to_deterministic_cbor();
        let mut bytes = Vec::with_capacity(80 + exact_protected.len() + payload.len());
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .tag(minicbor::data::Tag::new(COSE_SIGN1_TAG))
            .and_then(|encoder| encoder.array(4))
            .and_then(|encoder| encoder.bytes(&exact_protected))
            .and_then(|encoder| encoder.map(0))
            .and_then(|encoder| encoder.bytes(payload))
            .and_then(|encoder| encoder.bytes(signature))
            .map_err(|_| KeyError::Crypto(CryptoError::InvalidCose))?;
        ea_crypto::parse_cose_sign1(&bytes, &[]).map_err(KeyError::Crypto)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Der Fehler eines Schluesselports.
///
/// Wie ueberall in diesem Bauwerk assertieren Tests gegen [`KeyError::code`]
/// und nie gegen eine Formatierung.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyError {
    /// Der Eintrag existiert nicht (mehr).
    NotFound,
    /// Der Griff dient einem anderen Zweck als der aufgerufene Vorgang.
    PurposeMismatch,
    /// Ein Zweck, der auf einem Writer nie privat vorliegt.
    ForbiddenPurpose,
    /// Das erreichte Schutzprofil weicht vom BEANSPRUCHTEN ab.
    ///
    /// Es gibt keinen stillen Rueckfall (`design.md`:1489): jede Abweichung
    /// bricht ab.
    ProtectionProfileMismatch,
    /// Ein Schutzprofil ausserhalb der Teilmenge, die Stufe 2 traegt.
    ///
    /// Die Varianten 2 bis 4 von [`KeyProtectionProfileV1`] kommen mit Stufe 5.
    /// Bis dahin ist ihre Verwendung ein Abbruch und keine Annaeherung.
    UnsupportedProtectionProfile,
    /// Der Provider kann das VERLANGTE Schutzprofil nicht erreichen.
    ///
    /// Scharf getrennt von [`Self::UnsupportedProtectionProfile`]: dort traegt
    /// die Stufe das Profil nicht, hier traegt es DIESER Provider nicht. Ein
    /// Provider, der Hardware verspricht und Software liefert, waere genau der
    /// stille Rueckfall, den `design.md`:1489 verbietet.
    UnreachableProtectionProfile,
    /// Ein Zertifikat traegt ein Faehigkeitsliteral ausserhalb der
    /// Stufe-1-Allowlist.
    UnknownCapability,
    /// Ein bekanntes Faehigkeitsliteral, das einem Writer nicht zusteht.
    ForbiddenCapability,
    /// Ein Vorgang der Kryptografieschicht ist gescheitert.
    Crypto(CryptoError),
}

impl KeyError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "EA-KEY-NOT-FOUND",
            Self::PurposeMismatch => "EA-KEY-PURPOSE-MISMATCH",
            Self::ForbiddenPurpose => "EA-KEY-FORBIDDEN-PURPOSE",
            Self::ProtectionProfileMismatch => "EA-KEY-PROTECTION-PROFILE-MISMATCH",
            Self::UnsupportedProtectionProfile => "EA-KEY-PROTECTION-PROFILE-UNSUPPORTED",
            Self::UnreachableProtectionProfile => "EA-KEY-PROTECTION-PROFILE-UNREACHABLE",
            Self::UnknownCapability => "EA-KEY-UNKNOWN-CAPABILITY",
            Self::ForbiddenCapability => "EA-KEY-FORBIDDEN-CAPABILITY",
            Self::Crypto(error) => error.code(),
        }
    }
}

impl From<CryptoError> for KeyError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for KeyError {}

/// Der synchrone Port zum nativen Schluesselspeicher.
///
/// Jede Methode ist synchron, wie der ganze Rust-Kern. Damit ist
/// `Arc<dyn KeyProvider>` trivial konstruierbar; Async lebt ausschliesslich in
/// `apps/desktop/src-tauri`, wo jeder `#[tauri::command]`-Handler die
/// synchrone Kernoperation ueber `tauri::async_runtime::spawn_blocking`
/// ausfuehrt.
///
/// Der Port zeigt GENAU die Vorgaenge eines Writers: Writer-Signatur und
/// Bedienersignatur, Ein- und Auspacken des `draftDEK` und den Schluessel der
/// lokalen Datenbank. Einen HPKE-Entkapselungsport gibt es hier bewusst NICHT
/// — ein KEM-Empfaengerzweck auf einem Writer widerspraeche der
/// Produktinvariante, dass dort kein privater Reader- oder
/// Wiederherstellungsschluessel existiert.
pub trait KeyProvider: Send + Sync {
    /// Erzeugt frisches Material IM Schluesselspeicher.
    ///
    /// `protection` ist das VERLANGTE Profil. Ein Provider, der es nicht
    /// erreicht, bricht ab; er weicht nie stillschweigend aus.
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError>;

    /// Signiert `payload` unter `content_type`.
    ///
    /// Der Port nimmt inhaltstypisierte NUTZLASTBYTES und keinen Digest: die
    /// sechs nicht-Digest-Inhaltstypen werden gegen ihren vollstaendigen
    /// CBOR-Kern geprueft, und der Writer signiert `local-audit-event-v1`-CBOR
    /// durch genau diesen Port.
    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError>;

    /// Packt ein ausserhalb erzeugtes Geheimnis in den Schluesselspeicher ein.
    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError>;

    /// Packt ein eingepacktes Geheimnis wieder aus.
    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError>;

    /// Packt den Schluessel der lokalen Datenbank aus.
    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError>;

    /// Loescht den Eintrag endgueltig.
    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError>;

    /// Meldet, ob der Eintrag existiert.
    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError>;

    /// Das Schutzprofil, das fuer diesen Eintrag TATSAECHLICH erreicht wurde.
    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError>;
}
