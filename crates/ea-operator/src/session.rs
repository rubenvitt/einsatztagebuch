//! Die Wiederanmeldung und ihr undurchsichtiger Praesenznachweis.

use core::fmt;

use ea_trust::PreexistingEffectiveNow;
use ea_types::{DeviceId, ObjectHash, OrganizationId, UnixMillis};

use crate::account::{BoundOperator, OperatorError, OsAccountProvider};

/// Die Domaintrennung der lokalen Praesenz-Challenge.
///
/// Sie gehoert DIESER Crate und ist ausdruecklich keine Stufe-1-Konstante: die
/// Challenge wird nie zu Archivbytes, nie zu Protokollbytes und verlaesst das
/// Geraet nie. Insbesondere ist sie NICHT `challenge-response-core-v1` — das ist
/// die servergestellte Sync-Challenge, die einen `server-certificate-hash`
/// traegt und an `SignerRole::ServerReceipt` gebunden ist.
pub const REAUTH_CHALLENGE_DOMAIN: &[u8] = b"EINSATZARCHIV-OPERATOR-REAUTH-v1";

/// Der Vorgabewert der maximalen Untaetigkeit einer Sitzung: fuenf Minuten.
pub const MAX_INACTIVITY_MS: i64 = 5 * 60 * 1_000;

/// Der Zweck, fuer den eine Wiederanmeldung verlangt wird.
///
/// Geschlossen. Ein Nachweis traegt genau EINEN dieser Zwecke und autorisiert
/// keinen anderen — eine Wiederanmeldung fuer den Abschluss eines Eintrags ist
/// keine fuer eine Vernichtung.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReauthPurpose {
    /// Abschluss eines Eintrags.
    Finalize,
    /// Verwerfen eines Entwurfs.
    DiscardDraft,
    /// Abschluss gegen einen veralteten Registry-Stand.
    RegistryStaleFinalize,
    /// Ausgabe von Klartext aus dem Archiv.
    PlaintextExport,
    /// Eine administrative Root-Zeremonie.
    AdminRootCeremony,
    /// Eine Wiederherstellungsprobe.
    RecoveryTest,
    /// Eine nachtraegliche Neuberechtigung.
    HistoricalRegrant,
    /// Vernichtung.
    Destruction,
    /// Freigabe nach Uhrenversatz.
    ClockSkewRelease,
    /// Migration eines Archivprofils.
    ArchiveProfileMigration,
}

impl ReauthPurpose {
    /// Alle zehn Zwecke, in Deklarationsreihenfolge.
    ///
    /// Die Laenge ist Teil des Typs: ein elfter Zweck bricht dieses Literal und
    /// erzwingt damit, dass der Namensvergleich in
    /// `every_purpose_carries_a_distinct_label` ihn mitnimmt statt ihn
    /// stillschweigend auszulassen.
    pub const ALL: [Self; 10] = [
        Self::Finalize,
        Self::DiscardDraft,
        Self::RegistryStaleFinalize,
        Self::PlaintextExport,
        Self::AdminRootCeremony,
        Self::RecoveryTest,
        Self::HistoricalRegrant,
        Self::Destruction,
        Self::ClockSkewRelease,
        Self::ArchiveProfileMigration,
    ];

    /// Die Zeichenkette, die den Zweck in der Challenge NENNT.
    ///
    /// Sie geht in die signierten Bytes ein, damit eine Signatur fuer einen
    /// Zweck keine fuer einen anderen ist. Weil sie das Geraet nie verlaesst, ist
    /// sie kein eingefrorenes Format; sie ist aber stabil, weil ein
    /// ausgestellter Nachweis sonst nach einem Neustart nicht mehr auf sich
    /// selbst passt.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Finalize => "finalize",
            Self::DiscardDraft => "discard-draft",
            Self::RegistryStaleFinalize => "registry-stale-finalize",
            Self::PlaintextExport => "plaintext-export",
            Self::AdminRootCeremony => "admin-root-ceremony",
            Self::RecoveryTest => "recovery-test",
            Self::HistoricalRegrant => "historical-regrant",
            Self::Destruction => "destruction",
            Self::ClockSkewRelease => "clock-skew-release",
            Self::ArchiveProfileMigration => "archive-profile-migration",
        }
    }
}

/// Ein ausgestellter Praesenznachweis.
///
/// Der Nachweis TRAEGT seine Bindung: Zweck, Organisation, Geraet,
/// Bedienerbindung, die Nonce der Praesenz-Challenge, Ausstellzeit und Ablauf.
/// Dieselben Angaben stehen zusaetzlich in den Bytes, die der Instanzschluessel
/// signiert hat (siehe [`challenge_bytes`]) — die Signatur wird nach ihrer
/// Pruefung verworfen, und ohne die Felder koennte danach kein Verbraucher mehr
/// feststellen, zu WELCHEM Bediener ein Nachweis gehoert. Ein Nachweis gegen
/// Bindung A darf in einer Sitzung gegen Bindung B nicht durchgehen; dafuer
/// braucht der Vergleich einen Leser, und den geben
/// [`Self::binding_object_hash`], [`Self::organization_id`] und
/// [`Self::device_id`].
///
/// Undurchsichtig bleibt, was undurchsichtig gehoert: es gibt keinen Leser fuer
/// den OS-Kontobezeichner, den Instanzschluessel oder die Signatur. Organisation,
/// Geraet und Bindungsobjekthash sind dagegen oeffentliche Angaben des Trust
/// Bundle, und die Nonce ist verbraucht — keiner der drei ist ein Geheimnis, und
/// der `compile_fail`-Doctest in [`crate`] pinnt weiterhin, dass ein
/// Kontobezeichner nicht aus dem Nachweis zu holen ist.
///
/// `Debug` ist zulaessig, weil hier kein Geheimnis liegt: Zweck, zwei Zeitpunkte
/// und ein Sperrbit.
///
/// AUSDRUECKLICH NICHT `Clone` und nicht `Copy`. Ein kopierbarer Nachweis machte
/// [`Self::invalidate_on_lock`] wirkungslos: der Aufrufer behielte den gueltigen
/// Stand daneben und koennte nach der OS-Sperre mit ihm weiterarbeiten. Der
/// `compile_fail`-Doctest in [`crate`] belegt das.
///
/// Die Gleichheit unterscheidet zwei Wiederanmeldungen desselben Zwecks zur
/// selben Zeit, weil die Challenge-Nonce im Typ liegt: „frische Praesenz" ist
/// damit am Nachweis ablesbar und nicht nur in einer verworfenen Signatur.
#[derive(Eq, PartialEq)]
pub struct OperatorSessionProof {
    purpose: ReauthPurpose,
    organization_id: OrganizationId,
    device_id: DeviceId,
    binding_object_hash: ObjectHash,
    challenge_nonce: [u8; 32],
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    invalidated: bool,
}

impl OperatorSessionProof {
    /// Ob dieser Nachweis `purpose` zur Zeit des gewaehlten Head autorisiert.
    ///
    /// Vier Bedingungen, alle notwendig: der Zweck stimmt, der Nachweis ist
    /// nicht durch ein Sperr- oder Sitzungsereignis entwertet, die Zeit liegt
    /// nicht vor der Ausstellung und nicht hinter dem Ablauf.
    ///
    /// Die Zeit kommt als [`PreexistingEffectiveNow`] und nie als freier Wert:
    /// nur so traegt die Aussage die Zeitstatusbewertung des gewaehlten Head.
    ///
    /// Diese Methode prueft ausdruecklich NICHT die Bindung: ein Verbraucher, der
    /// fuer einen bestimmten Bediener handelt, vergleicht zusaetzlich
    /// [`Self::binding_object_hash`] mit dem [`BoundOperator`], gegen den er
    /// handelt — sonst akzeptiert er jeden Nachweis desselben Zwecks, auch einen
    /// fuer eine andere Bindung. Die Zweiteilung ist nicht Bequemlichkeit,
    /// sondern die woertlich vorgegebene Signatur dieser Methode; der
    /// Bindungsabgleich hat mit den drei Lesern seinen Ort, aber nicht seinen
    /// Zwang. Wer einen Nachweis annimmt, ohne die Bindung zu vergleichen, hat
    /// einen Fehler gemacht, und dieser Satz steht hier, damit er nachlesbar ist.
    #[must_use]
    pub fn is_valid_for(&self, purpose: ReauthPurpose, now: &PreexistingEffectiveNow) -> bool {
        let now = now.value().get();
        self.purpose == purpose
            && !self.invalidated
            && now >= self.issued_at.get()
            && now <= self.expires_at.get()
    }

    /// Entwertet den Nachweis wegen eines nativen Sperr- oder
    /// Sitzungsereignisses.
    ///
    /// Nimmt `self` und gibt den entwerteten Nachweis zurueck, damit der
    /// Aufrufer den gueltigen Stand nicht daneben behalten kann. Das Ereignis
    /// selbst — Windows-Sitzungswechsel, macOS-Screen-Lock-Notification,
    /// Ubuntu-Sitzungsmanager — wird in Task 13 und Task 15 an die Shell
    /// verdrahtet; Task 16 behandelt die Rueckkehr aus der Sperre als
    /// Wiederanmeldepflicht.
    #[must_use]
    pub const fn invalidate_on_lock(self) -> Self {
        Self {
            purpose: self.purpose,
            organization_id: self.organization_id,
            device_id: self.device_id,
            binding_object_hash: self.binding_object_hash,
            challenge_nonce: self.challenge_nonce,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            invalidated: true,
        }
    }

    /// Die Bedienerbindung, fuer die dieser Nachweis ausgestellt wurde.
    ///
    /// Kein Geheimnis: ein Bindungsobjekthash steht im oeffentlichen Trust
    /// Bundle. Ein Verbraucher, der fuer eine bestimmte Bindung handelt — Task 4
    /// beim Verwerfen, Task 11 beim Abschluss —, vergleicht ihn mit
    /// `BoundOperator`, statt jeden Nachweis desselben Zwecks zu akzeptieren.
    #[must_use]
    pub const fn binding_object_hash(&self) -> ObjectHash {
        self.binding_object_hash
    }

    /// Die Organisation, unter der dieser Nachweis ausgestellt wurde.
    ///
    /// Oeffentliche Angabe des Trust Bundle. Sie liegt hier, weil ein
    /// Verbraucher, der fuer eine Organisation handelt, ohne sie einen Nachweis
    /// aus einer FREMDEN Organisation nicht abweisen koennte.
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// Das Geraet, das das Writer-Zertifikat der Bindung nennt.
    ///
    /// Ebenfalls oeffentlich und aus dem Zertifikat aufgeloest, nicht aus einem
    /// Parameter uebernommen (siehe [`BoundOperator::resolve`]).
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Die verbrauchte Nonce der Praesenz-Challenge.
    ///
    /// Kein Geheimnis: sie war nie eines, sie ist gegen den gebundenen Schluessel
    /// geprueft und wird nie wiederverwendet. Sie liegt im Nachweis, damit zwei
    /// Wiederanmeldungen desselben Zwecks zur selben Zeit unterscheidbar sind —
    /// ohne sie waeren sie gleich, und „frische Praesenz" waere am Nachweis nicht
    /// ablesbar.
    #[must_use]
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }
}

/// Der synchrone Port der Wiederanmeldung.
///
/// Eine Plattform implementiert genau ZWEI Haken: welche Bindung gilt, und wie
/// Praesenz nachgewiesen und die Challenge signiert wird. Die Pruefung selbst —
/// Kontoabgleich, Instanzschluessel, Signaturpruefung, Ausstellung — liegt im
/// Standardkoerper von [`Self::reauthenticate`] und ist damit auf jeder Plattform
/// dieselbe.
pub trait OperatorAuthenticator {
    /// Die Bindung, gegen die diese Sitzung prueft.
    ///
    /// PFLICHT DES IMPLEMENTIERERS: die zurueckgegebene Bindung traegt die Zeit
    /// des Head, an dem sie aufgeloest wurde ([`BoundOperator::resolve`]), und
    /// [`Self::reauthenticate`] stellt gegen genau diese Zeit aus. Ein
    /// Authenticator, der die Bindung ueber die Lebensdauer einer Sitzung
    /// festhaelt, muss sie unmittelbar vor jeder Wiederanmeldung gegen den
    /// AKTUELLEN gewaehlten Head neu aufloesen. Sonst stellt er einen Nachweis
    /// aus, dessen Fuenfminutenfenster in der Vergangenheit liegt: der Aufrufer
    /// sieht `Ok`, und `is_valid_for` gegen den aktuellen Head sagt `false`.
    /// Fail-closed, aber eine erfolgreiche Wiederanmeldung ist es nicht.
    fn bound_operator(&self) -> &BoundOperator;

    /// Verlangt Praesenz und signiert `challenge` mit dem
    /// Bedienerinstanzschluessel.
    ///
    /// Windows Hello beziehungsweise die Credential-UI, LocalAuthentication auf
    /// macOS, PAM/Polkit auf Ubuntu. Der private Schluessel verlaesst den
    /// Schluesselspeicher nicht; er erscheint in dieser Signatur nicht und wird
    /// nirgends in dieser Crate gehalten.
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError>;

    /// Meldet den Bediener fuer genau `purpose` wieder an.
    ///
    /// Die Reihenfolge ist fail-closed und absichtlich: erst das Konto, dann das
    /// Vorhandensein des Instanzschluessels, dann seine Identitaet, dann die
    /// frische Praesenz. Kein Schritt wird durch einen spaeteren ersetzt.
    ///
    /// AUSSTELLZEIT IST DIE ZEIT DER BINDUNG, nicht die des Augenblicks. Diese
    /// Methode nimmt keine Zeit an — `PreexistingEffectiveNow` ist in Stufe 1
    /// nicht frei baubar —, sie nimmt sie aus dem [`BoundOperator`], den
    /// [`Self::bound_operator`] liefert. Ein `Ok` heisst deshalb NICHT „der
    /// Nachweis gilt jetzt", sondern „Konto, Instanzschluessel und Praesenz sind
    /// belegt, und der Nachweis gilt fuenf Minuten ab der Zeit dieser Bindung".
    /// Wer die Bindung eine Stunde vorher aufgeloest hat, bekommt einen Nachweis,
    /// der bei der Pruefung gegen den aktuellen Head bereits abgelaufen ist. Die
    /// Pflicht, die Bindung unmittelbar vorher neu aufzuloesen, liegt beim
    /// Implementierer von [`Self::bound_operator`]; der Test
    /// `a_binding_resolved_before_the_window_issues_a_proof_that_is_already_expired`
    /// macht sie messbar.
    fn reauthenticate(
        &self,
        account: Box<dyn OsAccountProvider>,
        purpose: ReauthPurpose,
    ) -> Result<OperatorSessionProof, OperatorError> {
        let bound = self.bound_operator();

        let reported =
            account.os_account_binding_hash(bound.organization_id(), bound.device_id())?;
        if reported != bound.os_account_binding_hash() {
            return Err(OperatorError::AccountMismatch);
        }

        let instance_key = account
            .operator_instance_public_key()?
            .ok_or(OperatorError::InstanceKeyMissing)?;
        if instance_key.thumbprint() != bound.operator_instance_key_thumbprint() {
            return Err(OperatorError::InstanceKeyMismatch);
        }

        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| OperatorError::LocalRng)?;

        let issued_at = bound.effective_now();
        let expires_at = issued_at
            .get()
            .checked_add(MAX_INACTIVITY_MS)
            .map(UnixMillis::new)
            .ok_or(OperatorError::ValidityWindowUnrepresentable)?;

        let challenge = challenge_bytes(bound, purpose, &nonce, issued_at, expires_at);
        let signature = self.prove_presence_and_sign(&challenge)?;
        instance_key
            .verify_ed25519_strict(&challenge, &signature)
            .map_err(|_| OperatorError::PresenceProofInvalid)?;

        Ok(OperatorSessionProof {
            purpose,
            organization_id: bound.organization_id(),
            device_id: bound.device_id(),
            binding_object_hash: bound.binding_object_hash(),
            challenge_nonce: nonce,
            issued_at,
            expires_at,
            invalidated: false,
        })
    }
}

impl fmt::Debug for OperatorSessionProof {
    /// Nennt, was die Gueltigkeit entscheidet — und keinen Hash.
    ///
    /// Bindungsobjekthash, Organisation, Geraet und Nonce bleiben draussen,
    /// obwohl der Nachweis sie traegt: `ObjectHash`, `OrganizationId` und
    /// `DeviceId` tragen in diesem Bauwerk bewusst keine Formatierung, weil ein
    /// Bezeichner in einer Protokollzeile dort nichts beitraegt. Dasselbe Muster
    /// wie `KeyHandle` in `crates/ea-key-provider/src/contract.rs`. Wer sie
    /// braucht, ruft die Leser; eine Protokollzeile braucht sie nicht.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorSessionProof")
            .field("purpose", &self.purpose)
            .field("issued_at", &self.issued_at.get())
            .field("expires_at", &self.expires_at.get())
            .field("invalidated", &self.invalidated)
            .finish_non_exhaustive()
    }
}

/// Die Bytes, die der Bedienerinstanzschluessel signiert.
///
/// Alles ausser dem Zwecknamen hat feste Laenge, und der Zweckname traegt seine
/// Laenge als fuehrendes Oktett — die Verkettung ist damit eindeutig zerlegbar
/// und zwei verschiedene Eingaben koennen nicht dieselben Bytes erzeugen.
///
/// Diese Kodierung ist ABSICHTLICH nicht eingefroren und ausdruecklich kein
/// COSE: sie wird nie geschrieben, nie uebertragen und nie von einem anderen
/// Programm gelesen.
fn challenge_bytes(
    bound: &BoundOperator,
    purpose: ReauthPurpose,
    nonce: &[u8; 32],
    issued_at: UnixMillis,
    expires_at: UnixMillis,
) -> Vec<u8> {
    let label = purpose.label().as_bytes();
    let mut challenge = Vec::with_capacity(REAUTH_CHALLENGE_DOMAIN.len() + label.len() + 113);
    challenge.extend_from_slice(REAUTH_CHALLENGE_DOMAIN);
    // Ein Zwecklabel ist kurz und ASCII; die Zusicherung haelt das fest, damit
    // das Laengenoktett nicht stillschweigend abschneidet.
    debug_assert!(label.len() <= usize::from(u8::MAX));
    challenge.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
    challenge.extend_from_slice(label);
    challenge.extend_from_slice(bound.organization_id().as_bytes());
    challenge.extend_from_slice(bound.device_id().as_bytes());
    challenge.extend_from_slice(bound.binding_object_hash().as_bytes());
    challenge.extend_from_slice(nonce);
    challenge.extend_from_slice(&issued_at.get().to_be_bytes());
    challenge.extend_from_slice(&expires_at.get().to_be_bytes());
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_purpose_carries_a_distinct_label() {
        let labels = ReauthPurpose::ALL.map(ReauthPurpose::label);
        let mut sorted = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        // Zehn Zwecke, zehn Namen: ein doppeltes Label liesse eine Signatur fuer
        // den einen Zweck als eine fuer den anderen durchgehen.
        assert_eq!(sorted.len(), labels.len());
    }

    #[test]
    fn the_inactivity_default_is_five_minutes() {
        assert_eq!(MAX_INACTIVITY_MS, 300_000);
    }
}
