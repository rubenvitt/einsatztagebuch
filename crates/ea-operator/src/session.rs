//! Die Wiederanmeldung und ihr undurchsichtiger Praesenznachweis.

use core::fmt;

use ea_trust::PreexistingEffectiveNow;
use ea_types::{ObjectHash, UnixMillis};

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
/// Undurchsichtig: es gibt keinen Leser fuer den Kontobezeichner, den
/// Instanzschluessel, die Challenge oder die Signatur. Organisation, Geraet,
/// Bindung und Nonce sind KRYPTOGRAFISCH gebunden — sie stehen in den Bytes, die
/// der Instanzschluessel signiert hat (siehe [`challenge_bytes`]) — und nicht als
/// Felder gespeichert, die ein Aufrufer wieder auslesen koennte. Der Nachweis
/// selbst traegt nur, was seine Gueltigkeit ENTSCHEIDET.
///
/// `Debug` ist zulaessig, weil hier kein Geheimnis liegt: Zweck, Bindung, zwei
/// Zeitpunkte und ein Sperrbit.
///
/// AUSDRUECKLICH NICHT `Clone` und nicht `Copy`. Ein kopierbarer Nachweis machte
/// [`Self::invalidate_on_lock`] wirkungslos: der Aufrufer behielte den gueltigen
/// Stand daneben und koennte nach der OS-Sperre mit ihm weiterarbeiten. Der
/// `compile_fail`-Doctest in [`crate`] belegt das.
#[derive(Eq, PartialEq)]
pub struct OperatorSessionProof {
    purpose: ReauthPurpose,
    binding_object_hash: ObjectHash,
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
            binding_object_hash: self.binding_object_hash,
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
            binding_object_hash: bound.binding_object_hash(),
            issued_at,
            expires_at,
            invalidated: false,
        })
    }
}

impl fmt::Debug for OperatorSessionProof {
    /// Nennt, was die Gueltigkeit entscheidet — und keinen Hash.
    ///
    /// Der Bindungsobjekthash bleibt draussen, weil `ObjectHash` in diesem
    /// Bauwerk bewusst keine Formatierung traegt: ein Hash in einer
    /// Protokollzeile ist ein Bezeichner, der dort nichts beitraegt. Dasselbe
    /// Muster wie `KeyHandle` in `crates/ea-key-provider/src/contract.rs`.
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
