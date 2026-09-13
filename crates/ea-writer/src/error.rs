//! Die Fehlermenge der Finalisierung, mit STABILEN Codes.
//!
//! Jeder Code ist ein Vertrag: Task 15 und Task 16 zeigen ihn, Task 17 und
//! Task 18 lesen ihn, und Tests assertieren gegen ihn statt gegen eine
//! Formatierung. Eine Umbenennung ist deshalb eine Aenderung an der
//! Schnittstelle und nicht am Namen allein.

use core::fmt;

use ea_archive::{ArchiveBackendError, ArchiveError};
use ea_chain::ChainError;
use ea_crypto::CryptoError;
use ea_draft::DraftError;
use ea_format::FormatError;
use ea_key_provider::KeyError;
use ea_schema::SchemaError;

/// Warum eine Finalisierung nicht stattgefunden hat.
///
/// Sie traegt KEIN `Debug` von `ea-types`-Hashes und keine Nutzlast: ein
/// Fehler der Finalisierung reist in eine Oberflaeche und moeglicherweise in
/// ein Protokoll.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum WriterError {
    /// Der Kettenkopf liess sich aus den committed Archivbytes nicht bilden.
    ChainHeadUnusable(ChainError),
    /// Eine authentifizierte Serveraussage widerspricht der Kette.
    RollbackDetected,
    /// Die vorgeschlagene Sequenz liegt ausserhalb der Sequenz-Lease des
    /// gebundenen Head.
    SequenceLeaseExhausted,
    /// Der gebundene Head ist veraltet, und das gebundene Profil blockiert.
    RegistryStaleBlocked,
    /// Es ist kein aktiver Recovery-Empfaenger vorhanden.
    NoActiveRecoveryRecipient,
    /// Ein aktives Readerzertifikat traegt keinen KEM-Abdruck.
    ReaderWithoutKemKey,
    /// Der Hash des konfigurierten Backendprofils steht nicht in
    /// `allowed_archive_profile_hashes` der gebundenen Policy.
    ArchiveProfileNotAllowed,
    /// Die Einsatznummer ist in dieser Organisation und diesem Jahr belegt.
    IncidentNumberTaken,
    /// Die nachgerechnete Profilzusage weicht von der gebundenen Bindung ab.
    OperatorProfileCommitment,
    /// Es liegt keine Profilzeile, gegen die sich die Zusage nachrechnen
    /// liesse.
    OperatorProfileMissing,
    /// Der Nachweis ist veraltet oder entwertet.
    ReauthRequired,
    /// Der Nachweis nennt einen anderen Zweck.
    ReauthPurposeMismatch,
    /// Der Nachweis gehoert zu einer anderen Bindung.
    ReauthBindingMismatch,
    /// Der lokale Kettenkopf widerspricht einer externen Aussage ueber die
    /// Kette, und der externe Kopfabgleich muss vor jeder Finalisierung
    /// stattfinden.
    ///
    /// Zwei Wege fuehren hierher: eine zurueckgespielte Sicherung, deren
    /// gewaehlter Head eine andere Sequenz vorschlaegt als die, die aus den
    /// committeten Bytes folgt — und ein wirksamer Writer-Uebergang, dessen
    /// `previous_entry_hash` nicht der `entryHash` des lokal verifizierten
    /// Kopfes ist. Beides ist dieselbe Lage: die Kette, die dieser Bestand
    /// zeigt, ist nicht die, gegen die Root oder der Server gesprochen haben,
    /// und der neue Writer muss sich gegen Server, Reader oder einen externen
    /// signierten Checkpoint abgleichen, bevor er aktiv wird.
    HeadReconciliationRequired,
    /// Die gebundene `chain_id` ist nicht die des gewaehlten Registry-Head.
    ///
    /// Fail-closed VOR jedem Schreibvorgang: auf einem leeren Bestand gibt es
    /// keinen Knoten, an dem die Kettenpruefung eine fremde Kennung erkennen
    /// koennte, und ein dort geminteter Genesis-Knoten machte den Bestand
    /// dauerhaft unfinalisierbar.
    ChainIdMismatch,
    /// Das Bindungszertifikat ist nicht der LAUFENDE Writer des gewaehlten
    /// Head.
    ///
    /// Der LOKALE Fehler eines zurueckgespielten alten Writers — oder eines
    /// neuen vor seinem Change 3. Er faellt in Schritt 3, vor dem Nachweis,
    /// vor jedem Anspruch und vor jedem Geheimnis; bisher erfuhr der Writer
    /// das erst vom Server (`EA-COMMIT-WRITER-REVOKED`). Die Familie
    /// `EA-WRITER-` gehoert den lokalen Finalisierungsfehlern, und dieser
    /// Code ist deshalb ausdruecklich NICHT der Servercode.
    WriterRevoked,
    /// An der vorgeschlagenen Sequenz wird der Uebergang wirksam, und der
    /// Aufrufer wollte einen Einsatz abschliessen.
    ///
    /// Die erste Sequenz des neuen Writers traegt GENAU EINEN `keyTransition`
    /// (`design.md`:669: der Transition-Hash ist gesetzt, wenn sich das
    /// Writer-Zertifikat gegenueber dem Vorgaenger aendert — und nur dann).
    WriterTransitionRequired,
    /// Ein `keyTransition` wurde verlangt, aber an der vorgeschlagenen Sequenz
    /// wird kein Uebergang auf diesen Writer wirksam — die Linie kennt keinen,
    /// oder seine Sequenz ist eine andere.
    ///
    /// Der Fall, dass der Uebergang wirksam ist, aber einen ANDEREN letzten
    /// Eintrag des alten Writers nennt als den, der lokal committet liegt, ist
    /// KEIN Mismatch dieser Art, sondern [`Self::HeadReconciliationRequired`]:
    /// dort widersprechen sich lokaler Kopf und Root-signierte Aussage ueber
    /// die Kette, und das verlangt den externen Kopfabgleich.
    WriterTransitionMismatch,
    /// Es liegt schon eine vorbereitete Abschlussmarke.
    PreparedFinalizationPresent,
    /// Es liegt keine vorbereitete Abschlussmarke.
    NoPreparedFinalization,
    /// Die vorbereitete Abschlussmarke traegt nicht die Gestalt, die dieser
    /// Baustand schreibt.
    PreparedFinalizationUnreadable,
    /// Die vorbereitete Abschlussmarke ist LESBAR und widerspricht sich selbst.
    ///
    /// Ein EIGENER Code neben [`Self::PreparedFinalizationUnreadable`], und der
    /// Unterschied ist keine Kosmetik: „nicht die Gestalt dieses Baustands"
    /// sagt einem Bediener, dass die Bytes aus einer anderen Fassung stammen
    /// oder beschaedigt sind, „widerspricht sich selbst" sagt, dass
    /// wohlgeformte Bytes eine Transaktion behaupten, die es so nie gab —
    /// abweichender Objekthash, abweichender `entryHash`, ein Grant-Plan-Hash,
    /// den das `.eip` nicht signiert, oder eine leere Grantliste. Die zweite
    /// Aussage ist ein Manipulationsbefund und keine Versionsfrage, und beide
    /// Wege enden fail-closed, ohne dass ein Byte veroeffentlicht wird.
    PreparedFinalizationInconsistent,
    /// Die Vorschau ist eine andere als die, die `finalize` unter der Sperre
    /// nachrechnet.
    StaleAckPreviewMismatch,
    /// Der gebundene Head ist veraltet und es liegt keine Bestaetigung.
    StaleAckRequired,
    /// Die Bestaetigung ist schon verbraucht.
    StaleAckReplay,
    /// Das Betriebssystem hat keine Entropie geliefert.
    LocalRng,
    /// Der `draftDEK` ist nach dem Loeschen noch vorhanden.
    KeyDeletionNotConfirmed,
    /// Es gibt keinen Entwurfsinhalt zu finalisieren.
    NoDraftContent,
    /// Retained Writer acquisition source is absent; archive alone cannot
    /// reveal the encrypted original identity. Restore its source backup.
    OriginalIdentityMissing,
    OriginalIdentityMismatch,
    DestructionEvidenceInvalid,
    OriginalArchiveUnverified,
    Archive(ArchiveError),
    Backend(ArchiveBackendError),
    Crypto(CryptoError),
    Draft(DraftError),
    Format(FormatError),
    Key(KeyError),
    Audit(ea_audit::AuditError),
    Store(ea_local_store::StoreError),
    /// Die Nutzlast oder eine Momentaufnahme ist ungueltig; der Code ist der
    /// von `ea-schema` gemeldete, unveraendert weitergegeben.
    ///
    /// Der Fehler wird auf seinen CODE reduziert und nicht mitgetragen:
    /// `SchemaError` ist nicht `Copy` und traegt Feldpfade, die in eine
    /// Protokollzeile geraten koennten.
    Payload(&'static str),
}

impl WriterError {
    /// Der STABILE Code dieses Fehlers.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::OriginalIdentityMissing => "EA-WRITER-ORIGINAL-IDENTITY-MISSING",
            Self::OriginalIdentityMismatch => "EA-WRITER-ORIGINAL-IDENTITY-MISMATCH",
            Self::DestructionEvidenceInvalid => "EA-WRITER-DESTRUCTION-EVIDENCE-INVALID",
            Self::OriginalArchiveUnverified => "EA-WRITER-ORIGINAL-ARCHIVE-UNVERIFIED",
            Self::ChainHeadUnusable(_) => "EA-WRITER-CHAIN-HEAD-UNUSABLE",
            Self::RollbackDetected => "EA-WRITER-ROLLBACK-DETECTED",
            Self::SequenceLeaseExhausted => "EA-WRITER-SEQUENCE-LEASE-EXHAUSTED",
            Self::RegistryStaleBlocked => "EA-REGISTRY-STALE-BLOCKED",
            Self::NoActiveRecoveryRecipient => "EA-WRITER-NO-ACTIVE-RECOVERY-RECIPIENT",
            Self::ReaderWithoutKemKey => "EA-WRITER-READER-WITHOUT-KEM-KEY",
            Self::ArchiveProfileNotAllowed => "EA-ARCHIVE-PROFILE-NOT-ALLOWED",
            Self::IncidentNumberTaken => "EA-WRITER-INCIDENT-NUMBER-TAKEN",
            Self::OperatorProfileCommitment => "EA-OPERATOR-PROFILE-COMMITMENT",
            Self::OperatorProfileMissing => "EA-OPERATOR-PROFILE-MISSING",
            Self::ReauthRequired => "EA-WRITER-REAUTH-REQUIRED",
            Self::ReauthPurposeMismatch => "EA-WRITER-REAUTH-PURPOSE-MISMATCH",
            Self::ReauthBindingMismatch => "EA-WRITER-REAUTH-BINDING-MISMATCH",
            Self::HeadReconciliationRequired => "EA-WRITER-HEAD-RECONCILIATION-REQUIRED",
            Self::ChainIdMismatch => "EA-WRITER-CHAIN-ID-MISMATCH",
            Self::WriterRevoked => "EA-WRITER-REVOKED",
            Self::WriterTransitionRequired => "EA-WRITER-TRANSITION-REQUIRED",
            Self::WriterTransitionMismatch => "EA-WRITER-TRANSITION-MISMATCH",
            Self::PreparedFinalizationPresent => "EA-WRITER-PREPARED-FINALIZATION-PRESENT",
            Self::NoPreparedFinalization => "EA-WRITER-NO-PREPARED-FINALIZATION",
            Self::PreparedFinalizationUnreadable => "EA-WRITER-PREPARED-FINALIZATION-UNREADABLE",
            Self::PreparedFinalizationInconsistent => {
                "EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT"
            }
            Self::StaleAckPreviewMismatch => "EA-REGISTRY-STALE-ACK-PREVIEW-MISMATCH",
            Self::StaleAckRequired => "EA-REGISTRY-STALE-ACK-REQUIRED",
            Self::StaleAckReplay => "EA-REGISTRY-STALE-ACK-REPLAY",
            Self::LocalRng => "EA-WRITER-LOCAL-RNG",
            Self::KeyDeletionNotConfirmed => "EA-WRITER-KEY-DELETION-NOT-CONFIRMED",
            Self::NoDraftContent => "EA-WRITER-NO-DRAFT-CONTENT",
            Self::Archive(error) => error.code(),
            Self::Backend(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Draft(error) => error.code(),
            Self::Format(error) => error.code(),
            Self::Key(error) => error.code(),
            Self::Audit(error) => error.code(),
            Self::Store(error) => error.code(),
            Self::Payload(code) => code,
        }
    }
}

impl fmt::Debug for WriterError {
    /// Der Code und nichts sonst.
    ///
    /// `unwrap_err()` verlangt `Debug`, und ein `Debug`, das eingebettete
    /// Hashes ausgibt, waere genau die Protokollzeile, die Stufe 1 mit ihren
    /// fehlenden `Debug`-Ableitungen verhindert.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for WriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl From<ArchiveError> for WriterError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}

impl From<ArchiveBackendError> for WriterError {
    fn from(error: ArchiveBackendError) -> Self {
        Self::Backend(error)
    }
}

impl From<CryptoError> for WriterError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DraftError> for WriterError {
    fn from(error: DraftError) -> Self {
        Self::Draft(error)
    }
}

impl From<FormatError> for WriterError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<KeyError> for WriterError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<ea_audit::AuditError> for WriterError {
    fn from(error: ea_audit::AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<ea_local_store::StoreError> for WriterError {
    fn from(error: ea_local_store::StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<SchemaError> for WriterError {
    fn from(error: SchemaError) -> Self {
        Self::Payload(error.code())
    }
}

impl From<ChainError> for WriterError {
    fn from(error: ChainError) -> Self {
        Self::ChainHeadUnusable(error)
    }
}
