//! Die NEUN Serverschritte eines Entry-Commits (`design.md` §13.3:1541-1549).
//!
//! Die Datei fuehrt sie in ihrer Reihenfolge und mit ihrer Nummerierung aus.
//! Kein Schritt wird zusammengezogen, keiner ausgelassen, keiner neu
//! nummeriert. Die dreizehn Schritte der Writer-Finalisierung aus §9.3 sind
//! eine ANDERE Transaktion und werden hier nirgends dagegengerechnet.
//!
//! # Wo die Transaktion beginnt — und wo nicht
//!
//! [`CommitRepository::commit_locked_head`] ist die SICHTBARKEITSENTSCHEIDUNG,
//! nicht die Baustelle. Es sperrt den Kopf, prueft Sequenz und Vorgaenger
//! erneut und schaltet Entry, Grants, Objektindex, Receipt-Hash und den neuen
//! Kopf gemeinsam sichtbar. Die Quittung ist zu diesem Zeitpunkt bereits
//! fertig und abgelegt — sie MUSS es sein, weil ihr Objekthash im Auftrag
//! steht und die Fremdschluessel von `receipts` darauf zeigen.
//!
//! Daraus folgt die Zusage aus `design.md`:1547 unveraendert: „Annahmezeit,
//! Due-Zeit und Signatur werden bei einem Commit nie neu berechnet." Verliert
//! dieser Aufruf das Rennen um den Kopf, wird nicht neu gerechnet und nicht
//! neu signiert — der Aufrufer bekommt `409` und schickt seinen Commit
//! erneut, und der ist dann ein NEUER Commit-Versuch mit einer neuen Zeit.
//!
//! # Warum ein verworfener Receipt kein Fehler ist
//!
//! Ein idempotenter Replay bildet zuerst eine Quittung — er weiss vorher
//! nicht, dass er einer ist — und bekommt dann die GESPEICHERTE zurueck. Die
//! eben gebildete bleibt als content-addressed, NICHT SICHTBARES Objekt
//! liegen. Genau das benennt `design.md` §13.3 im vorletzten Absatz als
//! zulaessig, und [`crate::reconcile`] ist die Stelle, die solche Objekte
//! spaeter beurteilt. Ein Vorabtest, der das vermiede, waere eine zweite
//! Idempotenzentscheidung neben der einen unter der Sperre — und damit ein
//! Rennen.
//!
//! # Was ein Security Event ist
//!
//! Die vier Faelle des letzten Absatzes von §13.3 und der Bytekonflikt aus
//! Schritt 3, und sonst nichts. Ein verlorenes Rennen um den Kopf ist KEIN
//! Security Event: der Aufrufer hat nichts falsch gemacht.

use core::fmt;

use aws_sdk_s3::primitives::ByteStream;
use ea_format::ObjectTypeV1;
use ea_sync_protocol::{
    EntryCommitIdentity, EntryCommitOutcome, EntryCommitRequestV1, MAX_ENTRY_OBJECT_BYTES_V1,
    MAX_GRANT_OBJECT_BYTES_V1, SyncProtocolError,
};
use ea_types::{ChainId, ObjectHash, OrganizationId, RegistryVersion, UnixMillis};

use crate::{
    models::{
        ChainHeadStateV1, CommitDbCommand, CommitIdentityV1, IndexedObjectV1, RepositoryError,
        SecurityEventKindV1, SecurityEventV1, StoreError,
    },
    ports::{
        ActiveRegistryHeadV1, AuthorityError, CommitRepository, ObjectStore, RegistryHeadDirectory,
        RegistryHeadSelectionV1, SecurityEventSink, ServerClock, ServerSigner,
    },
    receipt::{ReceiptBindingV1, ReceiptError, accepted_at, build_receipt, exact_receipt_bytes},
    validation::{CommitValidationError, ValidatedCommitV1, parse_entry, validate_commit},
};

/// Was der Commit-Pfad an Ports braucht.
pub struct CommitPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub signer: &'a dyn ServerSigner,
    pub objects: &'a dyn ObjectStore,
    pub commits: &'a dyn CommitRepository,
    pub heads: &'a dyn RegistryHeadDirectory,
    pub security: &'a dyn SecurityEventSink,
}

/// Der Ausgang eines angenommenen Commits.
///
/// Beide Arme tragen die EXAKTEN, ZURUECKGELESENEN Receipt-Bytes. Der Replay
/// traegt ausdruecklich nicht die eben gebildeten: `design.md` §13.3 sagt,
/// „nach dem Commit kann ein Retry ausschliesslich die GESPEICHERTEN
/// Receipt-Bytes wieder ausliefern".
#[derive(Clone, Eq, PartialEq)]
pub enum CommitOutcome {
    Accepted { receipt_bytes: Vec<u8> },
    IdempotentReplay { receipt_bytes: Vec<u8> },
}

impl CommitOutcome {
    #[must_use]
    pub fn receipt_bytes(&self) -> &[u8] {
        match self {
            Self::Accepted { receipt_bytes } | Self::IdempotentReplay { receipt_bytes } => {
                receipt_bytes
            }
        }
    }

    /// Der Ausgang, wie ihn `entry-commit-response-v1` fuehrt.
    #[must_use]
    pub const fn wire_outcome(&self) -> EntryCommitOutcome {
        match self {
            Self::Accepted { .. } => EntryCommitOutcome::Accepted,
            Self::IdempotentReplay { .. } => EntryCommitOutcome::IdempotentReplay,
        }
    }
}

impl fmt::Debug for CommitOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accepted { .. } => "CommitOutcome::Accepted(<bound>)",
            Self::IdempotentReplay { .. } => "CommitOutcome::IdempotentReplay(<bound>)",
        })
    }
}

/// Jeder Befund des Commit-Dienstes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommitServiceError {
    /// Ein Befund aus Schritt 2.
    Validation(CommitValidationError),
    /// Ein Befund aus Schritt 7 oder 9.
    Receipt(ReceiptError),
    /// Derselbe `entryHash` mit anderen Objektbytes oder Grants.
    IdentityConflict,
    /// Dieselbe Sequenz traegt bereits einen anderen Eintrag.
    SequenceFork,
    /// Der behauptete Vorgaenger ist nicht der aktuelle Kopf.
    PredecessorMismatch,
    /// Der Kopf hat sich unter dem Aufrufer bewegt. Ein verlorenes RENNEN und
    /// kein Vorwurf — deshalb kein Security Event.
    HeadConflict,
    /// Gleicher Objektschluessel, ANDERE Bytes (`design.md` §13.3, Schritt 3).
    ObjectConflict,
    /// Der naechste Registry-Head gilt erst spaeter; der Fehlerkoerper nennt
    /// ihn.
    RegistryHeadRequired,
    /// Fuer diese Sequenz ist kein Registry-Head anwendbar. Ohne Kopf gibt es
    /// keine aktive Empfaengermenge, und ohne die keinen Commit.
    NoApplicableRegistryHead,
    /// Der persistente Vertrauenszustand hat sich unter dem Aufrufer bewegt.
    /// Wiederholbar und ausdruecklich keine Aussage ueber seine Autoritaet.
    StateConflict,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
    /// Ein durchgereichter Rahmenbefund.
    Protocol(SyncProtocolError),
}

impl CommitServiceError {
    /// Die Arme ohne Nutzlast — damit ein spaeter ergaenzter auffaellt.
    pub const ALL: [Self; 10] = [
        Self::IdentityConflict,
        Self::SequenceFork,
        Self::PredecessorMismatch,
        Self::HeadConflict,
        Self::ObjectConflict,
        Self::RegistryHeadRequired,
        Self::NoApplicableRegistryHead,
        Self::StateConflict,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Validation(error) => error.code(),
            Self::Receipt(error) => error.code(),
            Self::IdentityConflict => "EA-COMMIT-IDENTITY-CONFLICT",
            Self::SequenceFork => "EA-COMMIT-SEQUENCE-FORK",
            Self::PredecessorMismatch => "EA-COMMIT-PREDECESSOR",
            Self::HeadConflict => "EA-COMMIT-HEAD-CONFLICT",
            Self::ObjectConflict => "EA-COMMIT-OBJECT-CONFLICT",
            Self::RegistryHeadRequired => "EA-COMMIT-REGISTRY-HEAD-REQUIRED",
            Self::NoApplicableRegistryHead => "EA-COMMIT-NO-REGISTRY-HEAD",
            // DERSELBE Code wie im Trust-Pfad: es ist derselbe Befund ueber
            // denselben Speicher, und der Nachtrag fuehrt ihn genau einmal.
            Self::StateConflict => "EA-TRUST-STATE-CONFLICT",
            Self::DependencyUnavailable => "EA-COMMIT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-COMMIT-INTERNAL",
            Self::Protocol(error) => error.code(),
        }
    }

    /// Die HTTP-Abbildung des Sync-Wire-Nachtrags.
    ///
    /// Die 409-Zeile des Nachtrags lautet VOLLSTAENDIG „Fork, Kopfabweichung,
    /// Bytekonflikt, nicht idempotenter Replay oder ERFORDERLICHER NEUERER
    /// REGISTRY-HEAD" (`…sync-wire-addendum.md`:248). Der letzte Halbsatz
    /// gehoert dazu: ein Paket, das den falschen Registry-Head bindet, ist
    /// genau dieser Fall — und `protocol-error-v1` traegt dafuer
    /// `required-registry-version` und `required-registry-head-hash` (ebenda
    /// :266). Es waere kein 422: der Aufrufer soll wiederkommen, nicht
    /// aufgeben.
    ///
    /// Die vier Abweichungsfaelle des letzten Absatzes von §13.3 — nicht
    /// idempotenter Replay, Fork, falscher Vorgaenger, unzulaessiger Writer —
    /// stehen in derselben Zeile. Alles uebrige, was wohlgeformt aber ungueltig
    /// ist, ist 422.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Validation(
                CommitValidationError::WriterUnauthorized | CommitValidationError::RegistryMismatch,
            )
            | Self::IdentityConflict
            | Self::SequenceFork
            | Self::PredecessorMismatch
            | Self::HeadConflict
            | Self::ObjectConflict
            | Self::RegistryHeadRequired => 409,
            Self::Validation(CommitValidationError::OrganizationMismatch) => 403,
            Self::Validation(_)
            | Self::NoApplicableRegistryHead
            | Self::Receipt(ReceiptError::EvidenceOverflow) => 422,
            Self::Receipt(_) | Self::Internal => 500,
            Self::StateConflict | Self::DependencyUnavailable => 503,
            Self::Protocol(error) => error.http_status(),
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl fmt::Display for CommitServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for CommitServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CommitServiceError {}

impl From<CommitValidationError> for CommitServiceError {
    fn from(value: CommitValidationError) -> Self {
        Self::Validation(value)
    }
}

impl From<ReceiptError> for CommitServiceError {
    fn from(value: ReceiptError) -> Self {
        Self::Receipt(value)
    }
}

impl From<SyncProtocolError> for CommitServiceError {
    fn from(value: SyncProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<StoreError> for CommitServiceError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::HashConflict => Self::ObjectConflict,
            StoreError::ObjectTypeMismatch => Self::Validation(CommitValidationError::ObjectFamily),
            StoreError::LimitExceeded => Self::Protocol(SyncProtocolError::BodyLimit),
            StoreError::NotFound => Self::Receipt(ReceiptError::ReadBack),
            StoreError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl From<RepositoryError> for CommitServiceError {
    /// Jeder Arm einzeln, damit ein spaeter ergaenzter nicht stillschweigend
    /// zu einem Kopfkonflikt wird.
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::HeadConflict => Self::HeadConflict,
            RepositoryError::CommitIdentityConflict => Self::IdentityConflict,
            // Die Request-ID-Sperre gehoert der Authentisierung; hier kann sie
            // nicht entstehen, und sie stillschweigend zu einem Kopfkonflikt
            // zu machen waere eine falsche Auskunft.
            RepositoryError::RequestIdReplay => Self::Internal,
            RepositoryError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl From<AuthorityError> for CommitServiceError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Unavailable => Self::DependencyUnavailable,
            AuthorityError::StateConflict => Self::StateConflict,
        }
    }
}

/// Ein Befund MIT dem, was `protocol-error-v1` sonst nicht tragen koennte.
///
/// Dieselbe Bauart wie [`crate::trust::TrustPublishError`]: der Befund bleibt
/// eine geschlossene `Copy`-Aufzaehlung, und die beiden Pflichtpositionen
/// `required-registry-version` und `required-registry-head-hash` reisen in
/// dieser Huelle mit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommitFailure {
    pub error: CommitServiceError,
    pub required_registry_version: Option<RegistryVersion>,
    pub required_registry_head_hash: Option<ObjectHash>,
}

impl CommitFailure {
    /// Der Kopf, den der Aufrufer zuerst holen muss.
    #[must_use]
    pub const fn requiring_head(
        error: CommitServiceError,
        version: RegistryVersion,
        head_hash: ObjectHash,
    ) -> Self {
        Self {
            error,
            required_registry_version: Some(version),
            required_registry_head_hash: Some(head_hash),
        }
    }
}

impl<E: Into<CommitServiceError>> From<E> for CommitFailure {
    fn from(value: E) -> Self {
        Self {
            error: value.into(),
            required_registry_version: None,
            required_registry_head_hash: None,
        }
    }
}

impl fmt::Debug for CommitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.error, formatter)
    }
}

/// `POST /v1/chains/{chainId}/entry-commits` — die neun Schritte.
///
/// # Errors
///
/// Jeder Befund aus [`CommitServiceError`], eingepackt in [`CommitFailure`].
/// Auf JEDEM Fehlerweg bleibt nichts Sichtbares zurueck: die Datenbanktransaktion
/// von Schritt 8 ist entweder ganz oder gar nicht gelaufen, und was vor ihr im
/// Object Store liegt, ist content-addressed und unsichtbar.
#[allow(clippy::too_many_lines)]
pub async fn commit_entry(
    request: &EntryCommitRequestV1,
    organization_id: OrganizationId,
    chain_id: ChainId,
    writer_certificate_hash: ea_types::CertificateHash,
    ports: &CommitPorts<'_>,
) -> Result<CommitOutcome, CommitFailure> {
    // ---------------------------------------------------------------------
    // Schritt 1: jedes Objekt groessenbegrenzt in einen TEMPORAEREN Schluessel
    // stromen und dabei hashen. Die Decken sind die des Nachtrags, und sie
    // greifen VOR jeder Akkumulation.
    // ---------------------------------------------------------------------
    let entry_limit = u64::try_from(MAX_ENTRY_OBJECT_BYTES_V1).unwrap_or(u64::MAX);
    let grant_limit = u64::try_from(MAX_GRANT_OBJECT_BYTES_V1).unwrap_or(u64::MAX);
    let staged_entry = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Entry,
            ByteStream::from(request.entry_bytes().to_vec()),
            entry_limit,
        )
        .await
        .map_err(CommitFailure::from)?;
    let mut staged_grants = Vec::with_capacity(request.sorted_grant_bytes().len());
    for bytes in request.sorted_grant_bytes() {
        staged_grants.push(
            ports
                .objects
                .stage_stream(
                    ObjectTypeV1::Grant,
                    ByteStream::from(bytes.clone()),
                    grant_limit,
                )
                .await
                .map_err(CommitFailure::from)?,
        );
    }

    // ---------------------------------------------------------------------
    // Schritt 2: pruefen — Format, Hashes, Writer, Signatur, Suite,
    // Registry-Linie, Plan, Grant-Signaturen, genau ein Recovery-Grant und
    // jedes aktive Readerzertifikat.
    //
    // Die Kopfauswahl steht hier, weil die aktive Empfaengermenge zur
    // EINTRAGSSEQUENZ gehoert und Schritt 2 sie braucht. Es ist die EINE
    // Auswahl dieses Commits; Schritt 5 waehlt keinen zweiten Kopf, sondern
    // BINDET diesen an Zeit und Sequenz.
    // ---------------------------------------------------------------------
    let entry = parse_entry(request.entry_bytes()).map_err(CommitFailure::from)?;
    let sequence = entry.value().manifest().fields().chain_sequence;
    let now = ports.clock.now();

    // Schritt 4 (das LESEN) und Schritt 5 (die Bestimmung) laufen HIER, vor
    // der Pruefung — nicht, weil die Nummerierung sich verschoebe, sondern weil
    // §13.3 selbst diese Abhaengigkeit stellt: Schritt 2 verlangt „genau einen
    // initialen Grant fuer jedes ZUR EINTRAGSSEQUENZ aktive Reader-Zertifikat",
    // und WELCHE das sind, sagt der Kopf, den Schritt 5 „fuer diese Zeit und
    // Sequenz" bestimmt. Die Zeit ist dabei `acceptedAtServer` und
    // ausdruecklich NICHT die rohe Serveruhr; beide fallen auseinander, sobald
    // die Annahmezeit des Vorgaengers vor der Uhr liegt.
    let current = ports
        .commits
        .head_state(organization_id, chain_id)
        .await
        .map_err(CommitFailure::from)?;
    let accepted_at_server = accepted_at(now, current.map(|head| head.accepted_at_server));
    let head = select_head(organization_id, sequence, accepted_at_server, ports).await?;
    // Der gestromte Hash und der geparste Hash MUESSEN derselbe sein. Sie
    // entstehen auf zwei Wegen — im Object Store beim Stromen, in `ea-format`
    // beim Parsen —, und ein Auseinanderlaufen waere ein Objekt, dessen
    // Adresse nicht zu seinem Inhalt gehoert.
    if staged_entry.object_hash() != entry.object_hash() {
        return Err(CommitServiceError::ObjectConflict.into());
    }

    let validated = match validate_commit(
        request,
        &entry,
        organization_id,
        chain_id,
        writer_certificate_hash,
        head.as_ref(),
    ) {
        Ok(validated) => validated,
        Err(error) => {
            return Err(validation_failure(
                error,
                entry.value().entry_hash(),
                bound_head(&entry),
                head.as_ref(),
                organization_id,
                now,
                ports,
            )
            .await);
        }
    };
    // Die LAENGEN zuerst: `zip` haelt bei der kuerzeren an, und ein Vergleich
    // ueber ein Praefix ist kein Vergleich. Beide Listen entstehen aus derselben
    // sortierten Lieferung, also ist eine Abweichung ein Widerspruch und keine
    // Erwartung.
    if staged_grants.len() != validated.grant_object_hashes.len() {
        return Err(CommitServiceError::Internal.into());
    }
    for (staged, expected) in staged_grants.iter().zip(&validated.grant_object_hashes) {
        if staged.object_hash() != *expected {
            return Err(CommitServiceError::ObjectConflict.into());
        }
    }

    // ---------------------------------------------------------------------
    // Schritt 3: die VERIFIZIERTEN Bytes content-addressed uebernehmen.
    // Gleiche Schluessel mit anderen Bytes sind ein Security Event.
    // ---------------------------------------------------------------------
    put_verified(staged_entry, organization_id, now, ports).await?;
    for staged in staged_grants {
        put_verified(staged, organization_id, now, ports).await?;
    }

    // ---------------------------------------------------------------------
    // Schritt 4: den Kettenkopf sperren.
    //
    // Die SPERRE selbst haelt `commit_locked_head` — sie muss dieselbe
    // Transaktion sein, in der Schritt 8 sichtbar schaltet, sonst waere
    // zwischen Sperre und Sichtbarkeit ein Fenster. Das LESEN des Kopfes ist
    // oben schon geschehen (`current`), weil Schritt 5 seine Annahmezeit
    // braucht und Schritt 2 wiederum den Kopf, den Schritt 5 daraus waehlt.
    // Bewegt er sich dazwischen, weist die Transaktion ihn ab, und
    // `classify_head_conflict` liest ihn dafuer erneut.
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Schritt 5: `acceptedAtServer` EINMALIG als Maximum aus Serverzeit und
    // Annahmezeit des direkten Vorgaengers, und der fuer GENAU DIESE ZEIT und
    // diese Sequenz gewaehlte Kopf.
    //
    // Beides ist oben geschehen, und die Reihenfolge darin ist die des
    // Spezifikationssatzes: erst die Zeit, dann der Kopf „fuer diese Zeit und
    // Sequenz" (`design.md`:1545). Die rohe Serveruhr taugt dafuer NICHT — sie
    // faellt von `acceptedAtServer` genau dann ab, wenn die Annahmezeit des
    // Vorgaengers vor ihr liegt, und dann waehlte sie einen Kopf fuer einen
    // Zeitpunkt, den keine Quittung je traegt.
    //
    // Bindet das Paket einen anderen Kopf als den so gewaehlten, hat Schritt 2
    // das mit `RegistryMismatch` festgestellt, und `validation_failure` nennt
    // dem Aufrufer den erforderlichen — in der Richtung, in die er zu gehen
    // hat.
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Schritt 6: ausschliesslich `currentSequence + 1`, der aktuelle Entry-Hash
    // als Vorgaenger und der dafuer autorisierte Writer.
    //
    // Der Writer steht seit Schritt 2 fest. Sequenz und Vorgaenger DURCHSETZEN
    // tut die gesperrte Transaktion aus Schritt 8 — dort, wo `design.md` §13.3
    // sie hingestellt hat, und nur dort ist die Aussage unter Nebenlaeufigkeit
    // ueberhaupt wahr.
    //
    // Hier steht deshalb KEINE zweite Pruefung. Eine solche Vorabpruefung war
    // die Falle: ein idempotenter Replay traegt die Sequenz, die BEREITS
    // vergeben ist, also `currentSequence` und nicht `currentSequence + 1`.
    // Sie haette jeden Retry nach einer verlorenen Antwort als `sequence-fork`
    // abgewiesen und dabei ein falsches Security Event geschrieben — obwohl
    // `commit_locked_head` den Replay korrekt erkennt, weil es seine
    // Identitaetssuche VOR seiner Sequenzpruefung fuehrt.
    //
    // Der gelesene Kopf aus Schritt 4 wird stattdessen aufgehoben. Er dient
    // Schritt 8 dazu, den „Kopfkonflikt" der Transaktion in die drei Befunde
    // zu ZERLEGEN, die §13.3 unterscheidet: Fork, falscher Vorgaenger und ein
    // schlicht verlorenes Rennen.
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Schritt 7: `receipt-core-v1` samt `evidence-due-at` bilden, signieren
    // und die exakten `esr-v1`-Bytes content-addressed ablegen. EINMAL.
    // ---------------------------------------------------------------------
    let receipt = build_receipt(
        ReceiptBindingV1 {
            organization_id,
            chain_id,
            chain_sequence: validated.chain_sequence,
            entry_hash: validated.entry_hash,
            entry_object_hash: validated.entry_object_hash,
            previous_entry_hash: validated.previous_entry_hash,
            registry_version: head.registry_version(),
            registry_head_hash: hash32_of(head.registry_head_hash())?,
            policy_object_hash: head.policy_object_hash(),
            initial_grant_plan_hash: request.identity().initial_grant_plan_hash(),
            initial_grant_object_hashes: validated.grant_object_hashes.clone(),
        },
        head.policy_fields(),
        accepted_at_server,
        ports.signer,
    )
    .map_err(CommitFailure::from)?;
    let evidence_due_at = receipt.core().fields().evidence_due_at;
    let receipt_bytes = exact_receipt_bytes(&receipt).map_err(CommitFailure::from)?;
    let receipt_limit = u64::try_from(ea_format::ESR_MAX_RAW_BYTES_V1).unwrap_or(u64::MAX);
    let staged_receipt = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Receipt,
            ByteStream::from(receipt_bytes.clone()),
            receipt_limit,
        )
        .await
        .map_err(CommitFailure::from)?;
    let receipt_object_hash = staged_receipt.object_hash();
    let receipt_size = staged_receipt.size_bytes();
    put_verified(staged_receipt, organization_id, now, ports).await?;

    // ---------------------------------------------------------------------
    // Schritt 8: Entry, initiale Grants, neuer Kettenkopf und der
    // `receiptObjectHash` GEMEINSAM sichtbar, in EINER Transaktion.
    // ---------------------------------------------------------------------
    let mut indexed_objects = validated.indexed_objects.clone();
    indexed_objects.push(IndexedObjectV1 {
        kind: ObjectTypeV1::Receipt,
        object_hash: receipt_object_hash,
        size_bytes: receipt_size,
    });
    let committed = match ports
        .commits
        .commit_locked_head(CommitDbCommand {
            organization_id,
            chain_id,
            device_id: validated.device_id,
            sequence: validated.chain_sequence,
            previous_entry_hash: validated.previous_entry_hash,
            identity: db_identity(request.identity()),
            receipt_object_hash,
            accepted_at_server,
            evidence_due_at,
            registry_version: head.registry_version(),
            registry_head_hash: head.registry_head_hash(),
            indexed_objects,
        })
        .await
    {
        Ok(committed) => committed,
        Err(RepositoryError::CommitIdentityConflict) => {
            record(
                organization_id,
                SecurityEventKindV1::EntryIdentityMismatch,
                &validated.entry_hash,
                now,
                ports,
            )
            .await;
            return Err(CommitServiceError::IdentityConflict.into());
        }
        Err(RepositoryError::HeadConflict) => {
            return Err(classify_head_conflict(
                &validated,
                current,
                organization_id,
                chain_id,
                now,
                ports,
            )
            .await);
        }
        Err(error) => return Err(CommitFailure::from(error)),
    };

    // ---------------------------------------------------------------------
    // Schritt 9: die Quittung anhand IHRES HASHES zurueklesen, ihre exakten
    // Bytes verifizieren und sie ausliefern.
    //
    // Gelesen wird der Hash, den die TRANSAKTION nennt, und nicht der eben
    // gebildete: bei einem Replay sind das verschiedene Objekte, und
    // ausgeliefert wird das gespeicherte.
    // ---------------------------------------------------------------------
    let stored_bytes = read_back(committed.receipt_object_hash, ports).await?;
    if committed.newly_committed {
        if stored_bytes != receipt_bytes {
            return Err(CommitServiceError::Receipt(ReceiptError::ReadBack).into());
        }
        return Ok(CommitOutcome::Accepted {
            receipt_bytes: stored_bytes,
        });
    }
    Ok(CommitOutcome::IdempotentReplay {
        receipt_bytes: stored_bytes,
    })
}

/// Die eine Kopfauswahl dieses Commits.
async fn select_head(
    organization_id: OrganizationId,
    sequence: ea_types::ChainSequence,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) -> Result<std::sync::Arc<dyn ActiveRegistryHeadV1>, CommitFailure> {
    match ports
        .heads
        .select_head_for_sequence(organization_id, sequence, now)
        .await
        .map_err(CommitFailure::from)?
    {
        RegistryHeadSelectionV1::Selected(head) => Ok(head),
        RegistryHeadSelectionV1::PendingFuture {
            required_registry_version,
            required_registry_head_hash,
        } => Err(CommitFailure::requiring_head(
            CommitServiceError::RegistryHeadRequired,
            required_registry_version,
            required_registry_head_hash,
        )),
        RegistryHeadSelectionV1::NoApplicableHead => {
            Err(CommitServiceError::NoApplicableRegistryHead.into())
        }
    }
}

/// Der Registry-Head, den das PAKET bindet.
fn bound_head(entry: &ea_format::Parsed<ea_format::EntryPackageV1>) -> (RegistryVersion, [u8; 32]) {
    let manifest = entry.value().manifest().fields();
    (manifest.registry_version, manifest.registry_head_hash)
}

/// Ein Pruefbefund, samt Security Event und erforderlichem Kopf.
///
/// # Der Registry-Head hat eine RICHTUNG
///
/// „Erforderlicher neuerer Registry-Head" steht in der 409-Zeile der Abbildung,
/// und `protocol-error-v1` fuehrt Version und Hash an eigenen
/// Pflichtpositionen. WELCHE Version dort steht, haengt daran, wer
/// hinterherhinkt:
///
/// * Bindet das Paket einen AELTEREN Kopf als den gewaehlten, hinkt der
///   Aufrufer. Er bekommt den Kopf des Servers genannt und holt ihn nach —
///   `design.md` §13.3, Schritt 5, woertlich.
/// * Bindet es einen NEUEREN, hinkt der SERVER. Ihm den Kopf des Servers zu
///   nennen hiesse, ihn rueckwaerts zu schicken: er soll einen Kopf binden, den
///   er nachweislich schon ueberholt hat. Genannt wird deshalb der Kopf, den
///   das Paket bindet — der Server muss ihn erst lernen, und der Weg dahin ist
///   `POST /v1/trust/events`. Es ist derselbe Befund wie ein noch nicht
///   anwendbarer Kopf aus der Auswahl, und er traegt denselben Code.
async fn validation_failure(
    error: CommitValidationError,
    entry_hash: ea_types::EntryHash,
    bound: (RegistryVersion, [u8; 32]),
    head: &dyn ActiveRegistryHeadV1,
    organization_id: OrganizationId,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) -> CommitFailure {
    if error.is_writer_violation() {
        // Der Gegenstand ist der ABGEWIESENE COMMIT und nicht der
        // Registry-Kopf: wer das Ereignis liest, muss erkennen koennen, WELCHE
        // Schreibung verweigert wurde. Der Eintragshash ist dafuer die
        // technische Kennung — und er traegt keinen fachlichen Wert.
        record(
            organization_id,
            SecurityEventKindV1::WriterUnauthorized,
            &entry_hash,
            now,
            ports,
        )
        .await;
    }
    if error == CommitValidationError::RegistryMismatch {
        let (bound_version, bound_hash) = bound;
        if bound_version.get() > head.registry_version().get() {
            let Ok(required) = ObjectHash::try_from(&bound_hash[..]) else {
                return CommitServiceError::Internal.into();
            };
            return CommitFailure::requiring_head(
                CommitServiceError::RegistryHeadRequired,
                bound_version,
                required,
            );
        }
        return CommitFailure::requiring_head(
            CommitServiceError::Validation(error),
            head.registry_version(),
            head.registry_head_hash(),
        );
    }
    CommitFailure::from(CommitServiceError::Validation(error))
}

/// Den „Kopfkonflikt" der Transaktion in die Befunde von §13.3 zerlegen.
///
/// `commit_locked_head` kennt genau einen Ausgang fuer vier verschiedene
/// Sachverhalte: die Sequenz war nicht `currentSequence + 1`, der Vorgaenger
/// war nicht der aktuelle Kopf, die Annahmezeit lag unter der des Vorgaengers,
/// oder jemand anderes hat das Rennen um den Kopf gewonnen. `design.md` §13.3
/// unterscheidet sie — die ersten beiden sind Security Events, die letzten
/// beiden ausdruecklich nicht.
///
/// ZUERST wird der Kopf ERNEUT gelesen. Bewegt er sich zwischen dem Lesen aus
/// Schritt 4 und der Sperre, dann ist jeder Vergleich gegen den ALTEN Stand
/// eine Anschuldigung ueber einen Zustand, den es nicht mehr gibt: ein
/// Nachzuegler, der ein Rennen verloren hat, bekaeme ein `sequence-fork`
/// eingetragen. Ein bewegter Kopf ist deshalb IMMER ein verlorenes Rennen,
/// und nur ein UNVERAENDERTER Kopf laesst die Unterscheidung zu.
///
/// Ist der Kopf auch beim Wiederlesen nicht abrufbar, wird ebenfalls kein
/// Ereignis geschrieben: eine Anschuldigung auf einer nicht beweisbaren
/// Grundlage ist schlimmer als keine.
async fn classify_head_conflict(
    validated: &ValidatedCommitV1,
    current: Option<ChainHeadStateV1>,
    organization_id: OrganizationId,
    chain_id: ChainId,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) -> CommitFailure {
    let Ok(observed) = ports.commits.head_state(organization_id, chain_id).await else {
        return CommitServiceError::HeadConflict.into();
    };
    if observed.map(head_identity) != current.map(head_identity) {
        return CommitServiceError::HeadConflict.into();
    }

    let expected_sequence = current.map_or(Some(0), |head| head.sequence.get().checked_add(1));
    let Some(expected_sequence) = expected_sequence else {
        return CommitServiceError::Internal.into();
    };
    if validated.chain_sequence.get() != expected_sequence {
        record(
            organization_id,
            SecurityEventKindV1::SequenceFork,
            &validated.entry_hash,
            now,
            ports,
        )
        .await;
        return CommitServiceError::SequenceFork.into();
    }
    if validated.previous_entry_hash != current.map(|head| head.entry_hash) {
        record(
            organization_id,
            SecurityEventKindV1::PredecessorMismatch,
            &validated.entry_hash,
            now,
            ports,
        )
        .await;
        return CommitServiceError::PredecessorMismatch.into();
    }
    // Sequenz und Vorgaenger passten, der Kopf steht unveraendert — dann hat
    // die Transaktion an der MONOTONIE der Annahmezeit abgewiesen, oder das
    // Rennen ging in einem Fenster verloren, das dieser Lesezugriff nicht
    // sieht. Beides ist ein verlorenes Rennen und kein Vorwurf.
    CommitServiceError::HeadConflict.into()
}

/// Die Identitaet eines Kopfes fuer den Vergleich zweier Lesezugriffe.
///
/// Sequenz, Eintragshash UND Annahmezeit: die ersten beiden koennten in einem
/// Sonderfall gleich bleiben, waehrend die Annahmezeit sich bewegt, und genau
/// diese Bewegung ist der Grund, aus dem die Transaktion abgewiesen haben
/// kann.
fn head_identity(head: ChainHeadStateV1) -> (u64, [u8; 32], i64) {
    (
        head.sequence.get(),
        *head.entry_hash.as_bytes(),
        head.accepted_at_server.get(),
    )
}

/// Schritt 3 fuer EIN Objekt, samt Security Event bei Bytekonflikt.
async fn put_verified(
    staged: crate::models::StagedObject,
    organization_id: OrganizationId,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) -> Result<(), CommitFailure> {
    let key = staged.object_key();
    match ports.objects.put_if_absent(staged).await {
        Ok(_) => Ok(()),
        Err(StoreError::HashConflict) => {
            record_subject(
                organization_id,
                SecurityEventKindV1::ObjectHashConflict,
                key,
                now,
                ports,
            )
            .await;
            Err(CommitServiceError::ObjectConflict.into())
        }
        Err(error) => Err(CommitFailure::from(error)),
    }
}

/// Schritt 9: die exakten Bytes zu diesem Hash.
async fn read_back(
    receipt_object_hash: ObjectHash,
    ports: &CommitPorts<'_>,
) -> Result<Vec<u8>, CommitFailure> {
    let stream = ports
        .objects
        .get_exact(receipt_object_hash)
        .await
        .map_err(CommitFailure::from)?;
    let bytes = stream
        .collect()
        .await
        .map_err(|_| CommitServiceError::DependencyUnavailable)?
        .into_bytes()
        .to_vec();
    // Der Beweis, dass die zurueckgelesenen Bytes DIESES Objekt sind: ihr Hash
    // gegen den Hash, unter dem sie stehen. Ohne ihn waere „zurueckgelesen"
    // nur ein zweiter Netzzugriff.
    if ea_crypto::object_hash(&bytes) != receipt_object_hash {
        return Err(CommitServiceError::Receipt(ReceiptError::ReadBack).into());
    }
    Ok(bytes)
}

/// Die Commit-Identitaet der Leitung als die der Persistenz.
///
/// Eine Umschreibung und keine zweite Ableitung:
/// [`ea_sync_protocol::EntryCommitIdentity`] hat die vier Bestandteile bereits
/// gebildet und die Grant-Hashes bytweise sortiert.
fn db_identity(identity: &EntryCommitIdentity) -> CommitIdentityV1 {
    CommitIdentityV1 {
        entry_hash: identity.entry_hash(),
        entry_object_hash: identity.entry_object_hash(),
        initial_grant_plan_hash: identity.initial_grant_plan_hash(),
        initial_grant_object_hashes: identity.sorted_grant_object_hashes().to_vec(),
    }
}

/// Ein `ObjectHash` als `Hash32` — `receipt-core-v1` fuehrt den Registry-Head
/// unter dem allgemeinen Hashtyp.
fn hash32_of(hash: ObjectHash) -> Result<ea_types::Hash32, CommitFailure> {
    ea_types::Hash32::try_from(&hash.as_bytes()[..])
        .map_err(|_| CommitFailure::from(CommitServiceError::Internal))
}

/// Ein Security Event ueber einen Eintragshash.
async fn record(
    organization_id: OrganizationId,
    kind: SecurityEventKindV1,
    entry_hash: &ea_types::EntryHash,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) {
    record_subject(
        organization_id,
        kind,
        hex::encode(entry_hash.as_bytes()),
        now,
        ports,
    )
    .await;
}

/// Ein Security Event ueber eine technische Kennung.
///
/// Der Ausgang wird ABSICHTLICH verworfen: der Befund, der gerade festgestellt
/// wurde, gilt auch dann, wenn er sich nicht protokollieren liess, und ihn in
/// einen Ausfall umzudeuten machte aus einer Abweisung eine Wiederholung.
async fn record_subject(
    organization_id: OrganizationId,
    kind: SecurityEventKindV1,
    subject: String,
    now: UnixMillis,
    ports: &CommitPorts<'_>,
) {
    let _ = ports
        .security
        .record(SecurityEventV1 {
            organization_id,
            kind,
            subject,
            observed_at: now,
        })
        .await;
}
