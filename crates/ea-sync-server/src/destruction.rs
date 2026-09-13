//! `POST /v1/destructions` und `GET /v1/destructions/{destructionId}`
//! (`design.md` §13.3, §16.3).
//!
//! # Was diese Stufe leistet — und was Stufe 5 leistet
//!
//! `design.md` §16.3 beschreibt einen Zustandsautomaten aus fuenf Zustaenden
//! und acht Uebergaengen, verteilt ueber Repliken, Attestierungen und
//! Backupfristen. DIESE Stufe baut davon genau die drei Zusagen, die der
//! Server allein halten kann und ohne die alles Weitere unsicher waere:
//!
//! 1. Angenommen wird AUSSCHLIESSLICH eine gueltige Mehr-Augen-
//!    `DestructionAuthorization` — zwei UNTERSCHIEDLICHE, aktuell berechtigte
//!    destructionApprove-Personen nach ihrer stabilen authoritySubjectId.
//! 2. Die Annahme legt eine nicht ausfuehrbare Sperrreservierung unter dem
//!    bestehenden Wire-Code requested an. Ohne signiertes Transition-Event
//!    ist diese Zeile KEIN autoritativer Zustand des Automaten. Der native
//!    Dienst ea-destruction bindet Reauth, Signatur und dauerhaftes Audit.
//! 3. Ab der Annahme sind neue Auslieferungen und historische Re-Grants fuer
//!    die Ziele GESPERRT (§16.3, Schritt 2).
//!
//! Zustandsuebergaenge, Attestierungen und `completeManagedScope` bleiben
//! Stufe 5. Die Ablage traegt sie bereits append-only, damit dort kein
//! Schema entsteht, das die Historie eines laufenden Vorgangs nachtraeglich
//! umschreiben koennte.
//!
//! # Die zwei Augen sind ZWEI
//!
//! Wie bei der `grantAuthorization` erzwingt `ea-format` nur „mindestens zwei
//! Signaturen“. Dass es zwei UNTERSCHIEDLICHE Approver sind, prueft
//! [`crate::historical_grant::distinct_approvers`] — einmal, geteilt, ueber
//! [`ea_crypto::verify_cose_sign1`] und
//! [`ea_crypto::VerificationContext::destruction_approval_trust_digest`].

use core::fmt;

use ea_crypto::{CryptoError, VerificationContext};
use ea_format::{
    DecodedTrustPayloadV1, FormatError, ObjectTypeV1, ParsedArchiveObject, decode_exact_object,
};
use ea_sync_protocol::{DestructionStatusResponseV1, ObjectRecordV1};
use ea_types::{ChainSequence, DestructionId, EntryHash, ObjectHash, OrganizationId};

use crate::{
    historical_grant::{REQUIRED_DISTINCT_APPROVERS_V1, distinct_approvers},
    models::{
        AppendOutcome, DestructionRequestCommandV1, IndexedObjectV1, RepositoryError, StoreError,
    },
    ports::{
        AuthorityError, ChainHeadReader, DestructionStore, ObjectStore, RegistryHeadDirectory,
        RegistryHeadSelectionV1, ServerClock,
    },
};

/// Der Code, mit dem eine gesperrte Auslieferung oder ein gesperrter Re-Grant
/// abgewiesen wird.
///
/// Er steht HIER und wird von [`crate::reader_sync`] und
/// [`crate::historical_grant`] mitbenutzt: die Sperre ist EINE Aussage, also
/// hat sie EINEN Code. Der Status ist `422` und nicht `403` — die Identitaet
/// des Aufrufers ist in Ordnung, die Auslieferung ist es nicht.
pub const DESTRUCTION_BLOCKED_CODE_V1: &str = "EA-DESTRUCTION-BLOCKED";

/// Der Startzustand jedes Vorgangs: `requested` (`design.md` §16.3).
pub const DESTRUCTION_STATE_REQUESTED_V1: u8 = 0;

/// Was der Vernichtungspfad an Ports braucht.
pub struct DestructionPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub objects: &'a dyn ObjectStore,
    pub destructions: &'a dyn DestructionStore,
    pub heads: &'a dyn RegistryHeadDirectory,
    pub chain_heads: &'a dyn ChainHeadReader,
}

/// Warum ein Vernichtungsvorgang nicht angenommen oder nicht ausgegeben wurde.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DestructionError {
    /// Root-signed policy must enable destruction and name the recorded privacy decision.
    PrivacyGate,
    /// Die gelieferten Bytes sind kein `.etb`, keine
    /// `destructionAuthorization`, oder sie binden eine andere Organisation.
    AuthorizationInvalid,
    /// Ihre Signaturen tragen nicht, oder ein Approver ist zur
    /// Autorisierungssequenz nicht berechtigt.
    AuthorizationUnverifiable,
    /// Sie traegt weniger als [`REQUIRED_DISTINCT_APPROVERS_V1`]
    /// UNTERSCHIEDLICHE Approver.
    AuthorizationInsufficient,
    /// Diese Organisation kennt diese Vernichtungskennung nicht.
    Unknown,
    /// Unter derselben Kennung liegt bereits ein ANDERER Vorgang.
    Conflict,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
}

impl DestructionError {
    /// Alle Arme — damit ein spaeter ergaenzter sofort auffaellt.
    pub const ALL: [Self; 8] = [
        Self::PrivacyGate,
        Self::AuthorizationInvalid,
        Self::AuthorizationUnverifiable,
        Self::AuthorizationInsufficient,
        Self::Unknown,
        Self::Conflict,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrivacyGate => "EA-DESTRUCTION-PRIVACY-GATE",
            Self::AuthorizationInvalid => "EA-DESTRUCTION-AUTHORIZATION-INVALID",
            Self::AuthorizationUnverifiable => "EA-DESTRUCTION-AUTHORIZATION-UNVERIFIABLE",
            Self::AuthorizationInsufficient => "EA-DESTRUCTION-AUTHORIZATION-INSUFFICIENT",
            Self::Unknown => "EA-DESTRUCTION-UNKNOWN",
            Self::Conflict => "EA-DESTRUCTION-CONFLICT",
            Self::DependencyUnavailable => "EA-DESTRUCTION-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-DESTRUCTION-INTERNAL",
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unknown => 404,
            Self::Conflict => 409,
            Self::DependencyUnavailable => 503,
            Self::Internal => 500,
            _ => 422,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<FormatError> for DestructionError {
    fn from(_: FormatError) -> Self {
        Self::AuthorizationInvalid
    }
}

impl From<CryptoError> for DestructionError {
    fn from(_: CryptoError) -> Self {
        Self::AuthorizationUnverifiable
    }
}

impl From<RepositoryError> for DestructionError {
    fn from(_: RepositoryError) -> Self {
        Self::DependencyUnavailable
    }
}

impl From<AuthorityError> for DestructionError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Unavailable | AuthorityError::StateConflict => {
                Self::DependencyUnavailable
            }
        }
    }
}

impl From<StoreError> for DestructionError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::HashConflict => Self::Conflict,
            StoreError::LimitExceeded | StoreError::ObjectTypeMismatch => {
                Self::AuthorizationInvalid
            }
            // Ein indiziertes Objekt ohne Bytes ist ein Widerspruch im Bestand
            // des Servers und keine Aussage ueber den Aufrufer.
            StoreError::NotFound => Self::Internal,
            StoreError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for DestructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for DestructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for DestructionError {}

/// `POST /v1/destructions` — nimmt GENAU EINE Mehr-Augen-Authorization an.
///
/// Die Antwort ist die Sperrreservierung: Wire-Code requested, ohne
/// signierten Uebergang und ohne Attestierung. 202 bedeutet angenommen.
/// Erst der native, signierte und dauerhaft auditierte Start berechtigt den
/// Executor zur weiteren Vorpruefung; die Datenbankzahl allein tut das nicht.
///
/// # Errors
///
/// Jeder Arm von [`DestructionError`].
pub async fn accept_destruction_request(
    organization_id: OrganizationId,
    exact_authorization_etb_bytes: &[u8],
    ports: &DestructionPorts<'_>,
) -> Result<DestructionStatusResponseV1, DestructionError> {
    let now = ports.clock.now();

    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact_authorization_etb_bytes)?
    else {
        return Err(DestructionError::AuthorizationInvalid);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) = object.decoded_payload()? else {
        return Err(DestructionError::AuthorizationInvalid);
    };
    if fields.organization_id != organization_id {
        return Err(DestructionError::AuthorizationInvalid);
    }
    // Die Zielmenge ist nicht leer, aufsteigend und duplikatfrei — die Regel
    // steht in `ea-format` und wird hier NICHT nachgebaut.
    ea_format::validate_destruction_targets(&fields.targets)?;

    // Exact replay reads the existing immutable reservation. It grants no new
    // authority, writes no objects and remains available after policy changes.
    if let Some(saved) = ports
        .destructions
        .destruction_state(organization_id, fields.destruction_id)
        .await?
    {
        if saved.authorization_object_hash != parsed.object_hash() {
            return Err(DestructionError::Conflict);
        }
        let exact = ports
            .objects
            .get_exact_in(ObjectTypeV1::Trust, saved.authorization_object_hash)
            .await?
            .collect()
            .await
            .map_err(|_| DestructionError::DependencyUnavailable)?
            .into_bytes();
        if exact.as_ref() != exact_authorization_etb_bytes {
            return Err(DestructionError::Conflict);
        }
        return destruction_status(organization_id, fields.destruction_id, ports).await;
    }

    // Die Approver werden zur AUTORISIERUNGSSEQUENZ aufgeloest, nicht zur
    // aktuellen Kettenposition: die Autorisierung nennt sie selbst, und ihre
    // Berechtigung ist an genau diese Position gebunden.
    let head = match ports
        .heads
        .select_head_for_sequence(
            organization_id,
            ChainSequence::new(fields.authorization_sequence),
            now,
        )
        .await?
    {
        RegistryHeadSelectionV1::Selected(head) => head,
        RegistryHeadSelectionV1::PendingFuture { .. }
        | RegistryHeadSelectionV1::NoApplicableHead => {
            return Err(DestructionError::AuthorizationUnverifiable);
        }
    };
    // Native reauthentication and its signed audit live in the local request
    // service. This endpoint grants only a non-executable block reservation.
    // It MUST still enforce the signed privacy gate for direct HTTP clients.
    let policy = &head.policy_fields().retention_policy;
    if !policy.destruction_enabled || policy.eds_privacy_decision_document_hash.is_none() {
        return Err(DestructionError::PrivacyGate);
    }
    if fields.registry_version != head.registry_version()
        || fields.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || fields.organization_id != head.policy_fields().organization_id
    {
        return Err(DestructionError::AuthorizationUnverifiable);
    }
    let approvers = distinct_approvers(
        object.signatures(),
        object.exact_digest_input(),
        head.as_ref(),
        |digest_input, certificate_hash| {
            VerificationContext::destruction_approval_trust_digest(digest_input, certificate_hash)
        },
    )
    .map_err(|_| DestructionError::AuthorizationUnverifiable)?;
    if approvers < REQUIRED_DISTINCT_APPROVERS_V1 {
        return Err(DestructionError::AuthorizationInsufficient);
    }

    // NEW reservations require the policy at the server's next committed
    // operation, independently of authorization_sequence. A published future
    // successor is not effective until this boundary actually reaches it.
    let chain_id = head.chain_id();
    let expected_chain_head = ports
        .chain_heads
        .committed_chain_head(organization_id, chain_id)
        .await?
        .ok_or(DestructionError::AuthorizationUnverifiable)?;
    let next = expected_chain_head
        .sequence
        .get()
        .checked_add(1)
        .ok_or(DestructionError::AuthorizationUnverifiable)?;
    let current_admission = ports
        .heads
        .select_current_admission(organization_id, ChainSequence::new(next), now)
        .await?
        .ok_or(DestructionError::AuthorizationUnverifiable)?;
    let current = &current_admission.head;
    if current.chain_id() != chain_id || current.policy_fields().organization_id != organization_id
    {
        return Err(DestructionError::AuthorizationUnverifiable);
    }
    let current_policy = &current.policy_fields().retention_policy;
    if !current_policy.destruction_enabled
        || current_policy.eds_privacy_decision_document_hash.is_none()
    {
        return Err(DestructionError::PrivacyGate);
    }

    // Erst jetzt wird abgelegt. Die Authorization liegt content-addressed im
    // `etb/`-Namensraum wie jedes andere Trust-Objekt.
    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Trust,
            aws_sdk_s3::primitives::ByteStream::from(exact_authorization_etb_bytes.to_vec()),
            ea_format::ETB_MAX_RAW_BYTES_V1 as u64,
        )
        .await?;
    let stored = ports.objects.put_if_absent(staged).await?;

    let targets: Vec<(EntryHash, u64)> = fields
        .targets
        .iter()
        .map(|target| {
            Ok((
                EntryHash::try_from(&target.entry_hash()[..])
                    .map_err(|_| DestructionError::AuthorizationInvalid)?,
                target.chain_sequence(),
            ))
        })
        .collect::<Result<_, DestructionError>>()?;

    let outcome = ports
        .destructions
        .record_destruction_request(
            DestructionRequestCommandV1 {
                organization_id,
                chain_id,
                expected_chain_head,
                authority_fence: current_admission.fence,
                destruction_id: fields.destruction_id,
                authorization: IndexedObjectV1 {
                    kind: ObjectTypeV1::Trust,
                    object_hash: stored.object_hash(),
                    size_bytes: stored.size_bytes(),
                },
                targets,
                requested_at: now,
            },
            ports.clock,
        )
        .await?;
    if outcome == AppendOutcome::Conflict {
        return Err(DestructionError::Conflict);
    }

    // Der ausgegebene Stand kommt aus der ABLAGE und nicht aus dem, was diese
    // Funktion gerade gemeint hat: bei einer Wiederholung ist es der
    // gespeicherte Vorgang, genau wie beim idempotenten Commit-Replay.
    destruction_status(organization_id, fields.destruction_id, ports).await
}

/// `GET /v1/destructions/{destructionId}` — der gespeicherte Stand.
///
/// Die Uebergaenge und Attestierungen reisen als EXAKTE Objektbytes: der
/// Empfaenger rekonstruiert den Automaten aus ihnen selbst und nicht aus einer
/// Zahl, die der Server behauptet (`design.md` §16.3: „Ein Neustart
/// rekonstruiert Zustand und naechsten ausstehenden Schritt aus Authorization,
/// Transition-Events und Attestierungen“).
///
/// # Errors
///
/// Jeder Arm von [`DestructionError`].
pub async fn destruction_status(
    organization_id: OrganizationId,
    destruction_id: DestructionId,
    ports: &DestructionPorts<'_>,
) -> Result<DestructionStatusResponseV1, DestructionError> {
    let state = ports
        .destructions
        .destruction_state(organization_id, destruction_id)
        .await?
        .ok_or(DestructionError::Unknown)?;
    // A successful status is the host's delivery-barrier observation. Re-read
    // the exact accepted signed target set and require every reservation row;
    // a status flag or an unrelated operation's target block is insufficient.
    let exact = ports
        .objects
        .get_exact_in(ObjectTypeV1::Trust, state.authorization_object_hash)
        .await?
        .collect()
        .await
        .map_err(|_| DestructionError::DependencyUnavailable)?
        .into_bytes();
    let ParsedArchiveObject::Trust(auth) = decode_exact_object(&exact)? else {
        return Err(DestructionError::Internal);
    };
    let DecodedTrustPayloadV1::DestructionAuthorization(fields) = auth.value().decoded_payload()?
    else {
        return Err(DestructionError::Internal);
    };
    if auth.object_hash() != state.authorization_object_hash
        || fields.organization_id != organization_id
        || fields.destruction_id != destruction_id
    {
        return Err(DestructionError::Conflict);
    }
    let targets = fields
        .targets
        .iter()
        .map(|t| {
            Ok((
                EntryHash::try_from(t.entry_hash().as_slice())
                    .map_err(|_| DestructionError::Internal)?,
                t.chain_sequence(),
            ))
        })
        .collect::<Result<Vec<_>, DestructionError>>()?;
    if !ports
        .destructions
        .reservation_matches(
            organization_id,
            destruction_id,
            state.authorization_object_hash,
            &targets,
        )
        .await?
    {
        return Err(DestructionError::Conflict);
    }
    let transitions = exact_records(&state.transition_object_hashes, ports).await?;
    let attestations = exact_records(&state.attestation_object_hashes, ports).await?;
    crate::managed_destruction::verify_stored_history(
        organization_id,
        destruction_id,
        &state,
        &transitions,
        &attestations,
        ports,
    )
    .await?;
    DestructionStatusResponseV1::new(
        destruction_id,
        state.state,
        state.authorization_object_hash,
        transitions,
        attestations,
    )
    .map_err(|_| DestructionError::Internal)
}

/// Die exakten `.etb`-Bytes zu diesen Adressen, sortiert und duplikatfrei.
///
/// Duplikatfrei ueber einen `BTreeMap` und nicht ueber ein nachtraegliches
/// `dedup`: `destruction-status-response-v1` verlangt bytweise aufsteigende,
/// DUPLIKATFREIE Objektlisten, und die Sortierung faellt beim Sammeln ohnehin
/// an. Die Ablage kann heute keinen Hash zweimal liefern — beide Tabellen
/// fuehren `object_hash` als Primaerschluessel —, aber die Zusage des Rahmens
/// haengt dann an einer Eigenschaft, die woanders steht.
async fn exact_records(
    hashes: &[ObjectHash],
    ports: &DestructionPorts<'_>,
) -> Result<Vec<ObjectRecordV1>, DestructionError> {
    let mut sorted = std::collections::BTreeMap::new();
    for hash in hashes {
        if sorted.contains_key(hash.as_bytes()) {
            continue;
        }
        let bytes = ports
            .objects
            .get_exact_in(ObjectTypeV1::Trust, *hash)
            .await?
            .collect()
            .await
            .map_err(|_| DestructionError::DependencyUnavailable)?
            .into_bytes()
            .to_vec();
        if ea_crypto::object_hash(&bytes) != *hash {
            return Err(DestructionError::Internal);
        }
        sorted.insert(*hash.as_bytes(), ObjectRecordV1::new(*hash, bytes));
    }
    Ok(sorted.into_values().collect())
}
