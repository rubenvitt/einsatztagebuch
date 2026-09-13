//! Historical re-grants verify approval-time authority independently of Entry age.
use core::fmt;

use ea_crypto::{CryptoError, VerificationContext, verify_cose_sign1};
use ea_format::{
    DecodedTrustPayloadV1, FormatError, GrantAuthorizationFieldsV1, GrantKindV1, GrantPurposeV1,
    GrantV1, ObjectTypeV1, ParsedArchiveObject, decode_exact_object,
};
use ea_sync_protocol::MAX_GRANT_OBJECT_BYTES_V1;
use ea_types::{
    CertificateHash, ChainSequence, EntryHash, ObjectHash, OrganizationId, RegistryVersion,
    UnixMillis,
};

use crate::{
    models::{
        AppendOutcome, HistoricalGrantCommandV1, IndexedObjectV1, RepositoryError, StoreError,
    },
    ports::{
        ActiveRegistryHeadV1, AuthorityError, DestructionStore, EntryDirectory,
        HistoricalGrantStore, ObjectStore, RegistryHeadDirectory, RegistryHeadSelectionV1,
        ServerClock,
    },
    validation::HeadResolver,
};

/// Wie viele unterschiedliche Approver eine Mehr-Augen-Autorisierung
/// mindestens tragen muss (`design.md` §16.2).
pub const REQUIRED_DISTINCT_APPROVERS_V1: usize = 2;

/// Was der Annahmepfad an Ports braucht.
pub struct HistoricalGrantPorts<'a> {
    pub clock: &'a dyn ServerClock,
    pub objects: &'a dyn ObjectStore,
    pub entries: &'a dyn EntryDirectory,
    pub grants: &'a dyn HistoricalGrantStore,
    pub heads: &'a dyn RegistryHeadDirectory,
    pub destructions: &'a dyn DestructionStore,
}

/// Warum ein historischer Grant nicht angenommen wurde.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HistoricalGrantError {
    /// Die gelieferten Bytes sind kein `.eag`, kein HISTORISCHER Grant, oder
    /// sie binden eine andere Organisation, Kette oder einen anderen Eintrag
    /// als der Pfad.
    GrantInvalid,
    /// Der Pfad nennt einen Eintrag, den diese Organisation nicht fuehrt.
    EntryUnknown,
    /// Die Ausstellersignatur traegt nicht, oder das Ausstellerzertifikat ist
    /// zur aktuellen Autorisierungssequenz nicht als Historical Grant Authority aktiv.
    IssuerUnauthorized,
    /// Der genannte urspruengliche Recovery-Grant fehlt, ist kein
    /// Recovery-Grant, oder gehoert zu einem anderen Eintrag.
    RecoveryGrantMismatch,
    /// Die genannte `GrantAuthorization` fehlt, ist keine, oder ihre
    /// Signaturen tragen nicht.
    AuthorizationUnverifiable,
    /// Sie traegt weniger als [`REQUIRED_DISTINCT_APPROVERS_V1`]
    /// UNTERSCHIEDLICHE Approver.
    AuthorizationInsufficient,
    /// Sie deckt diesen Eintrag oder diesen Empfaenger nicht ab.
    AuthorizationMismatch,
    /// `effectiveNow > expiresAt`. Ein abgelaufener Grant wird weder
    /// angenommen noch ausgeliefert (`design.md` §13.3).
    Expired,
    /// Der Grant bindet einen anderen als den aktuell anwendbaren
    /// Registrierungskopf.
    RegistryStale,
    /// Fuer diesen Eintrag laeuft ein Vernichtungsvorgang; ein Re-Grant ist
    /// gesperrt (`design.md` §16.3, Schritt 2).
    Blocked,
    /// Unter derselben Adresse liegen bereits ANDERE Bytes.
    Conflict,
    /// Datenbank oder Object Store antworten nicht.
    DependencyUnavailable,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
}

impl HistoricalGrantError {
    /// Alle Arme — damit ein spaeter ergaenzter sofort auffaellt.
    pub const ALL: [Self; 13] = [
        Self::GrantInvalid,
        Self::EntryUnknown,
        Self::IssuerUnauthorized,
        Self::RecoveryGrantMismatch,
        Self::AuthorizationUnverifiable,
        Self::AuthorizationInsufficient,
        Self::AuthorizationMismatch,
        Self::Expired,
        Self::RegistryStale,
        Self::Blocked,
        Self::Conflict,
        Self::DependencyUnavailable,
        Self::Internal,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GrantInvalid => "EA-GRANT-INVALID",
            Self::EntryUnknown => "EA-GRANT-ENTRY-UNKNOWN",
            Self::IssuerUnauthorized => "EA-GRANT-ISSUER-UNAUTHORIZED",
            Self::RecoveryGrantMismatch => "EA-GRANT-RECOVERY-MISMATCH",
            Self::AuthorizationUnverifiable => "EA-GRANT-AUTHORIZATION-UNVERIFIABLE",
            Self::AuthorizationInsufficient => "EA-GRANT-AUTHORIZATION-INSUFFICIENT",
            Self::AuthorizationMismatch => "EA-GRANT-AUTHORIZATION-MISMATCH",
            Self::Expired => "EA-GRANT-EXPIRED",
            Self::RegistryStale => "EA-GRANT-REGISTRY-STALE",
            Self::Blocked => crate::destruction::DESTRUCTION_BLOCKED_CODE_V1,
            Self::Conflict => "EA-GRANT-CONFLICT",
            Self::DependencyUnavailable => "EA-GRANT-DEPENDENCY-UNAVAILABLE",
            Self::Internal => "EA-GRANT-INTERNAL",
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::EntryUnknown => 404,
            // Die 409-Zeile: „… oder erforderlicher neuerer Registry-Head“.
            Self::RegistryStale | Self::Conflict => 409,
            Self::DependencyUnavailable => 503,
            Self::Internal => 500,
            // Alles Uebrige ist wohlgeformt, aber ungueltig in Trust, Format,
            // Grant oder Autorisierung.
            _ => 422,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

impl From<FormatError> for HistoricalGrantError {
    fn from(_: FormatError) -> Self {
        Self::GrantInvalid
    }
}

impl From<CryptoError> for HistoricalGrantError {
    fn from(_: CryptoError) -> Self {
        Self::IssuerUnauthorized
    }
}

impl From<RepositoryError> for HistoricalGrantError {
    fn from(_: RepositoryError) -> Self {
        Self::DependencyUnavailable
    }
}

impl From<AuthorityError> for HistoricalGrantError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Unavailable | AuthorityError::StateConflict => {
                Self::DependencyUnavailable
            }
        }
    }
}

impl From<StoreError> for HistoricalGrantError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::HashConflict => Self::Conflict,
            StoreError::LimitExceeded | StoreError::ObjectTypeMismatch => Self::GrantInvalid,
            // Ein Objekt, das der Grant NENNT und das nicht da ist, ist kein
            // Ausfall des Servers, sondern ein unvollstaendiger Grant.
            StoreError::NotFound => Self::AuthorizationUnverifiable,
            StoreError::Unavailable => Self::DependencyUnavailable,
        }
    }
}

impl fmt::Display for HistoricalGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for HistoricalGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for HistoricalGrantError {}

/// Der Befund samt dem Kopf, den der Aufrufer vorher holen muss.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HistoricalGrantFailure {
    pub error: HistoricalGrantError,
    pub required_registry_version: Option<RegistryVersion>,
    pub required_registry_head_hash: Option<ObjectHash>,
}

impl<E: Into<HistoricalGrantError>> From<E> for HistoricalGrantFailure {
    fn from(value: E) -> Self {
        Self {
            error: value.into(),
            required_registry_version: None,
            required_registry_head_hash: None,
        }
    }
}

impl fmt::Debug for HistoricalGrantFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.error, formatter)
    }
}

/// Nimmt GENAU EIN exaktes `.eag` als historischen Grant an.
///
/// Die Reihenfolge ist fail-closed und nicht verhandelbar:
///
/// 1. Objektfamilie, Grantart und Organisationsbindung aus den EXAKTEN Bytes,
/// 2. Ziel-Entry — ein unbekannter Eintrag ist `404` und nicht `422`,
/// 3. die Vernichtungssperre, BEVOR irgendetwas abgelegt wird,
/// 4. der zur Eintragssequenz anwendbare Registrierungskopf,
/// 5. die Ausstellersignatur ueber die geteilte `ea-crypto`-Kante,
/// 6. der urspruengliche Recovery-Grant,
/// 7. die Mehr-Augen-Autorisierung samt Frist,
/// 8. und erst dann die Ablage.
///
/// Schritt 8 beruehrt AUSDRUECKLICH weder `.eip` noch initialen Grant-Plan
/// noch Kettenkopf — [`HistoricalGrantStore`] hat kein Feld, mit dem er es
/// koennte.
///
/// # Errors
///
/// Jeder Arm von [`HistoricalGrantError`].
pub async fn accept_historical_grant(
    organization_id: OrganizationId,
    caller_certificate_hash: CertificateHash,
    path_entry_hash: EntryHash,
    exact_eag_bytes: &[u8],
    ports: &HistoricalGrantPorts<'_>,
) -> Result<(), HistoricalGrantFailure> {
    let now = ports.clock.now();
    if exact_eag_bytes.len() > MAX_GRANT_OBJECT_BYTES_V1 {
        return Err(HistoricalGrantError::GrantInvalid.into());
    }

    // 1. Form, Art und Bindung.
    let ParsedArchiveObject::Grant(parsed) =
        decode_exact_object(exact_eag_bytes).map_err(HistoricalGrantError::from)?
    else {
        return Err(HistoricalGrantError::GrantInvalid.into());
    };
    let grant: &GrantV1 = parsed.value();
    let fields = grant.grant_body().fields();
    if grant.kind() != GrantKindV1::Historical
        || fields.organization_id != organization_id
        || fields.entry_hash != path_entry_hash
        || fields.issuer_certificate_hash != caller_certificate_hash
    {
        return Err(HistoricalGrantError::GrantInvalid.into());
    }

    // 2. Der Ziel-Entry, und ueber ihn die Sequenz, zu der alles Weitere
    //    geprueft wird.
    let entry = ports
        .entries
        .entry_of(organization_id, path_entry_hash)
        .await
        .map_err(HistoricalGrantError::from)?
        .ok_or(HistoricalGrantError::EntryUnknown)?;
    let bound = ports
        .entries
        .entry_at(organization_id, fields.chain_id, entry.sequence)
        .await
        .map_err(HistoricalGrantError::from)?;
    if bound.map(|found| found.entry_hash) != Some(path_entry_hash) {
        return Err(HistoricalGrantError::GrantInvalid.into());
    }

    // 3. Die Sperre VOR jeder Ablage.
    if ports
        .destructions
        .is_destruction_target(organization_id, path_entry_hash)
        .await
        .map_err(HistoricalGrantError::from)?
    {
        return Err(HistoricalGrantError::Blocked.into());
    }

    let authorization_hash = fields
        .grant_authorization_object_hash
        .ok_or(HistoricalGrantError::AuthorizationUnverifiable)?;
    let authorization =
        verify_grant_authorization(authorization_hash, now, ports, organization_id).await?;
    // A later Reader/HGA is authorized at the approval sequence, independently
    // of the immutable historical Entry sequence.
    let authorization_sequence = ChainSequence::new(authorization.authorization_sequence);
    let committed = ports
        .entries
        .chain_head(organization_id, fields.chain_id)
        .await
        .map_err(HistoricalGrantError::from)?
        .ok_or(HistoricalGrantError::EntryUnknown)?;
    let current_sequence = ChainSequence::new(
        committed
            .sequence
            .get()
            .checked_add(1)
            .ok_or(HistoricalGrantError::GrantInvalid)?,
    );
    if authorization_sequence > current_sequence {
        return Err(HistoricalGrantError::AuthorizationMismatch.into());
    }
    let head = select_head(organization_id, current_sequence, now, ports).await?;
    if fields.registry_version != head.registry_version()
        || fields.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
    {
        return Err(HistoricalGrantFailure {
            error: HistoricalGrantError::RegistryStale,
            required_registry_version: Some(head.registry_version()),
            required_registry_head_hash: Some(head.registry_head_hash()),
        });
    }

    // 5. Die Ausstellersignatur. Rolle und Capability stecken IM Kontext —
    //    `historical_grant` bindet `SignerRole::HistoricalGrantAuthority` und
    //    `CertificateCapability::HistoricalGrant`. Diese Datei liest keine
    //    Capability von Hand.
    let context =
        VerificationContext::historical_grant(grant.grant_body().exact_bytes(), current_sequence)
            .map_err(HistoricalGrantError::from)?;
    verify_cose_sign1(
        grant.issuer_signature(),
        &HeadResolver(head.as_ref()),
        &context,
    )
    .map_err(|_| HistoricalGrantError::IssuerUnauthorized)?;

    // 6. Der urspruengliche Recovery-Grant.
    let recovery_hash = fields
        .original_recovery_grant_object_hash
        .ok_or(HistoricalGrantError::RecoveryGrantMismatch)?;
    verify_original_recovery_grant(recovery_hash, &entry, organization_id, now, ports).await?;

    if !authorization.entry_hashes.contains(&path_entry_hash)
        || authorization.recipient_key_thumbprint != fields.recipient_key_thumbprint
        || authorization.recipient_certificate_hash != fields.recipient_certificate_hash
    {
        return Err(HistoricalGrantError::AuthorizationMismatch.into());
    }

    if authorization.registry_version != fields.registry_version
        || authorization.registry_head_hash != fields.registry_head_hash
        || fields.purpose != GrantPurposeV1::Reader
        || !head.active_certificates().iter().any(|(hash, cert)| {
            *hash == fields.recipient_certificate_hash
                && cert.certificate_kind == ea_format::CertificateKindV1::Reader
                && cert.kem_key_thumbprint == Some(fields.recipient_key_thumbprint)
        })
    {
        return Err(HistoricalGrantError::AuthorizationMismatch.into());
    }
    // Recheck the deadline immediately before crossing the publication boundary.
    if ports.clock.now() > authorization.expires_at {
        return Err(HistoricalGrantError::Expired.into());
    }
    // 8. Die Ablage. `expiresAt` kommt aus der Autorisierung und nicht aus dem
    //    Grant: die Frist gehoert der Mehr-Augen-Entscheidung, und der Grant
    //    fuehrt sie gar nicht.
    store_grant(
        organization_id,
        path_entry_hash,
        exact_eag_bytes,
        fields.recipient_key_thumbprint,
        authorization.expires_at,
        now,
        ports,
    )
    .await
}

async fn select_head(
    organization_id: OrganizationId,
    sequence: ChainSequence,
    now: UnixMillis,
    ports: &HistoricalGrantPorts<'_>,
) -> Result<std::sync::Arc<dyn ActiveRegistryHeadV1>, HistoricalGrantFailure> {
    match ports
        .heads
        .select_head_for_sequence(organization_id, sequence, now)
        .await
        .map_err(HistoricalGrantError::from)?
    {
        RegistryHeadSelectionV1::Selected(head) => Ok(head),
        RegistryHeadSelectionV1::PendingFuture {
            required_registry_version,
            required_registry_head_hash,
        } => Err(HistoricalGrantFailure {
            error: HistoricalGrantError::RegistryStale,
            required_registry_version: Some(required_registry_version),
            required_registry_head_hash: Some(required_registry_head_hash),
        }),
        RegistryHeadSelectionV1::NoApplicableHead => {
            Err(HistoricalGrantError::IssuerUnauthorized.into())
        }
    }
}

/// Der urspruengliche Recovery-Grant, content-addressed aufgeloest.
///
/// Er ist die Quelle des historischen CEK (`design.md` §16.2: „Der Recovery
/// Custodian entkapselt nur den historischen CEK aus dem urspruenglichen
/// Recovery-Grant“). Der Server oeffnet ihn NICHT — er ist blind — und prueft
/// nur, dass der genannte Grant existiert, zu DIESEM Eintrag gehoert und
/// tatsaechlich der Recovery-Grant ist.
async fn verify_original_recovery_grant(
    recovery_hash: ObjectHash,
    entry: &crate::models::EntryIndexEntryV1,
    organization_id: OrganizationId,
    now: UnixMillis,
    ports: &HistoricalGrantPorts<'_>,
) -> Result<(), HistoricalGrantFailure> {
    let delivery = ports
        .entries
        .grant_delivery(organization_id, recovery_hash)
        .await
        .map_err(HistoricalGrantError::from)?
        .ok_or(HistoricalGrantError::RecoveryGrantMismatch)?;
    if delivery.entry_hash != entry.entry_hash || delivery.expires_at.is_some() {
        return Err(HistoricalGrantError::RecoveryGrantMismatch.into());
    }
    let entry_bytes = exact_bytes(ObjectTypeV1::Entry, entry.entry_object_hash, ports).await?;
    let ParsedArchiveObject::Entry(package) = decode_exact_object(&entry_bytes)
        .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?
    else {
        return Err(HistoricalGrantError::RecoveryGrantMismatch.into());
    };
    let manifest = package.value().manifest().fields();
    let bytes = exact_bytes(ObjectTypeV1::Grant, recovery_hash, ports)
        .await
        .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?;
    let ParsedArchiveObject::Grant(parsed) =
        decode_exact_object(&bytes).map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?
    else {
        return Err(HistoricalGrantError::RecoveryGrantMismatch.into());
    };
    let recovery: &GrantV1 = parsed.value();
    let fields = recovery.grant_body().fields();
    if recovery.purpose() != GrantPurposeV1::Recovery
        || recovery.kind() != GrantKindV1::Initial
        || fields.entry_hash != entry.entry_hash
        || fields.organization_id != organization_id
        || fields.chain_id != manifest.chain_id
        || fields.issuer_certificate_hash != manifest.writer_certificate_hash
        || fields.registry_version != manifest.registry_version
        || fields.registry_head_hash.as_bytes() != &manifest.registry_head_hash
    {
        return Err(HistoricalGrantError::RecoveryGrantMismatch.into());
    }
    let context =
        VerificationContext::initial_grant(recovery.grant_body().exact_bytes(), entry.sequence)
            .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?;
    let archived = ports
        .heads
        .historical_registry_authority(
            organization_id,
            manifest.registry_version,
            ObjectHash::try_from(manifest.registry_head_hash.as_slice())
                .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?,
            entry.sequence,
        )
        .await
        .map_err(HistoricalGrantError::from)?;
    if let Some(head) = archived {
        verify_cose_sign1(recovery.issuer_signature(), &head, &context)
            .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?;
    } else {
        let head = select_head(organization_id, entry.sequence, now, ports).await?;
        if head.registry_version() != manifest.registry_version
            || head.registry_head_hash().as_bytes() != &manifest.registry_head_hash
        {
            return Err(HistoricalGrantError::RecoveryGrantMismatch.into());
        }
        verify_cose_sign1(
            recovery.issuer_signature(),
            &HeadResolver(head.as_ref()),
            &context,
        )
        .map_err(|_| HistoricalGrantError::RecoveryGrantMismatch)?;
    }
    Ok(())
}

/// Die Mehr-Augen-`GrantAuthorization`, content-addressed aufgeloest und
/// vollstaendig geprueft.
///
/// Geprueft wird ueber die GETEILTE Kante: jede Signatur laeuft durch
/// [`verify_cose_sign1`] mit
/// [`VerificationContext::historical_grant_approval_trust_digest`], und der
/// Kontext bindet dort bereits `SignerRole::KeyApprover` und
/// `CertificateCapability::HistoricalGrantApprove`. Was diese Funktion
/// hinzufuegt, ist genau eine Aussage, die `ea-crypto` je Signatur nicht
/// treffen kann: dass es ZWEI UNTERSCHIEDLICHE Approver waren.
async fn verify_grant_authorization(
    authorization_hash: ObjectHash,
    now: UnixMillis,
    ports: &HistoricalGrantPorts<'_>,
    organization_id: OrganizationId,
) -> Result<GrantAuthorizationFieldsV1, HistoricalGrantFailure> {
    let bytes = exact_bytes(ObjectTypeV1::Trust, authorization_hash, ports)
        .await
        .map_err(|_| HistoricalGrantError::AuthorizationUnverifiable)?;
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(&bytes).map_err(|_| HistoricalGrantError::AuthorizationUnverifiable)?
    else {
        return Err(HistoricalGrantError::AuthorizationUnverifiable.into());
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::GrantAuthorization(fields) = object
        .decoded_payload()
        .map_err(|_| HistoricalGrantError::AuthorizationUnverifiable)?
    else {
        return Err(HistoricalGrantError::AuthorizationUnverifiable.into());
    };
    if fields.organization_id != organization_id {
        return Err(HistoricalGrantError::AuthorizationMismatch.into());
    }
    // Die Frist steht VOR der Signaturarbeit: eine abgelaufene Autorisierung
    // ist abgelaufen, ganz gleich wie gut sie unterschrieben ist.
    if now > fields.expires_at {
        return Err(HistoricalGrantError::Expired.into());
    }

    let head = select_head(
        organization_id,
        ChainSequence::new(fields.authorization_sequence),
        now,
        ports,
    )
    .await?;
    if fields.registry_version != head.registry_version()
        || fields.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
    {
        return Err(HistoricalGrantError::AuthorizationMismatch.into());
    }
    let approvers = distinct_approvers(
        object.signatures(),
        object.exact_digest_input(),
        head.as_ref(),
        |digest_input, certificate_hash| {
            VerificationContext::historical_grant_approval_trust_digest(
                digest_input,
                certificate_hash,
            )
        },
    )
    .map_err(|_| HistoricalGrantError::AuthorizationUnverifiable)?;
    if approvers < REQUIRED_DISTINCT_APPROVERS_V1 {
        return Err(HistoricalGrantError::AuthorizationInsufficient.into());
    }
    Ok(fields)
}

/// Zaehlt die UNTERSCHIEDLICHEN authoritySubjectId-Werte, die diesen Digest gueltig
/// unterschrieben haben.
///
/// Der Zertifikatshash jeder Signatur kommt aus IHREM eigenen geschuetzten
/// COSE-Kopf und nicht von aussen; `verify_cose_sign1` stellt ihn danach gegen
/// denselben Wert im Kontext, loest ihn gegen den gewaehlten Kopf auf und
/// prueft Aktivitaet, Widerruf, Rolle und Capability. Eine Signatur, die
/// nicht traegt, weist die ganze Autorisierung ab — sie halb zu zaehlen waere
/// eine Mehrheit aus Fehlern.
pub(crate) fn distinct_approvers(
    signatures: &[Vec<u8>],
    exact_digest_input: &[u8],
    head: &dyn ActiveRegistryHeadV1,
    context_of: impl Fn(&[u8], CertificateHash) -> Result<VerificationContext, CryptoError>,
) -> Result<usize, CryptoError> {
    ea_trust::distinct_authority_subjects(
        signatures,
        exact_digest_input,
        &HeadResolver(head),
        context_of,
    )
}

async fn exact_bytes(
    kind: ObjectTypeV1,
    hash: ObjectHash,
    ports: &HistoricalGrantPorts<'_>,
) -> Result<Vec<u8>, HistoricalGrantError> {
    let bytes = ports
        .objects
        .get_exact_in(kind, hash)
        .await?
        .collect()
        .await
        .map_err(|_| HistoricalGrantError::DependencyUnavailable)?
        .into_bytes()
        .to_vec();
    // Die Adresse wird nachgerechnet: ein Objekt, das unter einem fremden
    // Schluessel liegt, ist nicht das genannte.
    if ea_crypto::object_hash(&bytes) != hash {
        return Err(HistoricalGrantError::Internal);
    }
    Ok(bytes)
}

async fn store_grant(
    organization_id: OrganizationId,
    entry_hash: EntryHash,
    exact_eag_bytes: &[u8],
    recipient_key_thumbprint: ea_types::KeyThumbprint,
    expires_at: UnixMillis,
    now: UnixMillis,
    ports: &HistoricalGrantPorts<'_>,
) -> Result<(), HistoricalGrantFailure> {
    let staged = ports
        .objects
        .stage_stream(
            ObjectTypeV1::Grant,
            aws_sdk_s3::primitives::ByteStream::from(exact_eag_bytes.to_vec()),
            MAX_GRANT_OBJECT_BYTES_V1 as u64,
        )
        .await
        .map_err(HistoricalGrantError::from)?;
    let stored = ports
        .objects
        .put_if_absent(staged)
        .await
        .map_err(HistoricalGrantError::from)?;
    if ports.clock.now() > expires_at {
        return Err(HistoricalGrantError::Expired.into());
    }
    let outcome = ports
        .grants
        .record_historical_grant(HistoricalGrantCommandV1 {
            organization_id,
            entry_hash,
            object: IndexedObjectV1 {
                kind: ObjectTypeV1::Grant,
                object_hash: stored.object_hash(),
                size_bytes: stored.size_bytes(),
            },
            recipient_key_thumbprint,
            expires_at,
            stored_at: now,
        })
        .await
        .map_err(HistoricalGrantError::from)?;
    match outcome {
        AppendOutcome::Recorded | AppendOutcome::AlreadyRecorded => Ok(()),
        AppendOutcome::Conflict => Err(HistoricalGrantError::Conflict.into()),
    }
}
