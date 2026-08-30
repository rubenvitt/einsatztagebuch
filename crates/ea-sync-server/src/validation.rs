//! Schritt 2 von `design.md` §13.3: die Pruefung VOR jeder Ablage.
//!
//! Geprueft werden Format, `entryHash`, `objectHash`, Writer-Zertifikat,
//! Signatur, Suite, Registry-Linie, Grant-Plan, Grant-Signaturen, genau der
//! verpflichtende Recovery-Grant und genau ein initialer Grant fuer jedes zur
//! Eintragssequenz aktive Reader-Zertifikat.
//!
//! # Woher die aktive Empfaengermenge kommt
//!
//! AUSSCHLIESSLICH aus [`ActiveRegistryHeadV1::active_certificates`], also aus
//! [`ea_trust::SelectedRegistryHead`]. Diese Datei leitet keine Empfaengermenge
//! aus Datenbankzeilen ab, und es gibt hier keine Abkuerzung, die es taete: eine
//! Zeile ist keine Signatur.
//!
//! Der erwartete Plan entsteht nach genau derselben Regel wie beim Writer
//! (`crates/ea-writer/src/grant_plan.rs`) und wird dann gegen den GELIEFERTEN
//! Plan gerechnet. Zwei verschiedene Regeln waeren zwei verschiedene
//! Wahrheiten, und der Writer haette immer die falsche.
//!
//! # Was hier NICHT nachgebaut wird
//!
//! Die Negativregeln des Grant-Plans — kein Recovery-Empfaenger, ein zweiter,
//! ein doppelter Empfaenger — kommen aus [`ea_format::GrantPlanV1::new`] und
//! werden hier nicht abgezaehlt. Die Signaturpruefung laeuft ueber
//! [`ea_crypto::verify_cose_sign1`] gegen den gewaehlten Kopf; es gibt keine
//! zweite Aufloesung eines Zertifikats.

use core::fmt;

use ea_crypto::{
    CryptoError, ResolvedSigner, SignerCertificateResolver, VerificationContext, verify_cose_sign1,
};
use ea_format::{
    CertificateKindV1, EntryPackageV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1, GrantPurposeV1,
    GrantV1, ObjectTypeV1, Parsed, ParsedArchiveObject, decode_exact_object,
};
use ea_sync_protocol::EntryCommitRequestV1;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, ObjectHash, OrganizationId,
};

use crate::{
    models::{GrantRecipientV1, IndexedObjectV1},
    ports::ActiveRegistryHeadV1,
};

/// Die Formatversion, die diese Stufe schreibt und annimmt.
const FORMAT_VERSION_V1: u64 = 1;

/// Ein Traeger bekannter Groesse fuer `&dyn ActiveRegistryHeadV1`.
///
/// [`ea_crypto::verify_cose_sign1`] nimmt seinen Aufloeser als
/// `&impl SignerCertificateResolver`, und `impl Trait` traegt eine
/// `Sized`-Schranke; ein Trait-Objekt passt dort nicht hinein. Der Traeger
/// LEITET AUSSCHLIESSLICH WEITER — er trifft keine eigene Aussage darueber,
/// welches Zertifikat aufloest, und er ist ausdruecklich keine zweite
/// Aufloesung neben der des gewaehlten Kopfes.
pub(crate) struct HeadResolver<'a>(pub(crate) &'a dyn ActiveRegistryHeadV1);

impl SignerCertificateResolver for HeadResolver<'_> {
    fn resolve(
        &self,
        certificate_hash: CertificateHash,
        bound_registry: ea_types::RegistryVersion,
    ) -> Result<ResolvedSigner<'_>, CryptoError> {
        self.0.resolve(certificate_hash, bound_registry)
    }
}

/// Warum ein Commit die Pruefung nicht bestanden hat.
///
/// Jeder Arm traegt einen eigenen stabilen Code. Kein Arm traegt einen
/// fachlichen Wert, und keiner traegt ein Fragment der gelieferten Nutzdaten.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommitValidationError {
    /// Das gelieferte Objekt ist kein `.eip` beziehungsweise kein `.eag`.
    ObjectFamily,
    /// Der Eintrag ist formal ungueltig.
    EntryInvalid,
    /// Der Eintrag bindet sich an eine andere Organisation als der Aufrufer.
    OrganizationMismatch,
    /// Die Kette des Manifests, die des Pfades und die des Ankers sind nicht
    /// dieselbe.
    ChainMismatch,
    /// Der Aufrufer ist nicht der Writer dieses Manifests, oder das benannte
    /// Zertifikat ist zur Sequenz nicht als Writer aktiv.
    WriterUnauthorized,
    /// Die Schreibersignatur traegt nicht.
    WriterSignature,
    /// Das Manifest behauptet einen Schreiberwechsel, den dieser Stand nicht
    /// nachpruefen kann. FAIL-CLOSED: `ea-trust` gibt die wirksamen
    /// Uebergaenge nicht heraus (`crates/ea-verify/src/entry.rs`), und was
    /// nicht geprueft werden kann, wird nicht angenommen.
    WriterTransitionUnverifiable,
    /// Suite oder Formatversion stehen nicht in der gebundenen Richtlinie.
    SuiteUnsupported,
    /// Registry-Version oder Registry-Head des Manifests sind nicht die des
    /// gewaehlten Kopfes.
    RegistryMismatch,
    /// Der gelieferte Plan ist nicht der Plan der gelieferten Grants, oder
    /// nicht der, den das Manifest signiert hat.
    GrantPlanMismatch,
    /// Der gelieferte Plan ist NICHT der Plan der zur Sequenz aktiven
    /// Empfaenger: ein Reader fehlt, einer ist zu viel, oder der
    /// Recovery-Empfaenger ist ein anderer.
    GrantSetIncomplete,
    /// Ein Grant ist formal ungueltig, historisch, oder gehoert zu einem
    /// anderen Eintrag.
    GrantInvalid,
    /// Eine Ausstellersignatur eines Grants traegt nicht.
    GrantSignature,
}

impl CommitValidationError {
    /// Alle Arme — damit ein spaeter ergaenzter sofort auffaellt.
    pub const ALL: [Self; 13] = [
        Self::ObjectFamily,
        Self::EntryInvalid,
        Self::OrganizationMismatch,
        Self::ChainMismatch,
        Self::WriterUnauthorized,
        Self::WriterSignature,
        Self::WriterTransitionUnverifiable,
        Self::SuiteUnsupported,
        Self::RegistryMismatch,
        Self::GrantPlanMismatch,
        Self::GrantSetIncomplete,
        Self::GrantInvalid,
        Self::GrantSignature,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ObjectFamily => "EA-COMMIT-OBJECT-FAMILY",
            Self::EntryInvalid => "EA-COMMIT-ENTRY-INVALID",
            Self::OrganizationMismatch => "EA-COMMIT-ORGANIZATION",
            Self::ChainMismatch => "EA-COMMIT-CHAIN",
            Self::WriterUnauthorized => "EA-COMMIT-WRITER-UNAUTHORIZED",
            Self::WriterSignature => "EA-COMMIT-WRITER-SIGNATURE",
            Self::WriterTransitionUnverifiable => "EA-COMMIT-WRITER-TRANSITION",
            Self::SuiteUnsupported => "EA-COMMIT-SUITE",
            Self::RegistryMismatch => "EA-COMMIT-REGISTRY",
            Self::GrantPlanMismatch => "EA-COMMIT-GRANT-PLAN",
            Self::GrantSetIncomplete => "EA-COMMIT-GRANT-SET",
            Self::GrantInvalid => "EA-COMMIT-GRANT-INVALID",
            Self::GrantSignature => "EA-COMMIT-GRANT-SIGNATURE",
        }
    }

    /// Ein unzulaessiger Writer ist ein SECURITY EVENT und nicht bloss eine
    /// Absage (`design.md` §13.3, letzter Absatz).
    #[must_use]
    pub const fn is_writer_violation(self) -> bool {
        matches!(self, Self::WriterUnauthorized | Self::WriterSignature)
    }
}

impl fmt::Display for CommitValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for CommitValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CommitValidationError {}

impl From<CryptoError> for CommitValidationError {
    fn from(_: CryptoError) -> Self {
        Self::WriterSignature
    }
}

/// Ein Commit, der Schritt 2 bestanden hat.
///
/// Er traegt AUSSCHLIESSLICH das, was die Schritte 3 bis 8 noch brauchen:
/// Hashes, Groessen, die Kettenposition und die Geraetekennung des Writers.
/// Objektbytes stehen nicht darin — sie liegen beim Aufrufer, der sie gleich
/// stromt.
pub struct ValidatedCommitV1 {
    pub entry_hash: EntryHash,
    pub entry_object_hash: ObjectHash,
    pub chain_sequence: ChainSequence,
    pub previous_entry_hash: Option<EntryHash>,
    /// Die Geraetekennung des Writers, gelesen aus SEINEM Zertifikat im
    /// gewaehlten Kopf — nicht aus einer Zeile und nicht aus dem Request.
    pub device_id: DeviceId,
    /// Entry und Grants fuer den Objektindex; die Quittung kommt spaeter
    /// dazu.
    pub indexed_objects: Vec<IndexedObjectV1>,
    /// Die Grant-Objekthashes in Lieferreihenfolge, also bereits bytweise
    /// sortiert (`EntryCommitRequestV1`).
    pub grant_object_hashes: Vec<ObjectHash>,
    /// Dieselben Grants MIT ihrem Empfaengerabdruck, gelesen aus dem
    /// geprueften Objekt. Die Ablage schreibt ihn; ohne ihn traege die Zeile
    /// einen Nullabdruck, und der ist eine Behauptung.
    pub grant_recipients: Vec<GrantRecipientV1>,
}

impl fmt::Debug for ValidatedCommitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ValidatedCommitV1(sequence={}, grants={})",
            self.chain_sequence.get(),
            self.grant_object_hashes.len()
        )
    }
}

/// Schritt 2 vollstaendig, in fail-closed Reihenfolge.
///
/// # Errors
///
/// Jeder Arm von [`CommitValidationError`]. Die Reihenfolge ist Absicht: erst
/// wird festgestellt, WAS geliefert wurde, dann WER es geliefert hat, dann OB
/// er es durfte, und erst zuletzt, ob die Freigabemenge vollstaendig ist. Eine
/// Signatur wird nie ueber Bytes geprueft, deren Familie noch offen ist.
pub fn validate_commit(
    request: &EntryCommitRequestV1,
    entry: &Parsed<EntryPackageV1>,
    organization_id: OrganizationId,
    chain_id: ChainId,
    writer_certificate_hash: CertificateHash,
    head: &dyn ActiveRegistryHeadV1,
) -> Result<ValidatedCommitV1, CommitValidationError> {
    let manifest = entry.value().manifest().fields();

    if manifest.organization_id != organization_id {
        return Err(CommitValidationError::OrganizationMismatch);
    }
    // DREI Kennungen, alle aus signierten Quellen: das Manifest, der Pfad des
    // Requests und der Anker, gegen den der Kopf gewaehlt wurde. Zwei davon zu
    // vergleichen liesse die dritte frei.
    if manifest.chain_id != chain_id || manifest.chain_id != head.chain_id() {
        return Err(CommitValidationError::ChainMismatch);
    }
    if manifest.writer_transition_event_hash.is_some() {
        return Err(CommitValidationError::WriterTransitionUnverifiable);
    }
    if manifest.writer_certificate_hash != writer_certificate_hash {
        return Err(CommitValidationError::WriterUnauthorized);
    }
    let writer = active_writer(head, writer_certificate_hash)?;

    let policy = head.policy_fields();
    if !policy
        .allowed_crypto_suite_ids
        .iter()
        .any(|suite| suite == ea_crypto::SUITE_ID)
        || !policy.allowed_format_versions.contains(&FORMAT_VERSION_V1)
    {
        return Err(CommitValidationError::SuiteUnsupported);
    }

    if manifest.registry_version != head.registry_version()
        || manifest.registry_head_hash != *head.registry_head_hash().as_bytes()
    {
        return Err(CommitValidationError::RegistryMismatch);
    }

    // Die Schreibersignatur gegen den gewaehlten Kopf. Alles davor sind
    // Bindungen, die `ea-format` beim Parsen schon geprueft hat; DIES ist die
    // kryptografische Pruefung gegen den Schluessel des aufgeloesten
    // Zertifikats.
    let context = VerificationContext::record(entry.value().signed_manifest().exact_bytes())
        .map_err(|_| CommitValidationError::WriterSignature)?;
    verify_cose_sign1(
        entry.value().writer_signature(),
        &HeadResolver(head),
        &context,
    )
    .map_err(|_| CommitValidationError::WriterSignature)?;

    let delivered_plan = request.grant_plan();
    if *delivered_plan.hash().as_bytes() != manifest.initial_grant_plan_hash {
        return Err(CommitValidationError::GrantPlanMismatch);
    }

    let grants = parse_grants(
        request.sorted_grant_bytes(),
        entry.value().entry_hash(),
        manifest.chain_sequence,
        head,
    )?;

    // Der Plan der GELIEFERTEN Grants. Er entsteht ueber denselben
    // eingefrorenen Konstruktor wie jeder andere Plan; die Negativregeln
    // kommen von dort und werden hier nicht abgezaehlt.
    let reconstructed = GrantPlanV1::new(
        grants
            .iter()
            .map(|grant| plan_item(grant.value()))
            .collect(),
    )
    .map_err(|_| CommitValidationError::GrantPlanMismatch)?;
    if reconstructed.hash() != delivered_plan.hash() {
        return Err(CommitValidationError::GrantPlanMismatch);
    }

    // Und erst jetzt die Vollstaendigkeit: der Plan, den die zur Sequenz
    // AKTIVEN Zertifikate verlangen.
    let expected = expected_plan(head)?;
    if expected.hash() != delivered_plan.hash() {
        return Err(CommitValidationError::GrantSetIncomplete);
    }

    let mut indexed_objects = Vec::with_capacity(grants.len() + 1);
    indexed_objects.push(IndexedObjectV1 {
        kind: ObjectTypeV1::Entry,
        object_hash: entry.object_hash(),
        size_bytes: object_size(request.entry_bytes()),
    });
    for (grant, bytes) in grants.iter().zip(request.sorted_grant_bytes()) {
        indexed_objects.push(IndexedObjectV1 {
            kind: ObjectTypeV1::Grant,
            object_hash: grant.object_hash(),
            size_bytes: object_size(bytes),
        });
    }

    Ok(ValidatedCommitV1 {
        entry_hash: entry.value().entry_hash(),
        entry_object_hash: entry.object_hash(),
        chain_sequence: manifest.chain_sequence,
        previous_entry_hash: manifest.previous_entry_hash,
        device_id: writer,
        indexed_objects,
        grant_object_hashes: grants.iter().map(Parsed::object_hash).collect(),
        grant_recipients: grants
            .iter()
            .map(|grant| GrantRecipientV1 {
                object_hash: grant.object_hash(),
                recipient_key_thumbprint: grant
                    .value()
                    .grant_body()
                    .fields()
                    .recipient_key_thumbprint,
            })
            .collect(),
    })
}

/// Die Bytelaenge eines Objekts als `u64`.
///
/// Die Umwandlung kann auf keiner Plattform dieses Projekts scheitern, und ein
/// `Result` an dieser Stelle waere ein Arm, den kein Test je erreicht: die
/// Objektdecken dieser Version liegen bei wenigen Megabyte.
fn object_size(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Der Eintrag aus den exakten Bytes.
///
/// Oeffentlich, weil der Commit-Dienst die KETTENSEQUENZ des Eintrags braucht,
/// bevor er den Registry-Head fuer genau diese Sequenz waehlen kann — und der
/// Head wiederum die Voraussetzung von [`validate_commit`] ist. Ein zweites
/// Parsen derselben bis zu zwei Megabyte waere die einzige Alternative.
///
/// # Errors
///
/// [`CommitValidationError::EntryInvalid`] oder
/// [`CommitValidationError::ObjectFamily`].
pub fn parse_entry(bytes: &[u8]) -> Result<Parsed<EntryPackageV1>, CommitValidationError> {
    match decode_exact_object(bytes).map_err(|_| CommitValidationError::EntryInvalid)? {
        ParsedArchiveObject::Entry(entry) => Ok(entry),
        _ => Err(CommitValidationError::ObjectFamily),
    }
}

/// Die Geraetekennung des Writers — und der Nachweis, dass er es sein darf.
///
/// Verlangt ausdruecklich ein Zertifikat der Art [`CertificateKindV1::Writer`]:
/// ein Server-, Admin- oder Readerzertifikat schreibt keine Eintraege.
fn active_writer(
    head: &dyn ActiveRegistryHeadV1,
    writer_certificate_hash: CertificateHash,
) -> Result<DeviceId, CommitValidationError> {
    head.active_certificates()
        .into_iter()
        .find(|(hash, fields)| {
            *hash == writer_certificate_hash && fields.certificate_kind == CertificateKindV1::Writer
        })
        .map(|(_, fields)| fields.device_id)
        .ok_or(CommitValidationError::WriterUnauthorized)
}

/// Jeder gelieferte Grant, geprueft gegen Eintrag und Kopf.
fn parse_grants(
    grant_bytes: &[Vec<u8>],
    entry_hash: EntryHash,
    chain_sequence: ChainSequence,
    head: &dyn ActiveRegistryHeadV1,
) -> Result<Vec<Parsed<GrantV1>>, CommitValidationError> {
    let mut grants = Vec::with_capacity(grant_bytes.len());
    for bytes in grant_bytes {
        let ParsedArchiveObject::Grant(grant) =
            decode_exact_object(bytes).map_err(|_| CommitValidationError::GrantInvalid)?
        else {
            return Err(CommitValidationError::ObjectFamily);
        };
        let fields = grant.value().grant_body().fields();
        // Ein historischer Grant gehoert an den GETRENNTEN Endpunkt
        // (`design.md` §13.3, vorletzter Absatz) und veraendert den initialen
        // Plan nicht.
        if fields.kind != GrantKindV1::Initial || fields.entry_hash != entry_hash {
            return Err(CommitValidationError::GrantInvalid);
        }
        let context = VerificationContext::initial_grant(
            grant.value().grant_body().exact_bytes(),
            chain_sequence,
        )
        .map_err(|_| CommitValidationError::GrantSignature)?;
        verify_cose_sign1(
            grant.value().issuer_signature(),
            &HeadResolver(head),
            &context,
        )
        .map_err(|_| CommitValidationError::GrantSignature)?;
        grants.push(grant);
    }
    Ok(grants)
}

/// Der Planeintrag eines Grants.
fn plan_item(grant: &GrantV1) -> GrantPlanItemV1 {
    let fields = grant.grant_body().fields();
    GrantPlanItemV1::new(
        fields.recipient_key_thumbprint,
        fields.recipient_certificate_hash,
        fields.purpose,
    )
}

/// Der Plan, den die zur Sequenz AKTIVEN Zertifikate verlangen.
///
/// Dieselbe Regel wie `crates/ea-writer/src/grant_plan.rs`: genau ein aktiver
/// Recovery-Empfaenger plus ausnahmslos jedes aktive Readerzertifikat. Ein
/// Empfaenger ohne KEM-Abdruck kann keinen Schluesselumschlag bekommen; ihn zu
/// UEBERSPRINGEN waere die stille Auslassung, die die Invariante verbietet,
/// also ist er hier ein Befund.
fn expected_plan(head: &dyn ActiveRegistryHeadV1) -> Result<GrantPlanV1, CommitValidationError> {
    let mut items = Vec::new();
    for (certificate_hash, fields) in head.active_certificates() {
        let purpose = match fields.certificate_kind {
            CertificateKindV1::Reader => GrantPurposeV1::Reader,
            CertificateKindV1::RecoveryRecipient => GrantPurposeV1::Recovery,
            _ => continue,
        };
        let thumbprint = fields
            .kem_key_thumbprint
            .ok_or(CommitValidationError::GrantSetIncomplete)?;
        items.push(GrantPlanItemV1::new(thumbprint, certificate_hash, purpose));
    }
    GrantPlanV1::new(items).map_err(|_| CommitValidationError::GrantSetIncomplete)
}
