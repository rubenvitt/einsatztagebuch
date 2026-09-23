//! Zeremonie A nativ: die Publikation eines Reader-Key-Escrows beim
//! Enrollment (Profil §5, DRK-458/DRK-461).
//!
//! # Die Sperre (GC:26)
//!
//! Der erste Schritt ist der Cutover-Port [`ReaderKeyEscrowCutover`] über die
//! exakten Trust-Objekte des Bestands. Der echte Port
//! [`ActiveWebBundleRelease`] verlangt eine aktive, wurzelsignierte
//! `webBundleRelease` eines v1.1-fähigen Bundles zur Version des gewählten
//! Kopfes — dieselbe Regel wie am Server
//! (`ea_trust::reader_key_escrow_cutover_release`); sonst
//! `EA-ESCROW-CUTOVER-NOT-READY` (Exit 21) — vor dem Lesen der Inbox, vor der
//! Reauthentifizierung, vor jeder Sperrzeile, jeder Auditzeile und jeder
//! Datei. [`CutoverPending`] scheitert immer. Die Fixture-Variante liegt
//! allein hinter `test-support`.
//!
//! # Der Ablauf hinter der Sperre
//!
//! 1. Genau ein Paket aus der eigenen Escrow-Inbox. Ein schon publiziertes
//!    Paket liefert dieselben exakten Bytes zurück, ohne Verbrauch und ohne
//!    Audit (Profil §5: exakter Wiedereinspielversuch), und wird erneut
//!    verteilt.
//! 2. Frische (Ruling Q2): `issued-at <= now <= issued-at + 300 000`, sonst
//!    `EA-ESCROW-PACKAGE-STALE`.
//! 3. Lokale Vorprüfung der Eindeutigkeit: kein publiziertes Escrow derselben
//!    Organisation zum selben Reader-Zertifikat, keines zur selben Person,
//!    deren Reader-Zertifikat im Kopf noch aktiv ist
//!    (`EA-ESCROW-PUBLICATION-CONFLICT`). Die Katalog-Eindeutigkeit prüft die
//!    Absichtsregel des Trust-Kerns über die ganze Escrow-Menge.
//! 4. Frische Reauthentifizierung `AdminRootCeremony` an `escrow-core-hash`.
//! 5. Freigabe bauen, Admin signiert, Prüfung über
//!    `verify_reader_key_escrow_approval`; Nutzlast, Prüfung über
//!    `verify_intended_reader_key_escrow`, Root signiert, Prüfung über
//!    `verify_signed_reader_key_escrow`.
//! 6. Frisch geöffnete Laufzeit: dieselbe Autorität und derselbe Port-Befund
//!    (ein Bundle-Widerruf bewegt den Kopf nicht).
//! 7. EINE Transaktion: beide Sperrzeilen im geteilten Namensraum (F8), die
//!    Publikationszeile mit den exakten Bytes und die Auditzeile
//!    13/`completed` mit dem Bundle-Release-Hash.
//! 8. Verteilung: Freigabe, dann Escrow unter `trust/` des Archivs; der
//!    frisch geöffnete Bestand trägt das Escrow als gültig.
//!
//! Signiert wird ohne `CoseSigner`, über die Slots des Autoritätswirts
//! (`NativeSigningSlot::Admin` und `::Root`). Einen nativen Uploader gibt es
//! nicht: zum Server gehen die Dateien über den Trust-Endpunkt, Release vor
//! Freigabe vor Escrow.

use std::path::Path;

use ea_audit::{
    AuditActorProof, SignedLocalAuditService, SqliteLocalAuditRepository, TypedLocalAuditEvent,
};
use ea_crypto::{ContentType, object_hash, reader_key_escrow_core_hash, trust_digest};
use ea_format::{
    DecodedTrustPayloadV1, OperatorRoleV1, ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1,
    ReaderKeyEscrowPackageV1, ReaderKeyEscrowTransferKindV1, TrustObjectV1, TrustPayloadV1,
    decode_reader_key_escrow_package, encode_trust,
};
use ea_key_provider::{KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreError, StoreRow, StoreValue};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_recovery::ReaderKeyEscrowError;
use ea_trust::{
    AdminAuthorizationReplayDimension, ReaderKeyEscrowHead, SelectedRegistryHead, TrustAnchorV1,
    TrustError, VerifiedTrust, reader_key_escrow_cutover_release,
    verify_intended_reader_key_escrow, verify_reader_key_escrow_approval,
    verify_reader_key_escrows, verify_signed_reader_key_escrow,
};
use ea_types::{AuthorizationId, CertificateHash, Hash32, ObjectHash, UnixMillis};

use crate::{
    native_provider::NativeSigningSlot,
    operator_runtime::{OperatorRuntime, fresh_wall_clock},
    reader_key_escrow_inbox::read_escrow_inbox,
    reader_key_escrow_opening::purge_expired_reader_key_escrow_results,
};

/// Die Höchstdauer einer Publikationsfreigabe und zugleich das Fenster, in
/// dem ein Paket verarbeitet werden muss (Ruling Q2).
pub const READER_KEY_ESCROW_PACKAGE_WINDOW_MS: i64 = 300_000;

/// Der Cutover-Port: die aktive v1.1-`webBundleRelease`, die die
/// Vorbedingung erfüllt (Profil §5, U4), als ihr Objekthash.
///
/// VERSIEGELT: außerhalb dieser Crate lässt sich kein Port bauen, der die
/// Sperre öffnet — produktiv gibt es allein [`CutoverPending`], die
/// Fixture-Variante nur hinter `test-support`. Scheibe (f) setzt hier den
/// echten Port ein.
///
/// ```compile_fail
/// struct Open;
/// impl ea_admin::reader_key_escrow_publication::ReaderKeyEscrowCutover for Open {
///     fn active_v11_bundle_release(
///         &self,
///         _anchor: &ea_trust::TrustAnchorV1,
///         _exact_trust_objects: &[&[u8]],
///         _head: &ea_trust::SelectedRegistryHead,
///     ) -> Result<ea_types::ObjectHash, ea_recovery::ReaderKeyEscrowError> {
///         unimplemented!()
///     }
/// }
/// ```
pub trait ReaderKeyEscrowCutover: sealed::Sealed {
    /// Der Objekthash der aktiven v1.1-Freigabe zum gewählten Kopf, über die
    /// exakten Trust-Objekte des Bestands.
    ///
    /// # Errors
    ///
    /// `EA-ESCROW-CUTOVER-NOT-READY`, solange die Vorbedingung nicht erfüllt
    /// ist.
    fn active_v11_bundle_release(
        &self,
        anchor: &TrustAnchorV1,
        exact_trust_objects: &[&[u8]],
        head: &SelectedRegistryHead,
    ) -> Result<ObjectHash, ReaderKeyEscrowError>;
}

mod sealed {
    /// Nur diese Crate implementiert den Cutover-Port.
    pub trait Sealed {}
}

/// Der produktive Port bis Scheibe (f): die Vorbedingung gilt nie als
/// erfüllt.
pub struct CutoverPending;

impl sealed::Sealed for CutoverPending {}

impl ReaderKeyEscrowCutover for CutoverPending {
    fn active_v11_bundle_release(
        &self,
        _anchor: &TrustAnchorV1,
        _exact_trust_objects: &[&[u8]],
        _head: &SelectedRegistryHead,
    ) -> Result<ObjectHash, ReaderKeyEscrowError> {
        Err(ReaderKeyEscrowError::CutoverNotReady)
    }
}

/// Der echte Port: die aktive, wurzelsignierte `webBundleRelease` eines
/// v1.1-fähigen Bundles zur Version des gewählten Kopfes — dieselbe Regel
/// ([`ea_trust::reader_key_escrow_cutover_release`]), mit der der Server
/// annimmt. Jeder Befund wird `EA-ESCROW-CUTOVER-NOT-READY`.
pub struct ActiveWebBundleRelease;

impl sealed::Sealed for ActiveWebBundleRelease {}

impl ReaderKeyEscrowCutover for ActiveWebBundleRelease {
    fn active_v11_bundle_release(
        &self,
        anchor: &TrustAnchorV1,
        exact_trust_objects: &[&[u8]],
        head: &SelectedRegistryHead,
    ) -> Result<ObjectHash, ReaderKeyEscrowError> {
        reader_key_escrow_cutover_release(anchor, exact_trust_objects, head.registry_version())
            .map_err(|_| ReaderKeyEscrowError::CutoverNotReady)
    }
}

/// Fixture-Port: eine als aktiv gesetzte Freigabe. Nur hinter
/// `test-support`; kein Produktivpfad erreicht ihn.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct FixtureBundleRelease(pub ObjectHash);

#[cfg(feature = "test-support")]
impl sealed::Sealed for FixtureBundleRelease {}

#[cfg(feature = "test-support")]
impl ReaderKeyEscrowCutover for FixtureBundleRelease {
    fn active_v11_bundle_release(
        &self,
        _anchor: &TrustAnchorV1,
        _exact_trust_objects: &[&[u8]],
        _head: &SelectedRegistryHead,
    ) -> Result<ObjectHash, ReaderKeyEscrowError> {
        Ok(self.0)
    }
}

/// Das Ergebnis einer Publikation — die exakten Bytes von Freigabe und
/// Escrow. `replayed` sagt, ob es ein exakter Wiedereinspielversuch war.
pub struct PublishedReaderKeyEscrow {
    pub package_hash: ObjectHash,
    pub approval_object_hash: ObjectHash,
    pub escrow_object_hash: ObjectHash,
    pub exact_approval: Vec<u8>,
    pub exact_escrow: Vec<u8>,
    pub replayed: bool,
}

/// Ein geprüftes, noch nicht publiziertes Paket.
pub struct FreshReaderKeyEscrowPackage {
    package_hash: ObjectHash,
    package: ReaderKeyEscrowPackageV1,
}

impl FreshReaderKeyEscrowPackage {
    /// `escrow-core-hash`: der Kontext der Reauthentifizierung.
    #[must_use]
    pub fn escrow_core_hash(&self) -> Hash32 {
        reader_key_escrow_core_hash(self.package.exact_core())
    }
}

/// Was die Vorprüfung eines Pakets ergibt.
pub enum PreparedReaderKeyEscrowPackage {
    /// Schon publiziert: dieselben Bytes, kein Verbrauch, kein Audit.
    Published(PublishedReaderKeyEscrow),
    /// Neu und frisch; bereit für die Zeremonie.
    Fresh(FreshReaderKeyEscrowPackage),
}

fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}

fn store_error(_: StoreError) -> ReaderKeyEscrowError {
    ReaderKeyEscrowError::Store
}

struct Tx(ReaderKeyEscrowError);
impl From<StoreError> for Tx {
    fn from(_: StoreError) -> Self {
        Self(ReaderKeyEscrowError::Store)
    }
}

/// Schritte 1 bis 3 ohne jede Nebenwirkung: Paket dekodieren, exakte
/// Wiederholung erkennen, Frische und lokale Eindeutigkeit.
///
/// # Errors
///
/// `TransferFile`, `PackageStale`, `PublicationConflict`, `Store`.
pub fn prepare_reader_key_escrow_package(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    exact_package: &[u8],
    now: UnixMillis,
) -> Result<PreparedReaderKeyEscrowPackage, ReaderKeyEscrowError> {
    let package = decode_reader_key_escrow_package(exact_package)
        .map_err(|_| ReaderKeyEscrowError::TransferFile)?;
    let package_hash = object_hash(exact_package);
    if let Some(row) = database
        .query_row(
            "SELECT approval_object_hash,escrow_object_hash,exact_approval,exact_escrow FROM reader_key_escrow_publication WHERE package_hash=?1",
            &[blob(package_hash.as_bytes())],
        )
        .map_err(store_error)?
    {
        let hash = |index| {
            ObjectHash::try_from(row.blob(index).map_err(store_error)?)
                .map_err(|_| ReaderKeyEscrowError::Store)
        };
        return Ok(PreparedReaderKeyEscrowPackage::Published(
            PublishedReaderKeyEscrow {
                package_hash,
                approval_object_hash: hash(0)?,
                escrow_object_hash: hash(1)?,
                exact_approval: row.blob(2).map_err(store_error)?.to_vec(),
                exact_escrow: row.blob(3).map_err(store_error)?.to_vec(),
                replayed: true,
            },
        ));
    }
    let core = package.core();
    let issued = core.issued_at.get();
    if now.get() < issued
        || issued
            .checked_add(READER_KEY_ESCROW_PACKAGE_WINDOW_MS)
            .is_none_or(|deadline| now.get() > deadline)
    {
        return Err(ReaderKeyEscrowError::PackageStale);
    }
    require_unique_publication(&|sql, params| database.query_row(sql, params), head, core)?;
    Ok(PreparedReaderKeyEscrowPackage::Fresh(
        FreshReaderKeyEscrowPackage {
            package_hash,
            package,
        },
    ))
}

/// Eine Leseabfrage gegen die Datenbank oder die laufende Transaktion.
type StoreQuery<'a> = &'a dyn Fn(&str, &[StoreValue]) -> Result<Option<StoreRow>, StoreError>;

/// Lokale Eindeutigkeit (Profil §5.3): höchstens ein Escrow je
/// Reader-Zertifikat und höchstens eines je Person unter einem im Kopf noch
/// aktiven Zertifikat. Läuft in der Vorprüfung und noch einmal in der
/// Transaktion des Commits, damit ein nebenläufiger Prozess zwischen beiden
/// nichts durchlässt; `UNIQUE(organization_id, reader_certificate_hash)` in
/// Migration 28 ist die Rückfallebene.
fn require_unique_publication(
    query: StoreQuery<'_>,
    head: &SelectedRegistryHead,
    core: &ReaderKeyEscrowCoreV1,
) -> Result<(), ReaderKeyEscrowError> {
    if query(
            "SELECT 1 FROM reader_key_escrow_publication WHERE organization_id=?1 AND reader_certificate_hash=?2",
            &[
                blob(core.organization_id.as_bytes()),
                blob(core.reader_certificate_object_hash.as_bytes()),
            ],
        )
        .map_err(store_error)?
        .is_some()
    {
        return Err(ReaderKeyEscrowError::PublicationConflict);
    }
    let mut offset = 0_i64;
    while let Some(row) = query(
            "SELECT reader_certificate_hash FROM reader_key_escrow_publication WHERE organization_id=?1 AND reader_subject_id=?2 ORDER BY package_hash LIMIT 1 OFFSET ?3",
            &[
                blob(core.organization_id.as_bytes()),
                blob(core.reader_subject_id.as_bytes()),
                StoreValue::Integer(offset),
            ],
        )
        .map_err(store_error)?
    {
        let certificate = CertificateHash::try_from(row.blob(0).map_err(store_error)?)
            .map_err(|_| ReaderKeyEscrowError::Store)?;
        // Widerrufsbewusst (Ruling F4/U2): ein Escrow, dessen
        // Reader-Zertifikat im Kopf nicht mehr aktiv ist, blockiert den
        // Ersatz nicht.
        if head.active_certificate_fields(certificate).is_some() {
            return Err(ReaderKeyEscrowError::PublicationConflict);
        }
        offset += 1;
    }
    Ok(())
}

/// Ein Signierer über einen Trust-Digest: `(zertifikat, digest) -> COSE`.
#[doc(hidden)]
pub type TrustDigestSigner<'a> =
    &'a dyn Fn(CertificateHash, Hash32) -> Result<Vec<u8>, ReaderKeyEscrowError>;

/// Alles, was Schritte 5 und 6 brauchen. Öffentlich baubar nur hinter
/// `test-support`; der Produktivpfad ist allein [`publish_reader_key_escrow`].
#[doc(hidden)]
pub struct ReaderKeyEscrowPublicationContext<'a> {
    pub anchor: &'a TrustAnchorV1,
    /// Die exakten Trust-Objekte des Bestands — Eingabe des Cutover-Ports.
    pub catalog: &'a [&'a [u8]],
    /// Legt exakte Trust-Bytes ins Archiv; nach dem Commit, erst die
    /// Freigabe, dann das Escrow (review-b P3-2), auch beim exakten
    /// Wiedereinspielen (idempotent).
    pub distribute: &'a dyn Fn(&[u8]) -> Result<(), ReaderKeyEscrowError>,
    pub database: &'a EncryptedDatabase,
    pub trust: &'a VerifiedTrust,
    pub head: &'a SelectedRegistryHead,
    pub audit: &'a SignedLocalAuditService,
    pub proof: &'a OperatorSessionProof,
    pub admin_certificate: CertificateHash,
    pub admin_binding: ObjectHash,
    pub admin_sign: TrustDigestSigner<'a>,
    pub root_sign: TrustDigestSigner<'a>,
    pub now: UnixMillis,
    pub session_current: &'a dyn Fn() -> Result<(), ReaderKeyEscrowError>,
    /// `authorization-id` und `nonce` der Freigabe; produktiv frische
    /// Betriebssystementropie.
    pub fresh_approval_ids: &'a dyn Fn() -> Result<([u8; 16], [u8; 32]), ReaderKeyEscrowError>,
}

fn fresh_entropy() -> Result<([u8; 16], [u8; 32]), ReaderKeyEscrowError> {
    let mut id = [0; 16];
    let mut nonce = [0; 32];
    getrandom::fill(&mut id).map_err(|_| ReaderKeyEscrowError::Crypto)?;
    getrandom::fill(&mut nonce).map_err(|_| ReaderKeyEscrowError::Crypto)?;
    Ok((id, nonce))
}

/// Schritte 5 und 6: Freigabe, Root-Signatur, atomarer Verbrauch mit
/// Publikationszeile und Audit 13/`completed`.
///
/// Crate-privat: ein öffentlicher Weg mit frei gewähltem
/// Bundle-Release-Hash wäre eine Publikation an der Sperre vorbei.
fn commit_reader_key_escrow_publication(
    context: &ReaderKeyEscrowPublicationContext<'_>,
    fresh: &FreshReaderKeyEscrowPackage,
    bundle_release_object_hash: ObjectHash,
) -> Result<PublishedReaderKeyEscrow, ReaderKeyEscrowError> {
    let head = context.head;
    let core = fresh.package.core();
    let admin_key_thumbprint = head
        .active_certificate_fields(context.admin_certificate)
        .and_then(|fields| fields.signing_key_thumbprint)
        .ok_or(ReaderKeyEscrowError::Operator)?;
    let expires_at = core
        .issued_at
        .get()
        .checked_add(READER_KEY_ESCROW_PACKAGE_WINDOW_MS)
        .ok_or(ReaderKeyEscrowError::PackageStale)?;
    let (authorization_id, nonce) = (context.fresh_approval_ids)()?;
    let approval_fields = ReaderKeyEscrowApprovalCoreV1 {
        authorization_id: AuthorizationId::try_from(authorization_id.as_slice())
            .map_err(|_| ReaderKeyEscrowError::Crypto)?,
        organization_id: context.trust.organization_id(),
        registry_version: head.registry_version(),
        registry_head_hash: Hash32::try_from(head.registry_head_hash().as_bytes().as_slice())
            .map_err(|_| ReaderKeyEscrowError::Store)?,
        authorization_sequence: head.proposed_sequence().get(),
        admin_key_thumbprint,
        admin_certificate_object_hash: context.admin_certificate,
        admin_operator_binding_object_hash: context.admin_binding,
        escrow_core_hash: fresh.escrow_core_hash(),
        reader_certificate_object_hash: core.reader_certificate_object_hash,
        reader_subject_id: core.reader_subject_id,
        issued_at: core.issued_at,
        expires_at: UnixMillis::new(expires_at),
        nonce,
    };
    let approval_payload = TrustPayloadV1::reader_key_escrow_approval(approval_fields)
        .map_err(|_| ReaderKeyEscrowError::Crypto)?;
    let approval_signature = (context.admin_sign)(
        context.admin_certificate,
        trust_digest(approval_payload.exact_digest_input()),
    )?;
    let exact_approval = encode_trust(
        &TrustObjectV1::new(approval_payload, vec![approval_signature])
            .map_err(|_| ReaderKeyEscrowError::Crypto)?,
    )
    .map_err(|_| ReaderKeyEscrowError::Crypto)?
    .into_vec();
    let approval =
        verify_reader_key_escrow_approval(context.trust, head, &exact_approval, context.now)?;

    let escrow_payload = TrustPayloadV1::reader_key_escrow(core.clone(), approval.object_hash())
        .map_err(|_| ReaderKeyEscrowError::Crypto)?;
    let DecodedTrustPayloadV1::ReaderKeyEscrow(intended) = escrow_payload
        .decoded_payload()
        .map_err(|_| ReaderKeyEscrowError::Crypto)?
    else {
        return Err(ReaderKeyEscrowError::Crypto);
    };
    let intent = verify_intended_reader_key_escrow(context.trust, head, &approval, &intended)?;
    let root_signature = (context.root_sign)(
        intent.root_certificate_hash(),
        trust_digest(escrow_payload.exact_digest_input()),
    )?;
    let exact_escrow = encode_trust(
        &TrustObjectV1::new(escrow_payload, vec![root_signature])
            .map_err(|_| ReaderKeyEscrowError::Crypto)?,
    )
    .map_err(|_| ReaderKeyEscrowError::Crypto)?
    .into_vec();
    let escrow = verify_signed_reader_key_escrow(&intent, &exact_escrow)?;

    let prepared = context
        .audit
        .prepare_signed(
            AuditActorProof::OperatorSession(context.proof),
            TypedLocalAuditEvent::reader_key_escrow_published(
                escrow.object_hash(),
                approval.object_hash(),
                bundle_release_object_hash,
            ),
        )
        .map_err(|_| ReaderKeyEscrowError::Audit)?;
    (context.session_current)()?;
    context
        .database
        .transaction(|tx| {
            require_unique_publication(&|sql, params| tx.query_row(sql, params), head, core)
                .map_err(Tx)?;
            for key in approval.replay_keys() {
                if key.organization_id() != context.proof.organization_id() {
                    return Err(Tx(ReaderKeyEscrowError::Trust(TrustError::ActionMismatch)));
                }
                let (dimension, value) = match key.dimension() {
                    AdminAuthorizationReplayDimension::AuthorizationId(id) => {
                        (0, blob(id.as_bytes()))
                    }
                    AdminAuthorizationReplayDimension::Nonce(nonce) => (1, blob(&nonce)),
                };
                let inserted = tx.execute(
                    "INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",
                    &[blob(key.organization_id().as_bytes()), StoreValue::Integer(dimension), value],
                )?;
                if inserted != 1 {
                    return Err(Tx(ReaderKeyEscrowError::Trust(TrustError::AuthReplay)));
                }
            }
            SqliteLocalAuditRepository::append_prepared_in(tx, &prepared)
                .map_err(|_| Tx(ReaderKeyEscrowError::Audit))?;
            tx.execute(
                "INSERT INTO reader_key_escrow_publication(package_hash,organization_id,reader_certificate_hash,reader_subject_id,approval_object_hash,escrow_object_hash,exact_approval,exact_escrow,audit_event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                &[
                    blob(fresh.package_hash.as_bytes()),
                    blob(core.organization_id.as_bytes()),
                    blob(core.reader_certificate_object_hash.as_bytes()),
                    blob(core.reader_subject_id.as_bytes()),
                    blob(approval.object_hash().as_bytes()),
                    blob(escrow.object_hash().as_bytes()),
                    blob(&exact_approval),
                    blob(&exact_escrow),
                    blob(prepared.id().as_bytes()),
                ],
            )?;
            Ok(())
        })
        .map_err(|Tx(error)| error)?;
    Ok(PublishedReaderKeyEscrow {
        package_hash: fresh.package_hash,
        approval_object_hash: approval.object_hash(),
        escrow_object_hash: escrow.object_hash(),
        exact_approval,
        exact_escrow,
        replayed: false,
    })
}

/// Fixture-Eingang hinter der Sperre: derselbe Cutover-Port zuerst, dann
/// Vorprüfung und Zeremonie gegen einen gegebenen Kontext (Präsenznachweis,
/// Signierer, Uhr). Nur hinter `test-support`.
///
/// # Errors
///
/// Wie [`publish_reader_key_escrow`].
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn publish_reader_key_escrow_in_context(
    cutover: &dyn ReaderKeyEscrowCutover,
    context: &ReaderKeyEscrowPublicationContext<'_>,
    exact_package: &[u8],
) -> Result<PublishedReaderKeyEscrow, ReaderKeyEscrowError> {
    let bundle_release =
        cutover.active_v11_bundle_release(context.anchor, context.catalog, context.head)?;
    let published = match prepare_reader_key_escrow_package(
        context.database,
        context.head,
        exact_package,
        context.now,
    )? {
        PreparedReaderKeyEscrowPackage::Published(published) => published,
        PreparedReaderKeyEscrowPackage::Fresh(fresh) => {
            commit_reader_key_escrow_publication(context, &fresh, bundle_release)?
        }
    };
    distribute_published(context.distribute, &published)?;
    Ok(published)
}

/// Freigabe, dann Escrow ins Archiv — erst nach dem Commit (review-b P3-2).
fn distribute_published(
    distribute: &dyn Fn(&[u8]) -> Result<(), ReaderKeyEscrowError>,
    published: &PublishedReaderKeyEscrow,
) -> Result<(), ReaderKeyEscrowError> {
    distribute(&published.exact_approval)?;
    distribute(&published.exact_escrow)
}

/// Die exakten Trust-Objekte des Bestands einer Laufzeit.
fn trust_objects(runtime: &OperatorRuntime) -> Vec<&[u8]> {
    runtime
        .inventory()
        .trust()
        .iter()
        .map(|object| object.exact_bytes().as_bytes())
        .collect()
}

/// Genau ein Paket in der Escrow-Inbox.
fn single_package(inbox: &Path) -> Result<Vec<u8>, ReaderKeyEscrowError> {
    let mut packages = read_escrow_inbox(inbox)?
        .into_iter()
        .filter(|file| file.kind == ReaderKeyEscrowTransferKindV1::Package);
    let package = packages.next().ok_or(ReaderKeyEscrowError::TransferFile)?;
    if packages.next().is_some() {
        return Err(ReaderKeyEscrowError::TransferFile);
    }
    Ok(package.exact_bytes)
}

pub(crate) fn trust_digest_signer(
    runtime: &OperatorRuntime,
    slot: NativeSigningSlot,
) -> impl Fn(CertificateHash, Hash32) -> Result<Vec<u8>, ReaderKeyEscrowError> + '_ {
    move |certificate, digest| {
        runtime
            .ensure_current()
            .map_err(|_| ReaderKeyEscrowError::Operator)?;
        let provider = runtime.native().signing_provider(slot);
        provider
            .sign(
                &provider.handle(SecretPurpose::WriterSigningKey),
                ContentType::TrustDigest,
                certificate,
                digest.as_bytes(),
            )
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(|_| ReaderKeyEscrowError::Crypto)
    }
}

/// Zeremonie A in der Laufzeit des Autoritätswirts.
///
/// Der ERSTE Schritt ist `cutover` über die exakten Trust-Objekte des
/// Bestands; ohne aktive v1.1-Freigabe endet die Zeremonie dort, ohne Inbox,
/// Reauthentifizierung, Sperrzeile, Audit oder Datei.
///
/// Vor dem Commit wird die Laufzeit frisch geöffnet: dieselbe Autorität
/// (Kopf, Version, vorgeschlagene Sequenz, Konto, Zeitgrenzen) UND derselbe
/// Port-Befund. Ein `webBundleRevocation` bewegt den Registry-Kopf nicht; nur
/// der zweite Lauf des Ports sieht ihn. Er muss GENAU die Freigabe nennen, die
/// ins Audit 13 geht.
///
/// Nach dem Commit gehen Freigabe, dann Escrow inhaltsadressiert unter
/// `trust/` ins Archiv (auch beim exakten Wiedereinspielen), und der frisch
/// geöffnete Bestand muss das Escrow im gewählten Kopf als gültig tragen.
///
/// # Errors
///
/// `CutoverNotReady` zuerst; danach jeder [`ReaderKeyEscrowError`].
pub fn publish_reader_key_escrow(
    runtime: &OperatorRuntime,
    cutover: &dyn ReaderKeyEscrowCutover,
    inbox: &Path,
) -> Result<PublishedReaderKeyEscrow, ReaderKeyEscrowError> {
    let bundle_release = cutover.active_v11_bundle_release(
        runtime.anchor(),
        &trust_objects(runtime),
        runtime.head(),
    )?;
    let config = runtime.config();
    if !config.authority
        || config.role != OperatorRoleV1::OrganizationAdmin
        || config.purpose != ReauthPurpose::AdminRootCeremony
    {
        return Err(ReaderKeyEscrowError::Operator);
    }
    // Verfall beim Kommandostart, hinter dem Cutover-Port und vor jeder
    // Reauthentifizierung.
    purge_expired_reader_key_escrow_results(runtime)?;
    let exact_package = single_package(inbox)?;
    let now = || fresh_wall_clock().map_err(|_| ReaderKeyEscrowError::Operator);
    let archive_directory = config.archive_directory.clone();
    let distribute = |bytes: &[u8]| {
        crate::web_bundle_release::distribute_trust_object(&archive_directory, bytes)
    };
    let fresh = match prepare_reader_key_escrow_package(
        runtime.database(),
        runtime.head(),
        &exact_package,
        now()?,
    )? {
        PreparedReaderKeyEscrowPackage::Published(published) => {
            distribute_published(&distribute, &published)?;
            return Ok(published);
        }
        PreparedReaderKeyEscrowPackage::Fresh(fresh) => fresh,
    };
    let context_hash = fresh.escrow_core_hash();
    let session = runtime
        .reauthenticate_for_context(ReauthPurpose::AdminRootCeremony, context_hash)
        .map_err(|_| ReaderKeyEscrowError::Operator)?;
    if session.proof().context_hash() != Some(context_hash) {
        return Err(ReaderKeyEscrowError::Operator);
    }
    let audit = runtime.audit_service();
    let admin_sign = trust_digest_signer(runtime, NativeSigningSlot::Admin);
    let root_sign = trust_digest_signer(runtime, NativeSigningSlot::Root);
    let operator = |_| ReaderKeyEscrowError::Operator;
    let session_current = || {
        runtime.ensure_current().map_err(operator)?;
        let reopened = runtime.reopened_for_action().map_err(operator)?;
        reopened.ensure_current().map_err(operator)?;
        runtime
            .ensure_same_authority_as(&reopened)
            .map_err(operator)?;
        let again = cutover.active_v11_bundle_release(
            reopened.anchor(),
            &trust_objects(&reopened),
            reopened.head(),
        )?;
        if again != bundle_release {
            return Err(ReaderKeyEscrowError::CutoverNotReady);
        }
        if !session
            .proof()
            .is_valid_at(ReauthPurpose::AdminRootCeremony, now()?)
        {
            return Err(ReaderKeyEscrowError::Operator);
        }
        Ok(())
    };
    let catalog = trust_objects(runtime);
    let published = commit_reader_key_escrow_publication(
        &ReaderKeyEscrowPublicationContext {
            anchor: runtime.anchor(),
            catalog: &catalog,
            distribute: &distribute,
            database: runtime.database(),
            trust: runtime.trust(),
            head: runtime.head(),
            audit: &audit,
            proof: session.proof(),
            admin_certificate: config.device_certificate_hash,
            admin_binding: config.binding_object_hash,
            admin_sign: &admin_sign,
            root_sign: &root_sign,
            now: now()?,
            session_current: &session_current,
            fresh_approval_ids: &fresh_entropy,
        },
        &fresh,
        bundle_release,
    )?;
    distribute_published(&distribute, &published)?;
    // Der Bestand trägt das Escrow jetzt selbst: frisch geöffnet (Gate `trust`
    // über die ganze Escrow-Menge) und gültig im gewählten Kopf.
    let reopened = runtime.reopened_for_action().map_err(operator)?;
    let escrows = verify_reader_key_escrows(
        reopened.trust(),
        ReaderKeyEscrowHead::Selected(reopened.head()),
    )?;
    if escrows
        .get(published.escrow_object_hash)
        .is_none_or(|escrow| escrow.standing() != ea_trust::ReaderKeyEscrowStanding::Valid)
    {
        return Err(ReaderKeyEscrowError::Trust(TrustError::ActionMismatch));
    }
    Ok(published)
}
