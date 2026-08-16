//! Der Einstiegspunkt der Verifikation: [`verify_archive`].
//!
//! DIESE FASSUNG fuehrt ausschliesslich die Inventarisierung und damit Gate
//! `format` aus. Alle uebrigen Berichtsfelder bleiben leer, und
//! `pipeline_completed` bleibt falsch — der Bestand gilt also ausdruecklich
//! NICHT als vollstaendig verifiziert. Die Gates `trust` bis `recipient-grant`
//! folgen in den naechsten Tasks.

use core::marker::PhantomData;

use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;

use crate::{ChainHeadV1, ObjectErrorV1, QuarantinedObjectV1, VerificationReportV1, VerifyError};

/// Die Stellschrauben eines Verifikationslaufs.
///
/// DIE UHR IST PFLICHT und ausdruecklich KEIN `Option`: sie laesst sich aus dem
/// Bestand nicht herleiten. `ea_trust::VerifiedSignedTime` gibt keinen Rohwert
/// heraus (`crates/ea-trust/src/time.rs:19-32`), `prepare_local_time` verwirft
/// jede Zeitquelle, solange kein Kopf gepinnt ist
/// (`crates/ea-trust/src/time.rs:110-114`), und `verify_receipt_time` verlangt
/// eine `PreexistingRegistryAuthority`, die vor dem ersten Pin gar nicht
/// existiert (`crates/ea-trust/src/registry.rs:484`). Ohne uebergebene Uhr kann
/// diese Crate deshalb keinen Registrierungskopf auswaehlen.
///
/// Aus demselben Grund gibt es BEWUSST kein `Default`: ein Vorgabewert waere
/// entweder eine erfundene Zeit oder eine Uhrabfrage — und `SystemTime::now`
/// gehoert nicht in diese Crate.
///
/// Der Lebenszeitparameter traegt die spaeteren geliehenen Stellschrauben
/// (Empfaengerschluessel, Zustandsspeicher, Schema-Registry); bis dahin haelt
/// [`PhantomData`] ihn offen, damit die gepinnte Signatur `VerifyOptions<'_>`
/// nicht spaeter bricht.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyOptions<'a> {
    os_wall_clock: UnixMillis,
    borrowed: PhantomData<&'a ()>,
}

impl VerifyOptions<'_> {
    /// Ein Lauf gegen die uebergebene Betriebssystemuhr.
    #[must_use]
    pub const fn new(os_wall_clock: UnixMillis) -> Self {
        Self {
            os_wall_clock,
            borrowed: PhantomData,
        }
    }

    /// Die uebergebene Betriebssystemuhr. Roher Vergleichswert, kein Nachweis.
    #[must_use]
    pub const fn os_wall_clock(&self) -> UnixMillis {
        self.os_wall_clock
    }
}

/// Verifiziert einen Bestand und liefert den Bericht darueber.
///
/// Der Trust Anchor kommt als PARAMETER und nie aus dem Bestand
/// (`design.md` §11.4); daraus stammt insbesondere die Kettenkennung des
/// Berichts, sodass kein untergeschobenes Objekt sie bestimmen kann.
///
/// Ein Befund ueber ein einzelnes Objekt ist NIE ein `Err`: unlesbare, doppelte
/// und widerspruechliche Objekte stehen als `formatErrors` und
/// `quarantinedObjects` im Bericht, und der Lauf liefert `Ok`.
///
/// # Errors
///
/// [`VerifyError::Archive`], wenn der Bestand sich nicht vollstaendig
/// durchlaufen laesst, und [`VerifyError::NonCanonicalReport`], wenn der
/// Berichtsschreiber eine Zeichenkette ausser der Reihe vorfindet.
pub fn verify_archive(
    source: &dyn ArchiveSource,
    anchor: &TrustAnchorV1,
    options: VerifyOptions<'_>,
) -> Result<VerificationReportV1, VerifyError> {
    // Die Uhr traegt erst die Gates `trust` und `registry`. Sie wird hier
    // bewusst schon verlangt, damit die Signatur nicht spaeter bricht.
    let _ = options;

    // Gate `format`: das Inventar klassifiziert am 9-Byte-Exact-Object-Praefix
    // und parst jede Bytesequenz mit Praefix. Ein Fehlschlag erzeugt PAARWEISE
    // einen `formatError` und einen Quarantaeneeintrag `malformed`.
    let inventory = ArchiveInventory::build(source)?;

    let mut report = VerificationReportV1::empty(ChainHeadV1::sentinel(anchor.chain_id()));
    report.archive_object_count = inventory.archive_object_count();
    report.non_object_file_count = inventory.non_object_file_count();
    report.entry_package_count = inventory.entries().len();
    report.destroyed_entry_count = inventory.destroyed().len();
    for entry in inventory.format_errors() {
        report.format_errors.insert(
            entry.object_hash(),
            ObjectErrorV1::new(entry.object_hash(), entry.code()),
        );
    }
    for entry in inventory.quarantined() {
        report.quarantined_objects.insert(
            entry.object_hash(),
            QuarantinedObjectV1::new(entry.object_hash(), entry.reason()),
        );
    }
    report.seal()
}
