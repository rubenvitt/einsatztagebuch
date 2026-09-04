//! Die Bruecke des Einzelexports: GENAU EINE Ausfuhr, und sie nimmt GENAU
//! EINEN Eintragshash.
//!
//! # Was hinein- und was herausgeht
//!
//! Hinein gehen die Sitzungskennung, die Uhr, der versiegelte Tresor samt der
//! FRISCHEN PRF-Ausgabe der Bestaetigungszeremonie, der Eintragshash des
//! Datensatzes, die Zielart als Zahl, die Aussage, ob das Ziel besetzt ist,
//! die drei Identitaetsfelder der Auditzeile und eine JS-Funktion, die den
//! Klartext entgegennimmt. Hinaus geht das GENERIERTE `SingleExportReportView`
//! als JSON — Entry-Hash und Zielart. Nie der Pfad: die Bruecke kennt ihn
//! nicht, und `export-context-v1` hat keine Position fuer ihn.
//!
//! # Die Grenze ist der Aufruf der JS-Funktion
//!
//! `ReaderExportService::export_one` schreibt die `Accepted`-Zeile, ruft dann
//! `ReaderExportTarget::write`, und DIESES Modul reicht die Bytes in eine
//! `js_sys::Function`. Der Aufruf kopiert den Klartext in den JS-Heap des
//! Workers — das ist der Augenblick, in dem er den WASM-Speicher verlaesst.
//! Was der Wirt danach tut (den Dateidialog schreiben, einen Download
//! anstossen), bezeugt die `Completed`-Zeile NICHT; sie bezeugt die Uebergabe.
//! `crates/ea-reader/src/export.rs` schreibt dasselbe im Modulkopf aus.
//!
//! # Ein Versuch verbraucht die offene Kopie
//!
//! `export_one` nimmt den Datensatz BESITZEND, und `ReaderSession::take_open_record`
//! gibt ihn heraus. Auch ein abgewiesener Versuch — besetztes Ziel, abgelaufene
//! Bestaetigung — laesst den Datensatz fallen; die Flaeche oeffnet ihn fuer
//! einen zweiten Versuch neu. Das ist die schmalere Zusage, und sie ist
//! Absicht: eine Kopie, die einen Fehlschlag ueberlebt, ist eine Kopie mehr.
//!
//! # Warum die Identitaet HEREINKOMMT
//!
//! `LocalAuditEventCoreFieldsV1` verlangt Organisation, Geraet und den
//! Objekthash des signierenden Zertifikats, und der Browser-Tresor traegt
//! keinen dieser Werte. Ein Reader-Zertifikat stellt die Administrationsstufe
//! aus; bis dahin reicht die Flaeche die drei Werte herein, und die Bruecke
//! erfindet keinen.

use ea_reader::{EntryHash, ReaderExportTargetKindV1};

use crate::bridge::Json;

#[cfg(target_arch = "wasm32")]
use ea_crypto::SecretBytes;
#[cfg(target_arch = "wasm32")]
use ea_reader::{
    AuthenticatorPrfV1, DeviceId, ObjectHash, OrganizationId, READER_AUDIT_LOG_BLOB_KEY_V1,
    ReaderAuditIdentityV1, ReaderAuditLogSink, ReaderAuditLogStore,
    ReaderAuthenticatorConfirmation, ReaderBlobKey, ReaderConfirmationPurpose, ReaderExportService,
    ReaderExportTarget, ReaderExportTargetError, ReaderSessionState, SealedVaultV1, UnixMillis,
};
#[cfg(target_arch = "wasm32")]
use js_sys::{Function, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroize;

#[cfg(target_arch = "wasm32")]
use crate::opfs_worker::OpfsBlobStore;
#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::{SESSION_UNKNOWN_CODE, with_session};

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage ueber den Export
/// ist: eine falsche Laenge, eine Zielart, die keine ist.
#[cfg(target_arch = "wasm32")]
const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-EXPORT-BRIDGE-ARGUMENT";

/// Der Code fuer einen Eintragshash, der in dieser Sitzung nicht offen ist.
///
/// Eine EIGENE Aussage neben den Codes von `ReaderExportError`: der Dienst
/// sieht einen Datensatz oder keinen, die Bruecke muss ihn erst finden.
pub const NO_OPEN_RECORD_CODE: &str = "EA-READER-EXPORT-NO-RECORD";

/// Das Verzeichnis des versiegelten Auditprotokolls — dasselbe wie das des
/// Tresors, der Zustaende und des Sync-Cursors.
#[cfg(target_arch = "wasm32")]
const AUDIT_BLOB_DIRECTORY: &str = "ea-reader";

/// Die Laenge einer PRF-Ausgabe in Byte.
#[cfg(target_arch = "wasm32")]
const PRF_OUTPUT_SIZE: usize = 32;

/// Das `SingleExportReportView` als JSON — die REINE Haelfte.
#[must_use]
pub fn export_report_json(entry_hash: EntryHash, target_kind: ReaderExportTargetKindV1) -> String {
    let mut json = Json::object();
    json.string("entryHash", &hex::encode(entry_hash.as_bytes()))
        .raw("targetKind", &target_kind.target_kind().to_string());
    json.finish()
}

/// Die Zielart aus ihrer Zahl — die Form, in der die Flaeche sie nennt.
///
/// Zahlen und nicht Wortlaute, damit `apps/web` kein Literal fuehrt, das
/// gegen `ReaderExportTargetKindV1::label` driften koennte; die Zahlen sind
/// die eingefrorenen Werte der Position `target-kind`.
#[must_use]
pub fn target_kind_from_number(value: u32) -> Option<ReaderExportTargetKindV1> {
    match value {
        1 => Some(ReaderExportTargetKindV1::UserChosenFile),
        2 => Some(ReaderExportTargetKindV1::UserInitiatedDownload),
        _ => None,
    }
}

/// Das Ziel der Bruecke: eine JS-Funktion, die den Klartext annimmt.
#[cfg(target_arch = "wasm32")]
struct JsTarget {
    kind: ReaderExportTargetKindV1,
    occupied: bool,
    sink: Function,
}

#[cfg(target_arch = "wasm32")]
impl ReaderExportTarget for JsTarget {
    fn kind(&self) -> ReaderExportTargetKindV1 {
        self.kind
    }

    fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Kopiert die Bytes in ein `Uint8Array` des JS-Heaps und ruft die Senke.
    /// `true` heisst angenommen; alles andere — `false`, ein geworfener
    /// Fehler — ist der wortlose Fehlschlag.
    fn write(&mut self, plaintext: &[u8]) -> Result<(), ReaderExportTargetError> {
        let bytes = Uint8Array::from(plaintext);
        match self.sink.call1(&JsValue::NULL, &bytes) {
            Ok(accepted) if accepted.is_truthy() => Ok(()),
            _ => Err(ReaderExportTargetError),
        }
    }
}

/// Liest genau `N` Byte oder weist ab.
#[cfg(target_arch = "wasm32")]
fn exactly<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))
}

/// Exportiert GENAU EINEN offenen Datensatz dieser Sitzung.
///
/// Die Reihenfolge: Argumente pruefen, das Auditprotokoll in OPFS oeffnen
/// (der EINE asynchrone Vorlauf), die Sitzung als offen pruefen, den
/// Datensatz der Sitzung ENTNEHMEN, die Bestaetigung gegen den versiegelten
/// Tresor belegen, dann `ReaderExportService::export_one` — das die
/// `Accepted`-Zeile schreibt, die Bytes in `sink` reicht und `Completed` oder
/// `Failed` nachschreibt. Der Rueckgabewert ist das `SingleExportReportView`.
///
/// # Errors
/// `EA-READER-EXPORT-BRIDGE-ARGUMENT` fuer eine Eingabe falscher Form,
/// `EA-READER-SESSION-UNKNOWN` und `EA-READER-SESSION-LOCKED` fuer die
/// Sitzung, `EA-READER-EXPORT-NO-RECORD` fuer einen Eintragshash, der nicht
/// offen ist, die Codes des Tresors fuer eine Bestaetigung, die der
/// Authenticator nicht belegt (`EA-CRYPTO-AEAD-OPEN`,
/// `EA-READER-VAULT-NO-ENVELOPE`), `EA-READER-BLOB-HOST` fuer den OPFS-Wirt
/// und die stabilen Codes von `ReaderExportError`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerExportOne")]
#[allow(clippy::too_many_arguments)]
pub async fn reader_export_one(
    session: u32,
    now_ms: f64,
    sealed: Vec<u8>,
    credential_id: Vec<u8>,
    mut prf_output: Vec<u8>,
    entry_hash: Vec<u8>,
    target_kind: u32,
    target_occupied: bool,
    organization_id: Vec<u8>,
    device_id: Vec<u8>,
    signer_certificate_object_hash: Vec<u8>,
    sink: Function,
) -> Result<String, JsValue> {
    let now = UnixMillis::new(now_ms as i64);
    let mut prf: [u8; PRF_OUTPUT_SIZE] = exactly(&prf_output)?;
    prf_output.zeroize();
    let authenticator = AuthenticatorPrfV1::new(credential_id, SecretBytes::new(prf));
    prf.zeroize();
    let entry_hash = EntryHash::from(
        ea_reader::Hash32::try_from(entry_hash.as_slice())
            .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?,
    );
    let kind = target_kind_from_number(target_kind)
        .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
    let identity = ReaderAuditIdentityV1::new(
        OrganizationId::try_from(organization_id.as_slice())
            .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?,
        DeviceId::try_from(device_id.as_slice())
            .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?,
        ObjectHash::try_from(signer_certificate_object_hash.as_slice())
            .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?,
    );
    let sealed = SealedVaultV1::from_deterministic_cbor(&sealed)
        .map_err(|error| JsValue::from_str(error.code()))?;

    // Der EINE asynchrone Vorlauf, VOR jeder Ausleihe der Sitzungstabelle.
    let audit_key = ReaderBlobKey::new(READER_AUDIT_LOG_BLOB_KEY_V1)
        .map_err(|error| JsValue::from_str(error.code()))?;
    let mut store = OpfsBlobStore::open(AUDIT_BLOB_DIRECTORY, std::slice::from_ref(&audit_key))
        .await
        .map_err(|error| JsValue::from_str(error.code()))?;

    with_session(session, |session| {
        if session.state_at(now) == ReaderSessionState::Locked {
            return Err(JsValue::from_str(
                ea_reader::ReaderSessionError::Locked.code(),
            ));
        }
        let record = session
            .take_open_record(entry_hash)
            .ok_or_else(|| JsValue::from_str(NO_OPEN_RECORD_CODE))?;
        let confirmation = ReaderAuthenticatorConfirmation::prove(
            &sealed,
            &authenticator,
            ReaderConfirmationPurpose::SingleExport,
            now,
        )
        .map_err(|error| JsValue::from_str(error.code()))?;
        let log = {
            let vault = session
                .vault(now)
                .ok_or_else(|| JsValue::from_str(ea_reader::ReaderSessionError::Locked.code()))?;
            ReaderAuditLogStore::open(vault)
        };
        let mut audit_sink = ReaderAuditLogSink::new(&log, &mut store);
        let mut target = JsTarget {
            kind,
            occupied: target_occupied,
            sink,
        };
        let mut service = ReaderExportService::open(session, identity, &mut audit_sink, now);
        let report = service
            .export_one(record, Some(&mut target), confirmation)
            .map_err(|error| JsValue::from_str(error.code()))?;
        Ok(export_report_json(
            report.entry_hash(),
            report.target_kind(),
        ))
    })
    .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))?
}
