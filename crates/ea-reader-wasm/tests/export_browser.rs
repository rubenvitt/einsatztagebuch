#![cfg(target_arch = "wasm32")]

//! Die Exportausfuhr und die Sitzungssperre in Headless-Chromium, ueber die
//! ECHTEN Ausfuhren der Bruecke.
//!
//! Die Kopfzeile `#![cfg(target_arch = "wasm32")]` steht in der ERSTEN Zeile,
//! aus dem Grund, den `tests/opfs_browser.rs` ausschreibt.
//!
//! # Was dieser Zeuge misst, das kein Wirtszeuge messen kann
//!
//! `crates/ea-reader/tests/export.rs` misst den Dienst mit einem Ziel im
//! Speicher. HIER laeuft die Bruecke selbst: `readerVaultUnlock` eroeffnet
//! eine Sitzung in der Tabelle des Workers, `readerExportOne` belegt die
//! Bestaetigung gegen den versiegelten Tresor, entnimmt den offenen Datensatz
//! und reicht den Klartext in eine `js_sys::Function` — die Grenze, an der
//! der Klartext den WASM-Speicher verlaesst —, und das signierte Protokoll
//! liegt danach versiegelt in OPFS. Daneben die Sperre: ein `Hidden` und
//! dreissig Sekunden Uhr, ohne Timer, und die Exportausfuhr weist ab.
//!
//! # IM DEDIZIERTEN WORKER
//!
//! `OpfsBlobStore::open` verlangt ihn, und die Sitzungstabelle liegt in einem
//! `thread_local!` — derselbe Faden fuer Eroeffnung und Export, wie in
//! `apps/web/src/bridge/opfs-worker.ts`.

#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;

use core::cell::RefCell;
use std::rc::Rc;

use ea_reader::{
    LocalAuditOutcomeV1, READER_AUDIT_LOG_BLOB_KEY_V1, ReaderAuditLogStore, ReaderBlobKey,
    UnixMillis, decode_local_audit_event,
};
use ea_reader_wasm::export_bridge::reader_export_one;
use ea_reader_wasm::opfs_worker::OpfsBlobStore;
use ea_reader_wasm::vault_bridge::{reader_vault_unlock, with_session};
use ea_reader_wasm::visibility::{reader_note_visibility, reader_session_state_at};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

use verify_fixtures::fixtures;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Das Verzeichnis, unter dem die Bruecke das Auditprotokoll fuehrt —
/// zeichengleich zu `AUDIT_BLOB_DIRECTORY` in `src/export_bridge.rs`.
const AUDIT_BLOB_DIRECTORY: &str = "ea-reader";

fn t(offset_ms: i64) -> f64 {
    (fixtures::EFFECTIVE_NOW.get() + offset_ms) as f64
}

fn sealed_bytes() -> Vec<u8> {
    fixtures::sealed_vault_with_pinned_anchor().to_deterministic_cbor()
}

/// Eine Senke, die den Klartext festhaelt und `true` zurueckgibt.
fn accepting_sink(received: Rc<RefCell<Option<Vec<u8>>>>) -> Function {
    let closure = Closure::<dyn FnMut(Uint8Array) -> bool>::new(move |bytes: Uint8Array| {
        *received.borrow_mut() = Some(bytes.to_vec());
        true
    });
    let function: Function = closure.as_ref().clone().unchecked_into();
    closure.forget();
    function
}

fn open_session(now: f64) -> u32 {
    reader_vault_unlock(
        sealed_bytes(),
        fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
        fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
        now,
    )
    .expect("der Kulissen-Authenticator eroeffnet die Sitzung")
}

/// Der Weg ueber die Bruecke, vollstaendig: Sitzung, offener Datensatz,
/// frische Bestaetigung, Klartext in die Senke, zwei signierte Zeilen in
/// OPFS.
#[wasm_bindgen_test]
async fn the_bridge_exports_one_open_record_and_seals_two_audit_lines_into_opfs() {
    let session = open_session(t(0));
    let record = fixtures::decrypted_genesis_record();
    let entry_hash = record.entry_hash();
    let expected_plaintext = record.with_plaintext(<[u8]>::to_vec);
    with_session(session, |session| session.open_record(record)).expect("die Sitzung existiert");

    let received = Rc::new(RefCell::new(None));
    let identity = fixtures::audit_identity();
    let rendered = reader_export_one(
        session,
        t(1_000),
        sealed_bytes(),
        fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
        fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
        entry_hash.as_bytes().to_vec(),
        1,
        false,
        identity.organization_id().as_bytes().to_vec(),
        identity.device_id().as_bytes().to_vec(),
        identity
            .signer_certificate_object_hash()
            .as_bytes()
            .to_vec(),
        accepting_sink(Rc::clone(&received)),
    )
    .await
    .expect("der Export ueber die Bruecke gelingt");

    assert_eq!(
        rendered,
        format!(
            "{{\"entryHash\":\"{}\",\"targetKind\":1}}",
            hex::encode(entry_hash.as_bytes())
        )
    );
    assert_eq!(
        received.borrow().as_deref(),
        Some(expected_plaintext.as_slice())
    );

    // Der Datensatz hat die Sitzung VERLASSEN — ein Versuch verbraucht die
    // offene Kopie.
    let view = reader_session_state_at(session, t(1_001)).expect("die Sitzung existiert");
    assert_eq!(view, "{\"locked\":false,\"openEntryHashes\":[]}");

    // Und das Protokoll liegt versiegelt in OPFS: zwei Zeilen, Accepted und
    // Completed, jede fuer sich signiert und wieder dekodierbar.
    let key = ReaderBlobKey::new(READER_AUDIT_LOG_BLOB_KEY_V1).unwrap();
    let store = OpfsBlobStore::open(AUDIT_BLOB_DIRECTORY, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    let events = with_session(session, |session| {
        let vault = session
            .vault(UnixMillis::new(t(1_002) as i64))
            .expect("die Sitzung ist offen");
        ReaderAuditLogStore::open(vault).events(&store)
    })
    .expect("die Sitzung existiert")
    .expect("das Protokoll geht auf");
    let outcomes: Vec<LocalAuditOutcomeV1> = events
        .iter()
        .map(|event| {
            decode_local_audit_event(event)
                .expect("signierte Zeile")
                .outcome()
        })
        .collect();
    assert_eq!(
        outcomes,
        vec![
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ]
    );

    // GESCHLOSSEN, bevor die Bruecke den Schluessel ein zweites Mal oeffnet:
    // `OpfsBlobStore::open` wartet auf den Platz in der Warteschlange des
    // Schluessels, und ein Speicher, den dieser Fall noch haelt, liesse den
    // zweiten Versuch auf sich selbst warten. GEMESSEN gegen die erste Fassung
    // dieses Zeugen, woertlich: `Failed to detect test as having been run. It
    // might have timed out.` — dieselbe Lehre, die `tests/index_browser.rs`
    // schon traegt.
    drop(store);

    // Ein zweiter Versuch auf denselben Hash: der Datensatz ist nicht mehr
    // offen, und die Senke wird nie gerufen.
    let untouched = Rc::new(RefCell::new(None));
    let refused = reader_export_one(
        session,
        t(2_000),
        sealed_bytes(),
        fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
        fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
        entry_hash.as_bytes().to_vec(),
        1,
        false,
        identity.organization_id().as_bytes().to_vec(),
        identity.device_id().as_bytes().to_vec(),
        identity
            .signer_certificate_object_hash()
            .as_bytes()
            .to_vec(),
        accepting_sink(Rc::clone(&untouched)),
    )
    .await
    .expect_err("kein offener Datensatz, kein Export");
    assert_eq!(
        refused.as_string().as_deref(),
        Some("EA-READER-EXPORT-NO-RECORD")
    );
    assert!(untouched.borrow().is_none());
}

/// Die Sperre ueber die Bruecke: `Hidden`, dreissig Sekunden Uhr, KEIN Timer —
/// und die Exportausfuhr weist ab, ohne die Senke zu rufen.
#[wasm_bindgen_test]
async fn a_hidden_tab_locks_the_bridge_session_and_the_export_refuses() {
    let session = open_session(t(0));
    let record = fixtures::decrypted_genesis_record();
    let entry_hash = record.entry_hash();
    with_session(session, |session| session.open_record(record)).expect("die Sitzung existiert");
    reader_note_visibility(session, true, t(1_000)).expect("die Sitzung existiert");

    let before = reader_session_state_at(session, t(1_000 + 29_999)).expect("Sitzung");
    assert_eq!(
        before,
        format!(
            "{{\"locked\":false,\"openEntryHashes\":[\"{}\"]}}",
            hex::encode(entry_hash.as_bytes())
        )
    );
    let after = reader_session_state_at(session, t(1_000 + 30_000)).expect("Sitzung");
    assert_eq!(after, "{\"locked\":true,\"openEntryHashes\":[]}");

    let untouched = Rc::new(RefCell::new(None));
    let identity = fixtures::audit_identity();
    let refused = reader_export_one(
        session,
        t(1_000 + 30_001),
        sealed_bytes(),
        fixtures::VAULT_CREDENTIAL_ID_V1.to_vec(),
        fixtures::VAULT_PRF_OUTPUT_V1.to_vec(),
        entry_hash.as_bytes().to_vec(),
        2,
        false,
        identity.organization_id().as_bytes().to_vec(),
        identity.device_id().as_bytes().to_vec(),
        identity
            .signer_certificate_object_hash()
            .as_bytes()
            .to_vec(),
        accepting_sink(Rc::clone(&untouched)),
    )
    .await
    .expect_err("eine gesperrte Sitzung exportiert nicht");
    assert_eq!(
        refused.as_string().as_deref(),
        Some("EA-READER-SESSION-LOCKED")
    );
    assert!(untouched.borrow().is_none());

    // Eine unbekannte Kennung ist die ANDERE Weigerung.
    let unknown = reader_session_state_at(session + 1_000, t(0)).expect_err("unbekannt");
    assert_eq!(
        unknown.as_string().as_deref(),
        Some("EA-READER-SESSION-UNKNOWN")
    );
}
