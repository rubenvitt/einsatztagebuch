//! Die vier Abweisungen des Lesestapels — und die eine Anfrage, die im
//! gesperrten Zustand gar nicht erst entsteht.

#[path = "sync_support/mod.rs"]
mod sync_support;

use ea_reader::ReaderSyncError;
use sync_support::{ReaderSyncHarness, fixtures};

/// Die vier Abbruchgruende, jeder mit seinem eigenen Code und jeder OHNE
/// Cursorfortschritt. Ein gemeinsamer Sammelcode waere hier der Defekt: eine
/// Luecke ist eine Aussage ueber den Bestand, ein Fork eine ueber den Server.
#[test]
fn every_refusal_carries_its_own_code_and_leaves_the_cursor_where_it_was() {
    for (batch, code) in [
        (
            fixtures::batch_for_a_different_start_head(),
            "EA-READER-START-HEAD-MISMATCH",
        ),
        (
            fixtures::batch_with_a_missing_object(),
            "EA-READER-MISSING-OBJECT",
        ),
        (fixtures::batch_with_a_sequence_gap(), "EA-READER-CHAIN-GAP"),
        (
            fixtures::batch_forking_at_the_head(),
            "EA-READER-CHAIN-FORK",
        ),
    ] {
        let mut harness = ReaderSyncHarness::with_two_batches();
        let before = harness.confirmed_cursor();
        assert_eq!(harness.accept(batch).unwrap_err().code(), code);
        assert_eq!(harness.confirmed_cursor(), before);
        assert_eq!(harness.reopen_store().confirmed_cursor(), before);
    }
}

/// Der Startkopf wird gegen den EIGENEN bestaetigten Cursor geprueft und nicht
/// gegen das, was die Antwort ueber sich selbst sagt. Deshalb ist ein Batch,
/// der in sich stimmig ist und an einem fremden Kopf ansetzt, eine Abweisung.
#[test]
fn a_self_consistent_batch_at_a_foreign_head_is_still_refused() {
    let harness = ReaderSyncHarness::with_two_batches();
    let foreign = fixtures::internally_valid_batch_at_sequence(41);
    assert_eq!(
        harness.accept(foreign).unwrap_err().code(),
        "EA-READER-START-HEAD-MISMATCH"
    );
}

/// Kein Signaturheader entsteht ausserhalb von `RequestSigner`. Der Zeuge liest
/// den Request, den die Bruecke herausgibt, und verlangt beide Kopfzeilen samt
/// dem Label `ea1` und der Nonce, die in `signature-input` steht.
#[test]
fn the_pull_request_is_signed_with_the_vault_ed25519_key() {
    let harness = ReaderSyncHarness::with_two_batches();
    let request = harness.next_request().unwrap();
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
            .clone()
    };
    assert!(header("signature-input").starts_with("ea1=("));
    assert!(header("signature").starts_with("ea1=:"));
    assert!(request.target.starts_with("/v1/chains/"));
    assert_eq!(request.method, ea_sync_protocol::HttpMethod::Get);
}

/// Ein gesperrter Tresor ist keine Netzanfrage OHNE Signatur, sondern GAR
/// KEINE Anfrage.
///
/// Der Ed25519-Schluessel kommt nach `web-reader-design.md` §6.1
/// ausschliesslich aus der entsperrten Sitzung. Ein Dienst, der ohne sie einen
/// unsignierten Request herausgaebe, verschoebe die Weigerung an den Server —
/// und damit an eine Stelle, an der der Reader sie nicht mehr sieht.
#[test]
fn a_locked_vault_produces_no_request_at_all() {
    let harness = ReaderSyncHarness::with_a_locked_vault();
    assert_eq!(
        harness.next_request().unwrap_err().code(),
        ReaderSyncError::Store.code()
    );
}
