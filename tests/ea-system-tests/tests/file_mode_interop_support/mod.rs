//! Die Kulisse des Datei-Modus-Systemzeugen `reader_file_mode_interop`.
//!
//! # Zwei `#[path]`-Ketten und KEIN zweiter Baukasten
//!
//! 1. `crates/ea-reader/tests/verify_fixtures/mod.rs` — der Kulissen-Tresor
//!    (`unlocked_vault_with_pinned_anchor`, `vault_pinning`), die Bestaende
//!    (`complete_archive`, `archive_with_receipts`) und der Containerkodierer
//!    `exported_bundle_bytes`. Es ist DIESELBE Kette, die
//!    `crates/ea-reader-wasm` faehrt; hier wird nichts davon nachgebaut.
//! 2. `crates/ea-archive-fs/tests/support/mod.rs` — `BundleHarness` (der
//!    lueckenlose Bestand auf einer ECHTEN `LocalPathBackend`-Wurzel und
//!    `write_archive_bundle` darueber), `temp_root`, `local_profile` und
//!    `policy_allowing_only_source`.
//!
//! Beide Ketten binden ihrerseits `crates/ea-verify/tests/support/mod.rs` ein;
//! daher `allow(clippy::duplicate_mod)`, aus demselben Grund wie in
//! `tests/ea-system-tests/tests/support/mod.rs`. Die zwei Kopien werden nie
//! gemischt: der Tresor kommt IMMER aus Kette 1, der Plattenbestand IMMER aus
//! Kette 2, und dass beide denselben Anker meinen, MISST der Zeuge
//! (`harness.anchor().trust_anchor_hash() == fixtures::pinned_anchor_hash()`),
//! statt es anzunehmen.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`
//! auf Modulebene, genau wie in den eingebundenen Modulen.
#![allow(dead_code, clippy::duplicate_mod)]

#[path = "../../../../crates/ea-reader/tests/verify_fixtures/mod.rs"]
pub mod verify_fixtures;

#[path = "../../../../crates/ea-archive-fs/tests/support/mod.rs"]
pub mod archive_fs_support;

use std::collections::BTreeSet;

use ea_format::ObjectTypeV1;
use ea_verify::{ChainGapV1, VerificationReportV1};

use verify_fixtures::verify_support::archive_support::{ArchiveFixture, has_exact_object_prefix};

/// Die Endung der Serverquittungen im Bestand.
pub const RECEIPT_SUFFIX_V1: &str = ".esr";

/// DERSELBE Bestand, dem die `.esr`-Objekte VORENTHALTEN sind.
///
/// Byte fuer Byte dieselben uebrigen Blobs unter denselben Adressen — kein
/// zweiter Aufbau der Kulisse. Das ist der Grund, weshalb der Zeuge nicht
/// `receipt_archive(ReceiptArchiveSpec::bare())` ruft: die `.eag` der Fixture
/// entstehen ueber eine echte HPKE-Kapselung und sind je Aufbau verschieden
/// (`crates/ea-reader/tests/verify_fixtures/fixtures.rs`, Modulkopf); ein
/// zweiter Aufbau waere nicht „derselbe Bestand ohne Quittungen", sondern ein
/// anderer.
#[must_use]
pub fn without_receipts(source: &ArchiveFixture) -> ArchiveFixture {
    let mut withheld = ArchiveFixture::new();
    for (path_hint, bytes) in source.blobs() {
        if path_hint.ends_with(RECEIPT_SUFFIX_V1) {
            continue;
        }
        if has_exact_object_prefix(bytes) {
            withheld.push_exact_bytes(path_hint, bytes.clone());
        } else {
            withheld.push_non_object(path_hint, bytes);
        }
    }
    withheld
}

/// Wie viele `.esr`-Blobs der Bestand traegt.
#[must_use]
pub fn receipt_count(source: &ArchiveFixture) -> usize {
    source
        .blobs()
        .iter()
        .filter(|(path_hint, _)| path_hint.ends_with(RECEIPT_SUFFIX_V1))
        .count()
}

/// Eine Zeile der `objectResults`, ordnungsfaehig gemacht.
///
/// `ObjectResultKindV1` und `ServerConfirmationV1` leiten kein `Ord` ab; ihre
/// `as_str()`-Werte sind die Schemaspalten aus
/// `schemas/verification-report-v1.json` und damit genau das, was der Bericht
/// nach aussen traegt.
pub type ResultRow = ([u8; 32], ObjectTypeV1, &'static str, &'static str);

/// Die MENGE der `objectResults` samt der Spalte `serverConfirmation`.
///
/// Eine Menge und keine Liste, weil der Plan die Menge vergleicht: der
/// Container ist streng sortiert, die Kulissenquelle ist es nicht, und die
/// Reihenfolge der Zeilen ist keine Aussage des Berichts.
#[must_use]
pub fn result_rows(report: &VerificationReportV1) -> BTreeSet<ResultRow> {
    report
        .object_results()
        .map(|result| {
            (
                *result.object_hash().as_bytes(),
                result.object_type(),
                result.result().as_str(),
                result.server_confirmation().as_str(),
            )
        })
        .collect()
}

/// Die Luecken des Berichts als vergleichbare Liste.
#[must_use]
pub fn gap_rows(report: &VerificationReportV1) -> Vec<ChainGapV1> {
    report.gaps().copied().collect()
}
