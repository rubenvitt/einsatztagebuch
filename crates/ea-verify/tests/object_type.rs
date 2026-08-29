//! `ObjectTypeV1` wird DURCHGEREICHT, nicht ein zweites Mal deklariert.
//!
//! Die geschlossene Menge 1..6 wohnt seit dieser Stufe neben den
//! Exact-Object-Praefixen in `crates/ea-format/src/parser.rs`; `ea-verify`
//! exportiert sie mit `pub use ea_format::ObjectTypeV1;` weiter — dasselbe
//! Muster wie `crates/ea-ui-contracts/src/lib.rs`.
//!
//! Der Nachweis steht HIER und nicht in `crates/ea-format/tests/object_type.rs`:
//! `ea-verify` haengt bereits an `ea-format`, die Gegenrichtung braeuchte eine
//! neue Dev-Kante der Formatcrate auf ihren eigenen Verbraucher. Die
//! ea-format-Seite der Aussage — `code()` gegen die Praefixbytes, der
//! geschlossene Bereich, die `Ord`-Reihenfolge — steht dort.

#[test]
fn object_type_v1_is_the_very_type_that_ea_format_declares() {
    assert_eq!(
        ea_verify::ObjectTypeV1::Trust,
        ea_format::ObjectTypeV1::Trust
    );

    // Identitaet, nicht nur Gleichheit: eine zweite Deklaration mit denselben
    // Varianten kaeme durch das `assert_eq!` oben nicht mehr durch, wohl aber
    // durch eine `PartialEq`-Implementierung von Hand. Diese Bindung nicht.
    let re_exported: ea_format::ObjectTypeV1 = ea_verify::ObjectTypeV1::Grant;
    assert_eq!(re_exported.code(), 2);
}

#[test]
fn the_report_still_names_every_one_of_the_six_object_types() {
    // `objectResult.objectType` des Berichtsschemas ist genau der Wertebereich
    // dieses Typs; das Durchreichen darf ihn nicht verengt haben.
    let codes: Vec<u64> = [
        ea_verify::ObjectTypeV1::Entry,
        ea_verify::ObjectTypeV1::Grant,
        ea_verify::ObjectTypeV1::Receipt,
        ea_verify::ObjectTypeV1::Evidence,
        ea_verify::ObjectTypeV1::Trust,
        ea_verify::ObjectTypeV1::Destroyed,
    ]
    .into_iter()
    .map(ea_verify::ObjectTypeV1::code)
    .collect();
    assert_eq!(codes, vec![1, 2, 3, 4, 5, 6]);
}
