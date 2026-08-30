//! `ObjectTypeV1` steht GENAU EINMAL im Arbeitsbaum.
//!
//! Die geschlossene Menge 1..6 lag dreifach: als Praefixkonstanten in
//! `crates/ea-format/src/parser.rs`, als Zahlenzweig in `decode_exact_object`
//! und als getippter Aufzaehlungstyp in `crates/ea-verify/src/report.rs`. Der
//! Typ wohnt jetzt neben den Praefixkonstanten; `ea-verify` reicht ihn nur
//! noch durch.
//!
//! Dieser Test misst die Seite, die `ea-format` allein belegen kann: dass
//! `code()` die Typbytes der Praefixe SIND und nicht bloss zufaellig gleich.
//! Dass `ea-verify` GENAU diesen Typ durchreicht, steht in
//! `crates/ea-verify/tests/object_type.rs` — die Formatcrate darf dafuer keine
//! Dev-Kante auf ihren eigenen Verbraucher ziehen.

use ea_format::{
    EAG_PREFIX_V1, ECP_PREFIX_V1, EDS_PREFIX_V1, EIP_PREFIX_V1, ESR_PREFIX_V1, ETB_PREFIX_V1,
    ObjectTypeV1,
};

#[test]
fn every_code_is_the_type_byte_of_its_exact_object_prefix() {
    for (object_type, prefix) in [
        (ObjectTypeV1::Entry, EIP_PREFIX_V1),
        (ObjectTypeV1::Grant, EAG_PREFIX_V1),
        (ObjectTypeV1::Receipt, ESR_PREFIX_V1),
        (ObjectTypeV1::Evidence, ECP_PREFIX_V1),
        (ObjectTypeV1::Trust, ETB_PREFIX_V1),
        (ObjectTypeV1::Destroyed, EDS_PREFIX_V1),
    ] {
        assert_eq!(object_type.code(), u64::from(prefix[6]));
    }
}

#[test]
fn the_six_codes_are_the_closed_range_one_to_six_in_variant_order() {
    let codes: Vec<u64> = [
        ObjectTypeV1::Entry,
        ObjectTypeV1::Grant,
        ObjectTypeV1::Receipt,
        ObjectTypeV1::Evidence,
        ObjectTypeV1::Trust,
        ObjectTypeV1::Destroyed,
    ]
    .into_iter()
    .map(ObjectTypeV1::code)
    .collect();
    assert_eq!(codes, vec![1, 2, 3, 4, 5, 6]);

    // Die `Ord`-Ableitung traegt die Sortierung der Berichtssammlungen in
    // `ea-verify`; sie muss der Variantenreihenfolge folgen.
    let mut sorted = vec![ObjectTypeV1::Destroyed, ObjectTypeV1::Entry];
    sorted.sort_unstable();
    assert_eq!(sorted, vec![ObjectTypeV1::Entry, ObjectTypeV1::Destroyed]);
}
