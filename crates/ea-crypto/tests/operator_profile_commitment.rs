use ea_crypto::{operator_profile_commitment, operator_profile_digest};
use ea_types::{OperatorSubjectId, OrganizationId};

#[test]
fn profile_fields_match_the_literal_five_element_cbor_context() {
    let organization = OrganizationId::try_from(&[0x11; 16][..]).unwrap();
    let subject = OperatorSubjectId::try_from(&[0x22; 16][..]).unwrap();
    // Definite array(5), two bytes(16), UTF-8 text, bytes(32). This literal
    // catches field order, accidental version fields, and text/byte confusion.
    let exact = hex::decode(concat!(
        "855011111111111111111111111111111111",
        "5022222222222222222222222222222222",
        "654ac3b67267", // text(5): Jörg
        "63494142",     // text(3): IAB
        "58203333333333333333333333333333333333333333333333333333333333333333"
    ))
    .unwrap();
    let expected = operator_profile_digest(&exact);
    assert!(
        operator_profile_commitment(organization, subject, "Jörg", "IAB", &[0x33; 32]) == expected
    );
    for actual in [
        operator_profile_commitment(
            OrganizationId::try_from(&[0x12; 16][..]).unwrap(),
            subject,
            "Jörg",
            "IAB",
            &[0x33; 32],
        ),
        operator_profile_commitment(
            organization,
            OperatorSubjectId::try_from(&[0x23; 16][..]).unwrap(),
            "Jörg",
            "IAB",
            &[0x33; 32],
        ),
        operator_profile_commitment(organization, subject, "Jörg X", "IAB", &[0x33; 32]),
        operator_profile_commitment(organization, subject, "Jörg", "Führung", &[0x33; 32]),
        operator_profile_commitment(organization, subject, "Jörg", "IAB", &[0x34; 32]),
    ] {
        assert!(actual != expected);
    }
}

#[test]
fn the_digest_does_not_silently_normalize_claimed_profile_text() {
    let organization = OrganizationId::try_from(&[0x11; 16][..]).unwrap();
    let subject = OperatorSubjectId::try_from(&[0x22; 16][..]).unwrap();
    assert!(
        operator_profile_commitment(organization, subject, "Jörg", "IAB", &[0x33; 32])
            != operator_profile_commitment(
                organization,
                subject,
                "Jo\u{308}rg",
                "IAB",
                &[0x33; 32]
            )
    );
}
