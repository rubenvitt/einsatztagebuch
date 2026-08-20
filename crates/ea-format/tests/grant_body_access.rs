mod support;

use ea_format::{
    GrantBodyFieldsV1, GrantBodyV1, GrantKindV1, GrantPurposeV1, GrantV1, ParsedArchiveObject,
    decode_exact_object, encode_grant,
};
use ea_types::{RegistryVersion, UnixMillis};

fn sample_fields() -> GrantBodyFieldsV1 {
    GrantBodyFieldsV1 {
        organization_id: support::organization(1),
        chain_id: support::chain(2),
        entry_hash: support::entry_hash(3),
        kind: GrantKindV1::Initial,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: support::key_thumbprint(4),
        recipient_certificate_hash: support::certificate(5),
        issuer_key_thumbprint: support::signer_thumbprint(),
        issuer_certificate_hash: support::certificate(3),
        registry_version: RegistryVersion::new(6),
        registry_head_hash: support::typed_hash(7),
        created_at_device: UnixMillis::new(8),
        original_recovery_grant_object_hash: None,
        grant_authorization_object_hash: None,
        encapsulated_key: [9; 32],
        wrapped_cek: [10; 48],
    }
}

/// Ohne diesen Zugriff sind die Gates `grant-plan`, `recipient-grant` und die
/// Entkapselung `hpke-open` (design.md §14.1) nicht implementierbar: ein
/// Verifizierer kann aus einem geparsten Grant weder den Empfaenger noch den
/// gebundenen Eintrag noch das HPKE-Material lesen.
#[test]
fn a_parsed_grant_exposes_its_verified_body_fields() {
    let fields = sample_fields();
    let body = GrantBodyV1::new(fields.clone()).unwrap();
    let signature = support::signer()
        .sign_initial_grant(body.exact_bytes())
        .unwrap();
    let bytes = encode_grant(&GrantV1::new(body, signature).unwrap())
        .unwrap()
        .into_vec();

    let ParsedArchiveObject::Grant(parsed) = decode_exact_object(&bytes).unwrap() else {
        panic!("expected a grant");
    };
    let decoded = parsed.value().grant_body().fields();

    assert_eq!(
        decoded.entry_hash.as_bytes(),
        fields.entry_hash.as_bytes(),
        "recipient-grant must bind the grant to its entry"
    );
    assert_eq!(
        decoded.recipient_key_thumbprint.as_bytes(),
        fields.recipient_key_thumbprint.as_bytes(),
        "recipient-grant must identify the recipient"
    );
    assert_eq!(
        decoded.recipient_certificate_hash.as_bytes(),
        fields.recipient_certificate_hash.as_bytes()
    );
    assert_eq!(decoded.encapsulated_key, fields.encapsulated_key);
    assert_eq!(decoded.wrapped_cek, fields.wrapped_cek);
    assert_eq!(
        decoded.registry_version.get(),
        fields.registry_version.get()
    );
    assert_eq!(decoded.kind, GrantKindV1::Initial);
    assert_eq!(decoded.purpose, GrantPurposeV1::Reader);

    // Die exakten Bytes bleiben erreichbar und sind mit den Feldern konsistent.
    assert_eq!(
        parsed.value().grant_body().exact_bytes(),
        parsed.value().exact_grant_body()
    );
}

/// Der Schnitt auf `grant-context-v1` ist jetzt oeffentlich, weil BEIDE Seiten
/// dieselben Bytes brauchen: `ea-verify` oeffnet damit, und der Writer
/// versiegelt damit. Zwei Kopien des Schnitts waeren zwei Gelegenheiten,
/// `hpke_info` und `hpke_aad` mit verschiedenen Bytes zu speisen.
#[test]
fn the_grant_context_cut_is_the_body_without_its_fixed_eighty_four_byte_tail() {
    let body = GrantBodyV1::new(sample_fields()).unwrap();
    let exact = body.exact_bytes();
    let context = body
        .exact_grant_context()
        .expect("ein selbst gebauter Rumpf traegt den bewiesenen Schwanz");

    // Arraykopf (1) + Kontext + zwei kanonische Bytefolgen (2 + 32, 2 + 48).
    assert_eq!(exact.len(), 1 + context.len() + 84);
    assert_eq!(&exact[1..1 + context.len()], context);
    assert_eq!(
        exact[0], 0x83,
        "grant-body-v1 ist ein Array der Laenge drei"
    );

    // Kapselung und umschlossener CEK stehen AUSSERHALB des Kontexts. Genau
    // das ist der Grund fuer den Schnitt: `hpkeInfo` und `hpkeAad` binden den
    // Kontext und nie das Material, das sie selbst erzeugen — sonst waere die
    // Versiegelung zirkulaer und der Writer koennte sie nicht zweistufig
    // bauen.
    let other_material = GrantBodyV1::new(GrantBodyFieldsV1 {
        encapsulated_key: [99; 32],
        wrapped_cek: [11; 48],
        ..sample_fields()
    })
    .unwrap();
    assert_eq!(
        other_material.exact_grant_context().unwrap(),
        context,
        "Kapselung und umschlossener CEK duerfen den Kontext nicht veraendern"
    );

    // Ein Feld INNERHALB des Kontexts veraendert ihn. Ohne diese Haelfte waere
    // die Zusage mit einem konstanten Schnitt erfuellbar.
    let other_entry = GrantBodyV1::new(GrantBodyFieldsV1 {
        entry_hash: support::entry_hash(77),
        ..sample_fields()
    })
    .unwrap();
    assert_ne!(
        other_entry.exact_grant_context().unwrap(),
        context,
        "ein anderer gebundener Eintrag MUSS einen anderen Kontext ergeben"
    );
}
