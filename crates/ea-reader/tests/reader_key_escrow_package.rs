//! Zeremonie A im Browser: das Escrow-Paket hinter dem KEM-Gleichheitsgate
//! (Profil §5 Schritte 2–3, Scheibe e).
mod escrow_line;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_crypto::{
    HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info, hpke_open,
    reader_key_escrow_core_hash,
};
use ea_format::{
    DecodedTrustPayloadV1, ReaderKeyEscrowHpkeContextV1, ReaderKeyEscrowTransferKindV1,
    TrustPayloadV1, decode_reader_key_escrow_package, reader_key_escrow_transfer_file_name,
};
use ea_reader::{match_sealing_key, seal_reader_key_escrow_package};
use ea_testkit::reader_key_escrow_fixture::escrow_core_hash;
use ea_trust::{
    ReaderKeyEscrowHead, verify_intended_reader_key_escrow, verify_reader_key_escrow_approval,
    verify_reader_key_escrow_sealing_target,
};
use ea_types::{SubjectId, UnixMillis};
use escrow_line::{LineSource, vault_on};
use escrow_support::{
    Basis, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED, SECOND_READER_KEM_SEED,
    approval_core, escrow_line, select, signed_approval, subject, tip_sequence, x25519_key,
};

const NOW: UnixMillis = UnixMillis::new(1_200);

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

#[test]
fn the_package_opens_to_the_vault_kem_and_carries_the_target_fields() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let vault = vault_on(&escrow, READER_KEM_SEED);
    let file =
        seal_reader_key_escrow_package(&vault, &LineSource::of(&escrow), reader_subject(), NOW)
            .unwrap();

    let package = decode_reader_key_escrow_package(file.exact_bytes()).unwrap();
    let core = package.core();
    let (trust, _) = select(&escrow.line, tip_sequence(&escrow.line));
    let target = verify_reader_key_escrow_sealing_target(
        &trust,
        ReaderKeyEscrowHead::CatalogLineTip,
        vault.kem_key_thumbprint(),
        reader_subject(),
    )
    .unwrap();
    let (version, head_hash, sequence) = target.enrollment();
    assert!(core.organization_id == target.organization_id());
    assert!(core.reader_certificate_object_hash == escrow.reader.certificate);
    assert!(core.reader_subject_id == reader_subject());
    assert_eq!(core.enrollment_registry_version, version);
    assert!(core.enrollment_registry_head_hash == head_hash);
    assert_eq!(core.enrollment_sequence, sequence);
    assert!(core.recovery_certificate_object_hash == escrow.recovery);
    assert!(core.recovery_kem_key_thumbprint == x25519_key(RECOVERY_KEM_SEED).thumbprint());
    assert!(core.root_key_thumbprint == target.root_key_thumbprint());
    assert_eq!(core.issued_at, NOW);

    // Das Chiffrat öffnet mit dem Recovery-Geheimnis zum Tresor-KEM.
    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(core).encode();
    let recovered = hpke_open(
        &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED)).unwrap(),
        &HpkeSealed::from_parts(core.encapsulated_key, core.encrypted_reader_kem_key).unwrap(),
        &hpke_info(&context),
        &hpke_aad(&context),
    )
    .unwrap();
    recovered.with_exposed(|bytes| assert_eq!(bytes, &READER_KEM_SEED));

    // Öffentliche Metadaten zur Anzeige, alle aus den Bytes.
    assert_eq!(
        file.file_name(),
        reader_key_escrow_transfer_file_name(
            ReaderKeyEscrowTransferKindV1::Package,
            file.exact_bytes()
        )
    );
    assert!(file.escrow_core_hash() == reader_key_escrow_core_hash(package.exact_core()));
    assert!(file.reader_certificate_object_hash() == escrow.reader.certificate);
    assert!(file.recovery_certificate_object_hash() == escrow.recovery);
    assert!(file.kem_key_thumbprint() == vault.kem_key_thumbprint());
}

/// Scheibenübergreifend: das Paket durch den C4-Decoder, eine
/// Testkit-Freigabe über seinen Core, dann nimmt die native Prüfung vor der
/// Wurzelsignatur es an.
#[test]
fn the_decoded_package_is_accepted_as_an_intended_escrow() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let vault = vault_on(&escrow, READER_KEM_SEED);
    let file =
        seal_reader_key_escrow_package(&vault, &LineSource::of(&escrow), reader_subject(), NOW)
            .unwrap();
    let package = decode_reader_key_escrow_package(file.exact_bytes()).unwrap();
    let core = package.core().clone();

    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let mut fields = approval_core(
        &escrow.line,
        Basis::of_selected(&head),
        (NOW.get() as u64 - 100, NOW.get() as u64 + 100),
        0xe3,
    );
    fields.escrow_core_hash = escrow_core_hash(&core);
    assert!(fields.escrow_core_hash == reader_key_escrow_core_hash(package.exact_core()));
    fields.reader_certificate_object_hash = core.reader_certificate_object_hash;
    fields.reader_subject_id = core.reader_subject_id;
    let approval_bytes = signed_approval(&escrow.line, &fields);
    let approval = verify_reader_key_escrow_approval(&trust, &head, &approval_bytes, NOW).unwrap();
    let payload = TrustPayloadV1::reader_key_escrow(core, approval.object_hash()).unwrap();
    let DecodedTrustPayloadV1::ReaderKeyEscrow(intended) = payload.decoded_payload().unwrap()
    else {
        panic!("an escrow payload")
    };
    verify_intended_reader_key_escrow(&trust, &head, &approval, &intended).unwrap();
}

/// Das Gate: ein Tresor, dessen KEM nicht der des Zertifikats ist, bekommt
/// keinen Beweis — und ohne Beweis gibt es kein Chiffrat.
#[test]
fn a_vault_with_a_foreign_kem_gets_no_match_and_no_bytes() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, _) = select(&escrow.line, tip_sequence(&escrow.line));
    let target = verify_reader_key_escrow_sealing_target(
        &trust,
        ReaderKeyEscrowHead::CatalogLineTip,
        x25519_key(READER_KEM_SEED).thumbprint(),
        reader_subject(),
    )
    .unwrap();
    let foreign = vault_on(&escrow, SECOND_READER_KEM_SEED);
    let refused = match_sealing_key(&foreign, target);
    assert_eq!(
        refused.err().map(|error| error.code()),
        Some("EA-READER-ESCROW-KEM-MISMATCH")
    );

    // Der ganze Weg mit dem fremden Tresor findet schon kein Zertifikat zu
    // seinem Abdruck.
    let whole =
        seal_reader_key_escrow_package(&foreign, &LineSource::of(&escrow), reader_subject(), NOW);
    assert_eq!(
        whole.err().map(|error| error.code()),
        Some("EA-TRUST-ESCROW-ENROLLMENT-MISMATCH")
    );
}

#[test]
fn the_gate_is_the_only_construction_and_hpke_seal_has_one_call_site() {
    // Gezählt wird der CODE: Doc-Kommentare (auch der compile_fail-Zeuge)
    // bleiben draußen.
    let source: String = include_str!("../src/reader_key_escrow.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        source
            .matches("pub struct EscrowSealingKeyMatchV1<")
            .count(),
        1,
        "genau eine Deklaration"
    );
    assert_eq!(
        source.matches("EscrowSealingKeyMatchV1 {").count(),
        1,
        "GENAU EIN Strukturausdruck, in match_sealing_key"
    );
    assert_eq!(source.matches("impl EscrowSealingKeyMatchV1").count(), 0);
    assert!(!source.contains("Clone for EscrowSealingKeyMatchV1"));
    assert!(!source.contains("Default for EscrowSealingKeyMatchV1"));
    assert_eq!(
        source.matches("hpke_seal(").count(),
        1,
        "versiegelt wird an genau einer Stelle, in seal_package"
    );
}
