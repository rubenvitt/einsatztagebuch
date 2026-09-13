//! Genuine byte mutations of the existing interrupted-writer fixture.
//! Removing or misclassifying a structural check must fail its exact witness.
mod support;

use ea_writer::{
    FinalizationFaultPoint, PreparedMarkerDiagnosisV1 as Diagnosis,
    PreparedMarkerDiscrepancyV1 as Discrepancy, diagnose_prepared_marker,
};
use support::WriterHarness;

fn prepared_bytes(harness: &WriterHarness) -> Vec<u8> {
    harness
        .repository()
        .prepared_finalization_marker()
        .expect("repository readable")
        .expect("prepared marker present")
        .as_bytes()
        .to_vec()
}

// Locate CBOR items in the real marker; never reproduce its encoder.
fn field(bytes: &[u8], index: usize) -> std::ops::Range<usize> {
    let mut decoder = minicbor::Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(7));
    for _ in 0..index {
        decoder.skip().unwrap();
    }
    let start = decoder.position();
    decoder.skip().unwrap();
    start..decoder.position()
}

fn first_grant_fields(bytes: &[u8]) -> [std::ops::Range<usize>; 2] {
    let mut decoder = minicbor::Decoder::new(bytes);
    decoder.set_position(field(bytes, 6).start);
    assert!(decoder.array().unwrap().unwrap() > 0);
    assert_eq!(decoder.array().unwrap(), Some(2));
    let hash_start = decoder.position();
    decoder.skip().unwrap();
    let bytes_start = decoder.position();
    decoder.skip().unwrap();
    [hash_start..bytes_start, bytes_start..decoder.position()]
}

fn payload<'a>(bytes: &'a [u8], item: &std::ops::Range<usize>) -> &'a [u8] {
    minicbor::Decoder::new(&bytes[item.clone()])
        .bytes()
        .unwrap()
}

fn replace(bytes: &[u8], item: std::ops::Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed.splice(item, replacement.iter().copied());
    changed
}

fn byte_string(value: &[u8]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.bytes(value).unwrap();
    encoder.into_writer()
}

fn flip_payload(bytes: &[u8], item: std::ops::Range<usize>) -> Vec<u8> {
    let mut value = payload(bytes, &item).to_vec();
    assert!(!value.is_empty());
    value[0] ^= 0x01;
    replace(bytes, item, &byte_string(&value))
}

#[test]
fn structural_consistency_does_not_distinguish_the_key_boundary_or_mutate_the_marker() {
    for point in [
        FinalizationFaultPoint::AfterPreparedMarkerCommit,
        FinalizationFaultPoint::AfterAbsenceConfirmation,
    ] {
        let mut harness = WriterHarness::with_incident();
        let interrupted = harness
            .finalize_with_fault(point)
            .expect("real interruption");
        let exact = interrupted
            .prepared()
            .expect("marker prepared")
            .exact_bytes();
        let original = exact.to_vec();
        assert_eq!(
            diagnose_prepared_marker(exact),
            Diagnosis::StructurallyConsistent
        );
        assert_eq!(exact, original);
        assert_eq!(prepared_bytes(&harness), original);
        assert!(harness.published_entry_paths().is_empty());
        assert!(harness.published_grant_paths().is_empty());
    }
}

#[test]
fn genuine_marker_discrepancies_keep_precise_diagnosis_and_legacy_recovery_errors() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterAbsenceConfirmation)
        .expect("real interruption");
    let original = prepared_bytes(&harness);
    assert_eq!(
        diagnose_prepared_marker(&original),
        Diagnosis::StructurallyConsistent
    );
    let [grant_hash, grant_bytes] = first_grant_fields(&original);
    let entry_bytes = field(&original, 5);
    assert_eq!(
        &original[field(&original, 1)],
        &[0x00],
        "fixture sequence zero"
    );
    let cases = [
        (
            Discrepancy::NoncanonicalReencoding,
            replace(&original, field(&original, 1), &[0x18, 0x00]),
        ),
        (
            Discrepancy::EmptyGrants,
            replace(&original, field(&original, 6), &[0x80]),
        ),
        (
            Discrepancy::GrantDecode,
            replace(&original, grant_bytes.clone(), &byte_string(&[0x00])),
        ),
        (
            Discrepancy::GrantType,
            replace(
                &original,
                grant_bytes.clone(),
                &original[entry_bytes.clone()],
            ),
        ),
        (
            Discrepancy::GrantObjectHash,
            flip_payload(&original, grant_hash),
        ),
        (
            Discrepancy::EntryDecode,
            replace(&original, entry_bytes.clone(), &byte_string(&[0x00])),
        ),
        (
            Discrepancy::EntryType,
            replace(&original, entry_bytes, &original[grant_bytes]),
        ),
        (
            Discrepancy::EntryObjectHash,
            flip_payload(&original, field(&original, 3)),
        ),
        (
            Discrepancy::EntryHash,
            flip_payload(&original, field(&original, 2)),
        ),
        (
            Discrepancy::Sequence,
            replace(&original, field(&original, 1), &[0x09]),
        ),
        (
            Discrepancy::GrantPlanHash,
            flip_payload(&original, field(&original, 4)),
        ),
    ];
    for (expected, bytes) in cases {
        assert_ne!(bytes, original, "witness must change real input");
        let opaque = ea_draft::PreparedFinalizationMarker::new(bytes.clone());
        assert_eq!(
            diagnose_prepared_marker(opaque.as_bytes()),
            Diagnosis::Inconsistent(expected)
        );
        assert_eq!(opaque.as_bytes(), bytes);
        // Existing Writer behavior must keep its stable aggregate code and marker.
        harness
            .repository()
            .replace_prepared_finalization_marker(Some(opaque))
            .unwrap();
        let source = harness.source();
        let error = harness
            .service(&source)
            .recover_pending()
            .expect_err("fail closed");
        assert_eq!(error.code(), "EA-WRITER-PREPARED-FINALIZATION-INCONSISTENT");
        assert_eq!(prepared_bytes(&harness), bytes);
        assert!(harness.published_entry_paths().is_empty());
        assert!(harness.published_grant_paths().is_empty());
    }
}

#[test]
fn unreadable_shapes_are_not_reported_as_later_verifier_discrepancies() {
    let mut harness = WriterHarness::with_incident();
    harness
        .finalize_with_fault(FinalizationFaultPoint::AfterAbsenceConfirmation)
        .expect("real interruption");
    let original = prepared_bytes(&harness);
    let mut trailing = original.clone();
    trailing.push(0x00);
    let mut truncated = original.clone();
    truncated.pop();
    let cases = [
        vec![],
        vec![0x86, 0x01],
        trailing,
        truncated,
        replace(&original, field(&original, 0), &[0x02]),
        replace(&original, field(&original, 2), &byte_string(&[0; 31])),
        // A malformed pair/count never constructs unequal internal vectors.
        replace(&original, field(&original, 6), &[0x81, 0x81, 0x40]),
    ];
    for bytes in cases {
        let opaque = ea_draft::PreparedFinalizationMarker::new(bytes.clone());
        assert_eq!(
            diagnose_prepared_marker(opaque.as_bytes()),
            Diagnosis::Unreadable
        );
        assert_eq!(opaque.as_bytes(), bytes);
        harness
            .repository()
            .replace_prepared_finalization_marker(Some(opaque))
            .unwrap();
        let source = harness.source();
        let error = harness
            .service(&source)
            .recover_pending()
            .expect_err("fail closed");
        assert_eq!(error.code(), "EA-WRITER-PREPARED-FINALIZATION-UNREADABLE");
        assert_eq!(prepared_bytes(&harness), bytes);
    }
}
