#[path = "../../ea-writer/tests/support/mod.rs"]
mod support;

use ea_admin::amendment::AmendmentDraftService;
use ea_crypto::SecretBytes;
use ea_operator::ReauthPurpose;
use ea_reader::{
    AuthenticatorPrfV1, ReaderEntryThread, ReaderMode, ReaderVault, ReaderVerifier, SchemaRegistry,
    SilentObserver, VaultContentsV1,
};
use ea_schema::{AmendmentChangeV1, PayloadV1};
use ea_writer::AmendmentContentV1;

#[test]
fn amendment_finalization_preserves_original_bytes_and_reader_keeps_multiple_amendments() {
    let mut harness = support::WriterHarness::with_variant(support::LineVariantV1 {
        reader_recipient_openable: true,
        ..support::LineVariantV1::default()
    });
    harness.materialize_trust_objects();
    let original = harness.finalize_once();
    let before = harness
        .published_entry(original.entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();
    // Only this independent Reader owns its KEM secret. Writer owns public
    // certificates plus its own signing and draft keys.
    let auth = || AuthenticatorPrfV1::new(vec![0x71], SecretBytes::new([0x73; 32]));
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            SecretBytes::new([0x72; 32]),
            SecretBytes::new([0x74; 32]),
            harness.anchor_bytes(),
            None,
        ),
        &[auth()],
    )
    .unwrap();
    let reader = ReaderVault::unlock(&sealed, &auth()).unwrap();
    let now = harness.observed_now();
    let open = |hash| {
        let source = harness.source();
        let classified = ReaderVerifier::new(ReaderMode::Server, now)
            .classify(&source, &reader, &mut SilentObserver)
            .unwrap();
        ea_reader::decrypt_verified(
            classified.verified_entry(hash).unwrap(),
            classified.verified_grant(hash).unwrap(),
            &reader,
            &SchemaRegistry::v1(),
            now,
            &mut SilentObserver,
        )
        .unwrap()
    };
    let thread = ReaderEntryThread::build(open(original.entry_hash), vec![]).unwrap();
    let reference = thread.correction_reference();
    drop(thread);
    let mut amendments = Vec::new();
    for sequence in 1..=2 {
        harness.select_sequence(sequence);
        let source = harness.source();
        let writer = harness.service(&source);
        let anchor = harness.anchor();
        let admin = AmendmentDraftService::new(&writer, &anchor);
        let input = || {
            admin
                .create_from_reference(
                    reference,
                    AmendmentContentV1 {
                        timezone: "Europe/Berlin".into(),
                        source: support::valid_incident().source,
                        reason: format!("Berichtigung {sequence}"),
                        changes: vec![
                            AmendmentChangeV1::new("notes", format!("Ergänzung {sequence}"))
                                .unwrap(),
                        ],
                    },
                    now,
                )
                .unwrap()
        };
        let proof = harness.proof_for(ReauthPurpose::Finalize);
        let preview = writer.preview_amendment(&proof, input(), now).unwrap();
        let outcome = writer
            .finalize_amendment(&proof, input(), &preview, now)
            .unwrap();
        assert!(harness.writer_keys_cannot_decrypt(outcome.entry_hash));
        amendments.push(outcome.entry_hash);
    }
    let source = harness.source();
    let classified = ReaderVerifier::new(ReaderMode::Server, now)
        .classify(&source, &reader, &mut SilentObserver)
        .unwrap();
    let open = |hash| {
        ea_reader::decrypt_verified(
            classified.verified_entry(hash).unwrap(),
            classified.verified_grant(hash).unwrap(),
            &reader,
            &SchemaRegistry::v1(),
            now,
            &mut SilentObserver,
        )
        .unwrap()
    };
    let thread = ReaderEntryThread::build(
        open(original.entry_hash),
        amendments.iter().map(|hash| open(*hash)).collect(),
    )
    .unwrap();
    assert_eq!(thread.amendments().len(), 2);
    assert!(thread.rejected().is_empty());
    // FR-121: jeder finalisierte Nachtrag trägt Original-ID, Original-Hash,
    // Grund und Ersteller — gelesen aus den veröffentlichten, verifizierten
    // und entschlüsselten Bytes, nicht aus der Eingabestruktur. Der
    // Original-Hash wird gegen den Abschlussbericht des Originals gemessen,
    // die Original-ID gegen den Kopf des entschlüsselten Originals, der
    // Ersteller gegen die Profilzeile der Fixture (`support`:
    // `BINDING_MARKER`, `FIXTURE_DISPLAY_NAME`, `FIXTURE_FUNCTION_LABEL`) und
    // gegen die Bindung, für die der Präsenznachweis ausgestellt wurde.
    let original_record_id = thread.original().with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            panic!("das Original ist ein Einsatz");
        };
        incident.header().record_id()
    });
    let binding = harness
        .proof_for(ReauthPurpose::Finalize)
        .binding_object_hash();
    for (index, amendment) in thread.amendments().iter().enumerate() {
        let expected_reason = format!("Berichtigung {}", index + 1);
        amendment.with_payload(|payload| {
            let PayloadV1::Amendment(stored) = payload else {
                panic!("ein beigetretener Nachtrag ist ein Nachtrag");
            };
            assert!(stored.original_record_id() == original_record_id);
            assert!(stored.original_entry_hash() == original.entry_hash);
            assert!(stored.original_sequence() == thread.original().chain_sequence());
            assert_eq!(stored.reason(), expected_reason);
            let creator = stored.header().operator();
            assert_eq!(creator.operator_subject_id().as_bytes(), &[0x22; 16]);
            assert_eq!(creator.display_name(), "Ada Lovelace");
            assert_eq!(creator.function_label(), "Einsatzleitung");
            assert!(creator.operator_binding_object_hash() == binding);
        });
    }
    assert!(thread.original().entry_hash() == original.entry_hash);
    assert_eq!(
        harness
            .published_entry(original.entry_hash)
            .exact_bytes()
            .as_bytes(),
        before
    );
}
