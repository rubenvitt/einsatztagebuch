//! Gate `manifest-signature` gegen die ZWEI erreichbaren Signaturklassen.
//!
//! KORRIGIERTER ZUSCHNITT nach Messung. Der urspruengliche Plan verlangte fuenf
//! Ein-Byte-Mutationen fuer fuenf Manifestbindungen. Ein Byte-Sweep ueber alle
//! 535 Positionen der Eintragsbytes dieser Fixture zeigt: nur zwei Bereiche
//! ueberleben Gate `format`, und beide liegen INNERHALB der COSE_Sign1-Struktur
//! — der Schluesselabdruck im geschuetzten Header und der rohe Signaturwert.
//! Alles andere faellt bereits beim Parsen, weil `ea-format` die objektinternen
//! Bindungen erzwingt: `crates/ea-format/src/eip.rs:294` prueft `cose.payload()`
//! gegen `record_digest(signed_manifest.exact_bytes())`,
//! `crates/ea-format/src/eip.rs:288` prueft `ciphertext_hash` gegen
//! `ciphertext_digest(ciphertext)`, und der `entryHash` steht gar nicht erst
//! auf dem Draht (`crates/ea-format/src/eip.rs:197-198` leitet ihn ab).
//! `support::mutate_one_byte` belegt diesen Zuschnitt ausfuehrbar: jede
//! Mutation dieser Datei MUSS parsbar bleiben, sonst traefe sie Gate 1.
//!
//! TEILDECKUNG BEIM PROTOKOLL, absichtlich. Dass das Protokoll nach
//! `manifest-signature` endet und `hpke-open` nie fuehrt, haelt
//! `tests/order.rs` gegen `run_gates` fest; die Fixture-Variante desselben
//! Contracts aktiviert Task 17. Hier wird die Aussage stattdessen
//! SACHLICH gefuehrt: ein gefallenes Gate 4 erzeugt kein `objectResults`, keine
//! `registryVersions` und keine `publicKeyThumbprints` — ueber ein Objekt, das
//! seine Signatur nicht traegt, wird nichts ausgesagt.

#[path = "support/mod.rs"]
mod support;

use ea_verify::{ManifestSignatureErrorV1, VerifyOptions, verify_archive};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1,
    MUTATED_EIP_SIGNATURE_OFFSET_V1, archive_with_one_mutated_entry, archive_with_one_signed_entry,
    writer_device_key_thumbprint,
};

fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(ea_types::UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
}

/// Jede der beiden ERREICHBAREN Bindungen faellt an ihrer eigenen
/// Ein-Byte-Mutation, und zwar an Gate `manifest-signature`, nicht frueher.
#[test]
fn each_reachable_manifest_signature_binding_fails_on_its_own_one_byte_mutation() {
    let cases = [
        (
            "gekippter Signaturwert",
            MUTATED_EIP_SIGNATURE_OFFSET_V1,
            ManifestSignatureErrorV1::SignatureInvalid,
        ),
        (
            "gekippter geschuetzter Header",
            MUTATED_EIP_KEY_THUMBPRINT_OFFSET_V1,
            ManifestSignatureErrorV1::SignerMismatch,
        ),
    ];

    for (label, offset, expected) in cases {
        let built = archive_with_one_mutated_entry(offset);
        let anchor = built.anchor();
        let report = verify_archive(&built.fixture, &anchor, options())
            .unwrap_or_else(|error| panic!("{label}: der Bestand muss berichten, nicht {error}"));

        // Die Bytes sind ein wohlgeformtes Eintragspaket: der Befund ist ein
        // Signaturbefund, kein Formbefund.
        assert_eq!(report.entry_package_count(), 1, "{label}");
        assert_eq!(report.format_errors().len(), 0, "{label}");

        // GENAU EIN Eintrag, in GENAU EINEM Array.
        let errors: Vec<_> = report.signature_errors().collect();
        assert_eq!(errors.len(), 1, "{label}: genau ein Signaturbefund");
        assert!(
            errors[0].object_hash() == built.entry_object_hash,
            "{label}: der Befund traegt den Hash der abgelegten Bytes"
        );
        assert_eq!(errors[0].code(), expected.code(), "{label}");
        assert!(
            errors[0].code().starts_with("EA-VERIFY-MANIFEST-"),
            "{label}: der Code gehoert in die Familie des Gates"
        );

        // Die uebrigen vier Arrays bleiben leer — ein Objekt erscheint NIE in
        // zweien.
        assert_eq!(report.quarantined_objects().len(), 0, "{label}");
        assert_eq!(report.evidence_errors().len(), 0, "{label}");
        assert_eq!(report.decryption_errors().len(), 0, "{label}");
        assert_eq!(report.gaps().len(), 0, "{label}");

        // Nichts hinter Gate 4 hat gearbeitet, und aus unauthentischen Bytes
        // stammt keine Sachaussage.
        assert_eq!(report.object_results().len(), 0, "{label}");
        assert_eq!(
            report.registry_versions().len(),
            0,
            "{label}: eine gefallene Signatur traegt keine Registrierungsversion bei"
        );
        assert_eq!(
            report.public_key_thumbprints().len(),
            0,
            "{label}: publicKeyThumbprints ist Nachweis des GEPRUEFTEN"
        );
        assert!(!report.is_fully_verified(), "{label}");
    }
}

/// Der unversehrte Bestand: das Gate traegt und speist beide Sachfelder.
///
/// `is_fully_verified()` bleibt hier absichtlich unassertiert — `pipeline_completed`
/// setzt erst Task 17.
#[test]
fn a_verified_manifest_signature_feeds_the_registry_version_and_the_thumbprint() {
    let built = archive_with_one_signed_entry();
    let anchor = built.anchor();
    let report =
        verify_archive(&built.fixture, &anchor, options()).expect("der Bestand muss berichten");

    assert_eq!(report.entry_package_count(), 1);
    assert_eq!(report.format_errors().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);

    // `registryVersions` stammt aus dem GEPRUEFTEN Manifest.
    let versions: Vec<_> = report.registry_versions().collect();
    assert_eq!(versions.len(), 1);
    assert!(versions[0] == built.registry_version);

    // `publicKeyThumbprints` traegt den Abdruck, der die Pruefung getragen hat.
    let thumbprints: Vec<_> = report.public_key_thumbprints().collect();
    assert_eq!(thumbprints.len(), 1);
    assert!(thumbprints[0] == writer_device_key_thumbprint());
}
