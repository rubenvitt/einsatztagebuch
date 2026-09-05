//! Stufe-4-Systemzeuge: EIN Chiffrat, ZWEI Reader, zwei getrennte Grants.
//!
//! Der Plansatz (Task 14, Schritt 1): „Ein Writer-Chiffrat mit Grants fuer
//! zwei verschiedene Reader-Zertifikate und -KEM-Schluessel wird repliziert
//! und von beiden unabhaengig verifiziert und entschluesselt; wird einem der
//! beiden sein Grant genommen, sieht NUR dieser `fehlender Grant`, und der
//! Befund ist nie eine `Lücke`."
//!
//! Warum der Bestand nicht vom Writer stammt und warum „sein Grant genommen"
//! ein zweiter Bau und kein Loeschen ist, steht im Modulkommentar von
//! `two_reader_support`. Der Klartext verlaesst `with_plaintext` nur HIER, im
//! Test, und nur fuer den Gleichheitsvergleich — der ueber `assert!` laeuft,
//! damit ein Fehlschlag keine Klartextbytes in das Testprotokoll druckt.

mod two_reader_support;

use ea_reader::{
    DECAPSULATION_EVENT_V1, GATE_ORDER_V1, ReaderMode, ReaderVerifier, RecordingObserver,
    SchemaRegistry, SilentObserver, VerificationStatus, decrypt_verified,
};
use ea_verify::{GRANT_PLAN_MISMATCH_CODE_V1, VerifyOptions, verify_archive_observed};

use two_reader_support as fixtures;
use two_reader_support::Reader;

/// Wie viele Grants [`fixtures::archive_with_grants_for_both_readers`] auf
/// seinen einen Eintrag legt: Recovery an einen Dritten, je einer an A und B.
///
/// Die Zahl steht hier, weil sie eine Tatsache UEBER DIE KULISSE ist: ein
/// Zeuge, der nur „mindestens zwei" verlangte, hielte auch ueber einem Bestand,
/// in dem A und B denselben Grant teilen.
const GRANTS_ON_THE_SHARED_CIPHERTEXT: usize = 3;

#[test]
fn one_ciphertext_opens_under_two_distinct_reader_kem_keys_through_separate_grants() {
    let archive = fixtures::archive_with_grants_for_both_readers();
    let entry_hash = archive.entry_hash();
    let reader_a = fixtures::reader_a();
    let reader_b = fixtures::reader_b();

    // ZWEI VERSCHIEDENE KEM-Schluessel, und je ein EIGENER Grant darauf.
    // `assert!` statt `assert_ne!`: `hash_newtype!` leitet kein `Debug` ab.
    assert!(reader_a.key_thumbprint() != reader_b.key_thumbprint());
    assert!(
        archive.grant_object_hash_for(&reader_a) != archive.grant_object_hash_for(&reader_b),
        "A und B oeffnen ueber zwei verschiedene Grantobjekte"
    );
    assert_eq!(
        ea_archive::ArchiveInventory::build(archive.source())
            .expect("der Bestand ist inventarisierbar")
            .grants()
            .len(),
        GRANTS_ON_THE_SHARED_CIPHERTEXT
    );

    let mut opened = Vec::new();
    for reader in [&reader_a, &reader_b] {
        // Verifikation VOR HPKE: die neun Gates in ihrer Reihenfolge, danach
        // GENAU EIN `hpke-open` — der Schritt der Pipeline, nicht die Zahl der
        // geoeffneten Objekte.
        let mut observer = RecordingObserver::new();
        let report = verify_archive_observed(
            archive.source(),
            &archive.anchor(),
            VerifyOptions::new(fixtures::OS_WALL_CLOCK)
                .with_recipient(reader.key_thumbprint(), reader.private_key()),
            &mut observer,
        )
        .unwrap_or_else(|error| panic!("{}: {error:?}", reader.label()));
        assert!(report.is_fully_verified(), "{}", reader.label());
        assert_eq!(report.decryption_errors().len(), 0, "{}", reader.label());
        assert_eq!(report.gaps().len(), 0, "{}", reader.label());
        assert_eq!(
            &observer.events()[..GATE_ORDER_V1.len()],
            &GATE_ORDER_V1[..],
            "{}",
            reader.label()
        );
        assert_eq!(
            observer.events().len(),
            GATE_ORDER_V1.len() + 1,
            "{}: genau ein Ereignis hinter den neun Gates",
            reader.label()
        );
        assert_eq!(
            observer.events().last(),
            Some(&DECAPSULATION_EVENT_V1),
            "{}",
            reader.label()
        );

        opened.push(open_with(&archive, reader));
    }

    // `assert!` statt `assert_eq!`: ein fehlgeschlagener Vergleich druckte den
    // Klartext sonst als `Debug`-Ausgabe in das Testprotokoll.
    assert!(
        opened[0] == opened[1],
        "derselbe Klartext aus zwei verschiedenen Grants"
    );
    assert!(
        opened[0] == fixtures::genesis_plaintext(),
        "und es ist der Klartext, der hineingelegt wurde"
    );

    // Wird EINEM der beiden sein Grant genommen, sieht NUR dieser
    // `fehlender Grant`. Der Plan dieses Bestands hat B nie genannt.
    let without_b = fixtures::archive_with_a_grant_for_reader_a_only();
    let entry_without_b = without_b.entry_hash();
    let verifier = ReaderVerifier::new(ReaderMode::Server, fixtures::OS_WALL_CLOCK);
    let for_b = verifier
        .classify(
            without_b.source(),
            &reader_b.vault_pinning(without_b.anchor_bytes()),
            &mut SilentObserver,
        )
        .expect("ein Fixture-Bestand laesst sich klassifizieren");
    let for_a = verifier
        .classify(
            without_b.source(),
            &reader_a.vault_pinning(without_b.anchor_bytes()),
            &mut SilentObserver,
        )
        .expect("ein Fixture-Bestand laesst sich klassifizieren");
    assert_eq!(
        for_b
            .state_of(entry_without_b)
            .expect("der Eintrag bleibt fuer B sichtbar")
            .verification(),
        VerificationStatus::MissingGrant
    );
    assert_eq!(
        for_a
            .state_of(entry_without_b)
            .expect("der Eintrag bleibt fuer A sichtbar")
            .verification(),
        VerificationStatus::Verified
    );
    // Und ein fehlender Grant ist NIE eine Luecke und nie ein Mangel: kein
    // Zeugenpaar fuer B, kein Befund, `is_fully_verified()` bleibt stehen.
    assert!(for_b.verified_grant(entry_without_b).is_none());
    assert!(for_b.verified_entry(entry_without_b).is_none());
    assert_eq!(for_b.report().gaps().len(), 0);
    assert_eq!(for_b.report().decryption_errors().len(), 0);
    assert!(for_b.report().is_fully_verified());
    // A oeffnet diesen Bestand weiterhin — derselbe Klartext, und wieder ohne
    // Bytes in der Meldung.
    assert!(
        open_with(&without_b, &reader_a) == fixtures::genesis_plaintext(),
        "A oeffnet den Ein-Reader-Bestand auf den Genesis-Vektor"
    );
    // Der Eintrag des Zwei-Reader-Bestands und der des Ein-Reader-Bestands
    // sind VERSCHIEDENE Eintraege: der Planhash steht im signierten Manifest.
    assert!(
        entry_hash != entry_without_b,
        "der initiale Grantplan ist Teil der Eintragsidentitaet"
    );
}

// Die Gegenprobe, ohne die der Zeuge oben missverstaendlich bliebe: das
// PHYSISCHE Entfernen von Bs Grantobjekt aus dem Drei-Grant-Bestand ist KEIN
// `fehlender Grant`. Gate `grant-plan` rekonstruiert den Plan aus den
// vorhandenen `.eag` und haelt ihn gegen das signierte Manifest — der Eintrag
// wird fuer BEIDE Reader `ungueltig`, auch fuer A, dessen Grant noch da ist.
// Ein Replikat, dem ein Grant fehlt, ist ein beschaedigtes Replikat.
#[test]
fn removing_one_grant_object_is_a_plan_mismatch_for_both_readers_and_never_a_missing_grant() {
    let archive = fixtures::archive_with_grants_for_both_readers();
    let reader_a = fixtures::reader_a();
    let reader_b = fixtures::reader_b();
    let damaged = archive.without_the_grant_object_of(&reader_b);
    let entry_hash = fixtures::entry_hash_of(&damaged);
    assert!(
        entry_hash == archive.entry_hash(),
        "das Loeschen eines Grants aendert den Eintrag nicht"
    );

    let verifier = ReaderVerifier::new(ReaderMode::Server, fixtures::OS_WALL_CLOCK);
    for reader in [&reader_a, &reader_b] {
        let classification = verifier
            .classify(
                &damaged,
                &reader.vault_pinning(archive.anchor_bytes()),
                &mut SilentObserver,
            )
            .expect("ein beschaedigter Bestand laesst sich klassifizieren");
        let state = classification
            .state_of(entry_hash)
            .expect("der Eintrag bleibt sichtbar");
        assert_eq!(
            state.verification(),
            VerificationStatus::Invalid,
            "{}",
            reader.label()
        );
        assert_eq!(
            state.detail_code(),
            Some(GRANT_PLAN_MISMATCH_CODE_V1),
            "{}",
            reader.label()
        );
        assert!(
            classification.verified_grant(entry_hash).is_none(),
            "{}: kein Zeuge ueber einem ungueltigen Eintrag",
            reader.label()
        );
        assert!(!classification.report().is_fully_verified());
        assert_eq!(classification.report().gaps().len(), 0);
    }
}

/// Klassifiziert `archive` mit der Sitzung von `reader`, oeffnet den einen
/// Eintrag ueber `decrypt_verified` und kopiert den Klartext HIER heraus.
///
/// Das ist die einzige Stelle, an der Klartextbytes `with_plaintext`
/// verlassen — und sie liegt im Test.
fn open_with(archive: &fixtures::TwoReaderArchive, reader: &Reader) -> Vec<u8> {
    let entry_hash = archive.entry_hash();
    let vault = reader.vault_pinning(archive.anchor_bytes());
    // Die Sitzung, mit der klassifiziert UND entschluesselt wird, traegt den
    // KEM-Schluessel DIESES Readers. Ohne die Zusicherung oeffnete ein B, dem
    // die Kulisse As Seed unterschiebt, still ueber As Grant — und „zwei
    // Reader" waere ein Reader mit zwei Namen.
    assert!(
        vault.kem_key_thumbprint() == reader.key_thumbprint(),
        "{}: die Sitzung traegt den eigenen KEM-Schluessel",
        reader.label()
    );
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::OS_WALL_CLOCK)
        .classify(archive.source(), &vault, &mut SilentObserver)
        .expect("ein Fixture-Bestand laesst sich klassifizieren");
    assert_eq!(
        classification
            .state_of(entry_hash)
            .expect("der Eintrag ist sichtbar")
            .verification(),
        VerificationStatus::Verified,
        "{}",
        reader.label()
    );
    let entry = classification
        .verified_entry(entry_hash)
        .unwrap_or_else(|| panic!("{}: der Eintrag traegt einen Zeugen", reader.label()));
    let grant = classification
        .verified_grant(entry_hash)
        .unwrap_or_else(|| panic!("{}: und einen eigenen Grant", reader.label()));
    assert!(
        grant.recipient_key_thumbprint() == reader.key_thumbprint(),
        "{}: der Zeuge ist der EIGENE Grant",
        reader.label()
    );
    let mut observer = RecordingObserver::new();
    let record = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::OS_WALL_CLOCK,
        &mut observer,
    )
    .unwrap_or_else(|error| panic!("{}: {}", reader.label(), error.code()));
    // Die Entschluesselung des Readers ist kein zehntes Gate: ein frischer
    // Beobachter sieht genau das eine Ereignis.
    assert_eq!(observer.events(), [DECAPSULATION_EVENT_V1]);
    assert!(record.entry_hash() == entry_hash);
    record.with_plaintext(<[u8]>::to_vec)
}
