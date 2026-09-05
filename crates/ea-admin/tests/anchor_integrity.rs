//! Die tragende Invariante des vierten Einrichtungsschrittes.
//!
//! Die Zusage lautet: jede Aenderung an einem Feld, das die Vorstufe bereits
//! auf den schreibgeschuetzten Medien festgeschrieben hat, erzwingt neue
//! Organisations- und Ketten-IDs — der Uebergang scheitert mit
//! `EA-ANCHOR-PRE-FIELD-CHANGED`
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1349`).
//!
//! Der wichtigste Zeuge dieser Datei ist der dritte: ein finaler Anker, dessen
//! Felder DURCHGAENGIG mitgeaendert wurden, ist in sich vollkommen stimmig.
//! [`ea_trust::decode_trust_anchor`] nimmt ihn an — es rechnet die Vorstufe aus
//! den EIGENEN Feldern des finalen Ankers nach
//! (`crates/ea-trust/src/anchor.rs:665-676`) und kann eine nachtraeglich
//! korrigierte Zeremonie strukturell nicht sehen. Nur der Vergleich gegen die
//! unabhaengig bestaetigte Vorstufe faengt sie. Genau dafuer gibt es
//! [`ea_admin::verify_anchor_transition`].
//!
//! Zwei weitere Flaechen haengen an derselben Invariante und stehen deshalb
//! hier: die ABWEHRSCHICHTEN von [`ea_trust::decode_pre_anchor`] — was von den
//! Medien zurueckgelesen wird, ist unvertraute Drahtform und muss Lage fuer
//! Lage scheitern koennen — und die Genesisbindung
//! [`ea_admin::bind_genesis`], die Schritt 11 an die Kennungen und den
//! Registrierungskopf DIESER Zeremonie haengt.
//!
//! Alles hier ist `#[test]` und synchron; diese Crate kennt kein Tokio.

mod support;

use std::collections::BTreeMap;

use ea_admin::{
    AdminError, AnchorMedia, AnchorMediumId, GenesisEnvelopeV1, MediaConfirmation,
    SecondChannelConfirmation, bind_genesis, confirm_on_media, confirm_pre_anchor_fingerprint,
    verify_anchor_transition,
};
use ea_crypto::CanonicalPublicCoseKey;
use ea_schema::{CommonHeaderV1, GenesisV1, NativeSourceV1, OperatorSnapshotV1};
use ea_trust::{
    PreAnchorV1, TrustAnchorV1, TrustError, decode_pre_anchor, decode_trust_anchor,
    encode_pre_anchor_v1,
};
use ea_types::{
    ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, OperatorSubjectId, OrganizationId,
    RecordId, RegistryVersion, UnixMillis,
};
use minicbor::Encoder;

use support::trust_support;
use trust_support::RegistryLineBuilder;

const FINAL_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-v1";
const PRE_ANCHOR_DOMAIN: &str = "EINSATZARCHIV-TRUST-ANCHOR-PRE-v1";

/// Der Genesis-Eintragshash, den die Zeugen an ihre finalen Anker haengen. Er
/// steht ausdruecklich NICHT in der Vorstufe (Spezifikation `:1737-1748`) und
/// darf den Uebergang deshalb nie beeinflussen.
const GENESIS: [u8; 32] = [0x44; 32];

fn expect_admin_code(error: AdminError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

/// `ea-types` gibt seinen Kennungen bewusst KEIN `Debug`; Zeugen vergleichen
/// deshalb ueber die Bytes.
fn hash_bytes(hashes: &[ObjectHash]) -> Vec<[u8; 32]> {
    hashes.iter().map(|hash| *hash.as_bytes()).collect()
}

fn expect_trust_code(error: TrustError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

/// Der finale Anker der Fixture — eine ECHTE Registrierungslinie, kein von
/// Hand gestreuter Bytehaufen.
fn fixture_final_anchor() -> TrustAnchorV1 {
    let line = RegistryLineBuilder::new();
    decode_trust_anchor(line.exact_anchor_bytes())
        .expect("die Fixture traegt einen gueltigen Anker")
}

/// Baut die finalen Ankerbytes AUS einer Vorstufe.
///
/// Das ist die Bewegung des elften Schrittes (`:1346`): finale Domain,
/// `bootstrap-anchor-hash` und `genesis-entry-hash` kommen hinzu, alles andere
/// wird bytegleich uebernommen (`:1780`). Ein so gebauter Anker ist per
/// Konstruktion selbstkonsistent — das ist der Punkt des dritten Zeugen.
fn final_anchor_bytes(pre: &PreAnchorV1, genesis_entry_hash: &[u8; 32]) -> Vec<u8> {
    let certificates = pre.initial_admin_certificate_object_hashes();
    let bindings = pre.initial_admin_operator_binding_object_hashes();
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(12)
        .and_then(|encoder| encoder.str(FINAL_ANCHOR_DOMAIN))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(pre.bootstrap_anchor_hash().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.organization_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.chain_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_public_cose_key_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_key_thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_certificate_object_hash().as_bytes()))
        .and_then(|encoder| encoder.array(u64::try_from(certificates.len()).unwrap()))
        .expect("der Zeuge kodiert in einen Vec");
    for hash in certificates {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(u64::try_from(bindings.len()).unwrap())
        .expect("Bindungsliste kodiert");
    for hash in bindings {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .bytes(genesis_entry_hash)
        .and_then(|encoder| encoder.array(0))
        .expect("Genesis und leere kritische Erweiterungen kodieren");
    bytes
}

/// Die Vorstufe der Fixture, wie sie auf den Medien steht.
fn fixture_pre_anchor() -> PreAnchorV1 {
    let anchor = fixture_final_anchor();
    decode_pre_anchor(anchor.exact_pre_anchor_bytes())
        .expect("die Vorstufe eines gueltigen finalen Ankers ist selbst gueltig")
}

/// Eine Vorstufe mit genau EINEM veraenderten Feld, sonst identisch.
enum Changed {
    Organization,
    Chain,
    RootCertificateObjectHash,
    AdminBindingHash,
}

fn pre_anchor_with(change: &Changed) -> PreAnchorV1 {
    let source = fixture_pre_anchor();
    let mut organization = source.organization_id();
    let mut chain = source.chain_id();
    let mut root_certificate = source.root_certificate_object_hash();
    let mut bindings = source
        .initial_admin_operator_binding_object_hashes()
        .to_vec();
    match change {
        Changed::Organization => {
            organization = OrganizationId::try_from(&[0x5a_u8; 16][..]).unwrap();
        }
        Changed::Chain => chain = ChainId::try_from(&[0x6b_u8; 16][..]).unwrap(),
        Changed::RootCertificateObjectHash => {
            root_certificate = ObjectHash::try_from(&[0x7c_u8; 32][..]).unwrap();
        }
        Changed::AdminBindingHash => {
            // Der GROESSTE Wert, damit die Liste sortiert bleibt: die Aenderung
            // soll am Uebergang scheitern und nicht schon an der Form.
            let last = bindings.len() - 1;
            bindings[last] = ObjectHash::try_from(&[0xfe_u8; 32][..]).unwrap();
        }
    }
    encode_pre_anchor_v1(
        organization,
        chain,
        source.root_public_cose_key_bytes(),
        source.root_key_thumbprint(),
        root_certificate,
        source.initial_admin_certificate_object_hashes(),
        &bindings,
    )
    .expect("die geaenderte Vorstufe ist formal gueltig")
}

/// Ein Stapel benannter Medien im Speicher.
///
/// Die Attrappe liest zurueck, was sie geschrieben hat — ausser fuer die
/// Kennungen in `corrupting`, die beim Lesen andere Bytes liefern, und die in
/// `failing`, die gar nicht antworten.
#[derive(Default)]
struct MediaStack {
    written: BTreeMap<AnchorMediumId, Vec<u8>>,
    corrupting: Vec<AnchorMediumId>,
    failing: Vec<AnchorMediumId>,
}

impl AnchorMedia for MediaStack {
    fn write_exact_bytes(
        &mut self,
        medium: AnchorMediumId,
        exact_bytes: &[u8],
    ) -> Result<(), AdminError> {
        if self.failing.contains(&medium) {
            return Err(AdminError::MediaUnavailable);
        }
        self.written.insert(medium, exact_bytes.to_vec());
        Ok(())
    }

    fn read_exact_bytes(&self, medium: AnchorMediumId) -> Result<Vec<u8>, AdminError> {
        if self.failing.contains(&medium) {
            return Err(AdminError::MediaUnavailable);
        }
        let stored = self
            .written
            .get(&medium)
            .cloned()
            .ok_or(AdminError::MediaUnavailable)?;
        if self.corrupting.contains(&medium) {
            let mut corrupted = stored;
            corrupted[0] ^= 0xff;
            return Ok(corrupted);
        }
        Ok(stored)
    }
}

const FIRST: AnchorMediumId = AnchorMediumId::new([0x01; 16]);
const SECOND: AnchorMediumId = AnchorMediumId::new([0x02; 16]);
const THIRD: AnchorMediumId = AnchorMediumId::new([0x03; 16]);

fn confirmed(pre: &PreAnchorV1) -> SecondChannelConfirmation {
    confirm_pre_anchor_fingerprint(pre, pre.bootstrap_anchor_hash())
        .expect("der zurueckgemeldete Fingerprint ist der gerechnete")
}

// ---------------------------------------------------------------------------
// Der Uebergang
// ---------------------------------------------------------------------------

#[test]
fn a_final_anchor_built_on_the_confirmed_pre_anchor_passes_the_transition() {
    let pre = fixture_pre_anchor();
    let final_anchor = decode_trust_anchor(&final_anchor_bytes(&pre, &GENESIS))
        .expect("ein aus der Vorstufe gebauter finaler Anker dekodiert");

    verify_anchor_transition(&pre, &final_anchor)
        .expect("die bestaetigte Vorstufe traegt genau diesen finalen Anker");
}

#[test]
fn the_shipped_fixture_anchor_continues_its_own_confirmed_pre_anchor() {
    let final_anchor = fixture_final_anchor();
    let pre = decode_pre_anchor(final_anchor.exact_pre_anchor_bytes()).expect("Vorstufe dekodiert");

    assert_eq!(
        pre.bootstrap_anchor_hash().as_bytes(),
        final_anchor.bootstrap_anchor_hash().as_bytes()
    );
    verify_anchor_transition(&pre, &final_anchor).expect("der Uebergang der Fixture haelt");
}

#[test]
fn changing_any_pre_anchor_field_requires_new_org_and_chain_ids() {
    let confirmed_pre = fixture_pre_anchor();
    for change in [
        Changed::Organization,
        Changed::Chain,
        Changed::RootCertificateObjectHash,
        Changed::AdminBindingHash,
    ] {
        let corrected = pre_anchor_with(&change);
        let final_anchor = decode_trust_anchor(&final_anchor_bytes(&corrected, &GENESIS))
            .expect("auch der korrigierte Anker ist in sich stimmig");

        let Err(error) = verify_anchor_transition(&confirmed_pre, &final_anchor) else {
            panic!("ein geaendertes Vorstufenfeld bricht das Setup ab");
        };
        expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");
    }
}

#[test]
fn a_consistently_rewritten_final_anchor_decodes_but_still_fails_the_transition() {
    let confirmed_pre = fixture_pre_anchor();
    let source = fixture_pre_anchor();
    // ALLE beweglichen Felder auf einmal, durchgaengig mitgezogen: neue
    // Organisation, neue Kette, neue Wurzelurkunde, neue Bindungsliste.
    let mut bindings = source
        .initial_admin_operator_binding_object_hashes()
        .to_vec();
    let last = bindings.len() - 1;
    bindings[last] = ObjectHash::try_from(&[0xfd_u8; 32][..]).unwrap();
    let corrected = encode_pre_anchor_v1(
        OrganizationId::try_from(&[0x11_u8; 16][..]).unwrap(),
        ChainId::try_from(&[0x22_u8; 16][..]).unwrap(),
        source.root_public_cose_key_bytes(),
        source.root_key_thumbprint(),
        ObjectHash::try_from(&[0x33_u8; 32][..]).unwrap(),
        source.initial_admin_certificate_object_hashes(),
        &bindings,
    )
    .expect("die durchgaengig korrigierte Vorstufe ist formal gueltig");

    let exact_final = final_anchor_bytes(&corrected, &GENESIS);
    // Der Kern des Zeugen: die Vertrauensschicht nimmt diese Bytes AN. Sie
    // rechnet die Vorstufe aus den eigenen Feldern des finalen Ankers nach
    // (`crates/ea-trust/src/anchor.rs:665-676`) und findet nichts.
    let final_anchor =
        decode_trust_anchor(&exact_final).expect("die selbstkonsistente Faelschung dekodiert");
    assert_eq!(
        final_anchor.bootstrap_anchor_hash().as_bytes(),
        corrected.bootstrap_anchor_hash().as_bytes()
    );

    let Err(error) = verify_anchor_transition(&confirmed_pre, &final_anchor) else {
        panic!("nur der Vergleich gegen die bestaetigte Vorstufe sieht das");
    };
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");
}

#[test]
fn the_transition_compares_the_pre_anchor_image_byte_for_byte() {
    let confirmed_pre = fixture_pre_anchor();

    // Der annehmende Fall haelt genau eine Zusage: die beiden Vorstufenbilder
    // sind BYTEGLEICH und nicht bloss gleichwertig (`:1780`).
    let matching = decode_trust_anchor(&final_anchor_bytes(&confirmed_pre, &GENESIS))
        .expect("ein aus der Vorstufe gebauter finaler Anker dekodiert");
    assert_eq!(
        confirmed_pre.exact_bytes(),
        matching.exact_pre_anchor_bytes()
    );
    verify_anchor_transition(&confirmed_pre, &matching).expect("bytegleich traegt den Uebergang");

    // Und ein EINZIGES abweichendes Byte reicht zum Abbruch. Das ist der
    // Unterschied, den ein feldweiser Vergleich nicht schaerfer machen
    // koennte: kleiner als ein Byte wird eine Abweichung nicht.
    let mut bindings = confirmed_pre
        .initial_admin_operator_binding_object_hashes()
        .to_vec();
    let last = bindings.len() - 1;
    let mut flipped = *bindings[last].as_bytes();
    flipped[31] ^= 0x01;
    bindings[last] = ObjectHash::try_from(&flipped[..]).unwrap();
    let changed_pre = encode_pre_anchor_v1(
        confirmed_pre.organization_id(),
        confirmed_pre.chain_id(),
        confirmed_pre.root_public_cose_key_bytes(),
        confirmed_pre.root_key_thumbprint(),
        confirmed_pre.root_certificate_object_hash(),
        confirmed_pre.initial_admin_certificate_object_hashes(),
        &bindings,
    )
    .expect("die Liste bleibt sortiert und die Vorstufe formal gueltig");
    let differing = decode_trust_anchor(&final_anchor_bytes(&changed_pre, &GENESIS))
        .expect("auch dieser Anker ist in sich stimmig");

    assert_eq!(
        confirmed_pre.exact_bytes().len(),
        differing.exact_pre_anchor_bytes().len()
    );
    let differing_positions = confirmed_pre
        .exact_bytes()
        .iter()
        .zip(differing.exact_pre_anchor_bytes())
        .filter(|(confirmed, offered)| confirmed != offered)
        .count();
    assert_eq!(
        differing_positions, 1,
        "die beiden Bilder unterscheiden sich in genau einem Byte"
    );

    let Err(error) = verify_anchor_transition(&confirmed_pre, &differing) else {
        panic!("`:1780` sagt bytegleich und nicht gleichwertig");
    };
    expect_admin_code(error, "EA-ANCHOR-PRE-FIELD-CHANGED");
}

#[test]
fn the_genesis_entry_hash_is_not_a_pre_anchor_field_and_does_not_break_the_transition() {
    let pre = fixture_pre_anchor();
    let other_genesis = [0x99_u8; 32];
    let final_anchor = decode_trust_anchor(&final_anchor_bytes(&pre, &other_genesis))
        .expect("ein anderer Genesis-Hash bleibt ein gueltiger Anker");

    verify_anchor_transition(&pre, &final_anchor)
        .expect("Genesis steht erst in Schritt 11 fest und gehoert nicht zur Vorstufe");
}

// ---------------------------------------------------------------------------
// Medien und zweiter Kanal
// ---------------------------------------------------------------------------

#[test]
fn a_single_medium_cannot_carry_the_pre_anchor() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack::default();

    let Err(error) = confirm_on_media(&mut media, &[FIRST], pre.exact_bytes(), confirmed(&pre))
    else {
        panic!("ein Medium ist kein Recovery-Bestand");
    };
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
}

#[test]
fn two_names_for_one_medium_do_not_make_a_second_medium() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack::default();

    let Err(error) = confirm_on_media(
        &mut media,
        &[FIRST, FIRST],
        pre.exact_bytes(),
        confirmed(&pre),
    ) else {
        panic!("dieselbe Kennung zweimal ist ein Medium und nicht zwei");
    };
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
}

#[test]
fn a_repeated_name_among_three_media_is_still_not_a_quorum() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack::default();

    // ZWEI unterscheidbare Kennungen unter DREI Namen: das Quorum aus `:1339`
    // ist erreicht, und trotzdem ist der Bestand nicht der, den der Aufrufer
    // benannt hat. Genau diese Luecke schliesst der Vergleich der Anzahlen —
    // die Untergrenze allein sieht sie nicht.
    let Err(error) = confirm_on_media(
        &mut media,
        &[FIRST, SECOND, FIRST],
        pre.exact_bytes(),
        confirmed(&pre),
    ) else {
        panic!("ein doppelt genannter Datentraeger ist kein dritter");
    };
    expect_admin_code(error, "EA-CEREMONY-MEDIA-QUORUM-MISSING");
    assert!(
        media.written.is_empty(),
        "fail-closed: vor dem Quorum wird nichts geschrieben"
    );
}

#[test]
fn a_medium_that_reads_back_other_bytes_fails_the_confirmation() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack {
        corrupting: vec![SECOND],
        ..MediaStack::default()
    };

    let Err(error) = confirm_on_media(
        &mut media,
        &[FIRST, SECOND],
        pre.exact_bytes(),
        confirmed(&pre),
    ) else {
        panic!("nur was zurueckgelesen bytegleich ist, ist festgeschrieben");
    };
    expect_admin_code(error, "EA-CEREMONY-MEDIA-READBACK-MISMATCH");
}

#[test]
fn a_medium_that_does_not_answer_fails_the_confirmation() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack {
        failing: vec![SECOND],
        ..MediaStack::default()
    };

    let Err(error) = confirm_on_media(
        &mut media,
        &[FIRST, SECOND],
        pre.exact_bytes(),
        confirmed(&pre),
    ) else {
        panic!("ein stummes Medium ist kein bestaetigtes Medium");
    };
    expect_admin_code(error, "EA-CEREMONY-MEDIA-UNAVAILABLE");
}

#[test]
fn the_written_media_yield_a_confirmation_over_exactly_those_bytes() {
    let pre = fixture_pre_anchor();
    let mut media = MediaStack::default();

    let confirmation: MediaConfirmation = confirm_on_media(
        &mut media,
        &[FIRST, SECOND, THIRD],
        pre.exact_bytes(),
        confirmed(&pre),
    )
    .expect("drei gelesene Medien tragen die Vorstufe");

    assert_eq!(confirmation.medium_count(), 3);
    assert_eq!(
        confirmation.fingerprint().as_bytes(),
        pre.bootstrap_anchor_hash().as_bytes()
    );
    for medium in [FIRST, SECOND, THIRD] {
        assert_eq!(
            media
                .read_exact_bytes(medium)
                .expect("das Medium antwortet"),
            pre.exact_bytes()
        );
    }
}

#[test]
fn a_second_channel_fingerprint_that_differs_is_not_a_confirmation() {
    let pre = fixture_pre_anchor();

    let Err(error) =
        confirm_pre_anchor_fingerprint(&pre, Hash32::try_from(&[0x00_u8; 32][..]).unwrap())
    else {
        panic!("der zweite Kanal meldete einen anderen Wert zurueck");
    };
    expect_admin_code(error, "EA-CEREMONY-SECOND-CHANNEL-MISMATCH");
}

#[test]
fn a_confirmation_for_another_pre_anchor_does_not_cover_these_bytes() {
    let pre = fixture_pre_anchor();
    let other = pre_anchor_with(&Changed::Organization);
    let mut media = MediaStack::default();

    let Err(error) = confirm_on_media(
        &mut media,
        &[FIRST, SECOND],
        pre.exact_bytes(),
        confirmed(&other),
    ) else {
        panic!("bestaetigt wurde eine ANDERE Vorstufe");
    };
    expect_admin_code(error, "EA-CEREMONY-SECOND-CHANNEL-MISMATCH");
}

// ---------------------------------------------------------------------------
// Die Form der Vorstufe
// ---------------------------------------------------------------------------

#[test]
fn the_pre_anchor_round_trips_byte_identically() {
    let source = fixture_pre_anchor();
    let encoded = encode_pre_anchor_v1(
        source.organization_id(),
        source.chain_id(),
        source.root_public_cose_key_bytes(),
        source.root_key_thumbprint(),
        source.root_certificate_object_hash(),
        source.initial_admin_certificate_object_hashes(),
        source.initial_admin_operator_binding_object_hashes(),
    )
    .expect("die Felder der Fixture kodieren");

    assert_eq!(encoded.exact_bytes(), source.exact_bytes());
    let decoded = decode_pre_anchor(encoded.exact_bytes()).expect("die eigene Kodierung dekodiert");
    assert_eq!(decoded.exact_bytes(), encoded.exact_bytes());
    assert_eq!(
        decoded.bootstrap_anchor_hash().as_bytes(),
        encoded.bootstrap_anchor_hash().as_bytes()
    );
    assert_eq!(
        decoded.organization_id().as_bytes(),
        source.organization_id().as_bytes()
    );
    assert_eq!(decoded.chain_id().as_bytes(), source.chain_id().as_bytes());
    assert_eq!(
        decoded.root_public_cose_key_bytes(),
        source.root_public_cose_key_bytes()
    );
    assert_eq!(
        decoded.root_key_thumbprint().as_bytes(),
        source.root_key_thumbprint().as_bytes()
    );
    assert_eq!(
        decoded.root_certificate_object_hash().as_bytes(),
        source.root_certificate_object_hash().as_bytes()
    );
    assert_eq!(
        hash_bytes(decoded.initial_admin_certificate_object_hashes()),
        hash_bytes(source.initial_admin_certificate_object_hashes())
    );
    assert_eq!(
        hash_bytes(decoded.initial_admin_operator_binding_object_hashes()),
        hash_bytes(source.initial_admin_operator_binding_object_hashes())
    );
    assert!(matches!(
        decoded.root_public_cose_key(),
        ea_crypto::CanonicalPublicCoseKey::Ed25519(_)
    ));
}

#[test]
fn trailing_bytes_behind_the_pre_anchor_are_rejected() {
    let pre = fixture_pre_anchor();
    let mut bytes = pre.exact_bytes().to_vec();
    bytes.push(0x00);

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("ein Anhaengsel ist keine Vorstufe");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn the_final_anchor_bytes_are_not_a_pre_anchor() {
    let final_anchor = fixture_final_anchor();

    let Err(error) = decode_pre_anchor(final_anchor.exact_bytes()) else {
        panic!("zwoelf Elemente sind keine Vorstufe");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_pre_anchor_carrying_the_final_domain_is_rejected() {
    let pre = fixture_pre_anchor();
    let bytes = hand_rolled_pre_anchor(
        &pre,
        FINAL_ANCHOR_DOMAIN,
        pre.initial_admin_certificate_object_hashes(),
        pre.initial_admin_operator_binding_object_hashes(),
    );

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("die Domain traegt die Bedeutung");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn unequal_admin_hash_lists_are_rejected_by_the_decoder() {
    let pre = fixture_pre_anchor();
    let mut bindings = pre.initial_admin_operator_binding_object_hashes().to_vec();
    bindings.push(ObjectHash::try_from(&[0xff_u8; 32][..]).unwrap());
    let bytes = hand_rolled_pre_anchor(
        &pre,
        PRE_ANCHOR_DOMAIN,
        pre.initial_admin_certificate_object_hashes(),
        &bindings,
    );

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("Zertifikate und Bindungen paaren eins zu eins");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_single_admin_pair_is_not_enough_to_encode_a_pre_anchor() {
    let source = fixture_pre_anchor();

    let Err(error) = encode_pre_anchor_v1(
        source.organization_id(),
        source.chain_id(),
        source.root_public_cose_key_bytes(),
        source.root_key_thumbprint(),
        source.root_certificate_object_hash(),
        &source.initial_admin_certificate_object_hashes()[..1],
        &source.initial_admin_operator_binding_object_hashes()[..1],
    ) else {
        panic!("mindestens zwei Administratoren, sonst keine Vorstufe");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn unsorted_admin_hash_lists_are_rejected_by_the_encoder() {
    let source = fixture_pre_anchor();
    let mut certificates = source.initial_admin_certificate_object_hashes().to_vec();
    certificates.reverse();

    let Err(error) = encode_pre_anchor_v1(
        source.organization_id(),
        source.chain_id(),
        source.root_public_cose_key_bytes(),
        source.root_key_thumbprint(),
        source.root_certificate_object_hash(),
        &certificates,
        source.initial_admin_operator_binding_object_hashes(),
    ) else {
        panic!("die Listen sind byteweise sortiert und duplikatfrei");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_root_key_whose_thumbprint_does_not_match_is_rejected_by_the_encoder() {
    let source = fixture_pre_anchor();

    let Err(error) = encode_pre_anchor_v1(
        source.organization_id(),
        source.chain_id(),
        source.root_public_cose_key_bytes(),
        ea_types::KeyThumbprint::try_from(&[0x00_u8; 32][..]).unwrap(),
        source.root_certificate_object_hash(),
        source.initial_admin_certificate_object_hashes(),
        source.initial_admin_operator_binding_object_hashes(),
    ) else {
        panic!("der Abdruck wird nach RFC 9679 neu gerechnet und nicht geglaubt");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-PIN");
}

/// Baut Vorstufenbytes VON HAND, damit ein Zeuge auch Formen erzeugen kann,
/// die [`encode_pre_anchor_v1`] gar nicht erst herausgibt.
fn hand_rolled_pre_anchor(
    pre: &PreAnchorV1,
    domain: &str,
    certificates: &[ObjectHash],
    bindings: &[ObjectHash],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(10)
        .and_then(|encoder| encoder.str(domain))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(pre.organization_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.chain_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_public_cose_key_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_key_thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_certificate_object_hash().as_bytes()))
        .and_then(|encoder| encoder.array(u64::try_from(certificates.len()).unwrap()))
        .expect("der Zeuge kodiert in einen Vec");
    for hash in certificates {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(u64::try_from(bindings.len()).unwrap())
        .expect("Bindungsliste kodiert");
    for hash in bindings {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(0)
        .expect("leere kritische Erweiterungen kodieren");
    bytes
}

/// Baut Vorstufenbytes VON HAND mit einem BELIEBIGEN Wurzelschluessel.
///
/// [`encode_pre_anchor_v1`] gibt genau die Schluessel nicht heraus, die die
/// Abwehrschichten des Dekodierers pruefen sollen: eine Bytekette, die keine
/// 40 Bytes lang ist, und einen kanonischen COSE_Key, der nicht Ed25519 ist.
fn hand_rolled_pre_anchor_with_root_key(
    pre: &PreAnchorV1,
    exact_root_public_cose_key: &[u8],
    root_key_thumbprint: &[u8; 32],
) -> Vec<u8> {
    let certificates = pre.initial_admin_certificate_object_hashes();
    let bindings = pre.initial_admin_operator_binding_object_hashes();
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(10)
        .and_then(|encoder| encoder.str(PRE_ANCHOR_DOMAIN))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(pre.organization_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.chain_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(exact_root_public_cose_key))
        .and_then(|encoder| encoder.bytes(root_key_thumbprint))
        .and_then(|encoder| encoder.bytes(pre.root_certificate_object_hash().as_bytes()))
        .and_then(|encoder| encoder.array(u64::try_from(certificates.len()).unwrap()))
        .expect("der Zeuge kodiert in einen Vec");
    for hash in certificates {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(u64::try_from(bindings.len()).unwrap())
        .expect("Bindungsliste kodiert");
    for hash in bindings {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(0)
        .expect("leere kritische Erweiterungen kodieren");
    bytes
}

/// Die Stelle der Fassungsnummer in den Vorstufenbytes.
///
/// Die Form ist fest: `array(10)` als ein Byte, die Domain als Textkette mit
/// zweibytigem Kopf (33 Zeichen), dann die Fassung `1`. Jeder Zeuge, der hier
/// hineinschreibt, prueft die Umgebung vorher nach.
const PRE_ANCHOR_VERSION_OFFSET: usize = 1 + 2 + PRE_ANCHOR_DOMAIN.len();

fn assert_pre_anchor_prologue(bytes: &[u8]) {
    assert_eq!(bytes[0], 0x8a, "array(10) als ein Byte");
    assert_eq!(bytes[1], 0x78, "Textkette mit einbytiger Laengenangabe");
    assert_eq!(bytes[2], 0x21, "33 Zeichen Domain");
    assert_eq!(
        &bytes[3..PRE_ANCHOR_VERSION_OFFSET],
        PRE_ANCHOR_DOMAIN.as_bytes()
    );
    assert_eq!(bytes[PRE_ANCHOR_VERSION_OFFSET], 0x01, "Fassung 1, minimal");
}

// ---------------------------------------------------------------------------
// Die Abwehrschichten des Vorstufendekodierers
//
// `decode_pre_anchor` spiegelt `decode_trust_anchor`: geliehener Vorlauf ueber
// die flache Drahtform, `ea_cbor::validate` mit `ParserLimits::V1`, besitzende
// Dekodierung, Listenpruefung, Schluesselbindung. Jede dieser Lagen faengt
// etwas, das die naechste durchliesse — die Zeugen unten benennen fuer jede
// genau so eine Eingabe.
// ---------------------------------------------------------------------------

#[test]
fn an_indefinite_length_container_is_not_a_pre_anchor() {
    let pre = fixture_pre_anchor();
    let mut bytes = pre.exact_bytes().to_vec();
    assert_pre_anchor_prologue(&bytes);
    // `0x9f` ist ein Array unbestimmter Laenge; deterministisches CBOR kennt
    // das nicht.
    bytes[0] = 0x9f;
    bytes.push(0xff);

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("eine Huelle unbestimmter Laenge ist keine Vorstufe");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_non_minimal_integer_encoding_is_not_a_pre_anchor() {
    let pre = fixture_pre_anchor();
    let mut bytes = pre.exact_bytes().to_vec();
    assert_pre_anchor_prologue(&bytes);
    // `0x18 0x01` ist dieselbe Zahl 1 in zwei Bytes. Der geliehene Vorlauf
    // liest sie klaglos; erst `ea_cbor::validate` mit `ParserLimits::V1`
    // besteht auf der kuerzesten Form.
    bytes.splice(
        PRE_ANCHOR_VERSION_OFFSET..=PRE_ANCHOR_VERSION_OFFSET,
        [0x18, 0x01],
    );

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("eine nicht minimale Zahlkodierung ist kein deterministisches CBOR");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_root_key_that_is_not_forty_bytes_fails_the_flat_preflight() {
    let pre = fixture_pre_anchor();
    let mut oversized_key = pre.root_public_cose_key_bytes().to_vec();
    assert_eq!(oversized_key.len(), 40);
    oversized_key.push(0x00);
    let bytes = hand_rolled_pre_anchor_with_root_key(
        &pre,
        &oversized_key,
        pre.root_key_thumbprint().as_bytes(),
    );

    // Der Befund ist der Punkt dieses Zeugen: die Laengenschranke des
    // Vorlaufs meldet einen FORMFEHLER. Ohne sie kaeme derselbe Schluessel
    // erst an der Schluesselbindung zu Fall und meldete `EA-TRUST-ANCHOR-PIN`
    // — eine andere Aussage ueber dieselben Bytes.
    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("ein Wurzelschluessel hat genau 40 Bytes");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn a_non_ed25519_root_key_is_rejected_by_the_pre_anchor_decoder() {
    let pre = fixture_pre_anchor();
    let kem_key = CanonicalPublicCoseKey::x25519([0x44; 32]).expect("X25519 ist ein COSE_Key");
    let exact_kem_key = kem_key.to_deterministic_cbor();
    assert_eq!(
        exact_kem_key.len(),
        40,
        "der Vorlauf laesst diesen Schluessel passieren; die Bindung faengt ihn"
    );
    let bytes =
        hand_rolled_pre_anchor_with_root_key(&pre, &exact_kem_key, kem_key.thumbprint().as_bytes());

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("eine Organisationswurzel signiert und schluesselt nicht ein");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-PIN");
}

#[test]
fn a_root_key_that_does_not_match_its_thumbprint_is_rejected_by_the_decoder() {
    let pre = fixture_pre_anchor();
    let bytes =
        hand_rolled_pre_anchor_with_root_key(&pre, pre.root_public_cose_key_bytes(), &[0x00; 32]);

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("der Abdruck wird nach RFC 9679 neu gerechnet und nicht geglaubt");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-PIN");
}

#[test]
fn a_duplicate_admin_hash_is_rejected_by_the_decoder() {
    let pre = fixture_pre_anchor();
    let certificates = pre.initial_admin_certificate_object_hashes();
    let duplicated = vec![certificates[0]; certificates.len()];
    let bytes = hand_rolled_pre_anchor(
        &pre,
        PRE_ANCHOR_DOMAIN,
        &duplicated,
        pre.initial_admin_operator_binding_object_hashes(),
    );

    // Anzahl und Groesse stimmen, der Vorlauf sieht nichts. Nur die
    // Listenpruefung besteht auf STRENGER Sortierung und damit auf
    // Duplikatfreiheit.
    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("zwei gleiche Hashes sind ein Administrator und nicht zwei");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

#[test]
fn an_unsorted_admin_hash_list_is_rejected_by_the_decoder() {
    let pre = fixture_pre_anchor();
    let mut certificates = pre.initial_admin_certificate_object_hashes().to_vec();
    certificates.reverse();
    let bytes = hand_rolled_pre_anchor(
        &pre,
        PRE_ANCHOR_DOMAIN,
        &certificates,
        pre.initial_admin_operator_binding_object_hashes(),
    );

    let Err(error) = decode_pre_anchor(&bytes) else {
        panic!("die Reihenfolge der Liste ist Teil der festgeschriebenen Bytes");
    };
    expect_trust_code(error, "EA-TRUST-ANCHOR-SHAPE");
}

// ---------------------------------------------------------------------------
// Genesis: Schritt 11, erste Haelfte
// ---------------------------------------------------------------------------

/// Die Kennungen der Zeremonie, in der die Genesiszeugen spielen.
const CEREMONY_ORGANIZATION: [u8; 16] = [0x10; 16];
const CEREMONY_CHAIN: [u8; 16] = [0x11; 16];
const CEREMONY_POLICY: [u8; 32] = [0x13; 32];
const CEREMONY_REGISTRY_VERSION: u64 = 7;
const GENESIS_ENTRY: [u8; 32] = [0x91; 32];

fn ceremony_organization() -> OrganizationId {
    OrganizationId::try_from(&CEREMONY_ORGANIZATION[..]).unwrap()
}

fn ceremony_chain() -> ChainId {
    ChainId::try_from(&CEREMONY_CHAIN[..]).unwrap()
}

fn ceremony_policy() -> ObjectHash {
    ObjectHash::try_from(&CEREMONY_POLICY[..]).unwrap()
}

/// Ein fertiger, von `ea-schema` bereits gepruefter Genesis-Koerper.
///
/// Er entsteht LOKAL in dieser Datei: `bind_genesis` prueft nichts, was
/// `ea-schema` schon prueft, und die Zeugen sollen genau die drei Aussagen der
/// Zeremonie treffen.
fn ceremony_genesis(
    organization_id: OrganizationId,
    chain_id: ChainId,
    initial_policy_object_hash: ObjectHash,
    registry_version: u64,
) -> GenesisV1 {
    // UUIDv7: Fassung in Byte 6, Variante in Byte 8 (`CommonHeaderV1::new`).
    let mut record = [0x21_u8; 16];
    record[6] = 0x71;
    record[8] = 0x81;
    let header = CommonHeaderV1::new(
        RecordId::try_from(&record[..]).unwrap(),
        UnixMillis::new(1_700_000_000_000),
        "Europe/Berlin",
        OperatorSnapshotV1::new(
            organization_id,
            OperatorSubjectId::try_from(&[0x20; 16][..]).unwrap(),
            "Erika Beispiel",
            "Einsatzleitung",
            [0x30; 32],
            ObjectHash::try_from(&[0x40; 32][..]).unwrap(),
        )
        .unwrap(),
        NativeSourceV1::new("writer-native", 1).unwrap(),
        RegistryVersion::new(registry_version),
    )
    .unwrap();
    GenesisV1::new(
        header,
        organization_id,
        chain_id,
        ObjectHash::try_from(&[0x12; 32][..]).unwrap(),
        1,
        initial_policy_object_hash,
    )
    .expect("der Genesis-Koerper ist gegen den Nutzlastnachtrag gueltig")
}

fn genesis_of_this_ceremony() -> GenesisV1 {
    ceremony_genesis(
        ceremony_organization(),
        ceremony_chain(),
        ceremony_policy(),
        CEREMONY_REGISTRY_VERSION,
    )
}

fn genesis_envelope(sequence: u64, previous: Option<EntryHash>) -> GenesisEnvelopeV1 {
    GenesisEnvelopeV1 {
        chain_sequence: ChainSequence::new(sequence),
        previous_entry_hash: previous,
        genesis_entry_hash: EntryHash::try_from(&GENESIS_ENTRY[..]).unwrap(),
    }
}

fn bind_ceremony_genesis(
    genesis: &GenesisV1,
    envelope: &GenesisEnvelopeV1,
) -> Result<ea_admin::GenesisBinding, AdminError> {
    bind_genesis(
        genesis,
        ceremony_organization(),
        ceremony_chain(),
        ceremony_policy(),
        RegistryVersion::new(CEREMONY_REGISTRY_VERSION),
        envelope,
    )
}

#[test]
fn a_genesis_of_this_ceremony_binds_its_entry_hash_and_registry_head() {
    let genesis = genesis_of_this_ceremony();
    let binding = bind_ceremony_genesis(&genesis, &genesis_envelope(0, None))
        .expect("Sequenz 0 ohne Vorgaenger, und die Kennungen sind die dieser Zeremonie");

    assert_eq!(binding.genesis_entry_hash().as_bytes(), &GENESIS_ENTRY);
    assert_eq!(
        binding.registry_version().get(),
        CEREMONY_REGISTRY_VERSION,
        "gebunden wird der Kopf aus Schritt 10 (`:1145`)"
    );
}

#[test]
fn a_genesis_at_a_nonzero_chain_sequence_is_refused() {
    let genesis = genesis_of_this_ceremony();

    let Err(error) = bind_ceremony_genesis(&genesis, &genesis_envelope(1, None)) else {
        panic!("Genesis ist der ERSTE Eintrag der Kette");
    };
    expect_admin_code(error, "EA-CEREMONY-GENESIS-SEQUENCE");
}

#[test]
fn a_genesis_carrying_a_previous_entry_hash_is_refused() {
    let genesis = genesis_of_this_ceremony();
    let previous = EntryHash::try_from(&[0x77_u8; 32][..]).unwrap();

    // `design.md:927`: „Fuer Genesis ist `previous-entry-hash = null`".
    let Err(error) = bind_ceremony_genesis(&genesis, &genesis_envelope(0, Some(previous))) else {
        panic!("vor dem ersten Eintrag steht kein Eintrag");
    };
    expect_admin_code(error, "EA-CEREMONY-GENESIS-SEQUENCE");
}

#[test]
fn a_genesis_from_another_organization_chain_policy_or_head_is_refused() {
    let other_organization = OrganizationId::try_from(&[0x5a_u8; 16][..]).unwrap();
    let other_chain = ChainId::try_from(&[0x6b_u8; 16][..]).unwrap();
    let other_policy = ObjectHash::try_from(&[0x7c_u8; 32][..]).unwrap();

    let mismatches = [
        (
            "Organisation",
            ceremony_genesis(
                other_organization,
                ceremony_chain(),
                ceremony_policy(),
                CEREMONY_REGISTRY_VERSION,
            ),
        ),
        (
            "Kette",
            ceremony_genesis(
                ceremony_organization(),
                other_chain,
                ceremony_policy(),
                CEREMONY_REGISTRY_VERSION,
            ),
        ),
        (
            "Richtlinie",
            ceremony_genesis(
                ceremony_organization(),
                ceremony_chain(),
                other_policy,
                CEREMONY_REGISTRY_VERSION,
            ),
        ),
        (
            "Registrierungskopf",
            ceremony_genesis(
                ceremony_organization(),
                ceremony_chain(),
                ceremony_policy(),
                CEREMONY_REGISTRY_VERSION - 1,
            ),
        ),
    ];

    for (label, genesis) in mismatches {
        let Err(error) = bind_ceremony_genesis(&genesis, &genesis_envelope(0, None)) else {
            panic!("{label} gehoert nicht zu dieser Zeremonie");
        };
        expect_admin_code(error, "EA-CEREMONY-GENESIS-CONTEXT-MISMATCH");
    }
}
