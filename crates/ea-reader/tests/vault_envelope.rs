//! Der Browser-Tresor, seine PRF-Envelopes und die zwei Weigerungen, die ihn
//! tragen.
//!
//! `web-reader-design.md` §6.2 verlangt woertlich, dass die PRF-Ausgabe NICHT
//! selbst der Verschluesselungsschluessel ist: `KEK_i = HKDF(PRF_i(festes
//! App-Salt), info = "ea-reader-vault-v1")`. Der Grund steht in derselben
//! Sektion und ist betrieblich, nicht aesthetisch — waere die PRF-Ausgabe der
//! Schluessel, machte das Loeschen EINES Passkeys die Daten dauerhaft
//! unerreichbar. Genau das misst
//! `the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone`,
//! und das Entfernen eines Envelopes kostet dort einen Entsperrweg und nie den
//! Inhalt.
//!
//! # Die Ableitung wird DIREKT gemessen und nicht ueber das Chiffrat erschlossen
//!
//! Die Kanarienschleife ueber `wrapped_vault_key()` ist eine ANWESENHEITSPROBE
//! und fuer sich kein Beleg von §6.2: ein AEAD-Chiffrat traegt seinen eigenen
//! Schluessel auch dann nicht im Klartext, wenn dieser Schluessel die rohe
//! PRF-Ausgabe WAERE. Der Beleg ist deshalb der Vergleich von `derive_kek_v1`
//! gegen `Hkdf::<Sha256>::new(None, prf).expand(VAULT_KEK_INFO_V1, ..)`, den
//! derselbe Zeuge unmittelbar danach fuehrt — er faerbt, sobald `derive_kek_v1`
//! die Ableitung ueberspringt oder den Info-Kontext still wechselt. `hkdf` und
//! `sha2` sind regulaere Abhaengigkeiten von `ea-reader` und stehen einem
//! Integrationstestziel ohne Manifestaenderung zur Verfuegung.
//!
//! # Zwei Weigerungen, und beide reichen einen FREMDEN Code durch
//!
//! `a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse` erwartet
//! `EA-CRYPTO-AEAD-OPEN` aus `ea_crypto::aead_open` und
//! `EA-TRUST-ANCHOR-HASH` aus `ea_trust::decode_trust_anchor`. Kein zweiter,
//! eigener Code tritt daneben — ein Tresor, der seine eigenen Namen fuer
//! fremde Befunde erfaende, verschoebe die Aussage beim naechsten Umbau still.
//! Der untergeschobene Anker faellt, WEIL `unlock` ihn neu dekodiert und
//! `bootstrap_anchor_hash` ueber die Vorstufenbytes NEU rechnet: der Anker gilt
//! nicht, weil er im Tresor lag, sondern weil er sich selbst traegt.

mod fixtures;

use ea_crypto::SecretBytes;
use ea_reader::{AuthenticatorPrfV1, ReaderVault};
use ea_trust::RegistryHeadPin;
use ea_types::RegistryVersion;

#[test]
fn the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone() {
    let first = [0xa1_u8; 32];
    let second = [0xb2_u8; 32];
    let sealed = ReaderVault::seal(
        fixtures::vault_contents(),
        &[
            AuthenticatorPrfV1::new(fixtures::credential_id(1), SecretBytes::new(first)),
            AuthenticatorPrfV1::new(fixtures::credential_id(2), SecretBytes::new(second)),
        ],
    )
    .unwrap();

    assert_eq!(sealed.envelopes().len(), 2);
    for envelope in sealed.envelopes() {
        for raw in [first, second] {
            assert!(
                !ea_testkit::contains_canary(envelope.wrapped_vault_key(), &raw),
                "die rohe PRF-Ausgabe steht in KEINEM Chiffrat"
            );
        }
    }

    // Die HKDF-Richtung DIREKT gemessen, und nicht ueber die Anwesenheitsprobe
    // darueber: dass die rohe PRF-Ausgabe nicht im Chiffrat steht, gilt auch
    // dann, wenn sie SELBST der Wrapping-Schluessel waere — ein AEAD-Chiffrat
    // traegt seinen eigenen Schluessel nie im Klartext. Gemessen wird deshalb
    // `KEK_i` selbst, gegen die Rechnung aus §6.2 und gegen die rohe Ausgabe.
    let kek = ea_reader::derive_kek_v1(&AuthenticatorPrfV1::new(
        fixtures::credential_id(1),
        SecretBytes::new(first),
    ))
    .unwrap();
    let mut expected = [0_u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &first)
        .expand(ea_reader::VAULT_KEK_INFO_V1, &mut expected)
        .unwrap();
    assert!(
        !kek.matches(&first),
        "die PRF-Ausgabe DARF NICHT selbst der Wrapping-Schluessel sein"
    );
    // Die zweite Zusicherung pinnt zugleich den zeichengleichen Info-String:
    // ein stiller Kontextwechsel faerbt hier und nicht erst in einem spaeteren
    // Tresor, der sich dann nicht mehr oeffnen liesse.
    assert!(
        kek.matches(&expected),
        "KEK_i MUSS HKDF-SHA-256(PRF_i, info = VAULT_KEK_INFO_V1) sein"
    );

    for (index, raw) in [(1_u8, first), (2, second)] {
        let unlocked = ReaderVault::unlock(
            &sealed,
            &AuthenticatorPrfV1::new(fixtures::credential_id(index), SecretBytes::new(raw)),
        )
        .unwrap();
        // Der Vergleich laeuft ueber `as_bytes()`, weil `Hash32` kein `Debug`
        // ableitet (`crates/ea-types/src/ids.rs`, `hash_newtype!`).
        assert_eq!(
            unlocked.pinned_anchor().trust_anchor_hash().as_bytes(),
            fixtures::pinned_anchor().trust_anchor_hash().as_bytes()
        );
        assert_eq!(
            unlocked.kem_private_key().public_key().as_bytes(),
            fixtures::reader_kem_public_key().as_bytes()
        );
        assert_eq!(
            unlocked
                .last_registry_pin()
                .map(RegistryHeadPin::registry_version),
            Some(RegistryVersion::new(7))
        );
    }

    // Ein geloeschter Passkey kostet einen Entsperrweg und nie die Daten.
    let reduced = sealed
        .without_credential(fixtures::credential_id(1))
        .unwrap();
    assert_eq!(reduced.envelopes().len(), 1);
    assert!(
        ReaderVault::unlock(
            &reduced,
            &AuthenticatorPrfV1::new(fixtures::credential_id(2), SecretBytes::new(second)),
        )
        .is_ok()
    );
    assert_eq!(
        ReaderVault::unlock(
            &reduced,
            &AuthenticatorPrfV1::new(fixtures::credential_id(1), SecretBytes::new(first)),
        )
        .unwrap_err()
        .code(),
        "EA-READER-VAULT-NO-ENVELOPE"
    );
}

#[test]
fn a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse() {
    let sealed = fixtures::sealed_vault();
    let prf = fixtures::authenticator(1);

    let mut tampered = sealed.clone();
    tampered.flip_one_wrapped_key_byte_for_test(fixtures::credential_id(1));
    assert_eq!(
        ReaderVault::unlock(&tampered, &prf).unwrap_err().code(),
        "EA-CRYPTO-AEAD-OPEN"
    );

    // Der Anchor wird beim Entsperren NEU dekodiert, nicht geglaubt.
    //
    // Die Hilfe bekommt den Authenticator MIT, und das ist keine Bequemlichkeit:
    // ein roher Byte-Patch am Chiffrat faellt zuerst mit `EA-CRYPTO-AEAD-OPEN`
    // und erreicht `decode_trust_anchor` nie — dieser Zeuge pruefte dann zweimal
    // dasselbe. Das Ersetzen MUSS also entsiegeln, tauschen und NEU versiegeln,
    // und dafuer braucht es den Tresorschluessel. `SealedVaultV1` haelt selbst
    // kein Schluesselmaterial, und genau das soll so bleiben; der einzige Weg
    // dorthin ist ein Envelope.
    let mut foreign = sealed.clone();
    foreign.replace_sealed_anchor_bytes_for_test(&prf, fixtures::foreign_anchor_exact_bytes());
    assert_eq!(
        ReaderVault::unlock(&foreign, &prf).unwrap_err().code(),
        "EA-TRUST-ANCHOR-HASH"
    );

    assert_eq!(
        ReaderVault::seal(fixtures::vault_contents(), &[])
            .unwrap_err()
            .code(),
        "EA-READER-VAULT-NO-AUTHENTICATOR"
    );
}
