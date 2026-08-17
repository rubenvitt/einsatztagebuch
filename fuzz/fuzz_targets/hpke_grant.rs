#![no_main]

//! Fuzzt die Grant-Entkapselung und den Grant-Signaturinput aus `ea-crypto` —
//! eine der fuenf Flaechen, die `design.md` 22.1 verlangt.
//!
//! Die Kapselungsrichtung ist nicht fuzzbar: `hpke_seal` zieht bei jedem Aufruf
//! frische Betriebssystementropie, und der einzige Injektionspunkt
//! `hpke_seal_with_random_source` ist absichtlich privat. Fuzzbar und
//! deterministisch ist die ENTKAPSELUNG: fester Empfaengerschluessel,
//! mutierter Kapselungswert, mutierter umschlossener CEK, mutierter
//! Grant-Kontext. Genau diese Richtung sieht ein Reader.
//!
//! Die Eingabe wird deterministisch zerlegt: 32 Byte Kapselungswert, 48 Byte
//! umschlossener CEK, Rest als Grant-Kontext-CBOR fuer `hpke_info`/`hpke_aad`
//! und den Grant-Signaturinput.

use libfuzzer_sys::fuzz_target;

/// Der Empfaengerschluessel ist fest: gefuzzt wird der Umschlag, nicht der
/// Schluessel. Ein mutierter Privatschluessel machte jeden Fehlschlag
/// uninterpretierbar.
const RECIPIENT_PRIVATE_KEY: [u8; 32] = [0x42; 32];

const ENC_SIZE: usize = ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE;
const WRAPPED_SIZE: usize = ea_crypto::HPKE_WRAPPED_CEK_SIZE;

const _: () = assert!(ENC_SIZE == 32);
const _: () = assert!(WRAPPED_SIZE == 48);

fuzz_target!(|data: &[u8]| {
    if data.len() < ENC_SIZE + WRAPPED_SIZE {
        return;
    }
    let mut encapsulated_key = [0_u8; ENC_SIZE];
    encapsulated_key.copy_from_slice(&data[..ENC_SIZE]);
    let mut wrapped_cek = [0_u8; WRAPPED_SIZE];
    wrapped_cek.copy_from_slice(&data[ENC_SIZE..ENC_SIZE + WRAPPED_SIZE]);
    let context = &data[ENC_SIZE + WRAPPED_SIZE..];

    // Der Grant-Signaturinput: beide Domaenen praefixen ihren Kontext, sind
    // voneinander getrennt und ueber wiederholte Aufrufe stabil.
    let info = ea_crypto::hpke_info(context);
    let aad = ea_crypto::hpke_aad(context);
    assert!(
        info.starts_with(b"EINSATZARCHIV-HPKE-INFO-v1") && info.ends_with(context),
        "hpke_info must prefix its domain and keep the context verbatim"
    );
    assert!(
        aad.starts_with(b"EINSATZARCHIV-HPKE-AAD-v1") && aad.ends_with(context),
        "hpke_aad must prefix its domain and keep the context verbatim"
    );
    assert_ne!(info, aad, "the info and AAD domains must stay separated");

    let plan_digest = ea_crypto::grant_plan_digest(context);
    let grant_digest = ea_crypto::grant_digest(context);
    assert_ne!(
        plan_digest.as_bytes(),
        grant_digest.as_bytes(),
        "the grant plan and grant domains must stay separated"
    );
    assert_eq!(
        ea_crypto::grant_digest(context).as_bytes(),
        grant_digest.as_bytes(),
        "the grant signature input must be deterministic"
    );

    let Ok(sealed) = ea_crypto::HpkeSealed::from_parts(encapsulated_key, wrapped_cek) else {
        return;
    };
    assert_eq!(
        sealed.encapsulated_key(),
        &encapsulated_key,
        "the encapsulated key must survive from_parts unchanged"
    );
    assert_eq!(
        sealed.wrapped_cek(),
        &wrapped_cek,
        "the wrapped CEK must survive from_parts unchanged"
    );

    let recipient = ea_crypto::HpkeRecipientPrivateKey::from_bytes(ea_crypto::SecretBytes::new(
        RECIPIENT_PRIVATE_KEY,
    ))
    .expect("the fixed recipient key must load");

    // Nahezu jede mutierte Eingabe MUSS als `HpkeOpen` scheitern. Gelingt die
    // Entkapselung doch, ist der CEK genau 32 Byte lang; alles andere waere ein
    // Bruch der Suite-1-Invariante.
    match ea_crypto::hpke_open(&recipient, &sealed, &info, &aad) {
        Ok(cek) => assert_eq!(cek.len(), 32, "an opened CEK must be exactly 32 bytes"),
        Err(error) => assert_eq!(
            error,
            ea_crypto::CryptoError::HpkeOpen,
            "a failed decapsulation must report HpkeOpen"
        ),
    }

    // Ein abweichendes AAD MUSS die Entkapselung scheitern lassen. Das gilt
    // auch dann, wenn der Umschlag selbst gueltig waere.
    let mut foreign_aad = aad.clone();
    foreign_aad.push(0);
    assert!(
        ea_crypto::hpke_open(&recipient, &sealed, &info, &foreign_aad).is_err(),
        "a mutated AAD must never decapsulate"
    );
});
