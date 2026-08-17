#![no_main]

//! Fuzzt die COSE-Sign1-Dekodierung aus `ea-crypto` — eine der fuenf Flaechen,
//! die `design.md` 22.1 verlangt.
//!
//! Ein blosser `parse_cose_sign1(data, &[])`-Aufruf auf rohe Mutatorbytes
//! erreicht den Parser nicht: `parse_cose_sign1` verlangt zuerst das
//! CBOR-Tag 18 und danach ein vierelementiges Array, also die Praefixbytes
//! `d2 84`. Die Wahrscheinlichkeit, dass ein zufaelliger Block sie trifft,
//! ist verschwindend, und ein Ziel ohne Praefixsynthese wuerde ausschliesslich
//! die erste Ablehnung ueben. Das erste Eingabebyte waehlt deshalb den Modus:
//! ein Modus laesst die Bytes roh durch und haelt den Ablehnungspfad am
//! Leben, der andere setzt das Praefix davor, damit der Mutator an
//! geschuetztem Header, Payload und Signatur arbeitet.

use libfuzzer_sys::fuzz_target;

/// Tag 18 (`COSE_Sign1`) gefolgt vom Kopf eines vierelementigen Arrays.
const COSE_SIGN1_PREFIX: [u8; 2] = [0xd2, 0x84];

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let input = if mode % 2 == 0 {
        rest.to_vec()
    } else {
        let mut synthesized = Vec::with_capacity(COSE_SIGN1_PREFIX.len() + rest.len());
        synthesized.extend_from_slice(&COSE_SIGN1_PREFIX);
        synthesized.extend_from_slice(rest);
        synthesized
    };

    // Ein nicht leeres externes AAD ist in Suite 1 nicht definiert und MUSS
    // ausnahmslos abgelehnt werden — unabhaengig davon, wie wohlgeformt die
    // uebrigen Bytes sind.
    assert!(
        ea_crypto::parse_cose_sign1(&input, b"x").is_err(),
        "a non-empty external AAD must never parse"
    );

    let Ok(parsed) = ea_crypto::parse_cose_sign1(&input, &[]) else {
        return;
    };

    // Angenommene Bytes sind exakt die Eingabebytes: kein Nachlauf, keine
    // Umkodierung. Die Vergleichsrichtung spiegelt `parse_cose_sign1`, das
    // `exact` aus genau diesem Eingabefenster bildet.
    assert_eq!(
        parsed.exact_bytes(),
        input.as_slice(),
        "an accepted COSE_Sign1 must expose exactly the input bytes"
    );

    // Der Parser laeuft ueber die Grenzen von `ea_cbor::ParserLimits::V1`;
    // eine angenommene Eingabe MUSS sie folglich auch einzeln einhalten.
    assert!(
        ea_cbor::validate(&input, ea_cbor::ParserLimits::V1).is_ok(),
        "an accepted COSE_Sign1 must satisfy the v1 parser limits"
    );
    assert!(
        parsed.payload().len() <= ea_cbor::ParserLimits::V1.max_text_or_bytes,
        "an accepted payload must stay inside the v1 byte-string limit"
    );

    // Idempotenz: die exakten Bytes einer angenommenen Eingabe parsen erneut
    // und liefern denselben Rahmen.
    let reparsed = ea_crypto::parse_cose_sign1(parsed.exact_bytes(), &[])
        .expect("the exact bytes of an accepted COSE_Sign1 must parse again");
    assert_eq!(
        reparsed.exact_bytes(),
        parsed.exact_bytes(),
        "re-parsing must be stable"
    );
    assert_eq!(
        reparsed.signature_bytes(),
        parsed.signature_bytes(),
        "re-parsing must yield the same signature"
    );
    assert_eq!(
        reparsed.payload(),
        parsed.payload(),
        "re-parsing must yield the same payload"
    );
});
