//! Die exakten Planbytes und ihr Dekodierer.
//!
//! Die `.bin` unter `vectors/grants/v1/plan/` tragen ROHES Elementmaterial —
//! je Element 32 Byte Fingerabdruck des Empfaengerschluessels, 32 Byte Hash
//! des Empfaengerzertifikats und ein Zweckbyte —, KEINE Wire-Bytes. Die
//! Wire-Bytes entstehen in diesem Test aus diesem Material; eingefroren ist
//! der Manifestdigest `grantPlanHash` von `plan/accepted-total-order` aus
//! `vectors/grants/v1/manifest.json`.
//!
//! Der Negativfall der REIHENFOLGE entsteht deshalb hier und nicht als neuer
//! eingefrorener Vektor: diese Stufe friert keinen Planvektor ein.

use std::path::PathBuf;

use ea_format::{GrantPlanItemV1, GrantPlanV1, GrantPurposeV1, decode_grant_plan};
use ea_types::{CertificateHash, KeyThumbprint};
use minicbor::Encoder;

/// Der eingefrorene `grantPlanHash` von `plan/accepted-total-order`.
const FROZEN_GRANT_PLAN_HASH: &str =
    "acf4ba75d7df5506cd5909d4f776ecc258b268dbd6af3ca3cf920952fa245ab8";

/// Ein Element im ROHMATERIAL der Vektordateien: 32 + 32 + 1 Byte.
const RAW_ITEM_BYTES: usize = 65;

mod fixtures {
    use super::{
        CertificateHash, GrantPlanItemV1, GrantPurposeV1, KeyThumbprint, PathBuf, RAW_ITEM_BYTES,
    };

    /// Die Elemente eines eingefrorenen Planvektors, in DATEIREIHENFOLGE.
    ///
    /// Die Reihenfolge bleibt unangetastet: nur so kann der Test einen
    /// abgelehnten Fall UNSORTIERT an den Dekodierer geben.
    ///
    /// # Panics
    ///
    /// Wenn die Vektordatei fehlt oder ihr Material nicht auf ganze Elemente
    /// aufgeht. Beides waere ein Fehler des Arbeitsbaums, kein Laufzeitzustand.
    pub fn plan_items(name: &str) -> Vec<GrantPlanItemV1> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("vectors/grants/v1/plan")
            .join(format!("{name}.bin"));
        let raw = std::fs::read(&path)
            .unwrap_or_else(|_| panic!("der eingefrorene Planvektor {name} muss lesbar sein"));
        assert!(
            !raw.is_empty() && raw.len().is_multiple_of(RAW_ITEM_BYTES),
            "das Rohmaterial von {name} muss auf ganze Elemente aufgehen"
        );
        raw.chunks_exact(RAW_ITEM_BYTES)
            .map(|chunk| {
                GrantPlanItemV1::new(
                    KeyThumbprint::try_from(&chunk[..32])
                        .expect("32 Byte sind ein Schluesselfingerabdruck"),
                    CertificateHash::try_from(&chunk[32..64])
                        .expect("32 Byte sind ein Zertifikatshash"),
                    match chunk[64] {
                        0 => GrantPurposeV1::Recovery,
                        1 => GrantPurposeV1::Reader,
                        other => panic!("unbekanntes Zweckbyte {other} in {name}"),
                    },
                )
            })
            .collect()
    }

    /// Der eingefrorene Erwartungswert aus `vectors/grants/v1/manifest.json`.
    #[must_use]
    pub fn frozen_grant_plan_hash() -> String {
        super::FROZEN_GRANT_PLAN_HASH.to_owned()
    }
}

/// Die Wire-Bytes der Elemente in GENAU der uebergebenen Reihenfolge.
///
/// Der Test braucht eine Kodierung OHNE die Sortierung und die Doppelpruefung
/// von `GrantPlanV1::new` — sonst gaebe es kein Material, das der Dekodierer
/// ablehnen koennte. Die Produktion kodiert weiterhin ausschliesslich ueber
/// `GrantPlanV1`.
fn encode_items(items: &[GrantPlanItemV1]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(u64::try_from(items.len()).expect("die Testplaene sind kurz"))
        .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    for item in items {
        encoder
            .array(4)
            .and_then(|encoder| encoder.bytes(item.recipient_key_thumbprint().as_bytes()))
            .and_then(|encoder| encoder.bytes(item.recipient_certificate_hash().as_bytes()))
            .and_then(|encoder| encoder.str(item.grant_suite_id()))
            .and_then(|encoder| encoder.u8(item.purpose() as u8))
            .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    }
    bytes
}

fn reversed(items: &[GrantPlanItemV1]) -> Vec<GrantPlanItemV1> {
    let mut reversed = items.to_vec();
    reversed.reverse();
    reversed
}

#[test]
fn grant_plan_round_trips_and_rejects_a_wrong_order() {
    let plan = GrantPlanV1::new(fixtures::plan_items("accepted-total-order")).unwrap();
    assert_eq!(
        hex::encode(plan.hash().as_bytes()),
        fixtures::frozen_grant_plan_hash()
    );

    let decoded = decode_grant_plan(plan.exact_bytes()).unwrap();
    assert_eq!(decoded.exact_bytes(), plan.exact_bytes());
    assert_eq!(decoded.hash().as_bytes(), plan.hash().as_bytes());
    assert_eq!(decoded.items(), plan.items());

    // Der Negativfall entsteht im Test, nicht als neuer eingefrorener Vektor.
    assert_eq!(
        decode_grant_plan(&encode_items(&reversed(plan.items())))
            .unwrap_err()
            .code(),
        "EA-FORMAT-UNSORTED"
    );

    for (name, code) in [
        ("rejected-missing-recovery", "EA-GRANT-MISSING-RECOVERY"),
        ("rejected-duplicate-recovery", "EA-GRANT-DUPLICATE-RECOVERY"),
        (
            "rejected-duplicate-recipient-key",
            "EA-GRANT-DUPLICATE-RECIPIENT-KEY",
        ),
        (
            "rejected-duplicate-recipient-certificate",
            "EA-GRANT-DUPLICATE-RECIPIENT-CERTIFICATE",
        ),
    ] {
        assert_eq!(
            decode_grant_plan(&encode_items(&fixtures::plan_items(name)))
                .unwrap_err()
                .code(),
            code,
            "{name} muss der Dekodierer mit demselben Code ablehnen wie GrantPlanV1::new"
        );
    }
}

#[test]
fn the_decoder_refuses_every_material_that_the_constructor_refuses() {
    // Dieselben Materialien, diesmal durch `GrantPlanV1::new`: Kodierer und
    // Dekodierer duerfen sich in KEINEM Code unterscheiden, sonst wichen
    // `initialGrantPlanHash` und Wiedergabeidentitaet zwischen Schreiber und
    // Server voneinander ab.
    for name in [
        "rejected-missing-recovery",
        "rejected-duplicate-recovery",
        "rejected-duplicate-recipient-key",
        "rejected-duplicate-recipient-certificate",
    ] {
        let items = fixtures::plan_items(name);
        let from_constructor = GrantPlanV1::new(items.clone()).unwrap_err().code();
        let from_decoder = decode_grant_plan(&encode_items(&items)).unwrap_err().code();
        assert_eq!(from_constructor, from_decoder, "{name}");
    }
}

#[test]
fn the_decoder_never_re_sorts_and_never_accepts_trailing_bytes() {
    let plan = GrantPlanV1::new(fixtures::plan_items("accepted-total-order")).unwrap();

    // Eine verdrehte Reihenfolge wird ABGELEHNT, nicht nachsortiert: ein
    // nachsortierender Dekodierer lieferte denselben Hash und verloere damit
    // genau die Bindung, die der Plan traegt.
    let mut swapped = plan.items().to_vec();
    swapped.swap(0, 1);
    assert!(decode_grant_plan(&encode_items(&swapped)).is_err());

    let mut trailing = plan.exact_bytes().to_vec();
    trailing.push(0x00);
    assert_eq!(
        decode_grant_plan(&trailing).unwrap_err().code(),
        "EA-CBOR-TRAILING"
    );
}
