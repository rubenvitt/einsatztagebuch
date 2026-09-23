//! Zeugen der Cutover-Vorbedingung des Reader-Key-Escrows (v1.1-Profil §5,
//! Ruling O1 = P1): ein Escrow wird nur angenommen, wenn eine aktive,
//! wurzelsignierte `webBundleRelease` eines v1.1-fähigen Bundles gilt, deren
//! `effective-from-registry-version` nicht größer ist als die Registry-Version
//! der Publikation.
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_format::{WebBundleReleaseCoreV1, WebBundleRevocationCoreV1};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, signed_web_bundle_release, signed_web_bundle_revocation,
};
use ea_trust::{
    BundleRejectionCodeV1, EscrowCutoverError, MIN_ESCROW_BUNDLE_VERSION, TrustAnchorV1,
    bundle_version_carries_reader_key_escrow, decode_trust_anchor,
    reader_key_escrow_cutover_release,
};
use ea_types::{CertificateHash, Hash32, ObjectHash, RegistryVersion, UnixMillis};
use support::RegistryLineBuilder;

/// Die Registry-Version der Publikation in diesen Zeugen.
const PUBLICATION_VERSION: u64 = 5;

struct Fixture {
    anchor: TrustAnchorV1,
    root: FixtureTrustSigner,
}

fn fixture() -> Fixture {
    let line = RegistryLineBuilder::new();
    Fixture {
        anchor: decode_trust_anchor(line.exact_anchor_bytes()).unwrap(),
        root: FixtureTrustSigner {
            seed: support::root_signing_secret(),
            certificate_hash: CertificateHash::try_from(
                line.current_root_hash().as_bytes().as_slice(),
            )
            .unwrap(),
        },
    }
}

fn release_core(version: &str, effective_from: u64, fill: u8) -> WebBundleReleaseCoreV1 {
    WebBundleReleaseCoreV1 {
        organization_id: support::organization(),
        bundle_hash: Hash32::try_from([fill; 32].as_slice()).unwrap(),
        bundle_version: version.to_owned(),
        effective_from_registry_version: RegistryVersion::new(effective_from),
        issued_at: UnixMillis::new(i64::from(fill)),
        root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
            .thumbprint(),
    }
}

fn release(fixture: &Fixture, version: &str, effective_from: u64, fill: u8) -> Vec<u8> {
    signed_web_bundle_release(&release_core(version, effective_from, fill), &fixture.root)
}

/// Der Objekthash als Bytes: `ObjectHash` trägt bewusst kein `Debug`.
fn gate(fixture: &Fixture, objects: &[&[u8]]) -> Result<[u8; 32], EscrowCutoverError> {
    reader_key_escrow_cutover_release(
        &fixture.anchor,
        objects,
        RegistryVersion::new(PUBLICATION_VERSION),
    )
    .map(|hash: ObjectHash| *hash.as_bytes())
}

#[test]
fn an_empty_catalog_keeps_the_escrow_gate_shut() {
    let fixture = fixture();
    assert_eq!(
        gate(&fixture, &[]),
        Err(EscrowCutoverError::NoActiveRelease)
    );
}

#[test]
fn an_active_capable_release_opens_the_gate_and_is_named() {
    let fixture = fixture();
    let capable = release(
        &fixture,
        MIN_ESCROW_BUNDLE_VERSION,
        PUBLICATION_VERSION,
        0x41,
    );
    assert_eq!(
        gate(&fixture, &[&capable]),
        Ok(*ea_crypto::object_hash(&capable).as_bytes())
    );
}

#[test]
fn the_frozen_bundle_version_is_not_escrow_capable() {
    // `2026.3.1` ist die Fassung des eingefrorenen Vektors unter
    // `vectors/web-bundle/v1/`; sie trägt die drei Familien nicht.
    let fixture = fixture();
    let old = release(&fixture, "2026.3.1", 1, 0x42);
    assert_eq!(
        gate(&fixture, &[&old]),
        Err(EscrowCutoverError::ReleaseNotCapable)
    );
}

#[test]
fn a_newer_but_older_version_active_release_shuts_the_gate() {
    // Aktiv ist die jüngste wirksame Freigabe, nicht die höchste Fassung:
    // eine spätere Freigabe einer alten Fassung schließt die Sperre wieder.
    let fixture = fixture();
    let capable = release(&fixture, MIN_ESCROW_BUNDLE_VERSION, 2, 0x43);
    let downgrade = release(&fixture, "2026.3.1", 3, 0x44);
    assert_eq!(
        gate(&fixture, &[&capable, &downgrade]),
        Err(EscrowCutoverError::ReleaseNotCapable)
    );
}

#[test]
fn a_revoked_capable_release_does_not_open_the_gate() {
    let fixture = fixture();
    let capable = release(&fixture, MIN_ESCROW_BUNDLE_VERSION, 2, 0x45);
    let revocation = signed_web_bundle_revocation(
        &WebBundleRevocationCoreV1 {
            organization_id: support::organization(),
            release_object_hash: ea_crypto::object_hash(&capable),
            effective_from_registry_version: RegistryVersion::new(3),
            issued_at: UnixMillis::new(0x46),
            root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
                .thumbprint(),
        },
        &fixture.root,
    );
    assert_eq!(
        gate(&fixture, &[&capable, &revocation]),
        Err(EscrowCutoverError::NoActiveRelease)
    );
}

#[test]
fn a_release_effective_after_the_publication_does_not_open_the_gate() {
    let fixture = fixture();
    let later = release(
        &fixture,
        MIN_ESCROW_BUNDLE_VERSION,
        PUBLICATION_VERSION + 1,
        0x47,
    );
    assert_eq!(
        gate(&fixture, &[&later]),
        Err(EscrowCutoverError::NoActiveRelease)
    );
}

#[test]
fn a_release_under_a_foreign_root_is_an_attack_not_an_absence() {
    let fixture = fixture();
    let foreign = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 1, 0x48),
        &FixtureTrustSigner {
            seed: [0x99; 32],
            certificate_hash: fixture.root.certificate_hash,
        },
    );
    assert_eq!(
        gate(&fixture, &[&foreign]),
        Err(EscrowCutoverError::Bundle(BundleRejectionCodeV1::WrongRoot))
    );
}

#[test]
fn an_unparseable_bundle_version_is_not_escrow_capable() {
    let fixture = fixture();
    let odd = release(&fixture, "2027.1.0-rc1", 1, 0x49);
    assert_eq!(
        gate(&fixture, &[&odd]),
        Err(EscrowCutoverError::ReleaseNotCapable)
    );
}

#[test]
fn the_version_order_is_numeric_per_dotted_component_and_fail_closed() {
    let capable = |version: &str| bundle_version_carries_reader_key_escrow(version);
    assert!(capable(MIN_ESCROW_BUNDLE_VERSION));
    assert!(!capable("2026.3.1"));
    assert!(!capable("2026.3.99"));
    // Numerisch, nicht lexikografisch: 10 > 9.
    assert!(capable("2026.10.0"));
    assert!(capable("2027.0.0"));
    // Fehlende Komponenten zählen als null.
    assert!(capable("2026.4"));
    assert!(capable("2027"));
    assert!(!capable("2026"));
    assert!(capable("2026.4.0.0"));
    // Führende Nullen sind Ziffern und ändern den Wert nicht.
    assert!(capable("2026.04.0"));
    // Alles, was sich nicht zerlegen lässt, gilt als nicht fähig.
    for odd in [
        "",
        ".",
        "2026..4",
        "2026.4.",
        ".2026.4",
        "+2026.4.0",
        "2026.4.0-rc1",
        " 2026.4.0",
        "v2026.4.0",
        "2026.4.18446744073709551616",
    ] {
        assert!(!capable(odd), "{odd:?} must not count as escrow capable");
    }
}
