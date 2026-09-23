//! Zeugen der Annahme der Bundle-Familie (`webBundleRelease`,
//! `webBundleRevocation`) über ihren EIGENEN Einstieg (v1.1-Profil §1.3 U4,
//! Scheibe f). Der Registrierungsabschluss weist beide weiter mit
//! `ActionMismatch` ab; angenommen wird hier, mit derselben Regel, die der
//! Reader-Pin und die Cutover-Sperre benutzen.
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_format::{WebBundleReleaseCoreV1, WebBundleRevocationCoreV1};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, signed_web_bundle_release, signed_web_bundle_revocation,
};
use ea_trust::{
    BundleRejectionCodeV1, MIN_ESCROW_BUNDLE_VERSION, TrustAnchorV1, WebBundleAdmission,
    WebBundleAdmissionError, decode_trust_anchor, verify_web_bundle_family_admission,
};
use ea_types::{CertificateHash, Hash32, OrganizationId, RegistryVersion, UnixMillis};
use support::RegistryLineBuilder;

struct Fixture {
    line: RegistryLineBuilder,
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
        line,
    }
}

fn release_core(version: &str, fill: u8) -> WebBundleReleaseCoreV1 {
    WebBundleReleaseCoreV1 {
        organization_id: support::organization(),
        bundle_hash: Hash32::try_from([fill; 32].as_slice()).unwrap(),
        bundle_version: version.to_owned(),
        effective_from_registry_version: RegistryVersion::new(1),
        issued_at: UnixMillis::new(i64::from(fill)),
        root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
            .thumbprint(),
    }
}

fn revocation_core(release: &[u8], fill: u8) -> WebBundleRevocationCoreV1 {
    WebBundleRevocationCoreV1 {
        organization_id: support::organization(),
        release_object_hash: ea_crypto::object_hash(release),
        effective_from_registry_version: RegistryVersion::new(2),
        issued_at: UnixMillis::new(i64::from(fill)),
        root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
            .thumbprint(),
    }
}

fn foreign_root(fixture: &Fixture) -> FixtureTrustSigner {
    FixtureTrustSigner {
        seed: [0x99; 32],
        certificate_hash: fixture.root.certificate_hash,
    }
}

type Outcome = Result<WebBundleAdmission, WebBundleAdmissionError>;

fn admit(fixture: &Fixture, catalog: &[&[u8]], candidate: &[u8]) -> Outcome {
    verify_web_bundle_family_admission(&fixture.anchor, catalog, candidate)
}

fn release_named(outcome: &Outcome) -> Option<([u8; 32], bool)> {
    match outcome {
        Ok(WebBundleAdmission::Release {
            object_hash,
            carries_reader_key_escrow,
        }) => Some((*object_hash.as_bytes(), *carries_reader_key_escrow)),
        _ => None,
    }
}

fn revocation_named(outcome: &Outcome) -> Option<([u8; 32], [u8; 32])> {
    match outcome {
        Ok(WebBundleAdmission::Revocation {
            object_hash,
            release_object_hash,
        }) => Some((*object_hash.as_bytes(), *release_object_hash.as_bytes())),
        _ => None,
    }
}

fn error(outcome: Outcome) -> Option<WebBundleAdmissionError> {
    outcome.err()
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *ea_crypto::object_hash(bytes).as_bytes()
}

#[test]
fn a_root_signed_release_is_admitted_and_says_whether_it_carries_the_escrow() {
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x41),
        &fixture.root,
    );
    assert_eq!(
        release_named(&admit(&fixture, &[], &capable)),
        Some((hash(&capable), true))
    );
    // Eine ältere Fassung ist ein legitimer Rückzug — angenommen, aber nicht
    // fähig. Die Sperre entscheidet die Cutover-Regel, nicht die Annahme.
    let older = signed_web_bundle_release(&release_core("2026.3.1", 0x42), &fixture.root);
    assert_eq!(
        release_named(&admit(&fixture, &[&capable], &older)),
        Some((hash(&older), false))
    );
}

#[test]
fn a_candidate_already_in_the_catalog_is_admitted_again() {
    // Der Server legt den Kandidaten vor der Prüfung in seine Quelle; ein
    // erneutes Einreichen derselben Bytes bleibt annehmbar (idempotent).
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x43),
        &fixture.root,
    );
    assert_eq!(
        release_named(&admit(&fixture, &[&capable], &capable)),
        Some((hash(&capable), true))
    );
}

#[test]
fn a_release_under_a_foreign_root_key_is_refused_as_wrong_root() {
    let fixture = fixture();
    let foreign = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x44),
        &foreign_root(&fixture),
    );
    assert_eq!(
        error(admit(&fixture, &[], &foreign)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongRoot
        ))
    );
}

#[test]
fn a_release_naming_another_root_key_thumbprint_is_refused_as_wrong_root() {
    // Richtig signiert, aber der Core nennt einen anderen Wurzelabdruck.
    let fixture = fixture();
    let mut core = release_core(MIN_ESCROW_BUNDLE_VERSION, 0x45);
    core.root_key_thumbprint = support::device_signing_key([0x98; 32]).thumbprint();
    let mislabeled = signed_web_bundle_release(&core, &fixture.root);
    assert_eq!(
        error(admit(&fixture, &[], &mislabeled)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongRoot
        ))
    );
}

#[test]
fn a_release_of_a_foreign_organization_is_refused() {
    let fixture = fixture();
    let mut core = release_core(MIN_ESCROW_BUNDLE_VERSION, 0x46);
    core.organization_id = OrganizationId::try_from([0x0e; 16].as_slice()).unwrap();
    let foreign = signed_web_bundle_release(&core, &fixture.root);
    assert_eq!(
        error(admit(&fixture, &[], &foreign)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongOrganization
        ))
    );
}

#[test]
fn a_revocation_of_a_release_in_the_catalog_is_admitted() {
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x47),
        &fixture.root,
    );
    let revocation = signed_web_bundle_revocation(&revocation_core(&capable, 0x48), &fixture.root);
    assert_eq!(
        revocation_named(&admit(&fixture, &[&capable], &revocation)),
        Some((hash(&revocation), hash(&capable)))
    );
}

#[test]
fn a_revocation_without_its_release_in_the_catalog_is_refused() {
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x49),
        &fixture.root,
    );
    let revocation = signed_web_bundle_revocation(&revocation_core(&capable, 0x4a), &fixture.root);
    assert_eq!(
        error(admit(&fixture, &[], &revocation)),
        Some(WebBundleAdmissionError::UnknownRelease)
    );
    // Auch ein Objekt ANDERER Art unter dem genannten Hash ist keine Freigabe.
    let registry_object = fixture
        .line
        .exact_object_bytes(fixture.line.current_root_hash())
        .to_vec();
    let misdirected =
        signed_web_bundle_revocation(&revocation_core(&registry_object, 0x4b), &fixture.root);
    assert_eq!(
        error(admit(&fixture, &[&registry_object], &misdirected)),
        Some(WebBundleAdmissionError::UnknownRelease)
    );
}

#[test]
fn a_revocation_naming_another_root_key_thumbprint_is_refused_as_wrong_root() {
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x50),
        &fixture.root,
    );
    let mut core = revocation_core(&capable, 0x51);
    core.root_key_thumbprint = support::device_signing_key([0x98; 32]).thumbprint();
    let mislabeled = signed_web_bundle_revocation(&core, &fixture.root);
    assert_eq!(
        error(admit(&fixture, &[&capable], &mislabeled)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongRoot
        ))
    );
}

#[test]
fn a_revocation_under_a_foreign_root_key_is_refused() {
    let fixture = fixture();
    let capable = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x4c),
        &fixture.root,
    );
    let forged =
        signed_web_bundle_revocation(&revocation_core(&capable, 0x4d), &foreign_root(&fixture));
    assert_eq!(
        error(admit(&fixture, &[&capable], &forged)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongRoot
        ))
    );
}

#[test]
fn a_catalog_carrying_a_forged_bundle_object_refuses_every_candidate() {
    // Fail-closed wie der Reader-Pin: die Familie trägt nur als Ganzes.
    let fixture = fixture();
    let forged = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x4e),
        &foreign_root(&fixture),
    );
    let good = signed_web_bundle_release(
        &release_core(MIN_ESCROW_BUNDLE_VERSION, 0x4f),
        &fixture.root,
    );
    assert_eq!(
        error(admit(&fixture, &[&forged], &good)),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::WrongRoot
        ))
    );
}

#[test]
fn an_object_outside_the_bundle_family_is_not_admitted_here() {
    let fixture = fixture();
    let registry_object = fixture
        .line
        .exact_object_bytes(fixture.line.current_root_hash())
        .to_vec();
    assert_eq!(
        error(admit(&fixture, &[], &registry_object)),
        Some(WebBundleAdmissionError::NotBundleFamily)
    );
    assert_eq!(
        error(admit(&fixture, &[], b"not an exact object")),
        Some(WebBundleAdmissionError::Bundle(
            BundleRejectionCodeV1::Unsigned
        ))
    );
}
