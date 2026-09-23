//! Die native Root-Zeremonie der Bundle-Familie (v1.1-Profil §1.3 U4, §5;
//! Scheibe f): `webBundleRelease` und `webBundleRevocation`.
//!
//! Gezeigt über den Fixture-Eingang (nur `test-support`) gegen eine echte
//! Trust-Linie: Reauthentifizierung am Kontexthash der Nutzlast, Root-Signatur,
//! Selbstprüfung über den Einstieg der Serverannahme, erst dann die Datei.
//! Die Laufzeit-Hülle (Rolle, Zweck, Autoritätswirt) bezeugt der CLI-Zeuge.
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use std::cell::RefCell;

use ea_admin::web_bundle_release::{
    PublishedWebBundleObject, WebBundleCeremonyContext, WebBundleRequest,
    publish_web_bundle_object_in_context,
};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, trust_digest};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject};
use ea_recovery::ReaderKeyEscrowError;
use ea_trust::{
    EscrowCutoverError, MIN_ESCROW_BUNDLE_VERSION, SelectedRegistryHead, TrustAnchorV1,
    TrustObjectSource, decode_trust_anchor, reader_key_escrow_cutover_release,
};
use ea_types::{CertificateHash, Hash32, ObjectHash, RegistryVersion, UnixMillis};
use ed25519_dalek::{Signer as _, SigningKey};
use escrow_support::{EscrowLineOptions, escrow_line, push_filler, select, tip_sequence};

const NOW: i64 = 1_500;

fn trust_digest_cose(seed: [u8; 32], certificate: CertificateHash, digest: Hash32) -> Vec<u8> {
    let key = SigningKey::from_bytes(&seed);
    let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes()).unwrap();
    let protected =
        ProtectedHeader::normal(ContentType::TrustDigest, public.thumbprint(), certificate);
    let signature = key.sign(&protected.sig_structure_bytes(digest.as_bytes()));
    let mut bytes = vec![0xd2, 0x84];
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder.bytes(&protected.to_deterministic_cbor()).unwrap();
    encoder.map(0).unwrap();
    encoder.bytes(digest.as_bytes()).unwrap();
    encoder.bytes(&signature.to_bytes()).unwrap();
    bytes
}

/// Eine Linie mit ein paar Köpfen, ihr Anker, der gewählte letzte Kopf und
/// die exakten Trust-Objekte des Bestands.
struct Line {
    anchor: TrustAnchorV1,
    head: SelectedRegistryHead,
    catalog: Vec<Vec<u8>>,
}

fn line() -> Line {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    push_filler(&mut escrow.line);
    let (_, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let source = escrow.line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .unwrap();
    let catalog = hashes
        .into_iter()
        .map(|hash| {
            source
                .read_exact_trust_object(hash)
                .unwrap()
                .unwrap()
                .to_vec()
        })
        .collect();
    Line {
        anchor: decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap(),
        head,
        catalog,
    }
}

/// Was die Zeremonie nach außen getan hat.
#[derive(Default)]
struct Effects {
    reauthenticated_at: RefCell<Vec<Hash32>>,
    written: RefCell<Vec<Vec<u8>>>,
}

struct Knobs {
    reauth_fails: bool,
    head_moved: bool,
    root_seed: [u8; 32],
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            reauth_fails: false,
            head_moved: false,
            root_seed: support::root_signing_secret(),
        }
    }
}

fn run(
    line: &Line,
    request: WebBundleRequest,
    knobs: &Knobs,
    effects: &Effects,
) -> Result<PublishedWebBundleObject, ReaderKeyEscrowError> {
    let catalog: Vec<&[u8]> = line.catalog.iter().map(Vec::as_slice).collect();
    let reauthenticate = |context: Hash32| {
        effects.reauthenticated_at.borrow_mut().push(context);
        if knobs.reauth_fails {
            Err(ReaderKeyEscrowError::Operator)
        } else {
            Ok(())
        }
    };
    let root_sign = |certificate: CertificateHash, digest: Hash32| {
        Ok(trust_digest_cose(knobs.root_seed, certificate, digest))
    };
    let session_current = || {
        if knobs.head_moved {
            Err(ReaderKeyEscrowError::Operator)
        } else {
            Ok(())
        }
    };
    let write = |bytes: &[u8]| {
        effects.written.borrow_mut().push(bytes.to_vec());
        Ok(())
    };
    publish_web_bundle_object_in_context(
        &WebBundleCeremonyContext {
            anchor: &line.anchor,
            head: &line.head,
            catalog: &catalog,
            reauthenticate: &reauthenticate,
            root_sign: &root_sign,
            session_current: &session_current,
            write: &write,
            now: UnixMillis::new(NOW),
        },
        request,
    )
}

fn release_request(version: &str, effective_from: Option<u64>) -> WebBundleRequest {
    WebBundleRequest::Release {
        bundle_hash: Hash32::try_from([0x5a; 32].as_slice()).unwrap(),
        bundle_version: version.to_owned(),
        effective_from: effective_from.map(RegistryVersion::new),
    }
}

fn code<T>(result: Result<T, ReaderKeyEscrowError>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

fn payload_digest(exact: &[u8]) -> Hash32 {
    let Ok(ParsedArchiveObject::Trust(parsed)) = ea_format::decode_exact_object(exact) else {
        panic!("a trust object");
    };
    trust_digest(parsed.value().exact_digest_input())
}

/// Positivpfad: ein v1.1-fähiges Release wird wurzelsigniert, geprüft und als
/// Datei geschrieben; die Cutover-Regel nennt genau diese Freigabe.
#[test]
fn a_capable_release_is_root_signed_written_and_opens_the_cutover() {
    let line = line();
    let effects = Effects::default();
    let published = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, None),
        &Knobs::default(),
        &effects,
    )
    .unwrap();
    assert_eq!(published.carries_reader_key_escrow, Some(true));
    let written = effects.written.borrow();
    assert_eq!(written.len(), 1, "exactly one file");
    assert_eq!(written[0], published.exact_bytes);
    assert!(published.object_hash == ea_crypto::object_hash(&written[0]));
    // Reauthentifiziert am Kontexthash GENAU dieser Nutzlast.
    let contexts: Vec<[u8; 32]> = effects
        .reauthenticated_at
        .borrow()
        .iter()
        .map(|hash| *hash.as_bytes())
        .collect();
    assert_eq!(contexts, [*payload_digest(&written[0]).as_bytes()]);
    // Standard für effective-from ist die Kopfversion.
    let Ok(ParsedArchiveObject::Trust(parsed)) = ea_format::decode_exact_object(&written[0]) else {
        panic!("a trust object");
    };
    let Ok(DecodedTrustPayloadV1::WebBundleRelease(core)) = parsed.value().decoded_payload() else {
        panic!("a release");
    };
    assert!(core.effective_from_registry_version == line.head.registry_version());
    assert!(core.organization_id == line.anchor.organization_id());
    assert!(core.root_key_thumbprint == line.anchor.root_key_thumbprint());
    assert_eq!(core.issued_at.get(), NOW);

    let mut objects: Vec<&[u8]> = line.catalog.iter().map(Vec::as_slice).collect();
    objects.push(&written[0]);
    assert_eq!(
        reader_key_escrow_cutover_release(&line.anchor, &objects, line.head.registry_version())
            .map(|hash: ObjectHash| *hash.as_bytes()),
        Ok(*published.object_hash.as_bytes())
    );
}

/// Eine ältere Fassung ist ein legitimer Rückzug: geschrieben, aber nicht fähig.
#[test]
fn an_older_release_is_written_but_named_incapable() {
    let line = line();
    let effects = Effects::default();
    let published = run(
        &line,
        release_request("2026.3.1", None),
        &Knobs::default(),
        &effects,
    )
    .unwrap();
    assert_eq!(published.carries_reader_key_escrow, Some(false));
    assert_eq!(effects.written.borrow().len(), 1);
}

/// Der Widerruf der eben geschriebenen Freigabe schließt die Sperre wieder.
#[test]
fn a_revocation_of_a_catalog_release_shuts_the_cutover() {
    let mut line = line();
    let effects = Effects::default();
    let release = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, None),
        &Knobs::default(),
        &effects,
    )
    .unwrap();
    line.catalog.push(release.exact_bytes.clone());
    let revocation = run(
        &line,
        WebBundleRequest::Revocation {
            release_object_hash: release.object_hash,
            effective_from: None,
        },
        &Knobs::default(),
        &effects,
    )
    .unwrap();
    assert_eq!(revocation.carries_reader_key_escrow, None);
    line.catalog.push(revocation.exact_bytes.clone());
    let objects: Vec<&[u8]> = line.catalog.iter().map(Vec::as_slice).collect();
    assert_eq!(
        reader_key_escrow_cutover_release(&line.anchor, &objects, line.head.registry_version())
            .map(|hash: ObjectHash| *hash.as_bytes()),
        Err(EscrowCutoverError::NoActiveRelease)
    );
    assert_eq!(effects.written.borrow().len(), 2);
}

/// Ein Widerruf einer Freigabe, die nicht im Bestand liegt, wird nicht
/// geschrieben — dieselbe Regel wie bei der Serverannahme.
#[test]
fn a_revocation_of_an_unknown_release_writes_nothing() {
    let line = line();
    let effects = Effects::default();
    let result = run(
        &line,
        WebBundleRequest::Revocation {
            release_object_hash: ObjectHash::try_from([0x77; 32].as_slice()).unwrap(),
            effective_from: None,
        },
        &Knobs::default(),
        &effects,
    );
    assert_eq!(code(result), "EA-TRUST-ACTION-MISMATCH");
    assert!(effects.written.borrow().is_empty());
}

/// Rückdatierung unter die Kopfversion würde die historische Sperre für
/// ältere Freigaben rückwirkend öffnen: abgewiesen, bevor reauthentifiziert
/// oder signiert wird.
#[test]
fn a_backdated_effective_from_is_refused_before_reauthentication() {
    let line = line();
    let effects = Effects::default();
    let backdated = line.head.registry_version().get() - 1;
    let result = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, Some(backdated)),
        &Knobs::default(),
        &effects,
    );
    assert_eq!(code(result), "EA-TRUST-ACTION-MISMATCH");
    assert!(effects.reauthenticated_at.borrow().is_empty());
    assert!(effects.written.borrow().is_empty());
    // Ein späterer Stand ist erlaubt.
    let later = line.head.registry_version().get() + 1;
    assert_eq!(
        code(run(
            &line,
            release_request(MIN_ESCROW_BUNDLE_VERSION, Some(later)),
            &Knobs::default(),
            &effects,
        )),
        "OK"
    );
}

/// Scheitert die frische Reauthentifizierung, wird nichts signiert und
/// nichts geschrieben.
#[test]
fn a_failing_reauthentication_writes_nothing() {
    let line = line();
    let effects = Effects::default();
    let result = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, None),
        &Knobs {
            reauth_fails: true,
            ..Knobs::default()
        },
        &effects,
    );
    assert_eq!(code(result), "EA-ESCROW-OPERATOR-UNAUTHORIZED");
    assert!(effects.written.borrow().is_empty());
}

/// Bewegt sich der Kopf zwischen Signatur und Schreiben, bleibt die Datei aus.
#[test]
fn a_moved_head_before_the_write_writes_nothing() {
    let line = line();
    let effects = Effects::default();
    let result = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, None),
        &Knobs {
            head_moved: true,
            ..Knobs::default()
        },
        &effects,
    );
    assert_eq!(code(result), "EA-ESCROW-OPERATOR-UNAUTHORIZED");
    assert!(effects.written.borrow().is_empty());
}

/// Signiert der Wurzel-Slot mit einem fremden Schlüssel, fängt die
/// Selbstprüfung das vor dem Schreiben.
#[test]
fn a_signature_under_a_foreign_root_key_writes_nothing() {
    let line = line();
    let effects = Effects::default();
    let result = run(
        &line,
        release_request(MIN_ESCROW_BUNDLE_VERSION, None),
        &Knobs {
            root_seed: [0x99; 32],
            ..Knobs::default()
        },
        &effects,
    );
    assert_eq!(code(result), "EA-TRUST-ACTION-MISMATCH");
    assert!(effects.written.borrow().is_empty());
}
