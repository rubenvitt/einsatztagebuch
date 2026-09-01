//! Die Aktivierungsregel des Web-Bundles nach
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §4.2.
//!
//! Die eingefrorenen Bytes stammen aus `vectors/web-bundle/v1/object/`. Dieser
//! Test baut KEINE neuen Vektoren: die Familie ist seit Stufe 3 eingefroren,
//! und die Negativfaelle entstehen im Test, indem einzelne Bytes des positiven
//! Vektors gekippt oder Anker und Unterzeichner ausgetauscht werden.
//!
//! Der aktive Buendelhash wird ueber `as_bytes()` verglichen und nie direkt:
//! `Hash32` traegt bewusst KEIN `Debug` (`crates/ea-types/src/ids.rs`), also
//! uebersetzt `assert_eq!` auf `Option<Hash32>` nicht.
//!
//! # Ein Test je Fehlerpunkt
//!
//! `unsigned-candidate` und `foreign-root-candidate` sind zwei Abschnitte von
//! `docs/traceability/stage-4-fault-points.json` und brauchen deshalb zwei
//! VERSCHIEDENE, aufloesbare Testnamen. Eine Schleife ueber beide Faelle
//! lieferte nur einen Namen, und die Zeugenaufloesung des Stufengates
//! entdeckelte die Doppelung erst dort.

mod fixtures;

use ea_reader::{BundleActivationDecisionV1, BundleRejectionCodeV1, ReaderBundlePin};
use ea_types::RegistryVersion;

#[test]
fn a_root_signed_release_pins_its_bundle_hash_against_the_vault_anchor() {
    let release = fixtures::frozen_release_object();
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[release.as_slice()],
        RegistryVersion::new(6),
    )
    .unwrap();

    assert_eq!(
        pin.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::frozen_bundle_hash().as_bytes())
    );
    assert!(matches!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::Activate { .. }
    ));
    assert_eq!(
        pin.evaluate(fixtures::other_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::HashMismatch
        }
    );
}

#[test]
fn an_unsigned_release_never_pins_anything() {
    for bytes in [
        fixtures::release_without_signature(),
        fixtures::release_with_one_flipped_signature_byte(),
    ] {
        // Kein `unwrap_err`: `ReaderBundlePin` traegt kein `Debug`, weil
        // `Hash32` keins traegt.
        let Err(error) = ReaderBundlePin::from_trust_objects(
            &fixtures::vault_anchor(),
            &[bytes.as_slice()],
            RegistryVersion::new(6),
        ) else {
            panic!("eine Freigabe ohne tragende Signatur wird abgewiesen");
        };
        assert_eq!(error.code(), BundleRejectionCodeV1::Unsigned);
    }
}

#[test]
fn a_release_under_a_foreign_root_never_pins_anything() {
    let foreign = fixtures::release_signed_by_another_root();
    let Err(error) = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[foreign.as_slice()],
        RegistryVersion::new(6),
    ) else {
        panic!("eine fremd signierte Freigabe wird abgewiesen");
    };

    // NICHT `HashMismatch`: die Unterscheidung ist der ganze Punkt von §4.1.
    // Ein kompromittierter Sync-Server versuchte genau diesen Tausch, und ein
    // Code, der ihn als blosse Hashabweichung fuehrte, verstellte den Blick
    // auf den Angriff.
    assert_eq!(error.code(), BundleRejectionCodeV1::WrongRoot);
}

#[test]
fn a_release_of_a_foreign_organization_never_pins_anything() {
    let foreign = fixtures::release_of_a_foreign_organization();
    let Err(error) = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[foreign.as_slice()],
        RegistryVersion::new(6),
    ) else {
        panic!("eine Freigabe fremder Organisation wird abgewiesen");
    };

    // Ihre Signatur TRAEGT; abgewiesen wird sie allein wegen der Organisation.
    assert_eq!(error.code(), BundleRejectionCodeV1::WrongOrganization);
}

#[test]
fn a_revocation_withdraws_its_release_and_the_last_valid_version_stays_active() {
    let previous = fixtures::previous_release_object();
    let release = fixtures::frozen_release_object();
    let revocation = fixtures::frozen_revocation_object();

    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[
            previous.as_slice(),
            release.as_slice(),
            revocation.as_slice(),
        ],
        RegistryVersion::new(7),
    )
    .unwrap();

    // Der Widerruf nennt die Freigabe ausschliesslich ueber ihren Objekthash
    // und schreibt sie nie um; wirksam wird er ab seiner eigenen
    // Registry-Version.
    assert_eq!(
        pin.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::previous_bundle_hash().as_bytes())
    );
    assert_eq!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::Revoked
        }
    );

    // Vor der Wirksamkeit des Widerrufs bleibt die Freigabe gepinnt.
    let earlier = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[release.as_slice(), revocation.as_slice()],
        RegistryVersion::new(6),
    )
    .unwrap();
    assert_eq!(
        earlier.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::frozen_bundle_hash().as_bytes())
    );
}

#[test]
fn a_release_that_is_not_yet_effective_activates_nothing() {
    let release = fixtures::frozen_release_object();
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[release.as_slice()],
        RegistryVersion::new(5),
    )
    .unwrap();

    assert!(pin.active_bundle_hash().is_none());
    assert_eq!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::NotYetEffective
        }
    );
}

#[test]
fn an_empty_trust_store_activates_nothing_and_says_so() {
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[],
        RegistryVersion::new(6),
    )
    .unwrap();

    assert!(pin.active_bundle_hash().is_none());
    assert_eq!(
        pin.evaluate(fixtures::frozen_bundle_hash()),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::NoPinnedRelease
        }
    );
}

#[test]
fn an_object_of_another_subtype_is_passed_over_and_is_not_an_error() {
    // Ein fremder Subtyp gehoert einem ANDEREN Pruefweg und ist kein Fehler
    // dieses. Ein Objekt DIESER Familie, das seine Wurzelsignatur nicht
    // belegt, ist dagegen der Angriff, gegen den §4.1 gebaut ist — der
    // Unterschied zwischen Uebergehen und Abweisen ist normativ.
    let foreign = fixtures::foreign_subtype_trust_object();
    let release = fixtures::frozen_release_object();
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[foreign.as_slice(), release.as_slice()],
        RegistryVersion::new(6),
    )
    .unwrap();

    assert_eq!(
        pin.active_bundle_hash().map(|hash| *hash.as_bytes()),
        Some(*fixtures::frozen_bundle_hash().as_bytes())
    );
}

/// Der Browserlauf legt dem Service Worker Hexdateien vor. Sie stehen unter
/// `apps/web/tests/e2e/fixtures/` und muessen ZEICHENGLEICH das sein, was
/// diese Zeugen hier fahren.
///
/// Ohne diesen Pin maesse der Browserlauf still etwas anderes als die acht
/// Zeugen darueber — und die Abweichung faende niemand, weil beide Seiten fuer
/// sich gruen blieben. Die Richtung ist AUSDRUECKLICH die Pruefung und nicht
/// das Schreiben: ein Test, der seine Erwartung selbst erzeugt, belegt nichts.
#[test]
fn the_browser_fixtures_are_pinned_to_what_the_rust_witnesses_run() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/web/tests/e2e/fixtures");

    for (file, expected) in [
        ("vault-anchor.hex", fixtures::vault_anchor_exact_bytes()),
        ("accepted-release.hex", fixtures::browser_release_object()),
        (
            "accepted-revocation.hex",
            fixtures::browser_revocation_object(),
        ),
        ("pinned-bundle.hex", fixtures::browser_candidate_bundle()),
    ] {
        let pinned = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|error| panic!("{file} muss lesbar sein: {error}"));
        assert_eq!(
            pinned.trim(),
            hex::encode(&expected),
            "{file} ist nicht mehr das, was die Rust-Zeugen fahren"
        );
    }
}

/// Und die Freigabe des Browserlaufs geht gegen den ECHTEN Hash ihrer
/// Kandidatenfassung auf — anders als die eingefrorene, deren `bundle_hash`
/// eine Konstante ist, auf die kein reales Buendel hashen kann.
#[test]
fn the_browser_release_pins_the_real_hash_of_its_candidate() {
    let release = fixtures::browser_release_object();
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[release.as_slice()],
        RegistryVersion::new(6),
    )
    .unwrap();

    let candidate = fixtures::browser_candidate_bundle();
    assert!(matches!(
        pin.evaluate(ea_crypto::web_bundle_hash(&candidate)),
        BundleActivationDecisionV1::Activate { .. }
    ));

    // Ein einziges gekipptes Byte der Kandidatenfassung geht NICHT mehr auf.
    let mut tampered = candidate.clone();
    tampered[0] ^= 0x01;
    assert_eq!(
        pin.evaluate(ea_crypto::web_bundle_hash(&tampered)),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::HashMismatch
        }
    );
}

/// Der Widerruf des Browserlaufs entzieht GENAU seine Freigabe.
#[test]
fn the_browser_revocation_withdraws_the_browser_release() {
    let release = fixtures::browser_release_object();
    let revocation = fixtures::browser_revocation_object();
    let pin = ReaderBundlePin::from_trust_objects(
        &fixtures::vault_anchor(),
        &[release.as_slice(), revocation.as_slice()],
        RegistryVersion::new(7),
    )
    .unwrap();

    assert!(pin.active_bundle_hash().is_none());
    assert_eq!(
        pin.evaluate(ea_crypto::web_bundle_hash(
            &fixtures::browser_candidate_bundle()
        )),
        BundleActivationDecisionV1::KeepActive {
            code: BundleRejectionCodeV1::Revoked
        }
    );
}
