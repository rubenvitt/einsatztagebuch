//! RFC-9421-Abdeckung, Signierer/Pruefer-Round-Trip und jeder unterscheidbare
//! Fehlerfall des Request-Pruefers.
//!
//! Jeder negative Fall wird ueber seinen STABILEN Code verglichen, nicht ueber
//! `is_err()`: ein Pruefer, der zwei verschiedene Verstoesse auf denselben Code
//! abbildet, waere von einem `is_err()`-Test nicht zu unterscheiden.

use ea_sync_protocol::{AuthenticatedDevice, EndpointAuthentication, EndpointV1};

mod fixtures {
    use std::collections::BTreeSet;

    use ea_crypto::{CertificateCapability, SecretBytes};
    use ea_sync_protocol::{
        DeviceDirectory, EndpointV1, RegisteredDevice, ReplayStore, RequestIdV1, RequestParts,
        RequestSigner, RequestVerifier, SignatureParametersV1, SignedRequestV1, body_digest,
        organization_tag,
    };
    use ea_types::{CertificateHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId};

    pub const AUTHORITY: &str = "sync.einsatzarchiv.example";
    pub const NOW: i64 = 1_800_000_000;

    #[must_use]
    pub fn organization() -> OrganizationId {
        OrganizationId::try_from([0x11; 16].as_slice()).unwrap()
    }

    #[must_use]
    pub fn writer() -> RequestSigner {
        RequestSigner::from_secret(SecretBytes::new([0x21; 32]))
    }

    /// Der beantragte, noch nicht freigegebene Geraeteschluessel.
    #[must_use]
    pub fn requested() -> RequestSigner {
        RequestSigner::from_secret(SecretBytes::new([0x22; 32]))
    }

    /// Ein Schluessel, den die Geraeteliste des Servers nicht kennt.
    #[must_use]
    pub fn foreign() -> RequestSigner {
        RequestSigner::from_secret(SecretBytes::new([0x23; 32]))
    }

    #[must_use]
    pub fn certificate_hash() -> CertificateHash {
        CertificateHash::from(ObjectHash::from(
            Hash32::try_from([0x31; 32].as_slice()).unwrap(),
        ))
    }

    pub struct Directory(Vec<RegisteredDevice>);

    impl DeviceDirectory for Directory {
        fn lookup(&self, key_thumbprint: KeyThumbprint) -> Option<RegisteredDevice> {
            self.0
                .iter()
                .find(|device| device.key_thumbprint() == key_thumbprint)
                .cloned()
        }
    }

    fn registered(
        organization_id: OrganizationId,
        capabilities: Vec<CertificateCapability>,
    ) -> Directory {
        Directory(vec![RegisteredDevice::new(
            organization_id,
            certificate_hash(),
            writer().public_key(),
            capabilities,
        )])
    }

    /// Die Geraeteliste kennt genau den Writer, mit allen Faehigkeiten, die die
    /// Endpunkte dieser Stufe verlangen.
    #[must_use]
    pub fn directory() -> Directory {
        registered(
            organization(),
            vec![
                CertificateCapability::InitialGrant,
                CertificateCapability::HistoricalGrant,
                CertificateCapability::OrganizationAdminApprove,
                CertificateCapability::DestructionApprove,
                CertificateCapability::DeletionAttest,
                CertificateCapability::ServerReceipt,
            ],
        )
    }

    /// Dieselbe Identitaet, dieselbe Organisation, aber ohne jede Faehigkeit.
    #[must_use]
    pub fn directory_without_capabilities() -> Directory {
        registered(organization(), Vec::new())
    }

    /// Dieselbe Identitaet in einer FREMDEN Organisation.
    #[must_use]
    pub fn directory_of_another_organization() -> Directory {
        registered(
            OrganizationId::try_from([0x99; 16].as_slice()).unwrap(),
            vec![CertificateCapability::InitialGrant],
        )
    }

    #[derive(Default)]
    pub struct MemoryReplayStore {
        nonces: BTreeSet<[u8; 32]>,
        request_ids: BTreeSet<[u8; 16]>,
    }

    impl ReplayStore for MemoryReplayStore {
        fn claim_nonce(&mut self, nonce: &[u8; 32]) -> bool {
            self.nonces.insert(*nonce)
        }

        fn claim_request_id(&mut self, request_id: RequestIdV1) -> bool {
            self.request_ids.insert(*request_id.as_bytes())
        }
    }

    #[must_use]
    pub fn nonce_store() -> MemoryReplayStore {
        MemoryReplayStore::default()
    }

    /// Der Pruefer dieses Tests: Autoritaet, Organisation und Serverzeit stehen
    /// fest, die Geraeteliste wechselt je Fall.
    #[must_use]
    pub fn verifier(endpoint: EndpointV1, directory: &Directory) -> RequestVerifier<'_> {
        RequestVerifier::new(endpoint, AUTHORITY, organization(), NOW, directory)
    }

    /// Ein konkreter Pfad je Endpunkt — die Platzhalter der Vorlage sind mit
    /// wohlgeformten Werten belegt.
    #[must_use]
    pub fn path(endpoint: EndpointV1) -> String {
        const CHAIN: &str = "11111111111111111111111111111111";
        const HASH: &str = "3131313131313131313131313131313131313131313131313131313131313131";
        const DESTRUCTION: &str = "51515151515151515151515151515151";
        endpoint
            .path_template()
            .replace("{chainId}", CHAIN)
            .replace("{objectHash}", HASH)
            .replace("{entryHash}", HASH)
            .replace("{destructionId}", DESTRUCTION)
    }

    #[must_use]
    pub fn request_id(seed: u8) -> RequestIdV1 {
        RequestIdV1::try_from([seed; 16].as_slice()).unwrap()
    }

    #[must_use]
    pub fn parts(endpoint: EndpointV1, nonce: u8) -> RequestParts {
        RequestParts {
            method: endpoint.method(),
            authority: AUTHORITY.to_owned(),
            target_uri: format!("https://{AUTHORITY}{}", path(endpoint)),
            content_type: endpoint.request_media_type().map(str::to_owned),
            body_digest: endpoint.request_media_type().map(|_| body_digest(b"body")),
            request_id: request_id(nonce),
        }
    }

    #[must_use]
    pub fn parameters(nonce: u8, tag: String) -> SignatureParametersV1 {
        SignatureParametersV1::new(NOW - 10, NOW + 110, [nonce; 32], tag)
    }

    #[must_use]
    pub fn signed(signer: &RequestSigner, endpoint: EndpointV1, nonce: u8) -> SignedRequestV1 {
        signed_with_tag(signer, endpoint, nonce, organization_tag(organization()))
    }

    #[must_use]
    pub fn signed_with_tag(
        signer: &RequestSigner,
        endpoint: EndpointV1,
        nonce: u8,
        tag: String,
    ) -> SignedRequestV1 {
        signer
            .sign(&parts(endpoint, nonce), &parameters(nonce, tag))
            .unwrap()
    }

    /// Serialisiert den Request in seine Header und liest ihn wieder ein — der
    /// Weg, den auch der Servertransport nimmt.
    #[must_use]
    pub fn reparse(signed: &SignedRequestV1, signature_input: &str) -> SignedRequestV1 {
        SignedRequestV1::parse(
            &signed.to_received(),
            signature_input,
            &signed.signature_header(),
        )
        .unwrap()
    }

    /// Schreibt die abgedeckte Komponentenliste eines `Signature-Input`-Headers
    /// neu. Der Weg ueber die Liste statt ueber `replace` trifft auch die erste
    /// Komponente, vor der kein Leerzeichen steht.
    fn rewrite_covered_list(header: &str, rewrite: impl Fn(Vec<String>) -> Vec<String>) -> String {
        let (prefix, rest) = header.split_once('(').unwrap();
        let (list, suffix) = rest.split_once(')').unwrap();
        let rewritten = rewrite(list.split(' ').map(str::to_owned).collect());
        format!("{prefix}({}){suffix}", rewritten.join(" "))
    }

    /// Ein signierter Commit-Request, dessen `Signature-Input` `component`
    /// nicht mehr nennt.
    #[must_use]
    pub fn signed_commit_missing(component: &str) -> SignedRequestV1 {
        let signed = signed(&writer(), EndpointV1::EntryCommits, 1);
        let quoted = format!("\"{component}\"");
        let header = rewrite_covered_list(&signed.signature_input_header(), |items| {
            items.into_iter().filter(|item| *item != quoted).collect()
        });
        reparse(&signed, &header)
    }

    /// Ein signierter Commit-Request, dessen `Signature-Input` `component`
    /// zweimal nennt.
    #[must_use]
    pub fn signed_commit_duplicating(component: &str) -> SignedRequestV1 {
        let signed = signed(&writer(), EndpointV1::EntryCommits, 1);
        let quoted = format!("\"{component}\"");
        let header = rewrite_covered_list(&signed.signature_input_header(), |items| {
            let mut duplicated = Vec::with_capacity(items.len() + 1);
            for item in items {
                let repeat = item == quoted;
                duplicated.push(item);
                if repeat {
                    duplicated.push(quoted.clone());
                }
            }
            duplicated
        });
        reparse(&signed, &header)
    }

    /// Derselbe signierte Request, aber der Transport hat andere Bytes
    /// empfangen, als der `content-digest`-Header behauptet.
    #[must_use]
    pub fn signed_commit_with_other_body() -> SignedRequestV1 {
        let signed = signed(&writer(), EndpointV1::EntryCommits, 2);
        let mut received = signed.to_received();
        received.body_digest = Some(body_digest(b"andere bytes"));
        SignedRequestV1::parse(
            &received,
            &signed.signature_input_header(),
            &signed.signature_header(),
        )
        .unwrap()
    }

    /// Ein Request, der eine fremde Autoritaet nennt und ueber sie signiert.
    #[must_use]
    pub fn signed_commit_at_authority(authority: &str) -> SignedRequestV1 {
        let mut parts = parts(EndpointV1::EntryCommits, 3);
        parts.target_uri = format!("https://{authority}{}", path(EndpointV1::EntryCommits));
        parts.authority = authority.to_owned();
        writer()
            .sign(&parts, &parameters(3, organization_tag(organization())))
            .unwrap()
    }

    /// Ein Request, dessen Ziel-URI auf einen anderen Endpunkt zeigt.
    #[must_use]
    pub fn signed_commit_at_path(path: &str) -> SignedRequestV1 {
        let mut parts = parts(EndpointV1::EntryCommits, 4);
        parts.target_uri = format!("https://{AUTHORITY}{path}");
        writer()
            .sign(&parts, &parameters(4, organization_tag(organization())))
            .unwrap()
    }

    #[must_use]
    pub fn expired_commit() -> SignedRequestV1 {
        writer()
            .sign(
                &parts(EndpointV1::EntryCommits, 12),
                &SignatureParametersV1::new(
                    NOW - 200,
                    NOW - 100,
                    [12; 32],
                    organization_tag(organization()),
                ),
            )
            .unwrap()
    }

    /// `created` liegt DICHT VOR der Toleranzgrenze — eine leicht vorgehende
    /// Geraeteuhr, die der Pruefer noch annimmt.
    #[must_use]
    pub fn commit_created_just_inside_the_skew() -> SignedRequestV1 {
        writer()
            .sign(
                &parts(EndpointV1::EntryCommits, 30),
                &SignatureParametersV1::new(
                    NOW + 59,
                    NOW + 59 + ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1,
                    [30; 32],
                    organization_tag(organization()),
                ),
            )
            .unwrap()
    }

    /// `created` liegt JENSEITS der Toleranzgrenze — eine Uhr, der der
    /// Pruefer nicht mehr folgt.
    #[must_use]
    pub fn commit_created_beyond_the_skew() -> SignedRequestV1 {
        writer()
            .sign(
                &parts(EndpointV1::EntryCommits, 31),
                &SignatureParametersV1::new(
                    NOW + 61,
                    NOW + 61 + ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1,
                    [31; 32],
                    organization_tag(organization()),
                ),
            )
            .unwrap()
    }

    /// `expires` liegt jenseits des festgeschriebenen Fensters.
    #[must_use]
    pub fn commit_with_unbounded_window() -> SignedRequestV1 {
        writer()
            .sign(
                &parts(EndpointV1::EntryCommits, 13),
                &SignatureParametersV1::new(
                    NOW - 10,
                    NOW + 86_400,
                    [13; 32],
                    organization_tag(organization()),
                ),
            )
            .unwrap()
    }

    #[must_use]
    pub fn commit_with_request_id(nonce: u8, request_id: RequestIdV1) -> SignedRequestV1 {
        let mut parts = parts(EndpointV1::EntryCommits, nonce);
        parts.request_id = request_id;
        writer()
            .sign(&parts, &parameters(nonce, organization_tag(organization())))
            .unwrap()
    }

    /// Der Transport hat die Nonce nach dem Signieren ausgetauscht: die
    /// Signaturbasis passt nicht mehr zu den Signaturparametern.
    #[must_use]
    pub fn commit_with_swapped_nonce() -> SignedRequestV1 {
        let signed = signed(&writer(), EndpointV1::EntryCommits, 14);
        let header = signed
            .signature_input_header()
            .replace(&hex::encode([14u8; 32]), &hex::encode([15u8; 32]));
        reparse(&signed, &header)
    }
}

use fixtures::AUTHORITY;

#[test]
fn body_request_requires_every_covered_component() {
    let request = fixtures::signed_commit_missing("content-digest");
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap_err()
            .code(),
        "EA-HTTP-SIGNATURE-COVERAGE"
    );
}

#[test]
fn signer_and_verifier_round_trip_every_signed_endpoint_through_the_wire_headers() {
    let directory = fixtures::directory();
    let mut store = fixtures::nonce_store();
    let mut round_trips = 0;
    for (index, endpoint) in EndpointV1::ALL.into_iter().enumerate() {
        if endpoint.authentication() != EndpointAuthentication::Signed {
            continue;
        }
        let nonce = u8::try_from(index).unwrap();
        let signed = fixtures::signed(&fixtures::writer(), endpoint, nonce);
        let received = fixtures::reparse(&signed, &signed.signature_input_header());
        let device = fixtures::verifier(endpoint, &directory)
            .verify(&received, &mut store)
            .unwrap_or_else(|error| panic!("{}: {}", endpoint.path_template(), error.code()));
        match device {
            AuthenticatedDevice::Certified {
                organization_id,
                certificate_hash,
                ..
            } => {
                assert_eq!(
                    organization_id.as_bytes(),
                    fixtures::organization().as_bytes()
                );
                assert_eq!(
                    certificate_hash.as_bytes(),
                    fixtures::certificate_hash().as_bytes()
                );
            }
            AuthenticatedDevice::ProofOfPossession { .. } => panic!(
                "{} must not yield a proof of possession",
                endpoint.path_template()
            ),
        }
        round_trips += 1;
    }
    assert_eq!(
        round_trips, 14,
        "fourteen of the seventeen endpoints are RFC-9421 signed"
    );
}

#[test]
fn device_registration_yields_proof_of_possession_without_organization_authority() {
    let requested = fixtures::requested();
    let request = fixtures::signed(&requested, EndpointV1::DeviceRegistrations, 7);
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::DeviceRegistrations, &directory)
            .with_requested_key(requested.public_key())
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap(),
        AuthenticatedDevice::ProofOfPossession {
            requested_key: requested.key_thumbprint()
        }
    );
    // Ohne den beantragten Schluessel aus dem Koerper gibt es keine
    // Identitaet — der Pfad besteht nicht still.
    assert_eq!(
        fixtures::verifier(EndpointV1::DeviceRegistrations, &directory)
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap_err()
            .code(),
        "EA-HTTP-KEY-UNRESOLVED"
    );
    // Ein anderer beantragter Schluessel als der signierende ebenfalls nicht.
    assert_eq!(
        fixtures::verifier(EndpointV1::DeviceRegistrations, &directory)
            .with_requested_key(fixtures::foreign().public_key())
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap_err()
            .code(),
        "EA-HTTP-KEY-UNRESOLVED"
    );
}

#[test]
fn the_requested_key_is_rejected_on_every_other_endpoint() {
    let requested = fixtures::requested();
    let directory = fixtures::directory();
    let mut rejected = 0;
    for (index, endpoint) in EndpointV1::ALL.into_iter().enumerate() {
        if endpoint.authentication() != EndpointAuthentication::Signed {
            continue;
        }
        let request = fixtures::signed(&requested, endpoint, u8::try_from(index).unwrap());
        let error = fixtures::verifier(endpoint, &directory)
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap_err();
        assert_eq!(
            error.code(),
            "EA-HTTP-KEY-UNRESOLVED",
            "{}",
            endpoint.path_template()
        );
        assert_eq!(error.http_status(), 401, "{}", endpoint.path_template());
        rejected += 1;
    }
    assert_eq!(rejected, 14);
}

#[test]
fn absent_and_duplicate_components_fail_with_distinct_codes() {
    let directory = fixtures::directory();
    for component in [
        "@method",
        "@authority",
        "@target-uri",
        "content-type",
        "content-digest",
    ] {
        assert_eq!(
            fixtures::verifier(EndpointV1::EntryCommits, &directory)
                .verify(
                    &fixtures::signed_commit_missing(component),
                    &mut fixtures::nonce_store()
                )
                .unwrap_err()
                .code(),
            "EA-HTTP-SIGNATURE-COVERAGE",
            "{component}"
        );
        assert_eq!(
            fixtures::verifier(EndpointV1::EntryCommits, &directory)
                .verify(
                    &fixtures::signed_commit_duplicating(component),
                    &mut fixtures::nonce_store()
                )
                .unwrap_err()
                .code(),
            "EA-HTTP-SIGNATURE-DUPLICATE-COMPONENT",
            "{component}"
        );
    }
}

#[test]
fn a_wrong_content_digest_fails_closed() {
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::signed_commit_with_other_body(),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-CONTENT-DIGEST"
    );
}

#[test]
fn a_foreign_authority_and_a_foreign_target_uri_fail_with_distinct_codes() {
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::signed_commit_at_authority("angreifer.example"),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-AUTHORITY-MISMATCH"
    );
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::signed_commit_at_path("/v1/checkpoints"),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-TARGET-URI-MISMATCH"
    );
}

#[test]
fn a_tag_of_another_organization_fails_closed() {
    let directory = fixtures::directory();
    let other = ea_types::OrganizationId::try_from([0x99; 16].as_slice()).unwrap();
    let request = fixtures::signed_with_tag(
        &fixtures::writer(),
        EndpointV1::EntryCommits,
        3,
        ea_sync_protocol::organization_tag(other),
    );
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(&request, &mut fixtures::nonce_store())
            .unwrap_err()
            .code(),
        "EA-HTTP-TAG-MISMATCH"
    );
}

#[test]
fn an_expired_request_and_an_unbounded_window_fail_with_distinct_codes() {
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(&fixtures::expired_commit(), &mut fixtures::nonce_store())
            .unwrap_err()
            .code(),
        "EA-HTTP-REQUEST-EXPIRED"
    );
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::commit_with_unbounded_window(),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-WINDOW-INVALID"
    );
}

/// Der Pruefer toleriert eine begrenzt vorgehende Uhr — und nur die.
///
/// Ohne Toleranz faellt ein Schreiber, dessen Uhr eine Sekunde vorgeht, mit
/// JEDEM signierten Request auf `401`, und der Klient fuehrt `401` als nicht
/// automatisch wiederholbar: aus einer Sekunde Drift wuerde ein harter
/// Betriebsausfall. Beide Seiten der Grenze stehen hier, weil eine Toleranz
/// ohne obere Kante keine Toleranz mehr waere, sondern ein offenes Fenster.
#[test]
fn a_bounded_forward_clock_skew_is_tolerated_and_anything_beyond_it_is_not() {
    let directory = fixtures::directory();
    fixtures::verifier(EndpointV1::EntryCommits, &directory)
        .verify(
            &fixtures::commit_created_just_inside_the_skew(),
            &mut fixtures::nonce_store(),
        )
        .expect("a clock 59 seconds ahead is a running device, not an attack");
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::commit_created_beyond_the_skew(),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-WINDOW-INVALID"
    );
    // Die Toleranz ist in MILLISEKUNDEN geschrieben und wird in SEKUNDEN
    // verglichen; ohne diese Zeile faenge kein Zeuge den Einheitenfehler.
    assert_eq!(ea_sync_protocol::MAX_CLOCK_SKEW_MS_V1, 60_000);
}

#[test]
fn nonce_and_request_id_are_each_single_use_and_fail_with_distinct_codes() {
    let directory = fixtures::directory();
    let mut store = fixtures::nonce_store();
    let first = fixtures::signed(&fixtures::writer(), EndpointV1::EntryCommits, 5);
    fixtures::verifier(EndpointV1::EntryCommits, &directory)
        .verify(&first, &mut store)
        .unwrap();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(&first, &mut store)
            .unwrap_err()
            .code(),
        "EA-HTTP-NONCE-REPLAY"
    );
    // Frische Nonce, verbrauchte Request-ID: nur getrennte Einmalspeicher
    // machen die beiden Codes unterscheidbar.
    let replayed = fixtures::commit_with_request_id(6, fixtures::request_id(5));
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(&replayed, &mut store)
            .unwrap_err()
            .code(),
        "EA-HTTP-REQUEST-ID-REPLAY"
    );
}

#[test]
fn an_unknown_certificate_a_missing_capability_and_a_foreign_organization_fail_distinctly() {
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::signed(&fixtures::foreign(), EndpointV1::EntryCommits, 8),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-KEY-UNRESOLVED"
    );
    let without_capabilities = fixtures::directory_without_capabilities();
    assert_eq!(
        fixtures::verifier(EndpointV1::HistoricalGrants, &without_capabilities)
            .verify(
                &fixtures::signed(&fixtures::writer(), EndpointV1::HistoricalGrants, 9),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-CAPABILITY-MISSING"
    );
    let other_organization = fixtures::directory_of_another_organization();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &other_organization)
            .verify(
                &fixtures::signed(&fixtures::writer(), EndpointV1::EntryCommits, 10),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-ORGANIZATION-MISMATCH"
    );
}

#[test]
fn a_tampered_signature_base_fails_as_an_invalid_signature() {
    let directory = fixtures::directory();
    assert_eq!(
        fixtures::verifier(EndpointV1::EntryCommits, &directory)
            .verify(
                &fixtures::commit_with_swapped_nonce(),
                &mut fixtures::nonce_store()
            )
            .unwrap_err()
            .code(),
        "EA-HTTP-SIGNATURE-INVALID"
    );
}

#[test]
fn the_signature_base_is_built_exactly_as_rfc_9421_prescribes() {
    let signed = fixtures::signed(&fixtures::writer(), EndpointV1::EntryCommits, 11);
    let base = signed.signature_base();
    assert!(base.starts_with("\"@method\": POST\n"));
    assert!(base.contains(&format!("\"@authority\": {AUTHORITY}\n")));
    assert!(base.contains("\"@signature-params\": ("));
    assert!(base.contains(";alg=\"ed25519\";"));
    assert!(!base.ends_with('\n'));
    let digest_header = signed.content_digest_header().unwrap();
    assert!(digest_header.starts_with("sha-256=:"));
    assert!(digest_header.ends_with(':'));
    // 32 Byte SHA-256 werden zu 44 Base64-Zeichen mit einem Fuellzeichen.
    assert_eq!(digest_header.len(), "sha-256=::".len() + 44);
    assert!(base.contains(&format!("\"content-digest\": {digest_header}\n")));
}
