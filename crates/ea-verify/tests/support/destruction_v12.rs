//! Actual Root-authorized distinct approvers and immutable v1 destruction events.
use super::*;
use ea_types::SubjectId;

pub struct Fixture {
    pub source: ArchiveFixture,
    pub anchor: TrustAnchorV1,
    pub authorization: Vec<u8>,
}

/// Shared exact pre-state for the native executor and Reader Stub witnesses.
/// Additional native bindings may be appended at sequence 1 before signing.
pub struct OriginalFixture {
    pub line: trust_support::RegistryLineBuilder,
    pub anchor: TrustAnchorV1,
    pub approvers: [CertificateHash; 2],
    pub deletion: CertificateHash,
    pub original_bytes: Vec<u8>,
    pub initial_grant_bytes: Vec<u8>,
    pub entry_hash: EntryHash,
}

impl OriginalFixture {
    pub fn new(plaintext: &[u8]) -> Self {
        Self::from_historical(historical::fixture(plaintext))
    }
    pub fn new_with_writer_signer(plaintext: &[u8], signer: &CoseSigner) -> Self {
        Self::from_historical(historical::fixture_with_writer_signer(plaintext, signer))
    }
    fn from_historical(original: historical::HistoricalFixture) -> Self {
        let mut line = original.line;
        let mut approvers = Vec::new();
        let mut deletion = None;
        for (kind, marker) in [
            (CertificateKindV1::KeyApprover, 0x71),
            (CertificateKindV1::KeyApprover, 0x72),
            (CertificateKindV1::DeletionAttest, 0x73),
        ] {
            let head = line.push(
                trust_support::ActionSpec::Device {
                    kind,
                    marker,
                    effective_from: Some(1),
                },
                trust_support::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    not_after: UnixMillis::new(10_000),
                    authority_subject_id_override: Some(
                        SubjectId::try_from(&[marker; 16][..]).unwrap(),
                    ),
                    certificate_capabilities_override: (kind == CertificateKindV1::KeyApprover)
                        .then(|| vec!["destructionApprove".into()]),
                    ..Default::default()
                },
            );
            let cert = CertificateHash::from(head.direct_object_hash.unwrap());
            if kind == CertificateKindV1::KeyApprover {
                approvers.push(cert);
            } else {
                deletion = Some(cert);
            }
        }
        Self {
            line,
            anchor: original.anchor,
            approvers: approvers.try_into().ok().unwrap(),
            deletion: deletion.unwrap(),
            original_bytes: original.entry_bytes,
            initial_grant_bytes: original.original_bytes,
            entry_hash: original.entry_hash,
        }
    }

    pub fn head(&self) -> trust_support::BuiltHead {
        *self.line.heads().last().unwrap()
    }

    pub fn source(&self) -> ArchiveFixture {
        let mut source = ArchiveFixture::new();
        push_trust_objects(&mut source, &self.line);
        source.push_exact_bytes("entries/original.eip", self.original_bytes.clone());
        source.push_exact_bytes("grants/original.eag", self.initial_grant_bytes.clone());
        source
    }

    pub fn authorization(&self) -> Vec<u8> {
        let head = self.head();
        let payload = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
            destruction_id: DestructionId::try_from(&[0x74; 16][..]).unwrap(),
            organization_id: self.anchor.organization_id(),
            registry_version: head.version,
            registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
            authorization_sequence: 1,
            targets: vec![DestructionTargetV1::new(*self.entry_hash.as_bytes(), 0)],
            scope_code: 0,
            legal_reason_code: 0,
        })
        .unwrap();
        let signatures = self
            .approvers
            .into_iter()
            .map(|cert| {
                trust_support::authorized_device_signer()
                    .sign_destruction_approval_digest(cert, payload.exact_digest_input())
                    .unwrap()
            })
            .collect();
        encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
            .unwrap()
            .into_vec()
    }

    pub fn append_evidence_entry(&self, source: &mut ArchiveFixture, payload: &[u8]) -> EntryHash {
        self.append_evidence_at(source, payload, 1)
    }
    pub fn append_evidence_at(
        &self,
        source: &mut ArchiveFixture,
        payload: &[u8],
        sequence: u64,
    ) -> EntryHash {
        let ea_format::ParsedArchiveObject::Entry(original) =
            ea_format::decode_exact_object(&self.original_bytes).unwrap()
        else {
            panic!("original")
        };
        let ea_format::ParsedArchiveObject::Grant(grant) =
            ea_format::decode_exact_object(&self.initial_grant_bytes).unwrap()
        else {
            panic!("grant")
        };
        let writer = original.value().manifest().fields().writer_certificate_hash;
        let recipient = grant
            .value()
            .grant_body()
            .fields()
            .recipient_certificate_hash;
        let head = HeadRefV1::of(&self.head());
        let entry = build_complete_entry(
            head,
            writer,
            self.anchor.chain_id(),
            complete_grant_plan_hash(complete_recipient_key_thumbprint(), recipient),
            sequence,
            Some(self.entry_hash),
            payload,
        );
        let entry_hash = entry.entry_hash();
        source.push_exact_bytes(
            "entries/evidence.eip",
            encode_entry_package(&entry).unwrap().into_vec(),
        );
        source.push_exact_bytes(
            "grants/evidence.eag",
            complete_grant_bytes(
                head,
                writer,
                self.anchor.chain_id(),
                entry_hash,
                sequence,
                GrantPurposeV1::Recovery,
                complete_recipient_key_thumbprint(),
                recipient,
                &complete_recipient_private_key().public_key(),
            ),
        );
        entry_hash
    }
}

pub fn fixture(same_subject: bool, not_after: i64, privacy: bool) -> Fixture {
    let mut line = trust_support::RegistryLineBuilder::new();
    let options = || trust_support::HeadOptions {
        effective_from: Some(1),
        valid_through: Some(100),
        not_after: UnixMillis::new(not_after),
        ..Default::default()
    };
    line.push(
        policy_action(),
        trust_support::HeadOptions {
            policy_destruction_enabled_override: Some(privacy),
            effective_from: Some(0),
            valid_through: Some(0),
            ..options()
        },
    );
    let mut approvers = Vec::new();
    for marker in [0x71, 0x72] {
        let from = if marker == 0x71 { 1 } else { 101 };
        let head = line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::KeyApprover,
                marker,
                effective_from: Some(from),
            },
            trust_support::HeadOptions {
                authority_subject_id_override: Some(
                    SubjectId::try_from(&[if same_subject { 0x71 } else { marker }; 16][..])
                        .unwrap(),
                ),
                certificate_capabilities_override: Some(vec!["destructionApprove".into()]),
                effective_from: Some(from),
                valid_through: Some(from + 99),
                ..options()
            },
        );
        approvers.push(CertificateHash::from(head.direct_object_hash.unwrap()));
    }
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::DeletionAttest,
            marker: 0x73,
            effective_from: Some(201),
        },
        trust_support::HeadOptions {
            effective_from: Some(201),
            valid_through: Some(300),
            ..options()
        },
    );
    let deletion = CertificateHash::from(head.direct_object_hash.unwrap());
    let id = DestructionId::try_from(&[0x74; 16][..]).unwrap();
    let payload = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
        destruction_id: id,
        organization_id: trust_support::organization(),
        registry_version: head.version,
        registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
        authorization_sequence: 201,
        targets: vec![DestructionTargetV1::new([0x75; 32], 0)],
        scope_code: 0,
        legal_reason_code: 0,
    })
    .unwrap();
    let signatures = approvers
        .into_iter()
        .map(|cert| {
            trust_support::authorized_device_signer()
                .sign_destruction_approval_digest(cert, payload.exact_digest_input())
                .unwrap()
        })
        .collect();
    let authorization = encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
        .unwrap()
        .into_vec();
    let mut source = ArchiveFixture::new();
    push_trust_objects(&mut source, &line);
    source.push_exact_bytes("destructions/authorization.etb", authorization.clone());
    let mut previous = None;
    for state in [0, 1] {
        let event = destruction_transition_bytes(
            &authorization,
            id,
            object_hash(&authorization),
            EventId::try_from(&[0x76 + state; 16][..]).unwrap(),
            previous,
            if state == 0 { None } else { Some(0) },
            state,
            deletion,
        );
        previous = Some(object_hash(&event));
        source.push_exact_bytes(&format!("destructions/{state}.etb"), event);
    }
    Fixture {
        source,
        anchor: decode_trust_anchor(line.exact_anchor_bytes()).unwrap(),
        authorization,
    }
}

/// Web-Reader-Design §3 (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`:47-68):
/// ein Bestand mit ZWEI Vernichtungsvorgaengen unter DEMSELBEN
/// Autorisierungskopf.
///
/// Beide Uebergaenge tragen ein Root-zertifiziertes
/// `deletionAttest`-Zertifikat, beide Signaturen rechnen nach, beide
/// Autorisierungen tragen zwei verschiedene `destructionApprove`-Subjekte.
/// Sie unterscheiden sich AUSSCHLIESSLICH im Geraet, auf dem das signierende
/// Zertifikat sitzt: beim ersten haelt dasselbe Geraet zusaetzlich ein
/// Reader-Zertifikat. Damit ist das Reader-Geraet die EINZIGE Variable
/// zwischen Befund und Positivkontrolle.
pub struct ReaderSignerFixture {
    pub source: ArchiveFixture,
    pub anchor: TrustAnchorV1,
    /// Der Uebergang, dessen Signierergeraet ein Reader-Zertifikat traegt.
    pub reader_event_object_hash: ObjectHash,
    pub reader_destruction_id: DestructionId,
    /// Der Uebergang der Positivkontrolle: dasselbe in Gruen, ohne
    /// Reader-Zertifikat auf dem Geraet.
    pub control_event_object_hash: ObjectHash,
    pub control_destruction_id: DestructionId,
}

/// Baut [`ReaderSignerFixture`].
///
/// `reader_revoked` widerruft das Reader-Zertifikat VOR der
/// `authorizationSequence`. Es verschwindet damit aus
/// `active_certificate_fields`, bleibt aber in `known_certificate_fields` —
/// genau die Unterscheidung, auf der `device_holds_reader_certificate` steht,
/// und dieselbe Fixturgestalt wie in
/// `crates/ea-destruction/tests/transitions.rs`.
#[must_use]
pub fn reader_signer_fixture(reader_revoked: bool) -> ReaderSignerFixture {
    let reader_device = ea_types::DeviceId::try_from(&[0xa5; 16][..]).unwrap();
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(policy_action(), trust_support::HeadOptions::default());
    let approvers: [CertificateHash; 2] = [0x71, 0x72].map(|marker| {
        let head = line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::KeyApprover,
                marker,
                effective_from: None,
            },
            trust_support::HeadOptions {
                authority_subject_id_override: Some(
                    SubjectId::try_from(&[marker; 16][..]).unwrap(),
                ),
                certificate_capabilities_override: Some(vec!["destructionApprove".into()]),
                ..Default::default()
            },
        );
        CertificateHash::from(head.direct_object_hash.unwrap())
    });
    let reader_head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x65,
            effective_from: None,
        },
        trust_support::HeadOptions {
            device_id_override: Some(reader_device),
            ..Default::default()
        },
    );
    let reader_certificate_object_hash = reader_head.direct_object_hash.unwrap();
    let reader_certificate = CertificateHash::from(reader_certificate_object_hash);
    if reader_revoked {
        line.push(
            trust_support::ActionSpec::Revoke {
                target_kind: 0,
                object_hash: reader_certificate_object_hash,
            },
            trust_support::HeadOptions::default(),
        );
    }
    // Das `deletionAttest`-Zertifikat des Readers: seine Cache-Attestierung
    // ist ausdruecklich vorgesehen (Ruling 2026-09-13, DRK-250), der
    // Zustandsuebergang ausdruecklich nicht.
    let reader_deletion = CertificateHash::from(
        line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest,
                marker: 0x66,
                effective_from: None,
            },
            trust_support::HeadOptions {
                device_id_override: Some(reader_device),
                ..Default::default()
            },
        )
        .direct_object_hash
        .unwrap(),
    );
    let head = line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::DeletionAttest,
            marker: 0x67,
            effective_from: None,
        },
        trust_support::HeadOptions::default(),
    );
    let control_deletion = CertificateHash::from(head.direct_object_hash.unwrap());
    let sequence = head.effective_from.get();

    // Fixturbeleg statt Fixturhoffnung: das Reader-Zertifikat ist am
    // Autorisierungskopf bekannt, und GENAU DANN aktiv, wenn es nicht
    // widerrufen wurde.
    let authority = {
        let trust = line.verified_with_floor(
            trust_support::Pin::Exact(head.version, head.object_hash),
            UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1),
        );
        ea_trust::verify_historical_registry_authority(
            &trust,
            head.version,
            head.object_hash,
            ChainSequence::new(sequence),
        )
        .unwrap()
    };
    assert!(
        authority
            .known_certificate_fields()
            .any(|(hash, _)| hash == reader_certificate),
        "das Reader-Zertifikat muss am Autorisierungskopf bekannt sein",
    );
    assert_eq!(
        authority
            .active_certificate_fields(reader_certificate)
            .is_none(),
        reader_revoked,
        "das Reader-Zertifikat ist genau dann inaktiv, wenn es widerrufen wurde",
    );
    for certificate in [reader_deletion, control_deletion] {
        assert!(
            authority.active_certificate_fields(certificate).is_some(),
            "beide Loeschzeugenzertifikate sind am Autorisierungskopf aktiv",
        );
    }

    let mut source = ArchiveFixture::new();
    push_trust_objects(&mut source, &line);
    let mut build = |marker: u8, certificate: CertificateHash| {
        let id = DestructionId::try_from(&[marker; 16][..]).unwrap();
        let payload = TrustPayloadV1::destruction_authorization(DestructionAuthorizationFieldsV1 {
            destruction_id: id,
            organization_id: trust_support::organization(),
            registry_version: head.version,
            registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
            authorization_sequence: sequence,
            targets: vec![DestructionTargetV1::new([marker; 32], 0)],
            scope_code: 0,
            legal_reason_code: 0,
        })
        .unwrap();
        let signatures = approvers
            .into_iter()
            .map(|cert| {
                trust_support::authorized_device_signer()
                    .sign_destruction_approval_digest(cert, payload.exact_digest_input())
                    .unwrap()
            })
            .collect();
        let authorization = encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
            .unwrap()
            .into_vec();
        source.push_exact_bytes(
            &format!("destructions/{marker:02x}/authorization.etb"),
            authorization.clone(),
        );
        let event = destruction_transition_bytes(
            &authorization,
            id,
            object_hash(&authorization),
            EventId::try_from(&[marker; 16][..]).unwrap(),
            None,
            None,
            0,
            certificate,
        );
        let event_object_hash = object_hash(&event);
        source.push_exact_bytes(&format!("destructions/{marker:02x}/events/0.etb"), event);
        (id, event_object_hash)
    };
    let (reader_destruction_id, reader_event_object_hash) = build(0x81, reader_deletion);
    let (control_destruction_id, control_event_object_hash) = build(0x82, control_deletion);

    ReaderSignerFixture {
        source,
        anchor: decode_trust_anchor(line.exact_anchor_bytes()).unwrap(),
        reader_event_object_hash,
        reader_destruction_id,
        control_event_object_hash,
        control_destruction_id,
    }
}
