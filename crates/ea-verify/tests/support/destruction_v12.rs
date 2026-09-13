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
