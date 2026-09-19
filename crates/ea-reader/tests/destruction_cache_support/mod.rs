#![allow(dead_code)]
use super::support;
use ea_crypto::object_hash;
use ea_format::*;
use ea_reader::ReaderDestructionInstructionBytes;
use ea_types::*;
use support::archive_support::trust_support as trust;
pub struct Fixture {
    pub original: support::destruction_v12::OriginalFixture,
    pub authorization: Vec<u8>,
    pub event: Vec<u8>,
    pub core: Vec<u8>,
    pub signature: Vec<u8>,
    pub inventory: Vec<u8>,
    pub reader: KeyThumbprint,
    pub replica: DeviceId,
    pub event_certificate: CertificateHash,
    pub reader_attestation_certificate: Option<CertificateHash>,
    pub alternate_reader_attestation_certificate: Option<CertificateHash>,
}
impl Fixture {
    pub fn new() -> Self {
        Self::with_alternate_event_signer(false)
    }
    pub fn with_alternate_event_signer(alternate: bool) -> Self {
        Self::build(alternate, None, None, false, false)
    }
    pub fn with_reader_attestation_key(secret: [u8; 32]) -> Self {
        Self::build(false, Some(secret), None, false, false)
    }
    /// The initiating 0→1 event is signed by the reader's own
    /// `deletionAttest` key on its Reader device (Web-Reader-Design §3 forbids it).
    pub fn with_reader_signed_initiating_event(secret: [u8; 32]) -> Self {
        Self::build(false, Some(secret), None, false, true)
    }
    pub fn with_reader_attestation_identity(secret: [u8; 32], device: DeviceId) -> Self {
        Self::build(false, Some(secret), Some(device), false, false)
    }
    pub fn with_two_reader_attestation_certificates(secret: [u8; 32]) -> Self {
        Self::build(false, Some(secret), None, true, false)
    }
    fn build(
        alternate: bool,
        reader_secret: Option<[u8; 32]>,
        device_override: Option<DeviceId>,
        two_reader_certificates: bool,
        reader_signs_event: bool,
    ) -> Self {
        let mut original =
            support::destruction_v12::OriginalFixture::new(support::COMPLETE_PLAINTEXT_V1);
        let event_certificate = if alternate {
            let head = original.line.push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x76,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    not_after: UnixMillis::new(10_000),
                    ..Default::default()
                },
            );
            CertificateHash::from(head.direct_object_hash.unwrap())
        } else {
            original.deletion
        };
        let mut alternate_reader_attestation_certificate = None;
        let reader_attestation_certificate = reader_secret.map(|secret| {
            let archive = ea_archive::ArchiveInventory::build(&original.source()).unwrap();
            let device = archive
                .trust()
                .iter()
                .find_map(|p| match p.value().decoded_payload() {
                    Ok(DecodedTrustPayloadV1::AuthorizedDevice(c))
                        if c.fields().certificate_kind == CertificateKindV1::Reader =>
                    {
                        Some(c.fields().device_id)
                    }
                    _ => None,
                })
                .unwrap();
            let head = original.line.push(
                trust::ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x77,
                    effective_from: Some(1),
                },
                trust::HeadOptions {
                    effective_from: Some(1),
                    valid_through: Some(100),
                    not_after: UnixMillis::new(10_000),
                    device_id_override: Some(device_override.unwrap_or(device)),
                    signing_public_key_override: Some(
                        ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(secret))
                            .public_key()
                            .unwrap(),
                    ),
                    ..Default::default()
                },
            );
            let first = CertificateHash::from(head.direct_object_hash.unwrap());
            if two_reader_certificates {
                let head = original.line.push(
                    trust::ActionSpec::Device {
                        kind: CertificateKindV1::DeletionAttest,
                        marker: 0x78,
                        effective_from: Some(1),
                    },
                    trust::HeadOptions {
                        effective_from: Some(1),
                        valid_through: Some(100),
                        not_after: UnixMillis::new(10_000),
                        device_id_override: Some(device_override.unwrap_or(device)),
                        signing_public_key_override: Some(
                            ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(secret))
                                .public_key()
                                .unwrap(),
                        ),
                        ..Default::default()
                    },
                );
                alternate_reader_attestation_certificate =
                    Some(CertificateHash::from(head.direct_object_hash.unwrap()));
            }
            first
        });
        let authorization = original.authorization();
        let ParsedArchiveObject::Trust(auth) = decode_exact_object(&authorization).unwrap() else {
            panic!()
        };
        let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
            auth.value().decoded_payload().unwrap()
        else {
            panic!()
        };
        let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
            destruction_id: fields.destruction_id,
            destruction_authorization_object_hash: object_hash(&authorization),
            event_id: EventId::from(Id16::try_from(&[0x79; 16][..]).unwrap()),
            previous_event_object_hash: Some(ObjectHash::from(
                Hash32::try_from(&[0x78; 32][..]).unwrap(),
            )),
            from_state: Some(0),
            to_state: 1,
            trigger_code: 0,
            executed_at: UnixMillis::new(800),
        })
        .unwrap();
        let (event_signer, event_certificate) = match (reader_signs_event, reader_secret) {
            (true, Some(secret)) => (
                ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(secret)),
                reader_attestation_certificate.unwrap(),
            ),
            _ => (trust::authorized_device_signer(), event_certificate),
        };
        let signature = event_signer
            .sign_destruction_transition_digest(
                event_certificate,
                payload.exact_digest_input(),
                &authorization,
            )
            .unwrap();
        let event = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec();
        let archive = ea_archive::ArchiveInventory::build(&original.source()).unwrap();
        let reader = archive
            .trust()
            .iter()
            .find_map(|p| match p.value().decoded_payload() {
                Ok(DecodedTrustPayloadV1::AuthorizedDevice(c))
                    if c.fields().certificate_kind == CertificateKindV1::Reader =>
                {
                    Some((p.object_hash(), c.fields().clone()))
                }
                _ => None,
            })
            .unwrap();
        let replica = reader.1.device_id;
        let mut record = Vec::new();
        let mut e = minicbor::Encoder::new(&mut record);
        e.array(4)
            .unwrap()
            .u8(0)
            .unwrap()
            .bytes(reader.0.as_bytes())
            .unwrap()
            .bytes(replica.as_bytes())
            .unwrap()
            .u8(CertificateKindV1::Reader as u8)
            .unwrap();
        let mut custody = Vec::new();
        let mut e = minicbor::Encoder::new(&mut custody);
        e.array(6)
            .unwrap()
            .str("EINSATZARCHIV-MANAGED-CUSTODY-v1")
            .unwrap()
            .bytes(fields.organization_id.as_bytes())
            .unwrap()
            .bytes(fields.destruction_id.as_bytes())
            .unwrap()
            .bytes(auth.object_hash().as_bytes())
            .unwrap()
            .bytes(original.anchor.chain_id().as_bytes())
            .unwrap()
            .array(1)
            .unwrap()
            .bytes(&record)
            .unwrap();
        let ParsedArchiveObject::Entry(entry) =
            decode_exact_object(&original.original_bytes).unwrap()
        else {
            panic!()
        };
        let stub = encode_destroyed_entry_stub(
            &DestroyedEntryStubV1::new(
                entry.value().signed_manifest().clone(),
                entry.value().writer_signature().to_vec(),
                entry.object_hash(),
                fields.destruction_id,
                auth.object_hash(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut inventory = Vec::new();
        let mut e = minicbor::Encoder::new(&mut inventory);
        e.array(4)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1")
            .unwrap()
            .bytes(&custody)
            .unwrap()
            .array(1)
            .unwrap()
            .array(3)
            .unwrap()
            .bytes(original.entry_hash.as_bytes())
            .unwrap()
            .bytes(entry.object_hash().as_bytes())
            .unwrap()
            .bytes(stub.as_bytes())
            .unwrap()
            .array(0)
            .unwrap();
        let report = ea_verify::verify_archive(
            &original.source(),
            &original.anchor,
            ea_verify::VerifyOptions::new(UnixMillis::new(800)),
        )
        .unwrap()
        .to_canonical_json()
        .unwrap();
        let head = original.head();
        let mut core = Vec::new();
        let mut e = minicbor::Encoder::new(&mut core);
        e.array(16)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(fields.organization_id.as_bytes())
            .unwrap()
            .bytes(original.anchor.chain_id().as_bytes())
            .unwrap()
            .bytes(fields.destruction_id.as_bytes())
            .unwrap()
            .bytes(auth.object_hash().as_bytes())
            .unwrap()
            .bytes(object_hash(&inventory).as_bytes())
            .unwrap()
            .bytes(object_hash(report.as_bytes()).as_bytes())
            .unwrap()
            .bytes(report.as_bytes())
            .unwrap()
            .u64(head.version.get())
            .unwrap()
            .bytes(head.object_hash.as_bytes())
            .unwrap()
            .u64(1)
            .unwrap()
            .u64(head.version.get())
            .unwrap()
            .bytes(head.object_hash.as_bytes())
            .unwrap()
            .u64(1)
            .unwrap()
            .i64(800)
            .unwrap();
        let signature = trust::authorized_device_signer()
            .sign_destruction_preflight_report(original.deletion, &core)
            .unwrap();
        Self {
            original,
            authorization,
            event,
            core,
            signature,
            inventory,
            reader: reader.1.kem_key_thumbprint.unwrap(),
            replica,
            event_certificate,
            reader_attestation_certificate,
            alternate_reader_attestation_certificate,
        }
    }
    pub fn add_custody_record(&mut self, kind: u8) {
        let mut d = minicbor::Decoder::new(&self.inventory);
        d.array().unwrap();
        d.str().unwrap();
        let custody = d.bytes().unwrap();
        let suffix = self.inventory[d.position()..].to_vec();
        let mut c = minicbor::Decoder::new(custody);
        c.array().unwrap();
        let domain = c.str().unwrap();
        let org = c.bytes().unwrap();
        let id = c.bytes().unwrap();
        let auth = c.bytes().unwrap();
        let chain = c.bytes().unwrap();
        let n = c.array().unwrap().unwrap();
        let mut records = Vec::new();
        for _ in 0..n {
            records.push(c.bytes().unwrap().to_vec())
        }
        let mut record = minicbor::Decoder::new(&records[0]);
        record.array().unwrap();
        record.u8().unwrap();
        let cert = record.bytes().unwrap().to_vec();
        let device = record.bytes().unwrap().to_vec();
        let certificate_kind = record.u8().unwrap();
        let mut extra = Vec::new();
        let mut e = minicbor::Encoder::new(&mut extra);
        e.array(match kind {
            1 => 6,
            2 => 9,
            _ => 4,
        })
        .unwrap()
        .u8(if kind == 8 { 0 } else { kind })
        .unwrap()
        .bytes(&cert)
        .unwrap()
        .bytes(&device)
        .unwrap()
        .u8(if kind == 8 { 9 } else { certificate_kind })
        .unwrap();
        if matches!(kind, 1 | 2) {
            e.bytes(&[0x81; 32]).unwrap().bytes(&[0x82; 32]).unwrap();
        }
        if kind == 2 {
            e.bytes(object_hash(&self.original.original_bytes).as_bytes())
                .unwrap()
                .bytes(self.original.entry_hash.as_bytes())
                .unwrap()
                .u8(1)
                .unwrap();
        }
        records.push(extra);
        records.sort_by_key(|record| object_hash(record));
        let mut new_custody = Vec::new();
        let mut e = minicbor::Encoder::new(&mut new_custody);
        e.array(6)
            .unwrap()
            .str(domain)
            .unwrap()
            .bytes(org)
            .unwrap()
            .bytes(id)
            .unwrap()
            .bytes(auth)
            .unwrap()
            .bytes(chain)
            .unwrap()
            .array(records.len() as u64)
            .unwrap();
        for record in records {
            e.bytes(&record).unwrap();
        }
        let mut inventory = Vec::new();
        let mut e = minicbor::Encoder::new(&mut inventory);
        e.array(4)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1")
            .unwrap()
            .bytes(&new_custody)
            .unwrap();
        inventory.extend_from_slice(&suffix);
        self.inventory = inventory;
        let report = ea_crypto::decode_destruction_preflight_core(&self.core)
            .unwrap()
            .report_json
            .to_vec();
        self.replace_report(&report);
    }
    pub fn corrupt_custody_order(&mut self, duplicate: bool) {
        let mut d = minicbor::Decoder::new(&self.inventory);
        d.array().unwrap();
        d.str().unwrap();
        let custody = d.bytes().unwrap();
        let suffix = &self.inventory[d.position()..];
        let mut c = minicbor::Decoder::new(custody);
        c.array().unwrap();
        for _ in 0..5 {
            c.skip().unwrap();
        }
        let prefix = &custody[..c.position()];
        let count = c.array().unwrap().unwrap();
        let mut records = (0..count)
            .map(|_| c.bytes().unwrap().to_vec())
            .collect::<Vec<_>>();
        assert!(records.len() > 1);
        if duplicate {
            records.push(records[0].clone());
            records.sort_by_key(|record| object_hash(record));
        } else {
            records.reverse();
        }
        let mut new_custody = prefix.to_vec();
        let mut e = minicbor::Encoder::new(&mut new_custody);
        e.array(records.len() as u64).unwrap();
        for record in records {
            e.bytes(&record).unwrap();
        }
        let mut inventory = Vec::new();
        let mut e = minicbor::Encoder::new(&mut inventory);
        e.array(4)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1")
            .unwrap()
            .bytes(&new_custody)
            .unwrap();
        inventory.extend_from_slice(suffix);
        self.inventory = inventory;
        let report = ea_crypto::decode_destruction_preflight_core(&self.core)
            .unwrap()
            .report_json
            .to_vec();
        self.replace_report(&report);
    }
    pub fn admit_late_event_signer(&mut self) {
        let head = self.original.line.push(
            trust::ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest,
                marker: 0x77,
                effective_from: Some(2),
            },
            trust::HeadOptions {
                effective_from: Some(2),
                valid_through: Some(100),
                not_after: UnixMillis::new(10000),
                ..Default::default()
            },
        );
        let cert = CertificateHash::from(head.direct_object_hash.unwrap());
        let ParsedArchiveObject::Trust(event) = decode_exact_object(&self.event).unwrap() else {
            panic!()
        };
        let DecodedTrustPayloadV1::DestructionTransition(fields) =
            event.value().decoded_payload().unwrap()
        else {
            panic!()
        };
        let payload = TrustPayloadV1::destruction_transition(fields).unwrap();
        let signature = trust::authorized_device_signer()
            .sign_destruction_transition_digest(
                cert,
                payload.exact_digest_input(),
                &self.authorization,
            )
            .unwrap();
        self.event = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .into_vec();
    }
    pub fn revoke_component_after_valid_progress(
        &mut self,
        certificate: CertificateHash,
    ) -> support::archive_support::ArchiveFixture {
        let mut before = self.original.source();
        self.original
            .append_evidence_entry(&mut before, support::COMPLETE_PLAINTEXT_V1);
        self.revoke_component(certificate);
        let mut source = self.original.source();
        for (path, bytes) in before
            .blobs()
            .iter()
            .filter(|(path, _)| path == "entries/evidence.eip" || path == "grants/evidence.eag")
        {
            source.push_exact_bytes(path, bytes.clone());
        }
        source
    }
    pub fn revoke_component(&mut self, certificate: CertificateHash) {
        self.original.line.push(
            trust::ActionSpec::Revoke {
                target_kind: 2,
                object_hash: ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
            },
            trust::HeadOptions {
                effective_from: Some(2),
                valid_through: Some(100),
                not_after: UnixMillis::new(10_000),
                ..Default::default()
            },
        );
    }
    pub fn revoke_reader(&mut self) {
        let inventory = ea_archive::ArchiveInventory::build(&self.original.source()).unwrap();
        let reader=inventory.trust().iter().find(|p|matches!(p.value().decoded_payload(),Ok(DecodedTrustPayloadV1::AuthorizedDevice(c)) if c.fields().certificate_kind==CertificateKindV1::Reader)).unwrap().object_hash();
        self.original.line.push(
            trust::ActionSpec::Revoke {
                target_kind: 0,
                object_hash: reader,
            },
            trust::HeadOptions {
                effective_from: Some(2),
                valid_through: Some(100),
                not_after: UnixMillis::new(10_000),
                ..Default::default()
            },
        );
    }
    pub fn remove_current_privacy_document(&mut self) {
        self.original.line.push(
            trust::ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: Some(2),
            },
            trust::HeadOptions {
                effective_from: Some(2),
                valid_through: Some(100),
                not_after: UnixMillis::new(10_000),
                policy_eds_privacy_decision_document_hash_override: Some(None),
                ..Default::default()
            },
        );
    }
    pub fn replace_report(&mut self, report: &[u8]) {
        let p = ea_crypto::decode_destruction_preflight_core(&self.core).unwrap();
        let mut core = Vec::new();
        let mut e = minicbor::Encoder::new(&mut core);
        e.array(16)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&p.organization_id)
            .unwrap()
            .bytes(&p.chain_id)
            .unwrap()
            .bytes(&p.destruction_id)
            .unwrap()
            .bytes(&p.authorization_hash)
            .unwrap()
            .bytes(object_hash(&self.inventory).as_bytes())
            .unwrap()
            .bytes(object_hash(report).as_bytes())
            .unwrap()
            .bytes(report)
            .unwrap()
            .u64(p.authorization_registry)
            .unwrap()
            .bytes(&p.authorization_head)
            .unwrap()
            .u64(p.authorization_sequence)
            .unwrap()
            .u64(p.execution_registry)
            .unwrap()
            .bytes(&p.execution_head)
            .unwrap()
            .u64(p.execution_sequence)
            .unwrap()
            .i64(p.observed_effective_now)
            .unwrap();
        self.signature = trust::authorized_device_signer()
            .sign_destruction_preflight_report(self.original.deletion, &core)
            .unwrap();
        self.core = core;
    }
    pub fn input(&self) -> ReaderDestructionInstructionBytes<'_> {
        ReaderDestructionInstructionBytes {
            authorization: &self.authorization,
            initiating_event: &self.event,
            preflight_core: &self.core,
            preflight_signature: &self.signature,
            inventory: &self.inventory,
            preflight_certificate: self.original.deletion,
        }
    }
    pub fn current(&self) -> ea_trust::SelectedRegistryHead {
        self.current_at(1)
    }
    pub fn current_at(&self, sequence: u64) -> ea_trust::SelectedRegistryHead {
        let inventory = ea_archive::ArchiveInventory::build(&self.original.source()).unwrap();
        let key = ea_verify::verification_state_key(self.original.anchor.organization_id());
        let mut store = ea_verify::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
        for _ in 0..=inventory.trust().len() {
            let trust = ea_trust::verify_trust(
                &self.original.anchor,
                &inventory,
                ea_trust::load_trust_state(&mut store, key).unwrap(),
            )
            .unwrap();
            let previous = trust.pinned_head().copied();
            let candidate =
                ea_trust::verify_registry_candidate(&trust, ChainSequence::new(sequence)).unwrap();
            let time =
                ea_trust::prepare_local_time(&mut store, &candidate, UnixMillis::new(800), &[])
                    .unwrap();
            if let ea_trust::RegistrySelectionOutcome::Selected(head) =
                ea_trust::select_registry_head(candidate, time, None).unwrap()
                && previous.is_some_and(|pin| pin.registry_head_hash() == head.registry_head_hash())
            {
                return head;
            }
        }
        panic!("current head");
    }
}
