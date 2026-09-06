//! Die Zeugen der Registrierungs-, Policy-, Geraete- und Widerrufsablaeufe.
//!
//! Drei Zusagen tragen diese Datei:
//!
//! 1. **Kein zweiter Auswahlkern.** Die Linie, der Anker, die Objekte und die
//!    Kopfauswahl kommen aus dem `#[path]`-eingebundenen Supportmodul; die
//!    Zeugen pruefen die ea-admin-FASSADE ueber
//!    [`ea_trust::verify_registry_candidate`] →
//!    [`ea_trust::prepare_local_time`] → [`ea_trust::select_registry_head`]
//!    und nicht diesen Dreischritt selbst.
//! 2. **Kein zweiter Fehlercode.** Wo der Kern bereits einen Befund hat,
//!    behauptet der Zeuge GENAU dessen Code — ein erschoepftes Lease bleibt
//!    `EA-TRUST-SEQUENCE-LEASE`.
//! 3. **Die Grenze wird an der Grenze gemessen.** Lease und Widerruf werden
//!    an der letzten erlaubten UND der ersten verwehrten Stelle belegt, nicht
//!    an zwei weit auseinanderliegenden Punkten.
//! 4. **Kein Zeuge misst die Kulisse.** Was die Fixture ueber sich selbst
//!    aussagt, ist hier kein Gegenstand. Dass ein direktes Ziel und seine
//!    Aktivierung ueber EINEM Vorgaengerkopf getrennte Kennungen und Nonces
//!    tragen, ist eine Zusage von
//!    [`ea_admin::OperatorBindingService`]; sie wird an ihrem Erzeuger
//!    gemessen, in `crates/ea-admin/tests/operator_binding.rs`.
#![allow(clippy::too_many_lines)]

/// Die Kulisse der Zeremonienzeugen, unveraendert weiterverwendet. Sie bindet
/// ihrerseits das Supportmodul von `ea-trust` ein; ein zweiter `#[path]`
/// dorthin waere eine zweite Uebersetzung derselben Linie.
#[path = "support/mod.rs"]
mod support;

use ea_admin::{
    RegistryWindow, VerifiedLocalDeviceIdentity,
    device::{PendingDeviceRegistration, confirm_device_fingerprint, plan_device_approval},
    policy::{InitialPolicyPlan, InitialPolicyRequest, initial_policy_plan},
    registry::{RegistryActionV1, RegistryEventFactory, RegistryWorkflowService},
    revocation::{RevocationTargetClass, classify_revocation_target, plan_revocation},
};
use ea_format::{
    CertificateKindV1, FreeTextPolicyFieldsV1, RegistryChangeV1, RetentionPolicyFieldsV1,
};
use ea_time::{IndependentTimeInput, IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, VerifiedTrust,
};
use ea_types::{CertificateHash, ChainSequence, ObjectHash, RegistryVersion, UnixMillis};
use support::trust_support::{
    ActionSpec, HeadOptions, Pin, PreviousHash, RegistryLineBuilder, hash32, object_hash_marker,
    organization, state_key,
};

/// Die Ausgangsrevision der Zeugen — dieselbe, die das Supportmodul benutzt.
const REVISION: u64 = 17;

/// Die Betriebssystemuhr der Zeugen.
const NOW_MS: i64 = 1_000;

/// Ein Speicher, der Uebernahmen TATSAECHLICH schreibt.
///
/// Die Attrappe des Supportmoduls ist privat und weist
/// `commit_independent_time` ab; ein Zeuge des Vorrueckpfads bekaeme dadurch
/// einen Speicherfehler statt des Befunds, um den es geht.
struct WorkflowStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
}

impl WorkflowStore {
    fn new(trusted_time: TrustedTimeState, pinned_head: Option<RegistryHeadPin>) -> Self {
        Self {
            key: state_key(),
            revision: REVISION,
            trusted_time,
            pinned_head,
        }
    }
}

impl TrustStateStore for WorkflowStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            self.pinned_head,
        ))
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            self.pinned_head,
        ))
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        self.pinned_head = Some(*commit.next_head());
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            self.pinned_head,
        ))
    }
}

fn window(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        ..HeadOptions::default()
    }
}

fn policy_action() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn trusted_time_at(floor_ms: i64) -> TrustedTimeState {
    TrustedTimeState::initial(UnixMillis::new(floor_ms))
}

/// Der gepruefte Bestand mit einem Pin und der Ausgangsrevision.
fn trust_at(line: &RegistryLineBuilder, pin: Pin, floor_ms: i64) -> VerifiedTrust {
    line.verified_with_record(pin, REVISION, trusted_time_at(floor_ms), state_key())
}

fn pin_of(line: &RegistryLineBuilder, index: usize) -> RegistryHeadPin {
    let head = line.heads()[index];
    RegistryHeadPin::new(head.version, head.object_hash)
}

/// Waehlt ueber die FASSADE und gibt den Ausgang heraus.
fn select(
    line: &RegistryLineBuilder,
    pin: Pin,
    proposed: u64,
    now_ms: i64,
) -> Result<RegistrySelectionOutcome, ea_admin::registry::RegistryWorkflowError> {
    let pinned = match pin {
        Pin::None => None,
        Pin::Head(index) => Some(pin_of(line, index)),
        Pin::Exact(version, hash) => Some(RegistryHeadPin::new(version, hash)),
    };
    let trust = trust_at(line, pin, now_ms);
    let mut store = WorkflowStore::new(trusted_time_at(now_ms), pinned);
    let mut service = RegistryWorkflowService::new(&mut store);
    service.select(
        &trust,
        ChainSequence::new(proposed),
        UnixMillis::new(now_ms),
        &[],
        None,
    )
}

/// Der Code, mit dem die Fassade blockiert.
fn blocked(line: &RegistryLineBuilder, pin: Pin, proposed: u64, now_ms: i64) -> &'static str {
    select(line, pin, proposed, now_ms)
        .err()
        .expect("die Fassade muss hier blockieren")
        .code()
}

/// Der gewaehlte Kopf oder ein Abbruch mit sprechendem Text.
fn selected(
    line: &RegistryLineBuilder,
    pin: Pin,
    proposed: u64,
    now_ms: i64,
) -> SelectedRegistryHead {
    match select(line, pin, proposed, now_ms) {
        Ok(RegistrySelectionOutcome::Selected(head)) => head,
        Ok(_) => panic!("die Fassade muss hier einen Kopf waehlen"),
        Err(error) => panic!("die Auswahl scheitert unerwartet: {}", error.code()),
    }
}

fn holds_certificate(head: &SelectedRegistryHead, certificate: CertificateHash) -> bool {
    head.active_certificates()
        .any(|(hash, _)| hash == certificate)
}

/// Die Bytes eines Objekthashes fuer die FEHLERMELDUNG eines Zeugen.
///
/// [`ObjectHash`] traegt bewusst kein `Debug` — ein Hash soll nicht beilaeufig
/// in eine Ausgabe geraten. Ein `assert!(a == b)` daneben meldete deshalb gar
/// nichts ausser „false". Ein Zeuge, der scheitert, muss aber sagen koennen,
/// WELCHE Werte auseinanderlaufen; `[u8; 32]` kann das.
fn hash_bytes(hash: ObjectHash) -> [u8; 32] {
    *hash.as_bytes()
}

fn optional_hash_bytes(hash: Option<ObjectHash>) -> Option<[u8; 32]> {
    hash.map(hash_bytes)
}

/// Eine Linie mit einem Lesegeraet, das ab Sequenz 41 widerrufen ist.
///
/// Kopf 2 (21..40) fuehrt das Zertifikat, Kopf 3 (41..60) widerruft es. Die
/// Grenze liegt damit ZWISCHEN zwei Koepfen — `active_certificates` iteriert
/// an der `proposed_sequence` des Kopfes, ein Sequenzparameter allein koennte
/// sie gar nicht bewegen.
fn revocation_line() -> (RegistryLineBuilder, ObjectHash) {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), window(1, 20));
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x71,
            effective_from: None,
        },
        window(21, 40),
    );
    let reader_hash = reader
        .direct_object_hash
        .expect("das Lesezertifikat ist ein direktes Ziel");
    line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: reader_hash,
        },
        window(41, 60),
    );
    (line, reader_hash)
}

/// Die Ereignisfabrik ueber dem gewaehlten Kopf der Zeremonienlinie.
struct Factory {
    ceremony: support::CeremonyLine,
}

impl Factory {
    fn new() -> Self {
        Self {
            ceremony: support::ceremony_line(),
        }
    }

    fn head(&self) -> SelectedRegistryHead {
        support::selected_head(&self.ceremony.line)
    }

    fn local_device(&self, head: &SelectedRegistryHead) -> VerifiedLocalDeviceIdentity {
        let certificate = CertificateHash::from(self.ceremony.writer_certificate_object_hash);
        let device = head
            .active_certificate_fields(certificate)
            .expect("das Writer-Zertifikat der Fixture ist aktiv")
            .device_id;
        VerifiedLocalDeviceIdentity::verify(head, certificate, device)
            .expect("das Writer-Zertifikat der Fixture ist die lokale Geraeteidentitaet")
    }
}

/// Das Fenster, das die Fabrik am gewaehlten Kopf akzeptiert.
fn next_window() -> RegistryWindow {
    RegistryWindow {
        effective_from_sequence: ChainSequence::new(101),
        valid_through_sequence: ChainSequence::new(200),
        not_after: UnixMillis::new(10_000_000),
    }
}

// ---------------------------------------------------------------------------
// 1. Der hoechste anwendbare Kopf
// ---------------------------------------------------------------------------

#[test]
fn the_workflow_selects_the_highest_applicable_head() {
    let ceremony = support::ceremony_line();
    let line = &ceremony.line;
    let last = line.heads()[support::LAST_HEAD];

    // Gebunden ist der VORLETZTE Kopf; anwendbar an Sequenz 50 ist der letzte.
    let advanced = selected(line, Pin::Head(support::EARLIER_HEAD), 50, NOW_MS);
    assert_eq!(advanced.registry_version(), last.version);

    // Am selben Punkt mit dem letzten Kopf gebunden: derselbe Kopf.
    let current = selected(line, Pin::Head(support::LAST_HEAD), 50, NOW_MS);
    assert_eq!(current.registry_version(), last.version);
    assert_eq!(
        hash_bytes(current.registry_head_hash()),
        hash_bytes(last.object_hash),
        "der gewaehlte Kopf ist der letzte der Linie"
    );
}

// ---------------------------------------------------------------------------
// 2. Die Leasegrenze
// ---------------------------------------------------------------------------

#[test]
fn the_sequence_lease_boundary_is_exact() {
    let ceremony = support::ceremony_line();
    let line = &ceremony.line;
    let last = line.heads()[support::LAST_HEAD];
    let boundary = last.valid_through.get();

    let allowed = selected(line, Pin::Head(support::LAST_HEAD), boundary, NOW_MS);
    assert_eq!(allowed.proposed_sequence(), ChainSequence::new(boundary));

    assert_eq!(
        blocked(line, Pin::Head(support::LAST_HEAD), boundary + 1, NOW_MS),
        "EA-TRUST-SEQUENCE-LEASE",
    );
}

// ---------------------------------------------------------------------------
// 3. Die Widerrufsgrenze ueber drei Koepfe
// ---------------------------------------------------------------------------

#[test]
fn the_revocation_boundary_spans_three_heads() {
    let (line, reader_hash) = revocation_line();
    let reader = CertificateHash::from(reader_hash);

    let before = selected(&line, Pin::Head(1), 40, NOW_MS);
    let at = selected(&line, Pin::Head(2), 41, NOW_MS);
    let after = selected(&line, Pin::Head(2), 42, NOW_MS);

    assert!(holds_certificate(&before, reader));
    assert!(!holds_certificate(&at, reader));
    assert!(!holds_certificate(&after, reader));
}

// ---------------------------------------------------------------------------
// 4. Die Stelligkeit aller sieben Aktionscodes
// ---------------------------------------------------------------------------

#[test]
fn every_action_code_carries_its_exact_arity() {
    let target = object_hash_marker(0xa1);
    let cases: [(RegistryActionV1, u8, Option<ObjectHash>); 7] = [
        (
            RegistryActionV1::DeviceApprove {
                certificate_object_hash: target,
            },
            0,
            Some(target),
        ),
        (
            RegistryActionV1::PolicyChange {
                policy_object_hash: target,
            },
            2,
            Some(target),
        ),
        (
            RegistryActionV1::WriterTransition {
                transition_object_hash: target,
            },
            3,
            Some(target),
        ),
        (
            RegistryActionV1::OperatorBinding {
                binding_object_hash: target,
            },
            4,
            Some(target),
        ),
        (
            RegistryActionV1::AdminKeyIssue {
                certificate_object_hash: target,
            },
            5,
            Some(target),
        ),
        (
            RegistryActionV1::AdminKeyRevoke {
                certificate_object_hash: target,
            },
            5,
            None,
        ),
        (
            RegistryActionV1::RootRotation {
                certificate_object_hash: target,
            },
            6,
            Some(target),
        ),
    ];

    for (index, (action, code, direct)) in cases.iter().enumerate() {
        assert_eq!(
            action.action_code(),
            *code,
            "Fall {index}: der Aktionscode steht fest"
        );
        assert_eq!(
            optional_hash_bytes(action.direct_target_object_hash()),
            optional_hash_bytes(*direct),
            "Fall {index} (Aktionscode {code}): die Stelligkeit des direkten Ziels"
        );
        let change = action.change();
        assert_eq!(
            change_tag(&change),
            *code,
            "Fall {index} (Aktionscode {code}): die Aenderung passt zur Aktion"
        );
        assert_eq!(
            hash_bytes(change_object_hash(&change)),
            hash_bytes(target),
            "Fall {index} (Aktionscode {code}): die Aenderung benennt dasselbe Objekt"
        );
    }

    // Aktionscode 1 steht NICHT in der Tabelle, weil er nicht in sie passt:
    // sein Ziel ist kein frei gewaehlter Hash, sondern ein
    // `ClassifiedRevocationTarget` — und das gibt es nur aus dem Bestand eines
    // gewaehlten Kopfes. Genau das ist die Zusage aus A7; gemessen wird sie
    // hier trotzdem an denselben vier Stellen wie jede andere Aktion.
    let (line, reader_hash) = revocation_line();
    let head = selected(&line, Pin::Head(1), 40, NOW_MS);
    let classified = classify_revocation_target(&head, reader_hash)
        .expect("das Lesezertifikat ist an Sequenz 40 aktiv");
    let revoke = RegistryActionV1::DeviceRevoke(classified);

    assert_eq!(revoke.action_code(), 1);
    assert_eq!(
        optional_hash_bytes(revoke.direct_target_object_hash()),
        None,
        "Aenderung 1 bereitet kein neues Objekt vor"
    );
    let change = revoke.change();
    assert_eq!(change_tag(&change), 1);
    assert_eq!(
        hash_bytes(change_object_hash(&change)),
        hash_bytes(reader_hash),
        "die Aenderung benennt das eingeordnete Objekt"
    );

    // Aktion 5 unterscheidet ihre beiden Effekte, und nur Effekt 0 traegt ein
    // direktes neues Zertifikat.
    assert!(matches!(
        RegistryActionV1::AdminKeyIssue {
            certificate_object_hash: target,
        }
        .change(),
        RegistryChangeV1::AdminCertificate { effect: 0, .. }
    ));
    assert!(matches!(
        RegistryActionV1::AdminKeyRevoke {
            certificate_object_hash: target,
        }
        .change(),
        RegistryChangeV1::AdminCertificate { effect: 1, .. }
    ));
}

const fn change_tag(change: &RegistryChangeV1) -> u8 {
    match change {
        RegistryChangeV1::Certificate { .. } => 0,
        RegistryChangeV1::Target { .. } => 1,
        RegistryChangeV1::Policy { .. } => 2,
        RegistryChangeV1::WriterTransition { .. } => 3,
        RegistryChangeV1::OperatorBinding { .. } => 4,
        RegistryChangeV1::AdminCertificate { .. } => 5,
        RegistryChangeV1::RootCertificate { .. } => 6,
    }
}

const fn change_object_hash(change: &RegistryChangeV1) -> ObjectHash {
    match change {
        RegistryChangeV1::Certificate { object_hash }
        | RegistryChangeV1::Target { object_hash, .. }
        | RegistryChangeV1::Policy { object_hash }
        | RegistryChangeV1::WriterTransition { object_hash }
        | RegistryChangeV1::OperatorBinding { object_hash }
        | RegistryChangeV1::AdminCertificate { object_hash, .. }
        | RegistryChangeV1::RootCertificate { object_hash } => *object_hash,
    }
}

#[test]
fn change_one_never_revokes_an_admin_certificate() {
    let ceremony = support::ceremony_line();
    let head = support::selected_head(&ceremony.line);
    let admin_hash = ceremony.line.bootstrap_admin_hash();

    // Die Bedienerbindung derselben Administratorin IST ueber Aenderung 1
    // widerrufbar — Zielart 1.
    let binding = classify_revocation_target(&head, ceremony.line.bootstrap_admin_binding_hash())
        .expect("eine aktive Bedienerbindung ist widerrufbar");
    assert_eq!(binding.class(), RevocationTargetClass::OperatorBinding);
    assert_eq!(RevocationTargetClass::OperatorBinding.target_kind(), 1);
    assert_eq!(
        hash_bytes(binding.object_hash()),
        hash_bytes(ceremony.line.bootstrap_admin_binding_hash()),
        "die eingeordnete Art bleibt an IHREM Objekt"
    );

    // Ihr ZERTIFIKAT ist es nicht: `ea-trust` fuehrt Administrationszertifikate
    // in einer eigenen Ablage, und Aktion 5 Effekt 1 ist ihr Weg.
    assert_eq!(
        classify_revocation_target(&head, admin_hash)
            .expect_err("ein Administrationszertifikat ist ueber Aenderung 1 nicht widerrufbar")
            .code(),
        "EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE",
    );

    // Und der Weg AM Einordner vorbei ist keiner mehr: die Aktionsvariante
    // nimmt kein Paar aus frei gewaehlter Art und frei gewaehltem Hash
    // entgegen, sondern nur das Ergebnis genau dieser Einordnung. Ein Zeuge
    // kann daher gar nicht mehr vorfuehren, wie ein Administrationszertifikat
    // unter Zielart 0 auf den Draht geraet — der Uebersetzer weist es ab.
    // Belegt ist das als `compile_fail`-Doktest an
    // `ea_admin::revocation::ClassifiedRevocationTarget`.
    let planned = RegistryActionV1::DeviceRevoke(binding).change();
    assert!(matches!(
        planned,
        RegistryChangeV1::Target {
            target_kind: 1,
            object_hash,
        } if object_hash == ceremony.line.bootstrap_admin_binding_hash()
    ));
}

#[test]
fn a_component_certificate_is_target_kind_two() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), window(1, 20));
    let receipt = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x73,
            effective_from: None,
        },
        window(21, 40),
    );
    let receipt_hash = receipt
        .direct_object_hash
        .expect("das Serverquittungszertifikat ist ein direktes Ziel");
    let head = selected(&line, Pin::Head(0), 30, NOW_MS);

    let classified = classify_revocation_target(&head, receipt_hash)
        .expect("das Serverquittungszertifikat ist an Sequenz 30 aktiv");
    assert_eq!(classified.class(), RevocationTargetClass::Component);
    assert_eq!(RevocationTargetClass::Component.target_kind(), 2);

    // Und die Zielart landet UNVERAENDERT auf dem Draht: waere sie hier 0,
    // benennte die Aenderung eine Komponente als Geraet.
    assert!(matches!(
        RegistryActionV1::DeviceRevoke(classified).change(),
        RegistryChangeV1::Target {
            target_kind: 2,
            object_hash,
        } if object_hash == receipt_hash
    ));
}

#[test]
fn a_target_that_is_no_longer_active_is_refused() {
    let (line, reader_hash) = revocation_line();

    // Kopf 3 (41..60) hat das Lesezertifikat widerrufen. Derselbe Name, der an
    // Sequenz 40 noch einzuordnen war, ist hier kein Bestand mehr — und ein
    // Widerruf des Widerrufenen ist keine Handlung, sondern ein Irrtum.
    let after = selected(&line, Pin::Head(2), 45, NOW_MS);
    assert!(
        !holds_certificate(&after, CertificateHash::from(reader_hash)),
        "an Sequenz 45 ist das Lesezertifikat widerrufen"
    );
    assert_eq!(
        classify_revocation_target(&after, reader_hash)
            .expect_err("ein widerrufenes Zertifikat ist kein Widerrufsziel")
            .code(),
        "EA-WORKFLOW-TARGET-NOT-ACTIVE",
    );

    // Ein Name, den die Linie ueberhaupt nicht kennt, ist derselbe Befund.
    assert_eq!(
        classify_revocation_target(&after, object_hash_marker(0x00))
            .expect_err("ein unbekannter Name ist kein Widerrufsziel")
            .code(),
        "EA-WORKFLOW-TARGET-NOT-ACTIVE",
    );

    // Der Gegenzeuge an derselben Linie: an Sequenz 40 ist dasselbe Zertifikat
    // sehr wohl einzuordnen. Ohne ihn koennte der Zeuge oben auch gruen sein,
    // weil die Kulisse gar nichts traegt.
    let before = selected(&line, Pin::Head(1), 40, NOW_MS);
    assert_eq!(
        classify_revocation_target(&before, reader_hash)
            .expect("an Sequenz 40 ist das Lesezertifikat aktiv")
            .class(),
        RevocationTargetClass::NonAdminDevice,
    );
}

// ---------------------------------------------------------------------------
// 5. Genau ein direktes Ziel, genau eine passende Aenderung
// ---------------------------------------------------------------------------

#[test]
fn an_activation_event_binds_the_checked_head_and_its_version_plus_one() {
    let factory = Factory::new();
    let head = factory.head();
    let audit =
        support::AuditHarness::new(&head, factory.ceremony.writer_certificate_object_hash, 0);
    let local = factory.local_device(&head);
    let events = RegistryEventFactory::new(&head, audit.service(), local);

    let policy_hash = object_hash_marker(0xb2);
    let event = events
        .plan(
            next_window(),
            &RegistryActionV1::PolicyChange {
                policy_object_hash: policy_hash,
            },
        )
        .expect("das Fenster liegt im Lease und in der Registrierungsalterung");

    assert_eq!(
        event.registry_version,
        RegistryVersion::new(head.registry_version().get() + 1),
    );
    assert_eq!(
        event.previous_registry_hash.map(|hash| *hash.as_bytes()),
        Some(hash_bytes(head.registry_head_hash())),
        "das Ereignis bindet den GEPRUEFTEN Vorgaengerkopf"
    );
    assert!(matches!(
        event.change,
        RegistryChangeV1::Policy { object_hash } if object_hash == policy_hash
    ));
    assert_eq!(event.effective_from_sequence, ChainSequence::new(101));
    assert_eq!(
        hash_bytes(event.policy_object_hash),
        hash_bytes(head.policy_object_hash()),
        "das Ereignis uebernimmt den Policy-Hash des gewaehlten Kopfes"
    );
}

#[test]
fn the_factory_refuses_a_window_outside_the_lease_of_the_selected_head() {
    let factory = Factory::new();
    let head = factory.head();
    let audit =
        support::AuditHarness::new(&head, factory.ceremony.writer_certificate_object_hash, 0);
    let local = factory.local_device(&head);
    let events = RegistryEventFactory::new(&head, audit.service(), local);
    let action = RegistryActionV1::PolicyChange {
        policy_object_hash: object_hash_marker(0xb3),
    };

    // Das Lease des gewaehlten Kopfes endet bei 100; anschliessen darf ein
    // Fenster genau an 101. Zwei Schritte weiter ist eine LUECKE, und die
    // Fabrik reicht den Befund der Fensterpruefung unveraendert durch.
    assert_eq!(
        events
            .plan(
                RegistryWindow {
                    effective_from_sequence: ChainSequence::new(102),
                    valid_through_sequence: ChainSequence::new(200),
                    not_after: UnixMillis::new(10_000_000),
                },
                &action,
            )
            .err()
            .expect("ein Fenster hinter dem Lease ist kein Fenster")
            .code(),
        "EA-OPERATOR-REGISTRY-WINDOW",
    );

    // Und die zweite Haelfte derselben Zusage: die Registrierungsalterung der
    // GEBUNDENEN Policy. Die Grenze wird aus dem Kopf gelesen und nicht hier
    // gerechnet — eine zweite Uhr waere eine zweite Wahrheit.
    let now = head.preexisting_effective_now().value().get();
    let max_age = i64::try_from(head.policy_fields().max_registry_age_ms)
        .expect("die Registrierungsalterung der Fixture passt in i64");
    assert_eq!(
        events
            .plan(
                RegistryWindow {
                    effective_from_sequence: ChainSequence::new(101),
                    valid_through_sequence: ChainSequence::new(200),
                    not_after: UnixMillis::new(now + max_age + 1),
                },
                &action,
            )
            .err()
            .expect("ein Fenster jenseits der Registrierungsalterung ist kein Fenster")
            .code(),
        "EA-OPERATOR-REGISTRY-WINDOW",
    );

    // Der Gegenzeuge an derselben Grenze: eine Millisekunde davor traegt.
    events
        .plan(
            RegistryWindow {
                effective_from_sequence: ChainSequence::new(101),
                valid_through_sequence: ChainSequence::new(200),
                not_after: UnixMillis::new(now + max_age),
            },
            &action,
        )
        .expect("die letzte erlaubte Stelle der Registrierungsalterung traegt");
}

// ---------------------------------------------------------------------------
// 6. Die Blockaden
// ---------------------------------------------------------------------------

#[test]
fn a_rollback_blocks() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), HeadOptions::default());
    let second = line.push(policy_action(), HeadOptions::default());
    line.remove_object(second.object_hash);

    assert_eq!(
        blocked(
            &line,
            Pin::Exact(second.version, second.object_hash),
            200,
            NOW_MS
        ),
        "EA-TRUST-REGISTRY-ROLLBACK",
    );
}

#[test]
fn a_same_version_fork_blocks() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), HeadOptions::default());
    line.push(
        policy_action(),
        HeadOptions {
            registry_version: Some(1),
            ..HeadOptions::default()
        },
    );

    assert_eq!(
        blocked(&line, Pin::Head(0), 101, NOW_MS),
        "EA-TRUST-REGISTRY-FORK"
    );
}

#[test]
fn a_wrong_previous_head_blocks() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), HeadOptions::default());
    line.push(
        policy_action(),
        HeadOptions {
            previous_hash: PreviousHash::Value(hash32(0xd1)),
            ..HeadOptions::default()
        },
    );

    assert_eq!(
        blocked(&line, Pin::Head(0), 101, NOW_MS),
        "EA-TRUST-REGISTRY-PREVIOUS",
    );
}

#[test]
fn a_future_only_successor_blocks_outside_the_bound_lease() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), window(1, 100));
    line.push(
        policy_action(),
        HeadOptions {
            issued_at: UnixMillis::new(50_000),
            not_before: UnixMillis::new(50_000),
            not_after: UnixMillis::new(100_000),
            ..window(101, 200)
        },
    );

    // Die vorgeschlagene Sequenz liegt AUSSERHALB des gebundenen Lease; es
    // gibt keinen Kopf, unter den zurueckgefallen werden koennte.
    assert_eq!(
        blocked(&line, Pin::Head(0), 150, NOW_MS),
        "EA-TRUST-PENDING-FUTURE",
    );
}

#[test]
fn an_expired_head_blocks_fail_closed() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        policy_action(),
        HeadOptions {
            not_after: UnixMillis::new(500),
            ..window(1, 100)
        },
    );

    assert_eq!(blocked(&line, Pin::Head(0), 50, NOW_MS), "EA-TRUST-STALE");
}

#[test]
fn a_ready_successor_blocks_the_current_head_fallback() {
    let mut line = RegistryLineBuilder::new();
    let current = line.push(
        policy_action(),
        HeadOptions {
            not_after: UnixMillis::new(10_000),
            ..window(1, 100)
        },
    );
    line.push(
        policy_action(),
        HeadOptions {
            issued_at: UnixMillis::new(1_200),
            not_before: UnixMillis::new(1_100),
            not_after: UnixMillis::new(20_000),
            ..window(50, 200)
        },
    );

    let key = state_key();
    let floor = TrustedTimeState::from_persisted(
        UnixMillis::new(900),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(hash32(0xc6)),
            UnixMillis::new(900),
        )),
    )
    .expect("der Zeitboden der Fixture ist stimmig");
    let pinned = RegistryHeadPin::new(current.version, current.object_hash);

    let trust = line.verified_with_record(Pin::Head(0), REVISION, floor.clone(), key);
    let mut store = WorkflowStore::new(floor.clone(), Some(pinned));
    let mut service = RegistryWorkflowService::new(&mut store);
    let RegistrySelectionOutcome::PendingFuture(pending) = service
        .select(
            &trust,
            ChainSequence::new(60),
            UnixMillis::new(950),
            &[],
            None,
        )
        .expect("der Nachfolger ist zunaechst nur zukuenftig")
    else {
        panic!("der Nachfolger muss zunaechst nur zukuenftig sein");
    };

    let reloaded = line.verified_with_record(Pin::Head(0), REVISION, floor, key);
    let mut service = RegistryWorkflowService::new(&mut store);
    assert_eq!(
        service
            .select_after_future_successor(&reloaded, pending, UnixMillis::new(1_200), &[], None,)
            .err()
            .expect("der bereitstehende Nachfolger sperrt den Rueckfall")
            .code(),
        "EA-TRUST-SUCCESSOR-READY",
    );
}

// ---------------------------------------------------------------------------
// 7. Der Widerruf holt nichts zurueck
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_recalls_nothing_and_stops_only_new_grants() {
    let (line, reader_hash) = revocation_line();
    let reader = CertificateHash::from(reader_hash);
    let head = selected(&line, Pin::Head(1), 40, NOW_MS);
    let audit = support::AuditHarness::new(&head, reader_hash, 0);
    let device = head
        .active_certificate_fields(reader)
        .expect("das Lesezertifikat ist an Sequenz 40 aktiv")
        .device_id;
    let local = VerifiedLocalDeviceIdentity::verify(&head, reader, device)
        .expect("das Lesezertifikat ist eine gueltige lokale Geraeteidentitaet");
    let events = RegistryEventFactory::new(&head, audit.service(), local);

    let (event, effect) = plan_revocation(
        &events,
        RegistryWindow {
            effective_from_sequence: ChainSequence::new(41),
            valid_through_sequence: ChainSequence::new(60),
            not_after: UnixMillis::new(9_000),
        },
        reader_hash,
    )
    .expect("der Widerruf des Lesegeraets ist planbar");

    assert!(matches!(
        event.change,
        RegistryChangeV1::Target {
            target_kind: 0,
            object_hash,
        } if object_hash == reader_hash
    ));
    assert_eq!(
        effect.stops_new_grants_from(),
        ChainSequence::new(41),
        "neue Freigaben bleiben erst ab der Wirksamkeitssequenz aus"
    );
    assert!(
        !effect.recalls_issued_grants(),
        "bereits erteilte Freigaben werden nicht zurueckgeholt"
    );
    assert!(
        !effect.recalls_decrypted_plaintext(),
        "bereits entschluesselter Klartext wird nicht zurueckgeholt"
    );

    // Und der Bestand belegt dasselbe: der Kopf VOR der Wirksamkeitssequenz
    // fuehrt das Zertifikat unveraendert weiter.
    assert!(holds_certificate(&head, reader));
}

// ---------------------------------------------------------------------------
// Geraetefreigabe und initiale Policy
// ---------------------------------------------------------------------------

#[test]
fn a_device_approval_requires_a_pending_request_and_an_external_confirmation() {
    let factory = Factory::new();
    let head = factory.head();
    let audit =
        support::AuditHarness::new(&head, factory.ceremony.writer_certificate_object_hash, 0);
    let local = factory.local_device(&head);
    let events = RegistryEventFactory::new(&head, audit.service(), local);

    let exact_bytes = factory
        .ceremony
        .line
        .exact_object_bytes(factory.ceremony.writer_certificate_object_hash)
        .to_vec();
    let pending = PendingDeviceRegistration::new(exact_bytes)
        .expect("das Writer-Zertifikat ist ein zulaessiger Antrag");
    assert_eq!(pending.certificate_kind(), CertificateKindV1::Writer);

    // Ein falsch zurueckgemeldeter Fingerprint bestaetigt gar nichts.
    assert_eq!(
        confirm_device_fingerprint(&pending, object_hash_marker(0x00))
            .err()
            .expect("ein abweichender Fingerprint bestaetigt nichts")
            .code(),
        "EA-WORKFLOW-FINGERPRINT-MISMATCH",
    );

    let confirmation = confirm_device_fingerprint(&pending, pending.fingerprint())
        .expect("der ueber den zweiten Kanal gemeldete Fingerprint stimmt");
    let event = plan_device_approval(&events, next_window(), &pending, confirmation)
        .expect("Antrag und Bestaetigung liegen vor");

    assert!(matches!(
        event.change,
        RegistryChangeV1::Certificate { object_hash }
            if object_hash == factory.ceremony.writer_certificate_object_hash
    ));
    assert_eq!(
        event.registry_version,
        RegistryVersion::new(head.registry_version().get() + 1)
    );

    // Aenderung 0 aktiviert nie ein Administrationszertifikat.
    let admin_bytes = factory
        .ceremony
        .line
        .exact_object_bytes(factory.ceremony.line.bootstrap_admin_hash())
        .to_vec();
    assert_eq!(
        PendingDeviceRegistration::new(admin_bytes)
            .err()
            .expect("ein Administrationszertifikat ist kein Geraeteantrag")
            .code(),
        "EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE",
    );
}

#[test]
fn a_confirmation_only_covers_the_request_it_was_made_for() {
    let mut ceremony = support::ceremony_line();
    let head = support::selected_head(&ceremony.line);
    let audit = support::AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
    let certificate = CertificateHash::from(ceremony.writer_certificate_object_hash);
    let device = head
        .active_certificate_fields(certificate)
        .expect("das Writer-Zertifikat der Fixture ist aktiv")
        .device_id;
    let local = VerifiedLocalDeviceIdentity::verify(&head, certificate, device)
        .expect("das Writer-Zertifikat der Fixture ist die lokale Geraeteidentitaet");
    let events = RegistryEventFactory::new(&head, audit.service(), local);

    // ZWEI gleichzeitig offene Antraege — genau der Fall, den eine
    // Bedienfuehrung treffen kann, die zwei Geraete nacheinander vorliest.
    let first = PendingDeviceRegistration::new(
        ceremony
            .line
            .exact_object_bytes(ceremony.writer_certificate_object_hash)
            .to_vec(),
    )
    .expect("das Writer-Zertifikat ist ein zulaessiger Antrag");
    let second_hash = ceremony.line.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Reader,
        marker: 0x74,
        effective_from: None,
    });
    let second =
        PendingDeviceRegistration::new(ceremony.line.exact_object_bytes(second_hash).to_vec())
            .expect("das vorbereitete Lesezertifikat ist ein zulaessiger Antrag");
    assert_ne!(
        hash_bytes(first.certificate_object_hash()),
        hash_bytes(second.certificate_object_hash()),
        "die beiden Antraege meinen verschiedene Zertifikate"
    );

    // Die Bestaetigung des ERSTEN Antrags aktiviert den zweiten nicht. Ohne
    // diesen Vergleich deckte eine einmal vorgelesene Bestaetigung jedes
    // beliebige andere Zertifikat, das gerade offen ist.
    let for_first = confirm_device_fingerprint(&first, first.fingerprint())
        .expect("der Fingerprint des ersten Antrags stimmt");
    assert_eq!(
        plan_device_approval(&events, next_window(), &second, for_first)
            .err()
            .expect("eine Bestaetigung deckt genau EINEN Antrag")
            .code(),
        "EA-WORKFLOW-FINGERPRINT-MISMATCH",
    );

    // Und umgekehrt genauso.
    let for_second = confirm_device_fingerprint(&second, second.fingerprint())
        .expect("der Fingerprint des zweiten Antrags stimmt");
    assert_eq!(
        plan_device_approval(&events, next_window(), &first, for_second)
            .err()
            .expect("eine Bestaetigung deckt genau EINEN Antrag")
            .code(),
        "EA-WORKFLOW-FINGERPRINT-MISMATCH",
    );

    // Der Gegenzeuge: das PASSENDE Paar traegt.
    let matching = confirm_device_fingerprint(&second, second.fingerprint())
        .expect("der Fingerprint des zweiten Antrags stimmt");
    let event = plan_device_approval(&events, next_window(), &second, matching)
        .expect("Antrag und Bestaetigung gehoeren zusammen");
    assert!(matches!(
        event.change,
        RegistryChangeV1::Certificate { object_hash } if object_hash == second_hash
    ));
}

#[test]
fn the_initial_policy_fixes_every_dimension_and_uses_change_two() {
    let plan = initial_policy_plan(InitialPolicyRequest {
        organization_id: organization(),
        effective_from_sequence: ChainSequence::new(1),
        lease_valid_through_sequence: ChainSequence::new(100),
        not_after: UnixMillis::new(10_000_000),
        operating_profile: 0,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 86_400_000,
        reader_trust_refresh_ms: 86_400_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: vec![hash32(0x31)],
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: RetentionPolicyFieldsV1 {
            minimum_retention_ms: Some(86_400_000),
            destruction_enabled: true,
            eds_privacy_decision_document_hash: None,
        },
        free_text_policy: FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "workflow-v1".into(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec!["suite-a".into()],
        allowed_format_versions: vec![1],
    })
    .expect("die initiale Policy benennt jede Dimension");

    assert_eq!(plan.policy.policy_version, 1);
    assert!(plan.policy.previous_policy_object_hash.is_none());
    assert_eq!(plan.policy.effective_from_sequence, ChainSequence::new(1));
    assert_eq!(
        plan.window.valid_through_sequence,
        ChainSequence::new(100),
        "die initiale Policy legt das Sequenz-Lease des ersten Kopfes fest"
    );

    // Kopf 1 traegt die initiale Policy als Aenderung 2 — und die Aktion dazu
    // kommt aus DEM Erzeuger, nicht aus diesem Testkoerper. Ein hier selbst
    // gebautes `PolicyChange` maesse den Stelligkeitszeugen ein zweites Mal
    // und `policy.rs` gar nicht.
    let policy_hash = object_hash_marker(0xc1);
    let action = InitialPolicyPlan::action(policy_hash);
    assert_eq!(action.action_code(), 2);
    assert!(matches!(
        action.change(),
        RegistryChangeV1::Policy { object_hash } if object_hash == policy_hash
    ));

    // Jede der vier Dimensionen der Vollstaendigkeitspruefung fuer sich: eine
    // Sammelprobe liesse drei Arme sich wegloeschen, ohne dass ein Zeuge rot
    // wird.
    assert_eq!(
        incomplete(InitialPolicyRequest {
            allowed_crypto_suite_ids: Vec::new(),
            ..sound_initial_request()
        }),
        "EA-WORKFLOW-POLICY-INCOMPLETE",
        "eine leere Suitenliste laesst eine Dimension offen"
    );
    assert_eq!(
        incomplete(InitialPolicyRequest {
            allowed_format_versions: Vec::new(),
            ..sound_initial_request()
        }),
        "EA-WORKFLOW-POLICY-INCOMPLETE",
        "eine leere Formatliste laesst eine Dimension offen"
    );
    assert_eq!(
        incomplete(InitialPolicyRequest {
            allowed_archive_profile_hashes: Vec::new(),
            ..sound_initial_request()
        }),
        "EA-WORKFLOW-POLICY-INCOMPLETE",
        "ohne zugelassenes Archivprofil ist auch das Netzwerkfehlerverhalten offen"
    );
    assert_eq!(
        incomplete(InitialPolicyRequest {
            effective_from_sequence: ChainSequence::new(101),
            lease_valid_through_sequence: ChainSequence::new(100),
            ..sound_initial_request()
        }),
        "EA-WORKFLOW-POLICY-INCOMPLETE",
        "ein Lease, das vor seiner Wirksamkeitssequenz endet, ist keines"
    );

    // Die Grenze GENAU an der letzten erlaubten Stelle: ein Lease der Laenge
    // null ist eines. Ohne diesen Gegenzeugen koennte die Pruefung `<=` statt
    // `<` sein und alle vier Proben oben blieben rot.
    initial_policy_plan(InitialPolicyRequest {
        effective_from_sequence: ChainSequence::new(100),
        lease_valid_through_sequence: ChainSequence::new(100),
        ..sound_initial_request()
    })
    .expect("ein Lease, das an seiner Wirksamkeitssequenz endet, ist eines");
}

/// Der Code, mit dem die initiale Policy eine offene Dimension meldet.
fn incomplete(request: InitialPolicyRequest) -> &'static str {
    initial_policy_plan(request)
        .err()
        .expect("eine offene Dimension muss die initiale Policy abweisen")
        .code()
}

fn sound_initial_request() -> InitialPolicyRequest {
    InitialPolicyRequest {
        organization_id: organization(),
        effective_from_sequence: ChainSequence::new(1),
        lease_valid_through_sequence: ChainSequence::new(100),
        not_after: UnixMillis::new(10_000_000),
        operating_profile: 0,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 86_400_000,
        reader_trust_refresh_ms: 86_400_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: vec![hash32(0x31)],
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: RetentionPolicyFieldsV1 {
            minimum_retention_ms: Some(86_400_000),
            destruction_enabled: true,
            eds_privacy_decision_document_hash: None,
        },
        free_text_policy: FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "workflow-v1".into(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec!["suite-a".into()],
        allowed_format_versions: vec![1],
    }
}
