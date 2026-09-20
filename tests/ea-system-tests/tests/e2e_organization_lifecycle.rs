//! Der Lebenszyklus EINER Organisation — in einem Durchgang.
//!
//! # Die eine Aussage
//!
//! Stufe 5 hat fuer jede Einzelzusage aus Task 14 Step 3 einen Zeugen
//! (`docs/traceability/stage-5-gate.md`, Abschnitt 3). Was bis DRK-427 fehlte,
//! ist der EINE Lauf, der sie in der Reihenfolge ausfuehrt, in der eine
//! Organisation sie durchlebt: Einrichtung bis zur Recovery-Bereitschaft,
//! ausstehende Aktivierung eines Geraets, Widerruf eines Lesegeraets,
//! Wirksamkeit und Ueberalterung der Registrierung, administrative
//! Uhrfreigabe, Writer-Uebergang, Nachtrag und kontrollierte Vernichtung.
//!
//! Dieser Zeuge erfindet dabei NICHTS. Jeder Abschnitt ruft dieselbe Fassade,
//! die der in Abschnitt 3 genannte Einzelzeuge ruft, und benutzt dessen
//! Kulisse: `crates/ea-admin/tests/support/mod.rs` fuer die Zeremonie,
//! `tests/registry_effectiveness_support/mod.rs` fuer Zustandsspeicher,
//! Auditdienst und Bedienernachweis, `tests/writer_transition_support/mod.rs`
//! (und ueber sie `crates/ea-writer/tests/support/mod.rs`) fuer Writer und
//! Nachtrag, `crates/ea-destruction/tests/support/mod.rs` fuer die
//! Vernichtung. Eine zweite Fixture-Welt entsteht hier nicht.
//!
//! # Die Naht, die der Lauf NICHT schliesst
//!
//! Der Lebenszyklus laeuft ueber VIER Kulissen und nicht ueber eine. Das ist
//! keine Bequemlichkeit, sondern die Gestalt des Produkts: die
//! Einrichtungszeremonie (`ea-admin`) lebt VOR der Registrierungslinie und
//! kennt sie nicht, die Writer-Fixture haelt ihre eigene Linie mit zwei
//! Writer-Zertifikaten, und die Vernichtung verlangt eine Policy mit
//! `destructionEnabled`, zwei Approver-Zertifikate mit
//! `destructionApprove` und ein Loeschattest-Zertifikat, die keine der
//! anderen Linien fuehrt. Die vier Naehte sind unten JEWEILS benannt; wo eine
//! Zusage nur innerhalb einer Kulisse messbar ist, steht das dort und nicht in
//! einer Zusicherung, die mehr behauptet.
//!
//! # Dienste
//!
//! Keine. Dieser Zeuge ist rein dateisystem- und prozessintern — wie
//! `e2e_registry_effectiveness` und `e2e_writer_transition`, und anders als
//! `e2e_historical_grant`, `e2e_destruction_policy` und die beiden
//! Vernichtungs-Rennen, die `DATABASE_URL` und `EA_OBJECT_STORE_ENDPOINT`
//! verlangen. Es braucht kein `xtask integration up`.
#![allow(clippy::duplicate_mod, clippy::too_many_lines)]

#[path = "../../../crates/ea-admin/tests/support/mod.rs"]
mod ceremony_support;

#[path = "../../../crates/ea-destruction/tests/support/mod.rs"]
mod destruction_support;

#[path = "registry_effectiveness_support/mod.rs"]
mod registry_support;

#[path = "writer_transition_support/mod.rs"]
mod transition_support;

use ea_admin::amendment::AmendmentDraftService;
use ea_admin::clock_release::{
    ClockReleaseAvailability, ClockReleaseRequest, ClockReleaseService, ClockReleaseWorkflowError,
    apply_clock_release,
};
use ea_admin::device::{
    PendingDeviceRegistration, confirm_device_fingerprint, plan_device_approval,
};
use ea_admin::registry::{RegistryEventFactory, RegistryWorkflowError, RegistryWorkflowService};
use ea_admin::revocation::{RevocationTargetClass, plan_revocation};
use ea_admin::writer_transition::{TrustedChainHead, WriterTransitionService};
use ea_admin::{BootstrapStep, ProductionState, RegistryWindow, VerifiedLocalDeviceIdentity};
use ea_crypto::CanonicalPublicCoseKey;
use ea_destruction::{build_stub, verify_authorization, verify_stub_against_original};
use ea_format::{
    CertificateKindV1, ClockReleaseJustificationV1, DestructionTargetV1, GrantPlanV1,
    OperatorRoleV1, ParsedArchiveObject, RegistryChangeV1, decode_exact_object,
    encode_entry_package,
};
use ea_operator::ReauthPurpose;
use ea_schema::{PayloadV1, SCHEMA_VERSION_V1, SchemaRegistry};
use ea_time::TrustedTimeState;
use ea_trust::{
    RegistryHeadPin, RegistrySelectionOutcome, SelectedRegistryHead, TrustStateKey, VerifiedTrust,
};
use ea_types::{CertificateHash, ChainSequence, DeviceId, ObjectHash, RegistryVersion, UnixMillis};
use ea_writer::build_grant_plan;

use registry_support::trust_support::{
    ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder,
};
use registry_support::{AuditHarness, INSTANCE_SECRET, OS_ACCOUNT_MARKER, WorkflowStore};
use transition_support::{
    AdminTransition, new_writer_finalizes_key_transition, run_admin_transition,
};

// ===========================================================================
// Die Zahlen der Linie
// ===========================================================================

/// Der persistierte Anfangsstand der Zustandsablage.
const REVISION: u64 = 17;
/// Der persistierte Zeitboden.
const FLOOR_MS: i64 = 3_100;
/// Die geprüfte Zeit der persistierten unabhängigen Referenz.
const REFERENCE_MS: i64 = 3_000;
/// Die Betriebssystemuhr der ungesperrten Abschnitte: `3_000 <= 3_000 + 50`.
const WALL_MS: i64 = 3_000;
/// `raw_now` der ungesperrten Bewertung: `max(3_100, 3_000)`.
const NOW_MS: i64 = FLOOR_MS;
/// Eine Wanduhr JENSEITS der Wachgrenze: `3_201 > 3_000 + 50`.
const BLOCKED_WALL_MS: i64 = 3_201;
/// Dieselbe Sperre, aber die Uhr ist um eine Millisekunde ZURUECKgelaufen.
const ROLLED_BACK_WALL_MS: i64 = 3_200;
/// Die untere Grenze des Freigabefensters, EINSCHLIESSEND.
const ISSUED_AT_MS: i64 = 3_150;
/// Die obere Grenze des Freigabefensters, EINSCHLIESSEND.
const EXPIRES_AT_MS: i64 = 3_250;
/// Die Wachrichtlinie der Linie erlaubt 50 ms Vorlauf.
const GUARD_SKEW_MS: u64 = 50;

const RECOVERY_MARKER: u8 = 0x51;
const READER_MARKER: u8 = 0x63;
const SECOND_READER_MARKER: u8 = 0x64;
const ADMIN_MARKER: u8 = 0x11;

/// Die Sequenz, an der das erste Lesegerät zuletzt einen Grant bekommt.
const LAST_GRANTING_SEQUENCE: u64 = 49;
/// Die `effectiveFromSequence` des Widerrufs.
const REVOCATION_SEQUENCE: u64 = 50;

/// Die Köpfe der Linie, an denen die Abschnitte binden.
const HEAD_ADMIN_BINDING: usize = 4;
const HEAD_GUARD_POLICY: usize = 6;

// ===========================================================================
// Die Linie der Organisation
// ===========================================================================

/// Alles, was die Abschnitte 2 bis 5 über die gebaute Linie wissen müssen.
struct Organization {
    line: RegistryLineBuilder,
    recovery_certificate_object_hash: ObjectHash,
    reader_certificate_object_hash: ObjectHash,
    admin_certificate_object_hash: ObjectHash,
    admin_binding_object_hash: ObjectHash,
}

fn policy_action() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn window(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        ..HeadOptions::default()
    }
}

/// Der KEM-Schlüssel eines Empfängers.
///
/// Ohne diese Überschreibung trüge JEDER Empfänger `x25519([0xa5; 32])` und
/// `GrantPlanV1::new` wiese den Plan als doppelten Empfänger ab.
fn kem_key(marker: u8) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519([marker; 32]).expect("der Fixturschluessel bleibt kanonisch")
}

/// Baut die Registrierungslinie dieser Organisation.
///
/// Sieben Köpfe mit je zehn Sequenzstellen Lease: Anfangspolicy,
/// Wiederherstellungsempfänger, Lesegerät, Adminzertifikat, Adminbindung,
/// Widerruf des Lesegeräts, Wachrichtlinie. Die Gestalt ist die der Linie in
/// `e2e_registry_effectiveness.rs`; der Baukasten ist derselbe
/// [`RegistryLineBuilder`], und die Zusammensetzung gehört wie dort zum
/// Zeugen und nicht in ein geteiltes Modul — zwei Zeugen mit derselben Linie
/// bleiben dadurch unabhängig voneinander änderbar.
fn organization_line() -> Organization {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), window(1, 9));

    let recovery = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::RecoveryRecipient,
            marker: RECOVERY_MARKER,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(kem_key(RECOVERY_MARKER)),
            ..window(10, 19)
        },
    );

    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: READER_MARKER,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(kem_key(READER_MARKER)),
            ..window(20, 29)
        },
    );

    let admin = line.push(
        ActionSpec::AdminIssue {
            marker: ADMIN_MARKER,
            effective_from: None,
        },
        window(30, 39),
    );
    let admin_certificate_object_hash = admin
        .direct_object_hash
        .expect("das Adminzertifikat der Linie ist ein direktes Ziel");

    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: admin_certificate_object_hash,
            role: OperatorRoleV1::OrganizationAdmin,
            marker: ADMIN_MARKER,
            effective_from: None,
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(
                registry_support::public_key(INSTANCE_SECRET).thumbprint(),
            ),
            binding_os_account_hash_override: Some(registry_support::trust_support::hash32(
                OS_ACCOUNT_MARKER,
            )),
            ..window(40, 49)
        },
    );
    let admin_binding_object_hash = binding
        .direct_object_hash
        .expect("die Adminbindung der Linie ist ein direktes Ziel");

    let reader_certificate_object_hash = reader
        .direct_object_hash
        .expect("das Lesezertifikat der Linie ist ein direktes Ziel");
    line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: reader_certificate_object_hash,
        },
        window(REVOCATION_SEQUENCE, 59),
    );

    line.push(
        policy_action(),
        HeadOptions {
            policy_max_future_clock_skew_ms_override: Some(GUARD_SKEW_MS),
            ..window(60, 69)
        },
    );

    Organization {
        line,
        recovery_certificate_object_hash: recovery
            .direct_object_hash
            .expect("das Wiederherstellungszertifikat der Linie ist ein direktes Ziel"),
        reader_certificate_object_hash,
        admin_certificate_object_hash,
        admin_binding_object_hash,
    }
}

// ===========================================================================
// Zustand und Auswahl
// ===========================================================================

/// Der Zustandsschlüssel der Organisation.
///
/// Das Gerät IST das des Adminzertifikats: die Freigabezeile bindet
/// `targetDeviceId`, und `verify_clock_release` vergleicht sie gegen genau
/// diesen Schlüssel.
fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: registry_support::trust_support::organization(),
        device_id: DeviceId::try_from(&[ADMIN_MARKER.wrapping_add(0x40); 16][..])
            .expect("16 Byte sind eine Geraetekennung"),
    }
}

fn time_without_reference() -> TrustedTimeState {
    TrustedTimeState::initial(UnixMillis::new(FLOOR_MS))
}

fn time_with_reference() -> TrustedTimeState {
    TrustedTimeState::from_persisted(
        UnixMillis::new(FLOOR_MS),
        Some(ea_time::IndependentTimeInput::new(
            ea_time::IndependentTimeKind::Receipt,
            ObjectHash::from(registry_support::trust_support::hash32(0xc5)),
            UnixMillis::new(REFERENCE_MS),
        )),
    )
    .expect("die persistierte Referenz liegt nicht hinter dem Zeitboden")
}

fn pin_of(line: &RegistryLineBuilder, index: usize) -> RegistryHeadPin {
    let head = line.heads()[index];
    RegistryHeadPin::new(head.version, head.object_hash)
}

fn store_at(
    line: &RegistryLineBuilder,
    index: usize,
    trusted_time: TrustedTimeState,
) -> WorkflowStore {
    WorkflowStore::new(
        state_key(),
        REVISION,
        trusted_time,
        Some(pin_of(line, index)),
    )
}

fn trust_of(line: &RegistryLineBuilder, store: &WorkflowStore) -> VerifiedTrust {
    let pin = store.pinned_head().map_or(Pin::None, |head| {
        Pin::Exact(head.registry_version(), head.registry_head_hash())
    });
    line.verified_with_record(
        pin,
        store.revision(),
        store.trusted_time().clone(),
        store.key(),
    )
}

fn select(
    line: &RegistryLineBuilder,
    store: &mut WorkflowStore,
    proposed: u64,
    wall_clock: i64,
) -> Result<RegistrySelectionOutcome, RegistryWorkflowError> {
    let trust = trust_of(line, store);
    RegistryWorkflowService::new(store).select(
        &trust,
        ChainSequence::new(proposed),
        UnixMillis::new(wall_clock),
        &[],
        None,
    )
}

fn selected(
    line: &RegistryLineBuilder,
    store: &mut WorkflowStore,
    proposed: u64,
    wall_clock: i64,
) -> SelectedRegistryHead {
    match select(line, store, proposed, wall_clock) {
        Ok(RegistrySelectionOutcome::Selected(head)) => head,
        Ok(_) => panic!("die Fassade muss an Sequenz {proposed} einen Kopf waehlen"),
        Err(error) => panic!(
            "die Auswahl an Sequenz {proposed} scheitert: {}",
            error.code()
        ),
    }
}

fn blocked(
    line: &RegistryLineBuilder,
    store: &mut WorkflowStore,
    proposed: u64,
    wall_clock: i64,
) -> &'static str {
    match select(line, store, proposed, wall_clock) {
        Ok(_) => panic!("die Fassade muss an Sequenz {proposed} blockieren"),
        Err(error) => error.code(),
    }
}

/// Der Grant-Plan, den der Schreiber aus diesem Kopf bildet — die FOLGE, an
/// der Wirksamkeit gemessen wird.
fn grant_plan(head: &SelectedRegistryHead) -> GrantPlanV1 {
    build_grant_plan(head)
        .expect("der Bestand des Kopfes traegt genau einen Wiederherstellungsempfaenger")
}

fn grants(plan: &GrantPlanV1, certificate: ObjectHash) -> bool {
    plan.items()
        .iter()
        .any(|item| item.recipient_certificate_hash() == CertificateHash::from(certificate))
}

fn hash_bytes(hash: ObjectHash) -> [u8; 32] {
    *hash.as_bytes()
}

/// Die lokale Geräteidentität der Adminmaschine an diesem Kopf.
fn local_admin(org: &Organization, head: &SelectedRegistryHead) -> VerifiedLocalDeviceIdentity {
    let certificate = CertificateHash::from(org.admin_certificate_object_hash);
    let device = head
        .active_certificate_fields(certificate)
        .expect("das Adminzertifikat der Linie ist am gewaehlten Kopf aktiv")
        .device_id;
    VerifiedLocalDeviceIdentity::verify(head, certificate, device)
        .expect("das Adminzertifikat der Linie ist die lokale Geraeteidentitaet")
}

// ===========================================================================
// Der Lauf
// ===========================================================================

/// Der Lebenszyklus, Abschnitt für Abschnitt, in EINEM Durchgang.
#[test]
fn the_organization_walks_its_lifecycle_from_bootstrap_to_destruction() {
    let ceremony = bootstrap_to_recovery_readiness();

    let mut org = organization_line();
    let mut store = store_at(&org.line, HEAD_ADMIN_BINDING, time_without_reference());

    revocation_stops_new_grants_from_its_effective_sequence(&org, &mut store);
    let activated = a_pending_device_is_confirmed_and_activated(&mut org);

    // Der Speicher rückt auf den Wachkopf: ab hier läuft die Linie unter der
    // Policy, die den Uhrvorlauf begrenzt.
    let mut store = store_at(&org.line, HEAD_GUARD_POLICY, time_without_reference());
    the_activation_grants_only_from_its_effective_sequence(&org, &mut store, activated);
    the_registry_holds_its_lease_rollback_fork_and_expiry(&org);
    the_administrative_clock_release_is_exact_expiring_and_single_use(&org);

    // Die Zeremonie ist mit dem Lauf fertig: sie steht weiterhin vor Schritt
    // 12, weil der Frischrechner-Recovery-Test der Gegenstand des zweiten
    // Systemziels ist (`e2e_recovery_fresh_machine`).
    assert_eq!(
        ceremony.production_state(),
        ProductionState::BlockedRecoveryTest
    );

    let entry = the_writer_transition_carries_the_published_transition_hash();
    the_amendment_leaves_the_original_bytes_untouched(entry);
    the_destruction_needs_a_privacy_release_two_approvers_and_leaves_a_stub();
}

// ---------------------------------------------------------------------------
// 1. Einrichtung bis zur Recovery-Bereitschaft
//
// Zeuge: `crates/ea-admin/tests/bootstrap.rs::production_state_requires_all_
// twelve_steps_and_fresh_recovery` (53/0/0) und `::an_anchor_that_names_
// another_genesis_is_refused`; Anker: `crates/ea-admin/tests/anchor_
// integrity.rs` (33/0/0).
//
// NAHT: die Zeremonie lebt vor der Registrierungslinie. Ihre Kennungen sind
// nicht die der Linie unten, und das ist richtig so — der finale Anker
// entsteht in Schritt 11, die Linie beginnt danach.
// ---------------------------------------------------------------------------

fn bootstrap_to_recovery_readiness() -> ceremony_support::BootstrapHarness {
    // Ein ungültiger Anker zuerst: er nennt einen anderen Genesis als den,
    // den diese Zeremonie gebunden hat, und ist in sich völlig stimmig —
    // `decode_trust_anchor` nimmt ihn an. Nur der Vergleich gegen die
    // unabhängig bestätigte Vorstufe fängt ihn.
    let mut refused = ceremony_support::BootstrapHarness::new();
    assert_eq!(
        refused
            .adopt_anchor_of_another_genesis()
            .expect_err("ein anderer Genesis ist ein anderer Bestand")
            .code(),
        "EA-CEREMONY-GENESIS-CONTEXT-MISMATCH"
    );
    assert_eq!(
        refused.production_state(),
        ProductionState::BlockedRecoveryTest
    );

    // Und derselbe Weg mit dem GÜLTIGEN Anker: elf Schritte, Genesis
    // gebunden — und der Produktivzustand bleibt gesperrt, bis Schritt 12
    // auf einem frischen Rechner gelaufen ist.
    let mut ceremony = ceremony_support::BootstrapHarness::new();
    ceremony
        .complete_through_genesis()
        .expect("die elf Schritte der Einrichtung tragen");
    assert_eq!(ceremony.step(), BootstrapStep::CreateGenesisAndFinalAnchor);
    assert_eq!(
        ceremony.production_state(),
        ProductionState::BlockedRecoveryTest,
        "ohne Schritt 12 gibt es keinen Produktivzustand"
    );
    ceremony
}

// ---------------------------------------------------------------------------
// 2. Der Widerruf und seine Grenze (AK 11)
//
// Zeuge: `tests/ea-system-tests/tests/e2e_registry_effectiveness.rs::a_
// revocation_stops_new_grants_from_its_effective_sequence_and_leaves_the_
// earlier_grant_intact` (7/0/0) und `crates/ea-admin/tests/registry_
// workflows.rs::a_revocation_recalls_nothing_and_stops_only_new_grants`
// (20/0/0).
// ---------------------------------------------------------------------------

fn revocation_stops_new_grants_from_its_effective_sequence(
    org: &Organization,
    store: &mut WorkflowStore,
) {
    let before = selected(&org.line, store, LAST_GRANTING_SEQUENCE, WALL_MS);
    let plan_before = grant_plan(&before);
    assert!(grants(&plan_before, org.reader_certificate_object_hash));
    assert!(grants(&plan_before, org.recovery_certificate_object_hash));

    let audit = AuditHarness::new(org.admin_certificate_object_hash, UnixMillis::new(NOW_MS));
    let events = RegistryEventFactory::new(&before, audit.service(), local_admin(org, &before));
    let (event, effect) = plan_revocation(
        &events,
        RegistryWindow {
            effective_from_sequence: ChainSequence::new(REVOCATION_SEQUENCE),
            valid_through_sequence: ChainSequence::new(59),
            not_after: UnixMillis::new(10_000),
        },
        org.reader_certificate_object_hash,
    )
    .expect("das Lesegeraet ist am gewaehlten Kopf aktiv und damit widerrufbar");

    assert_eq!(effect.target_class(), RevocationTargetClass::NonAdminDevice);
    assert_eq!(
        effect.stops_new_grants_from(),
        ChainSequence::new(REVOCATION_SEQUENCE)
    );
    assert!(!effect.recalls_issued_grants());
    assert!(!effect.recalls_decrypted_plaintext());
    assert!(matches!(
        event.change,
        RegistryChangeV1::Target { target_kind: 0, object_hash }
            if object_hash == org.reader_certificate_object_hash
    ));
    assert_eq!(
        event.registry_version,
        RegistryVersion::new(before.registry_version().get() + 1)
    );
    // Die Fabrik bucht keine Auditzeile; sie bereitet vor.
    assert_eq!(audit.booked(), 0);

    let at = selected(&org.line, store, REVOCATION_SEQUENCE, WALL_MS);
    let plan_at = grant_plan(&at);
    assert!(!grants(&plan_at, org.reader_certificate_object_hash));
    assert!(grants(&plan_at, org.recovery_certificate_object_hash));
    assert!(plan_at.hash() != plan_before.hash());

    // Der VORHER erteilte Grant bleibt unangetastet.
    let mut earlier = store_at(&org.line, HEAD_ADMIN_BINDING, time_without_reference());
    let again = selected(&org.line, &mut earlier, LAST_GRANTING_SEQUENCE, WALL_MS);
    assert_eq!(
        *grant_plan(&again).hash().as_bytes(),
        *plan_before.hash().as_bytes(),
        "derselbe Kopf bildet Byte fuer Byte denselben Plan"
    );
}

// ---------------------------------------------------------------------------
// 3. Der ausstehende Antrag: Fingerprint, Bestätigung, Aktivierung
//
// Zeugen: `crates/ea-admin/tests/fingerprint.rs` (5/0/0),
// `::ceremony_steps.rs::device_approve_walks_all_six_steps_in_order` (7/0/0),
// `::registry_workflows.rs` (20/0/0).
// ---------------------------------------------------------------------------

/// Der Objekthash des neu aktivierten Lesegeräts.
fn a_pending_device_is_confirmed_and_activated(org: &mut Organization) -> ObjectHash {
    // Die vorbereiteten Bytes liegen im Katalog, OHNE dass die Linie
    // vorrückt: genau der Stand, den eine Verwaltung vor der Veröffentlichung
    // in der Hand hat.
    let prepared = org.line.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Reader,
        marker: SECOND_READER_MARKER,
        effective_from: None,
    });
    let pending = PendingDeviceRegistration::new(org.line.exact_object_bytes(prepared).to_vec())
        .expect("die vorbereiteten Bytes tragen ein Geraetezertifikat");
    assert_eq!(pending.certificate_kind(), CertificateKindV1::Reader);
    assert_eq!(
        hash_bytes(pending.certificate_object_hash()),
        hash_bytes(prepared),
        "der Antrag meint genau die vorbereiteten Bytes"
    );

    // Ohne den über den zweiten Kanal zurückgelesenen Fingerprint gibt es
    // keine Bestätigung.
    assert_eq!(
        confirm_device_fingerprint(&pending, org.admin_certificate_object_hash)
            .err()
            .expect("ein abweichender Fingerprint bestaetigt nichts")
            .code(),
        "EA-WORKFLOW-FINGERPRINT-MISMATCH",
    );
    let confirmation = confirm_device_fingerprint(&pending, pending.fingerprint())
        .expect("der zurueckgelesene Fingerprint stimmt");

    let mut store = store_at(&org.line, HEAD_GUARD_POLICY, time_without_reference());
    let head = selected(&org.line, &mut store, 69, WALL_MS);
    let audit = AuditHarness::new(org.admin_certificate_object_hash, UnixMillis::new(NOW_MS));
    let events = RegistryEventFactory::new(&head, audit.service(), local_admin(org, &head));
    let planned = plan_device_approval(
        &events,
        RegistryWindow {
            effective_from_sequence: ChainSequence::new(70),
            valid_through_sequence: ChainSequence::new(169),
            not_after: UnixMillis::new(10_000),
        },
        &pending,
        confirmation,
    )
    .expect("Antrag und Bestaetigung liegen vor");

    let activation: BuiltHead = org.line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: SECOND_READER_MARKER,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    assert_eq!(
        activation.direct_object_hash.map(hash_bytes),
        Some(hash_bytes(prepared)),
        "die veroeffentlichte Aktivierung traegt genau die vorbereiteten Bytes"
    );
    assert_eq!(activation.version, planned.registry_version);
    assert_eq!(activation.effective_from, planned.effective_from_sequence);
    assert!(matches!(
        planned.change,
        RegistryChangeV1::Certificate { object_hash } if object_hash == prepared
    ));
    prepared
}

fn the_activation_grants_only_from_its_effective_sequence(
    org: &Organization,
    store: &mut WorkflowStore,
    activated: ObjectHash,
) {
    let before = selected(&org.line, store, 69, WALL_MS);
    assert!(!grants(&grant_plan(&before), activated));

    let after = selected(&org.line, store, 70, WALL_MS);
    let plan_after = grant_plan(&after);
    assert!(grants(&plan_after, activated));
    assert!(grants(&plan_after, org.recovery_certificate_object_hash));
    // Das WIDERRUFENE Lesegerät bleibt draußen; eine neue Freigabe holt es
    // nicht zurück.
    assert!(!grants(&plan_after, org.reader_certificate_object_hash));
}

// ---------------------------------------------------------------------------
// 4. Registrierung: Lease, Rückrollen, Gabelung, Überalterung (AK 24/35/49)
//
// Zeugen: `e2e_registry_effectiveness.rs::a_rollback_a_same_version_fork_and_
// an_expired_head_block_the_line` und `::the_sequence_lease_boundary_of_the_
// line_is_exact` (7/0/0), `crates/ea-admin/tests/registry_workflows.rs`
// (20/0/0).
// ---------------------------------------------------------------------------

fn the_registry_holds_its_lease_rollback_fork_and_expiry(org: &Organization) {
    // Der aktuelle Kopf der Linie ist die Aktivierung aus Abschnitt 3; sie
    // traegt das Lease 70..169.
    let current = org.line.heads()[org.line.heads().len() - 1];
    let pin_index = org.line.heads().len() - 1;
    let boundary = current.valid_through.get();

    // Das Lease ist EXAKT: die letzte Stelle traegt, die naechste nicht.
    let mut store = store_at(&org.line, pin_index, time_without_reference());
    let allowed = selected(&org.line, &mut store, boundary, WALL_MS);
    assert_eq!(allowed.proposed_sequence(), ChainSequence::new(boundary));
    let mut store = store_at(&org.line, pin_index, time_without_reference());
    assert_eq!(
        blocked(&org.line, &mut store, boundary + 1, WALL_MS),
        "EA-TRUST-SEQUENCE-LEASE"
    );

    // Rueckrollen: der gebundene Kopf ist aus der Quelle verschwunden, der
    // hoechste noch belegbare liegt DAHINTER.
    let mut rolled_back = org.line.clone();
    rolled_back.remove_object(current.object_hash);
    let mut store = WorkflowStore::new(
        state_key(),
        REVISION,
        time_without_reference(),
        Some(RegistryHeadPin::new(current.version, current.object_hash)),
    );
    assert_eq!(
        blocked(&rolled_back, &mut store, boundary - 4, WALL_MS),
        "EA-TRUST-REGISTRY-ROLLBACK"
    );

    // Gabelung: ZWEI Nachfolger derselben Registrierungsversion auf demselben
    // gebundenen Kopf. `add_branch` legt den Zwilling in den Katalog, ohne die
    // Linie vorzuruecken.
    let mut forked = org.line.clone();
    forked.add_branch(policy_action(), window(boundary + 1, boundary + 20));
    forked.push(policy_action(), window(boundary + 1, boundary + 10));
    let mut store = store_at(&forked, pin_index, time_without_reference());
    assert_eq!(
        blocked(&forked, &mut store, boundary + 1, WALL_MS),
        "EA-TRUST-REGISTRY-FORK"
    );

    // Ueberalterung: die Zeitgrenze liegt hinter der bewerteten Gegenwart.
    // Fail-closed, ohne zweite Gnadenfrist.
    let mut expired = org.line.clone();
    expired.push(
        policy_action(),
        HeadOptions {
            not_after: UnixMillis::new(NOW_MS - 100),
            ..window(boundary + 1, boundary + 10)
        },
    );
    let last = expired.heads().len() - 1;
    let mut store = WorkflowStore::new(
        state_key(),
        REVISION,
        time_without_reference(),
        Some(pin_of(&expired, last)),
    );
    assert_eq!(
        blocked(&expired, &mut store, boundary + 1, WALL_MS),
        "EA-TRUST-STALE"
    );
}

// ---------------------------------------------------------------------------
// 5. Die administrative Uhrfreigabe: exakt, ablaufend, EINMALIG
//
// Zeugen: `crates/ea-admin/tests/clock_release.rs::a_release_is_issued_once_
// consumed_once_and_replayed_never` (18/0/0) und `e2e_registry_
// effectiveness.rs::a_clock_release_binds_the_clock_it_was_issued_for_and_is_
// consumed_exactly_once` (7/0/0). Der NATIVE Release steht in
// `apps/cli/tests/operator_administration/clock_repair.rs` (13/0/0) und
// bleibt dort: er verlangt einen gemessenen Wirt.
// ---------------------------------------------------------------------------

fn the_administrative_clock_release_is_exact_expiring_and_single_use(org: &Organization) {
    let mut store = store_at(&org.line, HEAD_GUARD_POLICY, time_with_reference());
    let guard_head = selected(&org.line, &mut store, 65, WALL_MS);
    let proof = registry_support::operator_proof(
        &guard_head,
        org.admin_binding_object_hash,
        ReauthPurpose::ClockSkewRelease,
    );
    let audit = AuditHarness::new(
        org.admin_certificate_object_hash,
        UnixMillis::new(BLOCKED_WALL_MS),
    );
    let service =
        ClockReleaseService::new(&guard_head, audit.service(), org.admin_binding_object_hash);

    // Angeboten wird eine Freigabe nur, wenn die Uhr wirklich sperrt.
    let time = store.trusted_time().clone();
    assert_eq!(
        service
            .availability(&time, UnixMillis::new(WALL_MS))
            .expect("die Bewertung der ungesperrten Uhr gelingt"),
        ClockReleaseAvailability::NotBlocked
    );
    assert_eq!(
        service
            .availability(&time, UnixMillis::new(BLOCKED_WALL_MS))
            .expect("die Bewertung der gesperrten Uhr gelingt"),
        ClockReleaseAvailability::Offered
    );

    // GENAU EINE Ausstellung; alle drei Anwendungen legen DIESELBEN Bytes vor.
    let trust = trust_of(&org.line, &store);
    let candidate = ea_trust::verify_registry_candidate(&trust, ChainSequence::new(65))
        .expect("der gesperrte Kandidat der Linie verifiziert");
    let release = service
        .issue(
            ClockReleaseRequest {
                candidate: &candidate,
                trusted_time: &time,
                observed_os_wall_clock: UnixMillis::new(BLOCKED_WALL_MS),
                justification: ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                issued_at: UnixMillis::new(ISSUED_AT_MS),
                expires_at: UnixMillis::new(EXPIRES_AT_MS),
            },
            &proof,
        )
        .expect("die Verwaltung stellt eine Freigabe aus");
    assert_eq!(audit.booked(), 1);

    // Die Uhr läuft um eine Millisekunde ZURÜCK: sie sperrt weiter, ist aber
    // nicht mehr die Uhr, für die diese Freigabe ausgestellt wurde.
    let commits_before = store.selection_commits();
    assert_eq!(
        apply_at(
            &org.line,
            &mut store,
            65,
            ROLLED_BACK_WALL_MS,
            release.exact_bytes()
        ),
        "EA-TRUST-CLOCK-RELEASE-MISMATCH"
    );
    assert_eq!(store.selection_commits(), commits_before);
    assert_eq!(store.consumed_releases(), 0);

    // Dieselben Bytes an der Uhr, für die sie ausgestellt wurden.
    let floor_before = store.trusted_time().floor();
    let trust = trust_of(&org.line, &store);
    let outcome = apply_clock_release(
        &mut store,
        &trust,
        ChainSequence::new(65),
        UnixMillis::new(BLOCKED_WALL_MS),
        &[],
        release.exact_bytes(),
    )
    .expect("die Freigabe traegt genau eine gesperrte Auswahl");
    assert!(matches!(outcome, RegistrySelectionOutcome::Selected(_)));
    assert_eq!(store.selection_commits(), commits_before + 1);
    assert_eq!(store.consumed_releases(), 1);
    assert_eq!(store.trusted_time().floor(), floor_before);
    assert_eq!(floor_before, UnixMillis::new(FLOOR_MS));

    // Und genau EINMAL.
    assert_eq!(
        apply_at(
            &org.line,
            &mut store,
            65,
            BLOCKED_WALL_MS,
            release.exact_bytes()
        ),
        "EA-TRUST-CLOCK-RELEASE-REPLAY"
    );
    assert_eq!(store.consumed_releases(), 1);
}

fn apply_at(
    line: &RegistryLineBuilder,
    store: &mut WorkflowStore,
    proposed: u64,
    wall_clock: i64,
    bytes: &[u8],
) -> &'static str {
    let trust = trust_of(line, store);
    let result: Result<RegistrySelectionOutcome, ClockReleaseWorkflowError> = apply_clock_release(
        store,
        &trust,
        ChainSequence::new(proposed),
        UnixMillis::new(wall_clock),
        &[],
        bytes,
    );
    result
        .err()
        .expect("der Dreischritt muss hier geschlossen scheitern")
        .code()
}

// ---------------------------------------------------------------------------
// 6. Der Writer-Übergang (AK 47)
//
// Zeugen: `crates/ea-admin/tests/writer_transition.rs` (15/0/0) und
// `tests/ea-system-tests/tests/e2e_writer_transition.rs::first_new_writer_
// entry_binds_exact_transition_hash`.
//
// NAHT: der Übergang läuft auf der Linie der WRITER-Fixture, weil er zwei
// freigegebene Writer-Zertifikate, zwei Geräte mit eigenem Schlüsselspeicher
// und einen echten Bestand auf der Platte verlangt. Die Linie oben führt
// keines davon.
// ---------------------------------------------------------------------------

/// Der erste Eintrag des NEUEN Writers — Eingang des Nachtrags.
struct TransitionedWriter {
    harness: transition_support::writer_support::TransitionHarness,
    /// Der letzte Eintrag des ALTEN Writers — die Checkpoint-Behauptung, die
    /// jeder folgende Abschluss des neuen Writers mitfuehrt.
    first: ea_writer::FinalizeOutcome,
}

fn the_writer_transition_carries_the_published_transition_hash() -> TransitionedWriter {
    let mut harness = transition_support::writer_support::TransitionHarness::new();
    let first = harness.old_writer_finalizes_first_entry();
    assert_eq!(first.sequence, ChainSequence::new(0));

    let admin: AdminTransition = run_admin_transition(
        &mut harness,
        TrustedChainHead {
            chain_sequence: first.sequence,
            entry_hash: first.entry_hash,
        },
    );

    // Die Verwaltung: das Änderung-3-Ereignis nennt GENAU die Bytes, die die
    // Wurzelzeremonie herausgegeben hat.
    assert!(admin.transition_hash == ea_crypto::object_hash(&admin.published));
    assert!(matches!(
        admin.event.change,
        RegistryChangeV1::WriterTransition { object_hash } if object_hash == admin.transition_hash
    ));
    assert_eq!(admin.event.effective_from_sequence, ChainSequence::new(1));

    // Der Kern: ab der Wirksamkeitssequenz führt der Nachfolgekopf den neuen
    // Writer und den alten nicht mehr.
    let head = harness.post_transition_head(1);
    assert!(
        head.current_writer_certificate_hash() == Some(harness.new_writer_certificate_hash()),
        "ab der Wirksamkeitssequenz laeuft der neue Writer"
    );
    assert!(
        head.active_certificate_fields(harness.old_writer_certificate_hash())
            .is_none(),
        "der alte Writer ist ab der Wirksamkeitssequenz widerrufen"
    );
    assert!(
        head.effective_writer_transition()
            .is_some_and(|transition| transition.object_hash() == admin.transition_hash)
    );
    // Derselbe Antrag ist am Nachfolgekopf nicht mehr vorbereitbar.
    assert_eq!(
        WriterTransitionService::new(&head)
            .prepare(&admin.request, admin.authorization_object_hash)
            .err()
            .expect("der alte Writer ist nicht mehr der laufende")
            .code(),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
    );

    // Der NEUE Writer: sein erster Eintrag ist der `keyTransition`, und sein
    // Manifest trägt GENAU den Objekthash der veröffentlichten Bytes.
    let claims = harness.checkpoint_claims_through(&first);
    let key_transition = new_writer_finalizes_key_transition(&harness, &head, &claims);
    assert_eq!(key_transition.sequence, ChainSequence::new(1));
    let entry = harness.old().published_entry(key_transition.entry_hash);
    let fields = entry.value().manifest().fields();
    assert!(fields.writer_transition_event_hash == Some(admin.transition_hash));
    assert!(fields.writer_certificate_hash == harness.new_writer_certificate_hash());
    assert!(fields.previous_entry_hash == Some(first.entry_hash));

    let plaintext = harness.decrypt_entry_as_recovery_recipient(key_transition.entry_hash);
    let validated = SchemaRegistry::v1()
        .validate("ea.key-transition", SCHEMA_VERSION_V1, &plaintext)
        .expect("die entschluesselte Nutzlast ist ein gueltiger keyTransition");
    let PayloadV1::KeyTransition(payload) = validated.payload() else {
        panic!("die Nutzlast ist kein keyTransition");
    };
    assert!(payload.writer_transition_event_object_hash() == admin.transition_hash);
    assert_eq!(harness.old().staged_object_count(), 0);

    TransitionedWriter { harness, first }
}

// ---------------------------------------------------------------------------
// 7. Der Nachtrag (AK 18)
//
// Zeuge: `crates/ea-admin/tests/amendment.rs::amendment_finalization_
// preserves_original_bytes_and_reader_keeps_multiple_amendments` (1/0/0).
//
// GRENZE: die ZWEITE Hälfte jenes Zeugen — dass ein Reader mehrere verkettete
// Nachträge an einem Faden hält — bleibt dort. Sie verlangt eine Linie mit
// `reader_recipient_openable`, und die Übergangskulisse führt stattdessen den
// öffenbaren Wiederherstellungsempfänger. Hier wird die erste Hälfte
// gemessen: der Nachtrag referenziert das Original und ändert keine
// Originalbytes.
// ---------------------------------------------------------------------------

fn the_amendment_leaves_the_original_bytes_untouched(writer: TransitionedWriter) {
    let TransitionedWriter { harness, first } = writer;

    // Der Nachtrag verifiziert das Original IM Bestand gegen den Anker; dazu
    // muessen die Vertrauensobjekte der Linie dort liegen.
    harness.old().materialize_trust_objects();

    // Ein Einsatz des neuen Writers an N+2 — er ist das Original, das der
    // Nachtrag berichtigt.
    let claims = harness.checkpoint_claims_through(&first);
    let incident_head = harness.post_transition_head(2);
    let original = transition_support::new_writer_finalizes_incident(
        &harness,
        &incident_head,
        &claims,
        "2026-000043",
    );
    let before = harness
        .old()
        .published_entry(original.entry_hash)
        .exact_bytes()
        .as_bytes()
        .to_vec();

    // Die Berichtigungsreferenz kommt aus dem ENTSCHLÜSSELTEN Original: die
    // Datensatzkennung aus der versiegelten Nutzlast, Sequenz und
    // Eintragshash aus dem, was der Writer gemeldet hat.
    let plaintext = harness.decrypt_entry_as_recovery_recipient(original.entry_hash);
    let validated = SchemaRegistry::v1()
        .validate("ea.incident", SCHEMA_VERSION_V1, &plaintext)
        .expect("die entschluesselte Nutzlast ist ein gueltiger Einsatz");
    let PayloadV1::Incident(incident) = validated.payload() else {
        panic!("die Nutzlast ist kein Einsatz");
    };
    let reference = ea_reader::CorrectionReference {
        original_record_id: incident.header().record_id(),
        original_sequence: original.sequence,
        original_entry_hash: original.entry_hash,
    };

    let head = harness.post_transition_head(3);
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, &head, &claims);
    let anchor = harness.old().anchor();
    let admin = AmendmentDraftService::new(&service, &anchor);
    let now = harness.old().observed_now();
    let content = || ea_writer::AmendmentContentV1 {
        timezone: "Europe/Berlin".into(),
        source: transition_support::writer_support::valid_incident().source,
        reason: "Berichtigung des Lebenszyklus".into(),
        changes: vec![
            ea_schema::AmendmentChangeV1::new("notes", "Ergaenzung nach dem Uebergang").unwrap(),
        ],
    };
    let input = || {
        admin
            .create_from_reference(reference, content(), now)
            .expect("der Nachtrag entsteht aus der Berichtigungsreferenz")
    };
    let proof = harness.new_writer_proof(&head);
    let preview = service
        .preview_amendment(&proof, input(), now)
        .expect("die Vorschau des Nachtrags entsteht");
    let outcome = service
        .finalize_amendment(&proof, input(), &preview, now)
        .expect("der Nachtrag schliesst ab");

    // Das Original bleibt Byte für Byte, was es war.
    assert_eq!(
        harness
            .old()
            .published_entry(original.entry_hash)
            .exact_bytes()
            .as_bytes(),
        before.as_slice(),
        "der Nachtrag aendert keine Originalbytes"
    );
    assert!(outcome.entry_hash != original.entry_hash);
    assert_eq!(
        outcome.sequence,
        ChainSequence::new(original.sequence.get() + 1)
    );

    // Und der Nachtrag nennt das Original.
    let amended = harness.decrypt_entry_as_recovery_recipient(outcome.entry_hash);
    let validated = SchemaRegistry::v1()
        .validate("ea.amendment", SCHEMA_VERSION_V1, &amended)
        .expect("die entschluesselte Nutzlast ist ein gueltiger Nachtrag");
    let PayloadV1::Amendment(amendment) = validated.payload() else {
        panic!("die Nutzlast ist kein Nachtrag");
    };
    assert!(amendment.original_entry_hash() == original.entry_hash);
    assert_eq!(amendment.original_sequence(), original.sequence);
}

// ---------------------------------------------------------------------------
// 8. Die kontrollierte Vernichtung (AK 30, 41, 44)
//
// Zeugen: `crates/ea-destruction/tests/authorization.rs` (10/0/0) für das
// Datenschutz-Gate und die zwei Approver, `::stub.rs` und
// `crates/ea-verify/tests/destruction_stub.rs` (8/0/0) für den Stub.
//
// NAHT: die Vernichtung verlangt eine Policy mit `destructionEnabled` UND
// einem `edsPrivacyDecisionDocumentHash`, zwei Approver-Zertifikate mit
// `destructionApprove` verschiedener Subjekte und ein Writer-Zertifikat der
// Linie. Das führt die Kulisse `crates/ea-destruction/tests/support/mod.rs`,
// und keine der drei Linien darüber.
//
// GRENZE: die physischen Zweige (sofort, backup-pending, unerreichbar,
// Fortsetzen) laufen nativ in `einsatzarchiv-cli --test operator
// process_native::destruction::` und sind hier ausdrücklich nicht gebündelt —
// sie verlangen einen gemessenen Wirt und laufen seriell in Stunden.
// ---------------------------------------------------------------------------

fn the_destruction_needs_a_privacy_release_two_approvers_and_leaves_a_stub() {
    // Ohne beide signierten Datenschutzbedingungen startet nichts.
    for (enabled, document) in [(false, false), (false, true), (true, false)] {
        let refused = destruction_support::Fixture::new(enabled, document, false);
        assert_eq!(
            verify_authorization(&refused.authorization(), &refused.head())
                .expect_err("ohne dokumentierte Freigabe startet keine Vernichtung")
                .code(),
            "EA-DESTRUCTION-PRIVACY-GATE"
        );
    }

    // Zwei Zertifikate EINER Person sind nicht zwei Approver.
    let one_person = destruction_support::Fixture::new(true, true, true);
    assert_eq!(
        verify_authorization(&one_person.authorization(), &one_person.head())
            .expect_err("eine Person ist kein Vier-Augen-Prinzip")
            .code(),
        "EA-DESTRUCTION-APPROVERS"
    );

    // Mit Freigabe und zwei Approvern: die Autorisierung bindet ihre exakten
    // Bytes, und der Stub bewahrt die Identität des Originals ohne einen
    // einzigen Ciphertext-Byte.
    let organization =
        destruction_support::with_writer(destruction_support::Fixture::new(true, true, false));
    let original = destruction_support::entry(&organization);
    let encoded = encode_entry_package(&original).expect("das Eintragspaket kodiert");
    let ParsedArchiveObject::Entry(parsed) =
        decode_exact_object(encoded.as_bytes()).expect("das Eintragspaket dekodiert")
    else {
        panic!("die Fixture legt ein Eintragspaket vor");
    };
    let mut fields = organization.fields();
    fields.targets = vec![DestructionTargetV1::new(
        *original.entry_hash().as_bytes(),
        original.manifest().fields().chain_sequence.get(),
    )];
    let exact = organization.sign(fields, organization.approvers.to_vec());
    let authorization = verify_authorization(&exact, &organization.head())
        .expect("zwei Approver und die dokumentierte Freigabe tragen");
    assert_eq!(authorization.exact_bytes(), exact);

    let target = authorization
        .verify_target(&original, &organization.head())
        .expect("der benannte Eintrag ist das Ziel");
    let stub = build_stub(&parsed, &authorization, &target).expect("der Stub entsteht");
    let ParsedArchiveObject::Destroyed(parsed_stub) =
        decode_exact_object(stub.as_bytes()).expect("der Stub dekodiert")
    else {
        panic!("der Stub ist ein Destroyed Entry Stub");
    };
    let body = parsed_stub.value();
    assert_eq!(
        body.signed_manifest().exact_bytes(),
        original.signed_manifest().exact_bytes()
    );
    assert!(body.entry_hash() == original.entry_hash());
    assert!(body.destruction_authorization_object_hash() == authorization.object_hash());
    assert!(
        !stub
            .as_bytes()
            .windows(original.ciphertext().len())
            .any(|window| window == original.ciphertext()),
        "der Stub traegt keinen Ciphertext"
    );
    verify_stub_against_original(stub.as_bytes(), &parsed, &authorization, &target)
        .expect("der gueltige Stub prueft gegen sein Original");

    // Die unerklärte Entfernung: ein Byte gekippt, und der Stub erklärt
    // nichts mehr.
    let mut unexplained = stub.as_bytes().to_vec();
    let last = unexplained.len() - 1;
    unexplained[last] ^= 1;
    assert!(
        verify_stub_against_original(&unexplained, &parsed, &authorization, &target).is_err(),
        "eine unerklaerte Loeschung ist kein gueltiger Stub"
    );
}
