//! Der Systemzeuge der WIRKSAMKEIT einer Registrierungsaenderung.
//!
//! # Die eine Aussage
//!
//! Eine Registrierungsaenderung wird ab ihrer `effectiveFromSequence` wirksam
//! und NICHT frueher. Gemessen wird das nicht an einem Flag, sondern an der
//! Folge, die die Aenderung im Betrieb hat: an dem Grant-Plan, den
//! [`ea_writer::build_grant_plan`] aus
//! [`ea_trust::SelectedRegistryHead::active_certificates`] bildet. Ein
//! widerrufenes Lesezertifikat bekommt ab der Wirksamkeitssequenz keinen neuen
//! Grant mehr, und der davor gebildete Plan bleibt Byte fuer Byte derselbe.
//!
//! # Warum dieser Zeuge in `ea-system-tests` wohnt
//!
//! Er spannt drei Kisten zusammen, die sich untereinander nicht kennen
//! duerfen: die Verwaltungsfassade `ea-admin` plant die Aenderung, der
//! Auswahlkern `ea-trust` waehlt den Kopf, und der Schreiber `ea-writer`
//! bildet daraus den Empfaengerplan. `ea-admin` haelt bewusst keine
//! `ea-writer`-Kante; die Zusammenschau hat nur hier einen Ort.
//!
//! # Abgrenzung gegen `task8_trust_time.rs`
//!
//! Jener Zeuge hat die ZEITKETTE zum Gegenstand: er baut Receipt und
//! Checkpoint selbst, kodiert die Freigabezeile von Hand und belegt, dass
//! Anker, Uebergaenge und Freigabe unter einer Ein-Byte-Mutation geschlossen
//! ausfallen. Nichts davon wird hier wiederholt. Dieser Zeuge nimmt die
//! geprueften Zustaende als GEGEBEN und fragt, was die ea-admin-Fassade aus
//! ihnen macht: welche Blockade sie meldet, welchen Aktivierungsvorgang sie
//! plant und welche Folge die geplante Aenderung ab ihrer Wirksamkeitssequenz
//! hat. Die unabhaengige Zeitreferenz der Uhrfreigabe kommt deshalb aus dem
//! persistierten Zustand und nicht aus einer zweiten, hier nachgebauten
//! Quittung.
//!
//! # Abgrenzung gegen `crates/ea-admin/tests/registry_workflows.rs`
//!
//! Dort wird jede Blockade EINZELN an einer eigenen Zweikopf-Kulisse
//! gemessen. Hier gibt es EINE archivfoermige Linie — Anfangspolicy,
//! Wiederherstellungsempfaenger, Lesegeraet, Adminzertifikat, Adminbindung,
//! Widerruf, Wachrichtlinie —, und jede Blockade ist eine Abzweigung genau
//! dieser Linie. Die Codes sind dieselben, weil es fuer denselben Befund nur
//! eine Wahrheit gibt; der Gegenstand ist die Kette bis zur Folge.
//!
//! # Die acht Blockaden
//!
//! `EA-TRUST-REGISTRY-ROLLBACK`, `EA-TRUST-REGISTRY-FORK`,
//! `EA-TRUST-PENDING-FUTURE`, `EA-TRUST-STALE`, `EA-TRUST-SEQUENCE-LEASE`,
//! `EA-TRUST-SUCCESSOR-READY` (serverbekannter neuerer anwendbarer Kopf),
//! `EA-TRUST-CLOCK-RELEASE-MISMATCH` (Uhrruecklauf nach der Ausstellung) und
//! `EA-TRUST-CLOCK-RELEASE-REPLAY`.
//!
//! # Was hier NICHT gerechnet wird
//!
//! Keine Millisekunde. Skew, Ablauf, Alterung und Lease kommen aus `ea-time`
//! und `ea-trust`; dieser Zeuge liest ihre Befunde ab, statt sie
//! nachzurechnen. Und keine Nonce erreicht eine Ausgabe: der Speicher zaehlt
//! verbrauchte Freigaben, er nennt sie nicht.
#![allow(clippy::too_many_lines)]

#[path = "registry_effectiveness_support/mod.rs"]
mod support;

use ea_admin::clock_release::{
    ClockReleaseAvailability, ClockReleaseRequest, ClockReleaseService, ClockReleaseWorkflowError,
    apply_clock_release,
};
use ea_admin::device::{
    PendingDeviceRegistration, confirm_device_fingerprint, plan_device_approval,
};
use ea_admin::registry::{RegistryEventFactory, RegistryWorkflowError, RegistryWorkflowService};
use ea_admin::revocation::{RevocationTargetClass, plan_revocation};
use ea_admin::{RegistryWindow, VerifiedLocalDeviceIdentity};
use ea_crypto::CanonicalPublicCoseKey;
use ea_format::{
    CertificateKindV1, ClockReleaseJustificationV1, GrantPlanV1, OperatorRoleV1, RegistryChangeV1,
};
use ea_operator::ReauthPurpose;
use ea_time::{IndependentTimeInput, IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    RegistryHeadPin, RegistrySelectionOutcome, SelectedRegistryHead, TrustStateKey, VerifiedTrust,
};
use ea_types::{CertificateHash, ChainSequence, DeviceId, ObjectHash, RegistryVersion, UnixMillis};
use ea_writer::build_grant_plan;

use support::trust_support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};
use support::{AuditHarness, INSTANCE_SECRET, OS_ACCOUNT_MARKER, WorkflowStore, public_key};

// ===========================================================================
// Die Zahlen der Kulisse
// ===========================================================================

/// Der persistierte Anfangsstand der Zustandsablage.
const REVISION: u64 = 17;
/// Der persistierte Zeitboden.
const FLOOR_MS: i64 = 3_100;
/// Die gepruefte Zeit der persistierten unabhaengigen Referenz.
const REFERENCE_MS: i64 = 3_000;
/// Die Betriebssystemuhr der ungesperrten Laeufe: `3_000 <= 3_000 + 50`.
const WALL_MS: i64 = 3_000;
/// `raw_now` der ungesperrten Bewertung: `max(3_100, 3_000)`.
const NOW_MS: i64 = FLOOR_MS;
/// Eine Wanduhr JENSEITS der Wachgrenze: `3_201 > 3_000 + 50`.
const BLOCKED_WALL_MS: i64 = 3_201;
/// Dieselbe Sperre, aber die Uhr ist um eine Millisekunde ZURUECKgelaufen —
/// immer noch jenseits der Grenze, aber nicht mehr die Uhr, fuer die die
/// Freigabe ausgestellt wurde.
const ROLLED_BACK_WALL_MS: i64 = 3_200;
/// Die untere Grenze des Freigabefensters, EINSCHLIESSEND.
const ISSUED_AT_MS: i64 = 3_150;
/// Die obere Grenze des Freigabefensters, EINSCHLIESSEND.
const EXPIRES_AT_MS: i64 = 3_250;
/// Die Wachrichtlinie der Linie erlaubt 50 ms Vorlauf.
const GUARD_SKEW_MS: u64 = 50;

/// Die Marke des Wiederherstellungsempfaengers.
const RECOVERY_MARKER: u8 = 0x51;
/// Die Marke des Lesegeraets, das spaeter widerrufen wird.
const READER_MARKER: u8 = 0x63;
/// Die Marke des zweiten, spaeter freigegebenen Lesegeraets.
const SECOND_READER_MARKER: u8 = 0x64;
/// Die Marke des Adminzertifikats und seiner Bindung.
const ADMIN_MARKER: u8 = 0x11;

/// Die Sequenz, an der das erste Lesegeraet zuletzt einen Grant bekommt.
const LAST_GRANTING_SEQUENCE: u64 = 49;
/// Die `effectiveFromSequence` des Widerrufs — ab hier bleibt der Grant aus.
const REVOCATION_SEQUENCE: u64 = 50;

/// `scene()` baut die Koepfe in dieser Reihenfolge: 0 Anfangspolicy,
/// 1 Wiederherstellungsempfaenger, 2 Lesegeraet, 3 Adminzertifikat,
/// 4 Adminbindung, 5 Widerruf des Lesegeraets, 6 Wachrichtlinie. Benannt sind
/// die beiden, an denen die Zeugen binden.
const HEAD_ADMIN_BINDING: usize = 4;
const HEAD_GUARD_POLICY: usize = 6;
/// Der Kopf, den ein Blockadenzeuge selbst an die Linie haengt.
const HEAD_APPENDED: usize = HEAD_GUARD_POLICY + 1;

// ===========================================================================
// Die Linie
// ===========================================================================

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

/// Der KEM-Schluessel eines Empfaengers.
///
/// Ohne diese Ueberschreibung traegt JEDER Reader und JEDER
/// Wiederherstellungsempfaenger `x25519([0xa5; 32])`; `GrantPlanV1::new`
/// wiese den Plan dann als doppelten Empfaenger ab, und der Zeuge kaeme gar
/// nicht bis zu seiner Aussage.
fn kem_key(marker: u8) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::x25519([marker; 32]).expect("der Fixturschluessel bleibt kanonisch")
}

/// Alles, was ein Zeuge ueber die gebaute Linie wissen muss.
struct Scene {
    line: RegistryLineBuilder,
    recovery_certificate_object_hash: ObjectHash,
    reader_certificate_object_hash: ObjectHash,
    admin_certificate_object_hash: ObjectHash,
    admin_binding_object_hash: ObjectHash,
}

/// Baut die EINE archivfoermige Linie dieses Zeugen.
///
/// Sieben Koepfe, jeder mit einem eigenen Sequenz-Lease von zehn Stellen:
/// Anfangspolicy, Wiederherstellungsempfaenger, Lesegeraet, Adminzertifikat,
/// Adminbindung, Widerruf des Lesegeraets, Wachrichtlinie. Der Widerruf liegt
/// MITTEN in der Linie und nicht an ihrem Ende: nur so laesst sich belegen,
/// dass die Aenderung ab ihrer Wirksamkeitssequenz greift und die Linie
/// danach normal weiterlaeuft.
fn scene() -> Scene {
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
            // Ohne diese beiden Ueberschreibungen naehme `reauthenticate` die
            // Bindung nicht an: die Fixture nennt sonst einen ausgedachten
            // Instanzabdruck, den kein echter Schluessel trifft.
            binding_instance_key_thumbprint_override: Some(
                public_key(INSTANCE_SECRET).thumbprint(),
            ),
            binding_os_account_hash_override: Some(support::trust_support::hash32(
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

    Scene {
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

/// Der Zustandsschluessel der Kulisse.
///
/// Das Geraet IST das des Adminzertifikats: die Freigabezeile bindet
/// `targetDeviceId`, und `verify_clock_release` vergleicht sie gegen genau
/// diesen Schluessel. Ein anderes Geraet hier machte jede Freigabe
/// unanwendbar — aus dem richtigen Grund, aber am falschen Zeugen.
fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: support::trust_support::organization(),
        device_id: DeviceId::try_from(&[ADMIN_MARKER.wrapping_add(0x40); 16][..])
            .expect("16 Byte sind eine Geraetekennung"),
    }
}

/// Der Zeitzustand OHNE unabhaengige Referenz.
///
/// `FutureSkew::Blocked` ist ohne Referenz strukturell unerreichbar; die
/// Blockadenzeugen kommen deshalb ohne sie aus und messen genau ihren eigenen
/// Befund statt eines Zeitversatzes.
fn time_without_reference() -> TrustedTimeState {
    TrustedTimeState::initial(UnixMillis::new(FLOOR_MS))
}

/// Derselbe Zustand MIT der persistierten unabhaengigen Referenz.
fn time_with_reference() -> TrustedTimeState {
    TrustedTimeState::from_persisted(
        UnixMillis::new(FLOOR_MS),
        Some(IndependentTimeInput::new(
            IndependentTimeKind::Receipt,
            ObjectHash::from(support::trust_support::hash32(0xc5)),
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

/// Der gepruefte Bestand, gelesen aus dem AKTUELLEN Stand des Speichers.
///
/// Der Pin kommt nicht aus einer Konstanten, sondern aus dem, was die letzte
/// Auswahl gebucht hat — sonst waere der Speicher nur Beiwerk.
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

/// Waehlt ueber die FASSADE.
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

/// Der gewaehlte Kopf oder ein Abbruch mit sprechendem Text.
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

/// Der Code, mit dem die Fassade blockiert.
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

/// Der Grant-Plan, den der Schreiber aus diesem Kopf bildet.
///
/// Das ist die FOLGE, an der die Wirksamkeit gemessen wird — nicht ein
/// zweites, hier nachgebautes Aktivbestandsmodell.
fn grant_plan(head: &SelectedRegistryHead) -> GrantPlanV1 {
    build_grant_plan(head)
        .expect("der Bestand des Kopfes traegt genau einen Wiederherstellungsempfaenger")
}

/// Die Bytes eines Hashes fuer die FEHLERMELDUNG eines Zeugen.
///
/// [`ObjectHash`] und [`Hash32`] tragen im ganzen Baum bewusst kein `Debug` —
/// ein Hash soll nicht beilaeufig in eine Ausgabe geraten. Ein
/// `assert!(a == b)` daneben meldete deshalb nichts ausser „false"; ein Zeuge,
/// der scheitert, muss aber die auseinanderlaufenden Werte zeigen koennen.
fn hash_bytes(hash: ObjectHash) -> [u8; 32] {
    *hash.as_bytes()
}

fn optional_hash_bytes(hash: Option<ObjectHash>) -> Option<[u8; 32]> {
    hash.map(hash_bytes)
}

fn grants(plan: &GrantPlanV1, certificate: ObjectHash) -> bool {
    plan.items()
        .iter()
        .any(|item| item.recipient_certificate_hash() == CertificateHash::from(certificate))
}

/// Die lokale Geraeteidentitaet der Adminmaschine an diesem Kopf.
fn local_admin(scene: &Scene, head: &SelectedRegistryHead) -> VerifiedLocalDeviceIdentity {
    let certificate = CertificateHash::from(scene.admin_certificate_object_hash);
    let device = head
        .active_certificate_fields(certificate)
        .expect("das Adminzertifikat der Linie ist am gewaehlten Kopf aktiv")
        .device_id;
    VerifiedLocalDeviceIdentity::verify(head, certificate, device)
        .expect("das Adminzertifikat der Linie ist die lokale Geraeteidentitaet")
}

// ===========================================================================
// 1. Die Wirksamkeit ab der Wirksamkeitssequenz
// ===========================================================================

#[test]
fn a_revocation_stops_new_grants_from_its_effective_sequence_and_leaves_the_earlier_grant_intact() {
    let scene = scene();
    let mut store = store_at(&scene.line, HEAD_ADMIN_BINDING, time_without_reference());

    // VOR der Wirksamkeitssequenz: das Lesegeraet ist Empfaenger.
    let before = selected(&scene.line, &mut store, LAST_GRANTING_SEQUENCE, WALL_MS);
    let plan_before = grant_plan(&before);
    assert!(grants(&plan_before, scene.reader_certificate_object_hash));
    assert!(grants(&plan_before, scene.recovery_certificate_object_hash));

    // Die Fassade plant den Widerruf an genau dieser Grenze — und sagt selbst,
    // wie weit er reicht.
    let audit = AuditHarness::new(scene.admin_certificate_object_hash, UnixMillis::new(NOW_MS));
    let events = RegistryEventFactory::new(&before, audit.service(), local_admin(&scene, &before));
    let (event, effect) = plan_revocation(
        &events,
        RegistryWindow {
            effective_from_sequence: ChainSequence::new(REVOCATION_SEQUENCE),
            valid_through_sequence: ChainSequence::new(59),
            not_after: UnixMillis::new(10_000),
        },
        scene.reader_certificate_object_hash,
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
            if object_hash == scene.reader_certificate_object_hash
    ));
    assert_eq!(
        event.effective_from_sequence,
        ChainSequence::new(REVOCATION_SEQUENCE)
    );
    assert_eq!(
        event.registry_version,
        RegistryVersion::new(before.registry_version().get() + 1)
    );
    // Die Fabrik bucht keine Auditzeile; sie bereitet vor.
    assert_eq!(audit.booked(), 0);

    // AB der Wirksamkeitssequenz: kein neuer Grant fuer dasselbe Zertifikat.
    let at = selected(&scene.line, &mut store, REVOCATION_SEQUENCE, WALL_MS);
    let plan_at = grant_plan(&at);
    assert!(!grants(&plan_at, scene.reader_certificate_object_hash));
    assert!(grants(&plan_at, scene.recovery_certificate_object_hash));
    assert!(plan_at.hash() != plan_before.hash());

    // Und der VORHER erteilte Grant bleibt unangetastet: derselbe Kopf bildet
    // Byte fuer Byte denselben Plan, obwohl der Widerruf laengst in der Linie
    // steht und der Speicher inzwischen weitergerueckt ist.
    let mut earlier = store_at(&scene.line, HEAD_ADMIN_BINDING, time_without_reference());
    let again = selected(&scene.line, &mut earlier, LAST_GRANTING_SEQUENCE, WALL_MS);
    assert_eq!(
        *grant_plan(&again).hash().as_bytes(),
        *plan_before.hash().as_bytes(),
        "derselbe Kopf bildet Byte fuer Byte denselben Plan"
    );
}

// ===========================================================================
// 2. Der positive Durchlauf: Antrag, Bestaetigung, Aktivierung, Folge
// ===========================================================================

#[test]
fn a_confirmed_device_request_grants_only_from_the_sequence_its_activation_names() {
    let mut scene = scene();
    let mut store = store_at(&scene.line, HEAD_GUARD_POLICY, time_without_reference());
    let head = selected(&scene.line, &mut store, 69, WALL_MS);

    // Die vorbereiteten Bytes sind FRISCH: ein Registrierungsereignis, das ein
    // bereits aktives Zertifikat aktivieren will, ist in `ea-trust` nicht
    // selektierbar. `add_prepared` legt Autorisierung und Ziel in den Katalog,
    // OHNE die Linie vorzuruecken — genau der Stand, den eine Verwaltung in
    // der Hand hat, bevor die Aktivierung veroeffentlicht ist.
    let prepared = scene.line.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Reader,
        marker: SECOND_READER_MARKER,
        effective_from: None,
    });
    let pending = PendingDeviceRegistration::new(scene.line.exact_object_bytes(prepared).to_vec())
        .expect("die vorbereiteten Bytes tragen ein Geraetezertifikat");
    assert_eq!(pending.certificate_kind(), CertificateKindV1::Reader);
    assert_eq!(
        hash_bytes(pending.certificate_object_hash()),
        hash_bytes(prepared),
        "der Antrag meint genau die vorbereiteten Bytes"
    );

    // Ohne den ueber den zweiten Kanal zurueckgelesenen Fingerprint gibt es
    // keine Bestaetigung.
    assert_eq!(
        confirm_device_fingerprint(&pending, scene.admin_certificate_object_hash)
            .err()
            .expect("ein abweichender Fingerprint bestaetigt nichts")
            .code(),
        "EA-WORKFLOW-FINGERPRINT-MISMATCH",
    );
    let confirmation = confirm_device_fingerprint(&pending, pending.fingerprint())
        .expect("der zurueckgelesene Fingerprint stimmt");

    let audit = AuditHarness::new(scene.admin_certificate_object_hash, UnixMillis::new(NOW_MS));
    let events = RegistryEventFactory::new(&head, audit.service(), local_admin(&scene, &head));
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

    // Die veroeffentlichte Aktivierung traegt GENAU die vorbereiteten Bytes.
    let activation: BuiltHead = scene.line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: SECOND_READER_MARKER,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    assert_eq!(
        optional_hash_bytes(activation.direct_object_hash),
        Some(hash_bytes(prepared)),
        "die veroeffentlichte Aktivierung traegt genau die vorbereiteten Bytes"
    );
    assert_eq!(activation.version, planned.registry_version);
    assert_eq!(activation.effective_from, planned.effective_from_sequence);
    assert!(matches!(
        planned.change,
        RegistryChangeV1::Certificate { object_hash } if object_hash == prepared
    ));

    // Und die Folge: an der letzten Stelle VOR der Wirksamkeitssequenz bekommt
    // das neue Lesegeraet keinen Grant, ab ihr bekommt es einen.
    let before = selected(&scene.line, &mut store, 69, WALL_MS);
    assert!(!grants(&grant_plan(&before), prepared));

    let after = selected(
        &scene.line,
        &mut store,
        activation.effective_from.get(),
        WALL_MS,
    );
    let plan_after = grant_plan(&after);
    assert!(grants(&plan_after, prepared));
    assert!(grants(&plan_after, scene.recovery_certificate_object_hash));
    // Das WIDERRUFENE Lesegeraet bleibt draussen; eine neue Freigabe holt es
    // nicht zurueck.
    assert!(!grants(&plan_after, scene.reader_certificate_object_hash));
}

// ===========================================================================
// 3. Rueckrollen, Gabelung, veralteter Kopf
// ===========================================================================

#[test]
fn a_rollback_a_same_version_fork_and_an_expired_head_block_the_line() {
    let scene = scene();
    let guard = scene.line.heads()[HEAD_GUARD_POLICY];

    // Rueckrollen: der gebundene Kopf ist aus der Quelle verschwunden, der
    // hoechste noch belegbare liegt DAHINTER.
    let mut rolled_back = scene.line.clone();
    rolled_back.remove_object(guard.object_hash);
    let mut store = WorkflowStore::new(
        state_key(),
        REVISION,
        time_without_reference(),
        Some(RegistryHeadPin::new(guard.version, guard.object_hash)),
    );
    assert_eq!(
        blocked(&rolled_back, &mut store, 65, WALL_MS),
        "EA-TRUST-REGISTRY-ROLLBACK"
    );

    // Gabelung: ZWEI Nachfolger derselben Registrierungsversion, beide auf
    // demselben gebundenen Kopf. `add_branch` legt den Zwilling in den
    // Katalog, ohne die Linie vorzuruecken; er unterscheidet sich nur in
    // seinem Lease und ist damit ein anderes Objekt derselben Version.
    let mut forked = scene.line.clone();
    forked.add_branch(policy_action(), window(70, 89));
    forked.push(policy_action(), window(70, 79));
    let mut store = store_at(&forked, HEAD_GUARD_POLICY, time_without_reference());
    assert_eq!(
        blocked(&forked, &mut store, 70, WALL_MS),
        "EA-TRUST-REGISTRY-FORK"
    );

    // Veralteter Kopf: die Zeitgrenze liegt hinter der bewerteten Gegenwart.
    // Fail-closed, ohne zweite Gnadenfrist.
    let mut expired = scene.line.clone();
    expired.push(
        policy_action(),
        HeadOptions {
            not_after: UnixMillis::new(NOW_MS - 100),
            ..window(70, 79)
        },
    );
    let mut store = WorkflowStore::new(
        state_key(),
        REVISION,
        time_without_reference(),
        Some(pin_of(&expired, HEAD_APPENDED)),
    );
    assert_eq!(blocked(&expired, &mut store, 70, WALL_MS), "EA-TRUST-STALE");
}

// ===========================================================================
// 4. Die Leasegrenze
// ===========================================================================

#[test]
fn the_sequence_lease_boundary_of_the_line_is_exact() {
    let scene = scene();
    let guard = scene.line.heads()[HEAD_GUARD_POLICY];
    let boundary = guard.valid_through.get();

    let mut store = store_at(&scene.line, HEAD_GUARD_POLICY, time_without_reference());
    let allowed = selected(&scene.line, &mut store, boundary, WALL_MS);
    assert_eq!(allowed.proposed_sequence(), ChainSequence::new(boundary));

    // Genau eine Stelle weiter ist das Lease erschoepft. Der Code ist der des
    // Kerns; `EA-REGISTRY-LEASE-EXHAUSTED` gibt es im ganzen Baum nicht.
    let mut store = store_at(&scene.line, HEAD_GUARD_POLICY, time_without_reference());
    assert_eq!(
        blocked(&scene.line, &mut store, boundary + 1, WALL_MS),
        "EA-TRUST-SEQUENCE-LEASE"
    );
}

// ===========================================================================
// 5. Nur zukuenftiger Nachfolger und der bereitstehende Nachfolger
// ===========================================================================

#[test]
fn a_future_only_successor_pends_and_a_ready_one_blocks_the_current_head_fallback() {
    let scene = scene();

    // Nur zukuenftig UND ausserhalb des gebundenen Lease: es gibt keinen Kopf,
    // unter den zurueckgefallen werden koennte.
    let mut future_only = scene.line.clone();
    future_only.push(
        policy_action(),
        HeadOptions {
            issued_at: UnixMillis::new(50_000),
            not_before: UnixMillis::new(50_000),
            not_after: UnixMillis::new(100_000),
            ..window(70, 79)
        },
    );
    let mut store = store_at(&future_only, HEAD_GUARD_POLICY, time_without_reference());
    assert_eq!(
        blocked(&future_only, &mut store, 75, WALL_MS),
        "EA-TRUST-PENDING-FUTURE"
    );

    // Der serverbekannte neuere anwendbare Kopf: sein Lease UEBERLAPPT das
    // gebundene, er ist zunaechst nur zukuenftig — und sobald er bereitsteht,
    // sperrt er den Rueckfall auf den gebundenen Kopf.
    let mut successor = scene.line.clone();
    successor.push(
        policy_action(),
        HeadOptions {
            issued_at: UnixMillis::new(4_100),
            not_before: UnixMillis::new(4_000),
            not_after: UnixMillis::new(20_000),
            ..window(65, 169)
        },
    );
    let mut store = store_at(&successor, HEAD_GUARD_POLICY, time_without_reference());

    let trust = trust_of(&successor, &store);
    let RegistrySelectionOutcome::PendingFuture(pending) = RegistryWorkflowService::new(&mut store)
        .select(
            &trust,
            ChainSequence::new(68),
            UnixMillis::new(WALL_MS),
            &[],
            None,
        )
        .expect("der Nachfolger ist an dieser Uhr erst zukuenftig")
    else {
        panic!("der Nachfolger muss an dieser Uhr erst zukuenftig sein");
    };

    let reloaded = trust_of(&successor, &store);
    assert_eq!(
        RegistryWorkflowService::new(&mut store)
            .select_after_future_successor(&reloaded, pending, UnixMillis::new(4_500), &[], None,)
            .err()
            .expect("der bereitstehende Nachfolger sperrt den Rueckfall")
            .code(),
        "EA-TRUST-SUCCESSOR-READY"
    );
}

// ===========================================================================
// 6. Uhrruecklauf und Wiedereinspielung einer Freigabe
// ===========================================================================

#[test]
fn a_clock_release_binds_the_clock_it_was_issued_for_and_is_consumed_exactly_once() {
    let scene = scene();
    let mut store = store_at(&scene.line, HEAD_GUARD_POLICY, time_with_reference());

    // Der Wachkopf wird gewaehlt, WAEHREND die Uhr nicht gesperrt ist. In
    // seinem Zeitrahmen wird der Bedienernachweis ausgestellt; die gesperrte
    // Bewertung liegt daneben und traegt eine eigene `raw_now`.
    let guard_head = selected(&scene.line, &mut store, 65, WALL_MS);
    let proof = support::operator_proof(
        &guard_head,
        scene.admin_binding_object_hash,
        ReauthPurpose::ClockSkewRelease,
    );
    let audit = AuditHarness::new(
        scene.admin_certificate_object_hash,
        UnixMillis::new(BLOCKED_WALL_MS),
    );
    let service = ClockReleaseService::new(
        &guard_head,
        audit.service(),
        scene.admin_binding_object_hash,
    );

    // Die Bedienfuehrung bietet eine Freigabe nur an, wenn die Uhr wirklich
    // sperrt.
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

    // GENAU EINE Ausstellung. Alle drei folgenden Anwendungen legen DIESELBEN
    // Bytes vor; die einzige Groesse, die sich zwischen ihnen bewegt, ist die
    // beobachtete Wanduhr. Nur so belegt der Befund die UHR und nicht
    // irgendeine andere Abweichung — `EA-TRUST-CLOCK-RELEASE-MISMATCH` ist
    // auch der Code einer unlesbaren Zeile, und ein Zeuge, der die Bytes
    // zwischen den Laeufen wechselte, koennte beides nicht unterscheiden.
    let release = issue(&service, &scene, &store, &time, &proof);
    assert_eq!(audit.booked(), 1);
    assert_eq!(format!("{release:?}"), "IssuedClockRelease(<signed>)");

    // Die Uhr laeuft um eine Millisekunde ZURUECK. Sie sperrt weiterhin — 3_200
    // liegt genauso jenseits von `3_000 + 50` wie 3_201 —, aber sie ist nicht
    // mehr die Uhr, fuer die diese Freigabe ausgestellt wurde. Nichts wird
    // gebucht.
    let commits_before = store.selection_commits();
    assert_eq!(
        apply_at(
            &scene.line,
            &mut store,
            65,
            ROLLED_BACK_WALL_MS,
            release.exact_bytes()
        ),
        "EA-TRUST-CLOCK-RELEASE-MISMATCH"
    );
    assert_eq!(store.selection_commits(), commits_before);
    assert_eq!(store.consumed_releases(), 0);

    // Dieselben Bytes an der Uhr, fuer die sie ausgestellt wurden: der
    // Fehlschlag verschwindet mit der Uhrbewegung, die ihn ausgeloest hat.
    // Genau eine Auswahl, und der Zeitboden sinkt dabei nicht.
    let floor_before = store.trusted_time().floor();
    let trust = trust_of(&scene.line, &store);
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
    assert!(store.trusted_time().floor() >= floor_before);
    // Der Boden ist nicht durch eine NEUE unabhaengige Referenz gestiegen: die
    // Zeugen dieser Datei legen keine Zeitquellen vor.
    assert_eq!(store.independent_commits(), 0);

    // Und genau einmal: dieselben Bytes an derselben Uhr sind verbraucht.
    assert_eq!(
        apply_at(
            &scene.line,
            &mut store,
            65,
            BLOCKED_WALL_MS,
            release.exact_bytes()
        ),
        "EA-TRUST-CLOCK-RELEASE-REPLAY"
    );
    assert_eq!(store.consumed_releases(), 1);
}

/// Stellt eine Freigabe gegen den GESPERRTEN Kandidaten aus.
///
/// `verify_registry_candidate` wird hier AUSNAHMSWEISE direkt gerufen:
/// [`ClockReleaseRequest`] nimmt einen `&RegistryCandidate` entgegen, und die
/// Fassade hat fuer diesen Zwischenstand keinen eigenen Erzeuger — die
/// Auswahl verbraucht ihren Kandidaten. Ein in dieser Datei nachgebauter
/// Kandidat waere die zweite Wahrheit, die der Zeuge sonst vermeidet; der
/// Kernaufruf ist genau derselbe, den `RegistryWorkflowService::select`
/// intern anordnet.
fn issue(
    service: &ClockReleaseService<'_>,
    scene: &Scene,
    store: &WorkflowStore,
    trusted_time: &TrustedTimeState,
    proof: &ea_operator::OperatorSessionProof,
) -> ea_admin::clock_release::IssuedClockRelease {
    let trust = trust_of(&scene.line, store);
    let candidate = ea_trust::verify_registry_candidate(&trust, ChainSequence::new(65))
        .expect("der gesperrte Kandidat der Kulisse verifiziert");
    service
        .issue(
            ClockReleaseRequest {
                candidate: &candidate,
                trusted_time,
                observed_os_wall_clock: UnixMillis::new(BLOCKED_WALL_MS),
                justification: ClockReleaseJustificationV1::OperatorVerifiedWallClock,
                issued_at: UnixMillis::new(ISSUED_AT_MS),
                expires_at: UnixMillis::new(EXPIRES_AT_MS),
            },
            proof,
        )
        .expect("die Kulisse stellt eine Freigabe aus")
}

/// Wendet Freigabebytes an und gibt den Code des Fehlschlags heraus.
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
