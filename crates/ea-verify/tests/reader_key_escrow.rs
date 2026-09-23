//! Gate `trust` über den GESAMTEN Bestand: jedes Objekt der drei
//! Escrow-Familien wird offline geprüft (v1.1-Profil §9, Scheibe f).
//!
//! `verify_trust` allein prüft kein Escrow-Familienobjekt. Ein Bestand, dessen
//! Vertrauenskette trägt, dessen Escrow-Menge aber scheitert, darf an Gate
//! `trust` nicht vorbeikommen (Ruling Q11: ein ungültiges Familienobjekt kippt
//! den ganzen Bestand). Die Cutover-Vorbedingung prüft der Offline-Prüfer
//! bewusst NICHT: nach einer Wurzelrotation würde sie jedes Archiv mit Escrow
//! unprüfbar machen.
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

/// `escrow_support` erwartet den Zustandsspeicher des Prüfers unter
/// `crate::state` — hier derselbe öffentliche Speicher dieser Crate.
mod state {
    pub use ea_verify::{EphemeralTrustStateStore, verification_state_key};
}

use ea_archive::{
    ArchiveBlob, ArchiveError, ArchiveInventory, ArchiveSource, REGISTRY_EVENTS_DIR_V1,
};
use ea_crypto::object_hash;
use ea_format::{ReaderKeyEscrowCoreV1, WebBundleReleaseCoreV1};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, signed_reader_key_escrow, signed_web_bundle_release,
};
use ea_trust::{TrustAnchorV1, TrustObjectSource, decode_trust_anchor};
use ea_types::{CertificateHash, Hash32, ObjectHash, OrganizationId, RegistryVersion, UnixMillis};
use ea_verify::{
    Gate, GateObserver, VerificationReportV1, VerifyOptions, historical_registry_head,
    verify_archive_observed,
};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, SECOND_READER_KEM_SEED, SELECTION_NOW,
    approval_core, escrow_bytes, escrow_core, escrow_line, publish_escrow, push_reader,
    recovery_core, root, signed_approval, signed_recovery, subject,
};
use support::{ActionSpec, HeadOptions};

const APPROVAL_WINDOW: (u64, u64) = (1_000, 1_300);
const ESCROW_ISSUED_AT: u64 = 1_200;

/// Ein Bestand im Speicher: Pfadhinweis und exakte Bytes.
struct Archive(Vec<(String, Vec<u8>)>);

impl ArchiveSource for Archive {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path_hint, bytes) in &self.0 {
            visitor(ArchiveBlob::new(path_hint, bytes))?;
        }
        Ok(())
    }
}

/// Die Linie als Bestand: Registry-Ereignisse und alle weiteren
/// Trust-Objekte, jedes unter seinem Objekthash. Der Anker liegt daneben.
fn archive_of(line: &support::RegistryLineBuilder) -> Archive {
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .unwrap();
    let blobs = hashes
        .into_iter()
        .map(|hash| {
            let bytes = source.read_exact_trust_object(hash).unwrap().unwrap();
            (
                format!(
                    "{REGISTRY_EVENTS_DIR_V1}{}.etb",
                    hex::encode(hash.as_bytes())
                ),
                bytes.to_vec(),
            )
        })
        .collect();
    Archive(blobs)
}

fn anchor_of(line: &support::RegistryLineBuilder) -> TrustAnchorV1 {
    decode_trust_anchor(line.exact_anchor_bytes()).unwrap()
}

/// Das Protokoll der betretenen Gates.
#[derive(Default)]
struct Gates(Vec<Gate>);

impl GateObserver for Gates {
    fn on_gate(&mut self, gate: Gate) {
        self.0.push(gate);
    }
    fn on_decapsulation(&mut self) {}
}

fn verified(line: &support::RegistryLineBuilder) -> (VerificationReportV1, Vec<Gate>) {
    let mut gates = Gates::default();
    let report = verify_archive_observed(
        &archive_of(line),
        &anchor_of(line),
        VerifyOptions::new(SELECTION_NOW),
        &mut gates,
    )
    .unwrap();
    (report, gates.0)
}

/// Gate `trust` hat getragen: der Lauf ging weiter, der Wurzelabdruck steht.
fn trust_carried(line: &support::RegistryLineBuilder) -> bool {
    let (report, gates) = verified(line);
    let carried = gates.len() > 2;
    assert_eq!(
        carried,
        report.public_key_thumbprints().len() == 1,
        "publicKeyThumbprints steht genau dann, wenn Gate trust trägt"
    );
    carried
}

/// Ein Bestand, dessen Lauf an Gate `trust` versiegelt wurde.
fn assert_sealed_at_trust(line: &support::RegistryLineBuilder) {
    let (report, gates) = verified(line);
    assert_eq!(gates, [Gate::Format, Gate::Trust], "Lauf endet an trust");
    assert_eq!(report.public_key_thumbprints().len(), 0);
}

fn tip_basis(escrow: &EscrowLine) -> Basis {
    let tip = *escrow.line.heads().last().unwrap();
    Basis::of(&tip, tip.effective_from.get())
}

fn reader_core(escrow: &EscrowLine) -> ReaderKeyEscrowCoreV1 {
    escrow_core(
        escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xc1),
        ESCROW_ISSUED_AT,
    )
}

/// Freigabe und Escrow zu `core` im Katalog.
fn publish(escrow: &mut EscrowLine, core: &ReaderKeyEscrowCoreV1, id: u8) -> ObjectHash {
    let approval = approval_core(&escrow.line, tip_basis(escrow), APPROVAL_WINDOW, id);
    publish_escrow(escrow, core, &approval).1
}

/// Eine wurzelsignierte Freigabe eines v1.1-fähigen Bundles.
fn capable_release(line: &support::RegistryLineBuilder) -> Vec<u8> {
    signed_web_bundle_release(
        &WebBundleReleaseCoreV1 {
            organization_id: support::organization(),
            bundle_hash: Hash32::try_from([0x5a; 32].as_slice()).unwrap(),
            bundle_version: ea_trust::MIN_ESCROW_BUNDLE_VERSION.to_owned(),
            effective_from_registry_version: RegistryVersion::new(1),
            issued_at: UnixMillis::new(900),
            root_key_thumbprint: support::device_signing_key(support::root_signing_secret())
                .thumbprint(),
        },
        &root(line),
    )
}

/// Zeuge 1: die vollständige Linie aus Freigabe des Bundles, Freigabe des
/// Escrows, Escrow und Öffnungsautorisierung. Gate `trust` trägt; der
/// Bericht unterscheidet sich vom selben Bestand OHNE die vier Objekte
/// allein in `archiveObjectCount`.
#[test]
fn a_complete_escrow_line_carries_the_trust_gate_and_changes_only_the_object_count() {
    let bare = escrow_line(EscrowLineOptions::default());
    let mut escrow = escrow_line(EscrowLineOptions::default());
    escrow.line.add_object(capable_release(&escrow.line));
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xa1);
    let recovery = signed_recovery(
        &recovery_core(
            escrow_hash,
            &core,
            tip_basis(&escrow),
            APPROVAL_WINDOW,
            0xa2,
        ),
        &escrow.approvers,
    );
    escrow.line.add_object(recovery);

    assert!(trust_carried(&escrow.line));
    let (with, _) = verified(&escrow.line);
    let (without, _) = verified(&bare.line);
    assert_eq!(
        with.archive_object_count(),
        without.archive_object_count() + 4
    );
    // Der Bericht ohne Zähler und ohne den Hash über ihn.
    let rest = |report: &VerificationReportV1| {
        report
            .to_canonical_json()
            .unwrap()
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !line.starts_with("\"archiveObjectCount\"") && !line.starts_with("\"reportHash\"")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        rest(&with),
        rest(&without),
        "sonst ist der Bericht identisch"
    );
}

/// Zeuge 2a: zwei je für sich gültige Escrows zu derselben Subject-ID unter
/// zwei Reader-Zertifikaten — widersprüchlich (EA-TRUST-ESCROW-CONFLICT).
#[test]
fn two_contradicting_valid_escrows_seal_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let second = push_reader(&mut escrow.line, 0x82, SECOND_READER_KEM_SEED);
    let first = reader_core(&escrow);
    publish(&mut escrow, &first, 0xb1);
    let other = escrow_core(
        &escrow,
        &second,
        SECOND_READER_KEM_SEED,
        subject(0xc1),
        ESCROW_ISSUED_AT,
    );
    publish(&mut escrow, &other, 0xb2);
    assert_sealed_at_trust(&escrow.line);
}

/// Zeuge 2b: ein Escrow, dessen Freigabe nicht im Bestand liegt.
#[test]
fn an_escrow_without_its_approval_seals_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb3);
    let (_, escrow_only) = escrow_bytes(&escrow, &core, &approval);
    escrow.line.add_object(escrow_only);
    assert_sealed_at_trust(&escrow.line);
}

/// Zeuge 2c: eine voll signierte Freigabe einer fremden Organisation.
#[test]
fn an_approval_of_a_foreign_organization_seals_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let mut fields = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb4);
    fields.organization_id = OrganizationId::try_from([0x0e; 16].as_slice()).unwrap();
    let approval = signed_approval(&escrow.line, &fields);
    escrow.line.add_object(approval);
    assert_sealed_at_trust(&escrow.line);
}

/// Zeuge 2d: eine Öffnungsautorisierung, die nur EINE echte Person trägt.
#[test]
fn a_recovery_authorization_with_one_real_approver_seals_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xb5);
    let forged =
        ea_testkit::reader_key_escrow_fixture::signed_reader_key_escrow_recovery_authorization(
            &recovery_core(
                escrow_hash,
                &core,
                tip_basis(&escrow),
                APPROVAL_WINDOW,
                0xb6,
            ),
            &[
                escrow_support::approver(escrow.approvers[0]),
                FixtureTrustSigner {
                    seed: [0x08; 32],
                    certificate_hash: escrow.approvers[1],
                },
            ],
        );
    escrow.line.add_object(forged);
    assert_sealed_at_trust(&escrow.line);
}

/// Zeuge 2e: ein Escrow mit Wurzelsignatur unter dem falschen Schlüssel —
/// der Fall, den `verify_trust` allein durchlässt.
#[test]
fn an_escrow_under_a_foreign_root_key_seals_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb7);
    let (approval_bytes, _) = escrow_bytes(&escrow, &core, &approval);
    let forged = signed_reader_key_escrow(
        &core,
        object_hash(&approval_bytes),
        &FixtureTrustSigner {
            seed: [0x0f; 32],
            certificate_hash: CertificateHash::from(escrow.line.current_root_hash()),
        },
    );
    escrow.line.add_object(approval_bytes);
    escrow.line.add_object(forged);
    assert_sealed_at_trust(&escrow.line);
}

/// Zeuge 3: `historical_registry_head` stützt sich auf denselben Gate-Helfer
/// — beim defekten Bestand gibt es keine historische Autorität.
#[test]
fn historical_registry_head_refuses_a_defective_escrow_set() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let tip = *escrow.line.heads().last().unwrap();
    let lookup = |line: &support::RegistryLineBuilder| {
        let inventory = ArchiveInventory::build(&archive_of(line)).unwrap();
        historical_registry_head(
            &inventory,
            &anchor_of(line),
            tip.version,
            tip.object_hash,
            tip.effective_from,
            SELECTION_NOW,
        )
        .is_some()
    };
    let core = reader_core(&escrow);
    publish(&mut escrow, &core, 0xb8);
    assert!(lookup(&escrow.line), "Kontrolle: gültige Menge");

    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb9);
    let (_, escrow_only) = escrow_bytes(&escrow, &core, &approval);
    escrow.line.add_object(escrow_only);
    assert!(!lookup(&escrow.line));
}

/// Hängt an die Linie einen Kopf, dessen Registry-Version eine Lücke lässt:
/// die Katalog-Linie ist offline nicht mehr bis zur Spitze nachspielbar.
/// `verify_trust` selbst bleibt dabei grün (derselbe Bau wie im
/// F1-Zeugen von `ea-trust`).
fn with_line_gap(line: &mut support::RegistryLineBuilder) {
    let skipped = line.heads().last().unwrap().version.get() + 2;
    line.add_branch(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            registry_version: Some(skipped),
            ..HeadOptions::default()
        },
    );
}

/// Kontrolle F1: ohne jedes Escrow-Familienobjekt trägt Gate `trust` auch
/// über einer Katalog-Linie, die offline NICHT bis zur Spitze nachspielbar
/// ist — der Datei-Modus spielt ohne Familienobjekt keine Linie nach. Ohne
/// F1 würde genau dieser Bestand an `trust` versiegelt.
#[test]
fn a_catalog_without_escrow_objects_carries_the_trust_gate() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    assert!(trust_carried(&escrow.line), "Kontrolle ohne Lücke");
    with_line_gap(&mut escrow.line);
    assert!(
        trust_carried(&escrow.line),
        "ohne Familienobjekt trägt auch die nicht nachspielbare Linie"
    );
}

/// Gegenprobe zur Kontrolle F1 und benannte Grenze des Gates: dieselbe
/// Lücke mit einem GÜLTIGEN Escrow im Katalog versiegelt den Bestand an
/// `trust` — die Menge verlangt die Linie bis zur Spitze.
#[test]
fn a_valid_escrow_over_a_line_that_is_not_replayable_offline_seals_the_report_at_trust() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    publish(&mut escrow, &core, 0xba);
    assert!(trust_carried(&escrow.line), "Kontrolle ohne Lücke");
    with_line_gap(&mut escrow.line);
    assert_sealed_at_trust(&escrow.line);
}
