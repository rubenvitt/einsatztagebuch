//! Der LESEZUGRIFF auf den wirksamen Writer-Uebergang eines gewaehlten Kopfes.
//!
//! Stufe 5, Task 5, Luecke 1: `ea-trust` baut den Uebergang seit Stufe 1–3
//! vollstaendig nach, gab ihn aber nicht heraus. Diese Zeugen bezeugen die drei
//! Leser auf `SelectedRegistryHead`, die den Server, den Writer und die
//! Pruefung von ihrer Pauschalabweisung befreien: den laufenden Writer, den
//! wirksamen Uebergang mit ALLEN seinen Feldern und den Blick auf ein
//! bereichsaktives Writer-Zertifikat, das noch nicht der laufende Writer ist.

mod support;

use ea_format::CertificateKindV1;
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
    verify_registry_candidate,
};
use ea_types::{CertificateHash, ChainSequence, EntryHash, ObjectHash, UnixMillis};

use support::{ActionSpec, BuiltHead, HeadOptions, Pin, RegistryLineBuilder};

/// Der Zeitpunkt der Kopfauswahl: innerhalb von `not_before = 90` und
/// `not_after = 10_000` jedes Kopfes mit Vorgabewerten.
const SELECTION_NOW: UnixMillis = UnixMillis::new(1_000);

/// Der `previous_entry_hash`, den der Zeuge dem Uebergang MITGIBT — nicht der
/// feste Vorgabewert der Fixture, damit der Leser bezeugt, dass er das Feld
/// des veroeffentlichten Objekts durchreicht und keinen Platzhalter.
fn transition_previous_entry_hash() -> EntryHash {
    EntryHash::from(support::hash32(0x77))
}

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn device(kind: CertificateKindV1, marker: u8) -> ActionSpec {
    ActionSpec::Device {
        kind,
        marker,
        effective_from: None,
    }
}

fn certificate(head: BuiltHead) -> CertificateHash {
    CertificateHash::from(head.direct_object_hash.expect("ein direktes Zielobjekt"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Ein Speicher, der die Kopfauswahl der Fixture traegt — mehr braucht die
/// Auswahl nicht.
struct SelectionStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: RegistryHeadPin,
}

impl TrustStateStore for SelectionStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
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
        self.pinned_head = *commit.next_head();
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }
}

/// Waehlt den Kopf mit Index `index` der Linie als AKTUELLEN Kopf an der
/// vorgeschlagenen Sequenz `proposed_sequence`, die in seinem Fenster liegt.
fn select_head(
    line: &RegistryLineBuilder,
    index: usize,
    proposed_sequence: u64,
) -> SelectedRegistryHead {
    let head = line.heads()[index];
    let proposed_sequence = ChainSequence::new(proposed_sequence);
    assert!(
        head.effective_from <= proposed_sequence && proposed_sequence <= head.valid_through,
        "die Fixture waehlt innerhalb des Kopffensters"
    );
    let key = support::state_key();
    let trusted_time = TrustedTimeState::initial(SELECTION_NOW);
    let trust = line.verified_with_record(Pin::Head(index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, proposed_sequence)
        .expect("die Fixture muss ihren eigenen Kopf als Kandidaten tragen");
    let mut store = SelectionStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time = prepare_local_time(&mut store, &candidate, SELECTION_NOW, &[])
        .expect("die lokale Zeit der Fixture muss vorbereitbar sein");
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).expect("die Auswahl muss gelingen")
    else {
        panic!("die Fixture muss ihren eigenen aktuellen Kopf waehlen");
    };
    assert_eq!(selected.registry_version(), head.version);
    assert_eq!(selected.proposed_sequence(), proposed_sequence);
    selected
}

/// Die Linie mit einem Change 3 und den Koepfen, auf die sich die Zeugen
/// beziehen.
struct TransitionLine {
    line: RegistryLineBuilder,
    old_writer: BuiltHead,
    reader: BuiltHead,
    new_writer: BuiltHead,
    transition: BuiltHead,
    after: BuiltHead,
}

/// Kopf 1 Policy `[1, 100]`, Kopf 2 alter Writer `[101, 200]`, Kopf 3 Reader
/// `[201, 300]`, Kopf 4 neuer Writer `[301, 400]`, Kopf 5 Uebergang
/// `[401, 500]`, Kopf 6 Policy `[501, 600]`.
fn transition_line() -> TransitionLine {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let old_writer = line.push(
        device(CertificateKindV1::Writer, 0x61),
        HeadOptions::default(),
    );
    let reader = line.push(
        device(CertificateKindV1::Reader, 0x63),
        HeadOptions::default(),
    );
    let new_writer = line.push(
        device(CertificateKindV1::Writer, 0x62),
        HeadOptions::default(),
    );
    let transition = line.push(
        ActionSpec::WriterTransition {
            old_writer: old_writer.direct_object_hash.unwrap(),
            new_writer: new_writer.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions {
            writer_transition_previous_entry_hash: Some(transition_previous_entry_hash()),
            ..HeadOptions::default()
        },
    );
    let after = line.push(policy(), HeadOptions::default());
    assert_eq!(new_writer.effective_from, ChainSequence::new(301));
    assert_eq!(transition.effective_from, ChainSequence::new(401));
    TransitionLine {
        line,
        old_writer,
        reader,
        new_writer,
        transition,
        after,
    }
}

#[test]
fn a_change_3_moves_the_current_writer_and_exposes_exactly_the_effective_transition() {
    let fixture = transition_line();
    let old = certificate(fixture.old_writer);
    let new = certificate(fixture.new_writer);
    let transition_object_hash = fixture.transition.direct_object_hash.unwrap();

    // VOR dem Uebergang: der alte Writer laeuft, ein Uebergang ist nicht bekannt.
    let before = select_head(&fixture.line, 3, 350);
    assert!(before.current_writer_certificate_hash() == Some(old));
    assert!(before.effective_writer_transition().is_none());
    assert!(before.active_certificate_fields(old).is_some());
    assert!(before.active_certificate_fields(new).is_none());

    // AM Uebergangskopf, an seiner ersten Sequenz: der neue Writer laeuft, und
    // der Uebergang traegt genau die Felder des veroeffentlichten Objekts.
    let at = select_head(&fixture.line, 4, 401);
    assert!(at.current_writer_certificate_hash() == Some(new));
    let transition = *at
        .effective_writer_transition()
        .expect("der Uebergangskopf traegt seinen Uebergang");
    assert!(transition.object_hash() == transition_object_hash);
    assert!(transition.old_writer_certificate_hash() == old);
    assert!(transition.new_writer_certificate_hash() == new);
    assert_eq!(
        transition.effective_from_sequence(),
        fixture.transition.effective_from
    );
    assert!(transition.previous_entry_hash() == transition_previous_entry_hash());
    assert!(at.active_certificate_fields(old).is_none());
    assert!(at.active_certificate_fields(new).is_some());

    // Die Debug-Ausgabe ist von Hand geschrieben und zeigt die Hashes als Hex.
    let debug = format!("{transition:?}");
    assert!(debug.starts_with("EffectiveWriterTransitionV1"));
    assert!(debug.contains(&hex(transition_object_hash.as_bytes())));
    assert!(debug.contains(&hex(old.as_bytes())));
    assert!(debug.contains(&hex(new.as_bytes())));
    assert!(debug.contains(&hex(transition_previous_entry_hash().as_bytes())));
    assert!(debug.contains("401"));

    // NACH dem Uebergang: der Zustand der Linie traegt ihn unveraendert weiter.
    let after = select_head(&fixture.line, 5, 550);
    assert!(after.current_writer_certificate_hash() == Some(new));
    assert_eq!(after.effective_writer_transition(), Some(&transition));
    assert_eq!(after.registry_version(), fixture.after.version);
}

#[test]
fn approved_writer_certificate_fields_reads_range_activity_without_the_current_writer_filter() {
    let fixture = transition_line();
    let old = certificate(fixture.old_writer);
    let new = certificate(fixture.new_writer);
    let reader = certificate(fixture.reader);
    let unknown = CertificateHash::from(ObjectHash::from(support::hash32(0x99)));

    // VOR dem Uebergang sieht der Admin das NEUE Writer-Zertifikat, das
    // `active_certificate_fields` als nicht laufenden Writer verbirgt.
    let before = select_head(&fixture.line, 3, 350);
    let approved = before
        .approved_writer_certificate_fields(new, fixture.transition.effective_from)
        .expect("das freigegebene neue Writer-Zertifikat ist an effective_from bereichsaktiv");
    assert_eq!(approved.certificate_kind, CertificateKindV1::Writer);
    assert_eq!(
        approved.effective_from_sequence,
        fixture.new_writer.effective_from
    );
    assert_eq!(approved.revoked_from_sequence, None);
    assert!(before.active_certificate_fields(new).is_none());
    // Die untere Grenze ist einschliesslich: 300 liegt davor, 301 ist der Beginn.
    assert!(
        before
            .approved_writer_certificate_fields(new, ChainSequence::new(300))
            .is_none()
    );
    assert!(
        before
            .approved_writer_certificate_fields(new, ChainSequence::new(301))
            .is_some()
    );
    // Der alte Writer ist auf dieser Linie noch nirgends widerrufen.
    assert!(
        before
            .approved_writer_certificate_fields(old, fixture.transition.effective_from)
            .is_some()
    );
    // Ein Reader ist bereichsaktiv, aber kein Writer-Zertifikat.
    assert!(before.active_certificate_fields(reader).is_some());
    assert!(
        before
            .approved_writer_certificate_fields(reader, ChainSequence::new(350))
            .is_none()
    );
    assert!(
        before
            .approved_writer_certificate_fields(unknown, ChainSequence::new(350))
            .is_none()
    );

    // AM Uebergangskopf ist der alte Writer ab `effective_from` widerrufen:
    // die obere Grenze ist ausschliesslich, 400 ist noch aktiv, 401 nicht mehr.
    let at = select_head(&fixture.line, 4, 401);
    assert!(
        at.approved_writer_certificate_fields(old, ChainSequence::new(400))
            .is_some()
    );
    assert!(
        at.approved_writer_certificate_fields(old, ChainSequence::new(401))
            .is_none()
    );
    assert!(
        at.approved_writer_certificate_fields(new, ChainSequence::new(401))
            .is_some()
    );
    assert!(
        at.approved_writer_certificate_fields(reader, ChainSequence::new(401))
            .is_none()
    );
}

#[test]
fn a_line_without_a_change_3_reports_the_first_approved_writer_and_no_transition() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let first_writer = line.push(
        device(CertificateKindV1::Writer, 0x61),
        HeadOptions::default(),
    );
    let second_writer = line.push(
        device(CertificateKindV1::Writer, 0x62),
        HeadOptions::default(),
    );
    let first = certificate(first_writer);
    let second = certificate(second_writer);

    let head = select_head(&line, 2, 250);
    assert!(head.current_writer_certificate_hash() == Some(first));
    assert!(head.effective_writer_transition().is_none());
    assert!(head.active_certificate_fields(first).is_some());
    assert!(head.active_certificate_fields(second).is_none());
    assert!(
        head.approved_writer_certificate_fields(second, second_writer.effective_from)
            .is_some()
    );
    assert!(
        head.approved_writer_certificate_fields(first, ChainSequence::new(250))
            .is_some()
    );

    // Ein Kopf VOR jedem Writer kennt keinen laufenden Writer.
    let mut bare = RegistryLineBuilder::new();
    bare.push(policy(), HeadOptions::default());
    let bare_head = select_head(&bare, 0, 30);
    assert!(bare_head.current_writer_certificate_hash().is_none());
    assert!(bare_head.effective_writer_transition().is_none());
}
