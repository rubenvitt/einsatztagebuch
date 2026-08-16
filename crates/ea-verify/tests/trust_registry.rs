//! Die Gates `trust` und `registry` gegen eine echte Registrierungslinie.
//!
//! Der Kern dieses Targets ist die Abgrenzung W3: ein Eintrag, dessen
//! `writer_certificate_hash` in KEINEM zur Eintragssequenz aktiven Zertifikat
//! aufgeht, ist nicht zuordenbar — und ein nicht zuordenbarer Eintrag darf
//! niemals als blosse Kettenluecke erscheinen. Er wird deshalb gar nicht erst
//! als Kettenknoten aufgenommen, sondern isoliert.

#[path = "support/mod.rs"]
mod support;

use ea_archive::{ArchiveInventory, QuarantineReason};
use ea_trust::{
    RegistrySelectionOutcome, StateStoreError, TrustStateKey, TrustStateStore, load_trust_state,
    prepare_local_time, select_registry_head, verify_registry_candidate, verify_trust,
};
use ea_types::{ChainSequence, DeviceId, Id16, UnixMillis};
use ea_verify::{EphemeralTrustStateStore, VerifyOptions, verification_state_key, verify_archive};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, KNOWN_WRITER_SEQUENCE_V1, archive_with_a_second_lease,
    archive_with_one_unknown_writer,
};

fn clock() -> UnixMillis {
    UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)
}

fn options() -> VerifyOptions<'static> {
    VerifyOptions::new(clock())
}

#[test]
fn an_entry_with_an_unknown_writer_certificate_is_unattributable_not_a_gap() {
    let built = archive_with_one_unknown_writer();
    let anchor = built.anchor();
    let report =
        verify_archive(&built.fixture, &anchor, options()).expect("der Bestand muss berichten");

    // Beide Eintraege sind geparst; die Zaehler sind vom Gate-Ausgang
    // unabhaengig.
    assert_eq!(report.entry_package_count(), 2);
    assert_eq!(report.destroyed_entry_count(), 0);
    assert_eq!(report.format_errors().len(), 0);

    // Der Befund: KEINE Luecke, sondern genau ein unzuordenbares Objekt.
    assert_eq!(
        report.gaps().len(),
        0,
        "ein unzuordenbarer Eintrag darf nie als blosse Luecke erscheinen"
    );
    let quarantined: Vec<_> = report.quarantined_objects().collect();
    assert_eq!(quarantined.len(), 1, "genau ein isoliertes Objekt");
    assert!(
        quarantined[0].object_hash() == built.unknown_writer_object_hash,
        "isoliert wird der Eintrag mit dem unbekannten Schreiber"
    );
    assert_eq!(quarantined[0].reason(), QuarantineReason::Unattributable);

    // Der aufloesbare Schreiber traegt die Registrierungsversion in den
    // Bericht: ein gueltiger Bestand liefert nicht leere registryVersions.
    let versions: Vec<_> = report.registry_versions().collect();
    assert_eq!(versions.len(), 1);
    assert!(versions[0] == built.registry_version);

    assert!(
        !report.is_fully_verified(),
        "mit einem isolierten Objekt ist nichts vollstaendig verifiziert"
    );

    // Der Bericht haengt nicht an der Reihenfolge des Bestands.
    let json = report
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    let shuffled = verify_archive(&built.fixture.randomized_paths(), &anchor, options())
        .expect("der Bestand muss berichten")
        .to_canonical_json()
        .expect("der kanonische Schreiber muss ausgeben");
    assert_eq!(json, shuffled);
}

#[test]
fn the_ephemeral_store_starts_empty_and_advances_only_through_a_committed_selection() {
    let built = archive_with_one_unknown_writer();
    let anchor = built.anchor();
    let key = verification_state_key(anchor.organization_id());
    let mut store = EphemeralTrustStateStore::new(key, clock());

    // Ein leerer Stand: Revision null, kein gepinnter Kopf.
    assert_eq!(store.revision(), 0);
    let record = store.load(key).expect("der leere Stand muss laden");
    assert_eq!(record.revision(), 0);
    assert!(record.pinned_head().is_none());

    // Ein fremder Schluessel ist ein Konflikt, kein stiller Neustart.
    let foreign = TrustStateKey {
        organization_id: key.organization_id,
        device_id: DeviceId::from(Id16::try_from(&[0x5a_u8; 16][..]).unwrap()),
    };
    assert!(matches!(
        store.load(foreign),
        Err(StateStoreError::Conflict)
    ));

    // Ein echter Durchlauf ueber genau diesen Speicher. Aus dem leeren Stand
    // zieht die erste Runde den Policy-Kopf nach (`Advanced`), erst die zweite
    // erreicht den Kopf mit Operationsautoritaet.
    let inventory = ArchiveInventory::build(&built.fixture).expect("das Inventar muss entstehen");
    let mut revisions = Vec::new();
    let mut selected = None;
    for _ in 0..2 {
        let snapshot = load_trust_state(&mut store, key).expect("der Stand muss laden");
        let trust =
            verify_trust(&anchor, &inventory, snapshot).expect("die Vertrauenskette muss tragen");
        let candidate =
            verify_registry_candidate(&trust, ChainSequence::new(KNOWN_WRITER_SEQUENCE_V1))
                .expect("der Kandidat muss entstehen");
        let local_time = prepare_local_time(&mut store, &candidate, clock(), &[])
            .expect("die lokale Zeit muss entstehen");
        let outcome =
            select_registry_head(candidate, local_time, None).expect("die Auswahl muss gelingen");
        revisions.push(store.revision());
        match outcome {
            RegistrySelectionOutcome::Selected(head) => selected = Some(head),
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => {
                panic!("die Fixture-Uhr liegt hinter beiden Koepfen");
            }
        }
    }
    let selected = selected.expect("die zweite Runde erreicht den Kopf mit Autoritaet");
    assert!(selected.registry_version() == built.registry_version);

    // Jeder Commit bewegt den Speicher streng vorwaerts, keine Revision
    // kommt zweimal vor.
    assert_eq!(revisions, vec![1, 2]);
    let after = store
        .load(key)
        .expect("der fortgeschriebene Stand muss laden");
    assert_eq!(after.revision(), store.revision());
    assert!(
        after
            .pinned_head()
            .is_some_and(|pin| pin.registry_head_hash() == selected.registry_head_hash()),
        "die Auswahl pinnt genau den ausgewaehlten Kopf"
    );
}

#[test]
fn an_earlier_entry_keeps_its_head_even_when_a_later_one_carries_the_smaller_object_hash() {
    let built = archive_with_a_second_lease();
    // Die Voraussetzung, die diesen Test ueberhaupt aussagekraeftig macht:
    // die Inventarreihenfolge (nach Objekthash) WIDERSPRICHT der
    // Sequenzreihenfolge.
    assert!(
        built.late_object_hash < built.early_object_hash,
        "der Bestand muss den hoeheren Eintrag zuerst inventarisieren"
    );
    assert!(
        built.early_registry_version != built.late_registry_version,
        "die beiden Eintraege muessen unter verschiedenen Koepfen liegen"
    );

    let anchor = built.anchor();
    let report =
        verify_archive(&built.fixture, &anchor, options()).expect("der Bestand muss berichten");

    // Beide Eintraege sind zugeordnet: die Pipeline zieht die
    // Registrierungslinie nach aufsteigender Sequenz nach. Behandelte sie den
    // Eintrag mit der hoeheren Sequenz zuerst, pinnte sie dessen Kopf, und der
    // frueheren Sequenz bliebe nur `EA-REGISTRY-SEQUENCE-LEASE` — sie fiele
    // stillschweigend aus dem Bericht.
    // `registryVersions` ist numerisch aufsteigend; die Reihenfolge ist Teil
    // des Contracts und wird hier nicht nachsortiert.
    let versions: Vec<_> = report.registry_versions().collect();
    assert_eq!(versions.len(), 2);
    assert!(versions[0] == built.early_registry_version);
    assert!(versions[1] == built.late_registry_version);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
}
