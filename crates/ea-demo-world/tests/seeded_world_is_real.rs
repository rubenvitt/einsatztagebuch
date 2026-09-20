//! Der Zeuge, dass die gesäte Fixture-Demowelt eine ECHTE Welt ist.
//!
//! Die Demowelt lässt sich auf diesem Rechner nicht STARTEN — der Wirt
//! verlangt einen signierten nativen Helfer, den kein Entwicklungsbau hat
//! (`NativeExecutableIdentity::for_installed`). Was sich messen lässt, ist
//! der Schritt davor und der eigentliche Anspruch: dass ein Bediener-Wirt die
//! Welt OEFFNEN würde.
//!
//! [`OperatorArchiveSnapshot::open`] ist genau dieser Schritt. Sie prüft in
//! einem Zug
//!
//! * dass die Ankerbytes AUSSERHALB des Archivverzeichnisses liegen,
//! * dass der Bestand `entry_package_count() + destroyed_entry_count() > 0`
//!   erfüllt, also mindestens einen finalisierten Eintrag trägt,
//! * und dass der Bericht über den Bestand überhaupt entsteht.
//!
//! Ein Test, der nur nachsieht, ob Dateien da sind, würde all das verfehlen.
#![cfg(feature = "fixture-world")]

use std::fs;

use ea_admin::operator_runtime::OperatorArchiveSnapshot;
use ea_demo_world::{seed_demo_world, support};

/// Ein Verzeichnis, das beim Fallenlassen verschwindet — dieselbe Form wie in
/// der Support-Kette, hier aber über deren eigenen Helfer.
fn scratch(tag: &str) -> support::TempDir {
    support::temp_dir(tag)
}

#[test]
fn the_seeded_demo_world_opens_as_an_operator_archive_snapshot() {
    let scratch = scratch("demo-world-open");
    let root = scratch.path().join("welt");
    let world = seed_demo_world(&root).expect("die Demowelt muss sich säen lassen");

    // 1. Der Anker liegt außerhalb des Archivs. Ohne diese Lage wiese
    //    `open` ab, und der Zeuge darunter wäre blind.
    assert!(
        !world.anchor_path.starts_with(&world.archive_directory),
        "die Ankerbytes dürfen nicht im Archivverzeichnis liegen: {} unter {}",
        world.anchor_path.display(),
        world.archive_directory.display()
    );

    // 2. Der eigentliche Zeuge.
    let snapshot = OperatorArchiveSnapshot::open(
        &world.archive_directory,
        &world.anchor_path,
        support::live_clock(),
    )
    .expect("ein Bediener-Wirt muss die gesäte Demowelt öffnen können");

    // 3. Der Bestand trägt wirklich einen finalisierten Eintrag. `open`
    //    verlangt die Summe > 0; hier wird die Zahl selbst festgehalten,
    //    damit ein späterer Bestand ohne Einträge nicht still durchginge.
    assert_eq!(
        snapshot.report().entry_package_count() + snapshot.report().destroyed_entry_count(),
        1,
        "die Demowelt führt genau einen finalisierten Eintrag"
    );
}

#[test]
fn the_writer_archive_profile_is_allowed_by_the_effective_policy() {
    let scratch = scratch("demo-world-policy");
    let root = scratch.path().join("welt");
    let world = seed_demo_world(&root).expect("die Demowelt muss sich säen lassen");

    // Die Zusage aus der Aufgabe: `profile_hash()` des Archivprofils MUSS in
    // `policy_allowed_archive_profile_hashes` der wirksamen Policy stehen.
    // Gemessen wird das am geschriebenen `writer.json` gegen die Policy der
    // gesäten Linie — nicht an der Absicht des Saatcodes.
    let written: serde_json::Value =
        serde_json::from_slice(&fs::read(&world.writer.role_config).unwrap()).unwrap();
    assert_eq!(written["version"], 1);
    let profile = ea_demo_world::world::demo_archive_profile();
    // `Hash32` trägt bewusst kein `Debug`; deshalb `assert!` statt
    // `assert_eq!`.
    assert!(
        profile.profile_hash().unwrap() == world.archive_profile_hash,
        "der gemeldete Profilhash muss der des geschriebenen Profils sein"
    );

    // Gemessen wird an den MATERIALISIERTEN Vertrauensobjekten: die Policy
    // mit der höchsten `policy_version` ist die wirksame, und ihre
    // Zulassungsliste muss den Profilhash tragen. Die Absicht des Saatcodes
    // steht hier ausdrücklich nicht zur Debatte.
    let snapshot = OperatorArchiveSnapshot::open(
        &world.archive_directory,
        &world.anchor_path,
        support::live_clock(),
    )
    .unwrap();
    let effective = snapshot
        .inventory()
        .trust()
        .iter()
        .filter_map(|object| match object.value().decoded_payload().ok()? {
            ea_format::DecodedTrustPayloadV1::Policy(core) => Some(core.fields().clone()),
            _ => None,
        })
        .max_by_key(|fields| fields.policy_version)
        .expect("die Demowelt muss eine Policy tragen");
    assert!(
        ea_archive::BoundArchiveProfilePolicyV1::from_policy(&effective)
            .permits(world.archive_profile_hash),
        "der Profilhash der Writer-Station muss in `allowed-archive-profile-hashes` der \
         wirksamen Policy (Version {}) stehen",
        effective.policy_version
    );
}

#[test]
fn the_administration_registration_inbox_is_a_real_directory() {
    let scratch = scratch("demo-world-inbox");
    let root = scratch.path().join("welt");
    let world = seed_demo_world(&root).expect("die Demowelt muss sich säen lassen");

    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(&world.admin.role_config).unwrap()).unwrap();
    let inbox = std::path::PathBuf::from(config["registration_inbox"].as_str().unwrap());
    // `AdministrationResources::open` liest `symlink_metadata` und weist einen
    // Symlink ausdrücklich ab. Genau das wird hier gemessen, nicht `is_dir`
    // über den aufgelösten Pfad.
    let metadata = fs::symlink_metadata(&inbox).expect("der Eingang muss existieren");
    assert!(metadata.is_dir(), "der Eingang muss ein Verzeichnis sein");
    assert!(
        !metadata.file_type().is_symlink(),
        "der Eingang darf kein Symlink sein"
    );
}

#[test]
fn both_stations_carry_their_own_directory_database_and_configuration() {
    let scratch = scratch("demo-world-stations");
    let root = scratch.path().join("welt");
    let world = seed_demo_world(&root).expect("die Demowelt muss sich säen lassen");

    assert_ne!(world.writer.directory, world.admin.directory);
    assert_ne!(world.writer.database, world.admin.database);
    for station in [&world.writer, &world.admin] {
        assert!(station.operator_config.is_file());
        assert!(station.role_config.is_file());
        assert!(station.database.is_file());
    }
    let writer: serde_json::Value =
        serde_json::from_slice(&fs::read(&world.writer.operator_config).unwrap()).unwrap();
    let admin: serde_json::Value =
        serde_json::from_slice(&fs::read(&world.admin.operator_config).unwrap()).unwrap();
    assert_eq!(writer["role"], "writer");
    assert_eq!(admin["role"], "organization-admin");
    // Der Wirt schließt `--writer-config` und `--administration-config`
    // gegenseitig aus; zwei Rollen brauchen deshalb zwei Konfigurationen.
    assert_ne!(writer["binding_object_hash"], admin["binding_object_hash"]);

    // Beide Bedienerkonfigurationen müssen so ladbar sein, wie der Wirt sie
    // lädt.
    for station in [&world.writer, &world.admin] {
        ea_admin::operator_runtime::OperatorRuntimeConfig::load(&station.operator_config)
            .expect("die Bedienerkonfiguration muss ladbar sein");
    }
}

#[test]
fn the_reader_finds_its_entry_package_and_its_grant() {
    let scratch = scratch("demo-world-reader");
    let root = scratch.path().join("welt");
    let world = seed_demo_world(&root).expect("die Demowelt muss sich säen lassen");

    // Ohne Grant zeigt der Reader nichts. Beide Dateien liegen im Archiv, das
    // die Web-Anwendung über „Archiv öffnen" lädt.
    assert!(
        world.reader_entry_package.is_file(),
        "die .eip-Datei muss im Archiv liegen: {}",
        world.reader_entry_package.display()
    );
    assert!(
        world.reader_grant.is_file(),
        "der Reader-Grant muss im Archiv liegen: {}",
        world.reader_grant.display()
    );
    assert_eq!(world.reader_archive_directory, world.archive_directory);
    assert_eq!(world.reader_private_key_hex.len(), 64);
}

#[test]
fn the_seed_never_overwrites_an_occupied_directory() {
    let scratch = scratch("demo-world-occupied");
    let root = scratch.path().join("welt");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("bestand.txt"), b"nicht anfassen").unwrap();
    assert!(
        seed_demo_world(&root).is_err(),
        "ein belegtes Verzeichnis muss die Saat abweisen"
    );
    assert_eq!(
        fs::read(root.join("bestand.txt")).unwrap(),
        b"nicht anfassen"
    );
}
