//! Das kontrollierte Netzbackend: gepinntes Profil oder gar nichts.

mod support;

use ea_archive_fs::ControlledNetworkBackend;

#[test]
fn controlled_network_requires_a_local_commit_component_and_rejects_a_generic_share() {
    let (_guard, root) = support::temp_root("controlled-network");
    let policy = support::policy_allowing_controlled_network();

    // GAR KEINE lokale Commit-Komponente: fail-closed. „Fehlend" heisst hier
    // tatsaechlich fehlend — ohne diesen Aufruf waere der Arm unerreichbar.
    assert_eq!(
        ControlledNetworkBackend::open(
            root.join("network"),
            None,
            support::controlled_network_profile(),
            &policy,
        )
        .unwrap_err()
        .code(),
        "EA-ARCHIVE-MISSING-LOCAL-COMMIT"
    );

    // Eine Komponente, deren Ablage KLARTEXT schreibt: ebenfalls fail-closed,
    // und zwar an einer MESSUNG des Ruheorts und nicht an einem
    // Konstruktornamen.
    assert_eq!(
        ControlledNetworkBackend::open(
            root.join("network"),
            Some(support::plaintext_local_commit(
                root.join("plaintext-commit")
            )),
            support::controlled_network_profile(),
            &policy,
        )
        .unwrap_err()
        .code(),
        "EA-ARCHIVE-MISSING-LOCAL-COMMIT"
    );

    // Ein generischer UNC-/SMB-/NFS-/WebDAV-Pfad OHNE freigegebenes Profil:
    // ebenfalls fail-closed. Das Profil eines lokalen Pfades ist fuer ein
    // Netzziel kein freigegebenes Profil.
    assert_eq!(
        ControlledNetworkBackend::open(
            root.join("network"),
            Some(support::encrypted_local_commit(root.join("commit"))),
            support::local_profile(),
            &policy,
        )
        .unwrap_err()
        .code(),
        "EA-ARCHIVE-UNPROFILED-NETWORK-PATH"
    );

    // Und mit beidem: es traegt.
    ControlledNetworkBackend::open(
        root.join("network"),
        Some(support::encrypted_local_commit(root.join("commit"))),
        support::controlled_network_profile(),
        &policy,
    )
    .expect("ein vollstaendig gepinntes Netzprofil MUSS tragen");
}

#[test]
fn an_unknown_profile_hash_blocks_before_any_archive_path_is_used() {
    let (_guard, root) = support::temp_root("unknown-profile");
    let network_root = root.join("network");
    let commit_root = root.join("commit");

    assert_eq!(
        ControlledNetworkBackend::open(
            network_root.clone(),
            Some(support::encrypted_local_commit(commit_root.clone())),
            support::controlled_network_profile(),
            &support::policy_allowing_nothing(),
        )
        .unwrap_err()
        .code(),
        "EA-ARCHIVE-PROFILE-NOT-ALLOWED"
    );

    // KEIN Pfad des Ziels wurde benutzt: die Wurzeln existieren nicht, obwohl
    // ein tragender Aufruf sie anlegen wuerde.
    assert!(
        !network_root.exists(),
        "die Netzwurzel darf vor der Policypruefung nicht angelegt werden"
    );
    assert!(
        !commit_root.exists(),
        "die Commit-Wurzel darf vor der Policypruefung nicht angelegt werden"
    );
}

#[test]
fn a_local_backend_also_refuses_a_profile_outside_the_effective_policy() {
    let (_guard, root) = support::temp_root("local-profile-policy");
    let archive_root = root.join("archive");
    assert_eq!(
        ea_archive_fs::LocalPathBackend::open(
            archive_root.clone(),
            support::local_profile(),
            &support::policy_allowing_nothing(),
        )
        .unwrap_err()
        .code(),
        "EA-ARCHIVE-PROFILE-NOT-ALLOWED"
    );
    assert!(!archive_root.exists());
}

/// Enthaelt `haystack` die Folge `needle`?
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn the_local_commit_component_keeps_no_plaintext_at_rest() {
    let (_guard, root) = support::temp_root("commit-at-rest");
    let backend = ControlledNetworkBackend::open(
        root.join("network"),
        Some(support::encrypted_local_commit(root.join("commit"))),
        support::controlled_network_profile(),
        &support::policy_allowing_controlled_network(),
    )
    .expect("ein vollstaendig gepinntes Netzprofil MUSS tragen");

    let component = backend.local_commit();
    let published = support::signed_grant_a();
    component
        .create_if_absent("grants/a.eag", published.as_bytes())
        .expect("die erste Ablage traegt");

    // Die Zusage ist MESSBAR: wiederherstellbar durch die Komponente, aber am
    // Ruheort nicht im Klartext.
    assert_eq!(
        component.read("grants/a.eag").as_deref(),
        Some(published.as_bytes())
    );
    let at_rest = component
        .bytes_at_rest("grants/a.eag")
        .expect("die Bytes am Ruheort MUESSEN lesbar sein");
    assert_ne!(at_rest.as_slice(), published.as_bytes());
    assert!(
        !contains(&at_rest, published.as_bytes()),
        "am Ruheort darf der Klartext des Objekts NICHT stehen"
    );

    // Und Create-if-absent gilt auch hier: bytegleich idempotent, sonst
    // fail-closed.
    component
        .create_if_absent("grants/a.eag", published.as_bytes())
        .expect("eine bytegleiche Wiederholung MUSS idempotent sein");
    assert_eq!(
        component
            .create_if_absent("grants/a.eag", support::signed_grant_b().as_bytes())
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
}
