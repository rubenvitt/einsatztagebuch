//! Das kontrollierte Netzbackend: gepinntes Profil oder gar nichts.

mod support;

use ea_archive_fs::{ControlledNetworkBackend, LocalCommitComponentV1};

#[test]
fn controlled_network_requires_a_local_commit_component_and_rejects_a_generic_share() {
    let (_guard, root) = support::temp_root("controlled-network");
    let policy = support::policy_allowing_controlled_network();

    // Ohne verschluesselte lokale Commit-Komponente: fail-closed.
    assert_eq!(
        ControlledNetworkBackend::open(
            root.join("network"),
            LocalCommitComponentV1::plaintext(root.join("commit")),
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
            support::encrypted_local_commit(root.join("commit")),
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
        support::encrypted_local_commit(root.join("commit")),
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
            support::encrypted_local_commit(commit_root.clone()),
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
