//! Die drei Urbilder des Archivprofils und der Migrationsauditkontext.
//!
//! Jede Zusicherung nennt die REGEL und nie eine Abschrift davon: der Digest
//! wird gegen eine UNABHAENGIGE Nachrechnung gestellt — SHA-256 ueber die
//! ausgeschriebene Domainzeichenkette und die kodierten Bytes —, nicht gegen
//! ein Literal und nicht gegen dieselbe Funktion, die geprueft wird. Ein Test,
//! der `archive_profile_digest` gegen `archive_profile_digest` stellt, kann
//! nicht fehlschlagen und waere damit ein Defekt.
//!
//! Die Vergleiche laufen ueber `hex::encode(..as_bytes())` und nicht ueber die
//! Hashwerte selbst: `ea_types::Hash32` traegt bewusst kein `Debug`
//! (`crates/ea-types/src/ids.rs:64`), und `assert_eq!` verlangt es.

mod support {
    use ea_format::{
        ActiveProfilePointerCoreV1, ArchiveBackendProfileCoreFieldsV1, ArchiveBackendProfileCoreV1,
        ArchiveInventoryEntryV1, ArchiveProfileKindV1,
    };
    use ea_types::{Hash32, ObjectHash};

    /// Die Domainzeichenkette des Profilurbilds, AUSGESCHRIEBEN.
    ///
    /// Bewusst ein Literal und keine Uebernahme der Konstante aus `ea-crypto`:
    /// nur so kann dieser Test dem Quelltext widersprechen. Wuerde er die
    /// Konstante importieren, zoege eine Umbenennung die Erwartung
    /// stillschweigend mit — dieselbe Entscheidung wie bei
    /// `CRYPTO_SUITE_ONE_SUITE_ID` in `crates/ea-testkit/src/lib.rs:708`.
    const ARCHIVE_PROFILE_DOMAIN: &[u8] = b"EINSATZARCHIV-ARCHIVE-PROFILE-v1";

    /// Die UNABHAENGIGE Nachrechnung von `archiveProfileHash`.
    ///
    /// SHA-256 ueber Domain und Bytes, hexadezimal. Sie ruft ausdruecklich
    /// NICHT `ea_crypto::archive_profile_digest`, sondern baut das Urbild
    /// selbst — sonst waere die Zusicherung eine Tautologie.
    #[must_use]
    pub fn expected_profile_digest(bytes: &[u8]) -> String {
        let mut preimage = ARCHIVE_PROFILE_DOMAIN.to_vec();
        preimage.extend_from_slice(bytes);
        ea_testkit::sha256_hex(&preimage)
    }

    /// Die hexadezimale Darstellung eines Digests, damit `assert_eq!` eine
    /// `Debug`-Ausgabe hat.
    #[must_use]
    pub fn hex32(value: Hash32) -> String {
        hex::encode(value.as_bytes())
    }

    /// Ein `localPath`-Profil: kein Protokoll, kein Server, keine Queue.
    ///
    /// Die Kanarienvoegel stecken NICHT darin — genau das prueft der Test.
    #[must_use]
    pub fn local_path_profile_core() -> ArchiveBackendProfileCoreV1 {
        ArchiveBackendProfileCoreV1::new(ArchiveBackendProfileCoreFieldsV1 {
            kind: ArchiveProfileKindV1::LocalPath,
            filesystem_row_id: "apfs-macos-15-case-sensitive".to_owned(),
            protocol_id: String::new(),
            server_product: String::new(),
            server_version: String::new(),
            mount_options: Vec::new(),
            failover_config_id: String::new(),
            capability_test_vector_id: "cap-v1-local".to_owned(),
            queue_max_objects: 0,
            queue_max_bytes: 0,
            resume_backoff_initial_ms: 0,
            resume_backoff_max_ms: 0,
            resume_max_attempts: 0,
        })
        .expect("das localPath-Profil der Fixture ist wohlgeformt")
    }

    /// Ein `controlledNetworkPath`-Profil, gepinnt durch Protokoll,
    /// Serverprodukt, Version, Mountoptionen, Failover und Testvektor.
    #[must_use]
    pub fn controlled_network_profile_core() -> ArchiveBackendProfileCoreV1 {
        ArchiveBackendProfileCoreV1::new(ArchiveBackendProfileCoreFieldsV1 {
            kind: ArchiveProfileKindV1::ControlledNetworkPath,
            filesystem_row_id: "smb-3-1-1-windows-server-2022".to_owned(),
            protocol_id: "smb-3.1.1".to_owned(),
            server_product: "windows-server".to_owned(),
            server_version: "2022".to_owned(),
            mount_options: vec!["nobrl".to_owned(), "sync".to_owned()],
            failover_config_id: "failover-single-node".to_owned(),
            capability_test_vector_id: "cap-v1-smb".to_owned(),
            queue_max_objects: 4096,
            queue_max_bytes: 1_073_741_824,
            resume_backoff_initial_ms: 250,
            resume_backoff_max_ms: 60_000,
            resume_max_attempts: 12,
        })
        .expect("das controlledNetworkPath-Profil der Fixture ist wohlgeformt")
    }

    fn object_hash(fill: u8) -> ObjectHash {
        ObjectHash::try_from(&[fill; 32][..]).expect("32 Bytes sind ein Objekthash")
    }

    fn hash32_of(fill: u8) -> Hash32 {
        Hash32::try_from(&[fill; 32][..]).expect("32 Bytes sind ein Hash32")
    }

    /// Der Quellprofilhash der Kontextfixture.
    ///
    /// Eine FUNKTION und keine Konstante: `Hash32` hat keinen `const`
    /// Konstruktor aus Bytes (`crates/ea-types/src/ids.rs:76`).
    #[must_use]
    pub fn source_profile_hash() -> Hash32 {
        hash32_of(0xa1)
    }

    #[must_use]
    pub fn target_profile_hash() -> Hash32 {
        hash32_of(0xa2)
    }

    #[must_use]
    pub fn inventory_hash() -> Hash32 {
        hash32_of(0xa3)
    }

    #[must_use]
    pub fn active_pointer_hash() -> Hash32 {
        hash32_of(0xa4)
    }

    #[must_use]
    pub fn inventory_entries_sorted() -> Vec<ArchiveInventoryEntryV1> {
        vec![
            ArchiveInventoryEntryV1::new("entries/000001.eip", object_hash(0x11)),
            ArchiveInventoryEntryV1::new("format/schemas/archive.cddl", object_hash(0x12)),
            ArchiveInventoryEntryV1::new("trust/organization.etb", object_hash(0x13)),
        ]
    }

    #[must_use]
    pub fn inventory_entries_in_reverse_order() -> Vec<ArchiveInventoryEntryV1> {
        let mut entries = inventory_entries_sorted();
        entries.reverse();
        entries
    }

    /// Dieselbe Pfadzeichenkette zweimal, mit VERSCHIEDENEN Inhaltshashes.
    ///
    /// Bytegleiche Doppel waeren als Duplikat trivial; zwei widerspruechliche
    /// Aussagen ueber denselben Pfad sind der Fall, der fail-closed abgewiesen
    /// werden MUSS.
    #[must_use]
    pub fn inventory_entries_with_duplicate() -> Vec<ArchiveInventoryEntryV1> {
        let mut entries = inventory_entries_sorted();
        entries.push(ArchiveInventoryEntryV1::new(
            "entries/000001.eip",
            object_hash(0x99),
        ));
        entries
    }

    #[must_use]
    pub fn inventory_entries_with_absolute_path() -> Vec<ArchiveInventoryEntryV1> {
        let mut entries = inventory_entries_sorted();
        entries.push(ArchiveInventoryEntryV1::new(
            "/entries/000002.eip",
            object_hash(0x14),
        ));
        entries
    }

    #[must_use]
    pub fn active_pointer_core(
        active_profile_hash: Hash32,
        generation: u64,
    ) -> ActiveProfilePointerCoreV1 {
        ActiveProfilePointerCoreV1::new(active_profile_hash, generation)
    }
}

#[test]
fn a_local_path_profile_hashes_over_the_fifteen_positions_and_never_over_a_path() {
    let core = support::local_path_profile_core();
    let bytes = ea_format::encode_archive_backend_profile_core(&core).unwrap();
    assert_eq!(
        support::hex32(ea_crypto::archive_profile_digest(&bytes)),
        support::expected_profile_digest(&bytes)
    );
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-HOSTNAME"));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-ACCOUNT"));
}

#[test]
fn a_controlled_network_profile_differs_from_the_local_profile_in_its_hash() {
    let local = ea_format::encode_archive_backend_profile_core(&support::local_path_profile_core())
        .unwrap();
    let network =
        ea_format::encode_archive_backend_profile_core(&support::controlled_network_profile_core())
            .unwrap();
    assert_ne!(
        support::hex32(ea_crypto::archive_profile_digest(&local)),
        support::hex32(ea_crypto::archive_profile_digest(&network))
    );
}

#[test]
fn the_inventory_list_is_root_relative_sorted_and_duplicate_free() {
    let unsorted = support::inventory_entries_in_reverse_order();
    let list = ea_format::ArchiveInventoryListV1::new(unsorted).unwrap();
    let bytes = ea_format::encode_archive_inventory_list(&list).unwrap();
    assert_eq!(
        support::hex32(ea_crypto::archive_inventory_digest(&bytes)),
        support::hex32(ea_crypto::archive_inventory_digest(
            &ea_format::encode_archive_inventory_list(
                &ea_format::ArchiveInventoryListV1::new(support::inventory_entries_sorted())
                    .unwrap()
            )
            .unwrap()
        ))
    );
    assert_eq!(
        ea_format::ArchiveInventoryListV1::new(support::inventory_entries_with_duplicate())
            .unwrap_err()
            .code(),
        "EA-FORMAT-INVENTORY-DUPLICATE"
    );
    assert_eq!(
        ea_format::ArchiveInventoryListV1::new(support::inventory_entries_with_absolute_path())
            .unwrap_err()
            .code(),
        "EA-FORMAT-INVENTORY-PATH"
    );
}

#[test]
fn the_active_pointer_hash_changes_with_every_generation() {
    let first = support::active_pointer_core(support::target_profile_hash(), 1);
    let second = support::active_pointer_core(support::target_profile_hash(), 2);
    assert_ne!(
        support::hex32(ea_crypto::active_profile_pointer_digest(
            &ea_format::encode_active_profile_pointer_core(&first).unwrap()
        )),
        support::hex32(ea_crypto::active_profile_pointer_digest(
            &ea_format::encode_active_profile_pointer_core(&second).unwrap()
        ))
    );
}

#[test]
fn the_migration_audit_context_carries_only_the_four_digests() {
    let context = ea_format::ArchiveProfileMigrationContextV1::new(
        support::source_profile_hash(),
        support::target_profile_hash(),
        support::inventory_hash(),
        support::active_pointer_hash(),
    );
    let bytes = ea_format::encode_archive_profile_migration_context(&context).unwrap();
    assert!(ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1).is_ok());
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(
        &bytes,
        b"CANARY-ORGANIZATION-NAME"
    ));
}
