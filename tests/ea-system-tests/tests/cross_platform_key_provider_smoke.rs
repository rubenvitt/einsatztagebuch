//! Der plattformuebergreifende Rauchtest des Schluesselports.
//!
//! Er belegt drei Dinge fuer den HOST, auf dem er laeuft: dass genau eine Zeile
//! der Support-Matrix aufgeloest wird, dass diese Zeile ihr Schutzprofil als
//! Variante von `KeyProtectionProfileV1` und nicht als eigene
//! Stufe-2-Aufzaehlung nennt, und dass auf diesem Host kein
//! Hardwareanspruch durchgeht.
//!
//! Er belegt AUSDRUECKLICH NICHT Baubarkeit oder Lauffaehigkeit fuer
//! `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`
//! oder `x86_64-apple-darwin`: `rust-toolchain.toml` stellt neben dem Host nur
//! `wasm32-unknown-unknown` bereit (gepinnt durch
//! `rust_toolchain_declares_wasm32_and_no_release_target` in
//! `tools/xtask/tests/workspace.rs`), und Task 18 traegt die vier Tripel als
//! offene Stufe-7-Ledgerzeilen ein.

use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    InMemoryKeyProvider, KeyProvider, KeystoreProvider, SecretPurpose, SupportMatrixRow,
    require_claimed_protection_profile,
};

#[test]
fn the_row_resolved_for_this_host_reports_itself_and_the_wire_protection_profile() {
    let row = SupportMatrixRow::current_host()
        .expect("the host target must be one row of the v0.1 support matrix");

    #[cfg(target_os = "windows")]
    assert_eq!(row, SupportMatrixRow::Windows11X86_64);
    #[cfg(target_os = "linux")]
    assert_eq!(row, SupportMatrixRow::Ubuntu2404X86_64);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    assert_eq!(row, SupportMatrixRow::MacOsArm64);
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    assert_eq!(row, SupportMatrixRow::MacOsX86_64);

    // Die Zeile nennt ein Profil des WIRE-FORMATS. Die Annotation ist die
    // Zusicherung: gaebe es eine eigene Stufe-2-Aufzaehlung, uebersetzte diese
    // Zeile nicht.
    let reached_by_row: KeyProtectionProfileV1 = row.reachable_protection_profile();
    assert_eq!(reached_by_row, KeyProtectionProfileV1::OsWrapped);

    let provider = InMemoryKeyProvider::new_for_test([0x2b; 32]);
    let handle = provider
        .generate(SecretPurpose::DraftDek, KeyProtectionProfileV1::OsWrapped)
        .expect("the in-process provider reaches the osWrapped floor");
    let reached_by_port: KeyProtectionProfileV1 = provider
        .reached_protection_profile(&handle)
        .expect("a generated entry reports its reached profile");
    assert_eq!(reached_by_port, reached_by_row);

    // Kein Provider dieser Stufe erreicht nicht-exportierbare Hardware, also
    // besteht auf diesem Host kein solcher Anspruch — auch nicht der einer
    // Support-Matrix-Zeile.
    assert_eq!(
        require_claimed_protection_profile(
            KeystoreProvider::InMemory,
            reached_by_port,
            KeyProtectionProfileV1::HardwareNonExportable,
        )
        .unwrap_err()
        .code(),
        "EA-KEY-PROTECTION-PROFILE-MISMATCH"
    );
}

/// Drei Plattformen, drei Kontoidentitaeten — nie dieselbe.
///
/// Der Bindungshash desselben Geraets und derselben Organisation faellt auf
/// Windows, macOS und Ubuntu auseinander, weil Stufe 1 die kanonische Angabe je
/// Plattform anders bildet (`crates/ea-crypto/src/os_account.rs`). Waere das
/// nicht so, koennte ein Konto einer Plattform als das gebundene Konto einer
/// anderen durchgehen — und `OperatorAuthenticator::reauthenticate` prueft
/// ausschliesslich diesen Hash.
///
/// Dies ist die Zusicherung, die diesen Test PLATTFORMUEBERGREIFEND macht: sie
/// laeuft fuer alle drei Raender auf jedem Host, weil `ea-operator` seine drei
/// Erntemodule bedingungslos deklariert.
#[test]
fn the_three_platform_harvests_never_collide_on_one_device() {
    let organization = ea_types::OrganizationId::try_from([0x21; 16].as_slice()).unwrap();
    let device = ea_types::DeviceId::try_from([0xf0; 16].as_slice()).unwrap();
    let sid = [
        0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
    ];

    let hashes = [
        ea_operator::windows::account_inputs(
            sid.to_vec(),
            [0, 0, 0, 0, 0, 5],
            vec![21, 1, 2, 3, 1000],
        ),
        ea_operator::macos::account_inputs(
            vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_owned()],
            vec!["1000".to_owned()],
            1000,
        ),
        ea_operator::linux::account_inputs(b"f81d4fae7dec11d0a76500a0c91e6bf6\n".to_vec(), 1000),
    ]
    .map(|inputs| {
        inputs
            .binding_hash(organization, device)
            .expect("every harvest of this test carries a canonical account identifier")
    });

    // `Hash32` traegt bewusst keine Formatierung, also vergleicht dieser Test
    // die Bytes und nicht ein `assert_ne!`.
    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        assert!(
            hashes[left].as_bytes() != hashes[right].as_bytes(),
            "platform {left} and platform {right} must never share a binding hash"
        );
    }
}
