//! Nachweis ohne Fenster: beide Stationen der gesäten Demowelt kommen über
//! den FIXTURE-Wirt bis zur geöffneten Sitzung.
//!
//! Der Test bindet `src/bin/ea-desktop-fixture/fixture.rs` per `#[path]` ein —
//! denselben Text, den `ea-desktop-fixture` ausführt — und startet den
//! Fixture-Helfer als echten Kindprozess (`ea-native-operator-fixture`, als
//! `ea-native-operator` ins Stationsverzeichnis kopiert). Nur das Tauri-Fenster
//! fehlt.

// `station_directory` und `HELPER_BUILD_NAME` braucht nur das Programm.
#[allow(dead_code)]
#[path = "../src/bin/ea-desktop-fixture/fixture.rs"]
mod fixture;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use ea_demo_world::{DemoWorld, native_fixture::HELPER_FILE_NAME, seed_demo_world};
use ea_desktop::{
    runtime::DesktopLaunchConfig,
    state::{ReauthPort, RuntimeSessionPort},
};
use ea_format::OperatorRoleV1;

fn helper_build() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ea-native-operator-fixture"))
}

fn seeded(tag: &str) -> (ea_demo_world::support::TempDir, DemoWorld) {
    let directory = ea_demo_world::support::temp_dir(tag);
    let world = seed_demo_world(&directory.path().join("demowelt")).unwrap();
    (directory, world)
}

fn launch(
    world: &DemoWorld,
    station: &ea_demo_world::world::DemoStation,
    flag: &str,
) -> DesktopLaunchConfig {
    DesktopLaunchConfig::parse([
        "--operator-config".into(),
        station.operator_config.clone().into_os_string(),
        "--trust-anchor".into(),
        world.anchor_path.clone().into_os_string(),
        flag.into(),
        station.role_config.clone().into_os_string(),
    ])
    .unwrap()
    .unwrap()
}

fn entry_packages(archive: &Path) -> usize {
    fs::read_dir(archive.join("entries"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "eip")
        })
        .count()
}

fn incident() -> ea_ui_contracts::IncidentInputView {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    ea_ui_contracts::IncidentInputView {
        human_incident_number: "FIXTURE-DEMO-1".into(),
        occurred_at: ea_ui_contracts::OccurredAtView {
            start: ea_types::UnixMillis::new(i64::try_from(now).unwrap()),
            end: None,
        },
        keyword: ea_ui_contracts::KeywordView {
            reference_id: Some("N1".into()),
            display_text: "Hilfeleistung".into(),
        },
        location: ea_ui_contracts::LocationView {
            free_text: Some("Fixture-Demo-Ort".into()),
            address: None,
            coordinates: None,
        },
        personnel: vec![],
        personnel_empty_reason: Some("Keine weiteren Kräfte".into()),
        vehicles: vec![],
        vehicles_empty_reason: Some("Kein Fahrzeug".into()),
        patient_count: ea_ui_contracts::PatientCountView::Known(0),
        notes: None,
        external_organizations: vec![],
    }
}

#[test]
fn the_writer_station_opens_a_session_saves_a_draft_and_finalizes_an_entry() {
    let (_directory, world) = seeded("fixture-host-writer");
    let helper = fixture::install_helper(&helper_build(), &world.writer.directory).unwrap();
    assert_eq!(helper, world.writer.directory.join(HELPER_FILE_NAME));

    let started = Instant::now();
    let native =
        fixture::open_fixture_runtime(launch(&world, &world.writer, "--writer-config"), &helper)
            .unwrap();
    let opened = started.elapsed();
    // Wie im ausgelieferten Wirt: ohne Anmeldung keine Sitzung.
    assert_eq!(native.verified_role().unwrap(), None);
    native.login().unwrap();
    let logged_in = started.elapsed();
    assert_eq!(
        native.verified_role().unwrap(),
        Some(OperatorRoleV1::Writer)
    );

    let state = native.desktop_state();
    let drafts = state.drafts().expect("Entwurfsablage der Writer-Station");
    drafts.save_payload("FIXTURE-DEMO Entwurf".into()).unwrap();
    assert_eq!(drafts.load_payload().unwrap(), "FIXTURE-DEMO Entwurf");

    let before = entry_packages(&world.archive_directory);
    let writer = state.writer().expect("Writer-Dienst der Writer-Station");
    let input = incident();
    let preview = writer.preview(&input).unwrap();
    native
        .reauthenticate(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    let outcome = writer.finalize(&input, &preview).unwrap();
    let after = entry_packages(&world.archive_directory);
    eprintln!(
        "Writer: Laufzeit offen nach {} ms, angemeldet nach {} ms, finalisiert als \
         Sequenz {}, Eintragspakete {before} -> {after}, gesamt {} ms",
        opened.as_millis(),
        logged_in.as_millis(),
        outcome.sequence.get(),
        started.elapsed().as_millis()
    );
    assert_eq!(
        before, 1,
        "die Saat trägt genau einen finalisierten Eintrag"
    );
    assert_eq!(outcome.sequence.get(), 1);
    assert_eq!(after, 2);
    assert_eq!(drafts.load_payload().unwrap(), "");
}

/// Gegenprobe zum Writer-Zeugen oben: die frühere Saat legte für die
/// Writer-Station ein ZWEITES Writer-Zertifikat an. `ea-trust` macht nur das
/// erste Writer-Zertifikat einer Linie zum laufenden Writer; an dieser Welt
/// muss die Writer-Laufzeit deshalb abweisen. Bestünde sie hier, sähe der
/// Zeuge oben den Fehler nicht, gegen den er steht.
#[test]
fn a_second_writer_certificate_in_the_seed_is_refused_as_not_active() {
    let directory = ea_demo_world::support::temp_dir("fixture-host-second-writer");
    let world = ea_demo_world::seed_demo_world_with_second_writer_certificate(
        &directory.path().join("demowelt"),
    )
    .unwrap();
    let helper = fixture::install_helper(&helper_build(), &world.writer.directory).unwrap();
    let refused =
        fixture::open_fixture_runtime(launch(&world, &world.writer, "--writer-config"), &helper)
            .err()
            .expect("ein zweites Writer-Zertifikat darf keine Writer-Laufzeit öffnen");
    assert_eq!(
        refused,
        "Bedienerlaufzeit: EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE"
    );
}

#[test]
fn the_administration_station_opens_a_session_and_reads_its_inbox() {
    let (_directory, world) = seeded("fixture-host-admin");
    let helper = fixture::install_helper(&helper_build(), &world.admin.directory).unwrap();

    let started = Instant::now();
    let native = fixture::open_fixture_runtime(
        launch(&world, &world.admin, "--administration-config"),
        &helper,
    )
    .unwrap();
    let opened = started.elapsed();
    let state = native.desktop_state();
    let port = state
        .administration_port()
        .expect("Verwaltungsport der Adminstation");
    assert!(
        port.pending_device_requests().is_err(),
        "ohne Anmeldung liest auch der Port nichts"
    );
    assert_eq!(native.verified_role().unwrap(), None);
    native.login().unwrap();
    let logged_in = started.elapsed();
    assert_eq!(
        native.verified_role().unwrap(),
        Some(OperatorRoleV1::OrganizationAdmin)
    );
    let requests = port.pending_device_requests().unwrap();
    let ceremonies = port.open_ceremonies().unwrap();
    eprintln!(
        "Verwaltung: Laufzeit offen nach {} ms, angemeldet nach {} ms, \
         {} offene Geräteanfragen, {} offene Zeremonien",
        opened.as_millis(),
        logged_in.as_millis(),
        requests.len(),
        ceremonies.len()
    );
    assert!(requests.is_empty());
    assert!(ceremonies.is_empty());
}

#[test]
fn the_same_helper_serves_either_station_only_from_inside_that_station() {
    let (_directory, world) = seeded("fixture-host-helper");
    let account = |helper: &Path| {
        let mut child = Command::new(helper)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), br#"{"op":"account"}"#).unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    };
    // Unter seinem Baunamen antwortet der Helfer nicht.
    let refused = account(&helper_build());
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty());

    let mut installation_ids = Vec::new();
    for station in [&world.writer, &world.admin] {
        let helper = fixture::install_helper(&helper_build(), &station.directory).unwrap();
        // Ein zweites Einlegen derselben Datei ist ein No-op.
        assert_eq!(
            fixture::install_helper(&helper_build(), &station.directory).unwrap(),
            helper
        );
        let answered = account(&helper);
        assert_eq!(answered.status.code(), Some(0));
        let response: serde_json::Value = serde_json::from_slice(&answered.stdout).unwrap();
        assert_eq!(response["ok"], serde_json::json!(true));
        assert_eq!(response["locked"], serde_json::json!(false));
        installation_ids.push(response["installation_id"].as_str().unwrap().to_owned());
    }
    assert_ne!(installation_ids[0], installation_ids[1]);
}

/// `run()` bleibt unverändert, also steht die Kommandoliste des Fixture-Wirts
/// ein zweites Mal im Quelltext. Dieser Zeuge hält beide zeichengleich: ein
/// Kommando, das nur der ausgelieferte Wirt kennt, wäre im Fixture-Fenster
/// still tot.
#[test]
fn the_fixture_host_registers_exactly_the_shipped_command_list() {
    fn handler_list(source: &str) -> &str {
        let start = source
            .find("generate_handler![")
            .expect("eine generate_handler!-Liste");
        let rest = &source[start..];
        &rest[..rest.find("])").expect("das Ende der Liste")]
    }
    let shipped = include_str!("../src/lib.rs");
    let fixture = include_str!("../src/bin/ea-desktop-fixture/main.rs");
    assert_eq!(shipped.matches("generate_handler![").count(), 1);
    assert_eq!(fixture.matches("generate_handler![").count(), 1);
    assert_eq!(handler_list(fixture), handler_list(shipped));
    assert_eq!(
        handler_list(fixture).matches("commands::").count(),
        ea_desktop::COMMAND_NAMES.len()
    );
}
