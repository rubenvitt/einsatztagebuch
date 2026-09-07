//! Die Kommandoflaeche der VERWALTUNG (Stufe 5, Task 6, DRK-274) — als
//! LITERAL verankert, in derselben Bauart wie `writer_commands.rs`.
//!
//! Drei Zusagen greifen ineinander:
//!
//! 1. Der `invoke_handler` registriert GENAU diese siebzehn Namen, in dieser
//!    Reihenfolge, hinter `sync_state`; das App-ACL-Manifest in `build.rs` und
//!    die Faehigkeitserklaerung in `tauri.conf.json` decken dieselbe Menge.
//! 2. Die Schale (`apps/desktop/src/features/admin/AdminPage.tsx`,
//!    `ADMIN_COMMANDS`) nennt jeden dieser Namen als Literal — ein Tippfehler
//!    dort ist zur Uebersetzungszeit sonst auf keiner Seite sichtbar.
//! 3. Kein Name bedient das Lesen, Entschluesseln oder den Verlauf eines
//!    Eintrags: die Verwaltung fuehrt Zeremonien, sie oeffnet kein Archiv.

/// Die siebzehn Namen aus `.superpowers/admin-ui-contract.md` §5, woertlich.
const ADMIN_EXPECTED: &[&str] = &[
    "admin_pending_device_requests",
    "admin_ceremony_begin",
    "admin_ceremony_confirm_fingerprint",
    "admin_ceremony_authorize",
    "admin_ceremony_export_request",
    "admin_ceremony_import_reply",
    "admin_ceremony_publish",
    "admin_policy_profile",
    "admin_registry_health",
    "admin_go_live_checklist",
    "admin_go_live_export_unresolved",
    "admin_clock_release_offer",
    "admin_clock_release_issue",
    "admin_writer_transition_state",
    "admin_writer_transition_prepare",
    "admin_writer_transition_activate",
    "admin_revocation_effect",
];

/// Die Kommandonamen, die die Faehigkeitserklaerung freigibt — derselbe
/// Rueckweg `allow-$kebab` → `snake_case` wie in `writer_commands.rs`.
fn capability_command_names(conf: &str) -> Vec<String> {
    let value: serde_json::Value =
        serde_json::from_str(conf).expect("die Wirtskonfiguration ist kein JSON");
    let capabilities = value["app"]["security"]["capabilities"]
        .as_array()
        .expect("die Wirtskonfiguration erklaert keine Faehigkeitsliste");
    let mut names = Vec::new();
    for capability in capabilities {
        let Some(permissions) = capability["permissions"].as_array() else {
            continue;
        };
        for permission in permissions {
            let identifier = permission
                .as_str()
                .expect("jede Erlaubnis ist eine Zeichenkette");
            if let Some(command) = identifier.strip_prefix("allow-") {
                names.push(command.replace('-', "_"));
            }
        }
    }
    names
}

/// Die Kommandoliste des Bauskripts, aus seiner Quelle gelesen.
fn acl_declared_commands() -> Vec<String> {
    let build_source = include_str!("../build.rs");
    let start = build_source
        .find("EA_COMMANDS")
        .expect("build.rs fuehrt keine Kommandoliste");
    let assignment = "= &[";
    let list = &build_source[start..];
    let open = list
        .find(assignment)
        .expect("die Kommandoliste ist keine zugewiesene Liste")
        + assignment.len();
    let close = list[open..]
        .find(']')
        .expect("die Kommandoliste ist nicht geschlossen")
        + open;
    list[open..close]
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.trim_matches('"').to_owned())
        .collect()
}

/// Registriert, ACL-erklaert und erlaubt — dieselben siebzehn, ueberall.
#[test]
fn the_administration_commands_are_registered_declared_and_permitted() {
    let registered = ea_desktop::registered_command_names();
    let admin_registered: Vec<&str> = registered
        .iter()
        .copied()
        .filter(|name| name.starts_with("admin_"))
        .collect();
    assert_eq!(admin_registered, ADMIN_EXPECTED);
    // Hinter `sync_state`, als geschlossener Block.
    let sync_at = registered
        .iter()
        .position(|name| *name == "sync_state")
        .expect("sync_state fehlt");
    assert_eq!(&registered[sync_at + 1..], ADMIN_EXPECTED);

    let declared = acl_declared_commands();
    for name in ADMIN_EXPECTED {
        assert!(
            declared.iter().any(|entry| entry == name),
            "build.rs erklaert {name} nicht im App-ACL-Manifest"
        );
    }

    let permitted = capability_command_names(include_str!("../tauri.conf.json"));
    assert!(!permitted.is_empty());
    for name in ADMIN_EXPECTED {
        assert_eq!(
            permitted.iter().filter(|entry| entry == name).count(),
            1,
            "tauri.conf.json erlaubt {name} nicht genau einmal"
        );
    }
}

/// Die Schale nennt DIESELBEN Kommandonamen wie der Wirt.
///
/// `include_str!` und nicht `fs::read_to_string`, wie bei `WriterPage.tsx`:
/// verschwindet die Datei, UEBERSETZT dieser Zeuge nicht mehr — eine
/// Verwaltungsflaeche ohne Schale waere sonst nur ein roter Zeuge.
#[test]
fn the_administration_surface_names_the_same_commands_as_the_host() {
    const ADMIN_PAGE: &str = include_str!("../../src/features/admin/AdminPage.tsx");
    assert!(
        ADMIN_PAGE.contains("ADMIN_COMMANDS"),
        "AdminPage.tsx fuehrt keine Tabelle ADMIN_COMMANDS"
    );
    let mut checked = 0_usize;
    for name in ADMIN_EXPECTED {
        assert!(
            ADMIN_PAGE.contains(&format!("'{name}'")),
            "AdminPage.tsx nennt {name} nicht"
        );
        checked += 1;
    }
    // Ohne diese Zaehlung liefe die Schleife ueber nichts und blieb gruen.
    assert_eq!(checked, 17);
}

/// Kein Verwaltungskommando liest, entschluesselt oder blaettert: die
/// Verwaltung fuehrt Zeremonien ueber Vertrauen, nicht ueber Inhalte.
#[test]
fn no_administration_command_serves_content() {
    for name in ADMIN_EXPECTED {
        for forbidden in ["reader", "read", "decrypt", "history", "content", "entry"] {
            assert!(
                !name.contains(forbidden),
                "{name} enthaelt {forbidden} und bedient damit eine Flaeche, die der Verwaltung nicht gehoert"
            );
        }
    }
    assert_eq!(ADMIN_EXPECTED.len(), 17);
}

/// Jeder Wiederanmeldungszweck, den eine Flaeche sendet, ist ein
/// `ReauthPurpose::label()`.
///
/// `session_reauthenticate_core` findet den Zweck ueber genau dieses Etikett
/// und weist alles andere mit `EA-DESKTOP-REAUTH-PURPOSE-UNKNOWN` ab. Bis
/// DRK-274 war die Wiederanmeldung ein Stumpf, und die Writer-Flaeche sendete
/// `discard` und `stale-ack` — zwei Woerter, die nie ein Etikett waren und
/// deren Fehler kein Zeuge sah. Dieser hier liest beide Flaechen und laesst
/// keine Zweckzeichenkette durch, die der Kern nicht kennt.
#[test]
fn every_surface_purpose_is_a_reauth_label() {
    const SURFACES: [(&str, &str); 2] = [
        (
            "WriterPage.tsx",
            include_str!("../../src/features/writer/WriterPage.tsx"),
        ),
        (
            "AdminPage.tsx",
            include_str!("../../src/features/admin/AdminPage.tsx"),
        ),
    ];
    let labels: Vec<&str> = ea_operator::ReauthPurpose::ALL
        .into_iter()
        .map(ea_operator::ReauthPurpose::label)
        .collect();
    let mut checked = 0;
    for (name, source) in SURFACES {
        let mut in_purpose_table = false;
        for line in source.lines() {
            if line.contains("REAUTH_PURPOSES = {") {
                in_purpose_table = true;
                continue;
            }
            if in_purpose_table && line.starts_with('}') {
                in_purpose_table = false;
                continue;
            }
            let is_purpose_line = line.contains("_PURPOSE = '") || in_purpose_table;
            if !is_purpose_line {
                continue;
            }
            let start = line
                .find('\'')
                .expect("ein Zweck steht in Anfuehrungszeichen")
                + 1;
            let end = line[start..]
                .find('\'')
                .expect("ein Zweck endet mit Anfuehrungszeichen")
                + start;
            let purpose = &line[start..end];
            assert!(
                labels.contains(&purpose),
                "{name} sendet den Zweck {purpose:?}, den `ReauthPurpose::label()` nicht kennt"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 5, "drei Writer-Zwecke und zwei Verwaltungszwecke");
}
