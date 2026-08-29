//! Die Kommandoflaeche des Writers — als LITERAL verankert.
//!
//! Drei Zusagen greifen ineinander, und nur zusammen sind sie dicht:
//!
//! 1. Der `invoke_handler` registriert GENAU diese Namen, in dieser
//!    Reihenfolge. Ein Kommando, das dazukommt, faellt hier auf; ein Kommando,
//!    das verschwindet, ebenso.
//! 2. Die Faehigkeitserklaerung in `tauri.conf.json` deckt GENAU dieselbe
//!    Menge. Seit `build.rs` ein App-ACL-Manifest erklaert, ist das keine
//!    Zierde: `tauri`s Webview verlangt fuer JEDES Kommando eine aufgeloeste
//!    Erlaubnis, sobald ein App-Manifest existiert
//!    (`tauri-2.11.5/src/webview/mod.rs`: `plugin_command.is_some() ||
//!    has_app_acl_manifest`), und eine Erlaubnis, die kein Kommando des
//!    Manifests benennt, laesst `tauri::generate_context!` abbrechen
//!    (gemessen: `failed to resolve ACL: UnknownPermission`).
//! 3. Kein Name dieser Menge bedient das Entschluesseln, den Verlauf oder den
//!    Inhalt eines abgeschlossenen Eintrags.

/// Die vierzehn Namen, die der Brief dieses Tasks woertlich nennt.
///
/// Sie stehen SEPARAT und nicht in [`EXPECTED`] aufgeloest, damit die Werte des
/// Briefes nachlesbar bleiben und ein spaeteres Weglassen eines von ihnen
/// auffaellt.
const BRIEF_EXPECTED: &[&str] = &[
    "session_current",
    "session_reauthenticate",
    "master_data_search",
    "draft_load_active",
    "draft_save",
    "draft_discard_begin",
    "draft_discard_resume",
    "writer_preview",
    "writer_acknowledge_stale_registry",
    "writer_finalize",
    "writer_recover_pending",
    "archive_health_report",
    "device_posture_report",
    "archive_export_bundle_file",
    "sync_state",
];

/// EIN Name des Briefes traegt bereits ein Kommando der Stufe 2.
///
/// `verified_session` (Task 15) liefert genau die geprueften Sitzungsangaben,
/// die der Brief `session_current` nennt — dieselbe Antwort, derselbe Kern. Ein
/// zweiter Name dafuer waere eine zweite Kommandoflaeche fuer eine Wahrheit;
/// ein Umbenennen brach die Sperrpflicht der Stufe 2, deren Zeuge
/// `invalidate_session_on_lock` in der Liste verlangt und deren Oberflaeche
/// `verified_session` beim Namen nennt.
///
/// `writer_recover_pending` steht dagegen SELBST in der Liste: es ist nicht
/// `startup_recovery` unter anderem Namen, sondern liefert eine andere Antwort —
/// die Fortsetzungsansicht MIT Blockadecode und Veroeffentlichungszustand, die
/// die Erfassungsflaeche synchron braucht.
const BRIEF_TO_REGISTERED: &[(&str, &str)] = &[("session_current", "verified_session")];

/// Jeder registrierte Name, in REGISTRIERUNGSREIHENFOLGE.
///
/// Die ersten vier sind die Kommandos der Stufe 2 aus Task 15, danach folgen
/// die zwoelf dieses Tasks.
const EXPECTED: &[&str] = &[
    "verified_session",
    "invalidate_session_on_lock",
    "startup_recovery",
    "master_data_counts",
    "session_reauthenticate",
    "master_data_search",
    "draft_load_active",
    "draft_save",
    "draft_discard_begin",
    "draft_discard_resume",
    "writer_recover_pending",
    "writer_preview",
    "writer_acknowledge_stale_registry",
    "writer_finalize",
    "archive_health_report",
    "device_posture_report",
    "archive_export_bundle_file",
    "sync_state",
];

/// Die Kommandonamen, die die Faehigkeitserklaerung der Wirtskonfiguration
/// freigibt.
///
/// `tauri-build` erzeugt aus jedem Namen des App-Manifests die Erlaubnisse
/// `allow-$kebab` und `deny-$kebab` (`tauri-build-2.6.3/src/acl.rs`:98-103).
/// Diese Funktion geht denselben Weg zurueck.
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

#[test]
fn registered_commands_match_the_literal_writer_allowlist() {
    assert_eq!(ea_desktop::registered_command_names(), EXPECTED);

    let conf = include_str!("../tauri.conf.json");
    let mut from_capabilities: Vec<String> = capability_command_names(conf);
    // Ohne diese Zusicherung liefe der Vergleich darunter ueber die leere
    // Menge, wenn die Erklaerung wandert — und blieb gruen.
    assert!(!from_capabilities.is_empty());
    from_capabilities.sort_unstable();
    let mut expected_sorted: Vec<String> = EXPECTED.iter().map(|name| (*name).to_owned()).collect();
    expected_sorted.sort_unstable();
    assert_eq!(from_capabilities, expected_sorted);

    for name in EXPECTED {
        assert!(!name.contains("decrypt"));
        assert!(!name.contains("history"));
        assert!(!name.contains("entry_content"));
    }
}

/// Jeder Name des Briefes ist erreichbar — direkt oder unter dem Namen, den die
/// Stufe 2 ihm schon gegeben hat.
#[test]
fn every_command_the_brief_names_is_reachable() {
    for name in BRIEF_EXPECTED {
        let registered = BRIEF_TO_REGISTERED
            .iter()
            .find_map(|(brief, actual)| (brief == name).then_some(*actual))
            .unwrap_or(name);
        assert!(
            EXPECTED.contains(&registered),
            "der Brief nennt {name}, und {registered} steht nicht in der Liste"
        );
    }
    // Die Ersetzungstabelle darf nicht zur Ausrede werden: jeder Eintrag muss
    // einen Namen des Briefes ersetzen, und die Zahl ist gepinnt.
    assert_eq!(BRIEF_TO_REGISTERED.len(), 1);
    for (brief, _) in BRIEF_TO_REGISTERED {
        assert!(BRIEF_EXPECTED.contains(brief));
    }
}

/// Das App-ACL-Manifest kennt GENAU die registrierten Kommandos.
///
/// `build.rs` kann `ea_desktop::COMMAND_NAMES` nicht importieren — ein
/// Bauskript uebersetzt vor seiner eigenen Crate. Die Liste steht dort also ein
/// zweites Mal, und dieser Zeuge liest die QUELLE des Bauskripts. Laufen die
/// zwei auseinander, ist entweder ein Kommando ohne Erlaubnis (zur Laufzeit von
/// der ACL verweigert) oder eine Erlaubnis ohne Kommando (der Bau bricht ab).
#[test]
fn the_app_acl_manifest_declares_every_registered_command() {
    let build_source = include_str!("../build.rs");
    let start = build_source
        .find("EA_COMMANDS")
        .expect("build.rs fuehrt keine Kommandoliste");
    // Ab der ZUWEISUNG und nicht ab dem ersten `[`: die Typangabe `&[&str]`
    // steht davor, und ein Parser, der sie mitnimmt, liest `&str` als
    // Kommandonamen (gemessen).
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
    let declared: Vec<String> = list[open..close]
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.trim_matches('"').to_owned())
        .collect();
    assert_eq!(declared, EXPECTED);
}

/// Die Oberflaeche nennt DIESELBEN Kommandonamen wie der Wirt.
///
/// Zwei Sprachen, zwei Listen: `WRITER_COMMANDS` in
/// `apps/desktop/src/features/writer/WriterPage.tsx` traegt die Namen, die
/// `invoke` schickt, und ein Tippfehler dort ist zur Uebersetzungszeit auf
/// keiner Seite sichtbar — er faellt erst im laufenden Fenster als abgelehntes
/// Kommando auf. Dieser Zeuge liest die TypeScript-Quelle und verlangt jeden
/// Namen dieses Tasks darin.
///
/// Die vier Kommandos der Stufe 2 stehen nicht in dieser Liste: sie werden von
/// `session-lock.ts` und `StartupRecovery.tsx` gerufen, und Task 15 fuehrt fuer
/// sie eigene Zeugen (`the_shell_listens_to_the_event_the_host_announces`).
#[test]
fn the_writer_surface_names_the_same_commands_as_the_host() {
    const WRITER_PAGE: &str = include_str!("../../src/features/writer/WriterPage.tsx");
    const STAGE_TWO: &[&str] = &[
        "verified_session",
        "invalidate_session_on_lock",
        "startup_recovery",
        "master_data_counts",
    ];
    let mut checked = 0_usize;
    for name in EXPECTED {
        if STAGE_TWO.contains(name) {
            continue;
        }
        assert!(
            WRITER_PAGE.contains(&format!("'{name}'")),
            "WriterPage.tsx nennt {name} nicht"
        );
        checked += 1;
    }
    // Ohne diese Zaehlung liefe die Schleife bei einer leeren Restmenge ueber
    // nichts und blieb gruen.
    assert_eq!(checked, EXPECTED.len() - STAGE_TWO.len());
    assert!(checked >= 12);
}

/// Die eingebettete Faehigkeitsliste der Konfiguration ist eine ALLOWLIST — und
/// die eingecheckte Erklaerung steht darin.
///
/// Der Fehlerfall, den dieser Zeuge faengt, und er ist ein stiller: sobald
/// `app.security.capabilities` gesetzt ist, gilt „nicht genannt heisst nicht
/// aktiv" (`tauri-utils-2.9.3/src/config.rs`:2931-2954 — ohne den Eintrag oder
/// mit leerer Liste werden ALLE Dateien aus `./capabilities/` eingeschlossen,
/// mit Eintraegen genau die genannten). Faellt die Kennung von
/// `capabilities/default.json` aus dieser Liste, verschwindet `core:default`,
/// damit `core:event:allow-listen` — und `apps/desktop/src/app/session-lock.ts`
/// kann die Sperrpflicht in einem echten Fenster nicht mehr einhaengen. Kein
/// anderer Zeuge sieht das: die zwei bestehenden lesen die DATEI und nicht ihre
/// Aktivierung.
#[test]
fn the_configuration_activates_the_checked_in_capability() {
    const CONF: &str = include_str!("../tauri.conf.json");
    const CAPABILITY: &str = include_str!("../capabilities/default.json");
    let conf: serde_json::Value =
        serde_json::from_str(CONF).expect("die Wirtskonfiguration ist kein JSON");
    let capability: serde_json::Value =
        serde_json::from_str(CAPABILITY).expect("die Faehigkeitserklaerung ist kein JSON");
    let identifier = capability["identifier"]
        .as_str()
        .expect("die Erklaerung traegt keine Kennung");
    let active = conf["app"]["security"]["capabilities"]
        .as_array()
        .expect("die Konfiguration erklaert keine Faehigkeitsliste");
    assert!(!active.is_empty());
    assert!(
        active
            .iter()
            .any(|entry| entry.as_str() == Some(identifier)),
        "die Konfiguration aktiviert die Erklaerung {identifier} nicht"
    );
    // Und die Erlaubnis, an der die Sperrpflicht haengt, steht in genau dieser
    // Erklaerung — Quelle gegen Quelle und nicht gegen eine Erinnerung.
    let permissions = capability["permissions"]
        .as_array()
        .expect("die Erklaerung nennt keine Erlaubnisliste");
    assert!(
        permissions
            .iter()
            .any(|entry| entry.as_str() == Some("core:default")),
        "die aktivierte Erklaerung traegt core:default nicht"
    );
}
