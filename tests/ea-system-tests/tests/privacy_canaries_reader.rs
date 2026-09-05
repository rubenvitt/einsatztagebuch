//! Die Kanarienvoegel des Readers: kein fachliches Zeichen verlaesst den
//! entsperrten Tresor auf einem anderen Weg als dem EINEN bewusst gewaehlten
//! Exportziel.
//!
//! Je fachlichem Feld GENAU EIN eigener Marker. Ein gemeinsamer Marker fuer
//! zwei Felder liesse offen, welches von beiden geleckt hat — dieselbe Regel,
//! die `tests/ea-system-tests/tests/privacy_canaries_writer.rs` schon
//! durchsetzt. Gesucht wird mit `ea_testkit::contains_canary`.
//!
//! # Die sieben Stroeme, und WIE jeder gemessen wird
//!
//! | Strom | Messung | Zeuge |
//! |---|---|---|
//! | rohe OPFS-Bytes (Tresor, Cache, Zustandsspeicher, Indexblob, Auditblob) | ECHTE Bytes | [`no_fachliche_reader_canary_survives_in_the_raw_opfs_bytes`] |
//! | Service-Worker-Cache | QUELLENSCAN | [`no_production_source_writes_into_a_service_worker_cache`] |
//! | Zwischenablage-Haken | QUELLENSCAN | [`no_production_source_reaches_for_a_clipboard_automation`] |
//! | strukturierte Logs | ECHTE Bytes | [`the_signed_local_audit_log_carries_binding_and_hashes_and_never_a_marker`] |
//! | Fehlerberichte | ECHTE Bytes | [`no_error_report_of_the_reader_carries_a_fachlichen_marker`] |
//! | Servermetadaten | ECHTE Bytes | [`the_server_never_sees_a_fachlichen_marker_in_the_reader_request_metadata`] |
//! | Telemetrie | QUELLENSCAN | [`no_production_source_ships_telemetry`] |
//!
//! **Die drei Quellenscans sind Quellenscans und keine Laufzeitmessung**, und
//! der Bericht sagt es an jeder der drei Stellen noch einmal. Service-Worker-
//! Cache, Zwischenablage und Telemetrie haben in diesem Baum keine
//! Rust-Darstellung: der Service Worker ist TypeScript
//! (`apps/web/src/sw/service-worker.ts`), die Zwischenablage und die
//! Telemetrie sind Wirt-APIs, die niemand ruft. „Niemand ruft sie" ist eine
//! Aussage ueber den QUELLTEXT, mechanisch pruefbar und staerker als eine
//! Laufzeitstichprobe — aber sie ist nicht dieselbe Aussage, und dieser Zeuge
//! behauptet die andere nicht.
//!
//! # Die LAUFZEITHAELFTE des Service Workers ist UNBEZEUGT
//!
//! Eine fruehere Fassung dieses Kopfes verwies dafuer auf
//! `apps/web/src/sw/service-worker.test.ts`. Der Verweis war falsch, GEMESSEN
//! am 2026-09-05: diese Datei fuehrt acht Zeugen ueber der Buendelpinnung und
//! nennt `fetch`, `addEventListener`, `respondWith` und `cache.put` KEIN
//! einziges Mal. Es gibt in diesem Baum also keinen Zeugen dafuer, wie sich
//! ein registrierter Service Worker zur Laufzeit gegenueber einer Antwort
//! verhaelt — nur den Quellenscan darueber, dass keine Quelle einen solchen
//! Haken schreibt.
//!
//! Was die Luecke schloesse, benannt statt umschrieben: ein Laufzeitzeuge im
//! Service-Worker-Bereich, der eine `fetch`-Anfrage stellt und danach
//! zusichert, dass KEIN Eintrag in irgendeinem `caches`-Namensraum liegt —
//! also dass kein `fetch`-Haken eine Antwort zwischenspeichert. Er gehoerte
//! nach `apps/web` und kann in dieser Rust-Testcrate nicht entstehen.
//!
//! # Der Reader liest den Bestand, den er misst
//!
//! `ReaderCanaryHarness::run` faehrt den Kanarieneinsatz durch die volle
//! Kette: versiegelter Tresor in OPFS, Klassifikation ueber neun Gates,
//! `decrypt_verified`, inhaltsadressierter Cache, Zustandsspeicher,
//! verschluesselter Index samt Suche, signierter Lesestapel-Request,
//! Sitzungssperre und authenticator-bestaetigter Einzelexport mit zwei
//! signierten Auditzeilen.
//!
//! # Die Positivkontrollen, ohne die die Datei nichts belegt
//!
//! 1. Jeder Marker steckt WIRKLICH in den kodierten Klartextbytes
//!    ([`every_named_field_carries_its_own_marker_and_the_vault_gives_it_back`]).
//! 2. Derselbe Marker kommt ueber den ENTSPERRTEN Tresor zurueck — aus
//!    `decrypt_verified`, nicht behauptet —, und die Suche ueber dem
//!    Stichwortmarker findet genau diesen Einsatz.
//! 3. Die Suche FINDET einen Marker, der wirklich unverschluesselt im Byteport
//!    liegt ([`the_search_finds_a_marker_that_really_lies_in_the_raw_opfs_bytes`]).
//!    Ohne sie waere eine leere Stromsammlung von einem sauberen Speicher nicht
//!    zu unterscheiden.
//! 4. Der eine ERLAUBTE Ausgang traegt die Marker: das bewusst gewaehlte
//!    Exportziel bekommt den Klartext. Ein Zeuge, in dem die Marker nirgends
//!    ankommen, waere gruen und wertlos.
//!
//! # Keine Bytes in Zusicherungen
//!
//! Panik- und Zusicherungstexte landen in CI-Protokollen. Keine Meldung dieser
//! Datei gibt Klartext oder Schluesselmaterial aus; sie nennt das FELD und die
//! STELLE, und nie den Inhalt.

mod reader_canary_support;

use std::collections::BTreeSet;

use ea_format::{LocalAuditOutcomeV1, decode_local_audit_event};
use reader_canary_support::{
    ALLOWED_CACHE_CALLS_V1, CANARY_EXPORT_FILENAME_V1, CLIPBOARD_NEEDLES_V1, NON_SCHEMA_MARKERS_V1,
    READER_CANARY_MARKERS, ReaderCanaryHarness, SERVICE_WORKER_CACHE_NEEDLES_V1,
    TELEMETRY_NEEDLES_V1, UNMARKED_SCHEMA_FIELDS_V1, cache_api_call_sites, canary, canary_text,
    first_forbidden_call, hand_written_browser_sources, incident_schema_surface,
    is_plaintext_export,
};

/// Wie viele Zeilen ein gelungener Einzelexport schreibt: `Accepted` vor der
/// unwiderruflichen Grenze und `Completed` danach.
const AUDIT_LINES_OF_ONE_EXPORT_V1: usize = 2;

/// Die ACHT Abweisungen, die [`ReaderCanaryHarness::error_reports`] wirklich
/// fuehrt — benannt und nicht gezaehlt.
///
/// Vier davon erzeugt EIN fremder Tresor: er oeffnet weder ein Cacheobjekt
/// noch einen Eintragszustand noch das Protokoll noch den Index. Die vier
/// uebrigen kommen aus vier verschiedenen Ursachen: ein Genesis-Paket traegt
/// keine fachliche Indexzeile, ein Export ohne Ziel wird VOR der Grenze
/// abgewiesen, ein fremder PRF-Ausgang oeffnet den Tresor nicht, und eine
/// ausbrechende Blobadresse ist keine Adresse.
///
/// Jede der acht schreibt eine `Debug`-Zeile unter dem hier genannten Namen;
/// DREI von ihnen zusaetzlich eine `Display`-Zeile (Cache-, Index- und
/// Exportabweisung). Mit den drei `Debug`-Zeilen der GELUNGENEN Wege — Bericht,
/// Suchtreffer, Schwellenzustand — und der des zweiten entschluesselten
/// Datensatzes sind es fuenfzehn Berichte, gezaehlt am 2026-09-05.
const ABGEWIESENE_WEGE_V1: [&str; 8] = [
    "Cachefehler unter fremdem Tresor",
    "Zustandsspeicherfehler unter fremdem Tresor",
    "Protokollfehler unter fremdem Tresor",
    "Indexfehler unter fremdem Tresor",
    "Schemaweigerung des Index",
    "Debug der Exportabweisung",
    "Tresorfehler",
    "Adressfehler des Byteports",
];

/// STROM 1 — die rohen OPFS-Bytes. ECHTE Bytes.
///
/// Gemessen wird der `InMemoryReaderBlobStore` nach dem vollen Lauf: der
/// versiegelte Tresor, jeder Cacheblob, der Eintragszustand, der versiegelte
/// Index und das versiegelte Auditprotokoll — dazu die Adressliste, die den
/// Byteport im KLARTEXT verlaesst.
#[test]
fn no_fachliche_reader_canary_survives_in_the_raw_opfs_bytes() {
    let harness = ReaderCanaryHarness::run();
    let streams = harness.raw_opfs_bytes();
    // ANTI-LEERLAUF, und zwar NAMENTLICH: ein `streams.len() > 0` haelt auch
    // ueber einem Speicher, dem der Indexblob fehlt. Verlangt wird deshalb
    // jede der fuenf Flaechen, die dieser Lauf wirklich belegt — Tresor,
    // Cache, Zustandsspeicher, Indexblob und das versiegelte Auditprotokoll.
    for surface in [
        "OPFS-Blob vault/",
        "OPFS-Blob cache/",
        "OPFS-Blob entry-state/",
        "OPFS-Blob search-index",
        "OPFS-Blob audit-log",
    ] {
        assert!(
            streams.iter().any(|(place, _)| place.starts_with(surface)),
            "die Suche MUSS {surface} umfassen; ohne ihn misst sie diese Flaeche nicht"
        );
    }
    assert!(
        streams
            .iter()
            .any(|(place, _)| place == "die Adressliste des Byteports"),
        "die Adressliste verlaesst den Byteport im Klartext und gehoert in die Suche"
    );
    for (field, marker) in READER_CANARY_MARKERS {
        for (place, bytes) in &streams {
            assert!(
                !ea_testkit::contains_canary(bytes, marker),
                "der Marker des Feldes {field} steht in {place}"
            );
        }
    }
}

/// STROM 4 — die strukturierten Logs. ECHTE Bytes.
///
/// Das signierte lokale Audit IST der strukturierte Log des Readers: es gibt
/// in diesem Kern keinen zweiten Protokollweg (`ea-reader` zieht kein
/// Log-Framework, und `apps/web` fuehrt keinen `console.`-Aufruf, was
/// `apps/web/src/features/export/SingleExport.test.tsx` fuer WR-082 auf der
/// TypeScript-Seite haelt).
///
/// Die Zeile traegt, was `web-reader-design.md` §8.2 verlangt — pseudonyme
/// Bedienerbindung, Eintragshash, Zielart, `EffectiveNow`, Aktionscode und
/// Ausgang — und NIE die Nutzlast und NIE einen Klartext-Dateinamen.
#[test]
fn the_signed_local_audit_log_carries_binding_and_hashes_and_never_a_marker() {
    let harness = ReaderCanaryHarness::run();
    let events = harness.audit_events();
    assert_eq!(
        events.len(),
        AUDIT_LINES_OF_ONE_EXPORT_V1,
        "ein gelungener Einzelexport schreibt genau zwei Zeilen"
    );

    // Die POSITIVE Haelfte: was in der Zeile STEHEN muss. Ohne sie belegte der
    // Rest nur, dass die Zeile leer ist.
    let outcomes: Vec<LocalAuditOutcomeV1> = events.iter().map(|event| event.outcome()).collect();
    assert_eq!(
        outcomes,
        vec![
            LocalAuditOutcomeV1::Accepted,
            LocalAuditOutcomeV1::Completed
        ],
        "erst `Accepted` vor der Grenze, dann `Completed` danach"
    );
    for event in &events {
        assert!(
            is_plaintext_export(event.action()),
            "die Zeile eines Einzelexports traegt die Aktion `PlaintextExport`"
        );
        assert_eq!(
            event.action().code(),
            5,
            "der eingefrorene Aktionscode des Klartextexports"
        );
        assert!(
            event.operator_binding_object_hash().is_some(),
            "die Zeile traegt die pseudonyme Bedienerbindung"
        );
        assert_eq!(
            event.effective_now(),
            reader_canary_support::fixtures::EFFECTIVE_NOW,
            "die Zeile traegt die `EffectiveNow` des Laufs"
        );
        let ea_format::LocalAuditActionV1::PlaintextExport(context) = event.action() else {
            unreachable!("die Aktion wurde eine Zeile darueber geprueft");
        };
        // `EntryHash` traegt ABSICHTLICH kein `Debug` — ein `assert_eq!`
        // druckte den Hash in das CI-Protokoll. Verglichen wird deshalb mit
        // `assert!`, und die Meldung nennt die Stelle und nie den Wert.
        assert!(
            context.entry_hash() == harness.entry_hash(),
            "die Zeile nennt GENAU den exportierten Eintrag"
        );
        assert_eq!(
            context.target_kind(),
            ea_reader::ReaderExportTargetKindV1::UserChosenFile.target_kind(),
            "die Zeile nennt die Zielart"
        );
    }

    // Die NEGATIVE Haelfte: kein Marker, kein Klartext-Dateiname.
    let streams = harness.structured_log_lines();
    assert!(
        !streams.is_empty(),
        "ohne Zeilen liefe die Suche ueber nichts"
    );
    for (field, marker) in READER_CANARY_MARKERS {
        for (place, bytes) in &streams {
            assert!(
                !ea_testkit::contains_canary(bytes, marker),
                "der Marker des Feldes {field} steht in {place}"
            );
        }
    }
    // Der Dateiname des Ziels ist unter den Markern; diese Zusicherung nennt
    // ihn noch einmal ausdruecklich, weil `web-reader-design.md` §8.2 ihn als
    // eigenen Verbotsfall fuehrt.
    for (place, bytes) in &streams {
        assert!(
            !ea_testkit::contains_canary(bytes, CANARY_EXPORT_FILENAME_V1.as_bytes()),
            "der Klartext-Dateiname des Ziels steht in {place}"
        );
    }
}

/// STROM 5 — die Fehlerberichte. ECHTE Bytes.
///
/// Jede `Debug`- und `Display`-Ausgabe, die dieser Kern auf den gefahrenen
/// Wegen ueberhaupt bilden kann, samt den ACHT Abweisungen, die
/// [`ABGEWIESENE_WEGE_V1`] aufzaehlt.
///
/// Die vorige Fassung sagte „sechs" und zaehlte darunter FUENF Ursachen auf,
/// die acht Abweisungen erzeugen; die Zahl gehoerte zu keiner der beiden
/// Mengen. Und eine der acht war gar keine: die Cacheabfrage lief gegen
/// `object_hash(b"kanarie")`, eine Adresse, die im Byteport nicht existiert.
/// Ein Cache-FEHLGRIFF meldet `Ok(None)`; der Eintrag trug damit die
/// Zeichenkette „None" und zaehlte trotzdem gegen die Untergrenze. Er fragt
/// jetzt nach einem Objekt, das WIRKLICH im Cache liegt, und bekommt eine
/// echte Weigerung.
#[test]
fn no_error_report_of_the_reader_carries_a_fachlichen_marker() {
    let harness = ReaderCanaryHarness::run();
    let streams = harness.error_reports();
    // ANTI-LEERLAUF, und zwar NAMENTLICH statt ueber einer Zahl: eine
    // Untergrenze `>= 12` haelt auch ueber einer Sammlung, der ein ganzer
    // Abweisungsweg fehlt, solange irgendwo zwei Debugzeilen nachwachsen.
    for way in ABGEWIESENE_WEGE_V1 {
        assert!(
            streams.iter().any(|(place, _)| place == way),
            "die Sammlung MUSS den Bericht `{way}` fuehren"
        );
    }
    assert!(
        streams.len() >= ABGEWIESENE_WEGE_V1.len(),
        "es waren {}",
        streams.len()
    );
    for (field, marker) in READER_CANARY_MARKERS {
        for (place, bytes) in streams {
            assert!(
                !ea_testkit::contains_canary(bytes, marker),
                "der Marker des Feldes {field} steht in {place}"
            );
        }
    }
}

/// STROM 6 — die Servermetadaten. ECHTE Bytes.
///
/// Der fertig signierte Lesestapel-Request ist alles, was dieser Reader dem
/// Server je mitteilt: `apps/web/src/sync/transport.ts` darf ihn abschicken
/// und sonst nichts (`crates/ea-reader/src/http.rs`, Modulkopf). Gemessen
/// werden Methode, Autoritaet, Ziel samt Abfragezeichenkette, jede Kopfzeile
/// und der Koerper.
#[test]
fn the_server_never_sees_a_fachlichen_marker_in_the_reader_request_metadata() {
    let harness = ReaderCanaryHarness::run();
    let streams = harness.server_metadata();
    assert!(
        !streams.is_empty(),
        "ohne Request liefe die Suche ueber nichts"
    );
    for (field, marker) in READER_CANARY_MARKERS {
        for (place, bytes) in streams {
            assert!(
                !ea_testkit::contains_canary(bytes, marker),
                "der Marker des Feldes {field} steht in {place}"
            );
        }
    }
}

/// STROM 2 — der Service-Worker-Cache. QUELLENSCAN, keine Laufzeitmessung.
///
/// Gemessen am eingecheckten Quelltext: `apps/web/src/sw/service-worker.ts`
/// haengt sich in KEIN `fetch`-Ereignis ein und schreibt in keinen Cache. Die
/// drei Cache-Aufrufe, die er fuehrt, legen den Namensraum der neuen Fassung
/// an, listen die alten und raeumen sie ab. Ein Cache, in den nie etwas
/// geschrieben wird, kann keinen entschluesselten Inhalt tragen.
#[test]
fn no_production_source_writes_into_a_service_worker_cache() {
    let sources = hand_written_browser_sources();
    assert!(
        sources.len() > 20,
        "ein falscher Wurzelpfad liefert eine leere Menge; es waren {}",
        sources.len()
    );
    assert!(
        sources
            .iter()
            .any(|(path, _)| path == "apps/web/src/sw/service-worker.ts"),
        "der Service Worker MUSS in der gescannten Menge liegen"
    );
    for (path, text) in &sources {
        assert!(
            first_forbidden_call(text, &SERVICE_WORKER_CACHE_NEEDLES_V1).is_none(),
            "{path} greift auf einen Service-Worker-Cache oder auf `fetch` zu"
        );
    }

    // Und jede Stelle, die die Cache-API ueberhaupt anspricht, ist eine der
    // drei erlaubten. Ohne diese Haelfte bliebe ein neuer Aufrufweg, den die
    // Nadelliste noch nicht kennt, unbemerkt.
    let sites = cache_api_call_sites(&sources);
    assert!(
        !sites.is_empty(),
        "der Service Worker fuehrt Cache-Aufrufe; eine leere Menge hiesse, der Scan sieht die \
         Datei nicht"
    );
    for (path, site) in &sites {
        assert!(
            ALLOWED_CACHE_CALLS_V1
                .iter()
                .any(|allowed| site.ends_with(allowed)),
            "{path} fuehrt einen Cache-Aufruf ausserhalb von Anlegen, Listen und Abraeumen"
        );
    }

    // POSITIVKONTROLLE des Praedikats: es FINDET einen Treffer, wenn es einen
    // gibt. Ein Praedikat, das nie trifft, waere von einem sauberen Baum nicht
    // zu unterscheiden.
    assert_eq!(
        first_forbidden_call(
            "await cache.put(request, response)",
            &SERVICE_WORKER_CACHE_NEEDLES_V1
        ),
        Some("cache.put(")
    );

    // Und zwar UNABHAENGIG vom Anfuehrungszeichen. Diese drei Zusicherungen
    // sind der Kern des Befundes, der diese Fassung ausgeloest hat: die vorige
    // Nadelliste kannte nur die einfache Schreibung, und der Baum fuehrt weder
    // eslint noch biome noch prettier noch oxlint, die eine erzwaenge.
    for registration in [
        "self.addEventListener('fetch', handler)",
        "self.addEventListener(\"fetch\", handler)",
        "self.addEventListener(`fetch`, handler)",
        "self.addEventListener(\n  'fetch',\n  handler,\n)",
    ] {
        assert_eq!(
            first_forbidden_call(registration, &SERVICE_WORKER_CACHE_NEEDLES_V1),
            Some("addEventListener('fetch'"),
            "eine `fetch`-Registrierung MUSS unabhaengig von Anfuehrungszeichen und Umbruch \
             auffallen"
        );
    }

    // POSITIVKONTROLLE der ZWEITEN Haelfte: die Fundstellensuche kommt aus der
    // BINDUNG und nicht aus dem Empfaengernamen. Genau dieser Fall — ein
    // Handle aus `caches.open(`, unter einem anderen Namen beschrieben — war
    // vor dieser Fassung gemessen gruen.
    let leaking = vec![(
        "apps/web/src/sw/service-worker.ts".to_owned(),
        "const box = await caches.open('ea-reader-bundle-leak')\nawait box.put(request, response)"
            .to_owned(),
    )];
    let leaking_sites = cache_api_call_sites(&leaking);
    assert!(
        leaking_sites
            .iter()
            .any(|(_, site)| site.ends_with("box.put(")),
        "ein Cachehandle unter fremdem Namen MUSS eine Fundstelle sein, es waren {leaking_sites:?}"
    );
    assert!(
        leaking_sites.iter().any(|(_, site)| !ALLOWED_CACHE_CALLS_V1
            .iter()
            .any(|allowed| site.ends_with(allowed))),
        "und sie MUSS die Erlaubnisliste verfehlen"
    );
}

/// STROM 3 — die Zwischenablage-Haken. QUELLENSCAN, keine Laufzeitmessung.
///
/// Diese Datei wiederholt die Aussage von
/// `apps/web/src/features/export/SingleExport.test.tsx` auf der Rustseite und
/// erweitert sie um `crates/ea-reader-wasm`: eine Zwischenablage-Automatik
/// koennte auch aus `web_sys` kommen, und die TypeScript-Suche saehe sie nicht.
#[test]
fn no_production_source_reaches_for_a_clipboard_automation() {
    let sources = hand_written_browser_sources();
    assert!(
        sources
            .iter()
            .any(|(path, _)| path.starts_with("crates/ea-reader-wasm/src/")),
        "die wasm-Bruecke MUSS in der gescannten Menge liegen"
    );
    for (path, text) in &sources {
        assert!(
            first_forbidden_call(text, &CLIPBOARD_NEEDLES_V1).is_none(),
            "{path} greift auf eine Zwischenablage zu"
        );
    }
    assert_eq!(
        first_forbidden_call(
            "await navigator.clipboard.writeText(hash)",
            &CLIPBOARD_NEEDLES_V1
        ),
        Some("navigator.clipboard")
    );
    assert_eq!(
        first_forbidden_call(
            "let board = web_sys::Clipboard::new();",
            &CLIPBOARD_NEEDLES_V1
        ),
        Some("web_sys::Clipboard")
    );
}

/// STROM 7 — die Telemetrie. QUELLENSCAN, keine Laufzeitmessung.
///
/// Es gibt in diesem Baum keinen Telemetriedienst, den man abschalten koennte:
/// die Aussage ist, dass gar keiner eingebaut ist.
#[test]
fn no_production_source_ships_telemetry() {
    let sources = hand_written_browser_sources();
    assert!(
        sources.len() > 20,
        "ein falscher Wurzelpfad liefert eine leere Menge; es waren {}",
        sources.len()
    );
    for (path, text) in &sources {
        assert!(
            first_forbidden_call(text, &TELEMETRY_NEEDLES_V1).is_none(),
            "{path} verschickt Telemetrie"
        );
    }
    assert_eq!(
        first_forbidden_call("navigator.sendBeacon(url, view)", &TELEMETRY_NEEDLES_V1),
        Some("sendBeacon")
    );
    assert_eq!(
        first_forbidden_call("Sentry.captureException(error)", &TELEMETRY_NEEDLES_V1),
        Some("Sentry.")
    );
}

/// Die GEGENKONTROLLE der ganzen Datei: liegt ein Marker wirklich
/// unverschluesselt im Byteport, MUSS die Suche ihn finden.
///
/// Ohne sie waere jede Abwesenheitszusicherung auch dann gruen, wenn die
/// Stromsammlung leer liefe oder `contains_canary` nichts taete.
#[test]
fn the_search_finds_a_marker_that_really_lies_in_the_raw_opfs_bytes() {
    let mut harness = ReaderCanaryHarness::run();
    let marker = canary("IncidentBodyV1.keyword");
    assert!(
        !harness
            .raw_opfs_bytes()
            .iter()
            .any(|(_, bytes)| ea_testkit::contains_canary(bytes, marker)),
        "vor der Probe darf der Marker in keinem Blob stehen"
    );
    harness.plant_the_unencrypted_control_stream();
    for (field, planted) in READER_CANARY_MARKERS {
        assert!(
            harness
                .raw_opfs_bytes()
                .iter()
                .any(|(_, bytes)| ea_testkit::contains_canary(bytes, planted)),
            "die Suche MUSS den Marker des Feldes {field} in einem absichtlich \
             unverschluesselten Kontrollstrom finden"
        );
    }
}

/// Die Vollstaendigkeit der Markermenge ist selbst eine Zusage — und die
/// Positivkontrolle, dass die Marker WIRKLICH ins System gelangt sind.
///
/// Zwei Felder mit demselben Marker liessen offen, welches geleckt hat; ein
/// leerer Marker liesse `contains_canary` immer `false` melden; und ein Feld,
/// dessen Marker die Kulisse nie saet, liefe ungemessen mit.
#[test]
fn every_named_field_carries_its_own_marker_and_the_vault_gives_it_back() {
    let markers: BTreeSet<&[u8]> = READER_CANARY_MARKERS
        .iter()
        .map(|(_, marker)| *marker)
        .collect();
    assert_eq!(
        markers.len(),
        READER_CANARY_MARKERS.len(),
        "jeder Marker MUSS genau einem Feld gehoeren"
    );
    let fields: BTreeSet<&str> = READER_CANARY_MARKERS
        .iter()
        .map(|(field, _)| *field)
        .collect();
    assert_eq!(fields.len(), READER_CANARY_MARKERS.len());
    for (field, marker) in READER_CANARY_MARKERS {
        assert!(
            !marker.is_empty(),
            "{field} traegt einen leeren Marker, und `contains_canary` meldet fuer einen leeren \
             Marker immer false"
        );
        // Jeder Textmarker MUSS ein Fixpunkt der Termfaltung sein.
        // `normalize_term` (`crates/ea-index/src/inverted.rs`) rechnet
        // `NFC → to_lowercase → NFC`; ein Marker, der das nicht uebersteht,
        // stuende in einem leckenden Indexkoerper nur gefaltet, und die Suche
        // nach dem Original faende ihn nicht. `timezone` ist die begruendete
        // Ausnahme: eine IANA-Zone schreibt ihre Grossbuchstaben vor, und
        // `indexable_record` projiziert die Zone in KEINEN Term.
        if field == "CommonHeaderV1.timezone" {
            continue;
        }
        if let Ok(text) = core::str::from_utf8(marker) {
            assert!(
                text.to_lowercase() == text,
                "der Marker des Feldes {field} ueberlebt die Termfaltung des Index nicht"
            );
        }
    }

    let harness = ReaderCanaryHarness::run();

    // 1. Der Marker steckt in den KODIERTEN Klartextbytes.
    let encoded = harness.markers_in_the_encoded_payload();
    assert_eq!(encoded.len(), READER_CANARY_MARKERS.len());
    for (field, present) in encoded {
        // Der Dateiname des Exportziels ist kein Feld der Nutzlast; er wird am
        // ZIEL gesaet und nicht im Einsatz.
        if NON_SCHEMA_MARKERS_V1.contains(field) {
            assert!(
                !present,
                "der Dateiname des Ziels gehoert NICHT in die Nutzlast"
            );
            continue;
        }
        assert!(
            present,
            "die Kulisse MUSS den Marker des Feldes {field} in den Klartext gelegt haben"
        );
    }

    // 2. Derselbe Marker kommt ueber den ENTSPERRTEN Tresor zurueck.
    let opened = harness.markers_readable_through_the_vault();
    assert_eq!(opened.len(), READER_CANARY_MARKERS.len());
    for (field, present) in opened {
        if NON_SCHEMA_MARKERS_V1.contains(field) {
            continue;
        }
        assert!(
            present,
            "der entsperrte Tresor MUSS den Marker des Feldes {field} wieder herausgeben"
        );
    }
    assert!(
        harness.plaintext_len() > 0,
        "ein leerer Klartext machte jede Aussage darueber leer"
    );

    // 3. Der Index hat den Einsatz WIRKLICH aufgenommen, und die Suche ueber
    //    dem Stichwortmarker findet genau ihn.
    assert_eq!(harness.indexed_packages(), 1);
    assert_eq!(
        harness.search_hit_incident_number(),
        canary_text("IncidentBodyV1.human_incident_number"),
        "die Suche gibt die Einsatznummer des Kanarieneinsatzes zurueck"
    );

    // 4. Der EINE erlaubte Ausgang traegt die Marker. Ein Lauf, in dem sie
    //    nirgends ankommen, waere gruen und wertlos.
    for (field, marker) in READER_CANARY_MARKERS {
        if NON_SCHEMA_MARKERS_V1.contains(&field) {
            continue;
        }
        assert!(
            ea_testkit::contains_canary(harness.exported_bytes(), marker),
            "das bewusst gewaehlte Exportziel MUSS den Marker des Feldes {field} bekommen haben"
        );
    }

    // 5. Und die Auditzeilen dieses Exports sind dekodierbar — sonst maesse
    //    der Logzeuge daneben eine Zeile, die es gar nicht gibt.
    assert_eq!(
        harness.structured_log_lines().len(),
        AUDIT_LINES_OF_ONE_EXPORT_V1 * 3,
        "je Zeile drei Stroeme: signierte Bytes, Kern und Debug"
    );
    for (_, bytes) in harness.structured_log_lines() {
        let _ = decode_local_audit_event(&bytes);
    }
}

/// Die Markermenge ist VOLLSTAENDIG gegenueber der Schemaflaeche — und das
/// wird an der Quelle gemessen, nicht an der eigenen Liste.
///
/// # Warum die vorige Fassung das nicht konnte
///
/// `every_named_field_carries_its_own_marker_and_the_vault_gives_it_back`
/// zaehlt [`READER_CANARY_MARKERS`] ab. Eine Liste, die sich selbst abzaehlt,
/// kann nichts vermissen: `personnelEmptyReason`, `vehiclesEmptyReason`,
/// `roleOrFunction`, `radioCallSign`, `licensePlate`, die Koordinaten und
/// `functionLabel` fehlten, und kein Zeuge dieses Baums sagte es.
///
/// Dieser Zeuge liest die Feldnamen aus `crates/ea-schema/src/model.rs` und
/// verlangt eine LUECKENLOSE, UEBERSCHNEIDUNGSFREIE Aufteilung in „traegt
/// einen Marker" und „traegt keinen, und hier ist der gemessene Grund". Ein
/// neues Feld in `ea-schema` faellt damit rot auf, ohne dass jemand daran
/// denken muss.
#[test]
fn every_schema_field_of_the_canary_incident_is_marked_or_named_with_a_reason() {
    let surface = incident_schema_surface();
    // ANTI-LEERLAUF: ein verschobener Pfad oder ein umbenannter Blockkopf
    // liefert sonst eine leere Flaeche, und eine leere Flaeche teilt jede
    // Liste luechenlos auf.
    assert!(
        surface.len() > 50,
        "die Schemaflaeche des Kanarieneinsatzes hat mehr als 50 benannte Felder, es waren {}",
        surface.len()
    );
    for named in ["IncidentBodyV1.notes", "VehicleSnapshotV1.license_plate"] {
        assert!(
            surface.contains(named),
            "{named} MUSS in der gelesenen Schemaflaeche liegen"
        );
    }

    let marked: BTreeSet<&str> = READER_CANARY_MARKERS
        .iter()
        .map(|(field, _)| *field)
        .filter(|field| !NON_SCHEMA_MARKERS_V1.contains(field))
        .collect();
    let excused: BTreeSet<&str> = UNMARKED_SCHEMA_FIELDS_V1
        .iter()
        .map(|(field, _)| *field)
        .collect();
    assert_eq!(
        excused.len(),
        UNMARKED_SCHEMA_FIELDS_V1.len(),
        "kein Feld steht zweimal in der Begruendungsliste"
    );
    for (field, reason) in UNMARKED_SCHEMA_FIELDS_V1 {
        assert!(
            !reason.is_empty(),
            "{field} steht ohne Begruendung in der Liste"
        );
    }

    // Jeder NICHT-Schemamarker MUSS wirklich einer der Marker sein; sonst
    // schnitte die Ausnahmeliste ein Schemafeld still aus der Pruefung.
    for exception in NON_SCHEMA_MARKERS_V1 {
        assert!(
            READER_CANARY_MARKERS
                .iter()
                .any(|(field, _)| *field == exception),
            "{exception} ist als Nicht-Schemafeld gefuehrt, steht aber unter keinem Marker"
        );
        assert!(
            !surface.contains(exception),
            "{exception} ist als Nicht-Schemafeld gefuehrt und steht trotzdem in der Schemaflaeche"
        );
    }

    let doubled: Vec<&&str> = marked.intersection(&excused).collect();
    assert!(
        doubled.is_empty(),
        "ein Feld traegt einen Marker UND eine Begruendung: {doubled:?}"
    );

    let covered: BTreeSet<&str> = marked.union(&excused).copied().collect();
    let surface_names: BTreeSet<&str> = surface.iter().map(String::as_str).collect();
    let uncovered: Vec<&&str> = surface_names.difference(&covered).collect();
    assert!(
        uncovered.is_empty(),
        "diese Schemafelder tragen weder Marker noch Begruendung: {uncovered:?}"
    );
    let phantom: Vec<&&str> = covered.difference(&surface_names).collect();
    assert!(
        phantom.is_empty(),
        "diese Namen stehen in Marker- oder Begruendungsliste, aber in keinem Schema: {phantom:?}"
    );
}
