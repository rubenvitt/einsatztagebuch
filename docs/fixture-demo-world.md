# Die Fixture-Demowelt

`xtask seed-demo <verzeichnis>` schreibt eine vollständige, vorführbare
Einsatzarchiv-Welt auf die Platte: eine Registrierungslinie mit Policy,
Geräte- und Bedienerbindungen, ein Archiv mit einem finalisierten Eintrag,
einen Reader-Grant, zwei Stationsverzeichnisse und die Ankerbytes.

Alles daran ist **Fixture**. Die Schlüssel stehen als Konstanten im Quelltext
von `crates/ea-demo-world` und sind damit öffentlich bekannt. Nichts an dieser
Welt ist Bestand, nichts ist Beweis, und nichts davon darf in eine echte
Organisation geraten.

## Aufruf

```
cargo run -p xtask --features seed-demo -- seed-demo /pfad/zur/demowelt
```

Das Zielverzeichnis muss fehlen oder leer sein; die Saat überschreibt nie
etwas, das schon da ist.

Ohne `--features seed-demo` existiert das Ziel nicht — und die Kante zur
Fixture-Fläche existiert ebenfalls nicht. Das ist Absicht: der Zeuge
`no_production_build_carries_the_ea_admin_test_surface` in
`tools/xtask/tests/workspace.rs` liest den Merkmalsgraphen jedes
Produktionswirts, `tools/xtask` eingeschlossen, mit **Vorgabe**merkmalen. Die
Bauweise ist dieselbe wie bei `desktop-fixture` in `apps/cli`.

## Was entsteht

```
<verzeichnis>/
  archiv/                                 das Archiv, das auch der Reader lädt
    entries/000000000000_entry.eip        der eine finalisierte Eintrag
    grants/historical.eag                 der Reader-Grant
    grants/000000000000_original.eag      der ursprüngliche Recovery-Grant
    trust/…                               Vertrauensobjekte und Registry-Ereignisse
  fixture-demo-trust-anchor.etb           die Ankerbytes, AUSSERHALB des Archivs
  writer-station/
    operator.json                         --operator-config
    writer.json                           --writer-config
    operator.sqlite                       SQLCipher, mit einer operator_profile-Zeile
  admin-station/
    operator.json                         --operator-config
    administration.json                   --administration-config
    operator.sqlite                       eigene SQLCipher-Datenbank
    registrierungs-eingang/               echtes Verzeichnis, kein Symlink
    zeremonie-austausch/
```

Die Ankerbytes liegen außerhalb des Archivverzeichnisses, weil
`OperatorArchiveSnapshot::open` beide Pfade kanonisiert und einen Anker im
Archiv abweist.

Zwei Stationen sind keine Bequemlichkeit, sondern eine Folge des Wirts:
`--writer-config` verlangt die Rolle `writer`, `--administration-config` die
Rolle `organization-admin`. Eine einzige Bedienerkonfiguration kann nie beides
sein.

Der `profile_hash()` des Archivprofils aus `writer.json` steht in
`allowed-archive-profile-hashes` der wirksamen Policy. Ohne diesen Eintrag
wiese der Writer jede Serialisierung ab, bevor ein Byte entsteht.

## Die Stationen starten

Das Saat-Kommando nennt am Ende die beiden vollständigen Befehle. Ihre Form
ist

```
ea-desktop --operator-config <station>/operator.json \
           --trust-anchor    <verzeichnis>/fixture-demo-trust-anchor.etb \
           --writer-config   <station>/writer.json
```

beziehungsweise `--administration-config <station>/administration.json`.

**Ein Entwicklungsbau des Wirts öffnet diese Welt nicht.** Jede native Sitzung
läuft über `NativeOperatorProvider::open_installed`, und dessen
`NativeExecutableIdentity::for_installed` verlangt einen signierten,
installierten Geschwisterhelfer `ea-native-operator` mit passender
Signaturkennung — auf macOS `org.einsatzarchiv.operator.native` unter derselben
Team-ID wie `org.einsatzarchiv.cli`. Ohne diese Installation bricht der Start
mit `EA-OPERATOR-NATIVE-DENIED` ab, bevor eine Zeile der Welt gelesen wird.
[`docs/operator-ceremony.md`](operator-ceremony.md) sagt dasselbe für die
Zeremonie: „Ein kopierter unsignierter Helper neben einem
Entwicklungs-Binary genügt dem Produktionspfad nicht."

Die Demowelt ändert daran nichts und will es auch nicht: sie liefert den
Bestand, nicht die Installation.

## Der Fixture-Wirt (ohne native Sicherheitskette)

Zum Anklicken der Oberfläche gibt es ein EIGENES Programm, kein Zweig im
ausgelieferten Wirt (Ruling A, DRK-437): `ea-desktop-fixture`, nur mit dem
Merkmal `test-support`. Es nimmt dieselben Startflags wie `ea-desktop`, legt
den Fixture-Helfer `ea-native-operator-fixture` als `ea-native-operator` in
das Stationsverzeichnis und baut die Laufzeit über
`NativeOperatorProvider::open_test_fixture`. Der Helfer antwortet mit den
öffentlich bekannten Schlüsseln dieser Welt (`ea_demo_world::native_fixture`);
er liest seine Station aus der `operator.json` neben sich, weil der Wirt ihn
ohne Umgebung und ohne Argumente startet.

```
cargo build -p ea-desktop --features test-support \
            --bin ea-desktop-fixture --bin ea-native-operator-fixture
target/debug/ea-desktop-fixture --operator-config <welt>/writer-station/operator.json \
           --trust-anchor <welt>/fixture-demo-trust-anchor.etb \
           --writer-config <welt>/writer-station/writer.json
```

beziehungsweise mit `admin-station/operator.json` und
`--administration-config <welt>/admin-station/administration.json`. Vor dem
ersten Bau muss `apps/desktop/dist` stehen (`pnpm --dir apps/desktop exec vite
build`), weil der Wirt die Oberfläche einbettet.

Kein Schlüsselbund, keine Identitätsprüfung, keine Anwesenheits- und keine
Sperrprüfung. Nur für die Handprobe gegen diese Welt.

Der Nachweis ohne Fenster ist `apps/desktop/src-tauri/tests/fixture_demo_world.rs`
(`cargo test -p ea-desktop --features test-support --test fixture_demo_world`):
beide Stationen melden sich an, der Writer finalisiert einen zweiten Eintrag.

## Der Writer der Welt

Die Writer-Station bindet das Writer-Zertifikat, das den alten Eintrag
signiert hat — kein zweites. `ea-trust` macht nur das ERSTE
Writer-Zertifikat einer Linie zum laufenden Writer; ein zweites gilt als nicht
aktiv, und eine frühere Fassung dieser Saat brach deshalb in jedem Wirt mit
`EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE` ab. Die Gegenprobe
`seed_demo_world_with_second_writer_certificate` hält diese Form für den
Zeugen fest.

## Der Reader

Die Web-Anwendung öffnet im Datei-Modus dasselbe Archivverzeichnis (in Edge
und Chrome über den Ordnerweg `showDirectoryPicker`: den Ordner `archiv`
wählen). Sie zeigt den Verifikations- und Server-Bestätigungsstand der
Objekte: den Eintrag als gültig, nicht serverbestätigt.

Entschlüsselte Eintragsinhalte zeigt sie mit dieser Saat NICHT. Der Reader hat
keine Eingabe für einen Rohschlüssel; Schlüssel kommen ausschließlich über das
Enrollment, gebunden an einen WebAuthn-Authenticator mit PRF-Erweiterung. Das
Saat-Kommando gibt den privaten X25519-Readerschlüssel zwar roh als Hex aus,
aber er lässt sich dort nicht einbringen — das ist Absicht.

## Plattformbindung

Die Bedienerbindungen tragen einen Hash des Betriebssystemkontos. Die Demowelt
bindet dafür ein **festes Fixture-Konto**, kein echtes. Die Welt ist deshalb
zwischen Rechnern portabel — aber an die Plattformfamilie gebunden, denn die
Ableitung in `ea_operator::{macos,linux,windows}::account_inputs` unterscheidet
macOS, Linux und Windows. Eine auf macOS gesäte Welt passt nicht auf Linux oder
Windows; dort muss neu gesät werden.

Auf Windows steht ein festes SID-Tripel. Einen produktiven Ernter des echten
Windows-Kontos hat dieser Arbeitsbereich nicht:
`crates/ea-operator/src/windows.rs` trägt ausdrücklich nur die typisierte
Übergabe an Stufe 1 und hält fest, dass die Win32-Familie ADR-pflichtig ist.

## Warum eine eigene Crate

Die Bauwerkzeuge — `RegistryLineBuilder`, `ActionSpec`, `HeadOptions`,
`fixture_with_host_options`, `materialize` — lagen nur in
`tests/support/`-Modulen und waren damit ausschließlich aus einem Testziel
erreichbar. Ein `xtask`-Ziel ist kein Testziel.

`crates/ea-demo-world` bindet **genau dieselben Quelldateien** per `#[path]`
ein, die die Testziele einbinden. Es gibt damit weiterhin genau eine Quelle je
Bauwerkzeug: was ein Test baut und was die Demowelt baut, entsteht aus
demselben Text. Ein Verschieben der Dateien hätte über fünfzig
`#[path]`-Verweise angefasst, davon einige aus `src/`
(`crates/ea-trust/src/time.rs`, `crates/ea-admin/src/lib.rs`), ohne an der
Wahrheit etwas zu gewinnen.
