-- 0003_master_data.sql — die Stammdatentabellen und die Aufbewahrung des
-- Protokollurbilds.
--
-- Eine registrierte Migration wird nie mehr geaendert. `0001_writer.sql` und
-- `0002_discard.sql` bleiben deshalb unberuehrt; insbesondere lebt das
-- Einsatznummernregister mit seiner `UNIQUE`-Bedingung weiter dort und wird
-- hier NICHT nachgebaut. Die Eindeutigkeit der Einsatznummer sitzt auf drei
-- getrennten Ebenen, und keine davon ist der Import: das Register gehoert
-- `0001_writer.sql`, die Momentaufnahme traegt ueberhaupt keine Einsatznummer
-- (`schemas/payload/v1/payload.cddl`:131-142), und der Anspruch wird beim
-- Abschluss unter der ausschliesslichen Writer-Sperre erhoben.
--
-- Alle Tabellen sind `STRICT`.

-- 1. Die Aufbewahrung des EXAKTEN `import-report-v1`-Urbilds.
--
--    Sie steht ZUERST, weil die Stammdatentabellen einen Fremdschluessel auf
--    sie tragen. Ohne diese Aufbewahrung haette der in einer Momentaufnahme
--    versiegelte `importProtocolHash` kein nachpruefbares Urbild, und die
--    Provenienzzusage AK 28 (`design.md`:404) waere nicht einloesbar — auch
--    mit definierter Rechenregel.
--
--    Die Bytes liegen INNERHALB der verschluesselten Datenbank und nie als
--    Datei daneben: eine Klartext-Temporaerdatei entsteht dabei nicht
--    (`design.md`:1961, :1967).
CREATE TABLE import_report (
  import_protocol_hash BLOB PRIMARY KEY NOT NULL
                            CHECK (length(import_protocol_hash) = 32),
  exact_bytes          BLOB NOT NULL,
  source_kind          INTEGER NOT NULL CHECK (source_kind IN (0, 1)),
  imported_at          INTEGER NOT NULL
) STRICT;

-- 2. Die Personenstammdaten.
--
--    `revision` ist die EINZIGE Quelle der Pflichtposition `revision` einer
--    Momentaufnahme (`crates/ea-schema/src/model.rs`:852): die beiden
--    eingefrorenen Kopfzeilen tragen keine Revisionsspalte, also kann der Wert
--    nicht aus der Datei kommen. Ein gebuchter Import setzt `1`, und jede
--    Aenderung erhoeht um genau eins.
--
--    Die drei Provenienzspalten sind NOT NULL: in Stufe 2 entsteht eine
--    Stammdatenzeile AUSSCHLIESSLICH aus einem gebuchten CSV-Import. Ein
--    Ad-hoc-Eintrag legt gar keine Zeile an — er ist
--    `PersonnelSnapshotV1::AdHoc` und damit strukturell erkennbar, nicht durch
--    ein Kennzeichen in dieser Tabelle.
--
--    Der Fremdschluessel ist die STRUKTURELLE Fassung der Provenienzzusage:
--    eine Stammdatenzeile kann keinen Protokollhash nennen, dessen Urbild
--    nicht aufbewahrt ist. `PRAGMA foreign_keys = ON` steht beim Oeffnen.
CREATE TABLE master_person (
  master_personnel_id   TEXT    PRIMARY KEY NOT NULL CHECK (length(master_personnel_id) > 0),
  display_name          TEXT    NOT NULL CHECK (length(display_name) > 0),
  role_or_function      TEXT,
  revision              INTEGER NOT NULL CHECK (revision >= 1),
  active                INTEGER NOT NULL CHECK (active IN (0, 1)),
  source_id             TEXT    NOT NULL,
  source_format_version INTEGER NOT NULL,
  import_protocol_hash  BLOB    NOT NULL CHECK (length(import_protocol_hash) = 32),
  updated_at_ms         INTEGER NOT NULL,
  FOREIGN KEY (import_protocol_hash) REFERENCES import_report (import_protocol_hash)
) STRICT;

-- 3. Die Fahrzeugstammdaten, nach demselben Muster.
CREATE TABLE master_vehicle (
  master_vehicle_id     TEXT    PRIMARY KEY NOT NULL CHECK (length(master_vehicle_id) > 0),
  display_name          TEXT    NOT NULL CHECK (length(display_name) > 0),
  radio_call_sign       TEXT,
  license_plate         TEXT,
  revision              INTEGER NOT NULL CHECK (revision >= 1),
  active                INTEGER NOT NULL CHECK (active IN (0, 1)),
  source_id             TEXT    NOT NULL,
  source_format_version INTEGER NOT NULL,
  import_protocol_hash  BLOB    NOT NULL CHECK (length(import_protocol_hash) = 32),
  updated_at_ms         INTEGER NOT NULL,
  FOREIGN KEY (import_protocol_hash) REFERENCES import_report (import_protocol_hash)
) STRICT;
