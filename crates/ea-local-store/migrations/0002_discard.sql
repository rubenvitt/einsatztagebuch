-- 0002_discard.sql — der EINE Uebergangsplatz des Entwurfs.
--
-- Eine registrierte Migration wird nie mehr geaendert. `0001_writer.sql` legt
-- diese Tabelle deshalb NICHT nachtraeglich an; sie entsteht hier, und
-- `crates/ea-local-store/src/migrations.rs` nennt die Fassung als
-- `DISCARD_MIGRATION_VERSION`.
--
-- EINE Tabelle mit EINER Zeile, und ihre `kind`-Spalte traegt entweder die
-- dauerhaft gebuchte Verwerfensabsicht oder die vorbereitete Abschlussmarke.
-- Weil beide Zustaende Zeilen DESSELBEN Einzelplatzes sind, existiert zu jedem
-- Zeitpunkt hoechstens einer von ihnen: die gegenseitige Ausschliessung von
-- `discardIntent` und `PreparedFinalization` ist DEKLARATIV und ueberlebt einen
-- Implementierer, der die Sperre vergisst, statt allein auf der Transaktion zu
-- ruhen (`design.md`:456, :467).
--
-- `DraftRepository::commit_discard_intent` schreibt die erste Art,
-- `replace_prepared_finalization_marker` die zweite. Genau deshalb braucht
-- Task 11 hierfuer keine eigene Migration.
--
-- Die Spalten:
--   * `singleton`  — der Einzelplatz. `PRIMARY KEY CHECK (singleton = 0)` ist
--                    die Zusage „hoechstens ein Uebergang", und sie ist die
--                    Konfliktzielspalte des `ON CONFLICT(singleton)`-Upserts,
--                    mit dem eine Abschlussmarke eine Verwerfensabsicht
--                    verdraengt und umgekehrt.
--   * `kind`       — 0 = `discardIntent`, 1 = `PreparedFinalization`. Der
--                    `CHECK` laesst GENAU diese zwei zu; eine dritte Art ist
--                    kein neuer Zustand, sondern ein Abbruch.
--   * `draft_id`   — der Entwurf, auf den sich der Uebergang bezieht. Bei der
--                    Verwerfensabsicht ist es der zu verwerfende Entwurf.
--   * `save_revision` — die Fassung, gegen die die Absicht gebucht wurde. Sie
--                    macht `remove_ciphertext_and_intent_create_blank` gegen
--                    eine zwischenzeitliche Speicherung pruefbar.
--   * `marker`     — der UNDURCHSICHTIGE Verweis auf den vorbereiteten
--                    Abschluss. `NULL` bei der Verwerfensabsicht; der `CHECK`
--                    unten bindet die Belegung an `kind`, damit keine der zwei
--                    Arten mit den Feldern der anderen dasteht.
CREATE TABLE draft_transition (
    singleton      INTEGER PRIMARY KEY CHECK (singleton = 0),
    kind           INTEGER NOT NULL CHECK (kind IN (0, 1)),
    draft_id       BLOB    NOT NULL CHECK (length(draft_id) = 16),
    save_revision  INTEGER NOT NULL CHECK (save_revision >= 0),
    marker         BLOB,
    recorded_at_ms INTEGER NOT NULL,
    -- Die Verwerfensabsicht traegt keine Abschlussmarke, und der vorbereitete
    -- Abschluss traegt eine. Ohne diese Bedingung koennte eine Absicht mit
    -- einer Marke danebenliegen, und „hoechstens einer der zwei Zustaende"
    -- waere wieder eine Frage der Programmdisziplin.
    CHECK ((kind = 0 AND marker IS NULL) OR (kind = 1 AND marker IS NOT NULL))
) STRICT;
