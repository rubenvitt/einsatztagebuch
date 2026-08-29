-- 0004_sync_retry.sql — der BEGRENZTE Wiederaufnahmezustand des Writer-Sync.
--
-- Eine registrierte Migration wird nie mehr geaendert. `0001_writer.sql` legt
-- diese Tabelle deshalb NICHT nachtraeglich an; sie entsteht hier, und
-- `crates/ea-local-store/src/migrations.rs` nennt die Fassung als
-- `SYNC_RETRY_MIGRATION_VERSION`.
--
-- Warum ueberhaupt eine Tabelle, und warum GENAU diese Spalten:
--
-- `design.md`:1584 verlangt fuer Netzwerk- und 5xx-Fehler „begrenzten
-- exponentiellen Backoff und Jitter". Begrenzt heisst ABZAEHLBAR, und
-- abzaehlbar ueber einen Neustart hinweg heisst dauerhaft: ein Zaehler im
-- Prozess faenge nach jedem Absturz wieder bei null an, und die Schranke des
-- Profils waere unerreichbar. `PublicationQueue::pending` bleibt ausdruecklich
-- ein PROZESSFELD und traegt keinen persistenten Zustand — die Warteschlange
-- selbst wird aus committeten Archivbytes abgeleitet und nie gespeichert.
-- Dauerhaft ist allein, was sich NICHT ableiten laesst: wie oft schon
-- vergeblich versucht wurde und wann der naechste Versuch fruehestens laufen
-- darf.
--
-- Die Spalten:
--   * `entry_object_hash` — der Eintrag, um den es geht. Der Objekthash und
--                    nicht die Sequenz: er ist die Adresse, unter der der
--                    Eintrag committet liegt, und er ist ueber eine
--                    Kettenreorganisation hinweg stabil. Er ist ein HASH und
--                    traegt damit keinen fachlichen Klartext.
--   * `failed_attempts` — die Zahl der vergeblichen Versuche. `CHECK >= 0`
--                    und aufsteigend; erreicht sie die Schranke des Profils,
--                    entsteht `DetailCause::ResumeAttemptsExhausted`.
--   * `next_attempt_at_ms` — der fruehestens zulaessige naechste Versuch. Der
--                    ERRECHNETE Wert mit Jitter wird hier abgelegt und nicht
--                    bei jedem Start neu gezogen: zwei verschiedene Zahlen
--                    fuer denselben Wartepunkt waeren zwei Wahrheiten, und die
--                    zweite fiele zufaellig frueher aus.
--   * `cursor`     — der zuletzt BESTAETIGTE technische Cursor, undurchsichtig
--                    und signiert (`TechnicalCursorV1`). `NULL`, solange der
--                    Dienst noch keinen ausgestellt hat. Er ist der Punkt, an
--                    dem eine unterbrochene Uebertragung wieder aufsetzt.
--   * `recorded_at_ms` — wann die Zeile zuletzt geschrieben wurde. Sie macht
--                    einen liegengebliebenen Zustand erkennbar, ohne dass
--                    jemand ihn aus `next_attempt_at_ms` erraten muss.
CREATE TABLE sync_retry (
    entry_object_hash  BLOB    PRIMARY KEY CHECK (length(entry_object_hash) = 32),
    failed_attempts    INTEGER NOT NULL CHECK (failed_attempts >= 0),
    next_attempt_at_ms INTEGER NOT NULL,
    cursor             BLOB,
    recorded_at_ms     INTEGER NOT NULL
) STRICT;
