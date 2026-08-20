//! Die EINE Registratur der Migrationsdateien.
//!
//! Eine registrierte Migration wird nie mehr geaendert. Jede weitere
//! Schemaaenderung ist eine neue, aufsteigende Datei; das ist der Grund, warum
//! `0001_writer.sql` die Uebergangstabelle des Verwerfens NICHT anlegt und die
//! Aufbewahrungstabelle der `import-report-v1`-Bytes ebenso wenig.
//!
//! Die Kette laeuft in EINER Transaktion: entweder das Schema steht danach
//! vollstaendig, oder es steht unveraendert.

use rusqlite::Connection;

use crate::database::{StoreError, unix_millis_now};

/// Eine registrierte Migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Migration {
    /// Die aufsteigende Fassung. Sie wird nie wiederverwendet.
    pub version: u32,
    /// Der Dateiname, so wie er unter `migrations/` liegt.
    pub name: &'static str,
    /// Der eingebettete Inhalt der Datei.
    pub sql: &'static str,
}

/// Die Kette, aufsteigend. Ein spaeterer Task HAENGT AN und schreibt nicht um.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_writer.sql",
        sql: include_str!("../migrations/0001_writer.sql"),
    },
    Migration {
        version: DISCARD_MIGRATION_VERSION,
        name: "0002_discard.sql",
        sql: include_str!("../migrations/0002_discard.sql"),
    },
];

/// Die Fassung, in der die Uebergangstabelle des Verwerfens entsteht.
///
/// Sie wird HIER benannt und nicht in `ea-draft`, weil dieses Modul die
/// Registratur besitzt. Die Uebergangsarme der Entwurfsablage fragen sie
/// POSITIV ab, statt an einem rohen SQL-Fehler zu scheitern — „die Tabelle gibt
/// es noch nicht" ist eine andere Aussage als „die Datenbank ist beschaedigt".
/// Seit Task 7 ist `0002_discard.sql` registriert, und die Abfrage ist auf einer
/// migrierten Datenbank wahr; sie bleibt stehen, weil eine Datenbank, die vor
/// dieser Migration entstand, sie beim Oeffnen noch durchlaeuft.
pub const DISCARD_MIGRATION_VERSION: u32 = 2;

const CREATE_REGISTRY: &str = "CREATE TABLE IF NOT EXISTS schema_migration (\
     version INTEGER PRIMARY KEY, \
     name TEXT NOT NULL, \
     applied_at_ms INTEGER NOT NULL) STRICT";

/// Wendet jede noch nicht angewandte Migration in aufsteigender Ordnung an.
///
/// # Errors
///
/// [`StoreError::Migration`], wenn die Registratur nicht streng aufsteigend ist
/// — das ist ein Programmierfehler und kein Zustand der Datenbank —, sonst
/// [`StoreError::Database`].
pub(crate) fn apply(connection: &mut Connection) -> Result<(), StoreError> {
    let mut previous = 0_u32;
    for migration in MIGRATIONS {
        if migration.version <= previous {
            return Err(StoreError::Migration);
        }
        previous = migration.version;
    }

    connection
        .execute_batch(CREATE_REGISTRY)
        .map_err(|_| StoreError::Database)?;

    let transaction = connection.transaction().map_err(|_| StoreError::Database)?;
    for migration in MIGRATIONS {
        let applied: i64 = transaction
            .query_row(
                "SELECT count(*) FROM schema_migration WHERE version = ?1",
                [i64::from(migration.version)],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Database)?;
        if applied > 0 {
            continue;
        }
        transaction
            .execute_batch(migration.sql)
            .map_err(|_| StoreError::Migration)?;
        transaction
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    i64::from(migration.version),
                    migration.name,
                    unix_millis_now()
                ],
            )
            .map_err(|_| StoreError::Migration)?;
    }
    transaction.commit().map_err(|_| StoreError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    /// Die Registratur ist streng aufsteigend und nennt jede Datei genau
    /// einmal.
    ///
    /// Ohne diese Zusicherung koennte ein spaeterer Task eine Fassung
    /// wiederverwenden; `apply` bricht dann zwar ab, aber erst zur Laufzeit
    /// einer geoeffneten Datenbank.
    #[test]
    fn the_registry_is_strictly_ascending_and_names_every_file_once() {
        assert!(!MIGRATIONS.is_empty());
        for pair in MIGRATIONS.windows(2) {
            assert!(
                pair[0].version < pair[1].version,
                "die Migrationskette muss streng aufsteigen"
            );
            assert_ne!(pair[0].name, pair[1].name);
        }
        for migration in MIGRATIONS {
            assert!(!migration.sql.trim().is_empty());
            assert!(migration.name.ends_with(".sql"));
        }
    }
}
