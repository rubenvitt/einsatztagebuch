//! Die verschluesselte Datenbank und die schmale Wertflaeche, ueber die sie
//! erreichbar ist.
//!
//! Die Flaeche nennt bewusst KEINEN `rusqlite`-Typ: `ea-draft` und `ea-audit`
//! tragen keine `rusqlite`-Kante, und ein durchgereichter `Connection` waere
//! genau diese Kante durch eine bequemere Tuer.

use core::fmt;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_crypto::SecretVec;
use ea_key_provider::{KeyError, KeyHandle, KeyProvider};
use rusqlite::{Connection, ErrorCode, Statement, TransactionBehavior, types::ValueRef};

use crate::migrations;

/// Ein Fehlschlag an der Speichergrenze.
///
/// Wie ueberall in diesem Bauwerk assertieren Tests gegen [`StoreError::code`]
/// und nie gegen eine Formatierung.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum StoreError {
    /// Ohne Schluessel wird nicht geoeffnet.
    ///
    /// Fail-closed und ohne Umweg: es gibt keinen Nur-Lese- und keinen
    /// Wiederherstellungspfad an dieser Bedingung vorbei.
    KeyRequired,
    /// Der wirksame Unterbau ist kein SQLCipher.
    ///
    /// `PRAGMA cipher_version` bleibt leer, wenn `LIBSQLITE3_SYS_USE_PKG_CONFIG`
    /// den Bau auf ein Klartext-SQLite umgelenkt hat (ADR 0002,
    /// *Consequences*). Eine so geoeffnete Datenbank naehme `PRAGMA key` als
    /// unbekanntes Pragma an und speicherte Klartext.
    CipherUnavailable,
    /// Der Schluesselport hat den Datenbankschluessel nicht herausgegeben.
    Key(KeyError),
    /// Die Datenbank kann den Vorgang nicht ausfuehren.
    Database,
    /// Eine Eindeutigkeits- oder Pruefbedingung des Schemas hat abgelehnt.
    Constraint,
    /// Die Migrationskette ist nicht anwendbar.
    Migration,
    /// Eine Zeile hat nicht die Gestalt, die der Leser erwartet.
    Shape,
}

impl StoreError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::KeyRequired => "EA-STORE-KEY-REQUIRED",
            Self::CipherUnavailable => "EA-STORE-CIPHER-UNAVAILABLE",
            Self::Key(error) => error.code(),
            Self::Database => "EA-STORE-DATABASE",
            Self::Constraint => "EA-STORE-CONSTRAINT",
            Self::Migration => "EA-STORE-MIGRATION",
            Self::Shape => "EA-STORE-SHAPE",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for StoreError {}

impl From<KeyError> for StoreError {
    /// `NotFound` wird zu [`StoreError::KeyRequired`] und nicht durchgereicht.
    ///
    /// Ein fehlender Eintrag ist an dieser Grenze die Aussage „ohne Schluessel
    /// wird nicht geoeffnet"; sie traegt den Code, gegen den der Test
    /// assertiert, und nicht den des Ports.
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::NotFound => Self::KeyRequired,
            other => Self::Key(other),
        }
    }
}

/// Ein Wert, wie ihn eine Spalte traegt.
///
/// Vier Gestalten, mehr kennt das Schema nicht. Der Typ existiert, damit
/// `ea-draft` und `ea-audit` Zeilen lesen und schreiben koennen, ohne
/// `rusqlite` zu sehen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreValue {
    Null,
    Integer(i64),
    Text(String),
    Blob(Vec<u8>),
}

/// Eine gelesene Zeile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreRow(Vec<StoreValue>);

impl StoreRow {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn at(&self, index: usize) -> Result<&StoreValue, StoreError> {
        self.0.get(index).ok_or(StoreError::Shape)
    }

    /// # Errors
    ///
    /// [`StoreError::Shape`], wenn die Spalte fehlt oder keine ganze Zahl ist.
    pub fn integer(&self, index: usize) -> Result<i64, StoreError> {
        match self.at(index)? {
            StoreValue::Integer(value) => Ok(*value),
            _ => Err(StoreError::Shape),
        }
    }

    /// # Errors
    ///
    /// [`StoreError::Shape`], wenn die Spalte fehlt oder kein Text ist.
    pub fn text(&self, index: usize) -> Result<&str, StoreError> {
        match self.at(index)? {
            StoreValue::Text(value) => Ok(value),
            _ => Err(StoreError::Shape),
        }
    }

    /// # Errors
    ///
    /// [`StoreError::Shape`], wenn die Spalte fehlt oder keine Bytefolge ist.
    pub fn blob(&self, index: usize) -> Result<&[u8], StoreError> {
        match self.at(index)? {
            StoreValue::Blob(value) => Ok(value),
            _ => Err(StoreError::Shape),
        }
    }

    /// Der Wert als Zeichenkette, wie ihn ein `PRAGMA` meldet.
    ///
    /// # Errors
    ///
    /// [`StoreError::Shape`], wenn die Spalte fehlt oder eine Bytefolge ist —
    /// ein Pragma meldet nie eine.
    pub fn pragma_string(&self, index: usize) -> Result<String, StoreError> {
        match self.at(index)? {
            StoreValue::Integer(value) => Ok(value.to_string()),
            StoreValue::Text(value) => Ok(value.clone()),
            StoreValue::Null => Ok(String::new()),
            StoreValue::Blob(_) => Err(StoreError::Shape),
        }
    }
}

/// Die aktuelle Systemzeit in Millisekunden seit der Unix-Epoche.
///
/// AUSSCHLIESSLICH fuer die technischen Zeitstempel dieses Speichers — wann
/// eine Zeile geschrieben und wann eine Migration angewandt wurde. Es ist
/// KEINE Vertrauenszeit: jede fachliche Zeitaussage laeuft ueber die
/// Zeitstatusbewertung des gewaehlten Registry-Head und nie ueber diese
/// Funktion.
#[must_use]
pub fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Die geoeffnete, vollstaendig verschluesselte Datenbank.
pub struct EncryptedDatabase {
    connection: Mutex<Connection>,
    path: PathBuf,
    cipher_version: String,
}

impl fmt::Debug for EncryptedDatabase {
    /// Undurchsichtig: der Pfad einer Einsatzdatenbank gehoert nicht in eine
    /// Protokollzeile. Der Rumpf existiert, damit `Result::unwrap_err` an
    /// diesem Typ ueberhaupt aufrufbar ist.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedDatabase(<open>)")
    }
}

impl EncryptedDatabase {
    /// Oeffnet die Datenbank — den Schluessel ZUERST.
    ///
    /// Der Schluessel wird ueber den nativen Port geholt, BEVOR SQLite
    /// geoeffnet wird. Es gibt keinen Konstruktor, der einen Pfad allein nimmt;
    /// genau das macht die Zusage strukturell statt prozedural. Fehlt der
    /// Eintrag im Schluesselspeicher, bricht das Oeffnen mit
    /// [`StoreError::KeyRequired`] ab — es gibt keinen Nur-Lese- und keinen
    /// Wiederherstellungspfad daran vorbei.
    ///
    /// Der Schluessel reist als [`SecretVec`] und erreicht das
    /// SQLCipher-Pragma ueber das bereits oeffentliche
    /// `SecretVec::with_exposed`; `ea-crypto` bekommt dafuer keinen neuen
    /// Leser.
    ///
    /// # Errors
    ///
    /// [`StoreError::KeyRequired`] ohne Schluesselmaterial,
    /// [`StoreError::CipherUnavailable`], wenn der wirksame Unterbau kein
    /// SQLCipher ist, [`StoreError::Database`] bei jedem Fehlschlag der
    /// Datenbank — darunter ein Schluessel, der die vorhandene Datei nicht
    /// aufschliesst — und [`StoreError::Migration`], wenn die Kette nicht
    /// anwendbar ist.
    pub fn open(
        path: &Path,
        provider: &dyn KeyProvider,
        database_key: &KeyHandle,
    ) -> Result<Self, StoreError> {
        let key: SecretVec = provider.unwrap_database_key(database_key)?;
        if key.is_empty() {
            return Err(StoreError::KeyRequired);
        }

        let mut connection = Connection::open(path).map_err(|_| StoreError::Database)?;

        // `PRAGMA key` ist die ERSTE Anweisung auf der Verbindung. Danach ist
        // die Verbindung entschluesselt oder gar nicht brauchbar.
        key.with_exposed(|bytes| set_cipher_key(&connection, bytes))?;

        let cipher_version = scalar_pragma(&connection, "PRAGMA cipher_version")?;
        if cipher_version.trim().is_empty() {
            return Err(StoreError::CipherUnavailable);
        }

        // Vollverschluesselung heisst jede Datei, nicht nur die Hauptdatei:
        // WAL-Seiten und Indizes liegen unter SQLCipher, und die temporaere
        // Ablage bleibt im Speicher, damit kein Spill je im Klartext auf die
        // Platte gelangt (`design.md`:1961, :1965). `temp_store` wird
        // AUSDRUECKLICH gesetzt und nicht vom Compile-Default `2` geerbt: der
        // Default ist ueberschreibbar, die Setzung ist es nicht.
        let journal_mode = scalar_pragma(&connection, "PRAGMA journal_mode = WAL")?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Database);
        }
        run_ignoring_rows(&connection, "PRAGMA temp_store = MEMORY")?;
        run_ignoring_rows(&connection, "PRAGMA foreign_keys = ON")?;

        // Der erste echte Lesevorgang. Ein falscher Schluessel scheitert HIER
        // und nicht irgendwann spaeter mitten in einem Schreibvorgang.
        run_ignoring_rows(&connection, "SELECT count(*) FROM sqlite_schema")?;

        migrations::apply(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            path: path.to_path_buf(),
            cipher_version,
        })
    }

    /// Der Pfad der Hauptdatei.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Die Fassung des wirksamen SQLCipher.
    ///
    /// Nie leer: [`Self::open`] bricht sonst ab. Der Leser existiert, damit der
    /// wirksame Unterbau messbar ist und nicht nur behauptet — die Auflage, die
    /// ADR 0002 unter *Consequences* an diesen Task stellt.
    #[must_use]
    pub fn cipher_version(&self) -> &str {
        &self.cipher_version
    }

    /// Meldet, ob die Migration `version` bereits angewandt ist.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] bei jedem Fehlschlag der Datenbank.
    pub fn has_migration(&self, version: u32) -> Result<bool, StoreError> {
        let row = self.query_row(
            "SELECT count(*) FROM schema_migration WHERE version = ?1",
            &[StoreValue::Integer(i64::from(version))],
        )?;
        Ok(row.is_some_and(|row| row.integer(0).is_ok_and(|count| count > 0)))
    }

    /// Fuehrt eine Anweisung ausserhalb einer eigenen Transaktion aus.
    ///
    /// # Errors
    ///
    /// [`StoreError::Constraint`] bei einer Schemaverletzung, sonst
    /// [`StoreError::Database`].
    pub fn execute(&self, sql: &str, params: &[StoreValue]) -> Result<usize, StoreError> {
        let connection = self.lock();
        execute_on(&connection, sql, params)
    }

    /// Liest hoechstens eine Zeile.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] bei jedem Fehlschlag der Datenbank.
    pub fn query_row(
        &self,
        sql: &str,
        params: &[StoreValue],
    ) -> Result<Option<StoreRow>, StoreError> {
        let connection = self.lock();
        query_row_on(&connection, sql, params)
    }

    /// Fuehrt `work` in EINER unmittelbar exklusiven Transaktion aus.
    ///
    /// `Immediate` und nicht `Deferred`: der Vergleich-und-Setze-Schritt des
    /// Autosave liest und schreibt, und eine aufgeschobene Transaktion holte
    /// ihre Schreibsperre erst beim Schreiben — zwischen Lesen und Schreiben
    /// laege dann ein Fenster, in dem eine zweite Sitzung dieselbe Fassung
    /// liest.
    ///
    /// Ein `Err` aus `work` rollt zurueck, weil die Transaktion ungebucht
    /// fallen gelassen wird.
    ///
    /// Der Fehlertyp gehoert dem AUFRUFER: `ea-draft` meldet `DraftError`,
    /// `ea-audit` meldet `AuditError`, und keiner der beiden muss den
    /// Speicherfehler auf dem Rueckweg wieder auspacken.
    ///
    /// # Errors
    ///
    /// Was `work` meldet, sonst [`StoreError::Database`], in `E` uebersetzt.
    pub fn transaction<R, E>(
        &self,
        work: impl FnOnce(&StoreTransaction<'_>) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let mut connection = self.lock();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| E::from(map_error(error)))?;
        let value = {
            let handle = StoreTransaction {
                connection: &transaction,
            };
            work(&handle)?
        };
        transaction
            .commit()
            .map_err(|error| E::from(map_error(error)))?;
        Ok(value)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Eine laufende Transaktion.
pub struct StoreTransaction<'a> {
    connection: &'a Connection,
}

impl StoreTransaction<'_> {
    /// # Errors
    ///
    /// [`StoreError::Constraint`] bei einer Schemaverletzung, sonst
    /// [`StoreError::Database`].
    pub fn execute(&self, sql: &str, params: &[StoreValue]) -> Result<usize, StoreError> {
        execute_on(self.connection, sql, params)
    }

    /// # Errors
    ///
    /// [`StoreError::Database`] bei jedem Fehlschlag der Datenbank.
    pub fn query_row(
        &self,
        sql: &str,
        params: &[StoreValue],
    ) -> Result<Option<StoreRow>, StoreError> {
        query_row_on(self.connection, sql, params)
    }
}

/// Setzt den SQLCipher-Rohschluessel.
///
/// Die Hexform `x'…'` ist die dokumentierte Rohschluesselform: sie umgeht die
/// Passphrasenableitung und uebergibt genau die Bytes, die der Schluesselport
/// herausgegeben hat. Die aufgebaute Anweisung wird unmittelbar nach dem
/// Ausfuehren ueberschrieben; ohne das bliebe der Schluessel als gewoehnliche
/// Zeichenkette im Prozessspeicher liegen, waehrend [`SecretVec`] genau das
/// verhindern soll.
fn set_cipher_key(connection: &Connection, key: &[u8]) -> Result<(), StoreError> {
    // Die Kapazitaet muss die GANZE Anweisung tragen: Praefix `PRAGMA key = "x'`
    // sind 16 Zeichen, die Hexform 2n, der Abschluss `'"` zwei — zusammen
    // 2n + 18. Waere sie kleiner, wuechse der Puffer beim letzten `push_str`
    // und wuerde umgelagert; der freigegebene alte Block traege dann den
    // vollstaendigen Schluessel in Hex, ungenullt, waehrend das Ueberschreiben
    // unten nur den NEUEN Puffer erreicht.
    let mut statement = String::with_capacity(key.len() * 2 + 18);
    let reserved = statement.capacity();
    statement.push_str("PRAGMA key = \"x'");
    for byte in key {
        statement.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        statement.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    statement.push_str("'\"");
    // Ein `String` lagert ausschliesslich beim WACHSEN um. Unveraenderte
    // Kapazitaet heisst deshalb: derselbe Block, in dem der Schluessel je
    // stand, ist derjenige, den `overwrite_in_place` schrubbt. Die Zusicherung
    // laeuft unter `cargo test` mit und ist kein Kommentar.
    debug_assert_eq!(reserved, statement.capacity());
    let outcome = run_ignoring_rows(connection, &statement);
    // Ueberschreiben statt bloss fallen lassen: `String::clear` gibt den Puffer
    // nicht frei und `drop` nullt ihn nicht.
    overwrite_in_place(&mut statement);
    outcome
}

/// Ueberschreibt die Zeichen einer Zeichenkette an Ort und Stelle.
///
/// Ohne `unsafe`: die Kette besteht ausschliesslich aus ASCII, also hat jedes
/// Zeichen dieselbe Bytelaenge wie `0`, und `replace_range` schreibt ohne
/// Umschichtung in denselben Puffer.
fn overwrite_in_place(statement: &mut String) {
    let filler = "0".repeat(statement.len());
    statement.replace_range(.., &filler);
}

/// Fuehrt eine Anweisung aus und verwirft jede Zeile, die sie meldet.
///
/// `Statement::execute` lehnt eine zeilenliefernde Anweisung ab; ein `PRAGMA`
/// liefert je nach Pragma Zeilen oder keine. Der rohe Weg behandelt beide
/// gleich.
fn run_ignoring_rows(connection: &Connection, sql: &str) -> Result<(), StoreError> {
    let mut statement = connection.prepare(sql).map_err(map_error)?;
    let mut rows = statement.raw_query();
    while rows.next().map_err(map_error)?.is_some() {}
    Ok(())
}

/// Fuehrt ein `PRAGMA` aus und gibt seinen ersten Wert als Zeichenkette zurueck.
fn scalar_pragma(connection: &Connection, sql: &str) -> Result<String, StoreError> {
    let mut statement = connection.prepare(sql).map_err(map_error)?;
    let mut rows = statement.raw_query();
    let value = match rows.next().map_err(map_error)? {
        Some(row) => read_row(row)?.pragma_string(0)?,
        None => String::new(),
    };
    while rows.next().map_err(map_error)?.is_some() {}
    Ok(value)
}

fn bind(statement: &mut Statement<'_>, params: &[StoreValue]) -> Result<(), StoreError> {
    for (position, value) in params.iter().enumerate() {
        let index = position + 1;
        let bound = match value {
            StoreValue::Null => statement.raw_bind_parameter(index, rusqlite::types::Null),
            StoreValue::Integer(value) => statement.raw_bind_parameter(index, *value),
            StoreValue::Text(value) => statement.raw_bind_parameter(index, value.as_str()),
            StoreValue::Blob(value) => statement.raw_bind_parameter(index, value.as_slice()),
        };
        bound.map_err(map_error)?;
    }
    Ok(())
}

fn execute_on(
    connection: &Connection,
    sql: &str,
    params: &[StoreValue],
) -> Result<usize, StoreError> {
    let mut statement = connection.prepare(sql).map_err(map_error)?;
    bind(&mut statement, params)?;
    statement.raw_execute().map_err(map_error)
}

fn query_row_on(
    connection: &Connection,
    sql: &str,
    params: &[StoreValue],
) -> Result<Option<StoreRow>, StoreError> {
    let mut statement = connection.prepare(sql).map_err(map_error)?;
    bind(&mut statement, params)?;
    let mut rows = statement.raw_query();
    let row = match rows.next().map_err(map_error)? {
        Some(row) => Some(read_row(row)?),
        None => None,
    };
    Ok(row)
}

fn read_row(row: &rusqlite::Row<'_>) -> Result<StoreRow, StoreError> {
    let columns = row.as_ref().column_count();
    let mut values = Vec::with_capacity(columns);
    for index in 0..columns {
        let value = match row.get_ref(index).map_err(map_error)? {
            ValueRef::Null => StoreValue::Null,
            ValueRef::Integer(value) => StoreValue::Integer(value),
            ValueRef::Real(_) => return Err(StoreError::Shape),
            ValueRef::Text(bytes) => StoreValue::Text(
                core::str::from_utf8(bytes)
                    .map_err(|_| StoreError::Shape)?
                    .to_owned(),
            ),
            ValueRef::Blob(bytes) => StoreValue::Blob(bytes.to_vec()),
        };
        values.push(value);
    }
    Ok(StoreRow(values))
}

/// Uebersetzt einen Datenbankfehler.
///
/// Eine Verletzung der Eindeutigkeit oder einer `CHECK`-Bedingung wird
/// UNTERSCHIEDEN, weil das Einsatznummernregister genau daran seinen fachlichen
/// Fehlercode bildet — ohne die Trennung waere ein zweiter Anspruch auf
/// dieselbe Nummer von einer defekten Datenbank nicht zu unterscheiden.
fn map_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            StoreError::Constraint
        }
        _ => StoreError::Database,
    }
}
