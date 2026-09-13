//! Storage maintenance only; authorization belongs to the destruction service.
use super::{EncryptedDatabase, StoreError};
impl EncryptedDatabase {
    /// Require secure deletion, then checkpoint/vacuum/checkpoint under the
    /// single connection lock. Success is a storage observation, not consent.
    pub fn compact_after_authorized_destruction(&self) -> Result<(), StoreError> {
        let connection = self.lock();
        let secure: i64 = connection
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if secure != 1 || !matches!(synchronous, 2 | 3) {
            return Err(StoreError::Database);
        }
        checkpoint(&connection)?;
        connection
            .execute_batch("VACUUM")
            .map_err(|_| StoreError::Database)?;
        checkpoint(&connection)?;
        let free: i64 = connection
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if free != 0 {
            return Err(StoreError::Database);
        }
        Ok(())
    }
}

fn checkpoint(connection: &rusqlite::Connection) -> Result<(), StoreError> {
    let (busy, log, done): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|_| StoreError::Database)?;
    if busy != 0 || log != 0 || done != 0 {
        return Err(StoreError::Database);
    }
    Ok(())
}
