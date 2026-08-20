use core::fmt;
use std::sync::Arc;

/// Wie eine exklusive Schreibersperre wieder freigegeben wird.
///
/// Der Wirt liefert die Implementierung; diese Crate kennt sie nicht. Genau
/// deshalb kann [`WriterLock`] hier leben, obwohl das Freigeben eine
/// Dateisystemoperation ist: `ea-archive` traegt nur Ports und kein `std::fs`
/// (`crates/ea-archive/src/source.rs`) und bleibt damit auf der
/// wasm32-Positivliste.
pub trait WriterLockRelease: Send + Sync {
    /// Gibt die Sperre frei. Wird GENAU EINMAL gerufen, aus [`WriterLock::drop`].
    fn release(&self);
}

/// Der RAII-Waechter der exklusiven Schreibersperre.
///
/// Es gibt keine `unlock`-Methode: eine Sperre, die man vergessen kann
/// freizugeben, ist genau die Sperre, die nach einem Abbruch haengt. `Drop`
/// gibt sie frei — auch beim Abwickeln eines Panics.
pub struct WriterLock {
    release: Arc<dyn WriterLockRelease>,
}

impl WriterLock {
    /// Uebernimmt die Freigabe.
    #[must_use]
    pub fn new(release: Arc<dyn WriterLockRelease>) -> Self {
        Self { release }
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        self.release.release();
    }
}

impl fmt::Debug for WriterLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriterLock(<held>)")
    }
}
