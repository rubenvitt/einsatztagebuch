//! Die EINE Entropiequelle dieser Crate, und ihre Zaehlnaht.
//!
//! `getrandom::fill` ist dasselbe Betriebssystemmaterial, das `ea-crypto`
//! intern benutzt (`crates/ea-crypto/src/hpke.rs`). Der Aufruf laeuft hier
//! durch [`draw`] und nirgends sonst, weil die Zusage „Sequenz, UUIDv7, CEK und
//! AEAD-Nonce werden GENAU EINMAL gezogen" sonst unmessbar waere: eine freie
//! Funktion laesst sich von einem Test nicht abfangen.
//!
//! Der Zaehler ist ein `thread_local` und existiert AUSSCHLIESSLICH unter
//! `test-support`. Im Produktionsbau bleibt von diesem Modul ein
//! `getrandom::fill` mit einer Typmarke daneben.

use crate::WriterError;

/// Wofuer Entropie gezogen wird.
///
/// Die SEQUENZ steht ausdruecklich NICHT darin. Sie wird ABGELEITET — der
/// direkte Vorgaenger plus eins —, denn eine gezogene Sequenz koennte den
/// Vorgaenger nicht binden. `design.md` §9.3 Schritt 6 nennt sie in einem Atem
/// mit den drei gezogenen Werten; das ist an dieser Stelle irrefuehrend
/// formuliert, und die Kettenzusage entscheidet.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EntropyKind {
    /// Der `recordId` des Nutzlastkopfes, ein UUIDv7.
    Uuid,
    /// Der frische Content Encryption Key dieses Eintrags.
    Cek,
    /// Die frische AEAD-Nonce dieses Eintrags.
    Nonce,
}

/// Wie oft je Art gezogen wurde.
///
/// Drei Felder, keines fuer die Sequenz. `Eq` ist da, damit die Zusage
/// „genau einmal" eine GLEICHHEIT ist und keine Beschreibung.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntropyDraws {
    pub uuid: usize,
    pub cek: usize,
    pub nonce: usize,
}

#[cfg(any(test, feature = "test-support"))]
mod counter {
    use core::cell::Cell;

    use super::{EntropyDraws, EntropyKind};

    thread_local! {
        static UUID: Cell<usize> = const { Cell::new(0) };
        static CEK: Cell<usize> = const { Cell::new(0) };
        static NONCE: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record(kind: EntropyKind) {
        match kind {
            EntropyKind::Uuid => UUID.with(|cell| cell.set(cell.get() + 1)),
            EntropyKind::Cek => CEK.with(|cell| cell.set(cell.get() + 1)),
            EntropyKind::Nonce => NONCE.with(|cell| cell.set(cell.get() + 1)),
        }
    }

    /// Der Zaehlerstand dieses Threads.
    ///
    /// Ein `thread_local` und kein globaler Zaehler: die Tests dieses Ziels
    /// serialisieren sich zwar ueber eine prozessweite Sperre, aber ein Zaehler,
    /// der ueber Threadgrenzen laeuft, waere von einem fremden Test
    /// verschmutzbar, und dann bezeugte er nichts.
    #[must_use]
    pub fn entropy_draws() -> EntropyDraws {
        EntropyDraws {
            uuid: UUID.with(Cell::get),
            cek: CEK.with(Cell::get),
            nonce: NONCE.with(Cell::get),
        }
    }

    /// Setzt den Zaehlerstand dieses Threads auf null.
    pub fn reset_entropy_draws() {
        UUID.with(|cell| cell.set(0));
        CEK.with(|cell| cell.set(0));
        NONCE.with(|cell| cell.set(0));
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use counter::{entropy_draws, reset_entropy_draws};

/// Fuellt `buffer` aus dem CSPRNG des Betriebssystems.
///
/// # Errors
///
/// [`WriterError::LocalRng`], wenn das Betriebssystem keine Entropie liefert.
/// Fail-closed: ohne frisches Material entsteht kein Eintrag.
pub(crate) fn draw(kind: EntropyKind, buffer: &mut [u8]) -> Result<(), WriterError> {
    #[cfg(any(test, feature = "test-support"))]
    counter::record(kind);
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = kind;
    getrandom::fill(buffer).map_err(|_| WriterError::LocalRng)
}

/// Bildet einen UUIDv7 aus der Millisekundenzeit und frischen Zufallsbits.
///
/// RFC 9562 §5.7: 48 Bit Unix-Millisekunden, dann Version 7 in den oberen vier
/// Bit von Oktett 6, dann die Variante `0b10` in den oberen zwei Bit von
/// Oktett 8; die uebrigen 74 Bit sind Zufall. KEINE neue Abhaengigkeit — der
/// ADR-Katalog wird davon nicht beruehrt.
///
/// # Errors
///
/// [`WriterError::LocalRng`], wenn das Betriebssystem keine Entropie liefert.
pub(crate) fn uuid_v7(unix_millis: i64) -> Result<[u8; 16], WriterError> {
    let mut bytes = [0_u8; 16];
    draw(EntropyKind::Uuid, &mut bytes)?;
    // Die 48 Bit Zeit stehen in Netzwerkbyteordnung ganz vorn. Eine negative
    // Zeit gibt es hier nicht: sie kaeme aus einem Head, dessen Zeitpruefung
    // schon gefallen waere.
    let millis = u64::try_from(unix_millis.max(0)).unwrap_or(0);
    bytes[0] = ((millis >> 40) & 0xff) as u8;
    bytes[1] = ((millis >> 32) & 0xff) as u8;
    bytes[2] = ((millis >> 24) & 0xff) as u8;
    bytes[3] = ((millis >> 16) & 0xff) as u8;
    bytes[4] = ((millis >> 8) & 0xff) as u8;
    bytes[5] = (millis & 0xff) as u8;
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}
