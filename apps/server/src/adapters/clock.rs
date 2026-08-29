//! Die UTC-Serverzeit.
//!
//! Ein eigener Adapter, weil `design.md` §13.3 Schritt 5 `acceptedAtServer`
//! aus ihr bildet und ein Test diese Zeit setzen koennen muss, ohne die Uhr
//! des Rechners zu stellen. Die echte Uhr steht deshalb hier und nicht in
//! einem `SystemTime::now()` mitten im Handler.

use std::time::{SystemTime, UNIX_EPOCH};

use ea_sync_server::ServerClock;
use ea_types::UnixMillis;

/// Die Uhr des Wirtsbetriebssystems.
pub struct SystemClock;

impl ServerClock for SystemClock {
    /// Millisekunden seit der Unix-Epoche.
    ///
    /// Eine Uhr VOR der Epoche ist ein Betriebsfehler und kein Zeitpunkt: sie
    /// antwortet mit `0` statt mit einem negativen Wert, den jede
    /// Ablauffrist danach als „laengst faellig“ lesen wuerde.
    fn now(&self) -> UnixMillis {
        UnixMillis::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
                .unwrap_or(0),
        )
    }
}

/// Eine feste Uhr.
///
/// Sie steht hier und nicht in einem Testmodul, weil ein Integrationstest
/// dieses Pakets sie braucht: eine Registry-Linie gilt nur innerhalb ihres
/// `notBefore`/`notAfter`-Fensters, und ein Test kann diese Fenster nicht auf
/// die Wanduhr des Rechners heben.
pub struct FixedClock(pub UnixMillis);

impl ServerClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}
