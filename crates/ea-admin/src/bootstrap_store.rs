//! Die dateigestuetzte Ablage des Zeremoniezustands.
//!
//! [`BootstrapStore`] ist der Port; eine Zeremonie ueberlebt Neustarts nur,
//! wenn ihn jemand umsetzt. Die Zeugen in `crates/ea-admin/tests` benutzen
//! dafuer eine Ablage im Speicher — die ueberlebt den Prozess nicht, und genau
//! das soll sie auch nicht. Diese hier ist die produktive Umsetzung fuer einen
//! Wirt mit einem Dateisystem.
//!
//! # Warum in dieser Crate und nicht in einer eigenen `ea-admin-fs`
//!
//! Der Baum trennt Dateisystemarbeit dort in eine eigene Kiste, wo sie ein
//! eigenes PROTOKOLL ist: `ea-archive-fs` traegt Create-if-absent,
//! Verzeichnis-Flush, Rename auf demselben Dateisystem und exklusive
//! Schreibsperren ueber einem Bestand aus vielen Objekten. Hier gibt es EINE
//! Datei, zwei Vorgaenge und kein Protokoll darueber hinaus; `ea-recovery`
//! haelt mit `load_trust_anchor` auf derselben Ebene ebenfalls einen
//! Dateizugriff, ohne dafuer eine Kiste zu eroeffnen. Eine Crategrenze koennte
//! hier nichts trennen, was nicht schon getrennt ist — sie kostete einen
//! Manifesteintrag und eine Ausnahme auf der wasm32-Positivliste, und
//! `ea-admin` steht dort ohnehin schon als ausgenommen
//! (`tools/xtask/src/main.rs`).
//!
//! # Was hier NICHT entschieden wird
//!
//! Wo die Datei liegt. Den Pfad waehlt der Aufrufer; `apps/cli` legt sie neben
//! den kuenftigen Anker und begruendet das dort. Diese Ablage schreibt, was
//! ihr gegeben wird, an den Ort, der ihr genannt wird.

use std::{
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use crate::{AdminError, BootstrapStateV1, BootstrapStore};

/// Der Zeremoniezustand in EINER Datei.
pub struct FileBootstrapStore {
    path: PathBuf,
}

impl FileBootstrapStore {
    /// Die Ablage unter `path`.
    ///
    /// Legt nichts an: eine Ablage, die beim Bauen schriebe, hinterliesse eine
    /// Zeremonie, die niemand begonnen hat.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Der Pfad der Zustandsdatei.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Der Pfad, auf dem das neue Abbild entsteht, bevor es das alte ersetzt.
    ///
    /// Als Suffix an die GANZE Zeichenkette angehaengt und nicht ueber
    /// [`Path::with_extension`]: das ersetzte eine vorhandene Endung und liesse
    /// zwei verschiedene Zustandsdateien auf dieselbe Zwischendatei zeigen.
    fn temporary_path(&self) -> PathBuf {
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".writing");
        PathBuf::from(temporary)
    }
}

impl BootstrapStore for FileBootstrapStore {
    /// # Errors
    /// [`AdminError::BootstrapStoreUnavailable`], wenn die Datei nicht LESBAR
    /// ist, und [`AdminError::BootstrapStateShape`], wenn sie lesbar ist und
    /// nicht passt. Die Trennung ist dieselbe wie bei
    /// `ea_recovery::RecoveryError::{Io, TrustAnchor}`: ein Betreiber
    /// unterscheidet daran einen nicht eingehaengten Datentraeger von einem
    /// Zustand, der nicht mehr der seine ist.
    ///
    /// Eine FEHLENDE Datei ist keines von beidem, sondern schlicht keine
    /// Zeremonie.
    fn load(&self) -> Result<Option<BootstrapStateV1>, AdminError> {
        match fs::read(&self.path) {
            Ok(image) => BootstrapStateV1::from_persisted_image(&image).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AdminError::BootstrapStoreUnavailable),
        }
    }

    /// Schreibt GENAU [`BootstrapStateV1::persisted_image`] — vollstaendig
    /// oder gar nicht.
    ///
    /// Erst in eine Zwischendatei, dann `sync_all`, dann ein Rename ueber die
    /// Zustandsdatei. Ein Absturz mittendrin laesst damit entweder das alte
    /// Abbild stehen oder das neue, nie ein halbes: ein halbes faellt beim
    /// naechsten Lesen zwar auf [`AdminError::BootstrapStateShape`], aber dann
    /// waere die Zeremonie verloren, statt bei ihrem letzten Schritt zu warten.
    ///
    /// # Errors
    /// [`AdminError::BootstrapStoreUnavailable`] fuer jeden Befund des
    /// Dateisystems. Die zugrunde liegende [`io::Error`] wird ausdruecklich
    /// NICHT durchgereicht — ihre Anzeige nimmt je nach Pfad den Hostpfad auf,
    /// und der gehoert in keine Diagnose.
    fn store(&mut self, state: &BootstrapStateV1) -> Result<(), AdminError> {
        let temporary = self.temporary_path();
        let written = (|| -> io::Result<()> {
            let mut file = File::create(&temporary)?;
            file.write_all(&state.persisted_image())?;
            file.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(AdminError::BootstrapStoreUnavailable);
        }
        fs::rename(&temporary, &self.path).map_err(|_| {
            let _ = fs::remove_file(&temporary);
            AdminError::BootstrapStoreUnavailable
        })
    }
}
