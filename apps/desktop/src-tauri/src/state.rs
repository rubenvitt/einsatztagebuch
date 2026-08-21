//! Der Zustand des Wirts — und die zwei Naehte, an denen Task 16 andockt.

use std::sync::{Arc, Mutex, PoisonError};

use ea_draft::MasterDataRepository;
use ea_format::OperatorRoleV1;
use ea_operator::OperatorSessionProof;
use ea_writer::{RecoveryOutcome, WriterError, WriterService};

/// Der synchrone Port des automatischen Startpfads.
///
/// Der Port existiert, weil [`WriterService`] eine Lebensdauer traegt
/// (`&'a dyn ArchiveBackend`) und damit nicht in den `'static`-Zustand einer
/// Tauri-Anwendung passt. Die Implementierung fuer [`WriterService`] darunter
/// ist die Naht: ein Implementierer, der die Ports haelt, baut je Aufruf einen
/// Dienst und ruft genau diese Methode.
///
/// `Send + Sync` steht NICHT als Supertrait daran, weil [`WriterService`] es
/// nicht ist; die Schranke sitzt an der Stelle, die sie braucht — am Feld von
/// [`DesktopState`].
pub trait StartupRecoveryPort {
    /// Loest eine liegende Abschlussmarke auf.
    ///
    /// # Errors
    ///
    /// Der Fehler des Schreibports, unveraendert.
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError>;
}

impl StartupRecoveryPort for WriterService<'_> {
    fn resolve_pending_finalization(&self) -> Result<RecoveryOutcome, WriterError> {
        self.recover_pending()
    }
}

/// Die geprueften Sitzungsangaben dieses Geraets.
///
/// Die Rolle ist eine `Option`, und `None` ist der Anfangszustand: sie kommt
/// aus einer Root-signierten Geraete-/OS-Kontobindung mit frischer Praesenz,
/// und diese Aufloesung gehoert Task 16. Solange sie fehlt, liefert
/// `verified_session` einen benannten Fehlschlag, und die Schale zeigt ihre
/// Flaeche ohne Sitzung — fail-closed und nicht ein erfundener Lesezustand.
///
/// Der Nachweis liegt daneben und nicht in der Rolle: [`OperatorSessionProof`]
/// ist absichtlich nicht `Clone`, damit [`Self::invalidate_on_lock`] keinen
/// gueltigen Stand daneben lassen kann.
pub struct SessionState {
    role: Option<OperatorRoleV1>,
    proof: Option<OperatorSessionProof>,
}

impl SessionState {
    #[must_use]
    pub const fn new(role: Option<OperatorRoleV1>, proof: Option<OperatorSessionProof>) -> Self {
        Self { role, proof }
    }

    /// Die geprueften Rolle, wenn eine Bindung gilt.
    #[must_use]
    pub const fn role(&self) -> Option<OperatorRoleV1> {
        self.role
    }

    /// Entwertet die Sitzung wegen einer Sperre des Betriebssystems.
    ///
    /// Zwei Wirkungen, und beide sind notwendig: der Nachweis wird ueber
    /// [`OperatorSessionProof::invalidate_on_lock`] verbraucht, und die Rolle
    /// faellt weg. Ohne die zweite Haelfte blieben Rolle und Faehigkeiten
    /// lesbar, und die Oberflaeche haette nach der Sperre weiter eine Flaeche.
    pub fn invalidate_on_lock(&mut self) {
        self.role = None;
        self.proof = self
            .proof
            .take()
            .map(OperatorSessionProof::invalidate_on_lock);
    }
}

/// Der geteilte Zustand der Anwendung.
///
/// `Clone` ist billig — drei Zeiger — und ist die Voraussetzung dafuer, dass
/// jeder Kommandorumpf seine synchrone Kernoperation ueber
/// `tauri::async_runtime::spawn_blocking` schicken kann: der Abschluss dort
/// muss `Send + 'static` sein und darf deshalb keinen `tauri::State` fangen.
#[derive(Clone)]
pub struct DesktopState {
    session: Arc<Mutex<SessionState>>,
    startup: Option<Arc<dyn StartupRecoveryPort + Send + Sync>>,
    master_data: Option<Arc<MasterDataRepository>>,
}

impl DesktopState {
    #[must_use]
    pub fn new(
        session: SessionState,
        startup: Option<Arc<dyn StartupRecoveryPort + Send + Sync>>,
        master_data: Option<Arc<MasterDataRepository>>,
    ) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            startup,
            master_data,
        }
    }

    /// Die geprueften Sitzungsangaben, unter ihrem Schloss.
    #[must_use]
    pub fn session(&self) -> &Mutex<SessionState> {
        &self.session
    }

    /// Entwertet die Sitzung, und zwar UNABHAENGIG von einem vergifteten
    /// Schloss.
    ///
    /// Ein `Err` waere hier die falsche Antwort: eine Sperre, die nicht
    /// wirkt, weil ein anderer Thread beim Halten des Schlosses abgestuerzt
    /// ist, liesse die Sitzung stehen. [`PoisonError::into_inner`] ist genau
    /// dafuer da.
    pub fn invalidate_session_on_lock(&self) {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .invalidate_on_lock();
    }

    /// Der Startpfad, wenn einer verdrahtet ist.
    #[must_use]
    pub fn startup(&self) -> Option<&(dyn StartupRecoveryPort + Send + Sync)> {
        self.startup.as_deref()
    }

    /// Die Stammdatenablage, wenn eine geoeffnete Datenbank vorliegt.
    #[must_use]
    pub fn master_data(&self) -> Option<&MasterDataRepository> {
        self.master_data.as_deref()
    }
}
