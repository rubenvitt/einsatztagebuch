//! Die neun Gate-Bezeichner aus `design.md` §14.1 und ihr Durchlauf.
//!
//! [`GATE_ORDER_V1`] ist die EINZIGE Quelle dieser neun Zeichenketten. Kein
//! zweiter Ort dieser Crate schreibt einen der Bezeichner als Literal;
//! [`Gate::name`] indiziert ausschliesslich in das Array, und
//! `tools/xtask/tests/spec_completeness.rs` haelt das Array gegen §14.1.
//!
//! Die Entkapselung [`DECAPSULATION_EVENT_V1`] ist KEIN Gate: sie folgt auf
//! das neunte, und keine Verifikationsentscheidung haengt an ihr. Sie steht
//! deshalb ausdruecklich NICHT in [`GATE_ORDER_V1`].

/// Die neun Gate-Bezeichner aus `design.md` §14.1, in normativer Reihenfolge.
///
/// Diese Reihenfolge ist der Contract, nicht bloss eine Aufzaehlung: ein
/// Protokoll, in dem ein Bezeichner fehlt oder in dem die Entkapselung vor
/// einem der neun erscheint, ist ein Implementierungsfehler und MUSS als
/// Testfehlschlag sichtbar werden.
pub const GATE_ORDER_V1: [&str; 9] = [
    "format",
    "trust",
    "registry",
    "manifest-signature",
    "chain-position",
    "grant-plan",
    "receipt",
    "evidence",
    "recipient-grant",
];

/// Protokollname der Entkapselung, die auf das neunte Gate folgt.
///
/// Kein Gate. `design.md` §14.1: die Entkapselung wird protokolliert, aber
/// keine Verifikationsentscheidung haengt an ihr.
pub const DECAPSULATION_EVENT_V1: &str = "hpke-open";

/// Ein Gate der Verifikationsreihenfolge aus `design.md` §14.1.
///
/// Die Reihenfolge der Varianten ist die Reihenfolge von [`GATE_ORDER_V1`];
/// [`Gate::index`] und [`Gate::ALL`] halten das ausfuehrbar fest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Gate {
    /// Format und Parserlimits.
    Format,
    /// Organisations-Root und Trust-Event-Kette.
    Trust,
    /// Registry-Head, Sequenz-Lease und Writer-Zertifikat.
    Registry,
    /// `signedManifest`, COSE-Signatur, `entryHash` und Ciphertext-Hash.
    ManifestSignature,
    /// Sequenz, Vorgaengerhash und Writer-Transition-Ereignis.
    ChainPosition,
    /// Initialer Grant-Plan und verpflichtender Recovery-Grant.
    GrantPlan,
    /// Server-Receipt und Checkpoints, sofern vorhanden.
    Receipt,
    /// Evidence-Objekte und Zeitstempel, sofern gefordert.
    Evidence,
    /// Eigener Grant, Aussteller-Capability, Authorization und Nutzungsfrist.
    RecipientGrant,
}

impl Gate {
    /// Alle neun Gates in der Reihenfolge von [`GATE_ORDER_V1`].
    pub const ALL: [Self; GATE_ORDER_V1.len()] = [
        Self::Format,
        Self::Trust,
        Self::Registry,
        Self::ManifestSignature,
        Self::ChainPosition,
        Self::GrantPlan,
        Self::Receipt,
        Self::Evidence,
        Self::RecipientGrant,
    ];

    /// Position des Gates in [`GATE_ORDER_V1`], von null an.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Format => 0,
            Self::Trust => 1,
            Self::Registry => 2,
            Self::ManifestSignature => 3,
            Self::ChainPosition => 4,
            Self::GrantPlan => 5,
            Self::Receipt => 6,
            Self::Evidence => 7,
            Self::RecipientGrant => 8,
        }
    }

    /// Protokollname des Gates.
    ///
    /// Ausschliesslich ein Zugriff auf [`GATE_ORDER_V1`] — die Bezeichner
    /// stehen an keinem zweiten Ort als Literal.
    #[must_use]
    pub const fn name(self) -> &'static str {
        GATE_ORDER_V1[self.index()]
    }
}

/// Ausgang der Entkapselung hinter dem neunten Gate.
///
/// `Skipped` ist KEIN Mangel: ein fehlender Empfaengerschluessel bedeutet
/// keine versuchte Entschluesselung und senkt weder ein Gate noch die
/// vollstaendige Verifikation — das ist die Phase-B-Regel zu
/// `is_fully_verified()`, nicht der Wortlaut von §14.1, der von `fehlender
/// Grant` und `unbekannter Schluessel` spricht. Ein uebersprungener Schritt
/// erzeugt folgerichtig kein [`DECAPSULATION_EVENT_V1`], denn das Ereignis
/// behauptet eine durchgefuehrte Entkapselung.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decapsulation {
    /// Der CEK wurde entkapselt.
    Performed,
    /// Es lag kein Empfaengerschluessel vor; es wurde nichts geoeffnet.
    Skipped,
}

/// Beobachter des Verifikationsprotokolls.
///
/// [`run_gates`] meldet jedes BETRETENE Gate — auch das abbrechende, denn ein
/// Abbruch ist ein Befund ueber genau dieses Gate.
pub trait GateObserver {
    /// Das Gate wurde betreten.
    fn on_gate(&mut self, gate: Gate);
    /// Die Entkapselung wurde durchgefuehrt.
    fn on_decapsulation(&mut self);
}

/// Die Pruefarbeit eines Gates, aufgetrennt vom Durchlauf.
///
/// Der Durchlauf (Reihenfolge, Abbruch, Protokoll) gehoert [`run_gates`], die
/// Sacharbeit dem Implementierer. Die Gates 4 bis 9 entstehen inhaltlich in
/// den Tasks 13 bis 17 und fuellen `run_gate`; die Reihenfolge bleibt davon
/// unberuehrt.
pub trait GateRunner {
    /// Fehler, mit dem ein Gate abbricht.
    type Error;

    /// Fuehrt die Pruefungen von `gate` aus.
    ///
    /// `Err` bricht den gesamten Durchlauf ab: kein spaeteres Gate laeuft,
    /// und es wird nicht entkapselt.
    fn run_gate(&mut self, gate: Gate) -> Result<(), Self::Error>;

    /// Entkapselt den CEK, nachdem alle neun Gates getragen haben.
    fn decapsulate(&mut self) -> Result<Decapsulation, Self::Error>;
}

/// Protokolliert jedes gemeldete Ereignis als Zeichenkette.
///
/// Testinstrument, bewusst NICHT hinter `cfg(test)`: die
/// Integrationstests von `ea-verify` und die Systemtests greifen darauf zu.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordingObserver {
    events: Vec<&'static str>,
}

impl RecordingObserver {
    /// Ein Beobachter ohne Ereignisse.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Die gemeldeten Ereignisse in Meldereihenfolge.
    #[must_use]
    pub fn events(&self) -> &[&'static str] {
        &self.events
    }
}

impl GateObserver for RecordingObserver {
    fn on_gate(&mut self, gate: Gate) {
        self.events.push(gate.name());
    }

    fn on_decapsulation(&mut self) {
        self.events.push(DECAPSULATION_EVENT_V1);
    }
}

/// Erzwingt in Debug-Builds, dass die Gates dicht und aufsteigend laufen.
///
/// Der Durchlauf ist strukturell durch [`Gate::ALL`] festgelegt; der
/// Sequencer sichert diese Struktur gegen eine spaeter eingefuegte
/// Umsortierung ab, statt sie nur zu kommentieren.
struct GateSequencer {
    entered: Option<usize>,
}

impl GateSequencer {
    const fn new() -> Self {
        Self { entered: None }
    }

    /// Betritt `gate`; verlangt `gate.index() == last_index + 1`.
    fn enter(&mut self, gate: Gate) {
        debug_assert_eq!(
            gate.index(),
            self.entered.map_or(0, |last| last + 1),
            "das Gate an Index {} laeuft ausser der Reihe",
            gate.index()
        );
        self.entered = Some(gate.index());
    }

    /// Verlangt, dass alle neun Gates gelaufen sind.
    fn assert_complete(&self) {
        debug_assert_eq!(
            self.entered,
            Some(GATE_ORDER_V1.len() - 1),
            "vor der Entkapselung muessen alle neun Gates gelaufen sein"
        );
    }
}

/// Faehrt die neun Gates in Indexreihenfolge und danach die Entkapselung.
///
/// Jedes betretene Gate wird `observer` genau einmal gemeldet, bevor seine
/// Pruefung laeuft — ein abbrechendes Gate erscheint damit im Protokoll, ein
/// spaeteres nie. [`DECAPSULATION_EVENT_V1`] wird ausschliesslich gemeldet,
/// wenn alle neun Gates getragen haben UND tatsaechlich entkapselt wurde.
///
/// # Errors
///
/// Reicht den Fehler des ersten abbrechenden Gates beziehungsweise der
/// Entkapselung unveraendert durch.
pub fn run_gates<R>(runner: &mut R, observer: &mut dyn GateObserver) -> Result<(), R::Error>
where
    R: GateRunner + ?Sized,
{
    let mut sequencer = GateSequencer::new();
    for gate in Gate::ALL {
        sequencer.enter(gate);
        observer.on_gate(gate);
        runner.run_gate(gate)?;
    }
    sequencer.assert_complete();
    if runner.decapsulate()? == Decapsulation::Performed {
        observer.on_decapsulation();
    }
    Ok(())
}
