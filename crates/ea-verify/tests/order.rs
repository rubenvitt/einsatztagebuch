//! Reihenfolge-Contract der neun Gate-Bezeichner aus `design.md` §14.1.
//!
//! TEILDECKUNG, ABSICHTLICH. Diese Tests fahren einen **In-Test-Verifizierer**
//! durch [`run_gates`], keine vollstaendige Archivfixture. Die Gates 4 bis 9
//! entstehen inhaltlich erst in den Tasks 13 bis 17; liefe hier bereits eine
//! echte Fixture, meldete sich ein Gate, das mangels Voraussetzungen nichts
//! pruefen kann, faelschlich als bestanden. Geprueft wird deshalb genau das,
//! was dieser Task herstellt: dass [`run_gates`] jedes betretene Gate genau
//! einmal, in der Indexreihenfolge von [`GATE_ORDER_V1`] und niemals nach
//! einem Abbruch meldet, und dass die Entkapselung `hpke-open` ausschliesslich
//! hinter dem neunten Gate erscheint.
//!
//! Die Fixture-Variante desselben Contracts wird in **Task 17** aktiviert.
//! Solange sie aussteht, ist der Contract fuer die echte Pipeline NICHT
//! erfuellt — dieser Testlauf belegt allein das Geruest.
//!
//! Kein Test dieser Datei schreibt einen der neun Bezeichner als Literal:
//! [`GATE_ORDER_V1`] ist die einzige Quelle, und `tools/xtask` haelt sie
//! gegen `design.md` §14.1.

use ea_verify::{
    DECAPSULATION_EVENT_V1, Decapsulation, GATE_ORDER_V1, Gate, GateRunner, RecordingObserver,
    run_gates,
};

/// Fehler des In-Test-Verifizierers: benennt das Gate, das abgebrochen hat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifierError {
    gate: Gate,
}

/// In-Test-Verifizierer, der die neun Gates als **Datenfluss** durchlaeuft.
///
/// `proven` ist der Zustand, den das zuletzt bestandene Gate hinterlassen hat.
/// Jedes Gate nimmt genau diesen Zustand entgegen und schreibt seinen eigenen
/// Index zurueck. Die Reihenfolge ist damit nicht behauptet, sondern
/// Datenabhaengigkeit: ein umsortierter Durchlauf saehe den Zustand seines
/// Vorgaengers nicht und schluege sofort fehl.
struct RecordingVerifier {
    /// Gate, das abbricht; `None` steht fuer die vollstaendig gueltige Lage.
    failing: Option<Gate>,
    /// Index des zuletzt bestandenen Gates.
    proven: Option<usize>,
    /// Wurde entkapselt?
    decapsulated: bool,
}

impl RecordingVerifier {
    /// Lage, in der jedes Gate traegt und entkapselt werden kann.
    fn complete_valid_entry() -> Self {
        Self {
            failing: None,
            proven: None,
            decapsulated: false,
        }
    }

    /// Lage, in der `gate` abbricht — alle frueheren Gates tragen.
    fn failing_at(gate: Gate) -> Self {
        Self {
            failing: Some(gate),
            proven: None,
            decapsulated: false,
        }
    }
}

impl GateRunner for RecordingVerifier {
    type Error = VerifierError;

    fn run_gate(&mut self, gate: Gate) -> Result<(), Self::Error> {
        assert_eq!(
            gate.index(),
            self.proven.map_or(0, |index| index + 1),
            "das Gate an Index {} sah nicht den Zustand seines Vorgaengers",
            gate.index()
        );
        if self.failing == Some(gate) {
            return Err(VerifierError { gate });
        }
        self.proven = Some(gate.index());
        Ok(())
    }

    fn decapsulate(&mut self) -> Result<Decapsulation, Self::Error> {
        assert_eq!(
            self.proven,
            Some(GATE_ORDER_V1.len() - 1),
            "die Entkapselung sah nicht den Zustand des neunten Gates"
        );
        self.decapsulated = true;
        Ok(Decapsulation::Performed)
    }
}

/// Vollstaendig gueltige Lage: alle neun Gates, danach `hpke-open`.
///
/// TEILDECKUNG: der Durchlauf arbeitet gegen den In-Test-Verifizierer dieser
/// Datei, nicht gegen `fixtures::complete_valid_entry()`. Die Fixture-Variante
/// folgt in Task 17; vorher ist dieser Contract fuer die echte Pipeline nicht
/// erfuellt.
#[test]
fn a_fully_valid_entry_records_every_gate_in_order_before_decryption() {
    let mut observer = RecordingObserver::new();
    let mut verifier = RecordingVerifier::complete_valid_entry();

    run_gates(&mut verifier, &mut observer).expect("die vollstaendig gueltige Lage traegt");

    let mut expected = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    assert_eq!(
        observer.events(),
        expected.as_slice(),
        "das Protokoll fuehrt die neun Gates in Indexreihenfolge, danach die Entkapselung"
    );
    assert!(
        verifier.decapsulated,
        "die Entkapselung folgt auf das neunte Gate"
    );
    assert_eq!(
        observer.events().last(),
        Some(&DECAPSULATION_EVENT_V1),
        "hpke-open steht hinter dem neunten Gate, nie davor"
    );
}

/// Abbruch bei kaputter Writer-Signatur: das Protokoll endet nach dem vierten
/// Gate und kennt `hpke-open` nicht.
///
/// TEILDECKUNG wie oben — die kaputte Signatur ist hier als Abbruch des
/// vierten Gates modelliert, nicht als Fixture. Task 17 setzt
/// `fixtures::bad_writer_signature()` ein.
#[test]
fn verification_stops_before_grant_or_decryption_on_bad_signature() {
    let mut observer = RecordingObserver::new();
    let mut verifier = RecordingVerifier::failing_at(Gate::ManifestSignature);

    let error = run_gates(&mut verifier, &mut observer)
        .expect_err("die kaputte Writer-Signatur bricht das vierte Gate ab");

    assert_eq!(error.gate, Gate::ManifestSignature);
    assert_eq!(
        observer.events(),
        &GATE_ORDER_V1[..=Gate::ManifestSignature.index()],
        "das abbrechende Gate wird gemeldet, kein spaeteres"
    );
    assert!(
        !observer.events().contains(&DECAPSULATION_EVENT_V1),
        "nach einem Abbruch wird nie entkapselt"
    );
    assert!(!verifier.decapsulated);
}

/// Ein Abbruch an JEDEM Gate schneidet das Protokoll an genau dieser Stelle ab.
#[test]
fn an_aborting_gate_suppresses_every_later_event_in_the_in_test_verifier() {
    for gate in Gate::ALL {
        let mut observer = RecordingObserver::new();
        let mut verifier = RecordingVerifier::failing_at(gate);

        let error = run_gates(&mut verifier, &mut observer).expect_err("das Gate bricht ab");

        assert_eq!(error.gate, gate);
        assert_eq!(observer.events(), &GATE_ORDER_V1[..=gate.index()]);
        assert!(!observer.events().contains(&DECAPSULATION_EVENT_V1));
    }
}

/// Eine uebersprungene Entkapselung wird nicht protokolliert.
///
/// Ein fehlender Empfaengerschluessel ist keine versuchte Entschluesselung
/// (Phase-B-Regel zu `is_fully_verified()`). `hpke-open` behauptet eine
/// durchgefuehrte Entkapselung und darf deshalb ausbleiben, ohne dass ein
/// Gate faellt.
#[test]
fn a_skipped_decapsulation_records_no_event_in_the_in_test_verifier() {
    struct WithoutRecipientKey;

    impl GateRunner for WithoutRecipientKey {
        type Error = VerifierError;

        fn run_gate(&mut self, _gate: Gate) -> Result<(), Self::Error> {
            Ok(())
        }

        fn decapsulate(&mut self) -> Result<Decapsulation, Self::Error> {
            Ok(Decapsulation::Skipped)
        }
    }

    let mut observer = RecordingObserver::new();
    run_gates(&mut WithoutRecipientKey, &mut observer).expect("kein Gate faellt");

    assert_eq!(observer.events(), GATE_ORDER_V1.as_slice());
    assert!(!observer.events().contains(&DECAPSULATION_EVENT_V1));
}

/// `Gate::name()` und `Gate::index()` stimmen mit [`GATE_ORDER_V1`] ueberein.
///
/// Damit ist `GATE_ORDER_V1` nachweislich die einzige Quelle der Bezeichner:
/// jeder Name entsteht aus dem Array, und die Indizes sind dicht und
/// aufsteigend.
#[test]
fn gate_names_and_indices_are_exactly_the_pinned_order() {
    assert_eq!(Gate::ALL.len(), GATE_ORDER_V1.len());
    for (index, gate) in Gate::ALL.into_iter().enumerate() {
        assert_eq!(gate.index(), index);
        assert_eq!(gate.name(), GATE_ORDER_V1[index]);
    }
    assert!(
        !GATE_ORDER_V1.contains(&DECAPSULATION_EVENT_V1),
        "die Entkapselung ist kein Gate"
    );
}
