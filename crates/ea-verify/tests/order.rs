//! Reihenfolge-Contract der neun Gate-Bezeichner aus `design.md` §14.1.
//!
//! ZWEI EBENEN, und sie messen Verschiedenes.
//!
//! [`run_gates`] faehrt einen Verifizierer ueber GENAU EIN Objekt und bricht
//! beim ersten fallenden Gate ab. Die In-Test-Verifizierer dieser Datei messen
//! diesen Durchlauf: dass jedes betretene Gate genau einmal, in der
//! Indexreihenfolge von [`GATE_ORDER_V1`] und niemals nach einem Abbruch
//! gemeldet wird, und dass `hpke-open` ausschliesslich hinter dem neunten Gate
//! erscheint.
//!
//! [`verify_archive_observed`] faehrt dieselbe Reihenfolge ueber einen ganzen
//! BESTAND und meldet den Eintritt in eine Stufe. Seit Task 17 laeuft der
//! Contract auch gegen eine echte Fixture:
//! `a_fully_valid_entry_records_every_gate_in_order_before_decryption` misst
//! die neun Bezeichner und danach die Entkapselung an einem lueckenfreien
//! Bestand mit echtem Ciphertext, echtem Grant und echtem
//! Empfaengerschluessel.
//!
//! FUER DEN ABBRUCH GILT DAS NICHT, und das ist keine Luecke, sondern der
//! Unterschied zwischen den beiden Ebenen: eine kaputte Writer-Signatur ist ein
//! Befund ueber EIN OBJEKT und bricht den Bestandslauf ausdruecklich nicht ab
//! (`crates/ea-verify/src/archive.rs` traegt sie als `signatureErrors`-Eintrag
//! ein und faehrt fort). Archivweit bricht nur Gate `trust` ab — fail-closed
//! fuer den ganzen Bestand —, und genau das misst
//! `a_failing_trust_gate_truncates_the_archive_protocol`.
//!
//! Kein Test dieser Datei schreibt einen der neun Bezeichner als Literal:
//! [`GATE_ORDER_V1`] ist die einzige Quelle, und `tools/xtask` haelt sie
//! gegen `design.md` §14.1.

#[path = "support/mod.rs"]
mod support;

use ea_types::UnixMillis;
use ea_verify::{
    DECAPSULATION_EVENT_V1, Decapsulation, GATE_ORDER_V1, Gate, GateRunner, RecordingObserver,
    VerifyOptions, run_gates, verify_archive_observed,
};

use support::{
    FIXTURE_OS_WALL_CLOCK_V1, archive_support::ArchiveFixture, complete_recipient_key_thumbprint,
    complete_recipient_private_key, complete_valid_archive,
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
/// GEGEN EINE ECHTE FIXTURE, seit Task 17. Der Bestand ist lueckenfrei, sein
/// Ciphertext ist wirklich verschluesselt, sein Grant kapselt wirklich, und
/// der Lauf haelt wirklich den privaten Schluessel dazu — ein Protokoll mit
/// zehn Ereignissen ist damit gemessen und nicht gestellt.
#[test]
fn a_fully_valid_entry_records_every_gate_in_order_before_decryption() {
    let archive = complete_valid_archive();
    let recipient = complete_recipient_private_key();
    let mut observer = RecordingObserver::new();

    let report = verify_archive_observed(
        &archive.fixture,
        &archive.anchor(),
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
            .with_recipient(complete_recipient_key_thumbprint(), &recipient),
        &mut observer,
    )
    .expect("der lueckenfreie Bestand traegt");

    let mut expected = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    assert_eq!(
        observer.events(),
        expected.as_slice(),
        "das Protokoll fuehrt die neun Gates in Indexreihenfolge, danach die Entkapselung"
    );
    assert_eq!(
        observer.events().last(),
        Some(&DECAPSULATION_EVENT_V1),
        "hpke-open steht hinter dem neunten Gate, nie davor"
    );
    assert!(
        report.is_fully_verified(),
        "ein Protokoll ohne Befund gehoert zu einem vollstaendig verifizierten Bestand"
    );
}

/// Dieselbe Lage gegen den In-Test-Verifizierer: `run_gates` haelt die
/// Reihenfolge als DATENFLUSS.
///
/// Neben der Fixture und nicht statt ihrer: hier sieht jedes Gate den Zustand
/// seines Vorgaengers, ein umsortierter Durchlauf schluege deshalb sofort fehl.
/// Die Fixture kann das nicht zeigen — sie misst, DASS die Pipeline die
/// Reihenfolge faehrt, nicht, dass sie es muss.
#[test]
fn the_in_test_verifier_records_every_gate_in_order_before_decryption() {
    let mut observer = RecordingObserver::new();
    let mut verifier = RecordingVerifier::complete_valid_entry();

    run_gates(&mut verifier, &mut observer).expect("die vollstaendig gueltige Lage traegt");

    let mut expected = GATE_ORDER_V1.to_vec();
    expected.push(DECAPSULATION_EVENT_V1);
    assert_eq!(observer.events(), expected.as_slice());
    assert!(
        verifier.decapsulated,
        "die Entkapselung folgt auf das neunte Gate"
    );
}

/// Archivweit bricht NUR Gate `trust` ab, und dann endet das Protokoll dort.
///
/// Ein Bestand ohne jedes Trust-Objekt hat keine Vertrauenskette; ueber kein
/// Objekt ist dann etwas zu sagen, und kein spaeteres Gate laeuft.
#[test]
fn a_failing_trust_gate_truncates_the_archive_protocol() {
    let anchor = complete_valid_archive().anchor();
    let empty = ArchiveFixture::new();
    let mut observer = RecordingObserver::new();

    let report = verify_archive_observed(
        &empty,
        &anchor,
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)),
        &mut observer,
    )
    .expect("auch ein Vertrauensmangel liefert einen lesbaren Bericht");

    assert_eq!(
        observer.events(),
        &GATE_ORDER_V1[..=Gate::Trust.index()],
        "ohne Vertrauenskette laeuft kein spaeteres Gate"
    );
    assert!(
        !report.is_fully_verified(),
        "ein Lauf, der die Pipeline nicht beendet, ist nie vollstaendig verifiziert"
    );
}

/// Jedes archivweit gemeldete Protokoll ist ein PRAEFIX der gepinnten
/// Reihenfolge.
///
/// Der Contract in einem Satz, ueber beide gemessenen Bestaende hinweg: es gibt
/// kein Ereignis ausser der Reihe, keine Wiederholung und keine Luecke.
#[test]
fn every_archive_protocol_is_a_prefix_of_the_pinned_order() {
    let archive = complete_valid_archive();
    let recipient = complete_recipient_private_key();
    for (source, options) in [
        (
            &archive.fixture,
            VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1)),
        ),
        (
            &archive.fixture,
            VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
                .with_recipient(complete_recipient_key_thumbprint(), &recipient),
        ),
    ] {
        let mut observer = RecordingObserver::new();
        verify_archive_observed(source, &archive.anchor(), options, &mut observer)
            .expect("der lueckenfreie Bestand traegt");
        let events = observer.events();
        let gates = events
            .iter()
            .position(|event| *event == DECAPSULATION_EVENT_V1)
            .unwrap_or(events.len());
        assert_eq!(&events[..gates], &GATE_ORDER_V1[..gates]);
        assert!(
            events[gates..]
                .iter()
                .all(|event| *event == DECAPSULATION_EVENT_V1),
            "hinter den Gates steht hoechstens die Entkapselung"
        );
    }
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
