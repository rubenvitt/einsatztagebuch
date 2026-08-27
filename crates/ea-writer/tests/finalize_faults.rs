//! Die Waechter VOR der unwiderruflichen Grenze — und der Beleg, dass nichts
//! dauerhaft wurde.
//!
//! Diese Datei ist das Gegenstueck zu `crates/ea-draft/tests/discard_faults.rs`
//! auf der FINALISIERUNGSSEITE. Die Verwerfensseite beweist ihre
//! Praesenznachweispruefung mit Codevergleich (`discard_faults.rs`:85-99,
//! :101-117, :127-149), die Finalisierungsseite bewies sie nicht — genau diese
//! Asymmetrie ist Befund F9 der Abnahmepruefung. Jede Zusicherung hier ist
//! bewusst nach dem Vorbild des Zwillings gebaut und nicht nach einer neuen
//! Form: Ablehnung mit STABILEM Code, danach die Nachpruefung, dass kein Byte,
//! keine Marke und keine Einsatznummer den abgewiesenen Versuch ueberlebt hat.
//!
//! `FinalizationPreview` traegt bewusst kein `Debug` (Stufe 1 leitet es fuer
//! Werte mit Hashes nicht ab), also wird der Fehlerarm durchgaengig ueber
//! `map_or_else` genommen und nicht ueber `expect_err`.

mod support;

use ea_chain::CheckpointClaim;
use ea_operator::ReauthPurpose;
use ea_types::{ChainSequence, EntryHash, ObjectHash};
use support::{FIXTURE_INCIDENT_NUMBER, LineVariantV1, WriterHarness, valid_incident};

/// Der Objekthash, unter dem die synthetische Checkpointaussage steht.
///
/// Er ist die HERKUNFT der Aussage und geht in keine Pruefung ein; `ea_chain`
/// traegt ihn nur in den Befund. Ein Literal ist hier deshalb ehrlicher als
/// eine gerechnete Groesse, die Genauigkeit vortaeuschte.
fn checkpoint_origin() -> ObjectHash {
    ObjectHash::try_from([0xc7; 32].as_slice()).expect("32 Byte sind 32 Byte")
}

/// Ein Eintragshash, den DIESER Bestand nie erzeugt hat.
fn foreign_entry_hash() -> EntryHash {
    EntryHash::try_from([0x1d; 32].as_slice()).expect("32 Byte sind 32 Byte")
}

/// Nichts ist dauerhaft geworden: kein Objekt, kein Staging, keine Marke, der
/// Entwurf steht, und die Einsatznummer ist frei.
///
/// `published` ist die Zahl der Eintraege, die VOR dem abgewiesenen Versuch
/// schon lagen — nicht immer null: zwei der Zusicherungen unten messen auf
/// einem Bestand, der bereits einen Eintrag traegt, und „leer" waere dort die
/// falsche Frage.
fn nothing_became_durable(harness: &WriterHarness, published: usize) {
    assert_eq!(
        harness.published_entry_paths().len(),
        published,
        "der abgewiesene Versuch darf keinen Eintrag hinterlassen"
    );
    assert_eq!(
        harness.staged_object_count(),
        0,
        "der abgewiesene Versuch darf nichts stagen"
    );
    assert!(
        !harness.prepared_marker_is_present(),
        "der abgewiesene Versuch darf keine Abschlussmarke legen"
    );
    assert!(
        harness.draft_dek_is_present(),
        "der abgewiesene Versuch darf den Entwurfsschluessel nicht anruehren"
    );
}

/// Ein Nachweis, dessen Fuenfminutenfenster abgelaufen ist, autorisiert keine
/// Finalisierung.
///
/// Der Zwilling ist `discard_without_a_fresh_proof_is_rejected`
/// (`crates/ea-draft/tests/discard_faults.rs`:85-99). Der Nachweis ist ECHT —
/// `OperatorAuthenticator::reauthenticate` hat ihn ausgestellt und seine
/// Signatur selbst nachgeprueft —, er nennt die RICHTIGE Bindung und den
/// RICHTIGEN Zweck. Er scheitert ALLEIN an der Zeit, und das ist genau der
/// Fall, den `reauthenticate` in seinem Vertrag beschreibt: ein `Ok` heisst
/// nicht „der Nachweis gilt jetzt".
#[test]
fn finalization_without_a_fresh_proof_is_rejected() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);

    // POSITIVKONTROLLE und zugleich die bestaetigte Vorschau des zweiten
    // Eingangs: mit einem frischen Nachweis traegt derselbe Aufruf.
    let fresh = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service
        .preview(&fresh, valid_incident(), harness.observed_now())
        .expect("ein frischer Nachweis MUSS tragen");

    let expired = harness.expired_proof();
    assert!(
        expired.binding_object_hash() == harness.binding().binding_object_hash,
        "der abgelaufene Nachweis nennt DIESELBE Bindung — allein die Zeit entscheidet"
    );

    let previewed = harness
        .service(&source)
        .preview(&expired, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein abgelaufener Nachweis MUSS fail-closed abweisen"),
        );
    assert_eq!(previewed, "EA-WRITER-REAUTH-REQUIRED");

    // Der ZWEITE Eingang. Er ist die tragende Haelfte: der Nachweis wird an
    // JEDEM Eingang neu bewertet und nicht nur am ersten — dieselbe Aussage,
    // die der Zwilling ueber `resume_after_restart` macht.
    let finalized = service
        .finalize(&expired, valid_incident(), &preview, harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein abgelaufener Nachweis MUSS fail-closed abweisen"),
        );
    assert_eq!(finalized, "EA-WRITER-REAUTH-REQUIRED");

    nothing_became_durable(&harness, 0);
    assert!(
        !harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER),
        "die abgewiesene Finalisierung darf die Einsatznummer nicht verbrauchen"
    );
}

/// Ein taufrischer Nachweis eines ANDEREN Zwecks autorisiert keine
/// Finalisierung.
///
/// Der Zwilling ist `a_proof_of_another_purpose_never_authorizes_a_discard`
/// (`discard_faults.rs`:101-117), und die Richtung ist gespiegelt: dort
/// autorisiert ein `Finalize`-Nachweis kein Verwerfen, hier autorisiert ein
/// `DiscardDraft`-Nachweis keinen Abschluss. Der Unterschied zum Fall darueber
/// ist der CODE, und er ist keine Kosmetik: `-PURPOSE-MISMATCH` sagt dem
/// Bediener, dass eine Wiederanmeldung mit dem RICHTIGEN Zweck weiterhilft,
/// `-REAUTH-REQUIRED` sagt, dass die Zeit abgelaufen ist.
#[test]
fn a_proof_of_another_purpose_never_authorizes_a_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);

    let fresh = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service
        .preview(&fresh, valid_incident(), harness.observed_now())
        .expect("ein frischer Nachweis MUSS tragen");

    // TAUFRISCH und fuer DIESELBE Bindung — er nennt nur einen anderen Zweck.
    let other_purpose = harness.proof_for(ReauthPurpose::DiscardDraft);
    assert!(
        other_purpose.binding_object_hash() == harness.binding().binding_object_hash,
        "der Nachweis nennt DIESELBE Bindung — allein der Zweck entscheidet"
    );

    let previewed = harness
        .service(&source)
        .preview(&other_purpose, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein zweckfremder Nachweis MUSS fail-closed abweisen"),
        );
    assert_eq!(previewed, "EA-WRITER-REAUTH-PURPOSE-MISMATCH");

    let finalized = service
        .finalize(
            &other_purpose,
            valid_incident(),
            &preview,
            harness.observed_now(),
        )
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein zweckfremder Nachweis MUSS fail-closed abweisen"),
        );
    assert_eq!(finalized, "EA-WRITER-REAUTH-PURPOSE-MISMATCH");

    nothing_became_durable(&harness, 0);
    assert!(
        !harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER),
        "die abgewiesene Finalisierung darf die Einsatznummer nicht verbrauchen"
    );
}

/// Die BINDUNGSPRUEFUNG der Finalisierungsseite — der Vergleich, den
/// `OperatorSessionProof` seinem Verbraucher ausdruecklich zuweist.
///
/// `is_valid_for` prueft die Bindung nicht
/// (`crates/ea-operator/src/session.rs`: „Wer einen Nachweis annimmt, ohne die
/// Bindung zu vergleichen, hat einen Fehler gemacht"), und
/// `binding_object_hash` nennt neben „Task 4 beim Verwerfen" ausdruecklich
/// „Task 11 beim Abschluss" als den zweiten Verbraucher, der vergleichen MUSS.
/// Ohne den Vergleich autorisierte ein frischer, zweckgleicher Nachweis EINER
/// FREMDEN Bedienerbindung den unwiderruflichen Abschluss — und der Eintrag
/// truege die Bedieneraufnahme DIESES Geraets unter der Praesenz eines
/// anderen.
///
/// # Warum der Nachweis fremd ist und nicht der Dienst
///
/// Die naheliegende Bauart — der Dienst wird auf einen erfundenen
/// Bindungshash gebunden — bezeugt den falschen Waechter. Ein erfundener Hash
/// ist im gewaehlten Head nicht aktiv, also faellt schon
/// `active_operator_binding_fields` (`finalize.rs`:579) mit DEMSELBEN Code,
/// und die Zusicherung waere auch dann gruen, wenn `require_fresh_proof` gar
/// nicht vergliche. Hier ist es umgekehrt: der Dienst behaelt seine eigene,
/// aktive Bindung, und ALLEIN der Nachweis gehoert zu einer anderen.
#[test]
fn a_proof_of_another_operator_binding_never_authorizes_a_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let service = harness.service(&source);

    let fresh = harness.proof_for(ReauthPurpose::Finalize);
    let preview = service
        .preview(&fresh, valid_incident(), harness.observed_now())
        .expect("ein Nachweis der eigenen Bindung MUSS tragen");

    // Der Nachweis ist taufrisch UND nennt genau `Finalize`. Er scheitert
    // ALLEIN daran, dass er zu einer anderen Bedienerbindung gehoert.
    let foreign = harness.proof_of_another_operator_binding(ReauthPurpose::Finalize);
    assert!(
        foreign.binding_object_hash() != harness.binding().binding_object_hash,
        "der Fall darf nicht in dieselbe Bindung entarten"
    );

    let previewed = harness
        .service(&source)
        .preview(&foreign, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein Nachweis fremder Bindung MUSS fail-closed abweisen"),
        );
    assert_eq!(previewed, "EA-WRITER-REAUTH-BINDING-MISMATCH");

    // Auch der zweite Eingang nimmt ihn nicht an: die Bindung wird an JEDEM
    // Eingang verglichen, nicht nur am ersten.
    let finalized = service
        .finalize(&foreign, valid_incident(), &preview, harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein Nachweis fremder Bindung MUSS fail-closed abweisen"),
        );
    assert_eq!(finalized, "EA-WRITER-REAUTH-BINDING-MISMATCH");

    nothing_became_durable(&harness, 0);
    assert!(
        !harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER),
        "die abgewiesene Finalisierung darf die Einsatznummer nicht verbrauchen"
    );
}

/// Schritt 2: eine erreichbare Serveraussage bezeugt eine Sequenz, die der
/// lokale Bestand nicht zeigen kann.
///
/// Das ist der einfachste erkennbare Rollback und der Fall, den Produkt-
/// invariante 1 traegt: der Server hat den Eintrag nachweislich gesehen, der
/// lokale Bestand hat ihn nicht mehr. Weiterzuschreiben hiesse, dieselbe
/// Sequenz ein zweites Mal zu vergeben.
///
/// Die POSITIVKONTROLLE steht daneben und ist nicht dekorativ: derselbe
/// Bestand, derselbe Nachweis, dieselbe Vorschau — nur OHNE die Aussage — muss
/// tragen. Ohne sie waere die Zusicherung auch gruen, wenn die Vorschau aus
/// einem ganz anderen Grund abwiese.
#[test]
fn a_checkpoint_beyond_the_local_head_stops_the_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ReauthPurpose::Finalize);

    // POSITIVKONTROLLE: ohne Aussage ist Schritt 2 `NotAssessable` und traegt.
    harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("ohne Serveraussage MUSS derselbe Bestand tragen");

    // Der Bestand ist LEER — es gibt keinen verifizierten Kopf. Eine Aussage
    // ueber Sequenz 0 bezeugt damit einen Eintrag, den dieser Bestand nicht
    // zeigen kann.
    let claims = [CheckpointClaim {
        chain_id: harness.head().chain_id(),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: ChainSequence::new(0),
        head_entry_hash: foreign_entry_hash(),
        checkpoint_object_hash: checkpoint_origin(),
    }];
    let code = harness
        .service_with_checkpoints(&source, &claims)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein erkannter Rollback MUSS fail-closed abweisen"),
        );
    assert_eq!(code, "EA-WRITER-ROLLBACK-DETECTED");

    nothing_became_durable(&harness, 0);
    assert!(!harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER));
}

/// Schritt 2: die Serveraussage bezeugt fuer DIESELBE Sequenz einen ANDEREN
/// Eintragshash.
///
/// Die schaerfste Messung des Bundels, weil ihre beiden Haelften sich in GENAU
/// einem Feld unterscheiden. Beide Aussagen sprechen ueber dieselbe Kette und
/// dieselbe Sequenz; die eine nennt den Eintragshash, den dieser Bestand
/// wirklich traegt, die andere einen fremden. Die stimmige Aussage MUSS
/// Schritt 2 passieren — belegt dadurch, dass der Lauf am naechsten Waechter
/// haengenbleibt (die Sequenz ist verbraucht, Schritt 3 verlangt den externen
/// Kopfabgleich) und nicht schon hier. Die unstimmige MUSS abbrechen.
#[test]
fn a_checkpoint_that_witnesses_another_entry_hash_stops_the_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let preview = harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");
    let outcome = harness
        .service(&source)
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("der erste Abschluss muss tragen");
    assert_eq!(harness.published_entry_paths().len(), 1);

    let claim_for = |entry_hash| CheckpointClaim {
        chain_id: harness.head().chain_id(),
        covered_from_sequence: ChainSequence::new(0),
        covered_through_sequence: outcome.sequence,
        head_entry_hash: entry_hash,
        checkpoint_object_hash: checkpoint_origin(),
    };

    // POSITIVKONTROLLE: die STIMMIGE Aussage passiert Schritt 2. Sichtbar wird
    // das daran, dass der Lauf erst am naechsten Waechter haengenbleibt.
    let consistent = [claim_for(outcome.entry_hash)];
    let passed = harness
        .service_with_checkpoints(&source, &consistent)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("die verbrauchte Sequenz MUSS am Kopfabgleich haengenbleiben"),
        );
    assert_eq!(
        passed, "EA-WRITER-HEAD-RECONCILIATION-REQUIRED",
        "die stimmige Aussage darf Schritt 2 nicht anhalten"
    );

    // Und dieselbe Aussage mit EINEM anderen Feld bricht ab.
    let conflicting = [claim_for(foreign_entry_hash())];
    let blocked = harness
        .service_with_checkpoints(&source, &conflicting)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein bezeugter Kopfkonflikt MUSS fail-closed abweisen"),
        );
    assert_eq!(blocked, "EA-WRITER-ROLLBACK-DETECTED");

    // Der EINE Eintrag des ersten Abschlusses steht — und kein zweiter.
    nothing_became_durable(&harness, 1);
}

/// Schritt 1: der Kettenkopf laesst sich aus den committed Archivbytes nicht
/// bilden.
///
/// Der Fall ist im Bestand angelegt und nicht erfunden: `sequence_id.rs`
/// (`a_binding_in_a_foreign_chain_is_refused_before_anything_is_staged`)
/// beschreibt ihn woertlich als das, was OHNE den Waechter aus Schritt 3
/// dauerhaft entstuende — „danach waere derselbe Bestand mit `ForeignChainId`
/// DAUERHAFT nicht mehr finalisierbar". Hier wird genau diese Lage hergestellt
/// und gemessen: ein Bestand mit einem Eintrag der Kette A, und eine Bindung,
/// die Kette B behauptet.
///
/// Die POSITIVKONTROLLE zeigt, dass derselbe Bestand mit der RICHTIGEN Kennung
/// einen Kopf hergibt: der Lauf kommt bis Schritt 3 und bleibt dort am
/// Kopfabgleich haengen — ein Fehler, den Schritt 1 gar nicht kennt.
#[test]
fn a_chain_head_that_cannot_be_rebuilt_stops_the_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let preview = harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("die Vorschau muss entstehen");
    harness
        .service(&source)
        .finalize(&proof, valid_incident(), &preview, harness.observed_now())
        .expect("der erste Abschluss muss tragen");
    assert_eq!(harness.published_entry_paths().len(), 1);

    // POSITIVKONTROLLE: mit der Kennung DIESER Linie bildet Schritt 1 den Kopf,
    // und der Lauf faellt erst am Kopfabgleich in Schritt 3.
    let rebuilt = harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("die verbrauchte Sequenz MUSS am Kopfabgleich haengenbleiben"),
        );
    assert_eq!(
        rebuilt, "EA-WRITER-HEAD-RECONCILIATION-REQUIRED",
        "mit der richtigen Kennung ist der Kopf bildbar"
    );

    let mut foreign = harness.binding();
    foreign.chain_id = ea_types::ChainId::try_from(&[0x7f; 16][..]).expect("16 Byte");
    let code = harness
        .service_with_binding(&source, foreign)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("ein unbildbarer Kettenkopf MUSS fail-closed abweisen"),
        );
    assert_eq!(code, "EA-WRITER-CHAIN-HEAD-UNUSABLE");

    nothing_became_durable(&harness, 1);
}

/// Schritt 4: die nachgerechnete Profilzusage weicht von der gebundenen ab.
///
/// `operatorProfileCommitment` steht in der SIGNIERTEN Bedienerbindung und ist
/// die Zusage, dass die Bedieneraufnahme des Eintrags aus GENAU der Profilzeile
/// stammt, die die Registrierung gesehen hat. Der Writer rechnet sie in
/// Schritt 4 aus der lokalen Zeile nach — und in der glatten Fixture stimmen
/// beide per Konstruktion ueberein, weshalb der Waechter ohne diese Variante
/// eine Zeile ist, die kein Test je ausfuehrt.
///
/// Zuerst wird belegt, dass die Abweichung ueberhaupt bis zum Writer kommt:
/// scheiterte schon die Kandidatenpruefung der Stufe 1, waere die Zusicherung
/// eine Aussage ueber `ea-trust` und nicht ueber Schritt 4.
#[test]
fn a_binding_that_promises_another_operator_profile_stops_the_finalization() {
    let variant = LineVariantV1 {
        foreign_operator_profile_commitment: true,
        ..LineVariantV1::default()
    };
    assert!(
        WriterHarness::candidate_rejection(variant).is_none(),
        "die Abweichung MUSS bis zum Writer kommen und nicht schon an der Kandidatenpruefung fallen"
    );

    let harness = WriterHarness::with_variant(variant);
    let source = harness.source();
    let proof = harness.proof_for(ReauthPurpose::Finalize);
    let code = harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("eine fremde Profilzusage MUSS fail-closed abweisen"),
        );
    assert_eq!(code, "EA-OPERATOR-PROFILE-COMMITMENT");

    nothing_became_durable(&harness, 0);
    assert!(!harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER));
}

/// Schritt 4: es liegt keine Profilzeile, gegen die sich die Zusage
/// nachrechnen liesse.
///
/// Die Lage nach einer zurueckgespielten Sicherung, die aelter ist als die
/// Bedieneranlage. Fail-closed ist hier die einzige richtige Antwort: eine
/// Momentaufnahme aus Vorgabewerten truege einen Bediener, den niemand
/// angelegt hat, und sie wuerde signiert und unwiderruflich.
///
/// Die POSITIVKONTROLLE steht davor: derselbe Bestand MIT Zeile traegt. Ohne
/// sie waere die Zusicherung auch gruen, wenn die Vorschau aus einem ganz
/// anderen Grund abwiese.
#[test]
fn a_missing_operator_profile_row_stops_the_finalization() {
    let harness = WriterHarness::with_incident();
    let source = harness.source();
    let proof = harness.proof_for(ReauthPurpose::Finalize);

    harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .expect("mit gesetzter Profilzeile MUSS derselbe Bestand tragen");

    harness.remove_operator_profile();

    let code = harness
        .service(&source)
        .preview(&proof, valid_incident(), harness.observed_now())
        .map_or_else(
            |error| error.code(),
            |_| panic!("eine fehlende Profilzeile MUSS fail-closed abweisen"),
        );
    assert_eq!(code, "EA-OPERATOR-PROFILE-MISSING");

    nothing_became_durable(&harness, 0);
    assert!(!harness.incident_number_is_taken(FIXTURE_INCIDENT_NUMBER));
}
