//! Die Zeugen des Writer-Uebergangs (Stufe 5, Task 5).
//!
//! Drei Zusagen tragen diese Datei:
//!
//! 1. **Kein zweiter Kodierer.** Die Nutzlast, die der Dienst vorbereitet,
//!    wird gegen die Nutzlast gehalten, die die `ea-trust`-Fixture fuer
//!    DENSELBEN Uebergang gebaut hat — und gegen den EINEN Kodierer
//!    `TrustPayloadV1::writer_transition`. Ein Zeuge, der die Felder selbst
//!    kodierte, maesse sich selbst.
//! 2. **Die Zeremonie ist ECHT.** Das Transitionsobjekt entsteht ueber
//!    `RootCeremonyService::publish_authorized_target` mit dem
//!    Wurzelschluessel der Linie, dem echten Bedienernachweis und dem echten
//!    Auditdienst; die Aktivierung bindet die BYTES, die dabei herauskamen.
//! 3. **Der Kern hat das letzte Wort.** Das geplante Ereignis wird als Kopf
//!    in die Linie gelegt und der Nachfolgekopf ueber
//!    `ea_trust::verify_registry_candidate` → `select_registry_head` gewaehlt:
//!    erst wenn DER den neuen Writer als laufenden Writer fuehrt, hat der
//!    Uebergang stattgefunden.
#![allow(clippy::too_many_lines)]

/// Die Kulisse der Zeremonienzeugen, unveraendert weiterverwendet.
#[path = "support/mod.rs"]
mod support;

use std::sync::{Arc, Mutex};

use ea_admin::{
    RegistryWindow, VerifiedLocalDeviceIdentity,
    registry::RegistryEventFactory,
    writer_transition::{
        PreparedWriterTransition, TrustedChainHead, WriterTransitionError, WriterTransitionRequest,
        WriterTransitionRequestError, WriterTransitionService,
    },
};
use ea_crypto::object_hash;
use ea_format::{
    DecodedTrustPayloadV1, ParsedArchiveObject, RegistryChangeV1, TrustPayloadV1, TrustSubtypeV1,
    decode_exact_object,
};
use ea_operator::ReauthPurpose;
use ea_trust::{SelectedRegistryHead, verify_intended_trust_target};
use ea_types::{
    CertificateHash, ChainSequence, EntryHash, ObjectHash, RegistryVersion, UnixMillis,
};
use support::{
    AuditHarness, FIXTURE_NOW_MS, FIXTURE_TRANSITION_REASON_CODE, FixtureKeyProvider,
    PersistentStore, ReplayTable, TRANSITION_EFFECTIVE_FROM, TRANSITION_PRE_HEAD,
    TRANSITION_PROPOSED_SEQUENCE, TRANSITION_TRUSTED_SEQUENCE, TransitionCeremonyLine,
    ceremony_proof, ceremony_service, selected_head_at, trust_support,
    writer_transition_ceremony_line,
};
use trust_support::{ActionSpec, ChangeOverride, HeadOptions, hash32};

/// Der Hash des letzten Eintrags des alten Writers — vom Zeugen gewaehlt,
/// nicht der Platzhalter der Fixture.
fn previous_entry_hash() -> EntryHash {
    EntryHash::from(hash32(0x77))
}

/// Die Zeitgrenze des Uebergangskopfes — dieselbe wie die der uebrigen
/// Koepfe der Linie.
const TRANSITION_NOT_AFTER_MS: i64 = 10_000_000;

/// Das Fenster des Uebergangskopfes: Lease `[effective_from, 200]`.
fn window(effective_from: u64) -> RegistryWindow {
    RegistryWindow {
        effective_from_sequence: ChainSequence::new(effective_from),
        valid_through_sequence: ChainSequence::new(200),
        not_after: UnixMillis::new(TRANSITION_NOT_AFTER_MS),
    }
}

fn unknown_certificate() -> CertificateHash {
    CertificateHash::from(ObjectHash::from(hash32(0x99)))
}

fn expect_code(error: WriterTransitionError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

/// Die Kulisse eines Zeugen: Linie, gewaehlter Kopf vor dem Uebergang und
/// der Antrag, den die Autorisierung der Fixture deckt.
struct Scene {
    fixture: TransitionCeremonyLine,
    head: SelectedRegistryHead,
}

impl Scene {
    fn new() -> Self {
        let fixture = writer_transition_ceremony_line(previous_entry_hash());
        let head = selected_head_at(
            &fixture.ceremony.line,
            TRANSITION_PRE_HEAD,
            TRANSITION_PROPOSED_SEQUENCE,
        );
        assert!(
            head.current_writer_certificate_hash() == Some(fixture.old_writer_certificate_hash),
            "vor dem Uebergang laeuft der alte Writer"
        );
        assert!(head.effective_writer_transition().is_none());
        Self { fixture, head }
    }

    fn request(&self) -> WriterTransitionRequest {
        WriterTransitionRequest {
            old_writer_certificate_hash: self.fixture.old_writer_certificate_hash,
            new_writer_certificate_hash: self.fixture.new_writer_certificate_hash,
            trusted_head: TrustedChainHead {
                chain_sequence: ChainSequence::new(TRANSITION_TRUSTED_SEQUENCE),
                entry_hash: self.fixture.previous_entry_hash,
            },
            reason_code: FIXTURE_TRANSITION_REASON_CODE,
        }
    }

    fn service(&self) -> WriterTransitionService<'_> {
        WriterTransitionService::new(&self.head)
    }

    fn authorization_hash(&self) -> ObjectHash {
        self.fixture.ceremony.authorization_object_hash
    }

    fn prepared(&self) -> PreparedWriterTransition {
        self.service()
            .prepare(&self.request(), self.authorization_hash())
            .expect("der Uebergang vom laufenden auf den freigegebenen Writer ist vorbereitbar")
    }

    fn prepare_code(&self, request: &WriterTransitionRequest) -> &'static str {
        self.service()
            .prepare(request, self.authorization_hash())
            .err()
            .expect("der Antrag muss abgewiesen werden")
            .code()
    }

    fn audit(&self) -> AuditHarness {
        AuditHarness::new(
            &self.head,
            self.fixture.ceremony.writer_certificate_object_hash,
            0,
        )
    }

    /// Die lokale Geraeteidentitaet der Ereignisfabrik: der alte Writer, der
    /// am gewaehlten Kopf aktiv ist.
    fn local_device(&self) -> VerifiedLocalDeviceIdentity {
        let certificate = self.fixture.old_writer_certificate_hash;
        let device = self
            .head
            .active_certificate_fields(certificate)
            .expect("der alte Writer ist am gewaehlten Kopf aktiv")
            .device_id;
        VerifiedLocalDeviceIdentity::verify(&self.head, certificate, device)
            .expect("der alte Writer ist die lokale Geraeteidentitaet")
    }

    /// Die Wurzelzeremonie ueber die Nutzlast des DIENSTES: echter Nachweis,
    /// echter Auditdienst, Wurzelschluessel der Linie. Gibt die exakten
    /// veroeffentlichten Bytes heraus.
    fn publish(&self, prepared: &PreparedWriterTransition) -> Vec<u8> {
        let trust = support::verified(&self.fixture.ceremony.line);
        let intent = verify_intended_trust_target(
            &trust,
            Some(&self.head),
            prepared.payload(),
            UnixMillis::new(FIXTURE_NOW_MS),
            self.head.proposed_sequence(),
        )
        .expect("die vorbereitete Autorisierung deckt die vorbereitete Nutzlast");
        let provider = FixtureKeyProvider::root();
        let audit = self.audit();
        let ceremony = ceremony_service(&self.head, &provider, &audit, &self.fixture.ceremony);
        let proof = ceremony_proof(
            &self.fixture.ceremony,
            &self.head,
            ReauthPurpose::AdminRootCeremony,
        );
        let table = Arc::new(Mutex::new(ReplayTable::default()));
        let mut store = PersistentStore::open(&table);
        let authorization_bytes = self.fixture.ceremony.authorization_bytes().to_vec();
        let published = ceremony
            .publish_authorized_target(
                &intent,
                prepared.payload().clone(),
                &authorization_bytes,
                &mut store,
                &proof,
            )
            .expect("die Zeremonie veroeffentlicht den Uebergang");
        assert_eq!(audit.booked().len(), 1, "die Zeremonie bucht ihre Zeile");
        published.as_bytes().to_vec()
    }

    /// Ein Uebergang, wie die FIXTURE ihn Wurzel-signiert — auf einem Zweig
    /// der Linie, der gewaehlte Kopf bleibt unberuehrt.
    ///
    /// Die Fixture stellt dafuer eine EIGENE Autorisierung aus: dieselben
    /// Felder, ein anderer Autorisierungshash in der Nutzlast.
    fn fixture_transition_bytes(&mut self, previous_entry_hash: EntryHash) -> Vec<u8> {
        let head = self.fixture.ceremony.line.add_branch(
            ActionSpec::WriterTransition {
                old_writer: self.fixture.ceremony.writer_certificate_object_hash,
                new_writer: self.fixture.new_writer_certificate_object_hash,
                effective_from: None,
            },
            HeadOptions {
                writer_transition_previous_entry_hash: Some(previous_entry_hash),
                ..HeadOptions::default()
            },
        );
        self.fixture
            .ceremony
            .line
            .exact_object_bytes(
                head.direct_object_hash
                    .expect("der Uebergang der Fixture ist ein direktes Ziel"),
            )
            .to_vec()
    }
}

// ---------------------------------------------------------------------------
// 1. Die Vorbereitung
// ---------------------------------------------------------------------------

#[test]
fn prepare_binds_the_trusted_head_and_encodes_through_the_one_encoder() {
    let scene = Scene::new();
    let prepared = scene.prepared();

    let fields = prepared.fields();
    assert_eq!(
        fields.effective_from_sequence,
        ChainSequence::new(TRANSITION_EFFECTIVE_FROM),
        "der neue Writer schreibt ab der Sequenz NACH dem abgeglichenen Kopf"
    );
    assert_eq!(
        prepared.effective_from_sequence(),
        fields.effective_from_sequence
    );
    assert!(fields.previous_entry_hash == previous_entry_hash());
    assert!(fields.old_writer_certificate_hash == scene.fixture.old_writer_certificate_hash);
    assert!(fields.new_writer_certificate_hash == scene.fixture.new_writer_certificate_hash);
    assert_eq!(fields.reason_code, FIXTURE_TRANSITION_REASON_CODE);
    assert!(fields.organization_id == trust_support::organization());
    assert!(fields.chain_id == scene.head.chain_id());

    // Die Nutzlast ist die des EINEN Kodierers ...
    let expected = TrustPayloadV1::writer_transition(fields.clone(), scene.authorization_hash())
        .expect("die Felder erfuellen ihre Grammatik");
    assert_eq!(
        prepared.payload().subtype(),
        TrustSubtypeV1::WriterTransition
    );
    assert!(prepared.payload() == &expected);
    // ... und Byte fuer Byte die, die die Fixture fuer denselben Uebergang
    // gebaut hat — zwei Erzeuger, dieselben Bytes.
    assert!(prepared.payload() == &scene.fixture.ceremony.target_payload);

    // Und der Beweiszustand der Zeremonie deckt genau diese Nutzlast.
    let trust = support::verified(&scene.fixture.ceremony.line);
    verify_intended_trust_target(
        &trust,
        Some(&scene.head),
        prepared.payload(),
        UnixMillis::new(FIXTURE_NOW_MS),
        scene.head.proposed_sequence(),
    )
    .expect("die vorbereitete Autorisierung deckt die vorbereitete Nutzlast");
}

// ---------------------------------------------------------------------------
// 2. Der volle Ablauf: vorbereiten → Zeremonie → aktivieren → Nachfolgekopf
// ---------------------------------------------------------------------------

#[test]
fn the_full_transition_moves_the_current_writer_on_the_successor_head() {
    let mut scene = Scene::new();
    let request = scene.request();
    let prepared = scene.prepared();
    let published = scene.publish(&prepared);
    let transition_hash = object_hash(&published);

    // Die Aktivierung bindet die VEROEFFENTLICHTEN Bytes.
    let audit = scene.audit();
    let events = RegistryEventFactory::new(&scene.head, audit.service(), scene.local_device());
    let activated = scene
        .service()
        .activate(
            &prepared,
            &published,
            &events,
            window(TRANSITION_EFFECTIVE_FROM),
        )
        .expect("die veroeffentlichten Bytes sind der vorbereitete Uebergang");
    assert!(activated.transition_object_hash() == transition_hash);
    let event = activated.event().clone();
    assert!(matches!(
        event.change,
        RegistryChangeV1::WriterTransition { object_hash } if object_hash == transition_hash
    ));
    assert_eq!(
        event.effective_from_sequence,
        ChainSequence::new(TRANSITION_EFFECTIVE_FROM)
    );
    assert_eq!(
        event.registry_version,
        RegistryVersion::new(scene.head.registry_version().get() + 1)
    );
    assert!(event.policy_object_hash == scene.head.policy_object_hash());

    // Der Kern: das Transitionsobjekt und ein Kopf mit GENAU dem geplanten
    // Ereignis wandern in die Linie. Die Fixture signiert das Ereignis und
    // stellt seine Autorisierung aus; `ChangeOverride::Raw` laesst es die
    // Aenderung des Dienstes tragen, das eigene Zielobjekt der Fixture bleibt
    // aus dem Katalog fort.
    let line = &mut scene.fixture.ceremony.line;
    line.add_object(published.clone());
    let successor = line.push(
        ActionSpec::WriterTransition {
            old_writer: scene.fixture.ceremony.writer_certificate_object_hash,
            new_writer: scene.fixture.new_writer_certificate_object_hash,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(event.effective_from_sequence.get()),
            valid_through: Some(event.valid_through_sequence.get()),
            issued_at: event.issued_at,
            not_before: event.not_before,
            not_after: event.not_after,
            change_override: ChangeOverride::Raw(event.change.clone()),
            omit_direct_object: true,
            omit_direct_authorization: true,
            ..HeadOptions::default()
        },
    );
    // Das Ereignis der Linie IST das geplante — Feld fuer Feld.
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(line.exact_object_bytes(successor.object_hash))
            .expect("der Kopf der Linie ist wohlgeformt")
    else {
        panic!("der Kopf der Linie ist ein Trust-Objekt");
    };
    let DecodedTrustPayloadV1::RegistryEvent(core) = parsed
        .value()
        .decoded_payload()
        .expect("der Kopf traegt eine Registrierungsnutzlast")
    else {
        panic!("der Kopf ist ein Registrierungsereignis");
    };
    assert!(
        core.fields() == &event,
        "das Ereignis, das der Kern annimmt, ist Feld fuer Feld das geplante"
    );

    // Der Nachfolgekopf, vom Kern gewaehlt.
    let after = selected_head_at(line, TRANSITION_PRE_HEAD + 1, TRANSITION_EFFECTIVE_FROM);
    assert_eq!(after.registry_version(), event.registry_version);
    assert!(
        after.current_writer_certificate_hash() == Some(scene.fixture.new_writer_certificate_hash),
        "ab der Wirksamkeitssequenz laeuft der neue Writer"
    );
    let effective = after
        .effective_writer_transition()
        .expect("der Nachfolgekopf traegt den Uebergang");
    assert!(effective.object_hash() == transition_hash);
    assert!(effective.previous_entry_hash() == previous_entry_hash());
    assert!(effective.old_writer_certificate_hash() == scene.fixture.old_writer_certificate_hash);
    assert!(effective.new_writer_certificate_hash() == scene.fixture.new_writer_certificate_hash);
    assert_eq!(
        effective.effective_from_sequence(),
        ChainSequence::new(TRANSITION_EFFECTIVE_FROM)
    );
    assert!(
        after
            .active_certificate_fields(scene.fixture.old_writer_certificate_hash)
            .is_none(),
        "der alte Writer ist ab der Wirksamkeitssequenz widerrufen"
    );

    // Der alte Writer ist am Nachfolgekopf nicht mehr der laufende: derselbe
    // Antrag ist dort nicht mehr vorbereitbar.
    expect_code(
        WriterTransitionService::new(&after)
            .prepare(&request, scene.authorization_hash())
            .err()
            .expect("der alte Writer ist nicht mehr der laufende"),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT",
    );
}

// ---------------------------------------------------------------------------
// 3. Die Abweisungen der Vorbereitung
// ---------------------------------------------------------------------------

#[test]
fn an_old_writer_that_is_not_the_current_writer_is_refused() {
    let scene = Scene::new();

    // Ein Lesegeraet ist kein Writer.
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            old_writer_certificate_hash: scene.fixture.reader_certificate_hash,
            ..scene.request()
        }),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
    );
    // Der NEUE Writer ist freigegeben, aber nicht der laufende — auch er
    // kann nicht abgeben.
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            old_writer_certificate_hash: scene.fixture.new_writer_certificate_hash,
            new_writer_certificate_hash: scene.fixture.old_writer_certificate_hash,
            ..scene.request()
        }),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
    );
    // Ein unbekannter Hash erst recht nicht.
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            old_writer_certificate_hash: unknown_certificate(),
            ..scene.request()
        }),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
    );
}

#[test]
fn a_new_writer_that_is_not_approved_at_the_effective_sequence_is_refused() {
    let scene = Scene::new();

    // Ein Lesegeraet: bereichsaktiv, aber kein Writer-Zertifikat.
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            new_writer_certificate_hash: scene.fixture.reader_certificate_hash,
            ..scene.request()
        }),
        "EA-TRANSITION-NEW-WRITER-NOT-APPROVED"
    );
    // Ein Hash, den der Kopf nicht kennt.
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            new_writer_certificate_hash: unknown_certificate(),
            ..scene.request()
        }),
        "EA-TRANSITION-NEW-WRITER-NOT-APPROVED"
    );
    // Das neue Zertifikat wird erst an 81 wirksam: ein Uebergang, der schon
    // an 80 gelten soll, traefe einen Writer, der dort noch nicht freigegeben
    // ist. Die Grenze GENAU an der ersten erlaubten Stelle: ein Uebergang an
    // 81 trifft ihn.
    let new_effective_from = scene.fixture.new_writer_effective_from.get();
    let trusted_at = |chain_sequence: u64| WriterTransitionRequest {
        trusted_head: TrustedChainHead {
            chain_sequence: ChainSequence::new(chain_sequence),
            entry_hash: scene.fixture.previous_entry_hash,
        },
        ..scene.request()
    };
    assert_eq!(
        scene.prepare_code(&trusted_at(new_effective_from - 2)),
        "EA-TRANSITION-NEW-WRITER-NOT-APPROVED"
    );
    let at_the_boundary = scene
        .service()
        .prepare(
            &trusted_at(new_effective_from - 1),
            scene.authorization_hash(),
        )
        .expect("an seiner eigenen Wirksamkeitssequenz ist der neue Writer freigegeben");
    assert_eq!(
        at_the_boundary.effective_from_sequence(),
        scene.fixture.new_writer_effective_from
    );
}

#[test]
fn a_transition_onto_the_same_writer_is_refused() {
    let scene = Scene::new();
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            new_writer_certificate_hash: scene.fixture.old_writer_certificate_hash,
            ..scene.request()
        }),
        "EA-TRANSITION-SAME-WRITER"
    );
}

#[test]
fn a_trusted_head_at_the_end_of_the_sequence_space_is_refused() {
    let scene = Scene::new();
    assert_eq!(
        scene.prepare_code(&WriterTransitionRequest {
            trusted_head: TrustedChainHead {
                chain_sequence: ChainSequence::new(u64::MAX),
                entry_hash: scene.fixture.previous_entry_hash,
            },
            ..scene.request()
        }),
        "EA-TRANSITION-SEQUENCE-OVERFLOW"
    );
}

// ---------------------------------------------------------------------------
// 4. Die Abweisungen der Aktivierung
// ---------------------------------------------------------------------------

#[test]
fn activation_binds_only_the_bytes_of_the_prepared_transition() {
    let mut scene = Scene::new();
    let prepared = scene.prepared();

    // Die Kulisse ZUERST, weil sie die Linie um Zweige erweitert: der Kopf
    // ist laengst gewaehlt, die Zweige aendern ihn nicht — aber die Fabrik
    // unten borgt ihn.
    //
    // Ein ANDERES Trust-Objekt — die Policy der Linie, Wurzel-signiert und
    // im Katalog.
    let policy_hash = scene
        .fixture
        .ceremony
        .line
        .current_policy_hash()
        .expect("die Linie fuehrt eine Policy");
    let policy_bytes = scene
        .fixture
        .ceremony
        .line
        .exact_object_bytes(policy_hash)
        .to_vec();
    // Ein ECHTER Uebergang mit ANDEREN Feldern: die Fixture baut ihn
    // Wurzel-signiert mit einem anderen `previous_entry_hash`.
    let other_fields = scene.fixture_transition_bytes(EntryHash::from(hash32(0x78)));
    // Ein ECHTER Uebergang mit DENSELBEN Feldern unter einer ANDEREN
    // Autorisierung: die Nutzlast nennt ihren Autorisierungshash, und auch er
    // ist Teil dessen, was der Dienst vorbereitet hat.
    let other_authorization = scene.fixture_transition_bytes(previous_entry_hash());
    {
        let ParsedArchiveObject::Trust(parsed) =
            decode_exact_object(&other_authorization).expect("der Zweig ist wohlgeformt")
        else {
            panic!("der Zweig ist ein Trust-Objekt");
        };
        let DecodedTrustPayloadV1::WriterTransition(core) = parsed
            .value()
            .decoded_payload()
            .expect("der Zweig traegt seine Nutzlast")
        else {
            panic!("der Zweig ist ein writerTransition");
        };
        assert!(
            core.fields() == prepared.fields(),
            "die Kulisse: dieselben Felder"
        );
        assert!(
            core.authorization_object_hash() != scene.authorization_hash(),
            "die Kulisse: eine andere Autorisierung"
        );
    }

    let audit = scene.audit();
    let events = RegistryEventFactory::new(&scene.head, audit.service(), scene.local_device());
    let service = WriterTransitionService::new(&scene.head);
    let activate = |bytes: &[u8]| {
        service
            .activate(&prepared, bytes, &events, window(TRANSITION_EFFECTIVE_FROM))
            .err()
            .expect("diese Bytes sind nicht der vorbereitete Uebergang")
    };

    expect_code(activate(&policy_bytes), "EA-TRANSITION-OBJECT-MISMATCH");
    expect_code(activate(&[]), "EA-TRANSITION-OBJECT-MISMATCH");
    expect_code(activate(&other_fields), "EA-TRANSITION-OBJECT-MISMATCH");
    expect_code(
        activate(&other_authorization),
        "EA-TRANSITION-OBJECT-MISMATCH",
    );
}

#[test]
fn activation_refuses_a_window_that_does_not_start_at_the_effective_sequence() {
    let scene = Scene::new();
    let prepared = scene.prepared();
    let published = scene.publish(&prepared);
    let audit = scene.audit();
    let events = RegistryEventFactory::new(&scene.head, audit.service(), scene.local_device());
    let service = WriterTransitionService::new(&scene.head);

    for wrong in [TRANSITION_EFFECTIVE_FROM - 1, TRANSITION_EFFECTIVE_FROM + 1] {
        expect_code(
            service
                .activate(&prepared, &published, &events, window(wrong))
                .err()
                .expect("das Fenster muss an der Wirksamkeitssequenz beginnen"),
            "EA-TRANSITION-WINDOW-MISMATCH",
        );
    }
    // Der Gegenzeuge: das passende Fenster traegt.
    let activated = service
        .activate(
            &prepared,
            &published,
            &events,
            window(TRANSITION_EFFECTIVE_FROM),
        )
        .expect("das Fenster beginnt an der Wirksamkeitssequenz");
    assert!(activated.transition_object_hash() == object_hash(&published));
}

#[test]
fn registry_findings_keep_their_own_code() {
    let scene = Scene::new();
    let prepared = scene.prepared();
    let published = scene.publish(&prepared);
    let audit = scene.audit();
    let events = RegistryEventFactory::new(&scene.head, audit.service(), scene.local_device());

    // Ein Fenster, das an der Wirksamkeitssequenz beginnt, aber vor ihr
    // endet: der Dienst hat dazu nichts zu sagen, die Ereignisfabrik schon.
    let error = scene
        .service()
        .activate(
            &prepared,
            &published,
            &events,
            RegistryWindow {
                valid_through_sequence: ChainSequence::new(TRANSITION_EFFECTIVE_FROM - 1),
                ..window(TRANSITION_EFFECTIVE_FROM)
            },
        )
        .err()
        .expect("ein Lease, das vor seiner Wirksamkeitssequenz endet, ist keines");
    expect_code(error, "EA-OPERATOR-REGISTRY-WINDOW");
}

// ---------------------------------------------------------------------------
// 5. Die Antragsdatei
// ---------------------------------------------------------------------------

/// Ein eigenes, leeres Arbeitsverzeichnis unter dem Temp-Pfad des Systems.
fn tempdir(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "ea-admin-writer-transition-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("das Arbeitsverzeichnis muss anlegbar sein");
    directory
}

/// Die Antragsdatei, wie `apps/cli` sie entgegennimmt: vier Felder, die
/// Hashes als 64 Hex-Zeichen, der Kettenkopf als eigenes Objekt — und
/// wahlweise als fuenftes der Hash der erteilten Autorisierung.
fn request_document(old: &str, new: &str, chain_sequence: u64, entry: &str, reason: u64) -> String {
    format!(
        r#"{{"old_writer_certificate_hash":"{old}","new_writer_certificate_hash":"{new}","trusted_head":{{"chain_sequence":{chain_sequence},"entry_hash":"{entry}"}},"reason_code":{reason}}}"#
    )
}

fn with_authorization(document: &str, authorization: &str) -> String {
    format!(
        r#"{},"admin_authorization_object_hash":"{authorization}"}}"#,
        document.trim_end_matches('}')
    )
}

/// Die Datei des Zeugen fuer `Scene::request`, ohne Autorisierungshash.
fn scene_document(expected: &WriterTransitionRequest) -> String {
    request_document(
        &hex::encode(expected.old_writer_certificate_hash.as_bytes()),
        &hex::encode(expected.new_writer_certificate_hash.as_bytes()),
        expected.trusted_head.chain_sequence.get(),
        &hex::encode(expected.trusted_head.entry_hash.as_bytes()),
        expected.reason_code,
    )
}

fn assert_same_request(loaded: &WriterTransitionRequest, expected: &WriterTransitionRequest) {
    assert!(loaded.old_writer_certificate_hash == expected.old_writer_certificate_hash);
    assert!(loaded.new_writer_certificate_hash == expected.new_writer_certificate_hash);
    assert_eq!(
        loaded.trusted_head.chain_sequence,
        expected.trusted_head.chain_sequence
    );
    assert!(loaded.trusted_head.entry_hash == expected.trusted_head.entry_hash);
    assert_eq!(loaded.reason_code, expected.reason_code);
}

fn expect_request_code(error: WriterTransitionRequestError, expected: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(format!("{error:?}"), expected);
}

/// Die Datei OHNE Autorisierungshash kommt Feld fuer Feld als Antrag
/// zurueck, der Hash ist `None` — und der Antrag ist gegen den Kopf
/// vorbereitbar, also DERSELBE, den `Scene::request` baut.
#[test]
fn a_request_file_round_trips_into_the_request_the_service_accepts() {
    let scene = Scene::new();
    let expected = scene.request();
    let directory = tempdir("round-trip");
    let path = directory.join("transition.json");
    std::fs::write(&path, scene_document(&expected))
        .expect("die Antragsdatei muss schreibbar sein");

    let loaded = WriterTransitionRequest::load(&path).expect("die Antragsdatei muss laden");
    assert_same_request(&loaded.request, &expected);
    assert!(
        loaded.admin_authorization_object_hash.is_none(),
        "ohne das Feld gibt es keinen Hash"
    );

    let prepared = scene
        .service()
        .prepare(&loaded.request, scene.authorization_hash())
        .expect("der geladene Antrag ist der vorbereitbare Antrag");
    assert!(prepared.fields() == scene.prepared().fields());
}

/// Die Datei MIT Autorisierungshash liefert ihn daneben — und mit ihm bildet
/// der Dienst GENAU die Nutzlast, die die Zeremonie signiert: die
/// veroeffentlichten Bytes halten in `activate`.
#[test]
fn a_request_file_with_the_authorization_hash_prepares_the_payload_the_ceremony_signs() {
    let scene = Scene::new();
    let expected = scene.request();
    let directory = tempdir("round-trip-authorized");
    let path = directory.join("transition.json");
    std::fs::write(
        &path,
        with_authorization(
            &scene_document(&expected),
            &hex::encode(scene.authorization_hash().as_bytes()),
        ),
    )
    .expect("die Antragsdatei muss schreibbar sein");

    let loaded = WriterTransitionRequest::load(&path).expect("die Antragsdatei muss laden");
    assert_same_request(&loaded.request, &expected);
    let authorization = loaded
        .admin_authorization_object_hash
        .expect("die Datei nennt den Hash");
    assert!(authorization == scene.authorization_hash());

    let prepared = scene
        .service()
        .prepare(&loaded.request, authorization)
        .expect("der geladene Antrag ist vorbereitbar");
    assert!(prepared.payload() == scene.prepared().payload());
    let published = scene.publish(&prepared);
    let audit = scene.audit();
    let events = RegistryEventFactory::new(&scene.head, audit.service(), scene.local_device());
    let activated = scene
        .service()
        .activate(
            &prepared,
            &published,
            &events,
            window(TRANSITION_EFFECTIVE_FROM),
        )
        .expect("mit dem Hash der Datei halten die veroeffentlichten Bytes");
    assert!(activated.transition_object_hash() == object_hash(&published));

    // Der Gegenzeuge: mit dem Platzhalter halten dieselben Bytes NICHT.
    let placeholder = scene
        .service()
        .prepare(&loaded.request, ObjectHash::from(hash32(0x00)))
        .expect("auch mit Platzhalter ist der Antrag vorbereitbar");
    expect_code(
        scene
            .service()
            .activate(
                &placeholder,
                &published,
                &events,
                window(TRANSITION_EFFECTIVE_FROM),
            )
            .err()
            .expect("ein anderer Autorisierungshash ist ein anderes Objekt"),
        "EA-TRANSITION-OBJECT-MISMATCH",
    );
}

/// Auch der Autorisierungshash muss 64 Hex-Zeichen sein.
#[test]
fn a_request_file_with_a_short_authorization_hash_is_refused_as_shape() {
    let directory = tempdir("short-authorization");
    let path = directory.join("transition.json");
    let full = "11".repeat(32);
    std::fs::write(
        &path,
        with_authorization(
            &request_document(&full, &full, 7, &full, 1),
            &"44".repeat(31),
        ),
    )
    .expect("die Antragsdatei muss schreibbar sein");
    expect_request_code(
        WriterTransitionRequest::load(&path)
            .err()
            .expect("ein kurzer Autorisierungshash ist ein Formfehler"),
        "EA-TRANSITION-REQUEST-SHAPE",
    );
}

/// Ein Feld, das der Antrag nicht kennt, ist ein Formfehler — dieselbe
/// Strenge wie `deny_unknown_fields` der Bedienerdatei.
#[test]
fn a_request_file_with_an_unknown_field_is_refused_as_shape() {
    let directory = tempdir("unknown-field");
    let path = directory.join("transition.json");
    let mut document = request_document(&"11".repeat(32), &"22".repeat(32), 7, &"33".repeat(32), 1);
    document.insert_str(1, r#""organization_id":"4444","#);
    std::fs::write(&path, document).expect("die Antragsdatei muss schreibbar sein");
    expect_request_code(
        WriterTransitionRequest::load(&path)
            .err()
            .expect("ein unbekanntes Feld ist ein Formfehler"),
        "EA-TRANSITION-REQUEST-SHAPE",
    );
}

/// Ein Hash mit weniger als 64 Hex-Zeichen ist ein Formfehler — fuer jedes
/// der drei Hashfelder, und ebenso ein Nicht-Hex-Wert voller Laenge.
#[test]
fn a_request_file_with_a_short_or_non_hex_hash_is_refused_as_shape() {
    let directory = tempdir("short-hash");
    let path = directory.join("transition.json");
    let full = "11".repeat(32);
    let short = "11".repeat(31);
    let non_hex = "zz".repeat(32);
    for document in [
        request_document(&short, &full, 7, &full, 1),
        request_document(&full, &short, 7, &full, 1),
        request_document(&full, &full, 7, &short, 1),
        request_document(&non_hex, &full, 7, &full, 1),
    ] {
        std::fs::write(&path, document).expect("die Antragsdatei muss schreibbar sein");
        expect_request_code(
            WriterTransitionRequest::load(&path)
                .err()
                .expect("ein kurzer Hash ist ein Formfehler"),
            "EA-TRANSITION-REQUEST-SHAPE",
        );
    }
}

/// Eine Datei, die es nicht gibt, ist kein Formfehler, sondern unlesbar.
#[test]
fn a_missing_request_file_is_refused_as_unreadable() {
    let directory = tempdir("missing-file");
    expect_request_code(
        WriterTransitionRequest::load(&directory.join("absent.json"))
            .err()
            .expect("eine fehlende Datei ist unlesbar"),
        "EA-TRANSITION-REQUEST-UNREADABLE",
    );
}
