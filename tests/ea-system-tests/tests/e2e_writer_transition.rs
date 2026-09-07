//! Der Writer-Uebergang von der Verwaltung bis zum Server — in EINEM Prozess.
//!
//! Stufe 5, Task 5, die Zusammenschau, die keine Crate allein hat
//! (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
//! Luecke 4): `ea-admin` bereitet vor und aktiviert, die Wurzelzeremonie
//! signiert, der Kern waehlt den Nachfolgekopf, der NEUE Writer finalisiert
//! seinen `keyTransition` ueber `ea-writer`, und `ea_sync_server::validate_commit`
//! haelt die Eintraege beider Writer gegen den ECHTEN `SelectedRegistryHead`.
//!
//! # Was hier gemessen wird — und was nicht
//!
//! Drei Tore: der Writer lokal (`EA-WRITER-REVOKED`,
//! `EA-WRITER-TRANSITION-REQUIRED`, `EA-WRITER-TRANSITION-MISMATCH`), der Kern
//! (nur der Nachfolgekopf fuehrt den neuen Writer) und der Server
//! (`EA-COMMIT-WRITER-REVOKED` als Security Event,
//! `EA-COMMIT-WRITER-TRANSITION` als Formatbefund). Der Server wird an seiner
//! REGEL gemessen: `validate_commit` ist je Anfrage, ohne Ablage, ohne
//! Sequenzsperre. Die atomare Ablage — wer die Sequenz zuerst bekommt —
//! bezeugt `crates/ea-sync-server/tests/commit_service.rs`; `ea-verify` hat
//! seinen eigenen Zeugen (`crates/ea-verify/tests/writer_transition.rs`) und
//! wird hier nicht erreicht.
//!
//! Die Fixture haelt eine prozessweite Sperre je Writer-Geraet; kein Zeuge
//! braucht `--test-threads=1`.
#![allow(clippy::too_many_lines)]

#[path = "writer_transition_support/mod.rs"]
mod support;

use ea_admin::writer_transition::{TrustedChainHead, WriterTransitionService};
use ea_format::RegistryChangeV1;
use ea_schema::{PayloadV1, SCHEMA_VERSION_V1, SchemaRegistry};
use ea_sync_server::validation::CommitValidationError;
use ea_testkit::contains_canary;
use ea_trust::SelectedRegistryHead;
use ea_types::{ChainSequence, ObjectHash};

use support::{
    AdminTransition, FIXTURE_TRANSITION_REASON_CODE, OLD_WRITER_STALE_NUMBERS, OldWriterReplica,
    PublishedEntry, blocked_with, new_writer_finalizes_incident,
    new_writer_finalizes_key_transition, refused_with, resigned_with_transition_hash,
    run_admin_transition, validate_at_server,
    writer_support::{
        CANARY_TRANSITION_REASON, TransitionHarness, key_transition_input, other_incident,
        trust_support,
    },
};

/// Die Einsatznummer des ersten Einsatzes des NEUEN Writers (`other_incident`).
const NEW_WRITER_INCIDENT_NUMBER: &str = "2026-000043";

/// Ein Objekthash, den KEIN Objekt dieser Linie traegt.
fn foreign_transition_hash() -> ObjectHash {
    ObjectHash::from(trust_support::hash32(0x5e))
}

/// Die Kulisse nach dem Uebergang: der alte Writer hat Eintrag 0 geschrieben,
/// die Verwaltung hat den Uebergang ab Sequenz 1 vorbereitet, signieren
/// lassen und aktiviert, der Change 3 liegt in der Linie.
struct Scene {
    harness: TransitionHarness,
    first: ea_writer::FinalizeOutcome,
    admin: AdminTransition,
}

impl Scene {
    fn establish() -> Self {
        let mut harness = TransitionHarness::new();
        let first = harness.old_writer_finalizes_first_entry();
        assert_eq!(first.sequence, ChainSequence::new(0));
        let admin = run_admin_transition(
            &mut harness,
            TrustedChainHead {
                chain_sequence: first.sequence,
                entry_hash: first.entry_hash,
            },
        );
        Self {
            harness,
            first,
            admin,
        }
    }

    /// Der Nachfolgekopf — vom Kern gewaehlt, fuer `proposed`.
    fn successor(&self, proposed: u64) -> SelectedRegistryHead {
        let head = self.harness.post_transition_head(proposed);
        assert!(
            head.current_writer_certificate_hash()
                == Some(self.harness.new_writer_certificate_hash()),
            "ab der Wirksamkeitssequenz laeuft der neue Writer"
        );
        assert!(
            head.effective_writer_transition()
                .is_some_and(|t| t.object_hash() == self.admin.transition_hash),
            "der Nachfolgekopf traegt GENAU den veroeffentlichten Uebergang"
        );
        head
    }

    /// Der STALE Kopf des alten Writers — die Linie ohne Change 3.
    fn stale(&self, proposed: u64) -> SelectedRegistryHead {
        let head = self.harness.pre_transition_head(proposed);
        assert!(head.effective_writer_transition().is_none());
        assert!(
            head.current_writer_certificate_hash()
                == Some(self.harness.old_writer_certificate_hash()),
            "der stale Kopf kennt keinen Uebergang"
        );
        head
    }

    fn claims(&self) -> [ea_chain::CheckpointClaim; 1] {
        self.harness.checkpoint_claims_through(&self.first)
    }
}

// ---------------------------------------------------------------------------
// 1. Der volle Weg: Verwaltung → Zeremonie → Kern → neuer Writer
// ---------------------------------------------------------------------------

#[test]
fn first_new_writer_entry_binds_exact_transition_hash() {
    let scene = Scene::establish();
    let Scene {
        harness,
        first,
        admin,
    } = &scene;

    // Die Verwaltung: das Aenderung-3-Ereignis nennt GENAU die Bytes, die die
    // Zeremonie herausgegeben hat, ab der Sequenz nach dem vertrauten Kopf.
    assert!(admin.transition_hash == ea_crypto::object_hash(&admin.published));
    assert!(matches!(
        admin.event.change,
        RegistryChangeV1::WriterTransition { object_hash } if object_hash == admin.transition_hash
    ));
    assert_eq!(admin.event.effective_from_sequence, ChainSequence::new(1));
    assert_eq!(admin.head.version, admin.event.registry_version);

    // Der Kern: der Nachfolgekopf fuehrt den neuen Writer, den Uebergang mit
    // dem vertrauten Kopf als Vorgaenger, und den alten Writer nicht mehr.
    let head = scene.successor(1);
    assert_eq!(head.registry_version(), admin.event.registry_version);
    let effective = *head
        .effective_writer_transition()
        .expect("der Nachfolgekopf traegt den Uebergang");
    assert!(effective.previous_entry_hash() == first.entry_hash);
    assert!(effective.old_writer_certificate_hash() == harness.old_writer_certificate_hash());
    assert!(effective.new_writer_certificate_hash() == harness.new_writer_certificate_hash());
    assert_eq!(effective.effective_from_sequence(), ChainSequence::new(1));
    assert!(
        head.active_certificate_fields(harness.old_writer_certificate_hash())
            .is_none(),
        "der alte Writer ist ab der Wirksamkeitssequenz widerrufen"
    );
    // Derselbe Antrag ist am Nachfolgekopf nicht mehr vorbereitbar.
    assert_eq!(admin.request.reason_code, FIXTURE_TRANSITION_REASON_CODE);
    assert_eq!(
        WriterTransitionService::new(&head)
            .prepare(&admin.request, admin.authorization_object_hash)
            .err()
            .expect("der alte Writer ist nicht mehr der laufende")
            .code(),
        "EA-TRANSITION-OLD-WRITER-NOT-CURRENT"
    );

    // Der NEUE Writer: sein erster Eintrag ist der keyTransition, und sein
    // Manifest traegt GENAU den Objekthash der veroeffentlichten Bytes.
    let claims = scene.claims();
    let outcome = new_writer_finalizes_key_transition(harness, &head, &claims);
    assert_eq!(outcome.sequence, ChainSequence::new(1));
    let entry = harness.old().published_entry(outcome.entry_hash);
    let fields = entry.value().manifest().fields();
    assert!(fields.writer_transition_event_hash == Some(admin.transition_hash));
    assert!(fields.writer_certificate_hash == harness.new_writer_certificate_hash());
    assert!(fields.previous_entry_hash == Some(first.entry_hash));
    assert_eq!(fields.registry_version, head.registry_version());

    // Die versiegelte Nutzlast — gelesen wie ein Recovery-Empfaenger liest —
    // ist ein keyTransition mit demselben Hash und der Begruendung.
    let plaintext = harness.decrypt_entry_as_recovery_recipient(outcome.entry_hash);
    let validated = SchemaRegistry::v1()
        .validate("ea.key-transition", SCHEMA_VERSION_V1, &plaintext)
        .expect("die entschluesselte Nutzlast ist ein gueltiger keyTransition");
    let PayloadV1::KeyTransition(key_transition) = validated.payload() else {
        panic!("die Nutzlast ist kein keyTransition");
    };
    assert!(key_transition.writer_transition_event_object_hash() == admin.transition_hash);
    assert_eq!(
        key_transition.organizational_reason(),
        CANARY_TRANSITION_REASON
    );
    for (path, bytes) in &harness.old().published_archive_bytes() {
        assert!(
            !contains_canary(bytes, CANARY_TRANSITION_REASON.as_bytes()),
            "die organisatorische Begruendung steht im Klartext in {path}"
        );
    }
    assert_eq!(harness.old().staged_object_count(), 0);
}

// ---------------------------------------------------------------------------
// 2. Der zurueckgespielte alte Writer: lokal UND am Server blockiert
// ---------------------------------------------------------------------------

#[test]
fn the_restored_old_writer_is_blocked_locally_and_at_the_server() {
    let scene = Scene::establish();
    let harness = &scene.harness;
    let claims = scene.claims();
    let now = harness.old().observed_now();
    let successor = scene.successor(1);
    let stale = scene.stale(1);

    // Lokal: waehlt der alte Writer den Nachfolgekopf, faellt er am
    // Writer-Waechter — vor jedem Nachweis, jeder Nummer, jedem Geheimnis.
    {
        let source = harness.old().source();
        let service = harness.old_writer_service(&source, &successor, &claims);
        // Der Nachweis stammt vom stalen Kopf: gegen den neuen ist die alte
        // Bindung nicht mehr aktiv, ein Nachweis dagegen nicht ausstellbar.
        let proof = harness.old_writer_proof(&stale);
        assert_eq!(
            blocked_with(
                service.preview(&proof, other_incident(), now),
                "der alte Writer ist auf dem Nachfolgekopf widerrufen",
            ),
            "EA-WRITER-REVOKED"
        );
        assert_eq!(
            blocked_with(
                service.preview_key_transition(
                    &proof,
                    key_transition_input(CANARY_TRANSITION_REASON),
                    now,
                ),
                "der alte Writer schreibt auch keinen keyTransition",
            ),
            "EA-WRITER-REVOKED"
        );
        let stale_preview = harness
            .old_writer_service(&source, &stale, &claims)
            .preview(&proof, other_incident(), now)
            .expect("auf dem stalen Kopf entsteht eine Vorschau");
        assert_eq!(
            blocked_with(
                service.finalize(&proof, other_incident(), &stale_preview, now),
                "die Neubewertung unter der Sperre weist den alten Writer ab",
            ),
            "EA-WRITER-REVOKED"
        );
        assert_eq!(harness.old().staged_object_count(), 0);
        assert!(
            !harness
                .old()
                .incident_number_is_taken(NEW_WRITER_INCIDENT_NUMBER)
        );
    }

    // Am Server: der alte Writer schreibt auf seiner Kopie des Bestands
    // gegen seinen stalen Kopf einen Eintrag an N+1 — lokal traegt das, der
    // stale Kopf kennt keinen Uebergang. Der Server haelt ihn gegen den
    // Nachfolgekopf.
    let replica = OldWriterReplica::taken_now(harness);
    let stale_entry = replica.old_writer_finalizes_incident(
        harness,
        &stale,
        &claims,
        OLD_WRITER_STALE_NUMBERS[0],
    );
    assert_eq!(stale_entry.sequence, ChainSequence::new(1));
    let published = PublishedEntry::read(replica.backend(), stale_entry.entry_hash);
    let fields = published.parsed.value().manifest().fields();
    assert!(fields.writer_certificate_hash == harness.old_writer_certificate_hash());
    assert!(fields.previous_entry_hash == Some(scene.first.entry_hash));
    assert!(fields.writer_transition_event_hash.is_none());
    assert_eq!(
        harness.old().published_entry_paths().len(),
        1,
        "der geteilte Bestand bleibt bei Eintrag 0"
    );

    let request = published.commit_request(&stale);
    let failure = refused_with(
        validate_at_server(
            &request,
            &published.parsed,
            &successor,
            harness.old_writer_certificate_hash(),
        ),
        "der widerrufene Writer darf am Server nicht schreiben",
    );
    assert_eq!(failure, CommitValidationError::WriterRevoked);
    assert_eq!(failure.code(), "EA-COMMIT-WRITER-REVOKED");
    assert!(
        failure.is_writer_violation(),
        "der widerrufene Writer ist ein Security Event"
    );

    // Gegenprobe: gegen den STALEN Kopf — den Kopf, den der alte Writer
    // selbst gewaehlt hat — bestuende dieselbe Anfrage. Die Blockade haengt
    // an der Kopfauswahl des Servers, nicht an den Bytes des Writers.
    let accepted = validate_at_server(
        &request,
        &published.parsed,
        &stale,
        harness.old_writer_certificate_hash(),
    )
    .expect("gegen den stalen Kopf ist der alte Writer noch der laufende");
    assert_eq!(accepted.chain_sequence, ChainSequence::new(1));
}

// ---------------------------------------------------------------------------
// 3. Nur der autorisierte neue Writer schreibt die Kette fort
// ---------------------------------------------------------------------------

#[test]
fn only_the_authorized_new_writer_advances_the_chain() {
    let scene = Scene::establish();
    let harness = &scene.harness;
    let claims = scene.claims();
    let head_1 = scene.successor(1);
    let head_2 = scene.successor(2);

    // Der alte Writer auf seiner Kopie — genommen, BEVOR der neue Writer
    // schreibt: die Kopie zeigt den Bestand, wie er ihn zuletzt gesehen hat.
    // Auf ihr schreibt er N+1 und N+2 gegen seine stalen Koepfe.
    let replica = OldWriterReplica::taken_now(harness);
    let stale_1 = replica.old_writer_finalizes_incident(
        harness,
        &scene.stale(1),
        &claims,
        OLD_WRITER_STALE_NUMBERS[0],
    );
    let stale_2 = replica.old_writer_finalizes_incident(
        harness,
        &scene.stale(2),
        &harness.checkpoint_claims_through(&stale_1),
        OLD_WRITER_STALE_NUMBERS[1],
    );
    assert_eq!(stale_2.sequence, ChainSequence::new(2));

    // Der neue Writer: keyTransition an N+1 — die VOLLE Serverpruefung bis
    // zur Vollstaendigkeit der Grants.
    let transition = new_writer_finalizes_key_transition(harness, &head_1, &claims);
    let transition_published = PublishedEntry::read(harness.old().backend(), transition.entry_hash);
    let validated = validate_at_server(
        &transition_published.commit_request(&head_1),
        &transition_published.parsed,
        &head_1,
        harness.new_writer_certificate_hash(),
    )
    .expect("der keyTransition des neuen Writers besteht Schritt 2 des Servers");
    assert_eq!(validated.chain_sequence, ChainSequence::new(1));
    assert!(validated.previous_entry_hash == Some(scene.first.entry_hash));
    assert!(
        validated.device_id
            == head_1
                .active_certificate_fields(harness.new_writer_certificate_hash())
                .expect("der neue Writer ist am Nachfolgekopf aktiv")
                .device_id,
        "die Geraetekennung kommt aus dem Zertifikat des neuen Writers im Kopf"
    );
    assert_eq!(
        validated.grant_object_hashes.len(),
        ea_writer::build_grant_plan(&head_1)
            .expect("der Nachfolgekopf verlangt einen baubaren Plan")
            .items()
            .len(),
        "genau ein Grant je aktivem Empfaenger"
    );
    assert_eq!(validated.grant_object_hashes.len(), 3);

    // Der neue Writer: ein Einsatz an N+2 — ohne Uebergangshash, und der
    // Server nimmt ihn an.
    let incident =
        new_writer_finalizes_incident(harness, &head_2, &claims, NEW_WRITER_INCIDENT_NUMBER);
    assert_eq!(incident.sequence, ChainSequence::new(2));
    let incident_published = PublishedEntry::read(harness.old().backend(), incident.entry_hash);
    let fields = incident_published.parsed.value().manifest().fields();
    assert!(fields.writer_transition_event_hash.is_none());
    assert!(fields.writer_certificate_hash == harness.new_writer_certificate_hash());
    assert!(fields.previous_entry_hash == Some(transition.entry_hash));
    let validated = validate_at_server(
        &incident_published.commit_request(&head_2),
        &incident_published.parsed,
        &head_2,
        harness.new_writer_certificate_hash(),
    )
    .expect("der Einsatz des neuen Writers besteht Schritt 2 des Servers");
    assert_eq!(validated.chain_sequence, ChainSequence::new(2));
    assert!(validated.previous_entry_hash == Some(transition.entry_hash));

    // Der alte Writer: beide stalen Eintraege werden abgewiesen — an N+1 wie
    // an N+2, jeweils gegen den fuer diese Sequenz gewaehlten Nachfolgekopf.
    for (stale, head) in [(&stale_1, &head_1), (&stale_2, &head_2)] {
        let published = PublishedEntry::read(replica.backend(), stale.entry_hash);
        let failure = refused_with(
            validate_at_server(
                &published.commit_request(&scene.stale(stale.sequence.get())),
                &published.parsed,
                head,
                harness.old_writer_certificate_hash(),
            ),
            "ein stale Eintrag des alten Writers schreibt die Kette nicht fort",
        );
        assert_eq!(failure, CommitValidationError::WriterRevoked);
        assert_eq!(failure.code(), "EA-COMMIT-WRITER-REVOKED");
    }
    assert_eq!(harness.old().published_entry_paths().len(), 3);
}

// ---------------------------------------------------------------------------
// 4. Fehlend, fremd oder zusaetzlich: an jedem erreichten Tor abgewiesen
// ---------------------------------------------------------------------------

#[test]
fn a_missing_or_foreign_transition_hash_is_refused_at_every_gate() {
    let scene = Scene::establish();
    let harness = &scene.harness;
    let claims = scene.claims();
    let now = harness.old().observed_now();
    let head_1 = scene.successor(1);

    // Das Writer-Tor, FEHLEND: an der Uebergangssequenz ist ein Einsatz —
    // ein Manifest ohne Hash — nicht zulaessig. Der Writer nimmt den Hash
    // von keinem Aufrufer entgegen; ein FREMDER Hash ist auf dem Writer-Weg
    // deshalb nicht konstruierbar und wird unten am Server gemessen.
    {
        let source = harness.old().source();
        let service = harness.new_writer_service(&source, &head_1, &claims);
        let proof = harness.new_writer_proof(&head_1);
        assert_eq!(
            blocked_with(
                service.preview(&proof, other_incident(), now),
                "ein Einsatz an der Uebergangssequenz ist kein Uebergang",
            ),
            "EA-WRITER-TRANSITION-REQUIRED"
        );
        assert_eq!(harness.old().staged_object_count(), 0);
    }
    let transition = new_writer_finalizes_key_transition(harness, &head_1, &claims);

    // Das Writer-Tor, ZUSAETZLICH: nach dem ersten Eintrag gibt es keinen
    // zweiten keyTransition — der wirksame Uebergang gilt fuer GENAU seine
    // Sequenz.
    let head_2 = scene.successor(2);
    {
        let source = harness.old().source();
        let service = harness.new_writer_service(&source, &head_2, &claims);
        let proof = harness.new_writer_proof(&head_2);
        assert_eq!(
            blocked_with(
                service.preview_key_transition(
                    &proof,
                    key_transition_input(CANARY_TRANSITION_REASON),
                    now,
                ),
                "ein zweiter keyTransition hat keinen wirksamen Uebergang",
            ),
            "EA-WRITER-TRANSITION-MISMATCH"
        );
    }
    let incident =
        new_writer_finalizes_incident(harness, &head_2, &claims, NEW_WRITER_INCIDENT_NUMBER);

    // Das Server-Tor: dieselben Eintraege, vom neuen Writer mit seinem
    // echten Schluessel nachsigniert — allein der Hash weicht ab.
    let provider = harness.new_writer_provider();
    let binding = harness.new_writer_binding();
    let transition_published = PublishedEntry::read(harness.old().backend(), transition.entry_hash);
    let incident_published = PublishedEntry::read(harness.old().backend(), incident.entry_hash);
    let cases: [(
        &str,
        &PublishedEntry,
        &SelectedRegistryHead,
        Option<ObjectHash>,
    ); 3] = [
        ("fehlend an N+1", &transition_published, &head_1, None),
        (
            "fremd an N+1",
            &transition_published,
            &head_1,
            Some(foreign_transition_hash()),
        ),
        (
            "zusaetzlich an N+2",
            &incident_published,
            &head_2,
            Some(scene.admin.transition_hash),
        ),
    ];
    for (label, original, head, hash) in cases {
        let bytes = resigned_with_transition_hash(&original.parsed, &provider, binding, hash);
        let entry = ea_sync_server::validation::parse_entry(&bytes)
            .expect("das nachsignierte Paket ist ein Eintragspaket");
        assert!(
            entry.value().entry_hash() != original.parsed.value().entry_hash(),
            "{label}: ein anderes Manifest ist ein anderer Eintrag"
        );
        assert!(
            entry
                .value()
                .manifest()
                .fields()
                .writer_transition_event_hash
                == hash
        );
        let failure = refused_with(
            validate_at_server(
                &original.commit_request_with_entry(head, bytes),
                &entry,
                head,
                harness.new_writer_certificate_hash(),
            ),
            "der Server nimmt einen unpassenden Uebergangshash nicht an",
        );
        assert_eq!(
            failure,
            CommitValidationError::WriterTransitionMismatch,
            "{label}"
        );
        assert_eq!(failure.code(), "EA-COMMIT-WRITER-TRANSITION", "{label}");
        assert!(
            !failure.is_writer_violation(),
            "{label}: ein Formatbefund des zulaessigen Writers, kein Security Event"
        );
    }

    // Gegenprobe: die UNVERAENDERTEN Eintraege bestehen — der einzige
    // Unterschied zu den drei Faellen oben ist das eine Manifestfeld.
    for (original, head) in [
        (&transition_published, &head_1),
        (&incident_published, &head_2),
    ] {
        validate_at_server(
            &original.commit_request(head),
            &original.parsed,
            head,
            harness.new_writer_certificate_hash(),
        )
        .expect("der veroeffentlichte Eintrag des neuen Writers besteht");
    }
}

// ---------------------------------------------------------------------------
// 5. Alt und neu an DERSELBEN Sequenz
// ---------------------------------------------------------------------------

#[test]
fn only_the_new_writer_is_accepted_when_both_claim_the_same_sequence() {
    let scene = Scene::establish();
    let harness = &scene.harness;
    let claims = scene.claims();
    let successor = scene.successor(1);

    // Beide bereiten einen Eintrag an N+1 vor, jeder gegen SEINEN Kopf:
    // der alte auf seiner Kopie gegen den stalen Kopf — ZUERST —, der neue
    // auf dem geteilten Bestand gegen den Nachfolgekopf.
    let replica = OldWriterReplica::taken_now(harness);
    let stale = scene.stale(1);
    let old_entry = replica.old_writer_finalizes_incident(
        harness,
        &stale,
        &claims,
        OLD_WRITER_STALE_NUMBERS[0],
    );
    let new_entry = new_writer_finalizes_key_transition(harness, &successor, &claims);
    assert_eq!(old_entry.sequence, new_entry.sequence);
    assert!(old_entry.entry_hash != new_entry.entry_hash);

    let old_published = PublishedEntry::read(replica.backend(), old_entry.entry_hash);
    let new_published = PublishedEntry::read(harness.old().backend(), new_entry.entry_hash);
    assert!(
        old_published
            .parsed
            .value()
            .manifest()
            .fields()
            .previous_entry_hash
            == new_published
                .parsed
                .value()
                .manifest()
                .fields()
                .previous_entry_hash,
        "beide nennen denselben Vorgaenger — den letzten Eintrag des alten Writers"
    );
    let old_request = old_published.commit_request(&stale);
    let new_request = new_published.commit_request(&successor);

    // Die Pruefung ist je Anfrage: der alte wird abgewiesen, obwohl er zuerst
    // eingereicht wird; der neue besteht. Was die REIHENFOLGE an der Ablage
    // entscheidet, bezeugt `commit_service.rs` — hier wird die Regel gemessen.
    let first_verdict = refused_with(
        validate_at_server(
            &old_request,
            &old_published.parsed,
            &successor,
            harness.old_writer_certificate_hash(),
        ),
        "der alte Writer wird auch als Erster nicht angenommen",
    );
    assert_eq!(first_verdict, CommitValidationError::WriterRevoked);
    assert_eq!(first_verdict.code(), "EA-COMMIT-WRITER-REVOKED");
    let accepted = validate_at_server(
        &new_request,
        &new_published.parsed,
        &successor,
        harness.new_writer_certificate_hash(),
    )
    .expect("der neue Writer besteht an derselben Sequenz");
    assert_eq!(accepted.chain_sequence, ChainSequence::new(1));

    // In umgekehrter Reihenfolge dieselben Urteile: die Regel haengt nicht
    // daran, wer zuerst geprueft wurde.
    validate_at_server(
        &new_request,
        &new_published.parsed,
        &successor,
        harness.new_writer_certificate_hash(),
    )
    .expect("der neue Writer besteht auch nach dem alten");
    assert_eq!(
        refused_with(
            validate_at_server(
                &old_request,
                &old_published.parsed,
                &successor,
                harness.old_writer_certificate_hash(),
            ),
            "der alte Writer bleibt abgewiesen",
        ),
        CommitValidationError::WriterRevoked
    );

    // Der geteilte Bestand traegt an N+1 GENAU den Eintrag des neuen Writers.
    let paths = harness.old().published_entry_paths();
    assert_eq!(paths.len(), 2);
    assert!(
        paths
            .iter()
            .any(|path| path.contains(&hex::encode(new_entry.entry_hash.as_bytes())))
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.contains(&hex::encode(old_entry.entry_hash.as_bytes())))
    );
}
