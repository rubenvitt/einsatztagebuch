//! Persisted lifecycle audits must verify under the certificate they actually name.
#[path = "support/operator_lifecycle.rs"]
mod lifecycle;
mod support;

use ea_crypto::{SignerRole, VerificationContext, verify_cose_sign1};
use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1, decode_local_audit_event};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, ObjectHash};
use lifecycle::*;

fn certificate_hash(certificate: CertificateHash) -> ObjectHash {
    ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap()
}

fn signature_verifies(bytes: &[u8], head: &SelectedRegistryHead, role: SignerRole) -> bool {
    let row = ea_format::decode_local_audit_event(bytes).unwrap();
    let mut decoder = minicbor::Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(2));
    decoder.skip().unwrap();
    let signature_start = decoder.position();
    decoder.skip().unwrap();
    let signature = &bytes[signature_start..decoder.position()];
    let context = VerificationContext::local_audit(
        row.exact_core(),
        head.proposed_sequence(),
        role,
        head.registry_version(),
    )
    .unwrap();
    verify_cose_sign1(signature, head, &context).is_ok()
}

#[test]
fn persisted_login_signature_matches_its_named_writer_certificate() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let authenticator = h.authenticator(&head);
    h.service(&head, audit.service())
        .verify_session(h.login(&authenticator))
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    assert!(signature_verifies(&rows[0], &head, SignerRole::Writer));
    let row = decode_local_audit_event(&rows[0]).unwrap();
    assert!(row.signer_certificate_object_hash() == certificate_hash(h.certificate));
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Completed);
    let LocalAuditActionV1::Login(context) = row.action() else {
        panic!("login expected")
    };
    assert!(context.subject_object_hash() == Some(h.binding));
}

#[test]
fn failed_login_and_reauth_have_valid_device_signatures_and_the_known_binding() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let mut authenticator = h.authenticator(&head);
    authenticator.fail = true;
    assert!(
        h.service(&head, audit.service())
            .verify_session(h.login(&authenticator))
            .is_err()
    );
    let rows = audit.booked();
    assert_eq!(rows.len(), 2);
    for (index, bytes) in rows.iter().enumerate() {
        assert!(signature_verifies(bytes, &head, SignerRole::Writer));
        let row = decode_local_audit_event(bytes).unwrap();
        assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
        assert!(row.operator_binding_object_hash() == Some(h.binding));
        assert!(row.signer_certificate_object_hash() == certificate_hash(h.certificate));
        let context = match (index, row.action()) {
            (0, LocalAuditActionV1::Login(context))
            | (1, LocalAuditActionV1::ReauthFailure(context)) => context,
            _ => panic!("exact failure action order expected"),
        };
        assert!(context.subject_object_hash() == Some(h.binding));
    }
}

#[test]
fn unknown_requested_binding_is_audited_without_attributing_it_to_an_operator() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let authenticator = h.authenticator(&head);
    let mut request = h.login(&authenticator);
    request.binding_object_hash = ObjectHash::try_from(&[0xab; 32][..]).unwrap();
    assert!(
        head.active_operator_binding_fields(request.binding_object_hash)
            .is_none()
    );
    assert!(
        h.service(&head, audit.service())
            .verify_session(request)
            .is_err()
    );
    let rows = audit.booked();
    assert_eq!(rows.len(), 2);
    for bytes in rows {
        assert!(signature_verifies(&bytes, &head, SignerRole::Writer));
        let row = decode_local_audit_event(&bytes).unwrap();
        assert!(row.operator_binding_object_hash().is_none());
        assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
        match row.action() {
            LocalAuditActionV1::Login(context) | LocalAuditActionV1::ReauthFailure(context) => {
                assert!(context.subject_object_hash().is_none());
            }
            _ => panic!("expected failed login or reauth"),
        }
    }
}

#[test]
fn binding_and_revocation_audits_verify_exact_actor_targets_and_effective_sequence() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("audit-target");
    let native = Native::new();
    let mut authorization = h.authorization();
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity::valid(),
            &mut authorization,
        )
        .unwrap();
    let expected_sequence = registry_fields(prepared.activation_bytes()).effective_from_sequence;
    let rows = audit.booked();
    for bytes in &rows {
        assert!(signature_verifies(bytes, &head, SignerRole::Writer));
    }
    let binding_changes: Vec<_> = rows
        .iter()
        .map(|bytes| decode_local_audit_event(bytes).unwrap())
        .filter(|row| matches!(row.action(), LocalAuditActionV1::BindingChange(_)))
        .collect();
    assert_eq!(binding_changes.len(), 4);
    for row in &binding_changes {
        let LocalAuditActionV1::BindingChange(context) = row.action() else {
            unreachable!()
        };
        assert!(context.old_binding_object_hash().is_none());
        assert!(context.new_binding_object_hash() == Some(prepared.binding_object_hash()));
        assert_eq!(context.effective_from_sequence(), expected_sequence);
    }
    let row = &binding_changes[0];
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Accepted);
    let LocalAuditActionV1::BindingChange(context) = row.action() else {
        unreachable!()
    };
    assert!(context.old_binding_object_hash().is_none());
    assert!(context.new_binding_object_hash() == Some(prepared.binding_object_hash()));
    assert_eq!(context.effective_from_sequence(), expected_sequence);

    let active = authorization.activate(&prepared);
    let audit = h.audit(&active, 0);
    let revoked = h
        .revoke(
            &active,
            audit.service(),
            prepared.binding_object_hash(),
            &mut authorization,
        )
        .unwrap();
    let expected_sequence = registry_fields(revoked.registry_bytes()).effective_from_sequence;
    let rows = audit.booked();
    for bytes in &rows {
        assert!(signature_verifies(bytes, &active, SignerRole::Writer));
    }
    let revocations: Vec<_> = rows
        .iter()
        .map(|bytes| decode_local_audit_event(bytes).unwrap())
        .filter(|row| matches!(row.action(), LocalAuditActionV1::Revocation(_)))
        .collect();
    assert_eq!(revocations.len(), 1);
    let row = &revocations[0];
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Accepted);
    let LocalAuditActionV1::Revocation(context) = row.action() else {
        unreachable!()
    };
    assert!(context.old_binding_object_hash() == Some(prepared.binding_object_hash()));
    assert!(context.new_binding_object_hash().is_none());
    assert_eq!(context.effective_from_sequence(), expected_sequence);
}

#[test]
fn signature_verification_rejects_tampering_and_the_original_root_device_mismatch() {
    let h = Harness::new();
    let head = h.head();
    let authenticator = h.authenticator(&head);
    let audit = h.audit(&head, 0);
    h.service(&head, audit.service())
        .verify_session(h.login(&authenticator))
        .unwrap();
    let mut bytes = audit.booked().remove(0);
    assert!(signature_verifies(&bytes, &head, SignerRole::Writer));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(!signature_verifies(&bytes, &head, SignerRole::Writer));

    let mismatched = support::AuditHarness::with_provider(
        &head,
        certificate_hash(h.certificate),
        0,
        support::FixtureKeyProvider::root(),
    );
    assert_eq!(
        h.service(&head, mismatched.service())
            .verify_session(h.login(&authenticator))
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-AUDIT-FAILED"
    );
    assert!(!signature_verifies(
        &mismatched.booked()[0],
        &head,
        SignerRole::Writer
    ));
}

#[test]
fn sqlcipher_persisted_login_bytes_verify_after_reopening_the_database() {
    let h = Harness::new();
    let head = h.head();
    let authenticator = h.authenticator(&head);
    let audit = sql_audit(&head, &h.database, h.certificate);
    h.service(&head, &audit)
        .verify_session(h.login(&authenticator))
        .unwrap();
    drop(audit);
    let directory = h.directory;
    drop(h.database);
    let reopened = reopen_database(directory.path());
    let row = reopened
        .query_row("SELECT exact_bytes FROM local_audit_event", &[])
        .unwrap()
        .unwrap();
    let bytes = row.blob(0).unwrap();
    assert!(signature_verifies(bytes, &head, SignerRole::Writer));
    assert_eq!(
        decode_local_audit_event(bytes).unwrap().outcome(),
        LocalAuditOutcomeV1::Completed
    );
}

#[test]
fn recovery_admin_login_is_signed_by_its_own_admin_certificate() {
    let mut h = Harness::new();
    let admin = RecoveryAdmin::enroll(&mut h.line);
    let head = support::selected_head_at(&h.line, 3, 50);
    let audit = admin.audit(&head);
    let authenticator = admin.authenticator(&head);
    admin
        .service(&head, audit.service())
        .verify_session(admin.login(&authenticator))
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    assert!(signature_verifies(
        &rows[0],
        &head,
        SignerRole::OrganizationAdmin
    ));
    assert!(
        decode_local_audit_event(&rows[0])
            .unwrap()
            .signer_certificate_object_hash()
            == certificate_hash(admin.certificate)
    );
}

/// Die Klartextmerkmale eines gespeicherten Bedienerprofils: Anzeigename,
/// Funktionsbezeichnung und Profil-Salt, GELESEN aus der Profiltabelle und
/// nicht abgeschrieben — der Zeuge sucht nach dem, was wirklich gespeichert ist.
fn stored_profile_canaries(database: &ea_local_store::EncryptedDatabase) -> Vec<Vec<u8>> {
    let row = database
        .query_row(
            "SELECT display_name, function_label, profile_commitment_salt FROM operator_profile",
            &[],
        )
        .unwrap()
        .expect("das Bedienerprofil ist gespeichert");
    vec![
        row.text(0).unwrap().as_bytes().to_vec(),
        row.text(1).unwrap().as_bytes().to_vec(),
        row.blob(2).unwrap().to_vec(),
    ]
}

/// Findet `canary` roh oder hexkodiert (klein und groß) in `bytes`?
fn leaks(bytes: &[u8], canary: &[u8]) -> bool {
    assert!(
        !canary.is_empty(),
        "ein leerer Kanarienvogel bezeugt nichts"
    );
    let lower = hex::encode(canary);
    let upper = lower.to_uppercase();
    ea_testkit::contains_canary(bytes, canary)
        || ea_testkit::contains_canary(bytes, lower.as_bytes())
        || ea_testkit::contains_canary(bytes, upper.as_bytes())
}

/// AK 53, Widerruf: das Widerrufsaudit ist signiert und KLARTEXTFREI.
///
/// Kanarien sind Anzeigename, Funktionsbezeichnung und Profil-Salt BEIDER
/// Bedienerinnen — der handelnden und der widerrufenen — sowie beider
/// Kontokennungen. Eine Klarkontokennung (Benutzername, UID) erreicht
/// `ea-admin` in dieser Fixture gar nicht; die einzige Kontokennung ist der
/// `os_account_binding_hash`, und der wird deshalb gesucht.
///
/// GEGENPROBE gegen Leerlauf: dieselbe Suche FINDET den Bindungshash der
/// handelnden Bedienerin in derselben Zeile — der Heuhaufen ist also wirklich
/// die Auditzeile, und die Suche trifft, was dort steht.
#[test]
fn the_revocation_audit_carries_no_operator_plaintext() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    let target = database("revocation-canary-target");
    let native = Native::new();
    let mut authorization = h.authorization();
    let salt: [u8; 32] = std::array::from_fn(|index| 0xa5 ^ (index as u8).wrapping_mul(29));
    let prepared = h
        .provision(
            &head,
            &audit,
            &target.database,
            &native,
            &Identity {
                salt: Some(salt),
                ..Identity::valid()
            },
            &mut authorization,
        )
        .unwrap();
    let active = authorization.activate(&prepared);
    let audit = h.audit(&active, 0);
    h.revoke(
        &active,
        audit.service(),
        prepared.binding_object_hash(),
        &mut authorization,
    )
    .unwrap();

    let mut canaries = stored_profile_canaries(&h.database);
    let revoked = stored_profile_canaries(&target.database);
    assert!(
        revoked[2] == salt,
        "das Salt der widerrufenen Bedienerin ist das gesetzte"
    );
    canaries.extend(revoked);
    canaries.push(h.account.hash.as_bytes().to_vec());
    canaries.push(native.account.borrow().hash.as_bytes().to_vec());

    let rows = audit.booked();
    let revocations: Vec<_> = rows
        .iter()
        .filter(|bytes| {
            matches!(
                decode_local_audit_event(bytes).unwrap().action(),
                LocalAuditActionV1::Revocation(_)
            )
        })
        .collect();
    assert_eq!(revocations.len(), 1);
    assert!(signature_verifies(
        revocations[0],
        &active,
        SignerRole::Writer
    ));
    assert!(
        leaks(revocations[0], h.binding.as_bytes()),
        "Gegenprobe: die Suche findet, was in der Zeile steht"
    );
    for bytes in &rows {
        for canary in &canaries {
            assert!(
                !leaks(bytes, canary),
                "eine Auditzeile des Widerrufs trägt Klartext: {}",
                hex::encode(canary)
            );
        }
    }
}

/// AK 53, abgelaufene Sitzung: ein Nachweis, dessen Fünf-Minuten-Sitzung
/// abgelaufen ist, wird abgewiesen — und die Abweisung ist als signiertes,
/// klartextfreies Auditereignis gebucht.
///
/// Der Nachweis entsteht am gewählten Kopf zur Fixture-Zeit und wird am
/// SELBEN Kopf vorgelegt, dessen vertraute Zeit um genau
/// `MAX_INACTIVITY_MS` weitergerückt ist. Vorgelegt wird er dort, wo ein
/// mitgebrachter Nachweis tatsächlich gegen die Zeit geprüft wird: an der
/// Wurzelzeremonie (`RootCeremonyService::publish_authorized_target`).
///
/// DRK-282 (Ruling 19.09.2026): gebucht wird die eigene Aktion
/// `sessionExpired` (Code 12) mit dem Ausgang `failed`, VOR der Abweisung,
/// deren Code unverändert bleibt. Den Laufzeitpfad
/// (`OperatorRuntime::reauthenticate_with_context`) bezeugen
/// `the_runtime_expiry_row_is_device_signed_and_names_only_the_known_binding`
/// und der Modultest `only_an_expiry_is_booked_once_before_the_unchanged_refusal`.
#[test]
fn an_expired_operator_session_is_refused_and_audited_without_plaintext() {
    use ea_operator::{MAX_INACTIVITY_MS, ReauthPurpose};
    use support::{
        AuditHarness, FIXTURE_NOW_MS, FixtureKeyProvider, LAST_HEAD, PROPOSED_SEQUENCE,
        PersistentStore, ReplayTable, ceremony_line, ceremony_proof, ceremony_service,
        selected_head, selected_head_at_time,
    };

    let ceremony = ceremony_line();
    let opened = selected_head(&ceremony.line);
    let proof = ceremony_proof(&ceremony, &opened, ReauthPurpose::AdminRootCeremony);
    assert!(
        proof.is_valid_for(
            ReauthPurpose::AdminRootCeremony,
            opened.preexisting_effective_now()
        ),
        "Vorbedingung: beim Öffnen ist die Sitzung gültig"
    );
    let head = selected_head_at_time(
        &ceremony.line,
        LAST_HEAD,
        PROPOSED_SEQUENCE,
        FIXTURE_NOW_MS + MAX_INACTIVITY_MS,
    );
    assert!(
        !proof.is_valid_for(
            ReauthPurpose::AdminRootCeremony,
            head.preexisting_effective_now()
        ),
        "Vorbedingung: fünf Minuten später ist dieselbe Sitzung abgelaufen"
    );

    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::with_provider(
        &head,
        ceremony.writer_certificate_object_hash,
        0,
        FixtureKeyProvider::device(),
    );
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let table = std::sync::Arc::new(std::sync::Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    let authorization_bytes = ceremony.authorization_bytes().to_vec();
    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload(),
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .err()
        .expect("eine abgelaufene Sitzung autorisiert keine Zeremonie");
    assert_eq!(error.code(), "EA-CEREMONY-REAUTH-MISMATCH");
    assert_eq!(provider.signatures_produced(), 0);

    // DIE ZUSAGE: die Abweisung ist gebucht.
    let rows = audit.booked();
    assert!(
        !rows.is_empty(),
        "AK 53: eine abgelaufene Sitzung wird auditiert — gebucht wurde nichts"
    );
    // Die einzige Kontokennung der Fixture ist der `os_account_binding_hash`
    // der Bindung: `hash32(BINDING_MARKER + 2)` (`support::operator_proof`).
    let account = support::trust_support::hash32(0x71 + 2);
    for bytes in &rows {
        assert!(signature_verifies(bytes, &head, SignerRole::Writer));
        assert!(!leaks(bytes, account.as_bytes()));
    }
    // Als ABLAUF erkennbar: genau eine Zeile `sessionExpired` (Code 12) mit
    // dem Ausgang `failed`, zugerechnet der Bindung des Nachweises.
    assert_eq!(rows.len(), 1, "je Abweisung genau eine Zeile");
    let row = decode_local_audit_event(&rows[0]).unwrap();
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
    let LocalAuditActionV1::SessionExpired(context) = row.action() else {
        panic!("sessionExpired expected");
    };
    assert!(context.subject_object_hash() == Some(proof.binding_object_hash()));
    assert!(row.operator_binding_object_hash() == Some(proof.binding_object_hash()));
    assert!(row.effective_now() == head.preexisting_effective_now().value());

    // Kein Audit-Spam: ein zweiter Aufruf mit derselben abgelaufenen Sitzung
    // bucht genau eine weitere Zeile — je Aufruf eine, keine Schleife.
    let again = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload(),
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .err()
        .expect("auch beim zweiten Mal abgewiesen");
    assert_eq!(again.code(), "EA-CEREMONY-REAUTH-MISMATCH");
    assert_eq!(audit.booked().len(), 2);
}

/// AK 53, Gegenprobe zur Beschriftung: ein Nachweis für einen FREMDEN Zweck
/// ist abgelaufen UND falsch — die Zeremonie weist ihn ab, bucht aber keinen
/// Ablauf, weil der Grund nicht (nur) der Ablauf ist. Ein nicht abgelaufener
/// Nachweis des falschen Zwecks bucht ebenfalls nichts.
#[test]
fn a_foreign_purpose_proof_is_refused_without_an_expiry_row() {
    use ea_operator::{MAX_INACTIVITY_MS, ReauthPurpose};
    use support::{
        AuditHarness, FIXTURE_NOW_MS, FixtureKeyProvider, LAST_HEAD, PROPOSED_SEQUENCE,
        PersistentStore, ReplayTable, ceremony_line, ceremony_proof, ceremony_service,
        selected_head, selected_head_at_time,
    };

    let ceremony = ceremony_line();
    let opened = selected_head(&ceremony.line);
    let proof = ceremony_proof(&ceremony, &opened, ReauthPurpose::RecoveryTest);
    for now in [FIXTURE_NOW_MS, FIXTURE_NOW_MS + MAX_INACTIVITY_MS] {
        let head = selected_head_at_time(&ceremony.line, LAST_HEAD, PROPOSED_SEQUENCE, now);
        let intent = ceremony.intent(&head);
        let provider = FixtureKeyProvider::root();
        let audit = AuditHarness::with_provider(
            &head,
            ceremony.writer_certificate_object_hash,
            0,
            FixtureKeyProvider::device(),
        );
        let service = ceremony_service(&head, &provider, &audit, &ceremony);
        let table = std::sync::Arc::new(std::sync::Mutex::new(ReplayTable::default()));
        let mut store = PersistentStore::open(&table);
        let authorization_bytes = ceremony.authorization_bytes().to_vec();
        let error = service
            .publish_authorized_target(
                &intent,
                ceremony.target_payload(),
                &authorization_bytes,
                &mut store,
                &proof,
            )
            .err()
            .expect("ein fremder Zweck autorisiert keine Zeremonie");
        assert_eq!(error.code(), "EA-CEREMONY-REAUTH-MISMATCH");
        assert!(
            audit.booked().is_empty(),
            "ein fremder Zweck ist kein Ablauf"
        );
    }
}

/// AK 53, fail-closed: scheitert die Buchung des Ablaufs, bleibt es bei der
/// Abweisung mit ihrem bisherigen Code — nichts wird freigegeben.
#[test]
fn an_expired_session_stays_refused_when_its_audit_cannot_be_booked() {
    use ea_operator::{MAX_INACTIVITY_MS, ReauthPurpose};
    use support::{
        AuditHarness, FIXTURE_NOW_MS, FixtureKeyProvider, LAST_HEAD, PROPOSED_SEQUENCE,
        PersistentStore, ReplayTable, ceremony_line, ceremony_proof, ceremony_service,
        selected_head, selected_head_at_time,
    };

    let ceremony = ceremony_line();
    let opened = selected_head(&ceremony.line);
    let proof = ceremony_proof(&ceremony, &opened, ReauthPurpose::AdminRootCeremony);
    let head = selected_head_at_time(
        &ceremony.line,
        LAST_HEAD,
        PROPOSED_SEQUENCE,
        FIXTURE_NOW_MS + MAX_INACTIVITY_MS,
    );
    let intent = ceremony.intent(&head);
    let provider = FixtureKeyProvider::root();
    let audit = AuditHarness::with_provider(
        &head,
        ceremony.writer_certificate_object_hash,
        1,
        FixtureKeyProvider::device(),
    );
    let service = ceremony_service(&head, &provider, &audit, &ceremony);
    let table = std::sync::Arc::new(std::sync::Mutex::new(ReplayTable::default()));
    let mut store = PersistentStore::open(&table);
    let authorization_bytes = ceremony.authorization_bytes().to_vec();
    let error = service
        .publish_authorized_target(
            &intent,
            ceremony.target_payload(),
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .err()
        .expect("ohne Buchung erst recht keine Zeremonie");
    assert_eq!(error.code(), "EA-CEREMONY-REAUTH-MISMATCH");
    assert_eq!(provider.signatures_produced(), 0);
    assert!(audit.booked().is_empty());
}

/// AK 53, Laufzeitpfad: `OperatorRuntime::reauthenticate_with_context` bucht
/// über `OperatorBindingService::record_session_expired`, bevor es
/// `EA-OPERATOR-RUNTIME-EXPIRED` meldet. Die Zeile ist gerätesigniert, nennt
/// die bekannte Bindung als Hash und sonst nichts.
#[test]
fn the_runtime_expiry_row_is_device_signed_and_names_only_the_known_binding() {
    let h = Harness::new();
    let head = h.head();
    let audit = h.audit(&head, 0);
    h.service(&head, audit.service())
        .record_session_expired(h.binding, h.certificate)
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    assert!(signature_verifies(&rows[0], &head, SignerRole::Writer));
    let row = decode_local_audit_event(&rows[0]).unwrap();
    assert_eq!(row.outcome(), LocalAuditOutcomeV1::Failed);
    assert!(row.signer_certificate_object_hash() == certificate_hash(h.certificate));
    assert!(row.operator_binding_object_hash() == Some(h.binding));
    let LocalAuditActionV1::SessionExpired(context) = row.action() else {
        panic!("sessionExpired expected");
    };
    assert!(context.subject_object_hash() == Some(h.binding));
    // Klartextfrei: Anzeigename, Funktion, Profil-Salt und Kontokennung
    // stehen weder roh noch hexkodiert in der Zeile. Gegenprobe: der
    // Bindungshash, der dort stehen SOLL, wird gefunden.
    let mut canaries = stored_profile_canaries(&h.database);
    canaries.push(h.account.hash.as_bytes().to_vec());
    for canary in &canaries {
        assert!(
            !leaks(&rows[0], canary),
            "die Ablaufzeile trägt Klartext: {}",
            hex::encode(canary)
        );
    }
    assert!(leaks(&rows[0], h.binding.as_bytes()));

    // Eine unbekannte Bindung wird niemandem zugerechnet.
    let audit = h.audit(&head, 0);
    let unknown = ObjectHash::try_from(&[0xab; 32][..]).unwrap();
    h.service(&head, audit.service())
        .record_session_expired(unknown, h.certificate)
        .unwrap();
    let rows = audit.booked();
    assert_eq!(rows.len(), 1);
    let row = decode_local_audit_event(&rows[0]).unwrap();
    assert!(row.operator_binding_object_hash().is_none());
    let LocalAuditActionV1::SessionExpired(context) = row.action() else {
        panic!("sessionExpired expected");
    };
    assert!(context.subject_object_hash().is_none());

    // Fail-closed: scheitert die Ablage, meldet der Dienst den Fehler.
    let audit = h.audit(&head, 1);
    assert!(
        h.service(&head, audit.service())
            .record_session_expired(h.binding, h.certificate)
            .is_err()
    );
    assert!(audit.booked().is_empty());
}
