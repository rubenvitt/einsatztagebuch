#[allow(dead_code)]
#[path = "historical_grant/support.rs"]
mod issuance;
mod support;
use ea_crypto::object_hash;
use issuance::*;
use support::verify_support::{self as fixture, archive_support::trust_support};

#[test]
fn wrong_device_switched_os_account_lock_and_mismatched_hga_signature_fail_closed() {
    use ea_operator::{OperatorAuthenticator, OsAccountProvider};
    use ea_recovery::*;
    let h = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &h.fixture;
    let head = f.selected(1, 800, 800);
    let auth = ea_trust::verify_grant_authorization(&f.authorization(800), &head).unwrap();
    let registry = Registry {
        fixture: f,
        now: std::cell::Cell::new(800),
    };
    let locked =
        Authenticator(ea_operator::BoundOperator::resolve(&head, f.operator_binding).unwrap())
            .reauthenticate(
                Box::new(Account),
                ea_operator::ReauthPurpose::HistoricalRegrant,
            )
            .unwrap()
            .invalidate_on_lock();
    struct SwitchedAccount;
    impl OsAccountProvider for SwitchedAccount {
        fn os_account_binding_hash(
            &self,
            _: ea_types::OrganizationId,
            _: ea_types::DeviceId,
        ) -> Result<ea_types::Hash32, ea_operator::OperatorError> {
            Ok(ea_types::Hash32::ZERO)
        }
        fn operator_instance_public_key(
            &self,
        ) -> Result<Option<ea_crypto::CanonicalPublicCoseKey>, ea_operator::OperatorError> {
            Account.operator_instance_public_key()
        }
    }
    for (proof, account) in [
        (&locked, &Account as &dyn OsAccountProvider),
        (&h.proof, &SwitchedAccount),
    ] {
        assert_eq!(
            h.create_using(
                &auth,
                &fixture::complete_recipient_private_key(),
                &trust_support::authorized_device_signer(),
                proof,
                account,
                &h.audit,
                &registry,
                &f.recipient_certificate
            )
            .err()
            .unwrap()
            .code(),
            "EA-GRANT-OPERATOR-UNAUTHORIZED"
        );
    }
    let error = HistoricalGrantService::create(
        &h.entry,
        &auth,
        &fixture::complete_recipient_private_key(),
        &trust_support::authorized_device_signer(),
        f.hga_certificate,
        &f.recipient_certificate,
        &registry,
        GrantOperatorContext {
            device_certificate: f.hga_certificate,
            proof: &h.proof,
            account: &Account,
        },
        &h.audit,
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "EA-GRANT-OPERATOR-UNAUTHORIZED");
    struct WrongSignature;
    impl HistoricalGrantSigner for WrongSignature {
        fn key_thumbprint(&self) -> Result<ea_types::KeyThumbprint, ea_crypto::CryptoError> {
            HistoricalGrantSigner::key_thumbprint(&trust_support::authorized_device_signer())
        }
        fn sign_historical_grant(
            &self,
            body: &ea_format::GrantBodyV1,
        ) -> Result<Vec<u8>, ea_crypto::CryptoError> {
            ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x99; 32]))
                .sign_historical_grant(body.exact_bytes())
        }
    }
    assert_eq!(
        h.create_using(
            &auth,
            &fixture::complete_recipient_private_key(),
            &WrongSignature,
            &h.proof,
            &Account,
            &h.audit,
            &registry,
            &f.recipient_certificate
        )
        .err()
        .unwrap()
        .code(),
        "EA-GRANT-ISSUER-UNAUTHORIZED"
    );
    assert!(
        h.db.query_row("SELECT exact_bytes FROM local_audit_event", &[])
            .unwrap()
            .is_none()
    );
}

struct FailedAudit;
impl ea_audit::LocalAuditService for FailedAudit {
    fn record_signed(
        &self,
        _: ea_audit::AuditActorProof<'_>,
        _: ea_audit::TypedLocalAuditEvent,
    ) -> Result<ea_audit::SignedLocalAuditEvent, ea_audit::AuditError> {
        Err(ea_audit::AuditError::SessionExpired)
    }
}
#[test]
fn separate_key_roles_recipient_native_presence_and_durable_audit_are_required() {
    use ea_operator::OperatorAuthenticator;
    use ea_recovery::*;
    let h = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &h.fixture;
    let head = f.selected(1, 800, 800);
    let auth = ea_trust::verify_grant_authorization(&f.authorization(800), &head).unwrap();
    let registry = Registry {
        fixture: f,
        now: std::cell::Cell::new(800),
    };
    let wrong_proof =
        Authenticator(ea_operator::BoundOperator::resolve(&head, f.operator_binding).unwrap())
            .reauthenticate(
                Box::new(Account),
                ea_operator::ReauthPurpose::AdminRootCeremony,
            )
            .unwrap();
    let foreign = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x99; 32]));
    let recovery = fixture::complete_recipient_private_key();
    let authority = trust_support::authorized_device_signer();
    for (key, signer, proof, recipient, audit, code) in [
        (
            &fixture::other_recipient_private_key() as &dyn RecoveryKem,
            &authority as &dyn HistoricalGrantSigner,
            &h.proof,
            f.recipient_certificate.as_slice(),
            &h.audit as &dyn ea_audit::LocalAuditService,
            "EA-GRANT-RECOVERY-KEY",
        ),
        (
            &recovery,
            &foreign,
            &h.proof,
            f.recipient_certificate.as_slice(),
            &h.audit,
            "EA-GRANT-ISSUER-UNAUTHORIZED",
        ),
        (
            &recovery,
            &authority,
            &wrong_proof,
            f.recipient_certificate.as_slice(),
            &h.audit,
            "EA-GRANT-OPERATOR-UNAUTHORIZED",
        ),
        (
            &recovery,
            &authority,
            &h.proof,
            &[][..],
            &h.audit,
            "EA-GRANT-RECIPIENT-MISMATCH",
        ),
        (
            &recovery,
            &authority,
            &h.proof,
            f.recipient_certificate.as_slice(),
            &FailedAudit,
            "EA-GRANT-AUDIT-FAILED",
        ),
    ] {
        assert_eq!(
            h.create_using(
                &auth, key, signer, proof, &Account, audit, &registry, recipient
            )
            .err()
            .unwrap()
            .code(),
            code
        );
    }
    assert!(
        h.db.query_row("SELECT exact_bytes FROM local_audit_event", &[])
            .unwrap()
            .is_none()
    );
}
#[test]
fn explicit_entry_recipient_registry_and_original_bindings_cannot_be_substituted() {
    let h = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &h.fixture;
    let head = f.selected(1, 800, 800);
    for change in [
        (|a: &mut ea_format::GrantAuthorizationFieldsV1| {
            a.organization_id = ea_types::OrganizationId::try_from(&[0x99; 16][..]).unwrap()
        }) as fn(&mut ea_format::GrantAuthorizationFieldsV1),
        |a| a.registry_head_hash = ea_types::Hash32::ZERO,
        |a| a.registry_version = ea_types::RegistryVersion::new(0),
        |a| a.authorization_sequence = 0,
    ] {
        assert!(
            ea_trust::verify_grant_authorization(&f.authorization_changed(800, change), &head)
                .is_err()
        );
    }
    for (change, code) in [
        (
            (|a: &mut ea_format::GrantAuthorizationFieldsV1| {
                a.entry_hashes = vec![ea_types::EntryHash::from(ea_types::Hash32::ZERO)]
            }) as fn(&mut ea_format::GrantAuthorizationFieldsV1),
            "EA-GRANT-AUTHORIZATION-MISMATCH",
        ),
        (
            |a| {
                a.recipient_certificate_hash = ea_types::CertificateHash::from(
                    ea_types::ObjectHash::from(ea_types::Hash32::ZERO),
                )
            },
            "EA-GRANT-RECIPIENT-MISMATCH",
        ),
        (
            |a| a.recipient_key_thumbprint = fixture::complete_recipient_key_thumbprint(),
            "EA-GRANT-RECIPIENT-MISMATCH",
        ),
    ] {
        let proof =
            ea_trust::verify_grant_authorization(&f.authorization_changed(800, change), &head)
                .unwrap();
        assert_eq!(h.create(&proof).err().unwrap().code(), code);
    }
    assert!(
        ea_recovery::VerifiedRecoveryEntry::verify(
            &h.source,
            &f.anchor,
            f.entry_hash,
            ea_types::ObjectHash::from(ea_types::Hash32::ZERO),
            ea_types::UnixMillis::new(800)
        )
        .is_err()
    );
}
#[test]
fn expiry_rechecked_after_kem_and_audit_and_rollback_never_reopens_authorization() {
    use ea_recovery::*;
    let h = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &h.fixture;
    let auth =
        ea_trust::verify_grant_authorization(&f.authorization(800), &f.selected(1, 800, 800))
            .unwrap();
    struct Advancing<'a> {
        fixture: &'a fixture::historical::HistoricalFixture,
        calls: std::cell::Cell<usize>,
        expire_on: usize,
    }
    impl GrantRegistrySource for Advancing<'_> {
        fn current_head(&self) -> Result<ea_trust::SelectedRegistryHead, HistoricalGrantError> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            let now = if call >= self.expire_on { 801 } else { 800 };
            Ok(self.fixture.selected(1, now, now))
        }
    }
    for expire_on in [1, 2, 3] {
        let registry = Advancing {
            fixture: f,
            calls: std::cell::Cell::new(0),
            expire_on,
        };
        assert_eq!(
            h.create_using(
                &auth,
                &fixture::complete_recipient_private_key(),
                &trust_support::authorized_device_signer(),
                &h.proof,
                &Account,
                &h.audit,
                &registry,
                &f.recipient_certificate
            )
            .err()
            .unwrap()
            .code(),
            "EA-GRANT-AUTH-EXPIRED"
        );
    }
    let rollback = f.selected(1, 100, 801);
    assert_eq!(
        ea_trust::verify_grant_authorization(auth.exact_bytes(), &rollback)
            .err()
            .unwrap()
            .code(),
        "EA-GRANT-AUTH-EXPIRED"
    );
}

#[test]
fn issuance_rewraps_the_original_cek_and_commits_signed_audit_before_release() {
    let harness = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &harness.fixture;
    let auth =
        ea_trust::verify_grant_authorization(&f.authorization(800), &f.selected(1, 800, 800))
            .unwrap();
    let bytes = harness
        .create(&auth)
        .expect("valid ceremony produces an exact grant");
    assert_eq!(
        std::fs::read(
            harness
                .root
                .path()
                .join("archive/entries/000000000000_entry.eip")
        )
        .unwrap(),
        f.entry_bytes
    );
    let row = harness
        .db
        .query_row("SELECT exact_bytes FROM local_audit_event", &[])
        .unwrap()
        .expect("signed audit durably committed");
    let event = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
    let ea_format::LocalAuditActionV1::HistoricalRegrant(context) = event.action() else {
        panic!("historical action")
    };
    assert!(context.new_grant_object_hash() == object_hash(bytes.as_bytes()));
    // Plan T8 Step 3: the audit binds exactly the Authorization, Entry,
    // original Recovery grant, recipient certificate and new grant hashes
    // plus the outcome. Each binding is checked on its own value, so a
    // consistent swap in construction and self-check cannot pass.
    assert!(
        context.authorization_object_hash() == auth.object_hash(),
        "audit must bind the Authorization hash"
    );
    assert!(
        context.entry_hash() == f.entry_hash,
        "audit must bind the Entry hash"
    );
    assert!(
        context.original_recovery_grant_object_hash() == object_hash(&f.original_bytes),
        "audit must bind the original Recovery grant hash"
    );
    assert!(
        context.recipient_certificate_object_hash() == object_hash(&f.recipient_certificate),
        "audit must bind the recipient certificate hash"
    );
    assert!(event.outcome() == ea_format::LocalAuditOutcomeV1::Completed);
    let mut output = harness.fixture.fixture;
    output.push_exact_bytes("trust/authorization.etb", auth.exact_bytes().to_vec());
    output.push_object("grants/historical.eag", bytes);
    let key = fixture::other_recipient_private_key();
    let report = ea_verify::verify_archive(
        &output,
        &harness.fixture.anchor,
        ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(800))
            .with_recipient(fixture::other_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(report.is_fully_verified(), "{report:?}");
    assert_eq!(report.recipient_grants().count(), 1);
}

#[test]
fn a_valid_current_authorization_regrants_an_entry_whose_original_registry_lease_expired() {
    let h = Harness::new(fixture::historical::fixture_with_expired_original_head(
        |_, _| fixture::COMPLETE_PLAINTEXT_V1.to_vec(),
    ));
    let f = &h.fixture;
    let auth =
        ea_trust::verify_grant_authorization(&f.authorization(800), &f.selected(1, 800, 800))
            .unwrap();
    let exact = h
        .create(&auth)
        .expect("original lease age is not a reading deadline");
    let mut archive = fixture::archive_support::ArchiveFixture::new();
    for (path, bytes) in f.fixture.blobs() {
        archive.push_exact_bytes(path, bytes.clone());
    }
    archive.push_exact_bytes(
        "trust/current-authorization.etb",
        auth.exact_bytes().to_vec(),
    );
    archive.push_object("grants/new.eag", exact);
    let reader = fixture::other_recipient_private_key();
    let report = ea_verify::verify_archive(
        &archive,
        &f.anchor,
        ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(800))
            .with_recipient(fixture::other_recipient_key_thumbprint(), &reader),
    )
    .unwrap();
    assert_eq!(
        report.recipient_grants().count(),
        1,
        "expired original lease remains readable under valid current authorization: {report:?}"
    );
    assert!(report.is_fully_verified(), "{report:?}");
}

/// AK 12, die NEGATIVE Hälfte: ein neuer Reader ohne vergangenen Zugriff
/// öffnet den ausgewählten alten Eintrag erst NACH dem Recovery-Re-Grant.
///
/// „Öffnen" ist hier die Empfängerstufe von `ea_verify::verify_archive` mit
/// dem Schlüssel des neuen Readers — dieselbe, die
/// `issuance_rewraps_the_original_cek_and_commits_signed_audit_before_release`
/// für die positive Hälfte benutzt: Sie verifiziert den eigenen Grant und
/// entschlüsselt dahinter den Eintrag (`GateObserver::on_decapsulation`).
///
/// KEIN FEHLERCODE, UND DAS IST GEMESSEN: Ein fehlender eigener Grant ist
/// nach `crates/ea-verify/src/archive.rs` („FEHLENDER GRANT ist kein Befund")
/// kein Befund. Fail-closed heißt hier: kein Grant im Bericht, keine
/// Entkapselung, kein Entschlüsselungsbefund — der Eintrag selbst bleibt
/// gültig und sichtbar.
#[test]
fn a_new_reader_opens_the_selected_old_entry_only_after_the_recovery_regrant() {
    struct Decapsulations(usize);
    impl ea_verify::GateObserver for Decapsulations {
        fn on_gate(&mut self, _: ea_verify::Gate) {}
        fn on_decapsulation(&mut self) {
            self.0 += 1;
        }
    }
    let h = Harness::new(fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1));
    let f = &h.fixture;
    let stored = h.root.path().join("archive/entries/000000000000_entry.eip");
    let entry_object = object_hash(&f.entry_bytes);
    let reader = fixture::other_recipient_private_key();
    let open_as_new_reader = |archive: &fixture::archive_support::ArchiveFixture| {
        let mut observer = Decapsulations(0);
        let report = ea_verify::verify_archive_observed(
            archive,
            &f.anchor,
            ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(800))
                .with_recipient(fixture::other_recipient_key_thumbprint(), &reader),
            &mut observer,
        )
        .unwrap();
        (report, observer.0)
    };
    let auth =
        ea_trust::verify_grant_authorization(&f.authorization(800), &f.selected(1, 800, 800))
            .unwrap();
    // Derselbe Bestand vorher und nachher, bis auf GENAU den neuen Grant.
    let mut before = fixture::archive_support::ArchiveFixture::new();
    for (path, bytes) in f.fixture.blobs() {
        before.push_exact_bytes(path, bytes.clone());
    }
    before.push_exact_bytes("trust/authorization.etb", auth.exact_bytes().to_vec());

    // VORHER: kein eigener Grant, keine Entkapselung — der Eintrag bleibt aber
    // gültig; es scheitert das Öffnen und nicht die Verifikation.
    assert_eq!(std::fs::read(&stored).unwrap(), f.entry_bytes);
    let (report, decapsulations) = open_as_new_reader(&before);
    assert!(
        report
            .recipient_grants()
            .all(|(entry, _, _)| entry != f.entry_hash),
        "vor dem Re-Grant hat der neue Reader KEINEN Grant auf den alten Eintrag"
    );
    assert_eq!(report.recipient_grants().count(), 0);
    assert_eq!(
        decapsulations, 0,
        "vor dem Re-Grant wird für den neuen Reader nichts entkapselt"
    );
    assert!(report.is_fully_verified(), "{report:?}");
    assert!(
        report
            .object_results()
            .any(|result| result.object_hash() == entry_object
                && result.object_type() == ea_verify::ObjectTypeV1::Entry
                && result.result() == ea_verify::ObjectResultKindV1::Valid),
        "der alte Eintrag bleibt gültig und sichtbar: {report:?}"
    );
    assert_eq!(report.decryption_errors().len(), 0);

    // Der Recovery-Re-Grant über den echten Ausstellungsdienst.
    let grant = h
        .create(&auth)
        .expect("die gültige Zeremonie stellt den Re-Grant aus");
    let grant_object = object_hash(grant.as_bytes());
    let mut after = before;
    after.push_object("grants/historical.eag", grant);

    // NACHHER: genau dieser Grant öffnet genau diesen Eintrag.
    let (report, decapsulations) = open_as_new_reader(&after);
    assert!(report.is_fully_verified(), "{report:?}");
    let opened: Vec<_> = report.recipient_grants().collect();
    assert_eq!(opened.len(), 1, "{report:?}");
    assert!(opened[0].0 == f.entry_hash);
    assert!(opened[0].1 == grant_object);
    assert!(
        opened[0].2.is_some(),
        "ein historischer Grant trägt sein Ablaufdatum"
    );
    assert_eq!(decapsulations, 1, "nach dem Re-Grant wird entkapselt");
    assert_eq!(report.decryption_errors().len(), 0);

    // Die gespeicherten Eintragsbytes sind vorher und nachher dieselben.
    assert_eq!(std::fs::read(&stored).unwrap(), f.entry_bytes);
    assert!(
        report
            .object_results()
            .any(|result| result.object_hash() == entry_object
                && result.result() == ea_verify::ObjectResultKindV1::Valid),
        "derselbe Eintrag, dieselben Bytes: {report:?}"
    );
}

/// AK 12, die AUSWAHL: von ZWEI alten Einträgen öffnet der neue Reader nach
/// dem Re-Grant genau den ausgewählten; der nicht ausgewählte bleibt zu.
///
/// Die Einträge liegen an Sequenz 0 und 1, beide vor der Aufnahme des Readers
/// (wirksam ab Sequenz 2), beide nur mit ihrem ursprünglichen Recovery-Grant.
/// Die Autorisierung nennt ausschließlich den ersten. Gemessen wird wie im
/// Einzeleintragszeugen an der Empfängerstufe von `verify_archive_observed`.
///
/// Zusätzlich öffnet ein DRITTER Schlüssel ohne jeden Grant dasselbe Archiv:
/// der historische Grant des neuen Readers darf ihm weder zugeschrieben noch
/// für ihn entkapselt werden. Das ist der Empfängerfilter der historischen
/// Hälfte in `crates/ea-verify/src/archive.rs` (`claim_own_grants`,
/// `f.recipient_key_thumbprint == recipient.key_thumbprint()`).
#[test]
fn of_two_old_entries_only_the_selected_one_opens_for_the_new_reader_after_the_regrant() {
    struct Decapsulations(usize);
    impl ea_verify::GateObserver for Decapsulations {
        fn on_gate(&mut self, _: ea_verify::Gate) {}
        fn on_decapsulation(&mut self) {
            self.0 += 1;
        }
    }
    let h = Harness::new(fixture::historical::fixture_with_two_old_entries(
        fixture::COMPLETE_PLAINTEXT_V1,
    ));
    let f = &h.fixture;
    let second = f
        .second_old_entry
        .as_ref()
        .expect("die Fixture trägt einen zweiten alten Eintrag");
    assert!(second.entry_hash != f.entry_hash);
    let stored = [
        (
            h.root.path().join("archive/entries/000000000000_entry.eip"),
            &f.entry_bytes,
        ),
        (
            h.root.path().join("archive/entries/000000000001_entry.eip"),
            &second.entry_bytes,
        ),
    ];
    let entry_objects = [
        object_hash(&f.entry_bytes),
        object_hash(&second.entry_bytes),
    ];
    let reader = fixture::other_recipient_private_key();
    let stranger =
        ea_crypto::HpkeRecipientPrivateKey::from_bytes(ea_crypto::SecretBytes::new([0x7a; 32]))
            .unwrap();
    let stranger_thumbprint = fixture::key_thumbprint_of(&stranger);
    assert!(stranger_thumbprint != fixture::other_recipient_key_thumbprint());
    assert!(stranger_thumbprint != fixture::complete_recipient_key_thumbprint());
    let open = |archive: &fixture::archive_support::ArchiveFixture,
                thumbprint,
                key: &ea_crypto::HpkeRecipientPrivateKey| {
        let mut observer = Decapsulations(0);
        let report = ea_verify::verify_archive_observed(
            archive,
            &f.anchor,
            ea_verify::VerifyOptions::new(ea_types::UnixMillis::new(800))
                .with_recipient(thumbprint, key),
            &mut observer,
        )
        .unwrap();
        (report, observer.0)
    };
    let both_entries_valid = |report: &ea_verify::VerificationReportV1| {
        entry_objects.iter().all(|entry| {
            report.object_results().any(|result| {
                result.object_hash() == *entry
                    && result.object_type() == ea_verify::ObjectTypeV1::Entry
                    && result.result() == ea_verify::ObjectResultKindV1::Valid
            })
        })
    };

    // Die Autorisierung wählt GENAU den ersten Eintrag aus.
    let auth = ea_trust::verify_grant_authorization(
        &f.authorization(800),
        &f.selected(f.current_sequence, 800, 800),
    )
    .unwrap();
    let mut before = fixture::archive_support::ArchiveFixture::new();
    for (path, bytes) in f.fixture.blobs() {
        before.push_exact_bytes(path, bytes.clone());
    }
    before.push_exact_bytes("trust/authorization.etb", auth.exact_bytes().to_vec());

    // VORHER: beide Einträge gültig, keiner geöffnet.
    let (report, decapsulations) =
        open(&before, fixture::other_recipient_key_thumbprint(), &reader);
    assert!(report.is_fully_verified(), "{report:?}");
    assert!(both_entries_valid(&report), "{report:?}");
    assert_eq!(report.recipient_grants().count(), 0, "{report:?}");
    assert_eq!(decapsulations, 0);
    assert_eq!(report.decryption_errors().len(), 0);

    // Der Recovery-Re-Grant über den echten Ausstellungsdienst.
    let grant = h
        .create(&auth)
        .expect("die gültige Zeremonie stellt den Re-Grant aus");
    let grant_object = object_hash(grant.as_bytes());
    let mut after = before;
    after.push_object("grants/historical.eag", grant);

    // NACHHER: genau der ausgewählte Eintrag öffnet, der andere nicht.
    let (report, decapsulations) = open(&after, fixture::other_recipient_key_thumbprint(), &reader);
    assert!(report.is_fully_verified(), "{report:?}");
    assert!(both_entries_valid(&report), "{report:?}");
    let opened: Vec<_> = report.recipient_grants().collect();
    assert_eq!(opened.len(), 1, "{report:?}");
    assert!(opened[0].0 == f.entry_hash, "geöffnet ist der AUSGEWÄHLTE");
    assert!(opened[0].1 == grant_object);
    assert!(
        report
            .recipient_grants()
            .all(|(entry, _, _)| entry != second.entry_hash),
        "der NICHT ausgewählte alte Eintrag hat keinen Grant für den neuen Reader"
    );
    assert_eq!(
        decapsulations, 1,
        "genau eine Entkapselung: die des ausgewählten Eintrags"
    );
    assert_eq!(report.decryption_errors().len(), 0);

    // Ein dritter Schlüssel ohne Grant: der historische Grant des neuen
    // Readers wird ihm weder zugeschrieben noch für ihn entkapselt.
    let (report, decapsulations) = open(&after, stranger_thumbprint, &stranger);
    assert_eq!(
        report.recipient_grants().count(),
        0,
        "ein fremder historischer Grant ist nicht der eigene"
    );
    assert_eq!(decapsulations, 0);
    assert_eq!(report.decryption_errors().len(), 0);
    assert!(report.is_fully_verified(), "{report:?}");

    // Beide gespeicherten Eintragsdateien sind unverändert.
    for (path, bytes) in &stored {
        assert_eq!(&&std::fs::read(path).unwrap(), bytes);
    }
}
