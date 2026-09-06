use super::*;

fn save_request(directory: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
    let path = directory.join(format!(
        "request-{}.json",
        hex::encode(object_hash(bytes).as_bytes())
    ));
    write_exchange_file(&path, bytes).unwrap();
    path
}

fn advance(
    line: &mut fixtures::RegistryLineBuilder,
    database: &Arc<EncryptedDatabase>,
) -> SelectedRegistryHead {
    line.push(
        fixtures::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        fixtures::HeadOptions::default(),
    );
    select(line, database)
}

fn complete(
    database: &Arc<EncryptedDatabase>,
    request: &PendingExchange,
    head: &SelectedRegistryHead,
    target: CertificateHash,
    admin: CertificateHash,
    binding: ObjectHash,
) -> Vec<u8> {
    let (verified, _) =
        verify_request(request.request_bytes(), head, target, admin, binding).unwrap();
    assert!(
        begin_request(database, request.request_bytes())
            .unwrap()
            .is_none()
    );
    let signer = Signing(SigningKey::from_bytes(
        &fixtures::second_admin_signing_secret(),
    ));
    let reply = verified
        .reply(json!({"error":"synthetic completed failure"}), &signer)
        .unwrap();
    finish_request(database, request.request_bytes(), &reply).unwrap();
    let public = CanonicalPublicCoseKey::ed25519(signer.0.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        request.open_reply(&reply, &public).unwrap()["error"],
        "synthetic completed failure"
    );
    reply
}

#[test]
fn retained_completed_error_reply_is_exact_while_unknown_and_pending_old_requests_stay_closed() {
    let (mut line, before, target, database, directory) = fixture();
    let admin = CertificateHash::from(line.second_bootstrap_admin_hash());
    let binding = line.second_bootstrap_admin_binding_hash();
    let old = request_for(&before, target, admin, binding, json!({}));
    let reply = complete(&database, &old, &before, target, admin, binding);
    let old_path = save_request(&directory, old.request_bytes());
    let pending = request_for(&before, target, admin, binding, json!({}));
    assert!(
        begin_request(&database, pending.request_bytes())
            .unwrap()
            .is_none()
    );
    let pending_path = save_request(&directory, pending.request_bytes());
    let unknown = request_for(&before, target, admin, binding, json!({}));
    let unknown_path = save_request(&directory, unknown.request_bytes());
    let after = advance(&mut line, &database);
    assert!(before.registry_head_hash() != after.registry_head_hash());

    let cached =
        prepare_request_file(&database, &after, target, admin, binding, &old_path).unwrap();
    assert_eq!(cached.cached.unwrap(), reply);
    for path in [&pending_path, &unknown_path] {
        assert!(matches!(
            prepare_request_file(&database, &after, target, admin, binding, path),
            Err(AuthorityError::Context)
        ));
    }
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM operator_authority_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        2
    );
    assert_eq!(
        database
            .query_row(
                "SELECT state FROM operator_authority_request WHERE request_hash=?1",
                &[blob(object_hash(pending.request_bytes()).as_bytes())]
            )
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );

    // A current, authenticated pending authorization must still reach the
    // existing staged-signature recovery path, not be mistaken for completed.
    let current = request_for(&after, target, admin, binding, json!({}));
    let current_path = save_request(&directory, current.request_bytes());
    assert!(
        prepare_request_file(&database, &after, target, admin, binding, &current_path)
            .unwrap()
            .cached
            .is_none()
    );
    assert!(
        prepare_request_file(&database, &after, target, admin, binding, &current_path)
            .unwrap()
            .cached
            .is_none()
    );
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM operator_authority_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        3
    );
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_completed_cache_never_bypasses_pinned_configuration_canonical_bytes_or_file_integrity() {
    let (mut line, before, target, database, directory) = fixture();
    let admin = CertificateHash::from(line.second_bootstrap_admin_hash());
    let binding = line.second_bootstrap_admin_binding_hash();
    let old = request_for(&before, target, admin, binding, json!({}));
    let reply = complete(&database, &old, &before, target, admin, binding);
    let path = save_request(&directory, old.request_bytes());
    let after = advance(&mut line, &database);

    for (configured_target, configured_admin, configured_binding) in [
        (
            CertificateHash::from(line.bootstrap_admin_hash()),
            admin,
            binding,
        ),
        (
            target,
            CertificateHash::from(line.bootstrap_admin_hash()),
            binding,
        ),
        (target, admin, line.bootstrap_admin_binding_hash()),
    ] {
        assert!(
            prepare_request_file(
                &database,
                &after,
                configured_target,
                configured_admin,
                configured_binding,
                &path
            )
            .is_err()
        );
    }
    let renamed = directory.join(format!("request-{}.json", "00".repeat(32)));
    std::fs::write(&renamed, old.request_bytes()).unwrap();
    assert!(matches!(
        prepare_request_file(&database, &after, target, admin, binding, &renamed),
        Err(AuthorityError::Invalid)
    ));
    let mut changed = old.request_bytes().to_vec();
    changed.push(b' ');
    let changed_path = save_request(&directory, &changed);
    assert!(
        prepare_request_file(&database, &after, target, admin, binding, &changed_path).is_err()
    );

    // Even a corrupt durable row cannot authorize malformed or foreign input.
    let public = CanonicalPublicCoseKey::ed25519(
        SigningKey::from_bytes(&fixtures::device_signing_secret())
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let verified = VerifiedExchangeRequest::verify(old.request_bytes(), &public).unwrap();
    for field in [
        "organization_id",
        "chain_id",
        "device_certificate_hash",
        "admin_certificate_hash",
        "admin_binding_object_hash",
        "registry_head_hash",
    ] {
        let mut payload = verified.payload().clone();
        payload["context"][field] = json!("00".repeat(if field == "registry_head_hash" {
            1
        } else if field.ends_with("_id") {
            16
        } else {
            32
        }));
        let malformed = PendingExchange::new(
            payload,
            &Signing(SigningKey::from_bytes(&fixtures::device_signing_secret())),
        )
        .unwrap();
        begin_request(&database, malformed.request_bytes()).unwrap();
        finish_request(&database, malformed.request_bytes(), &reply).unwrap();
        let malformed_path = save_request(&directory, malformed.request_bytes());
        assert!(
            prepare_request_file(&database, &after, target, admin, binding, &malformed_path)
                .is_err()
        );
    }
    let malformed = b"not an exchange envelope";
    begin_request(&database, malformed).unwrap();
    finish_request(&database, malformed, &reply).unwrap();
    let malformed_path = save_request(&directory, malformed);
    assert!(
        prepare_request_file(&database, &after, target, admin, binding, &malformed_path).is_err()
    );
    database
        .execute(
            "UPDATE operator_authority_request SET request_bytes=?1 WHERE request_hash=?2",
            &[
                blob(&changed),
                blob(object_hash(old.request_bytes()).as_bytes()),
            ],
        )
        .unwrap();
    assert!(matches!(
        prepare_request_file(&database, &after, target, admin, binding, &path),
        Err(AuthorityError::Invalid)
    ));
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cached_reply_recovers_a_lost_file_but_refuses_changed_or_symlinked_destinations() {
    let (mut line, before, target, database, directory) = fixture();
    let admin = CertificateHash::from(line.second_bootstrap_admin_hash());
    let binding = line.second_bootstrap_admin_binding_hash();
    let old = request_for(&before, target, admin, binding, json!({}));
    let reply = complete(&database, &old, &before, target, admin, binding);
    let path = save_request(&directory, old.request_bytes());
    let after = advance(&mut line, &database);
    let cached = prepare_request_file(&database, &after, target, admin, binding, &path)
        .unwrap()
        .cached
        .unwrap();
    let destination = directory.join(format!("reply-{}.json", old.request_id()));
    publish_reply_file(&directory, &old.request_id(), &cached).unwrap();
    publish_reply_file(&directory, &old.request_id(), &cached).unwrap();
    assert_eq!(read_exchange_file(&destination).unwrap(), reply);
    std::fs::remove_file(&destination).unwrap();
    publish_reply_file(&directory, &old.request_id(), &cached).unwrap();
    assert_eq!(read_exchange_file(&destination).unwrap(), reply);
    std::fs::write(&destination, b"changed reply").unwrap();
    assert!(matches!(
        publish_reply_file(&directory, &old.request_id(), &cached),
        Err(AuthorityError::Invalid)
    ));
    #[cfg(unix)]
    {
        std::fs::remove_file(&destination).unwrap();
        std::os::unix::fs::symlink(&path, &destination).unwrap();
        assert!(publish_reply_file(&directory, &old.request_id(), &cached).is_err());
    }
    drop(database);
    std::fs::remove_dir_all(directory).unwrap();
}
