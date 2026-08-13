use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DestructionId, DeviceId, EntryHash,
    EntryStatus, ErrorClass, EventId, EvidenceStatus, FormatVersion, Hash32, Id16, JitterSource,
    KeyThumbprint, ObjectHash, ObjectVersion, OperatorSubjectId, OrganizationId, RecordId,
    Redacted, RegistryVersion, RetryConfig, RetryDecision, RetryDisposition, SchemaVersion,
    SubjectId, SyncStatus, TechnicalError, TechnicalErrorCode, UnixMillis, VerificationStatus,
};

#[test]
fn hashes_require_exact_length_and_errors_do_not_echo_input() {
    assert!(Hash32::try_from(&[0_u8; 31][..]).is_err());
    let err = TechnicalError::new(TechnicalErrorCode::InvalidObject).with_secret("CANARY-NAME");
    assert_eq!(format!("{err}"), "EA-FORMAT-INVALID-OBJECT");
    assert!(!format!("{err:?}").contains("CANARY-NAME"));
}

#[test]
fn status_is_machine_stable() {
    assert_eq!(SyncStatus::UploadPending.code(), "uploadPending");
    assert_eq!(EntryHash::from(Hash32::ZERO).as_bytes(), &[0_u8; 32]);
}

#[test]
fn every_error_class_has_one_fail_closed_retry_contract() {
    assert_eq!(
        ErrorClass::Domain.disposition(),
        RetryDisposition::CorrectInput
    );
    assert_eq!(
        ErrorClass::LocalResource.disposition(),
        RetryDisposition::RetainDraftAndBlock
    );
    assert_eq!(
        ErrorClass::TemporaryTransport.disposition(),
        RetryDisposition::BoundedRetry
    );
    assert_eq!(
        ErrorClass::TrustSecurity.disposition(),
        RetryDisposition::FailClosed
    );
    assert_eq!(
        ErrorClass::Format.disposition(),
        RetryDisposition::IsolateObject
    );
    assert_eq!(
        ErrorClass::Evidence.disposition(),
        RetryDisposition::PreserveEntryAndReport
    );
    assert_eq!(
        ErrorClass::RecoveryDestruction.disposition(),
        RetryDisposition::ReportExactPartialState
    );
}

#[test]
fn closed_byte_types_reject_every_wrong_length_without_echoing_bytes() {
    for length in [0, 15, 17, 31, 33] {
        let input = vec![0x41; length];
        let result = if length < 24 {
            Id16::try_from(input.as_slice()).map(|_| ())
        } else {
            Hash32::try_from(input.as_slice()).map(|_| ())
        };
        let error = result.expect_err("wrong lengths must be rejected");
        let display = format!("{error}");
        let debug = format!("{error:?}");
        assert!(display.contains(&format!("actual={length}")));
        assert!(!display.contains("AAAA"));
        assert!(!debug.contains("AAAA"));
    }

    assert_eq!(
        Id16::try_from(&[7_u8; 16][..]).unwrap().as_bytes(),
        &[7_u8; 16]
    );
    assert_eq!(
        ObjectHash::try_from(&[9_u8; 32][..]).unwrap().as_bytes(),
        &[9_u8; 32]
    );
}

#[test]
fn domain_hashes_and_integer_wrappers_keep_their_values() {
    let raw = Hash32::try_from(&[3_u8; 32][..]).unwrap();
    assert_eq!(EntryHash::from(raw).as_bytes(), &[3_u8; 32]);
    assert_eq!(ObjectHash::from(raw).as_bytes(), &[3_u8; 32]);
    assert_eq!(FormatVersion::new(1).get(), 1);
    assert_eq!(ObjectVersion::new(2).get(), 2);
    assert_eq!(SchemaVersion::new(3).get(), 3);
    assert_eq!(ChainSequence::new(4).get(), 4);
}

#[test]
fn domain_ids_are_closed_and_cannot_be_accidentally_interchanged() {
    let raw = Id16::try_from(&[5_u8; 16][..]).unwrap();
    assert_eq!(OrganizationId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(ChainId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(DeviceId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(EventId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(AuthorizationId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(DestructionId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(RecordId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(SubjectId::from(raw).as_bytes(), &[5_u8; 16]);
    assert_eq!(OperatorSubjectId::from(raw).as_bytes(), &[5_u8; 16]);

    assert!(OrganizationId::try_from(&[0_u8; 15][..]).is_err());
    assert!(ChainId::try_from(&[0_u8; 17][..]).is_err());
}

#[test]
fn every_status_variant_has_an_exhaustive_stable_code() {
    assert_eq!(SyncStatus::LocallySecured.code(), "locallySecured");
    assert_eq!(SyncStatus::UploadPending.code(), "uploadPending");
    assert_eq!(SyncStatus::Synchronized.code(), "synchronized");
    assert_eq!(SyncStatus::Error.code(), "error");

    assert_eq!(VerificationStatus::Verified.code(), "verified");
    assert_eq!(VerificationStatus::Gap.code(), "gap");
    assert_eq!(VerificationStatus::MissingGrant.code(), "missingGrant");
    assert_eq!(VerificationStatus::UnknownKey.code(), "unknownKey");
    assert_eq!(
        VerificationStatus::UnsupportedSchema.code(),
        "unsupportedSchema"
    );
    assert_eq!(VerificationStatus::Invalid.code(), "invalid");

    assert_eq!(EvidenceStatus::Complete.code(), "complete");
    assert_eq!(EvidenceStatus::Pending.code(), "pending");
    assert_eq!(EvidenceStatus::Overdue.code(), "overdue");
    assert_eq!(EvidenceStatus::Invalid.code(), "invalid");

    assert_eq!(EntryStatus::Present.code(), "present");
    assert_eq!(
        EntryStatus::AuthorizedDestroyed.code(),
        "authorizedDestroyed"
    );
    assert_eq!(EntryStatus::UnexplainedGap.code(), "unexplainedGap");
}

#[test]
fn technical_codes_derive_exactly_one_class_and_stable_code() {
    let cases = [
        (
            TechnicalErrorCode::InvalidInput,
            ErrorClass::Domain,
            "EA-DOMAIN-INVALID-INPUT",
        ),
        (
            TechnicalErrorCode::LocalResourceUnavailable,
            ErrorClass::LocalResource,
            "EA-LOCAL-RESOURCE-UNAVAILABLE",
        ),
        (
            TechnicalErrorCode::TemporaryTransport,
            ErrorClass::TemporaryTransport,
            "EA-TRANSPORT-TEMPORARY",
        ),
        (
            TechnicalErrorCode::TrustViolation,
            ErrorClass::TrustSecurity,
            "EA-TRUST-VIOLATION",
        ),
        (
            TechnicalErrorCode::InvalidObject,
            ErrorClass::Format,
            "EA-FORMAT-INVALID-OBJECT",
        ),
        (
            TechnicalErrorCode::EvidenceUnavailable,
            ErrorClass::Evidence,
            "EA-EVIDENCE-UNAVAILABLE",
        ),
        (
            TechnicalErrorCode::RecoveryPartialState,
            ErrorClass::RecoveryDestruction,
            "EA-RECOVERY-PARTIAL-STATE",
        ),
    ];

    for (code, expected_class, expected_code) in cases {
        assert_eq!(code.class(), expected_class);
        assert_eq!(code.code(), expected_code);
        assert_eq!(TechnicalError::new(code).class(), expected_class);
    }
}

#[test]
fn error_formatting_allows_only_code_and_numeric_metadata() {
    let error = TechnicalError::new(TechnicalErrorCode::TemporaryTransport)
        .with_attempt(7)
        .with_secret("SECRET-LOCATION");

    assert_eq!(format!("{error}"), "EA-TRANSPORT-TEMPORARY attempt=7");
    assert_eq!(format!("{error:?}"), "EA-TRANSPORT-TEMPORARY attempt=7");
    assert!(!format!("{error}").contains("SECRET-LOCATION"));
    assert!(!format!("{error:?}").contains("SECRET-LOCATION"));
    assert!(error.secret_matches("SECRET-LOCATION"));
    assert!(!error.secret_matches("OTHER-LOCATION"));
    assert!(!TechnicalError::new(TechnicalErrorCode::InvalidObject).secret_matches(""));

    let redacted = Redacted::new(String::from("CANARY-NAME"));
    assert!(redacted.matches("CANARY-NAME"));
    assert!(!redacted.matches("OTHER-NAME"));
}

struct FixedJitter {
    value: u64,
    observed_ceiling: u64,
    calls: u16,
}

impl JitterSource for FixedJitter {
    fn jitter_ms(&mut self, ceiling_ms: u64) -> u64 {
        self.calls += 1;
        self.observed_ceiling = ceiling_ms;
        self.value
    }
}

#[test]
fn only_temporary_transport_exposes_bounded_automatic_retry() {
    let config = RetryConfig::new(3, 100, 250).unwrap();
    for code in [
        TechnicalErrorCode::InvalidInput,
        TechnicalErrorCode::LocalResourceUnavailable,
        TechnicalErrorCode::TrustViolation,
        TechnicalErrorCode::InvalidObject,
        TechnicalErrorCode::EvidenceUnavailable,
        TechnicalErrorCode::RecoveryPartialState,
    ] {
        let error = TechnicalError::new(code);
        let returned = error
            .into_retry_policy(config)
            .expect_err("non-transport errors must not create retry state");
        assert_eq!(returned.code(), code);
    }

    let mut policy = TechnicalError::new(TechnicalErrorCode::TemporaryTransport)
        .into_retry_policy(config)
        .unwrap();
    let mut jitter = FixedJitter {
        value: u64::MAX,
        observed_ceiling: 0,
        calls: 0,
    };
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::RetryAfter { delay_ms: 100 }
    );
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::RetryAfter { delay_ms: 200 }
    );
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::RetryAfter { delay_ms: 250 }
    );
    assert_eq!(jitter.observed_ceiling, 250);
    assert_eq!(jitter.calls, 3);
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::Exhausted { failed_attempts: 4 }
    );
    assert_eq!(jitter.calls, 3, "exhaustion must not call jitter");
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::Exhausted { failed_attempts: 4 }
    );
    assert_eq!(jitter.calls, 3, "terminal exhaustion must not call jitter");
}

#[test]
fn retry_backoff_is_overflow_safe_and_jitter_is_controllable() {
    let config = RetryConfig::new(u8::MAX, u64::MAX, 900).unwrap();
    let mut policy = TechnicalError::new(TechnicalErrorCode::TemporaryTransport)
        .into_retry_policy(config)
        .unwrap();
    let mut jitter = FixedJitter {
        value: 123,
        observed_ceiling: 0,
        calls: 0,
    };

    for _ in 0..254 {
        assert_eq!(
            policy.next(&mut jitter),
            RetryDecision::RetryAfter { delay_ms: 123 }
        );
    }
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::RetryAfter { delay_ms: 123 }
    );
    assert_eq!(jitter.observed_ceiling, 900);
    assert_eq!(jitter.calls, 255);
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::Exhausted {
            failed_attempts: 256
        }
    );
    assert_eq!(jitter.calls, 255);
    assert_eq!(
        policy.next(&mut jitter),
        RetryDecision::Exhausted {
            failed_attempts: 256
        }
    );
    assert_eq!(jitter.calls, 255);
}

#[test]
fn retry_config_rejects_unbounded_or_zero_delay_contracts() {
    assert!(RetryConfig::new(0, 100, 200).is_none());
    assert!(RetryConfig::new(1, 0, 200).is_none());
    assert!(RetryConfig::new(1, 100, 0).is_none());
}

#[test]
fn cross_stage_hash_and_time_primitives_are_closed_and_typed() {
    let object_hash = ObjectHash::try_from(&[11_u8; 32][..]).unwrap();
    assert_eq!(CertificateHash::from(object_hash).as_bytes(), &[11_u8; 32]);
    assert_eq!(
        CertificateHash::try_from(&[12_u8; 32][..])
            .unwrap()
            .as_bytes(),
        &[12_u8; 32]
    );
    assert!(CertificateHash::try_from(&[0_u8; 31][..]).is_err());

    let hash = Hash32::try_from(&[13_u8; 32][..]).unwrap();
    assert_eq!(KeyThumbprint::from(hash).as_bytes(), &[13_u8; 32]);
    assert_eq!(
        KeyThumbprint::try_from(&[14_u8; 32][..])
            .unwrap()
            .as_bytes(),
        &[14_u8; 32]
    );
    assert!(KeyThumbprint::try_from(&[0_u8; 33][..]).is_err());

    assert_eq!(RegistryVersion::new(u64::MAX).get(), u64::MAX);
    assert_eq!(UnixMillis::new(i64::MIN).get(), i64::MIN);
}
