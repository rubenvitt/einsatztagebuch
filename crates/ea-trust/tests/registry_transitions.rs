mod support;

use ea_format::{CertificateKindV1, OperatorRoleV1};
use ea_trust::{RegistryError, verify_registry_candidate};
use ea_types::{ChainSequence, RegistryVersion, UnixMillis};

use support::{ActionSpec, AuthorizationSigner, HeadOptions, Pin, RegistryLineBuilder};

fn policy() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn expect_error(line: &RegistryLineBuilder, pin: Pin, proposed_sequence: u64, expected_code: &str) {
    let trust = line.verified(pin);
    let error: RegistryError =
        verify_registry_candidate(&trust, ChainSequence::new(proposed_sequence))
            .err()
            .expect("the Registry attack must fail closed");
    assert_eq!(error.code(), expected_code);
    assert_eq!(error.to_string(), expected_code);
    assert_eq!(format!("{error:?}"), expected_code);
}

#[test]
fn bootstrap_and_direct_successor_bind_exact_version_head_and_authority() {
    let mut bootstrap = RegistryLineBuilder::new();
    let head1 = bootstrap.push(policy(), HeadOptions::default());
    let trust = bootstrap.verified(Pin::None);
    let candidate = verify_registry_candidate(&trust, head1.effective_from)
        .expect("Registry 0/zero authorizes only Head 1/null");
    assert!(candidate.preexisting_authority().is_none());
    assert_eq!(candidate.registry_version(), head1.version);
    assert!(candidate.registry_head_hash() == head1.object_hash);

    let mut successor = RegistryLineBuilder::new();
    let head1 = successor.push(policy(), HeadOptions::default());
    let head2 = successor.push(policy(), HeadOptions::default());
    let trust = successor.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, head2.effective_from)
        .expect("a pinned Head N authorizes only N+1 with its exact hash");
    assert!(candidate.preexisting_authority().is_some());
    assert_eq!(candidate.registry_version(), head2.version);
    assert!(candidate.registry_head_hash() == head2.object_hash);
    assert_eq!(head1.version, RegistryVersion::new(1));
    assert_eq!(head2.version, RegistryVersion::new(2));

    let mut sequence_future_bootstrap = RegistryLineBuilder::new();
    sequence_future_bootstrap.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(20),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &sequence_future_bootstrap,
        Pin::None,
        1,
        "EA-TRUST-SEQUENCE-LEASE",
    );
}

#[test]
fn registry_topology_rejects_same_version_gap_fork_rollback_overflow_and_wrong_previous() {
    let mut bootstrap_gap = RegistryLineBuilder::new();
    bootstrap_gap.push(
        policy(),
        HeadOptions {
            registry_version: Some(2),
            ..HeadOptions::default()
        },
    );
    expect_error(&bootstrap_gap, Pin::None, 1, "EA-TRUST-REGISTRY-GAP");

    let mut bootstrap_previous = RegistryLineBuilder::new();
    bootstrap_previous.push(
        policy(),
        HeadOptions {
            previous_hash: support::PreviousHash::Value(support::hash32(0xd0)),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &bootstrap_previous,
        Pin::None,
        1,
        "EA-TRUST-REGISTRY-PREVIOUS",
    );

    let mut same_version = RegistryLineBuilder::new();
    same_version.push(policy(), HeadOptions::default());
    same_version.push(
        policy(),
        HeadOptions {
            registry_version: Some(1),
            ..HeadOptions::default()
        },
    );
    expect_error(&same_version, Pin::Head(0), 101, "EA-TRUST-REGISTRY-FORK");

    let mut gap = RegistryLineBuilder::new();
    gap.push(policy(), HeadOptions::default());
    gap.add_branch(
        policy(),
        HeadOptions {
            registry_version: Some(3),
            ..HeadOptions::default()
        },
    );
    expect_error(&gap, Pin::Head(0), 101, "EA-TRUST-REGISTRY-GAP");

    let mut fork = RegistryLineBuilder::new();
    fork.push(policy(), HeadOptions::default());
    fork.add_branch(policy(), HeadOptions::default());
    fork.add_branch(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(101),
            ..HeadOptions::default()
        },
    );
    expect_error(&fork, Pin::Head(0), 101, "EA-TRUST-REGISTRY-FORK");

    let mut rollback = RegistryLineBuilder::new();
    rollback.push(policy(), HeadOptions::default());
    let head2 = rollback.push(policy(), HeadOptions::default());
    rollback.remove_object(head2.object_hash);
    expect_error(
        &rollback,
        Pin::Exact(head2.version, head2.object_hash),
        200,
        "EA-TRUST-REGISTRY-ROLLBACK",
    );

    let mut non_registry_pin = RegistryLineBuilder::new();
    let head1 = non_registry_pin.push(policy(), HeadOptions::default());
    let policy_hash = non_registry_pin.current_policy_hash().unwrap();
    expect_error(
        &non_registry_pin,
        Pin::Exact(head1.version, policy_hash),
        101,
        "EA-TRUST-REGISTRY-ROLLBACK",
    );

    let maximum_pin = RegistryLineBuilder::new();
    expect_error(
        &maximum_pin,
        Pin::Exact(
            RegistryVersion::new(u64::MAX),
            support::object_hash_marker(0xfe),
        ),
        1,
        "EA-TRUST-REGISTRY-OVERFLOW",
    );

    let mut wrong_previous = RegistryLineBuilder::new();
    wrong_previous.push(policy(), HeadOptions::default());
    wrong_previous.push(
        policy(),
        HeadOptions {
            previous_hash: support::PreviousHash::Value(support::hash32(0xd1)),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_previous,
        Pin::Head(0),
        101,
        "EA-TRUST-REGISTRY-PREVIOUS",
    );
}

#[test]
fn direct_successor_topology_is_checked_before_current_head_fallback() {
    let mut fork = RegistryLineBuilder::new();
    fork.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    fork.add_branch(
        policy(),
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    fork.add_branch(
        policy(),
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(200),
            issued_at: UnixMillis::new(101),
            ..HeadOptions::default()
        },
    );
    expect_error(&fork, Pin::Head(0), 50, "EA-TRUST-REGISTRY-FORK");

    let mut gap = RegistryLineBuilder::new();
    gap.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    gap.add_branch(
        policy(),
        HeadOptions {
            registry_version: Some(3),
            effective_from: Some(101),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    expect_error(&gap, Pin::Head(0), 50, "EA-TRUST-REGISTRY-GAP");

    let mut previous = RegistryLineBuilder::new();
    previous.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    previous.push(
        policy(),
        HeadOptions {
            previous_hash: support::PreviousHash::Value(support::hash32(0xd6)),
            effective_from: Some(101),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    expect_error(&previous, Pin::Head(0), 50, "EA-TRUST-REGISTRY-PREVIOUS");
}

#[test]
fn sequence_lease_accepts_inside_or_exact_successor_and_rejects_every_larger_jump() {
    for successor_effective in [15, 21] {
        let mut line = RegistryLineBuilder::new();
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(10),
                valid_through: Some(20),
                ..HeadOptions::default()
            },
        );
        let head2 = line.push(
            policy(),
            HeadOptions {
                effective_from: Some(successor_effective),
                valid_through: Some(40),
                ..HeadOptions::default()
            },
        );
        let trust = line.verified(Pin::Head(0));
        verify_registry_candidate(&trust, head2.effective_from)
            .expect("inside-Lease and exact Lease+1 transitions are valid");
    }

    for (label, successor_effective) in [("larger gap", 22), ("before prior effective", 9)] {
        let mut line = RegistryLineBuilder::new();
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(10),
                valid_through: Some(20),
                ..HeadOptions::default()
            },
        );
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(successor_effective),
                valid_through: Some(40),
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(0), 22, "EA-TRUST-SEQUENCE-LEASE");
        assert!(!label.is_empty());
    }

    let mut maximum = RegistryLineBuilder::new();
    maximum.push(
        policy(),
        HeadOptions {
            valid_through: Some(u64::MAX),
            ..HeadOptions::default()
        },
    );
    let trust = maximum.verified(Pin::Head(0));
    verify_registry_candidate(&trust, ChainSequence::new(u64::MAX))
        .expect("a current Head ending at MAX must not eagerly add one");

    let mut exhausted_current = RegistryLineBuilder::new();
    exhausted_current.push(
        policy(),
        HeadOptions {
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &exhausted_current,
        Pin::Head(0),
        101,
        "EA-TRUST-SEQUENCE-LEASE",
    );
}

#[test]
fn successor_priority_current_fallback_and_intermediate_catch_up_are_singular() {
    let mut overlap = RegistryLineBuilder::new();
    overlap.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    overlap.push(
        policy(),
        HeadOptions {
            effective_from: Some(50),
            valid_through: Some(150),
            ..HeadOptions::default()
        },
    );
    let trust = overlap.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(50))
        .expect("an applicable direct successor wins despite Lease overlap");
    assert!(candidate.preexisting_authority().is_some());
    assert_eq!(candidate.registry_version(), overlap.heads()[1].version);
    assert!(candidate.registry_head_hash() == overlap.heads()[1].object_hash);

    let mut future_sequence = RegistryLineBuilder::new();
    future_sequence.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    future_sequence.push(
        policy(),
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    let trust = future_sequence.verified(Pin::Head(0));
    let current = verify_registry_candidate(&trust, ChainSequence::new(50))
        .expect("a sequence-future successor leaves the covering current Head candidate");
    assert_eq!(
        current.registry_version(),
        future_sequence.heads()[0].version
    );
    assert!(current.registry_head_hash() == future_sequence.heads()[0].object_hash);

    let mut lazy_future = RegistryLineBuilder::new();
    lazy_future.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    lazy_future.push(
        policy(),
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(200),
            root_signer: support::RootSigner::Corrupt,
            ..HeadOptions::default()
        },
    );
    let trust = lazy_future.verified(Pin::Head(0));
    let current = verify_registry_candidate(&trust, ChainSequence::new(50))
        .expect("a sequence-ineligible successor's semantics are outside the current candidate");
    assert_eq!(current.registry_version(), lazy_future.heads()[0].version);
    assert!(current.registry_head_hash() == lazy_future.heads()[0].object_hash);

    let trust = future_sequence.verified(Pin::Head(0));
    let catch_up = verify_registry_candidate(&trust, ChainSequence::new(250))
        .expect("the one direct intermediate Head is returned even if its Lease is exhausted");
    assert!(catch_up.preexisting_authority().is_some());
    assert_eq!(
        catch_up.registry_version(),
        future_sequence.heads()[1].version
    );
    assert!(catch_up.registry_head_hash() == future_sequence.heads()[1].object_hash);
}

#[test]
fn candidate_times_are_not_used_to_activate_the_candidate_during_task_seven() {
    let mut line = RegistryLineBuilder::new();
    let head1 = line.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(9_000_000_000_000),
            not_before: UnixMillis::new(8_999_999_999_500),
            not_after: UnixMillis::new(9_000_000_001_000),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::None);
    let candidate = verify_registry_candidate(&trust, head1.effective_from)
        .expect("future issuedAt/notBefore remain Task-11 selection concerns");
    assert_eq!(candidate.registry_version(), head1.version);
    assert!(candidate.registry_head_hash() == head1.object_hash);
}

#[test]
fn authorized_future_revocation_schedules_survive_registry_activation() {
    let mut device_line = RegistryLineBuilder::new();
    device_line.push(policy(), HeadOptions::default());
    let reader = device_line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions {
            revoked_from_sequence: Some(ChainSequence::new(1_000)),
            ..HeadOptions::default()
        },
    );
    let trust = device_line.verified(Pin::Head(0));
    verify_registry_candidate(&trust, reader.effective_from)
        .expect("an authorized Device may carry a future revocation schedule");

    for schedule_certificate in [true, false] {
        let mut admin_line = RegistryLineBuilder::new();
        admin_line.push(policy(), HeadOptions::default());
        let admin = admin_line.push(
            ActionSpec::AdminIssue {
                marker: 0x43,
                effective_from: None,
            },
            HeadOptions {
                revoked_from_sequence: schedule_certificate.then_some(ChainSequence::new(1_000)),
                ..HeadOptions::default()
            },
        );
        let admin_hash = admin.direct_object_hash.unwrap();
        let binding = admin_line.push(
            ActionSpec::OperatorBinding {
                certificate_hash: admin_hash,
                role: OperatorRoleV1::OrganizationAdmin,
                marker: 0x43,
                effective_from: None,
            },
            HeadOptions {
                revoked_from_sequence: (!schedule_certificate).then_some(ChainSequence::new(1_000)),
                ..HeadOptions::default()
            },
        );
        let binding_hash = binding.direct_object_hash.unwrap();
        let before_boundary = admin_line.push(
            policy(),
            HeadOptions {
                valid_through: Some(999),
                authorization_signer: AuthorizationSigner::NewAdmin {
                    certificate_hash: admin_hash,
                    binding_hash,
                },
                ..HeadOptions::default()
            },
        );
        let trust = admin_line.verified(Pin::Head(2));
        verify_registry_candidate(&trust, before_boundary.effective_from)
            .expect("a future-revoked Admin authority remains usable before its signed boundary");

        admin_line.push(
            policy(),
            HeadOptions {
                effective_from: Some(1_000),
                valid_through: Some(1_100),
                ..HeadOptions::default()
            },
        );
        admin_line.push(
            policy(),
            HeadOptions {
                effective_from: Some(1_001),
                authorization_signer: AuthorizationSigner::NewAdmin {
                    certificate_hash: admin_hash,
                    binding_hash,
                },
                ..HeadOptions::default()
            },
        );
        expect_error(&admin_line, Pin::Head(4), 1_001, "EA-TRUST-SIGNER-INACTIVE");
    }
}

#[test]
fn persisted_time_floor_cannot_change_the_structural_candidate_identity() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let head2 = line.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(1_800_000_000_000),
            not_before: UnixMillis::new(1_800_000_000_000),
            not_after: UnixMillis::new(1_800_000_010_000),
            ..HeadOptions::default()
        },
    );
    for floor in [UnixMillis::new(0), UnixMillis::new(9_000_000_000_000)] {
        let trust = line.verified_with_floor(Pin::Head(0), floor);
        let candidate = verify_registry_candidate(&trust, head2.effective_from)
            .expect("Task 7 cannot compare candidate time to either persisted floor");
        assert_eq!(candidate.registry_version(), head2.version);
        assert!(candidate.registry_head_hash() == head2.object_hash);
    }
}

#[test]
fn signed_event_time_and_sequence_shape_fail_closed_before_candidate_time() {
    for (label, options) in [
        (
            "notBefore after issuedAt",
            HeadOptions {
                issued_at: UnixMillis::new(100),
                not_before: UnixMillis::new(101),
                not_after: UnixMillis::new(200),
                ..HeadOptions::default()
            },
        ),
        (
            "issuedAt equals notAfter",
            HeadOptions {
                issued_at: UnixMillis::new(100),
                not_before: UnixMillis::new(90),
                not_after: UnixMillis::new(100),
                ..HeadOptions::default()
            },
        ),
        (
            "issuedAt after notAfter",
            HeadOptions {
                issued_at: UnixMillis::new(101),
                not_before: UnixMillis::new(90),
                not_after: UnixMillis::new(100),
                ..HeadOptions::default()
            },
        ),
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), options);
        expect_error(&line, Pin::None, 1, "EA-TRUST-POLICY-MISMATCH");
        assert!(!label.is_empty());
    }

    let mut target_policy_age = RegistryLineBuilder::new();
    target_policy_age.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(1_000),
            policy_max_registry_age_ms_override: Some(1_000),
            ..HeadOptions::default()
        },
    );
    target_policy_age.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(200),
            not_before: UnixMillis::new(190),
            not_after: UnixMillis::new(301),
            policy_max_registry_age_ms_override: Some(100),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &target_policy_age,
        Pin::Head(0),
        101,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut full_unsigned_age = RegistryLineBuilder::new();
    let full_age_head = full_unsigned_age.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(i64::MIN),
            not_before: UnixMillis::new(i64::MIN),
            not_after: UnixMillis::new(i64::MAX),
            policy_max_registry_age_ms_override: Some(u64::MAX),
            ..HeadOptions::default()
        },
    );
    let trust = full_unsigned_age.verified(Pin::None);
    verify_registry_candidate(&trust, full_age_head.effective_from)
        .expect("the full mathematically valid u64 age is accepted at the exact policy bound");

    let mut one_too_old = RegistryLineBuilder::new();
    one_too_old.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(i64::MIN),
            not_before: UnixMillis::new(i64::MIN),
            not_after: UnixMillis::new(i64::MAX),
            policy_max_registry_age_ms_override: Some(u64::MAX - 1),
            ..HeadOptions::default()
        },
    );
    expect_error(&one_too_old, Pin::None, 1, "EA-TRUST-POLICY-MISMATCH");

    let mut inverted_lease = RegistryLineBuilder::new();
    inverted_lease.push(
        policy(),
        HeadOptions {
            effective_from: Some(10),
            valid_through: Some(9),
            ..HeadOptions::default()
        },
    );
    expect_error(&inverted_lease, Pin::None, 10, "EA-TRUST-SEQUENCE-LEASE");
}

#[test]
fn immediate_successor_signer_state_uses_previous_lease_end_not_future_transition_sequence() {
    let mut line =
        RegistryLineBuilder::with_first_admin_revoked_from(Some(ChainSequence::new(101)));
    line.push(
        policy(),
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    let head2 = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(101),
            valid_through: Some(200),
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::Head(0));
    verify_registry_candidate(&trust, head2.effective_from).expect(
        "the signer is active at prior validThrough even if revoked at successor effectiveFrom",
    );
}

#[test]
fn every_action_zero_through_six_builds_one_exact_historical_transition() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let writer_a = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let writer_b = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::WriterTransition {
            old_writer: writer_a.direct_object_hash.unwrap(),
            new_writer: writer_b.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_b.direct_object_hash.unwrap(),
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let reader = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let server = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x64,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: reader.direct_object_hash.unwrap(),
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::Revoke {
            target_kind: 1,
            object_hash: binding.direct_object_hash.unwrap(),
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::Revoke {
            target_kind: 2,
            object_hash: server.direct_object_hash.unwrap(),
        },
        HeadOptions::default(),
    );
    let new_admin = line.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::AdminRevoke {
            object_hash: new_admin.direct_object_hash.unwrap(),
        },
        HeadOptions::default(),
    );
    line.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions::default(),
    );
    line.push(policy(), HeadOptions::default());

    for index in 0..line.heads().len() {
        let head = line.heads()[index];
        let pin = if index == 0 {
            Pin::None
        } else {
            Pin::Head(index - 1)
        };
        let trust = line.verified(pin);
        verify_registry_candidate(&trust, head.effective_from)
            .unwrap_or_else(|error| panic!("Head {} must verify: {}", index + 1, error.code()));
    }
}

#[test]
fn newly_activated_admin_certificate_and_binding_authorize_the_next_transition() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let new_admin = line.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let new_admin_hash = new_admin.direct_object_hash.unwrap();
    let new_binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: new_admin_hash,
            role: OperatorRoleV1::OrganizationAdmin,
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let new_binding_hash = new_binding.direct_object_hash.unwrap();
    let head4 = line.push(
        policy(),
        HeadOptions {
            authorization_signer: AuthorizationSigner::NewAdmin {
                certificate_hash: new_admin_hash,
                binding_hash: new_binding_hash,
            },
            ..HeadOptions::default()
        },
    );

    let trust = line.verified(Pin::Head(2));
    let candidate = verify_registry_candidate(&trust, head4.effective_from)
        .expect("the H2 Admin plus exact H3 Admin Binding must authorize H4");
    assert_eq!(candidate.registry_version(), head4.version);
    assert!(candidate.registry_head_hash() == head4.object_hash);
}

#[test]
fn policy_root_and_direct_effective_correlations_fail_closed() {
    let mut non_policy_head1 = RegistryLineBuilder::new();
    non_policy_head1.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(&non_policy_head1, Pin::None, 1, "EA-TRUST-ACTION-MISMATCH");

    let mut wrong_bootstrap_policy_version = RegistryLineBuilder::new();
    wrong_bootstrap_policy_version.push(
        ActionSpec::Policy {
            policy_version: Some(2),
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_bootstrap_policy_version,
        Pin::None,
        1,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut bootstrap_policy_with_previous = RegistryLineBuilder::new();
    bootstrap_policy_with_previous.push(
        ActionSpec::Policy {
            policy_version: Some(1),
            previous_policy_hash: Some(Some(support::object_hash_marker(0xc0))),
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &bootstrap_policy_with_previous,
        Pin::None,
        1,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut wrong_policy_increment = RegistryLineBuilder::new();
    wrong_policy_increment.push(policy(), HeadOptions::default());
    wrong_policy_increment.push(
        ActionSpec::Policy {
            policy_version: Some(3),
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_policy_increment,
        Pin::Head(0),
        101,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut wrong_policy_previous = RegistryLineBuilder::new();
    wrong_policy_previous.push(policy(), HeadOptions::default());
    wrong_policy_previous.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: Some(Some(support::object_hash_marker(0xc1))),
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_policy_previous,
        Pin::Head(0),
        101,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut wrong_change_two_event_policy = RegistryLineBuilder::new();
    wrong_change_two_event_policy.push(policy(), HeadOptions::default());
    let old_policy = wrong_change_two_event_policy.current_policy_hash().unwrap();
    wrong_change_two_event_policy.push(
        policy(),
        HeadOptions {
            policy_hash_override: Some(old_policy),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_change_two_event_policy,
        Pin::Head(0),
        101,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut wrong_nonchange_policy_hash = RegistryLineBuilder::new();
    wrong_nonchange_policy_hash.push(policy(), HeadOptions::default());
    wrong_nonchange_policy_hash.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            policy_hash_override: Some(support::object_hash_marker(0xc2)),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_nonchange_policy_hash,
        Pin::Head(0),
        101,
        "EA-TRUST-POLICY-MISMATCH",
    );

    for action in [
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: Some(102),
        },
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(102),
        },
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: Some(102),
        },
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(action, HeadOptions::default());
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");
    }

    let mut wrong_writer_effective = RegistryLineBuilder::new();
    wrong_writer_effective.push(policy(), HeadOptions::default());
    let writer_a = wrong_writer_effective.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let writer_b = wrong_writer_effective.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    wrong_writer_effective.push(
        ActionSpec::WriterTransition {
            old_writer: writer_a.direct_object_hash.unwrap(),
            new_writer: writer_b.direct_object_hash.unwrap(),
            effective_from: Some(302),
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_writer_effective,
        Pin::Head(2),
        301,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_binding_effective = RegistryLineBuilder::new();
    wrong_binding_effective.push(policy(), HeadOptions::default());
    let writer = wrong_binding_effective.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    wrong_binding_effective.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer.direct_object_hash.unwrap(),
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: Some(202),
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_binding_effective,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_root_version = RegistryLineBuilder::new();
    wrong_root_version.push(policy(), HeadOptions::default());
    wrong_root_version.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: Some(9),
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_root_version,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut new_root_signed_event = RegistryLineBuilder::new();
    new_root_signed_event.push(policy(), HeadOptions::default());
    new_root_signed_event.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            root_signer: support::RootSigner::Rotated,
            ..HeadOptions::default()
        },
    );
    expect_error(
        &new_root_signed_event,
        Pin::Head(0),
        101,
        "EA-TRUST-SIGNATURE",
    );

    let mut wrong_root_thumbprint = RegistryLineBuilder::new();
    wrong_root_thumbprint.push(policy(), HeadOptions::default());
    wrong_root_thumbprint.push(
        policy(),
        HeadOptions {
            root_key_thumbprint_override: Some(ea_types::KeyThumbprint::from(support::hash32(
                0xd5,
            ))),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_root_thumbprint,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTION-MISMATCH",
    );
}

#[test]
fn all_non_policy_actions_retain_the_exact_previous_policy_hash() {
    let wrong_policy = support::object_hash_marker(0xcf);

    let (mut revoke, standby_writer) = {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let standby_writer = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x62,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        (line, standby_writer.direct_object_hash.unwrap())
    };
    revoke.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: standby_writer,
        },
        HeadOptions {
            policy_hash_override: Some(wrong_policy),
            ..HeadOptions::default()
        },
    );
    expect_error(&revoke, Pin::Head(2), 301, "EA-TRUST-POLICY-MISMATCH");

    let mut writer_transition = RegistryLineBuilder::new();
    writer_transition.push(policy(), HeadOptions::default());
    let old = writer_transition.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let new = writer_transition.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    writer_transition.push(
        ActionSpec::WriterTransition {
            old_writer: old.direct_object_hash.unwrap(),
            new_writer: new.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions {
            policy_hash_override: Some(wrong_policy),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &writer_transition,
        Pin::Head(2),
        301,
        "EA-TRUST-POLICY-MISMATCH",
    );

    let mut binding = RegistryLineBuilder::new();
    binding.push(policy(), HeadOptions::default());
    let writer = binding.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    binding.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer.direct_object_hash.unwrap(),
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            policy_hash_override: Some(wrong_policy),
            ..HeadOptions::default()
        },
    );
    expect_error(&binding, Pin::Head(1), 201, "EA-TRUST-POLICY-MISMATCH");

    for action in [
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            action,
            HeadOptions {
                policy_hash_override: Some(wrong_policy),
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-POLICY-MISMATCH");
    }

    let mut admin_revoke = RegistryLineBuilder::new();
    admin_revoke.push(policy(), HeadOptions::default());
    let admin = admin_revoke.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    admin_revoke.push(
        ActionSpec::AdminRevoke {
            object_hash: admin.direct_object_hash.unwrap(),
        },
        HeadOptions {
            policy_hash_override: Some(wrong_policy),
            ..HeadOptions::default()
        },
    );
    expect_error(&admin_revoke, Pin::Head(1), 201, "EA-TRUST-POLICY-MISMATCH");
}
