mod support;

use ea_format::{CertificateKindV1, OperatorRoleV1, RegistryChangeV1, TrustSubtypeV1};
use ea_trust::{RegistryError, verify_registry_candidate};
use ea_types::{ChainId, ChainSequence, Hash32, RegistryVersion, UnixMillis};

use support::{
    ActionSpec, ChangeOverride, HeadOptions, Pin, PreviousHash, RegistryLineBuilder, RootSigner,
};

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

fn line_with_device(kind: CertificateKindV1) -> (RegistryLineBuilder, ea_types::ObjectHash) {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let device = line.push(
        ActionSpec::Device {
            kind,
            marker: kind as u8 + 0x60,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    (line, device.direct_object_hash.unwrap())
}

fn line_with_binding() -> (RegistryLineBuilder, ea_types::ObjectHash) {
    let (mut line, writer) = line_with_device(CertificateKindV1::Writer);
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    (line, binding.direct_object_hash.unwrap())
}

fn push_revoke(line: &mut RegistryLineBuilder, target_kind: u8, object_hash: ea_types::ObjectHash) {
    line.push(
        ActionSpec::Revoke {
            target_kind,
            object_hash,
        },
        HeadOptions::default(),
    );
}

#[test]
fn every_action_rejects_every_other_registry_change_class() {
    let wrong_changes = [
        (ChangeOverride::CertificateFromDirect, 0),
        (ChangeOverride::TargetFromDirect(0), 1),
        (ChangeOverride::WriterTransitionFromDirect, 3),
        (ChangeOverride::OperatorBindingFromDirect, 4),
        (ChangeOverride::AdminFromDirect(0), 5),
        (ChangeOverride::RootFromDirect, 6),
    ];
    for (change_override, event_action) in wrong_changes {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            policy(),
            HeadOptions {
                change_override,
                event_authorization_action: Some(event_action),
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");
    }

    let action_rows = [
        (
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            ChangeOverride::PolicyFromDirect,
            2,
        ),
        (
            ActionSpec::AdminIssue {
                marker: 0x43,
                effective_from: None,
            },
            ChangeOverride::CertificateFromDirect,
            0,
        ),
        (
            ActionSpec::RootRotate {
                previous_root_hash: None,
                effective_version: None,
            },
            ChangeOverride::AdminFromDirect(0),
            5,
        ),
    ];
    for (action, change_override, event_action) in action_rows {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            action,
            HeadOptions {
                change_override,
                event_authorization_action: Some(event_action),
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");
    }

    let (mut binding_line, writer) = line_with_device(CertificateKindV1::Writer);
    binding_line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            change_override: ChangeOverride::PolicyFromDirect,
            event_authorization_action: Some(2),
            ..HeadOptions::default()
        },
    );
    expect_error(&binding_line, Pin::Head(1), 201, "EA-TRUST-ACTION-MISMATCH");
}

#[test]
fn change_one_target_kind_partition_accepts_only_its_exact_active_classes() {
    let mut writer_line = RegistryLineBuilder::new();
    writer_line.push(policy(), HeadOptions::default());
    writer_line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let standby_writer = writer_line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    push_revoke(
        &mut writer_line,
        0,
        standby_writer.direct_object_hash.unwrap(),
    );
    let trust = writer_line.verified(Pin::Head(2));
    verify_registry_candidate(&trust, writer_line.heads()[3].effective_from)
        .expect("target-kind 0 may revoke a schedule-active non-current Writer");

    for kind in [
        CertificateKindV1::Reader,
        CertificateKindV1::KeyApprover,
        CertificateKindV1::RecoveryRecipient,
        CertificateKindV1::HistoricalGrantAuthority,
    ] {
        let (mut line, target) = line_with_device(kind);
        push_revoke(&mut line, 0, target);
        let trust = line.verified(Pin::Head(1));
        verify_registry_candidate(&trust, line.heads()[2].effective_from).unwrap_or_else(|error| {
            panic!(
                "target-kind 0 rejected kind {}: {}",
                kind as u8,
                error.code()
            )
        });
    }

    let (mut binding_line, binding) = line_with_binding();
    push_revoke(&mut binding_line, 1, binding);
    let trust = binding_line.verified(Pin::Head(2));
    verify_registry_candidate(&trust, binding_line.heads()[3].effective_from)
        .expect("target-kind 1 accepts only an active Operator Binding");

    for kind in [
        CertificateKindV1::ServerReceipt,
        CertificateKindV1::DeletionAttest,
    ] {
        let (mut line, target) = line_with_device(kind);
        push_revoke(&mut line, 2, target);
        let trust = line.verified(Pin::Head(1));
        verify_registry_candidate(&trust, line.heads()[2].effective_from).unwrap_or_else(|error| {
            panic!(
                "target-kind 2 rejected kind {}: {}",
                kind as u8,
                error.code()
            )
        });
    }
}

#[test]
fn change_one_crosses_each_target_kind_with_every_wrong_object_class() {
    for wrong_kind in [1, 2] {
        let (mut line, writer) = line_with_device(CertificateKindV1::Writer);
        push_revoke(&mut line, wrong_kind, writer);
        expect_error(
            &line,
            Pin::Head(1),
            line.heads()[2].effective_from.get(),
            "EA-TRUST-ACTION-MISMATCH",
        );
    }

    for wrong_kind in [0, 2] {
        let (mut line, binding) = line_with_binding();
        push_revoke(&mut line, wrong_kind, binding);
        expect_error(
            &line,
            Pin::Head(2),
            line.heads()[3].effective_from.get(),
            "EA-TRUST-ACTION-MISMATCH",
        );
    }

    for wrong_kind in [0, 1] {
        let (mut line, server) = line_with_device(CertificateKindV1::ServerReceipt);
        push_revoke(&mut line, wrong_kind, server);
        expect_error(
            &line,
            Pin::Head(1),
            line.heads()[2].effective_from.get(),
            "EA-TRUST-ACTION-MISMATCH",
        );
    }

    for target_kind in 0..=2 {
        let mut admin_line = RegistryLineBuilder::new();
        admin_line.push(policy(), HeadOptions::default());
        let admin = admin_line.bootstrap_admin_hash();
        push_revoke(&mut admin_line, target_kind, admin);
        expect_error(&admin_line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");

        let mut root_line = RegistryLineBuilder::new();
        root_line.push(policy(), HeadOptions::default());
        let root = root_line.current_root_hash();
        push_revoke(&mut root_line, target_kind, root);
        expect_error(&root_line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");

        let mut policy_line = RegistryLineBuilder::new();
        policy_line.push(policy(), HeadOptions::default());
        let active_policy = policy_line.current_policy_hash().unwrap();
        push_revoke(&mut policy_line, target_kind, active_policy);
        expect_error(&policy_line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");

        let mut transition_line = RegistryLineBuilder::new();
        transition_line.push(policy(), HeadOptions::default());
        let old = transition_line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let new = transition_line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x62,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let transition = transition_line.push(
            ActionSpec::WriterTransition {
                old_writer: old.direct_object_hash.unwrap(),
                new_writer: new.direct_object_hash.unwrap(),
                effective_from: None,
            },
            HeadOptions::default(),
        );
        push_revoke(
            &mut transition_line,
            target_kind,
            transition.direct_object_hash.unwrap(),
        );
        expect_error(
            &transition_line,
            Pin::Head(3),
            transition_line.heads()[4].effective_from.get(),
            "EA-TRUST-ACTION-MISMATCH",
        );
    }
}

#[test]
fn change_one_rejects_unknown_prepared_and_already_revoked_targets() {
    for target_kind in 0..=2 {
        let mut unknown = RegistryLineBuilder::new();
        unknown.push(policy(), HeadOptions::default());
        push_revoke(&mut unknown, target_kind, support::object_hash_marker(0xd1));
        expect_error(&unknown, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-MISSING");
    }

    let mut prepared = RegistryLineBuilder::new();
    prepared.push(policy(), HeadOptions::default());
    let prepared_writer = prepared.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Writer,
        marker: 0x61,
        effective_from: None,
    });
    push_revoke(&mut prepared, 0, prepared_writer);
    expect_error(&prepared, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-MISSING");

    let mut prepared_component = RegistryLineBuilder::new();
    prepared_component.push(policy(), HeadOptions::default());
    let component = prepared_component.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::ServerReceipt,
        marker: 0x66,
        effective_from: None,
    });
    push_revoke(&mut prepared_component, 2, component);
    expect_error(
        &prepared_component,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTIVATION-MISSING",
    );

    let (mut prepared_binding, writer) = line_with_device(CertificateKindV1::Writer);
    let binding = prepared_binding.add_prepared(ActionSpec::OperatorBinding {
        certificate_hash: writer,
        role: OperatorRoleV1::Writer,
        marker: 0x71,
        effective_from: None,
    });
    push_revoke(&mut prepared_binding, 1, binding);
    expect_error(
        &prepared_binding,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTIVATION-MISSING",
    );

    let (mut current_writer, writer) = line_with_device(CertificateKindV1::Writer);
    push_revoke(&mut current_writer, 0, writer);
    expect_error(
        &current_writer,
        Pin::Head(1),
        current_writer.heads()[2].effective_from.get(),
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut already_revoked = RegistryLineBuilder::new();
    already_revoked.push(policy(), HeadOptions::default());
    already_revoked.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let standby_writer = already_revoked.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let standby_writer = standby_writer.direct_object_hash.unwrap();
    push_revoke(&mut already_revoked, 0, standby_writer);
    push_revoke(&mut already_revoked, 0, standby_writer);
    expect_error(
        &already_revoked,
        Pin::Head(3),
        already_revoked.heads()[4].effective_from.get(),
        "EA-TRUST-ACTION-MISMATCH",
    );

    let (mut revoked_binding, binding) = line_with_binding();
    push_revoke(&mut revoked_binding, 1, binding);
    push_revoke(&mut revoked_binding, 1, binding);
    expect_error(
        &revoked_binding,
        Pin::Head(3),
        revoked_binding.heads()[4].effective_from.get(),
        "EA-TRUST-ACTION-MISMATCH",
    );

    let (mut revoked_component, server) = line_with_device(CertificateKindV1::ServerReceipt);
    push_revoke(&mut revoked_component, 2, server);
    push_revoke(&mut revoked_component, 2, server);
    expect_error(
        &revoked_component,
        Pin::Head(2),
        revoked_component.heads()[3].effective_from.get(),
        "EA-TRUST-ACTION-MISMATCH",
    );
}

#[test]
fn operator_binding_activation_requires_an_active_role_compatible_certificate() {
    let mut missing = RegistryLineBuilder::new();
    missing.push(policy(), HeadOptions::default());
    missing.push(
        ActionSpec::OperatorBinding {
            certificate_hash: support::object_hash_marker(0xe1),
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(&missing, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-MISSING");

    let mut prepared = RegistryLineBuilder::new();
    prepared.push(policy(), HeadOptions::default());
    let prepared_writer = prepared.add_prepared(ActionSpec::Device {
        kind: CertificateKindV1::Writer,
        marker: 0x61,
        effective_from: None,
    });
    prepared.push(
        ActionSpec::OperatorBinding {
            certificate_hash: prepared_writer,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            direct_authorization_id: Some(0xa0),
            event_authorization_id: Some(0xa1),
            direct_nonce: Some(0xb0),
            event_nonce: Some(0xb1),
            ..HeadOptions::default()
        },
    );
    expect_error(&prepared, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-MISSING");

    let (mut revoked, writer) = line_with_device(CertificateKindV1::Writer);
    push_revoke(&mut revoked, 0, writer);
    revoked.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(&revoked, Pin::Head(2), 301, "EA-TRUST-ACTION-MISMATCH");

    for (certificate_kind, role) in [
        (CertificateKindV1::Reader, OperatorRoleV1::Writer),
        (CertificateKindV1::Writer, OperatorRoleV1::Reader),
    ] {
        let (mut line, certificate) = line_with_device(certificate_kind);
        line.push(
            ActionSpec::OperatorBinding {
                certificate_hash: certificate,
                role,
                marker: 0x71,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        expect_error(&line, Pin::Head(1), 201, "EA-TRUST-ACTION-MISMATCH");
    }

    let (mut writer_as_admin, writer) = line_with_device(CertificateKindV1::Writer);
    writer_as_admin.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::OrganizationAdmin,
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &writer_as_admin,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_admin_subject = RegistryLineBuilder::new();
    wrong_admin_subject.push(policy(), HeadOptions::default());
    let admin = wrong_admin_subject.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    wrong_admin_subject.push(
        ActionSpec::OperatorBinding {
            certificate_hash: admin.direct_object_hash.unwrap(),
            role: OperatorRoleV1::OrganizationAdmin,
            marker: 0x44,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_admin_subject,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let (mut reused_signing_key, writer) = line_with_device(CertificateKindV1::Writer);
    reused_signing_key.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer,
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(
                support::authorized_device_signing_key_thumbprint(),
            ),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &reused_signing_key,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut revoked_at_binding_effective = RegistryLineBuilder::new();
    revoked_at_binding_effective.push(policy(), HeadOptions::default());
    let writer = revoked_at_binding_effective.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            revoked_from_sequence: Some(ChainSequence::new(201)),
            ..HeadOptions::default()
        },
    );
    revoked_at_binding_effective.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer.direct_object_hash.unwrap(),
            role: OperatorRoleV1::Writer,
            marker: 0x71,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &revoked_at_binding_effective,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );
}

#[test]
fn writer_transition_requires_two_distinct_active_writer_certificates() {
    let mut repeated = RegistryLineBuilder::new();
    repeated.push(policy(), HeadOptions::default());
    let writer = repeated.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let writer = writer.direct_object_hash.unwrap();
    repeated.push(
        ActionSpec::WriterTransition {
            old_writer: writer,
            new_writer: writer,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(&repeated, Pin::Head(1), 201, "EA-TRUST-ACTION-MISMATCH");

    let mut wrong_current_writer = RegistryLineBuilder::new();
    wrong_current_writer.push(policy(), HeadOptions::default());
    let current_writer = wrong_current_writer.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let next_writer = wrong_current_writer.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let unrelated_writer = wrong_current_writer.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x63,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    assert!(current_writer.direct_object_hash != unrelated_writer.direct_object_hash);
    wrong_current_writer.push(
        ActionSpec::WriterTransition {
            old_writer: unrelated_writer.direct_object_hash.unwrap(),
            new_writer: next_writer.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_current_writer,
        Pin::Head(3),
        401,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_chain = RegistryLineBuilder::new();
    wrong_chain.push(policy(), HeadOptions::default());
    let old_writer = wrong_chain.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let new_writer = wrong_chain.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    wrong_chain.push(
        ActionSpec::WriterTransition {
            old_writer: old_writer.direct_object_hash.unwrap(),
            new_writer: new_writer.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions {
            writer_chain_id_override: Some(ChainId::try_from(&[0xd4; 16][..]).unwrap()),
            ..HeadOptions::default()
        },
    );
    expect_error(&wrong_chain, Pin::Head(2), 301, "EA-TRUST-ACTION-MISMATCH");

    let mut new_writer_revoked_at_transition = RegistryLineBuilder::new();
    new_writer_revoked_at_transition.push(policy(), HeadOptions::default());
    let old_writer = new_writer_revoked_at_transition.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let new_writer = new_writer_revoked_at_transition.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions {
            revoked_from_sequence: Some(ChainSequence::new(301)),
            ..HeadOptions::default()
        },
    );
    new_writer_revoked_at_transition.push(
        ActionSpec::WriterTransition {
            old_writer: old_writer.direct_object_hash.unwrap(),
            new_writer: new_writer.direct_object_hash.unwrap(),
            effective_from: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &new_writer_revoked_at_transition,
        Pin::Head(2),
        301,
        "EA-TRUST-ACTION-MISMATCH",
    );

    for missing_is_new in [false, true] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        let active = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let active = active.direct_object_hash.unwrap();
        let missing = support::object_hash_marker(if missing_is_new { 0xe3 } else { 0xe2 });
        let (old, new) = if missing_is_new {
            (active, missing)
        } else {
            (missing, active)
        };
        line.push(
            ActionSpec::WriterTransition {
                old_writer: old,
                new_writer: new,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        expect_error(&line, Pin::Head(1), 201, "EA-TRUST-ACTIVATION-MISSING");
    }

    for prepared_is_new in [false, true] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        let active = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let active = active.direct_object_hash.unwrap();
        let prepared = line.add_prepared(ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x62,
            effective_from: None,
        });
        let (old, new) = if prepared_is_new {
            (active, prepared)
        } else {
            (prepared, active)
        };
        line.push(
            ActionSpec::WriterTransition {
                old_writer: old,
                new_writer: new,
                effective_from: None,
            },
            HeadOptions {
                direct_authorization_id: Some(0xa2),
                event_authorization_id: Some(0xa3),
                direct_nonce: Some(0xb2),
                event_nonce: Some(0xb3),
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(1), 201, "EA-TRUST-ACTIVATION-MISSING");
    }

    for reader_is_new in [false, true] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        let writer = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let reader = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Reader,
                marker: 0x62,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        let (old, new) = if reader_is_new {
            (
                writer.direct_object_hash.unwrap(),
                reader.direct_object_hash.unwrap(),
            )
        } else {
            (
                reader.direct_object_hash.unwrap(),
                writer.direct_object_hash.unwrap(),
            )
        };
        line.push(
            ActionSpec::WriterTransition {
                old_writer: old,
                new_writer: new,
                effective_from: None,
            },
            HeadOptions::default(),
        );
        expect_error(&line, Pin::Head(2), 301, "EA-TRUST-ACTION-MISMATCH");
    }
}

#[test]
fn direct_targets_require_exact_activation_and_same_previous_head() {
    let mut missing_target = RegistryLineBuilder::new();
    missing_target.push(policy(), HeadOptions::default());
    missing_target.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            change_override: ChangeOverride::Raw(RegistryChangeV1::Certificate {
                object_hash: support::object_hash_marker(0xd2),
            }),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &missing_target,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTIVATION-MISSING",
    );

    for options in [
        HeadOptions {
            direct_authorization_basis: Some((RegistryVersion::new(0), Hash32::ZERO)),
            ..HeadOptions::default()
        },
        HeadOptions {
            event_authorization_basis: Some((RegistryVersion::new(0), Hash32::ZERO)),
            ..HeadOptions::default()
        },
    ] {
        let mut wrong_head = RegistryLineBuilder::new();
        wrong_head.push(policy(), HeadOptions::default());
        wrong_head.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options,
        );
        expect_error(&wrong_head, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-HEAD");
    }

    for omission in 0..3 {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            HeadOptions {
                omit_direct_object: omission == 0,
                omit_direct_authorization: omission == 1,
                omit_event_authorization: omission == 2,
                ..HeadOptions::default()
            },
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-ACTIVATION-MISSING");
    }
}

#[test]
fn direct_and_event_authorizations_are_distinct_one_use_and_action_exact() {
    for options in [
        HeadOptions {
            direct_authorization_id: Some(0xa1),
            event_authorization_id: Some(0xa1),
            ..HeadOptions::default()
        },
        HeadOptions {
            direct_nonce: Some(0xb1),
            event_nonce: Some(0xb1),
            ..HeadOptions::default()
        },
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options,
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-AUTH-REPLAY");
    }

    for options in [
        HeadOptions {
            direct_authorization_id: Some(0x20),
            ..HeadOptions::default()
        },
        HeadOptions {
            direct_nonce: Some(0x60),
            ..HeadOptions::default()
        },
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options,
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-AUTH-REPLAY");
    }

    for options in [
        HeadOptions {
            direct_authorization_action: Some(2),
            ..HeadOptions::default()
        },
        HeadOptions {
            event_authorization_action: Some(2),
            ..HeadOptions::default()
        },
        HeadOptions {
            direct_authorization_subtype: Some(TrustSubtypeV1::Policy),
            ..HeadOptions::default()
        },
        HeadOptions {
            event_authorization_subtype: Some(TrustSubtypeV1::Policy),
            ..HeadOptions::default()
        },
    ] {
        let mut line = RegistryLineBuilder::new();
        line.push(policy(), HeadOptions::default());
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options,
        );
        expect_error(&line, Pin::Head(0), 101, "EA-TRUST-ACTION-MISMATCH");
    }
}

#[test]
fn competing_same_version_action_events_are_a_fork_not_a_multi_action_transition() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    line.add_branch(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    line.add_branch(policy(), HeadOptions::default());
    expect_error(&line, Pin::Head(0), 101, "EA-TRUST-REGISTRY-FORK");
}

#[test]
fn admin_effects_and_root_rotation_are_closed_to_their_exact_targets() {
    let mut missing_admin_capability = RegistryLineBuilder::new();
    missing_admin_capability.push(policy(), HeadOptions::default());
    missing_admin_capability.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions {
            certificate_capabilities_override: Some(Vec::new()),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &missing_admin_capability,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_issue_effect = RegistryLineBuilder::new();
    wrong_issue_effect.push(policy(), HeadOptions::default());
    wrong_issue_effect.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions {
            change_override: ChangeOverride::AdminFromDirect(1),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_issue_effect,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_revoke_effect = RegistryLineBuilder::new();
    wrong_revoke_effect.push(policy(), HeadOptions::default());
    let admin = wrong_revoke_effect.push(
        ActionSpec::AdminIssue {
            marker: 0x43,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let admin_hash = admin.direct_object_hash.unwrap();
    wrong_revoke_effect.push(
        ActionSpec::AdminRevoke {
            object_hash: admin_hash,
        },
        HeadOptions {
            change_override: ChangeOverride::Raw(RegistryChangeV1::AdminCertificate {
                object_hash: admin_hash,
                effect: 0,
            }),
            ..HeadOptions::default()
        },
    );
    expect_error(
        &wrong_revoke_effect,
        Pin::Head(1),
        201,
        "EA-TRUST-ACTION-MISMATCH",
    );

    let mut wrong_root_previous = RegistryLineBuilder::new();
    wrong_root_previous.push(policy(), HeadOptions::default());
    wrong_root_previous.push(
        ActionSpec::RootRotate {
            previous_root_hash: Some(support::object_hash_marker(0xd3)),
            effective_version: None,
        },
        HeadOptions::default(),
    );
    expect_error(
        &wrong_root_previous,
        Pin::Head(0),
        101,
        "EA-TRUST-ACTION-MISMATCH",
    );
}

#[test]
fn later_head_semantics_replay_and_time_cannot_cross_the_singular_prefix_barrier() {
    let mut valid_prefix = RegistryLineBuilder::new();
    valid_prefix.push(policy(), HeadOptions::default());
    let future_head2 = valid_prefix.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            issued_at: UnixMillis::new(1_800_000_000_000),
            not_before: UnixMillis::new(1_800_000_000_000),
            not_after: UnixMillis::new(1_800_000_010_000),
            ..HeadOptions::default()
        },
    );
    valid_prefix.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(1),
            not_before: UnixMillis::new(1),
            not_after: UnixMillis::new(10_000),
            ..HeadOptions::default()
        },
    );
    let trust = valid_prefix.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, future_head2.effective_from)
        .expect("a valid early H3 signed under H2 cannot skip future H2");
    assert_eq!(candidate.registry_version(), future_head2.version);
    assert!(candidate.registry_head_hash() == future_head2.object_hash);

    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    let head2 = line.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions {
            issued_at: UnixMillis::new(1_800_000_000_000),
            not_before: UnixMillis::new(1_800_000_000_000),
            not_after: UnixMillis::new(1_800_000_010_000),
            ..HeadOptions::default()
        },
    );
    line.push(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(1),
            not_before: UnixMillis::new(1),
            not_after: UnixMillis::new(10_000),
            direct_authorization_id: Some(0x22),
            event_authorization_id: Some(0x23),
            direct_nonce: Some(0x62),
            event_nonce: Some(0x63),
            root_signer: RootSigner::Corrupt,
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, head2.effective_from)
        .expect("H3 signature/action/replay/time must not affect singular future H2");
    assert!(candidate.preexisting_authority().is_some());
    assert_eq!(candidate.registry_version(), head2.version);
    assert!(candidate.registry_head_hash() == head2.object_hash);

    let topology_mutations = [
        HeadOptions {
            previous_hash: PreviousHash::Value(support::hash32(0xd4)),
            ..HeadOptions::default()
        },
        HeadOptions {
            registry_version: Some(4),
            ..HeadOptions::default()
        },
    ];
    for mutation in topology_mutations {
        let mut topology = RegistryLineBuilder::new();
        topology.push(policy(), HeadOptions::default());
        let head2 = topology.push(policy(), HeadOptions::default());
        topology.push(policy(), mutation);
        let trust = topology.verified(Pin::Head(0));
        let candidate = verify_registry_candidate(&trust, head2.effective_from)
            .expect("topology after singular H2 is outside the Task-7 prefix");
        assert_eq!(candidate.registry_version(), head2.version);
        assert!(candidate.registry_head_hash() == head2.object_hash);
    }

    let mut later_fork = RegistryLineBuilder::new();
    later_fork.push(policy(), HeadOptions::default());
    let head2 = later_fork.push(policy(), HeadOptions::default());
    later_fork.add_branch(policy(), HeadOptions::default());
    later_fork.add_branch(
        policy(),
        HeadOptions {
            issued_at: UnixMillis::new(101),
            ..HeadOptions::default()
        },
    );
    let trust = later_fork.verified(Pin::Head(0));
    let candidate = verify_registry_candidate(&trust, head2.effective_from)
        .expect("a fork after singular H2 is not inspected before H2 is persisted");
    assert_eq!(candidate.registry_version(), head2.version);
    assert!(candidate.registry_head_hash() == head2.object_hash);
}

#[test]
fn candidate_local_replay_is_discarded_after_a_late_failure() {
    let mut line = RegistryLineBuilder::new();
    line.push(policy(), HeadOptions::default());
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        HeadOptions {
            root_signer: RootSigner::Corrupt,
            ..HeadOptions::default()
        },
    );
    let trust = line.verified(Pin::Head(0));
    for _ in 0..2 {
        let error = verify_registry_candidate(&trust, ChainSequence::new(101))
            .err()
            .expect("the corrupt Root signature remains the only failure");
        assert_eq!(error.code(), "EA-TRUST-SIGNATURE");
    }
}
