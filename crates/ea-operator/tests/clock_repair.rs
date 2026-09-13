#[path = "../../ea-trust/tests/support/clock_repair_fixture.rs"]
mod fixture;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;
use ea_crypto::CanonicalPublicCoseKey;
use ea_operator::{
    ClockRepairProfileSnapshot, OperatorError, OsAccountProvider, authenticate_clock_repair,
};
use ea_types::{DeviceId, Hash32, OrganizationId, UnixMillis};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::Cell;

struct Account {
    wrong_account: bool,
    wrong_instance: bool,
}
impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _: OrganizationId,
        _: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(if self.wrong_account {
            support::hash32(0x44)
        } else {
            fixture::account_hash()
        })
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(if self.wrong_instance {
            CanonicalPublicCoseKey::ed25519(
                SigningKey::from_bytes(&[0x69; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap()
        } else {
            fixture::instance_public()
        }))
    }
}
fn profile(binding: ea_types::ObjectHash) -> ClockRepairProfileSnapshot<'static> {
    ClockRepairProfileSnapshot {
        organization_id: support::organization(),
        operator_subject_id: fixture::subject(),
        binding_hash: binding,
        display_name: fixture::NAME,
        function_label: fixture::FUNCTION,
        salt: &fixture::SALT,
    }
}
#[test]
fn repair_presence_signs_exact_context_once_and_never_becomes_a_general_session() {
    let f = fixture::fixture();
    let account = Account {
        wrong_account: false,
        wrong_instance: false,
    };
    let called = Cell::new(0);
    let mut proof = authenticate_clock_repair(
        &f.authority,
        &account,
        &fixture::signing_public(),
        &profile(f.binding),
        |challenge| {
            called.set(called.get() + 1);
            assert!(
                challenge
                    .windows(32)
                    .any(|bytes| bytes == f.authority.context_hash().as_bytes())
            );
            Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                .sign(challenge)
                .to_bytes())
        },
    )
    .expect("actual signed Clock-only presence");
    assert_eq!(called.get(), 1);
    assert!(proof.context_hash() == f.authority.context_hash());
    assert!(proof.is_valid_at(UnixMillis::new(fixture::NOW + 299_999)));
    assert!(!proof.is_valid_at(UnixMillis::new(fixture::NOW + 300_000)));
    proof.invalidate_on_lock();
    assert!(!proof.is_valid_at(UnixMillis::new(fixture::NOW + 1)));
}
#[test]
fn repair_presence_refuses_foreign_account_instance_device_key_profile_and_signature() {
    let f = fixture::fixture();
    for (account_wrong, instance_wrong, key_wrong, profile_wrong) in [
        (true, false, false, false),
        (false, true, false, false),
        (false, false, true, false),
        (false, false, false, true),
    ] {
        let account = Account {
            wrong_account: account_wrong,
            wrong_instance: instance_wrong,
        };
        let mut data = profile(f.binding);
        if profile_wrong {
            data.display_name = "changed profile";
        }
        let key = if key_wrong {
            fixture::instance_public()
        } else {
            fixture::signing_public()
        };
        let called = Cell::new(0);
        let result = authenticate_clock_repair(&f.authority, &account, &key, &data, |challenge| {
            called.set(called.get() + 1);
            Ok(SigningKey::from_bytes(&fixture::INSTANCE)
                .sign(challenge)
                .to_bytes())
        });
        assert!(result.is_err());
        assert_eq!(
            called.get(),
            0,
            "identity/profile refusal precedes presence"
        );
    }
    assert!(
        authenticate_clock_repair(
            &f.authority,
            &Account {
                wrong_account: false,
                wrong_instance: false
            },
            &fixture::signing_public(),
            &profile(f.binding),
            |_| Ok([0; 64]),
        )
        .is_err()
    );
}
