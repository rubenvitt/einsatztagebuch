//! Der Sitzungsvertrag des Bedieners.
//!
//! Die Fixture baut eine ECHTE Registry-Linie, waehlt einen ECHTEN Head und
//! loest die Bindung durch `SelectedRegistryHead::active_operator_binding_fields`
//! auf. Sie stellt keine Bindung frei her: eine selbst gebaute Bindung wuerde
//! genau die Pruefung ueberspringen, die dieser Test belegen soll. Aus demselben
//! Grund entsteht auch keine freie Zeit — jede Gueltigkeitsaussage laeuft ueber
//! `PreexistingEffectiveNow` eines gewaehlten Head.

#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_crypto::{
    linux_os_account_binding_hash, macos_os_account_binding_hash, windows_os_account_binding_hash,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OsAccountInputs, OsAccountProvider,
    ReauthPurpose,
};
use ea_types::{DeviceId, Hash32, OrganizationId};

/// Der Bedienerinstanzschluessel der Fixture.
///
/// Ein echtes Ed25519-Schluesselpaar: die Fixture setzt seinen Thumbprint in die
/// Bindung und signiert die Challenge damit, also prueft der Standardkoerper von
/// `reauthenticate` eine echte Signatur und keine Attrappe.
const INSTANCE_SECRET: [u8; 32] = [
    0x4a, 0x1c, 0x2e, 0x93, 0x77, 0x05, 0xbb, 0x61, 0x18, 0x8f, 0xd2, 0x40, 0x36, 0xa7, 0x5c, 0xe1,
    0x09, 0x94, 0x6d, 0x3b, 0xcf, 0x82, 0x17, 0x50, 0xe4, 0x2a, 0x68, 0xd9, 0x0b, 0x73, 0xf6, 0x84,
];

/// Ein ANDERER Instanzschluessel: dasselbe gebundene Konto, aber nicht der
/// Schluessel, den die Bindung nennt.
const OTHER_INSTANCE_SECRET: [u8; 32] = [
    0x1f, 0x3d, 0x55, 0x02, 0xa9, 0xc4, 0x6e, 0x17, 0x8b, 0x20, 0x74, 0xdd, 0x91, 0x0c, 0x38, 0xf2,
    0x46, 0xe7, 0xb1, 0x5a, 0x23, 0x9d, 0x60, 0xcc, 0x08, 0x71, 0x4f, 0xa3, 0xd6, 0x12, 0x89, 0x35,
];

mod fixtures {
    use std::cell::RefCell;

    use ea_crypto::CanonicalPublicCoseKey;
    use ea_format::{CertificateKindV1, OperatorRoleV1};
    use ea_operator::{BoundOperator, OperatorError, OsAccountProvider};
    use ea_time::TrustedTimeState;
    use ea_trust::{
        ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
        RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
        TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
        verify_registry_candidate,
    };
    use ea_types::{
        ChainSequence, DeviceId, Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis,
    };
    use ed25519_dalek::SigningKey;

    use super::{
        INSTANCE_SECRET, OTHER_INSTANCE_SECRET,
        support::{self, ActionSpec, HeadOptions, Pin, RegistryLineBuilder},
    };

    /// Die Marke, unter der die Fixture ihre Bedienerbindung baut.
    ///
    /// `crates/ea-trust/tests/support/mod.rs:811` bildet den
    /// `os_account_binding_hash` einer gebauten Bindung als `hash32(marke + 2)`.
    /// Das ist ein synthetischer Wert und kein Ergebnis von
    /// `ea_crypto::*_os_account_binding_hash` — ein Bindungshash ist nicht
    /// umkehrbar, also kann keine Rohangabe eines Kontos ihn treffen. Die
    /// Kontoattrappe meldet deshalb den Bindungshash unmittelbar, und die
    /// Umrechnung von Rohangaben zu einem Bindungshash belegt
    /// `the_three_platform_harvests_reproduce_the_frozen_stage_one_digests`
    /// gegen die eingefrorenen Stufe-1-Vektoren.
    const BINDING_MARKER: u8 = 0x71;

    /// Der Zeitpunkt, den die Fixture als OS-Wanduhr und als Vertrauenszeit
    /// setzt; `PreexistingEffectiveNow` des gewaehlten Head traegt genau ihn.
    pub const FIXTURE_NOW_MS: i64 = 1_000;

    /// Die Sequenz, an der die Fixture waehlt — im Fenster des letzten Head und
    /// hinter der Wirksamkeit von Zertifikat und Bindung.
    const PROPOSED_SEQUENCE: u64 = 30;

    /// Das Ende der Signaturgueltigkeit jedes Fixture-Objekts.
    ///
    /// Weit hinter jedem Zeitpunkt, an dem ein Test einen Head waehlt: die
    /// Ablaufpruefung dieses Tests gilt dem FUENFMINUTENFENSTER des Nachweises
    /// und nicht der Zertifikatsgueltigkeit, und ohne diese Ausweitung liefe die
    /// Fixture bei `FIXTURE_NOW_MS + 301_000` gegen den Vorgabewert `10_000`.
    const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;

    /// Der Speicher, aus dem die Auswahl ihren persistierten Stand liest.
    ///
    /// `PersistedTrustRecord` ist absichtlich nicht `Clone`, also haelt dieser
    /// Speicher seine Bestandteile und baut den Datensatz bei jedem Lesevorgang
    /// neu — wie `ModelStore` in `crates/ea-trust/tests/head_selection.rs:98`.
    /// Der Auswahl-Commit ist echt gebucht; `commit_independent_time` bleibt
    /// `Unavailable`, weil diese Fixture keine unabhaengigen Zeitquellen
    /// mitgibt. Wuerde sie es je tun, braeche sie laut ab statt stillschweigend
    /// einen anderen Zeitpfad zu belegen.
    struct ModelStore {
        key: TrustStateKey,
        revision: u64,
        trusted_time: TrustedTimeState,
        pinned_head: RegistryHeadPin,
    }

    impl TrustStateStore for ModelStore {
        fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
            if key != self.key {
                return Err(StateStoreError::Conflict);
            }
            Ok(PersistedTrustRecord::new(
                self.revision,
                self.trusted_time.clone(),
                Some(self.pinned_head),
            ))
        }

        fn commit_independent_time(
            &mut self,
            _key: TrustStateKey,
            _expected_revision: u64,
            _commit: &IndependentTimeCommit,
        ) -> Result<PersistedTrustRecord, StateStoreError> {
            Err(StateStoreError::Unavailable)
        }

        fn clock_release_consumed(
            &mut self,
            _key: &ClockReleaseReplayKey,
        ) -> Result<bool, StateStoreError> {
            Ok(false)
        }

        /// Der Auswahl-Commit, den `select_registry_head` auch auf dem
        /// „Head ist schon gepinnt"-Pfad IMMER faehrt
        /// (`crates/ea-trust/src/registry.rs:626-633`).
        ///
        /// Er wird gebucht und nicht bejaht: die Fassung steigt, und der
        /// zurueckgegebene Datensatz traegt genau die Zeit und den Pin, die der
        /// Commit nennt. Ein Speicher, der hier etwas anderes zurueckgibt, wird
        /// von `commit_selection` mit `StateConflict` abgewiesen — die Fixture
        /// belegt also den echten Auswahlpfad und keinen verkuerzten.
        fn commit_registry_selection(
            &mut self,
            key: TrustStateKey,
            expected_revision: u64,
            commit: &RegistrySelectionCommit,
        ) -> Result<PersistedTrustRecord, StateStoreError> {
            if key != self.key || expected_revision != self.revision {
                return Err(StateStoreError::Conflict);
            }
            self.revision += 1;
            self.trusted_time = commit.next_trusted_time().clone();
            self.pinned_head = *commit.next_head();
            Ok(PersistedTrustRecord::new(
                self.revision,
                self.trusted_time.clone(),
                Some(self.pinned_head),
            ))
        }
    }

    fn signing_key(secret: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&secret)
    }

    fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
            .expect("the fixture instance key is a valid Ed25519 public key")
    }

    fn head_options(effective_from: u64, valid_through: u64) -> HeadOptions {
        HeadOptions {
            effective_from: Some(effective_from),
            valid_through: Some(valid_through),
            not_after: UnixMillis::new(FIXTURE_NOT_AFTER_MS),
            ..HeadOptions::default()
        }
    }

    /// Baut die Registry-Linie und nennt den Objekthash der Bedienerbindung.
    ///
    /// Deterministisch: feste Geheimnisse, feste Marken, feste Fenster. Zwei
    /// Aufrufe liefern dieselbe Linie und denselben Bindungshash.
    fn build_line() -> (RegistryLineBuilder, ObjectHash, ObjectHash) {
        let mut line = RegistryLineBuilder::new();
        line.push(
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            head_options(1, 10),
        );
        let writer = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            head_options(11, 20),
        );
        let binding = line.push(
            ActionSpec::OperatorBinding {
                certificate_hash: writer
                    .direct_object_hash
                    .expect("the fixture Writer certificate is a direct target"),
                role: OperatorRoleV1::Writer,
                marker: BINDING_MARKER,
                effective_from: None,
            },
            HeadOptions {
                // Die Bindung nennt den Thumbprint des Instanzschluessels, den
                // die Kontoattrappe vorlegt und mit dem sie signiert.
                binding_instance_key_thumbprint_override: Some(KeyThumbprint::from(
                    Hash32::try_from(
                        public_key(INSTANCE_SECRET)
                            .thumbprint()
                            .as_bytes()
                            .as_slice(),
                    )
                    .expect("a thumbprint is 32 bytes"),
                )),
                ..head_options(21, 100)
            },
        );
        let binding_object_hash = binding
            .direct_object_hash
            .expect("the fixture operator binding is a direct target");
        let writer_object_hash = writer
            .direct_object_hash
            .expect("the fixture Writer certificate is a direct target");
        (line, binding_object_hash, writer_object_hash)
    }

    /// Der Objekthash der Bedienerbindung dieser Fixture.
    #[must_use]
    pub fn binding_object_hash() -> ObjectHash {
        build_line().1
    }

    /// Der Objekthash des Writer-Zertifikats — ein echtes Objekt der Linie, das
    /// KEINE Bedienerbindung ist.
    #[must_use]
    pub fn writer_certificate_object_hash() -> ObjectHash {
        build_line().2
    }

    /// Die Organisation, unter der die Fixture arbeitet.
    #[must_use]
    pub fn organization_id() -> OrganizationId {
        support::organization()
    }

    /// Das Geraet, das das Writer-Zertifikat der Bindung nennt.
    #[must_use]
    pub fn device_id(head: &SelectedRegistryHead) -> DeviceId {
        let fields = head
            .active_operator_binding_fields(binding_object_hash())
            .expect("the fixture binding is active at the selected sequence");
        head.active_certificate_fields(fields.device_certificate_hash)
            .expect("the bound Writer certificate is active at the selected sequence")
            .device_id
    }

    /// Waehlt den Head der Linie an `PROPOSED_SEQUENCE`, mit `now_ms` als
    /// OS-Wanduhr UND als Vertrauenszeit.
    ///
    /// Der Head ist an dieselbe Fassung gepinnt, die der Speicher vorhaelt, also
    /// ist der Kandidat aktuell und die Auswahl laeuft nicht ueber den
    /// Commit-Pfad. Weil beide Zeiten gleich sind, entsteht kein Uhrenversatz —
    /// die einzige Groesse, die dieser Parameter bewegt, ist
    /// `PreexistingEffectiveNow`.
    #[must_use]
    pub fn selected_registry_head_at(now_ms: i64) -> SelectedRegistryHead {
        let (line, _, _) = build_line();
        let head_index = line.heads().len() - 1;
        let head = line.heads()[head_index];
        let key = support::state_key();
        let trusted_time = TrustedTimeState::initial(UnixMillis::new(now_ms));
        let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
        let candidate =
            verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE)).unwrap();
        let mut store = ModelStore {
            key,
            revision: 17,
            trusted_time,
            pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
        };
        let local_time =
            prepare_local_time(&mut store, &candidate, UnixMillis::new(now_ms), &[]).unwrap();
        let RegistrySelectionOutcome::Selected(selected) =
            select_registry_head(candidate, local_time, None).unwrap()
        else {
            panic!("the fixture must select its own current Head");
        };
        selected
    }

    /// Der Head zum Standardzeitpunkt der Fixture.
    #[must_use]
    pub fn selected_registry_head() -> SelectedRegistryHead {
        selected_registry_head_at(FIXTURE_NOW_MS)
    }

    /// Loest die Bindung AUS dem gewaehlten Head auf.
    #[must_use]
    pub fn binding(head: &SelectedRegistryHead) -> BoundOperator {
        BoundOperator::resolve(head, binding_object_hash())
            .expect("the fixture binding is active at the selected sequence")
    }

    /// Der Bindungshash, den die Bindung der Fixture traegt.
    fn bound_account_hash() -> Hash32 {
        support::hash32(BINDING_MARKER.wrapping_add(2))
    }

    struct FakeAccount {
        binding_hash: Hash32,
        instance_public_key: Option<CanonicalPublicCoseKey>,
    }

    impl OsAccountProvider for FakeAccount {
        fn os_account_binding_hash(
            &self,
            _organization_id: OrganizationId,
            _device_id: DeviceId,
        ) -> Result<Hash32, OperatorError> {
            Ok(self.binding_hash)
        }

        fn operator_instance_public_key(
            &self,
        ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
            Ok(self.instance_public_key.clone())
        }
    }

    /// Das gebundene Konto mit vorhandenem Instanzschluessel.
    #[must_use]
    pub fn valid_account() -> Box<dyn OsAccountProvider> {
        Box::new(FakeAccount {
            binding_hash: bound_account_hash(),
            instance_public_key: Some(public_key(INSTANCE_SECRET)),
        })
    }

    /// Ein anderes OS-Konto desselben Geraets.
    #[must_use]
    pub fn wrong_account() -> Box<dyn OsAccountProvider> {
        Box::new(FakeAccount {
            binding_hash: support::hash32(BINDING_MARKER.wrapping_add(9)),
            instance_public_key: Some(public_key(INSTANCE_SECRET)),
        })
    }

    /// Das gebundene Konto, dessen Instanzschluessel fehlt — Neuinstallation,
    /// Restore oder Verlust des Schluessels.
    #[must_use]
    pub fn missing_instance_key() -> Box<dyn OsAccountProvider> {
        Box::new(FakeAccount {
            binding_hash: bound_account_hash(),
            instance_public_key: None,
        })
    }

    /// Das gebundene Konto mit einem ANDEREN Instanzschluessel.
    #[must_use]
    pub fn wrong_instance_key() -> Box<dyn OsAccountProvider> {
        Box::new(FakeAccount {
            binding_hash: bound_account_hash(),
            instance_public_key: Some(public_key(OTHER_INSTANCE_SECRET)),
        })
    }

    /// Die Attrappe der nativen Praesenzpruefung.
    ///
    /// Sie implementiert ausschliesslich die beiden Plattformhaken. Der
    /// Kontoabgleich, die Instanzschluesselpruefung und die Ausstellung des
    /// Nachweises liegen im Standardkoerper von
    /// `OperatorAuthenticator::reauthenticate` — wuerde die Attrappe ihn
    /// ueberschreiben, prueefte dieser Test die Attrappe und nicht die Crate.
    pub struct FakeAuthenticator {
        bound: BoundOperator,
        signing_key: SigningKey,
        challenges: RefCell<Vec<Vec<u8>>>,
    }

    impl FakeAuthenticator {
        /// Signiert mit dem Schluessel, den die Bindung nennt.
        #[must_use]
        pub fn new(bound: BoundOperator) -> Self {
            Self {
                bound,
                signing_key: signing_key(INSTANCE_SECRET),
                challenges: RefCell::new(Vec::new()),
            }
        }

        /// Signiert mit einem Schluessel, den die Bindung NICHT nennt, waehrend
        /// das Konto den richtigen oeffentlichen Schluessel vorlegt.
        #[must_use]
        pub fn with_foreign_signature(bound: BoundOperator) -> Self {
            Self {
                bound,
                signing_key: signing_key(OTHER_INSTANCE_SECRET),
                challenges: RefCell::new(Vec::new()),
            }
        }

        /// Die Challenges, die diese Attrappe zu signieren bekommen hat.
        #[must_use]
        pub fn challenges(&self) -> Vec<Vec<u8>> {
            self.challenges.borrow().clone()
        }
    }

    impl ea_operator::OperatorAuthenticator for FakeAuthenticator {
        fn bound_operator(&self) -> &BoundOperator {
            &self.bound
        }

        fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
            use ed25519_dalek::Signer as _;

            self.challenges.borrow_mut().push(challenge.to_vec());
            Ok(self.signing_key.sign(challenge).to_bytes())
        }
    }
}

use fixtures::FakeAuthenticator;

#[test]
fn finalization_requires_matching_account_instance_key_and_fresh_presence() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    assert_eq!(
        auth.reauthenticate(fixtures::wrong_account(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-ACCOUNT-MISMATCH"
    );
    assert_eq!(
        auth.reauthenticate(fixtures::missing_instance_key(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-INSTANCE-KEY-MISSING"
    );
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    assert!(proof.is_valid_for(ReauthPurpose::Finalize, head.preexisting_effective_now()));
}

/// Eine Bindung entsteht NUR aus dem gewaehlten Head.
///
/// Der Objekthash des Writer-Zertifikats ist ein echter, im Katalog vorhandener
/// Objekthash — er ist nur keine Bedienerbindung. Ohne diesen Test koennte
/// `resolve` jeden Objekthash annehmen und eine Bindung aus dem Nichts bauen,
/// womit der Kontoabgleich gegen einen selbst gewaehlten Wert liefe.
#[test]
fn an_object_that_is_not_an_active_operator_binding_never_becomes_a_bound_operator() {
    let head = fixtures::selected_registry_head();
    let Err(error) = BoundOperator::resolve(&head, fixtures::writer_certificate_object_hash())
    else {
        panic!("a Writer certificate is not an operator binding");
    };
    assert_eq!(error.code(), "EA-OPERATOR-BINDING-NOT-ACTIVE");
}

/// Ein VORHANDENER, aber anderer Instanzschluessel ist kein Vorhandensein.
///
/// Ohne diesen Test bliebe der Thumbprint-Abgleich ungemessen: `valid_account`
/// und `missing_instance_key` unterscheiden nur `Some` von `None`.
#[test]
fn a_foreign_instance_key_is_not_the_bound_instance_key() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    assert_eq!(
        auth.reauthenticate(fixtures::wrong_instance_key(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-INSTANCE-KEY-MISMATCH"
    );
}

/// Die Praesenzsignatur wird gegen den gebundenen Schluessel GEPRUEFT.
///
/// Ohne diesen Test koennte `reauthenticate` die Signatur anfordern und
/// wegwerfen; das Konto legt hier den richtigen oeffentlichen Schluessel vor und
/// nur die Attrappe signiert mit einem fremden.
#[test]
fn a_presence_signature_from_a_foreign_key_never_issues_a_proof() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::with_foreign_signature(fixtures::binding(&head));
    assert_eq!(
        auth.reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-PRESENCE-PROOF-INVALID"
    );
}

#[test]
fn a_proof_authorizes_only_its_own_purpose() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    assert!(!proof.is_valid_for(
        ReauthPurpose::DiscardDraft,
        head.preexisting_effective_now()
    ));
}

#[test]
fn an_os_lock_event_invalidates_the_proof() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    let binding_object_hash = proof.binding_object_hash();
    let proof = proof.invalidate_on_lock();
    assert!(!proof.is_valid_for(ReauthPurpose::Finalize, head.preexisting_effective_now()));
    // Der entwertete Nachweis behaelt seine Bindung; er ist entwertet und nicht
    // anonym. Und der GUELTIGE Stand existiert nach dem Aufruf nicht mehr:
    // `OperatorSessionProof` ist weder `Clone` noch `Copy`, was der
    // `compile_fail`-Doctest der Crate belegt.
    assert!(proof.binding_object_hash().as_bytes() == binding_object_hash.as_bytes());
}

/// Der Fuenfminuten-Vorgabewert der Untaetigkeit.
///
/// Beide Seiten des Fensters werden gemessen: ohne die erste Zusicherung waere
/// ein Nachweis, der SOFORT abliefe, gruen; ohne die zweite einer, der nie
/// ablaeuft. Die spaetere Zeit entsteht wieder als `PreexistingEffectiveNow`
/// eines gewaehlten Head und nicht als frei gebauter Wert.
#[test]
fn a_proof_expires_after_the_five_minute_inactivity_default() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();

    let inside = fixtures::selected_registry_head_at(fixtures::FIXTURE_NOW_MS + 299_000);
    assert!(proof.is_valid_for(ReauthPurpose::Finalize, inside.preexisting_effective_now()));

    let outside = fixtures::selected_registry_head_at(fixtures::FIXTURE_NOW_MS + 301_000);
    assert!(!proof.is_valid_for(ReauthPurpose::Finalize, outside.preexisting_effective_now()));
}

/// Die Challenge, die der Instanzschluessel signiert, ist domaingetrennt und
/// bindet Zweck, Organisation, Geraet und Bindung.
///
/// Sie verlaesst das Geraet nie und wird nie zu Archivbytes, hat also kein
/// eingefrorenes Format — geprueft wird deshalb ihr INHALT und nicht ihre
/// Kodierung. Ohne diesen Test waere „domaingetrennt und frisch" eine Zusage
/// ohne Messung: eine Challenge aus einer konstanten Nonce oder eine, die den
/// Zweck nicht nennt, bliebe unentdeckt.
#[test]
fn the_signed_challenge_is_domain_separated_and_binds_the_operator() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    auth.reauthenticate(fixtures::valid_account(), ReauthPurpose::Destruction)
        .unwrap();
    auth.reauthenticate(fixtures::valid_account(), ReauthPurpose::Destruction)
        .unwrap();

    let seen = auth.challenges();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0], seen[1], "every challenge carries a fresh nonce");

    let challenge = seen[0].as_slice();
    let device = fixtures::device_id(&head);
    for needle in [
        b"EINSATZARCHIV-OPERATOR-REAUTH-v1".as_slice(),
        ReauthPurpose::Destruction.label().as_bytes(),
        fixtures::organization_id().as_bytes().as_slice(),
        device.as_bytes().as_slice(),
        fixtures::binding_object_hash().as_bytes().as_slice(),
    ] {
        assert!(
            contains(challenge, needle),
            "the challenge must bind {needle:02x?}"
        );
    }

    // Der Zweck steht in der SIGNIERTEN Challenge und nicht nur im Nachweis.
    let other = FakeAuthenticator::new(fixtures::binding(&head));
    other
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::RecoveryTest)
        .unwrap();
    assert!(!contains(
        other.challenges()[0].as_slice(),
        ReauthPurpose::Destruction.label().as_bytes()
    ));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Die Umrechnung von ROHANGABEN einer Plattform zu einem Bindungshash.
///
/// Die Kontoattrappen oben melden einen Bindungshash unmittelbar, weil der
/// synthetische Wert der Registry-Fixture nicht umkehrbar ist. Damit die eigene
/// Aufgabe der Plattformadapter — Rohangaben ernten und UNVERAENDERT
/// weitergeben — dennoch gemessen ist, faehrt dieser Test die drei
/// Stufe-1-Vektoren aus `crates/ea-crypto/src/os_account.rs:391`, `:403` und
/// `:414` durch `OsAccountInputs::binding_hash`. Er faellt, sobald ein Adapter
/// eine Angabe umformt, umsortiert oder normalisiert — genau das, was
/// `design.md:233` verbietet.
#[test]
fn the_three_platform_harvests_reproduce_the_frozen_stage_one_digests() {
    let organization = OrganizationId::try_from(
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]
        .as_slice(),
    )
    .unwrap();
    let device = DeviceId::try_from(
        [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ]
        .as_slice(),
    )
    .unwrap();
    let sid = [
        0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
    ];

    let windows = ea_operator::windows::account_inputs(
        sid.to_vec(),
        [0, 0, 0, 0, 0, 5],
        vec![21, 1, 2, 3, 1000],
    );
    let windows_hash = windows.binding_hash(organization, device).unwrap();
    assert!(
        windows_hash
            == windows_os_account_binding_hash(
                organization,
                device,
                &sid,
                [0, 0, 0, 0, 0, 5],
                &[21, 1, 2, 3, 1000]
            )
            .unwrap()
    );
    assert_eq!(
        hex_of(windows_hash),
        "fcbb2ccb141966c57146aa6e578f56550bf86670ee9b31dea90f5a99b9f26220"
    );

    let macos = ea_operator::macos::account_inputs(
        vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_owned()],
        vec!["501".to_owned()],
        501,
    );
    let macos_hash = macos.binding_hash(organization, device).unwrap();
    assert!(
        macos_hash
            == macos_os_account_binding_hash(
                organization,
                device,
                &["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
                &["501"],
                501
            )
            .unwrap()
    );
    assert_eq!(
        hex_of(macos_hash),
        "0f4ed54a0330ed2bdbb5228d192d4dfa3a0853dae98aba3091f0c7c5f29fde7a"
    );

    let linux =
        ea_operator::linux::account_inputs(b"0123456789abcdef0123456789abcdef\n".to_vec(), 1000);
    let linux_hash = linux.binding_hash(organization, device).unwrap();
    assert!(
        linux_hash
            == linux_os_account_binding_hash(
                organization,
                device,
                b"0123456789abcdef0123456789abcdef\n",
                1000
            )
            .unwrap()
    );
    assert_eq!(
        hex_of(linux_hash),
        "bbca2d7b508415aed456efd6fc5499ddda65759250f6c8b5a1c2edd23a7883e4"
    );

    // Die beiden macOS-Wertlisten sind NICHT vertauschbar. Ohne diese
    // Zusicherung waere ein Adapter, der die Reihenfolge der Argumente dreht,
    // gegen die Gleichheitszusicherungen oben unauffaellig.
    let swapped = ea_operator::macos::account_inputs(
        vec!["501".to_owned()],
        vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_owned()],
        501,
    );
    match swapped.binding_hash(organization, device) {
        Ok(hash) => assert!(hash != macos_hash, "swapped macOS values must not collide"),
        Err(error) => assert_eq!(error.code(), "EA-IDENTITY-INVALID-OS-ACCOUNT"),
    }

    // Eine unzulaessige Rohangabe wird abgelehnt und nicht zurechtgebogen: eine
    // Text-UID mit fuehrender Null ist keine zulaessige kanonische Angabe.
    let Err(error) = ea_operator::macos::account_inputs(
        vec!["f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_owned()],
        vec!["0501".to_owned()],
        501,
    )
    .binding_hash(organization, device) else {
        panic!("a non-canonical unique id must never yield a binding hash");
    };
    assert_eq!(error.code(), "EA-IDENTITY-INVALID-OS-ACCOUNT");
}

fn hex_of(hash: Hash32) -> String {
    hash.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Der Port bleibt dyn-faehig und die Rohangaben bleiben geschlossen.
#[test]
fn the_operator_ports_are_object_safe_and_the_inputs_are_closed() {
    let head = fixtures::selected_registry_head();
    let authenticator: Box<dyn OperatorAuthenticator> =
        Box::new(FakeAuthenticator::new(fixtures::binding(&head)));
    let proof = authenticator
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::PlaintextExport)
        .unwrap();
    assert!(proof.is_valid_for(
        ReauthPurpose::PlaintextExport,
        head.preexisting_effective_now()
    ));
    let _: fn(&OsAccountInputs, OrganizationId, DeviceId) -> Result<Hash32, OperatorError> =
        OsAccountInputs::binding_hash;
    let _: &dyn OsAccountProvider = &*fixtures::valid_account();
    let _: BoundOperator = fixtures::binding(&head);
}
