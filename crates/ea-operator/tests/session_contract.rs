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
        select_head_of(&build_line().0, now_ms)
    }

    /// Waehlt den letzten Head EINER GEBAUTEN LINIE — der gemeinsame Rumpf von
    /// [`selected_registry_head_at`] und den beiden Randlinien darunter.
    ///
    /// Herausgezogen und nicht abgeschrieben: eine zweite Kopie des
    /// Auswahlpfads koennte still von diesem abweichen, und dann pruefte die
    /// Randlinie eine andere Auswahl als die Standardfixture.
    fn select_head_of(line: &RegistryLineBuilder, now_ms: i64) -> SelectedRegistryHead {
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

    /// Dieselbe Linie wie [`build_line`], aber mit ihrem Zeitfenster DICHT AN
    /// `axis_end` statt bei den vierstelligen Vorgabewerten.
    ///
    /// Nur das Zeitfenster wandert; Sequenzen, Marken, Rollen und der
    /// Instanzschluessel bleiben. `issuedAt` und `notBefore` wandern MIT, damit
    /// `notAfter - issuedAt` klein bleibt: `validate_event_time_shape`
    /// (`crates/ea-trust/src/registry.rs:1383-1396`) stellt genau diese
    /// Differenz gegen `max-registry-age-ms`, und eine Linie, die dafuer die
    /// Policy aufweiten muesste, belegte den Ueberlauf zusammen mit einer
    /// zweiten, unnoetigen Abweichung.
    fn build_line_near(axis_end: i64) -> (RegistryLineBuilder, ObjectHash) {
        let options = |effective_from: u64, valid_through: u64| HeadOptions {
            effective_from: Some(effective_from),
            valid_through: Some(valid_through),
            issued_at: UnixMillis::new(axis_end - 2_000),
            not_before: UnixMillis::new(axis_end - 3_000),
            not_after: UnixMillis::new(axis_end),
            ..HeadOptions::default()
        };
        let mut line = RegistryLineBuilder::new();
        line.push(
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            options(1, 10),
        );
        let writer = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::Writer,
                marker: 0x61,
                effective_from: None,
            },
            options(11, 20),
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
                binding_instance_key_thumbprint_override: Some(KeyThumbprint::from(
                    Hash32::try_from(
                        public_key(INSTANCE_SECRET)
                            .thumbprint()
                            .as_bytes()
                            .as_slice(),
                    )
                    .expect("a thumbprint is 32 bytes"),
                )),
                ..options(21, 100)
            },
        );
        let binding_object_hash = binding
            .direct_object_hash
            .expect("the fixture operator binding is a direct target");
        (line, binding_object_hash)
    }

    /// Ein aufgeloester Bediener auf einer Linie, deren Head bei `axis_end`
    /// endet, gewaehlt bei `axis_end - 1_000`.
    ///
    /// Die Bindung kommt AUS DIESEM Head — nicht aus der Standardlinie, deren
    /// Objekthashes andere sind.
    #[must_use]
    pub fn binding_near_the_end_of_the_time_axis(axis_end: i64) -> BoundOperator {
        let (line, binding_object_hash) = build_line_near(axis_end);
        let head = select_head_of(&line, axis_end - 1_000);
        BoundOperator::resolve(&head, binding_object_hash)
            .expect("the fixture binding is active at the selected sequence")
    }

    /// Dieselbe Linie wie [`build_line`], aber das Writer-Zertifikat ist ab
    /// `revoked_from` widerrufen — VOR [`PROPOSED_SEQUENCE`], waehrend das
    /// Fenster der Bindung selbst (21..100) offen bleibt.
    fn build_line_with_revoked_writer(revoked_from: u64) -> (RegistryLineBuilder, ObjectHash) {
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
            HeadOptions {
                revoked_from_sequence: Some(ChainSequence::new(revoked_from)),
                ..head_options(11, 20)
            },
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
        (line, binding_object_hash)
    }

    /// Der Head und der Bindungshash einer Linie, deren gebundenes
    /// Writer-Zertifikat bei der gewaehlten Sequenz widerrufen ist.
    ///
    /// Der Widerruf greift bei 25, gewaehlt wird bei
    /// [`PROPOSED_SEQUENCE`] = 30, und das Fenster der Bindung reicht bis 100 —
    /// also ist NUR das Zertifikat unwirksam.
    #[must_use]
    pub fn head_with_a_revoked_device_certificate() -> (SelectedRegistryHead, ObjectHash) {
        let (line, binding_object_hash) = build_line_with_revoked_writer(25);
        (select_head_of(&line, FIXTURE_NOW_MS), binding_object_hash)
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

/// Der Nachweis NENNT den Bediener, fuer den er ausgestellt wurde.
///
/// Ohne diese drei Leser koennte kein Verbraucher feststellen, zu welchem
/// Bediener ein Nachweis gehoert: ein Nachweis gegen Bindung A liefe in einer
/// Sitzung gegen Bindung B durch, weil `is_valid_for` nur Zweck und Zeit prueft.
/// Der Gegenwert des Bindungsvergleichs ist ein ECHTER Objekthash derselben
/// Linie — das Writer-Zertifikat —, damit der Test nicht gegen eine erfundene
/// Zahl vergleicht.
#[test]
fn a_proof_names_the_operator_binding_it_was_minted_for() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let proof = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();

    assert!(
        proof.binding_object_hash().as_bytes() == fixtures::binding_object_hash().as_bytes(),
        "the proof must name the binding it was minted for"
    );
    assert!(
        proof.binding_object_hash().as_bytes()
            != fixtures::writer_certificate_object_hash().as_bytes(),
        "a different object of the same line must be distinguishable from the binding"
    );
    assert!(proof.organization_id().as_bytes() == fixtures::organization_id().as_bytes());
    assert!(proof.device_id().as_bytes() == fixtures::device_id(&head).as_bytes());
}

/// Zwei Wiederanmeldungen desselben Zwecks zur selben Zeit sind
/// UNTERSCHEIDBAR.
///
/// Ohne die Nonce im Typ waeren beide Nachweise gleich, und „frische Praesenz"
/// waere am Nachweis nicht ablesbar — nur in einer Signatur, die nach ihrer
/// Pruefung verworfen wird.
#[test]
fn two_reauthentications_of_one_purpose_are_not_the_same_proof() {
    let head = fixtures::selected_registry_head();
    let auth = FakeAuthenticator::new(fixtures::binding(&head));
    let first = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    let second = auth
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();

    assert!(
        first.challenge_nonce() != second.challenge_nonce(),
        "every re-authentication carries its own presence nonce"
    );
    assert!(
        first != second,
        "two proofs of one purpose at one time must not compare equal"
    );
}

/// Eine Bindung ALTERT: wer sie fruehzeitig aufloest und spaet wieder anmeldet,
/// bekommt einen Nachweis, der bereits abgelaufen ist.
///
/// Das ist die Pflicht, die `BoundOperator::resolve` und
/// `OperatorAuthenticator::bound_operator` dokumentieren, hier gemessen: die
/// Ausstellzeit ist die Zeit der BINDUNG und nicht die des Augenblicks, also ist
/// `Ok` von `reauthenticate` keine Aussage darueber, dass der Nachweis jetzt
/// gilt. Die zweite Haelfte des Tests belegt die Abhilfe — neu aufloesen gegen
/// den aktuellen Head —, damit der Test nicht nur den Mangel, sondern auch den
/// vorgeschriebenen Weg festhaelt.
#[test]
fn a_binding_resolved_before_the_window_issues_a_proof_that_is_already_expired() {
    let early = fixtures::selected_registry_head();
    let late = fixtures::selected_registry_head_at(fixtures::FIXTURE_NOW_MS + 301_000);

    let stale = FakeAuthenticator::new(fixtures::binding(&early));
    let proof = stale
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .expect("account, instance key and presence are all proven");
    assert!(
        !proof.is_valid_for(ReauthPurpose::Finalize, late.preexisting_effective_now()),
        "a proof issued against a stale binding does not hold at the current Head"
    );

    let fresh = FakeAuthenticator::new(fixtures::binding(&late));
    let proof = fresh
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .unwrap();
    assert!(
        proof.is_valid_for(ReauthPurpose::Finalize, late.preexisting_effective_now()),
        "re-resolving the binding against the current Head is the prescribed remedy"
    );
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

/// Ein Gueltigkeitsfenster, das nicht mehr auf die Millisekundenachse passt,
/// wird abgelehnt — und zwar VOR der Praesenzabfrage.
///
/// `reauthenticate` bildet `expiresAt` als `issuedAt + MAX_INACTIVITY_MS`
/// (`crates/ea-operator/src/session.rs:304-308`). Ohne den `checked_add` liefe
/// die Summe am oberen Rand der `i64`-Achse um, und der Nachweis truege ein
/// `expiresAt` VOR seinem `issuedAt` — `is_valid_for` verglicht dann gegen ein
/// Fenster, das es nicht gibt. Der Abbruch ist deshalb kein Formfehler, sondern
/// die Weigerung, einen Nachweis mit unbestimmter Lebensdauer auszustellen.
///
/// Die Zeit entsteht wie ueberall in dieser Datei als
/// `PreexistingEffectiveNow` eines ECHT gewaehlten Head; nur das Zeitfenster der
/// Linie liegt am Achsenende. Die POSITIVKONTROLLE davor faehrt dieselbe Linie
/// eine Million Millisekunden frueher und stellt einen Nachweis aus — ohne sie
/// waere ein Fixturefehler (eine Linie, die aus einem ganz anderen Grund keinen
/// Nachweis hergibt) von der gemessenen Zusage nicht zu unterscheiden.
///
/// Die zweite Zusicherung ist die eigentliche fail-closed-Aussage: die Attrappe
/// hat KEINE Challenge zu signieren bekommen. Ein Bediener wird also nicht zur
/// Fingerabdruck- oder PIN-Eingabe aufgefordert fuer eine Sitzung, die danach
/// ohnehin nicht ausgestellt werden kann.
#[test]
fn a_validity_window_beyond_the_millisecond_axis_is_refused_before_any_presence_prompt() {
    let representable = FakeAuthenticator::new(fixtures::binding_near_the_end_of_the_time_axis(
        i64::MAX - 1_000_000,
    ));
    representable
        .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
        .expect("a window that still fits on the axis issues a proof");
    assert_eq!(
        representable.challenges().len(),
        1,
        "the representable case DOES reach the presence prompt"
    );

    let at_the_edge =
        FakeAuthenticator::new(fixtures::binding_near_the_end_of_the_time_axis(i64::MAX));
    assert_eq!(
        at_the_edge
            .reauthenticate(fixtures::valid_account(), ReauthPurpose::Finalize)
            .unwrap_err()
            .code(),
        "EA-OPERATOR-VALIDITY-WINDOW-UNREPRESENTABLE"
    );
    assert!(
        at_the_edge.challenges().is_empty(),
        "no presence prompt is raised for a session that cannot be represented"
    );
}

/// Ein widerrufenes Geraetezertifikat stoppt die Aufloesung schon an der
/// BINDUNG — und nicht erst am Zertifikatsarm dahinter.
///
/// Das ist der gemessene Grund dafuer, dass
/// `EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE` (`account.rs:52`, erhoben in
/// `account.rs:231`) ueber `SelectedRegistryHead` nicht erreichbar ist:
/// `PreviousHeadState::active_operator_binding`
/// (`crates/ea-trust/src/resolver.rs:151-168`) fuehrt die Zertifikatspruefung
/// SELBST — mit derselben `at_sequence`, die `BoundOperator::resolve`
/// unmittelbar danach benutzt. Ist das Zertifikat unwirksam, meldet schon der
/// erste Zugriff `None`, und `resolve` bricht mit
/// `EA-OPERATOR-BINDING-NOT-ACTIVE` ab. Der zweite Arm ist ein Tiefenschutz,
/// kein erreichbarer Ausgang.
///
/// Dieser Test haelt genau diese Kopplung fest: faellt die Zertifikatspruefung
/// je aus `active_operator_binding` heraus, wird der bislang tote Arm lebendig,
/// der gemessene Code wechselt und der Test wird rot. Er ersetzt keinen Zeugen
/// fuer den Code — es gibt keinen zu bauen — sondern bewacht die Aussage, dass
/// keiner noetig ist.
#[test]
fn a_revoked_device_certificate_already_stops_the_binding_lookup() {
    let (head, binding_object_hash) = fixtures::head_with_a_revoked_device_certificate();
    assert!(
        head.active_operator_binding_fields(binding_object_hash)
            .is_none(),
        "the Head itself refuses a binding whose device certificate is revoked"
    );
    let Err(error) = BoundOperator::resolve(&head, binding_object_hash) else {
        panic!("a binding on a revoked device certificate must not resolve");
    };
    assert_eq!(error.code(), "EA-OPERATOR-BINDING-NOT-ACTIVE");

    // Positivkontrolle: dieselbe Linie OHNE den Widerruf loest auf. Ohne sie
    // waere der Test auch dann gruen, wenn die Fixture aus einem beliebigen
    // anderen Grund keine Bindung mehr herstellte.
    let intact = fixtures::selected_registry_head();
    assert!(
        BoundOperator::resolve(&intact, fixtures::binding_object_hash()).is_ok(),
        "without the revocation the very same shape resolves"
    );
}
