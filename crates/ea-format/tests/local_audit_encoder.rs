//! Der allgemeine Kodierer der zwoelf `local-audit-event-v1`-Ereignisse.
//!
//! Der eingefrorene Stufe-1-Test `local_audit.rs` steht daneben und bleibt
//! unberuehrt: er prueft den SPEZIELLEN Dekodierer der Taktfreigabe gegen
//! handgeschnittene Bytes. Diese Datei prueft den allgemeinen Kodierer und
//! seinen allgemeinen Dekodierer, und sie stellt beide gegen den eingefrorenen
//! Pfad.

use ea_format::{
    AdminRootContextV1, ArchiveProfileMigrationContextV1, BindingLifecycleContextV1,
    ClockReleaseContextV1, ClockReleaseJustificationV1, DestructionContextV1, ExportContextV1,
    FormatError, GenericAuditContextV1, HistoricalRegrantContextV1, IndependentTimeKindV1,
    IndependentTimeReferenceV1, LocalAuditActionV1, LocalAuditEventCoreFieldsV1,
    LocalAuditOutcomeV1, StaleRegistryContextV1, decode_clock_release_audit,
    decode_local_audit_event, encode_local_audit_core, encode_local_audit_event,
};

#[test]
fn every_action_encodes_the_twelve_frozen_core_positions() {
    for event in fixtures::one_event_per_action() {
        let core = encode_local_audit_core(&event).unwrap();
        let mut decoder = minicbor::Decoder::new(&core);
        assert_eq!(decoder.array().unwrap(), Some(12));
        assert_eq!(decoder.u64().unwrap(), 1);
        // Regressionsanker: der Encoder ruft diese Pruefung selbst auf. Der Test
        // haelt sie fest, damit ihre Entfernung sichtbar wird.
        ea_crypto::validate_unsigned_protocol_core(ea_crypto::ContentType::LocalAuditCbor, &core)
            .unwrap();
    }
}

#[test]
fn the_action_code_and_the_context_tag_never_drift_apart() {
    for (event, action_code, context_tag) in fixtures::action_and_tag_expectations() {
        let core = encode_local_audit_core(&event).unwrap();
        assert_eq!(event.action.code(), action_code);
        assert_eq!(event.action.context_tag(), context_tag);
        assert_eq!(core[fixtures::ACTION_CODE_OFFSET], action_code);
        assert_eq!(core[fixtures::CONTEXT_TAG_OFFSET], context_tag);
    }
}

#[test]
fn the_general_decoder_agrees_with_the_frozen_clock_release_decoder() {
    let signed = fixtures::signed_clock_skew_release_event();
    let general = decode_local_audit_event(&signed).unwrap();
    let frozen = decode_clock_release_audit(&signed).unwrap();
    assert_eq!(general.exact_core(), frozen.exact_core());
    assert_eq!(general.exact_bytes(), signed.as_slice());
    assert_eq!(general.outcome(), frozen.outcome());
}

#[test]
fn a_cose_payload_that_does_not_carry_the_core_is_refused() {
    let signed = fixtures::signed_plaintext_export_event();
    let mut tampered = signed.clone();
    let offset = fixtures::nonce_offset(&signed);
    tampered[offset] ^= 0x01;
    assert_eq!(
        decode_local_audit_event(&tampered).unwrap_err(),
        FormatError::Cose
    );
}

#[test]
fn an_outcome_outside_the_frozen_range_is_refused() {
    let signed = fixtures::signed_plaintext_export_event();
    // Der Versatz ist GEMESSEN, nicht bloss behauptet: ohne diese Zusicherung
    // bestuende der Test auch, wenn er ein beliebiges anderes Kernbyte kippt —
    // jede Kernaenderung bricht schon den COSE-Abgleich.
    assert_eq!(
        signed[fixtures::OUTCOME_OFFSET],
        LocalAuditOutcomeV1::Completed as u8
    );
    let mut tampered = signed.clone();
    tampered[fixtures::OUTCOME_OFFSET] = 3;
    assert!(decode_local_audit_event(&tampered).is_err());
    // Und der Fehler ist der der KERNGESTALT, nicht der der Signatur: ein
    // Ausgang jenseits von `local-audit-outcome-v1 = 0..2` scheitert an der
    // Kernpruefung, bevor irgendeine COSE-Struktur betrachtet wird.
    assert_eq!(
        decode_local_audit_event(&tampered).unwrap_err(),
        FormatError::Shape
    );
}

/// Die Schlusspruefung des Kodierers ist tragend, nicht dekorativ.
///
/// Ohne diesen Test koennte der letzte Aufruf von
/// `validate_unsigned_protocol_core` aus `encode_local_audit_core` entfallen,
/// ohne dass ein Test fiele: der erste Test dieser Datei ruft die Pruefung
/// SELBST auf und wuerde die Bytes weiterhin durchlassen.
#[test]
fn an_event_the_signature_boundary_refuses_is_never_encoded() {
    let event = fixtures::clock_skew_release_event_with_inverted_window();
    assert_eq!(
        encode_local_audit_core(&event).unwrap_err(),
        FormatError::Shape
    );
}

/// Der Umschlag nimmt nur eine Signatur an, die genau diesen Kern traegt.
#[test]
fn the_wrapper_refuses_a_signature_over_another_core() {
    let export = fixtures::plaintext_export_event();
    let clock = fixtures::clock_skew_release_event();
    let export_core = encode_local_audit_core(&export).unwrap();
    let clock_core = encode_local_audit_core(&clock).unwrap();
    let clock_cose = fixtures::sign(&clock_core);
    assert_eq!(
        encode_local_audit_event(&export_core, &clock_cose).unwrap_err(),
        FormatError::Cose
    );
    // Und mit der eigenen Signatur entsteht genau die Bytefolge, die der
    // allgemeine Dekodierer wieder annimmt.
    let export_cose = fixtures::sign(&export_core);
    let signed = encode_local_audit_event(&export_core, &export_cose).unwrap();
    assert_eq!(
        decode_local_audit_event(&signed).unwrap().exact_core(),
        export_core.as_slice()
    );
}

/// Jedes Kontextfeld steht an der Position, die die Grammatik ihm gibt.
///
/// Der schaerfste Test dieser Datei, und der einzige, der eine VERTAUSCHUNG
/// zweier gleichgetypter Nachbarpositionen faengt: er liest die Bytes mit einem
/// eigenen Decoderlauf, unabhaengig von `decode_local_audit_event`, und stellt
/// sie gegen die erklaerten Fixturewerte. Ein Kodierer und ein Dekodierer, die
/// `registryHeadHash` und `policyObjectHash` BEIDE vertauschten, blieben von
/// jedem Rundlauftest und von der CDDL unentdeckt — beide Positionen sind
/// `bstr .size 32` —, hier aber nicht. Der zweite Teil liest dieselben Werte
/// ueber die Zugriffe des dekodierten Ereignisses und bindet damit auch sie an
/// die Grammatik.
#[test]
fn every_context_position_carries_the_field_the_grammar_names() {
    for event in fixtures::one_event_per_action() {
        let core = encode_local_audit_core(&event).unwrap();
        let expected = fixtures::expected_context_positions(&event.action);

        let mut decoder = minicbor::Decoder::new(&core);
        assert_eq!(decoder.array().unwrap(), Some(12));
        // Versionsliteral, drei Kennungen, Bindung, Zertifikat, Aktion, Ausgang
        // und `effective-now` — neun Positionen vor dem Kontextpaar.
        for _ in 0..9 {
            decoder.skip().unwrap();
        }
        let read = fixtures::read_context_positions(&mut decoder, &event.action, expected.len());
        assert_eq!(
            read,
            expected,
            "action {} writes its context positions out of order",
            event.action.code()
        );

        let signed = encode_local_audit_event(&core, &fixtures::sign(&core)).unwrap();
        let decoded = decode_local_audit_event(&signed).unwrap();
        assert_eq!(
            fixtures::accessor_context_positions(decoded.action()),
            expected,
            "action {} reads its context positions out of order",
            event.action.code()
        );
    }
}

mod fixtures {
    use super::{
        AdminRootContextV1, ArchiveProfileMigrationContextV1, BindingLifecycleContextV1,
        ClockReleaseContextV1, ClockReleaseJustificationV1, DestructionContextV1, ExportContextV1,
        GenericAuditContextV1, HistoricalRegrantContextV1, IndependentTimeKindV1,
        IndependentTimeReferenceV1, LocalAuditActionV1, LocalAuditEventCoreFieldsV1,
        LocalAuditOutcomeV1, StaleRegistryContextV1, encode_local_audit_core,
        encode_local_audit_event,
    };
    use ea_crypto::{CoseSigner, SecretBytes};
    use ea_types::{
        ChainSequence, DeviceId, EntryHash, EventId, Hash32, ObjectHash, OrganizationId,
        RegistryVersion, UnixMillis,
    };

    /// Die Kopfbytes, aus denen die drei Versaetze folgen. Sie sind hier
    /// AUSGERECHNET und nicht gezaehlt, damit ein Leser sie nachrechnen kann:
    /// ein definites `array`-Kopfbyte, das Versionsliteral `1`, drei
    /// 16-Byte-Bytestrings mit Einbytekopf, zwei 32-Byte-Bytestrings mit
    /// Zweibytekopf.
    const ARRAY_HEADER: usize = 1;
    const VERSION_LITERAL: usize = 1;
    const BSTR16: usize = 1 + 16;
    const BSTR32: usize = 2 + 32;
    /// `effective-now` als achtstellige CBOR-Ganzzahl: Kopf plus acht Bytes.
    /// Deshalb tragen ALLE Fixtures dieser Versaetze dieselbe Zeit.
    const INT64: usize = 1 + 8;

    /// Der Versatz des Aktionscodes im KERN.
    pub const ACTION_CODE_OFFSET: usize = ARRAY_HEADER + VERSION_LITERAL + 3 * BSTR16 + 2 * BSTR32;

    /// Der Versatz des Ausgangs im KERN.
    const CORE_OUTCOME_OFFSET: usize = ACTION_CODE_OFFSET + 1;

    /// Der Versatz der Kontextmarke im KERN: hinter Ausgang, Zeit und dem
    /// Kopfbyte des Kontextpaares.
    pub const CONTEXT_TAG_OFFSET: usize = CORE_OUTCOME_OFFSET + 1 + INT64 + ARRAY_HEADER;

    /// Der Versatz des Ausgangs im SIGNIERTEN Ereignis: der Kern steht hinter
    /// dem Kopfbyte des aeusseren Paares.
    pub const OUTCOME_OFFSET: usize = ARRAY_HEADER + CORE_OUTCOME_OFFSET;

    /// Die Zeit aller Fixtures, deren Versaetze fest sein muessen.
    const EFFECTIVE_NOW_MS: i64 = 1_700_000_000_000;

    /// Die Testentropie des Signierers dieser Datei.
    const SIGNER_SEED: [u8; 32] = [0x33; 32];

    // Die Fuellbytes der Kontextfelder. Jedes kommt genau EINMAL vor, damit
    // `every_context_position_carries_the_field_the_grammar_names` zwei
    // gleichgetypte Nachbarpositionen ueberhaupt unterscheiden kann: waeren
    // zwei `bstr .size 32` mit demselben Inhalt belegt, blieben ihre
    // Vertauschung im Kodierer UND im Dekodierer unsichtbar.
    const GENERIC_SUBJECT_FILL: u8 = 0x30;
    const BINDING_OLD_FILL: u8 = 0x31;
    const BINDING_NEW_FILL: u8 = 0x32;
    const STALE_REGISTRY_HEAD_FILL: u8 = 0x34;
    const STALE_POLICY_FILL: u8 = 0x35;
    const STALE_PREVIEW_FILL: u8 = 0x36;
    const EXPORT_ENTRY_FILL: u8 = 0x37;
    const CLOCK_REGISTRY_HEAD_FILL: u8 = 0x38;
    const CLOCK_GUARD_POLICY_FILL: u8 = 0x39;
    const CLOCK_REFERENCE_FILL: u8 = 0x3a;
    const ADMIN_AUTHORIZATION_FILL: u8 = 0x3b;
    const ADMIN_TARGET_FILL: u8 = 0x3c;
    const REGRANT_AUTHORIZATION_FILL: u8 = 0x3d;
    const REGRANT_ENTRY_FILL: u8 = 0x3e;
    const REGRANT_ORIGINAL_GRANT_FILL: u8 = 0x3f;
    const REGRANT_RECIPIENT_FILL: u8 = 0x41;
    const REGRANT_NEW_GRANT_FILL: u8 = 0x42;
    const DESTRUCTION_AUTHORIZATION_FILL: u8 = 0x43;
    const DESTRUCTION_STATE_EVENT_FILL: u8 = 0x44;
    const MIGRATION_SOURCE_FILL: u8 = 0x45;
    const MIGRATION_TARGET_FILL: u8 = 0x46;
    const MIGRATION_INVENTORY_FILL: u8 = 0x47;
    const MIGRATION_ACTIVE_POINTER_FILL: u8 = 0x48;

    const BINDING_CHANGE_SEQUENCE: u64 = 12;
    const REVOCATION_SEQUENCE: u64 = 13;
    const STALE_PROPOSED_SEQUENCE: u64 = 9;
    const CLOCK_REGISTRY_VERSION: u64 = 7;
    const MAX_FUTURE_CLOCK_SKEW_MS: u64 = 300_000;
    const EXPORT_TARGET_KIND: u64 = 1;
    const ADMIN_CONTEXT_ACTION_CODE: u64 = 4;

    fn event_id() -> EventId {
        EventId::try_from([0x11; 16].as_slice()).expect("16 bytes")
    }

    fn organization_id() -> OrganizationId {
        OrganizationId::try_from([0x12; 16].as_slice()).expect("16 bytes")
    }

    fn device_id() -> DeviceId {
        DeviceId::try_from([0x13; 16].as_slice()).expect("16 bytes")
    }

    fn object_hash(fill: u8) -> ObjectHash {
        ObjectHash::try_from([fill; 32].as_slice()).expect("32 bytes")
    }

    fn entry_hash(fill: u8) -> EntryHash {
        EntryHash::try_from([fill; 32].as_slice()).expect("32 bytes")
    }

    fn hash32(fill: u8) -> Hash32 {
        Hash32::try_from([fill; 32].as_slice()).expect("32 bytes")
    }

    /// Ein Ereignis mit gebundener Bindung, festem Ausgang und fester Zeit.
    fn event(
        action: LocalAuditActionV1,
        outcome: LocalAuditOutcomeV1,
    ) -> LocalAuditEventCoreFieldsV1 {
        LocalAuditEventCoreFieldsV1 {
            event_id: event_id(),
            organization_id: organization_id(),
            device_id: device_id(),
            operator_binding_object_hash: Some(object_hash(0x20)),
            signer_certificate_object_hash: object_hash(0x21),
            action,
            outcome,
            effective_now: UnixMillis::new(EFFECTIVE_NOW_MS),
            nonce: [0x22; 32],
        }
    }

    fn generic() -> GenericAuditContextV1 {
        GenericAuditContextV1::new(Some(object_hash(GENERIC_SUBJECT_FILL)))
    }

    fn stale_registry() -> StaleRegistryContextV1 {
        StaleRegistryContextV1::new(
            object_hash(STALE_REGISTRY_HEAD_FILL),
            object_hash(STALE_POLICY_FILL),
            ChainSequence::new(STALE_PROPOSED_SEQUENCE),
            UnixMillis::new(EFFECTIVE_NOW_MS - 1_000),
            UnixMillis::new(EFFECTIVE_NOW_MS),
            hash32(STALE_PREVIEW_FILL),
        )
    }

    fn export() -> ExportContextV1 {
        ExportContextV1::new(entry_hash(EXPORT_ENTRY_FILL), EXPORT_TARGET_KIND)
    }

    /// Der Bindungslebenslauf. Beide nullbaren Seiten stehen in der Familie je
    /// einmal als `null`: der Vorgaenger in der Bindungsaenderung, der
    /// Nachfolger im Widerruf.
    fn binding_lifecycle(
        old: Option<ObjectHash>,
        new: Option<ObjectHash>,
        sequence: u64,
    ) -> BindingLifecycleContextV1 {
        BindingLifecycleContextV1::new(old, new, ChainSequence::new(sequence))
    }

    fn admin_root() -> AdminRootContextV1 {
        AdminRootContextV1::new(
            object_hash(ADMIN_AUTHORIZATION_FILL),
            object_hash(ADMIN_TARGET_FILL),
            ADMIN_CONTEXT_ACTION_CODE,
        )
    }

    fn historical_regrant() -> HistoricalRegrantContextV1 {
        HistoricalRegrantContextV1::new(
            object_hash(REGRANT_AUTHORIZATION_FILL),
            entry_hash(REGRANT_ENTRY_FILL),
            object_hash(REGRANT_ORIGINAL_GRANT_FILL),
            object_hash(REGRANT_RECIPIENT_FILL),
            object_hash(REGRANT_NEW_GRANT_FILL),
        )
    }

    fn destruction() -> DestructionContextV1 {
        DestructionContextV1::new(
            object_hash(DESTRUCTION_AUTHORIZATION_FILL),
            object_hash(DESTRUCTION_STATE_EVENT_FILL),
        )
    }

    fn archive_profile_migration() -> ArchiveProfileMigrationContextV1 {
        ArchiveProfileMigrationContextV1::new(
            hash32(MIGRATION_SOURCE_FILL),
            hash32(MIGRATION_TARGET_FILL),
            hash32(MIGRATION_INVENTORY_FILL),
            hash32(MIGRATION_ACTIVE_POINTER_FILL),
        )
    }

    /// Die Taktfreigabe, deren Fenster und Zeitgleichheit die Grenze annimmt.
    fn clock_release(issued_at: i64, expires_at: i64) -> ClockReleaseContextV1 {
        ClockReleaseContextV1::new(
            UnixMillis::new(EFFECTIVE_NOW_MS - 1_000),
            UnixMillis::new(EFFECTIVE_NOW_MS),
            MAX_FUTURE_CLOCK_SKEW_MS,
            RegistryVersion::new(CLOCK_REGISTRY_VERSION),
            object_hash(CLOCK_REGISTRY_HEAD_FILL),
            object_hash(CLOCK_GUARD_POLICY_FILL),
            IndependentTimeReferenceV1::new(
                IndependentTimeKindV1::Receipt,
                object_hash(CLOCK_REFERENCE_FILL),
                UnixMillis::new(EFFECTIVE_NOW_MS - 2_000),
            ),
            ClockReleaseJustificationV1::OperatorVerifiedWallClock,
            UnixMillis::new(issued_at),
            UnixMillis::new(expires_at),
        )
    }

    /// Alle zwoelf Aktionen mit ihrem eigenen Kontext.
    ///
    /// `login` traegt KEINE Bindung: die nullbare sechste Position muss
    /// mindestens einmal als `null` durch den Kodierer laufen.
    pub fn one_event_per_action() -> Vec<LocalAuditEventCoreFieldsV1> {
        let mut login = event(
            LocalAuditActionV1::Login(generic()),
            LocalAuditOutcomeV1::Accepted,
        );
        login.operator_binding_object_hash = None;
        vec![
            login,
            event(
                LocalAuditActionV1::ReauthFailure(GenericAuditContextV1::new(None)),
                LocalAuditOutcomeV1::Failed,
            ),
            event(
                LocalAuditActionV1::BindingChange(binding_lifecycle(
                    None,
                    Some(object_hash(BINDING_NEW_FILL)),
                    BINDING_CHANGE_SEQUENCE,
                )),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::Revocation(binding_lifecycle(
                    Some(object_hash(BINDING_OLD_FILL)),
                    None,
                    REVOCATION_SEQUENCE,
                )),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::RegistryStaleWarnAcceptance(stale_registry()),
                LocalAuditOutcomeV1::Accepted,
            ),
            event(
                LocalAuditActionV1::PlaintextExport(export()),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::ClockSkewRelease(clock_release(
                    EFFECTIVE_NOW_MS,
                    EFFECTIVE_NOW_MS + 300_000,
                )),
                LocalAuditOutcomeV1::Accepted,
            ),
            event(
                LocalAuditActionV1::AdminRootCeremony(admin_root()),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::RecoveryTest(generic()),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::HistoricalRegrant(historical_regrant()),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::Destruction(destruction()),
                LocalAuditOutcomeV1::Completed,
            ),
            event(
                LocalAuditActionV1::ArchiveProfileMigration(archive_profile_migration()),
                LocalAuditOutcomeV1::Completed,
            ),
        ]
    }

    /// Dieselben zwoelf Aktionen mit den beiden eingefrorenen Zahlen.
    ///
    /// Anders als `one_event_per_action` traegt hier JEDES Ereignis eine
    /// Bindung und dieselbe Zeit, weil die beiden Versaetze sonst wandern.
    pub fn action_and_tag_expectations() -> Vec<(LocalAuditEventCoreFieldsV1, u8, u8)> {
        let mut expectations = Vec::new();
        for (index, event) in one_event_per_action().into_iter().enumerate() {
            let mut event = event;
            event.operator_binding_object_hash = Some(object_hash(0x20));
            let action_code = u8::try_from(index).expect("twelve actions");
            let context_tag = match action_code {
                0 | 1 | 8 => 0,
                2 | 3 => 4,
                4 => 1,
                5 => 3,
                6 => 2,
                7 => 5,
                9 => 6,
                10 => 7,
                11 => 8,
                _ => unreachable!("the twelve actions are closed"),
            };
            expectations.push((event, action_code, context_tag));
        }
        expectations
    }

    pub fn plaintext_export_event() -> LocalAuditEventCoreFieldsV1 {
        event(
            LocalAuditActionV1::PlaintextExport(export()),
            LocalAuditOutcomeV1::Completed,
        )
    }

    pub fn clock_skew_release_event() -> LocalAuditEventCoreFieldsV1 {
        event(
            LocalAuditActionV1::ClockSkewRelease(clock_release(
                EFFECTIVE_NOW_MS,
                EFFECTIVE_NOW_MS + 300_000,
            )),
            LocalAuditOutcomeV1::Accepted,
        )
    }

    /// Ein Freigabefenster, das rueckwaerts laeuft. Die Signaturgrenze lehnt es
    /// ab (`crates/ea-crypto/src/cose.rs`, `issued_at >= expires_at`).
    pub fn clock_skew_release_event_with_inverted_window() -> LocalAuditEventCoreFieldsV1 {
        event(
            LocalAuditActionV1::ClockSkewRelease(clock_release(
                EFFECTIVE_NOW_MS + 300_000,
                EFFECTIVE_NOW_MS,
            )),
            LocalAuditOutcomeV1::Accepted,
        )
    }

    pub fn sign(core: &[u8]) -> Vec<u8> {
        CoseSigner::from_secret(SecretBytes::new(SIGNER_SEED))
            .sign_local_audit(core)
            .expect("the frozen boundary accepts an encoded core")
    }

    fn signed(fields: &LocalAuditEventCoreFieldsV1) -> Vec<u8> {
        let core = encode_local_audit_core(fields).expect("the fixture core encodes");
        let cose = sign(&core);
        encode_local_audit_event(&core, &cose).expect("the fixture wrapper is well formed")
    }

    pub fn signed_plaintext_export_event() -> Vec<u8> {
        signed(&plaintext_export_event())
    }

    pub fn signed_clock_skew_release_event() -> Vec<u8> {
        signed(&clock_skew_release_event())
    }

    /// Eine Kontextposition, unabhaengig von ihrem Feldnamen.
    #[derive(Debug, Eq, PartialEq)]
    pub enum ContextPosition {
        OptionalHash(Option<[u8; 32]>),
        Hash([u8; 32]),
        Uint(u64),
        Int(i64),
    }

    fn hash_position(fill: u8) -> ContextPosition {
        ContextPosition::Hash([fill; 32])
    }

    /// Die erklaerten Fixturewerte, in der Reihenfolge der CDDL.
    ///
    /// Der generische Kontext hat genau eine Position und KEINE eigene Liste:
    /// `generic-audit-context-v1` traegt den Gegenstand unmittelbar hinter der
    /// Marke, ohne innere Liste.
    pub fn expected_context_positions(action: &LocalAuditActionV1) -> Vec<ContextPosition> {
        match action {
            LocalAuditActionV1::Login(_) | LocalAuditActionV1::RecoveryTest(_) => {
                vec![ContextPosition::OptionalHash(Some(
                    [GENERIC_SUBJECT_FILL; 32],
                ))]
            }
            LocalAuditActionV1::ReauthFailure(_) => {
                vec![ContextPosition::OptionalHash(None)]
            }
            LocalAuditActionV1::BindingChange(_) => vec![
                ContextPosition::OptionalHash(None),
                ContextPosition::OptionalHash(Some([BINDING_NEW_FILL; 32])),
                ContextPosition::Uint(BINDING_CHANGE_SEQUENCE),
            ],
            LocalAuditActionV1::Revocation(_) => vec![
                ContextPosition::OptionalHash(Some([BINDING_OLD_FILL; 32])),
                ContextPosition::OptionalHash(None),
                ContextPosition::Uint(REVOCATION_SEQUENCE),
            ],
            LocalAuditActionV1::RegistryStaleWarnAcceptance(_) => vec![
                hash_position(STALE_REGISTRY_HEAD_FILL),
                hash_position(STALE_POLICY_FILL),
                ContextPosition::Uint(STALE_PROPOSED_SEQUENCE),
                ContextPosition::Int(EFFECTIVE_NOW_MS - 1_000),
                ContextPosition::Int(EFFECTIVE_NOW_MS),
                hash_position(STALE_PREVIEW_FILL),
            ],
            LocalAuditActionV1::PlaintextExport(_) => vec![
                hash_position(EXPORT_ENTRY_FILL),
                ContextPosition::Uint(EXPORT_TARGET_KIND),
            ],
            LocalAuditActionV1::ClockSkewRelease(_) => vec![
                ContextPosition::Int(EFFECTIVE_NOW_MS - 1_000),
                ContextPosition::Int(EFFECTIVE_NOW_MS),
                ContextPosition::Uint(MAX_FUTURE_CLOCK_SKEW_MS),
                ContextPosition::Uint(CLOCK_REGISTRY_VERSION),
                hash_position(CLOCK_REGISTRY_HEAD_FILL),
                hash_position(CLOCK_GUARD_POLICY_FILL),
                // Die innere Zeitreferenz als ihre drei Positionen.
                ContextPosition::Uint(IndependentTimeKindV1::Receipt as u64),
                hash_position(CLOCK_REFERENCE_FILL),
                ContextPosition::Int(EFFECTIVE_NOW_MS - 2_000),
                ContextPosition::Uint(
                    ClockReleaseJustificationV1::OperatorVerifiedWallClock as u64,
                ),
                ContextPosition::Int(EFFECTIVE_NOW_MS),
                ContextPosition::Int(EFFECTIVE_NOW_MS + 300_000),
            ],
            LocalAuditActionV1::AdminRootCeremony(_) => vec![
                hash_position(ADMIN_AUTHORIZATION_FILL),
                hash_position(ADMIN_TARGET_FILL),
                ContextPosition::Uint(ADMIN_CONTEXT_ACTION_CODE),
            ],
            LocalAuditActionV1::HistoricalRegrant(_) => vec![
                hash_position(REGRANT_AUTHORIZATION_FILL),
                hash_position(REGRANT_ENTRY_FILL),
                hash_position(REGRANT_ORIGINAL_GRANT_FILL),
                hash_position(REGRANT_RECIPIENT_FILL),
                hash_position(REGRANT_NEW_GRANT_FILL),
            ],
            LocalAuditActionV1::Destruction(_) => vec![
                hash_position(DESTRUCTION_AUTHORIZATION_FILL),
                hash_position(DESTRUCTION_STATE_EVENT_FILL),
            ],
            LocalAuditActionV1::ArchiveProfileMigration(_) => vec![
                hash_position(MIGRATION_SOURCE_FILL),
                hash_position(MIGRATION_TARGET_FILL),
                hash_position(MIGRATION_INVENTORY_FILL),
                hash_position(MIGRATION_ACTIVE_POINTER_FILL),
            ],
        }
    }

    /// Liest die Kontextpositionen aus den Bytes, ohne den Dekodierer der Crate.
    ///
    /// Die Marke wird mitgelesen und gegen `context_tag()` gestellt; die
    /// Nutzlast folgt der Gestalt, die die Grammatik der Aktion gibt.
    pub fn read_context_positions(
        decoder: &mut minicbor::Decoder<'_>,
        action: &LocalAuditActionV1,
        positions: usize,
    ) -> Vec<ContextPosition> {
        assert_eq!(decoder.array().unwrap(), Some(2), "the context is a pair");
        assert_eq!(
            u8::try_from(decoder.u64().unwrap()).unwrap(),
            action.context_tag(),
            "the context pair must name the tag of its action"
        );
        let mut read = Vec::new();
        match action {
            LocalAuditActionV1::Login(_)
            | LocalAuditActionV1::ReauthFailure(_)
            | LocalAuditActionV1::RecoveryTest(_) => {
                read.push(read_optional_hash(decoder));
            }
            LocalAuditActionV1::ClockSkewRelease(_) => {
                assert_eq!(decoder.array().unwrap(), Some(10));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
                read.push(read_hash(decoder));
                read.push(read_hash(decoder));
                assert_eq!(decoder.array().unwrap(), Some(3));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
                read.push(read_hash(decoder));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
            }
            LocalAuditActionV1::BindingChange(_) | LocalAuditActionV1::Revocation(_) => {
                assert_eq!(decoder.array().unwrap(), Some(3));
                read.push(read_optional_hash(decoder));
                read.push(read_optional_hash(decoder));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
            }
            LocalAuditActionV1::RegistryStaleWarnAcceptance(_) => {
                assert_eq!(decoder.array().unwrap(), Some(6));
                read.push(read_hash(decoder));
                read.push(read_hash(decoder));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(ContextPosition::Int(decoder.i64().unwrap()));
                read.push(read_hash(decoder));
            }
            LocalAuditActionV1::PlaintextExport(_) => {
                assert_eq!(decoder.array().unwrap(), Some(2));
                read.push(read_hash(decoder));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
            }
            LocalAuditActionV1::AdminRootCeremony(_) => {
                assert_eq!(decoder.array().unwrap(), Some(3));
                read.push(read_hash(decoder));
                read.push(read_hash(decoder));
                read.push(ContextPosition::Uint(decoder.u64().unwrap()));
            }
            LocalAuditActionV1::HistoricalRegrant(_) => {
                assert_eq!(decoder.array().unwrap(), Some(5));
                for _ in 0..5 {
                    read.push(read_hash(decoder));
                }
            }
            LocalAuditActionV1::Destruction(_) => {
                assert_eq!(decoder.array().unwrap(), Some(2));
                for _ in 0..2 {
                    read.push(read_hash(decoder));
                }
            }
            LocalAuditActionV1::ArchiveProfileMigration(_) => {
                assert_eq!(decoder.array().unwrap(), Some(4));
                for _ in 0..4 {
                    read.push(read_hash(decoder));
                }
            }
        }
        assert_eq!(
            read.len(),
            positions,
            "the reader and the expectation must walk the same number of positions"
        );
        read
    }

    /// Dieselben Positionen, diesmal ueber die Zugriffe des dekodierten Werts.
    pub fn accessor_context_positions(action: &LocalAuditActionV1) -> Vec<ContextPosition> {
        match action {
            LocalAuditActionV1::Login(context)
            | LocalAuditActionV1::ReauthFailure(context)
            | LocalAuditActionV1::RecoveryTest(context) => {
                vec![ContextPosition::OptionalHash(
                    context.subject_object_hash().map(|hash| *hash.as_bytes()),
                )]
            }
            LocalAuditActionV1::BindingChange(context)
            | LocalAuditActionV1::Revocation(context) => vec![
                ContextPosition::OptionalHash(
                    context
                        .old_binding_object_hash()
                        .map(|hash| *hash.as_bytes()),
                ),
                ContextPosition::OptionalHash(
                    context
                        .new_binding_object_hash()
                        .map(|hash| *hash.as_bytes()),
                ),
                ContextPosition::Uint(context.effective_from_sequence().get()),
            ],
            LocalAuditActionV1::RegistryStaleWarnAcceptance(context) => vec![
                ContextPosition::Hash(*context.registry_head_hash().as_bytes()),
                ContextPosition::Hash(*context.policy_object_hash().as_bytes()),
                ContextPosition::Uint(context.proposed_sequence().get()),
                ContextPosition::Int(context.registry_not_after().get()),
                ContextPosition::Int(context.acknowledged_at().get()),
                ContextPosition::Hash(*context.preview_hash().as_bytes()),
            ],
            LocalAuditActionV1::PlaintextExport(context) => vec![
                ContextPosition::Hash(*context.entry_hash().as_bytes()),
                ContextPosition::Uint(context.target_kind()),
            ],
            LocalAuditActionV1::ClockSkewRelease(context) => vec![
                ContextPosition::Int(context.trusted_time_floor().get()),
                ContextPosition::Int(context.observed_os_wall_clock().get()),
                ContextPosition::Uint(context.max_future_clock_skew_ms()),
                ContextPosition::Uint(context.registry_version().get()),
                ContextPosition::Hash(*context.registry_head_hash().as_bytes()),
                ContextPosition::Hash(*context.guard_policy_object_hash().as_bytes()),
                ContextPosition::Uint(context.independent_reference().kind() as u64),
                ContextPosition::Hash(*context.independent_reference().object_hash().as_bytes()),
                ContextPosition::Int(context.independent_reference().verified_time().get()),
                ContextPosition::Uint(context.justification() as u64),
                ContextPosition::Int(context.issued_at().get()),
                ContextPosition::Int(context.expires_at().get()),
            ],
            LocalAuditActionV1::AdminRootCeremony(context) => vec![
                ContextPosition::Hash(*context.authorization_object_hash().as_bytes()),
                ContextPosition::Hash(*context.target_object_hash().as_bytes()),
                ContextPosition::Uint(context.action_code()),
            ],
            LocalAuditActionV1::HistoricalRegrant(context) => vec![
                ContextPosition::Hash(*context.authorization_object_hash().as_bytes()),
                ContextPosition::Hash(*context.entry_hash().as_bytes()),
                ContextPosition::Hash(*context.original_recovery_grant_object_hash().as_bytes()),
                ContextPosition::Hash(*context.recipient_certificate_object_hash().as_bytes()),
                ContextPosition::Hash(*context.new_grant_object_hash().as_bytes()),
            ],
            LocalAuditActionV1::Destruction(context) => vec![
                ContextPosition::Hash(*context.destruction_authorization_object_hash().as_bytes()),
                ContextPosition::Hash(*context.state_event_object_hash().as_bytes()),
            ],
            LocalAuditActionV1::ArchiveProfileMigration(context) => vec![
                ContextPosition::Hash(*context.source_profile_hash().as_bytes()),
                ContextPosition::Hash(*context.target_profile_hash().as_bytes()),
                ContextPosition::Hash(*context.inventory_hash().as_bytes()),
                ContextPosition::Hash(*context.active_pointer_hash().as_bytes()),
            ],
        }
    }

    fn read_hash(decoder: &mut minicbor::Decoder<'_>) -> ContextPosition {
        ContextPosition::Hash(decoder.bytes().unwrap().try_into().unwrap())
    }

    fn read_optional_hash(decoder: &mut minicbor::Decoder<'_>) -> ContextPosition {
        if decoder.datatype().unwrap() == minicbor::data::Type::Null {
            decoder.null().unwrap();
            return ContextPosition::OptionalHash(None);
        }
        ContextPosition::OptionalHash(Some(decoder.bytes().unwrap().try_into().unwrap()))
    }

    /// Der Versatz der Nonce IM KERN.
    ///
    /// Die Nonce steht im signierten Ereignis GENAU ZWEIMAL, weil die
    /// COSE-Nutzlast des lokalen Audits der ganze Kern ist. Der Versatz ist
    /// deshalb der erste der beiden Treffer, und die Zahl der Treffer wird
    /// mitgeprueft: waere sie eins, traefe die Kippung die Nutzlast statt den
    /// Kern und der Test messe eine andere Aussage.
    pub fn nonce_offset(signed: &[u8]) -> usize {
        let needle = [0x22_u8; 32];
        let hits = signed
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle.as_slice())
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>();
        assert_eq!(
            hits.len(),
            2,
            "the nonce must stand in the core and in the signed payload"
        );
        hits[0]
    }
}
