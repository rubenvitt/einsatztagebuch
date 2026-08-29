//! Ein Vertrauensabschluss MIT Writer, Reader und Recovery-Empfaenger.
//!
//! # Was dieses Modul modelliert — und warum es ueberhaupt existiert
//!
//! Der Commit-Endpunkt verlangt die Capability `initialGrant`, und die neun
//! Schritte aus `design.md` §13.3 brauchen zur Eintragssequenz aktive
//! Reader- und Recovery-Zertifikate. Die EINGEFROREN ausgelieferten
//! Vertrauensvektoren unter `vectors/trust/v1/` tragen weder das eine noch das
//! andere: ihr Erzeuger vergibt ausschliesslich `organizationAdminApprove`
//! (`crates/ea-testkit/src/lib.rs`:2711, :3241), und es gibt dort kein
//! `Writer`-, kein `Reader`- und kein `RecoveryRecipient`-Zertifikat.
//! `vectors/` und `crates/ea-testkit` sind eingefroren und werden hier NICHT
//! angefasst.
//!
//! Also wird der eingefrorene Abschluss FORTGESCHRIEBEN, nicht ersetzt: auf den
//! Anker und die beiden Koepfe von `registry/accepted-admin-rotation` setzt
//! dieses Modul drei weitere Registrierungskoepfe, die je ein Geraetezertifikat
//! aktivieren. Der Anker, die Wurzel, die Administratoren und die Richtlinie
//! bleiben die eingefrorenen.
//!
//! # Nichts hier ist eine Attrappe
//!
//! Jedes erzeugte Objekt ist ein echtes `.etb` mit echten Ed25519-Signaturen
//! ueber die echten Trust-Digests, gebildet mit den OEFFENTLICH deklarierten
//! Seeds aus `ea-testkit`. Eingespielt wird ueber den ECHTEN Endpunkt
//! `POST /v1/trust/events`, also durch dieselbe geteilte `ea-trust`-Pruefung,
//! die auch ein Reader fuehrt. Wird hier etwas falsch gebaut, antwortet der
//! Server mit `422` — die Kulisse kann sich nicht selbst fuer gueltig
//! erklaeren.
//!
//! # Die Sequenzleihe, und warum die Kette nicht bei null anfaengt
//!
//! Ein Registrierungskopf leiht sich einen Bereich von KETTENSEQUENZEN
//! (`design.md` §12.3), und die Leihe entscheidet, WELCHER Kopf gewaehlt wird:
//! `ea_trust::select_registry_head` haelt beim ERSTEN Kopf an, dessen Leihe die
//! vorgeschlagene Sequenz deckt, und laeuft nur ueber Koepfe hinweg, die sie
//! VERFEHLEN. Der zweite eingefrorene Kopf laeuft von 101 bis 200; wuerden die
//! neuen Koepfe dort ebenfalls beginnen, bliebe die Auswahl bei ihm stehen und
//! saehe die neuen Zertifikate nie.
//!
//! Aus demselben Grund leihen sich die neuen Koepfe LUECKENLOSE, aber
//! DISJUNKTE Bereiche: jeder Zwischenkopf deckt genau EINE Sequenz und
//! verfehlt damit die vorgeschlagene, sodass die Auswahl ueber ihn hinweg zum
//! naechsten laeuft. Erst der LETZTE Kopf deckt den Rest bis
//! [`LEASE_THROUGH_SEQUENCE`] und wird gewaehlt. Ein Zwischenkopf mit
//! ueberlappender Leihe hielte die Auswahl bei sich an, und die spaeter
//! aktivierten Zertifikate blieben unsichtbar.
//!
//! Ein Eintrag, den dieser Abschluss traegt, liegt also in `201..=500` — und
//! `commit_locked_head` verlangt fuer den ERSTEN Eintrag einer Kette die
//! Sequenz null. Beides zusammen geht nur, wenn die Kette schon steht: der
//! Testfall setzt den Kettenkopf deshalb ueber [`seed_chain_head`] auf eine
//! Sequenz innerhalb der Leihe und committet den Nachfolger. Das ist kein
//! Kunstgriff, sondern der Normalfall — eine Organisation im Betrieb hat ihre
//! erste Sequenz laengst hinter sich, und genau diesen Zustand bildet der
//! Testfall ab.

#![allow(dead_code)]

use ea_crypto::{
    CanonicalPublicCoseKey, CertificateCapability, CoseSigner, SecretBytes,
    authorized_trust_digest, object_hash, trust_digest,
};
use ea_format::{
    CertificateKindV1, DeviceCertificateFieldsV1, KeyProtectionProfileV1,
    OrganizationAdminAuthorizationFieldsV1, RegistryChangeV1, RegistryEventFieldsV1, TrustObjectV1,
    TrustPayloadV1, TrustSubtypeV1, encode_trust,
};
use ea_types::{
    AuthorizationId, CertificateHash, ChainId, ChainSequence, DeviceId, Hash32, ObjectHash,
    OrganizationId, RegistryVersion, UnixMillis,
};

/// Der eingefrorene Fall, auf dem dieses Modul aufsetzt.
pub const ROTATION_CASE: &str = "registry/accepted-admin-rotation";

/// Die Wurzel des eingefrorenen Abschlusses.
const ROOT_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ROOT_ED25519_SEED;
/// Der Administrator, der die neuen Uebergaenge autorisiert.
pub const ADMIN_SEED: [u8; 32] = ea_testkit::TEST_ENTROPY_ORGANIZATION_ADMIN_ED25519_SEED;

/// Der Signaturschluessel des WRITERS — der Aufrufer des Commit-Endpunkts.
pub const WRITER_SEED: [u8; 32] = [0xd1; 32];
/// Der KEM-Schluessel des Readers.
pub const READER_KEM_SEED: [u8; 32] = [0xd2; 32];
/// Der SIGNATURSCHLUESSEL des Readers.
///
/// Ein Readerzertifikat traegt BEIDE Schluessel: `ea-crypto` verlangt einen
/// Signaturschluessel fuer jede Art ausser dem Recovery-Empfaenger und einen
/// KEM-Schluessel fuer Reader und Recovery-Empfaenger
/// (`crates/ea-crypto/src/cose.rs`, `parse_device_certificate_core`). Ein
/// Reader quittiert schliesslich auch — `POST /v1/reader-acks` ist signiert.
pub const READER_SIGNING_SEED: [u8; 32] = [0xd5; 32];
/// Der Signaturschluessel des zweiten Readers.
pub const SECOND_READER_SIGNING_SEED: [u8; 32] = [0xd6; 32];
/// Der KEM-Schluessel des Recovery-Empfaengers.
pub const RECOVERY_KEM_SEED: [u8; 32] = [0xd3; 32];
/// Der KEM-Schluessel eines ZWEITEN Readers, den nur einzelne Faelle aktiv
/// schalten.
pub const SECOND_READER_KEM_SEED: [u8; 32] = [0xd4; 32];
/// Der Signaturschluessel der HISTORICAL GRANT AUTHORITY.
///
/// Sie ist die Rolle, die `design.md` §6.5 von der Recovery-Custodianschaft
/// TRENNT: der Custodian entkapselt den historischen CEK, die Authority
/// signiert den neuen Grant. Ihr Zertifikat traegt deshalb `historicalGrant`
/// und keine Empfaengerschluessel.
pub const HISTORICAL_GRANT_AUTHORITY_SEED: [u8; 32] = [0xd7; 32];
/// Der ERSTE Key Approver. Zwei UNTERSCHIEDLICHE braucht jede
/// Mehr-Augen-Autorisierung (`design.md` §16.2, §16.3).
pub const APPROVER_A_SEED: [u8; 32] = [0xd8; 32];
/// Der ZWEITE Key Approver.
pub const APPROVER_B_SEED: [u8; 32] = [0xd9; 32];

const WRITER_DEVICE_ID: [u8; 16] = [0xe1; 16];
const READER_DEVICE_ID: [u8; 16] = [0xe2; 16];
const RECOVERY_DEVICE_ID: [u8; 16] = [0xe3; 16];
const SECOND_READER_DEVICE_ID: [u8; 16] = [0xe4; 16];
const HISTORICAL_GRANT_AUTHORITY_DEVICE_ID: [u8; 16] = [0xe5; 16];
const APPROVER_A_DEVICE_ID: [u8; 16] = [0xe6; 16];
const APPROVER_B_DEVICE_ID: [u8; 16] = [0xe7; 16];
/// Die pseudonyme Betreiberkennung eines Approver-Zertifikats.
///
/// `Some` gilt GENAU fuer die Arten 2 und 3 — Organisationsadministrator und
/// Key Approver (`crates/ea-format/src/etb.rs`, `decode_device_core`); ohne
/// sie entsteht das Zertifikat gar nicht erst.
const APPROVER_A_SUBJECT_ID: [u8; 16] = [0xf1; 16];
const APPROVER_B_SUBJECT_ID: [u8; 16] = [0xf2; 16];

/// Ab dieser Kettensequenz gelten die neuen Zertifikate.
///
/// GENAU EINS hinter dem Ende der eingefrorenen Leihe (100 + 100 = 200): so
/// verfehlt der zweite eingefrorene Kopf die vorgeschlagene Sequenz, die
/// Auswahl laeuft ueber ihn hinweg, und die neuen Koepfe kommen ueberhaupt zum
/// Zug.
pub const LEASE_FROM_SEQUENCE: u64 = 201;
/// Bis zu dieser Kettensequenz laeuft die Leihe der neuen Koepfe.
pub const LEASE_THROUGH_SEQUENCE: u64 = 500;

/// Ausstellungs- und Zeitfenster der neuen Koepfe — die des eingefrorenen
/// Falls, damit die Serverzeit der Testfaelle unveraendert traegt.
const ISSUED_AT_MILLIS: i64 = 100;
const NOT_BEFORE_MILLIS: i64 = 90;
const NOT_AFTER_MILLIS: i64 = 10_000;
const AUTHORIZATION_EXPIRES_AT_MILLIS: i64 = 1_100;

/// Ein benanntes `.etb`, wie es ueber den Endpunkt geht.
pub struct ClosureObject {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

/// Der fortgeschriebene Abschluss.
pub struct ExtendedClosure {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub writer_certificate_hash: CertificateHash,
    pub reader_certificate_hash: CertificateHash,
    pub recovery_certificate_hash: CertificateHash,
    /// Nur gesetzt, wenn der Abschluss den zweiten Reader traegt.
    pub second_reader_certificate_hash: Option<CertificateHash>,
    /// Nur gesetzt, wenn der Abschluss die Grant- und Vernichtungsrollen
    /// traegt: Historical Grant Authority und zwei Key Approver.
    pub historical_grant_authority_certificate_hash: Option<CertificateHash>,
    pub approver_certificate_hashes: Option<[CertificateHash; 2]>,
    /// Der Kopf, den ein Commit binden muss.
    pub registry_version: RegistryVersion,
    pub registry_head_hash: ObjectHash,
    /// Die Objekte in ABHAENGIGKEITSREIHENFOLGE — so und nicht anders gehen
    /// sie ueber den Endpunkt.
    pub objects: Vec<ClosureObject>,
}

impl ExtendedClosure {
    /// Die Kettensequenz, auf der ein Testfall die Kette stehen laesst.
    ///
    /// Mit Abstand innerhalb der Leihe, damit auch ein zweiter und dritter
    /// Eintrag noch hineinpassen.
    #[must_use]
    pub const fn seeded_head_sequence() -> u64 {
        LEASE_FROM_SEQUENCE + 49
    }

    /// Die Sequenz des Eintrags, der committet wird.
    ///
    /// GENAU der gesetzte Kopf plus eins — `commit_locked_head` nimmt nichts
    /// anderes an. Sie liegt damit im Bereich des LETZTEN Kopfes, und nur
    /// dieser traegt alle drei Zertifikate.
    #[must_use]
    pub const fn commit_sequence() -> u64 {
        Self::seeded_head_sequence() + 1
    }
}

fn signer(seed: [u8; 32]) -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(seed))
}

fn signing_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    signer(seed)
        .public_key()
        .expect("a declared Ed25519 seed yields a canonical public key")
}

/// Der oeffentliche KEM-Schluessel zu einem deklarierten X25519-Seed.
#[must_use]
pub fn kem_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    let private = ea_crypto::HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
        .expect("a declared X25519 seed loads");
    CanonicalPublicCoseKey::x25519(*private.public_key().as_bytes())
        .expect("a declared X25519 seed yields a canonical public key")
}

fn hash32(hash: ObjectHash) -> Hash32 {
    Hash32::try_from(hash.as_bytes().as_slice()).expect("an object hash is 32 bytes")
}

/// Der Digest-Eingang, ueber den eine Admin-Autorisierung ihren Zielkern
/// bindet.
///
/// Der autorisierte Nutzinhalt ist `[kern, autorisierungshash]`; gebunden wird
/// `[subtyp, kern]`. Der Schnitt ist BEWIESEN und nicht geraten: die beiden
/// Zusicherungen messen die Arrayform und den abschliessenden 32-Byte-String,
/// bevor geschnitten wird — dieselbe Rechnung, die `ea-testkit` fuer die
/// eingefrorenen Vektoren fuehrt.
fn authorized_core_input(payload: &TrustPayloadV1) -> Vec<u8> {
    let exact = payload.exact_payload();
    let tail = exact
        .len()
        .checked_sub(34)
        .expect("an authorized payload carries at least its trailing hash");
    assert_eq!(
        exact[0], 0x82,
        "an authorized payload is a two element array"
    );
    assert_eq!(
        &exact[tail..tail + 2],
        &[0x58, 0x20],
        "an authorized payload ends on a 32 byte string"
    );
    let subtype = payload.subtype().as_str();
    let mut input = vec![0x82];
    input.push(0x60 | u8::try_from(subtype.len()).expect("a subtype literal is short"));
    input.extend_from_slice(subtype.as_bytes());
    input.extend_from_slice(&exact[1..tail]);
    input
}

/// Was eine Admin-Autorisierung dieses Moduls unterscheidet.
struct AuthorizationSpec<'a> {
    action_code: u8,
    target_trust_subtype: TrustSubtypeV1,
    authorization_id: u8,
    nonce: u8,
    /// Der Kopf, der zum Zeitpunkt des Uebergangs GILT — nicht der, der
    /// entsteht. `ea_trust::verify_bound_authorization` stellt genau das.
    registry_version: u64,
    registry_head_hash: Hash32,
    context: &'a FrozenContext,
}

/// Was aus dem eingefrorenen Abschluss gelesen wird.
pub struct FrozenContext {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    root_certificate_hash: CertificateHash,
    admin_certificate_hash: ObjectHash,
    admin_binding_hash: ObjectHash,
    policy_object_hash: ObjectHash,
    head_two_hash: ObjectHash,
}

/// Liest Anker, Wurzel, Administrator, Bindung, Richtlinie und den zweiten
/// Kopf aus den EINGEFRORENEN Dateien.
///
/// # Panics
///
/// Wenn eine der eingefrorenen Dateien fehlt oder nicht dekodiert.
#[must_use]
pub fn frozen_context() -> FrozenContext {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/trust/v1")
        .join(ROTATION_CASE);
    let read = |name: &str| std::fs::read(root.join(name)).expect("a frozen object must read");

    let anchor_bytes = read("anchor.bin");
    let anchor = ea_trust::decode_trust_anchor(&anchor_bytes).expect("the frozen anchor decodes");

    FrozenContext {
        organization_id: anchor.organization_id(),
        chain_id: anchor.chain_id(),
        root_certificate_hash: CertificateHash::from(object_hash(&read("root-certificate.bin"))),
        admin_certificate_hash: object_hash(&read("admin-certificate-a.bin")),
        admin_binding_hash: object_hash(&read("admin-binding-a.bin")),
        policy_object_hash: object_hash(&read("policy.bin")),
        head_two_hash: object_hash(&read("second-head-event.bin")),
    }
}

/// Eine Admin-Autorisierung ueber genau dieses Ziel.
fn authorization(target: &TrustPayloadV1, spec: &AuthorizationSpec<'_>) -> Vec<u8> {
    let payload =
        TrustPayloadV1::organization_admin_authorization(OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from([spec.authorization_id; 16].as_slice())
                .expect("16 bytes"),
            organization_id: spec.context.organization_id,
            registry_version: RegistryVersion::new(spec.registry_version),
            registry_head_hash: spec.registry_head_hash,
            admin_key_thumbprint: signing_key(ADMIN_SEED).thumbprint(),
            admin_certificate_hash: CertificateHash::from(spec.context.admin_certificate_hash),
            admin_operator_binding_object_hash: spec.context.admin_binding_hash,
            action_code: spec.action_code,
            target_trust_subtype: spec.target_trust_subtype,
            authorized_trust_core_hash: authorized_trust_digest(&authorized_core_input(target)),
            issued_at: UnixMillis::new(ISSUED_AT_MILLIS),
            expires_at: UnixMillis::new(AUTHORIZATION_EXPIRES_AT_MILLIS),
            nonce: [spec.nonce; 32],
        })
        .expect("the authorization payload is well formed");
    // Der ECHTE Signierer: er leitet den Zertifikatshash aus dem Nutzinhalt ab
    // und weist eine Abweichung selbst ab.
    let signature = signer(ADMIN_SEED)
        .sign_organization_admin_trust_digest(payload.exact_digest_input())
        .expect("signing the admin authorization must succeed");
    exact_object(payload, vec![signature])
}

/// Ein von der WURZEL signiertes `.etb`.
///
/// `sign_root_trust_digest` prueft die volle Bindung an die Autorisierung —
/// Zielsubtyp, Kernhash, Organisation und die zulaessige Aktion. Ein falsch
/// gebautes Objekt scheitert deshalb schon hier und nicht erst am Server.
fn root_signed(
    payload: TrustPayloadV1,
    authorization_bytes: &[u8],
    root: CertificateHash,
) -> Vec<u8> {
    let signature = signer(ROOT_SEED)
        .sign_root_trust_digest(
            root,
            payload.exact_digest_input(),
            Some(authorization_bytes),
        )
        .expect("signing with the root key must succeed");
    debug_assert_eq!(
        trust_digest(payload.exact_digest_input()).as_bytes().len(),
        32
    );
    exact_object(payload, vec![signature])
}

fn exact_object(payload: TrustPayloadV1, signatures: Vec<Vec<u8>>) -> Vec<u8> {
    encode_trust(&TrustObjectV1::new(payload, signatures).expect("the trust object is well formed"))
        .expect("encoding a well formed trust object cannot fail")
        .into_vec()
}

/// Die Felder eines Geraetezertifikats dieses Moduls.
#[allow(clippy::too_many_arguments)]
fn device_fields(
    context: &FrozenContext,
    device: [u8; 16],
    kind: CertificateKindV1,
    signing_seed: Option<[u8; 32]>,
    kem_seed: Option<[u8; 32]>,
    capabilities: Vec<CertificateCapability>,
    effective_from: u64,
    authority_subject_id: Option<[u8; 16]>,
) -> DeviceCertificateFieldsV1 {
    DeviceCertificateFieldsV1 {
        organization_id: context.organization_id,
        device_id: DeviceId::try_from(&device[..]).expect("16 bytes"),
        certificate_kind: kind,
        signing_public_cose_key: signing_seed.map(|seed| signing_key(seed).to_deterministic_cbor()),
        kem_public_cose_key: kem_seed.map(|seed| kem_key(seed).to_deterministic_cbor()),
        signing_key_thumbprint: signing_seed.map(|seed| signing_key(seed).thumbprint()),
        kem_key_thumbprint: kem_seed.map(|seed| kem_key(seed).thumbprint()),
        capabilities: capabilities
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        key_protection_profile: KeyProtectionProfileV1::OsWrapped,
        // Ein Zertifikat wird GENAU von dem Kopf aktiviert, dessen
        // `effective-from-sequence` es traegt (`ea_trust::validate_device_target`).
        effective_from_sequence: ChainSequence::new(effective_from),
        revoked_from_sequence: None,
        // `Some` gilt GENAU fuer die Arten 2 und 3 — Organisationsadministrator
        // und Key Approver (`crates/ea-format/src/etb.rs`, `decode_device_core`).
        // Writer, Reader und Recovery-Empfaenger tragen keine.
        authority_subject_id: authority_subject_id
            .map(|id| ea_types::SubjectId::try_from(&id[..]).expect("16 bytes")),
    }
}

/// EIN Uebergang: das Zertifikat, seine Autorisierung, der Kopf und dessen
/// Autorisierung — in genau dieser Reihenfolge.
struct Transition {
    certificate_hash: CertificateHash,
    head_hash: ObjectHash,
    objects: Vec<ClosureObject>,
}

/// Baut den Uebergang, der GENAU EIN Geraetezertifikat aktiviert.
#[allow(clippy::too_many_arguments)]
fn certificate_transition(
    context: &FrozenContext,
    fields: DeviceCertificateFieldsV1,
    registry_version: u64,
    current_head: ObjectHash,
    lease: (u64, u64),
    marker: u8,
    names: [&'static str; 4],
) -> Transition {
    let current_head32 = hash32(current_head);

    // Der Autorisierungshash steht IM Nutzinhalt, also entsteht das Zertifikat
    // zweimal: einmal mit Nullhash, um den Kern zu binden, und einmal mit dem
    // Hash der fertigen Autorisierung.
    let provisional = TrustPayloadV1::authorized_device_certificate(
        fields.clone(),
        ObjectHash::from(Hash32::ZERO),
    )
    .expect("the provisional certificate payload is well formed");
    let certificate_authorization = authorization(
        &provisional,
        &AuthorizationSpec {
            // `0` ist die Aktion fuer ein Geraetezertifikat, das KEIN
            // Administratorzertifikat ist (`ea-crypto`,
            // `admin_action_permits_device_certificate`).
            action_code: 0,
            target_trust_subtype: TrustSubtypeV1::DeviceCertificate,
            authorization_id: marker,
            nonce: marker,
            registry_version,
            registry_head_hash: current_head32,
            context,
        },
    );
    let certificate_payload = TrustPayloadV1::authorized_device_certificate(
        fields,
        object_hash(&certificate_authorization),
    )
    .expect("the certificate payload is well formed");
    let certificate_bytes = root_signed(
        certificate_payload,
        &certificate_authorization,
        context.root_certificate_hash,
    );
    let certificate_object_hash = object_hash(&certificate_bytes);

    let head_fields = RegistryEventFieldsV1 {
        organization_id: context.organization_id,
        registry_version: RegistryVersion::new(registry_version + 1),
        previous_registry_hash: Some(current_head32),
        effective_from_sequence: ChainSequence::new(lease.0),
        valid_through_sequence: ChainSequence::new(lease.1),
        issued_at: UnixMillis::new(ISSUED_AT_MILLIS),
        not_before: UnixMillis::new(NOT_BEFORE_MILLIS),
        not_after: UnixMillis::new(NOT_AFTER_MILLIS),
        policy_object_hash: context.policy_object_hash,
        change: RegistryChangeV1::Certificate {
            object_hash: certificate_object_hash,
        },
        root_key_thumbprint: signing_key(ROOT_SEED).thumbprint(),
    };
    let provisional_head =
        TrustPayloadV1::registry_event(head_fields.clone(), ObjectHash::from(Hash32::ZERO))
            .expect("the provisional head payload is well formed");
    let head_authorization = authorization(
        &provisional_head,
        &AuthorizationSpec {
            action_code: 0,
            target_trust_subtype: TrustSubtypeV1::RegistryEvent,
            authorization_id: marker.wrapping_add(1),
            nonce: marker.wrapping_add(1),
            registry_version,
            registry_head_hash: current_head32,
            context,
        },
    );
    let head_payload =
        TrustPayloadV1::registry_event(head_fields, object_hash(&head_authorization))
            .expect("the head payload is well formed");
    let head_bytes = root_signed(
        head_payload,
        &head_authorization,
        context.root_certificate_hash,
    );
    let head_hash = object_hash(&head_bytes);

    Transition {
        certificate_hash: CertificateHash::from(certificate_object_hash),
        head_hash,
        objects: vec![
            ClosureObject {
                name: names[0],
                bytes: certificate_authorization,
            },
            ClosureObject {
                name: names[1],
                bytes: certificate_bytes,
            },
            ClosureObject {
                name: names[2],
                bytes: head_authorization,
            },
            ClosureObject {
                name: names[3],
                bytes: head_bytes,
            },
        ],
    }
}

/// Der vollstaendige fortgeschriebene Abschluss.
///
/// Drei Uebergaenge auf den zweiten eingefrorenen Kopf: Writer, Reader,
/// Recovery-Empfaenger. `with_second_reader` schaltet einen VIERTEN Uebergang
/// dazu — er dient den Faellen, in denen die aktive Empfaengermenge groesser
/// sein muss als der gelieferte Grant-Satz.
///
/// # Panics
///
/// Wenn eines der eingefrorenen Objekte fehlt oder eine Konstruktion
/// fehlschlaegt. Beides waere ein Fehler dieser Kulisse, kein Laufzeitzustand.
#[must_use]
pub fn build(with_second_reader: bool) -> ExtendedClosure {
    build_with(with_second_reader, false)
}

/// Derselbe Abschluss, aber mit den Rollen des historischen Re-Grants und der
/// kontrollierten Vernichtung.
///
/// `with_grant_authorities` haengt DREI weitere Uebergaenge an: eine Historical
/// Grant Authority mit `historicalGrant` und ZWEI Key Approver mit
/// `historicalGrantApprove` und `destructionApprove`. Zwei und nicht einer,
/// weil eine Mehr-Augen-Autorisierung sonst gar nicht baubar waere — und genau
/// das ist die Aussage, die diese Endpunkte pruefen.
///
/// Die eingefrorenen Vektoren unter `vectors/trust/v1/` tragen keine dieser
/// Rollen (ihr Erzeuger vergibt ausschliesslich `organizationAdminApprove`),
/// und `vectors/` wie `crates/ea-testkit` bleiben unangetastet. Der Abschluss
/// wird deshalb FORTGESCHRIEBEN, nicht ersetzt.
///
/// # Panics
///
/// Wie [`build`].
#[must_use]
pub fn build_with(with_second_reader: bool, with_grant_authorities: bool) -> ExtendedClosure {
    let context = frozen_context();

    // Jeder Zwischenkopf deckt genau EINE Sequenz; der letzte deckt den Rest.
    let count = 3 + usize::from(with_second_reader) + if with_grant_authorities { 3 } else { 0 };
    let lease_of = |index: usize| {
        let from = LEASE_FROM_SEQUENCE + index as u64;
        let through = if index + 1 == count {
            LEASE_THROUGH_SEQUENCE
        } else {
            from
        };
        (from, through)
    };

    let writer = certificate_transition(
        &context,
        device_fields(
            &context,
            WRITER_DEVICE_ID,
            CertificateKindV1::Writer,
            Some(WRITER_SEED),
            None,
            vec![CertificateCapability::InitialGrant],
            lease_of(0).0,
            None,
        ),
        2,
        context.head_two_hash,
        lease_of(0),
        0x30,
        [
            "writer-certificate-authorization",
            "writer-certificate",
            "writer-head-authorization",
            "writer-head-event",
        ],
    );
    let reader = certificate_transition(
        &context,
        device_fields(
            &context,
            READER_DEVICE_ID,
            CertificateKindV1::Reader,
            Some(READER_SIGNING_SEED),
            Some(READER_KEM_SEED),
            Vec::new(),
            lease_of(1).0,
            None,
        ),
        3,
        writer.head_hash,
        lease_of(1),
        0x34,
        [
            "reader-certificate-authorization",
            "reader-certificate",
            "reader-head-authorization",
            "reader-head-event",
        ],
    );
    let recovery = certificate_transition(
        &context,
        device_fields(
            &context,
            RECOVERY_DEVICE_ID,
            CertificateKindV1::RecoveryRecipient,
            None,
            Some(RECOVERY_KEM_SEED),
            Vec::new(),
            lease_of(2).0,
            None,
        ),
        4,
        reader.head_hash,
        lease_of(2),
        0x38,
        [
            "recovery-certificate-authorization",
            "recovery-certificate",
            "recovery-head-authorization",
            "recovery-head-event",
        ],
    );

    let mut objects = Vec::new();
    objects.extend(writer.objects);
    objects.extend(reader.objects);
    objects.extend(recovery.objects);
    let mut registry_version = 5;
    let mut registry_head_hash = recovery.head_hash;
    let mut second_reader = None;
    let mut next_lease = 3;
    let mut historical_grant_authority = None;
    let mut approvers = None;

    if with_second_reader {
        let second = certificate_transition(
            &context,
            device_fields(
                &context,
                SECOND_READER_DEVICE_ID,
                CertificateKindV1::Reader,
                Some(SECOND_READER_SIGNING_SEED),
                Some(SECOND_READER_KEM_SEED),
                Vec::new(),
                lease_of(3).0,
                None,
            ),
            5,
            recovery.head_hash,
            lease_of(3),
            0x3c,
            [
                "second-reader-certificate-authorization",
                "second-reader-certificate",
                "second-reader-head-authorization",
                "second-reader-head-event",
            ],
        );
        objects.extend(second.objects);
        registry_version = 6;
        registry_head_hash = second.head_hash;
        second_reader = Some(second.certificate_hash);
        next_lease = 4;
    }

    if with_grant_authorities {
        let authority = certificate_transition(
            &context,
            device_fields(
                &context,
                HISTORICAL_GRANT_AUTHORITY_DEVICE_ID,
                CertificateKindV1::HistoricalGrantAuthority,
                Some(HISTORICAL_GRANT_AUTHORITY_SEED),
                None,
                vec![CertificateCapability::HistoricalGrant],
                lease_of(next_lease).0,
                None,
            ),
            registry_version,
            registry_head_hash,
            lease_of(next_lease),
            0x40,
            [
                "historical-grant-authority-certificate-authorization",
                "historical-grant-authority-certificate",
                "historical-grant-authority-head-authorization",
                "historical-grant-authority-head-event",
            ],
        );
        objects.extend(authority.objects);
        registry_version += 1;
        registry_head_hash = authority.head_hash;
        historical_grant_authority = Some(authority.certificate_hash);

        // Beide Approver tragen BEIDE Capabilities: derselbe Ausschuss
        // autorisiert einen historischen Re-Grant und eine Vernichtung, und
        // eine zweite Personenmenge dafuer waere eine Erfindung dieser
        // Kulisse.
        let mut approver_hashes = Vec::with_capacity(2);
        for (index, (device, subject, seed, names)) in [
            (
                APPROVER_A_DEVICE_ID,
                APPROVER_A_SUBJECT_ID,
                APPROVER_A_SEED,
                [
                    "approver-a-certificate-authorization",
                    "approver-a-certificate",
                    "approver-a-head-authorization",
                    "approver-a-head-event",
                ],
            ),
            (
                APPROVER_B_DEVICE_ID,
                APPROVER_B_SUBJECT_ID,
                APPROVER_B_SEED,
                [
                    "approver-b-certificate-authorization",
                    "approver-b-certificate",
                    "approver-b-head-authorization",
                    "approver-b-head-event",
                ],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let lease_index = next_lease + 1 + index;
            let approver = certificate_transition(
                &context,
                device_fields(
                    &context,
                    device,
                    CertificateKindV1::KeyApprover,
                    Some(seed),
                    None,
                    // Die Reihenfolge ist die des WIRE-Literals und keine
                    // Geschmacksfrage: `ea-format` verlangt eine sortierte
                    // Capability-Liste, und `destructionApprove` steht vor
                    // `historicalGrantApprove`.
                    vec![
                        CertificateCapability::DestructionApprove,
                        CertificateCapability::HistoricalGrantApprove,
                    ],
                    lease_of(lease_index).0,
                    Some(subject),
                ),
                registry_version,
                registry_head_hash,
                lease_of(lease_index),
                0x44_u8.wrapping_add(u8::try_from(index * 4).expect("two approvers")),
                names,
            );
            objects.extend(approver.objects);
            registry_version += 1;
            registry_head_hash = approver.head_hash;
            approver_hashes.push(approver.certificate_hash);
        }
        approvers = Some([approver_hashes[0], approver_hashes[1]]);
    }

    ExtendedClosure {
        organization_id: context.organization_id,
        chain_id: context.chain_id,
        writer_certificate_hash: writer.certificate_hash,
        reader_certificate_hash: reader.certificate_hash,
        recovery_certificate_hash: recovery.certificate_hash,
        second_reader_certificate_hash: second_reader,
        historical_grant_authority_certificate_hash: historical_grant_authority,
        approver_certificate_hashes: approvers,
        registry_version: RegistryVersion::new(registry_version),
        registry_head_hash,
        objects,
    }
}

/// Setzt den Kettenkopf auf eine Sequenz INNERHALB der Leihe.
///
/// Nur die technische Kopfzeile, kein Eintrag: `chain_heads` traegt keinen
/// Fremdschluessel auf `entries`, und der Testfall braucht genau diesen
/// Zustand — eine Kette, die schon laeuft. Die Annahmezeit des gesetzten
/// Kopfes ist ein PARAMETER, weil die Monotonie von `acceptedAtServer` an ihr
/// haengt.
///
/// # Panics
///
/// Wenn das Einfuegen scheitert.
pub async fn seed_chain_head(
    pool: &sqlx::PgPool,
    organization_id: OrganizationId,
    chain_id: ChainId,
    sequence: u64,
    head_entry_hash: [u8; 32],
    accepted_at_server: i64,
) {
    sqlx::query(
        "INSERT INTO chain_heads (organization_id, chain_id, head_sequence, head_entry_hash, \
         head_accepted_at_server_millis, revision) VALUES ($1, $2, $3, $4, $5, 0)",
    )
    .bind(&organization_id.as_bytes()[..])
    .bind(&chain_id.as_bytes()[..])
    .bind(i64::try_from(sequence).expect("a test sequence is small"))
    .bind(&head_entry_hash[..])
    .bind(accepted_at_server)
    .execute(pool)
    .await
    .expect("seeding the chain head must succeed");
}
