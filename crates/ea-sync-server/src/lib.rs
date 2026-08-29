//! Die Ports und technischen Modelle des Sync-Servers.
//!
//! Die Crate beschreibt, WAS der Server persistiert, und ueberlaesst `apps/server`,
//! WOMIT. Sie haelt keine Tokio-Laufzeit: die Ports sind
//! `#[async_trait]`-Kanten, hinter denen die echten Dienste stehen, und die
//! synchronen Kernbibliotheken (`ea-format`, `ea-crypto`, `ea-sync-protocol`)
//! werden direkt gerufen.
//!
//! Zwei Festlegungen tragen alles Weitere:
//!
//! 1. **Der Server bleibt blind.** Kein Typ dieser Crate hat ein Feld fuer eine
//!    Einsatznummer, eine Einsatzzeit, ein Stichwort, einen Ort, eine Person,
//!    ein Fahrzeug, einen Patienten oder eine Notiz. Objektschluessel sind
//!    `<type>/<hex objectHash>` und sonst nichts (`design.md` §13.4).
//! 2. **Die Objektarten haben genau eine Quelle.** Diese Crate erklaert keine
//!    eigene `ObjectType`-Aufzaehlung, sondern verbraucht
//!    [`ea_format::ObjectTypeV1`].

#![forbid(unsafe_code)]

pub mod auth;
pub mod models;
pub mod ports;
pub mod trust;

pub use models::{
    CommitDbCommand, CommitIdentityV1, CommittedDbState, CredentialRegistrationOutcome,
    IndexedObjectV1, PENDING_REGISTRATION_STATE_V1, PendingDeviceRequestV1,
    PendingRegistrationOutcome, RegistryLineEntryV1, RepositoryError, SecurityEventKindV1,
    SecurityEventV1, StagedObject, StoreError, StoredObject, TrustEventCommandV1,
    TrustIndexOutcome, WebauthnCredentialV1, object_key, object_type_segment,
};
pub use ports::{
    AuthorityError, ChallengeSpendOutcome, ChallengeStore, CommitRepository,
    DeviceAuthorityDirectory, DeviceRegistrationStore, ObjectStore, ObjectTypeDirectory,
    RequestIdStore, SecurityEventSink, ServerClock, ServerSigner, TrustEventStore,
    WebauthnCredentialStore,
};
