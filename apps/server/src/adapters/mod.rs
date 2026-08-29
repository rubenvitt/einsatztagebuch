//! Die echten Dienste hinter den Ports von `ea-sync-server`.
//!
//! Genau hier — und nur hier — beruehrt der Server PostgreSQL, den
//! S3-kompatiblen Object Store, seinen eigenen Ed25519-Schluessel und den
//! persistenten Vertrauenszustand. Die Ports selbst wissen von keinem davon.

pub mod auth_store;
pub mod clock;
pub mod postgres;
pub mod s3;
pub mod server_keys;
pub mod trust_authority;
pub mod trust_index;
pub mod trust_state;
