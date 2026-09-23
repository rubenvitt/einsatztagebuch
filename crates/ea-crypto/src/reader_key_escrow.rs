//! Die Höchstdauern der beiden Escrow-Autorisierungen (v1.1-Profil §3.1,
//! Entscheidung 4).
//!
//! Sie stehen HIER und nicht in `ea-format`, weil beide Seiten sie brauchen:
//! der Codec in `ea-format` prüft die Feldrelation beim Kodieren und Dekodieren,
//! und die Kernparser dieser Crate (die `VerificationContext`-Konstruktoren)
//! prüfen sie ein zweites Mal, ohne von `ea-format` abzuhängen. `ea-format`
//! hängt an `ea-crypto`, nicht umgekehrt; eine zweite Kopie der Zahl wäre die
//! Gelegenheit, sie verschieden zu machen.
//!
//! Geprüft wird ausschließlich `expires − issued ∈ 1..=MAX`, gerechnet mit
//! `checked_sub`. Die Randsemantik gegen die Uhr (`now > expiresAt` ist
//! abgelaufen, Entscheidung 10) gehört in den Trust-Kern, nicht in den Codec.

/// Höchstdauer der Publikationsfreigabe `readerKeyEscrowApproval` in
/// Millisekunden.
pub const READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS: i64 = 300_000;

/// Höchstdauer der Öffnungsautorisierung
/// `readerKeyEscrowRecoveryAuthorization` in Millisekunden.
pub const READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS: i64 = 900_000;

/// `true`, wenn `expires − issued` ohne Überlauf in `1..=max_lifetime_ms`
/// liegt.
#[must_use]
pub fn reader_key_escrow_lifetime_is_admissible(
    issued_at_ms: i64,
    expires_at_ms: i64,
    max_lifetime_ms: i64,
) -> bool {
    expires_at_ms
        .checked_sub(issued_at_ms)
        .is_some_and(|lifetime| (1..=max_lifetime_ms).contains(&lifetime))
}
