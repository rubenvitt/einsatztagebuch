//! Das Browser-Enrollment: zwei Pflicht-Authenticators und das nicht
//! ueberspringbare Fingerprint-Gate.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §6.6
//! beschreibt den Vorgang, §6.3 macht zwei unabhaengige Authenticators zur
//! Pflicht und §4.3 verlangt, dass der Fingerprint-Vergleich beim Erstaufruf
//! auf einem Geraet ohne gepinnten Trust-Store ERZWUNGEN und NICHT
//! ueberspringbar ist. Beides steht hier — und zwar so, dass es kein
//! Bildschirm, sondern der Typ traegt.
//!
//! # Das Gate ist eine TYPAUSSAGE
//!
//! [`ReaderEnrollment::finish`] nimmt eine [`FingerprintConfirmationV1`], und
//! dieser Wert entsteht ausschliesslich in
//! [`ReaderEnrollment::confirm_fingerprints`], dort nur nach einem
//! konstantzeitigen Vergleich BEIDER Werte. Es gibt keinen `skip`, kein
//! `force`, kein `Default` und keine zweite Konstruktionsstelle. Eine
//! Laufzeitpruefung waere umgehbar, sobald jemand einen zweiten Aufrufweg
//! baut; ein nicht darstellbarer Zustand ist es nicht.
//! `the_confirmation_has_no_construction_path_outside_a_match` in
//! `crates/ea-reader/tests/fingerprint_gate.rs` misst genau diese Abwesenheit
//! ueber den Quelltext dieser Datei.
//!
//! # Die Schluesselerzeugung laeuft im Browser
//!
//! §6.6 Schritt 1: der Reader erzeugt X25519- und Ed25519-Schluesselpaar
//! selbst, und die privaten Schluessel verlassen den Browser nie.
//! [`ReaderEnrollment::begin`] zieht 64 Byte ueber `getrandom::fill` — im
//! Browser `globalThis.crypto.getRandomValues`, ausfuehrbar nachgewiesen in
//! `spikes/wasm-runtime-proof/spike.sh`. Beide Schluessel liegen als
//! `SecretBytes<32>` und damit unter `ZeroizeOnDrop`.
//!
//! # Der Anker und der Bundle-Fingerprint kommen als PARAMETER
//!
//! Der gepinnte Root-Anker kommt niemals aus einer Serverantwort; die Bruecke
//! reicht ihn ueber `ea_trust::decode_trust_anchor` herein, und das ist der
//! ganze Punkt: der Anker gilt nicht, weil er im Tresor lag, sondern weil
//! `decode_trust_anchor` seinen Bootstrap-Hash beim Dekodieren NEU rechnet. Der
//! Bundle-Fingerprint kommt aus demselben Grund als Parameter — `ea-reader` hat
//! keinen Weg, das geladene Buendel zu lesen.
//!
//! # Uhr und Einmalwerte treten als WERTE ein
//!
//! `RequestSigner::sign` nimmt `created`, `expires`, `nonce` und die
//! `RequestIdV1` von aussen; der Modulkopf von
//! `crates/ea-sync-protocol/src/http_signature.rs` schreibt das als Absicht
//! aus. `ea-reader` erbt diese Lage aus einem harten Grund: auf
//! `wasm32-unknown-unknown` gibt es fuer `std::time::SystemTime::now()` keinen
//! Wirt. [`EnrollmentRequestContextV1`] traegt Herkunft und Zeitpunkt herein.

use core::hint::black_box;

use ea_crypto::{CanonicalPublicCoseKey, CryptoError, HpkeRecipientPrivateKey, SecretBytes};
use ea_sync_protocol::{
    EndpointV1, MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1, MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1,
    REQUEST_ID_HEADER_V1, RequestIdV1, RequestParts, RequestSigner, STRUCTURED_MEDIA_TYPE_V1,
    SignatureParametersV1, SyncProtocolError, VaultBlobRetrievalRequestV1,
    VaultBlobRetrievalResponseV1, VaultBlobUploadV1, WebauthnCredentialRegistrationV1, body_digest,
    content_digest_header, organization_tag,
};
use ea_trust::TrustAnchorV1;
use ea_types::{Hash32, KeyThumbprint, OrganizationId, SubjectId};
use zeroize::Zeroize;

use crate::blob_store::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
use crate::enrollment_endpoints::{
    EnrollmentEndpointError, EnrollmentEndpoints, EnrollmentRequestV1,
};
use crate::envelope::{AuthenticatorPrfV1, VaultEnvelopeV1};
use crate::vault::{ReaderVault, ReaderVaultError, SealedVaultV1, UnlockedVault, VaultContentsV1};

/// Das FESTE App-Salt der PRF-Auswertung (`web-reader-design.md` §6.2).
///
/// Fest und nicht je Geraet zufaellig: §6.4.1 verlangt, dass synchronisierte
/// Passkeys bei GLEICHEM Salt ueber die Geraete des Nutzers dieselbe Ausgabe
/// liefern. Ein geraeteabhaengiges Salt machte genau den Fall aus §6.4 — Blob
/// beziehen, Authenticator bestaetigen, weiterarbeiten — unmoeglich.
pub const VAULT_PRF_SALT_V1: [u8; 32] = *b"EINSATZARCHIV-READER-VAULT-PRF-1";

/// Die zwingende Untergrenze aus `web-reader-design.md` §6.3.
pub const MIN_ENROLLED_AUTHENTICATORS_V1: usize = 2;

/// Die Gueltigkeitsspanne der drei signierten Anfragen, in Sekunden.
///
/// Sie liegt UNTER `ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1` (300)
/// und wird nicht daraus abgeleitet: der Server nennt seine Obergrenze, der
/// Klient waehlt darunter.
pub const ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1: i64 = 60;

/// Die Unterschreitung steht als Zusicherung da und nicht als Absichtserklaerung
/// im Fliesstext: ein spaeter angehobener Klientenwert faellt beim UEBERSETZEN
/// und nicht erst an einem Server, der die Anfrage abweist.
const _: () = assert!(
    ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1 < ea_sync_protocol::MAX_SIGNATURE_WINDOW_SECONDS_V1
);

/// Der Schluessel, unter dem der versiegelte Tresor lokal liegt.
pub const READER_VAULT_BLOB_KEY_V1: &str = "vault/reader-vault-v1";

/// Das Transportprofil eines Credentials, so wie der Browser es meldet.
///
/// ZWEI Werte und nicht die volle `AuthenticatorTransport`-Liste: die einzige
/// Unterscheidung, die diese Flaeche trifft, ist „Cross-Device-Flow oder
/// nicht". Eine getreue Nachbildung der Browserliste legte vier weitere Werte
/// an, ueber die niemand entscheidet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorTransportProfileV1 {
    /// `internal`, `usb`, `nfc`, `ble` — ein Authenticator an diesem Geraet.
    ClientDevice,
    /// `hybrid`/`cable` — der QR-Flow, in Safari ohne PRF-Ausgabe (§6.4.1).
    CrossDevice,
}

/// Der Zustand des Vertrauensstandes DIESES Geraets.
///
/// Nicht zu verwechseln mit einem Fehlerfall: ein Geraet ohne lokalen Tresor
/// ist kein Fehlschlag, sondern die Bedingung, unter der §4.3 den
/// Fingerprint-Vergleich erzwingt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceTrustStateV1 {
    /// Der Bytespeicher traegt noch keinen versiegelten Tresor.
    NoPinnedAnchor,
    /// Ein versiegelter Tresor liegt lokal — mit ihm der gepinnte Anker.
    Pinned,
}

/// Der Fehlschlag des Enrollments.
///
/// Die acht eigenen Varianten tragen ihren Code ausgeschrieben, die fuenf
/// durchreichenden geben den Code IHRER QUELLE weiter und erfinden keinen
/// zweiten Namen fuer einen fremden Befund — dieselbe Regel wie bei
/// [`ReaderVaultError`].
#[derive(Debug)]
pub enum EnrollmentError {
    /// Weniger als [`MIN_ENROLLED_AUTHENTICATORS_V1`] beim Abschluss.
    SingleAuthenticator,
    /// Dieses Geraet traegt bereits einen versiegelten Reader-Tresor.
    ///
    /// Ein FRISCHES Enrollment ist nicht der Weg fuer ein Geraet, das schon
    /// einen hat: es zoege zwei neue Schluesselpaare, zwei neue Passkeys und
    /// einen neuen Tresor — und die zweite Zeremonie ersetzte auf demselben
    /// Plattform-Authenticator den Passkey des VORHANDENEN, bereits
    /// hochgeladenen Tresors. Der Weg fuer diesen Fall ist §6.4 und heisst
    /// [`recover_and_unlock_vault`].
    VaultAlreadyOnDevice,
    /// Dieselbe `credentialId` ein zweites Mal.
    DuplicateAuthenticator,
    /// Die `credentialId` liegt ausserhalb der Protokollgrenzen.
    CredentialIdLength,
    /// Der Cross-Device-QR-Flow ist kein Entsperrpfad.
    TransportRefused,
    /// Die eingegebene Referenz ist keine 32-Byte-Hexzeichenkette.
    FingerprintEncoding,
    /// Die eingegebene Referenz weicht vom angezeigten Wert ab.
    FingerprintMismatch,
    /// Kein abgerufenes Chiffrat traegt einen Envelope fuer diesen
    /// Authenticator.
    NoVaultForCredential,
    /// Der Endpunktport hat abgewiesen.
    Endpoint(EnrollmentEndpointError),
    /// Der Bytespeicher hat abgewiesen.
    Blob(ReaderBlobError),
    /// Der Tresor hat abgewiesen.
    Vault(ReaderVaultError),
    /// `ea-crypto` hat abgewiesen.
    Crypto(CryptoError),
    /// Ein Protokollrahmen hat abgewiesen.
    Protocol(SyncProtocolError),
}

impl EnrollmentError {
    /// Der stabile Code des Fehlschlags — dieselbe Regel wie bei
    /// [`ReaderVaultError::code`]: Zusicherungen stehen gegen ihn und nie gegen
    /// eine Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SingleAuthenticator => "EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR",
            Self::VaultAlreadyOnDevice => "EA-READER-ENROLLMENT-VAULT-PRESENT",
            Self::DuplicateAuthenticator => "EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR",
            Self::CredentialIdLength => "EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH",
            Self::TransportRefused => "EA-READER-ENROLLMENT-TRANSPORT-REFUSED",
            Self::FingerprintEncoding => "EA-READER-ENROLLMENT-FINGERPRINT-ENCODING",
            Self::FingerprintMismatch => "EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH",
            Self::NoVaultForCredential => "EA-READER-ENROLLMENT-NO-VAULT",
            Self::Endpoint(error) => error.code(),
            Self::Blob(error) => error.code(),
            Self::Vault(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Protocol(error) => error.code(),
        }
    }
}

impl From<EnrollmentEndpointError> for EnrollmentError {
    fn from(error: EnrollmentEndpointError) -> Self {
        Self::Endpoint(error)
    }
}

impl From<ReaderBlobError> for EnrollmentError {
    fn from(error: ReaderBlobError) -> Self {
        Self::Blob(error)
    }
}

impl From<ReaderVaultError> for EnrollmentError {
    fn from(error: ReaderVaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<CryptoError> for EnrollmentError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<SyncProtocolError> for EnrollmentError {
    fn from(error: SyncProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl core::fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EnrollmentError {}

/// Ein Authenticator, so wie der Browser ihn nach der WebAuthn-Zeremonie
/// meldet.
///
/// Vier Bestandteile, und der vierte ist ein Geheimnis: der Typ traegt deshalb
/// weder `Debug` noch `Clone` — dieselbe Regel, die
/// [`AuthenticatorPrfV1`] in `crates/ea-reader/src/envelope.rs` in seinem
/// eigenen Doc-Kommentar bereits ausschreibt.
pub struct AttestedAuthenticatorV1 {
    credential_id: Vec<u8>,
    credential_public_cose_key: Vec<u8>,
    transport_profile: AuthenticatorTransportProfileV1,
    prf_output: SecretBytes<32>,
}

impl AttestedAuthenticatorV1 {
    /// Alle vier Bestandteile BESITZEND.
    #[must_use]
    pub const fn new(
        credential_id: Vec<u8>,
        credential_public_cose_key: Vec<u8>,
        transport_profile: AuthenticatorTransportProfileV1,
        prf_output: SecretBytes<32>,
    ) -> Self {
        Self {
            credential_id,
            credential_public_cose_key,
            transport_profile,
            prf_output,
        }
    }
}

/// Ein AUFGENOMMENER Authenticator: was von [`AttestedAuthenticatorV1`] nach
/// den vier Pruefungen uebrig bleibt.
///
/// Das Transportprofil steht hier nicht mehr — es ist bei der Aufnahme
/// entschieden worden, und ein mitgefuehrter Wert liesse offen, ob spaeter noch
/// jemand darueber entscheidet. Kein `Debug` und kein `Clone`, aus demselben
/// Grund wie bei [`AttestedAuthenticatorV1`].
pub struct AuthenticatorRecordV1 {
    credential_id: Vec<u8>,
    credential_public_cose_key: Vec<u8>,
    prf_output: SecretBytes<32>,
}

/// Die ANGEZEIGTEN Werte des Fingerprint-Vergleichs.
///
/// Typisiert und nicht als Zeichenkette gehalten: `KeyThumbprint` und `Hash32`
/// sind beide `Copy` und bieten `as_bytes()`. Die zwei Hex-Zugriffe daneben
/// bauen bei jedem Aufruf eine `String` — ein `String`-FELD waere eine zweite
/// Quelle derselben Wahrheit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnrollmentFingerprintsV1 {
    key_fingerprint: KeyThumbprint,
    bundle_fingerprint: Hash32,
}

impl EnrollmentFingerprintsV1 {
    /// Der Abdruck des KEM-Schluessels dieses Readers.
    #[must_use]
    pub const fn key_fingerprint(&self) -> KeyThumbprint {
        self.key_fingerprint
    }

    /// Der Fingerprint des geladenen Buendels.
    #[must_use]
    pub const fn bundle_fingerprint(&self) -> Hash32 {
        self.bundle_fingerprint
    }

    /// Die Anzeigeform des Schluessel-Fingerprints: 64 Hexziffern, UNGRUPPIERT.
    ///
    /// Ohne Trennzeichen, und das ist keine Geschmacksfrage: `hex::decode`
    /// weist jedes Leer- und Bindezeichen ab, eine gruppierte Anzeige liefe
    /// also beim Abtippen in `EA-READER-ENROLLMENT-FINGERPRINT-ENCODING` statt
    /// in eine Uebereinstimmung.
    #[must_use]
    pub fn key_fingerprint_hex(&self) -> String {
        hex::encode(self.key_fingerprint.as_bytes())
    }

    /// Die Anzeigeform des Bundle-Fingerprints, ebenfalls ungruppiert.
    #[must_use]
    pub fn bundle_fingerprint_hex(&self) -> String {
        hex::encode(self.bundle_fingerprint.as_bytes())
    }
}

/// Konstruierbar AUSSCHLIESSLICH in
/// [`ReaderEnrollment::confirm_fingerprints`], und dort nur nach einem
/// konstantzeitigen Vergleich BEIDER Werte. Kein `Default`, kein `Clone`, kein
/// `Debug`, und ausdruecklich kein inhaerenter `impl`-Block: der koennte eine
/// zweite Konstruktionsstelle hinter einer assoziierten Funktion verstecken.
pub struct FingerprintConfirmationV1 {
    confirmed_key: KeyThumbprint,
    confirmed_bundle: Hash32,
}

/// Herkunft und Zeitpunkt der drei signierten Anfragen.
///
/// Die Zeit kommt von aussen, weil `wasm32-unknown-unknown` keinen Wirt fuer
/// `SystemTime::now()` hat — das ist eine Unmoeglichkeit. Die Herkunft des
/// Sync-Servers kommt von aussen, weil `ea-reader` keine Konfiguration liest,
/// und das ist eine ENTSCHEIDUNG: die Bruecke waehlt damit, an welche Autoritaet
/// die RFC-9421-Signatur bindet. Das bleibt innerhalb von §9 — die Herkunft ist
/// eine Betriebskonfiguration und kein kryptografischer Schritt —, aber es ist
/// der einzige Wert dieser Flaeche, den die Bruecke BESTIMMT statt zu TRAGEN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentRequestContextV1 {
    authority: String,
    created_unix_seconds: i64,
}

impl EnrollmentRequestContextV1 {
    /// Herkunft und Ausstellungszeitpunkt, beide von aussen.
    #[must_use]
    pub const fn new(authority: String, created_unix_seconds: i64) -> Self {
        Self {
            authority,
            created_unix_seconds,
        }
    }
}

/// Ein laufendes Enrollment: die im Browser erzeugten Schluessel und die bisher
/// aufgenommenen Authenticators.
///
/// WEDER Lebenszeit- NOCH Typparameter, weil Bytespeicher und Endpunktport erst
/// an [`ReaderEnrollment::finish`] uebergeben werden — dieselbe Anordnung wie
/// `ReaderObjectCache::put_exact_object`, die den Speicher je Aufruf nimmt und
/// nicht festhaelt. Der Zustand liegt in der Bruecke in einem `thread_local!`,
/// und ein festgehaltener Speicher band ihn an einen Faden.
pub struct ReaderEnrollment {
    organization_id: OrganizationId,
    subject_id: SubjectId,
    pinned_anchor: TrustAnchorV1,
    bundle_fingerprint: Hash32,
    kem_private_key: SecretBytes<32>,
    audit_private_key: SecretBytes<32>,
    kem_key_thumbprint: KeyThumbprint,
    authenticators: Vec<AuthenticatorRecordV1>,
}

impl ReaderEnrollment {
    /// Erzeugt die beiden Schluesselpaare dieses Readers im Browser — aber nur
    /// auf einem Geraet, das noch KEINEN versiegelten Tresor traegt.
    ///
    /// # Warum der Bytespeicher der ERSTE Parameter ist
    ///
    /// Weil die Weigerung VOR jeder Schluesselerzeugung faellt. `/enrollment`
    /// ist eine gewoehnliche, anfahrbare Route, und die Flaeche ruft `begin`
    /// bei JEDER Montage. Ein zweiter Besuch auf einem Geraet, dessen
    /// Enrollment laengst abgeschlossen ist, faenge sonst ein frisches
    /// Enrollment an, dessen Satz aufgenommener Kennungen LEER ist — und ein
    /// einziger Klick auf „Authenticator registrieren" liefe damit ohne
    /// `excludeCredentials` gegen denselben Plattform-Authenticator und
    /// ERSETZTE den Passkey des bereits versiegelten und hochgeladenen
    /// Tresors. Das ist derselbe Defekt wie der, den `excludeCredentials`
    /// INNERHALB eines Enrollments abwendet, nur schlimmer: dort steht ein
    /// halb gebauter Tresor auf dem Spiel, hier ein lebender.
    ///
    /// Die Antwort von §6.4 auf ein Geraet MIT Tresor ist nicht ein zweites
    /// Enrollment, sondern [`recover_and_unlock_vault`]; ein
    /// Wieder-Enrollment und der historische Re-grant liegen ausdruecklich
    /// ausserhalb dieser Aufgabe. Die Weigerung zieht den Umfang deshalb nicht
    /// enger — sie setzt die Grenze durch, die ohnehin gilt.
    ///
    /// Der Zustand wird ueber [`ReaderEnrollment::device_state`] gelesen, also
    /// ueber genau denselben Weg, den das Fingerprint-Gate aus §4.3 schon
    /// nimmt; eine zweite Lesart desselben Bytespeichers entsteht hier nicht.
    ///
    /// # Errors
    /// `EA-READER-ENROLLMENT-VAULT-PRESENT`, wenn unter
    /// [`READER_VAULT_BLOB_KEY_V1`] lokal schon ein Tresor liegt;
    /// `EA-LOCAL-CRYPTO-RNG` ueber [`EnrollmentError::Vault`], wenn der Wirt
    /// keine Entropie liefert, und `EA-CRYPTO-INVALID-PUBLIC-KEY` ueber
    /// [`EnrollmentError::Crypto`], wenn der gezogene KEM-Punkt keinen
    /// Thumbprint hergibt — der wird HIER einmal gerechnet und festgehalten,
    /// nicht bei jedem [`ReaderEnrollment::fingerprints`]. Daneben die
    /// durchgereichten Codes des Bytespeichers.
    pub fn begin(
        store: &dyn ReaderBlobStore,
        organization_id: OrganizationId,
        subject_id: SubjectId,
        pinned_anchor: TrustAnchorV1,
        bundle_fingerprint: Hash32,
    ) -> Result<Self, EnrollmentError> {
        // FAIL CLOSED, und zwar vor dem ersten Byte Entropie: ein abgewiesener
        // Anlauf zieht keine Schluessel, schreibt nichts und beruehrt keinen
        // Endpunkt.
        if matches!(Self::device_state(store)?, DeviceTrustStateV1::Pinned) {
            return Err(EnrollmentError::VaultAlreadyOnDevice);
        }
        let mut entropy = random_bytes::<64>()?;
        let mut kem_bytes = [0_u8; 32];
        let mut audit_bytes = [0_u8; 32];
        kem_bytes.copy_from_slice(&entropy[..32]);
        audit_bytes.copy_from_slice(&entropy[32..]);
        entropy.zeroize();

        let kem_private_key = SecretBytes::new(kem_bytes);
        kem_bytes.zeroize();
        let audit_private_key = SecretBytes::new(audit_bytes);
        audit_bytes.zeroize();

        // `SecretBytes` hat KEIN `Clone`, und `HpkeRecipientPrivateKey::from_bytes`
        // KONSUMIERT sein Geheimnis. `with_exposed` ist der einzige Weg an die
        // Bytes, den `ea-crypto` anbietet, und er haelt den Zeroize-Vertrag: die
        // Kopie ist selbst wieder ein `SecretBytes` und loescht sich beim Fallen.
        let recipient = HpkeRecipientPrivateKey::from_bytes(
            kem_private_key.with_exposed(|bytes| SecretBytes::new(*bytes)),
        )?;
        let kem_key_thumbprint =
            CanonicalPublicCoseKey::x25519(*recipient.public_key().as_bytes())?.thumbprint();

        Ok(Self {
            organization_id,
            subject_id,
            pinned_anchor,
            bundle_fingerprint,
            kem_private_key,
            audit_private_key,
            kem_key_thumbprint,
            authenticators: Vec::new(),
        })
    }

    /// Nimmt einen Authenticator auf — oder weist ihn ab.
    ///
    /// VIER Pruefungen laufen hier und nirgends sonst: die Laenge der
    /// `credentialId` gegen die Protokollgrenzen, das Transportprofil, die
    /// kanonische COSE-Karte des oeffentlichen Schluessels (derselbe
    /// `Ed25519`-Arm, den `WebauthnCredentialRegistrationV1::new` beim Bauen der
    /// Anfrage ein zweites Mal verlangt — ein hier akzeptierter Schluessel
    /// scheitert dort nie) und die Doppelung derselben `credentialId`. Der
    /// Envelope entsteht NICHT hier, sondern erst in
    /// [`ReaderEnrollment::finish`].
    ///
    /// Eine FUENFTE Absicherung gehoert dazu, und sie steht bewusst nicht hier:
    /// keine der vier sieht GERAETEIDENTITAET, und die Doppelungspruefung
    /// gerade nicht. Ein zweiter Passkey auf DEMSELBEN Geraet ersetzt den
    /// ersten und traegt dabei eine frische Kennung — er kommt hier also als
    /// vollwertiger zweiter Authenticator an und wird aufgenommen. Die einzige
    /// Instanz, die das abwenden kann, ist der Browser VOR der Zeremonie; wie,
    /// steht bei [`ReaderEnrollment::registered_credential_ids`].
    ///
    /// # Errors
    /// `EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH`,
    /// `EA-READER-ENROLLMENT-TRANSPORT-REFUSED`,
    /// `EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR` und
    /// `EA-CRYPTO-UNSUPPORTED-SUITE` fuer eine Karte, die kein kanonischer
    /// Ed25519-Punkt ist.
    pub fn register_authenticator(
        &mut self,
        attested: AttestedAuthenticatorV1,
    ) -> Result<&AuthenticatorRecordV1, EnrollmentError> {
        if attested.credential_id.len() < MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
            || attested.credential_id.len() > MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
        {
            return Err(EnrollmentError::CredentialIdLength);
        }
        if matches!(
            attested.transport_profile,
            AuthenticatorTransportProfileV1::CrossDevice
        ) {
            return Err(EnrollmentError::TransportRefused);
        }
        if !matches!(
            CanonicalPublicCoseKey::from_deterministic_cbor(&attested.credential_public_cose_key),
            Ok(CanonicalPublicCoseKey::Ed25519(_))
        ) {
            return Err(EnrollmentError::Crypto(CryptoError::UnsupportedSuite));
        }
        // Zwei Envelopes DESSELBEN Authenticators taeuschten die Zwei aus §6.3
        // vor, ohne sie zu erfuellen.
        if self
            .authenticators
            .iter()
            .any(|record| record.credential_id == attested.credential_id)
        {
            return Err(EnrollmentError::DuplicateAuthenticator);
        }
        self.authenticators.push(AuthenticatorRecordV1 {
            credential_id: attested.credential_id,
            credential_public_cose_key: attested.credential_public_cose_key,
            prf_output: attested.prf_output,
        });
        Ok(self
            .authenticators
            .last()
            .expect("der eben eingefuegte Eintrag liegt am Ende"))
    }

    /// Wie viele Authenticators bisher AUFGENOMMEN sind.
    #[must_use]
    pub fn registered_authenticator_count(&self) -> usize {
        self.authenticators.len()
    }

    /// Die `credentialId`s der bisher AUFGENOMMENEN Authenticators, in der
    /// Reihenfolge ihrer Aufnahme.
    ///
    /// # Die FUENFTE Absicherung von §6.3 — und die einzige, die ueberhaupt Geraeteidentitaet sehen kann
    ///
    /// Die vier Pruefungen in [`ReaderEnrollment::register_authenticator`]
    /// laufen NACH der Zeremonie und koennen den Schaden dann nicht mehr
    /// abwenden. Der Grund ist gemessen und nicht gefolgert: beide Zeremonien
    /// tragen dieselbe `rp.id` und dasselbe `user.id`, und ein
    /// `authenticatorMakeCredential` mit `rk=true` auf ein bereits vorhandenes
    /// Paar (rpId, userHandle) ERSETZT das auffindbare Credential. Der zweite
    /// Passkey bekommt dabei eine FRISCHE `credentialId` — die
    /// Doppelungspruefung de-dupliziert auf der Kennung und sieht deshalb
    /// nichts. [`AttestedAuthenticatorV1`] traegt weder AAGUID noch ein anderes
    /// geraeteunterscheidendes Feld; `ea-reader` sieht deshalb HEUTE nicht,
    /// dass beide Envelopes auf demselben Geraet liegen. Das Ergebnis waere
    /// zwei versiegelte Envelopes, von denen genau EINER noch aufgeht — das
    /// CredRandom des ersten stirbt mit dem ersetzten Credential, und die
    /// Oberflaeche meldete trotzdem zwei.
    ///
    /// **„Heute" und nicht „ueberhaupt", und die Unterscheidung ist keine
    /// Wortklauberei.** Das AAGUID ist unter `attestation: "none"` tatsaechlich
    /// nicht zu haben — der Client nullt es. Die Flags in `authData` ueberleben
    /// das dagegen, und darunter stehen BE (Backup Eligibility) und BS (Backup
    /// State): ein synchronisierter Passkey traegt BE gesetzt. `ea-reader`
    /// bekommt diese Bytes heute nicht — [`AttestedAuthenticatorV1`] fuehrt
    /// kein Flagfeld —, aber `attested_credential` in
    /// `crates/ea-reader-wasm/src/webauthn.rs` LIEST genau dieses Byte bereits,
    /// um Bit 6 zu pruefen, und verwirft den Rest. Eine Regel wie „hoechstens
    /// ein backup-faehiges Credential" waere also BAUBAR und fasste sogar den
    /// Fall, den `excludeCredentials` prinzipiell nicht sieht: zwei
    /// synchronisierte Passkeys desselben Anbieters in zwei getrennten
    /// Credential-Speichern. Sie steht hier NICHT, und das ist eine bewusste
    /// Auslassung: ob zwei synchronisierte Passkeys eine gemeinsame
    /// Ausfalldomaene oder der gedachte Normalfall sind, entscheidet
    /// `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`
    /// und nicht diese Datei. Der offene Punkt ist im Plan von Stufe 4 als
    /// solcher vermerkt.
    ///
    /// Verhindern kann das nur der Browser, und zwar VOR der Zeremonie: die
    /// Kennungen von hier gehen als `excludeCredentials` in
    /// `navigator.credentials.create`, und ein Authenticator, der eine davon
    /// schon traegt, weist die Zeremonie mit `InvalidStateError` ab. GEMESSEN
    /// an Chromiums virtuellem Authenticator: OHNE die Liste erzeugt die zweite
    /// Zeremonie klaglos ein Credential mit neuer Kennung, und danach liegt auf
    /// dem Geraet GENAU EINES; MIT der Liste faellt sie mit
    /// `InvalidStateError`, und es bleibt bei dem ersten. Der Zeuge ist
    /// `a second ceremony on the same authenticator is refused instead of
    /// silently replacing the first passkey` in
    /// `apps/web/tests/e2e/enrollment.spec.ts`.
    ///
    /// Die Liste kommt deshalb AUS RUST heraus und wird nicht in TypeScript
    /// gefuehrt: `web-reader-design.md` §9 laesst dort keine
    /// Sicherheitsentscheidung zu, und ein in der Oberflaeche gefuehrter Satz
    /// koennte leer sein, wo dieses Enrollment zwei Eintraege haelt.
    ///
    /// # Die GRENZE des Ausschlusses, benannt statt geglaettet
    ///
    /// `excludeCredentials` wird JE AUTHENTICATOR durchgesetzt: der Client
    /// legt die Liste jedem befragten Authenticator vor, und der antwortet mit
    /// `CTAP2_ERR_CREDENTIAL_EXCLUDED`, wenn er eine der Kennungen SELBST
    /// haelt. Ueber zwei getrennte Credential-Speicher auf EINEM physischen
    /// Rechner sagt das nichts: die Passkeys eines Chrome-Profils, die von
    /// Firefox, die einer Safari-/iCloud-Schluesselbundkette und ein
    /// Sicherheitsschluessel, der den Steckplatz nie verlaesst, sind
    /// wechselseitig unsichtbar. Beide Zeremonien gelingen, beide Envelopes
    /// landen auf demselben Geraet, und geht dieses Geraet verloren, ist der
    /// Tresor verloren — genau der Ausgang, den §6.3 abwenden will. Dieselbe
    /// Klasse hat eine mildere Auspraegung: ein Passkey-Verwalter, der statt
    /// still zu ersetzen NACHFRAGT, richtet keinen Schaden an, und beide
    /// Envelopes liegen trotzdem auf einem Geraet. Der Ausschluss verhindert
    /// die ZERSTOERUNG des ersten Passkeys, nicht die KONZENTRATION beider
    /// Envelopes auf einer Maschine. Diese Klasse ist mit dieser Aufgabe NICHT
    /// geschlossen; sie steht als benannte Grenze im Stufe-4-Plan.
    #[must_use]
    pub fn registered_credential_ids(&self) -> Vec<&[u8]> {
        self.authenticators
            .iter()
            .map(|record| record.credential_id.as_slice())
            .collect()
    }

    /// Gibt den in [`ReaderEnrollment::begin`] GERECHNETEN Thumbprint und den
    /// dort uebergebenen `Hash32` heraus und rechnet selbst nichts — deshalb
    /// `-> …V1` und kein `Result`.
    #[must_use]
    pub const fn fingerprints(&self) -> EnrollmentFingerprintsV1 {
        EnrollmentFingerprintsV1 {
            key_fingerprint: self.kem_key_thumbprint,
            bundle_fingerprint: self.bundle_fingerprint,
        }
    }

    /// Vergleicht die ABGETIPPTE Referenz gegen die ANGEZEIGTEN Werte.
    ///
    /// Zwei `&str`, weil das Argument aus einer TASTATUR kommt und nicht aus
    /// dem Programm: die Referenz ist unabhaengig verteilt, ein Mensch tippt
    /// sie ab. Der Vergleich laeuft ueber die DEKODIERTEN Werte und nicht ueber
    /// die Zeichenketten, damit die Gross-/Kleinschreibung der Anzeige keine
    /// falsche Abweichung erzeugt.
    ///
    /// # Errors
    /// `EA-READER-ENROLLMENT-FINGERPRINT-ENCODING` fuer alles, was keine
    /// 32-Byte-Hexzeichenkette ist, und
    /// `EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH` fuer jede Abweichung. Die
    /// beiden Codes sind ausdruecklich verschieden: ein Tippfehler in der Form
    /// ist etwas anderes als ein untergeschobener Wert.
    pub fn confirm_fingerprints(
        &self,
        expected_key: &str,
        expected_bundle: &str,
    ) -> Result<FingerprintConfirmationV1, EnrollmentError> {
        let expected_key = decode_fingerprint(expected_key)?;
        let expected_bundle = decode_fingerprint(expected_bundle)?;
        // `&` und nicht `&&`: BEIDE Vergleiche laufen, auch wenn der erste
        // schon abweicht. Ein Kurzschluss waere genau das Orakel, gegen das
        // `fingerprints_match` gebaut ist.
        let matching = fingerprints_match(&expected_key, self.kem_key_thumbprint.as_bytes())
            & fingerprints_match(&expected_bundle, self.bundle_fingerprint.as_bytes());
        if !matching {
            return Err(EnrollmentError::FingerprintMismatch);
        }
        Ok(FingerprintConfirmationV1 {
            confirmed_key: self.kem_key_thumbprint,
            confirmed_bundle: self.bundle_fingerprint,
        })
    }

    /// Schliesst das Enrollment ab: drei Endpunktaufrufe, DANN der lokale
    /// Schreibvorgang.
    ///
    /// Die Reihenfolge ist fail-closed und keine Bequemlichkeit: je
    /// Authenticator ein `POST /v1/webauthn-credentials`, dann GENAU EIN
    /// `PUT /v1/vault-blobs`, und erst danach `store.put`. Ein lokal
    /// geschriebener Tresor ohne serverseitige Kopie ueberstuende kein
    /// geraeumtes Browserprofil, und §6.4 verlangt genau, dass dieser Fall ohne
    /// Administrationsvorgang geloest wird. Bricht ein Aufruf ab, bleibt gar
    /// nichts geschrieben.
    ///
    /// # EIN Upload und nicht einer je Envelope
    ///
    /// Das ist eine BENANNTE ABWEICHUNG von der Wortwahl in §6.2 („Es entsteht
    /// ein Wrapped-Blob je Authenticator") und §6.4. Der Grund ist
    /// sicherheitlich und betrieblich zugleich: `SealedVaultV1` ist EIN Objekt,
    /// das Koerperchiffrat, Nonce und ALLE Envelopes traegt;
    /// `MAX_VAULT_BLOBS_PER_SUBJECT_V1` zaehlt Tresore je Subjekt und nicht
    /// Entsperrwege, und ein Upload je Envelope verriete dem Server nebenbei die
    /// Zahl der Authenticators.
    ///
    /// # Errors
    /// `EA-READER-ENROLLMENT-FINGERPRINT-MISMATCH`, wenn die Bestaetigung zu
    /// einem ANDEREN Enrollment gehoert; `EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR`
    /// unterhalb von [`MIN_ENROLLED_AUTHENTICATORS_V1`]; daneben die
    /// durchgereichten Codes von Protokollrahmen, Endpunktport, Tresor und
    /// Bytespeicher.
    pub fn finish(
        self,
        confirmation: FingerprintConfirmationV1,
        context: EnrollmentRequestContextV1,
        endpoints: &mut dyn EnrollmentEndpoints,
        store: &mut dyn ReaderBlobStore,
    ) -> Result<EnrolledReaderV1, EnrollmentError> {
        // Die Bestaetigung wird gegen DIESES Enrollment gestellt. Ohne diese
        // Probe oeffnete eine Bestaetigung aus einem zweiten, parallel
        // gefuehrten Enrollment dieses hier — und der Typ allein saehe das
        // nicht.
        let belongs_here = fingerprints_match(
            confirmation.confirmed_key.as_bytes(),
            self.kem_key_thumbprint.as_bytes(),
        ) & fingerprints_match(
            confirmation.confirmed_bundle.as_bytes(),
            self.bundle_fingerprint.as_bytes(),
        );
        if !belongs_here {
            return Err(EnrollmentError::FingerprintMismatch);
        }
        if self.authenticators.len() < MIN_ENROLLED_AUTHENTICATORS_V1 {
            return Err(EnrollmentError::SingleAuthenticator);
        }

        // Der Signierer bekommt eine KOPIE; das Original geht unten an
        // `VaultContentsV1::new`, das es BESITZEND nimmt.
        let signer = RequestSigner::from_secret(
            self.audit_private_key
                .with_exposed(|bytes| SecretBytes::new(*bytes)),
        );
        let tag = organization_tag(self.organization_id);

        for record in &self.authenticators {
            let registration = WebauthnCredentialRegistrationV1::new(
                self.subject_id,
                record.credential_id.clone(),
                record.credential_public_cose_key.clone(),
            )?;
            let request = signed_request(
                &signer,
                &context,
                &tag,
                EndpointV1::WebauthnCredentials,
                registration.exact_bytes().to_vec(),
            )?;
            endpoints.send(&request)?;
        }

        let authenticators: Vec<AuthenticatorPrfV1> = self
            .authenticators
            .iter()
            .map(|record| {
                AuthenticatorPrfV1::new(
                    record.credential_id.clone(),
                    record
                        .prf_output
                        .with_exposed(|bytes| SecretBytes::new(*bytes)),
                )
            })
            .collect();
        let contents = VaultContentsV1::new(
            self.kem_private_key,
            self.audit_private_key,
            self.pinned_anchor.exact_bytes().to_vec(),
            None,
        );
        let sealed = ReaderVault::seal(contents, &authenticators)?;
        let sealed_bytes = sealed.to_deterministic_cbor();

        let upload = VaultBlobUploadV1::new(self.subject_id, sealed_bytes.clone())?;
        let request = signed_request(
            &signer,
            &context,
            &tag,
            EndpointV1::VaultBlobs,
            upload.exact_bytes().to_vec(),
        )?;
        endpoints.send(&request)?;

        let blob_key = reader_vault_blob_key()?;
        store.put(&blob_key, &sealed_bytes)?;
        Ok(EnrolledReaderV1 { sealed, blob_key })
    }

    /// Der Vertrauensstand DIESES Geraets, aus seinem Bytespeicher gelesen.
    ///
    /// # Errors
    /// Die durchgereichten Codes des Bytespeichers.
    pub fn device_state(
        store: &dyn ReaderBlobStore,
    ) -> Result<DeviceTrustStateV1, EnrollmentError> {
        let blob_key = reader_vault_blob_key()?;
        if store.get(&blob_key)?.is_some() {
            Ok(DeviceTrustStateV1::Pinned)
        } else {
            Ok(DeviceTrustStateV1::NoPinnedAnchor)
        }
    }

    /// Ob §4.3 den Fingerprint-Vergleich fuer diesen Zustand ERZWINGT.
    #[must_use]
    pub const fn fingerprint_gate_required(state: &DeviceTrustStateV1) -> bool {
        matches!(state, DeviceTrustStateV1::NoPinnedAnchor)
    }
}

/// Der abgeschlossene Reader: sein versiegelter Tresor und seine lokale
/// Adresse.
///
/// Kein `Debug` — nicht weil der Typ ein Geheimnis truege, sondern weil kein
/// Zeuge eines braucht und ein abgeleitetes `Debug` auf einem Tresortyp eine
/// Einladung ist.
pub struct EnrolledReaderV1 {
    sealed: SealedVaultV1,
    blob_key: ReaderBlobKey,
}

impl EnrolledReaderV1 {
    /// Die Entsperrwege dieses Tresors, einer je aufgenommenem Authenticator.
    #[must_use]
    pub fn envelopes(&self) -> &[VaultEnvelopeV1] {
        self.sealed.envelopes()
    }

    /// Oeffnet den Tresor ueber GENAU EINEN Authenticator.
    ///
    /// # Errors
    /// `EA-READER-VAULT-NO-ENVELOPE`, wenn kein Envelope diese `credentialId`
    /// traegt; daneben die durchgereichten Codes des Tresors.
    pub fn unlock_with(
        &self,
        authenticator: &AuthenticatorPrfV1,
    ) -> Result<UnlockedVault, EnrollmentError> {
        Ok(ReaderVault::unlock(&self.sealed, authenticator)?)
    }

    /// Derselbe Reader OHNE den Entsperrweg dieses Authenticators.
    ///
    /// Reicht auf `SealedVaultV1::without_credential` durch — und das gibt ein
    /// `Result`, weil das Entfernen des LETZTEN Entsperrweges
    /// `EA-READER-VAULT-NO-AUTHENTICATOR` ist.
    ///
    /// # Errors
    /// Die durchgereichten Codes des Tresors.
    pub fn without_authenticator(&self, credential_id: Vec<u8>) -> Result<Self, EnrollmentError> {
        Ok(Self {
            sealed: self.sealed.without_credential(credential_id)?,
            blob_key: self.blob_key.clone(),
        })
    }

    /// Die lokale Adresse des versiegelten Tresors.
    #[must_use]
    pub const fn blob_key(&self) -> &ReaderBlobKey {
        &self.blob_key
    }
}

/// Holt den versiegelten Tresor auf einem Geraet OHNE lokalen Vault zurueck und
/// oeffnet ihn mit dem vorgelegten Authenticator.
///
/// Der Name sagt beides, weil die Funktion beides tut: sie schickt den EINEN
/// signaturfreien Abruf ueber den Port und gibt einen [`UnlockedVault`] heraus.
/// Der Aufruf traegt als einziger dieser Flaeche KEINE RFC-9421-Signatur, weil
/// der Signaturschluessel im noch verschlossenen Tresor liegt (§6.4.1). Alleinige
/// Autoritaet ist die WebAuthn-Assertion im vorgelegten Rahmen; sie wird HIER
/// nicht geprueft, sie ist die Autoritaet des SERVERS.
///
/// # Die Challenge kommt NICHT aus dieser Flaeche
///
/// §11 Punkt 7 der Spezifikation zaehlt sie als zweite Signaturausnahme neben
/// dem rate-limitierten Challenge-Endpunkt. Wer die Challenge holt und die
/// Assertion darueber zieht, ist der Browser; diese Funktion bekommt eine
/// FERTIGE `VaultBlobRetrievalRequestV1` samt Challenge, `authenticatorData`
/// und Signatur herein. Das ist eine benannte Luecke und kein Versehen — sie
/// stillschweigend in TypeScript zu schliessen, waere der Fall, den §9 verbietet.
///
/// # Errors
/// `EA-READER-ENROLLMENT-NO-VAULT`, wenn KEINES der zurueckgegebenen Chiffrate
/// einen Envelope fuer diesen Authenticator traegt;
/// `EA-READER-ENROLLMENT-ENDPOINT-RESPONSE` fuer eine Antwort, die kein
/// gueltiger Abrufrahmen ist; daneben die durchgereichten Codes des Ports.
pub fn recover_and_unlock_vault(
    request: &VaultBlobRetrievalRequestV1,
    authenticator: &AuthenticatorPrfV1,
    endpoints: &mut dyn EnrollmentEndpoints,
) -> Result<UnlockedVault, EnrollmentError> {
    let body = request.exact_bytes().to_vec();
    let digest = body_digest(&body);
    let request_id = RequestIdV1::try_from(&random_bytes::<16>()?[..])?;
    let call = EnrollmentRequestV1::new(
        EndpointV1::VaultBlobRetrievals.method(),
        String::new(),
        EndpointV1::VaultBlobRetrievals.path_template().to_owned(),
        body,
        vec![
            (
                "content-type".to_owned(),
                STRUCTURED_MEDIA_TYPE_V1.to_owned(),
            ),
            ("content-digest".to_owned(), content_digest_header(&digest)),
            (
                REQUEST_ID_HEADER_V1.to_owned(),
                request_id.to_header_value(),
            ),
        ],
        false,
    );
    let answer = endpoints.send(&call)?;
    let response = VaultBlobRetrievalResponseV1::decode(&answer)
        .map_err(|_| EnrollmentError::Endpoint(EnrollmentEndpointError::ResponseShape))?;
    // Der Reihe nach, und ein Fehlschlag ist KEIN Abbruch: die Antwort traegt
    // bis zu `MAX_VAULT_BLOBS_PER_SUBJECT_V1` Chiffrate, von denen genau eines
    // diesem Reader gehoert. Die uebrigen sind fuer ihn Rauschen.
    for ciphertext in response.ciphertexts() {
        let Ok(sealed) = SealedVaultV1::from_deterministic_cbor(ciphertext) else {
            continue;
        };
        if let Ok(unlocked) = ReaderVault::unlock(&sealed, authenticator) {
            return Ok(unlocked);
        }
    }
    Err(EnrollmentError::NoVaultForCredential)
}

/// Ein signierter Aufruf: Koerper, Kopfzeilen und die RFC-9421-Signatur.
///
/// # Der SIGNIERTE `@target-uri` ist absolut, der TRANSPORTIERTE ist ein Pfad
///
/// Das sind zwei verschiedene Dinge, und sie hier zusammenzuziehen waere ein
/// stiller Fehlschlag gegen den echten Server. `apps/server/src/http/mod.rs`
/// baut die geprueft Komponente als `format!("https://{authority}{path_and_query}")`,
/// und `crates/ea-sync-client/src/client.rs` signiert sie zeichengleich so. Eine
/// signierte Basis mit dem nackten Pfad ergaebe `EA-HTTP-SIGNATURE-INVALID` an
/// einer Stelle, an der niemand die Ursache sucht — und kein Wirtszeuge dieser
/// Aufgabe saehe es, weil die Doppelung keine Signatur prueft.
/// [`EnrollmentRequestV1::target_uri`] bleibt trotzdem der PFAD: er adressiert
/// den Transport, und die Herkunft steht daneben in
/// [`EnrollmentRequestV1::authority`].
fn signed_request(
    signer: &RequestSigner,
    context: &EnrollmentRequestContextV1,
    tag: &str,
    endpoint: EndpointV1,
    body: Vec<u8>,
) -> Result<EnrollmentRequestV1, EnrollmentError> {
    let digest = body_digest(&body);
    let request_id = RequestIdV1::try_from(&random_bytes::<16>()?[..])?;
    let parts = RequestParts {
        method: endpoint.method(),
        authority: context.authority.clone(),
        target_uri: format!("https://{}{}", context.authority, endpoint.path_template()),
        content_type: Some(STRUCTURED_MEDIA_TYPE_V1.to_owned()),
        body_digest: Some(digest),
        request_id,
    };
    let parameters = SignatureParametersV1::new(
        context.created_unix_seconds,
        context.created_unix_seconds + ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1,
        random_bytes::<32>()?,
        tag.to_owned(),
    );
    let signed = signer.sign(&parts, &parameters)?;
    Ok(EnrollmentRequestV1::new(
        endpoint.method(),
        context.authority.clone(),
        endpoint.path_template().to_owned(),
        body,
        vec![
            (
                "content-type".to_owned(),
                STRUCTURED_MEDIA_TYPE_V1.to_owned(),
            ),
            ("content-digest".to_owned(), content_digest_header(&digest)),
            (
                REQUEST_ID_HEADER_V1.to_owned(),
                request_id.to_header_value(),
            ),
            (
                "signature-input".to_owned(),
                signed.signature_input_header(),
            ),
            ("signature".to_owned(), signed.signature_header()),
        ],
        true,
    ))
}

/// Die lokale Adresse des versiegelten Tresors, aus der EINEN Konstante.
fn reader_vault_blob_key() -> Result<ReaderBlobKey, ReaderBlobError> {
    ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1)
}

/// 32 Byte aus einer Hexzeichenkette.
fn decode_fingerprint(value: &str) -> Result<[u8; 32], EnrollmentError> {
    let bytes = hex::decode(value).map_err(|_| EnrollmentError::FingerprintEncoding)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| EnrollmentError::FingerprintEncoding)
}

/// Ein byteweiser Vergleich zweier OEFFENTLICHER Fingerabdruecke OHNE frueher
/// Ausstieg.
///
/// Handgeschrieben und ausdruecklich KEIN `subtle`. Drei Gruende. Erstens die
/// Sache selbst: verglichen werden zwei oeffentliche 32-Byte-Abdruecke, kein
/// Schluesselmaterial; die Konstantzeitigkeit schuetzt hier nicht ein
/// Geheimnis, sondern verhindert ein Orakel, das einem Angreifer verriete, wie
/// viele fuehrende Stellen seiner untergeschobenen Referenz schon stimmen.
/// Zweitens die Kosten: `subtle` in `[workspace.dependencies]` waere eine NEUE
/// Abhaengigkeitsklasse und verlangte in
/// `docs/adr/0005-browser-runtime-and-wasm-dependency-class.md` einen eigenen
/// Abschnitt samt Pin und Begruendung. Drittens die Lage: `ea-reader` steht auf
/// der wasm32-Positivliste, und jede zusaetzliche Crate ist zusaetzliche
/// wasm32-Flaeche.
///
/// # Die GRENZE, benannt statt geglaettet
///
/// Das ist eine QUELLTEXTAUSSAGE ueber Konstantzeitigkeit und keine gemessene.
/// Weder `cargo test` noch `cargo clippy` pruefen die erzeugten Instruktionen,
/// `black_box` ist ausdruecklich keine Garantie des Compilers, und die
/// vorgeschaltete `hex::decode` der Eingabe ist ohnehin nicht konstantzeitig.
/// Was hier steht, ist der Verzicht auf einen fruehen Ausstieg im Vergleich
/// selbst — nicht mehr.
fn fingerprints_match(expected: &[u8; 32], shown: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (expected_byte, shown_byte) in expected.iter().zip(shown.iter()) {
        difference |= expected_byte ^ shown_byte;
    }
    black_box(difference) == 0
}

/// `N` Byte frischer Entropie vom Wirt.
///
/// Genau der Weg, den `crates/ea-reader/src/vault.rs` und
/// `crates/ea-writer/src/entropy.rs` bereits nehmen; ein zweites RNG entsteht
/// hier nicht. Die Weigerung reist als `EA-LOCAL-CRYPTO-RNG` und damit unter
/// dem Code, den `ea-crypto` dafuer fuehrt.
fn random_bytes<const N: usize>() -> Result<[u8; N], EnrollmentError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| EnrollmentError::Vault(ReaderVaultError::Crypto(CryptoError::LocalRng)))?;
    Ok(bytes)
}
