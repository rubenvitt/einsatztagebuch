//! Die beiden UNSIGNIERTEN Aufnahmerahmen der Auth- und Webflaeche.
//!
//! `schemas/protocol/v1/signed-protocol.cddl` traegt die drei SIGNIERTEN
//! Koerper (`challenge-response-v1`, `device-registration-request-v1`,
//! `reader-ack-v1`), und `schemas/protocol/v1/entry-commit.cddl` traegt die
//! schreibenden Rahmen. Zwei Koerper standen bisher in KEINEM der beiden
//! Dokumente: der Anfragekoerper des Challenge-Endpunkts und der Koerper von
//! `POST /v1/webauthn-credentials`. `schemas/protocol/v1/openapi.yaml` nennt
//! fuer beide nur `application/einsatzarchiv+cbor;v=1` und ein leeres Schema.
//!
//! Das ist eine LUECKE und kein Widerspruch: das Sync-Wire-Addendum blockiert
//! die Umsetzung nur dort, wo Design und Addendum einander widersprechen. Die
//! beiden Rahmen entstehen deshalb hier, in derselben Form wie jeder andere
//! v1-Rahmen — `[1, …, []]`, deterministisch nach Design §10.1, hoechstens
//! [`MAX_SMALL_BODY_BYTES_V1`] — und ihre Produktionen stehen normativ in
//! `schemas/protocol/v1/entry-commit.cddl`.
//!
//! WARUM DER CHALLENGE-KOERPER EINE `organizationId` TRAEGT: der Endpunkt ist
//! die eine Signaturausnahme ohne WebAuthn-Assertion, es gibt also kein
//! `tag`-Signaturparameter, aus dem die Organisation kaeme.
//! `challenge-response-core-v1` fuehrt die `organizationId` aber an Position 2
//! — der Server muss sie also kennen. Sie ist zugleich die
//! NICHT-INHALTLICHE technische Identitaet, an der die Ratenbegrenzung haengt.

use core::fmt;

use ea_types::{OrganizationId, SubjectId};
use minicbor::Decoder;

use crate::{
    MAX_SMALL_BODY_BYTES_V1, PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError, cbor, cbor_read,
};

/// Die kleinste und die groesste zulaessige `credentialId`.
///
/// Die Untergrenze ist die des WebAuthn-Level-2-Profils fuer ein auffindbares
/// Credential, die Obergrenze die Spaltengrenze der Servertabelle
/// `webauthn_credentials` (`apps/server/migrations/0001_initial.sql`). Beide
/// stehen hier, damit der Rahmen sie ABWEIST, statt sie der Datenbank zu
/// ueberlassen: ein Constraintbruch waere ein 500, die Rahmengrenze ist ein
/// stabiler Befund.
pub const MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1: usize = 16;
pub const MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1: usize = 1023;

/// `challenge-request-v1` — der Koerper von `POST /v1/auth/challenges`.
#[derive(Clone, Eq, PartialEq)]
pub struct ChallengeRequestV1 {
    organization_id: OrganizationId,
    exact: Vec<u8>,
}

impl ChallengeRequestV1 {
    #[must_use]
    pub fn new(organization_id: OrganizationId) -> Self {
        let mut exact = Vec::with_capacity(24);
        cbor::array(&mut exact, 3);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, organization_id.as_bytes());
        cbor::empty_extension(&mut exact);
        Self {
            organization_id,
            exact,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 3)?;
        cbor_read::expect_version(&mut decoder)?;
        let organization_id = OrganizationId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let request = Self::new(organization_id);
        if request.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(request)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }
}

impl fmt::Debug for ChallengeRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeRequestV1(<bound>)")
    }
}

/// `webauthn-credential-registration-v1` — der Koerper von
/// `POST /v1/webauthn-credentials`.
///
/// Die pseudonyme `subjectId` IST der `userHandle`
/// (`web-reader-design.md` §6.4.1). Der Rahmen traegt sonst nur die
/// `credentialId` und den oeffentlichen COSE-Schluessel des Authenticators —
/// keinen Anzeigenamen, keine Kennung eines Menschen und keinen fachlichen
/// Wert.
///
/// # Der Schluessel wird GEPARST
///
/// `credential_public_cose_key` ist die kanonische COSE-Karte dieses
/// Arbeitsbereichs ([`ea_crypto::CanonicalPublicCoseKey`]) und darin GENAU der
/// OKP-Ed25519-Arm. §6.4.1 nennt keinen Algorithmus, die Suite ist
/// durchgehend Ed25519 (`design.md` §13.1, `alg="ed25519"`), und die Assertion
/// muss spaeter gegen genau diesen Schluessel tragen — ein Schluessel, den der
/// Server nicht lesen kann, ist deshalb schon bei der Aufnahme ein Befund und
/// keine Zeile. Der Web-Reader normalisiert den `credentialPublicKey` seines
/// Authenticators vor der Registrierung in diese Form.
#[derive(Clone, Eq, PartialEq)]
pub struct WebauthnCredentialRegistrationV1 {
    subject_id: SubjectId,
    credential_id: Vec<u8>,
    credential_public_cose_key: Vec<u8>,
    exact: Vec<u8>,
}

impl WebauthnCredentialRegistrationV1 {
    pub fn new(
        subject_id: SubjectId,
        credential_id: Vec<u8>,
        credential_public_cose_key: Vec<u8>,
    ) -> Result<Self, SyncProtocolError> {
        if credential_id.len() < MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
            || credential_id.len() > MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
        {
            return Err(SyncProtocolError::FrameShape);
        }
        // Der oeffentliche Schluessel wird HIER geparst und nicht erst beim
        // Abruf. Ein Credential, dessen Schluessel keine gueltige kanonische
        // OKP-Ed25519-Karte ist, koennte nie eine Assertion tragen; ihn
        // ungeprueft aufzunehmen legte eine Zeile an, die spaeter nur noch
        // fail-closed abweisen kann.
        if !matches!(
            ea_crypto::CanonicalPublicCoseKey::from_deterministic_cbor(&credential_public_cose_key),
            Ok(ea_crypto::CanonicalPublicCoseKey::Ed25519(_))
        ) {
            return Err(SyncProtocolError::FrameShape);
        }
        let mut exact = Vec::with_capacity(128);
        cbor::array(&mut exact, 5);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, subject_id.as_bytes());
        cbor::bytes(&mut exact, &credential_id);
        cbor::bytes(&mut exact, &credential_public_cose_key);
        cbor::empty_extension(&mut exact);
        if exact.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        Ok(Self {
            subject_id,
            credential_id,
            credential_public_cose_key,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 5)?;
        cbor_read::expect_version(&mut decoder)?;
        let subject_id = SubjectId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let credential_id = cbor_read::bytes(&mut decoder)?.to_vec();
        let credential_public_cose_key = cbor_read::bytes(&mut decoder)?.to_vec();
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let registration = Self::new(subject_id, credential_id, credential_public_cose_key)?;
        if registration.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(registration)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    /// Der `userHandle` dieses Credentials.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    #[must_use]
    pub fn credential_public_cose_key(&self) -> &[u8] {
        &self.credential_public_cose_key
    }
}

impl fmt::Debug for WebauthnCredentialRegistrationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebauthnCredentialRegistrationV1(<bound>)")
    }
}
