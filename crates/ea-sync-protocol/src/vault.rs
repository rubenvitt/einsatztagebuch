//! Die drei Rahmen der Vault-Blob-Flaeche (`web-reader-design.md` §6.4).
//!
//! `schemas/protocol/v1/openapi.yaml` nennt fuer `PUT /v1/vault-blobs` und
//! `POST /v1/vault-blobs/retrievals` nur den Medientyp und ein leeres Schema,
//! und keines der beiden CDDL-Dokumente trug bisher eine Produktion dafuer.
//! Das ist dieselbe LUECKE, die [`crate::enrollment`] fuer die beiden
//! Aufnahmerahmen beschreibt, und sie wird auf demselben Weg geschlossen: die
//! Produktionen `vault-blob-upload-v1`, `vault-blob-retrieval-request-v1` und
//! `vault-blob-retrieval-response-v1` stehen normativ in
//! `schemas/protocol/v1/entry-commit.cddl`, in derselben Form wie jeder andere
//! v1-Rahmen — `[1, …, []]`, deterministisch nach Design §10.1.
//!
//! # Warum der Abrufrahmen die `organizationId` traegt
//!
//! `POST /v1/vault-blobs/retrievals` ist die ZWEITE und letzte
//! Signaturausnahme (`design.md` §13.1, Reader-Vorbehalt). Es gibt hier kein
//! `tag`-Signaturparameter, aus dem die Organisation kaeme, die Aufloesung des
//! Credentials laeuft aber ueber den Eindeutigkeitszwang
//! (`organizationId`, `credentialId`) der Servertabelle. Also traegt der
//! Koerper sie — genau wie `challenge-request-v1`, und aus demselben Grund.
//!
//! # Warum die `clientDataJSON` auf dem Draht steht
//!
//! Der Server PARST sie nicht. ADR 0004 hat das Merkmal `json` an Axum
//! ausdruecklich abgeschaltet, damit neben dem deterministischen CBOR des
//! Protokolls kein zweiter, ungeprueter Dekodierweg in den Server fuehrt; ein
//! JSON-Parser fuer genau dieses Feld holte ihn zurueck. Der Server BAUT die
//! erwartete Serialisierung aus Challenge und Bundle-Origin und vergleicht
//! byteweise. Der Rahmen traegt die gelieferten Bytes trotzdem, und das ist
//! kein doppeltes Feld: die Assertion signiert ueber genau diese Bytes, also
//! muessen sie auf dem Draht stehen, damit die Signatur ueberhaupt geprueft
//! werden kann.
//!
//! Die `challenge` steht daneben, weil der Server den Nonce-Digest braucht, um
//! die Challenge zu VERBRAUCHEN, und er ihn ohne Parser nicht aus der
//! `clientDataJSON` holt. Frei behaupten laesst sie sich damit nicht: der
//! Bytevergleich bindet sie an genau die Bytes, ueber die der Authenticator
//! signiert hat.

use core::fmt;

use ea_types::{OrganizationId, SubjectId};
use minicbor::Decoder;

use crate::{
    MAX_SMALL_BODY_BYTES_V1, PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError, cbor, cbor_read,
    enrollment::{MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1, MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1},
};

/// Die Bytedecke eines EINZELNEN Wrapped-Blobs.
///
/// Ein gewrapptes Vault-Chiffrat ist eine Umschlagkonstruktion ueber einem
/// 32-Byte-Vault-Key (`web-reader-design.md` §6.2) und misst damit einige
/// hundert Byte. Vier Kibibyte sind grosszuegig und halten den Rahmen
/// trotzdem so klein, dass die Abrufantwort unter der 64-KiB-Decke der
/// kleinen Koerper bleibt.
pub const MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1: usize = 4 * 1024;

/// Wie viele Wrapped-Blobs eine `subjectId` halten darf.
///
/// §6.3 verlangt MINDESTENS zwei unabhaengige Authenticators; acht decken
/// Neuanlagen und Wechsel und sind zugleich die Decke, ab der ein
/// freigegebenes Geraet die Tabelle unter einer fremden `subjectId` nicht mehr
/// beliebig fuellen kann. Acht mal vier Kibibyte bleiben unter der Decke der
/// kleinen Koerper.
pub const MAX_VAULT_BLOBS_PER_SUBJECT_V1: usize = 8;

/// Die kleinste zulaessige `authenticatorData`: `rpIdHash` (32),
/// `flags` (1), `signCount` (4). Alles darueber sind Erweiterungen.
pub const MIN_AUTHENTICATOR_DATA_BYTES_V1: usize = 37;
pub const MAX_AUTHENTICATOR_DATA_BYTES_V1: usize = 1024;

/// Die Decke der `clientDataJSON`. Sie traegt Typ, Challenge und Origin und
/// sonst nichts.
pub const MAX_CLIENT_DATA_JSON_BYTES_V1: usize = 2048;

/// `vault-blob-upload-v1` — der Koerper von `PUT /v1/vault-blobs`.
///
/// Er traegt die pseudonyme `subjectId` und GENAU EIN opakes Chiffrat. Einen
/// Blobhash traegt er NICHT: der Server rechnet ihn aus den Bytes und schreibt
/// create-if-absent ueber (`subjectId`, Blobhash). Ein vom Aufrufer
/// BEHAUPTETER Hash waere eine Adresse, die nicht auf ihren Inhalt zeigen
/// muss.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultBlobUploadV1 {
    subject_id: SubjectId,
    ciphertext: Vec<u8>,
    exact: Vec<u8>,
}

impl VaultBlobUploadV1 {
    pub fn new(subject_id: SubjectId, ciphertext: Vec<u8>) -> Result<Self, SyncProtocolError> {
        if ciphertext.is_empty() {
            return Err(SyncProtocolError::FrameShape);
        }
        if ciphertext.len() > MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        let mut exact = Vec::with_capacity(ciphertext.len().saturating_add(32));
        cbor::array(&mut exact, 4);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, subject_id.as_bytes());
        cbor::bytes(&mut exact, &ciphertext);
        cbor::empty_extension(&mut exact);
        Ok(Self {
            subject_id,
            ciphertext,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 4)?;
        cbor_read::expect_version(&mut decoder)?;
        let subject_id = SubjectId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let ciphertext = cbor_read::bytes(&mut decoder)?.to_vec();
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let upload = Self::new(subject_id, ciphertext)?;
        if upload.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(upload)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for VaultBlobUploadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultBlobUploadV1(<bound>)")
    }
}

/// `vault-blob-retrieval-request-v1` — der Koerper von
/// `POST /v1/vault-blobs/retrievals`.
///
/// Die WebAuthn-Assertion ueber ein auffindbares Credential dieses Lesers, und
/// sonst nichts. `subject_id` ist der BEHAUPTETE `userHandle`; der Server
/// stellt ihn gegen den, den das aufgeloeste Credential traegt, und weist eine
/// Abweichung genauso ab wie eine ungueltige Signatur.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultBlobRetrievalRequestV1 {
    organization_id: OrganizationId,
    subject_id: SubjectId,
    credential_id: Vec<u8>,
    challenge: [u8; 32],
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: [u8; 64],
    exact: Vec<u8>,
}

impl VaultBlobRetrievalRequestV1 {
    pub fn new(
        organization_id: OrganizationId,
        subject_id: SubjectId,
        credential_id: Vec<u8>,
        challenge: [u8; 32],
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<Self, SyncProtocolError> {
        if credential_id.len() < MIN_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
            || credential_id.len() > MAX_WEBAUTHN_CREDENTIAL_ID_BYTES_V1
            || authenticator_data.len() < MIN_AUTHENTICATOR_DATA_BYTES_V1
            || client_data_json.is_empty()
        {
            return Err(SyncProtocolError::FrameShape);
        }
        if authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES_V1
            || client_data_json.len() > MAX_CLIENT_DATA_JSON_BYTES_V1
        {
            return Err(SyncProtocolError::BodyLimit);
        }
        let mut exact = Vec::with_capacity(256);
        cbor::array(&mut exact, 9);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, organization_id.as_bytes());
        cbor::bytes(&mut exact, subject_id.as_bytes());
        cbor::bytes(&mut exact, &credential_id);
        cbor::bytes(&mut exact, &challenge);
        cbor::bytes(&mut exact, &authenticator_data);
        cbor::bytes(&mut exact, &client_data_json);
        cbor::bytes(&mut exact, &signature);
        cbor::empty_extension(&mut exact);
        if exact.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        Ok(Self {
            organization_id,
            subject_id,
            credential_id,
            challenge,
            authenticator_data,
            client_data_json,
            signature,
            exact,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 9)?;
        cbor_read::expect_version(&mut decoder)?;
        let organization_id = OrganizationId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let subject_id = SubjectId::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let credential_id = cbor_read::bytes(&mut decoder)?.to_vec();
        let challenge: [u8; 32] = cbor_read::bytes_exact(&mut decoder, 32)?
            .try_into()
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let authenticator_data = cbor_read::bytes(&mut decoder)?.to_vec();
        let client_data_json = cbor_read::bytes(&mut decoder)?.to_vec();
        let signature: [u8; 64] = cbor_read::bytes_exact(&mut decoder, 64)?
            .try_into()
            .map_err(|_| SyncProtocolError::FrameShape)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let request = Self::new(
            organization_id,
            subject_id,
            credential_id,
            challenge,
            authenticator_data,
            client_data_json,
            signature,
        )?;
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

    /// Der BEHAUPTETE `userHandle`.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    #[must_use]
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    #[must_use]
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }

    #[must_use]
    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

impl fmt::Debug for VaultBlobRetrievalRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultBlobRetrievalRequestV1(<bound>)")
    }
}

/// `vault-blob-retrieval-response-v1` — die opaken Chiffrate GENAU EINER
/// `subjectId`.
///
/// Kein Blobhash, kein Zeitstempel, keine Zaehlung: die Antwort traegt die
/// Bytes und sonst nichts. Alles Weitere waere ein Servermetadatum ueber einen
/// Bestand, den der Server nicht lesen kann.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultBlobRetrievalResponseV1 {
    ciphertexts: Vec<Vec<u8>>,
    exact: Vec<u8>,
}

impl VaultBlobRetrievalResponseV1 {
    pub fn new(ciphertexts: Vec<Vec<u8>>) -> Result<Self, SyncProtocolError> {
        if ciphertexts.len() > MAX_VAULT_BLOBS_PER_SUBJECT_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        if ciphertexts
            .iter()
            .any(|blob| blob.is_empty() || blob.len() > MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1)
        {
            return Err(SyncProtocolError::FrameShape);
        }
        let mut exact = Vec::with_capacity(64);
        cbor::array(&mut exact, 3);
        cbor::uint(&mut exact, 1);
        cbor::array(
            &mut exact,
            u64::try_from(ciphertexts.len()).map_err(|_| SyncProtocolError::ItemLimit)?,
        );
        for blob in &ciphertexts {
            cbor::bytes(&mut exact, blob);
        }
        cbor::empty_extension(&mut exact);
        if exact.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        Ok(Self { ciphertexts, exact })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 3)?;
        cbor_read::expect_version(&mut decoder)?;
        let count = cbor_read::array(&mut decoder)?;
        if usize::try_from(count).unwrap_or(usize::MAX) > MAX_VAULT_BLOBS_PER_SUBJECT_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        let mut ciphertexts = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for _ in 0..count {
            ciphertexts.push(cbor_read::bytes(&mut decoder)?.to_vec());
        }
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(ciphertexts)?;
        if response.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(response)
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub fn ciphertexts(&self) -> &[Vec<u8>] {
        &self.ciphertexts
    }
}

impl fmt::Debug for VaultBlobRetrievalResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultBlobRetrievalResponseV1(<bound>)")
    }
}
