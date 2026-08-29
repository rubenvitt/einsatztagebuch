use core::{cmp::Ordering, fmt};
use std::collections::BTreeSet;

use ea_crypto::{
    ContentType, HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE, grant_digest,
    grant_plan_digest, parse_cose_sign1,
};
use ea_types::{
    CertificateHash, ChainId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use minicbor::{Decoder, Encoder};

use crate::object::{
    FormatError, bytes_exact, exact_array_length, exact_item, expect_array_length, finish,
    optional_bytes_exact,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GrantPurposeV1 {
    Recovery = 0,
    Reader = 1,
}

impl TryFrom<u64> for GrantPurposeV1 {
    type Error = FormatError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Recovery),
            1 => Ok(Self::Reader),
            _ => Err(FormatError::Shape),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantKindV1 {
    Initial,
    Historical,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantPlanItemV1 {
    recipient_key_thumbprint: KeyThumbprint,
    recipient_certificate_hash: CertificateHash,
    purpose: GrantPurposeV1,
}

impl GrantPlanItemV1 {
    #[must_use]
    pub const fn new(
        recipient_key_thumbprint: KeyThumbprint,
        recipient_certificate_hash: CertificateHash,
        purpose: GrantPurposeV1,
    ) -> Self {
        Self {
            recipient_key_thumbprint,
            recipient_certificate_hash,
            purpose,
        }
    }

    #[must_use]
    pub const fn recipient_key_thumbprint(&self) -> KeyThumbprint {
        self.recipient_key_thumbprint
    }

    #[must_use]
    pub const fn recipient_certificate_hash(&self) -> CertificateHash {
        self.recipient_certificate_hash
    }

    #[must_use]
    pub const fn grant_suite_id(&self) -> &'static str {
        ea_crypto::GRANT_SUITE_ID
    }

    #[must_use]
    pub const fn purpose(&self) -> GrantPurposeV1 {
        self.purpose
    }

    fn tuple_cmp(&self, other: &Self) -> Ordering {
        self.recipient_key_thumbprint
            .as_bytes()
            .cmp(other.recipient_key_thumbprint.as_bytes())
            .then_with(|| {
                self.recipient_certificate_hash
                    .as_bytes()
                    .cmp(other.recipient_certificate_hash.as_bytes())
            })
            .then_with(|| self.purpose.cmp(&other.purpose))
    }
}

impl fmt::Debug for GrantPlanItemV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantPlanItemV1(<bound>)")
    }
}

pub struct GrantPlanV1 {
    items: Vec<GrantPlanItemV1>,
    exact: Vec<u8>,
    hash: Hash32,
}

impl GrantPlanV1 {
    pub fn new(mut items: Vec<GrantPlanItemV1>) -> Result<Self, FormatError> {
        validate_plan_items(&items)?;
        items.sort_by(GrantPlanItemV1::tuple_cmp);
        let exact = encode_plan_items(&items)?;
        let hash = grant_plan_digest(&exact);
        Ok(Self { items, exact, hash })
    }

    #[must_use]
    pub fn items(&self) -> &[GrantPlanItemV1] {
        &self.items
    }

    /// Die exakten Bytes, ueber die `grant_plan_digest` den Planhash bildet.
    ///
    /// Sie stehen HIER und nicht bei einem Verbraucher, weil der Serverpfad
    /// dieselben Bytes braucht wie der Schreiber. Eine zweite Kodierung des
    /// Elementmaterials waere eine zweite Gelegenheit, `initialGrantPlanHash`
    /// und damit die Wiedergabeidentitaet auseinanderlaufen zu lassen.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub const fn hash(&self) -> Hash32 {
        self.hash
    }
}

impl fmt::Debug for GrantPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantPlanV1(<bound>)")
    }
}

/// Der Plan aus seinen Wire-Bytes — das Gegenstueck zu `encode_plan_items`.
///
/// Der Dekodierer laeuft GENAU die Regeln von [`GrantPlanV1::new`]: genau eine
/// Wiederherstellung, kein doppelter Empfaengerschluessel, kein doppeltes
/// Empfaengerzertifikat. Danach besteht er zusaetzlich auf der KANONISCHEN
/// Reihenfolge und SORTIERT NICHT NACH: ein nachsortierender Dekodierer
/// lieferte zu abweichenden Bytes denselben Hash und loeste damit genau die
/// Bindung, die der Plan traegt — `initialGrantPlanHash` und mit ihm die
/// Wiedergabeidentitaet wichen vom Schreiber ab.
///
/// Die Gleichheit von Ein- und Ausgabebytes ist BEWIESEN, nicht geraten: die
/// dekodierten Elemente werden mit demselben `encode_plan_items` zurueck
/// kodiert, das der Schreiber benutzt, und gegen die Eingabe geprueft.
pub fn decode_grant_plan(bytes: &[u8]) -> Result<GrantPlanV1, FormatError> {
    ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1)?;
    let mut decoder = Decoder::new(bytes);
    let length = exact_array_length(&mut decoder)?;
    let count = usize::try_from(length).map_err(|_| FormatError::Shape)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array_length(&mut decoder, 4)?;
        let recipient_key_thumbprint = KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?)
            .map_err(|_| FormatError::Shape)?;
        let recipient_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
            .map_err(|_| FormatError::Shape)?;
        if decoder.str().map_err(|_| FormatError::Shape)? != ea_crypto::GRANT_SUITE_ID {
            return Err(FormatError::TagMismatch);
        }
        let purpose = GrantPurposeV1::try_from(decoder.u64().map_err(|_| FormatError::Shape)?)?;
        items.push(GrantPlanItemV1::new(
            recipient_key_thumbprint,
            recipient_certificate_hash,
            purpose,
        ));
    }
    finish(&decoder, bytes)?;

    validate_plan_items(&items)?;
    if items
        .windows(2)
        .any(|pair| pair[0].tuple_cmp(&pair[1]) != Ordering::Less)
    {
        return Err(FormatError::Unsorted);
    }

    let exact = encode_plan_items(&items)?;
    if exact != bytes {
        return Err(FormatError::Shape);
    }
    let hash = grant_plan_digest(&exact);
    Ok(GrantPlanV1 { items, exact, hash })
}

/// Die Kardinalitaets- und Doppelregeln des Plans, geteilt von Konstruktor und
/// Dekodierer.
///
/// Sie stehen einmal, damit beide Seiten bei DEMSELBEN Material DENSELBEN
/// Fehlercode liefern; die eingefrorenen `plan/rejected-*`-Vektoren nennen je
/// einen davon.
fn validate_plan_items(items: &[GrantPlanItemV1]) -> Result<(), FormatError> {
    let recovery_count = items
        .iter()
        .filter(|item| item.purpose == GrantPurposeV1::Recovery)
        .count();
    match recovery_count {
        0 => return Err(FormatError::MissingRecovery),
        1 => {}
        _ => return Err(FormatError::DuplicateRecovery),
    }
    let mut recipient_keys = BTreeSet::new();
    let mut recipient_certificates = BTreeSet::new();
    for item in items {
        if !recipient_keys.insert(*item.recipient_key_thumbprint.as_bytes()) {
            return Err(FormatError::DuplicateRecipientKey);
        }
        if !recipient_certificates.insert(*item.recipient_certificate_hash.as_bytes()) {
            return Err(FormatError::DuplicateRecipientCertificate);
        }
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantBodyFieldsV1 {
    pub organization_id: OrganizationId,
    pub chain_id: ChainId,
    pub entry_hash: EntryHash,
    pub kind: GrantKindV1,
    pub purpose: GrantPurposeV1,
    pub recipient_key_thumbprint: KeyThumbprint,
    pub recipient_certificate_hash: CertificateHash,
    pub issuer_key_thumbprint: KeyThumbprint,
    pub issuer_certificate_hash: CertificateHash,
    pub registry_version: RegistryVersion,
    pub registry_head_hash: Hash32,
    pub created_at_device: UnixMillis,
    pub original_recovery_grant_object_hash: Option<ObjectHash>,
    pub grant_authorization_object_hash: Option<ObjectHash>,
    pub encapsulated_key: [u8; ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE],
    pub wrapped_cek: [u8; ea_crypto::HPKE_WRAPPED_CEK_SIZE],
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantBodyV1 {
    fields: GrantBodyFieldsV1,
    exact: Vec<u8>,
}

impl GrantBodyV1 {
    pub fn new(fields: GrantBodyFieldsV1) -> Result<Self, FormatError> {
        validate_grant_field_correlations(&fields)?;
        let exact = encode_grant_body(&fields)?;
        Ok(Self { fields, exact })
    }

    #[must_use]
    pub const fn fields(&self) -> &GrantBodyFieldsV1 {
        &self.fields
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    /// Die exakten Bytes des `grant-context-v1` aus diesem `grant-body-v1`.
    ///
    /// `hpkeInfo` und `hpkeAad` sind ueber GENAU diese Bytes definiert
    /// (`design.md`:788-791) — nicht ueber den Grantrumpf, der Kapselung und
    /// umschlossenen CEK zusaetzlich enthaelt. Der Kontext hat keine eigene
    /// Kodierfunktion; er wird deshalb aus dem Rumpf HERAUSGESCHNITTEN.
    ///
    /// Sie steht HIER und nicht bei einem Verbraucher, weil beide Seiten
    /// dieselben Bytes brauchen: die Oeffnungsseite in `ea-verify` und die
    /// Versiegelungsseite des Writers. Zwei Kopien des Schnitts waeren zwei
    /// Gelegenheiten, `hpke_info` und `hpke_aad` mit verschiedenen Bytes zu
    /// speisen — und damit ein Grant, den niemand oeffnen kann.
    ///
    /// DER SCHNITT IST BEWIESEN, NICHT GERATEN, und genau deshalb steht hier
    /// ein Waechter statt eines Kommentars: `grant-body-v1` ist ein
    /// CBOR-Array fester Laenge drei (`0x83`), dessen zweites und drittes
    /// Glied Bytefolgen fester Groesse 32 und 48 sind. Beide werden kanonisch
    /// als `0x58 0x20 || …` beziehungsweise `0x58 0x30 || …` kodiert — 84
    /// Bytes, deren Inhalt hier unabhaengig aus den dekodierten Feldern
    /// nachgebaut und gegen den Rumpf geprueft wird. Stimmt der Schwanz exakt,
    /// ist alles davor (nach dem Arraykopf) definitionsgemaess das erste
    /// Glied: der Kontext.
    ///
    /// Faellt der Waechter, wird `None` geliefert. Der Dekodierpfad bekommt
    /// feindliche Bytes in die Hand; eine Entkapselung auf geratenen Bytes
    /// gibt es hier deshalb nicht.
    #[must_use]
    pub fn exact_grant_context(&self) -> Option<&[u8]> {
        /// CBOR-Kopf einer Bytefolge mit einbytiger Laengenangabe.
        const BYTE_STRING_ONE_BYTE_LENGTH: u8 = 0x58;
        /// CBOR-Kopf eines Arrays fester Laenge drei.
        const ARRAY_OF_THREE: u8 = 0x83;

        let exact = self.exact_bytes();
        let fields = self.fields();
        let mut tail = Vec::with_capacity(4 + HPKE_ENCAPSULATED_KEY_SIZE + HPKE_WRAPPED_CEK_SIZE);
        tail.push(BYTE_STRING_ONE_BYTE_LENGTH);
        tail.push(u8::try_from(HPKE_ENCAPSULATED_KEY_SIZE).ok()?);
        tail.extend_from_slice(&fields.encapsulated_key);
        tail.push(BYTE_STRING_ONE_BYTE_LENGTH);
        tail.push(u8::try_from(HPKE_WRAPPED_CEK_SIZE).ok()?);
        tail.extend_from_slice(&fields.wrapped_cek);

        let context_end = exact.len().checked_sub(tail.len())?;
        let (head, actual_tail) = exact.split_at(context_end);
        if actual_tail != tail.as_slice() || head.first() != Some(&ARRAY_OF_THREE) {
            return None;
        }
        head.get(1..)
    }

    fn from_exact(input: &[u8]) -> Result<Self, FormatError> {
        let fields = decode_grant_body(input)?;
        Ok(Self {
            fields,
            exact: input.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GrantV1 {
    grant_body: GrantBodyV1,
    issuer_signature: Vec<u8>,
    exact_body: Vec<u8>,
}

impl GrantV1 {
    pub fn new(grant_body: GrantBodyV1, issuer_signature: Vec<u8>) -> Result<Self, FormatError> {
        validate_issuer_signature(&grant_body, &issuer_signature)?;
        let exact_body = encode_grant_wrapper(grant_body.exact_bytes(), &issuer_signature)?;
        Ok(Self {
            grant_body,
            issuer_signature,
            exact_body,
        })
    }

    /// The verified grant body, including every field the verification gates
    /// `grant-plan`, `recipient-grant` and the following `hpke-open` need.
    ///
    /// The body is only reachable through a parsed or constructed [`GrantV1`],
    /// so its fields have always passed [`GrantBodyV1::new`]'s correlation
    /// checks and the issuer-signature binding.
    #[must_use]
    pub const fn grant_body(&self) -> &GrantBodyV1 {
        &self.grant_body
    }

    #[must_use]
    pub const fn kind(&self) -> GrantKindV1 {
        self.grant_body.fields.kind
    }

    #[must_use]
    pub const fn purpose(&self) -> GrantPurposeV1 {
        self.grant_body.fields.purpose
    }

    #[must_use]
    pub fn exact_grant_body(&self) -> &[u8] {
        self.grant_body.exact_bytes()
    }

    #[must_use]
    pub fn issuer_signature(&self) -> &[u8] {
        &self.issuer_signature
    }

    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.exact_body
    }
}

pub(crate) fn parse_body(input: &[u8]) -> Result<GrantV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 2)?;
    let exact_grant_body = exact_item(input, &mut decoder)?;
    let grant_body = GrantBodyV1::from_exact(exact_grant_body)?;
    let issuer_signature = exact_item(input, &mut decoder)?;
    finish(&decoder, input)?;
    validate_issuer_signature(&grant_body, issuer_signature)?;
    Ok(GrantV1 {
        grant_body,
        issuer_signature: issuer_signature.to_vec(),
        exact_body: input.to_vec(),
    })
}

fn validate_issuer_signature(
    grant_body: &GrantBodyV1,
    issuer_signature: &[u8],
) -> Result<(), FormatError> {
    let cose = parse_cose_sign1(issuer_signature, &[]).map_err(|_| FormatError::Cose)?;
    if cose.content_type() != ContentType::GrantDigest
        || cose.key_thumbprint() != grant_body.fields.issuer_key_thumbprint
        || cose.certificate_hash() != Some(grant_body.fields.issuer_certificate_hash)
        || cose.payload() != grant_digest(grant_body.exact_bytes()).as_bytes()
    {
        return Err(FormatError::Cose);
    }
    Ok(())
}

fn decode_grant_body(input: &[u8]) -> Result<GrantBodyFieldsV1, FormatError> {
    let mut decoder = Decoder::new(input);
    expect_array_length(&mut decoder, 3)?;
    expect_array_length(&mut decoder, 17)?;
    if decoder.u64().map_err(|_| FormatError::Shape)? != 1 {
        return Err(FormatError::UnknownVersion);
    }
    let organization_id =
        OrganizationId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
    let chain_id =
        ChainId::try_from(bytes_exact(&mut decoder, 16)?).map_err(|_| FormatError::Shape)?;
    let entry_hash =
        EntryHash::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let kind = match decoder.u64().map_err(|_| FormatError::Shape)? {
        0 => GrantKindV1::Initial,
        1 => GrantKindV1::Historical,
        _ => return Err(FormatError::Shape),
    };
    let purpose = GrantPurposeV1::try_from(decoder.u64().map_err(|_| FormatError::Shape)?)?;
    let recipient_key_thumbprint =
        KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let recipient_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
        .map_err(|_| FormatError::Shape)?;
    let issuer_key_thumbprint =
        KeyThumbprint::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    let issuer_certificate_hash = CertificateHash::try_from(bytes_exact(&mut decoder, 32)?)
        .map_err(|_| FormatError::Shape)?;
    let capability = decoder.str().map_err(|_| FormatError::Shape)?;
    let registry_version = RegistryVersion::new(decoder.u64().map_err(|_| FormatError::Shape)?);
    let registry_head_hash =
        Hash32::try_from(bytes_exact(&mut decoder, 32)?).map_err(|_| FormatError::Shape)?;
    if decoder.str().map_err(|_| FormatError::Shape)? != ea_crypto::GRANT_SUITE_ID {
        return Err(FormatError::TagMismatch);
    }
    let created_at_device = UnixMillis::new(decoder.i64().map_err(|_| FormatError::Shape)?);
    let original_recovery_grant_object_hash = optional_bytes_exact(&mut decoder, 32)?
        .map(ObjectHash::try_from)
        .transpose()
        .map_err(|_| FormatError::Shape)?;
    let grant_authorization_object_hash = optional_bytes_exact(&mut decoder, 32)?
        .map(ObjectHash::try_from)
        .transpose()
        .map_err(|_| FormatError::Shape)?;
    let encapsulated_key = bytes_exact(&mut decoder, ea_crypto::HPKE_ENCAPSULATED_KEY_SIZE)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    let wrapped_cek = bytes_exact(&mut decoder, ea_crypto::HPKE_WRAPPED_CEK_SIZE)?
        .try_into()
        .map_err(|_| FormatError::Shape)?;
    finish(&decoder, input)?;
    let fields = GrantBodyFieldsV1 {
        organization_id,
        chain_id,
        entry_hash,
        kind,
        purpose,
        recipient_key_thumbprint,
        recipient_certificate_hash,
        issuer_key_thumbprint,
        issuer_certificate_hash,
        registry_version,
        registry_head_hash,
        created_at_device,
        original_recovery_grant_object_hash,
        grant_authorization_object_hash,
        encapsulated_key,
        wrapped_cek,
    };
    let expected_capability = match kind {
        GrantKindV1::Initial => "initialGrant",
        GrantKindV1::Historical => "historicalGrant",
    };
    if capability != expected_capability {
        return Err(FormatError::Shape);
    }
    validate_grant_field_correlations(&fields)?;
    Ok(fields)
}

fn validate_grant_field_correlations(fields: &GrantBodyFieldsV1) -> Result<(), FormatError> {
    match fields.kind {
        GrantKindV1::Initial
            if fields.original_recovery_grant_object_hash.is_some()
                || fields.grant_authorization_object_hash.is_some() =>
        {
            Err(FormatError::Shape)
        }
        GrantKindV1::Historical
            if fields.purpose != GrantPurposeV1::Reader
                || fields.original_recovery_grant_object_hash.is_none()
                || fields.grant_authorization_object_hash.is_none() =>
        {
            Err(FormatError::Shape)
        }
        _ => Ok(()),
    }
}

fn encode_grant_body(fields: &GrantBodyFieldsV1) -> Result<Vec<u8>, FormatError> {
    let capability = match fields.kind {
        GrantKindV1::Initial => "initialGrant",
        GrantKindV1::Historical => "historicalGrant",
    };
    let mut exact = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut exact);
    encoder
        .array(3)
        .and_then(|encoder| encoder.array(17))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(fields.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.chain_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.entry_hash.as_bytes()))
        .and_then(|encoder| encoder.u8(fields.kind as u8))
        .and_then(|encoder| encoder.u8(fields.purpose as u8))
        .and_then(|encoder| encoder.bytes(fields.recipient_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.recipient_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.issuer_key_thumbprint.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.issuer_certificate_hash.as_bytes()))
        .and_then(|encoder| encoder.str(capability))
        .and_then(|encoder| encoder.u64(fields.registry_version.get()))
        .and_then(|encoder| encoder.bytes(fields.registry_head_hash.as_bytes()))
        .and_then(|encoder| encoder.str(ea_crypto::GRANT_SUITE_ID))
        .and_then(|encoder| encoder.i64(fields.created_at_device.get()))
        .map_err(|_| FormatError::Shape)?;
    encode_optional_object_hash(&mut encoder, fields.original_recovery_grant_object_hash)?;
    encode_optional_object_hash(&mut encoder, fields.grant_authorization_object_hash)?;
    encoder
        .bytes(&fields.encapsulated_key)
        .and_then(|encoder| encoder.bytes(&fields.wrapped_cek))
        .map_err(|_| FormatError::Shape)?;
    Ok(exact)
}

fn encode_optional_object_hash(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<ObjectHash>,
) -> Result<(), FormatError> {
    if let Some(value) = value {
        encoder
            .bytes(value.as_bytes())
            .map_err(|_| FormatError::Shape)?;
    } else {
        encoder.null().map_err(|_| FormatError::Shape)?;
    }
    Ok(())
}

fn encode_grant_wrapper(
    exact_grant_body: &[u8],
    issuer_signature: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(
        exact_grant_body
            .len()
            .saturating_add(issuer_signature.len())
            .saturating_add(8),
    );
    Encoder::new(&mut exact)
        .array(2)
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(exact_grant_body);
    exact.extend_from_slice(issuer_signature);
    Ok(exact)
}

fn encode_plan_items(items: &[GrantPlanItemV1]) -> Result<Vec<u8>, FormatError> {
    let length = u64::try_from(items.len()).map_err(|_| FormatError::Shape)?;
    let mut bytes = Vec::with_capacity(items.len().saturating_mul(100).saturating_add(8));
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(length).map_err(|_| FormatError::Shape)?;
    for item in items {
        encoder
            .array(4)
            .and_then(|encoder| encoder.bytes(item.recipient_key_thumbprint.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.recipient_certificate_hash.as_bytes()))
            .and_then(|encoder| encoder.str(ea_crypto::GRANT_SUITE_ID))
            .and_then(|encoder| encoder.u8(item.purpose as u8))
            .map_err(|_| FormatError::Shape)?;
    }
    Ok(bytes)
}
