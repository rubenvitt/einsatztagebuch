//! Die schreibenden Rahmen: Entry-Commit, seine Antwort und die drei
//! Einzelobjekt-Uploads.
//!
//! Objektbytes werden hier NICHT nachgebaut. Der Entry und jeder Grant laufen
//! durch `ea_format::decode_exact_object`, der Plan durch
//! `ea_format::decode_grant_plan`; diese Datei ordnet die Ergebnisse nur an und
//! setzt die Grenzen, die vor jeder Dienstanfrage greifen.

use core::fmt;

use ea_format::{
    GrantPlanV1, ObjectTypeV1, ParsedArchiveObject, decode_exact_object, decode_grant_plan,
};
use ea_types::{EntryHash, Hash32, ObjectHash};
use minicbor::Decoder;

use crate::{
    MAX_ENTRY_COMMIT_BODY_BYTES_V1, MAX_ENTRY_OBJECT_BYTES_V1, MAX_GRANT_OBJECT_BYTES_V1,
    MAX_GRANT_PLAN_ITEMS_V1, PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError, cbor, cbor_read,
};

/// Die stabile Wiedergabeidentitaet eines Commits.
///
/// Genau diese vier Positionen entscheiden ueber einen idempotenten Replay
/// (`design.md` §13.3). Die Grant-Hashes stehen bytweise sortiert darin, damit
/// die Identitaet von der Transportreihenfolge UNABHAENGIG ist.
#[derive(Clone, Eq, PartialEq)]
pub struct EntryCommitIdentity {
    entry_hash: EntryHash,
    entry_object_hash: ObjectHash,
    initial_grant_plan_hash: Hash32,
    sorted_grant_object_hashes: Vec<ObjectHash>,
}

impl EntryCommitIdentity {
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn entry_object_hash(&self) -> ObjectHash {
        self.entry_object_hash
    }

    #[must_use]
    pub const fn initial_grant_plan_hash(&self) -> Hash32 {
        self.initial_grant_plan_hash
    }

    #[must_use]
    pub fn sorted_grant_object_hashes(&self) -> &[ObjectHash] {
        &self.sorted_grant_object_hashes
    }
}

impl fmt::Debug for EntryCommitIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntryCommitIdentity(<bound>)")
    }
}

/// `entry-commit-request-v1`.
pub struct EntryCommitRequestV1 {
    entry_bytes: Vec<u8>,
    plan: GrantPlanV1,
    /// Bytweise nach `objectHash` sortiert — die Leitung traegt dieselbe
    /// Ordnung wie die Identitaet.
    sorted_grant_bytes: Vec<Vec<u8>>,
    identity: EntryCommitIdentity,
    exact: Vec<u8>,
}

impl EntryCommitRequestV1 {
    /// Baut den Request und weist jede Grenze VOR dem Parsen nach, soweit sie
    /// sich an der Bytelaenge entscheidet.
    pub fn new(
        entry_bytes: Vec<u8>,
        plan: GrantPlanV1,
        grant_bytes: Vec<Vec<u8>>,
    ) -> Result<Self, SyncProtocolError> {
        if entry_bytes.len() > MAX_ENTRY_OBJECT_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        if grant_bytes.is_empty() {
            return Err(SyncProtocolError::FrameShape);
        }
        if grant_bytes.len() > MAX_GRANT_PLAN_ITEMS_V1
            || plan.items().len() > MAX_GRANT_PLAN_ITEMS_V1
        {
            return Err(SyncProtocolError::ItemLimit);
        }
        if grant_bytes
            .iter()
            .any(|grant| grant.len() > MAX_GRANT_OBJECT_BYTES_V1)
        {
            return Err(SyncProtocolError::GrantLimit);
        }

        let ParsedArchiveObject::Entry(entry) = decode_exact_object(&entry_bytes)? else {
            return Err(SyncProtocolError::FrameShape);
        };
        let mut hashed = Vec::with_capacity(grant_bytes.len());
        for grant in grant_bytes {
            let ParsedArchiveObject::Grant(parsed) = decode_exact_object(&grant)? else {
                return Err(SyncProtocolError::FrameShape);
            };
            hashed.push((parsed.object_hash(), grant));
        }
        hashed.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        if hashed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SyncProtocolError::DuplicateObject);
        }

        let identity = EntryCommitIdentity {
            entry_hash: entry.value().entry_hash(),
            entry_object_hash: entry.object_hash(),
            initial_grant_plan_hash: plan.hash(),
            sorted_grant_object_hashes: hashed.iter().map(|(hash, _)| *hash).collect(),
        };
        let sorted_grant_bytes: Vec<Vec<u8>> = hashed.into_iter().map(|(_, bytes)| bytes).collect();
        let exact = encode_request(&entry_bytes, &plan, &sorted_grant_bytes);
        if exact.len() > MAX_ENTRY_COMMIT_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        Ok(Self {
            entry_bytes,
            plan,
            sorted_grant_bytes,
            identity,
            exact,
        })
    }

    /// Liest einen Commit-Koerper.
    ///
    /// Die Bytegrenze steht VOR dem Parser, damit ein ueberlanger Koerper nicht
    /// erst dekodiert werden muss. Am Ende wird der Rahmen neu kodiert und
    /// gegen die Eingabe geprueft: eine unsortierte oder nicht kanonische
    /// Leitungsform ist damit fail-closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_ENTRY_COMMIT_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 5)?;
        cbor_read::expect_version(&mut decoder)?;
        let entry_bytes = cbor_read::bytes(&mut decoder)?.to_vec();
        let plan = decode_grant_plan(cbor_read::exact_item(bytes, &mut decoder)?)?;
        let count = cbor_read::array(&mut decoder)?;
        if count == 0 {
            return Err(SyncProtocolError::FrameShape);
        }
        let count = usize::try_from(count).map_err(|_| SyncProtocolError::ItemLimit)?;
        if count > MAX_GRANT_PLAN_ITEMS_V1 {
            return Err(SyncProtocolError::ItemLimit);
        }
        let mut grant_bytes = Vec::with_capacity(count.min(MAX_GRANT_PLAN_ITEMS_V1));
        for _ in 0..count {
            grant_bytes.push(cbor_read::bytes(&mut decoder)?.to_vec());
        }
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let request = Self::new(entry_bytes, plan, grant_bytes)?;
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
    pub const fn identity(&self) -> &EntryCommitIdentity {
        &self.identity
    }

    #[must_use]
    pub fn entry_bytes(&self) -> &[u8] {
        &self.entry_bytes
    }

    #[must_use]
    pub const fn grant_plan(&self) -> &GrantPlanV1 {
        &self.plan
    }

    /// Die initialen Grants in bytweiser `objectHash`-Ordnung.
    #[must_use]
    pub fn sorted_grant_bytes(&self) -> &[Vec<u8>] {
        &self.sorted_grant_bytes
    }
}

impl fmt::Debug for EntryCommitRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntryCommitRequestV1(<bound>)")
    }
}

fn encode_request(entry_bytes: &[u8], plan: &GrantPlanV1, grants: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entry_bytes.len() + plan.exact_bytes().len() + 64);
    cbor::array(&mut out, 5);
    cbor::uint(&mut out, 1);
    cbor::bytes(&mut out, entry_bytes);
    // Der Plan steht als die EXAKTEN Bytes darin, ueber die
    // `grant_plan_digest` den `initialGrantPlanHash` bildet. Eine zweite
    // Kodierung waere eine zweite Gelegenheit, ihn abweichen zu lassen.
    out.extend_from_slice(plan.exact_bytes());
    cbor::array(&mut out, grants.len() as u64);
    for grant in grants {
        cbor::bytes(&mut out, grant);
    }
    cbor::empty_extension(&mut out);
    out
}

/// Der Ausgang eines Commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryCommitOutcome {
    /// Der Commit wurde angenommen.
    Accepted,
    /// Derselbe Commit lag bereits vor; der gespeicherte Receipt wird erneut
    /// ausgeliefert.
    IdempotentReplay,
}

impl EntryCommitOutcome {
    #[must_use]
    const fn code(self) -> u64 {
        match self {
            Self::Accepted => 0,
            Self::IdempotentReplay => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SyncProtocolError> {
        match code {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::IdempotentReplay),
            _ => Err(SyncProtocolError::FrameShape),
        }
    }
}

/// `entry-commit-response-v1`.
#[derive(Clone, Eq, PartialEq)]
pub struct EntryCommitResponseV1 {
    outcome: EntryCommitOutcome,
    receipt_bytes: Vec<u8>,
    checkpoint_bytes: Option<Vec<u8>>,
    exact: Vec<u8>,
}

impl EntryCommitResponseV1 {
    #[must_use]
    pub fn new(
        outcome: EntryCommitOutcome,
        receipt_bytes: Vec<u8>,
        checkpoint_bytes: Option<Vec<u8>>,
    ) -> Self {
        let exact = {
            let mut out = Vec::with_capacity(receipt_bytes.len() + 32);
            cbor::array(&mut out, 5);
            cbor::uint(&mut out, 1);
            cbor::uint(&mut out, outcome.code());
            cbor::bytes(&mut out, &receipt_bytes);
            match &checkpoint_bytes {
                Some(bytes) => cbor::bytes(&mut out, bytes),
                None => cbor::null(&mut out),
            }
            cbor::empty_extension(&mut out);
            out
        };
        Self {
            outcome,
            receipt_bytes,
            checkpoint_bytes,
            exact,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 5)?;
        cbor_read::expect_version(&mut decoder)?;
        let outcome = EntryCommitOutcome::from_code(cbor_read::uint(&mut decoder)?)?;
        let receipt_bytes = cbor_read::bytes(&mut decoder)?.to_vec();
        let checkpoint_bytes = cbor_read::optional_bytes(&mut decoder)?.map(<[u8]>::to_vec);
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let response = Self::new(outcome, receipt_bytes, checkpoint_bytes);
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
    pub const fn outcome(&self) -> EntryCommitOutcome {
        self.outcome
    }

    #[must_use]
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    #[must_use]
    pub fn checkpoint_bytes(&self) -> Option<&[u8]> {
        self.checkpoint_bytes.as_deref()
    }
}

impl fmt::Debug for EntryCommitResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntryCommitResponseV1(<bound>)")
    }
}

/// Der Rahmenaufschlag eines Einzelobjekt-Uploads.
///
/// `[1, bstr, []]` kostet einen Arraykopf, die Versionszahl, den `bstr`-Kopf
/// und das leere Erweiterungsarray. Sechzehn Byte decken das fuer jede
/// Objektlaenge dieser Version mit Reserve ab. Die Konstante existiert, damit
/// Erzeugung und Dekodierung dieselbe Grenze auf dasselbe MESSEN: die
/// Objektdecke gilt fuer die Objektbytes, der Rahmen wird getrennt begrenzt.
const SINGLE_OBJECT_FRAME_OVERHEAD_V1: usize = 16;

/// Ein Upload, der aus genau EINEM exakten Archivobjekt besteht.
///
/// Drei Endpunkte teilen sich diese Form — `POST /v1/trust/events`,
/// `POST /v1/entries/{entryHash}/historical-grants` und
/// `POST /v1/destructions`. Sie unterscheiden sich in der erwarteten
/// Objektart und in ihrer Objektdecke; beides gibt die Huelle unten als
/// Argument herein.
///
/// Geprueft wird hier das Exact-Object-PRAEFIX, nicht das ganze Objekt: die
/// Rahmenschicht entscheidet, ob ueberhaupt die richtige Objektfamilie
/// geliefert wurde, und die vollstaendige Pruefung von Signatur, Trust und
/// Autorisierung bleibt beim Dienst. Ohne diesen Schritt liefe ein `.eip` durch
/// den Rahmen von `POST /v1/trust/events`.
#[derive(Clone, Eq, PartialEq)]
struct SingleObjectUploadV1 {
    exact_object_bytes: Vec<u8>,
    exact: Vec<u8>,
}

/// Das Neun-Byte-Praefix der Objektfamilie.
const fn exact_object_prefix(object_type: ObjectTypeV1) -> [u8; 9] {
    match object_type {
        ObjectTypeV1::Entry => ea_format::EIP_PREFIX_V1,
        ObjectTypeV1::Grant => ea_format::EAG_PREFIX_V1,
        ObjectTypeV1::Receipt => ea_format::ESR_PREFIX_V1,
        ObjectTypeV1::Evidence => ea_format::ECP_PREFIX_V1,
        ObjectTypeV1::Trust => ea_format::ETB_PREFIX_V1,
        ObjectTypeV1::Destroyed => ea_format::EDS_PREFIX_V1,
    }
}

impl SingleObjectUploadV1 {
    fn new(
        exact_object_bytes: Vec<u8>,
        object_type: ObjectTypeV1,
        object_limit: usize,
        limit_error: SyncProtocolError,
    ) -> Result<Self, SyncProtocolError> {
        if exact_object_bytes.len() > object_limit {
            return Err(limit_error);
        }
        if !exact_object_bytes.starts_with(&exact_object_prefix(object_type)) {
            return Err(SyncProtocolError::ObjectTypeMismatch);
        }
        let mut exact =
            Vec::with_capacity(exact_object_bytes.len() + SINGLE_OBJECT_FRAME_OVERHEAD_V1);
        cbor::array(&mut exact, 3);
        cbor::uint(&mut exact, 1);
        cbor::bytes(&mut exact, &exact_object_bytes);
        cbor::empty_extension(&mut exact);
        Ok(Self {
            exact_object_bytes,
            exact,
        })
    }

    fn decode(
        bytes: &[u8],
        object_type: ObjectTypeV1,
        object_limit: usize,
        limit_error: SyncProtocolError,
    ) -> Result<Self, SyncProtocolError> {
        // Der Koerper darf genau die Objektdecke PLUS den Rahmenaufschlag
        // wiegen. Waere hier dieselbe Zahl wie fuer das Objekt gepruefft, wiese
        // `decode` genau die Rahmen zurueck, die `new` gerade erzeugt hat.
        if bytes.len() > object_limit.saturating_add(SINGLE_OBJECT_FRAME_OVERHEAD_V1) {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 3)?;
        cbor_read::expect_version(&mut decoder)?;
        let exact_object_bytes = cbor_read::bytes(&mut decoder)?.to_vec();
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let upload = Self::new(exact_object_bytes, object_type, object_limit, limit_error)?;
        if upload.exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(upload)
    }
}

macro_rules! single_object_upload {
    ($name:ident, $object_type:expr, $limit:expr, $limit_error:expr, $accessor:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(SingleObjectUploadV1);

        impl $name {
            pub fn new(exact_object_bytes: Vec<u8>) -> Result<Self, SyncProtocolError> {
                SingleObjectUploadV1::new(exact_object_bytes, $object_type, $limit, $limit_error)
                    .map(Self)
            }

            pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
                SingleObjectUploadV1::decode(bytes, $object_type, $limit, $limit_error).map(Self)
            }

            #[must_use]
            pub fn exact_bytes(&self) -> &[u8] {
                &self.0.exact
            }

            #[must_use]
            pub fn $accessor(&self) -> &[u8] {
                &self.0.exact_object_bytes
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<bound>)"))
            }
        }
    };
}

single_object_upload!(
    TrustEventUploadV1,
    ObjectTypeV1::Trust,
    ea_format::ETB_MAX_RAW_BYTES_V1,
    SyncProtocolError::BodyLimit,
    exact_etb_bytes,
    "`trust-event-upload-v1` — genau ein exaktes `.etb`."
);
single_object_upload!(
    HistoricalGrantUploadV1,
    ObjectTypeV1::Grant,
    MAX_GRANT_OBJECT_BYTES_V1,
    SyncProtocolError::GrantLimit,
    exact_eag_bytes,
    "`historical-grant-upload-v1` — genau ein exaktes `.eag`."
);
single_object_upload!(
    DestructionRequestV1,
    ObjectTypeV1::Trust,
    ea_format::ETB_MAX_RAW_BYTES_V1,
    SyncProtocolError::BodyLimit,
    exact_authorization_etb_bytes,
    "`destruction-request-v1` — genau eine exakte `DestructionAuthorization` als `.etb`."
);
