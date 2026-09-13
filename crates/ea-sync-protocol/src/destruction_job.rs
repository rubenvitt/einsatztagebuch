//! Approved additive transport for the existing internal signed preflight.
use crate::{
    MAX_READER_PAGE_BYTES_V1, PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError as Error, cbor,
};
use ea_types::CertificateHash;
use minicbor::Decoder;
#[derive(Clone, Eq, PartialEq)]
pub struct DestructionJobUploadV1 {
    exact: Vec<u8>,
    core: Vec<u8>,
    signature: Vec<u8>,
    inventory: Vec<u8>,
    certificate: CertificateHash,
}
impl DestructionJobUploadV1 {
    pub fn decode(exact: &[u8]) -> Result<Self, Error> {
        if exact.len() > MAX_READER_PAGE_BYTES_V1 {
            return Err(Error::FrameShape);
        }
        ea_cbor::validate(exact, PROTOCOL_PARSER_LIMITS_V1).map_err(|_| Error::FrameShape)?;
        let mut d = Decoder::new(exact);
        if d.array().map_err(|_| Error::FrameShape)? != Some(4) {
            return Err(Error::FrameShape);
        }
        let core = d.bytes().map_err(|_| Error::FrameShape)?.to_vec();
        let signature = d.bytes().map_err(|_| Error::FrameShape)?.to_vec();
        let inventory = d.bytes().map_err(|_| Error::FrameShape)?.to_vec();
        let certificate = CertificateHash::try_from(d.bytes().map_err(|_| Error::FrameShape)?)
            .map_err(|_| Error::FrameShape)?;
        if d.position() != exact.len()
            || core.is_empty()
            || signature.is_empty()
            || inventory.is_empty()
        {
            return Err(Error::FrameShape);
        }
        Ok(Self {
            exact: exact.to_vec(),
            core,
            signature,
            inventory,
            certificate,
        })
    }
    pub fn new(
        core: &[u8],
        signature: &[u8],
        inventory: &[u8],
        certificate: CertificateHash,
    ) -> Result<Self, Error> {
        let mut exact = Vec::new();
        cbor::array(&mut exact, 4);
        for value in [core, signature, inventory, certificate.as_bytes()] {
            cbor::bytes(&mut exact, value);
        }
        Self::decode(&exact)
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub fn core_bytes(&self) -> &[u8] {
        &self.core
    }
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
    pub fn inventory_bytes(&self) -> &[u8] {
        &self.inventory
    }
    pub fn certificate_hash(&self) -> CertificateHash {
        self.certificate
    }
}
