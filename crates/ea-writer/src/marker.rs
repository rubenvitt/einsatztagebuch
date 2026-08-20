//! Die vorbereitete Transaktion — der DAUERHAFTE Fortschrittsmarker.
//!
//! Sie ist der „gehashte Transaktionsdeskriptor" von `design.md` §9.3
//! Schritt 8: sie nennt jede Zieladresse, traegt jedes Byte, das
//! veroeffentlicht werden soll, und bindet sich mit ihrem eigenen Hash an
//! diesen Inhalt. Sie liegt in der verschluesselten Ablage als
//! [`PreparedFinalizationMarker`](ea_draft::PreparedFinalizationMarker) und
//! ist mit der Verwerfensabsicht aus Task 7 dieselbe Singletonzeile — beide
//! sind damit durch die Bauweise gegenseitig ausschliessend.
//!
//! # Warum die Bytes IN der Marke liegen
//!
//! Nach der bestaetigten Loeschung des `draftDEK` darf die Wiederherstellung
//! „weder neu serialisieren noch neue Zufallswerte erzeugen" (`design.md`
//! §9.4). Sie muss die exakten Bytes also FINDEN. Die Staging-Dateien tragen
//! sie ebenfalls, aber nur die Marke sagt, welche Staging-Datei zu WELCHER
//! Transaktion gehoert — und genau diese Zuordnung entscheidet, ob ein
//! vorab veroeffentlichter Grant uebernommen oder bereinigt wird.

use ea_archive::{
    ArchiveBackendError, ArchivePath, ENTRIES_DIR_V1, GRANTS_DIR_V1, STAGING_SUFFIX_V1,
};
use ea_types::{ChainSequence, EntryHash, Hash32, ObjectHash};
use minicbor::{Decoder, Encoder};

use crate::WriterError;

/// Die Strukturversion der Marke. Der Kodierer schreibt sie.
const MARKER_VERSION_V1: u64 = 1;

/// Alles, was aus den vorbereiteten Bytes einen Bestand macht.
pub(crate) struct PreparedTransactionV1 {
    pub(crate) sequence: ChainSequence,
    pub(crate) entry_hash: EntryHash,
    pub(crate) entry_object_hash: ObjectHash,
    pub(crate) entry_bytes: Vec<u8>,
    pub(crate) grant_object_hashes: Vec<Hash32>,
    pub(crate) grant_bytes: Vec<Vec<u8>>,
    /// Der `initialGrantPlanHash`. Er steht MIT in der Marke, damit die
    /// Wiederherstellung belegen kann, dass die uebernommenen Grants zu dem
    /// Plan gehoeren, den das `.eip` signiert.
    pub(crate) grant_plan_hash: Vec<u8>,
}

/// Die Zieladressen einer vorbereiteten Transaktion, in
/// VEROEFFENTLICHUNGSREIHENFOLGE: jeder Grant, dann das `.eip`.
pub(crate) struct PreparedTargetsV1 {
    pub(crate) grants: Vec<ArchivePath>,
    pub(crate) entry: ArchivePath,
}

impl PreparedTransactionV1 {
    /// Die Zieladressen nach §11.4.
    ///
    /// `entries/<12-stellige-nullgepolsterte-Sequenz>_<entry-hash>.eip` und
    /// `grants/<entry-hash>_<grant-object-hash>.eag`.
    pub(crate) fn targets(&self) -> Result<PreparedTargetsV1, ArchiveBackendError> {
        let entry_hex = hex(self.entry_hash.as_bytes());
        let entry = ArchivePath::in_dir(
            ENTRIES_DIR_V1,
            &format!("{:012}_{entry_hex}.eip", self.sequence.get()),
        )?;
        let grants = self
            .grant_object_hashes
            .iter()
            .map(|hash| {
                ArchivePath::in_dir(
                    GRANTS_DIR_V1,
                    &format!("{entry_hex}_{}.eag", hex(hash.as_bytes())),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedTargetsV1 { grants, entry })
    }

    /// Die Staging-Adressen mit ihren Bytes, in derselben Reihenfolge.
    ///
    /// Der Suffix liegt im ZIELVERZEICHNIS; damit ist der spaetere Rename schon
    /// durch die Bauweise dateisystemintern.
    pub(crate) fn staged_pairs<'a>(
        &'a self,
        targets: &PreparedTargetsV1,
    ) -> Result<Vec<(ArchivePath, &'a [u8])>, ArchiveBackendError> {
        let mut pairs = Vec::with_capacity(self.grant_bytes.len() + 1);
        for (target, bytes) in targets.grants.iter().zip(&self.grant_bytes) {
            pairs.push((staging_path(target)?, bytes.as_slice()));
        }
        pairs.push((staging_path(&targets.entry)?, self.entry_bytes.as_slice()));
        Ok(pairs)
    }

    /// Die exakten Markenbytes — deterministisches CBOR.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, WriterError> {
        let mut bytes = Vec::with_capacity(self.entry_bytes.len() + 512);
        let mut encoder = Encoder::new(&mut bytes);
        let grant_count =
            u64::try_from(self.grant_bytes.len()).map_err(|_| WriterError::LocalRng)?;
        encoder
            .array(7)
            .and_then(|encoder| encoder.u64(MARKER_VERSION_V1))
            .and_then(|encoder| encoder.u64(self.sequence.get()))
            .and_then(|encoder| encoder.bytes(self.entry_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.entry_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(&self.grant_plan_hash))
            .and_then(|encoder| encoder.bytes(&self.entry_bytes))
            .and_then(|encoder| encoder.array(grant_count))
            .map_err(|_| WriterError::PreparedFinalizationUnreadable)?;
        for (hash, grant) in self.grant_object_hashes.iter().zip(&self.grant_bytes) {
            encoder
                .array(2)
                .and_then(|encoder| encoder.bytes(hash.as_bytes()))
                .and_then(|encoder| encoder.bytes(grant))
                .map_err(|_| WriterError::PreparedFinalizationUnreadable)?;
        }
        Ok(bytes)
    }

    /// Liest eine Marke zurueck.
    ///
    /// Fail-closed: eine Marke, die nicht die Gestalt dieses Baustands hat,
    /// wird NICHT halb gelesen.
    pub(crate) fn decode(input: &[u8]) -> Result<Self, WriterError> {
        let mut decoder = Decoder::new(input);
        let shape = || WriterError::PreparedFinalizationUnreadable;
        if decoder.array().map_err(|_| shape())? != Some(7) {
            return Err(shape());
        }
        if decoder.u64().map_err(|_| shape())? != MARKER_VERSION_V1 {
            return Err(shape());
        }
        let sequence = ChainSequence::new(decoder.u64().map_err(|_| shape())?);
        let entry_hash =
            EntryHash::try_from(decoder.bytes().map_err(|_| shape())?).map_err(|_| shape())?;
        let entry_object_hash =
            ObjectHash::try_from(decoder.bytes().map_err(|_| shape())?).map_err(|_| shape())?;
        let grant_plan_hash = decoder.bytes().map_err(|_| shape())?.to_vec();
        let entry_bytes = decoder.bytes().map_err(|_| shape())?.to_vec();
        let grant_count = decoder.array().map_err(|_| shape())?.ok_or_else(shape)?;
        let mut grant_object_hashes = Vec::new();
        let mut grant_bytes = Vec::new();
        for _ in 0..grant_count {
            if decoder.array().map_err(|_| shape())? != Some(2) {
                return Err(shape());
            }
            grant_object_hashes.push(
                Hash32::try_from(decoder.bytes().map_err(|_| shape())?).map_err(|_| shape())?,
            );
            grant_bytes.push(decoder.bytes().map_err(|_| shape())?.to_vec());
        }
        if decoder.position() != input.len() {
            return Err(shape());
        }
        Ok(Self {
            sequence,
            entry_hash,
            entry_object_hash,
            entry_bytes,
            grant_object_hashes,
            grant_bytes,
            grant_plan_hash,
        })
    }
}

/// Die Staging-Adresse zu einer Zieladresse — derselbe Suffix wie in
/// [`ea_archive::ArchiveTransaction`], im SELBEN Layoutverzeichnis.
pub(crate) fn staging_path(target: &ArchivePath) -> Result<ArchivePath, ArchiveBackendError> {
    let directory = target.directory();
    let relative = &target.as_str()[directory.len()..];
    if directory.is_empty() {
        return Err(ArchiveBackendError::Path);
    }
    ArchivePath::in_dir(directory, &format!("{relative}{STAGING_SUFFIX_V1}"))
}

/// Kleinbuchstaben-Hex, wie jeder Dateiname des Layouts.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}
