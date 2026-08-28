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

impl PreparedTransactionV1 {
    /// Rechnet die Marke gegen IHRE EIGENEN BYTES und gegen den Inhalt nach,
    /// den sie traegt.
    ///
    /// # Warum das Dekodieren allein nicht reicht
    ///
    /// [`Self::decode`] belegt die GESTALT und sonst nichts. Eine Marke, die
    /// diese Gestalt hat, aber einen fremden Objekthash, einen fremden
    /// `entryHash` oder einen Grant-Plan-Hash nennt, den das eingebettete
    /// `.eip` nicht signiert, wuerde ohne diese Nachrechnung hinter der
    /// unwiderruflichen Grenze VOLLENDET — und zwar ausgerechnet auf dem
    /// einzigen Weg, der keine zweite Gelegenheit zur Pruefung mehr hat.
    /// `design.md` §9.4 verlangt umgekehrt, dass vorab veroeffentlichte Grants
    /// „nur von der ZUGEHOERIGEN vorbereiteten Transaktion uebernommen" werden;
    /// die Zugehoerigkeit ist genau das, was `grant_plan_hash` behauptet, und
    /// bis hierher hat sie niemand nachgerechnet.
    ///
    /// Fuenf Aussagen, jede gegen eine ANDERE Quelle:
    ///
    /// 1. Die Marke kodiert sich BYTEGLEICH zurueck. Damit ist sie kanonisch
    ///    und traegt keinen Anhang, den der Dekodierer ueberliest.
    /// 2. Die Grantliste ist NICHT leer. Der Plan traegt „genau einen aktiven
    ///    Recovery-Empfaenger und ausnahmslos jedes aktive Reader-Zertifikat"
    ///    (`design.md` §9.3 Schritt 5), ist also nie leer; eine leere Liste
    ///    ergaebe einen Eintrag, den kein Recovery-Empfaenger je oeffnet.
    /// 3. Jeder Grant liegt unter SEINEM Objekthash — derselbe Hash, aus dem
    ///    [`Self::targets`] die Zieladresse bildet.
    /// 4. Die Eintragsbytes tragen den genannten Objekthash, den genannten
    ///    `entryHash` UND die genannte Sequenz.
    /// 5. Der `grant_plan_hash` der Marke ist der `initialGrantPlanHash`, den
    ///    das `.eip` SIGNIERT.
    ///
    /// Die Sequenz gehoert ausdruecklich zu Aussage 4 und nicht zu Aussage 1:
    /// sie ist der EINZIGE Wert der Marke, den nichts ausserhalb ihrer selbst
    /// belegt, also spielt das Rueckkodieren einen manipulierten Wert
    /// bytegleich wieder ab. Erst das signierte `manifestCore` ist eine zweite
    /// Quelle — und aus genau diesem Feld bildet [`Self::targets`] den
    /// Zielnamen des `.eip`.
    ///
    /// # Warum nur die WIEDERAUFNAHME sie ruft und nicht auch der glatte Lauf
    ///
    /// Nicht, weil dort die exakten Bytes fehlten — Schritt 8 bildet sie mit
    /// `transaction.encode()`. Sondern weil die Nachrechnung dort
    /// TAUTOLOGISCH waere: die Marke und das `manifestCore` nehmen ihren
    /// Plan-Hash aus DEMSELBEN `state.grant_plan`, `entryHash` und Objekthash
    /// entstehen aus denselben Bytes, und ein Vergleich zweier Kopien einer
    /// Quelle ist keine Messung. Erst nach einem Neustart ist die Marke eine
    /// FREMDE Eingabe aus der Ablage, und erst dann sagt der Vergleich etwas.
    ///
    /// # Errors
    ///
    /// [`WriterError::PreparedFinalizationInconsistent`] fuer jede der fuenf
    /// Aussagen — fail-closed und ohne Teilausgabe.
    ///
    /// Aussage 1 kodiert dafuer zurueck, und [`Self::encode`] hat eine eigene,
    /// ENGERE Fehlermenge ([`WriterError::PreparedFinalizationUnreadable`],
    /// [`WriterError::LocalRng`]). Sie wird UNVERAENDERT durchgereicht und
    /// nicht auf den Code oben abgebildet: „diese Marke laesst sich gar nicht
    /// kodieren" ist eine andere Aussage als „sie widerspricht sich selbst",
    /// und ein umetikettierter Code verschwiege sie. Erreichbar ist sie hier
    /// ohnehin nicht — der Wert ist gerade erst aus denselben Bytes dekodiert
    /// worden —, und genau deshalb wird sie benannt statt verschluckt.
    pub(crate) fn verify(&self, exact: &[u8]) -> Result<(), WriterError> {
        let inconsistent = || WriterError::PreparedFinalizationInconsistent;
        if self.encode()? != exact {
            return Err(inconsistent());
        }
        if self.grant_object_hashes.len() != self.grant_bytes.len() || self.grant_bytes.is_empty() {
            return Err(inconsistent());
        }
        for (hash, bytes) in self.grant_object_hashes.iter().zip(&self.grant_bytes) {
            let parsed = ea_format::decode_exact_object(bytes).map_err(|_| inconsistent())?;
            let ea_format::ParsedArchiveObject::Grant(grant) = &parsed else {
                return Err(inconsistent());
            };
            if grant.object_hash().as_bytes() != hash.as_bytes() {
                return Err(inconsistent());
            }
        }
        let parsed =
            ea_format::decode_exact_object(&self.entry_bytes).map_err(|_| inconsistent())?;
        let ea_format::ParsedArchiveObject::Entry(entry) = &parsed else {
            return Err(inconsistent());
        };
        if entry.object_hash().as_bytes() != self.entry_object_hash.as_bytes() {
            return Err(inconsistent());
        }
        if entry.value().entry_hash().as_bytes() != self.entry_hash.as_bytes() {
            return Err(inconsistent());
        }
        if entry.value().manifest().fields().chain_sequence != self.sequence {
            return Err(inconsistent());
        }
        if entry
            .value()
            .manifest()
            .fields()
            .initial_grant_plan_hash
            .as_slice()
            != self.grant_plan_hash.as_slice()
        {
            return Err(inconsistent());
        }
        Ok(())
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
