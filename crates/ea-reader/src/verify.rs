//! Die Verifikation VOR der Entschluesselung und die Zustandssprache aus
//! `design.md` §17.4.
//!
//! # Hier entsteht KEIN Gate
//!
//! `crates/ea-verify` besitzt alle neun, [`crate::GATE_ORDER_V1`] ist ihre
//! einzige Quelle, und kein Gate-Bezeichner wird hier ein zweites Mal als
//! Literal geschrieben. [`ReaderVerifier::classify`] RUFT
//! `ea_verify::verify_archive_observed` und uebersetzt dessen Bericht; es baut
//! die Pipeline nicht nach. Es faehrt ausserdem kein OPFS-I/O, keinen
//! Netzaufruf und keine Indizierung.
//!
//! # Die zwei Bindungen, die dieser Schritt neu zieht
//!
//! `web-reader-design.md` §12 fordert fuer den Rustkern ausdruecklich nur neue
//! BINDUNGEN und keine neue Rechnung. Es sind genau zwei: der Entkapseler nimmt
//! den X25519-Schluessel aus der Vault-Sitzung statt aus einem nativen
//! Schluesselspeicher — §11.3 streicht den ersatzlos —, und der
//! `TrustAnchorV1`, der an die Pipeline geht, kommt ueber
//! [`crate::PinnedTrustAnchor`] ausschliesslich aus dem Tresor.
//!
//! # Warum diese Crate ein ZWEITES Inventar baut
//!
//! Der Bericht kennt ueber Objekte NUR den `ObjectHash`: `ObjectResultV1` hat
//! vier Zugriffe und weder `entry_hash` noch `chain_sequence`, `ObjectErrorV1`
//! traegt `object_hash` und `code`, `ChainGapV1` eine Kettenkennung und ein
//! Sequenzintervall. In `crates/ea-verify` gibt es keinen Accessor, der einen
//! `ObjectHash` auf einen `EntryHash` abbildet. [`ReaderClassification`] baut
//! deshalb selbst `ea_archive::ArchiveInventory::build(source)` und BESITZT es;
//! daraus entstehen der Join `ObjectHash → (EntryHash, ChainSequence)`, der Join
//! eigener Grant → Eintrag und die exakten Bytes der zwei Zeugen, also ohne
//! eine dritte Kopie. Der Preis ist ein zweiter voller Parserlauf ueber
//! denselben Bestand je Klassifikation. Die billigere Alternative waere,
//! `ea-verify` sein Inventar herausgeben zu lassen — eine Erweiterung einer
//! abgeschlossenen Stufe-1-Crate, und hier ausgeschlossen.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_format::{
    DecodedTrustPayloadV1, DestroyedEntryStubV1, EntryPackageV1, FormatError, GrantKindV1, GrantV1,
    Parsed,
};
use ea_types::{
    ChainSequence, DestructionId, EntryHash, EntryStatus, KeyThumbprint, ObjectHash, UnixMillis,
    VerificationStatus,
};
use ea_verify::{
    ChainGapV1, DecryptionErrorV1, GateObserver, ObjectErrorV1, ObjectResultKindV1,
    QuarantinedObjectV1, ServerConfirmationV1, VerificationReportV1, VerifyError, VerifyOptions,
    verify_archive_observed,
};

use crate::anchor::PinnedTrustAnchor;
use crate::entry_state::{ReaderEntryStateV1, persistable_detail_code};
use crate::grant::{VerifiedEncryptedEntry, VerifiedGrantForRecipient};
use crate::mode::ReaderMode;
use crate::vault::UnlockedVault;

/// Jeder Befund, der einen Reader-Lauf ALS GANZES abbricht.
///
/// Bauform von [`crate::ReaderVaultError`]: flaches Aufzaehlungswerk, ein
/// stabiler Code je Arm, FREMDE Codes DURCHGEREICHT, [`fmt::Display`] schreibt
/// ausschliesslich den Code, [`fmt::Debug`] delegiert an [`fmt::Display`].
///
/// # Zwei eigene Codes und sonst keiner
///
/// `EA-READER-WITNESS-STALE` und `EA-READER-SCHEMA-UNSUPPORTED`.
/// `EA-READER-VERIFICATION` ist AUSGESCHLOSSEN — `ReaderSyncError::Verification`
/// belegt ihn bereits, und ein zweiter Traeger desselben Codes waere genau die
/// Doppelschreibung, die dieses Repositorium verbietet. Der Name kollidiert
/// mit `ea_sync_server::ReaderError`; jede Datei, die beide sieht, aliast, und
/// keine der beiden Crates haengt an der anderen.
///
/// # KEIN Arm fuer `ea_trust::TrustError` und keiner fuer `ea_schema::SchemaError`
///
/// Beide haetten hier keinen Erzeuger. [`crate::PinnedTrustAnchor::from_vault`]
/// ist INFALLIBEL — `UnlockedVault::pinned_anchor` ist ein Pflichtfeld —, es
/// dekodiert nichts und kann folglich keinen `TrustError` liefern. Und die
/// Schemabestimmung von [`crate::decrypt_verified`] probiert alle Deskriptoren
/// durch und faellt erst, wenn KEINER traegt; die einzelnen `SchemaError` sind
/// dann Zwischenstaende und keine Aussage ueber den Lauf. Ein Arm, den kein
/// Zeuge faerben kann, ist kein fail-closed-Verhalten, sondern ein unbelegter
/// Zweig, den die Oberflaeche spaeter behandeln muesste, ohne ihn je zu sehen.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderError {
    /// Ueber diesen Bestand liess sich gar kein Bericht bilden.
    ///
    /// Ein Befund ueber ein EINZELNES Objekt ist nie ein `Err` — dieselbe
    /// Regel, die `crates/ea-verify/src/lib.rs` ausschreibt.
    Verify(VerifyError),
    /// Die exakten Objektbytes eines Zeugen liessen sich nicht erneut lesen.
    ///
    /// Durch Konstruktion unerreichbar: die Bytes stammen aus einem bereits
    /// erfolgreich geparsten Objekt desselben Inventars. Der Arm steht
    /// trotzdem, weil `ea_format::decode_exact_object` fehlbar IST und ein
    /// stillschweigendes `expect` auf feindlichen Bytes das Falsche waere.
    Format(FormatError),
    /// Die Entkapselung oder die AEAD-Oeffnung hat nicht getragen.
    ///
    /// Der Code kommt unveraendert aus `ea_verify::DecryptionErrorV1` — die
    /// Rechnung ist dieselbe wie in `crates/ea-verify/src/recipient.rs`, und
    /// zwei Codes fuer denselben Fehlschlag waeren zwei Wahrheiten darueber.
    Decryption(DecryptionErrorV1),
    /// Der Zeuge stammt aus einem anderen Klassifikationslauf.
    StaleWitness,
    /// Keine der Schemabestimmungen traegt diesen Klartext.
    UnsupportedSchema,
}

impl ReaderError {
    /// Der stabile Code des Befunds.
    ///
    /// Zusicherungen stehen gegen ihn und nie gegen eine Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Verify(error) => error.code(),
            Self::Format(error) => error.code(),
            Self::Decryption(error) => error.code(),
            Self::StaleWitness => "EA-READER-WITNESS-STALE",
            Self::UnsupportedSchema => "EA-READER-SCHEMA-UNSUPPORTED",
        }
    }
}

impl From<VerifyError> for ReaderError {
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

impl From<FormatError> for ReaderError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<DecryptionErrorV1> for ReaderError {
    fn from(error: DecryptionErrorV1) -> Self {
        Self::Decryption(error)
    }
}

impl fmt::Display for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderError {}

/// Der Klassifizierer EINER Sitzung ueber EINEM Zeitwert.
///
/// # Der Modus wird NICHT gelesen
///
/// `web-reader-design.md` §5.4 lautet woertlich „Die Reihenfolge aus Design
/// §14.1 gilt in beiden Modi wortgleich"; `verify_archive_observed` kennt gar
/// keinen Modusparameter, und `confirm_entries` bestimmt die
/// Server-Bestaetigung ohnehin aus den VORHANDENEN Quittungen — der
/// Datei-Modus ist fuer die Pipeline schlicht ein Bestand ohne `.esr`. Der
/// Modus wird deshalb GETRAGEN und nirgends in [`VerifyOptions`] gefaltet; er
/// benennt, woher der Aufrufer seine Quelle nimmt, und das entscheidet der
/// Aufrufer.
///
/// # EIN Zeitwert je Lauf
///
/// `VerifyOptions::effective_now()` ist wortgleich `os_wall_clock()`; es gibt je
/// Lauf genau EINEN Zeitwert, und Gate `recipient-grant` misst die Nutzungsfrist
/// des eigenen Grants gegen ihn. Derselbe Wert geht spaeter an
/// [`crate::decrypt_verified`], statt dort neu aus der Wirtsuhr gelesen zu
/// werden — ein je Entkapselung frisch gelesener Wert waere in
/// Millisekundenaufloesung praktisch nie gleich und machte die Entschluesselung
/// unmoeglich. Die Kehrseite ist benannt und gehoert woanders hin: friert eine
/// lange Sitzung ihren `effectiveNow` ein, bemerkt sie das Ablaufen eines
/// Registrierungskopfes nicht; die Neuklassifikation bei Sitzungsalter besitzt
/// die Reader-Oberflaeche.
pub struct ReaderVerifier {
    mode: ReaderMode,
    effective_now: UnixMillis,
}

impl ReaderVerifier {
    /// Ein Klassifizierer fuer einen Modus und eine Uhr.
    #[must_use]
    pub const fn new(mode: ReaderMode, effective_now: UnixMillis) -> Self {
        Self {
            mode,
            effective_now,
        }
    }

    /// Der Modus, in dem dieser Reader seine Bytes bezieht.
    ///
    /// Er wird von [`Self::classify`] ausdruecklich NICHT gelesen; siehe den
    /// Typkommentar.
    #[must_use]
    pub const fn mode(&self) -> ReaderMode {
        self.mode
    }

    /// Die Uhr dieses Laufs.
    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.effective_now
    }

    /// Faehrt die neun Gates aus `design.md` §14.1 UEBER
    /// `ea_verify::verify_archive_observed` und uebersetzt den Bericht in die
    /// Zustandssprache aus §17.4.
    ///
    /// # Errors
    ///
    /// Der Fehler von `ea_verify::verify_archive_observed` und der von
    /// `ea_archive::ArchiveInventory::build`, beide als
    /// [`ReaderError::Verify`]. Ein Befund ueber ein EINZELNES Objekt ist nie
    /// ein `Err` — auch ein Fehlschlag von Gate `trust` liefert `Ok`, ist aber
    /// fail-closed fuer den ganzen Bestand.
    pub fn classify(
        &self,
        source: &dyn ArchiveSource,
        session: &UnlockedVault,
        observer: &mut dyn GateObserver,
    ) -> Result<ReaderClassification, ReaderError> {
        let anchor = PinnedTrustAnchor::from_vault(session);
        let options = VerifyOptions::new(self.effective_now)
            .with_recipient(session.kem_key_thumbprint(), session.kem_private_key());
        let report = verify_archive_observed(source, anchor.as_trust_anchor(), options, observer)?;
        let inventory = ArchiveInventory::build(source).map_err(VerifyError::from)?;

        let findings = ReportFindingsV1::collect(&report);
        let mut rows: BTreeMap<EntryHash, ReaderEntryStateV1> = BTreeMap::new();
        let mut witnesses: BTreeMap<EntryHash, DecryptionWitnessesV1> = BTreeMap::new();

        // FAIL-CLOSED FUER DEN GANZEN BESTAND. `verify_archive_observed` steigt
        // nach `protocol.enter(Gate::Trust)` mit `return report.seal()` aus,
        // wenn die Vertrauenskette nicht traegt, und sagt dann ueber KEIN Objekt
        // etwas — `objectResults`, `registryVersions` und alle sechs
        // Mangelfelder bleiben leer. Ohne diese Schranke bekaeme jeder Eintrag
        // eines untergeschobenen Bestands eine Zeile, und eine Zeile IST eine
        // Aussage.
        //
        // `publicKeyThumbprints` ist der exakte Zeuge dafuer: der Lauf traegt
        // `anchor.root_key_thumbprint()` unmittelbar HINTER dem Ausstieg ein —
        // „ERST HINTER DEM FAIL-CLOSED-AUSSTIEG, nie davor" — und davor
        // ueberhaupt nichts. Leer heisst also genau: Gate `trust` hat nicht
        // getragen.
        if report.public_key_thumbprints().next().is_some() {
            let key_thumbprint = session.kem_key_thumbprint();
            for entry in inventory.entries() {
                let row = classify_entry(
                    &findings,
                    &inventory,
                    entry,
                    key_thumbprint,
                    self.effective_now,
                );
                if let Some(witness) = row.witnesses {
                    witnesses.insert(row.state.entry_hash(), witness);
                }
                rows.insert(row.state.entry_hash(), row.state);
            }
            for stub in inventory.destroyed() {
                if let Some(state) = classify_stub(&findings, &inventory, stub, &rows) {
                    rows.insert(state.entry_hash(), state);
                }
            }
        }

        // NACH KETTENSEQUENZ und erst danach nach Eintragshash: das ist die
        // Ordnung, in der eine Kette gelesen wird, und `EntryHash` traegt keine.
        // Der Index daneben haelt [`ReaderClassification::state_of`] logarithmisch
        // — eine lineare Suche waere ueber 50.000 Paketen quadratisch.
        let mut states: Vec<ReaderEntryStateV1> = rows.into_values().collect();
        states.sort_by_key(|state| (state.sequence(), state.entry_hash()));
        let states_by_entry = states
            .iter()
            .enumerate()
            .map(|(position, state)| (state.entry_hash(), position))
            .collect();

        Ok(ReaderClassification {
            report,
            inventory,
            states,
            states_by_entry,
            witnesses,
        })
    }
}

impl fmt::Debug for ReaderVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderVerifier")
            .field("mode", &self.mode.code())
            .field("effective_now", &self.effective_now.get())
            .finish()
    }
}

/// Das Ergebnis EINER Klassifikation: Bericht, Inventar, Zustaende, Zeugen.
///
/// OHNE Lebensdauerparameter, weil das Inventar hier BESITZT wird — siehe den
/// Modulkommentar.
pub struct ReaderClassification {
    report: VerificationReportV1,
    inventory: ArchiveInventory,
    states: Vec<ReaderEntryStateV1>,
    states_by_entry: BTreeMap<EntryHash, usize>,
    witnesses: BTreeMap<EntryHash, DecryptionWitnessesV1>,
}

impl ReaderClassification {
    /// Der unveraenderte Bericht der neun Gates.
    #[must_use]
    pub const fn report(&self) -> &VerificationReportV1 {
        &self.report
    }

    /// Das Inventar, aus dem die Joins dieser Klassifikation stammen.
    #[must_use]
    pub const fn inventory(&self) -> &ArchiveInventory {
        &self.inventory
    }

    /// Alle Zustandszeilen, nach Kettensequenz und Eintragshash geordnet.
    ///
    /// Je `EntryHash` GENAU EINE Zeile. Eine Luecke OHNE Traeger steht hier
    /// ausdruecklich NICHT — sie hat weder `EntryHash` noch `ObjectHash` und
    /// ist allein ueber [`Self::gaps`] darstellbar.
    #[must_use]
    pub fn states(&self) -> &[ReaderEntryStateV1] {
        &self.states
    }

    /// Die Zustandszeile eines Eintrags.
    #[must_use]
    pub fn state_of(&self, entry_hash: EntryHash) -> Option<&ReaderEntryStateV1> {
        self.states_by_entry
            .get(&entry_hash)
            .and_then(|position| self.states.get(*position))
    }

    /// Die Kettenluecken, SEQUENZadressiert.
    ///
    /// Die zweite Zugriffsform neben [`Self::states`] und keine Zugabe:
    /// `ea_chain::ChainGap` ist ein Intervall FEHLENDER Sequenzen, und zu einer
    /// solchen Sequenz existiert per Definition kein Objekt.
    /// `ReaderEntryStateV1::new` verlangt aber `entry_hash`, `object_hash` UND
    /// `sequence` — eine traegerlose Luecke ist als Zustandszeile schlicht nicht
    /// schreibbar.
    ///
    /// DURCHGEREICHT und nicht nachgebaut: der Bericht ist die einzige Quelle
    /// dieser Intervalle.
    pub fn gaps(&self) -> impl ExactSizeIterator<Item = &ChainGapV1> + '_ {
        self.report.gaps()
    }

    /// Der Eintragszeuge, sofern dieser Eintrag den Entkapseler erreichen darf.
    ///
    /// `Some` genau dann, wenn [`Self::verified_grant`] es auch ist: die zwei
    /// Zeugen entstehen PAARWEISE, und das ist die Typfassung von
    /// `web-reader-design.md` §9. Ein Eintrag ohne oeffenbaren eigenen Grant
    /// bleibt sichtbar und gueltig — er hat nur nichts, womit man ihn oeffnen
    /// koennte, und dann darf auch kein halber Zeuge herausgehen.
    #[must_use]
    pub fn verified_entry(&self, entry_hash: EntryHash) -> Option<&VerifiedEncryptedEntry> {
        self.witnesses.get(&entry_hash).map(|pair| &pair.entry)
    }

    /// Der Grantzeuge; siehe [`Self::verified_entry`].
    #[must_use]
    pub fn verified_grant(&self, entry_hash: EntryHash) -> Option<&VerifiedGrantForRecipient> {
        self.witnesses.get(&entry_hash).map(|pair| &pair.grant)
    }
}

/// Die zwei Zeugen EINES Eintrags, unzertrennlich.
struct DecryptionWitnessesV1 {
    entry: VerifiedEncryptedEntry,
    grant: VerifiedGrantForRecipient,
}

/// Eine Zustandszeile samt den Zeugen, die sie gegebenenfalls freigibt.
struct ClassifiedEntryV1 {
    state: ReaderEntryStateV1,
    witnesses: Option<DecryptionWitnessesV1>,
}

/// Der Bericht, EINMAL in Nachschlagewerke gezogen.
///
/// Die Accessoren des Berichts liefern ITERATOREN und keine Sammlungen; sie
/// lassen sich nicht wiederverwenden, und ein Bestand mit N Eintraegen wuerde
/// sie sonst N-mal durchlaufen. Die Codes werden dabei mitgenommen und die
/// Quarantaene ohne einen: `QuarantinedObjectV1` traegt einen
/// `QuarantineReason` und KEINEN Code — `QuarantineReason::as_str()` liefert
/// ein Schemaliteral und keinen `EA-`-Code.
struct ReportFindingsV1 {
    object_results: BTreeMap<ObjectHash, (ObjectResultKindV1, ServerConfirmationV1)>,
    format_errors: BTreeSet<ObjectHash>,
    quarantined: BTreeSet<ObjectHash>,
    signature_errors: BTreeMap<ObjectHash, &'static str>,
    evidence_errors: BTreeMap<ObjectHash, &'static str>,
    decryption_errors: BTreeMap<ObjectHash, &'static str>,
    gaps: Vec<(ChainSequence, ChainSequence)>,
    /// Je Vorgang der Autorisierungshash, den die TRANSITIONEN authentifiziert
    /// haben — nicht der, den ein Stummel behauptet.
    authorized_destructions: BTreeMap<DestructionId, ObjectHash>,
}

impl ReportFindingsV1 {
    fn collect(report: &VerificationReportV1) -> Self {
        Self {
            object_results: report
                .object_results()
                .map(|result| {
                    (
                        result.object_hash(),
                        (result.result(), result.server_confirmation()),
                    )
                })
                .collect(),
            format_errors: report
                .format_errors()
                .map(ObjectErrorV1::object_hash)
                .collect(),
            quarantined: report
                .quarantined_objects()
                .map(QuarantinedObjectV1::object_hash)
                .collect(),
            signature_errors: report
                .signature_errors()
                .map(|error| (error.object_hash(), error.code()))
                .collect(),
            evidence_errors: report
                .evidence_errors()
                .map(|error| (error.object_hash(), error.code()))
                .collect(),
            decryption_errors: report
                .decryption_errors()
                .map(|error| (error.object_hash(), error.code()))
                .collect(),
            gaps: report
                .gaps()
                .map(|gap| (gap.from_sequence(), gap.through_sequence()))
                .collect(),
            authorized_destructions: report
                .authorized_destructions()
                .map(|destruction| {
                    (
                        destruction.destruction_id(),
                        destruction.authorization_object_hash(),
                    )
                })
                .collect(),
        }
    }

    /// Die Server-Bestaetigung eines Objekts — eine EIGENE Dimension.
    ///
    /// `design.md` §17.4 verbietet die Vermischung mit der Verifikation
    /// ausdruecklich, und `notServerConfirmed` ist KEIN Mangel: im Datei-Modus
    /// ist es der Regelfall.
    fn server_confirmation(&self, object_hash: ObjectHash) -> ServerConfirmationV1 {
        self.object_results
            .get(&object_hash)
            .map_or(ServerConfirmationV1::NotServerConfirmed, |result| result.1)
    }

    /// Ob der Bericht dieses Objekt als vollstaendig geprueft fuehrt.
    fn is_valid_result(&self, object_hash: ObjectHash) -> bool {
        matches!(
            self.object_results.get(&object_hash),
            Some((ObjectResultKindV1::Valid, _))
        )
    }

    /// Ob eine Sequenz in einem Lueckenintervall liegt.
    fn is_missing_sequence(&self, sequence: ChainSequence) -> bool {
        self.gaps
            .iter()
            .any(|(from, through)| *from <= sequence && sequence <= *through)
    }
}

/// Die Vorrangordnung ueber GENAU EINEM Eintrag.
///
/// ZWEI ADRESSRAEUME, GETRENNT AUSGEWERTET, und das ist die tragende Aussage
/// dieser Funktion. `claim_own_grants` schreibt
/// `report.signature_errors.insert(ObjectErrorV1::new(grant.object_hash(), …))`
/// und `record_decapsulation` schreibt seinen Befund ebenfalls unter den
/// Objekthash des GRANTS — waehrend der Eintrag sein
/// `ObjectResultKindV1::Valid` behaelt. Wer beide Raeume in eine Regel faltet,
/// stellt einen gueltigen Eintrag mit unbrauchbarem eigenem Grant als
/// `ungueltig` dar; `design.md` §17.4 fuehrt `fehlender Grant` und `unbekannter
/// Schluessel` aber als eigene Begriffe NEBEN `ungueltig`, und
/// `web-reader-design.md` §9 sagt woertlich: „Fehlender eigener Grant bleibt
/// exakt `fehlender Grant` und wird nicht als Beschaedigung dargestellt."
///
/// Die Ordnung ist TOTAL: jeder Eintrag bekommt genau eine Zeile, und keine
/// Dimension faellt mit einer anderen zusammen.
fn classify_entry(
    findings: &ReportFindingsV1,
    inventory: &ArchiveInventory,
    entry: &Parsed<EntryPackageV1>,
    key_thumbprint: KeyThumbprint,
    minted_at: UnixMillis,
) -> ClassifiedEntryV1 {
    let object_hash = entry.object_hash();
    let entry_hash = entry.value().entry_hash();
    let sequence = entry.value().manifest().fields().chain_sequence;
    let mut witnesses = None;

    // STUFE 1, ueber dem EINTRAGS-Objekthash.
    let (verification, detail_code) = if findings.format_errors.contains(&object_hash) {
        (VerificationStatus::Invalid, None)
    } else if findings.quarantined.contains(&object_hash) {
        // OHNE Detailgrund: die Quarantaene traegt einen `QuarantineReason` und
        // keinen `EA-`-Code.
        (VerificationStatus::Invalid, None)
    } else if let Some(code) = findings.signature_errors.get(&object_hash) {
        (VerificationStatus::Invalid, persistable_detail_code(code))
    } else if let Some(code) = findings.evidence_errors.get(&object_hash) {
        (VerificationStatus::Invalid, persistable_detail_code(code))
    } else {
        match own_grant(inventory, entry_hash, key_thumbprint) {
            // EIN ISOLIERTER GRANT IST SO GUT WIE KEINER, dieselbe Schranke, die
            // `claim_own_grants` selbst traegt: eine doppelt abgelegte `.eag`
            // wird nicht benutzt, und was nicht benutzt wurde, hat auch keinen
            // Befund hinterlassen.
            Some(grant) if findings.quarantined.contains(&grant.object_hash()) => {
                (VerificationStatus::MissingGrant, None)
            }
            // STUFE 2, ueber dem GRANT-Objekthash des EIGENEN Grants.
            Some(grant) => {
                let grant_hash = grant.object_hash();
                if let Some(code) = findings.decryption_errors.get(&grant_hash) {
                    (
                        VerificationStatus::UnknownKey,
                        persistable_detail_code(code),
                    )
                } else if let Some(code) = findings.signature_errors.get(&grant_hash) {
                    // Der EINTRAG ist gueltig, nur der Grant traegt nicht.
                    (
                        VerificationStatus::MissingGrant,
                        persistable_detail_code(code),
                    )
                } else if findings.is_valid_result(object_hash) {
                    witnesses = Some(DecryptionWitnessesV1 {
                        entry: VerifiedEncryptedEntry::new(
                            entry.exact_bytes().as_bytes().to_vec(),
                            entry_hash,
                            object_hash,
                            sequence,
                            minted_at,
                        ),
                        grant: VerifiedGrantForRecipient::new(
                            grant.exact_bytes().as_bytes().to_vec(),
                            entry_hash,
                            key_thumbprint,
                            minted_at,
                        ),
                    });
                    (VerificationStatus::Verified, None)
                } else {
                    // Ohne `objectResult` hat der Eintrag die neun Gates nicht
                    // durchlaufen. Fail-closed und OHNE Detailgrund: der Bericht
                    // nennt fuer diesen Ausgang keinen.
                    (VerificationStatus::Invalid, None)
                }
            }
            // STUFE 3. FEHLENDER GRANT IST KEINE BESCHAEDIGUNG: der Eintrag
            // bleibt gueltig und sichtbar, er wird nur nicht geoeffnet.
            None if findings.is_valid_result(object_hash) => {
                (VerificationStatus::MissingGrant, None)
            }
            None => (VerificationStatus::Invalid, None),
        }
    };

    ClassifiedEntryV1 {
        state: ReaderEntryStateV1::new(
            entry_hash,
            object_hash,
            sequence,
            verification,
            EntryStatus::Present,
            findings.server_confirmation(object_hash),
            detail_code,
        ),
        witnesses,
    }
}

/// Die Zustandszeile eines `.eds`-Stummels, in BEIDEN Dimensionen getrennt.
///
/// # `ObjectResultKindV1::AuthorizedDestroyed` ist ein TOTER Zweig
///
/// `confirm_entries` ist der einzige Erzeuger von `objectResults` — sein
/// eigener Doc-Kommentar sagt „HIER UND NUR HIER entstehen die
/// `objectResults`" — und setzt ausnahmslos `Valid`; die Variante
/// `AuthorizedDestroyed` wird workspaceweit nirgends konstruiert. Der
/// Eintragszustand kommt deshalb aus einer PRUEFKETTE, die
/// [`stub_destruction_is_authorized`] zieht. Schliesst sie sich, ist der
/// Zustand `autorisiert vernichtet`; sonst `ungeklaerte Luecke`.
/// `web-reader-design.md` §14.1: „Ein Stub ohne vollstaendige Pruefkette bleibt
/// eine Luecke."
///
/// # Die VERIFIKATIONSdimension bleibt davon unberuehrt
///
/// Ein `.eds` wird nie ein Kettenknoten und bekommt nie ein `objectResult`;
/// seine Sequenz liegt damit in einem `gaps`-Intervall, und in der
/// Verifikationsdimension ist er `Luecke` — auch dann, wenn seine Vernichtung
/// autorisiert ist. `design.md` §17.4 haelt die beiden Dimensionen ausdruecklich
/// auseinander.
fn classify_stub(
    findings: &ReportFindingsV1,
    inventory: &ArchiveInventory,
    stub: &Parsed<DestroyedEntryStubV1>,
    placed: &BTreeMap<EntryHash, ReaderEntryStateV1>,
) -> Option<ReaderEntryStateV1> {
    let object_hash = stub.object_hash();
    // EIN ISOLIERTES ODER UNLESBARES OBJEKT WIRD NICHT BENUTZT. Ein Stummel,
    // der selbst in der Quarantaene steht, ist nicht zuordenbar — aus ihm eine
    // Zeile ueber einen Eintrag zu bilden hiesse, eine Zuordnung zu behaupten,
    // die der Lauf gerade verweigert hat.
    if findings.quarantined.contains(&object_hash) || findings.format_errors.contains(&object_hash)
    {
        return None;
    }
    let entry_hash = stub.value().entry_hash();
    // Ein VORHANDENES `.eip` regiert seine eigene Zeile. Sonst stuenden zwei
    // Zeilen unter demselben Schluessel, und `state_of` entschiede nach
    // Einfuegereihenfolge.
    if placed.contains_key(&entry_hash) {
        return None;
    }
    let sequence = stub
        .value()
        .signed_manifest()
        .manifest()
        .fields()
        .chain_sequence;
    let entry_state = if stub_destruction_is_authorized(findings, inventory, stub.value(), sequence)
    {
        EntryStatus::AuthorizedDestroyed
    } else {
        EntryStatus::UnexplainedGap
    };
    let verification = if findings.is_missing_sequence(sequence) {
        VerificationStatus::Gap
    } else {
        // Der Stummel behauptet eine Vernichtung auf einer Sequenz, die der
        // Bericht NICHT als fehlend fuehrt — die Kette widerspricht ihm also.
        // Ein Widerspruch ist keine Luecke; fail-closed in die strengere
        // Richtung.
        VerificationStatus::Invalid
    };
    Some(ReaderEntryStateV1::new(
        entry_hash,
        object_hash,
        sequence,
        verification,
        entry_state,
        findings.server_confirmation(object_hash),
        None,
    ))
}

/// Ob sich die Pruefkette eines Stummels bis zur Autorisierung SCHLIESST.
///
/// DREI GLIEDER, und jedes traegt allein: (1) die `destructionId`, die der
/// Stummel nennt, fuehrt der Bericht unter `authorizedDestructions`; (2) der
/// `destructionAuthorizationObjectHash`, den der Stummel nennt, ist GENAU der
/// Hash, den die signierten Transitionen dieses Vorgangs authentifiziert haben
/// — `ea_verify::destruction` uebernimmt ihn aus der Kette, nie aus einem
/// Stummel; (3) die Autorisierung unter diesem Hash nennt unter `targets` den
/// `entryHash` UND die Sequenz des Stummels.
///
/// Ein Join allein ueber die Kennung liesse jedes kopierte, signierte Manifest
/// unter einer im Bestand liegenden Kennung als `autorisiert vernichtet`
/// erscheinen — GEMESSEN am Bestand
/// `report_archive_with_a_stub_naming_a_forged_authorization_hash`, ohne einen
/// einzigen neuen Befund im Bericht, weil `ea-verify` die beiden Stummelfelder
/// an keiner Stelle prueft. Die Ziele der Autorisierung liest `ea-verify`
/// ebenfalls nicht; deshalb stehen beide Glieder HIER. Was die Vier-Augen-
/// Signaturen der Autorisierung selbst angeht, gilt weiter das Wort von
/// `ea_verify::destruction`: die Transitionen binden ihren Objekthash
/// kryptografisch, aus unauthentischen Bytes stammt hier keine Sachaussage.
///
/// Der Zustand des Vorgangs (`beantragt` … `vollstaendig`) bleibt ohne
/// Gewicht: der Bericht fuehrt ihn, und `autorisiert` ist er in jedem davon.
///
/// `inventory.trust()` liegt aufsteigend nach Objekthash — die dokumentierte
/// Invariante, auf der auch `ArchiveInventory::read_exact_trust_object`
/// binaer sucht.
fn stub_destruction_is_authorized(
    findings: &ReportFindingsV1,
    inventory: &ArchiveInventory,
    stub: &DestroyedEntryStubV1,
    sequence: ChainSequence,
) -> bool {
    let Some(authorization_object_hash) =
        findings.authorized_destructions.get(&stub.destruction_id())
    else {
        return false;
    };
    if *authorization_object_hash != stub.destruction_authorization_object_hash() {
        return false;
    }
    let Ok(index) = inventory
        .trust()
        .binary_search_by_key(authorization_object_hash, Parsed::object_hash)
    else {
        return false;
    };
    let Ok(DecodedTrustPayloadV1::DestructionAuthorization(fields)) =
        inventory.trust()[index].value().decoded_payload()
    else {
        return false;
    };
    fields.destruction_id == stub.destruction_id()
        && fields.targets.iter().any(|target| {
            target.entry_hash() == stub.entry_hash().as_bytes()
                && target.chain_sequence() == sequence.get()
        })
}

/// Der eigene INITIALE Grant auf `entry_hash`.
///
/// Das Praedikat von `ea_verify::own_grant`, ZEICHENGLEICH nachgebaut, weil
/// jenes `pub(crate)` ist. Die drei Bindungen sind die Art, der `entryHash` und
/// der eigene Abdruck; `find` laeuft ueber das nach Objekthash aufsteigende
/// `inventory.grants()` und waehlt damit denselben Grant wie die Pipeline.
fn own_grant(
    inventory: &ArchiveInventory,
    entry_hash: EntryHash,
    key_thumbprint: KeyThumbprint,
) -> Option<&Parsed<GrantV1>> {
    inventory.grants().iter().find(|grant| {
        let fields = grant.value().grant_body().fields();
        fields.kind == GrantKindV1::Initial
            && fields.entry_hash == entry_hash
            && fields.recipient_key_thumbprint == key_thumbprint
    })
}
