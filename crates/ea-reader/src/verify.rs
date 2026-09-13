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
use ea_format::{DestroyedEntryStubV1, EntryPackageV1, FormatError, Parsed};
use ea_types::{EntryHash, EntryStatus, KeyThumbprint, ObjectHash, UnixMillis, VerificationStatus};
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
/// # Eigene Reader-Codes und durchgereichte Fachcodes
///
/// `EA-READER-WITNESS-STALE` und `EA-READER-SCHEMA-UNSUPPORTED`.
/// Der Operator-Abgleich verwendet den gemeinsamen Fachcode
/// `EA-OPERATOR-PROFILE-COMMITMENT` aus Design §6.8.
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
    GrantExpired,
    /// Local expiry metadata must flush before a historical grant is consumed.
    TimePersistence(crate::ReaderVaultError),
    /// Keine der Schemabestimmungen traegt diesen Klartext.
    UnsupportedSchema,
    /// Der entschluesselte Operator passt nicht zur verifizierten historischen Bindung.
    OperatorProfileCommitment,
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
            Self::GrantExpired => "EA-GRANT-EXPIRED",
            Self::TimePersistence(error) => error.code(),
            Self::UnsupportedSchema => "EA-READER-SCHEMA-UNSUPPORTED",
            Self::OperatorProfileCommitment => "EA-OPERATOR-PROFILE-COMMITMENT",
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
/// Each opening supplies a fresh host time and consumes the vault high-water
/// mark plus authenticated Receipt/Checkpoint times. Hosts restore and flush
/// ReaderGrantTimeStore BEFORE HPKE, using a recipient-free verified-time pass.
/// Raw classify refuses uncommitted historical-grant time. Witnesses retain the
/// effective opening time; decrypt_verified independently checks grant expiry
/// and rejects stale witnesses before HPKE.
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

    /// Verify independent signed times WITHOUT a recipient key. Hosts may
    /// persist this result before invoking classification/decapsulation.
    pub fn verified_time(
        &self,
        source: &dyn ArchiveSource,
        session: &UnlockedVault,
    ) -> Result<UnixMillis, ReaderError> {
        let now = session.observe_effective_time(self.effective_now);
        let anchor = PinnedTrustAnchor::from_vault(session);
        let report =
            ea_verify::verify_archive(source, anchor.as_trust_anchor(), VerifyOptions::new(now))?;
        Ok(now.max(report.verified_time_floor().unwrap_or(now)))
    }

    /// Host path: authenticate signed time without KEM, merge/flush encrypted
    /// metadata, then permit HPKE only up to that successfully committed floor.
    pub fn classify_with_time_store(
        &self,
        source: &dyn ArchiveSource,
        session: &UnlockedVault,
        store: &mut dyn crate::ReaderBlobStore,
        observer: &mut dyn GateObserver,
    ) -> Result<ReaderClassification, ReaderError> {
        let observed = self.verified_time(source, session)?;
        let durable = crate::ReaderGrantTimeStore::observe(session, store, observed)
            .map_err(ReaderError::TimePersistence)?;
        Self::new(self.mode, durable).classify(source, session, observer)
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
        let effective_now = session.observe_effective_time(self.effective_now);
        let anchor = PinnedTrustAnchor::from_vault(session);
        let options = VerifyOptions::new(effective_now)
            .with_recipient(session.kem_key_thumbprint(), session.kem_private_key())
            .with_recipient_time_ceiling(session.durable_grant_time());
        let report = verify_archive_observed(source, anchor.as_trust_anchor(), options, observer)?;
        let effective_now =
            session.observe_effective_time(report.verified_time_floor().unwrap_or(effective_now));
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
                    effective_now,
                    anchor.as_trust_anchor(),
                );
                if let Some(witness) = row.witnesses {
                    witnesses.insert(row.state.entry_hash(), witness);
                }
                rows.insert(row.state.entry_hash(), row.state);
            }
            for stub in inventory.destroyed() {
                if let Some(state) = classify_stub(&findings, stub, &rows) {
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
    recipient_grants: BTreeMap<EntryHash, (ObjectHash, Option<UnixMillis>)>,
    object_results: BTreeMap<ObjectHash, (ObjectResultKindV1, ServerConfirmationV1)>,
    format_errors: BTreeSet<ObjectHash>,
    quarantined: BTreeSet<ObjectHash>,
    signature_errors: BTreeMap<ObjectHash, &'static str>,
    evidence_errors: BTreeMap<ObjectHash, &'static str>,
    decryption_errors: BTreeMap<ObjectHash, &'static str>,
}

impl ReportFindingsV1 {
    fn collect(report: &VerificationReportV1) -> Self {
        Self {
            recipient_grants: report
                .recipient_grants()
                .map(|(entry, grant, expires)| (entry, (grant, expires)))
                .collect(),
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
    anchor: &ea_trust::TrustAnchorV1,
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
        match findings
            .recipient_grants
            .get(&entry_hash)
            .and_then(|(hash, _)| {
                inventory
                    .grants()
                    .iter()
                    .find(|grant| grant.object_hash() == *hash)
            }) {
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
                        if *code == "EA-GRANT-EXPIRED" {
                            VerificationStatus::Invalid
                        } else {
                            VerificationStatus::MissingGrant
                        },
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
                            crate::operator_profile::historical_bindings(
                                anchor,
                                inventory,
                                entry.value().manifest().fields(),
                                minted_at,
                            ),
                        ),
                        grant: VerifiedGrantForRecipient::new(
                            grant.exact_bytes().as_bytes().to_vec(),
                            entry_hash,
                            key_thumbprint,
                            minted_at,
                            findings
                                .recipient_grants
                                .get(&entry_hash)
                                .and_then(|(_, expires)| *expires),
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

/// A Stub's result comes exclusively from the shared full verification chain,
/// including decrypted Writer Evidence. A state-event/target join alone cannot
/// authorize its unsigned original-object-hash field.
fn classify_stub(
    findings: &ReportFindingsV1,
    stub: &Parsed<DestroyedEntryStubV1>,
    placed: &BTreeMap<EntryHash, ReaderEntryStateV1>,
) -> Option<ReaderEntryStateV1> {
    let hash = stub.object_hash();
    if findings.quarantined.contains(&hash)
        || findings.format_errors.contains(&hash)
        || placed.contains_key(&stub.value().entry_hash())
    {
        return None;
    }
    let authorized = findings
        .object_results
        .get(&hash)
        .is_some_and(|(result, _)| *result == ObjectResultKindV1::AuthorizedDestroyed);
    Some(ReaderEntryStateV1::new(
        stub.value().entry_hash(),
        hash,
        stub.value()
            .signed_manifest()
            .manifest()
            .fields()
            .chain_sequence,
        if authorized {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Gap
        },
        if authorized {
            EntryStatus::AuthorizedDestroyed
        } else {
            EntryStatus::UnexplainedGap
        },
        findings.server_confirmation(hash),
        None,
    ))
}
