//! Die Warteschlange — ABGELEITET, nie gespeichert.
//!
//! # Die eine Quelle
//!
//! `design.md` §9.4: „Nach dem `.eip`-Rename ist das Archivpaket die Wahrheit.
//! Ein Neustart rekonstruiert Kettenkopf, Queue und UI daraus und erzeugt kein
//! Duplikat." Diese Datei ist die ausfuehrbare Fassung dieses Satzes. Sie liest
//! ausschliesslich COMMITTETE Bytes; eine gestagte Datei traegt dasselbe
//! Exact-Object-Praefix und stuende sonst als anstehender Eintrag da, obwohl
//! sie nie veroeffentlicht wurde.
//!
//! # Die Abbildung auf die vier Zustaende liegt HIER
//!
//! Bis zu diesem Task entschied `PublicationQueue` denselben Zustand ein
//! zweites Mal. Seitdem liefert sie ein Publikationsergebnis, und
//! [`sync_state_of`] ist die EINE Stelle, an der aus Publikationsergebnis,
//! Serverantwort und abgelegter Quittung ein oeffentlicher Zustand wird.
//! Normative Deckung: `design.md`:1584.

use std::collections::BTreeMap;

use ea_archive::{
    ArchiveBlob, ArchiveInventory, ArchiveSource, ENTRIES_DIR_V1, GRANTS_DIR_V1, is_staging_path,
};
use ea_archive_fs::{DetailCause, PublicationOutcomeV1, SyncStatus};
use ea_format::{GrantPlanItemV1, GrantPlanV1};
use ea_types::{ChainSequence, EntryHash, ObjectHash, UnixMillis};

use crate::SyncClientError;

/// Ein anstehender Eintrag, VOLLSTAENDIG aus committeten Bytes.
///
/// Er traegt die exakten Bytes und nicht ihre Adressen: der Upload sendet
/// genau diese Bytes weiter, und ein zweites Lesen von der Platte waere eine
/// zweite Gelegenheit, andere zu senden.
#[derive(Clone)]
pub struct PendingEntryV1 {
    entry_bytes: Vec<u8>,
    entry_hash: EntryHash,
    entry_object_hash: ObjectHash,
    sequence: ChainSequence,
    /// Die exakten initialen `.eag`, in der Ordnung des Plans.
    grant_bytes: Vec<Vec<u8>>,
    /// Die Positionen des initialen Grant-Plans. Als POSITIONEN und nicht als
    /// fertiger [`GrantPlanV1`], weil jener bewusst nicht `Clone` ist: er
    /// traegt seine exakten Bytes und seinen Hash, und eine Kopie davon waere
    /// eine zweite Gelegenheit, sie auseinanderlaufen zu lassen. Der Plan
    /// entsteht deshalb an der einen Stelle neu, an der er gebraucht wird —
    /// aus genau diesen Positionen.
    grant_plan_items: Vec<GrantPlanItemV1>,
    /// Die Adressen, unter denen Grants und `.eip` committet liegen — Grants
    /// zuerst, `.eip` zuletzt. Das IST die Publikationsreihenfolge von
    /// `design.md` §9.3 Schritt 12.
    committed_order: Vec<String>,
}

impl PendingEntryV1 {
    #[must_use]
    pub fn entry_bytes(&self) -> &[u8] {
        &self.entry_bytes
    }

    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    #[must_use]
    pub const fn entry_object_hash(&self) -> ObjectHash {
        self.entry_object_hash
    }

    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.sequence
    }

    #[must_use]
    pub fn grant_bytes(&self) -> &[Vec<u8>] {
        &self.grant_bytes
    }

    /// Der initiale Grant-Plan, aus den Positionen der committeten Grants.
    ///
    /// # Errors
    ///
    /// [`SyncClientError::QueueDerivation`], wenn die Positionen keinen
    /// gueltigen Plan ergeben. In einer abgeleiteten Warteschlange kann das
    /// nicht mehr eintreten — [`SyncQueueV1::derive`] hat den Plan schon
    /// gebildet und seinen Hash gegen das Manifest gehalten —, und genau
    /// deshalb bleibt der Fehler ein Fehler und wird nicht zur Panik.
    pub fn grant_plan(&self) -> Result<GrantPlanV1, SyncClientError> {
        Ok(GrantPlanV1::new(self.grant_plan_items.clone())?)
    }

    /// Grants zuerst, `.eip` zuletzt — mit den exakten Bytes daneben.
    #[must_use]
    pub fn publication_plan(&self) -> Vec<(String, Vec<u8>)> {
        let mut plan: Vec<(String, Vec<u8>)> = self
            .committed_order
            .iter()
            .take(self.grant_bytes.len())
            .cloned()
            .zip(self.grant_bytes.iter().cloned())
            .collect();
        if let Some(entry_path) = self.committed_order.last() {
            plan.push((entry_path.clone(), self.entry_bytes.clone()));
        }
        plan
    }
}

impl core::fmt::Debug for PendingEntryV1 {
    /// Nennt die Sequenz und die Zahl der Grants — nie ein Byte.
    ///
    /// Die Bytes eines `.eip` sind Ciphertext, und die eines `.eag` tragen
    /// gewickeltes Schluesselmaterial; ein Debug-Abzug davon gehoert in kein
    /// Protokoll.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "PendingEntryV1 {{ sequence: {}, grants: {} }}",
            self.sequence.get(),
            self.grant_bytes.len()
        )
    }
}

/// Die abgeleitete Warteschlange.
pub struct SyncQueueV1 {
    pending: Vec<PendingEntryV1>,
    /// Die Zahl der Eintraege, die schon eine gueltige lokale Quittung tragen.
    confirmed: usize,
}

impl SyncQueueV1 {
    /// Baut die Warteschlange aus dem committeten Bestand.
    ///
    /// Ein Eintrag steht genau dann an, wenn er committet ist, seine EXAKTEN
    /// initialen Grants vollstaendig danebenliegen und KEINE GUELTIGE lokale
    /// Quittung auf ihn zeigt.
    ///
    /// # Warum hier der VOLLE Verifizierer laeuft
    ///
    /// „Gueltig" ist der Punkt. Das Inventar klassifiziert am
    /// Exact-Object-Praefix, und `esr::parse_body` prueft Gestalt und Content
    /// Type — aber weder die Serversignatur noch die fuenf Bindungen an den
    /// Eintrag. Eine formgueltige, falsch signierte `.esr` unter `receipts/`
    /// naehme den Eintrag sonst aus der Warteschlange, der offene Rest fiele
    /// auf null, und `sync_state_of` meldete `synchronisiert` — genau die
    /// Zusage, die `design.md`:1584 an eine GEPRUEFTE Quittung bindet. Die
    /// Bedingung ist deshalb dieselbe wie beim Annehmen einer frisch
    /// empfangenen Quittung: [`crate::entry_is_server_confirmed`].
    ///
    /// # Errors
    ///
    /// [`SyncClientError::Archive`], wenn der Bestand nicht lesbar ist;
    /// [`SyncClientError::QueueDerivation`], wenn ein committeter Eintrag
    /// seine initialen Grants nicht vollstaendig danebenliegen hat — sein
    /// Grant-Plan-Hash ist dann nicht der des Manifests. Fail-closed: aus einem
    /// unvollstaendigen Bestand entsteht keine halbe Warteschlange, denn ein
    /// Commit mit fehlendem Grant waere ein Eintrag, den kein Empfaenger je
    /// oeffnen kann.
    pub fn derive(
        source: &dyn ArchiveSource,
        anchor: &ea_trust::TrustAnchorV1,
        observed_now: UnixMillis,
    ) -> Result<Self, SyncClientError> {
        let inventory = ArchiveInventory::build(source)?;
        let committed_paths = committed_addresses(source)?;
        let report =
            ea_verify::verify_archive(source, anchor, ea_verify::VerifyOptions::new(observed_now))
                .map_err(|_| SyncClientError::Archive)?;

        let mut pending = Vec::new();
        let mut confirmed = 0_usize;
        for entry in inventory.entries() {
            let object_hash = entry.object_hash();
            if crate::entry_is_server_confirmed(&report, object_hash) {
                confirmed += 1;
                continue;
            }
            // FAIL-CLOSED, und aus demselben Grund wie der fehlende Grant acht
            // Zeilen weiter unten: das Inventar klassifiziert am
            // Exact-Object-Praefix und ist pfadunabhaengig
            // (`crates/ea-archive/src/inventory.rs`), waehrend committete
            // Adressen nur unter `entries/` und `grants/` gezaehlt werden. Ein
            // inventarisiertes `.eip` ohne committete Adresse ist deshalb
            // etwas, das dieser Klient nicht erklaeren kann — und ein
            // stillschweigend uebersprungener Eintrag faellt aus BEIDEN
            // Zaehlern heraus, worauf ein Bestand ohne eine einzige gepruefte
            // Quittung als `synchronisiert` dastuende.
            let Some(entry_path) = committed_paths.get(object_hash.as_bytes()) else {
                return Err(SyncClientError::QueueDerivation);
            };

            let entry_hash = entry.value().entry_hash();
            let manifest = entry.value().manifest().fields();

            // Die EXAKTEN initialen Grants dieses Eintrags: jeder committete
            // `.eag`, dessen `entryHash` auf ihn zeigt.
            let mut grants: Vec<(String, Vec<u8>, GrantPlanItemV1)> = Vec::new();
            for grant in inventory.grants() {
                if grant.value().grant_body().fields().entry_hash != entry_hash {
                    continue;
                }
                let Some(path) = committed_paths.get(grant.object_hash().as_bytes()) else {
                    continue;
                };
                let fields = grant.value().grant_body().fields();
                grants.push((
                    path.clone(),
                    grant.exact_bytes().as_bytes().to_vec(),
                    GrantPlanItemV1::new(
                        fields.recipient_key_thumbprint,
                        fields.recipient_certificate_hash,
                        fields.purpose,
                    ),
                ));
            }
            if grants.is_empty() {
                return Err(SyncClientError::QueueDerivation);
            }

            // Der aus den GEFUNDENEN Grants gebildete Plan muss den Hash des
            // Manifests tragen. Das ist die Vollstaendigkeitspruefung und keine
            // Formalie: fehlt ein Grant, weicht der Hash ab, und der Eintrag
            // geht NICHT auf die Leitung.
            let plan = GrantPlanV1::new(
                grants
                    .iter()
                    .map(|(_, _, item)| item.clone())
                    .collect::<Vec<_>>(),
            )?;
            if *plan.hash().as_bytes() != manifest.initial_grant_plan_hash {
                return Err(SyncClientError::QueueDerivation);
            }

            grants.sort_by(|left, right| left.0.cmp(&right.0));
            let mut committed_order: Vec<String> =
                grants.iter().map(|(path, _, _)| path.clone()).collect();
            committed_order.push(entry_path.clone());

            pending.push(PendingEntryV1 {
                entry_bytes: entry.exact_bytes().as_bytes().to_vec(),
                entry_hash,
                entry_object_hash: object_hash,
                sequence: manifest.chain_sequence,
                grant_bytes: grants.iter().map(|(_, bytes, _)| bytes.clone()).collect(),
                grant_plan_items: grants.iter().map(|(_, _, item)| item.clone()).collect(),
                committed_order,
            });
        }

        // Aufsteigend nach Sequenz: die Kette wird in ihrer Reihenfolge
        // hochgeladen, und der Server prueft die Kettenposition.
        pending.sort_by_key(|entry| entry.sequence.get());
        Ok(Self { pending, confirmed })
    }

    /// Die anstehenden Eintraege, aufsteigend nach Sequenz.
    #[must_use]
    pub fn pending(&self) -> &[PendingEntryV1] {
        &self.pending
    }

    /// Die Zahl der Eintraege, die schon eine Quittung im Bestand tragen.
    #[must_use]
    pub const fn confirmed(&self) -> usize {
        self.confirmed
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Die COMMITTETEN Adressen der Eintraege und Grants, nach Objekthash.
///
/// Sie entstehen aus einem eigenen Durchlauf und nicht aus dem Inventar, und
/// das ist keine Doppelung: `ea_archive::Parsed` traegt Wert, exakte Bytes und
/// Objekthash, aber KEINEN Pfad — der Pfadhinweis ist im Inventar ausdruecklich
/// ein Diagnosewert und keine Klassifikationsgrundlage
/// (`crates/ea-archive/src/source.rs`). Fuer die Publikationsreihenfolge
/// braucht der Klient aber die Adresse, unter der ein Objekt committet liegt.
///
/// GESTAGTE Adressen sind hier ausgeschlossen und nicht bloss unerwaehnt: eine
/// `.eip.staging` traegt dasselbe Exact-Object-Praefix, stuende also als
/// anstehender Eintrag da, und der naechste Lauf luede ein Objekt hoch, das nie
/// veroeffentlicht wurde.
fn committed_addresses(
    source: &dyn ArchiveSource,
) -> Result<BTreeMap<[u8; 32], String>, SyncClientError> {
    let mut paths: BTreeMap<[u8; 32], String> = BTreeMap::new();
    source.visit_blobs(&mut |blob: ArchiveBlob<'_>| {
        let hint = blob.path_hint();
        if is_staging_path(hint)
            || (!hint.starts_with(ENTRIES_DIR_V1) && !hint.starts_with(GRANTS_DIR_V1))
        {
            return Ok(());
        }
        paths.insert(
            *ea_crypto::object_hash(blob.bytes()).as_bytes(),
            hint.to_owned(),
        );
        Ok(())
    })?;
    Ok(paths)
}

/// Woran ein Lauf haengengeblieben ist — die nichtnormative Detailursache.
///
/// GENAU die Schritte, die `design.md`:1584 als „aktuellen Schritt" versteht:
/// `Upload ausstehend` umfasst die Netzarchivpublikation UND den
/// anschliessenden Serverupload, und die Ursache erklaert, welcher der beiden
/// gerade wartet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingStepV1 {
    /// Das Netzarchiv hat die Bytes noch nicht.
    NetworkArchive,
    /// Das Netzarchiv hat sie, der Server noch nicht.
    ServerUpload,
    /// Die Wiederaufnahmeversuche des Profils sind erschoepft.
    ResumeExhausted,
    /// Die Queuegrenze des Profils ist erreicht.
    QueueLimit,
    /// Das Profil steht nicht in der wirksamen Policy.
    ProfileNotAllowed,
}

/// Die EINE Abbildung auf die vier oeffentlichen Zustaende.
///
/// `synchronisiert` verlangt DREIERLEI: es steht nichts mehr an, kein Schritt
/// wartet, UND mindestens ein Eintrag traegt eine GEPRUEFTE Quittung.
///
/// Die dritte Bedingung ist die tragende, und sie ist gemessen und nicht
/// gefolgert. Ein leerer Warteschlangenrest allein genuegt nicht: er ist auch
/// dann leer, wenn nie etwas anlag, und `step` ist in beiden Faellen `None` —
/// die zwei liessen sich daran also gar nicht unterscheiden. `confirmed` ist
/// die Zahl, die sie unterscheidet, und sie zaehlt ausschliesslich Eintraege,
/// fuer die [`crate::entry_is_server_confirmed`] wahr war.
///
/// Ein Bestand ohne einen einzigen committeten Eintrag meldet deshalb `lokal
/// gesichert` und nicht `synchronisiert`: es ist nichts offen, aber es ist
/// auch nichts bestaetigt, und von den vier Zustaenden ist das der einzige,
/// der ueber den Server nichts behauptet.
#[must_use]
pub const fn sync_state_of(
    outstanding: usize,
    confirmed: usize,
    step: Option<PendingStepV1>,
) -> (SyncStatus, Option<DetailCause>) {
    match step {
        None if outstanding == 0 && confirmed > 0 => (SyncStatus::Synchronized, None),
        None if outstanding == 0 => (SyncStatus::LocallySaved, None),
        None => (SyncStatus::UploadPending, None),
        Some(PendingStepV1::NetworkArchive) => (
            SyncStatus::UploadPending,
            Some(DetailCause::NetworkArchiveWaiting),
        ),
        Some(PendingStepV1::ServerUpload) => (SyncStatus::UploadPending, None),
        Some(PendingStepV1::ResumeExhausted) => (
            SyncStatus::Failed,
            Some(DetailCause::ResumeAttemptsExhausted),
        ),
        Some(PendingStepV1::QueueLimit) => {
            (SyncStatus::Failed, Some(DetailCause::QueueLimitReached))
        }
        Some(PendingStepV1::ProfileNotAllowed) => {
            (SyncStatus::Failed, Some(DetailCause::ProfileNotAllowed))
        }
    }
}

/// Uebersetzt das Publikationsergebnis in den wartenden Schritt.
///
/// Der Ort, an dem die Entkopplung sichtbar wird: `PublicationQueue` sagt, WAS
/// mit den Bytes geschah, und erst hier wird daraus ein Zustand.
#[must_use]
pub const fn step_of(outcome: PublicationOutcomeV1) -> Option<PendingStepV1> {
    match outcome {
        PublicationOutcomeV1::NothingPending | PublicationOutcomeV1::PublishedCompletely => None,
        PublicationOutcomeV1::Deferred => Some(PendingStepV1::NetworkArchive),
        PublicationOutcomeV1::QueueLimitReached => Some(PendingStepV1::QueueLimit),
    }
}

#[cfg(test)]
mod tests {
    use super::{PendingStepV1, step_of, sync_state_of};
    use ea_archive_fs::{DetailCause, PublicationOutcomeV1, SyncStatus};

    /// `synchronisiert` ist NUR mit einer gepruefften Quittung erreichbar.
    ///
    /// Die dritte Zeile ist die eigentliche: ohne offenen Rest und ohne
    /// wartenden Schritt, aber ohne eine einzige bestaetigte Quittung, ist der
    /// Zustand `lokal gesichert` — nicht `synchronisiert`. Genau dieser Fall
    /// entsteht ueber einem Bestand, in dem noch nie etwas hochgeladen wurde.
    #[test]
    fn only_a_settled_run_with_a_confirmed_receipt_reaches_synchronized() {
        assert_eq!(sync_state_of(0, 1, None), (SyncStatus::Synchronized, None));
        assert_eq!(sync_state_of(0, 0, None), (SyncStatus::LocallySaved, None));
        assert_eq!(sync_state_of(1, 0, None).0, SyncStatus::UploadPending);
        assert_eq!(sync_state_of(1, 3, None).0, SyncStatus::UploadPending);
    }

    /// JEDER wartende Schritt bildet auf GENAU einen der vier Zustaende ab.
    ///
    /// Die Tabelle steht ausgeschrieben da, weil sie die Zusage IST. Eine
    /// Schleife, die nur `!= Synchronized` und Mitgliedschaft in `ALL` prueft,
    /// bliebe auch dann gruen, wenn `Queuegrenze erreicht` auf `Upload
    /// ausstehend` abbildete — und die Queuegrenze ist der einzige Weg zum
    /// oeffentlichen Zustand `Fehler`, den dieser Bestand kennt.
    #[test]
    fn every_pending_step_maps_to_exactly_one_public_state() {
        assert_eq!(
            sync_state_of(1, 0, Some(PendingStepV1::NetworkArchive)),
            (
                SyncStatus::UploadPending,
                Some(DetailCause::NetworkArchiveWaiting)
            )
        );
        assert_eq!(
            sync_state_of(1, 0, Some(PendingStepV1::ServerUpload)),
            (SyncStatus::UploadPending, None)
        );
        assert_eq!(
            sync_state_of(1, 0, Some(PendingStepV1::ResumeExhausted)),
            (
                SyncStatus::Failed,
                Some(DetailCause::ResumeAttemptsExhausted)
            )
        );
        assert_eq!(
            sync_state_of(1, 0, Some(PendingStepV1::QueueLimit)),
            (SyncStatus::Failed, Some(DetailCause::QueueLimitReached))
        );
        assert_eq!(
            sync_state_of(1, 0, Some(PendingStepV1::ProfileNotAllowed)),
            (SyncStatus::Failed, Some(DetailCause::ProfileNotAllowed))
        );

        // Und kein wartender Schritt meldet je `synchronisiert` — auch nicht
        // mit leerer Warteschlange und bestaetigten Quittungen daneben.
        for step in [
            PendingStepV1::NetworkArchive,
            PendingStepV1::ServerUpload,
            PendingStepV1::ResumeExhausted,
            PendingStepV1::QueueLimit,
            PendingStepV1::ProfileNotAllowed,
        ] {
            let (status, cause) = sync_state_of(0, 9, Some(step));
            assert_ne!(status, SyncStatus::Synchronized, "{step:?}");
            assert!(SyncStatus::ALL.contains(&status));
            if let Some(cause) = cause {
                assert!(DetailCause::ALL.contains(&cause));
            }
        }
    }

    /// Der ueberschrittene Queuebound wird zum oeffentlichen Zustand `Fehler`.
    ///
    /// Die Kette Publikationsergebnis -> wartender Schritt -> Zustand steht
    /// hier GANZ da. Bis Task 10 pinnte
    /// `crates/ea-archive-fs/tests/publication_queue.rs` das Ende dieser Kette
    /// direkt; seit die Abbildung hierher gewandert ist, gehoert der Zeuge
    /// dafuer hierher — sonst haette der oeffentliche Zustand `Fehler` gar
    /// keinen mehr.
    #[test]
    fn the_exceeded_queue_bound_reaches_the_public_failed_state() {
        assert_eq!(
            step_of(PublicationOutcomeV1::QueueLimitReached),
            Some(PendingStepV1::QueueLimit)
        );
        assert_eq!(
            sync_state_of(1, 0, step_of(PublicationOutcomeV1::QueueLimitReached)),
            (SyncStatus::Failed, Some(DetailCause::QueueLimitReached))
        );
    }

    /// Die zwei Ausgaenge, die KEINEN Schritt warten lassen, und der dritte.
    #[test]
    fn a_settled_publication_leaves_no_waiting_step() {
        assert_eq!(step_of(PublicationOutcomeV1::NothingPending), None);
        assert_eq!(step_of(PublicationOutcomeV1::PublishedCompletely), None);
        assert_eq!(
            step_of(PublicationOutcomeV1::Deferred),
            Some(PendingStepV1::NetworkArchive)
        );
    }
}
