//! Nachtragsreferenzen und die Original/Nachtrag-Projektion.
//!
//! # Der Faden VERBINDET und ERSETZT NICHT
//!
//! `web-reader-design.md` §12 und die Produktinvariante „amendment-only
//! corrections" lassen dazu keinen zweiten Weg zu: der Nachtrag ist die
//! Korrektur, das Original bleibt der Eintrag. Dieses Modul traegt deshalb
//! AUSDRUECKLICH keine Methode, die ein Original als `ueberholt`, `ersetzt`
//! oder `verborgen` kennzeichnet, und keine, die einen zusammengefuehrten
//! „aktuellen Stand" berechnet. Was [`ReaderEntryThread`] herausgibt, sind die
//! vollstaendigen Datensaetze in stabiler Ordnung — die Zusammenfuehrung
//! findet im Kopf der lesenden Person statt und nicht in diesem Code.
//!
//! # Ein abgewiesener Nachtrag ist ein PRUEFPROBLEM und keine Luecke
//!
//! [`ReaderEntryThread::build`] gibt `Err` nur zurueck, wenn das ORIGINAL
//! untauglich ist. Ein Kandidat mit falscher Referenz nimmt dem Original
//! nichts: er wandert mit seinem Eintragshash, seiner Sequenz, dem Grund und
//! [`VerificationStatus::Invalid`] nach [`ReaderEntryThread::rejected`] und
//! bleibt damit ein vorhandenes, adressierbares Objekt. Genau diese Adresse
//! trennt „Verifikationsproblem" von „Luecke": ein fehlender Eintrag hat
//! keine.
//!
//! # Der Klartext bleibt AUSGELIEHEN
//!
//! Die vier Vergleiche laufen INNERHALB von
//! [`VerifiedDecryptedRecord::with_payload`], und der vierte laeuft in einer
//! GESCHACHTELTEN Ausleihe ueber Kandidat und Original zugleich. Der Preis ist
//! eine zweite Dekodierung des Originals je Kandidat; der Gegenwert ist, dass
//! die Einsatznummer — ein fachlicher Klartextwert — dieses Modul nie als
//! eigener `String` verlaesst. `WR-082` und die Produktinvariante ueber
//! Klartext in Caches, Protokollen und Telemetrie verlangen genau das.
//!
//! # Keine zweite NFC-Normalisierung
//!
//! `ea-schema` normalisiert in `AmendmentV1::new` und `IncidentV1::new` und
//! weist Nicht-NFC mit `EA-SCHEMA-NON-NFC` ab. Ein zweiter Normalisierer hier
//! waere die Stelle, an der zwei Textbegriffe auseinanderlaufen koennten, ohne
//! dass ein Tor es sieht; der Vergleich laeuft deshalb roh ueber `str`.

use core::fmt;

use ea_schema::PayloadV1;
use ea_types::{ChainSequence, EntryHash, RecordId, VerificationStatus};

use crate::decrypt::VerifiedDecryptedRecord;

/// Die klartextfreie Korrekturreferenz fuer die Writer-Uebergabe der Stufe 5.
///
/// Genau drei Felder. Die Einsatznummer steht AUSDRUECKLICH nicht darin: sie
/// ist ein fachlicher Klartextwert, und diese Struktur reist zum Writer.
///
/// Alle drei Felder werden AUSSCHLIESSLICH aus dem Original gelesen und nie
/// aus einem Nachtrag — ein Nachtrag, der behauptet, ein anderes Original zu
/// meinen, hat den Faden zu diesem Zeitpunkt bereits verlassen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CorrectionReference {
    pub original_record_id: RecordId,
    pub original_sequence: ChainSequence,
    pub original_entry_hash: EntryHash,
}

impl fmt::Debug for CorrectionReference {
    /// Handgeschrieben, weil ein abgeleitetes `Debug` hier gar nicht
    /// uebersetzt: `id_newtype!` und `hash_newtype!` in
    /// `crates/ea-types/src/ids.rs` leiten fuer [`RecordId`] und
    /// [`EntryHash`] `Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash` ab —
    /// KEIN `Debug`. Die zwei Kennungen erscheinen deshalb hexadezimal, wie
    /// `VerifiedDecryptedRecord` es fuer seinen Eintragshash bereits loest.
    /// Klartext steht in dieser Struktur ohnehin keiner.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CorrectionReference { original_record_id: ")?;
        write_hex(formatter, self.original_record_id.as_bytes())?;
        write!(
            formatter,
            ", original_sequence: {}, original_entry_hash: ",
            self.original_sequence.get()
        )?;
        write_hex(formatter, self.original_entry_hash.as_bytes())?;
        formatter.write_str(" }")
    }
}

/// Der Grund, aus dem ein Kandidat dem Faden NICHT beitritt.
///
/// `Debug` steht hier ab, weil die Aufzaehlung nur Einheitsvarianten traegt
/// und ihr Name genau die Aussage ist, die die Oberflaeche unter
/// `Pruefprobleme` zeigt — sie traegt keinen Klartext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmendmentJoinErrorV1 {
    /// Das Original ist kein Einsatz. Genesis, Schluesseluebergang und
    /// Vernichtungsnachweis tragen keine Einsatznummer und koennen deshalb
    /// kein Original eines Nachtrags sein.
    NotAnIncident,
    /// Der Kandidat ist kein Nachtrag.
    NotAnAmendment,
    /// `originalRecordId` nennt einen anderen Datensatz.
    OriginalRecordIdMismatch,
    /// `originalEntryHash` weicht ab — und sei es um ein einziges Byte.
    OriginalEntryHashMismatch,
    /// `originalSequence` nennt eine andere Kettenposition.
    OriginalSequenceMismatch,
    /// Die Referenz stimmt, aber der Kandidat nennt die Einsatznummer eines
    /// ANDEREN Einsatzes. Ohne diesen Vergleich wuechsen zwei verschiedene
    /// Einsaetze ueber eine gemeinsame Sequenz zusammen.
    IncidentNumberMismatch,
    /// Ein zweiter Nachtrag auf derselben Kettensequenz. Der Faden loest den
    /// Widerspruch NICHT auf: der erste in Sequenzordnung bleibt.
    DuplicateSequence,
}

/// Ein Kandidat, der dem Faden nicht beigetreten ist — mit seiner ADRESSE.
///
/// Eintragshash und Sequenz sind die zwei Spalten, unter denen die Oberflaeche
/// ihn wiederfindet; ohne sie waere ein Pruefproblem von einer Luecke nicht zu
/// unterscheiden.
pub struct RejectedAmendment {
    pub entry_hash: EntryHash,
    pub chain_sequence: ChainSequence,
    pub reason: AmendmentJoinErrorV1,
    pub status: VerificationStatus,
}

impl fmt::Debug for RejectedAmendment {
    /// Aus demselben Grund handgeschrieben wie bei [`CorrectionReference`]:
    /// [`EntryHash`] leitet kein `Debug` ab. Der Plan verlangt hier keins;
    /// es steht trotzdem, weil ein Pruefproblem in einer Testausgabe seine
    /// Adresse nennen koennen muss — und die ist hexadezimal und klartextfrei.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RejectedAmendment { entry_hash: ")?;
        write_hex(formatter, self.entry_hash.as_bytes())?;
        write!(
            formatter,
            ", chain_sequence: {}, reason: {:?}, status: {:?} }}",
            self.chain_sequence.get(),
            self.reason,
            self.status
        )
    }
}

/// Ein Original samt seinen Nachtraegen und den abgewiesenen Kandidaten.
///
/// Opak und ausschliesslich ueber [`Self::build`] konstruierbar. Kein `Debug`
/// und kein `Clone`: der Faden HAELT [`VerifiedDecryptedRecord`]-Werte, deren
/// Klartext in einem `ea_crypto::SecretVec` liegt, und beide Ableitungen waeren
/// genau der Ausgabe- beziehungsweise Vervielfaeltigungsweg, den `WR-082`
/// verbietet.
pub struct ReaderEntryThread {
    original: VerifiedDecryptedRecord,
    amendments: Vec<VerifiedDecryptedRecord>,
    rejected: Vec<RejectedAmendment>,
    reference: CorrectionReference,
}

impl ReaderEntryThread {
    /// Verbindet ein Original mit seinen Nachtragskandidaten.
    ///
    /// Die Eingabe ist ausschliesslich [`VerifiedDecryptedRecord`], und dieser
    /// Typ entsteht nur in [`crate::decrypt_verified`]. Die Reihenfolge
    /// „Verifikation vor Entschluesselung" steht damit schon in den Typen: ein
    /// Objekt, das die neun Gates nicht durchlaufen hat, erreicht diesen Faden
    /// nicht.
    ///
    /// Die Ordnung ist `(chain_sequence, entry_hash)` und nichts anderes —
    /// nicht `finalized_at_device`, das ein Geraetezeitwert ist, und nicht die
    /// Eingabereihenfolge, die vom Abrufweg abhaengt: Cache, Lesestapel und
    /// Dateimodus liefern in verschiedenen Ordnungen, und eine Anzeige, die
    /// davon abhinge, waere fuer denselben Bestand zweimal verschieden. Der
    /// Eintragshash als zweiter Schluessel macht die Ordnung TOTAL; ohne ihn
    /// bliebe bei doppelter Sequenz die Eingabereihenfolge stehen, und mit ihr
    /// die Frage, welcher der beiden abgewiesen wird. Aus demselben Grund ist
    /// auch [`Self::rejected`] reproduzierbar geordnet: die Abweisungen
    /// entstehen in genau diesem Durchlauf.
    ///
    /// # Errors
    ///
    /// [`AmendmentJoinErrorV1::NotAnIncident`], wenn die Nutzlast des
    /// Originals kein Einsatz ist. Das ist der EINZIGE `Err`-Fall: ein
    /// einzelner kaputter Nachtrag darf die Anzeige des Originals und seiner
    /// gueltigen Nachtraege nicht nehmen.
    pub fn build(
        original: VerifiedDecryptedRecord,
        amendments: Vec<VerifiedDecryptedRecord>,
    ) -> Result<Self, AmendmentJoinErrorV1> {
        let original_record_id = original.with_payload(|payload| {
            let PayloadV1::Incident(incident) = payload else {
                return Err(AmendmentJoinErrorV1::NotAnIncident);
            };
            Ok(incident.header().record_id())
        })?;
        // Die Referenz entsteht VOR dem ersten Kandidaten und aus dem
        // VERIFIZIERTEN Original allein. Danach ist sie die Messlatte jedes
        // Vergleichs; ein Kandidat wird nie gegen einen zweiten Kandidaten
        // gemessen.
        let reference = CorrectionReference {
            original_record_id,
            original_sequence: original.chain_sequence(),
            original_entry_hash: original.entry_hash(),
        };

        let mut candidates = amendments;
        candidates.sort_by_key(|candidate| (candidate.chain_sequence(), candidate.entry_hash()));

        let mut joined: Vec<VerifiedDecryptedRecord> = Vec::new();
        let mut rejected: Vec<RejectedAmendment> = Vec::new();
        for candidate in candidates {
            // Nur der zuletzt AUFGENOMMENE besetzt eine Sequenz. Ein
            // abgewiesener Kandidat besetzt sie nicht: sonst naehme ein
            // Nachtrag mit falscher Referenz einem gueltigen auf derselben
            // Sequenz den Platz weg.
            let occupied_sequence = joined.last().map(VerifiedDecryptedRecord::chain_sequence);
            if let Some(reason) = join_error(&original, &reference, &candidate, occupied_sequence) {
                rejected.push(RejectedAmendment {
                    entry_hash: candidate.entry_hash(),
                    chain_sequence: candidate.chain_sequence(),
                    reason,
                    status: VerificationStatus::Invalid,
                });
            } else {
                joined.push(candidate);
            }
        }

        Ok(Self {
            original,
            amendments: joined,
            rejected,
            reference,
        })
    }

    /// Das Original — vollstaendig, mit seinen Bytes und seinem Eintragshash.
    #[must_use]
    pub const fn original(&self) -> &VerifiedDecryptedRecord {
        &self.original
    }

    /// Die beigetretenen Nachtraege, nach `(chain_sequence, entry_hash)`
    /// geordnet.
    #[must_use]
    pub fn amendments(&self) -> &[VerifiedDecryptedRecord] {
        &self.amendments
    }

    /// Die Kandidaten, die dem Faden nicht beigetreten sind.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedAmendment] {
        &self.rejected
    }

    /// Die klartextfreie Uebergabe an den Writer-Import der Stufe 5.
    #[must_use]
    pub const fn correction_reference(&self) -> CorrectionReference {
        self.reference
    }
}

/// Der Grund, aus dem dieser Kandidat NICHT beitritt — oder `None`.
///
/// Die Reihenfolge der Pruefungen ist Absicht: erst die Gestalt, dann die vier
/// Referenzen, zuletzt die doppelte Sequenz. Ein Kandidat, der schon an einer
/// Referenz faellt, hat den Faden verlassen, bevor die Frage nach seinem Platz
/// ueberhaupt entsteht — und meldet damit den SPEZIFISCHEN Grund statt des
/// unspezifischen.
fn join_error(
    original: &VerifiedDecryptedRecord,
    reference: &CorrectionReference,
    candidate: &VerifiedDecryptedRecord,
    occupied_sequence: Option<ChainSequence>,
) -> Option<AmendmentJoinErrorV1> {
    candidate.with_payload(|payload| {
        let PayloadV1::Amendment(amendment) = payload else {
            return Some(AmendmentJoinErrorV1::NotAnAmendment);
        };
        if amendment.original_record_id() != reference.original_record_id {
            return Some(AmendmentJoinErrorV1::OriginalRecordIdMismatch);
        }
        if amendment.original_entry_hash() != reference.original_entry_hash {
            return Some(AmendmentJoinErrorV1::OriginalEntryHashMismatch);
        }
        if amendment.original_sequence() != reference.original_sequence {
            return Some(AmendmentJoinErrorV1::OriginalSequenceMismatch);
        }
        // Der VIERTE Vergleich ist der einzige ueber Klartext, und er laeuft
        // deshalb GESCHACHTELT: beide Zeichenketten bleiben Ausleihen ihres
        // jeweiligen `SecretVec`, und keine von beiden wird kopiert, um sie
        // vergleichen zu koennen. Er steht zuletzt, weil er als einziger eine
        // zweite Dekodierung des Originals kostet.
        let number_mismatch = original.with_payload(|original_payload| {
            let PayloadV1::Incident(incident) = original_payload else {
                // UNERREICHBAR DURCH KONSTRUKTION: `build` hat dieselben Bytes
                // bereits als Einsatz bestimmt, und sie liegen seither
                // unveraendert in einem `SecretVec`, den niemand von aussen
                // beschreiben kann. Fail-closed statt `unreachable!` — eine
                // Weigerung ist billiger als ein Abbruch im Browser, und ein
                // Kandidat ohne Einsatz als Original tritt zu Recht nicht bei.
                return true;
            };
            amendment.original_incident_number() != incident.human_incident_number()
        });
        if number_mismatch {
            return Some(AmendmentJoinErrorV1::IncidentNumberMismatch);
        }
        if occupied_sequence == Some(candidate.chain_sequence()) {
            return Some(AmendmentJoinErrorV1::DuplicateSequence);
        }
        None
    })
}

/// Schreibt Bytes hexadezimal — der einzige Ausgabeweg der zwei `Debug`-Impls.
///
/// `hex::encode` legte dafuer einen `String` an; hier genuegt der Formatter.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
