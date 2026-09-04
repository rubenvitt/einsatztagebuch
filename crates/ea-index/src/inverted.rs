//! Die Eingabe, der Bestand, die vier Filter und die Schwelle.

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use ea_types::{ChainSequence, EntryHash, RecordId, UnixMillis};
use unicode_normalization::UnicodeNormalization;

use crate::{IndexError, schema_view::SchemaViewV1};

/// Die VERBINDLICHE Schwelle des monolithischen Einzelblob-Index.
///
/// `web-reader-design.md` §8.1 sagt „einige zehntausend Einsaetze" und
/// verschiebt die verbindliche Zahl in die Stufe-4-Ueberarbeitung. Frei
/// waehlbar ist sie nicht: `design.md` §20.3 fordert „Ein Reader verifiziert
/// und indiziert mindestens 50.000 Pakete", die Kriterienliste fuehrt sie als
/// AK 31 und die Anforderungstabelle als `NFR-PERF-003`, und Stufe 7 misst sie
/// in `tests/ea-system-tests/tests/performance_reader_50000.rs` mit genau
/// dieser Zahl. Eine Schwelle UNTERHALB davon lieferte eine
/// Stufe-4-Indexarchitektur, die ihr eigenes Stufe-7-Gate nachweislich nicht
/// bestehen kann.
///
/// Die Einheit ist ausdruecklich das PAKET und nicht der Einsatz: ein Einsatz
/// traegt ein Original plus seine Nachtraege, die beide je ein eigenes Paket
/// sind.
pub const MONOLITHIC_INDEX_MAX_PACKAGES_V1: usize = 50_000;

/// Der Zustand des Bestands nach einer Aufnahme.
///
/// `SegmentationRequired` ist ein SIGNAL und keine Weigerung: die Suche bleibt
/// vollstaendig korrekt, und der Wechsel auf segmentierte, einzeln
/// verschluesselte Indexbloecke ist die von `web-reader-design.md` §8.1 vorab
/// genehmigte Massnahme.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IndexPressureV1 {
    /// Der Bestand liegt unterhalb von [`MONOLITHIC_INDEX_MAX_PACKAGES_V1`].
    #[default]
    Nominal,
    /// Die Schwelle ist erreicht oder ueberschritten.
    SegmentationRequired {
        /// Die Zahl der indizierten Pakete NACH dieser Aufnahme.
        indexed_packages: usize,
    },
}

/// Die EINGABE des Index — deklariert HIER und nicht im Reader.
///
/// Sie traegt abgeleitete Werte plus die Herkunftsspalten, die an jeder
/// Indexzeile haengen muessen. Keine Nutzlastbytes, kein Geheimniswrapper, kein
/// Zeugentyp: ein gewoehnlicher Wert, den diese Crate ohne jede Kenntnis des
/// Readers bauen, pruefen und ablegen kann.
///
/// # Wer normalisiert
///
/// Der TERMSCHLUESSEL entsteht in dieser Crate und nirgends sonst. Die Felder
/// hier tragen die projizierten Werte in ihrer Anzeigeform; die Faltung auf den
/// Suchschluessel rechnet [`InvertedIndexV1`] beim Aufnehmen UND beim Suchen
/// ueber denselben Weg. Muesste der Aufrufer vornormalisieren, gaebe es zwei
/// Normalisierer — und zwei Normalisierer, die auseinanderlaufen, liefern eine
/// Suche, die ihren eigenen Bestand nicht mehr findet.
pub struct IndexableRecordV1 {
    // Herkunft — an jeder Zeile, in jeder Suche, in jedem Treffer.
    /// Der Entry-Hash des Pakets. Er ist zugleich die IDENTITAET der Zeile.
    pub source_entry_hash: EntryHash,
    /// Die Kettensequenz des Pakets.
    pub chain_sequence: ChainSequence,
    /// Die Datensatzkennung aus dem gemeinsamen Kopf der Nutzlast.
    pub record_id: RecordId,
    /// Die Kennung des QUELLSCHEMAS.
    pub source_schema_id: String,
    /// Die Fassung des Quellschemas.
    pub source_schema_version: u64,
    /// Die Kennung des ZIELSCHEMAS der Ansicht.
    pub target_schema_id: String,
    /// Die Fassung des Zielschemas.
    pub target_schema_version: u64,
    // Die abgeleiteten Werte.
    /// Die menschliche Einsatznummer, in ihrer Anzeigeform.
    pub human_incident_number: String,
    /// Der Beginn des Einsatzzeitraums.
    pub occurred_at_start: UnixMillis,
    /// Sein Ende, sofern der Einsatz eines traegt.
    pub occurred_at_end: Option<UnixMillis>,
    /// Die Stichworttexte.
    pub keyword_terms: Vec<String>,
    /// Die Fahrzeugbezeichner: Anzeigename, Funkrufname, Kennzeichen.
    pub vehicle_terms: Vec<String>,
    /// Die Personennamen.
    pub person_terms: Vec<String>,
}

/// Eine Zeile des Index.
///
/// Sie traegt Herkunft UND beide Schemabeschriftungen, weil eine Zeile ohne sie
/// nicht sagen koennte, woraus sie hervorgegangen ist.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderSearchHitV1 {
    entry_hash: EntryHash,
    chain_sequence: ChainSequence,
    record_id: RecordId,
    human_incident_number: String,
    occurred_at_start: UnixMillis,
    source_schema_id: String,
    source_schema_version: u64,
    target_schema_id: String,
    target_schema_version: u64,
}

impl ReaderSearchHitV1 {
    /// Der Entry-Hash des Pakets, aus dem diese Zeile hervorgegangen ist.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Seine Kettensequenz.
    #[must_use]
    pub const fn chain_sequence(&self) -> ChainSequence {
        self.chain_sequence
    }

    /// Seine Datensatzkennung.
    #[must_use]
    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }

    /// Die menschliche Einsatznummer.
    #[must_use]
    pub fn human_incident_number(&self) -> &str {
        &self.human_incident_number
    }

    /// Der Beginn des Einsatzzeitraums.
    #[must_use]
    pub const fn occurred_at_start(&self) -> UnixMillis {
        self.occurred_at_start
    }

    /// Quellschema und -fassung.
    #[must_use]
    pub fn source_schema(&self) -> (&str, u64) {
        (&self.source_schema_id, self.source_schema_version)
    }

    /// Zielschema und -fassung.
    #[must_use]
    pub fn target_schema(&self) -> (&str, u64) {
        (&self.target_schema_id, self.target_schema_version)
    }
}

/// Kein abgeleitetes `Debug`: die Einsatznummer ist ein aus entschluesseltem
/// Inhalt abgeleiteter Wert, und eine Formatierung traegt ihn in Meldungen und
/// Protokolle. Ausgewiesen wird die HERKUNFT, an der ein Treffer ohnehin
/// haengt.
impl fmt::Debug for ReaderSearchHitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderSearchHitV1 { chain_sequence: ")?;
        fmt::Debug::fmt(&self.chain_sequence, formatter)?;
        formatter.write_str(", human_incident_number: <redacted> }")
    }
}

/// Ein aufgenommenes Paket: seine Zeile, sein Zeitraumende und seine Terme.
///
/// Die Terme bleiben am Paket, weil der versiegelte Koerper GENAU EINE
/// Darstellung traegt — die Pakete — und die drei Trefferlisten beim Oeffnen
/// daraus neu entstehen. Ein Koerper, der beide getrennt truege, koennte einen
/// Term nennen, zu dem es kein Paket gibt.
#[derive(Clone)]
pub(crate) struct IndexedPackageV1 {
    pub(crate) hit: ReaderSearchHitV1,
    pub(crate) occurred_at_end: Option<UnixMillis>,
    pub(crate) keyword_terms: BTreeSet<String>,
    pub(crate) vehicle_terms: BTreeSet<String>,
    pub(crate) person_terms: BTreeSet<String>,
}

/// Die vier Filter, KONJUNKTIV verknuepft.
///
/// Gesetzt wird ueber die vier Konstruktoren, verkettet ueber die vier
/// `and_`-Methoden. Ein leerer Aufbau — kein einziger gesetzter Filter — trifft
/// den ganzen Bestand; die Oberflaeche entscheidet, ob sie das anbietet.
///
/// Die drei Textachsen vergleichen einen GANZEN normalisierten Feldwert. Es
/// wird nicht zerlegt und nicht gestemmt: eine Stemming-Regel waere eine
/// fachliche Entscheidung ueber Einsatzsprache, die dieses Projekt nirgends
/// getroffen hat, und ihr stiller Einbau machte die Suche zwischen zwei
/// Releases inkompatibel, ohne dass ein Byte des Archivs sich aenderte.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ReaderQueryV1 {
    period: Option<(UnixMillis, UnixMillis)>,
    keyword: Option<String>,
    vehicle: Option<String>,
    person: Option<String>,
}

impl ReaderQueryV1 {
    /// Der Zeitraumfilter: Ueberschneidung mit `[from, to]`.
    #[must_use]
    pub fn period(from: UnixMillis, to: UnixMillis) -> Self {
        Self::default().and_period(from, to)
    }

    /// Der Stichwortfilter.
    #[must_use]
    pub fn keyword(term: &str) -> Self {
        Self::default().and_keyword(term)
    }

    /// Der Fahrzeugfilter.
    #[must_use]
    pub fn vehicle(term: &str) -> Self {
        Self::default().and_vehicle(term)
    }

    /// Der Personenfilter.
    #[must_use]
    pub fn person(term: &str) -> Self {
        Self::default().and_person(term)
    }

    /// Setzt den Zeitraumfilter zusaetzlich.
    #[must_use]
    pub fn and_period(mut self, from: UnixMillis, to: UnixMillis) -> Self {
        self.period = Some((from, to));
        self
    }

    /// Setzt den Stichwortfilter zusaetzlich.
    #[must_use]
    pub fn and_keyword(mut self, term: &str) -> Self {
        self.keyword = Some(normalize_term(term));
        self
    }

    /// Setzt den Fahrzeugfilter zusaetzlich.
    #[must_use]
    pub fn and_vehicle(mut self, term: &str) -> Self {
        self.vehicle = Some(normalize_term(term));
        self
    }

    /// Setzt den Personenfilter zusaetzlich.
    #[must_use]
    pub fn and_person(mut self, term: &str) -> Self {
        self.person = Some(normalize_term(term));
        self
    }
}

/// Kein abgeleitetes `Debug`: ein Suchbegriff ist ein aus entschluesseltem
/// Inhalt abgeleiteter Wert, und eine abgeleitete Formatierung truege ihn in
/// jede Zusicherungsmeldung, jedes Protokoll und jede Telemetriezeile.
/// Ausgewiesen werden die GESETZTEN Achsen und kein Wert.
impl fmt::Debug for ReaderQueryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderQueryV1 { axes: [")?;
        let mut written = 0_usize;
        for (name, set) in [
            ("period", self.period.is_some()),
            ("keyword", self.keyword.is_some()),
            ("vehicle", self.vehicle.is_some()),
            ("person", self.person.is_some()),
        ] {
            if !set {
                continue;
            }
            if written > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(name)?;
            written += 1;
        }
        formatter.write_str("] }")
    }
}

/// Der invertierte Index ueber entschluesselte Feldwerte.
///
/// Der Bestand liegt in `BTreeMap`/`BTreeSet` ueber den Entry-Hash und den
/// normalisierten Termschluessel. Das ist keine Geschmacksfrage: die
/// Einfuegereihenfolge DARF die versiegelten Bytes nicht erreichen, sonst waere
/// ein Rebuild keine Rekonstruktion, sondern eine zweite Wahrheit ueber
/// denselben Bestand.
#[derive(Clone, Default)]
pub struct InvertedIndexV1 {
    pub(crate) packages: BTreeMap<EntryHash, IndexedPackageV1>,
    keyword: BTreeMap<String, BTreeSet<EntryHash>>,
    vehicle: BTreeMap<String, BTreeSet<EntryHash>>,
    person: BTreeMap<String, BTreeSet<EntryHash>>,
}

impl InvertedIndexV1 {
    /// Der leere Bestand.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Nimmt einen Datensatz auf oder ERSETZT die Zeile derselben Herkunft.
    ///
    /// Die Identitaet einer Zeile ist ihr Entry-Hash. Ein zweiter Lauf ueber
    /// denselben Bestand zaehlt deshalb nicht hoch, und die Schwelle bleibt
    /// eine Zaehlung von Paketen statt von Aufrufen.
    ///
    /// Geprueft wird VOR jeder Veraenderung: ein Bestand, der die Zeile schon
    /// entfernt und erst danach abgewiesen haette, verloere ein Paket an einem
    /// Datensatz, den er gar nicht aufgenommen hat.
    ///
    /// # Errors
    /// `EA-SCHEMA-UNSUPPORTED`, wenn das Zielschema von dieser Fassung nicht
    /// projiziert werden kann. Der Datensatz wird ISOLIERT: es entsteht keine
    /// Zeile, [`InvertedIndexV1::indexed_packages`] steigt nicht, und der
    /// technische Zustand des Datensatzes liegt im Zustandsspeicher des
    /// Readers und nicht hier.
    pub fn upsert(&mut self, record: &IndexableRecordV1) -> Result<IndexPressureV1, IndexError> {
        let view = SchemaViewV1::derive(record)?;
        let package = IndexedPackageV1 {
            hit: ReaderSearchHitV1 {
                entry_hash: record.source_entry_hash,
                chain_sequence: record.chain_sequence,
                record_id: record.record_id,
                human_incident_number: view.human_incident_number().to_owned(),
                occurred_at_start: record.occurred_at_start,
                source_schema_id: view.source_schema().0.to_owned(),
                source_schema_version: view.source_schema().1,
                target_schema_id: view.target_schema().0.to_owned(),
                target_schema_version: view.target_schema().1,
            },
            occurred_at_end: record.occurred_at_end,
            keyword_terms: term_keys(&record.keyword_terms),
            vehicle_terms: term_keys(&record.vehicle_terms),
            person_terms: term_keys(&record.person_terms),
        };
        self.replace(package);
        Ok(self.pressure())
    }

    /// Baut den Bestand aus den exakt zwischengespeicherten Datensaetzen NEU.
    ///
    /// Kein veraenderlicher Indexzustand ist massgeblich: massgeblich sind die
    /// exakten Archivbytes im Cache, und der Index ist ihre ableitbare
    /// Projektion. Deshalb ist der Verlust des Blobs kein Datenverlust.
    ///
    /// # Errors
    /// Wie [`InvertedIndexV1::upsert`], beim ersten nicht projizierbaren
    /// Datensatz.
    pub fn rebuild_from<'a>(
        records: impl IntoIterator<Item = &'a IndexableRecordV1>,
    ) -> Result<Self, IndexError> {
        let mut index = Self::empty();
        for record in records {
            index.upsert(record)?;
        }
        Ok(index)
    }

    /// Die vier Filter, konjunktiv ueber den lokalen Bestand.
    ///
    /// Die Reihenfolge der Treffer ist die Kettenordnung und nicht die
    /// Trefferreihenfolge einer Liste: `(chain_sequence, entry_hash)`. Eine
    /// Ordnung, die von der inneren Ablage abhinge, waere zwischen zwei
    /// Bestaenden derselben Menge verschieden.
    ///
    /// # Errors
    /// Heute keiner. Der `Result` steht, weil die vorab genehmigte
    /// Segmentierung ihre Bloecke einzeln oeffnen wird und ein Fehlschlag dort
    /// eine Suche betrifft, nicht eine Aufnahme.
    pub fn search(&self, query: &ReaderQueryV1) -> Result<Vec<ReaderSearchHitV1>, IndexError> {
        let mut candidates: Option<BTreeSet<EntryHash>> = None;
        for (term, postings) in [
            (query.keyword.as_ref(), &self.keyword),
            (query.vehicle.as_ref(), &self.vehicle),
            (query.person.as_ref(), &self.person),
        ] {
            let Some(term) = term else { continue };
            let matched = postings.get(term).cloned().unwrap_or_default();
            candidates = Some(match candidates {
                Some(previous) => previous.intersection(&matched).copied().collect(),
                None => matched,
            });
        }

        let mut hits: Vec<&IndexedPackageV1> = match &candidates {
            Some(entry_hashes) => entry_hashes
                .iter()
                .filter_map(|entry_hash| {
                    // Die Invariante, auf der die Gestalt des versiegelten
                    // Koerpers ruht: jede Herkunft einer Trefferliste hat ein
                    // Paket. Ohne diese Zusicherung meldete eine verwaiste
                    // Trefferliste sich nie — die Suche zaehlte still zu wenig,
                    // und genau das ist der Fehlschlag, den kein Zeuge saehe.
                    debug_assert!(
                        self.packages.contains_key(entry_hash),
                        "a posting list may only name packages that exist"
                    );
                    self.packages.get(entry_hash)
                })
                .collect(),
            None => self.packages.values().collect(),
        };
        if let Some((from, to)) = query.period {
            hits.retain(|package| package.overlaps(from, to));
        }
        hits.sort_unstable_by_key(|package| {
            (
                package.hit.chain_sequence.get(),
                *package.hit.entry_hash.as_bytes(),
            )
        });
        Ok(hits
            .into_iter()
            .map(|package| package.hit.clone())
            .collect())
    }

    /// Die Zahl der indizierten Pakete.
    #[must_use]
    pub fn indexed_packages(&self) -> usize {
        self.packages.len()
    }

    /// Der Weg zurueck an einen Treffer laeuft ueber die HERKUNFTSKENNUNG und
    /// nie ueber eine Zeilennummer.
    #[must_use]
    pub fn hit_for(&self, entry_hash: EntryHash) -> Option<&ReaderSearchHitV1> {
        self.packages.get(&entry_hash).map(|package| &package.hit)
    }

    /// Der Schwellenzustand des Bestands.
    ///
    /// Er wird GERECHNET und nirgends gehalten: er ist eine Aussage ueber die
    /// Zahl der indizierten Pakete und keine Eigenschaft der versiegelten
    /// Bytes. Ein mitversiegelter Zustand koennte dem Bestand widersprechen,
    /// aus dem er stammt.
    #[must_use]
    pub fn pressure(&self) -> IndexPressureV1 {
        let indexed_packages = self.indexed_packages();
        if indexed_packages >= MONOLITHIC_INDEX_MAX_PACKAGES_V1 {
            IndexPressureV1::SegmentationRequired { indexed_packages }
        } else {
            IndexPressureV1::Nominal
        }
    }

    /// Legt ein Paket ab und raeumt die Trefferlisten der ersetzten Zeile.
    fn replace(&mut self, package: IndexedPackageV1) {
        let entry_hash = package.hit.entry_hash;
        if let Some(previous) = self.packages.remove(&entry_hash) {
            for (terms, postings) in [
                (&previous.keyword_terms, &mut self.keyword),
                (&previous.vehicle_terms, &mut self.vehicle),
                (&previous.person_terms, &mut self.person),
            ] {
                for term in terms {
                    let empty = postings.get_mut(term).is_some_and(|entries| {
                        entries.remove(&entry_hash);
                        entries.is_empty()
                    });
                    if empty {
                        postings.remove(term);
                    }
                }
            }
        }
        for (terms, postings) in [
            (&package.keyword_terms, &mut self.keyword),
            (&package.vehicle_terms, &mut self.vehicle),
            (&package.person_terms, &mut self.person),
        ] {
            for term in terms {
                postings.entry(term.clone()).or_default().insert(entry_hash);
            }
        }
        self.packages.insert(entry_hash, package);
    }
}

/// Kein abgeleitetes `Debug`: der Bestand IST entschluesselter Inhalt.
/// Ausgewiesen wird ausschliesslich seine Groesse.
impl fmt::Debug for InvertedIndexV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvertedIndexV1 { indexed_packages: ")?;
        fmt::Display::fmt(&self.packages.len(), formatter)?;
        formatter.write_str(", terms: <redacted> }")
    }
}

impl IndexedPackageV1 {
    /// Ob der Einsatzzeitraum sich mit `[from, to]` ueberschneidet.
    ///
    /// Ein Einsatz ohne Ende ist ein PUNKT und kein offenes Intervall: das Ende
    /// fehlt, weil es nicht bekannt ist, und ein unbekanntes Ende als „bis
    /// heute" zu lesen waere eine Behauptung ueber den Einsatz statt ueber die
    /// Daten.
    fn overlaps(&self, from: UnixMillis, to: UnixMillis) -> bool {
        let start = self.hit.occurred_at_start.get();
        let end = self
            .occurred_at_end
            .unwrap_or(self.hit.occurred_at_start)
            .get();
        start <= to.get() && end >= from.get()
    }
}

/// Die geordnete, doppelfreie Menge der Termschluessel einer Achse.
fn term_keys(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| normalize_term(value))
        .filter(|term| !term.is_empty())
        .collect()
}

/// Der Termschluessel eines Feldwerts: NFC, klein gefaltet, wieder NFC.
///
/// Die Reihenfolge ist GERECHNET und nicht gewaehlt. Die Faltung allein
/// genuegt nicht — `o` mit kombinierendem Trema und `ö` sind vor der
/// Zusammensetzung verschiedene Zeichenketten. Die Zusammensetzung allein
/// genuegt ebenso wenig — `ÖLSPUR` und `Ölspur` sind vor der Faltung
/// verschieden. Und die zweite Zusammensetzung steht, weil `str::to_lowercase`
/// nicht zusicherungsgemaess NFC-erhaltend ist; ohne sie truege ein
/// Termschluessel im Einzelfall eine zerlegte Form, und
/// `ea_cbor::validate` wiese den versiegelten Koerper mit `EA-CBOR-NON-NFC` ab
/// — an der Versiegelung, nicht beim Suchen.
///
/// Gefaltet wird ueber `str::to_lowercase` der Standardbibliothek: sie rechnet
/// die volle, sprachunabhaengige Kleinschreibung des Unicode-Standards. Eine
/// eigene Tabelle waere eine zweite Wahrheit ueber dieselbe Abbildung.
///
/// # Die BENANNTE Grenze: Kleinschreibung ist kein Case Folding
///
/// Unicode §3.13 schreibt fuer schreibungsunabhaengiges Vergleichen
/// `toCaseFold` vor; `toLowerCase` ist eine Anzeigeabbildung und traegt die
/// kontextabhaengige Schluss-Sigma-Regel. Die Standardbibliothek kennt kein
/// Case Folding, und der Arbeitsbereich fuehrt keine Crate, die es rechnete.
/// GEMESSEN heisst das: `ΣΣ` wird als `σς` abgelegt und von der Anfrage `σσ`
/// NICHT gefunden, `STRASSE` nicht von `straße`, und die Ligatur `ﬁre` nicht
/// von `fire` — letzteres eine Folge davon, dass NFC und nicht NFKC gilt, und
/// NFC ist durch den Waechter von `ea-cbor` erzwungen.
///
/// Das ist ein RUECKRUFmangel und kein Korrektheitsmangel: die Ablage bleibt
/// deterministisch, der Rebuild bytegleich, und kein Datensatz geht verloren.
/// Es steht hier, statt in einer Zusage ueber „schreibungsunabhaengige Suche"
/// unterzugehen.
fn normalize_term(value: &str) -> String {
    value
        .nfc()
        .collect::<String>()
        .to_lowercase()
        .nfc()
        .collect()
}

/// Die Anzeigeform eines Werts: NFC, ohne Faltung.
///
/// Sie steht neben [`normalize_term`], weil eine Einsatznummer ANGEZEIGT und
/// nicht gesucht wird. NFC trotzdem, denn jede Textzeichenkette des
/// versiegelten Koerpers laeuft durch den NFC-Waechter von `ea-cbor`.
pub(crate) fn normalize_display(value: &str) -> String {
    value.nfc().collect()
}
