//! Schritt 4 und die Naht zu Schritt 11 der Ersteinrichtung.
//!
//! Die Spezifikation legt den vierten Schritt so fest: „vor der ersten
//! Admin-Autorisierung `organization-trust-anchor-pre-v1` aus Abschnitt 16.1
//! auf mindestens zwei Recovery-Medien dauerhaft festschreiben und dessen
//! Fingerprint ueber den zweiten Kanal bestaetigen"
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1339`).
//! Schritt 9 vergleicht Fingerprints ueber QR-Code oder zweiten Kanal
//! (`:1344`), Schritt 11 bildet den finalen Anker „aus unveraenderten
//! Vorstufenfeldern" und bestaetigt dessen Bytes erneut auf beiden Medien
//! (`:1346`).
//!
//! Und dann der Satz, der diese Datei traegt: „Jede Aenderung eines bereits in
//! Schritt 4 festgeschriebenen Feldes bricht das Setup ab und beginnt mit neuen
//! Organisations-/Ketten-IDs" (`:1349`). Dazu `:1780`: „Organisation, Kette,
//! Root-Felder, sortierte Admin-Zertifikat-/Binding-Hashes, deren Paarungen und
//! kritische Erweiterungen MUESSEN in Vorstufe und finalem Anchor bytegleich
//! sein. […] Mindestens zwei schreibgeschuetzte Recovery-Medien erhalten zuerst
//! die exakten Vorstufen- und vor Go-live die finalen Anchor-Bytes; eine
//! optionale Archivkopie ist nur informativ und niemals Vertrauensquelle."
//!
//! Diese Crate fuegt der Vertrauensschicht wieder KEINE Regel hinzu. Die Form
//! der Vorstufe gehoert `ea-trust` ([`ea_trust::decode_pre_anchor`]); hier wird
//! nur festgehalten, dass die Schritte STATTGEFUNDEN haben, und der Uebergang
//! zwischen ihnen geprueft.

use std::collections::BTreeSet;

use ea_crypto::bootstrap_anchor_hash;
use ea_trust::{PreAnchorV1, TrustAnchorV1};
use ea_types::Hash32;

use crate::AdminError;

/// Prueft, dass ein finaler Anker GENAU die Vorstufe fortsetzt, die auf den
/// Medien bestaetigt wurde.
///
/// # Warum das nicht dasselbe ist wie [`ea_trust::decode_trust_anchor`]
///
/// Das ist der Kern dieser Aufgabe, deshalb ausfuehrlich. Beim Dekodieren
/// rechnet die Vertrauensschicht die Vorstufe AUS DEN EIGENEN FELDERN des
/// finalen Ankers nach und vergleicht deren Hash gegen den eingebetteten
/// `bootstrapAnchorHash` (`crates/ea-trust/src/anchor.rs:665-676`). Das ist
/// eine Aussage ueber SELBSTKONSISTENZ — und die haelt auch dann, wenn eine
/// Zeremonie nach Schritt 4 still korrigiert wurde: wer Organisation, Kette,
/// Wurzelurkunde oder eine Admin-Hashliste aendert und den
/// `bootstrapAnchorHash` durchgaengig mitzieht, erhaelt einen finalen Anker,
/// den `decode_trust_anchor` ANSTANDSLOS annimmt. Er ist in sich fehlerfrei.
/// Er ist nur nicht der, auf den sich die Zeremonie festgelegt hatte.
///
/// Sichtbar wird das ausschliesslich gegen ein UNABHAENGIGES Zeugnis: die
/// exakten Bytes, die in Schritt 4 auf die schreibgeschuetzten Medien gingen
/// und deren Fingerprint ueber den zweiten Kanal zurueckkam. Genau die
/// vergleicht diese Funktion — byteweise, nicht feldweise, denn `:1780` sagt
/// „bytegleich" und nicht „gleichwertig".
///
/// Der Hashvergleich daneben ist bewusst redundant: er ist bei gleichen Bytes
/// nie verletzbar und steht als geschlossener Riegel fuer den Fall, dass diese
/// Funktion je auf einen feldweisen Vergleich umgebaut wuerde.
///
/// `genesisEntryHash` gehoert NICHT zur Vorstufe (`:1737-1748`) und geht in
/// diesen Vergleich folgerichtig nicht ein — er entsteht erst in Schritt 11.
///
/// # Errors
/// [`AdminError::AnchorPreFieldChanged`] mit `EA-ANCHOR-PRE-FIELD-CHANGED`,
/// sobald die Vorstufe des finalen Ankers von der bestaetigten abweicht. Ein
/// zweiter Code waere hier falsch: welches Feld sich geaendert hat, aendert an
/// der Folge nichts — das Setup beginnt mit neuen Organisations- und
/// Ketten-IDs von vorn.
pub fn verify_anchor_transition(
    pre: &PreAnchorV1,
    final_anchor: &TrustAnchorV1,
) -> Result<(), AdminError> {
    if pre.exact_bytes() != final_anchor.exact_pre_anchor_bytes() {
        return Err(AdminError::AnchorPreFieldChanged);
    }
    if pre.bootstrap_anchor_hash() != final_anchor.bootstrap_anchor_hash() {
        return Err(AdminError::AnchorPreFieldChanged);
    }
    Ok(())
}

/// Die Kennung EINES schreibgeschuetzten Recovery-Mediums.
///
/// Sechzehn Bytes und kein Pfad: welcher Datentraeger, welcher Tresor und
/// welches Gehaeuse gemeint ist, weiss der Betrieb und nicht diese Crate. Fuer
/// [`confirm_on_media`] zaehlt allein, dass zwei Kennungen UNTERSCHEIDBAR sind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AnchorMediumId([u8; 16]);

impl AnchorMediumId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Der Port zu den schreibgeschuetzten Recovery-Medien.
///
/// Zwei Methoden, und das ZurueckLESEN ist nicht optional: „dauerhaft
/// festschreiben" (`:1339`) ist eine Aussage ueber den Zustand NACH dem
/// Schreiben. Ein Port, der nur schreiben koennte, liesse
/// [`confirm_on_media`] eine Bestaetigung ausstellen, fuer die niemand je
/// nachgesehen hat.
///
/// Die Implementierung liegt ausserhalb dieser Crate: `ea-admin` kennt kein
/// Dateisystem und keinen Datentraeger.
pub trait AnchorMedia {
    /// Schreibt die EXAKTEN Bytes dauerhaft auf ein Medium.
    ///
    /// # Errors
    /// Ein Befund des Mediums, ueblicherweise
    /// [`AdminError::MediaUnavailable`].
    fn write_exact_bytes(
        &mut self,
        medium: AnchorMediumId,
        exact_bytes: &[u8],
    ) -> Result<(), AdminError>;

    /// Liest zurueck, was auf dem Medium steht.
    ///
    /// # Errors
    /// Ein Befund des Mediums, ueblicherweise
    /// [`AdminError::MediaUnavailable`].
    fn read_exact_bytes(&self, medium: AnchorMediumId) -> Result<Vec<u8>, AdminError>;
}

/// Der Rueckkanal hat den vollen Fingerprint bestaetigt.
///
/// Konstruierbar AUSSCHLIESSLICH in [`confirm_pre_anchor_fingerprint`], und
/// dort nur nach einem Vergleich. Kein `Default`, kein `Clone`, kein `Debug`,
/// und ausdruecklich kein inhaerenter `impl`-Block — der koennte eine zweite
/// Konstruktionsstelle hinter einer assoziierten Funktion verstecken. Das ist
/// dieselbe Bauart wie `ea_reader::FingerprintConfirmationV1`
/// (`crates/ea-reader/src/enrollment.rs:326-329`), und aus demselben Grund:
/// „ein Mensch hat das bestaetigt" ist keine Behauptung, die ein Aufrufer sich
/// selbst ausstellen darf.
///
/// Der Typ wird von [`confirm_on_media`] VERBRAUCHT und nicht geliehen; eine
/// Bestaetigung deckt genau EINEN Schreibvorgang.
pub struct SecondChannelConfirmation {
    confirmed_fingerprint: Hash32,
}

/// Vergleicht den ueber den ZWEITEN Kanal zurueckgemeldeten Fingerprint gegen
/// den, den diese Maschine ueber die Vorstufe rechnet (`:1339`, `:1780`).
///
/// Der gemeldete Wert kommt von aussen — abgetippt, abfotografiert oder am
/// Telefon vorgelesen. Verglichen wird ueber [`Hash32`] und nicht ueber eine
/// Zeichenkette, damit die Anzeigeform (Gross-/Kleinschreibung, Gruppierung)
/// keine falsche Abweichung erzeugt; die Kodierung der Anzeige gehoert der
/// Oberflaeche.
///
/// Ein Konstantzeitvergleich waere hier Theater: der Fingerprint ist der
/// oeffentlich verteilte Wert der Zeremonie und kein Geheimnis.
///
/// # Errors
/// [`AdminError::SecondChannelMismatch`], wenn die Rueckmeldung abweicht.
pub fn confirm_pre_anchor_fingerprint(
    pre: &PreAnchorV1,
    reported_fingerprint: Hash32,
) -> Result<SecondChannelConfirmation, AdminError> {
    if pre.bootstrap_anchor_hash() != reported_fingerprint {
        return Err(AdminError::SecondChannelMismatch);
    }
    Ok(SecondChannelConfirmation {
        confirmed_fingerprint: reported_fingerprint,
    })
}

/// Der Nachweis, dass Schritt 4 WIRKLICH stattgefunden hat.
///
/// Private Felder, kein oeffentlicher Konstruktor, kein `Default`, kein
/// `Clone`: die naechste Scheibe — der Koordinator des Zwoelfschrittablaufs —
/// verlangt diesen Typ als Eintrittskarte, und eine frei baubare Eintrittskarte
/// waere keine.
pub struct MediaConfirmation {
    fingerprint: Hash32,
    medium_count: usize,
}

impl MediaConfirmation {
    /// Der bestaetigte volle Fingerprint der geschriebenen Bytes.
    #[must_use]
    pub const fn fingerprint(&self) -> Hash32 {
        self.fingerprint
    }

    /// Die Zahl der Medien, die die Bytes nachweislich tragen — mindestens
    /// zwei.
    #[must_use]
    pub const fn medium_count(&self) -> usize {
        self.medium_count
    }
}

/// Schreibt die exakten Vorstufenbytes auf JEDES genannte Medium, liest sie
/// von jedem zurueck und verlangt ueberall Bytegleichheit.
///
/// Die Reihenfolge ist fail-closed: erst wird die Bestaetigung des zweiten
/// Kanals gegen genau DIESE Bytes gebunden, dann das Medienquorum geprueft,
/// dann geschrieben, und erst danach gelesen. Alle Schreibvorgaenge laufen vor
/// dem ersten Lesevorgang — sonst bestaetigte das erste Medium sich selbst,
/// waehrend das zweite noch leer waere.
///
/// # Die Bindung an die Bytes
///
/// [`SecondChannelConfirmation`] belegt „ein Mensch hat einen Fingerprint
/// bestaetigt". Ohne Bindung koennte dieselbe Bestaetigung ANDERE Bytes auf die
/// Medien tragen — genau der Angriff, gegen den Schritt 4 steht. Deshalb wird
/// `bootstrapAnchorHash` ueber die uebergebenen Bytes neu gerechnet und gegen
/// den bestaetigten Wert gehalten.
///
/// # Errors
/// [`AdminError::SecondChannelMismatch`], wenn die Bestaetigung nicht ueber
/// diese Bytes ausgestellt wurde; [`AdminError::MediaQuorumMissing`] fuer
/// weniger als zwei unterscheidbare Kennungen — auch dann, wenn dieselbe
/// Kennung mehrfach genannt wird, denn zwei Namen sind kein zweiter
/// Datentraeger; [`AdminError::MediaReadbackMismatch`] fuer jedes Medium, das
/// etwas anderes zurueckliest; sowie jeder Befund, den der Port selbst meldet.
pub fn confirm_on_media(
    media: &mut dyn AnchorMedia,
    ids: &[AnchorMediumId],
    exact_bytes: &[u8],
    fingerprint_confirmed: SecondChannelConfirmation,
) -> Result<MediaConfirmation, AdminError> {
    if bootstrap_anchor_hash(exact_bytes) != fingerprint_confirmed.confirmed_fingerprint {
        return Err(AdminError::SecondChannelMismatch);
    }

    let distinct: BTreeSet<AnchorMediumId> = ids.iter().copied().collect();
    if distinct.len() < 2 || distinct.len() != ids.len() {
        return Err(AdminError::MediaQuorumMissing);
    }

    for medium in ids {
        media.write_exact_bytes(*medium, exact_bytes)?;
    }
    for medium in ids {
        if media.read_exact_bytes(*medium)? != exact_bytes {
            return Err(AdminError::MediaReadbackMismatch);
        }
    }

    Ok(MediaConfirmation {
        fingerprint: fingerprint_confirmed.confirmed_fingerprint,
        medium_count: distinct.len(),
    })
}
