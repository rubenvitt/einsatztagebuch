//! Der Vertrauensanker, der ausschliesslich aus dem Tresor kommt.
//!
//! `web-reader-design.md` §5.3: Trust-Objekte, die in einer geoeffneten Datei
//! mitliegen, begruenden fuer sich KEIN Vertrauen. Dieses Modul macht daraus
//! eine Typaussage statt einer Bitte — es gibt genau einen Weg an einen
//! [`PinnedTrustAnchor`], und der beginnt an einer entsperrten Sitzung.
//!
//! # Die `compile_fail`-Doctests sind der Beleg
//!
//! Sie stehen in derselben Bauform wie die von `crates/ea-key-provider/src/lib.rs`
//! und sind der EINZIGE Beleg: `verify-quick` faehrt Clippy mit
//! `--all-features`, und das Workspace-Testkommando laeuft mit `--all-targets`,
//! was Doctests gerade ausschliesst. Sie fahren allein in
//! `cargo test --workspace --doc --all-features --locked`.
//!
//! Aus rohen Archivbytes entsteht kein gepinnter Anker:
//!
//! ```compile_fail
//! use ea_reader::PinnedTrustAnchor;
//!
//! fn anchor_from_archive_bytes(exact_bytes: &[u8]) -> PinnedTrustAnchor<'_> {
//!     PinnedTrustAnchor::from_bytes(exact_bytes)
//! }
//! ```
//!
//! Und aus einer geoeffneten Quelle auch nicht — das ist §5.3 woertlich:
//!
//! ```compile_fail
//! use ea_reader::{ArchiveSource, PinnedTrustAnchor};
//!
//! fn anchor_from_the_opened_file(source: &dyn ArchiveSource) -> PinnedTrustAnchor<'_> {
//!     PinnedTrustAnchor::from_source(source)
//! }
//! ```
//!
//! Ein gepinnter Anker laesst sich auch nicht verdoppeln und dadurch von seiner
//! Sitzung loesen. Die RUECKGABEANNOTATION traegt diesen Zeugen: `anchor.clone()`
//! loeste sonst ueber die Autoreferenz auf `<&PinnedTrustAnchor as Clone>` auf
//! und uebersetzte anstandslos zu einem `&PinnedTrustAnchor`.
//!
//! ```compile_fail
//! use ea_reader::{PinnedTrustAnchor, UnlockedVault};
//!
//! fn duplicated(session: &UnlockedVault) -> PinnedTrustAnchor<'_> {
//!     let anchor = PinnedTrustAnchor::from_vault(session);
//!     anchor.clone()
//! }
//! ```
//!
//! Der folgende Block UEBERSETZT und benennt jeden Pfad, den die drei
//! Negativbloecke brauchen. Ohne ihn belegten sie auch dann, wenn
//! `ea_reader::PinnedTrustAnchor` oder `ea_reader::ArchiveSource` gar nicht
//! aufloeste — sie waeren dann kein Beleg fuer einen fehlenden Konstruktor,
//! sondern nur fuer einen kaputten Import:
//!
//! ```
//! use ea_reader::{ArchiveSource, PinnedTrustAnchor, TrustAnchorV1, UnlockedVault};
//!
//! fn the_one_way_in(session: &UnlockedVault) -> &TrustAnchorV1 {
//!     PinnedTrustAnchor::from_vault(session).as_trust_anchor()
//! }
//!
//! fn a_source_never_reaches_the_anchor(_source: &dyn ArchiveSource) {}
//!
//! let _resolved: fn(&UnlockedVault) -> &TrustAnchorV1 = the_one_way_in;
//! let _named: fn(&dyn ArchiveSource) = a_source_never_reaches_the_anchor;
//! ```

use ea_trust::TrustAnchorV1;

use crate::vault::UnlockedVault;

/// Der beim Enrollment im Tresor gepinnte Root-Anker.
///
/// Es gibt KEINEN Konstruktor aus rohen Bytes und KEINEN aus einer
/// [`ea_archive::ArchiveSource`]. Waere hier ein `from_bytes`, waere §5.3 eine
/// Bitte statt einer Schranke.
///
/// # AUSLEIHEND und INFALLIBEL, beides gemessen
///
/// [`UnlockedVault`] fuehrt `pinned_anchor` als PFLICHTFELD ohne `Option`, und
/// `ReaderVault::unlock` baut es unbedingt aus
/// `decode_trust_anchor(&contents.pinned_anchor_exact_bytes)?`. Eine entsperrte
/// Sitzung OHNE Anker ist nicht konstruierbar; ein Fehlerarm dafuer waere ein
/// Zweig, den kein Zeuge je faerben koennte.
///
/// Und [`TrustAnchorV1`] traegt kein einziges `derive`. Ein BESITZENDER Wert
/// waere nur ueber einen zweiten vollstaendigen Dekodierlauf je Klassifikation
/// zu haben — Kosten ohne Gegenwert, denn der Anker der Sitzung ist bereits
/// erfolgreich dekodiert. Der Lebensdauerparameter bleibt deshalb lokal in
/// `ReaderVerifier::classify` und erscheint in keiner anderen oeffentlichen
/// Signatur; [`crate::ReaderClassification`] traegt keinen.
pub struct PinnedTrustAnchor<'a>(&'a TrustAnchorV1);

impl<'a> PinnedTrustAnchor<'a> {
    /// Der Anker DIESER Sitzung.
    ///
    /// Der einzige Konstruktor, und er nimmt die Sitzung — nicht Bytes, nicht
    /// eine Quelle, nicht einen Bestand.
    #[must_use]
    pub const fn from_vault(session: &'a UnlockedVault) -> Self {
        Self(session.pinned_anchor())
    }

    /// Der Anker als Eingabe von `ea_verify::verify_archive_observed`.
    ///
    /// Die Ausleihe haengt an der SITZUNG und nicht an diesem Wert: der
    /// Rueckgabewert traegt `'a` und ueberlebt damit einen fallengelassenen
    /// [`PinnedTrustAnchor`] — was der Aufrufer hier bekommt, gehoert dem
    /// Tresor und nicht der Huelle darum.
    #[must_use]
    pub const fn as_trust_anchor(&self) -> &'a TrustAnchorV1 {
        self.0
    }
}
