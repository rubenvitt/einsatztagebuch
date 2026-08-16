//! Archivfixtures fuer `ea-archive` und alles, was darauf aufbaut.
//!
//! Dieses Modul wird per `#[path]` in Testtargets eingebunden, nie in das
//! Lib-Target. Damit bleibt `ed25519-dalek` aus dem Lib-Graphen, es entsteht
//! kein Feature-Flag und `clippy --all-features` sieht keinen Fixture-Code im
//! Lib-Target.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene, genau wie im
//! Trust-Support.
#![allow(dead_code)]

/// Das Trust-Support-Modul aus `ea-trust`, unveraendert weiterverwendet.
///
/// Liefert `RegistryLineBuilder`, `ActionSpec`, `HeadOptions`, `BuiltHead`,
/// `Pin`, `source()` und `verified()`. Hier wird nichts davon nachgebaut.
#[path = "../../../ea-trust/tests/support/mod.rs"]
pub mod trust_support;

/// Das Format-Support-Modul aus `ea-format`, unveraendert weiterverwendet.
///
/// Liefert die signierten Wirebytes der Objektfamilien. Hier wird kein COSE
/// nachgebaut.
#[path = "../../../ea-format/tests/support/mod.rs"]
pub mod format_support;

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use ea_crypto::CoseSigner;
use ea_format::{
    EAG_PREFIX_V1, ECP_PREFIX_V1, EDS_PREFIX_V1, EIP_PREFIX_V1, ESR_PREFIX_V1, ETB_PREFIX_V1,
    EntryPackageV1, ExactObjectBytes, SignedManifestV1, encode_entry_package,
};
use ea_trust::TrustObjectSource;

/// Die sechs 9-Byte-Exact-Object-Praefixe aus `crates/ea-format/src/parser.rs`.
pub const EXACT_OBJECT_PREFIXES_V1: [[u8; 9]; 6] = [
    EIP_PREFIX_V1,
    EAG_PREFIX_V1,
    ESR_PREFIX_V1,
    ECP_PREFIX_V1,
    ETB_PREFIX_V1,
    EDS_PREFIX_V1,
];

/// Traegt `bytes` eines der sechs Exact-Object-Praefixe?
///
/// Nur zur Absicherung der Fixtures selbst. Die verbindliche Klassifikation
/// des Bestands entsteht im Inventar, nicht hier.
#[must_use]
pub fn has_exact_object_prefix(bytes: &[u8]) -> bool {
    EXACT_OBJECT_PREFIXES_V1
        .iter()
        .any(|prefix| bytes.starts_with(prefix))
}

/// Ein Bestand im Speicher: geordnete Paare aus Pfadhinweis und Bytes.
///
/// Bewusst eine `Vec` und keine Abbildung ueber den Pfad: ein Bestand darf
/// dieselben Bytes mehrfach und unter beliebigen Hinweisen tragen, und genau
/// das muss pruefbar bleiben.
#[derive(Clone, Default)]
pub struct ArchiveFixture {
    blobs: Vec<(String, Vec<u8>)>,
}

impl ArchiveFixture {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Legt ein Archivobjekt ab.
    pub fn push_object(&mut self, path_hint: &str, object: ExactObjectBytes) -> &mut Self {
        self.push_exact_bytes(path_hint, object.into_vec())
    }

    /// Legt bereits kodierte Objektbytes ab.
    ///
    /// Fuer die Fixtures aus [`format_support`], die `Vec<u8>` liefern, weil
    /// `ExactObjectBytes::new` `pub(crate)` in `ea-format` ist.
    pub fn push_exact_bytes(&mut self, path_hint: &str, bytes: Vec<u8>) -> &mut Self {
        assert!(
            has_exact_object_prefix(&bytes),
            "push_object expects exact object bytes: {path_hint}"
        );
        self.blobs.push((path_hint.to_owned(), bytes));
        self
    }

    /// Legt Beiwerk ab — Bytes ohne Exact-Object-Praefix.
    pub fn push_non_object(&mut self, path_hint: &str, bytes: &[u8]) -> &mut Self {
        assert!(
            !has_exact_object_prefix(bytes),
            "push_non_object expects bytes without an exact object prefix: {path_hint}"
        );
        self.blobs.push((path_hint.to_owned(), bytes.to_vec()));
        self
    }

    #[must_use]
    pub fn blobs(&self) -> &[(String, Vec<u8>)] {
        &self.blobs
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Derselbe Bestand unter vertauschten Pfaden und in anderer Reihenfolge.
    ///
    /// Die Bytes bleiben als Multimenge identisch; nur die Hinweise wandern um
    /// eine Stelle weiter und der Durchlauf laeuft rueckwaerts. Da Pfade nie
    /// klassifizieren, muss jede Aussage ueber den Bestand unveraendert
    /// bleiben. Deterministisch statt zufaellig, damit ein Fehlschlag
    /// reproduzierbar ist.
    #[must_use]
    pub fn randomized_paths(&self) -> Self {
        let count = self.blobs.len();
        if count == 0 {
            return Self::default();
        }
        let mut blobs: Vec<(String, Vec<u8>)> = (0..count)
            .map(|index| {
                (
                    self.blobs[(index + 1) % count].0.clone(),
                    self.blobs[index].1.clone(),
                )
            })
            .collect();
        blobs.reverse();
        Self { blobs }
    }
}

impl ArchiveSource for ArchiveFixture {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path_hint, bytes) in &self.blobs {
            visitor(ArchiveBlob::new(path_hint, bytes))?;
        }
        Ok(())
    }
}

/// Ein Bestand mitsamt den Bytes, aus denen er gebaut wurde.
///
/// Der Trust Anchor liegt BEWUSST neben dem Bestand und nicht darin: er ist
/// nach `design.md` §11.4 nie Teil der Inventarklassifikation, sondern wird
/// der Verifikation als Parameter uebergeben.
pub struct BuiltArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    pub eip: Vec<u8>,
    pub eag: Vec<u8>,
    pub esr: Vec<u8>,
    pub ecp: Vec<u8>,
    pub eds: Vec<u8>,
    pub trust_object_count: usize,
    pub non_object_count: usize,
}

/// Baut einen Bestand aus einer Registrierungslinie, den vier Objektfamilien
/// und Beiwerk.
///
/// Die Vertrauensablage stammt vollstaendig aus [`trust_support`]; die
/// signierten Objekte stammen vollstaendig aus [`format_support`]. Die
/// Verteilung der Trust-Objekte auf Unterverzeichnisse ist beliebig, weil der
/// Pfad ein Hinweis ist und nie klassifiziert — das Inventar muss dieselbe
/// Aussage liefern, egal wo die Bytes liegen.
#[must_use]
pub fn canonical_archive() -> BuiltArchive {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        trust_support::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: None,
        },
        trust_support::HeadOptions::default(),
    );

    let mut fixture = ArchiveFixture::new();
    let mut trust_object_count = 0;
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .expect("the fixture trust line must enumerate");
    for hash in hashes {
        let bytes = source
            .read_exact_trust_object(hash)
            .expect("the fixture trust line must read")
            .expect("an enumerated trust object must be readable");
        fixture.push_exact_bytes(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes.to_vec(),
        );
        trust_object_count += 1;
    }

    let (entry, eip) = signed_entry_package();
    let eds = format_support::valid_eds_from_entry(&entry, &eip);
    let eag = format_support::valid_initial_eag();
    let esr = format_support::valid_esr();
    let ecp = format_support::valid_ecp();

    fixture.push_exact_bytes(
        &format!("{}000000000001_entry.eip", ea_archive::ENTRIES_DIR_V1),
        eip.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}entry_grant.eag", ea_archive::GRANTS_DIR_V1),
        eag.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}entry.esr", ea_archive::RECEIPTS_DIR_V1),
        esr.clone(),
    );
    fixture.push_exact_bytes(
        &format!(
            "{}000000000001_checkpoint.ecp",
            ea_archive::CHECKPOINTS_DIR_V1
        ),
        ecp.clone(),
    );
    fixture.push_exact_bytes(
        &format!(
            "{}000000000001_entry.eds",
            ea_archive::DESTROYED_ENTRIES_DIR_V1
        ),
        eds.clone(),
    );

    // Beiwerk nach §11.4: traegt kein Exact-Object-Praefix und zaehlt nur in
    // nonObjectFileCount.
    let mut non_object_count = 0;
    for (path_hint, bytes) in [
        (
            ea_archive::README_FORMAT_FILE_V1,
            &b"Einsatzarchiv v1\n"[..],
        ),
        (ea_archive::COMPATIBILITY_MATRIX_FILE_V1, &b"{}\n"[..]),
    ] {
        fixture.push_non_object(path_hint, bytes);
        non_object_count += 1;
    }

    BuiltArchive {
        fixture,
        anchor_bytes: line.exact_anchor_bytes().to_vec(),
        eip,
        eag,
        esr,
        ecp,
        eds,
        trust_object_count,
        non_object_count,
    }
}

/// Die Stelle im `.eip` aus [`signed_entry_package`], an der genau ein Byte
/// verkippt wird, um einen Parse-Fehlschlag zu erzeugen.
///
/// Byte 50 ist das CBOR-`null` (`0xf6`) eines optionalen Feldes im
/// Manifestkern. `0xf6 ^ 0x01` ergibt `0xf7` (`undefined`): ein wohlgeformtes
/// CBOR-Element, das die aeussere Strukturpruefung passiert und erst an der
/// Formpruefung des Manifestkerns scheitert. Genau deshalb ist der Fehler
/// [`MUTATED_EIP_FORMAT_ERROR_CODE_V1`] und kein `EA-CBOR-*`.
///
/// Bewusst eine feste Stelle und keine Suche: eine Suche wuerde bei einer
/// Layoutaenderung in `ea-format` stillschweigend eine andere Fehlerklasse
/// treffen. Diese Konstante bricht stattdessen laut.
pub const MUTATED_EIP_BODY_OFFSET_V1: usize = 50;

/// Der Fehlercode, den [`eip_with_one_mutated_body_byte`] erzeugt.
pub const MUTATED_EIP_FORMAT_ERROR_CODE_V1: &str = "EA-FORMAT-SHAPE";

/// Das kanonische `.eip` mit genau EINEM verkippten Byte im CBOR-Rumpf.
///
/// Das Exact-Object-Praefix bleibt unangetastet: die Bytes sind damit
/// weiterhin ein Archivobjekt im Sinne von `design.md` §11.4 und muessen als
/// Quarantaenefall mit Grund `malformed` erscheinen, nicht als Beiwerk.
#[must_use]
pub fn eip_with_one_mutated_body_byte() -> Vec<u8> {
    let (_, eip) = signed_entry_package();
    let mut mutated = eip.clone();
    mutated[MUTATED_EIP_BODY_OFFSET_V1] ^= 0x01;

    assert_eq!(
        mutated.len(),
        eip.len(),
        "the mutation must not change the byte length"
    );
    assert_eq!(
        mutated
            .iter()
            .zip(eip.iter())
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "exactly one byte must differ"
    );
    assert!(
        mutated.starts_with(&EIP_PREFIX_V1),
        "the mutation must leave the exact object prefix intact"
    );
    let error = ea_format::decode_exact_object(&mutated)
        .expect_err("the mutated entry package must fail to parse");
    assert_eq!(
        error.code(),
        MUTATED_EIP_FORMAT_ERROR_CODE_V1,
        "the pinned mutation offset must keep producing the pinned format error"
    );
    mutated
}

/// Ein signiertes `.eip` mitsamt dem Wert, aus dem das `.eds` gebaut wird.
///
/// Baut genau wie `format_support::valid_eip`, gibt aber zusaetzlich den
/// `EntryPackageV1` heraus, den `valid_eds_from_entry` verlangt.
#[must_use]
pub fn signed_entry_package() -> (EntryPackageV1, Vec<u8>) {
    let ciphertext = vec![0x5a; 16];
    let manifest = format_support::manifest_for_ciphertext(&ciphertext)
        .expect("the fixture manifest must encode");
    let signed =
        SignedManifestV1::new(manifest, &ciphertext).expect("the fixture manifest must sign");
    let signature = signer()
        .sign_record(signed.exact_bytes())
        .expect("the fixture signer must sign");
    let entry = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("the fixture entry package must assemble");
    let eip = encode_entry_package(&entry)
        .expect("the fixture entry package must encode")
        .into_vec();
    (entry, eip)
}

fn signer() -> CoseSigner {
    format_support::signer()
}
