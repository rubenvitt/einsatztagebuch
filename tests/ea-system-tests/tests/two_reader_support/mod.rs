//! Zwei Reader, EIN Chiffrat: die Kulisse des Stufe-4-Systemzeugen
//! `cross_platform_two_readers`.
//!
//! # Der Bestand kommt aus der Registrierungslinie von `ea-verify`
//!
//! Nicht aus dem Writer, und das ist GEMESSEN: `e2e_writer_archive.rs` haelt
//! fest, dass ein vom Writer geschriebener Bestand seine Registrierungslinie
//! im Vertrauensspeicher laesst und nicht im Bestand — er ist damit nie
//! `is_fully_verified()`, und genau das muss dieser Zeuge behaupten. Der
//! Bestand entsteht deshalb ueber dieselbe `#[path]`-Kette, die
//! `crates/ea-reader/tests/verify_fixtures/mod.rs`,
//! `crates/ea-archive-fs/tests/support/mod.rs` und das Nachbarmodul `support`
//! dieser Testcrate schon fahren, und ueber `complete_archive_for_recipients`
//! — den EINEN Bau um die Achse „mehrere Empfaenger" erweitert, statt ihn
//! hier zu verdoppeln (dieselbe Begruendung, die
//! `complete_valid_archive_with_plaintexts` dort ausschreibt).
//!
//! # „Ohne Grant fuer B" ist ein ZWEITER Bau, kein Loeschen
//!
//! Der initiale Grantplan ist in das signierte Manifest gebunden
//! (`initialGrantPlanHash`), und Gate `grant-plan` REKONSTRUIERT den Plan aus
//! den vorhandenen `.eag` (`crates/ea-verify/src/entry.rs:96-105`). Wer aus
//! einem Bestand mit drei Grants einen entfernt, erzeugt keinen `fehlenden
//! Grant`, sondern `EA-VERIFY-GRANT-PLAN-MISMATCH` — der Eintrag wird fuer
//! JEDEN Leser `ungueltig`. Der Zustand `fehlender Grant` entsteht nur, wenn
//! der Plan den eigenen Schluessel NIE genannt hat; dieselbe Konstruktion, die
//! `archive_without_the_own_grant()` in `ea-verify` faehrt.
//! [`archive_with_a_grant_for_reader_a_only`] ist deshalb ein eigener Bau, und
//! [`TwoReaderArchive::without_the_grant_object_of`] existiert allein, damit
//! der Zeuge das Loeschen als das misst, was es ist.
//!
//! # Der Klartext ist der eingefrorene Genesis-Vektor
//!
//! `decrypt_verified` endet in der Schemabestimmung; `COMPLETE_PLAINTEXT_V1`
//! traegt keine und fiele mit `EA-READER-SCHEMA-UNSUPPORTED`. Der Vektor aus
//! `vectors/format/payload-v1/genesis.hex` ist dieselbe Quelle, gegen die
//! `crates/ea-reader/tests/historical_expiry.rs` seinen Erfolgspfad misst.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`
//! auf Modulebene.
#![allow(dead_code)]

/// Das Fixture-Modul aus `ea-verify`, unveraendert weiterverwendet.
#[path = "../../../../crates/ea-verify/tests/support/mod.rs"]
pub mod verify_support;

use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPrivateKey, HpkeRecipientPublicKey, SecretBytes,
    object_hash,
};
use ea_format::GrantPurposeV1;
use ea_reader::{AuthenticatorPrfV1, ReaderVault, UnlockedVault, VaultContentsV1};
use ea_trust::TrustAnchorV1;
use ea_types::{CertificateHash, EntryHash, KeyThumbprint, ObjectHash, UnixMillis};

use verify_support::{CompleteArchive, PlannedRecipientV1, archive_support::ArchiveFixture};

/// Die Betriebssystemuhr jedes Laufs dieser Kulisse.
///
/// Nicht frei waehlbar: `select_registry_head` misst gegen das
/// not-before/not-after-Fenster der Fixture-Koepfe, und `verify_support` haelt
/// mit `FIXTURE_OS_WALL_CLOCK_V1` genau den Wert, gegen den die Linie gebaut
/// ist. `decrypt_verified` verlangt zudem EXAKT die Uhr des Laufs, in dem die
/// Zeugen entstanden.
pub const OS_WALL_CLOCK: UnixMillis = UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1);

/// Der OEFFENTLICHE X25519-Punkt des Recovery-Empfaengers.
///
/// Ein DRITTER Schluessel neben den beiden Readern: `GrantPlanV1::new`
/// verlangt genau EINEN Recovery-Grant, und der gehoert im Regelfall des
/// Writers weder dem einen noch dem anderen Reader. Sein Geheimnis haelt kein
/// Test — die Datei traegt nur den oeffentlichen Punkt, und mehr braucht die
/// Kapselung nicht. Der Punkt wurde am 2026-09-05 EINMAL aus einem seither
/// verworfenen Seed abgeleitet (`HpkeRecipientPrivateKey::from_bytes(..)
/// .public_key()`) und steht seitdem als Literal hier; Abdruck und Archivbytes
/// sind dieselben wie zuvor.
const RECOVERY_RECIPIENT_PUBLIC_KEY_V1: [u8; 32] = [
    0x4e, 0x4d, 0x21, 0x4c, 0x7b, 0x7b, 0x6a, 0xc8, 0x83, 0x68, 0x7a, 0x4b, 0xd5, 0xf6, 0x48, 0x4e,
    0x09, 0xf9, 0xef, 0xd4, 0x28, 0xe5, 0x60, 0xcb, 0x6d, 0xec, 0x6a, 0xe6, 0xa2, 0x22, 0x6a, 0x16,
];

/// Das Zertifikat des Recovery-Empfaengers.
///
/// Ein Fuellwert wie bei den beiden Readern — Gate `recipient-grant` loest den
/// AUSSTELLER auf, nie den Empfaenger —, aber ein EIGENER: der Plan weist ein
/// doppeltes Empfaengerzertifikat ab.
const RECOVERY_RECIPIENT_CERTIFICATE_V1: [u8; 32] = [0x43; 32];

/// Ein Reader: ein KEM-Schluessel, ein Zertifikat und ein Entsperrweg.
///
/// Der Typ traegt kein `Clone`: `HpkeRecipientPrivateKey` gibt sein Material
/// nicht heraus, und eine zweite Kopie waere genau das, was
/// `web-reader-design.md` §6.5 nicht will. Wer den Reader zweimal braucht,
/// ruft [`reader_a`] oder [`reader_b`] zweimal.
pub struct Reader {
    label: &'static str,
    kem_seed: [u8; 32],
    private_key: HpkeRecipientPrivateKey,
    certificate_hash: CertificateHash,
    audit_seed: [u8; 32],
    credential_id: &'static [u8],
    prf_output: [u8; 32],
}

impl Reader {
    fn new(
        label: &'static str,
        kem_seed: [u8; 32],
        certificate_hash: CertificateHash,
        audit_seed: [u8; 32],
        credential_id: &'static [u8],
        prf_output: [u8; 32],
    ) -> Self {
        let private_key = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(kem_seed))
            .expect("der Reader-Seed muss ein X25519-Schluessel sein");
        Self {
            label,
            kem_seed,
            private_key,
            certificate_hash,
            audit_seed,
            credential_id,
            prf_output,
        }
    }

    /// Der Name, unter dem dieser Reader in Zusicherungen erscheint.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// Der Abdruck seines KEM-Schluessels — zeichengleich zu dem, den
    /// `ReaderVault::unlock` fuer die Sitzung rechnet.
    #[must_use]
    pub fn key_thumbprint(&self) -> KeyThumbprint {
        verify_support::key_thumbprint_of(&self.private_key)
    }

    /// Sein privater KEM-Schluessel, fuer `VerifyOptions::with_recipient`.
    #[must_use]
    pub const fn private_key(&self) -> &HpkeRecipientPrivateKey {
        &self.private_key
    }

    /// Sein oeffentlicher KEM-Schluessel, auf den ein Grant gekapselt wird.
    #[must_use]
    pub fn public_key(&self) -> HpkeRecipientPublicKey {
        self.private_key.public_key()
    }

    /// Sein Zertifikat.
    #[must_use]
    pub const fn certificate_hash(&self) -> CertificateHash {
        self.certificate_hash
    }

    /// Dieser Reader als Planeintrag mit Zweck `Reader`.
    fn planned(&self) -> PlannedRecipientV1 {
        PlannedRecipientV1 {
            key_thumbprint: self.key_thumbprint(),
            certificate_hash: self.certificate_hash,
            public_key: self.public_key(),
            purpose: GrantPurposeV1::Reader,
        }
    }

    /// Eine entsperrte Sitzung dieses Readers, die die Ankerbytes des
    /// Bestands PINNT.
    ///
    /// Der KEM-Seed des Tresors ist derselbe wie der von [`Self::private_key`];
    /// nur so nennt `kem_key_thumbprint()` der Sitzung den Empfaenger, den der
    /// Grant adressiert.
    ///
    /// # Panics
    ///
    /// Wenn Versiegeln oder Entsperren scheitert.
    #[must_use]
    pub fn vault_pinning(&self, anchor_bytes: &[u8]) -> UnlockedVault {
        let contents = VaultContentsV1::new(
            SecretBytes::new(self.kem_seed),
            SecretBytes::new(self.audit_seed),
            anchor_bytes.to_vec(),
            None,
        );
        let sealed = ReaderVault::seal(contents, &[self.authenticator()])
            .expect("der Reader-Tresor muss sich versiegeln lassen");
        ReaderVault::unlock(&sealed, &self.authenticator())
            .expect("derselbe Authenticator muss ihn wieder oeffnen")
    }

    fn authenticator(&self) -> AuthenticatorPrfV1 {
        AuthenticatorPrfV1::new(
            self.credential_id.to_vec(),
            SecretBytes::new(self.prf_output),
        )
    }
}

/// Reader A: das Schluesselmaterial, das die `ea-verify`-Fixtures BESITZEN.
#[must_use]
pub fn reader_a() -> Reader {
    Reader::new(
        "Reader A",
        verify_support::complete_recipient_secret_bytes(),
        verify_support::complete_recipient_certificate_hash(),
        [0x52; 32],
        b"ea-system-two-readers-passkey-a",
        [0xa1; 32],
    )
}

/// Reader B: der ZWEITE Schluessel derselben Fixtures — dort „der falsche",
/// hier ein zweiter berechtigter Empfaenger.
#[must_use]
pub fn reader_b() -> Reader {
    Reader::new(
        "Reader B",
        verify_support::other_recipient_secret_bytes(),
        verify_support::other_recipient_certificate_hash(),
        [0x53; 32],
        b"ea-system-two-readers-passkey-b",
        [0xb2; 32],
    )
}

/// Der Recovery-Empfaenger als Planeintrag — allein aus dem oeffentlichen
/// Punkt: der Abdruck ist derselbe, den `verify_support::key_thumbprint_of`
/// ueber dem privaten Schluessel rechnet (`CanonicalPublicCoseKey::x25519`
/// ueber den Punktbytes).
fn recovery_recipient() -> PlannedRecipientV1 {
    let public_key = HpkeRecipientPublicKey::from_bytes(RECOVERY_RECIPIENT_PUBLIC_KEY_V1)
        .expect("der Recovery-Punkt muss ein X25519-Schluessel sein");
    PlannedRecipientV1 {
        key_thumbprint: CanonicalPublicCoseKey::x25519(*public_key.as_bytes())
            .expect("ein X25519-Punkt muss ein COSE-Schluessel sein")
            .thumbprint(),
        certificate_hash: CertificateHash::try_from(&RECOVERY_RECIPIENT_CERTIFICATE_V1[..])
            .expect("32 Bytes sind ein Zertifikatshash"),
        public_key,
        purpose: GrantPurposeV1::Recovery,
    }
}

/// Ein Bestand mit GENAU EINEM Eintrag und je einem Grant pro geplantem
/// Empfaenger.
pub struct TwoReaderArchive {
    archive: CompleteArchive,
    /// Je Grant der Abdruck seines Empfaengers, in Ablagereihenfolge —
    /// indexgleich zu `archive.grant_object_hashes`.
    grant_recipients: Vec<KeyThumbprint>,
}

impl TwoReaderArchive {
    fn build(recipients: Vec<PlannedRecipientV1>, plaintext: &[u8]) -> Self {
        let grant_recipients = recipients
            .iter()
            .map(|recipient| recipient.key_thumbprint)
            .collect();
        let archive = verify_support::complete_archive_for_recipients(&recipients, plaintext);
        assert_eq!(
            archive.grant_object_hashes.len(),
            recipients.len(),
            "je Empfaenger genau ein Grant"
        );
        Self {
            archive,
            grant_recipients,
        }
    }

    /// Der Bestand als Archivquelle.
    #[must_use]
    pub fn source(&self) -> &ArchiveFixture {
        &self.archive.fixture
    }

    /// Der dekodierte Anker der Linie.
    #[must_use]
    pub fn anchor(&self) -> TrustAnchorV1 {
        self.archive.anchor()
    }

    /// Die EXAKTEN Ankerbytes, die ein Tresor pinnt.
    #[must_use]
    pub fn anchor_bytes(&self) -> &[u8] {
        &self.archive.anchor_bytes
    }

    /// Der Eintragshash des EINEN Eintrags, aus dem geparsten `.eip` gewonnen.
    ///
    /// # Panics
    ///
    /// Wenn der Bestand nicht genau einen Eintrag traegt.
    #[must_use]
    pub fn entry_hash(&self) -> EntryHash {
        entry_hash_of(self.source())
    }

    /// Der Objekthash des Grants an `reader`.
    ///
    /// # Panics
    ///
    /// Wenn kein Grant dieses Bestands den Reader nennt.
    #[must_use]
    pub fn grant_object_hash_for(&self, reader: &Reader) -> ObjectHash {
        let thumbprint = reader.key_thumbprint();
        let position = self
            .grant_recipients
            .iter()
            .position(|recipient| *recipient == thumbprint)
            .unwrap_or_else(|| panic!("{} hat in diesem Bestand keinen Grant", reader.label()));
        self.archive.grant_object_hashes[position]
    }

    /// DERSELBE Bestand, dem das Grantobjekt an `reader` physisch FEHLT.
    ///
    /// Die Blobs bleiben in Ablagereihenfolge; nur das eine `.eag` ist weg. Das
    /// Manifest nennt den Plan weiterhin mit diesem Empfaenger — siehe den
    /// Modulkommentar.
    #[must_use]
    pub fn without_the_grant_object_of(&self, reader: &Reader) -> ArchiveFixture {
        let removed = self.grant_object_hash_for(reader);
        let mut fixture = ArchiveFixture::new();
        let mut dropped = 0;
        for (path_hint, bytes) in self.source().blobs() {
            if object_hash(bytes) == removed {
                dropped += 1;
                continue;
            }
            fixture.push_exact_bytes(path_hint, bytes.clone());
        }
        assert_eq!(dropped, 1, "genau ein Grantobjekt wird entfernt");
        fixture
    }
}

/// EIN Chiffrat, drei initiale Grants: Recovery an einen Dritten, je ein
/// `Reader`-Grant an [`reader_a`] und [`reader_b`]. Der Klartext ist der
/// Genesis-Vektor.
#[must_use]
pub fn archive_with_grants_for_both_readers() -> TwoReaderArchive {
    TwoReaderArchive::build(
        vec![
            recovery_recipient(),
            reader_a().planned(),
            reader_b().planned(),
        ],
        &genesis_plaintext(),
    )
}

/// Derselbe Bau, dessen Plan NUR [`reader_a`] nennt: fuer [`reader_b`] gibt es
/// hier keinen eigenen Grant — und hat es nie gegeben.
#[must_use]
pub fn archive_with_a_grant_for_reader_a_only() -> TwoReaderArchive {
    TwoReaderArchive::build(
        vec![recovery_recipient(), reader_a().planned()],
        &genesis_plaintext(),
    )
}

/// Der eingefrorene Genesis-Vektor aus `vectors/format/payload-v1/genesis.hex`.
#[must_use]
pub fn genesis_plaintext() -> Vec<u8> {
    hex::decode(include_str!("../../../../vectors/format/payload-v1/genesis.hex").trim_end())
        .expect("der eingefrorene Genesis-Vektor ist gueltiges Hex")
}

/// Der Eintragshash des EINEN Eintrags eines Bestands.
///
/// # Panics
///
/// Wenn der Bestand nicht genau einen Eintrag traegt.
#[must_use]
pub fn entry_hash_of(source: &dyn ArchiveSource) -> EntryHash {
    let inventory =
        ArchiveInventory::build(source).expect("die Fixture-Bestaende sind inventarisierbar");
    assert_eq!(
        inventory.entries().len(),
        1,
        "entry_hash_of gilt nur fuer einen einentraegigen Bestand"
    );
    inventory.entries()[0].value().entry_hash()
}
