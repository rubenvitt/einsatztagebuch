//! Die zwei Zeugen, ohne die der HPKE-Entkapseler nicht formulierbar ist.
//!
//! `web-reader-design.md` §9 verlangt, dass NUR ein vollstaendig verifizierter
//! Eintrag ZUSAMMEN MIT seinem geprueften eigenen Grant entschluesselt wird.
//! Dieses Modul macht daraus eine TYPZUSAGE statt einer Disziplin:
//! [`crate::decrypt_verified`] nimmt beide Werte, beide haben ausschliesslich
//! private Konstruktoren, und die ruft allein
//! [`crate::ReaderClassification::verified_entry`] beziehungsweise
//! [`crate::ReaderClassification::verified_grant`].
//!
//! # Warum die EXAKTEN Bytes und keine Ableitung
//!
//! `ea_format::Parsed<T>` hat keinen oeffentlichen Konstruktor, und die Zeugen
//! sollen ohne Lebensdauerparameter auskommen — sonst haenge jeder von ihnen an
//! dem Inventar, aus dem er stammt, und [`crate::ReaderClassification`] koennte
//! ihn nicht besitzen. Die Zeugen tragen deshalb die exakten Objektbytes, und
//! `decrypt_verified` parst sie mit `ea_format::decode_exact_object` erneut.
//! Das ist kein zweiter Parser: es ist derselbe, ein zweites Mal gerufen.

use ea_types::{ChainSequence, EntryHash, KeyThumbprint, ObjectHash, UnixMillis};

/// Ein Eintrag, der alle neun Gates aus `design.md` §14.1 getragen hat.
///
/// Der einzige Konstruktor ist privat und wird ausschliesslich von
/// [`crate::ReaderClassification::verified_entry`] gerufen — und die gibt einen
/// Zeugen nur heraus, wenn der Bericht fuer dieses Objekt
/// `ObjectResultKindV1::Valid` fuehrt, kein Fehlerfeld es nennt und der eigene
/// Grant dieses Eintrags weder isoliert ist noch in `decryptionErrors` oder
/// `signatureErrors` steht.
pub struct VerifiedEncryptedEntry {
    exact_entry_bytes: Vec<u8>,
    entry_hash: EntryHash,
    object_hash: ObjectHash,
    sequence: ChainSequence,
    minted_at: UnixMillis,
}

impl VerifiedEncryptedEntry {
    /// Der private Konstruktor; siehe den Typkommentar.
    pub(crate) fn new(
        exact_entry_bytes: Vec<u8>,
        entry_hash: EntryHash,
        object_hash: ObjectHash,
        sequence: ChainSequence,
        minted_at: UnixMillis,
    ) -> Self {
        Self {
            exact_entry_bytes,
            entry_hash,
            object_hash,
            sequence,
            minted_at,
        }
    }

    /// Der Eintragshash — die Adresse, unter der dieser Zeuge steht.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Der Objekthash des Eintragspakets.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    /// Die Kettensequenz des Eintrags.
    #[must_use]
    pub const fn chain_sequence(&self) -> ChainSequence {
        self.sequence
    }

    /// Der Lauf, in dem dieser Zeuge entstand.
    ///
    /// Ein Zeuge gilt fuer GENAU DIESEN Lauf, weil Gate `recipient-grant` seine
    /// Nutzungsfrist gegen genau diesen `effectiveNow` gemessen hat.
    #[must_use]
    pub const fn minted_at(&self) -> UnixMillis {
        self.minted_at
    }

    /// Die exakten Objektbytes, NUR fuer den Entkapseler dieser Crate.
    pub(crate) fn exact_entry_bytes(&self) -> &[u8] {
        &self.exact_entry_bytes
    }
}

/// Der eigene INITIALE Grant, gegen den gewaehlten Registrierungskopf geprueft.
///
/// Dieselbe Schranke wie bei [`VerifiedEncryptedEntry`]: privater Konstruktor,
/// ein einziger Aufrufer. Die Auswahl baut das Praedikat von
/// `ea_verify::own_grant` ZEICHENGLEICH nach — `kind == GrantKindV1::Initial`,
/// derselbe `entryHash`, derselbe Empfaengerabdruck, als `find` ueber das nach
/// Objekthash aufsteigende `inventory.grants()`. `own_grant` ist `pub(crate)`
/// und aus dieser Crate nicht rufbar; liefe die Auswahl hier anders als dort,
/// gaebe die Klassifikation einen Zeugen ueber einen Grant heraus, den die
/// Pipeline gar nicht geprueft hat.
pub struct VerifiedGrantForRecipient {
    exact_grant_bytes: Vec<u8>,
    entry_hash: EntryHash,
    recipient_key_thumbprint: KeyThumbprint,
    minted_at: UnixMillis,
}

impl VerifiedGrantForRecipient {
    /// Der private Konstruktor; siehe den Typkommentar.
    pub(crate) fn new(
        exact_grant_bytes: Vec<u8>,
        entry_hash: EntryHash,
        recipient_key_thumbprint: KeyThumbprint,
        minted_at: UnixMillis,
    ) -> Self {
        Self {
            exact_grant_bytes,
            entry_hash,
            recipient_key_thumbprint,
            minted_at,
        }
    }

    /// Der Eintrag, auf den dieser Grant sich beruft.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Der Empfaenger, den der Grant benennt — der Abdruck der Sitzung.
    #[must_use]
    pub const fn recipient_key_thumbprint(&self) -> KeyThumbprint {
        self.recipient_key_thumbprint
    }

    /// Der Lauf, in dem dieser Zeuge entstand.
    #[must_use]
    pub const fn minted_at(&self) -> UnixMillis {
        self.minted_at
    }

    /// Die exakten Objektbytes, NUR fuer den Entkapseler dieser Crate.
    pub(crate) fn exact_grant_bytes(&self) -> &[u8] {
        &self.exact_grant_bytes
    }
}
