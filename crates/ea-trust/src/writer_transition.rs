//! Der auf einer Registry-Linie WIRKSAME Writer-Uebergang.
//!
//! Das Transitionsobjekt selbst (`WriterTransitionFieldsV1`) und seine
//! Registry-Wirkung (Change 3) gibt es seit Stufe 1–3. Was fehlte, war ein
//! Wert, den `ea-trust` HERAUSGIBT: der Server, der Writer und die Pruefung
//! muessen wissen, welcher Uebergang auf dem gewaehlten Kopf gilt, ohne das
//! Objekt selbst noch einmal zu dekodieren — und ohne dass einer von ihnen
//! einen Uebergang ERFINDEN koennte, den die Linie nie angewandt hat.

use core::fmt;

use ea_types::{CertificateHash, ChainSequence, EntryHash, ObjectHash};

/// Der wirksame Writer-Uebergang eines gewaehlten Kopfes.
///
/// Er entsteht AUSSCHLIESSLICH beim Nachspielen eines Registry-Change 3 in
/// `verify_registry_candidate` und wird von
/// [`SelectedRegistryHead::effective_writer_transition`](crate::SelectedRegistryHead::effective_writer_transition)
/// herausgegeben. Ausserhalb der Crate gibt es keinen Konstruktor:
///
/// ```compile_fail
/// use ea_trust::EffectiveWriterTransitionV1;
/// let _ = EffectiveWriterTransitionV1 {
///     object_hash: panic!(),
///     old_writer_certificate_hash: panic!(),
///     new_writer_certificate_hash: panic!(),
///     effective_from_sequence: panic!(),
///     previous_entry_hash: panic!(),
/// };
/// ```
///
/// Die Felder sind genau die des veroeffentlichten `writerTransition`-Objekts,
/// die ein Verbraucher gegen einen Eintrag halten muss: der Objekthash (den
/// das Manifest des ersten neuen Eintrags als `writer_transition_event_hash`
/// nennt), alter und neuer Writer, die Sequenz, ab der der neue Writer
/// schreibt, und der Hash des letzten Eintrags des alten Writers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EffectiveWriterTransitionV1 {
    object_hash: ObjectHash,
    old_writer_certificate_hash: CertificateHash,
    new_writer_certificate_hash: CertificateHash,
    effective_from_sequence: ChainSequence,
    previous_entry_hash: EntryHash,
}

impl EffectiveWriterTransitionV1 {
    /// Fixture-Konstruktor fuer Zeugen anderer Crates, NUR unter dem Merkmal
    /// `test-support`. Produktiv entsteht der Wert ausschliesslich beim
    /// Nachspielen eines Registry-Change 3.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn fixture(
        object_hash: ObjectHash,
        old_writer_certificate_hash: CertificateHash,
        new_writer_certificate_hash: CertificateHash,
        effective_from_sequence: ChainSequence,
        previous_entry_hash: EntryHash,
    ) -> Self {
        Self::new(
            object_hash,
            old_writer_certificate_hash,
            new_writer_certificate_hash,
            effective_from_sequence,
            previous_entry_hash,
        )
    }

    pub(crate) const fn new(
        object_hash: ObjectHash,
        old_writer_certificate_hash: CertificateHash,
        new_writer_certificate_hash: CertificateHash,
        effective_from_sequence: ChainSequence,
        previous_entry_hash: EntryHash,
    ) -> Self {
        Self {
            object_hash,
            old_writer_certificate_hash,
            new_writer_certificate_hash,
            effective_from_sequence,
            previous_entry_hash,
        }
    }

    /// Der Objekthash des Root-signierten `writerTransition`-Objekts.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    /// Das Writer-Zertifikat, das ab `effective_from_sequence` widerrufen ist.
    #[must_use]
    pub const fn old_writer_certificate_hash(&self) -> CertificateHash {
        self.old_writer_certificate_hash
    }

    /// Das Writer-Zertifikat, das ab `effective_from_sequence` der laufende
    /// Writer ist.
    #[must_use]
    pub const fn new_writer_certificate_hash(&self) -> CertificateHash {
        self.new_writer_certificate_hash
    }

    /// Die erste Sequenz des neuen Writers; der alte ist ab hier widerrufen.
    #[must_use]
    pub const fn effective_from_sequence(&self) -> ChainSequence {
        self.effective_from_sequence
    }

    /// Der Hash des letzten Eintrags des alten Writers, an den der erste
    /// Eintrag des neuen anschliesst.
    #[must_use]
    pub const fn previous_entry_hash(&self) -> EntryHash {
        self.previous_entry_hash
    }
}

/// Schreibt 32 Hashbytes als Kleinbuchstaben-Hex.
///
/// `ea-types` leitet fuer Hashtypen kein `Debug` ab; die Debug-Ausgabe ist
/// deshalb von Hand geschrieben, genau wie in `ea-verify` und `ea-archive`.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for EffectiveWriterTransitionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveWriterTransitionV1")
            .field("object_hash", &Hex(self.object_hash.as_bytes()))
            .field(
                "old_writer_certificate_hash",
                &Hex(self.old_writer_certificate_hash.as_bytes()),
            )
            .field(
                "new_writer_certificate_hash",
                &Hex(self.new_writer_certificate_hash.as_bytes()),
            )
            .field("effective_from_sequence", &self.effective_from_sequence)
            .field(
                "previous_entry_hash",
                &Hex(self.previous_entry_hash.as_bytes()),
            )
            .finish()
    }
}
