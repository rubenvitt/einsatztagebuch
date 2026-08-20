use core::fmt;

use crate::{ArchiveBackendError, layout::LAYOUT_PATHS_V1};

/// Eine validierte TRANSPORTADRESSE innerhalb eines Bestands.
///
/// Relativ, ohne `..`, ohne absolute Wurzel, ausschliesslich unterhalb eines
/// Verzeichnisses aus [`LAYOUT_PATHS_V1`](crate::LAYOUT_PATHS_V1).
///
/// Sie entscheidet **nie** darueber, ob Bytes ein Archivobjekt sind — das
/// entscheidet weiterhin allein das 9-Byte-Exact-Object-Praefix
/// (`crates/ea-archive/src/source.rs`). Eine Adresse ist eine Adresse; die
/// Klasse steckt in den Bytes.
///
/// Sie fuegt [`LAYOUT_PATHS_V1`](crate::LAYOUT_PATHS_V1) auch keinen Pfad
/// hinzu: `tools/xtask/tests/spec_completeness.rs` haelt diese Liste in beiden
/// Richtungen gegen `design.md` §11.4 gepinnt.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ArchivePath {
    value: String,
    directory_length: usize,
}

impl ArchivePath {
    /// Eine Adresse unterhalb eines Verzeichnisses der Layoutliste.
    ///
    /// `relative_below_it` darf selbst `/` tragen — die Unterverzeichnisse
    /// eines Vernichtungsvorgangs verlangen das
    /// (`crates/ea-archive/src/layout.rs`).
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Path`], wenn `directory` kein Verzeichnis der
    /// Layoutliste ist oder `relative_below_it` leer ist, absolut beginnt, ein
    /// leeres Segment, `.`, `..` oder einen Backslash traegt.
    pub fn in_dir(directory: &str, relative_below_it: &str) -> Result<Self, ArchiveBackendError> {
        if !LAYOUT_PATHS_V1.contains(&directory) || !directory.ends_with('/') {
            return Err(ArchiveBackendError::Path);
        }
        validate_relative(relative_below_it)?;
        let mut value = String::with_capacity(directory.len() + relative_below_it.len());
        value.push_str(directory);
        value.push_str(relative_below_it);
        Ok(Self {
            value,
            directory_length: directory.len(),
        })
    }

    /// Eine der festen Dateien der Layoutliste.
    ///
    /// Abgeleitet aus [`LAYOUT_PATHS_V1`](crate::LAYOUT_PATHS_V1) und nicht aus
    /// einer Handzaehlung: jeder Eintrag der Liste, der nicht auf `/` endet,
    /// ist eine Datei. Der Brief nennt zwei; die Liste fuehrt drei
    /// (`trust/organization.etb`, `format/compatibility-matrix.json`,
    /// `README-FORMAT.txt`). Eine Ableitung kann nicht abdriften, eine Zahl
    /// kann es.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Path`], wenn `file` kein Dateieintrag der Liste
    /// ist.
    pub fn at_layout_file(file: &str) -> Result<Self, ArchiveBackendError> {
        if !LAYOUT_PATHS_V1.contains(&file) || file.ends_with('/') {
            return Err(ArchiveBackendError::Path);
        }
        let directory_length = file.rfind('/').map_or(0, |at| at + 1);
        Ok(Self {
            value: file.to_owned(),
            directory_length,
        })
    }

    /// Die Adresse als wurzelrelativer Pfad mit `/` als Trenner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Das tragende Verzeichnis dieser Adresse, mit abschliessendem `/`.
    ///
    /// Der Adressat von [`ArchiveBackend::sync_directory`](crate::ArchiveBackend::sync_directory):
    /// ein Dateiflush allein macht einen NEUEN Verzeichniseintrag nicht
    /// dauerhaft.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.value[..self.directory_length]
    }
}

fn validate_relative(relative: &str) -> Result<(), ArchiveBackendError> {
    if relative.is_empty() || relative.starts_with('/') || relative.contains('\\') {
        return Err(ArchiveBackendError::Path);
    }
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ArchiveBackendError::Path);
        }
    }
    Ok(())
}

impl fmt::Debug for ArchivePath {
    /// Nennt die Adresse. Sie ist strukturell — ein Layoutpfad und ein
    /// Objektname —, kein fachlicher Name und kein Inhalt.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ArchivePath({})", self.value)
    }
}
