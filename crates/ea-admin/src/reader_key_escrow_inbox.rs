//! Die eigene Escrow-Inbox und der Escrow-Ausgang (Profil §5/§6, Ruling U3).
//!
//! Ein EIGENES Verzeichnis und nicht die Registrierungs-Inbox: jene weist
//! jedes fremde Suffix ab, und Escrow-Dateien dort legten die
//! Registrierungsannahme lahm. Gelesen wird nach dem Muster von
//! `administration_runtime::inbox_directory`: keine Symlinks, eine stabile
//! Inode, höchstens [`MAX_FILES`] Dateien, der Stamm ist der Objekthash der
//! Bytes. Geschrieben wird mit `create_new`, `fsync` und atomarem Namen; liegt
//! die Datei schon mit gleichen Bytes vor, ist das idempotent.
//!
//! Die Verdrahtung in der Desktop-Administration ist eine benannte Grenze der
//! Scheiben (e)/(f).

use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::Path,
};

use ea_crypto::object_hash;
use ea_format::{
    READER_KEY_ESCROW_TRANSFER_MAX_BYTES, ReaderKeyEscrowTransferKindV1,
    decode_reader_key_escrow_transport_request, reader_key_escrow_transfer_file_name,
};
use ea_recovery::ReaderKeyEscrowError;
use ea_types::{ObjectHash, OrganizationId};

/// Höchstens so viele Dateien liegen in einer Escrow-Inbox.
pub const MAX_FILES: usize = 32;

/// Eine gelesene Übergabedatei: ihre exakten Bytes und ihr Objekthash, der
/// zugleich ihr Dateistamm ist.
pub struct EscrowTransferFile {
    pub kind: ReaderKeyEscrowTransferKindV1,
    pub exact_bytes: Vec<u8>,
    pub object_hash: ObjectHash,
}

fn transfer_error() -> ReaderKeyEscrowError {
    ReaderKeyEscrowError::TransferFile
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}

fn read_regular(path: &Path) -> Result<Vec<u8>, ReaderKeyEscrowError> {
    let limit = READER_KEY_ESCROW_TRANSFER_MAX_BYTES as u64;
    let before = fs::symlink_metadata(path).map_err(|_| transfer_error())?;
    if !before.is_file() || before.is_symlink() || before.len() == 0 || before.len() > limit {
        return Err(transfer_error());
    }
    let file = fs::File::open(path).map_err(|_| transfer_error())?;
    let opened = file.metadata().map_err(|_| transfer_error())?;
    if !opened.is_file() || !same_file(&before, &opened) {
        return Err(transfer_error());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| transfer_error())?;
    let after = fs::symlink_metadata(path).map_err(|_| transfer_error())?;
    if after.is_symlink() || !same_file(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(transfer_error());
    }
    Ok(bytes)
}

/// Liest ALLE Übergabedateien der Inbox, streng: ein fremder Name, ein
/// Symlink, eine Unterverzeichnis, eine zu große Datei oder ein Stamm, der
/// nicht der Objekthash der Bytes ist, lässt das ganze Lesen scheitern.
///
/// # Errors
///
/// [`ReaderKeyEscrowError::TransferFile`].
pub fn read_escrow_inbox(
    directory: &Path,
) -> Result<Vec<EscrowTransferFile>, ReaderKeyEscrowError> {
    let before = fs::symlink_metadata(directory).map_err(|_| transfer_error())?;
    if !before.is_dir() || before.is_symlink() {
        return Err(transfer_error());
    }
    let mut files = Vec::new();
    for (index, entry) in fs::read_dir(directory)
        .map_err(|_| transfer_error())?
        .enumerate()
    {
        if index >= MAX_FILES {
            return Err(transfer_error());
        }
        let entry = entry.map_err(|_| transfer_error())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| transfer_error())?;
        let kind = [
            ReaderKeyEscrowTransferKindV1::Package,
            ReaderKeyEscrowTransferKindV1::TransportRequest,
        ]
        .into_iter()
        .find(|kind| name.ends_with(kind.suffix()))
        .ok_or_else(transfer_error)?;
        let exact_bytes = read_regular(&entry.path())?;
        if reader_key_escrow_transfer_file_name(kind, &exact_bytes) != name {
            return Err(transfer_error());
        }
        files.push(EscrowTransferFile {
            kind,
            object_hash: object_hash(&exact_bytes),
            exact_bytes,
        });
    }
    let after = fs::symlink_metadata(directory).map_err(|_| transfer_error())?;
    if after.is_symlink() || !same_file(&before, &after) {
        return Err(transfer_error());
    }
    files.sort_by(|left, right| {
        left.object_hash
            .as_bytes()
            .cmp(right.object_hash.as_bytes())
    });
    Ok(files)
}

/// Der rohe Ziel-Transport-Schlüssel aus GENAU einer Transportdatei der Inbox,
/// die diese Organisation und dieses Escrow nennt. Keine oder zwei passende
/// Dateien sind ein Fehler; ob der Schlüssel der autorisierte ist, prüft danach
/// allein `ea-trust` (`require_target_transport_key`).
///
/// # Errors
///
/// [`ReaderKeyEscrowError::TransferFile`].
pub fn read_transport_key(
    inbox: &Path,
    organization: OrganizationId,
    escrow_object_hash: ObjectHash,
) -> Result<[u8; 32], ReaderKeyEscrowError> {
    let mut found = None;
    for file in read_escrow_inbox(inbox)? {
        if file.kind != ReaderKeyEscrowTransferKindV1::TransportRequest {
            continue;
        }
        let request = decode_reader_key_escrow_transport_request(&file.exact_bytes)
            .map_err(|_| transfer_error())?;
        if request.organization_id == organization
            && request.escrow_object_hash == escrow_object_hash
        {
            if found.is_some() {
                return Err(transfer_error());
            }
            found = Some(request.target_transport_public_key);
        }
    }
    found.ok_or_else(transfer_error)
}

/// Schreibt eine Übergabedatei in den Ausgang: `create_new` unter einem
/// zufälligen Zwischennamen, `fsync`, dann atomar unter dem Hash-Namen.
/// Existiert der Name schon mit denselben Bytes, ist das idempotent; mit
/// anderen Bytes scheitert es. Zurück kommt der Objekthash der Datei.
///
/// # Errors
///
/// [`ReaderKeyEscrowError::Output`].
pub fn write_escrow_outbox(
    directory: &Path,
    kind: ReaderKeyEscrowTransferKindV1,
    exact_bytes: &[u8],
) -> Result<ObjectHash, ReaderKeyEscrowError> {
    let output = |_| ReaderKeyEscrowError::Output;
    let metadata = fs::symlink_metadata(directory).map_err(output)?;
    if !metadata.is_dir() || metadata.is_symlink() {
        return Err(ReaderKeyEscrowError::Output);
    }
    let path = directory.join(reader_key_escrow_transfer_file_name(kind, exact_bytes));
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| ReaderKeyEscrowError::Output)?;
    let temporary = directory.join(format!(".escrow-{}.tmp", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = options.open(&temporary)?;
        file.write_all(exact_bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error)
                if error.kind() == ErrorKind::AlreadyExists
                    && !fs::symlink_metadata(&path)?.file_type().is_symlink()
                    && fs::read(&path)? == exact_bytes => {}
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    let cleanup = fs::remove_file(&temporary);
    result.map_err(output)?;
    cleanup.map_err(output)?;
    #[cfg(unix)]
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(output)?;
    Ok(object_hash(exact_bytes))
}
