//! Complete physical inspection, deliberately independent of committed sources.
use super::*;
use std::io::Read;

impl LocalPathBackend {
    pub(super) fn visit_managed_contents(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        walk(&self.root, &self.root, 0, &mut Limits::default(), visitor)
    }
}
#[derive(Default)]
struct Limits {
    entries: usize,
    bytes: u64,
}
fn walk(
    root: &Path,
    directory: &Path,
    depth: usize,
    limits: &mut Limits,
    visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
) -> Result<(), ArchiveError> {
    if depth > 128 {
        return Err(ArchiveError::Unavailable);
    }
    for entry in fs::read_dir(directory).map_err(|_| ArchiveError::Unavailable)? {
        let entry = entry.map_err(|_| ArchiveError::Unavailable)?;
        limits.entries = limits
            .entries
            .checked_add(1)
            .ok_or(ArchiveError::BlobLimit)?;
        if limits.entries > ea_archive::MAX_ARCHIVE_BLOBS_V1 {
            return Err(ArchiveError::BlobLimit);
        }
        let kind = entry.file_type().map_err(|_| ArchiveError::Unavailable)?;
        if kind.is_symlink() {
            return Err(ArchiveError::Unavailable);
        }
        if kind.is_dir() {
            walk(root, &entry.path(), depth + 1, limits, visitor)?;
            continue;
        }
        if !kind.is_file() {
            return Err(ArchiveError::Unavailable);
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ArchiveError::Unavailable)?
            .to_str()
            .ok_or(ArchiveError::Unavailable)?;
        let remaining = (ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 as u64)
            .checked_sub(limits.bytes)
            .ok_or(ArchiveError::TotalByteLimit)?;
        let file = File::open(&path).map_err(|_| ArchiveError::Unavailable)?;
        if file
            .metadata()
            .map_err(|_| ArchiveError::Unavailable)?
            .len()
            > remaining
        {
            return Err(ArchiveError::TotalByteLimit);
        }
        let mut bytes = Vec::new();
        file.take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ArchiveError::Unavailable)?;
        limits.bytes = limits
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(ArchiveError::TotalByteLimit)?;
        if limits.bytes > ea_archive::MAX_TOTAL_ARCHIVE_BYTES_V1 as u64 {
            return Err(ArchiveError::TotalByteLimit);
        }
        // No exclusions by path, suffix or role. Even control-file names cannot
        // hide exact target bytes from a physical-removal publication fence.
        visitor(ArchiveBlob::new(relative, &bytes))?;
    }
    Ok(())
}
