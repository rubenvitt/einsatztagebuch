//! Exact untrusted component union, no object/role classification shortcut.
mod support;
use ea_archive::{ArchiveBackendError, ArchiveBlob, ArchiveError, ArchiveSource, MAX_ARCHIVE_BLOBS_V1};
use ea_recovery::FsArchiveSource;

struct Component(Vec<(&'static str,&'static [u8])>);
impl ArchiveSource for Component {
    fn visit_blobs(&self,visit:&mut dyn FnMut(ArchiveBlob<'_>)->Result<(),ArchiveError>)->Result<(),ArchiveError>{
        for (path,bytes) in &self.0 {visit(ArchiveBlob::new(path,bytes))?;} Ok(())
    }
}
fn contents(source:&dyn ArchiveSource)->Vec<(String,Vec<u8>)>{
    let mut rows=Vec::new();source.visit_blobs(&mut|b|{rows.push((b.path_hint().into(),b.bytes().to_vec()));Ok(())}).unwrap();rows
}

#[test]
fn exact_union_keeps_identical_bytes_once_and_only_committed_view_excludes_staging(){
    let root=support::temp_dir("exact-component-union");
    std::fs::create_dir(root.path().join("entries")).unwrap();
    std::fs::write(root.path().join("entries/one.eip"),b"first-exact").unwrap();
    let union=FsArchiveSource::open(root.path()).unwrap().with_exact_component(&Component(vec![
        ("entries/one.eip",b"first-exact"),("entries/two.eip",b"second-exact"),
        ("entries/two.eip",b"second-exact"),("entries/prepared.eip.staging",b"prepared-exact"),
    ])).unwrap();
    assert_eq!(contents(&union).len(),3);
    assert_eq!(contents(&union.committed_view()),vec![("entries/one.eip".into(),b"first-exact".to_vec()),("entries/two.eip".into(),b"second-exact".to_vec())]);
    assert_eq!(contents(&FsArchiveSource::open(root.path()).unwrap()).len(),1,"the union never writes component bytes into the filesystem");
}

#[test]
fn address_conflicts_invalid_paths_and_incomplete_components_fail_without_precedence(){
    let root=support::temp_dir("exact-component-conflict");
    std::fs::create_dir(root.path().join("entries")).unwrap();
    std::fs::write(root.path().join("entries/one.eip"),b"original").unwrap();
    assert!(matches!(FsArchiveSource::open(root.path()).unwrap().with_exact_component(&Component(vec![("entries/one.eip",b"replacement")])),Err(ArchiveBackendError::ByteConflict)));
    for invalid in ["../escape","entries/../escape","/entries/absolute","entries/with\\slash","unknown/blob"]{
        assert!(matches!(FsArchiveSource::open(root.path()).unwrap().with_exact_component(&Component(vec![(invalid,b"x")])),Err(ArchiveBackendError::Path)));
    }
    struct Incomplete;
    impl ArchiveSource for Incomplete{
        fn visit_blobs(&self,visit:&mut dyn FnMut(ArchiveBlob<'_>)->Result<(),ArchiveError>)->Result<(),ArchiveError>{visit(ArchiveBlob::new("entries/new.eip",b"partial"))?;Err(ArchiveError::Unavailable)}
    }
    assert!(FsArchiveSource::open(root.path()).unwrap().with_exact_component(&Incomplete).is_err());
    assert_eq!(std::fs::read(root.path().join("entries/one.eip")).unwrap(),b"original");
}

#[test]
fn component_enumeration_stops_at_the_resource_limit_even_for_duplicate_zero_byte_rows(){
    use std::cell::Cell;
    struct Excessive(Cell<usize>);
    impl ArchiveSource for Excessive{
        fn visit_blobs(&self,visit:&mut dyn FnMut(ArchiveBlob<'_>)->Result<(),ArchiveError>)->Result<(),ArchiveError>{
            for _ in 0..MAX_ARCHIVE_BLOBS_V1+2 {self.0.set(self.0.get()+1);visit(ArchiveBlob::new("entries/duplicate.eip",b""))?;} Ok(())
        }
    }
    let root=support::temp_dir("exact-component-limit");let incoming=Excessive(Cell::new(0));
    assert!(matches!(FsArchiveSource::open(root.path()).unwrap().with_exact_component(&incoming),Err(ArchiveBackendError::InventoryMismatch)));
    assert_eq!(incoming.0.get(),MAX_ARCHIVE_BLOBS_V1+1);
}
