use std::{fs,path::Path};
pub struct TokenMedia {pub signing:ea_recovery::ResolvedSigningKey,pub recovery:ea_recovery::ResolvedRecipientKey}
impl TokenMedia {
    pub fn open(directory:&Path)->Self {
        use std::io::Write;
        let module=std::path::PathBuf::from(std::env::var_os("EA_TEST_PKCS11_MODULE").expect("explicit task fixture required")).canonicalize().unwrap();
        let base=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.superpowers/pkcs11-fixture-v1").canonicalize().unwrap();
        assert!(module.starts_with(base),"only the task-owned native module is authorized");
        let reference=|id|ea_recovery::Pkcs11KeyReference::new(module.clone(),"drk250-fixture".into(),id).unwrap();
        let write_pin=|path:&Path,value:&[u8]| {
            let mut options=fs::OpenOptions::new();options.create_new(true).write(true);
            #[cfg(unix)] {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).unwrap().write_all(value).unwrap();
        };
        let pin=directory.join("test-token.pin");write_pin(&pin,b"12345678");
        let recovery=ea_recovery::resolve_recipient_key(&ea_recovery::KeySourceSpec::Pkcs11{reference:reference("c1"),pin_file:pin.clone()}).unwrap();
        let signing=ea_recovery::resolve_signing_key(&ea_recovery::KeySourceSpec::Pkcs11{reference:reference("d1"),pin_file:pin}).unwrap();
        let wrong=directory.join("wrong-token.pin");write_pin(&wrong,b"wrong-task-pin");
        assert!(ea_recovery::resolve_signing_key(&ea_recovery::KeySourceSpec::Pkcs11{reference:reference("d1"),pin_file:wrong.clone()}).is_err());
        assert!(ea_recovery::resolve_recipient_key(&ea_recovery::KeySourceSpec::Pkcs11{reference:reference("c1"),pin_file:wrong}).is_err());
        Self{signing,recovery}
    }
    pub fn signing_thumbprint(&self)->String {hex::encode(self.signing.public_key().unwrap().thumbprint().as_bytes())}
}
