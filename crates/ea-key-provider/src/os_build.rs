//! Native build identity binds operational evidence to the actual OS state.
//! It is not a statement that the build satisfies an organizational patch policy.
use crate::KeyError;
use ea_types::ObjectHash;
use std::{process::Command, time::Duration};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HostOsBuild {
    family: u8,
    hash: ObjectHash,
}
impl HostOsBuild {
    pub const fn family(self) -> u8 {
        self.family
    }
    pub const fn hash(self) -> ObjectHash {
        self.hash
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_fixture(family: u8, marker: u8) -> Self {
        assert!((1..=3).contains(&family));
        Self {
            family,
            hash: ea_crypto::object_hash(&[family, marker]),
        }
    }
}
fn identity(family: u8, components: &[&str]) -> Result<HostOsBuild, KeyError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.str("EINSATZARCHIV-OS-BUILD-v1"))
        .and_then(|e| e.u8(family))
        .and_then(|e| e.array(components.len() as u64))
        .map_err(|_| KeyError::NotFound)?;
    for component in components {
        e.str(component).map_err(|_| KeyError::NotFound)?;
    }
    Ok(HostOsBuild {
        family,
        hash: ea_crypto::object_hash(&e.into_writer()),
    })
}
fn token(output: &str) -> Result<&str, KeyError> {
    let value = output.strip_suffix("\n").unwrap_or(output);
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
    {
        return Err(KeyError::NotFound);
    }
    Ok(value)
}
fn macos_build(output: &str) -> Result<HostOsBuild, KeyError> {
    identity(1, &[token(output)?])
}
fn ubuntu_build(release: &str, kernel: &str) -> Result<HostOsBuild, KeyError> {
    fn field<'a>(release: &'a str, name: &str) -> Result<&'a str, KeyError> {
        let mut matches = release.lines().filter_map(|line| line.strip_prefix(name));
        let value = matches.next().ok_or(KeyError::NotFound)?;
        if matches.next().is_some() {
            return Err(KeyError::NotFound);
        }
        let value = if let Some(quoted) = value.strip_prefix('"') {
            quoted.strip_suffix('"').ok_or(KeyError::NotFound)?
        } else {
            value
        };
        token(value)
    }
    let id = field(release, "ID=")?;
    let version = field(release, "VERSION_ID=")?;
    if id != "ubuntu" || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(KeyError::NotFound);
    }
    identity(2, &[id, version, token(kernel)?])
}
fn windows_build(output: &str) -> Result<HostOsBuild, KeyError> {
    let output = output.strip_suffix("\r\n").unwrap_or(output);
    let value = token(output)?;
    let Some((build, revision)) = value.split_once('.') else {
        return Err(KeyError::NotFound);
    };
    if [build, revision]
        .iter()
        .any(|v| v.is_empty() || v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(KeyError::NotFound);
    }
    identity(3, &[build, revision])
}
pub fn measure_native_os_build() -> Result<HostOsBuild, KeyError> {
    let run = |command| {
        crate::native_posture::run(command, Duration::from_secs(2)).ok_or(KeyError::NotFound)
    };
    if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/sw_vers");
        c.arg("-buildVersion");
        return macos_build(&run(c)?);
    }
    if cfg!(target_os = "linux") {
        let release = read_release()?;
        let mut c = Command::new("/usr/bin/uname");
        c.arg("-r");
        return ubuntu_build(&release, &run(c)?);
    }
    if cfg!(windows) {
        let mut c = Command::new(
            r"\\?\GLOBALROOT\SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        c.args(["-NoLogo","-NoProfile","-NonInteractive","-Command",r"$ErrorActionPreference='Stop'; $v=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; if ($v.CurrentBuildNumber -notmatch '^[0-9]{1,10}$' -or $v.UBR -isnot [int] -or $v.UBR -lt 0) { exit 1 }; [Console]::WriteLine($v.CurrentBuildNumber + '.' + $v.UBR)"]);
        return windows_build(&run(c)?);
    }
    Err(KeyError::NotFound)
}
#[cfg(unix)]
fn read_release() -> Result<String, KeyError> {
    use std::{
        io::Read as _,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };
    let file = std::fs::File::open("/etc/os-release").map_err(|_| KeyError::NotFound)?;
    let m = file.metadata().map_err(|_| KeyError::NotFound)?;
    if !m.is_file() || m.uid() != 0 || m.permissions().mode() & 0o022 != 0 || m.len() > 16_384 {
        return Err(KeyError::NotFound);
    }
    let mut text = String::new();
    file.take(16_385)
        .read_to_string(&mut text)
        .map_err(|_| KeyError::NotFound)?;
    if text.len() > 16_384 {
        return Err(KeyError::NotFound);
    }
    Ok(text)
}
#[cfg(not(unix))]
fn read_release() -> Result<String, KeyError> {
    Err(KeyError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_identity_is_exact_and_rejects_ambiguous_native_output() {
        let first = macos_build("25A123\n").unwrap();
        let second = macos_build("25A124\n").unwrap();
        assert!(first.hash() != second.hash());
        assert_eq!(first.family(), 1);
        for input in ["", "25A123\nextra", " 25A123", "25A123 $(payload)", "é"] {
            assert!(macos_build(input).is_err());
        }
    }
    #[test]
    fn ubuntu_build_requires_one_unambiguous_supported_distribution_and_native_kernel() {
        let good = ubuntu_build("ID=ubuntu\nVERSION_ID=\"24.04\"\n", "6.8.0-41-generic\n").unwrap();
        assert_eq!(good.family(), 2);
        for release in [
            "ID=ubuntu\n",
            "ID=debian\nVERSION_ID=24.04\n",
            "ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n",
            "ID=ubuntu\nVERSION_ID=\"24.04\n",
        ] {
            assert!(ubuntu_build(release, "6.8.0-41-generic\n").is_err());
        }
        assert!(ubuntu_build("ID=ubuntu\nVERSION_ID=24.04\n", "\n").is_err());
    }
    #[test]
    fn windows_build_binds_revision_and_rejects_unparsed_values() {
        let first = windows_build("26100.1\n").unwrap();
        assert!(first.hash() == windows_build("26100.1\r\n").unwrap().hash());
        assert_eq!(first.family(), 3);
        assert!(first.hash() != windows_build("26100.2\n").unwrap().hash());
        for input in ["26100", "26100.1.2", "26100.-1", "26100.1\nextra", "26100."] {
            assert!(windows_build(input).is_err());
        }
    }
}
